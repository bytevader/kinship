//! The outer packet: header, AEAD envelope and size limits.
//!
//! Encrypted layout (all integers big-endian):
//!
//! ```text
//!  0..2   magic "kn"
//!  2      version
//!  3      flags: bit 0 encrypted, bit 1 stream frame, rest reserved (zero)
//!  4..8   key_id, first 4 bytes of BLAKE3(key)
//!  8..32  nonce, 24 random bytes
//!  32..n  ciphertext of the inner payload
//!  n..+16 Poly1305 tag
//! ```
//!
//! The AEAD associated data is the 32 header bytes followed by the cluster label. Plaintext
//! mode, for tests only, replaces `key_id` and `nonce` with the first 8 bytes of
//! BLAKE3(label), giving a 12-byte header and no tag.

use chacha20poly1305::{AeadInOut, KeyInit, XChaCha20Poly1305};
use zeroize::Zeroize;

use crate::error::{ConfigError, DecodeError, EncodeError, KeyError, KeyringError};
use crate::limits::Limits;
use crate::message::{Message, Payload, put_payload};
use crate::wire::{Count, Sink};

/// Wire format version spoken by this build.
pub const WIRE_VERSION: u8 = 1;

/// First two bytes of every packet: "kn".
pub const MAGIC: [u8; 2] = *b"kn";

/// Longest cluster label in bytes. The label is part of the AEAD associated data, which is
/// assembled on the stack.
pub const MAX_LABEL_LEN: usize = 255;

/// Header size of an encrypted packet.
pub const ENCRYPTED_HEADER_LEN: usize = 32;
/// Header size of a plaintext packet.
pub const PLAINTEXT_HEADER_LEN: usize = 12;
/// Size of the Poly1305 tag.
pub const TAG_LEN: usize = 16;
/// Size of the XChaCha20 nonce.
pub const NONCE_LEN: usize = 24;
/// Per-packet cost of encryption: header plus tag.
pub const ENCRYPTED_OVERHEAD: usize = ENCRYPTED_HEADER_LEN + TAG_LEN;

const FLAG_ENCRYPTED: u8 = 0b01;
const FLAG_STREAM: u8 = 0b10;
const FLAGS_RESERVED: u8 = !(FLAG_ENCRYPTED | FLAG_STREAM);

/// Whether a packet travels as a UDP datagram or inside a TCP stream frame.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PacketKind {
    Datagram,
    Stream,
}

/// A 32-byte XChaCha20-Poly1305 key. Zeroized on drop and never printed.
#[derive(Clone, PartialEq, Eq)]
pub struct Key([u8; 32]);

impl Key {
    pub const LEN: usize = 32;

    pub fn from_bytes(bytes: [u8; 32]) -> Self {
        Self(bytes)
    }

    /// Returns `None` unless `bytes` is exactly 32 bytes long.
    pub fn from_slice(bytes: &[u8]) -> Option<Self> {
        Some(Self(bytes.try_into().ok()?))
    }

    /// A key written as standard base64, with or without `=` padding, as `kinship keygen`
    /// prints it. Surrounding whitespace is ignored.
    pub fn from_base64(text: &str) -> Result<Self, KeyError> {
        let text = text.trim();
        let digits = text.trim_end_matches('=');
        if text.len() - digits.len() > 2 {
            return Err(KeyError::NotBase64);
        }
        let mut key = [0u8; 32];
        let mut len = 0;
        let mut acc = 0u32;
        let mut bits = 0;
        let mut result = Ok(());
        for c in digits.bytes() {
            let v = match c {
                b'A'..=b'Z' => c - b'A',
                b'a'..=b'z' => c - b'a' + 26,
                b'0'..=b'9' => c - b'0' + 52,
                b'+' => 62,
                b'/' => 63,
                _ => {
                    result = Err(KeyError::NotBase64);
                    break;
                }
            };
            acc = (acc << 6) | u32::from(v);
            bits += 6;
            if bits >= 8 {
                bits -= 8;
                if len == key.len() {
                    result = Err(KeyError::WrongLength);
                    break;
                }
                key[len] = (acc >> bits) as u8;
                len += 1;
                acc &= (1 << bits) - 1;
            }
        }
        // Leftover bits must be the zero padding of the last group.
        if result.is_ok() && (bits >= 6 || acc != 0) {
            result = Err(KeyError::NotBase64);
        }
        if result.is_ok() && len != key.len() {
            result = Err(KeyError::WrongLength);
        }
        let out = result.map(|()| Self(key));
        key.zeroize();
        acc.zeroize();
        out
    }

    /// First 4 bytes of BLAKE3(key), big-endian. Sent in the clear to pick the right key.
    pub fn id(&self) -> u32 {
        let hash = blake3::hash(&self.0);
        let b = hash.as_bytes();
        u32::from_be_bytes([b[0], b[1], b[2], b[3]])
    }

    /// [`id`](Self::id) as a [`KeyId`], which prints as 8 hex characters.
    pub fn key_id(&self) -> KeyId {
        KeyId(self.id())
    }
}

/// The public id of a [`Key`]: safe to log, and printed as 8 hex characters.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct KeyId(u32);

impl KeyId {
    pub const fn from_raw(raw: u32) -> Self {
        Self(raw)
    }

    pub const fn to_raw(self) -> u32 {
        self.0
    }
}

impl core::fmt::Display for KeyId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "{:08x}", self.0)
    }
}

impl core::fmt::Debug for KeyId {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "KeyId({:08x})", self.0)
    }
}

impl Drop for Key {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl core::fmt::Debug for Key {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        write!(f, "Key({:08x})", self.id())
    }
}

enum Security {
    Plaintext,
    /// The first key seals; every key opens.
    Encrypted(Vec<Key>),
}

/// Encodes and decodes packets for one cluster.
///
/// The codec owns the cluster label, the size limits and the keys. It performs no I/O, reads no
/// clock and draws no randomness: the caller supplies the nonce for each sealed packet.
pub struct Codec {
    label: Vec<u8>,
    label_hash: [u8; 8],
    limits: Limits,
    security: Security,
}

impl Codec {
    /// A codec that encrypts with `keys[0]` and accepts any key in `keys`.
    pub fn encrypted(label: &[u8], limits: Limits, keys: Vec<Key>) -> Result<Self, ConfigError> {
        if keys.is_empty() {
            return Err(ConfigError::NoKeys);
        }
        Self::new(label, limits, Security::Encrypted(keys))
    }

    /// A codec that sends and accepts unauthenticated, unencrypted packets. This is the
    /// `insecure_plaintext` mode and exists for tests, the simulator and loopback use.
    pub fn insecure_plaintext(label: &[u8], limits: Limits) -> Result<Self, ConfigError> {
        Self::new(label, limits, Security::Plaintext)
    }

    fn new(label: &[u8], limits: Limits, security: Security) -> Result<Self, ConfigError> {
        if label.len() > MAX_LABEL_LEN {
            return Err(ConfigError::LabelTooLong);
        }
        let hash = blake3::hash(label);
        let mut label_hash = [0u8; 8];
        label_hash.copy_from_slice(&hash.as_bytes()[..8]);
        let codec = Self {
            label: label.to_vec(),
            label_hash,
            limits,
            security,
        };
        // The smallest packet holds a count, one message type and one length byte.
        let floor = codec.overhead() + 3;
        if limits.udp_max_payload < floor || limits.max_stream_frame < floor {
            return Err(ConfigError::LimitTooSmall);
        }
        Ok(codec)
    }

    /// Replaces the installed keys; `keys[0]` becomes the sealing key.
    pub fn set_keys(&mut self, keys: Vec<Key>) -> Result<(), ConfigError> {
        if keys.is_empty() {
            return Err(ConfigError::NoKeys);
        }
        self.security = Security::Encrypted(keys);
        Ok(())
    }

    pub fn is_encrypted(&self) -> bool {
        matches!(self.security, Security::Encrypted(_))
    }

    pub fn limits(&self) -> &Limits {
        &self.limits
    }

    /// Ids of the installed keys, sealing key first. Empty in plaintext mode.
    pub fn key_ids(&self) -> Vec<KeyId> {
        match &self.security {
            Security::Plaintext => Vec::new(),
            Security::Encrypted(keys) => keys.iter().map(Key::key_id).collect(),
        }
    }

    /// Adds `key` to the keys that open packets, after the existing ones. Does nothing if it is
    /// already installed.
    pub fn install_key(&mut self, key: Key) -> Result<(), KeyringError> {
        let keys = self.keys_mut()?;
        if !keys.contains(&key) {
            keys.push(key);
        }
        Ok(())
    }

    /// Makes the installed `key` the one that seals; the others keep their order and still open.
    pub fn use_key(&mut self, key: &Key) -> Result<(), KeyringError> {
        let keys = self.keys_mut()?;
        let at = keys
            .iter()
            .position(|k| k == key)
            .ok_or(KeyringError::NotInstalled)?;
        keys[..=at].rotate_right(1);
        Ok(())
    }

    /// Drops `key`. Refuses the only key and the sealing key; a key that is not installed is
    /// already gone, so that succeeds.
    pub fn remove_key(&mut self, key: &Key) -> Result<(), KeyringError> {
        let keys = self.keys_mut()?;
        match keys.iter().position(|k| k == key) {
            None => Ok(()),
            Some(_) if keys.len() == 1 => Err(KeyringError::LastKey),
            Some(0) => Err(KeyringError::InUse),
            Some(at) => {
                keys.remove(at);
                Ok(())
            }
        }
    }

    fn keys_mut(&mut self) -> Result<&mut Vec<Key>, KeyringError> {
        match &mut self.security {
            Security::Plaintext => Err(KeyringError::Plaintext),
            Security::Encrypted(keys) => Ok(keys),
        }
    }

    /// Bytes a packet adds around its inner payload.
    pub fn overhead(&self) -> usize {
        match self.security {
            Security::Plaintext => PLAINTEXT_HEADER_LEN,
            Security::Encrypted(_) => ENCRYPTED_OVERHEAD,
        }
    }

    /// Most inner-payload bytes (count included) that fit one packet of this kind.
    pub fn max_payload_len(&self, kind: PacketKind) -> usize {
        self.limit(kind) - self.overhead()
    }

    fn limit(&self, kind: PacketKind) -> usize {
        match kind {
            PacketKind::Datagram => self.limits.udp_max_payload,
            PacketKind::Stream => self.limits.max_stream_frame,
        }
    }

    /// Seals `msgs` into one packet appended to `out`.
    ///
    /// `nonce` must be 24 fresh random bytes for every call; it is ignored in plaintext mode.
    /// On error `out` is left as it was. For [`PacketKind::Stream`] the result has no length
    /// prefix; see [`seal_stream_frame`](Self::seal_stream_frame).
    pub fn seal(
        &self,
        kind: PacketKind,
        msgs: &[Message<'_>],
        nonce: &[u8; NONCE_LEN],
        out: &mut Vec<u8>,
    ) -> Result<(), EncodeError> {
        if msgs.is_empty() {
            return Err(EncodeError::Empty);
        }
        for m in msgs {
            m.validate(&self.limits)?;
        }
        let mut payload = Count::default();
        put_payload(&mut payload, msgs);
        self.seal_with(kind, nonce, payload.0, out, |out| put_payload(out, msgs))
    }

    /// Like [`seal`](Self::seal) for a TCP stream: prefixes the packet with its `u32`
    /// big-endian length.
    pub fn seal_stream_frame(
        &self,
        msgs: &[Message<'_>],
        nonce: &[u8; NONCE_LEN],
        out: &mut Vec<u8>,
    ) -> Result<(), EncodeError> {
        let start = out.len();
        out.put(&[0; 4]);
        if let Err(e) = self.seal(PacketKind::Stream, msgs, nonce, out) {
            out.truncate(start);
            return Err(e);
        }
        let len = (out.len() - start - 4) as u32;
        out[start..start + 4].copy_from_slice(&len.to_be_bytes());
        Ok(())
    }

    /// Seals arbitrary bytes as the inner payload, without checking that they parse. For tests
    /// and fuzzing of the receive path only.
    #[doc(hidden)]
    pub fn seal_raw(
        &self,
        kind: PacketKind,
        inner: &[u8],
        nonce: &[u8; NONCE_LEN],
        out: &mut Vec<u8>,
    ) -> Result<(), EncodeError> {
        self.seal_with(kind, nonce, inner.len(), out, |out| out.put(inner))
    }

    fn seal_with(
        &self,
        kind: PacketKind,
        nonce: &[u8; NONCE_LEN],
        payload_len: usize,
        out: &mut Vec<u8>,
        write_payload: impl FnOnce(&mut Vec<u8>),
    ) -> Result<(), EncodeError> {
        if payload_len > self.max_payload_len(kind) {
            return Err(EncodeError::TooLarge);
        }
        let start = out.len();
        let mut flags = if kind == PacketKind::Stream {
            FLAG_STREAM
        } else {
            0
        };
        out.put(&MAGIC);
        out.put_u8(WIRE_VERSION);
        match &self.security {
            Security::Plaintext => {
                out.put_u8(flags);
                out.put(&self.label_hash);
                write_payload(out);
            }
            Security::Encrypted(keys) => {
                let key = &keys[0];
                flags |= FLAG_ENCRYPTED;
                out.put_u8(flags);
                out.put(&key.id().to_be_bytes());
                out.put(nonce);
                write_payload(out);
                let aad = Aad::new(&out[start..start + ENCRYPTED_HEADER_LEN], &self.label);
                let cipher = XChaCha20Poly1305::new((&key.0).into());
                let body = &mut out[start + ENCRYPTED_HEADER_LEN..];
                let tag = cipher
                    .encrypt_inout_detached(nonce.into(), aad.as_slice(), (&mut *body).into())
                    // The only failure is a body past the cipher's 256 GiB limit.
                    .map_err(|_| EncodeError::TooLarge);
                match tag {
                    Ok(tag) => out.put(tag.as_slice()),
                    Err(e) => {
                        out.truncate(start);
                        return Err(e);
                    }
                }
            }
        }
        debug_assert_eq!(out.len() - start, payload_len + self.overhead());
        Ok(())
    }

    /// Authenticates, decrypts in place and parses one packet.
    ///
    /// The size limit, magic, version, flags, packet kind and key id are all checked before any
    /// cryptography runs, so unauthenticated traffic costs at most one tag verification per
    /// matching key. The returned payload borrows the decrypted bytes of `buf`; on success the
    /// ciphertext has been overwritten with plaintext, on failure `buf` is unchanged.
    pub fn open<'a>(
        &self,
        kind: PacketKind,
        buf: &'a mut [u8],
    ) -> Result<Payload<'a>, DecodeError> {
        if buf.len() > self.limit(kind) {
            return Err(DecodeError::TooLarge);
        }
        let [m0, m1, version, flags, ..] = *buf else {
            return Err(DecodeError::Truncated);
        };
        if [m0, m1] != MAGIC {
            return Err(DecodeError::BadMagic);
        }
        if version == 0 || version > WIRE_VERSION {
            return Err(DecodeError::UnsupportedVersion(version));
        }
        if flags & FLAGS_RESERVED != 0 {
            return Err(DecodeError::ReservedFlags);
        }
        if (flags & FLAG_STREAM != 0) != (kind == PacketKind::Stream) {
            return Err(DecodeError::WrongPacketKind);
        }
        let encrypted = flags & FLAG_ENCRYPTED != 0;
        let range = match (&self.security, encrypted) {
            (Security::Plaintext, false) => {
                let hash = buf
                    .get(4..PLAINTEXT_HEADER_LEN)
                    .ok_or(DecodeError::Truncated)?;
                if hash != self.label_hash {
                    return Err(DecodeError::WrongCluster);
                }
                PLAINTEXT_HEADER_LEN..buf.len()
            }
            (Security::Encrypted(keys), true) => {
                if buf.len() < ENCRYPTED_OVERHEAD {
                    return Err(DecodeError::Truncated);
                }
                let key_id = u32::from_be_bytes([buf[4], buf[5], buf[6], buf[7]]);
                let nonce: [u8; NONCE_LEN] = buf[8..ENCRYPTED_HEADER_LEN]
                    .try_into()
                    .map_err(|_| DecodeError::Truncated)?;
                let aad = Aad::new(&buf[..ENCRYPTED_HEADER_LEN], &self.label);
                let tag_at = buf.len() - TAG_LEN;
                let tag: [u8; TAG_LEN] = buf[tag_at..]
                    .try_into()
                    .map_err(|_| DecodeError::Truncated)?;
                let body = &mut buf[ENCRYPTED_HEADER_LEN..tag_at];
                let mut matched = false;
                let mut opened = false;
                for key in keys.iter().filter(|k| k.id() == key_id) {
                    matched = true;
                    let cipher = XChaCha20Poly1305::new((&key.0).into());
                    if cipher
                        .decrypt_inout_detached(
                            (&nonce).into(),
                            aad.as_slice(),
                            (&mut *body).into(),
                            (&tag).into(),
                        )
                        .is_ok()
                    {
                        opened = true;
                        break;
                    }
                }
                if !matched {
                    return Err(DecodeError::UnknownKey(key_id));
                }
                if !opened {
                    return Err(DecodeError::AuthFailed);
                }
                ENCRYPTED_HEADER_LEN..tag_at
            }
            _ => return Err(DecodeError::EncryptionMismatch),
        };
        Payload::parse(&buf[range], &self.limits)
    }
}

/// The AEAD associated data: header bytes then label, on the stack.
struct Aad {
    buf: [u8; ENCRYPTED_HEADER_LEN + MAX_LABEL_LEN],
    len: usize,
}

impl Aad {
    fn new(header: &[u8], label: &[u8]) -> Self {
        let mut buf = [0u8; ENCRYPTED_HEADER_LEN + MAX_LABEL_LEN];
        let len = header.len() + label.len();
        buf[..header.len()].copy_from_slice(header);
        buf[header.len()..len].copy_from_slice(label);
        Self { buf, len }
    }

    fn as_slice(&self) -> &[u8] {
        &self.buf[..self.len]
    }
}
