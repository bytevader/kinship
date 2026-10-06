use core::fmt;

/// Why a packet, stream frame or payload was rejected.
///
/// Every variant is a normal outcome for hostile or corrupt input; none of them is a bug in the
/// caller. Drivers count these under `decode_errors`, except [`DecodeError::is_auth_failure`]
/// ones which count under `decrypt_failures`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum DecodeError {
    /// The packet or frame is larger than the configured limit.
    TooLarge,
    /// The input ended before a field did.
    Truncated,
    /// The first two bytes are not the kinship magic.
    BadMagic,
    /// The version byte is zero or above the highest version this build speaks.
    UnsupportedVersion(u8),
    /// A reserved flag bit is set.
    ReservedFlags,
    /// A datagram carries the stream-frame flag, or a stream frame lacks it.
    WrongPacketKind,
    /// The packet is encrypted and this node is plaintext, or the other way round.
    EncryptionMismatch,
    /// A plaintext packet carries another cluster's label hash.
    WrongCluster,
    /// No installed key has the packet's key id.
    UnknownKey(u32),
    /// A key with the packet's id exists but the tag did not verify.
    AuthFailed,
    /// A varint is longer than five bytes, exceeds `u32::MAX` or is not minimal.
    BadVarint,
    /// A length or count does not fit the bytes that follow it.
    BadLength,
    /// The payload holds no messages.
    EmptyPayload,
    /// Bytes remain after the last message of the payload.
    TrailingBytes,
    /// A node id is empty, longer than 64 bytes or not UTF-8.
    BadNodeId,
    /// An address has an unknown family byte.
    BadAddr,
    /// A member state byte is not 0 to 3.
    BadState,
    /// A boolean byte is neither 0 nor 1.
    BadBool,
    /// An Alive record has `vmin > vmax` or `vmin == 0`.
    BadVersionRange,
    /// Metadata is longer than `max_meta_bytes`.
    MetaTooLarge,
    /// A metadata tag list is malformed.
    BadTags,
}

impl DecodeError {
    /// True when the packet was well-formed but failed authentication, which a driver counts as
    /// a decrypt failure rather than a decode error.
    pub fn is_auth_failure(&self) -> bool {
        matches!(self, Self::UnknownKey(_) | Self::AuthFailed)
    }
}

impl fmt::Display for DecodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str("packet exceeds the size limit"),
            Self::Truncated => f.write_str("input ended early"),
            Self::BadMagic => f.write_str("bad magic"),
            Self::UnsupportedVersion(v) => write!(f, "unsupported wire version {v}"),
            Self::ReservedFlags => f.write_str("reserved flag bits set"),
            Self::WrongPacketKind => f.write_str("datagram/stream flag mismatch"),
            Self::EncryptionMismatch => f.write_str("encrypted/plaintext mismatch"),
            Self::WrongCluster => f.write_str("cluster label hash mismatch"),
            Self::UnknownKey(id) => write!(f, "no key with id {id:08x}"),
            Self::AuthFailed => f.write_str("authentication failed"),
            Self::BadVarint => f.write_str("malformed varint"),
            Self::BadLength => f.write_str("length exceeds remaining input"),
            Self::EmptyPayload => f.write_str("payload holds no messages"),
            Self::TrailingBytes => f.write_str("trailing bytes after last message"),
            Self::BadNodeId => f.write_str("invalid node id"),
            Self::BadAddr => f.write_str("invalid address"),
            Self::BadState => f.write_str("invalid member state"),
            Self::BadBool => f.write_str("invalid boolean"),
            Self::BadVersionRange => f.write_str("invalid version range"),
            Self::MetaTooLarge => f.write_str("metadata too large"),
            Self::BadTags => f.write_str("malformed metadata tags"),
        }
    }
}

impl std::error::Error for DecodeError {}

/// Why a message list could not be sealed into a packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum EncodeError {
    /// The sealed packet would exceed `udp_max_payload` or `max_stream_frame`.
    TooLarge,
    /// No messages were given.
    Empty,
    /// An Alive record's metadata exceeds `max_meta_bytes`.
    MetaTooLarge,
    /// An Alive record has `vmin > vmax` or `vmin == 0`.
    BadVersionRange,
}

impl fmt::Display for EncodeError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::TooLarge => f.write_str("packet would exceed the size limit"),
            Self::Empty => f.write_str("no messages to send"),
            Self::MetaTooLarge => f.write_str("metadata too large"),
            Self::BadVersionRange => f.write_str("invalid version range"),
        }
    }
}

impl std::error::Error for EncodeError {}

/// A [`Codec`](crate::Codec) was configured with unusable parameters.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum ConfigError {
    /// The cluster label is longer than [`MAX_LABEL_LEN`](crate::MAX_LABEL_LEN) bytes.
    LabelTooLong,
    /// An encrypted codec needs at least one key.
    NoKeys,
    /// A limit is too small to hold even the packet overhead.
    LimitTooSmall,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::LabelTooLong => f.write_str("cluster label too long"),
            Self::NoKeys => f.write_str("encrypted codec needs at least one key"),
            Self::LimitTooSmall => f.write_str("size limit below packet overhead"),
        }
    }
}

impl std::error::Error for ConfigError {}

/// Text given as a key could not be turned into one.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyError {
    /// Not standard base64.
    NotBase64,
    /// Valid base64, but not 32 bytes.
    WrongLength,
}

impl fmt::Display for KeyError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::NotBase64 => f.write_str("key is not valid base64"),
            Self::WrongLength => f.write_str("key must be 32 bytes"),
        }
    }
}

impl std::error::Error for KeyError {}

/// A runtime change to a codec's keys was refused.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum KeyringError {
    /// The codec runs in plaintext mode and has no keys to change.
    Plaintext,
    /// The key is not installed.
    NotInstalled,
    /// The key is the one that encrypts.
    InUse,
    /// The key is the only one installed.
    LastKey,
}

impl fmt::Display for KeyringError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Plaintext => f.write_str("a plaintext node has no keys"),
            Self::NotInstalled => f.write_str("key is not installed"),
            Self::InUse => f.write_str("key is the one in use"),
            Self::LastKey => f.write_str("key is the last one installed"),
        }
    }
}

impl std::error::Error for KeyringError {}
