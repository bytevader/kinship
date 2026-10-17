//! Experimental identity primitives for the opt-in protocol planned after 1.0.
//!
//! Decoding checks structure; [`Certificate::verify`] checks trust, cluster and time.
//! These primitives do not enable signing, enforce membership policy or retain revocations.

use core::fmt;

use ctutils::CtEq;
use ed25519_dalek::Signer;
use zeroize::Zeroize;

use crate::wire::{Reader, Sink};
use crate::{DecodeError, NodeId};

pub type CertificateId = [u8; 8];
pub type IssuerId = [u8; 8];
pub type ClusterId = [u8; 8];
pub type Signature = [u8; 64];

/// An RFC 8032 seed, heap allocated, zeroized on drop and compared in constant time.
/// Moving it moves only a pointer. Copies supplied by the caller remain its responsibility.
#[derive(Clone)]
pub struct SigningKey(Box<[u8; 32]>);

impl SigningKey {
    pub const LEN: usize = 32;

    pub fn from_bytes(mut seed: [u8; 32]) -> Self {
        let key = Self(Box::new(seed));
        seed.zeroize();
        key
    }

    pub fn from_slice(seed: &[u8]) -> Result<Self, IdentityError> {
        if seed.len() != Self::LEN {
            return Err(IdentityError::WrongLength);
        }
        let mut key = Self(Box::new([0; 32]));
        key.0.copy_from_slice(seed);
        Ok(key)
    }

    pub fn public_key(&self) -> PublicKey {
        // Dalek zeroizes its temporary signing key (including its expanded secret) on drop.
        PublicKey(ed25519_dalek::SigningKey::from_bytes(&self.0).verifying_key())
    }

    /// Deterministic, ordinary Ed25519, not Ed25519ph or Ed25519ctx.
    pub fn sign(&self, bytes: &[u8]) -> Signature {
        ed25519_dalek::SigningKey::from_bytes(&self.0)
            .sign(bytes)
            .to_bytes()
    }
}

impl PartialEq for SigningKey {
    fn eq(&self, other: &Self) -> bool {
        self.0.ct_eq(&*other.0).to_bool()
    }
}

impl Eq for SigningKey {}

impl Drop for SigningKey {
    fn drop(&mut self) {
        self.0.zeroize();
    }
}

impl fmt::Debug for SigningKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("SigningKey(REDACTED)")
    }
}

/// A decompressed, canonical Ed25519 public key that is not small order.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct PublicKey(ed25519_dalek::VerifyingKey);

impl PublicKey {
    pub const LEN: usize = 32;

    pub fn from_bytes(bytes: [u8; 32]) -> Result<Self, IdentityError> {
        let key = ed25519_dalek::VerifyingKey::from_bytes(&bytes)
            .map_err(|_| IdentityError::InvalidPublicKey)?;
        // Dalek accepts ZIP-215 point encodings. Recompression also rejects noncanonical
        // y coordinates and the negative encoding of zero, before an identity is cached.
        if key.is_weak() || key.to_edwards().compress().to_bytes() != bytes {
            return Err(IdentityError::InvalidPublicKey);
        }
        Ok(Self(key))
    }

    pub fn from_slice(bytes: &[u8]) -> Result<Self, IdentityError> {
        Self::from_bytes(bytes.try_into().map_err(|_| IdentityError::WrongLength)?)
    }

    pub fn to_bytes(self) -> [u8; 32] {
        self.0.to_bytes()
    }

    pub fn issuer_id(self) -> IssuerId {
        hash_id(&self.to_bytes())
    }

    /// Always strict: rejects weak R points, noncanonical R and non-reduced S.
    pub fn verify(&self, bytes: &[u8], signature: &Signature) -> Result<(), IdentityError> {
        self.0
            .verify_strict(bytes, &ed25519_dalek::Signature::from_bytes(signature))
            .map_err(|_| IdentityError::InvalidSignature)
    }
}

pub fn cluster_id(label: &[u8]) -> ClusterId {
    hash_id(label)
}

fn hash_id(bytes: &[u8]) -> [u8; 8] {
    let mut id = [0; 8];
    id.copy_from_slice(&blake3::hash(bytes).as_bytes()[..8]);
    id
}

pub(crate) fn signed_bytes(kind: u8, cluster: ClusterId, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(11 + 1 + 8 + body.len());
    out.extend_from_slice(b"kinship v2 ");
    out.push(kind);
    out.extend_from_slice(&cluster);
    out.extend_from_slice(body);
    out
}

/// A CA's exact name-to-key binding, certificate format version 1.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Certificate<'a> {
    pub(crate) issuer: IssuerId,
    pub(crate) cluster: ClusterId,
    pub(crate) name: NodeId<'a>,
    pub(crate) key: PublicKey,
    /// Inclusive Unix seconds.
    pub(crate) not_before: u64,
    /// Exclusive Unix seconds; must be later than not_before.
    pub(crate) not_after: u64,
    pub(crate) signature: Signature,
}

impl<'a> Certificate<'a> {
    pub const VERSION: u8 = 1;
    pub const KIND: u8 = 0x0b;

    pub fn issuer(&self) -> IssuerId {
        self.issuer
    }
    pub fn cluster(&self) -> ClusterId {
        self.cluster
    }
    pub fn name(&self) -> NodeId<'a> {
        self.name
    }
    pub fn key(&self) -> PublicKey {
        self.key
    }
    pub fn not_before(&self) -> u64 {
        self.not_before
    }
    pub fn not_after(&self) -> u64 {
        self.not_after
    }
    pub fn signature(&self) -> &Signature {
        &self.signature
    }

    pub fn issue(
        ca: &SigningKey,
        label: &[u8],
        name: NodeId<'a>,
        key: PublicKey,
        not_before: u64,
        not_after: u64,
    ) -> Result<Self, IdentityError> {
        let mut cert = Self {
            issuer: ca.public_key().issuer_id(),
            cluster: cluster_id(label),
            name,
            key,
            not_before,
            not_after,
            signature: [0; 64],
        };
        cert.check_interval()?;
        cert.signature = ca.sign(&cert.signed_bytes());
        Ok(cert)
    }

    fn check_interval(&self) -> Result<(), IdentityError> {
        if self.not_before >= self.not_after {
            Err(IdentityError::InvalidValidity)
        } else {
            Ok(())
        }
    }

    pub(crate) fn put_unsigned<S: Sink>(&self, out: &mut S) {
        out.put_u8(Self::VERSION);
        out.put(&self.issuer);
        out.put(&self.cluster);
        out.put_bytes(self.name.as_str().as_bytes());
        out.put(&self.key.to_bytes());
        out.put_u64(self.not_before);
        out.put_u64(self.not_after);
    }

    pub(crate) fn put<S: Sink>(&self, out: &mut S) {
        self.put_unsigned(out);
        out.put(&self.signature);
    }

    /// The canonical body, without message type/length framing.
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(130 + self.name.as_str().len());
        self.put(&mut out);
        out
    }

    /// Strict structure only: no trust anchors or clock are consulted.
    pub fn decode(bytes: &'a [u8]) -> Result<Self, IdentityError> {
        let mut r = Reader::new(bytes);
        if r.u8()? != Self::VERSION {
            return Err(IdentityError::UnsupportedVersion);
        }
        let issuer = r.array()?;
        let cluster = r.array()?;
        let name =
            NodeId::new(core::str::from_utf8(r.bytes()?).map_err(|_| DecodeError::BadNodeId)?)?;
        let key = PublicKey::from_bytes(r.array()?)?;
        let not_before = r.u64()?;
        let not_after = r.u64()?;
        let signature = r.array()?;
        if !r.is_empty() {
            return Err(DecodeError::TrailingBytes.into());
        }
        let cert = Self {
            issuer,
            cluster,
            name,
            key,
            not_before,
            not_after,
            signature,
        };
        cert.check_interval()?;
        Ok(cert)
    }

    pub fn signed_bytes(&self) -> Vec<u8> {
        let mut body = Vec::with_capacity(66 + self.name.as_str().len());
        self.put_unsigned(&mut body);
        signed_bytes(Self::KIND, self.cluster, &body)
    }

    pub fn id(&self) -> CertificateId {
        hash_id(&self.encode())
    }

    fn verify_signature(
        &self,
        anchors: &[PublicKey],
        label: &[u8],
    ) -> Result<PublicKey, IdentityError> {
        self.check_interval()?;
        if self.cluster != cluster_id(label) {
            return Err(IdentityError::WrongCluster);
        }
        verify_issuer(self.issuer, anchors, &self.signed_bytes(), &self.signature)
    }

    /// Checks the CA, cluster and validity at caller-supplied Unix seconds.
    /// Skew is in seconds and arithmetic saturates at the integer boundaries.
    pub fn verify(
        &self,
        anchors: &[PublicKey],
        label: &[u8],
        now: u64,
        skew: u64,
    ) -> Result<(), IdentityError> {
        if now.saturating_add(skew) < self.not_before {
            return Err(IdentityError::NotYetValid);
        }
        if now.saturating_sub(skew) >= self.not_after {
            return Err(IdentityError::Expired);
        }
        self.verify_signature(anchors, label).map(|_| ())
    }
}

fn verify_issuer(
    issuer: IssuerId,
    anchors: &[PublicKey],
    bytes: &[u8],
    signature: &Signature,
) -> Result<PublicKey, IdentityError> {
    let mut matched = false;
    for anchor in anchors.iter().filter(|anchor| anchor.issuer_id() == issuer) {
        matched = true;
        if anchor.verify(bytes, signature).is_ok() {
            return Ok(*anchor);
        }
    }
    Err(if matched {
        IdentityError::InvalidSignature
    } else {
        IdentityError::UnknownIssuer
    })
}

/// A CA's revocation of one exact certificate. Retain until not_after (Unix seconds).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Revocation {
    pub issuer: IssuerId,
    pub certificate_id: CertificateId,
    pub not_after: u64,
    pub signature: Signature,
}

impl Revocation {
    pub const KIND: u8 = 0x0c;
    pub const LEN: usize = 88;

    pub fn issue(
        ca: &SigningKey,
        label: &[u8],
        certificate: &Certificate<'_>,
    ) -> Result<Self, IdentityError> {
        // An anchor is allowed to revoke only certificates it actually issued.
        certificate.verify_signature(&[ca.public_key()], label)?;
        let mut rev = Self {
            issuer: certificate.issuer,
            certificate_id: certificate.id(),
            not_after: certificate.not_after,
            signature: [0; 64],
        };
        rev.signature = ca.sign(&rev.signed_bytes(label));
        Ok(rev)
    }

    pub(crate) fn put_unsigned<S: Sink>(&self, out: &mut S) {
        out.put(&self.issuer);
        out.put(&self.certificate_id);
        out.put_u64(self.not_after);
    }

    pub fn encode(&self) -> [u8; Self::LEN] {
        let mut out = [0; Self::LEN];
        out[..8].copy_from_slice(&self.issuer);
        out[8..16].copy_from_slice(&self.certificate_id);
        out[16..24].copy_from_slice(&self.not_after.to_be_bytes());
        out[24..].copy_from_slice(&self.signature);
        out
    }

    pub fn decode(bytes: &[u8]) -> Result<Self, IdentityError> {
        if bytes.len() != Self::LEN {
            return Err(IdentityError::WrongLength);
        }
        let mut r = Reader::new(bytes);
        Ok(Self {
            issuer: r.array()?,
            certificate_id: r.array()?,
            not_after: r.u64()?,
            signature: r.array()?,
        })
    }

    pub fn signed_bytes(&self, label: &[u8]) -> Vec<u8> {
        let mut body = Vec::with_capacity(24);
        self.put_unsigned(&mut body);
        signed_bytes(Self::KIND, cluster_id(label), &body)
    }

    /// Verifies both the certificate's CA proof and its revocation under that same CA.
    /// Expiry/retention and runtime removal are the caller's policy, not a codec operation.
    pub fn verify_for(
        &self,
        certificate: &Certificate<'_>,
        anchors: &[PublicKey],
        label: &[u8],
    ) -> Result<(), IdentityError> {
        if self.issuer != certificate.issuer
            || self.certificate_id != certificate.id()
            || self.not_after != certificate.not_after
        {
            return Err(IdentityError::WrongCertificate);
        }
        let ca = certificate.verify_signature(anchors, label)?;
        ca.verify(&self.signed_bytes(label), &self.signature)
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentityError {
    Decode(DecodeError),
    WrongLength,
    UnsupportedVersion,
    InvalidPublicKey,
    InvalidSignature,
    InvalidValidity,
    NotYetValid,
    Expired,
    UnknownIssuer,
    WrongCluster,
    WrongCertificate,
}

impl From<DecodeError> for IdentityError {
    fn from(error: DecodeError) -> Self {
        Self::Decode(error)
    }
}

impl fmt::Display for IdentityError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "identity: {self:?}")
    }
}

impl std::error::Error for IdentityError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn moving_a_signing_key_moves_no_seed_bytes() {
        let first = SigningKey::from_bytes([7; 32]);
        let address = first.0.as_ptr();
        let mut keys = vec![first];
        keys.extend((8..40).map(|n| SigningKey::from_bytes([n; 32])));
        assert_eq!(keys.swap_remove(0).0.as_ptr(), address);
    }
}
