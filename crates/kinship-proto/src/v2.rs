//! Experimental version 2 grammar. It is deliberately separate from version 1 types so a
//! legacy caller cannot accidentally strip signatures. Parsing validates structure, not trust
//! or replay policy. See `docs/ki01-stage1.md` for the exact grammar and signature domains.

use core::fmt;
use core::net::SocketAddr;

use crate::identity::{self, Certificate, CertificateId, Revocation, Signature};
use crate::message::{put_node, read_addr, read_alive, read_bool, read_node};
use crate::wire::{Reader, Sink, varint_len};
use crate::{Alive, Dead, DecodeError, EncodeError, Limits, NodeId, State};

pub use crate::message::kind;

/// Fresh unpredictable bytes chosen by the original prober for each round. The codec
/// carries them; generating and matching them belongs to the opt-in runtime.
pub type ProbeChallenge = [u8; 16];

/// V2 rejects sizes that cannot be framed, including on 32-bit hosts. Keep this
/// independent of the legacy encoder so its behavior remains unchanged.
#[derive(Default)]
struct Count {
    len: usize,
    overflow: bool,
}

impl Sink for Count {
    fn put(&mut self, bytes: &[u8]) {
        if let Some(len) = self.len.checked_add(bytes.len()) {
            self.len = len;
        } else {
            self.len = usize::MAX;
            self.overflow = true;
        }
    }
}

impl Count {
    fn wire_len(&self) -> Result<usize, EncodeError> {
        if self.overflow || u32::try_from(self.len).is_err() {
            Err(EncodeError::TooLarge)
        } else {
            Ok(self.len)
        }
    }
}

/// Original requester's probe identity, carried unchanged by a relay's Ping.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Probe<'a> {
    pub requester: NodeId<'a>,
    pub epoch: u64,
    pub seq: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SignedAlive<'a> {
    pub alive: Alive<'a>,
    pub certificate_id: CertificateId,
    pub signature: Signature,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum RecordState {
    Alive,
    /// The peer's claim, not a signed reporter.
    Suspect {
        inc: u32,
    },
    /// The peer's claim, not a signed reporter.
    Dead {
        inc: u32,
    },
    /// A separate self-authored Left proof; the original Alive is never rewritten.
    Left {
        inc: u32,
        at: u64,
        certificate_id: CertificateId,
        signature: Signature,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record<'a> {
    pub alive: SignedAlive<'a>,
    pub state: RecordState,
}

impl<'a> Record<'a> {
    pub fn alive_message(&self) -> Message<'a> {
        Message::Alive(self.alive)
    }

    pub fn left_message(&self) -> Option<Message<'a>> {
        if let RecordState::Left {
            inc,
            at,
            certificate_id,
            signature,
        } = self.state
        {
            let a = self.alive.alive;
            Some(Message::Dead {
                dead: Dead {
                    inc,
                    node: a.node,
                    from: a.node,
                    epoch: a.epoch,
                },
                at,
                certificate_id,
                signature,
            })
        } else {
            None
        }
    }

    fn state_byte(&self) -> u8 {
        match self.state {
            RecordState::Alive => 0,
            RecordState::Suspect { .. } => 1,
            RecordState::Dead { .. } => 2,
            RecordState::Left { .. } => 3,
        }
    }

    fn put_body<S: Sink>(&self, out: &mut S) {
        out.put_u8(self.state_byte());
        put_signed_alive(out, &self.alive);
        match self.state {
            RecordState::Alive => {}
            RecordState::Suspect { inc } | RecordState::Dead { inc } => out.put_u32(inc),
            RecordState::Left {
                inc,
                at,
                certificate_id,
                signature,
            } => {
                out.put_u32(inc);
                out.put_u64(at);
                out.put(&certificate_id);
                out.put(&signature);
            }
        }
    }

    fn put<S: Sink>(&self, out: &mut S) {
        let mut count = Count::default();
        self.put_body(&mut count);
        out.put_varint(count.len as u32);
        self.put_body(out);
    }

    fn decode(body: &'a [u8], limits: &Limits) -> Result<Self, DecodeError> {
        let mut r = Reader::new(body);
        let state = State::from_wire(r.u8()?)?;
        let alive = read_signed_alive(&mut r, limits)?;
        let state = match state {
            State::Alive => RecordState::Alive,
            State::Suspect => RecordState::Suspect { inc: r.u32()? },
            State::Dead => RecordState::Dead { inc: r.u32()? },
            State::Left => RecordState::Left {
                inc: r.u32()?,
                at: r.u64()?,
                certificate_id: r.array()?,
                signature: r.array()?,
            },
        };
        if !r.is_empty() {
            return Err(DecodeError::TrailingBytes);
        }
        Ok(Self { alive, state })
    }
}

/// Validated borrowed records; fields are private so raw bytes cannot bypass validation.
#[derive(Debug, Clone, Copy)]
pub struct RecordBytes<'a> {
    count: u32,
    bytes: &'a [u8],
    limits: Limits,
}

#[derive(Clone, Copy)]
pub enum Records<'a> {
    Slice(&'a [Record<'a>]),
    Wire(RecordBytes<'a>),
}

impl<'a> Records<'a> {
    pub fn len(&self) -> usize {
        match self {
            Self::Slice(s) => s.len(),
            Self::Wire(w) => w.count as usize,
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn iter(&self) -> impl Iterator<Item = Record<'a>> + 'a {
        let records = *self;
        let mut reader = Reader::new(match records {
            Self::Wire(w) => w.bytes,
            Self::Slice(_) => &[],
        });
        (0..self.len()).map(move |i| match records {
            Self::Slice(s) => s[i],
            Self::Wire(w) => {
                // Only the decoder constructs RecordBytes, after walking every record.
                Record::decode(reader.bytes().expect("validated record length"), &w.limits)
                    .expect("validated record")
            }
        })
    }
}

impl PartialEq for Records<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.iter().eq(other.iter())
    }
}
impl Eq for Records<'_> {}
impl fmt::Debug for Records<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

/// A validated multiple of eight bytes, borrowed from a PushPull body.
#[derive(Debug, Clone, Copy)]
pub struct IdBytes<'a>(&'a [u8]);

#[derive(Clone, Copy)]
pub enum CertificateIds<'a> {
    Slice(&'a [CertificateId]),
    Wire(IdBytes<'a>),
}

impl<'a> CertificateIds<'a> {
    pub fn len(&self) -> usize {
        match self {
            Self::Slice(s) => s.len(),
            Self::Wire(w) => w.0.len() / 8,
        }
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    pub fn iter(&self) -> impl Iterator<Item = CertificateId> + 'a {
        let ids = *self;
        (0..self.len()).map(move |i| match ids {
            Self::Slice(s) => s[i],
            Self::Wire(w) => w.0[i * 8..i * 8 + 8]
                .try_into()
                .expect("validated id length"),
        })
    }
}

impl PartialEq for CertificateIds<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.iter().eq(other.iter())
    }
}
impl Eq for CertificateIds<'_> {}
impl fmt::Debug for CertificateIds<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

/// Certificates/revocations are sibling messages in the same TCP payload.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PushPull<'a> {
    pub join: bool,
    pub records: Records<'a>,
    pub known_certificates: CertificateIds<'a>,
}

/// All fields before a signature are its canonical signed body. Probe answers explicitly
/// name the requester and target so a relay can forward the target's Ack byte for byte.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Message<'a> {
    Ping {
        ping: crate::Ping<'a>,
        source_epoch: u64,
        challenge: ProbeChallenge,
        requester: Option<Probe<'a>>,
    },
    PingReq {
        request: crate::PingReq<'a>,
        requester: NodeId<'a>,
        requester_epoch: u64,
        challenge: ProbeChallenge,
    },
    Ack {
        seq: u32,
        target_epoch: u64,
        requester: NodeId<'a>,
        requester_epoch: u64,
        target: NodeId<'a>,
        challenge: ProbeChallenge,
        certificate_id: CertificateId,
        signature: Signature,
    },
    Nack {
        seq: u32,
        relay: NodeId<'a>,
        relay_epoch: u64,
        requester: NodeId<'a>,
        requester_epoch: u64,
        target: NodeId<'a>,
        challenge: ProbeChallenge,
        certificate_id: CertificateId,
        signature: Signature,
    },
    Alive(SignedAlive<'a>),
    Suspect {
        suspect: crate::Suspect<'a>,
        at: u64,
        certificate_id: CertificateId,
        signature: Signature,
    },
    Dead {
        dead: crate::Dead<'a>,
        at: u64,
        certificate_id: CertificateId,
        signature: Signature,
    },
    PushPull(PushPull<'a>),
    UserMessage {
        message: crate::UserMessage<'a>,
        certificate_id: CertificateId,
        signature: Signature,
    },
    UserBroadcast {
        broadcast: crate::UserBroadcast<'a>,
        certificate_id: CertificateId,
        signature: Signature,
    },
    Certificate(Certificate<'a>),
    Revocation(Revocation),
}

fn put_alive<S: Sink>(out: &mut S, a: &Alive<'_>) {
    crate::message::put_alive(out, a);
    if a.epoch == 0 {
        out.put_u64(0);
    }
}

fn put_signed_alive<S: Sink>(out: &mut S, a: &SignedAlive<'_>) {
    put_alive(out, &a.alive);
    out.put(&a.certificate_id);
    out.put(&a.signature);
}

fn read_signed_alive<'a>(
    r: &mut Reader<'a>,
    limits: &Limits,
) -> Result<SignedAlive<'a>, DecodeError> {
    Ok(SignedAlive {
        alive: read_alive(r, limits)?,
        certificate_id: r.array()?,
        signature: r.array()?,
    })
}

fn check_addr(addr: SocketAddr) -> Result<(), EncodeError> {
    if let SocketAddr::V6(a) = addr {
        if a.scope_id() != 0 || a.flowinfo() != 0 {
            return Err(EncodeError::InvalidMessage);
        }
    }
    Ok(())
}

fn check_len(len: usize) -> Result<(), EncodeError> {
    u32::try_from(len)
        .map(|_| ())
        .map_err(|_| EncodeError::TooLarge)
}

impl<'a> Message<'a> {
    pub fn kind(&self) -> u8 {
        match self {
            Self::Ping { .. } => kind::PING,
            Self::PingReq { .. } => kind::PING_REQ,
            Self::Ack { .. } => kind::ACK,
            Self::Nack { .. } => kind::NACK,
            Self::Alive(_) => kind::ALIVE,
            Self::Suspect { .. } => kind::SUSPECT,
            Self::Dead { .. } => kind::DEAD,
            Self::PushPull(_) => kind::PUSH_PULL,
            Self::UserMessage { .. } => kind::USER_MESSAGE,
            Self::UserBroadcast { .. } => kind::USER_BROADCAST,
            Self::Certificate(_) => Certificate::KIND,
            Self::Revocation(_) => Revocation::KIND,
        }
    }

    pub(crate) fn validate(&self, limits: &Limits) -> Result<(), EncodeError> {
        let check_alive = |a: &Alive<'_>| {
            check_addr(a.addr)?;
            check_len(a.meta.len())?;
            crate::Message::Alive(*a).validate(limits)
        };
        match self {
            Self::Ping { ping, .. } => check_addr(ping.source_addr),
            Self::PingReq { request, .. } => {
                check_addr(request.target_addr)?;
                check_addr(request.requester_addr)
            }
            Self::Alive(a) => check_alive(&a.alive),
            Self::PushPull(p) => {
                check_len(p.records.len())?;
                check_len(p.known_certificates.len())?;
                p.records
                    .iter()
                    .try_for_each(|r| check_alive(&r.alive.alive))
            }
            Self::UserMessage { message, .. } => check_len(message.data.len()),
            Self::UserBroadcast { broadcast, .. } => check_len(broadcast.data.len()),
            Self::Certificate(c) if c.not_before >= c.not_after => Err(EncodeError::InvalidMessage),
            _ => Ok(()),
        }?;
        let mut count = Count::default();
        self.put_body(&mut count);
        count.wire_len().map(|_| ())
    }

    fn put_unsigned<S: Sink>(&self, out: &mut S) {
        match self {
            Self::Ping {
                ping,
                source_epoch,
                challenge,
                requester,
            } => {
                crate::Message::Ping(*ping).put_body(out);
                out.put_u64(*source_epoch);
                out.put(challenge);
                out.put_u8(u8::from(requester.is_some()));
                if let Some(p) = requester {
                    put_node(out, &p.requester);
                    out.put_u64(p.epoch);
                    out.put_u32(p.seq);
                }
            }
            Self::PingReq {
                request,
                requester,
                requester_epoch,
                challenge,
            } => {
                crate::Message::PingReq(*request).put_body(out);
                put_node(out, requester);
                out.put_u64(*requester_epoch);
                out.put(challenge);
            }
            Self::Ack {
                seq,
                target_epoch,
                requester,
                requester_epoch,
                target,
                challenge,
                certificate_id,
                ..
            } => {
                out.put_u32(*seq);
                out.put_u64(*target_epoch);
                put_node(out, requester);
                out.put_u64(*requester_epoch);
                put_node(out, target);
                out.put(challenge);
                out.put(certificate_id);
            }
            Self::Nack {
                seq,
                relay,
                relay_epoch,
                requester,
                requester_epoch,
                target,
                challenge,
                certificate_id,
                ..
            } => {
                out.put_u32(*seq);
                put_node(out, relay);
                out.put_u64(*relay_epoch);
                put_node(out, requester);
                out.put_u64(*requester_epoch);
                put_node(out, target);
                out.put(challenge);
                out.put(certificate_id);
            }
            Self::Alive(a) => {
                put_alive(out, &a.alive);
                out.put(&a.certificate_id);
            }
            Self::Suspect {
                suspect,
                at,
                certificate_id,
                ..
            } => {
                crate::Message::Suspect(*suspect).put_body(out);
                if suspect.epoch == 0 {
                    out.put_u64(0);
                }
                out.put_u64(*at);
                out.put(certificate_id);
            }
            Self::Dead {
                dead,
                at,
                certificate_id,
                ..
            } => {
                crate::Message::Dead(*dead).put_body(out);
                if dead.epoch == 0 {
                    out.put_u64(0);
                }
                out.put_u64(*at);
                out.put(certificate_id);
            }
            Self::PushPull(p) => {
                out.put_u8(u8::from(p.join));
                out.put_varint(p.records.len() as u32);
                for record in p.records.iter() {
                    record.put(out);
                }
                out.put_varint(p.known_certificates.len() as u32);
                for id in p.known_certificates.iter() {
                    out.put(&id);
                }
            }
            Self::UserMessage {
                message,
                certificate_id,
                ..
            } => {
                crate::Message::UserMessage(*message).put_body(out);
                out.put(certificate_id);
            }
            Self::UserBroadcast {
                broadcast,
                certificate_id,
                ..
            } => {
                crate::Message::UserBroadcast(*broadcast).put_body(out);
                out.put(certificate_id);
            }
            Self::Certificate(c) => c.put_unsigned(out),
            Self::Revocation(r) => r.put_unsigned(out),
        }
    }

    pub fn signature(&self) -> Option<&Signature> {
        match self {
            Self::Alive(a) => Some(&a.signature),
            Self::Certificate(c) => Some(&c.signature),
            Self::Revocation(r) => Some(&r.signature),
            Self::Ack { signature, .. }
            | Self::Nack { signature, .. }
            | Self::Suspect { signature, .. }
            | Self::Dead { signature, .. }
            | Self::UserMessage { signature, .. }
            | Self::UserBroadcast { signature, .. } => Some(signature),
            _ => None,
        }
    }

    /// Canonical Ed25519 preimage. Only a direct UserMessage requires a packet nonce;
    /// other statements reject one. Unsigned control/aggregate messages return an error.
    pub fn signed_bytes(
        &self,
        label: &[u8],
        nonce: Option<&[u8; 24]>,
    ) -> Result<Vec<u8>, EncodeError> {
        self.validate(&Limits {
            max_meta_bytes: usize::MAX,
            ..Limits::default()
        })?;
        if self.signature().is_none()
            || (matches!(self, Self::UserMessage { .. }) != nonce.is_some())
        {
            return Err(EncodeError::InvalidMessage);
        }
        if let Self::Certificate(c) = self {
            if c.cluster != identity::cluster_id(label) {
                return Err(EncodeError::InvalidMessage);
            }
        }
        let mut body = Vec::new();
        self.put_unsigned(&mut body);
        let mut bytes = identity::signed_bytes(self.kind(), identity::cluster_id(label), &body);
        if let Some(nonce) = nonce {
            bytes.extend_from_slice(nonce);
        }
        Ok(bytes)
    }

    fn put_body<S: Sink>(&self, out: &mut S) {
        self.put_unsigned(out);
        if let Some(signature) = self.signature() {
            out.put(signature);
        }
    }

    pub(crate) fn put<S: Sink>(&self, out: &mut S) {
        let mut count = Count::default();
        self.put_body(&mut count);
        out.put_u8(self.kind());
        out.put_varint(count.len as u32);
        self.put_body(out);
    }

    pub fn encoded_len(&self) -> usize {
        let mut count = Count::default();
        self.put_body(&mut count);
        count.len.saturating_add(1 + varint_len(count.len as u32))
    }

    fn decode(ty: u8, body: &'a [u8], limits: &Limits) -> Result<Option<Self>, DecodeError> {
        if ty == Certificate::KIND {
            return Certificate::decode(body)
                .map(Self::Certificate)
                .map(Some)
                .map_err(|_| DecodeError::BadIdentity);
        }
        if ty == Revocation::KIND {
            return Revocation::decode(body)
                .map(Self::Revocation)
                .map(Some)
                .map_err(|_| DecodeError::BadIdentity);
        }
        let mut r = Reader::new(body);
        let m = match ty {
            kind::PING => {
                let ping = crate::Ping {
                    seq: r.u32()?,
                    target: read_node(&mut r)?,
                    source: read_node(&mut r)?,
                    source_addr: read_addr(&mut r)?,
                };
                let source_epoch = r.u64()?;
                let challenge = r.array()?;
                let requester = if read_bool(&mut r)? {
                    Some(Probe {
                        requester: read_node(&mut r)?,
                        epoch: r.u64()?,
                        seq: r.u32()?,
                    })
                } else {
                    None
                };
                Self::Ping {
                    ping,
                    source_epoch,
                    challenge,
                    requester,
                }
            }
            kind::PING_REQ => {
                let request = crate::PingReq {
                    seq: r.u32()?,
                    target: read_node(&mut r)?,
                    target_addr: read_addr(&mut r)?,
                    requester_addr: read_addr(&mut r)?,
                    want_nack: read_bool(&mut r)?,
                };
                Self::PingReq {
                    request,
                    requester: read_node(&mut r)?,
                    requester_epoch: r.u64()?,
                    challenge: r.array()?,
                }
            }
            kind::ACK => Self::Ack {
                seq: r.u32()?,
                target_epoch: r.u64()?,
                requester: read_node(&mut r)?,
                requester_epoch: r.u64()?,
                target: read_node(&mut r)?,
                challenge: r.array()?,
                certificate_id: r.array()?,
                signature: r.array()?,
            },
            kind::NACK => Self::Nack {
                seq: r.u32()?,
                relay: read_node(&mut r)?,
                relay_epoch: r.u64()?,
                requester: read_node(&mut r)?,
                requester_epoch: r.u64()?,
                target: read_node(&mut r)?,
                challenge: r.array()?,
                certificate_id: r.array()?,
                signature: r.array()?,
            },
            kind::ALIVE => Self::Alive(read_signed_alive(&mut r, limits)?),
            kind::SUSPECT => Self::Suspect {
                suspect: crate::Suspect {
                    inc: r.u32()?,
                    node: read_node(&mut r)?,
                    from: read_node(&mut r)?,
                    epoch: r.u64()?,
                },
                at: r.u64()?,
                certificate_id: r.array()?,
                signature: r.array()?,
            },
            kind::DEAD => Self::Dead {
                dead: crate::Dead {
                    inc: r.u32()?,
                    node: read_node(&mut r)?,
                    from: read_node(&mut r)?,
                    epoch: r.u64()?,
                },
                at: r.u64()?,
                certificate_id: r.array()?,
                signature: r.array()?,
            },
            kind::PUSH_PULL => {
                let join = read_bool(&mut r)?;
                let count = r.varint()?;
                if count as usize > r.rest().len() {
                    return Err(DecodeError::BadLength);
                }
                let start = r.rest();
                for _ in 0..count {
                    Record::decode(r.bytes()?, limits)?;
                }
                let bytes = &start[..start.len() - r.rest().len()];
                let id_count = r.varint()?;
                let id_len = (id_count as usize)
                    .checked_mul(8)
                    .ok_or(DecodeError::BadLength)?;
                let ids = r.take(id_len)?;
                Self::PushPull(PushPull {
                    join,
                    records: Records::Wire(RecordBytes {
                        count,
                        bytes,
                        limits: *limits,
                    }),
                    known_certificates: CertificateIds::Wire(IdBytes(ids)),
                })
            }
            kind::USER_MESSAGE => Self::UserMessage {
                message: crate::UserMessage {
                    to: read_node(&mut r)?,
                    to_epoch: r.u64()?,
                    from: read_node(&mut r)?,
                    from_epoch: r.u64()?,
                    data: r.bytes()?,
                },
                certificate_id: r.array()?,
                signature: r.array()?,
            },
            kind::USER_BROADCAST => Self::UserBroadcast {
                broadcast: crate::UserBroadcast {
                    from: read_node(&mut r)?,
                    from_epoch: r.u64()?,
                    seq: r.u64()?,
                    data: r.bytes()?,
                },
                certificate_id: r.array()?,
                signature: r.array()?,
            },
            _ => return Ok(None),
        };
        if !r.is_empty() {
            return Err(DecodeError::TrailingBytes);
        }
        Ok(Some(m))
    }
}

/// A fully validated borrowed v2 payload. No signature verification or allocation occurs.
#[derive(Clone, Copy)]
pub struct Payload<'a> {
    count: u32,
    unknown: u32,
    bytes: &'a [u8],
    limits: Limits,
}

impl<'a> Payload<'a> {
    pub fn parse(inner: &'a [u8], limits: &Limits) -> Result<Self, DecodeError> {
        let mut r = Reader::new(inner);
        let count = r.varint()?;
        if count == 0 {
            return Err(DecodeError::EmptyPayload);
        }
        let bytes = r.rest();
        if count as usize > bytes.len() / 2 {
            return Err(DecodeError::BadLength);
        }
        let mut unknown = 0;
        for _ in 0..count {
            let ty = r.u8()?;
            let body = r.bytes()?;
            if Message::decode(ty, body, limits)?.is_none() {
                unknown += 1;
            }
        }
        if !r.is_empty() {
            return Err(DecodeError::TrailingBytes);
        }
        Ok(Self {
            count,
            unknown,
            bytes,
            limits: *limits,
        })
    }

    pub fn count(&self) -> usize {
        self.count as usize
    }
    pub fn unknown(&self) -> usize {
        self.unknown as usize
    }
    pub fn iter(&self) -> Messages<'a> {
        Messages {
            left: self.count,
            bytes: self.bytes,
            limits: self.limits,
        }
    }
}

impl fmt::Debug for Payload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}
impl<'a> IntoIterator for Payload<'a> {
    type Item = Message<'a>;
    type IntoIter = Messages<'a>;
    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

pub struct Messages<'a> {
    left: u32,
    bytes: &'a [u8],
    limits: Limits,
}
impl<'a> Iterator for Messages<'a> {
    type Item = Message<'a>;
    fn next(&mut self) -> Option<Self::Item> {
        while self.left > 0 {
            self.left -= 1;
            let mut r = Reader::new(self.bytes);
            let ty = r.u8().ok()?;
            let body = r.bytes().ok()?;
            self.bytes = r.rest();
            if let Ok(Some(m)) = Message::decode(ty, body, &self.limits) {
                return Some(m);
            }
        }
        None
    }
}

pub(crate) fn put_payload<S: Sink>(out: &mut S, messages: &[Message<'_>]) {
    out.put_varint(messages.len() as u32);
    for message in messages {
        message.put(out);
    }
}

pub(crate) fn validate(messages: &[Message<'_>], limits: &Limits) -> Result<(), EncodeError> {
    if messages.is_empty() {
        return Err(EncodeError::Empty);
    }
    check_len(messages.len())?;
    messages.iter().try_for_each(|m| m.validate(limits))?;
    payload_len(messages).map(|_| ())
}

pub(crate) fn payload_len(messages: &[Message<'_>]) -> Result<usize, EncodeError> {
    let mut count = Count::default();
    put_payload(&mut count, messages);
    count.wire_len()
}

/// Encodes only an inner payload, with no packet header or encryption.
pub fn encode_payload(messages: &[Message<'_>], limits: &Limits) -> Result<Vec<u8>, EncodeError> {
    validate(messages, limits)?;
    let mut out = Vec::new();
    put_payload(&mut out, messages);
    Ok(out)
}
