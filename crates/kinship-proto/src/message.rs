//! Message types and the inner payload (`count:varint message*`).

use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::error::{DecodeError, EncodeError};
use crate::limits::Limits;
use crate::wire::{Count, Reader, Sink, varint_len};

/// Wire type bytes of the messages defined for version 1.
pub mod kind {
    pub const PING: u8 = 0x01;
    pub const PING_REQ: u8 = 0x02;
    pub const ACK: u8 = 0x03;
    pub const NACK: u8 = 0x04;
    pub const ALIVE: u8 = 0x05;
    pub const SUSPECT: u8 = 0x06;
    pub const DEAD: u8 = 0x07;
    pub const PUSH_PULL: u8 = 0x08;
}

/// A node name: UTF-8, 1 to [`NodeId::MAX_LEN`] bytes. Borrowed, so decoding allocates nothing.
#[derive(Clone, Copy, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct NodeId<'a>(&'a str);

impl<'a> NodeId<'a> {
    /// Longest name in bytes.
    pub const MAX_LEN: usize = 64;

    /// Validates a name.
    pub fn new(name: &'a str) -> Result<Self, DecodeError> {
        if name.is_empty() || name.len() > Self::MAX_LEN {
            return Err(DecodeError::BadNodeId);
        }
        Ok(Self(name))
    }

    pub fn as_str(&self) -> &'a str {
        self.0
    }
}

impl fmt::Debug for NodeId<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        fmt::Debug::fmt(self.0, f)
    }
}

impl fmt::Display for NodeId<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.0)
    }
}

/// A member's state as carried in push-pull records.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[repr(u8)]
pub enum State {
    Alive = 0,
    Suspect = 1,
    Dead = 2,
    Left = 3,
}

impl State {
    fn from_wire(b: u8) -> Result<Self, DecodeError> {
        match b {
            0 => Ok(Self::Alive),
            1 => Ok(Self::Suspect),
            2 => Ok(Self::Dead),
            3 => Ok(Self::Left),
            _ => Err(DecodeError::BadState),
        }
    }
}

/// `Ping`: probe `target`; the ack goes to `source_addr`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Ping<'a> {
    pub seq: u32,
    pub target: NodeId<'a>,
    pub source: NodeId<'a>,
    pub source_addr: SocketAddr,
}

/// `PingReq`: ask a relay to probe `target` on `requester_addr`'s behalf.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PingReq<'a> {
    pub seq: u32,
    pub target: NodeId<'a>,
    pub target_addr: SocketAddr,
    pub requester_addr: SocketAddr,
    pub want_nack: bool,
}

/// `Alive`: `node` is alive at incarnation `inc`, reachable at `addr`, speaking wire versions
/// `vmin` to `vmax`, carrying `meta`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Alive<'a> {
    pub inc: u32,
    pub node: NodeId<'a>,
    pub addr: SocketAddr,
    pub meta: &'a [u8],
    pub vmin: u8,
    pub vmax: u8,
}

/// `Suspect`: `from` suspects `node` at incarnation `inc`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Suspect<'a> {
    pub inc: u32,
    pub node: NodeId<'a>,
    pub from: NodeId<'a>,
}

/// `Dead`: `from` declares `node` dead at incarnation `inc`. `from == node` means the node left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dead<'a> {
    pub inc: u32,
    pub node: NodeId<'a>,
    pub from: NodeId<'a>,
}

impl Dead<'_> {
    /// True when the node announced its own departure.
    pub fn is_left(&self) -> bool {
        self.node == self.from
    }
}

/// One member in a push-pull exchange.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Record<'a> {
    pub state: State,
    pub alive: Alive<'a>,
}

/// The member list of a [`PushPull`]. Built from a slice when sending, borrowed from the frame
/// when received; iterating yields the same [`Record`]s either way.
#[derive(Clone, Copy)]
pub enum Records<'a> {
    /// Records to encode.
    Slice(&'a [Record<'a>]),
    /// Records validated by the decoder and still in wire form.
    Wire {
        count: u32,
        bytes: &'a [u8],
        limits: Limits,
    },
}

impl<'a> Records<'a> {
    /// Number of records.
    pub fn len(&self) -> usize {
        match self {
            Self::Slice(s) => s.len(),
            Self::Wire { count, .. } => *count as usize,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn iter(&self) -> RecordIter<'a> {
        match *self {
            Self::Slice(s) => RecordIter::Slice(s.iter()),
            Self::Wire {
                count,
                bytes,
                limits,
            } => RecordIter::Wire {
                left: count,
                bytes,
                limits,
            },
        }
    }
}

impl<'a> IntoIterator for Records<'a> {
    type Item = Record<'a>;
    type IntoIter = RecordIter<'a>;

    fn into_iter(self) -> RecordIter<'a> {
        self.iter()
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

/// Iterator over [`Records`].
pub enum RecordIter<'a> {
    Slice(core::slice::Iter<'a, Record<'a>>),
    Wire {
        left: u32,
        bytes: &'a [u8],
        limits: Limits,
    },
}

impl<'a> Iterator for RecordIter<'a> {
    type Item = Record<'a>;

    fn next(&mut self) -> Option<Record<'a>> {
        match self {
            Self::Slice(it) => it.next().copied(),
            Self::Wire {
                left,
                bytes,
                limits,
            } => {
                if *left == 0 {
                    return None;
                }
                *left -= 1;
                // The decoder walked these bytes once already, so a failure here cannot happen;
                // if it ever did, ending the iteration is the safe outcome.
                let mut r = Reader::new(bytes);
                let body = r.bytes().ok()?;
                let record = read_record(body, limits).ok()?;
                *bytes = r.rest();
                Some(record)
            }
        }
    }
}

/// `PushPull`: a full state exchange, TCP only. `join` marks the first message of a join.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PushPull<'a> {
    pub join: bool,
    pub records: Records<'a>,
}

/// A decoded or to-be-encoded message.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Message<'a> {
    Ping(Ping<'a>),
    PingReq(PingReq<'a>),
    Ack { seq: u32 },
    Nack { seq: u32 },
    Alive(Alive<'a>),
    Suspect(Suspect<'a>),
    Dead(Dead<'a>),
    PushPull(PushPull<'a>),
}

fn put_addr<S: Sink>(s: &mut S, addr: &SocketAddr) {
    match addr.ip() {
        IpAddr::V4(ip) => {
            s.put_u8(4);
            s.put(&ip.octets());
        }
        IpAddr::V6(ip) => {
            s.put_u8(6);
            s.put(&ip.octets());
        }
    }
    s.put_u16(addr.port());
}

fn read_addr(r: &mut Reader<'_>) -> Result<SocketAddr, DecodeError> {
    let ip = match r.u8()? {
        4 => IpAddr::V4(Ipv4Addr::from(r.array::<4>()?)),
        6 => IpAddr::V6(Ipv6Addr::from(r.array::<16>()?)),
        _ => return Err(DecodeError::BadAddr),
    };
    Ok(SocketAddr::new(ip, r.u16()?))
}

fn put_node<S: Sink>(s: &mut S, id: &NodeId<'_>) {
    s.put_bytes(id.as_str().as_bytes());
}

fn read_node<'a>(r: &mut Reader<'a>) -> Result<NodeId<'a>, DecodeError> {
    let bytes = r.bytes()?;
    let s = core::str::from_utf8(bytes).map_err(|_| DecodeError::BadNodeId)?;
    NodeId::new(s)
}

fn read_bool(r: &mut Reader<'_>) -> Result<bool, DecodeError> {
    match r.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(DecodeError::BadBool),
    }
}

fn put_alive<S: Sink>(s: &mut S, a: &Alive<'_>) {
    s.put_u32(a.inc);
    put_node(s, &a.node);
    put_addr(s, &a.addr);
    s.put_bytes(a.meta);
    s.put_u8(a.vmin);
    s.put_u8(a.vmax);
}

fn read_alive<'a>(r: &mut Reader<'a>, limits: &Limits) -> Result<Alive<'a>, DecodeError> {
    let inc = r.u32()?;
    let node = read_node(r)?;
    let addr = read_addr(r)?;
    let meta = r.bytes()?;
    if meta.len() > limits.max_meta_bytes {
        return Err(DecodeError::MetaTooLarge);
    }
    let vmin = r.u8()?;
    let vmax = r.u8()?;
    if vmin == 0 || vmin > vmax {
        return Err(DecodeError::BadVersionRange);
    }
    Ok(Alive {
        inc,
        node,
        addr,
        meta,
        vmin,
        vmax,
    })
}

fn put_record<S: Sink>(s: &mut S, rec: &Record<'_>) {
    let mut c = Count::default();
    c.put_u8(rec.state as u8);
    put_alive(&mut c, &rec.alive);
    s.put_varint(c.0 as u32);
    s.put_u8(rec.state as u8);
    put_alive(s, &rec.alive);
}

fn read_record<'a>(body: &'a [u8], limits: &Limits) -> Result<Record<'a>, DecodeError> {
    let mut r = Reader::new(body);
    let state = State::from_wire(r.u8()?)?;
    let alive = read_alive(&mut r, limits)?;
    // Bytes left in the record body are fields appended by a newer version; ignore them.
    Ok(Record { state, alive })
}

impl<'a> Message<'a> {
    /// The wire type byte.
    pub fn kind(&self) -> u8 {
        match self {
            Self::Ping(_) => kind::PING,
            Self::PingReq(_) => kind::PING_REQ,
            Self::Ack { .. } => kind::ACK,
            Self::Nack { .. } => kind::NACK,
            Self::Alive(_) => kind::ALIVE,
            Self::Suspect(_) => kind::SUSPECT,
            Self::Dead(_) => kind::DEAD,
            Self::PushPull(_) => kind::PUSH_PULL,
        }
    }

    /// Rejects values that [`encode`](Self::encode) must not emit because no conforming decoder
    /// would accept them.
    pub(crate) fn validate(&self, limits: &Limits) -> Result<(), EncodeError> {
        let check = |a: &Alive<'_>| {
            if a.meta.len() > limits.max_meta_bytes {
                Err(EncodeError::MetaTooLarge)
            } else if a.vmin == 0 || a.vmin > a.vmax {
                Err(EncodeError::BadVersionRange)
            } else {
                Ok(())
            }
        };
        match self {
            Self::Alive(a) => check(a),
            Self::PushPull(p) => p.records.iter().try_for_each(|r| check(&r.alive)),
            _ => Ok(()),
        }
    }

    fn put_body<S: Sink>(&self, s: &mut S) {
        match self {
            Self::Ping(p) => {
                s.put_u32(p.seq);
                put_node(s, &p.target);
                put_node(s, &p.source);
                put_addr(s, &p.source_addr);
            }
            Self::PingReq(p) => {
                s.put_u32(p.seq);
                put_node(s, &p.target);
                put_addr(s, &p.target_addr);
                put_addr(s, &p.requester_addr);
                s.put_u8(u8::from(p.want_nack));
            }
            Self::Ack { seq } | Self::Nack { seq } => s.put_u32(*seq),
            Self::Alive(a) => put_alive(s, a),
            Self::Suspect(m) => {
                s.put_u32(m.inc);
                put_node(s, &m.node);
                put_node(s, &m.from);
            }
            Self::Dead(m) => {
                s.put_u32(m.inc);
                put_node(s, &m.node);
                put_node(s, &m.from);
            }
            Self::PushPull(p) => {
                s.put_u8(u8::from(p.join));
                s.put_varint(p.records.len() as u32);
                for rec in p.records.iter() {
                    put_record(s, &rec);
                }
            }
        }
    }

    pub(crate) fn put<S: Sink>(&self, s: &mut S) {
        let mut c = Count::default();
        self.put_body(&mut c);
        s.put_u8(self.kind());
        s.put_varint(c.0 as u32);
        self.put_body(s);
    }

    /// Bytes this message takes inside a payload, including its type byte and length.
    pub fn encoded_len(&self) -> usize {
        let mut c = Count::default();
        self.put_body(&mut c);
        1 + varint_len(c.0 as u32) + c.0
    }

    /// Parses a message body. `Ok(None)` means the type is not one this version knows.
    fn decode(ty: u8, body: &'a [u8], limits: &Limits) -> Result<Option<Self>, DecodeError> {
        let mut r = Reader::new(body);
        // Trailing bytes after the known fields are appended fields from a newer version.
        let msg = match ty {
            kind::PING => Self::Ping(Ping {
                seq: r.u32()?,
                target: read_node(&mut r)?,
                source: read_node(&mut r)?,
                source_addr: read_addr(&mut r)?,
            }),
            kind::PING_REQ => Self::PingReq(PingReq {
                seq: r.u32()?,
                target: read_node(&mut r)?,
                target_addr: read_addr(&mut r)?,
                requester_addr: read_addr(&mut r)?,
                want_nack: read_bool(&mut r)?,
            }),
            kind::ACK => Self::Ack { seq: r.u32()? },
            kind::NACK => Self::Nack { seq: r.u32()? },
            kind::ALIVE => Self::Alive(read_alive(&mut r, limits)?),
            kind::SUSPECT => Self::Suspect(Suspect {
                inc: r.u32()?,
                node: read_node(&mut r)?,
                from: read_node(&mut r)?,
            }),
            kind::DEAD => Self::Dead(Dead {
                inc: r.u32()?,
                node: read_node(&mut r)?,
                from: read_node(&mut r)?,
            }),
            kind::PUSH_PULL => {
                let join = read_bool(&mut r)?;
                let count = r.varint()?;
                let bytes = r.rest();
                // Walk the records once so iteration later cannot fail. Each record costs at
                // least one byte, so a count larger than the input is rejected before any work.
                if count as usize > bytes.len() {
                    return Err(DecodeError::BadLength);
                }
                let mut walk = Reader::new(bytes);
                for _ in 0..count {
                    let rec = walk.bytes()?;
                    read_record(rec, limits)?;
                }
                Self::PushPull(PushPull {
                    join,
                    records: Records::Wire {
                        count,
                        bytes,
                        limits: *limits,
                    },
                })
            }
            _ => return Ok(None),
        };
        Ok(Some(msg))
    }
}

/// A validated inner payload: a list of messages, some of which this version may not know.
#[derive(Clone, Copy)]
pub struct Payload<'a> {
    count: u32,
    unknown: u32,
    bytes: &'a [u8],
    limits: Limits,
}

impl<'a> Payload<'a> {
    /// Validates `inner` completely: every message header, every known message body, and that no
    /// bytes trail the last message. Iterating afterwards cannot fail. Performs no allocation.
    pub fn parse(inner: &'a [u8], limits: &Limits) -> Result<Self, DecodeError> {
        let mut r = Reader::new(inner);
        let count = r.varint()?;
        if count == 0 {
            return Err(DecodeError::EmptyPayload);
        }
        let bytes = r.rest();
        // A message is at least a type byte and a length byte.
        if (count as usize).saturating_mul(2) > bytes.len() {
            return Err(DecodeError::BadLength);
        }
        let mut unknown = 0u32;
        for _ in 0..count {
            let ty = r.u8()?;
            let len = r.varint()? as usize;
            let body = r.take(len).map_err(|_| DecodeError::BadLength)?;
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

    /// Messages in the payload, including ones this version skips.
    pub fn count(&self) -> usize {
        self.count as usize
    }

    /// Messages skipped because their type is unknown to this version.
    pub fn unknown(&self) -> usize {
        self.unknown as usize
    }

    /// Iterates the known messages in order.
    pub fn iter(&self) -> Messages<'a> {
        Messages {
            left: self.count,
            bytes: self.bytes,
            limits: self.limits,
        }
    }
}

impl<'a> IntoIterator for Payload<'a> {
    type Item = Message<'a>;
    type IntoIter = Messages<'a>;

    fn into_iter(self) -> Messages<'a> {
        self.iter()
    }
}

impl fmt::Debug for Payload<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()?;
        if self.unknown > 0 {
            write!(f, " (+{} unknown)", self.unknown)?;
        }
        Ok(())
    }
}

/// Iterator over a [`Payload`]'s known messages.
pub struct Messages<'a> {
    left: u32,
    bytes: &'a [u8],
    limits: Limits,
}

impl<'a> Iterator for Messages<'a> {
    type Item = Message<'a>;

    fn next(&mut self) -> Option<Message<'a>> {
        while self.left > 0 {
            self.left -= 1;
            // `Payload::parse` validated these bytes; a failure would end the iteration.
            let mut r = Reader::new(self.bytes);
            let ty = r.u8().ok()?;
            let len = r.varint().ok()? as usize;
            let body = r.take(len).ok()?;
            self.bytes = r.rest();
            if let Ok(Some(msg)) = Message::decode(ty, body, &self.limits) {
                return Some(msg);
            }
        }
        None
    }
}

/// Appends a payload for `msgs` to `out`.
pub(crate) fn put_payload<S: Sink>(s: &mut S, msgs: &[Message<'_>]) {
    s.put_varint(msgs.len() as u32);
    for m in msgs {
        m.put(s);
    }
}
