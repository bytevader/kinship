//! Message types and the inner payload (`count:varint message*`).

use core::fmt;
use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use crate::error::{DecodeError, EncodeError};
use crate::limits::Limits;
use crate::wire::{Count, Reader, Sink, varint_len};

/// Wire type bytes. Identity messages require the explicitly selected v2 grammar.
pub mod kind {
    pub const PING: u8 = 0x01;
    pub const PING_REQ: u8 = 0x02;
    pub const ACK: u8 = 0x03;
    pub const NACK: u8 = 0x04;
    pub const ALIVE: u8 = 0x05;
    pub const SUSPECT: u8 = 0x06;
    pub const DEAD: u8 = 0x07;
    pub const PUSH_PULL: u8 = 0x08;
    /// From 0.4; nodes older than that skip it as a type they do not know.
    pub const USER_MESSAGE: u8 = 0x09;
    /// From 0.4; nodes older than that skip it as a type they do not know.
    pub const USER_BROADCAST: u8 = 0x0A;
    pub const CERTIFICATE: u8 = 0x0B;
    pub const REVOCATION: u8 = 0x0C;
    /// From 0.5, TCP only, and only to a member whose Alive advertises
    /// [`feature::DIGEST_PUSH_PULL`](super::feature::DIGEST_PUSH_PULL).
    pub const PUSH_PULL_DIGEST: u8 = 0x0D;
    /// From 0.5, TCP only: the reply to a [`PUSH_PULL_DIGEST`], after a [`PUSH_PULL`].
    pub const PUSH_PULL_WANTS: u8 = 0x0E;
}

/// Capability bits a node advertises in [`Alive::features`].
pub mod feature {
    /// The node answers a [`PushPullDigest`](super::PushPullDigest), so it may be sent one in
    /// place of a full push-pull.
    pub const DIGEST_PUSH_PULL: u32 = 1;
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
    pub(crate) fn from_wire(b: u8) -> Result<Self, DecodeError> {
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

/// `Alive`: `node` is alive at incarnation `inc` of its life `epoch`, reachable at `addr`,
/// speaking wire versions `vmin` to `vmax`, carrying `meta`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Alive<'a> {
    pub inc: u32,
    pub node: NodeId<'a>,
    pub addr: SocketAddr,
    pub meta: &'a [u8],
    pub vmin: u8,
    pub vmax: u8,
    /// When this life of the node started, in milliseconds of its wall clock, raised past
    /// any earlier life the node hears of. Appended in 0.3: 0 is not sent, and a message
    /// without it, from an older node, reads as 0.
    pub epoch: u64,
    /// The capabilities the node advertises, bits of [`feature`]. Appended in 0.5 after the
    /// epoch, which is then written even when 0: 0 is not sent, and a message without it reads
    /// as 0. Version 2 Alives do not carry it.
    pub features: u32,
}

/// `Suspect`: `from` suspects `node` at incarnation `inc` of its life `epoch`.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Suspect<'a> {
    pub inc: u32,
    pub node: NodeId<'a>,
    pub from: NodeId<'a>,
    /// The life of `node` that is suspected, 0 when unknown; appended as in [`Alive`].
    pub epoch: u64,
}

/// `Dead`: `from` declares `node` dead at incarnation `inc` of its life `epoch`. `from ==
/// node` means the node left.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Dead<'a> {
    pub inc: u32,
    pub node: NodeId<'a>,
    pub from: NodeId<'a>,
    /// The life of `node` that died or left, 0 when unknown; appended as in [`Alive`].
    pub epoch: u64,
}

impl Dead<'_> {
    /// True when the node announced its own departure.
    pub fn is_left(&self) -> bool {
        self.node == self.from
    }
}

/// `UserMessage`: application data from the life `from_epoch` of `from` to the life `to_epoch`
/// of `to`. Added in 0.4 with every field, epochs of 0 included.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserMessage<'a> {
    pub to: NodeId<'a>,
    /// The life of `to` the message is for; 0 when the sender knows none.
    pub to_epoch: u64,
    pub from: NodeId<'a>,
    /// The life of `from` that sent it; 0 for a sender without an epoch.
    pub from_epoch: u64,
    /// Opaque to the protocol, bounded only by the packet; the core checks its own limit.
    pub data: &'a [u8],
}

/// `UserBroadcast`: application data for every member, broadcast number `seq` of the life
/// `from_epoch` of `from`. Added in 0.4 with every field, as [`UserMessage`].
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct UserBroadcast<'a> {
    pub from: NodeId<'a>,
    pub from_epoch: u64,
    /// One higher for each broadcast of that life; with `from` and `from_epoch`, it tells a
    /// copy from a new broadcast.
    pub seq: u64,
    pub data: &'a [u8],
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

/// One member in a [`PushPullDigest`]: the state, incarnation and life a node holds it at,
/// without the rest of its record.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct DigestEntry<'a> {
    pub state: State,
    pub inc: u32,
    pub node: NodeId<'a>,
    /// Written even when 0, which means unknown, as in [`Alive::epoch`].
    pub epoch: u64,
}

/// The entries of a [`PushPullDigest`], from a slice or from the frame, as [`Records`].
#[derive(Clone, Copy)]
pub enum DigestEntries<'a> {
    /// Entries to encode.
    Slice(&'a [DigestEntry<'a>]),
    /// Entries validated by the decoder and still in wire form.
    Wire { count: u32, bytes: &'a [u8] },
}

impl<'a> DigestEntries<'a> {
    /// Number of entries.
    pub fn len(&self) -> usize {
        match self {
            Self::Slice(s) => s.len(),
            Self::Wire { count, .. } => *count as usize,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn iter(&self) -> DigestIter<'a> {
        match *self {
            Self::Slice(s) => DigestIter::Slice(s.iter()),
            Self::Wire { count, bytes } => DigestIter::Wire { left: count, bytes },
        }
    }
}

impl PartialEq for DigestEntries<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.iter().eq(other.iter())
    }
}

impl Eq for DigestEntries<'_> {}

impl fmt::Debug for DigestEntries<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

/// Iterator over [`DigestEntries`].
pub enum DigestIter<'a> {
    Slice(core::slice::Iter<'a, DigestEntry<'a>>),
    Wire { left: u32, bytes: &'a [u8] },
}

impl<'a> Iterator for DigestIter<'a> {
    type Item = DigestEntry<'a>;

    fn next(&mut self) -> Option<DigestEntry<'a>> {
        match self {
            Self::Slice(it) => it.next().copied(),
            Self::Wire { left, bytes } => {
                if *left == 0 {
                    return None;
                }
                *left -= 1;
                // The decoder walked these bytes once already, as for records.
                let mut r = Reader::new(bytes);
                let entry = read_digest_entry(r.bytes().ok()?).ok()?;
                *bytes = r.rest();
                Some(entry)
            }
        }
    }
}

/// `PushPullDigest`: the first frame of a digest exchange, TCP only. The sender lists every
/// member it holds, itself and tombstones included; the peer answers with a [`PushPull`] of the
/// records it holds later and a [`PushPullWants`] of the names whose records it wants.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PushPullDigest<'a> {
    pub join: bool,
    pub entries: DigestEntries<'a>,
}

/// A list of names, from a slice or from the frame, as [`Records`].
#[derive(Clone, Copy)]
pub enum Names<'a> {
    /// Names to encode.
    Slice(&'a [NodeId<'a>]),
    /// Names validated by the decoder and still in wire form.
    Wire { count: u32, bytes: &'a [u8] },
}

impl<'a> Names<'a> {
    /// Number of names.
    pub fn len(&self) -> usize {
        match self {
            Self::Slice(s) => s.len(),
            Self::Wire { count, .. } => *count as usize,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    pub fn iter(&self) -> NameIter<'a> {
        match *self {
            Self::Slice(s) => NameIter::Slice(s.iter()),
            Self::Wire { count, bytes } => NameIter::Wire { left: count, bytes },
        }
    }
}

impl PartialEq for Names<'_> {
    fn eq(&self, other: &Self) -> bool {
        self.len() == other.len() && self.iter().eq(other.iter())
    }
}

impl Eq for Names<'_> {}

impl fmt::Debug for Names<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_list().entries(self.iter()).finish()
    }
}

/// Iterator over [`Names`].
pub enum NameIter<'a> {
    Slice(core::slice::Iter<'a, NodeId<'a>>),
    Wire { left: u32, bytes: &'a [u8] },
}

impl<'a> Iterator for NameIter<'a> {
    type Item = NodeId<'a>;

    fn next(&mut self) -> Option<NodeId<'a>> {
        match self {
            Self::Slice(it) => it.next().copied(),
            Self::Wire { left, bytes } => {
                if *left == 0 {
                    return None;
                }
                *left -= 1;
                let mut r = Reader::new(bytes);
                let node = read_node(&mut r).ok()?;
                *bytes = r.rest();
                Some(node)
            }
        }
    }
}

/// `PushPullWants`: the names whose whole records the sender of a digest is to send back,
/// TCP only, after the [`PushPull`] that answers the digest.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct PushPullWants<'a> {
    pub names: Names<'a>,
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
    UserMessage(UserMessage<'a>),
    UserBroadcast(UserBroadcast<'a>),
    PushPullDigest(PushPullDigest<'a>),
    PushPullWants(PushPullWants<'a>),
}

pub(crate) fn put_addr<S: Sink>(s: &mut S, addr: &SocketAddr) {
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

pub(crate) fn read_addr(r: &mut Reader<'_>) -> Result<SocketAddr, DecodeError> {
    let ip = match r.u8()? {
        4 => IpAddr::V4(Ipv4Addr::from(r.array::<4>()?)),
        6 => IpAddr::V6(Ipv6Addr::from(r.array::<16>()?)),
        _ => return Err(DecodeError::BadAddr),
    };
    Ok(SocketAddr::new(ip, r.u16()?))
}

pub(crate) fn put_node<S: Sink>(s: &mut S, id: &NodeId<'_>) {
    s.put_bytes(id.as_str().as_bytes());
}

pub(crate) fn read_node<'a>(r: &mut Reader<'a>) -> Result<NodeId<'a>, DecodeError> {
    let bytes = r.bytes()?;
    let s = core::str::from_utf8(bytes).map_err(|_| DecodeError::BadNodeId)?;
    NodeId::new(s)
}

pub(crate) fn read_bool(r: &mut Reader<'_>) -> Result<bool, DecodeError> {
    match r.u8()? {
        0 => Ok(false),
        1 => Ok(true),
        _ => Err(DecodeError::BadBool),
    }
}

/// Appends an epoch after a message's version 1 fields. Epoch 0, which a node that does not
/// send one has, is not written, so such a node's messages are the bytes they always were.
fn put_epoch<S: Sink>(s: &mut S, epoch: u64) {
    if epoch != 0 {
        s.put_u64(epoch);
    }
}

/// Appends an Alive's features after its epoch. Features 0 are not written, so a node that
/// advertises none sends the bytes 0.4 did; any others need the epoch ahead of them, written
/// even when it is 0, which no node that sets features has.
fn put_epoch_and_features<S: Sink>(s: &mut S, epoch: u64, features: u32) {
    if features == 0 {
        return put_epoch(s, epoch);
    }
    s.put_u64(epoch);
    s.put_varint(features);
}

/// Reads the epoch appended after a message's version 1 fields: 0 when the body ends there, as
/// from a node older than 0.3. A body that ends part way into it is truncated. Bytes after it
/// are fields appended by a newer version.
fn read_epoch(r: &mut Reader<'_>) -> Result<u64, DecodeError> {
    if r.is_empty() { Ok(0) } else { r.u64() }
}

/// Writes a version 1 Alive: its fields, then the epoch and features appended since.
pub(crate) fn put_alive<S: Sink>(s: &mut S, a: &Alive<'_>) {
    put_alive_fields(s, a);
    put_epoch_and_features(s, a.epoch, a.features);
}

/// Writes an Alive's fields up to the version range, after which version 2 writes its own.
pub(crate) fn put_alive_fields<S: Sink>(s: &mut S, a: &Alive<'_>) {
    s.put_u32(a.inc);
    put_node(s, &a.node);
    put_addr(s, &a.addr);
    s.put_bytes(a.meta);
    s.put_u8(a.vmin);
    s.put_u8(a.vmax);
}

/// Reads a version 1 Alive: [`read_alive_fields`], then the features appended after the
/// epoch, 0 when the body ends before them. Bytes after them are fields a newer version
/// appended.
pub(crate) fn read_alive<'a>(
    r: &mut Reader<'a>,
    limits: &Limits,
) -> Result<Alive<'a>, DecodeError> {
    let mut alive = read_alive_fields(r, limits)?;
    if !r.is_empty() {
        alive.features = r.varint()?;
    }
    Ok(alive)
}

/// Reads an Alive's fields and the epoch after them, with features 0: all that a version 2
/// Alive holds ahead of its certificate id.
pub(crate) fn read_alive_fields<'a>(
    r: &mut Reader<'a>,
    limits: &Limits,
) -> Result<Alive<'a>, DecodeError> {
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
    let epoch = read_epoch(r)?;
    Ok(Alive {
        inc,
        node,
        addr,
        meta,
        vmin,
        vmax,
        epoch,
        features: 0,
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

fn put_digest_entry<S: Sink>(s: &mut S, e: &DigestEntry<'_>) {
    let mut c = Count::default();
    put_digest_body(&mut c, e);
    s.put_varint(c.0 as u32);
    put_digest_body(s, e);
}

fn put_digest_body<S: Sink>(s: &mut S, e: &DigestEntry<'_>) {
    s.put_u8(e.state as u8);
    s.put_u32(e.inc);
    put_node(s, &e.node);
    s.put_u64(e.epoch);
}

fn read_digest_entry(body: &[u8]) -> Result<DigestEntry<'_>, DecodeError> {
    let mut r = Reader::new(body);
    // Bytes after the known fields are fields a newer version appended, as in a record.
    Ok(DigestEntry {
        state: State::from_wire(r.u8()?)?,
        inc: r.u32()?,
        node: read_node(&mut r)?,
        epoch: r.u64()?,
    })
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
            Self::UserMessage(_) => kind::USER_MESSAGE,
            Self::UserBroadcast(_) => kind::USER_BROADCAST,
            Self::PushPullDigest(_) => kind::PUSH_PULL_DIGEST,
            Self::PushPullWants(_) => kind::PUSH_PULL_WANTS,
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

    pub(crate) fn put_body<S: Sink>(&self, s: &mut S) {
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
                put_epoch(s, m.epoch);
            }
            Self::Dead(m) => {
                s.put_u32(m.inc);
                put_node(s, &m.node);
                put_node(s, &m.from);
                put_epoch(s, m.epoch);
            }
            Self::PushPull(p) => {
                s.put_u8(u8::from(p.join));
                s.put_varint(p.records.len() as u32);
                for rec in p.records.iter() {
                    put_record(s, &rec);
                }
            }
            Self::UserMessage(m) => {
                put_node(s, &m.to);
                s.put_u64(m.to_epoch);
                put_node(s, &m.from);
                s.put_u64(m.from_epoch);
                s.put_bytes(m.data);
            }
            Self::UserBroadcast(b) => {
                put_node(s, &b.from);
                s.put_u64(b.from_epoch);
                s.put_u64(b.seq);
                s.put_bytes(b.data);
            }
            Self::PushPullDigest(d) => {
                s.put_u8(u8::from(d.join));
                s.put_varint(d.entries.len() as u32);
                for e in d.entries.iter() {
                    put_digest_entry(s, &e);
                }
            }
            Self::PushPullWants(w) => {
                s.put_varint(w.names.len() as u32);
                for n in w.names.iter() {
                    put_node(s, &n);
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
                epoch: read_epoch(&mut r)?,
            }),
            kind::DEAD => Self::Dead(Dead {
                inc: r.u32()?,
                node: read_node(&mut r)?,
                from: read_node(&mut r)?,
                epoch: read_epoch(&mut r)?,
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
            kind::USER_MESSAGE => Self::UserMessage(UserMessage {
                to: read_node(&mut r)?,
                to_epoch: r.u64()?,
                from: read_node(&mut r)?,
                from_epoch: r.u64()?,
                data: r.bytes()?,
            }),
            kind::USER_BROADCAST => Self::UserBroadcast(UserBroadcast {
                from: read_node(&mut r)?,
                from_epoch: r.u64()?,
                seq: r.u64()?,
                data: r.bytes()?,
            }),
            kind::PUSH_PULL_DIGEST => {
                let join = read_bool(&mut r)?;
                let count = r.varint()?;
                let bytes = r.rest();
                // Walked once here, as records are; each entry costs at least a byte.
                if count as usize > bytes.len() {
                    return Err(DecodeError::BadLength);
                }
                let mut walk = Reader::new(bytes);
                for _ in 0..count {
                    read_digest_entry(walk.bytes()?)?;
                }
                Self::PushPullDigest(PushPullDigest {
                    join,
                    entries: DigestEntries::Wire { count, bytes },
                })
            }
            kind::PUSH_PULL_WANTS => {
                let count = r.varint()?;
                let bytes = r.rest();
                // A name is at least its length and one byte.
                if (count as usize).saturating_mul(2) > bytes.len() {
                    return Err(DecodeError::BadLength);
                }
                let mut walk = Reader::new(bytes);
                for _ in 0..count {
                    read_node(&mut walk)?;
                }
                Self::PushPullWants(PushPullWants {
                    names: Names::Wire { count, bytes },
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
