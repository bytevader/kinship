//! The transmit-limited gossip queue, and packing it into outgoing datagrams.

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;

use kinship_proto::identity::{Certificate, CertificateId, Signature};
use kinship_proto::v2;
use kinship_proto::{Alive, Codec, Dead, Message, NodeId, PacketKind, Suspect, WireVersion};

use crate::Node;
use crate::io::{StreamId, Transmit};
use crate::member::State;
use crate::replay::STAMP_LEN;
use crate::rng::Nonces;
use crate::signing::{AccusationProof, AliveProof, signed_alive, signed_dead, signed_suspect};
use crate::suspicion::retransmit_limit;
use crate::table::Entry;
use crate::time::Instant;
use crate::user::UserQueue;

/// An Alive, Suspect or Dead rumour waiting to be spread, owned so it can outlive the packet
/// it arrived in. In mode `sign` it keeps its author's signature, and an Alive new to the node
/// spreading it keeps its certificate, to go ahead of it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Gossip {
    Alive {
        inc: u32,
        node: String,
        addr: SocketAddr,
        meta: Vec<u8>,
        vmin: u8,
        vmax: u8,
        epoch: u64,
        sig: Option<(CertificateId, Signature)>,
        cert: Option<Vec<u8>>,
    },
    Suspect {
        inc: u32,
        node: String,
        from: String,
        epoch: u64,
        proof: Option<AccusationProof>,
    },
    Dead {
        inc: u32,
        node: String,
        from: String,
        epoch: u64,
        proof: Option<AccusationProof>,
    },
}

/// Names held by the core were validated when they arrived, so this cannot fail.
pub(crate) fn id(name: &str) -> NodeId<'_> {
    NodeId::new(name).unwrap_or_else(|_| unreachable!("invalid name {name:?} in the core"))
}

impl Gossip {
    pub fn from_alive(a: &Alive<'_>) -> Self {
        Self::Alive {
            inc: a.inc,
            node: a.node.as_str().to_owned(),
            addr: a.addr,
            meta: a.meta.to_vec(),
            vmin: a.vmin,
            vmax: a.vmax,
            epoch: a.epoch,
            sig: None,
            cert: None,
        }
    }

    /// A signed Alive, with the certificate to go ahead of it if `cert`.
    pub fn signed_alive(
        a: &Alive<'_>,
        cert_id: CertificateId,
        sig: Signature,
        cert: Option<Vec<u8>>,
    ) -> Self {
        let mut g = Self::from_alive(a);
        if let Self::Alive {
            sig: s, cert: c, ..
        } = &mut g
        {
            *s = Some((cert_id, sig));
            *c = cert;
        }
        g
    }

    pub fn suspect(s: &Suspect<'_>, proof: Option<AccusationProof>) -> Self {
        Self::Suspect {
            inc: s.inc,
            node: s.node.as_str().to_owned(),
            from: s.from.as_str().to_owned(),
            epoch: s.epoch,
            proof,
        }
    }

    pub fn dead(d: &Dead<'_>, proof: Option<AccusationProof>) -> Self {
        Self::Dead {
            inc: d.inc,
            node: d.node.as_str().to_owned(),
            from: d.from.as_str().to_owned(),
            epoch: d.epoch,
            proof,
        }
    }

    /// The member this rumour is about.
    pub fn node(&self) -> &str {
        match self {
            Self::Alive { node, .. } | Self::Suspect { node, .. } | Self::Dead { node, .. } => node,
        }
    }

    /// The rumour in the version 1 grammar, without a signature.
    pub fn message(&self) -> Message<'_> {
        match self {
            Self::Alive {
                inc,
                node,
                addr,
                meta,
                vmin,
                vmax,
                epoch,
                ..
            } => Message::Alive(Alive {
                inc: *inc,
                node: id(node),
                addr: *addr,
                meta,
                vmin: *vmin,
                vmax: *vmax,
                epoch: *epoch,
            }),
            Self::Suspect {
                inc,
                node,
                from,
                epoch,
                ..
            } => Message::Suspect(Suspect {
                inc: *inc,
                node: id(node),
                from: id(from),
                epoch: *epoch,
            }),
            Self::Dead {
                inc,
                node,
                from,
                epoch,
                ..
            } => Message::Dead(Dead {
                inc: *inc,
                node: id(node),
                from: id(from),
                epoch: *epoch,
            }),
        }
    }

    /// The rumour in the version 2 grammar, behind its certificate if it carries one; `None`
    /// if it is unsigned.
    pub fn signed(&self) -> Option<(Option<Certificate<'_>>, v2::Message<'_>)> {
        match (self, self.message()) {
            (
                Self::Alive {
                    inc,
                    sig: Some((cert_id, sig)),
                    cert,
                    ..
                },
                Message::Alive(a),
            ) => {
                let proof = AliveProof {
                    inc: *inc,
                    cert: *cert_id,
                    sig: *sig,
                };
                let cert = cert.as_deref().and_then(|c| Certificate::decode(c).ok());
                Some((cert, signed_alive(&a, &proof)))
            }
            (
                Self::Suspect {
                    proof: Some(proof), ..
                },
                Message::Suspect(s),
            ) => Some((None, signed_suspect(&s, proof))),
            (
                Self::Dead {
                    proof: Some(proof), ..
                },
                Message::Dead(d),
            ) => Some((None, signed_dead(&d, proof))),
            _ => None,
        }
    }

    /// Sheds the certificate, and then the signature, while the version 2 form does not fit
    /// `room` bytes.
    fn fit(&mut self, room: usize) {
        if self.signed_len().is_some_and(|len| len > room) {
            if let Self::Alive { cert, .. } = self {
                *cert = None;
            }
        }
        if self.signed_len().is_some_and(|len| len > room) {
            match self {
                Self::Alive { sig, .. } => *sig = None,
                Self::Suspect { proof, .. } | Self::Dead { proof, .. } => *proof = None,
            }
        }
    }

    /// Bytes the version 2 form takes in a payload, its certificate included.
    fn signed_len(&self) -> Option<usize> {
        let (cert, msg) = self.signed()?;
        let cert = cert.map_or(0, |c| v2::Message::Certificate(c).encoded_len());
        Some(cert + msg.encoded_len())
    }
}

#[derive(Debug)]
struct Queued {
    gossip: Gossip,
    /// Encoded size inside a payload.
    len: usize,
    /// Encoded size of its version 2 form, certificate included, when it is signed.
    signed_len: Option<usize>,
    /// Only sends to live members count towards the limit.
    live_only: bool,
}

/// Where an entry stands in the queue: least sent first, and among those the newest first.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Rank {
    transmits: u32,
    /// Insertion order, reversed so that newer entries sort first among equals.
    id: core::cmp::Reverse<u64>,
}

/// Rumours still to be spread, at most one per member.
///
/// Each entry rides on outgoing packets until it has been sent `limit` times. Packets take the
/// least-sent entries first, and the newest among those, so fresh news overtakes old.
///
/// Entries are kept in that order and indexed by member, so a rumour replaces its member's
/// previous one, and a send counts, in O(log n): a bulk merge of n new members costs
/// O(n log n), not the O(n²) of scanning the queue for each (KI-04).
#[derive(Debug, Default)]
pub(crate) struct Broadcasts {
    queue: BTreeMap<Rank, Queued>,
    by_node: BTreeMap<String, Rank>,
    next_id: u64,
}

impl Broadcasts {
    /// Queues `gossip`, replacing anything queued about the same member.
    pub fn push(&mut self, gossip: Gossip) {
        self.push_with(gossip, false);
    }

    /// Queues `gossip` like [`push`](Self::push), but only sends to members this node holds
    /// live count towards its limit, so it is not done while it has only reached the dead.
    pub fn push_to_live(&mut self, gossip: Gossip) {
        self.push_with(gossip, true);
    }

    fn push_with(&mut self, gossip: Gossip, live_only: bool) {
        let rank = Rank {
            transmits: 0,
            id: core::cmp::Reverse(self.next_id),
        };
        self.next_id += 1;
        if let Some(old) = self.by_node.insert(gossip.node().to_owned(), rank) {
            self.queue.remove(&old);
        }
        let signed_len = gossip.signed_len();
        let len = gossip.message().encoded_len();
        self.queue.insert(
            rank,
            Queued {
                gossip,
                len,
                signed_len,
                live_only,
            },
        );
    }

    /// Drops anything queued about `node`.
    pub fn forget(&mut self, node: &str) {
        if let Some(rank) = self.by_node.remove(node) {
            self.queue.remove(&rank);
        }
    }

    /// Gives the queued rumour of `a`, if it is that unsigned Alive, its signature, and the
    /// certificate to go ahead of it if `cert`. It keeps its place and its count of sends.
    pub fn attach(
        &mut self,
        a: &Alive<'_>,
        cert_id: CertificateId,
        sig: Signature,
        cert: Option<Vec<u8>>,
    ) {
        let Some(rank) = self.by_node.get(a.node.as_str()) else {
            return;
        };
        let Some(q) = self.queue.get_mut(rank) else {
            return;
        };
        if q.gossip.message() != Message::Alive(*a) || q.gossip.signed().is_some() {
            return;
        }
        q.gossip = Gossip::signed_alive(a, cert_id, sig, cert);
        q.signed_len = q.gossip.signed_len();
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Whether a rumour about `node` is still being spread.
    pub fn contains(&self, node: &str) -> bool {
        self.by_node.contains_key(node)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// The rumour queued at `rank`, which [`select`](Self::select) returned.
    fn gossip(&self, rank: Rank) -> &Gossip {
        &self.queue[&rank].gossip
    }

    /// Bytes the rumour queued at `rank` takes in a payload.
    fn len_of(&self, rank: Rank) -> usize {
        self.queue[&rank].len
    }

    /// Bytes the version 2 form of the rumour queued at `rank` takes, its certificate included.
    fn signed_len_of(&self, rank: Rank) -> usize {
        self.queue[&rank].signed_len.unwrap_or(0)
    }

    /// Entries that fit in `budget` bytes, best first: in queue order, skipping any that do
    /// not fit what is left so that smaller ones behind it still can. Stops once what is left
    /// is too small for any rumour, so a long queue costs only what a packet takes from it.
    fn select(&self, budget: usize) -> Vec<Rank> {
        let smallest = smallest_rumour();
        let mut left = budget;
        let mut picked = Vec::new();
        for (&rank, q) in &self.queue {
            if left < smallest {
                break;
            }
            if q.len <= left {
                left -= q.len;
                picked.push(rank);
            }
        }
        picked
    }

    /// Like [`select`](Self::select) for a member that speaks version 2, which gets two
    /// packets: signed entries in their version 2 form fill `signed` bytes, the unsigned ones
    /// `unsigned` bytes. Returns the entries for each.
    fn select_split(&self, unsigned: usize, signed: usize) -> (Vec<Rank>, Vec<Rank>) {
        let smallest = smallest_rumour();
        let (mut left_v1, mut left_v2) = (unsigned, signed);
        let (mut v1, mut v2) = (Vec::new(), Vec::new());
        for (&rank, q) in &self.queue {
            if left_v1 < smallest && left_v2 < smallest {
                break;
            }
            match q.signed_len {
                Some(len) if len <= left_v2 => {
                    left_v2 -= len;
                    v2.push(rank);
                }
                Some(_) => {}
                None if q.len <= left_v1 => {
                    left_v1 -= q.len;
                    v1.push(rank);
                }
                None => {}
            }
        }
        (v1, v2)
    }

    /// Counts one more send of each entry in `sent`, to a live member if `live`, then drops
    /// every entry that has reached `limit`, including ones not in `sent`, which the limit
    /// can catch when it falls with the cluster's size.
    fn sent(&mut self, sent: &[Rank], limit: u32, live: bool) {
        for &rank in sent {
            let Some(q) = self.queue.get(&rank) else {
                continue;
            };
            if !live && q.live_only {
                continue;
            }
            let q = self.queue.remove(&rank).expect("looked up above");
            let next = Rank {
                transmits: rank.transmits + 1,
                ..rank
            };
            if let Some(r) = self.by_node.get_mut(q.gossip.node()) {
                *r = next;
            }
            self.queue.insert(next, q);
        }
        // The most sent entries sort last.
        while let Some(entry) = self.queue.last_entry() {
            if entry.key().transmits < limit {
                break;
            }
            let q = entry.remove();
            self.by_node.remove(q.gossip.node());
        }
    }
}

/// Bytes the smallest rumour takes in a payload: a Suspect with one-byte names.
fn smallest_rumour() -> usize {
    Message::Suspect(Suspect {
        inc: 0,
        node: id("n"),
        from: id("n"),
        epoch: 0,
    })
    .encoded_len()
}

/// Bytes a payload's message count can take: counts stay below 2^14 in any packet.
pub(crate) const COUNT_LEN: usize = 2;

/// Bytes a datagram sealed by `codec` has for its messages, past their count.
pub(crate) fn datagram_room(codec: &Codec) -> usize {
    codec
        .max_payload_len(PacketKind::Datagram)
        .saturating_sub(COUNT_LEN)
}

/// Seals packets, piggybacking queued gossip, and holds them until the driver polls.
pub(crate) struct Outbox {
    pub codec: Codec,
    pub broadcasts: Broadcasts,
    /// User broadcasts, which take the room membership rumours leave.
    pub user: UserQueue,
    pub transmits: VecDeque<Transmit>,
    /// The random bytes of nonces, apart from the protocol's RNG, which they must not give away
    /// and whose choices sealing must not shift.
    nonces: Nonces,
    /// Cluster time in milliseconds, which leads every nonce; the node keeps it current.
    pub stamp: u64,
}

impl Outbox {
    pub fn new(codec: Codec, nonces: Nonces) -> Self {
        Self {
            codec,
            broadcasts: Broadcasts::default(),
            user: UserQueue::default(),
            transmits: VecDeque::new(),
            nonces,
            stamp: 0,
        }
    }

    /// A fresh nonce: the cluster time, then random bytes. All zero in plaintext mode, which
    /// sends no nonce.
    pub fn nonce(&mut self) -> [u8; kinship_proto::NONCE_LEN] {
        let mut nonce = [0; kinship_proto::NONCE_LEN];
        if self.codec.is_encrypted() {
            nonce[..STAMP_LEN].copy_from_slice(&self.stamp.to_be_bytes());
            self.nonces.fill(&mut nonce[STAMP_LEN..]);
        }
        nonce
    }

    /// Sends `head` to `to` in one datagram, filling the space left with queued gossip that
    /// has been sent fewer than `limit` times (none if `limit` is `None`): membership rumours
    /// first, then, to a member held live, user broadcasts in the room they leave. `live` says
    /// whether `to` is a member this node holds live, Alive or Suspect. Sends nothing if there
    /// is nothing to send. Returns whether a datagram was queued.
    ///
    /// To a member that speaks `version` 2 the signed rumours go in a second, version 2
    /// datagram; see [`send_split`](Self::send_split).
    pub fn send(
        &mut self,
        to: SocketAddr,
        live: bool,
        version: WireVersion,
        head: &[Message<'_>],
        limit: Option<u32>,
    ) -> bool {
        if version == WireVersion::V2 {
            return self.send_split(to, live, head, &[], limit);
        }
        let max = datagram_room(&self.codec);
        let used: usize = head.iter().map(Message::encoded_len).sum();
        let picked = match limit {
            Some(_) => self.broadcasts.select(max.saturating_sub(used)),
            None => Vec::new(),
        };
        // Membership always wins: user broadcasts only take what the rumours leave.
        let users = match limit {
            Some(_) if live && !self.user.is_empty() => {
                let rumours: usize = picked.iter().map(|&r| self.broadcasts.len_of(r)).sum();
                self.user.select(max.saturating_sub(used + rumours))
            }
            _ => Vec::new(),
        };
        if head.is_empty() && picked.is_empty() && users.is_empty() {
            return false;
        }
        let nonce = self.nonce();
        let mut msgs = Vec::with_capacity(head.len() + picked.len() + users.len());
        msgs.extend_from_slice(head);
        msgs.extend(
            picked
                .iter()
                .map(|&rank| self.broadcasts.gossip(rank).message()),
        );
        msgs.extend(
            users
                .iter()
                .map(|&rank| self.user.broadcast(rank).message()),
        );
        let mut payload = Vec::new();
        // Only an oversized head can fail, and no head is near the limit.
        let sealed = self
            .codec
            .seal(PacketKind::Datagram, &msgs, &nonce, &mut payload)
            .is_ok();
        drop(msgs);
        if !sealed {
            return false;
        }
        if let Some(limit) = limit {
            self.broadcasts.sent(&picked, limit, live);
            if !users.is_empty() {
                self.user.sent(&users, limit);
            }
        }
        self.transmits.push_back(Transmit::Datagram { to, payload });
        true
    }

    /// Sends the version 2 `head` to `to`, a member that speaks version 2, filling the room left
    /// with queued gossip as [`send_split`](Self::send_split) does. Returns whether a datagram
    /// was queued.
    pub fn send_v2(
        &mut self,
        to: SocketAddr,
        live: bool,
        head: &[v2::Message<'_>],
        limit: Option<u32>,
    ) -> bool {
        self.send_split(to, live, &[], head, limit)
    }

    /// What [`send`](Self::send) sends to a member that speaks version 2, in up to two
    /// datagrams (`docs/ki01-stage2.md`, Packets once probes are version 2): a version 2 one
    /// with `head_v2`, the signed rumours, each new Alive behind its certificate, and the signed
    /// user broadcasts; and a version 1 one, as `off` would send it, with `head_v1`, the
    /// unsigned rumours and the unsigned user broadcasts, sent only when it holds any of them.
    /// Each fills the room of its own datagram, in queue order, membership first, and a rumour
    /// or broadcast counts one send.
    fn send_split(
        &mut self,
        to: SocketAddr,
        live: bool,
        head_v1: &[Message<'_>],
        head_v2: &[v2::Message<'_>],
        limit: Option<u32>,
    ) -> bool {
        let max = datagram_room(&self.codec);
        let used_v1: usize = head_v1.iter().map(Message::encoded_len).sum();
        let used_v2: usize = head_v2.iter().map(v2::Message::encoded_len).sum();
        let (room_v1, room_v2) = (max.saturating_sub(used_v1), max.saturating_sub(used_v2));
        let (unsigned, signed) = match limit {
            Some(_) => self.broadcasts.select_split(room_v1, room_v2),
            None => (Vec::new(), Vec::new()),
        };
        let (users_v1, users_v2) = match limit {
            Some(_) if live && !self.user.is_empty() => {
                let rumours_v1: usize = unsigned.iter().map(|&r| self.broadcasts.len_of(r)).sum();
                let rumours_v2: usize = signed
                    .iter()
                    .map(|&r| self.broadcasts.signed_len_of(r))
                    .sum();
                self.user.select_split(
                    room_v1.saturating_sub(rumours_v1),
                    room_v2.saturating_sub(rumours_v2),
                )
            }
            _ => (Vec::new(), Vec::new()),
        };
        let mut queued = false;
        if !head_v1.is_empty() || !unsigned.is_empty() || !users_v1.is_empty() {
            let nonce = self.nonce();
            let mut msgs = Vec::with_capacity(head_v1.len() + unsigned.len() + users_v1.len());
            msgs.extend_from_slice(head_v1);
            msgs.extend(
                unsigned
                    .iter()
                    .map(|&rank| self.broadcasts.gossip(rank).message()),
            );
            msgs.extend(
                users_v1
                    .iter()
                    .map(|&rank| self.user.broadcast(rank).message()),
            );
            let mut payload = Vec::new();
            if self
                .codec
                .seal(PacketKind::Datagram, &msgs, &nonce, &mut payload)
                .is_ok()
            {
                drop(msgs);
                self.transmits.push_back(Transmit::Datagram { to, payload });
                queued = true;
            }
        }
        if !head_v2.is_empty() || !signed.is_empty() || !users_v2.is_empty() {
            let nonce = self.nonce();
            let mut msgs = Vec::with_capacity(head_v2.len() + signed.len() * 2 + users_v2.len());
            msgs.extend_from_slice(head_v2);
            for &rank in &signed {
                if let Some((cert, msg)) = self.broadcasts.gossip(rank).signed() {
                    msgs.extend(cert.map(v2::Message::Certificate));
                    msgs.push(msg);
                }
            }
            for &rank in &users_v2 {
                if let Some((cert, msg)) = self.user.broadcast(rank).signed() {
                    msgs.extend(cert.map(v2::Message::Certificate));
                    msgs.push(msg);
                }
            }
            let mut payload = Vec::new();
            if self
                .codec
                .seal_v2(
                    WireVersion::V2,
                    PacketKind::Datagram,
                    &msgs,
                    &nonce,
                    &mut payload,
                )
                .is_ok()
            {
                drop(msgs);
                self.transmits.push_back(Transmit::Datagram { to, payload });
                queued = true;
            }
        }
        if let Some(limit) = limit {
            let mut sent = unsigned;
            sent.extend(signed);
            self.broadcasts.sent(&sent, limit, live);
            let mut users = users_v1;
            users.extend(users_v2);
            if !users.is_empty() {
                self.user.sent(&users, limit);
            }
        }
        queued
    }

    /// Writes `msgs` to `conn` as one length-prefixed stream frame. Returns false, sending
    /// nothing, if they do not fit in `max_stream_frame`.
    pub fn frame(&mut self, conn: StreamId, msgs: &[Message<'_>]) -> bool {
        let nonce = self.nonce();
        let mut frame = Vec::new();
        if self
            .codec
            .seal_stream_frame(msgs, &nonce, &mut frame)
            .is_err()
        {
            return false;
        }
        self.transmits.push_back(Transmit::Stream { conn, frame });
        true
    }

    /// Sends version 2 `msgs` to `to` alone in one version 2 datagram.
    pub fn send_signed(&mut self, to: SocketAddr, msgs: &[v2::Message<'_>]) {
        let nonce = self.nonce();
        self.send_signed_at(to, msgs, &nonce);
    }

    /// Sends version 2 `msgs` to `to` alone in one version 2 datagram sealed with `nonce`, which
    /// the caller drew from [`nonce`](Self::nonce) to sign a direct message over it. Returns
    /// whether it was queued.
    pub fn send_signed_at(
        &mut self,
        to: SocketAddr,
        msgs: &[v2::Message<'_>],
        nonce: &[u8; kinship_proto::NONCE_LEN],
    ) -> bool {
        let mut payload = Vec::new();
        let sealed = self.codec.seal_v2(
            WireVersion::V2,
            PacketKind::Datagram,
            msgs,
            nonce,
            &mut payload,
        );
        if sealed.is_ok() {
            self.transmits.push_back(Transmit::Datagram { to, payload });
        }
        sealed.is_ok()
    }

    /// Writes version 2 `msgs` to `conn` as one stream frame at version 2. Returns false,
    /// sending nothing, if they do not fit in `max_stream_frame`.
    pub fn frame_v2(&mut self, conn: StreamId, msgs: &[v2::Message<'_>]) -> bool {
        let nonce = self.nonce();
        self.frame_v2_at(conn, msgs, &nonce)
    }

    /// [`frame_v2`](Self::frame_v2) sealed with `nonce`, which the caller drew to sign the direct
    /// messages in it over.
    pub fn frame_v2_at(
        &mut self,
        conn: StreamId,
        msgs: &[v2::Message<'_>],
        nonce: &[u8; kinship_proto::NONCE_LEN],
    ) -> bool {
        let mut frame = Vec::new();
        if self
            .codec
            .seal_v2_stream_frame(WireVersion::V2, msgs, nonce, &mut frame)
            .is_err()
        {
            return false;
        }
        self.transmits.push_back(Transmit::Stream { conn, frame });
        true
    }
}

impl Node {
    /// Queues a rumour for piggybacking and gossip.
    pub(crate) fn broadcast(&mut self, gossip: Gossip) {
        self.queue_gossip(gossip, false);
    }

    /// Queues a rumour like [`broadcast`](Self::broadcast), counting only sends to members this
    /// node holds live towards its limit.
    pub(crate) fn broadcast_to_live(&mut self, gossip: Gossip) {
        self.queue_gossip(gossip, true);
    }

    /// A rumour too large for any datagram, even alone, could never be sent: it is dropped and
    /// counted, together with anything older queued about the same member, rather than kept
    /// forever. `Config::validate` refuses limits under which this node's own rumours or any it
    /// accepts could be that large.
    ///
    /// A signed rumour too large for a datagram, which validated limits also rule out, goes
    /// without its certificate, and failing that unsigned.
    fn queue_gossip(&mut self, mut gossip: Gossip, live_only: bool) {
        let room = datagram_room(&self.out.codec);
        gossip.fit(room);
        if gossip.message().encoded_len() > room {
            self.out.broadcasts.forget(gossip.node());
            self.metrics.gossip_too_large += 1;
        } else if live_only {
            self.out.broadcasts.push_to_live(gossip);
        } else {
            self.out.broadcasts.push(gossip);
        }
    }

    /// How many times each rumour is sent, for the current cluster size.
    pub(crate) fn retransmit_limit(&self) -> u32 {
        retransmit_limit(&self.cfg, self.cluster_size())
    }

    /// This node's own Alive rumour, signed in mode `sign`.
    pub(crate) fn local_alive(&self) -> Gossip {
        let me = &self.local;
        Gossip::Alive {
            inc: me.member.incarnation,
            node: me.member.name.clone(),
            addr: me.member.addr,
            meta: me.member.meta.clone(),
            vmin: me.vmin,
            vmax: me.vmax,
            epoch: me.member.epoch,
            sig: me.proof.map(|p| (p.cert, p.sig)),
            cert: None,
        }
    }

    /// This node's first Alive of a life, which in mode `sign` carries its certificate ahead of
    /// it (section 2, Distribution).
    pub(crate) fn local_alive_announced(&self) -> Gossip {
        let mut gossip = self.local_alive();
        if let Gossip::Alive { cert, .. } = &mut gossip {
            *cert = self.keys.as_ref().map(|k| k.own.bytes.clone());
        }
        gossip
    }

    /// Whether this node holds `name` as a live member, Alive or Suspect.
    pub(crate) fn holds_live(&self, name: &str) -> bool {
        self.table
            .get(name)
            .is_some_and(|e| e.member.state.is_live())
    }

    /// Sends queued rumours to `gossip_nodes` random members, those declared dead less than
    /// `gossip_to_the_dead` ago included, so a member wrongly declared dead hears about it and
    /// can refute. Members that left are not sent to: they have closed. User broadcasts go only
    /// to the live ones among them.
    pub(crate) fn gossip(&mut self, now: Instant) {
        if self.out.broadcasts.is_empty() && self.out.user.is_empty() {
            return;
        }
        let window = self.cfg.gossip_to_the_dead;
        let targets: Vec<(SocketAddr, bool, String)> = self
            .table
            .random(self.cfg.gossip_nodes, &mut self.rng, |e| {
                match e.member.state {
                    State::Alive | State::Suspect => true,
                    State::Dead => now - e.since < window,
                    State::Left => false,
                }
            })
            .into_iter()
            .map(|e| {
                (
                    e.member.addr,
                    e.member.state.is_live(),
                    e.member.name.clone(),
                )
            })
            .collect();
        let limit = self.retransmit_limit();
        for (to, live, name) in targets {
            // With nothing left to send, the rest get nothing either; a member that is not live
            // gets no user broadcasts, which the next one may.
            let empty = self.out.broadcasts.is_empty() && self.out.user.is_empty();
            if !self.send_to(to, live, Some(&name), &[], Some(limit)) && empty {
                break;
            }
        }
    }

    /// Whether this node may send a datagram to `to`. Always with encryption, where only members
    /// can make it send. In plaintext mode, where anyone can forge the addresses inside messages,
    /// only to the address of a member it knows, tombstones included, or one that an Alive in
    /// the packet it is handling announces, so that a forged packet cannot make it send to an
    /// address of the forger's choosing.
    pub(crate) fn may_send(&self, to: SocketAddr) -> bool {
        self.out.codec.is_encrypted() || self.table.has_addr(to) || self.announced.contains(&to)
    }

    /// Sends `head` to `to` in one datagram with queued gossip, as [`Outbox::send`] does, if
    /// this node [may send](Self::may_send) to `to`. `peer` names the member at `to`, when the
    /// caller knows it, for the version it speaks. Returns whether a datagram was queued.
    pub(crate) fn send_to(
        &mut self,
        to: SocketAddr,
        live: bool,
        peer: Option<&str>,
        head: &[Message<'_>],
        limit: Option<u32>,
    ) -> bool {
        let version = self.version_for(peer, to);
        self.may_send(to) && self.out.send(to, live, version, head, limit)
    }

    /// Sends the version 2 `head` to `to`, a member that speaks version 2: the sender of a
    /// version 2 probe message, or a target or relay of a version 2 round. Queued gossip fills
    /// the room as [`Outbox::send_v2`] does. Returns whether a datagram was queued.
    pub(crate) fn send_to_v2(
        &mut self,
        to: SocketAddr,
        live: bool,
        head: &[v2::Message<'_>],
        limit: Option<u32>,
    ) -> bool {
        self.may_send(to) && self.out.send_v2(to, live, head, limit)
    }

    /// The highest wire version this node and the member `peer` at `to` both speak: version 2
    /// in mode `sign` with a member whose Alive advertises it, and version 1 otherwise, which is
    /// also the version for an address this node holds no member at.
    pub(crate) fn version_for(&self, peer: Option<&str>, to: SocketAddr) -> WireVersion {
        let two = WireVersion::V2 as u8;
        let speaks = |e: &Entry| e.member.addr == to && e.vmin <= two && two <= e.vmax;
        if self.keys.is_some() && peer.and_then(|p| self.table.get(p)).is_some_and(speaks) {
            WireVersion::V2
        } else {
            WireVersion::V1
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kinship_proto::Limits;

    fn suspect(node: &str, inc: u32) -> Gossip {
        Gossip::Suspect {
            inc,
            node: node.to_owned(),
            from: "x".to_owned(),
            epoch: 0,
            proof: None,
        }
    }

    #[test]
    fn a_rumour_too_large_for_any_datagram_is_dropped_and_counted() {
        use crate::{Config, Identity, Security};
        let addr = SocketAddr::from(([127, 0, 0, 1], 1));
        let cfg = Config::lan(Security::InsecurePlaintext);
        let me = Identity::new("a", addr).unwrap();
        let mut n = Node::new(cfg, me, Instant::ZERO, 1, &[1; 32]).unwrap();
        n.broadcast(suspect("b", 1));
        assert!(n.out.broadcasts.contains("b"));
        let room = datagram_room(&n.out.codec);
        let huge = Gossip::Alive {
            inc: 2,
            node: "b".to_owned(),
            addr,
            meta: vec![0; room],
            vmin: 1,
            vmax: 1,
            epoch: 0,
            sig: None,
            cert: None,
        };
        n.broadcast(huge);
        assert_eq!(n.metrics().gossip_too_large, 1);
        assert!(!n.out.broadcasts.contains("b"), "nor is the older one kept");
        // Anything that fits is queued as before.
        n.broadcast(suspect("b", 2));
        assert!(n.out.broadcasts.contains("b"));
        assert_eq!(n.metrics().gossip_too_large, 1);
    }

    /// The members of the rumours `select` picks for `budget` bytes, in order.
    fn picks(b: &Broadcasts, budget: usize) -> Vec<String> {
        b.select(budget)
            .into_iter()
            .map(|rank| b.gossip(rank).node().to_owned())
            .collect()
    }

    /// Checks that the member index and the ordered queue agree.
    fn consistent(b: &Broadcasts) {
        assert_eq!(b.queue.len(), b.by_node.len());
        for (node, rank) in &b.by_node {
            assert_eq!(b.queue[rank].gossip.node(), node);
        }
    }

    #[test]
    fn newer_gossip_replaces_older_about_the_same_member() {
        let mut b = Broadcasts::default();
        b.push(suspect("a", 1));
        b.push(suspect("b", 1));
        let first = b.select(usize::MAX);
        b.sent(&first, 5, true);
        b.push(suspect("a", 2));
        assert_eq!(b.len(), 2);
        consistent(&b);
        assert_eq!(b.gossip(b.by_node["a"]), &suspect("a", 2));
        // The replacement starts unsent and newest, so it goes first again.
        assert_eq!(picks(&b, usize::MAX), ["a", "b"]);
        assert_eq!(b.by_node["a"].transmits, 0);
        assert_eq!(b.by_node["b"].transmits, 1);
        b.forget("a");
        consistent(&b);
        assert!(!b.contains("a") && b.contains("b"));
        b.forget("a");
        assert_eq!(b.len(), 1);
    }

    #[test]
    fn least_sent_then_newest_first_and_dropped_at_the_limit() {
        let mut b = Broadcasts::default();
        b.push(suspect("a", 1));
        b.push(suspect("b", 1));
        let first = b.select(usize::MAX);
        assert_eq!(b.gossip(first[0]).node(), "b");
        b.sent(&first[..1], 2, true);
        let next = b.select(usize::MAX);
        assert_eq!(b.gossip(next[0]).node(), "a");
        b.sent(&next, 2, true);
        assert_eq!(b.len(), 1, "b reached its limit of 2");
        consistent(&b);
        let one = b.queue.values().next().unwrap().len;
        assert!(b.select(one - 1).is_empty());
    }

    #[test]
    fn a_lower_limit_drops_every_entry_that_reached_it() {
        let mut b = Broadcasts::default();
        for node in ["a", "b", "c"] {
            b.push(suspect(node, 1));
        }
        // a and b go out three times each under a limit of 5; c is never picked.
        for _ in 0..3 {
            let two: Vec<Rank> = b
                .select(usize::MAX)
                .into_iter()
                .filter(|&r| b.gossip(r).node() != "c")
                .collect();
            b.sent(&two, 5, true);
        }
        assert_eq!(b.len(), 3);
        // The cluster shrank and the limit fell to 3: a send of c alone also drops a and b.
        let c = b.by_node["c"];
        b.sent(&[c], 3, true);
        assert_eq!(picks(&b, usize::MAX), ["c"]);
        consistent(&b);
    }

    #[test]
    fn packing_skips_what_does_not_fit_and_takes_smaller_rumours_behind_it() {
        let addr = SocketAddr::from(([127, 0, 0, 1], 1));
        let big = Gossip::Alive {
            inc: 1,
            node: "big".to_owned(),
            addr,
            meta: vec![7; 200],
            vmin: 1,
            vmax: 1,
            epoch: 0,
            sig: None,
            cert: None,
        };
        let mut b = Broadcasts::default();
        b.push(suspect("old", 1));
        b.push(big);
        b.push(suspect("new", 1));
        let small = suspect("new", 1).message().encoded_len();
        let large = b
            .queue
            .values()
            .find(|q| q.gossip.node() == "big")
            .unwrap()
            .len;
        assert_eq!(picks(&b, usize::MAX), ["new", "big", "old"]);
        // Room for the big one only after the newest, and not for the oldest beside it.
        assert_eq!(picks(&b, small + large), ["new", "big"]);
        // Too little for the big one: the smaller ones behind it still go.
        assert_eq!(picks(&b, small * 2), ["new", "old"]);
        assert!(picks(&b, smallest_rumour() - 1).is_empty());
    }

    #[test]
    fn rumours_to_the_live_count_only_sends_to_live_members() {
        let mut b = Broadcasts::default();
        b.push_to_live(suspect("left", 1));
        b.push(suspect("other", 1));
        let all = b.select(usize::MAX);
        // A send to a member not held live counts for the ordinary rumour only.
        b.sent(&all, 2, false);
        assert_eq!(b.by_node["left"].transmits, 0);
        assert_eq!(b.by_node["other"].transmits, 1);
        let all = b.select(usize::MAX);
        assert_eq!(b.gossip(all[0]).node(), "left", "still unsent, so first");
        b.sent(&all, 2, false);
        assert_eq!(picks(&b, usize::MAX), ["left"], "other reached its limit");
        for _ in 0..2 {
            let all = b.select(usize::MAX);
            b.sent(&all, 2, true);
        }
        assert!(b.is_empty());
        consistent(&b);
    }

    #[test]
    fn a_bulk_of_rumours_is_queued_and_replaced_in_log_time() {
        // Quadratic replacement took seconds here; the index takes milliseconds.
        let mut b = Broadcasts::default();
        let names: Vec<String> = (0..20_000).map(|i| format!("m-{i:05}")).collect();
        for name in &names {
            b.push(suspect(name, 1));
        }
        for name in &names {
            b.push(suspect(name, 2));
        }
        assert_eq!(b.len(), names.len());
        consistent(&b);
        let first = b.select(1_400);
        assert_eq!(b.gossip(first[0]), &suspect(names.last().unwrap(), 2));
    }

    #[test]
    fn packets_respect_the_datagram_limit() {
        let limits = Limits {
            udp_max_payload: 200,
            ..Limits::default()
        };
        let codec = Codec::insecure_plaintext(b"t", limits).unwrap();
        let mut out = Outbox::new(codec, Nonces::new(&[1; 32]));
        for i in 0..50 {
            out.broadcasts.push(suspect(&format!("node-{i:02}"), 7));
        }
        let to = SocketAddr::from(([127, 0, 0, 1], 1));
        let mut sends = 0;
        while !out.broadcasts.is_empty() {
            assert!(out.send(to, true, WireVersion::V1, &[], Some(1)));
            sends += 1;
        }
        assert!(sends > 1);
        for t in out.transmits {
            let Transmit::Datagram { payload, .. } = t else {
                panic!("{t:?}");
            };
            assert!(payload.len() <= 200, "{}", payload.len());
        }
        assert!(
            !Outbox::new(
                Codec::insecure_plaintext(b"t", limits).unwrap(),
                Nonces::new(&[1; 32])
            )
            .send(to, true, WireVersion::V1, &[], Some(1))
        );
    }
}
