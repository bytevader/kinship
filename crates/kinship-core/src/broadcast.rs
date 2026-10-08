//! The transmit-limited gossip queue, and packing it into outgoing datagrams.

use std::collections::VecDeque;
use std::net::SocketAddr;

use kinship_proto::{Alive, Codec, Dead, Message, NodeId, PacketKind, Suspect};

use crate::Node;
use crate::io::{StreamId, Transmit};
use crate::member::State;
use crate::replay::STAMP_LEN;
use crate::rng::Nonces;
use crate::suspicion::retransmit_limit;
use crate::time::Instant;

/// An Alive, Suspect or Dead rumour waiting to be spread, owned so it can outlive the packet
/// it arrived in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Gossip {
    Alive {
        inc: u32,
        node: String,
        addr: SocketAddr,
        meta: Vec<u8>,
        vmin: u8,
        vmax: u8,
    },
    Suspect {
        inc: u32,
        node: String,
        from: String,
    },
    Dead {
        inc: u32,
        node: String,
        from: String,
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
        }
    }

    pub fn from_suspect(s: &Suspect<'_>) -> Self {
        Self::Suspect {
            inc: s.inc,
            node: s.node.as_str().to_owned(),
            from: s.from.as_str().to_owned(),
        }
    }

    pub fn from_dead(d: &Dead<'_>) -> Self {
        Self::Dead {
            inc: d.inc,
            node: d.node.as_str().to_owned(),
            from: d.from.as_str().to_owned(),
        }
    }

    /// The member this rumour is about.
    pub fn node(&self) -> &str {
        match self {
            Self::Alive { node, .. } | Self::Suspect { node, .. } | Self::Dead { node, .. } => node,
        }
    }

    pub fn message(&self) -> Message<'_> {
        match self {
            Self::Alive {
                inc,
                node,
                addr,
                meta,
                vmin,
                vmax,
            } => Message::Alive(Alive {
                inc: *inc,
                node: id(node),
                addr: *addr,
                meta,
                vmin: *vmin,
                vmax: *vmax,
            }),
            Self::Suspect { inc, node, from } => Message::Suspect(Suspect {
                inc: *inc,
                node: id(node),
                from: id(from),
            }),
            Self::Dead { inc, node, from } => Message::Dead(Dead {
                inc: *inc,
                node: id(node),
                from: id(from),
            }),
        }
    }
}

#[derive(Debug)]
struct Queued {
    gossip: Gossip,
    /// Encoded size inside a payload.
    len: usize,
    transmits: u32,
    /// Only sends to live members count towards the limit.
    live_only: bool,
    /// Insertion order; newer entries go first among equals.
    id: u64,
}

/// Rumours still to be spread, at most one per member.
///
/// Each entry rides on outgoing packets until it has been sent `limit` times. Packets take the
/// least-sent entries first, and the newest among those, so fresh news overtakes old.
#[derive(Debug, Default)]
pub(crate) struct Broadcasts {
    queue: Vec<Queued>,
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
        self.queue.retain(|q| q.gossip.node() != gossip.node());
        let len = gossip.message().encoded_len();
        self.queue.push(Queued {
            gossip,
            len,
            transmits: 0,
            live_only,
            id: self.next_id,
        });
        self.next_id += 1;
    }

    /// Drops anything queued about `node`.
    pub fn forget(&mut self, node: &str) {
        self.queue.retain(|q| q.gossip.node() != node);
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    /// Whether a rumour about `node` is still being spread.
    pub fn contains(&self, node: &str) -> bool {
        self.queue.iter().any(|q| q.gossip.node() == node)
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// Entries that fit in `budget` bytes, best first.
    fn select(&self, budget: usize) -> Vec<usize> {
        let mut order: Vec<usize> = (0..self.queue.len()).collect();
        order.sort_unstable_by_key(|&i| {
            let q = &self.queue[i];
            (q.transmits, u64::MAX - q.id)
        });
        let mut left = budget;
        order.retain(|&i| {
            let len = self.queue[i].len;
            let fits = len <= left;
            if fits {
                left -= len;
            }
            fits
        });
        order
    }

    /// Counts one more send of each entry in `sent`, to a live member if `live`, dropping those
    /// that reached `limit`.
    fn sent(&mut self, sent: &[usize], limit: u32, live: bool) {
        for &i in sent {
            let q = &mut self.queue[i];
            if live || !q.live_only {
                q.transmits += 1;
            }
        }
        self.queue.retain(|q| q.transmits < limit);
    }
}

/// Bytes a payload's message count can take: counts stay below 2^14 in any packet.
const COUNT_LEN: usize = 2;

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
            transmits: VecDeque::new(),
            nonces,
            stamp: 0,
        }
    }

    /// A fresh nonce: the cluster time, then random bytes. All zero in plaintext mode, which
    /// sends no nonce.
    fn nonce(&mut self) -> [u8; kinship_proto::NONCE_LEN] {
        let mut nonce = [0; kinship_proto::NONCE_LEN];
        if self.codec.is_encrypted() {
            nonce[..STAMP_LEN].copy_from_slice(&self.stamp.to_be_bytes());
            self.nonces.fill(&mut nonce[STAMP_LEN..]);
        }
        nonce
    }

    /// Sends `head` to `to` in one datagram, filling the space left with queued gossip that
    /// has been sent fewer than `limit` times (none if `limit` is `None`). `live` says whether
    /// `to` is a member this node holds live, Alive or Suspect. Sends nothing if there is
    /// nothing to send. Returns whether a datagram was queued.
    pub fn send(
        &mut self,
        to: SocketAddr,
        live: bool,
        head: &[Message<'_>],
        limit: Option<u32>,
    ) -> bool {
        let max = datagram_room(&self.codec);
        let used: usize = head.iter().map(Message::encoded_len).sum();
        let picked = match limit {
            Some(_) => self.broadcasts.select(max.saturating_sub(used)),
            None => Vec::new(),
        };
        if head.is_empty() && picked.is_empty() {
            return false;
        }
        let nonce = self.nonce();
        let mut msgs = Vec::with_capacity(head.len() + picked.len());
        msgs.extend_from_slice(head);
        msgs.extend(
            picked
                .iter()
                .map(|&i| self.broadcasts.queue[i].gossip.message()),
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
        }
        self.transmits.push_back(Transmit::Datagram { to, payload });
        true
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
    fn queue_gossip(&mut self, gossip: Gossip, live_only: bool) {
        if gossip.message().encoded_len() > datagram_room(&self.out.codec) {
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

    /// This node's own Alive rumour.
    pub(crate) fn local_alive(&self) -> Gossip {
        let me = &self.local;
        Gossip::Alive {
            inc: me.member.incarnation,
            node: me.member.name.clone(),
            addr: me.member.addr,
            meta: me.member.meta.clone(),
            vmin: me.vmin,
            vmax: me.vmax,
        }
    }

    /// Whether this node holds `name` as a live member, Alive or Suspect.
    pub(crate) fn holds_live(&self, name: &str) -> bool {
        self.table
            .get(name)
            .is_some_and(|e| e.member.state.is_live())
    }

    /// Sends queued rumours to `gossip_nodes` random members, those declared dead less than
    /// `gossip_to_the_dead` ago included, so a member wrongly declared dead hears about it and
    /// can refute. Members that left are not sent to: they have closed.
    pub(crate) fn gossip(&mut self, now: Instant) {
        if self.out.broadcasts.is_empty() {
            return;
        }
        let window = self.cfg.gossip_to_the_dead;
        let targets: Vec<(SocketAddr, bool)> = self
            .table
            .random(self.cfg.gossip_nodes, &mut self.rng, |e| {
                match e.member.state {
                    State::Alive | State::Suspect => true,
                    State::Dead => now - e.since < window,
                    State::Left => false,
                }
            })
            .into_iter()
            .map(|e| (e.member.addr, e.member.state.is_live()))
            .collect();
        let limit = self.retransmit_limit();
        for (to, live) in targets {
            if !self.send_to(to, live, &[], Some(limit)) {
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
    /// this node [may send](Self::may_send) to `to`. Returns whether a datagram was queued.
    pub(crate) fn send_to(
        &mut self,
        to: SocketAddr,
        live: bool,
        head: &[Message<'_>],
        limit: Option<u32>,
    ) -> bool {
        self.may_send(to) && self.out.send(to, live, head, limit)
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
        };
        n.broadcast(huge);
        assert_eq!(n.metrics().gossip_too_large, 1);
        assert!(!n.out.broadcasts.contains("b"), "nor is the older one kept");
        // Anything that fits is queued as before.
        n.broadcast(suspect("b", 2));
        assert!(n.out.broadcasts.contains("b"));
        assert_eq!(n.metrics().gossip_too_large, 1);
    }

    #[test]
    fn newer_gossip_replaces_older_about_the_same_member() {
        let mut b = Broadcasts::default();
        b.push(suspect("a", 1));
        b.push(suspect("b", 1));
        b.push(suspect("a", 2));
        assert_eq!(b.len(), 2);
        assert!(b.queue.iter().any(|q| q.gossip == suspect("a", 2)));
    }

    #[test]
    fn least_sent_then_newest_first_and_dropped_at_the_limit() {
        let mut b = Broadcasts::default();
        b.push(suspect("a", 1));
        b.push(suspect("b", 1));
        let first = b.select(usize::MAX);
        assert_eq!(b.queue[first[0]].gossip.node(), "b");
        b.sent(&first[..1], 2, true);
        let next = b.select(usize::MAX);
        assert_eq!(b.queue[next[0]].gossip.node(), "a");
        b.sent(&next, 2, true);
        assert_eq!(b.len(), 1, "b reached its limit of 2");
        let one = b.queue[0].len;
        assert!(b.select(one - 1).is_empty());
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
            assert!(out.send(to, true, &[], Some(1)));
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
            .send(to, true, &[], Some(1))
        );
    }
}
