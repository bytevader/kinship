//! User messages: data the application sends to one member or to every member, in the
//! cluster's own packets. See `docs/design.md`, User messages.
//!
//! A direct message goes in one datagram when it fits, and otherwise over a connection of its
//! own, at most one per member at a time: messages for a member whose connection is still open
//! wait, within a bound, and go together in its next frame. A broadcast is numbered and queued
//! beside the membership rumours, spread with the same retransmit rule in the room they leave,
//! and recognised by every node as a copy by its sender, epoch and number.
//!
//! Every buffer here is bounded (KI-04): the broadcast queue by `user_broadcast_queue`, the
//! messages waiting for a connection by `max_stream_frame` bytes of data, and what a node
//! remembers of the broadcasts it has seen by one window per member it holds.

use core::net::SocketAddr;
use std::collections::{BTreeMap, VecDeque};

use kinship_proto::identity::{Certificate, CertificateId, Signature};
use kinship_proto::v2;
use kinship_proto::{Message, PacketKind, UserBroadcast, UserMessage, WireVersion};

use crate::Node;
use crate::broadcast::{COUNT_LEN, id};
use crate::event::{CommandError, CommandOutput, Event};
use crate::io::StreamId;
use crate::member::{Life, Member, life};
use crate::signing::PacketCerts;
use crate::sync::Purpose;

/// How many sequence numbers below the highest it has seen from a member a node remembers.
pub(crate) const SEEN_WINDOW: u64 = 256;

/// Most messages in one frame, so that the frame's message count fits the room
/// [`COUNT_LEN`] keeps for it.
const MAX_FRAME_MESSAGES: usize = 16_000;

/// A broadcast waiting to be spread, owned so it can outlive the packet it arrived in. In mode
/// `sign` it keeps its sender's signature, when it came with one, and the sender's certificate
/// to go ahead of it in every version 2 packet, so that a member that has not checked the
/// sender's certificate yet can check the broadcast (`docs/ki01-stage2.md`, Signed user
/// messages).
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct Broadcast {
    pub from: String,
    pub from_epoch: u64,
    pub seq: u64,
    pub data: Vec<u8>,
    pub sig: Option<(CertificateId, Signature)>,
    pub cert: Option<Vec<u8>>,
}

impl Broadcast {
    /// The broadcast in the version 1 grammar, without a signature.
    pub fn message(&self) -> Message<'_> {
        Message::UserBroadcast(self.body())
    }

    fn body(&self) -> UserBroadcast<'_> {
        UserBroadcast {
            from: id(&self.from),
            from_epoch: self.from_epoch,
            seq: self.seq,
            data: &self.data,
        }
    }

    /// The broadcast in the version 2 grammar, behind its certificate if it carries one; `None`
    /// if it is unsigned.
    pub fn signed(&self) -> Option<(Option<Certificate<'_>>, v2::Message<'_>)> {
        let (certificate_id, signature) = self.sig?;
        let cert = self
            .cert
            .as_deref()
            .and_then(|c| Certificate::decode(c).ok());
        let msg = v2::Message::UserBroadcast {
            broadcast: self.body(),
            certificate_id,
            signature,
        };
        Some((cert, msg))
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
    broadcast: Broadcast,
    /// Encoded size inside a payload.
    len: usize,
    /// Encoded size of its version 2 form, certificate included, when it is signed.
    signed_len: Option<usize>,
}

/// Where a broadcast stands in the queue: fewest sends first, and among those the oldest first,
/// so that one member's broadcasts mostly leave in the order it made them.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub(crate) struct Rank {
    transmits: u32,
    id: u64,
}

/// User broadcasts still to be spread: this node's own and those it relays.
///
/// Each rides on outgoing datagrams to live members, in the room the membership rumours leave,
/// until it has been sent `limit` times. When the queue holds more than its capacity, the entry
/// nearest to done is dropped: the most sent, and among those the newest.
#[derive(Debug, Default)]
pub(crate) struct UserQueue {
    queue: BTreeMap<Rank, Queued>,
    next_id: u64,
}

impl UserQueue {
    /// Queues `broadcast`. Returns false if that left more than `capacity` entries and one was
    /// dropped, which is the new one when none has been sent yet.
    pub fn push(&mut self, broadcast: Broadcast, capacity: usize) -> bool {
        let rank = Rank {
            transmits: 0,
            id: self.next_id,
        };
        self.next_id += 1;
        let len = broadcast.message().encoded_len();
        let signed_len = broadcast.signed_len();
        self.queue.insert(
            rank,
            Queued {
                broadcast,
                len,
                signed_len,
            },
        );
        if self.queue.len() <= capacity {
            return true;
        }
        self.queue.pop_last();
        false
    }

    pub fn is_empty(&self) -> bool {
        self.queue.is_empty()
    }

    #[cfg(test)]
    pub fn len(&self) -> usize {
        self.queue.len()
    }

    /// The broadcast queued at `rank`, which [`select`](Self::select) returned.
    pub fn broadcast(&self, rank: Rank) -> &Broadcast {
        &self.queue[&rank].broadcast
    }

    /// Entries that fit in `budget` bytes, in queue order, skipping any that do not fit what
    /// is left so that smaller ones behind it still can.
    pub fn select(&self, budget: usize) -> Vec<Rank> {
        let smallest = smallest_broadcast();
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

    /// Like [`select`](Self::select) for a member that speaks version 2: signed entries in their
    /// version 2 form fill `signed` bytes, the unsigned ones `unsigned` bytes. Returns the
    /// entries for each.
    pub fn select_split(&self, unsigned: usize, signed: usize) -> (Vec<Rank>, Vec<Rank>) {
        let smallest = smallest_broadcast();
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

    /// Counts one more send of each entry in `sent`, then drops every entry that has reached
    /// `limit`, as the membership queue does.
    pub fn sent(&mut self, sent: &[Rank], limit: u32) {
        for &rank in sent {
            if let Some(q) = self.queue.remove(&rank) {
                let next = Rank {
                    transmits: rank.transmits + 1,
                    ..rank
                };
                self.queue.insert(next, q);
            }
        }
        while let Some(entry) = self.queue.last_entry() {
            if entry.key().transmits < limit {
                break;
            }
            entry.remove();
        }
    }
}

/// Bytes the smallest broadcast takes in a payload: a one-byte name and no data.
fn smallest_broadcast() -> usize {
    Message::UserBroadcast(UserBroadcast {
        from: id("n"),
        from_epoch: 0,
        seq: 0,
        data: &[],
    })
    .encoded_len()
}

/// Bytes a stream frame sealed by `codec` has for its messages, past their count.
fn frame_room(codec: &kinship_proto::Codec) -> usize {
    codec
        .max_payload_len(PacketKind::Stream)
        .saturating_sub(COUNT_LEN)
}

/// What a node has seen of one member's broadcasts: the highest number from the life `epoch`,
/// and which of the [`SEEN_WINDOW`] numbers up to it, one bit each, at `seq % SEEN_WINDOW`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct Seen {
    epoch: u64,
    high: u64,
    bits: [u64; 4],
}

/// Whether a broadcast is new to this node.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Copy {
    New,
    Seen,
    /// So far below the highest number seen that the node can no longer tell.
    TooOld,
}

impl Seen {
    fn new(epoch: u64, seq: u64) -> Self {
        let mut seen = Self {
            epoch,
            high: seq,
            bits: [0; 4],
        };
        seen.mark(seq);
        seen
    }

    fn slot(seq: u64) -> (usize, u64) {
        let i = (seq % SEEN_WINDOW) as usize;
        (i / 64, 1 << (i % 64))
    }

    fn mark(&mut self, seq: u64) {
        let (word, bit) = Self::slot(seq);
        self.bits[word] |= bit;
    }

    fn is_marked(&self, seq: u64) -> bool {
        let (word, bit) = Self::slot(seq);
        self.bits[word] & bit != 0
    }

    /// What [`check`](Self::check) would say of broadcast `seq` of the life `epoch`, recording
    /// nothing.
    fn peek(&self, epoch: u64, seq: u64) -> Copy {
        if epoch != self.epoch || seq > self.high {
            Copy::New
        } else if self.high - seq >= SEEN_WINDOW {
            Copy::TooOld
        } else if self.is_marked(seq) {
            Copy::Seen
        } else {
            Copy::New
        }
    }

    /// Records broadcast `seq` of the life `epoch`, which starts over at a new life.
    fn check(&mut self, epoch: u64, seq: u64) -> Copy {
        if epoch != self.epoch {
            *self = Self::new(epoch, seq);
            return Copy::New;
        }
        if seq > self.high {
            if seq - self.high >= SEEN_WINDOW {
                self.bits = [0; 4];
            } else {
                for s in self.high + 1..seq {
                    let (word, bit) = Self::slot(s);
                    self.bits[word] &= !bit;
                }
            }
            self.high = seq;
            self.mark(seq);
            return Copy::New;
        }
        if self.high - seq >= SEEN_WINDOW {
            return Copy::TooOld;
        }
        if self.is_marked(seq) {
            return Copy::Seen;
        }
        self.mark(seq);
        Copy::New
    }
}

/// A direct message waiting for a connection to its member.
#[derive(Debug)]
struct Waiting {
    to_epoch: u64,
    data: Vec<u8>,
}

/// Direct messages to one member that go over TCP.
#[derive(Debug, Default)]
struct Target {
    /// The connection carrying the last frame, until it ends.
    open: Option<StreamId>,
    waiting: VecDeque<Waiting>,
}

/// User message state that is not the broadcast queue, which lives in the outbox.
#[derive(Debug)]
pub(crate) struct Users {
    /// The number of this node's next broadcast.
    next_seq: u64,
    /// What this node has seen of each member's broadcasts, for members in its table.
    seen: BTreeMap<String, Seen>,
    /// Members with direct messages on a connection or waiting for one.
    targets: BTreeMap<String, Target>,
    /// Bytes of data waiting in `targets`.
    waiting_bytes: usize,
    /// Each connection carrying messages: the member and how many it carries.
    streams: BTreeMap<StreamId, (String, usize)>,
}

impl Default for Users {
    fn default() -> Self {
        Self {
            next_seq: 1,
            seen: BTreeMap::new(),
            targets: BTreeMap::new(),
            waiting_bytes: 0,
            streams: BTreeMap::new(),
        }
    }
}

impl Node {
    /// Sends `data` to the life `epoch` of `to`, 0 for whichever life this node holds.
    pub(crate) fn send_user(
        &mut self,
        to: &str,
        epoch: u64,
        data: Vec<u8>,
    ) -> Result<CommandOutput, CommandError> {
        if self.has_left() {
            return Err(CommandError::Left);
        }
        if data.len() > self.cfg.max_user_message {
            self.metrics.user_messages_too_large += 1;
            return Err(CommandError::MessageTooLarge);
        }
        let held = self
            .table
            .get(to)
            .filter(|e| e.member.state.is_live() && life(epoch, e.member.epoch) == Life::Same)
            .map(|e| (e.member.addr, e.member.epoch));
        let Some((addr, to_epoch)) = held else {
            return Err(CommandError::NotAMember);
        };
        if self.version_for(Some(to), addr) == WireVersion::V2 {
            self.send_user_signed(to, addr, to_epoch, data);
            return Ok(CommandOutput::Done);
        }
        let me = self.local.member.name.clone();
        let msg = Message::UserMessage(UserMessage {
            to: id(to),
            to_epoch,
            from: id(&me),
            from_epoch: self.local.member.epoch,
            data: &data,
        });
        // A member that has not heard of this node yet learns it from the Alive ahead of the
        // message, while that Alive is still news.
        let alive = self.local_alive();
        let alive = alive.message();
        let room = crate::broadcast::datagram_room(&self.out.codec);
        let with_alive = [alive, msg];
        let head: &[Message<'_>] = if !self.out.broadcasts.contains(&me) {
            &with_alive[1..]
        } else if with_alive.iter().map(Message::encoded_len).sum::<usize>() <= room {
            &with_alive
        } else {
            &with_alive[1..]
        };
        if head.iter().map(Message::encoded_len).sum::<usize>() <= room {
            // No gossip rides along, so that messages to one member do not spend every rumour's
            // retransmissions on it.
            if self.send_to(addr, true, Some(to), head, None) {
                self.metrics.user_messages_sent += 1;
            }
            return Ok(CommandOutput::Done);
        }
        self.send_user_stream(to, addr, Waiting { to_epoch, data });
        Ok(CommandOutput::Done)
    }

    /// Mode `sign`, to a member that speaks version 2: the message goes signed over the nonce of
    /// the version 2 datagram that carries it, which is drawn first and seals it (Stage 1, the
    /// direct-message nonce binding). This node's certificate goes ahead of it, and its Alive
    /// too while that is still being spread, as far as they fit, so that a receiver can check
    /// it whatever it heard of this node so far. A message too large for a datagram goes over
    /// a connection.
    fn send_user_signed(&mut self, to: &str, addr: SocketAddr, to_epoch: u64, data: Vec<u8>) {
        let me = self.local.member.name.clone();
        let unsigned = v2::Message::UserMessage {
            message: UserMessage {
                to: id(to),
                to_epoch,
                from: id(&me),
                from_epoch: self.local.member.epoch,
                data: &data,
            },
            certificate_id: CertificateId::default(),
            signature: [0; 64],
        };
        // A signature does not change the length, so the nonce is drawn only for a datagram.
        let room = crate::broadcast::datagram_room(&self.out.codec);
        let len = unsigned.encoded_len();
        if len > room {
            return self.send_user_stream(to, addr, Waiting { to_epoch, data });
        }
        let gossip = self.local_alive_announced();
        let mut ahead: Vec<v2::Message<'_>> = Vec::new();
        if let Some((cert, alive)) = gossip.signed() {
            ahead.extend(cert.map(v2::Message::Certificate));
            if self.out.broadcasts.contains(&me) {
                ahead.push(alive);
            }
        }
        // Whatever of the certificate and the Alive fits beside the message, the Alive first to go.
        while ahead.iter().map(v2::Message::encoded_len).sum::<usize>() + len > room {
            ahead.pop();
        }
        let nonce = self.out.nonce();
        let Some(msg) = self.signed(unsigned, Some(&nonce)) else {
            return;
        };
        ahead.push(msg);
        // No gossip rides along, as in version 1.
        if self.may_send(addr) && self.out.send_signed_at(addr, &ahead, &nonce) {
            self.metrics.user_messages_sent += 1;
        }
    }

    /// Sends a message too large for a datagram over a connection to `to` at `addr`, or has it
    /// wait for the next one while one is open.
    fn send_user_stream(&mut self, to: &str, addr: SocketAddr, message: Waiting) {
        let target = self.user.targets.entry(to.to_owned()).or_default();
        if target.open.is_none() {
            return self.open_user_stream(to, addr, vec![message]);
        }
        let bytes = message.data.len();
        if self.user.waiting_bytes + bytes > self.cfg.limits.max_stream_frame {
            self.metrics.user_queue_overflow += 1;
            return;
        }
        self.user.waiting_bytes += bytes;
        target.waiting.push_back(message);
    }

    /// Opens a connection to `to` at `addr` with one frame: this node's Alive, then `batch`.
    /// A frame too small for both, which only a much lowered `max_stream_frame` makes, goes
    /// without the Alive.
    fn open_user_stream(&mut self, to: &str, addr: SocketAddr, batch: Vec<Waiting>) {
        let version = self.version_for(Some(to), addr);
        let conn = self.connect(addr, Purpose::Message, false, version);
        let me = self.local.member.name.clone();
        let from_epoch = self.local.member.epoch;
        fn message<'a>(
            to: &'a str,
            from: &'a str,
            from_epoch: u64,
            w: &'a Waiting,
        ) -> UserMessage<'a> {
            UserMessage {
                to: id(to),
                to_epoch: w.to_epoch,
                from: id(from),
                from_epoch,
                data: &w.data,
            }
        }
        let sent = if version == WireVersion::V2 {
            // Mode `sign`: every message signed over the frame's nonce, behind this node's signed
            // Alive and its certificate, so that the receiver can check them.
            let nonce = self.out.nonce();
            let gossip = self.local_alive_announced();
            let mut msgs: Vec<v2::Message<'_>> = Vec::with_capacity(batch.len() + 2);
            if let Some((cert, alive)) = gossip.signed() {
                msgs.extend(cert.map(v2::Message::Certificate));
                msgs.push(alive);
            }
            let ahead = msgs.len();
            for w in &batch {
                let unsigned = v2::Message::UserMessage {
                    message: message(to, &me, from_epoch, w),
                    certificate_id: CertificateId::default(),
                    signature: [0; 64],
                };
                msgs.extend(self.signed(unsigned, Some(&nonce)));
            }
            let len: usize = msgs.iter().map(v2::Message::encoded_len).sum();
            let skip = if len <= frame_room(&self.out.codec) {
                0
            } else {
                ahead
            };
            self.out.frame_v2_at(conn, &msgs[skip..], &nonce)
        } else {
            let alive = self.local_alive();
            let mut msgs = Vec::with_capacity(batch.len() + 1);
            msgs.push(alive.message());
            msgs.extend(
                batch
                    .iter()
                    .map(|w| Message::UserMessage(message(to, &me, from_epoch, w))),
            );
            let len: usize = msgs.iter().map(Message::encoded_len).sum();
            let with_alive = len <= frame_room(&self.out.codec);
            self.out.frame(conn, &msgs[usize::from(!with_alive)..])
        };
        let n = batch.len() as u64;
        if !sent {
            // Validated limits keep every message small enough for a frame of its own.
            self.metrics.user_messages_dropped += n;
            self.close_stream(conn);
            self.user.targets.remove(to);
            return;
        }
        self.metrics.user_messages_sent += n;
        self.user.streams.insert(conn, (to.to_owned(), batch.len()));
        self.user.targets.entry(to.to_owned()).or_default().open = Some(conn);
    }

    /// A connection carrying user messages ended: closed by the receiver once it handled the
    /// frame, or failed, timed out or answered with something else, which counts its messages
    /// as dropped. The messages waiting for the member go out on a new one.
    pub(crate) fn user_stream_ended(&mut self, conn: StreamId, closed: bool) {
        let Some((to, n)) = self.user.streams.remove(&conn) else {
            return;
        };
        if !closed {
            self.metrics.user_messages_dropped += n as u64;
        }
        let Some(target) = self.user.targets.get_mut(&to) else {
            return;
        };
        if target.open == Some(conn) {
            target.open = None;
        }
        self.flush_waiting(&to);
    }

    /// Sends what waits for `to` in one frame, as much as fits, if no connection to it is open.
    /// Messages for a member no longer held live, or for an earlier life of it, are dropped.
    fn flush_waiting(&mut self, to: &str) {
        let held = self
            .table
            .get(to)
            .filter(|e| e.member.state.is_live())
            .map(|e| (e.member.addr, e.member.epoch));
        let room = frame_room(&self.out.codec);
        // Signed, each message takes its certificate id and signature more.
        let signed =
            held.is_some_and(|(addr, _)| self.version_for(Some(to), addr) == WireVersion::V2);
        let Some(target) = self.user.targets.get_mut(to) else {
            return;
        };
        if target.open.is_some() {
            return;
        }
        let me = &self.local.member;
        let mut batch = Vec::new();
        let mut used = 0;
        let mut dropped = 0;
        while let Some(w) = target.waiting.front() {
            let Some((_, epoch)) = held.filter(|&(_, e)| life(w.to_epoch, e) == Life::Same) else {
                dropped += 1;
                self.user.waiting_bytes -= w.data.len();
                target.waiting.pop_front();
                continue;
            };
            let message = UserMessage {
                to: id(to),
                to_epoch: w.to_epoch.max(epoch),
                from: id(&me.name),
                from_epoch: me.epoch,
                data: &w.data,
            };
            let len = if signed {
                v2::Message::UserMessage {
                    message,
                    certificate_id: CertificateId::default(),
                    signature: [0; 64],
                }
                .encoded_len()
            } else {
                Message::UserMessage(message).encoded_len()
            };
            if !batch.is_empty() && (used + len > room || batch.len() == MAX_FRAME_MESSAGES) {
                break;
            }
            used += len;
            self.user.waiting_bytes -= w.data.len();
            batch.extend(target.waiting.pop_front());
        }
        self.metrics.user_messages_dropped += dropped;
        match held {
            Some((addr, _)) if !batch.is_empty() => self.open_user_stream(to, addr, batch),
            _ => {
                self.user.targets.remove(to);
            }
        }
    }

    /// Queues this node's own broadcast of `data`.
    pub(crate) fn broadcast_user(&mut self, data: Vec<u8>) -> Result<CommandOutput, CommandError> {
        if self.has_left() {
            return Err(CommandError::Left);
        }
        if data.len() > self.cfg.max_user_broadcast {
            self.metrics.user_messages_too_large += 1;
            return Err(CommandError::MessageTooLarge);
        }
        let seq = self.user.next_seq;
        self.user.next_seq += 1;
        self.metrics.user_messages_sent += 1;
        let mut broadcast = Broadcast {
            from: self.local.member.name.clone(),
            from_epoch: self.local.member.epoch,
            seq,
            data,
            sig: None,
            cert: None,
        };
        // Mode `sign`: signed over its sender, epoch, number and data, and spread with it,
        // behind this node's certificate.
        let unsigned = v2::Message::UserBroadcast {
            broadcast: broadcast.body(),
            certificate_id: CertificateId::default(),
            signature: [0; 64],
        };
        let sig = match self.signed(unsigned, None) {
            Some(v2::Message::UserBroadcast {
                certificate_id,
                signature,
                ..
            }) => Some((certificate_id, signature)),
            _ => None,
        };
        broadcast.sig = sig;
        broadcast.cert = self.keys.as_ref().map(|k| k.own.bytes.clone());
        self.queue_user_broadcast(broadcast);
        Ok(CommandOutput::Done)
    }

    fn queue_user_broadcast(&mut self, broadcast: Broadcast) {
        if !self.out.user.push(broadcast, self.cfg.user_broadcast_queue) {
            self.metrics.user_queue_overflow += 1;
        }
    }

    /// A user message or broadcast arrived; see the module docs.
    pub(crate) fn on_user(&mut self, msg: &Message<'_>) {
        match msg {
            Message::UserMessage(m) => {
                if let Some(sender) = self.direct_sender(m) {
                    self.deliver_direct(sender, m.data);
                }
            }
            Message::UserBroadcast(b) => self.on_user_broadcast(b, None),
            _ => {}
        }
    }

    /// The user messages and broadcasts of a version 2 packet sealed with `nonce`, in order,
    /// with the certificates it carries. A direct message whose proof is a repeat of one
    /// already in the packet is not handled again (Stage 1, the duplicate-proof note).
    pub(crate) fn on_signed_users(
        &mut self,
        msgs: &[v2::Message<'_>],
        packet: &PacketCerts<'_>,
        nonce: Option<&[u8; 24]>,
    ) {
        let mut proofs: BTreeMap<Signature, usize> = BTreeMap::new();
        for (i, msg) in msgs.iter().enumerate() {
            match msg {
                v2::Message::UserMessage { signature, .. } => {
                    let first = *proofs.entry(*signature).or_insert(i);
                    if first != i && msgs[first] == *msg {
                        continue;
                    }
                    self.on_signed_user_message(msg, packet, nonce);
                }
                v2::Message::UserBroadcast { broadcast, .. } => {
                    self.on_user_broadcast(broadcast, Some((msg, packet)));
                }
                _ => {}
            }
        }
    }

    /// A signed direct message: delivered only if it is for this run of this node, from a
    /// member it holds, and its signature over the packet's `nonce` checks, in that order.
    fn on_signed_user_message(
        &mut self,
        msg: &v2::Message<'_>,
        packet: &PacketCerts<'_>,
        nonce: Option<&[u8; 24]>,
    ) {
        let v2::Message::UserMessage {
            message: m,
            certificate_id,
            ..
        } = *msg
        else {
            return;
        };
        let Some(sender) = self.direct_sender(&m) else {
            return;
        };
        let from = m.from.as_str();
        let checked = nonce.is_some_and(|nonce| {
            self.check_bound(msg, from, certificate_id, packet, Some(nonce))
                .is_some()
        });
        if !checked {
            self.metrics.user_messages_dropped += 1;
            return;
        }
        self.deliver_direct(sender, m.data);
    }

    /// The member that sent the direct message `m`, if it is one to deliver: within this node's
    /// limit, for this run of it, and from a member it holds at that epoch. Counts what is not.
    fn direct_sender(&mut self, m: &UserMessage<'_>) -> Option<Member> {
        if m.data.len() > self.cfg.max_user_message {
            self.metrics.user_messages_too_large += 1;
            return None;
        }
        let me = &self.local.member;
        let for_me = m.to.as_str() == me.name
            && (m.to_epoch == 0 || m.to_epoch == me.epoch || m.to_epoch == self.me.epoch());
        let sender = for_me
            .then(|| self.sender(m.from.as_str(), m.from_epoch))
            .flatten();
        if sender.is_none() {
            self.metrics.user_messages_dropped += 1;
        }
        sender
    }

    fn deliver_direct(&mut self, sender: Member, data: &[u8]) {
        self.metrics.user_messages_received += 1;
        self.events.push_back(Event::UserMessage {
            sender,
            data: data.to_vec(),
            broadcast: false,
        });
    }

    /// A user broadcast, with `proof`, the version 2 message it came in and the certificates
    /// beside it, when it came signed. The copy rules come first, then the signature, and only
    /// a broadcast that passes both is remembered as seen, delivered and queued to relay, with
    /// its signature when it had one (rule 4).
    fn on_user_broadcast(
        &mut self,
        b: &UserBroadcast<'_>,
        proof: Option<(&v2::Message<'_>, &PacketCerts<'_>)>,
    ) {
        if b.data.len() > self.cfg.max_user_broadcast {
            self.metrics.user_messages_too_large += 1;
            return;
        }
        let from = b.from.as_str();
        if from == self.local.member.name {
            // This node's own, coming back.
            return;
        }
        let Some(sender) = self.sender(from, b.from_epoch) else {
            // Not remembered, so a copy that arrives after the sender's Alive still counts.
            self.metrics.user_messages_dropped += 1;
            return;
        };
        let copy = self
            .user
            .seen
            .get(from)
            .map_or(Copy::New, |seen| seen.peek(b.from_epoch, b.seq));
        match copy {
            Copy::Seen => return,
            Copy::TooOld => {
                self.metrics.user_messages_dropped += 1;
                return;
            }
            Copy::New => {}
        }
        let (mut sig, mut cert) = (None, None);
        if let Some((msg, packet)) = proof {
            let v2::Message::UserBroadcast {
                certificate_id,
                signature,
                ..
            } = *msg
            else {
                return;
            };
            let Some(signed) = self.check(msg, from, certificate_id, packet) else {
                // Not remembered either: a good copy may still come.
                self.metrics.user_messages_dropped += 1;
                return;
            };
            sig = Some((certificate_id, signature));
            // The certificate it was checked under goes ahead of it.
            cert = match signed.cert {
                Some(c) => Some(c.bytes),
                None => self.cert_bytes(from, certificate_id),
            };
        }
        match self.user.seen.get_mut(from) {
            Some(seen) => {
                seen.check(b.from_epoch, b.seq);
            }
            None => {
                self.user
                    .seen
                    .insert(from.to_owned(), Seen::new(b.from_epoch, b.seq));
            }
        }
        self.metrics.user_messages_received += 1;
        self.events.push_back(Event::UserMessage {
            sender,
            data: b.data.to_vec(),
            broadcast: true,
        });
        self.queue_user_broadcast(Broadcast {
            from: from.to_owned(),
            from_epoch: b.from_epoch,
            seq: b.seq,
            data: b.data.to_vec(),
            sig,
            cert,
        });
    }

    /// The member that sent a user message from the life `epoch` of `name`: one this node holds
    /// at that life, or where either epoch is unknown, in any state, tombstones included.
    fn sender(&self, name: &str, epoch: u64) -> Option<Member> {
        let e = self.table.get(name)?;
        (life(epoch, e.member.epoch) == Life::Same).then(|| e.member.clone())
    }

    /// Forgets what was seen of members that are no longer in the table.
    pub(crate) fn forget_reaped_senders(&mut self) {
        if self.user.seen.is_empty() {
            return;
        }
        let table = &self.table;
        self.user.seen.retain(|name, _| table.get(name).is_some());
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::io::{StreamEvent, Transmit};
    use crate::member::State;
    use crate::time::Instant;
    use crate::{Command, Config, Identity, Rng, Security};
    use kinship_proto::{Alive, Codec, Dead, Limits};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    /// `N` bytes drawn from the RNG seeded with `seed`, the same in every run.
    fn drawn<const N: usize>(seed: u64) -> [u8; N] {
        let mut rng = Rng::new(seed);
        std::array::from_fn(|_| rng.next_u64().to_le_bytes()[0])
    }

    /// Bytes to seal test packets with; plaintext sends no nonce, but the codec takes one.
    fn nonce() -> [u8; 24] {
        drawn(24)
    }

    fn plaintext() -> Codec {
        Codec::insecure_plaintext(b"default", Limits::default()).unwrap()
    }

    /// Node "a" at port 1, in its life `epoch`, running `cfg`.
    fn node_with(cfg: Config, epoch: u64) -> Node {
        let me = Identity::new("a", addr(1)).unwrap().with_epoch(epoch);
        Node::new(cfg, me, Instant::ZERO, 1, &drawn(1)).unwrap()
    }

    /// Node "a" in plaintext at epoch 100.
    fn node() -> Node {
        node_with(Config::local(Security::InsecurePlaintext), 100)
    }

    fn alive(name: &str, port: u16, epoch: u64) -> Message<'_> {
        Message::Alive(Alive {
            inc: 0,
            node: id(name),
            addr: addr(port),
            meta: b"",
            vmin: 1,
            vmax: 1,
            epoch,
        })
    }

    fn left(name: &str, epoch: u64) -> Message<'_> {
        Message::Dead(Dead {
            inc: 0,
            node: id(name),
            from: id(name),
            epoch,
        })
    }

    fn message<'a>(
        to: &'a str,
        to_epoch: u64,
        from: &'a str,
        from_epoch: u64,
        data: &'a [u8],
    ) -> Message<'a> {
        Message::UserMessage(UserMessage {
            to: id(to),
            to_epoch,
            from: id(from),
            from_epoch,
            data,
        })
    }

    fn broadcast<'a>(from: &'a str, from_epoch: u64, seq: u64, data: &'a [u8]) -> Message<'a> {
        Message::UserBroadcast(UserBroadcast {
            from: id(from),
            from_epoch,
            seq,
            data,
        })
    }

    /// Hands `n` one datagram holding `msgs`.
    fn deliver(n: &mut Node, msgs: &[Message<'_>]) {
        let mut pkt = Vec::new();
        plaintext()
            .seal(PacketKind::Datagram, msgs, &nonce(), &mut pkt)
            .unwrap();
        n.handle_datagram(n.now, addr(2), &pkt);
    }

    fn sent(n: &mut Node) -> Vec<Transmit> {
        std::iter::from_fn(|| n.poll_transmit()).collect()
    }

    fn events(n: &mut Node) -> Vec<Event> {
        std::iter::from_fn(|| n.poll_event()).collect()
    }

    /// The messages in a datagram or a frame, as debug text.
    fn opened(t: &Transmit) -> Vec<String> {
        let (kind, mut bytes) = match t {
            Transmit::Datagram { payload, .. } => (PacketKind::Datagram, payload.clone()),
            Transmit::Stream { frame, .. } => (PacketKind::Stream, frame[4..].to_vec()),
            _ => return Vec::new(),
        };
        let payload = plaintext().open(kind, &mut bytes).unwrap();
        payload.iter().map(|m| format!("{m:?}")).collect()
    }

    /// The type of each message in `msgs`, as `opened` writes them.
    fn kinds(msgs: &[String]) -> Vec<&str> {
        msgs.iter()
            .map(|m| m.split(['(', ' ']).next().unwrap())
            .collect()
    }

    fn done(n: &mut Node, cmd: Command) -> Result<CommandOutput, CommandError> {
        let id = n.command(n.now, cmd);
        events(n)
            .into_iter()
            .find_map(|e| match e {
                Event::CommandDone { id: done, result } if done == id => Some(result),
                _ => None,
            })
            .unwrap()
    }

    fn send(
        n: &mut Node,
        to: &str,
        epoch: u64,
        data: &[u8],
    ) -> Result<CommandOutput, CommandError> {
        let to = to.to_owned();
        let data = data.to_vec();
        done(n, Command::Send { to, epoch, data })
    }

    /// The data of the user messages among `events`.
    fn delivered(events: &[Event]) -> Vec<&[u8]> {
        events
            .iter()
            .filter_map(|e| match e {
                Event::UserMessage { data, .. } => Some(&data[..]),
                _ => None,
            })
            .collect()
    }

    #[test]
    fn a_small_message_goes_in_one_datagram_without_gossip() {
        let mut n = node();
        n.add_member(Instant::ZERO, "b", addr(2)).unwrap();
        // A rumour about d waits to be gossiped, and a's own Alive is still news.
        deliver(&mut n, &[alive("d", 4, 3)]);
        events(&mut n);
        sent(&mut n);
        assert_eq!(send(&mut n, "b", 0, b"hello"), Ok(CommandOutput::Done));
        let out = sent(&mut n);
        let [t @ Transmit::Datagram { to, .. }] = &out[..] else {
            panic!("{out:?}");
        };
        assert_eq!(*to, addr(2));
        let msgs = opened(t);
        assert_eq!(kinds(&msgs), ["Alive", "UserMessage"], "{msgs:?}");
        assert!(msgs[0].contains(r#"node: "a""#), "{msgs:?}");
        assert!(msgs[1].contains(r#"to: "b", to_epoch: 0, from: "a", from_epoch: 100"#));
        // Once a's Alive has spread, the message goes alone.
        n.out.broadcasts.forget("a");
        send(&mut n, "b", 0, b"again").unwrap();
        assert_eq!(kinds(&opened(&sent(&mut n)[0])), ["UserMessage"]);
        assert_eq!(n.metrics().user_messages_sent, 2);
        assert!(
            n.out.broadcasts.contains("d"),
            "the rumour still waits for gossip"
        );
    }

    #[test]
    fn a_message_is_delivered_once_its_sender_is_known() {
        let mut n = node();
        deliver(&mut n, &[message("a", 100, "b", 7, b"hi")]);
        assert_eq!(n.metrics().user_messages_dropped, 1, "from a stranger");
        assert!(events(&mut n).is_empty());
        // With b's Alive in the packet, even behind the message, b is known by then.
        deliver(
            &mut n,
            &[message("a", 100, "b", 7, b"hi"), alive("b", 2, 7)],
        );
        let ev = events(&mut n);
        assert!(
            matches!(&ev[..], [Event::MemberJoined(_), Event::UserMessage { sender, data, broadcast: false }]
                if sender.name == "b" && sender.epoch == 7 && data == b"hi"),
            "{ev:?}"
        );
        // Receiving a message sends nothing back.
        assert_eq!(sent(&mut n), []);
        // From another run of b than the one held: neither earlier nor later counts.
        deliver(&mut n, &[message("a", 100, "b", 6, b"old")]);
        deliver(&mut n, &[message("a", 100, "b", 8, b"new")]);
        assert!(events(&mut n).is_empty());
        assert_eq!(n.metrics().user_messages_dropped, 3);
        // One sent just before b left still arrives, from b as a's tombstone of it.
        deliver(&mut n, &[left("b", 7), message("a", 100, "b", 7, b"bye")]);
        let ev = events(&mut n);
        assert!(
            matches!(&ev[..], [Event::MemberLeft(_), Event::UserMessage { sender, .. }]
                if sender.state == State::Left),
            "{ev:?}"
        );
        assert_eq!(n.metrics().user_messages_received, 2);
    }

    #[test]
    fn a_message_for_another_name_or_an_earlier_run_is_dropped() {
        let mut n = node();
        deliver(&mut n, &[alive("b", 2, 7)]);
        events(&mut n);
        let to = |n: &mut Node, name: &str, epoch: u64| {
            deliver(n, &[message(name, epoch, "b", 7, b"m")]);
            delivered(&events(n)).len()
        };
        assert_eq!(to(&mut n, "a", 100), 1);
        assert_eq!(to(&mut n, "a", 0), 1, "a sender that knows no epoch for a");
        assert_eq!(to(&mut n, "a", 99), 0, "an earlier run of a");
        assert_eq!(to(&mut n, "c", 100), 0, "replayed here from another member");
        // A node that moved past a later life of its name takes messages for either run.
        deliver(&mut n, &[alive("a", 1, 150)]);
        assert_eq!(n.local().epoch, 151);
        assert_eq!(to(&mut n, "a", 151), 1);
        assert_eq!(to(&mut n, "a", 100), 1);
        assert_eq!(to(&mut n, "a", 150), 0);
        assert_eq!(n.metrics().user_messages_dropped, 3);
    }

    #[test]
    fn sends_are_refused_unless_the_member_is_held_live_at_that_epoch() {
        let mut n = node();
        deliver(&mut n, &[alive("b", 2, 7), alive("c", 3, 9)]);
        deliver(&mut n, &[left("c", 9)]);
        events(&mut n);
        sent(&mut n);
        let refused = Err(CommandError::NotAMember);
        assert_eq!(send(&mut n, "x", 0, b"m"), refused, "unknown");
        assert_eq!(send(&mut n, "a", 0, b"m"), refused, "itself");
        assert_eq!(send(&mut n, "c", 9, b"m"), refused, "left");
        assert_eq!(send(&mut n, "b", 6, b"m"), refused, "an earlier run");
        assert_eq!(send(&mut n, "b", 7, b"m"), Ok(CommandOutput::Done));
        assert_eq!(
            send(&mut n, "b", 0, b"m"),
            Ok(CommandOutput::Done),
            "any run"
        );
        let too_large = Err(CommandError::MessageTooLarge);
        let over = vec![0; n.cfg.max_user_message + 1];
        assert_eq!(send(&mut n, "b", 0, &over), too_large);
        let over = vec![0; n.cfg.max_user_broadcast + 1];
        assert_eq!(done(&mut n, Command::Broadcast(over)), too_large);
        assert_eq!(n.metrics().user_messages_too_large, 2);
        assert_eq!(n.metrics().user_messages_sent, 2);
        n.command(n.now, Command::Leave);
        assert_eq!(send(&mut n, "b", 0, b"m"), Err(CommandError::Left));
        let after = done(&mut n, Command::Broadcast(b"m".to_vec()));
        assert_eq!(after, Err(CommandError::Left));
    }

    #[test]
    fn large_messages_take_one_connection_per_member_at_a_time() {
        let mut cfg = Config::local(Security::InsecurePlaintext);
        cfg.limits.max_stream_frame = 16 * 1024;
        cfg.max_user_message = 6 * 1024;
        let mut n = node_with(cfg, 100);
        deliver(&mut n, &[alive("b", 2, 7)]);
        events(&mut n);
        sent(&mut n);
        let big = |i: u8| vec![i; 5 * 1024];
        send(&mut n, "b", 0, &big(1)).unwrap();
        let out = sent(&mut n);
        let [
            Transmit::Connect { conn, to },
            frame @ Transmit::Stream { .. },
        ] = &out[..]
        else {
            panic!("{out:?}");
        };
        assert_eq!(*to, addr(2));
        assert_eq!(kinds(&opened(frame)), ["Alive", "UserMessage"]);
        let first = *conn;
        // Three wait for it; a fifth would have more than max_stream_frame bytes waiting.
        for i in 2..=5 {
            send(&mut n, "b", 0, &big(i)).unwrap();
        }
        assert_eq!(sent(&mut n), []);
        assert_eq!(n.metrics().user_queue_overflow, 1);
        assert_eq!(n.metrics().user_messages_sent, 1);
        // The receiver closes the first: the three go together on a new connection.
        n.handle_stream(n.now, first, StreamEvent::Closed);
        let out = sent(&mut n);
        let [
            Transmit::Connect { conn, .. },
            frame @ Transmit::Stream { .. },
        ] = &out[..]
        else {
            panic!("{out:?}");
        };
        let second = *conn;
        assert_ne!(second, first);
        let msgs = opened(frame);
        assert_eq!(
            kinds(&msgs),
            ["Alive", "UserMessage", "UserMessage", "UserMessage"]
        );
        assert!(msgs[1].contains("data: [2, 2") && msgs[3].contains("data: [4, 4"));
        assert_eq!(n.metrics().user_messages_sent, 4);
        // That one fails, and its three count as dropped.
        n.handle_stream(n.now, second, StreamEvent::Failed);
        assert_eq!(n.metrics().user_messages_dropped, 3);
        assert_eq!(sent(&mut n), []);
        assert!(n.user.targets.is_empty() && n.user.streams.is_empty());
        assert_eq!(n.user.waiting_bytes, 0);
        // One the receiver never closes times out the same way.
        send(&mut n, "b", 0, &big(6)).unwrap();
        sent(&mut n);
        n.handle_timeout(n.now + n.cfg.tcp_timeout);
        assert_eq!(n.metrics().user_messages_dropped, 4);
        assert!(n.user.targets.is_empty() && n.user.streams.is_empty());
    }

    #[test]
    fn waiting_messages_for_a_member_that_restarted_are_dropped() {
        let mut cfg = Config::local(Security::InsecurePlaintext);
        cfg.limits.max_stream_frame = 16 * 1024;
        cfg.max_user_message = 6 * 1024;
        let mut n = node_with(cfg, 100);
        deliver(&mut n, &[alive("b", 2, 7)]);
        sent(&mut n);
        send(&mut n, "b", 0, &[1; 5000]).unwrap();
        let Transmit::Connect { conn, .. } = sent(&mut n)[0] else {
            panic!();
        };
        send(&mut n, "b", 0, &[2; 5000]).unwrap();
        // b restarts while its message waits: that message was for the old run.
        deliver(&mut n, &[alive("b", 2, 8)]);
        n.handle_stream(n.now, conn, StreamEvent::Closed);
        assert_eq!(sent(&mut n), []);
        assert_eq!(n.metrics().user_messages_dropped, 1);
        assert!(n.user.targets.is_empty());
    }

    #[test]
    fn a_frame_of_messages_is_delivered_and_closed() {
        let mut n = node();
        let msgs = [
            alive("b", 2, 7),
            message("a", 100, "b", 7, b"one"),
            message("a", 100, "b", 7, b"two"),
        ];
        let mut frame = Vec::new();
        plaintext()
            .seal(PacketKind::Stream, &msgs, &nonce(), &mut frame)
            .unwrap();
        let conn = StreamId::inbound(0);
        n.handle_stream(n.now, conn, StreamEvent::Frame(&frame));
        let ev = events(&mut n);
        assert!(matches!(&ev[0], Event::MemberJoined(m) if m.name == "b"));
        assert_eq!(delivered(&ev), [b"one", b"two"]);
        assert_eq!(sent(&mut n), [Transmit::Close { conn }]);
    }

    #[test]
    fn broadcasts_ride_behind_the_rumours_and_only_to_live_members() {
        let mut n = node();
        deliver(&mut n, &[alive("b", 2, 7), alive("c", 3, 9)]);
        let dead = Message::Dead(Dead {
            inc: 0,
            node: id("c"),
            from: id("b"),
            epoch: 9,
        });
        deliver(&mut n, &[dead]);
        events(&mut n);
        sent(&mut n);
        done(&mut n, Command::Broadcast(b"hello".to_vec())).unwrap();
        n.gossip(n.now);
        let out = sent(&mut n);
        assert_eq!(out.len(), 2, "b, and c recently dead: {out:?}");
        for t in &out {
            let Transmit::Datagram { to, .. } = t else {
                panic!("{t:?}");
            };
            let msgs = opened(t);
            let kinds = kinds(&msgs);
            if *to == addr(2) {
                let (last, rumours) = kinds.split_last().unwrap();
                assert_eq!(*last, "UserBroadcast");
                assert!(!rumours.is_empty() && !rumours.contains(&"UserBroadcast"));
            } else {
                assert_eq!(*to, addr(3));
                assert!(!kinds.contains(&"UserBroadcast"), "c is not live");
            }
        }
    }

    #[test]
    fn a_broadcast_is_sent_as_often_as_a_rumour_then_dropped() {
        let mut n = node();
        deliver(&mut n, &[alive("b", 2, 7), alive("c", 3, 9)]);
        sent(&mut n);
        done(&mut n, Command::Broadcast(b"x".to_vec())).unwrap();
        let limit = n.retransmit_limit() as usize;
        let mut copies = 0;
        while !n.out.user.is_empty() {
            n.gossip(n.now);
            for t in sent(&mut n) {
                let msgs = opened(&t);
                copies += kinds(&msgs)
                    .iter()
                    .filter(|&&k| k == "UserBroadcast")
                    .count();
            }
        }
        assert_eq!(copies, limit);
    }

    #[test]
    fn copies_are_told_apart_by_sender_epoch_and_number() {
        let mut n = node();
        deliver(&mut n, &[alive("b", 2, 7)]);
        events(&mut n);
        let got = |n: &mut Node, msgs: &[Message<'_>]| {
            deliver(n, msgs);
            delivered(&events(n)).len()
        };
        assert_eq!(got(&mut n, &[broadcast("b", 7, 1, b"one")]), 1);
        assert_eq!(got(&mut n, &[broadcast("b", 7, 1, b"one")]), 0, "a copy");
        assert_eq!(n.out.user.len(), 1, "relayed once");
        let two = [broadcast("b", 7, 3, b"three"), broadcast("b", 7, 2, b"two")];
        assert_eq!(got(&mut n, &two), 2, "out of order");
        assert_eq!(got(&mut n, &[broadcast("b", 7, 300, b"far")]), 1);
        assert_eq!(
            got(&mut n, &[broadcast("b", 7, 44, b"x")]),
            0,
            "too far behind"
        );
        assert_eq!(
            got(&mut n, &[broadcast("b", 7, 45, b"x")]),
            1,
            "just inside"
        );
        assert_eq!(n.metrics().user_messages_dropped, 1);
        // b restarts, and its new run numbers from 1 again; the old run's copies are stale.
        deliver(&mut n, &[alive("b", 2, 8)]);
        assert_eq!(got(&mut n, &[broadcast("b", 8, 1, b"again")]), 1);
        assert_eq!(got(&mut n, &[broadcast("b", 7, 4, b"four")]), 0);
        assert_eq!(n.metrics().user_messages_dropped, 2);
        // This node's own coming back are ignored, and not counted.
        assert_eq!(got(&mut n, &[broadcast("a", 100, 1, b"mine")]), 0);
        assert_eq!(n.metrics().user_messages_dropped, 2);
        assert_eq!(n.metrics().user_messages_received, 6);
    }

    #[test]
    fn a_broadcast_from_a_stranger_waits_for_its_alive() {
        let mut n = node();
        deliver(&mut n, &[broadcast("b", 7, 1, b"early")]);
        assert_eq!(n.metrics().user_messages_dropped, 1);
        assert!(n.out.user.is_empty(), "nor relayed, nor remembered");
        deliver(&mut n, &[broadcast("b", 7, 1, b"early"), alive("b", 2, 7)]);
        assert_eq!(delivered(&events(&mut n)), [b"early"]);
        // Over this node's limit: dropped alone, not relayed.
        let over = vec![0; n.cfg.max_user_broadcast + 1];
        let msgs = [broadcast("b", 7, 2, &over), broadcast("b", 7, 3, b"ok")];
        deliver(&mut n, &msgs);
        assert_eq!(delivered(&events(&mut n)), [b"ok"]);
        assert_eq!(n.metrics().user_messages_too_large, 1);
        assert_eq!(n.out.user.len(), 2);
    }

    #[test]
    fn a_full_queue_drops_the_entry_nearest_to_done() {
        let b = |seq| Broadcast {
            from: "b".to_owned(),
            from_epoch: 1,
            seq,
            data: Vec::new(),
            sig: None,
            cert: None,
        };
        let seqs = |q: &UserQueue| -> Vec<u64> {
            let picked = q.select(usize::MAX);
            picked.into_iter().map(|r| q.broadcast(r).seq).collect()
        };
        let mut q = UserQueue::default();
        assert!(q.push(b(1), 2) && q.push(b(2), 2));
        // None has been sent: the new one goes.
        assert!(!q.push(b(3), 2));
        assert_eq!(seqs(&q), [1, 2], "oldest first");
        // 1 has been sent: it is nearest to done.
        let first = q.select(usize::MAX)[..1].to_vec();
        q.sent(&first, 5);
        assert!(!q.push(b(4), 2));
        assert_eq!(seqs(&q), [2, 4]);
        let all = q.select(usize::MAX);
        q.sent(&all, 1);
        assert!(q.is_empty());

        let mut cfg = Config::local(Security::InsecurePlaintext);
        cfg.user_broadcast_queue = 2;
        let mut n = node_with(cfg, 100);
        for i in 0..3 {
            done(&mut n, Command::Broadcast(vec![i])).unwrap();
        }
        assert_eq!(n.metrics().user_queue_overflow, 1);
        assert_eq!(n.metrics().user_messages_sent, 3);
        assert_eq!(n.out.user.len(), 2);
    }

    #[test]
    fn the_seen_window_starts_over_with_each_life() {
        let mut s = Seen::new(5, 10);
        assert_eq!(s.check(5, 10), Copy::Seen);
        assert_eq!(s.check(5, 9), Copy::New);
        assert_eq!(s.check(5, 9), Copy::Seen);
        assert_eq!(s.check(5, 10 + SEEN_WINDOW), Copy::New);
        assert_eq!(s.check(5, 10), Copy::TooOld);
        assert_eq!(s.check(5, 11), Copy::New, "slots passed over are cleared");
        assert_eq!(s.check(5, 12 + SEEN_WINDOW), Copy::New);
        assert_eq!(s.check(5, 11), Copy::TooOld);
        assert_eq!(s.check(5, 12), Copy::TooOld);
        assert_eq!(s.check(5, 13), Copy::New);
        assert_eq!(s.check(6, 1), Copy::New, "a new life");
        assert_eq!(s.check(6, 1), Copy::Seen);
        assert_eq!(s.check(6, 13), Copy::New);
    }

    #[test]
    fn what_was_seen_of_a_member_goes_with_its_tombstone() {
        let mut n = node();
        deliver(&mut n, &[alive("b", 2, 7), broadcast("b", 7, 1, b"x")]);
        assert!(n.user.seen.contains_key("b"));
        deliver(&mut n, &[left("b", 7)]);
        let keep = n.cfg.dead_reclaim.max(n.replay.window());
        let later = n.now + keep + n.probe_interval() * 2;
        while let Some(at) = n.poll_timeout().filter(|&at| at <= later) {
            n.handle_timeout(at);
            sent(&mut n);
        }
        assert!(n.member("b").is_none());
        assert!(n.user.seen.is_empty());
    }
}
