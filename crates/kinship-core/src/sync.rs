//! The stream half of the protocol: push-pull state exchange and merge, join, periodic
//! anti-entropy, reconnects to recently dead members, the TCP fallback ping, and leaving.
//!
//! Every exchange is one short-lived connection. The side that opens it writes one frame and
//! waits for one frame back; the side that accepts it answers the first frame and closes. The
//! accepting side keeps no state between the two, so a peer that opens many connections costs
//! nothing beyond the frames it actually sends, and those are bounded by `max_stream_frame`
//! before the driver buffers them and again before the core copies them.
//!
//! A digest exchange (`docs/pushpull-digest.md`) takes one frame more: the side that opened it
//! sends a digest of every member it holds, the accepting side answers with the records it
//! holds later and the names whose records it wants, and when it wants some it keeps the
//! connection open, for at most `tcp_timeout` and at most [`MAX_AWAITING`] connections at once,
//! until the opener sends those records and closes.

use core::net::SocketAddr;
use core::time::Duration;
use std::collections::BTreeMap;

use std::collections::BTreeSet;

use kinship_proto::identity::CertificateId;
use kinship_proto::v2;
use kinship_proto::{
    Alive, Dead, DigestEntries, DigestEntry, Message, Names, PacketKind, Ping, PushPull,
    PushPullDigest, PushPullWants, Record, Records, VersionedPayload, WireVersion, feature,
};

use crate::broadcast::{Gossip, id};
use crate::config::Config;
use crate::event::{CommandError, CommandId, CommandOutput, Event};
use crate::io::{StreamEvent, StreamId, Transmit};
use crate::member::{Admission, Life, State, life, newer};
use crate::replay::stamp_of;
use crate::signing::{Keys, LeftProof, packet_certs, signed_alive};
use crate::table::Entry;
use crate::time::Instant;
use crate::{Node, Stamp};

/// Why this node opened a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Purpose {
    /// Seed `seed` of the join started by command `cmd`.
    Join { cmd: CommandId, seed: usize },
    /// Periodic anti-entropy with a live member, or a reconnect to a dead one.
    Sync,
    /// The TCP fallback ping of the probe round with this sequence number.
    Ping { seq: u32 },
    /// User messages too large for a datagram; the receiver closes once it handled them.
    Message,
}

/// A connection this node opened and is waiting on.
#[derive(Debug, Clone)]
pub(crate) struct Outbound {
    purpose: Purpose,
    deadline: Instant,
    to: SocketAddr,
    /// The cluster time this node's frame was sealed at.
    stamp: u64,
    /// This exchange repeats one the peer answered as stale; it is not repeated again.
    repeat: bool,
    /// The wire version its frames are sealed at: 2 for the exchange of signed records with a
    /// member that speaks it, 1 otherwise.
    version: WireVersion,
    /// The exchange started with a digest, so the reply carries the names the peer wants.
    digest: bool,
}

/// Most connections a peer opened that wait for the records their digest's answer asked for.
/// Each holds only a deadline, and the driver bounds the connections it accepts far below
/// this; a digest beyond it is answered without asking for any.
pub(crate) const MAX_AWAITING: usize = 1024;

/// A join in progress.
#[derive(Debug, Clone)]
pub(crate) struct Join {
    seeds: Vec<Seed>,
    answered: usize,
}

#[derive(Debug, Clone)]
struct Seed {
    addr: SocketAddr,
    attempts: u32,
    state: SeedState,
    /// Exchanges of the current attempt still open: two when a signing node tries version 2,
    /// the exchange of signed records and the version 1 one beside it.
    inflight: u32,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SeedState {
    /// An attempt is in flight.
    Trying,
    /// The last attempt failed; the next one starts at this instant.
    Waiting(Instant),
    Answered,
    /// Every attempt failed.
    Failed,
}

/// Connections, joins and the anti-entropy timers.
#[derive(Debug)]
pub(crate) struct Sync {
    pub streams: BTreeMap<StreamId, Outbound>,
    next_stream: u64,
    pub joins: BTreeMap<CommandId, Join>,
    /// Connections a peer opened whose digest this node answered with names it wants, each
    /// with the instant it stops waiting for their records.
    pub awaiting: BTreeMap<StreamId, Instant>,
    push_pull: Option<SyncTimer>,
    next_reconnect: Option<Instant>,
    /// The Leave command waiting for this node's Left rumour to finish spreading.
    pub leaving: Option<CommandId>,
}

impl Sync {
    /// Timers start at `first_push_pull` and `first_reconnect`; `None` disables them.
    pub fn new(first_push_pull: Option<Instant>, first_reconnect: Option<Instant>) -> Self {
        Self {
            streams: BTreeMap::new(),
            next_stream: 0,
            joins: BTreeMap::new(),
            awaiting: BTreeMap::new(),
            push_pull: first_push_pull.map(SyncTimer::First),
            next_reconnect: first_reconnect,
            leaving: None,
        }
    }
}

/// The periodic push-pull timer.
#[derive(Clone, Copy, Debug)]
enum SyncTimer {
    /// The first one, staggered within `push_pull_interval` of the start.
    First(Instant),
    /// The instant the last one was due. The next is due one interval for the current number
    /// of live members later, so it moves as the cluster grows or shrinks.
    Last(Instant),
}

/// The state a push-pull record carries for `state`.
fn wire_state(state: State) -> kinship_proto::State {
    match state {
        State::Alive => kinship_proto::State::Alive,
        State::Suspect => kinship_proto::State::Suspect,
        State::Dead => kinship_proto::State::Dead,
        State::Left => kinship_proto::State::Left,
    }
}

/// What a node holds about a member, as a digest lists it: state, incarnation and epoch.
type Held = (kinship_proto::State, u32, u64);

fn held(e: &Entry) -> Held {
    (
        wire_state(e.member.state),
        e.member.incarnation,
        e.member.epoch,
    )
}

/// How a state ranks against another at the same incarnation: a Suspect wins over Alive, and
/// Dead and Left over both, while neither of those two changes the other.
fn rank(state: kinship_proto::State) -> u8 {
    match state {
        kinship_proto::State::Alive => 0,
        kinship_proto::State::Suspect => 1,
        kinship_proto::State::Dead | kinship_proto::State::Left => 2,
    }
}

/// Whether a record held at `x` could change anything at a node that holds the same member at
/// `y`, when merged as a push-pull merges it: it is a later life, or the same life at a newer
/// incarnation, or the same incarnation in a state that wins. Where the two cannot be ordered,
/// as when one side does not know the epoch, it says yes, so that both records cross and each
/// side merges the other's as a full exchange would; equal entries send nothing, since an
/// equal epoch, incarnation and state mean an equal record.
fn teaches(x: Held, y: Held) -> bool {
    let ((xs, xi, xe), (ys, yi, ye)) = (x, y);
    if x == y {
        return false;
    }
    if xe != ye {
        // `Same` here means one of them is 0, unknown.
        return life(xe, ye) != Life::Earlier;
    }
    if newer(xi, yi) {
        true
    } else if newer(yi, xi) {
        false
    } else {
        // Equal, or exactly 2^31 apart and so unordered.
        xi != yi || rank(xs) > rank(ys)
    }
}

/// The push-pull record of `e`.
fn record(e: &Entry) -> Record<'_> {
    Record {
        state: wire_state(e.member.state),
        alive: Alive {
            inc: e.member.incarnation,
            node: id(&e.member.name),
            addr: e.member.addr,
            meta: &e.member.meta,
            vmin: e.vmin,
            vmax: e.vmax,
            epoch: e.member.epoch,
            features: e.features,
        },
    }
}

/// The first tick of `interval` after `now` that follows `prev`, skipping missed ones.
fn next_tick(prev: Instant, now: Instant, interval: Duration) -> Instant {
    let missed = (now - prev).as_nanos() / interval.as_nanos();
    prev + interval * u32::try_from(missed + 1).unwrap_or(u32::MAX)
}

/// The anti-entropy period with `live` live members: scaled in mode `off` if `push_pull_scale`
/// is set, and `push_pull_interval` in mode `sign`, whose repairs lean on push-pull more. A signing node
/// learns certificates from version 2 records and drops the signed rumours of members it holds
/// without one, a Left included; and the Acks of a member's later life, under a key it does not
/// hold yet, cannot refute its suspicion of the earlier one, so a node that gossip missed
/// learns of the restart only from push-pull. The 1,000-seed sweeps in mode `sign` found both
/// with a scaled period (`docs/results/pushpull.md`).
fn push_pull_period(cfg: &Config, live: usize, signing: bool) -> Duration {
    if signing {
        cfg.push_pull_interval
    } else {
        cfg.push_pull_interval_for(live)
    }
}

/// The last tick of `interval` at or before `now`, counting from `due`, skipping missed ones.
fn last_tick(due: Instant, now: Instant, interval: Duration) -> Instant {
    let missed = (now - due).as_nanos() / interval.as_nanos();
    due + interval.saturating_mul(u32::try_from(missed).unwrap_or(u32::MAX))
}

impl Node {
    pub(crate) fn has_left(&self) -> bool {
        self.local.member.state == State::Left
    }

    /// Something happened on a connection.
    pub(crate) fn on_stream(&mut self, conn: StreamId, ev: StreamEvent<'_>) {
        match ev {
            StreamEvent::Frame(frame) => self.on_frame(conn, frame),
            StreamEvent::Closed | StreamEvent::Failed => {
                // A peer that closes before sending the records it was asked for sends none.
                self.sync.awaiting.remove(&conn);
                if let Some(o) = self.sync.streams.remove(&conn) {
                    if o.purpose == Purpose::Message {
                        // The receiver closes once it has handled the messages.
                        self.user_stream_ended(conn, ev == StreamEvent::Closed);
                    } else {
                        // The peer hung up or the connection broke before it answered.
                        self.exchange_failed(o.purpose);
                    }
                }
            }
        }
    }

    fn on_frame(&mut self, conn: StreamId, frame: &[u8]) {
        let now = self.now;
        if !conn.is_inbound() && !self.sync.streams.contains_key(&conn) {
            // A late frame on a connection this node already gave up on.
            return;
        }
        // The records that this node's answer to a digest asked for, on the connection it kept
        // open for them; whatever else the frame holds, it is the last.
        let wanted = self.sync.awaiting.remove(&conn).is_some();
        // Checked before the copy below, as the driver's framer already did before buffering.
        if frame.len() > self.cfg.limits.max_stream_frame {
            self.metrics.decode_errors += 1;
            return self.end_stream(conn, false);
        }
        let stamp = self.check_stamp(frame);
        if matches!(stamp, Stamp::TooFarAhead) {
            self.metrics.replays_dropped += 1;
            return self.end_stream(conn, false);
        }
        if matches!(stamp, Stamp::Stale) && !conn.is_inbound() {
            // The peer sealed its reply after reading this node's request and catching up with
            // it, so a stale reply is a recording.
            self.metrics.replays_dropped += 1;
            return self.end_stream(conn, false);
        }
        let mut scratch = std::mem::take(&mut self.recv_buf);
        scratch.clear();
        scratch.extend_from_slice(frame);
        // Mode `sign` opens version 2 frames too, by the envelope's version.
        let opened = if self.keys.is_some() {
            self.out
                .codec
                .open_versioned(PacketKind::Stream, &mut scratch)
        } else {
            self.out
                .codec
                .open(PacketKind::Stream, &mut scratch)
                .map(VersionedPayload::V1)
        };
        let answered = match opened {
            Ok(_) if matches!(stamp, Stamp::Stale) && wanted => {
                // The opener caught up with this node's answer before it sealed these.
                self.metrics.replays_dropped += 1;
                false
            }
            Ok(payload) if matches!(stamp, Stamp::Stale) => {
                // An authentic request from a node that has fallen behind cluster time: one that
                // just started, or a recording. Merge nothing, and answer a push-pull or a
                // digest with this node's own record only: a real joiner catches up from it and
                // asks again.
                self.metrics.replays_dropped += 1;
                match payload {
                    VersionedPayload::V1(payload) => {
                        let push_pull = payload.iter().any(|m| {
                            matches!(m, Message::PushPull(_) | Message::PushPullDigest(_))
                        });
                        push_pull && self.send_state(conn, false, false)
                    }
                    VersionedPayload::V2(payload) => {
                        let known = payload.iter().find_map(|m| match m {
                            v2::Message::PushPull(p) => Some(p.known_certificates),
                            _ => None,
                        });
                        known.is_some_and(|known| {
                            self.send_signed_state(conn, false, false, Some(known))
                        })
                    }
                }
            }
            Ok(payload) => {
                if self.accept_stamp(&stamp) {
                    self.metrics.packets_received += 1;
                    let reply_stamp = match stamp {
                        Stamp::Fresh(nonce) => Some(stamp_of(&nonce)),
                        _ => None,
                    };
                    match payload {
                        VersionedPayload::V1(payload) if wanted => self.on_wanted(now, &payload),
                        VersionedPayload::V1(payload) => {
                            self.on_frame_v1(now, conn, &payload, reply_stamp)
                        }
                        VersionedPayload::V2(_) if wanted => false,
                        VersionedPayload::V2(payload) => {
                            // Direct messages are signed over the frame's nonce.
                            let nonce = kinship_proto::sealed_nonce(frame);
                            self.on_frame_v2(now, conn, &payload, reply_stamp, nonce.as_ref())
                        }
                    }
                } else {
                    false
                }
            }
            Err(e) => {
                self.count_error(&e);
                false
            }
        };
        self.recv_buf = scratch;
        if self.sync.awaiting.contains_key(&conn) {
            // Answered a digest, and waits for the records it asked for.
            return;
        }
        self.end_stream(conn, answered);
    }

    /// Handles an authenticated version 1 frame. True if it was answered, or was the reply.
    fn on_frame_v1(
        &mut self,
        now: Instant,
        conn: StreamId,
        payload: &kinship_proto::Payload<'_>,
        reply_stamp: Option<u64>,
    ) -> bool {
        // Every record in the frame shares one admission budget for new members.
        let mut budget = self.admission();
        if let Some(out) = self.sync.streams.get(&conn).filter(|o| o.digest).cloned() {
            return self.on_digest_reply(now, conn, &out, payload, reply_stamp, &mut budget);
        }
        let mut answered = false;
        // User messages wait for the rest, so that an Alive in the frame introduces their
        // sender; only a connection a peer opened carries them.
        let mut user = Vec::new();
        for msg in payload.iter() {
            if matches!(msg, Message::UserMessage(_) | Message::UserBroadcast(_)) {
                if conn.is_inbound() {
                    user.push(msg);
                }
                continue;
            }
            answered = if conn.is_inbound() {
                self.serve(now, conn, &msg, &mut budget)
            } else {
                self.on_reply(now, conn, &msg, reply_stamp, &mut budget)
            };
            if answered {
                break;
            }
        }
        for msg in &user {
            self.on_user(msg);
        }
        answered
    }

    /// Handles an authenticated version 2 frame sealed with `nonce`: a push-pull of signed
    /// records and the certificates beside it, a TCP fallback Ping and its Ack, or a sender's
    /// signed Alive and its direct messages. True if it was answered, or was the reply.
    fn on_frame_v2(
        &mut self,
        now: Instant,
        conn: StreamId,
        payload: &v2::Payload<'_>,
        reply_stamp: Option<u64>,
        nonce: Option<&[u8; 24]>,
    ) -> bool {
        let certs = packet_certs(payload.iter().filter_map(|m| match m {
            v2::Message::Certificate(c) => Some(c),
            _ => None,
        }));
        let mut budget = self.admission();
        if let Some(ping) = payload
            .iter()
            .find(|m| matches!(m, v2::Message::Ping { .. }))
        {
            if conn.is_inbound() {
                let me = self.local.member.name.clone();
                if let Some(ack) = self.signed_ack(&ping, &me) {
                    self.out.frame_v2(conn, &[ack]);
                }
                return true;
            }
            return false;
        }
        if let Some(ack) = payload
            .iter()
            .find(|m| matches!(m, v2::Message::Ack { .. }))
        {
            let v2::Message::Ack { seq: acked, .. } = ack else {
                return false;
            };
            let purpose = self.sync.streams.get(&conn).map(|o| o.purpose);
            if purpose != Some(Purpose::Ping { seq: acked }) {
                return false;
            }
            if self.on_signed_ack(&ack, &certs) {
                self.metrics.tcp_ping_acks += 1;
            }
            return true;
        }
        let Some(p) = payload.iter().find_map(|m| match m {
            v2::Message::PushPull(p) => Some(p),
            _ => None,
        }) else {
            if conn.is_inbound() {
                // A sender's signed Alive ahead of its direct messages, which ask for no answer.
                let mut user = Vec::new();
                for msg in payload.iter() {
                    match msg {
                        v2::Message::Alive(sa) => {
                            self.on_signed_alive(now, &sa, &certs, &mut budget, false);
                        }
                        v2::Message::UserMessage { .. } | v2::Message::UserBroadcast { .. } => {
                            user.push(msg);
                        }
                        _ => {}
                    }
                }
                self.on_signed_users(&user, &certs, nonce);
            }
            return false;
        };
        if conn.is_inbound() {
            self.merge_v2(now, p.records, &certs, &mut budget);
            if self.send_signed_state(conn, false, true, Some(p.known_certificates)) {
                self.metrics.push_pulls_served += 1;
            }
            self.joined |= p.join;
            return true;
        }
        let Some(out) = self.sync.streams.get(&conn).cloned() else {
            return false;
        };
        match out.purpose {
            Purpose::Join { .. } | Purpose::Sync => {
                self.merge_v2(now, p.records, &certs, &mut budget);
                self.pulled(&out, reply_stamp)
            }
            Purpose::Ping { .. } | Purpose::Message => false,
        }
    }

    /// Answers the first frame of a connection a peer opened. True if `msg` was answered.
    fn serve(
        &mut self,
        now: Instant,
        conn: StreamId,
        msg: &Message<'_>,
        budget: &mut Admission,
    ) -> bool {
        match msg {
            Message::PushPull(p) => {
                self.merge(now, p.records, budget);
                if self.send_state(conn, false, true) {
                    self.metrics.push_pulls_served += 1;
                }
                // Answering a join completes it on this side too.
                self.joined |= p.join;
                true
            }
            Message::PushPullDigest(d) => {
                self.answer_digest(conn, d, budget);
                self.joined |= d.join;
                true
            }
            Message::Ping(p) => {
                if p.target.as_str() == self.local.member.name {
                    self.out.frame(conn, &[Message::Ack { seq: p.seq }]);
                } else {
                    self.metrics.misdirected += 1;
                }
                true
            }
            // The sender's Alive ahead of its user messages, which asks for no answer.
            Message::Alive(a) => {
                self.on_alive(now, a, budget, None);
                false
            }
            _ => false,
        }
    }

    /// Handles the reply on a connection this node opened. True if `msg` was the reply.
    /// `stamp` is the cluster time the reply was sealed at, when encrypted.
    fn on_reply(
        &mut self,
        now: Instant,
        conn: StreamId,
        msg: &Message<'_>,
        stamp: Option<u64>,
        budget: &mut Admission,
    ) -> bool {
        let Some(out) = self.sync.streams.get(&conn).cloned() else {
            return false;
        };
        let purpose = out.purpose;
        match (purpose, msg) {
            (Purpose::Join { .. } | Purpose::Sync, Message::PushPull(p)) => {
                self.merge(now, p.records, budget);
                self.pulled(&out, stamp)
            }
            (Purpose::Ping { seq }, Message::Ack { seq: acked }) if seq == *acked => {
                // A version 1 Ack answers no version 2 round.
                let v1 =
                    |p: &&mut crate::probe::Probe| p.seq == seq && !p.acked && p.signed.is_none();
                if let Some(p) = self.probe.as_mut().filter(v1) {
                    p.acked = true;
                    self.metrics.tcp_ping_acks += 1;
                }
                true
            }
            _ => false,
        }
    }

    /// Answers a digest on `conn`: a push-pull of the records this node holds later than the
    /// digest lists them, or holds where it lists none, and the names whose records it wants.
    /// It wants a name the digest lists later than this node holds it, and one it does not
    /// hold only if listed Alive, as a merge adds no other, and only while `budget` and the
    /// table have room for it (KI-04); likewise it sends the record of a member the digest
    /// does not list only if it holds the member Alive. When it wants any, it keeps the
    /// connection open for their records.
    ///
    /// A Suspect, Dead or Left entry about this node needs nothing but what the digest says,
    /// and is refuted before the answer, as a full exchange's merge would be, so that the
    /// answer carries the refutation.
    fn answer_digest(&mut self, conn: StreamId, d: &PushPullDigest<'_>, budget: &mut Admission) {
        let theirs: BTreeMap<&str, DigestEntry<'_>> =
            d.entries.iter().map(|e| (e.node.as_str(), e)).collect();
        let me = theirs.get(self.local.member.name.as_str());
        if let Some(t) = me.filter(|t| t.state != kinship_proto::State::Alive) {
            self.about_self(t.inc, t.epoch);
        }
        let mut wants = Vec::new();
        if self.sync.awaiting.len() < MAX_AWAITING {
            for t in theirs.values() {
                let name = t.node.as_str();
                let mine = if name == self.local.member.name {
                    Some(&self.local)
                } else {
                    self.table.get(name)
                };
                let want = match mine {
                    Some(e) => teaches((t.state, t.inc, t.epoch), held(e)),
                    None => t.state == kinship_proto::State::Alive && self.admit(budget),
                };
                if want {
                    wants.push(t.node);
                }
            }
        }
        let records: Vec<Record<'_>> = std::iter::once(&self.local)
            .chain(self.table.iter())
            .filter(|e| match theirs.get(e.member.name.as_str()) {
                Some(t) => teaches(held(e), (t.state, t.inc, t.epoch)),
                None => e.member.state == State::Alive,
            })
            .map(record)
            .collect();
        let msgs = [
            Message::PushPull(PushPull {
                join: false,
                records: Records::Slice(&records),
            }),
            Message::PushPullWants(PushPullWants {
                names: Names::Slice(&wants),
            }),
        ];
        let sent = self.out.frame(conn, &msgs);
        drop(records);
        if !sent {
            self.metrics.state_too_large += 1;
            return;
        }
        self.metrics.push_pulls_served += 1;
        if !wants.is_empty() {
            let deadline = self.now + self.cfg.tcp_timeout;
            self.sync.awaiting.insert(conn, deadline);
        }
    }

    /// Handles the reply to a digest this node sent on `conn`: merges its records, then sends
    /// the whole records of the names the peer wants, which closes the exchange. True if it
    /// was the reply.
    fn on_digest_reply(
        &mut self,
        now: Instant,
        conn: StreamId,
        out: &Outbound,
        payload: &kinship_proto::Payload<'_>,
        stamp: Option<u64>,
        budget: &mut Admission,
    ) -> bool {
        let Some(p) = payload.iter().find_map(|m| match m {
            Message::PushPull(p) => Some(p),
            _ => None,
        }) else {
            return false;
        };
        self.merge(now, p.records, budget);
        // A stale answer holds the peer's own record and wants nothing; pulled() asks again.
        let wants = payload.iter().find_map(|m| match m {
            Message::PushPullWants(w) => Some(w.names),
            _ => None,
        });
        if let Some(names) = wants.filter(|n| !n.is_empty() && !self.stale_reply(out, stamp)) {
            self.send_wanted(conn, names);
        }
        self.pulled(out, stamp)
    }

    /// Writes to `conn` the whole records of the members in `names` that this node holds,
    /// itself included, each once, as they stand after the merge of the peer's records.
    fn send_wanted(&mut self, conn: StreamId, names: Names<'_>) {
        let names: BTreeSet<&str> = names.iter().map(|n| n.as_str()).collect();
        let records: Vec<Record<'_>> = std::iter::once(&self.local)
            .chain(self.table.iter())
            .filter(|e| names.contains(e.member.name.as_str()))
            .map(record)
            .collect();
        let msg = Message::PushPull(PushPull {
            join: false,
            records: Records::Slice(&records),
        });
        let sent = self.out.frame(conn, &[msg]);
        drop(records);
        if !sent {
            self.metrics.state_too_large += 1;
        }
    }

    /// Merges the records that this node's answer to a digest asked for, which share one
    /// admission budget, as a push-pull's do. True: the frame was the one awaited.
    fn on_wanted(&mut self, now: Instant, payload: &kinship_proto::Payload<'_>) -> bool {
        let Some(p) = payload.iter().find_map(|m| match m {
            Message::PushPull(p) => Some(p),
            _ => None,
        }) else {
            return false;
        };
        let mut budget = self.admission();
        self.merge(now, p.records, &mut budget);
        true
    }

    /// Whether the peer found this node's request stale, judging by the cluster time `stamp`
    /// it sealed its reply at, and the request was not already the second try.
    fn stale_reply(&self, out: &Outbound, stamp: Option<u64>) -> bool {
        let window = self.replay.window_ms();
        !out.repeat && stamp.is_some_and(|s| s.saturating_sub(out.stamp) > window)
    }

    /// Finishes a push-pull this node opened, once the reply merged. `stamp` is the cluster
    /// time the reply was sealed at, when encrypted. True: the reply was the answer.
    fn pulled(&mut self, out: &Outbound, stamp: Option<u64>) -> bool {
        if self.stale_reply(out, stamp) {
            // The peer found this node's request stale and sent only its own record.
            // This node has caught up from the reply, so it asks again at once.
            self.push_pull_with(out.to, out.purpose, true, out.version, out.digest);
            return true;
        }
        self.metrics.push_pulls += 1;
        if let Purpose::Join { cmd, seed } = out.purpose {
            self.seed_done(self.now, cmd, seed, true);
        }
        true
    }

    /// Closes `conn` after its frame was handled; an outbound exchange that got no usable
    /// reply has failed.
    fn end_stream(&mut self, conn: StreamId, answered: bool) {
        self.sync.awaiting.remove(&conn);
        if let Some(o) = self.sync.streams.remove(&conn) {
            if o.purpose == Purpose::Message {
                // Timed out, or answered with a frame the receiver never sends.
                self.user_stream_ended(conn, false);
            } else if !answered {
                self.exchange_failed(o.purpose);
            }
        }
        self.out.transmits.push_back(Transmit::Close { conn });
    }

    fn exchange_failed(&mut self, purpose: Purpose) {
        match purpose {
            Purpose::Join { cmd, seed } => {
                self.metrics.push_pull_failures += 1;
                self.seed_done(self.now, cmd, seed, false);
            }
            Purpose::Sync => self.metrics.push_pull_failures += 1,
            Purpose::Ping { .. } | Purpose::Message => {}
        }
    }

    /// Merges a peer's member table with the precedence rules, as gossip would.
    ///
    /// As in memberlist, a peer's Dead record becomes a suspicion rather than a death, but not
    /// one this node reports; see [`Node::on_merged_suspicion`]. Records about members this
    /// node does not know only add them if Alive, and only as many as `budget` and
    /// `max_members` allow (KI-04).
    fn merge(&mut self, now: Instant, records: Records<'_>, budget: &mut Admission) {
        for r in records.iter() {
            let a = r.alive;
            match r.state {
                kinship_proto::State::Alive => self.on_alive(now, &a, budget, None),
                kinship_proto::State::Left => self.on_dead(
                    now,
                    &Dead {
                        inc: a.inc,
                        node: a.node,
                        from: a.node,
                        epoch: a.epoch,
                    },
                    None,
                ),
                kinship_proto::State::Suspect | kinship_proto::State::Dead => {
                    self.on_merged_suspicion(now, a.node.as_str(), a.inc, a.epoch);
                }
            }
        }
    }

    /// Writes this node's whole view, tombstones included, to `conn`, or with `full` false its
    /// own record only. False if it does not fit.
    fn send_state(&mut self, conn: StreamId, join: bool, full: bool) -> bool {
        let others = if full { self.table.len() } else { 0 };
        let records: Vec<Record<'_>> = std::iter::once(&self.local)
            .chain(self.table.iter().take(others))
            .map(record)
            .collect();
        let msg = Message::PushPull(PushPull {
            join,
            records: Records::Slice(&records),
        });
        let sent = self.out.frame(conn, &[msg]);
        drop(records);
        if !sent {
            self.metrics.state_too_large += 1;
        }
        sent
    }

    /// Writes the digest of this node's whole view, tombstones included, to `conn`: the state,
    /// incarnation and epoch of every member. False if it does not fit.
    fn send_digest(&mut self, conn: StreamId, join: bool) -> bool {
        let entries: Vec<DigestEntry<'_>> = std::iter::once(&self.local)
            .chain(self.table.iter())
            .map(|e| DigestEntry {
                state: wire_state(e.member.state),
                inc: e.member.incarnation,
                node: id(&e.member.name),
                epoch: e.member.epoch,
            })
            .collect();
        let msg = Message::PushPullDigest(PushPullDigest {
            join,
            entries: DigestEntries::Slice(&entries),
        });
        let sent = self.out.frame(conn, &[msg]);
        drop(entries);
        if !sent {
            self.metrics.state_too_large += 1;
        }
        sent
    }

    /// The capabilities this node advertises in its Alive: digest push-pull with
    /// `push_pull_digest` in mode `off`, once it has an epoch, without which it could not
    /// write them.
    pub(crate) fn own_features(&self) -> u32 {
        let digest =
            self.cfg.push_pull_digest && self.keys.is_none() && self.local.member.epoch != 0;
        if digest { feature::DIGEST_PUSH_PULL } else { 0 }
    }

    /// Whether an exchange with the member `peer` at `to`, or with the member at `to` when no
    /// name is known, as for a seed, starts with a digest: when this node advertises digest
    /// push-pull and holds that member, at that address, advertising it too. A joiner holds
    /// nobody, so a join is a full exchange, and so is one with a member that does not
    /// advertise it, or that this node holds without it.
    fn digest_to(&self, peer: Option<&str>, to: SocketAddr) -> bool {
        let speaks = |e: &Entry| e.member.addr == to && e.features & feature::DIGEST_PUSH_PULL != 0;
        if self.local.features & feature::DIGEST_PUSH_PULL == 0 {
            return false;
        }
        match peer {
            Some(name) => self.table.get(name).is_some_and(speaks),
            None => self.table.iter().any(speaks),
        }
    }

    /// Writes the version 2 push-pull of this node's signed records to `conn`, every member it
    /// holds a proof for, or with `full` false its own only. A request (`known` is `None`)
    /// carries this node's own certificate and the ids of every certificate it holds; a reply
    /// carries the certificates of its records whose ids the request did not list. False if it
    /// does not fit.
    fn send_signed_state(
        &mut self,
        conn: StreamId,
        join: bool,
        full: bool,
        known: Option<v2::CertificateIds<'_>>,
    ) -> bool {
        let Some(keys) = &self.keys else {
            return false;
        };
        let me = self.local.member.name.as_str();
        let unix = keys.unix_now(self.now);
        let others = if full { self.table.len() } else { 0 };
        let known: Option<BTreeSet<CertificateId>> = known.map(|k| k.iter().collect());
        let mut records = Vec::new();
        let mut certs = Vec::new();
        for e in std::iter::once(&self.local).chain(self.table.iter().take(others)) {
            let Some(r) = signed_record(e, keys, me, unix) else {
                continue;
            };
            let cert = r.alive.certificate_id;
            if known.as_ref().is_some_and(|k| !k.contains(&cert)) {
                certs.extend(keys.held(me, &e.member.name, cert));
            }
            records.push(r);
        }
        let ids: Vec<CertificateId> = if known.is_none() {
            certs.push(&keys.own);
            std::iter::once(keys.own.id)
                .chain(keys.certs.values().map(|c| c.id))
                .collect()
        } else {
            Vec::new()
        };
        let mut msgs: Vec<v2::Message<'_>> = certs
            .iter()
            .filter_map(|c| c.certificate())
            .map(v2::Message::Certificate)
            .collect();
        msgs.push(v2::Message::PushPull(v2::PushPull {
            join,
            records: v2::Records::Slice(&records),
            known_certificates: v2::CertificateIds::Slice(&ids),
        }));
        let sent = self.out.frame_v2(conn, &msgs);
        drop(msgs);
        if !sent {
            self.metrics.state_too_large += 1;
        }
        sent
    }

    /// Whether this node holds a record that a version 2 push-pull cannot carry: a member
    /// without a proof of its Alive, or that left without its signed Left.
    fn omits_records(&self) -> bool {
        let Some(keys) = &self.keys else {
            return false;
        };
        let me = self.local.member.name.as_str();
        let unix = keys.unix_now(self.now);
        std::iter::once(&self.local)
            .chain(self.table.iter())
            .any(|e| signed_record(e, keys, me, unix).is_none())
    }

    /// Opens a connection to `to` and remembers why, and at which `version` it is.
    pub(crate) fn connect(
        &mut self,
        to: SocketAddr,
        purpose: Purpose,
        repeat: bool,
        version: WireVersion,
    ) -> StreamId {
        let conn = StreamId::outbound(self.sync.next_stream);
        self.sync.next_stream += 1;
        self.out.transmits.push_back(Transmit::Connect { conn, to });
        let deadline = self.now + self.cfg.tcp_timeout;
        let outbound = Outbound {
            purpose,
            deadline,
            to,
            stamp: self.out.stamp,
            repeat,
            version,
            digest: false,
        };
        self.sync.streams.insert(conn, outbound);
        conn
    }

    /// Exchanges state with the member `peer` at `to`, at `version`: version 1, the push-pull
    /// 0.4 sends, or its digest with a member that advertises it ([`Node::digest_to`]); or with
    /// a member that speaks version 2, the push-pull of signed records, and beside it, on a
    /// second connection, the version 1 one, whenever this node holds a record the first
    /// cannot carry or is joining (`docs/ki01-stage2.md`, Unsigned statements).
    fn exchange(
        &mut self,
        peer: Option<&str>,
        to: SocketAddr,
        purpose: Purpose,
        version: WireVersion,
    ) {
        let digest = version == WireVersion::V1 && self.digest_to(peer, to);
        self.push_pull_with(to, purpose, false, version, digest);
        if version == WireVersion::V2
            && (matches!(purpose, Purpose::Join { .. }) || self.omits_records())
        {
            self.push_pull_with(to, purpose, false, WireVersion::V1, false);
        }
    }

    /// Opens a push-pull exchange with `to` at `version`, starting with a digest if `digest`;
    /// `repeat` marks the second try after a stale one.
    fn push_pull_with(
        &mut self,
        to: SocketAddr,
        purpose: Purpose,
        repeat: bool,
        version: WireVersion,
        digest: bool,
    ) {
        if let (Purpose::Join { cmd, seed }, false) = (purpose, repeat) {
            if let Some(s) = self
                .sync
                .joins
                .get_mut(&cmd)
                .and_then(|j| j.seeds.get_mut(seed))
            {
                s.inflight += 1;
            }
        }
        let conn = self.connect(to, purpose, repeat, version);
        if let Some(o) = self.sync.streams.get_mut(&conn) {
            o.digest = digest;
        }
        let join = matches!(purpose, Purpose::Join { .. });
        let sent = if version == WireVersion::V2 {
            self.send_signed_state(conn, join, true, None)
        } else if digest {
            self.send_digest(conn, join)
        } else {
            self.send_state(conn, join, true)
        };
        if !sent {
            self.end_stream(conn, false);
        }
    }

    /// Sends the probe of round `seq` to `to` over TCP as well; the stream is closed with the
    /// round. A version 2 round, with its `signed` challenge and this node's epoch, sends its
    /// own version 2 Ping in a version 2 frame.
    pub(crate) fn tcp_ping(
        &mut self,
        to: SocketAddr,
        target: &str,
        seq: u32,
        signed: Option<(v2::ProbeChallenge, u64)>,
    ) -> StreamId {
        let version = match signed {
            Some(_) => WireVersion::V2,
            None => WireVersion::V1,
        };
        let conn = self.connect(to, Purpose::Ping { seq }, false, version);
        let me = self.local.member.name.clone();
        let ping = Ping {
            seq,
            target: id(target),
            source: id(&me),
            source_addr: self.local.member.addr,
        };
        match signed {
            None => {
                self.out.frame(conn, &[Message::Ping(ping)]);
            }
            Some((challenge, source_epoch)) => {
                let ping = v2::Message::Ping {
                    ping,
                    source_epoch,
                    challenge,
                    requester: None,
                };
                self.out.frame_v2(conn, &[ping]);
            }
        }
        self.metrics.tcp_pings += 1;
        conn
    }

    /// Abandons a connection without counting a failure.
    pub(crate) fn close_stream(&mut self, conn: StreamId) {
        if self.sync.streams.remove(&conn).is_some() {
            self.out.transmits.push_back(Transmit::Close { conn });
        }
    }

    /// The version attempt `attempts` of a join tries a seed at: in mode `sign`, version 2 on
    /// the first attempt and every other one after, version 1 between; version 1 in `off`.
    /// A seed is an address this node may hold no member at.
    fn join_version(&self, attempts: u32) -> WireVersion {
        if self.keys.is_some() && attempts % 2 == 1 {
            WireVersion::V2
        } else {
            WireVersion::V1
        }
    }

    /// Starts a join: a push-pull with every seed other than this node.
    pub(crate) fn join(&mut self, id: CommandId, seeds: Vec<SocketAddr>) {
        if self.has_left() {
            return self.finish(id, Err(CommandError::Left));
        }
        let mut addrs: Vec<SocketAddr> = Vec::with_capacity(seeds.len());
        for s in seeds {
            if s != self.local.member.addr && !addrs.contains(&s) {
                addrs.push(s);
            }
        }
        if addrs.is_empty() {
            return self.finish(id, Ok(CommandOutput::Joined { seeds: 0 }));
        }
        let seeds = addrs
            .iter()
            .map(|&addr| Seed {
                addr,
                attempts: 1,
                state: SeedState::Trying,
                inflight: 0,
            })
            .collect();
        self.sync.joins.insert(id, Join { seeds, answered: 0 });
        let version = self.join_version(1);
        for (seed, addr) in addrs.into_iter().enumerate() {
            self.exchange(None, addr, Purpose::Join { cmd: id, seed }, version);
        }
    }

    /// Records the outcome of one exchange with a seed and finishes the join when it can.
    ///
    /// A join waits for the first attempt with every seed, so it can say how many answered.
    /// Seeds that failed are retried, with backoff, only while none has answered. An attempt
    /// at version 2 opens two exchanges; the seed answered when either did, and failed when
    /// both did.
    fn seed_done(&mut self, now: Instant, cmd: CommandId, seed: usize, ok: bool) {
        let retries = self.cfg.join_retries;
        let base = self.cfg.probe_interval;
        let Some(join) = self.sync.joins.get_mut(&cmd) else {
            return;
        };
        let Some(s) = join.seeds.get_mut(seed) else {
            return;
        };
        s.inflight = s.inflight.saturating_sub(1);
        if s.state != SeedState::Trying {
            return;
        }
        if ok {
            s.state = SeedState::Answered;
            join.answered += 1;
            self.joined = true;
        } else if s.inflight > 0 {
            // The other exchange of this attempt may still answer.
            return;
        } else if s.attempts < retries {
            s.state = SeedState::Waiting(now + base * (1 << (s.attempts - 1).min(16)));
        } else {
            s.state = SeedState::Failed;
        }
        let trying = join.seeds.iter().any(|s| s.state == SeedState::Trying);
        let result = if join.answered > 0 && !trying {
            Ok(CommandOutput::Joined {
                seeds: join.answered,
            })
        } else if join.seeds.iter().all(|s| s.state == SeedState::Failed) {
            Err(CommandError::JoinFailed)
        } else {
            return;
        };
        self.sync.joins.remove(&cmd);
        self.finish(cmd, result);
    }

    /// Starts this node's departure: it gossips Left, stops probing and stops refuting.
    pub(crate) fn leave(&mut self, id: CommandId) {
        if self.has_left() {
            return self.finish(id, Ok(CommandOutput::Done));
        }
        self.local.member.state = State::Left;
        let me = &self.local.member;
        let (name, inc, epoch) = (me.name.clone(), me.incarnation, me.epoch);
        let dead = Dead {
            inc,
            node: crate::broadcast::id(&name),
            from: crate::broadcast::id(&name),
            epoch,
        };
        // In mode `sign` the Left is signed, and kept for push-pull records of this node.
        let proof = self.sign_dead(&dead);
        self.local.left = proof.map(|proof| LeftProof { inc, epoch, proof });
        let gossip = Gossip::dead(&dead, proof);
        // Sends to members that are dead or gone do not count: a leave that reached only them
        // has told nobody.
        self.broadcast_to_live(gossip);
        // Tell the first few members now instead of at the next gossip tick, so that a caller
        // whose leave times out and who closes the node at once has still been heard; they pass
        // it on.
        self.gossip(self.now);
        if let Some(p) = self.probe.take() {
            if let Some(conn) = p.fallback {
                self.close_stream(conn);
            }
        }
        let joins: Vec<CommandId> = self.sync.joins.keys().copied().collect();
        self.sync.joins.clear();
        for cmd in joins {
            self.finish(cmd, Err(CommandError::Left));
        }
        self.sync.leaving = Some(id);
        self.check_leave();
    }

    /// Finishes a pending Leave once the Left rumour has been sent `retransmit_limit` times to
    /// members this node holds live, or none is left to tell.
    pub(crate) fn check_leave(&mut self) {
        let Some(id) = self.sync.leaving else {
            return;
        };
        if self.table.live() == 0 || !self.out.broadcasts.contains(&self.local.member.name) {
            self.sync.leaving = None;
            self.finish(id, Ok(CommandOutput::Done));
        }
    }

    pub(crate) fn finish(&mut self, id: CommandId, result: Result<CommandOutput, CommandError>) {
        self.events.push_back(Event::CommandDone { id, result });
    }

    /// Connection timeouts, join retries, and the anti-entropy and reconnect ticks.
    pub(crate) fn sync_timers(&mut self, now: Instant) {
        let expired: Vec<StreamId> = self
            .sync
            .streams
            .iter()
            .filter(|(_, o)| o.deadline <= now)
            .map(|(&conn, _)| conn)
            .collect();
        let unanswered: Vec<StreamId> = self
            .sync
            .awaiting
            .iter()
            .filter(|&(_, &t)| t <= now)
            .map(|(&conn, _)| conn)
            .collect();
        for conn in expired.into_iter().chain(unanswered) {
            self.end_stream(conn, false);
        }

        let mut retries = Vec::new();
        for (&cmd, join) in &mut self.sync.joins {
            if join.answered > 0 {
                // Waiting only for attempts already in flight.
                continue;
            }
            for (i, s) in join.seeds.iter_mut().enumerate() {
                if matches!(s.state, SeedState::Waiting(t) if t <= now) {
                    s.state = SeedState::Trying;
                    s.attempts += 1;
                    retries.push((s.addr, Purpose::Join { cmd, seed: i }, s.attempts));
                }
            }
        }
        for (addr, purpose, attempts) in retries {
            let version = self.join_version(attempts);
            self.exchange(None, addr, purpose, version);
        }

        if let Some(t) = self.next_push_pull().filter(|&t| t <= now) {
            let last = last_tick(t, now, self.push_pull_interval());
            self.sync.push_pull = Some(SyncTimer::Last(last));
            if !self.has_left() {
                let to = self
                    .table
                    .random(1, &mut self.rng, |e| e.member.state.is_live())
                    .first()
                    .map(|e| (e.member.addr, e.member.name.clone()));
                if let Some((to, name)) = to {
                    let version = self.version_for(Some(&name), to);
                    self.exchange(Some(&name), to, Purpose::Sync, version);
                }
            }
        }

        if let Some(t) = self.sync.next_reconnect.filter(|&t| t <= now) {
            self.sync.next_reconnect = Some(next_tick(t, now, self.cfg.reconnect_interval));
            if !self.has_left() {
                // Tombstones live for dead_reclaim, so every Dead member in the table is
                // recent. A member that left will not answer, and is not asked.
                let to = self
                    .table
                    .random(1, &mut self.rng, |e| e.member.state == State::Dead)
                    .first()
                    .map(|e| (e.member.addr, e.member.name.clone()));
                if let Some((to, name)) = to {
                    let version = self.version_for(Some(&name), to);
                    self.exchange(Some(&name), to, Purpose::Sync, version);
                }
            }
        }
    }

    /// The period of anti-entropy push-pull at the current number of live members, this node
    /// included; see [`Config::push_pull_interval_for`].
    pub(crate) fn push_pull_interval(&self) -> Duration {
        push_pull_period(&self.cfg, self.table.live() + 1, self.keys.is_some())
    }

    /// When the next periodic push-pull is due, `None` if they are off.
    fn next_push_pull(&self) -> Option<Instant> {
        match self.sync.push_pull? {
            SyncTimer::First(t) => Some(t),
            SyncTimer::Last(t) => Some(t + self.push_pull_interval()),
        }
    }

    pub(crate) fn sync_deadline(&self) -> Option<Instant> {
        let streams = self
            .sync
            .streams
            .values()
            .map(|o| o.deadline)
            .chain(self.sync.awaiting.values().copied());
        let retries = self.sync.joins.values().flat_map(|j| {
            j.seeds.iter().filter_map(|s| match s.state {
                SeedState::Waiting(t) if j.answered == 0 => Some(t),
                _ => None,
            })
        });
        streams
            .chain(retries)
            .chain(self.next_push_pull())
            .chain(self.sync.next_reconnect)
            .min()
    }
}

/// The version 2 push-pull record of `e`: its member's signed Alive, as the member signed it,
/// with the state it is held in, and for a member that left, its signed Left. `None` if this
/// node holds no proof for it, or its certificate is not valid at Unix second `now`.
fn signed_record<'a>(e: &'a Entry, keys: &Keys, me: &str, now: u64) -> Option<v2::Record<'a>> {
    let proof = e.proof?;
    let m = &e.member;
    keys.held(me, &m.name, proof.cert)
        .filter(|c| c.is_current(now))?;
    let state = match m.state {
        State::Alive if proof.inc == m.incarnation => v2::RecordState::Alive,
        State::Alive => return None,
        State::Suspect => v2::RecordState::Suspect { inc: m.incarnation },
        State::Dead => v2::RecordState::Dead { inc: m.incarnation },
        State::Left => {
            let left = e.left.filter(|l| l.epoch == m.epoch)?;
            v2::RecordState::Left {
                inc: left.inc,
                at: left.proof.at,
                certificate_id: left.proof.cert,
                signature: left.proof.sig,
            }
        }
    };
    let alive = Alive {
        inc: m.incarnation,
        node: id(&m.name),
        addr: m.addr,
        meta: &m.meta,
        vmin: e.vmin,
        vmax: e.vmax,
        epoch: m.epoch,
        features: 0,
    };
    match signed_alive(&alive, &proof) {
        v2::Message::Alive(alive) => Some(v2::Record { alive, state }),
        _ => None,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Security};
    use crate::event::Command;
    use crate::{Identity, Member};
    use kinship_proto::Suspect;

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn node(name: &str, port: u16) -> Node {
        let cfg = Config::lan(Security::InsecurePlaintext);
        let me = Identity::new(name, addr(port)).unwrap();
        Node::new(cfg, me, Instant::ZERO, u64::from(port), &[port as u8; 32]).unwrap()
    }

    /// Adds `count` live members to `n`'s table, as a static list would.
    fn hold_members(n: &mut Node, count: u16) {
        for i in 0..count {
            n.table.insert(Entry {
                member: Member {
                    name: format!("m{i}"),
                    addr: addr(20_000 + i),
                    meta: Vec::new(),
                    state: State::Alive,
                    incarnation: 0,
                    epoch: 0,
                },
                since: Instant::ZERO,
                vmin: 1,
                vmax: 1,
                proof: None,
                left: None,
                features: 0,
            });
        }
    }

    #[test]
    fn push_pull_keeps_its_period_by_default() {
        let me = Identity::new("a", addr(1)).unwrap();
        let nonce_key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let cfg = Config::lan(Security::InsecurePlaintext);
        let mut n = Node::new(cfg, me, Instant::ZERO, 1, &nonce_key).unwrap();
        hold_members(&mut n, 999);
        assert_eq!(n.push_pull_interval(), n.cfg.push_pull_interval);
    }

    #[test]
    fn a_signing_node_keeps_the_base_period() {
        let cfg = Config {
            push_pull_scale: true,
            ..Config::lan(Security::InsecurePlaintext)
        };
        let base = cfg.push_pull_interval;
        assert_eq!(push_pull_period(&cfg, 1000, false), base * 6);
        assert_eq!(push_pull_period(&cfg, 1000, true), base);
        assert_eq!(push_pull_period(&cfg, 10, true), base);
    }

    #[test]
    fn push_pull_stretches_and_shrinks_with_the_live_members() {
        let cfg = Config {
            push_pull_scale: true,
            ..Config::lan(Security::InsecurePlaintext)
        };
        let me = Identity::new("a", addr(1)).unwrap();
        let nonce_key: [u8; 32] = std::array::from_fn(|i| i as u8);
        let mut n = Node::new(cfg, me, Instant::ZERO, 1, &nonce_key).unwrap();
        let base = n.cfg.push_pull_interval;
        // The first is staggered within the base interval, whatever the size.
        hold_members(&mut n, 199);
        let first = n.next_push_pull().unwrap();
        assert!(first < Instant::ZERO + base);
        n.handle_timeout(first);
        assert_eq!(n.sync.streams.len(), 1, "the first push-pull started");
        // 200 live members, this node included: four times the base after the last one.
        assert_eq!(n.next_push_pull(), Some(first + base * 4));
        // The cluster shrinks to 33: the same push-pull is due earlier.
        for i in 32..199 {
            n.table.update(
                &format!("m{i}"),
                State::Dead,
                0,
                first + Duration::from_secs(1),
            );
        }
        assert_eq!(n.push_pull_interval(), base * 2);
        assert_eq!(n.next_push_pull(), Some(first + base * 2));
        // To 32: the base interval, as with no scaling.
        n.table
            .update("m31", State::Dead, 0, first + Duration::from_secs(1));
        assert_eq!(n.next_push_pull(), Some(first + base));
        // A node that missed ticks runs the next one and stays on its grid.
        let late = first + base * 3 + Duration::from_secs(1);
        n.handle_timeout(late);
        assert_eq!(n.next_push_pull(), Some(first + base * 4));
    }

    fn key() -> crate::Key {
        crate::Key::from_bytes([5; 32])
    }

    fn secure_node(name: &str, port: u16) -> Node {
        let cfg = Config::lan(Security::Keys(vec![key()]));
        let me = Identity::new(name, addr(port)).unwrap();
        Node::new(cfg, me, Instant::ZERO, u64::from(port), &[port as u8; 32]).unwrap()
    }

    /// Two nodes on a perfect network: datagrams to the other's address arrive, and
    /// connections to it are accepted, unless `refuse` is set.
    struct Pair {
        nodes: [Node; 2],
        /// Each end of a connection, mapped to the other end.
        conns: BTreeMap<(usize, StreamId), (usize, StreamId)>,
        accepted: u64,
        refuse: bool,
        /// How far each node's clock runs ahead of the time the test passes in.
        skew: [Duration; 2],
        /// Every stream frame delivered, without its length prefix, and the node that sent it.
        frames: Vec<(usize, Vec<u8>)>,
        /// Datagrams are dropped.
        streams_only: bool,
    }

    impl Pair {
        fn new(a: Node, b: Node) -> Self {
            Self {
                nodes: [a, b],
                conns: BTreeMap::new(),
                accepted: 0,
                refuse: false,
                skew: [Duration::ZERO; 2],
                frames: Vec::new(),
                streams_only: false,
            }
        }

        /// Moves everything both nodes send until both are quiet.
        fn pump(&mut self, now: Instant) {
            loop {
                let mut moved = false;
                for i in 0..2 {
                    let out: Vec<Transmit> =
                        std::iter::from_fn(|| self.nodes[i].poll_transmit()).collect();
                    for t in out {
                        moved = true;
                        if !(self.streams_only && matches!(t, Transmit::Datagram { .. })) {
                            self.deliver(now, i, t);
                        }
                    }
                }
                if !moved {
                    return;
                }
            }
        }

        fn deliver(&mut self, now: Instant, i: usize, t: Transmit) {
            let j = 1 - i;
            let from = self.nodes[i].local().addr;
            let (now_i, now) = (now + self.skew[i], now + self.skew[j]);
            match t {
                Transmit::Datagram { to, payload } => {
                    if to == self.nodes[j].local().addr {
                        self.nodes[j].handle_datagram(now, from, &payload);
                    }
                }
                Transmit::Connect { conn, .. } if self.refuse => {
                    self.nodes[i].handle_stream(now_i, conn, StreamEvent::Failed);
                }
                Transmit::Connect { conn, .. } => {
                    let peer = StreamId::inbound(self.accepted);
                    self.accepted += 1;
                    self.conns.insert((i, conn), (j, peer));
                    self.conns.insert((j, peer), (i, conn));
                }
                Transmit::Stream { conn, frame } => {
                    if let Some(&(j, peer)) = self.conns.get(&(i, conn)) {
                        // Every write is one frame; strip its length prefix.
                        self.frames.push((i, frame[4..].to_vec()));
                        let ev = StreamEvent::Frame(&frame[4..]);
                        self.nodes[j].handle_stream(now, peer, ev);
                    }
                }
                Transmit::Close { conn } => {
                    if let Some((j, peer)) = self.conns.remove(&(i, conn)) {
                        self.conns.remove(&(j, peer));
                        self.nodes[j].handle_stream(now, peer, StreamEvent::Closed);
                    }
                }
            }
        }

        fn events(&mut self, i: usize) -> Vec<Event> {
            std::iter::from_fn(|| self.nodes[i].poll_event()).collect()
        }
    }

    fn joined(events: &[Event]) -> Vec<&Member> {
        events
            .iter()
            .filter_map(|e| match e {
                Event::MemberJoined(m) => Some(m),
                _ => None,
            })
            .collect()
    }

    fn done(events: &[Event], cmd: CommandId) -> Option<Result<CommandOutput, CommandError>> {
        events.iter().find_map(|e| match e {
            Event::CommandDone { id, result } if *id == cmd => Some(*result),
            _ => None,
        })
    }

    #[test]
    fn join_exchanges_state_both_ways() {
        let mut b = node("b", 2);
        b.add_member(Instant::ZERO, "c", addr(3)).unwrap();
        let mut p = Pair::new(node("a", 1), b);
        p.events(1);
        let t = Instant::ZERO;
        // Its own address is skipped, and a seed listed twice is tried once.
        let cmd = Command::Join {
            seeds: vec![addr(1), addr(2), addr(2)],
        };
        let cmd = p.nodes[0].command(t, cmd);
        p.pump(t);
        let ev = p.events(0);
        assert_eq!(done(&ev, cmd), Some(Ok(CommandOutput::Joined { seeds: 1 })));
        let names: Vec<&str> = joined(&ev).iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, ["b", "c"]);
        let ev = p.events(1);
        assert_eq!(joined(&ev)[0].name, "a");
        assert_eq!(p.nodes[0].metrics().push_pulls, 1);
        assert_eq!(p.nodes[1].metrics().push_pulls_served, 1);
        assert!(p.conns.is_empty(), "both ends closed");
        assert!(p.nodes[0].sync.streams.is_empty());
        assert!(p.nodes[0].joined && p.nodes[1].joined, "on both sides");
    }

    #[test]
    fn a_node_behind_cluster_time_joins_in_two_exchanges() {
        // The seed has run for an hour; the joiner just started, so its request is stale.
        let mut b = secure_node("b", 2);
        b.add_member(Instant::ZERO, "c", addr(3)).unwrap();
        let mut p = Pair::new(secure_node("a", 1), b);
        p.skew[1] = Duration::from_secs(3600);
        p.events(1);
        let t = Instant::ZERO;
        let cmd = p.nodes[0].command(
            t,
            Command::Join {
                seeds: vec![addr(2)],
            },
        );
        p.pump(t);
        let ev = p.events(0);
        assert_eq!(done(&ev, cmd), Some(Ok(CommandOutput::Joined { seeds: 1 })));
        let names: Vec<&str> = joined(&ev).iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, ["b", "c"], "the seed's own record, then the rest");
        assert_eq!(
            joined(&p.events(1))[0].name,
            "a",
            "the second request merged"
        );
        assert_eq!(p.nodes[1].metrics().replays_dropped, 1);
        assert_eq!(p.nodes[1].metrics().push_pulls_served, 1);
        assert_eq!(p.nodes[0].metrics().push_pulls, 1);
        assert!(p.conns.is_empty() && p.nodes[0].sync.streams.is_empty());
    }

    /// A push-pull from "x", which claims a member "ghost", sealed at cluster time `stamp`.
    fn recorded_push_pull(stamp: u64) -> Vec<u8> {
        let codec = kinship_proto::Codec::encrypted(
            b"default",
            kinship_proto::Limits::default(),
            vec![key()],
        )
        .unwrap();
        let alive = |name: &'static str, port| Record {
            state: kinship_proto::State::Alive,
            alive: Alive {
                inc: 0,
                node: id(name),
                addr: addr(port),
                meta: b"",
                vmin: 1,
                vmax: 1,
                epoch: 0,
                features: 0,
            },
        };
        let records = [alive("x", 8), alive("ghost", 9)];
        let msg = Message::PushPull(PushPull {
            join: true,
            records: Records::Slice(&records),
        });
        let mut nonce = [7; kinship_proto::NONCE_LEN];
        nonce[..8].copy_from_slice(&stamp.to_be_bytes());
        let mut frame = Vec::new();
        codec
            .seal(PacketKind::Stream, &[msg], &nonce, &mut frame)
            .unwrap();
        frame
    }

    /// Records in the push-pull `n` wrote to `conn`, and whether it closed the connection.
    fn answer(n: &mut Node, conn: StreamId) -> (Option<usize>, bool) {
        let codec = kinship_proto::Codec::encrypted(
            b"default",
            kinship_proto::Limits::default(),
            vec![key()],
        )
        .unwrap();
        let (mut records, mut closed) = (None, false);
        while let Some(t) = n.poll_transmit() {
            match t {
                Transmit::Stream { conn: c, mut frame } if c == conn => {
                    let payload = codec.open(PacketKind::Stream, &mut frame[4..]).unwrap();
                    if let Some(Message::PushPull(p)) = payload.iter().next() {
                        records = Some(p.records.len());
                    }
                }
                Transmit::Close { conn: c } if c == conn => closed = true,
                _ => {}
            }
        }
        (records, closed)
    }

    #[test]
    fn recorded_push_pulls_are_answered_with_no_more_than_one_record() {
        let mut b = secure_node("b", 2);
        b.add_member(Instant::ZERO, "c", addr(3)).unwrap();
        // Nodes that have been running for 100 s, waking every second.
        let run = |b: &mut Node| {
            for s in 1..=100 {
                b.handle_timeout(Instant::ZERO + Duration::from_secs(s));
                while b.poll_transmit().is_some() {}
            }
        };
        run(&mut b);
        let t = Instant::ZERO + Duration::from_secs(100);
        let frame = recorded_push_pull(95_000);
        let known = b.all_members().count();

        b.handle_stream(t, StreamId::inbound(0), StreamEvent::Frame(&frame));
        assert_eq!(
            answer(&mut b, StreamId::inbound(0)),
            (Some(known + 2), true)
        );
        assert!(b.member("ghost").is_some());

        // The same frame again, inside the window: a copy, closed unanswered.
        b.handle_stream(t, StreamId::inbound(1), StreamEvent::Frame(&frame));
        assert_eq!(answer(&mut b, StreamId::inbound(1)), (None, true));
        assert_eq!(b.metrics().replays_dropped, 1);

        // A recording older than the window: only b's own record goes back, nothing merges.
        let mut b = secure_node("b", 2);
        run(&mut b);
        let old = recorded_push_pull(60_000);
        b.handle_stream(t, StreamId::inbound(0), StreamEvent::Frame(&old));
        assert_eq!(answer(&mut b, StreamId::inbound(0)), (Some(1), true));
        assert!(b.member("ghost").is_none() && b.member("x").is_none());
        assert_eq!(b.metrics().replays_dropped, 1);
        assert_eq!(b.metrics().push_pulls_served, 0);
    }

    #[test]
    fn one_push_pull_frame_shares_one_admission_budget() {
        let t = Instant::ZERO;
        let mut b = node("b", 2);
        b.cfg.max_new_members_per_packet = 3;
        b.add_member(t, "c", addr(3)).unwrap();
        while b.poll_event().is_some() {}
        let record = |name: &'static str, inc, port| Record {
            state: kinship_proto::State::Alive,
            alive: Alive {
                inc,
                node: id(name),
                addr: addr(port),
                meta: b"",
                vmin: 1,
                vmax: 1,
                epoch: 0,
                features: 0,
            },
        };
        // Five members b has never heard of, then news about one it knows.
        let records = [
            record("n1", 0, 11),
            record("n2", 0, 12),
            record("n3", 0, 13),
            record("n4", 0, 14),
            record("n5", 0, 15),
            record("c", 4, 3),
        ];
        let msg = Message::PushPull(PushPull {
            join: false,
            records: Records::Slice(&records),
        });
        let codec =
            kinship_proto::Codec::insecure_plaintext(b"default", kinship_proto::Limits::default())
                .unwrap();
        let mut frame = Vec::new();
        codec
            .seal(PacketKind::Stream, &[msg], &[0; 24], &mut frame)
            .unwrap();
        b.handle_stream(t, StreamId::inbound(0), StreamEvent::Frame(&frame));
        let ev: Vec<Event> = std::iter::from_fn(|| b.poll_event()).collect();
        let names: Vec<&str> = joined(&ev).iter().map(|m| m.name.as_str()).collect();
        assert_eq!(names, ["n1", "n2", "n3"]);
        assert_eq!(b.metrics().members_refused, 2);
        assert_eq!(
            b.member("c").unwrap().incarnation,
            4,
            "known members update"
        );
        assert_eq!(
            b.metrics().push_pulls_served,
            1,
            "and the frame is answered"
        );
    }

    #[test]
    fn joining_only_yourself_succeeds_at_once() {
        let mut a = node("a", 1);
        let cmd = a.command(
            Instant::ZERO,
            Command::Join {
                seeds: vec![addr(1)],
            },
        );
        let ev: Vec<Event> = std::iter::from_fn(|| a.poll_event()).collect();
        assert_eq!(done(&ev, cmd), Some(Ok(CommandOutput::Joined { seeds: 0 })));
        assert_eq!(a.poll_transmit(), None);
    }

    /// The messages of a plaintext stream frame of cluster "default", each with the number of
    /// records, entries or names it lists.
    fn shape(frame: &[u8]) -> Vec<(&'static str, usize)> {
        let codec =
            kinship_proto::Codec::insecure_plaintext(b"default", kinship_proto::Limits::default())
                .unwrap();
        let mut buf = frame.to_vec();
        let payload = codec.open(PacketKind::Stream, &mut buf).unwrap();
        payload
            .iter()
            .map(|m| match m {
                Message::PushPull(p) => ("push-pull", p.records.len()),
                Message::PushPullDigest(d) => ("digest", d.entries.len()),
                Message::PushPullWants(w) => ("wants", w.names.len()),
                _ => ("other", 0),
            })
            .collect()
    }

    /// The shape of every frame `p` delivered since it last forgot them, by sender.
    fn shapes(p: &mut Pair) -> Vec<(usize, Vec<(&'static str, usize)>)> {
        std::mem::take(&mut p.frames)
            .iter()
            .map(|(i, f)| (*i, shape(f)))
            .collect()
    }

    /// a and b, at epochs 100 and 200, after a joined through b: each holds the other, which
    /// advertises digest push-pull. `b_cfg` adjusts b's config.
    fn digest_pair_with(b_cfg: impl FnOnce(&mut Config)) -> Pair {
        let t = Instant::ZERO;
        let mut b = node_at("b", 2, 200);
        b_cfg(&mut b.cfg);
        b.local.features = b.own_features();
        b.out.broadcasts.forget("b");
        let mut p = Pair::new(node_at("a", 1, 100), b);
        let cmd = p.nodes[0].command(
            t,
            Command::Join {
                seeds: vec![addr(2)],
            },
        );
        p.pump(t);
        assert_eq!(
            done(&p.events(0), cmd),
            Some(Ok(CommandOutput::Joined { seeds: 1 }))
        );
        p.events(1);
        assert_eq!(
            shapes(&mut p)[0].1,
            [("push-pull", 1)],
            "a join is a full exchange"
        );
        p
    }

    fn digest_pair() -> Pair {
        digest_pair_with(|_| {})
    }

    /// a starts an anti-entropy exchange with b.
    fn sync_a_with_b(p: &mut Pair, t: Instant) {
        p.nodes[0].exchange(Some("b"), addr(2), Purpose::Sync, WireVersion::V1);
        p.pump(t);
    }

    #[test]
    fn a_settled_pair_trades_a_digest_for_an_empty_answer() {
        let mut p = digest_pair();
        let t = Instant::ZERO;
        for n in &p.nodes {
            assert_eq!(n.local.features, feature::DIGEST_PUSH_PULL);
            let other = n.table.iter().next().unwrap();
            assert_eq!(other.features, feature::DIGEST_PUSH_PULL);
        }
        sync_a_with_b(&mut p, t);
        // Nothing differs, so b wants nothing, sends nothing and closes: two frames.
        assert_eq!(
            shapes(&mut p),
            [
                (0, vec![("digest", 2)]),
                (1, vec![("push-pull", 0), ("wants", 0)])
            ]
        );
        assert_eq!(p.nodes[0].metrics().push_pulls, 2, "the join and this one");
        assert_eq!(p.nodes[1].metrics().push_pulls_served, 2);
        assert!(p.conns.is_empty(), "both ends closed");
        assert!(p.nodes[0].sync.streams.is_empty() && p.nodes[1].sync.awaiting.is_empty());
    }

    #[test]
    fn a_digest_exchange_sends_only_the_records_that_differ() {
        let mut p = digest_pair();
        let t = Instant::ZERO;
        // a alone holds c, b alone holds d, and b holds e at a later incarnation.
        p.nodes[0].add_member(t, "c", addr(3)).unwrap();
        p.nodes[1].add_member(t, "d", addr(4)).unwrap();
        for n in &mut p.nodes {
            n.add_member(t, "e", addr(5)).unwrap();
        }
        let e3 = Alive {
            inc: 3,
            node: id("e"),
            addr: addr(5),
            meta: b"m",
            vmin: 1,
            vmax: 1,
            epoch: 0,
            features: 0,
        };
        let b = &mut p.nodes[1];
        b.on_alive(t, &e3, &mut b.admission(), None);
        p.events(0);
        p.events(1);
        sync_a_with_b(&mut p, t);
        // a lists itself, b, c and e; b sends d and its later e, and wants c, which a sends.
        assert_eq!(
            shapes(&mut p),
            [
                (0, vec![("digest", 4)]),
                (1, vec![("push-pull", 2), ("wants", 1)]),
                (0, vec![("push-pull", 1)]),
            ]
        );
        for n in &p.nodes {
            let mut names: Vec<_> = n.all_members().map(|m| m.name.clone()).collect();
            names.sort();
            assert_eq!(names, ["a", "b", "c", "d", "e"]);
            assert_eq!(n.member("e").unwrap().incarnation, 3);
            assert_eq!(n.member("e").unwrap().meta, b"m");
        }
        let names = |ev: &[Event]| {
            joined(ev)
                .iter()
                .map(|m| m.name.clone())
                .collect::<Vec<_>>()
        };
        assert_eq!(names(&p.events(0)), ["d"]);
        assert_eq!(names(&p.events(1)), ["c"]);
        assert!(p.conns.is_empty() && p.nodes[1].sync.awaiting.is_empty());
        assert_eq!(p.nodes[0].metrics().push_pull_failures, 0);
    }

    #[test]
    fn a_digest_entry_about_the_peer_is_refuted_in_the_answer() {
        let mut p = digest_pair();
        let t = Instant::ZERO;
        // a holds b as Suspect at b's own incarnation.
        let a = &mut p.nodes[0];
        a.on_merged_suspicion(t, "b", 0, 200);
        while a.poll_transmit().is_some() {}
        sync_a_with_b(&mut p, t);
        // b refutes before it answers, so the answer carries its Alive at incarnation 1.
        assert_eq!(p.nodes[1].local().incarnation, 1);
        let m = p.nodes[0].member("b").unwrap();
        assert_eq!((m.state, m.incarnation), (State::Alive, 1));
        assert_eq!(
            shapes(&mut p),
            [
                (0, vec![("digest", 2)]),
                (1, vec![("push-pull", 1), ("wants", 0)])
            ]
        );
    }

    #[test]
    fn members_that_do_not_advertise_it_get_the_full_exchange() {
        // b turned it off, so it advertises nothing and starts full exchanges itself.
        let mut p = digest_pair_with(|cfg| cfg.push_pull_digest = false);
        let t = Instant::ZERO;
        assert_eq!(p.nodes[1].local.features, 0);
        assert_eq!(p.nodes[0].table.get("b").unwrap().features, 0);
        sync_a_with_b(&mut p, t);
        p.nodes[1].exchange(Some("a"), addr(1), Purpose::Sync, WireVersion::V1);
        p.pump(t);
        assert_eq!(
            shapes(&mut p),
            [
                (0, vec![("push-pull", 2)]),
                (1, vec![("push-pull", 2)]),
                (1, vec![("push-pull", 2)]),
                (0, vec![("push-pull", 2)]),
            ]
        );
        // Nor does a node without an epoch, which could not write them.
        let mut n = node("c", 3);
        assert_eq!(n.local.features, 0);
        n.cfg.push_pull_digest = true;
        assert_eq!(n.own_features(), 0);
    }

    #[test]
    fn a_rejoin_with_a_seed_that_advertises_it_sends_a_digest() {
        let mut p = digest_pair();
        let t = Instant::ZERO;
        let cmd = p.nodes[0].command(
            t,
            Command::Join {
                seeds: vec![addr(2)],
            },
        );
        p.pump(t);
        assert_eq!(
            done(&p.events(0), cmd),
            Some(Ok(CommandOutput::Joined { seeds: 1 }))
        );
        assert_eq!(
            shapes(&mut p),
            [
                (0, vec![("digest", 2)]),
                (1, vec![("push-pull", 0), ("wants", 0)])
            ]
        );
    }

    #[test]
    fn wanted_names_share_one_admission_budget() {
        let mut p = digest_pair_with(|cfg| cfg.max_new_members_per_packet = 2);
        let t = Instant::ZERO;
        for i in 0..5 {
            p.nodes[0]
                .add_member(t, &format!("n{i}"), addr(10 + i))
                .unwrap();
        }
        p.events(1);
        sync_a_with_b(&mut p, t);
        assert_eq!(
            shapes(&mut p),
            [
                (0, vec![("digest", 7)]),
                (1, vec![("push-pull", 0), ("wants", 2)]),
                (0, vec![("push-pull", 2)]),
            ]
        );
        let names: Vec<String> = joined(&p.events(1))
            .iter()
            .map(|m| m.name.clone())
            .collect();
        assert_eq!(names, ["n0", "n1"]);
        assert_eq!(p.nodes[1].metrics().members_refused, 3);
    }

    #[test]
    fn a_peer_that_never_sends_the_wanted_records_is_closed_after_tcp_timeout() {
        let mut p = digest_pair();
        let t = Instant::ZERO;
        p.nodes[0].add_member(t, "c", addr(3)).unwrap();
        p.nodes[0].exchange(Some("b"), addr(2), Purpose::Sync, WireVersion::V1);
        // The digest reaches b; b's answer never reaches a.
        let out: Vec<Transmit> = std::iter::from_fn(|| p.nodes[0].poll_transmit()).collect();
        for x in out {
            p.deliver(t, 0, x);
        }
        let b = &mut p.nodes[1];
        while b.poll_transmit().is_some() {}
        assert_eq!(b.sync.awaiting.len(), 1);
        let deadline = t + b.config().tcp_timeout;
        assert!(b.poll_timeout().unwrap() <= deadline);
        b.handle_timeout(deadline);
        assert!(b.sync.awaiting.is_empty());
        let closed = std::iter::from_fn(|| b.poll_transmit())
            .any(|x| matches!(x, Transmit::Close { conn } if conn.is_inbound()));
        assert!(closed);
        assert!(b.member("c").is_none());
    }

    #[test]
    fn records_cross_where_one_could_teach_the_other() {
        use kinship_proto::State::{Alive, Dead, Left, Suspect};
        // Equal entries teach nothing either way.
        assert!(!teaches((Alive, 3, 100), (Alive, 3, 100)));
        // A newer incarnation teaches an older one, in any state, but not the reverse.
        assert!(teaches((Alive, 4, 100), (Dead, 3, 100)));
        assert!(teaches((Dead, 4, 100), (Alive, 3, 100)));
        assert!(!teaches((Suspect, 3, 100), (Alive, 4, 100)));
        // Incarnations wrap: 0 is newer than u32::MAX.
        assert!(teaches((Alive, 0, 100), (Alive, u32::MAX, 100)));
        // A later life teaches an earlier one whatever the incarnations; an earlier one nothing.
        assert!(teaches((Alive, 0, 200), (Alive, 9, 100)));
        assert!(!teaches((Dead, 9, 100), (Alive, 0, 200)));
        // At one incarnation a Suspect wins over Alive, and Dead and Left over both, but
        // neither of those two over the other.
        assert!(teaches((Suspect, 3, 100), (Alive, 3, 100)));
        assert!(!teaches((Alive, 3, 100), (Suspect, 3, 100)));
        assert!(teaches((Left, 3, 100), (Suspect, 3, 100)));
        assert!(teaches((Dead, 3, 100), (Alive, 3, 100)));
        assert!(!teaches((Dead, 3, 100), (Left, 3, 100)));
        assert!(!teaches((Left, 3, 100), (Dead, 3, 100)));
        // Unordered pairs cross both ways: an unknown epoch, and incarnations 2^31 apart.
        assert!(teaches((Alive, 3, 0), (Alive, 3, 100)) && teaches((Alive, 3, 100), (Alive, 3, 0)));
        let half = 1u32 << 31;
        assert!(teaches((Alive, 0, 100), (Alive, half, 100)));
        assert!(teaches((Alive, half, 100), (Alive, 0, 100)));
    }

    /// An entry for `name` at port `port`, held at `state`, `inc` and `epoch`.
    fn entry(name: &str, port: u16, state: State, inc: u32, epoch: u64, features: u32) -> Entry {
        Entry {
            member: Member {
                name: name.to_owned(),
                addr: addr(port),
                meta: name.as_bytes().to_vec(),
                state,
                incarnation: inc,
                epoch,
            },
            since: Instant::ZERO,
            vmin: 1,
            vmax: 1,
            proof: None,
            left: None,
            features,
        }
    }

    /// a and b, at epochs 100 and 200, each holding the other and a random mix of the members
    /// m0 to m11 in random states, incarnations and lives, drawn from `seed`; with `unknown`,
    /// some of them held without an epoch, as from nodes older than 0.3.
    fn mixed_pair(seed: u64, unknown: bool) -> Pair {
        let mut rng = crate::Rng::new(seed);
        let states = [State::Alive, State::Suspect, State::Dead, State::Left];
        let mut nodes = [node_at("a", 1, 100), node_at("b", 2, 200)];
        for (i, n) in nodes.iter_mut().enumerate() {
            let (other, port, epoch) = [("b", 2, 200), ("a", 1, 100)][i];
            // The other node as it is, or a stale or wrong view of it, refuted on the way. Not
            // Alive past its own incarnation: a digest says that much without the address an
            // Alive's refutation depends on, so the node refutes when the record follows, and
            // the opener hears of it by gossip rather than in the answer.
            let state = states[rng.index(3)];
            let inc = rng.below(2) as u32 * u32::from(state != State::Alive);
            let epoch = [epoch, 150, epoch, 0][rng.index(if unknown { 4 } else { 3 })];
            n.table.insert(entry(
                other,
                port,
                state,
                inc,
                epoch,
                feature::DIGEST_PUSH_PULL,
            ));
            for k in 0..12u16 {
                if rng.chance(0.25) {
                    continue;
                }
                let state = states[rng.index(4)];
                let inc = rng.below(3) as u32;
                let epoch = [50, 60, 0][rng.index(if unknown { 3 } else { 2 })];
                n.table
                    .insert(entry(&format!("m{k}"), 100 + k, state, inc, epoch, 0));
            }
            while n.poll_transmit().is_some() {}
        }
        let [a, b] = nodes;
        let mut p = Pair::new(a, b);
        p.streams_only = true;
        p
    }

    /// Every member each node holds, itself included, as (name, state, incarnation, epoch).
    fn views(p: &Pair) -> Vec<Vec<(String, State, u32, u64)>> {
        p.nodes
            .iter()
            .map(|n| {
                let mut v: Vec<_> = n
                    .all_members()
                    .map(|m| (m.name.clone(), m.state, m.incarnation, m.epoch))
                    .collect();
                v.sort_by(|x, y| x.0.cmp(&y.0));
                v
            })
            .collect()
    }

    /// The views of `p` after a's exchange with b, a full one or a digest one, and the bytes
    /// of the frames it took.
    fn exchanged(mut p: Pair, digest: bool) -> (Vec<Vec<(String, State, u32, u64)>>, usize) {
        let t = Instant::ZERO;
        p.nodes[0].push_pull_with(addr(2), Purpose::Sync, false, WireVersion::V1, digest);
        p.pump(t);
        assert!(p.conns.is_empty());
        assert_eq!(p.nodes[0].metrics().push_pulls, 1);
        let bytes = p.frames.iter().map(|(_, f)| f.len()).sum();
        (views(&p), bytes)
    }

    #[test]
    fn a_digest_exchange_ends_where_a_full_one_does() {
        let mut sent = [0, 0];
        for seed in 0..500 {
            let (full, full_bytes) = exchanged(mixed_pair(seed, false), false);
            let (digest, digest_bytes) = exchanged(mixed_pair(seed, false), true);
            assert_eq!(full, digest, "seed {seed}");
            sent[0] += full_bytes;
            sent[1] += digest_bytes;
        }
        assert!(sent[1] < sent[0], "{sent:?}");
    }

    /// Whether a view holds a member at `d` at least as late as at `f`, an unknown epoch in
    /// `f` deferring to incarnations.
    fn as_late(d: &(String, State, u32, u64), f: &(String, State, u32, u64)) -> bool {
        let (ds, di, de) = (wire_state(d.1), d.2, d.3);
        let (fs, fi, fe) = (wire_state(f.1), f.2, f.3);
        if de != fe && fe != 0 {
            return life(de, fe) == Life::Later;
        }
        newer(di, fi) || (di == fi && rank(ds) >= rank(fs))
    }

    #[test]
    fn with_unknown_epochs_a_digest_exchange_differs_only_in_what_is_unordered() {
        // Where one side holds a member without an epoch, the two entries cannot be ordered and
        // both records cross. A full exchange's opener merges the peer's record as it stands
        // after the peer merged its own; in a digest exchange the peer merges the opener's
        // after the opener merged the peer's. So the states and incarnations agree, and an
        // epoch only one side knew can end up known on one side or the other; and the opener
        // itself, which refutes what the peer holds about it, sends the refutation along.
        let mut differ = 0;
        for seed in 0..500 {
            let (full, _) = exchanged(mixed_pair(seed, true), false);
            let (digest, _) = exchanged(mixed_pair(seed, true), true);
            for (i, (f, d)) in full.iter().zip(&digest).enumerate() {
                assert_eq!(f.len(), d.len(), "seed {seed}");
                for (f, d) in f.iter().zip(d) {
                    assert_eq!(f.0, d.0, "seed {seed}");
                    differ += usize::from(f != d);
                    if i == 1 && f.0 == "a" {
                        assert!(as_late(d, f), "seed {seed}: {f:?} {d:?}");
                        continue;
                    }
                    assert_eq!((f.1, f.2), (d.1, d.2), "seed {seed}: {f:?} {d:?}");
                    assert!(
                        f.3 == d.3 || f.3 == 0 || d.3 == 0,
                        "seed {seed}: {f:?} {d:?}"
                    );
                }
            }
        }
        assert!(differ > 0);
    }

    #[test]
    fn join_retries_with_backoff_then_fails() {
        let mut p = Pair::new(node("a", 1), node("b", 2));
        p.refuse = true;
        let t0 = Instant::ZERO;
        let cmd = p.nodes[0].command(
            t0,
            Command::Join {
                seeds: vec![addr(2)],
            },
        );
        p.pump(t0);
        let mut attempts = vec![t0];
        let result = loop {
            if let Some(r) = done(&p.events(0), cmd) {
                break r;
            }
            let t = p.nodes[0].poll_timeout().unwrap();
            let before = p.nodes[0].metrics().push_pull_failures;
            p.nodes[0].handle_timeout(t);
            p.pump(t);
            if p.nodes[0].metrics().push_pull_failures > before {
                attempts.push(t);
            }
        };
        assert_eq!(result, Err(CommandError::JoinFailed));
        let interval = p.nodes[0].config().probe_interval;
        // join_retries = 3 attempts, the retries 1 and then 2 probe intervals apart.
        assert_eq!(attempts, [t0, t0 + interval, t0 + interval * 3]);
        assert_eq!(p.nodes[0].metrics().push_pull_failures, 3);
    }

    #[test]
    fn an_unanswered_exchange_times_out() {
        let mut a = node("a", 1);
        let t0 = Instant::ZERO;
        let cmd = a.command(
            t0,
            Command::Join {
                seeds: vec![addr(2)],
            },
        );
        // The seed accepts but never answers.
        while a.poll_transmit().is_some() {}
        let deadline = t0 + a.config().tcp_timeout;
        assert!(a.poll_timeout().unwrap() <= deadline);
        while let Some(t) = a.poll_timeout().filter(|&t| t <= deadline) {
            a.handle_timeout(t);
        }
        assert!(a.sync.streams.is_empty());
        assert_eq!(a.metrics().push_pull_failures, 1);
        assert!(matches!(a.poll_transmit(), Some(Transmit::Close { .. })));
        let ev: Vec<Event> = std::iter::from_fn(|| a.poll_event()).collect();
        assert_eq!(done(&ev, cmd), None, "a retry is due");
    }

    #[test]
    fn a_restarted_node_learns_its_old_incarnation_and_refutes() {
        let t = Instant::ZERO;
        // b remembers an earlier a that died at incarnation 7.
        let mut b = node("b", 2);
        b.add_member(t, "a", addr(1)).unwrap();
        b.on_alive(
            t,
            &Alive {
                inc: 7,
                node: id("a"),
                addr: addr(1),
                meta: b"",
                vmin: 1,
                vmax: 1,
                epoch: 0,
                features: 0,
            },
            &mut b.admission(),
            None,
        );
        b.on_dead(
            t,
            &Dead {
                inc: 7,
                node: id("a"),
                from: id("b"),
                epoch: 0,
            },
            None,
        );
        assert_eq!(b.member("a").unwrap().state, State::Dead);
        let mut p = Pair::new(node("a", 1), b);
        p.events(1);
        p.nodes[0].command(
            t,
            Command::Join {
                seeds: vec![addr(2)],
            },
        );
        p.pump(t);
        assert_eq!(p.nodes[0].local().incarnation, 8);
        // The refutation rides the next packet to b.
        let next = p.nodes[0].poll_timeout().unwrap();
        p.nodes[0].handle_timeout(next);
        p.pump(next);
        let m = p.nodes[1].member("a").unwrap();
        assert_eq!((m.state, m.incarnation), (State::Alive, 8));
        assert!(matches!(&p.events(1)[..], [Event::MemberJoined(m)] if m.name == "a"));
    }

    /// `name` at port `port`, starting at `epoch`, with nonces keyed from `port`'s RNG.
    fn node_at(name: &str, port: u16, epoch: u64) -> Node {
        let cfg = Config::lan(Security::InsecurePlaintext);
        let me = Identity::new(name, addr(port)).unwrap().with_epoch(epoch);
        let mut nonce_key = [0; 32];
        crate::Rng::new(u64::from(port)).fill(&mut nonce_key);
        Node::new(cfg, me, Instant::ZERO, u64::from(port), &nonce_key).unwrap()
    }

    /// b holding a live a at incarnation 7 of the life `epoch`.
    fn remembers_a(epoch: u64) -> Node {
        let t = Instant::ZERO;
        let mut b = node_at("b", 2, 1_000);
        let a = Alive {
            inc: 7,
            node: id("a"),
            addr: addr(1),
            meta: b"",
            vmin: 1,
            vmax: 1,
            epoch,
            features: 0,
        };
        b.on_alive(t, &a, &mut b.admission(), None);
        b
    }

    #[test]
    fn a_restarted_node_replaces_its_old_life_at_a_lower_incarnation() {
        let t = Instant::ZERO;
        let mut p = Pair::new(node_at("a", 1, 200), remembers_a(100));
        p.events(1);
        p.nodes[0].command(
            t,
            Command::Join {
                seeds: vec![addr(2)],
            },
        );
        p.pump(t);
        // The seed took the new life from the join itself: nothing to learn, nothing refuted.
        assert_eq!(p.nodes[0].local().incarnation, 0);
        assert_eq!(p.nodes[0].metrics().refutations, 0);
        let m = p.nodes[1].member("a").unwrap();
        assert_eq!((m.state, m.epoch, m.incarnation), (State::Alive, 200, 0));
        let ev = p.events(1);
        assert!(
            matches!(&ev[..], [Event::MemberLeft(old), Event::MemberJoined(new)]
                if (old.epoch, old.incarnation) == (100, 7) && new.epoch == 200),
            "{ev:?}"
        );
        // A peer's records of the old life, dead at a higher incarnation, suspect nothing and
        // tell a nothing.
        while p.nodes[1].poll_transmit().is_some() {}
        let stale = |state| Record {
            state,
            alive: Alive {
                inc: 9,
                node: id("a"),
                addr: addr(1),
                meta: b"",
                vmin: 1,
                vmax: 1,
                epoch: 100,
                features: 0,
            },
        };
        let records = [
            stale(kinship_proto::State::Dead),
            stale(kinship_proto::State::Left),
            stale(kinship_proto::State::Alive),
        ];
        let b = &mut p.nodes[1];
        b.merge(t, Records::Slice(&records), &mut b.admission());
        let m = b.member("a").unwrap();
        assert_eq!((m.state, m.epoch, m.incarnation), (State::Alive, 200, 0));
        assert!(b.poll_transmit().is_none() && b.poll_event().is_none());
    }

    #[test]
    fn a_node_whose_clock_is_behind_its_last_life_moves_past_it() {
        let t = Instant::ZERO;
        // a's last life started at 300 on a clock that ran ahead; this one reads 200.
        let mut p = Pair::new(node_at("a", 1, 200), remembers_a(300));
        p.events(1);
        p.nodes[0].command(
            t,
            Command::Join {
                seeds: vec![addr(2)],
            },
        );
        p.pump(t);
        // The seed kept the later life it holds; its reply teaches a that life.
        let local = p.nodes[0].local();
        assert_eq!((local.epoch, local.incarnation), (301, 8));
        // The Alive a gossips next replaces that life everywhere.
        let next = p.nodes[0].poll_timeout().unwrap();
        p.nodes[0].handle_timeout(next);
        p.pump(next);
        let m = p.nodes[1].member("a").unwrap();
        assert_eq!((m.state, m.epoch, m.incarnation), (State::Alive, 301, 8));
        let kinds: Vec<_> = p
            .events(1)
            .into_iter()
            .map(|e| match e {
                Event::MemberLeft(m) => ("left", m.epoch),
                Event::MemberJoined(m) => ("joined", m.epoch),
                _ => ("other", 0),
            })
            .collect();
        assert_eq!(kinds, [("left", 300), ("joined", 301)]);
    }

    #[test]
    fn state_too_large_for_a_frame_is_refused() {
        let mut cfg = Config::lan(Security::InsecurePlaintext);
        cfg.limits.max_stream_frame = 256;
        // A frame this small holds only a small user message.
        cfg.max_user_message = 64;
        let me = Identity::new("b", addr(2)).unwrap();
        let mut b = Node::new(cfg, me, Instant::ZERO, 2, &[2; 32]).unwrap();
        for i in 0..20 {
            b.add_member(Instant::ZERO, &format!("member-{i:02}"), addr(100 + i))
                .unwrap();
        }
        let mut p = Pair::new(node("a", 1), b);
        let cmd = p.nodes[0].command(
            Instant::ZERO,
            Command::Join {
                seeds: vec![addr(2)],
            },
        );
        p.pump(Instant::ZERO);
        assert_eq!(p.nodes[1].metrics().state_too_large, 1);
        assert_eq!(p.nodes[0].metrics().push_pull_failures, 1);
        assert_eq!(done(&p.events(0), cmd), None);
    }

    #[test]
    fn oversized_frames_are_dropped_before_they_are_copied() {
        let mut b = node("b", 2);
        let frame = vec![0; b.config().limits.max_stream_frame + 1];
        let conn = StreamId::inbound(0);
        b.handle_stream(Instant::ZERO, conn, StreamEvent::Frame(&frame));
        assert_eq!(b.metrics().decode_errors, 1);
        assert!(b.recv_buf.capacity() < 1024);
        assert_eq!(b.poll_transmit(), Some(Transmit::Close { conn }));
    }

    #[test]
    fn tcp_answers_a_ping_the_udp_path_lost() {
        let t0 = Instant::ZERO;
        let mut a = node("a", 1);
        a.add_member(t0, "b", addr(2)).unwrap();
        let mut p = Pair::new(a, node("b", 2));
        // Drop every datagram a sends; its streams still get through.
        let mut t = t0;
        while p.nodes[0].metrics().tcp_pings == 0 {
            t = p.nodes[0].poll_timeout().unwrap();
            p.nodes[0].handle_timeout(t);
            let out: Vec<Transmit> = std::iter::from_fn(|| p.nodes[0].poll_transmit()).collect();
            for x in out {
                if !matches!(x, Transmit::Datagram { .. }) {
                    p.deliver(t, 0, x);
                }
            }
        }
        p.pump(t);
        assert_eq!(p.nodes[0].metrics().tcp_ping_acks, 1);
        let end = p.nodes[0].next_probe;
        p.nodes[0].handle_timeout(end);
        assert_eq!(p.nodes[0].metrics().probes_failed, 0);
        let suspected = p
            .events(0)
            .iter()
            .any(|e| matches!(e, Event::MemberSuspect(_)));
        assert!(!suspected);
    }

    #[test]
    fn a_merged_suspicion_counts_no_reporter_and_is_not_gossiped() {
        let t = Instant::ZERO;
        let mut a = node("a", 1);
        for (name, port) in [("b", 2), ("c", 3), ("d", 4), ("e", 5)] {
            a.add_member(t, name, addr(port)).unwrap();
        }
        while a.poll_transmit().is_some() {}
        let record = |name: &'static str, port, state| Record {
            state,
            alive: Alive {
                inc: 0,
                node: id(name),
                addr: addr(port),
                meta: b"",
                vmin: 1,
                vmax: 1,
                epoch: 0,
                features: 0,
            },
        };
        // A peer holds b as Suspect and c as Dead.
        let records = [
            record("b", 2, kinship_proto::State::Suspect),
            record("c", 3, kinship_proto::State::Dead),
        ];
        a.merge(t, Records::Slice(&records), &mut a.admission());
        for name in ["b", "c"] {
            assert_eq!(a.member(name).unwrap().state, State::Suspect);
            assert_eq!(a.suspicions[name].confirmations(), 0);
            assert!(!a.out.broadcasts.contains(name), "not gossiped");
        }
        // Only the suspects themselves hear of it, so they can refute.
        let told: Vec<SocketAddr> = std::iter::from_fn(|| a.poll_transmit())
            .filter_map(|t| match t {
                Transmit::Datagram { to, .. } => Some(to),
                _ => None,
            })
            .collect();
        assert_eq!(told, [addr(2), addr(3)]);

        // The first member to report it is its first reporter, not a confirmation.
        let full = a.suspicions["b"].deadline;
        let from = |r| Suspect {
            inc: 0,
            node: id("b"),
            from: id(r),
            epoch: 0,
        };
        a.on_suspect(t, &from("d"), None);
        assert_eq!(a.suspicions["b"].confirmations(), 0);
        assert_eq!(a.suspicions["b"].deadline, full);
        // A merge that repeats it leaves it as it is.
        a.merge(t, Records::Slice(&records[..1]), &mut a.admission());
        assert_eq!(a.suspicions["b"].confirmations(), 0);
        a.on_suspect(t, &from("e"), None);
        assert_eq!(a.suspicions["b"].confirmations(), 1);
        assert!(a.suspicions["b"].deadline < full);
    }

    #[test]
    fn a_leave_counts_only_sends_to_live_members() {
        let t0 = Instant::ZERO;
        let mut a = node("a", 1);
        a.add_member(t0, "b", addr(2)).unwrap();
        a.add_member(t0, "c", addr(3)).unwrap();
        // c was declared dead a moment ago, so gossip still goes to it in case it refutes.
        let dead = Dead {
            inc: 0,
            node: id("c"),
            from: id("b"),
            epoch: 0,
        };
        a.on_dead(t0, &dead, None);
        let cmd = a.command(t0, Command::Leave);
        let limit = a.retransmit_limit();
        let (mut to_b, mut to_c) = (0, 0);
        loop {
            while let Some(t) = a.poll_transmit() {
                if let Transmit::Datagram { to, .. } = t {
                    to_b += usize::from(to == addr(2));
                    to_c += usize::from(to == addr(3));
                }
            }
            let ev: Vec<Event> = std::iter::from_fn(|| a.poll_event()).collect();
            if done(&ev, cmd).is_some() {
                break;
            }
            let t = a.poll_timeout().unwrap();
            a.handle_timeout(t);
        }
        // Every gossip packet carries the Left rumour to both; only b's count.
        assert_eq!(to_b, limit as usize);
        assert!(to_c >= to_b, "{to_c} sends to the dead member");
    }

    #[test]
    fn leaving_gossips_left_and_finishes_when_spread() {
        let t0 = Instant::ZERO;
        let mut a = node("a", 1);
        a.add_member(t0, "b", addr(2)).unwrap();
        let mut b = node("b", 2);
        b.add_member(t0, "a", addr(1)).unwrap();
        let mut p = Pair::new(a, b);
        p.events(0);
        p.events(1);
        let cmd = p.nodes[0].command(t0, Command::Leave);
        let mut t = t0;
        let result = loop {
            if let Some(r) = done(&p.events(0), cmd) {
                break r;
            }
            t = p.nodes[0].poll_timeout().unwrap();
            p.nodes[0].handle_timeout(t);
            p.pump(t);
        };
        assert_eq!(result, Ok(CommandOutput::Done));
        assert_eq!(p.nodes[1].member("a").unwrap().state, State::Left);
        assert!(matches!(&p.events(1)[..], [Event::MemberLeft(m)] if m.name == "a"));
        // The leaver no longer probes or refutes.
        let probes = p.nodes[0].metrics().probes_sent;
        let rumour = Suspect {
            inc: 5,
            node: id("a"),
            from: id("b"),
            epoch: 0,
        };
        p.nodes[0].on_suspect(t, &rumour, None);
        p.nodes[0].handle_timeout(t + Duration::from_secs(5));
        assert_eq!(p.nodes[0].metrics().probes_sent, probes);
        assert_eq!(p.nodes[0].local().incarnation, 0);
        assert_eq!(p.nodes[0].local().state, State::Left);
    }
}
