//! The stream half of the protocol: push-pull state exchange and merge, join, periodic
//! anti-entropy, reconnects to recently dead members, the TCP fallback ping, and leaving.
//!
//! Every exchange is one short-lived connection. The side that opens it writes one frame and
//! waits for one frame back; the side that accepts it answers the first frame and closes. The
//! accepting side keeps no state between the two, so a peer that opens many connections costs
//! nothing beyond the frames it actually sends, and those are bounded by `max_stream_frame`
//! before the driver buffers them and again before the core copies them.

use core::net::SocketAddr;
use core::time::Duration;
use std::collections::BTreeMap;

use kinship_proto::{Alive, Dead, Message, PacketKind, Ping, PushPull, Record, Records, Suspect};

use crate::Node;
use crate::broadcast::{Gossip, id};
use crate::event::{CommandError, CommandId, CommandOutput, Event};
use crate::io::{StreamEvent, StreamId, Transmit};
use crate::member::State;
use crate::time::Instant;

/// Why this node opened a connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Purpose {
    /// Seed `seed` of the join started by command `cmd`.
    Join { cmd: CommandId, seed: usize },
    /// Periodic anti-entropy with a live member, or a reconnect to a dead one.
    Sync,
    /// The TCP fallback ping of the probe round with this sequence number.
    Ping { seq: u32 },
}

/// A connection this node opened and is waiting on.
#[derive(Debug, Clone)]
pub(crate) struct Outbound {
    purpose: Purpose,
    deadline: Instant,
}

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
    next_push_pull: Option<Instant>,
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
            next_push_pull: first_push_pull,
            next_reconnect: first_reconnect,
            leaving: None,
        }
    }
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

/// The first tick of `interval` after `now` that follows `prev`, skipping missed ones.
fn next_tick(prev: Instant, now: Instant, interval: Duration) -> Instant {
    let missed = (now - prev).as_nanos() / interval.as_nanos();
    prev + interval * u32::try_from(missed + 1).unwrap_or(u32::MAX)
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
                if let Some(o) = self.sync.streams.remove(&conn) {
                    // The peer hung up or the connection broke before it answered.
                    self.exchange_failed(o.purpose);
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
        // Checked before the copy below, as the driver's framer already did before buffering.
        if frame.len() > self.cfg.limits.max_stream_frame {
            self.metrics.decode_errors += 1;
            return self.end_stream(conn, false);
        }
        let mut scratch = std::mem::take(&mut self.recv_buf);
        scratch.clear();
        scratch.extend_from_slice(frame);
        let answered = match self.out.codec.open(PacketKind::Stream, &mut scratch) {
            Ok(payload) => {
                self.metrics.packets_received += 1;
                let mut answered = false;
                for msg in payload.iter() {
                    answered = if conn.is_inbound() {
                        self.serve(now, conn, &msg)
                    } else {
                        self.on_reply(now, conn, &msg)
                    };
                    if answered {
                        break;
                    }
                }
                answered
            }
            Err(e) => {
                self.count_error(&e);
                false
            }
        };
        self.recv_buf = scratch;
        self.end_stream(conn, answered);
    }

    /// Answers the first frame of a connection a peer opened. True if `msg` was answered.
    fn serve(&mut self, now: Instant, conn: StreamId, msg: &Message<'_>) -> bool {
        match msg {
            Message::PushPull(p) => {
                self.merge(now, p.records);
                if self.send_state(conn, false) {
                    self.metrics.push_pulls_served += 1;
                }
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
            _ => false,
        }
    }

    /// Handles the reply on a connection this node opened. True if `msg` was the reply.
    fn on_reply(&mut self, now: Instant, conn: StreamId, msg: &Message<'_>) -> bool {
        let Some(purpose) = self.sync.streams.get(&conn).map(|o| o.purpose) else {
            return false;
        };
        match (purpose, msg) {
            (Purpose::Join { .. } | Purpose::Sync, Message::PushPull(p)) => {
                self.merge(now, p.records);
                self.metrics.push_pulls += 1;
                if let Purpose::Join { cmd, seed } = purpose {
                    self.seed_done(now, cmd, seed, true);
                }
                true
            }
            (Purpose::Ping { seq }, Message::Ack { seq: acked }) if seq == *acked => {
                if let Some(p) = self.probe.as_mut().filter(|p| p.seq == seq && !p.acked) {
                    p.acked = true;
                    self.metrics.tcp_ping_acks += 1;
                }
                true
            }
            _ => false,
        }
    }

    /// Closes `conn` after its frame was handled; an outbound exchange that got no usable
    /// reply has failed.
    fn end_stream(&mut self, conn: StreamId, answered: bool) {
        if let Some(o) = self.sync.streams.remove(&conn) {
            if !answered {
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
            Purpose::Ping { .. } => {}
        }
    }

    /// Merges a peer's member table with the precedence rules, as gossip would.
    ///
    /// As in memberlist, a peer's Dead record becomes a suspicion rather than a death: this
    /// node may have heard from the member more recently, and a suspicion gives the member the
    /// chance to refute. Records about members this node does not know only add them if Alive.
    fn merge(&mut self, now: Instant, records: Records<'_>) {
        let me = self.local.member.name.clone();
        for r in records.iter() {
            let a = r.alive;
            match r.state {
                kinship_proto::State::Alive => self.on_alive(now, &a),
                kinship_proto::State::Left => self.on_dead(
                    now,
                    &Dead {
                        inc: a.inc,
                        node: a.node,
                        from: a.node,
                    },
                ),
                kinship_proto::State::Suspect | kinship_proto::State::Dead => self.on_suspect(
                    now,
                    &Suspect {
                        inc: a.inc,
                        node: a.node,
                        from: id(&me),
                    },
                ),
            }
        }
    }

    /// Writes this node's whole view, tombstones included, to `conn`. False if it does not fit.
    fn send_state(&mut self, conn: StreamId, join: bool) -> bool {
        let records: Vec<Record<'_>> = std::iter::once(&self.local)
            .chain(self.table.iter())
            .map(|e| Record {
                state: wire_state(e.member.state),
                alive: Alive {
                    inc: e.member.incarnation,
                    node: id(&e.member.name),
                    addr: e.member.addr,
                    meta: &e.member.meta,
                    vmin: e.vmin,
                    vmax: e.vmax,
                },
            })
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

    /// Opens a connection to `to` and remembers why.
    fn connect(&mut self, to: SocketAddr, purpose: Purpose) -> StreamId {
        let conn = StreamId::outbound(self.sync.next_stream);
        self.sync.next_stream += 1;
        self.out.transmits.push_back(Transmit::Connect { conn, to });
        let deadline = self.now + self.cfg.tcp_timeout;
        self.sync
            .streams
            .insert(conn, Outbound { purpose, deadline });
        conn
    }

    /// Opens a push-pull exchange with `to`.
    fn push_pull(&mut self, to: SocketAddr, purpose: Purpose) {
        let conn = self.connect(to, purpose);
        let join = matches!(purpose, Purpose::Join { .. });
        if !self.send_state(conn, join) {
            self.end_stream(conn, false);
        }
    }

    /// Sends the probe of round `seq` to `to` over TCP as well; the stream is closed with the
    /// round.
    pub(crate) fn tcp_ping(&mut self, to: SocketAddr, target: &str, seq: u32) -> StreamId {
        let conn = self.connect(to, Purpose::Ping { seq });
        let ping = Message::Ping(Ping {
            seq,
            target: id(target),
            source: id(&self.local.member.name),
            source_addr: self.local.member.addr,
        });
        self.out.frame(conn, &[ping]);
        self.metrics.tcp_pings += 1;
        conn
    }

    /// Abandons a connection without counting a failure.
    pub(crate) fn close_stream(&mut self, conn: StreamId) {
        if self.sync.streams.remove(&conn).is_some() {
            self.out.transmits.push_back(Transmit::Close { conn });
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
            })
            .collect();
        self.sync.joins.insert(id, Join { seeds, answered: 0 });
        for (seed, addr) in addrs.into_iter().enumerate() {
            self.push_pull(addr, Purpose::Join { cmd: id, seed });
        }
    }

    /// Records the outcome of one attempt with a seed and finishes the join when it can.
    ///
    /// A join waits for the first attempt with every seed, so it can say how many answered.
    /// Seeds that failed are retried, with backoff, only while none has answered.
    fn seed_done(&mut self, now: Instant, cmd: CommandId, seed: usize, ok: bool) {
        let retries = self.cfg.join_retries;
        let base = self.cfg.probe_interval;
        let Some(join) = self.sync.joins.get_mut(&cmd) else {
            return;
        };
        let Some(s) = join.seeds.get_mut(seed) else {
            return;
        };
        if ok {
            s.state = SeedState::Answered;
            join.answered += 1;
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
        let me = &mut self.local.member;
        me.state = State::Left;
        let gossip = Gossip::Dead {
            inc: me.incarnation,
            node: me.name.clone(),
            from: me.name.clone(),
        };
        self.broadcast(gossip);
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

    /// Finishes a pending Leave once the Left rumour is spread, or nobody is left to tell.
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
        for conn in expired {
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
                    retries.push((s.addr, Purpose::Join { cmd, seed: i }));
                }
            }
        }
        for (addr, purpose) in retries {
            self.push_pull(addr, purpose);
        }

        if let Some(t) = self.sync.next_push_pull.filter(|&t| t <= now) {
            self.sync.next_push_pull = Some(next_tick(t, now, self.cfg.push_pull_interval));
            if !self.has_left() {
                let to = self
                    .table
                    .random(1, &mut self.rng, |e| e.member.state.is_live())
                    .first()
                    .map(|e| e.member.addr);
                if let Some(to) = to {
                    self.push_pull(to, Purpose::Sync);
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
                    .map(|e| e.member.addr);
                if let Some(to) = to {
                    self.push_pull(to, Purpose::Sync);
                }
            }
        }
    }

    pub(crate) fn sync_deadline(&self) -> Option<Instant> {
        let streams = self.sync.streams.values().map(|o| o.deadline);
        let retries = self.sync.joins.values().flat_map(|j| {
            j.seeds.iter().filter_map(|s| match s.state {
                SeedState::Waiting(t) if j.answered == 0 => Some(t),
                _ => None,
            })
        });
        streams
            .chain(retries)
            .chain(self.sync.next_push_pull)
            .chain(self.sync.next_reconnect)
            .min()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::{Config, Security};
    use crate::event::Command;
    use crate::{Identity, Member};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn node(name: &str, port: u16) -> Node {
        let cfg = Config::lan(Security::InsecurePlaintext);
        let me = Identity::new(name, addr(port)).unwrap();
        Node::new(cfg, me, Instant::ZERO, u64::from(port)).unwrap()
    }

    /// Two nodes on a perfect network: datagrams to the other's address arrive, and
    /// connections to it are accepted, unless `refuse` is set.
    struct Pair {
        nodes: [Node; 2],
        /// Each end of a connection, mapped to the other end.
        conns: BTreeMap<(usize, StreamId), (usize, StreamId)>,
        accepted: u64,
        refuse: bool,
    }

    impl Pair {
        fn new(a: Node, b: Node) -> Self {
            Self {
                nodes: [a, b],
                conns: BTreeMap::new(),
                accepted: 0,
                refuse: false,
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
                        self.deliver(now, i, t);
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
            match t {
                Transmit::Datagram { to, payload } => {
                    if to == self.nodes[j].local().addr {
                        self.nodes[j].handle_datagram(now, from, &payload);
                    }
                }
                Transmit::Connect { conn, .. } if self.refuse => {
                    self.nodes[i].handle_stream(now, conn, StreamEvent::Failed);
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
            },
        );
        b.on_dead(
            t,
            &Dead {
                inc: 7,
                node: id("a"),
                from: id("b"),
            },
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

    #[test]
    fn state_too_large_for_a_frame_is_refused() {
        let mut cfg = Config::lan(Security::InsecurePlaintext);
        cfg.limits.max_stream_frame = 256;
        let me = Identity::new("b", addr(2)).unwrap();
        let mut b = Node::new(cfg, me, Instant::ZERO, 2).unwrap();
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
        };
        p.nodes[0].on_suspect(t, &rumour);
        p.nodes[0].handle_timeout(t + Duration::from_secs(5));
        assert_eq!(p.nodes[0].metrics().probes_sent, probes);
        assert_eq!(p.nodes[0].local().incarnation, 0);
        assert_eq!(p.nodes[0].local().state, State::Left);
    }
}
