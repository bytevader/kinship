//! Sans-IO SWIM and Lifeguard protocol state machine.
//!
//! [`Node`] is the whole protocol with no sockets, clock, threads or randomness of its own. A
//! driver feeds it datagrams, stream events, timer expiries and commands, each with the current
//! [`Instant`], and then drains what it should send ([`Node::poll_transmit`]), what the
//! application should hear ([`Node::poll_event`]) and when to wake it next
//! ([`Node::poll_timeout`]). The same seed and the same inputs always give the same outputs,
//! byte for byte, which is what lets `kinship-sim` replay any run from its seed.
//!
//! Encryption happens inside the core: payloads in [`Transmit`] are already sealed, and inputs
//! are the raw bytes off the wire.
//!
//! The protocol is SWIM as described in `docs/design.md`: randomized round-robin probes, direct
//! and indirect pings, suspicion, incarnation numbers, and gossip piggybacked on every packet.
//! Streams carry the rest: joins and periodic anti-entropy as push-pull state exchanges,
//! reconnects to recently dead members, and a TCP fallback ping when a UDP probe goes unanswered.
//! Lifeguard (Dadgar et al., 2017) runs on top, each extension behind its own [`Config`] flag
//! so plain SWIM stays testable: the local health multiplier stretches this node's probe
//! interval and timeout when its own probes fail, missing Nacks from PingReq relays count
//! against it, suspicion timeouts start long and shrink as independent members confirm them,
//! and Pings to a suspected member carry the suspicion so it can refute at once.

mod awareness;
mod broadcast;
mod config;
mod event;
mod io;
mod member;
mod metrics;
mod probe;
mod replay;
mod rng;
mod suspicion;
mod sync;
mod table;
mod time;

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;

use kinship_proto::{KeyringError, Message, NodeId, PacketKind, Payload, sealed_nonce};

use crate::broadcast::Outbox;
use crate::probe::{Probe, Relay};
use crate::replay::Replay;
use crate::suspicion::Suspicion;
use crate::sync::Sync;
use crate::table::{Entry, Table};

pub use config::{Config, ConfigError, Security};
pub use event::{Command, CommandError, CommandId, CommandOutput, Event};
pub use io::{StreamEvent, StreamId, Transmit};
pub use kinship_proto::{Key, KeyError, KeyId, Limits, WIRE_VERSION};
pub use member::{Member, State};
pub use metrics::Metrics;
pub use rng::Rng;
pub use time::Instant;

/// Who this node is: its name, the address peers reach it on, and its metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    name: String,
    addr: SocketAddr,
    meta: Vec<u8>,
}

impl Identity {
    /// `name` must be 1 to 64 bytes of UTF-8 and unique in the cluster; `addr` is the advertised
    /// address, not necessarily the bind address.
    pub fn new(name: impl Into<String>, addr: SocketAddr) -> Result<Self, ConfigError> {
        let name = name.into();
        if NodeId::new(&name).is_err() {
            return Err(ConfigError {
                field: "name",
                reason: "must be 1 to 64 bytes",
            });
        }
        Ok(Self {
            name,
            addr,
            meta: Vec::new(),
        })
    }

    /// Initial metadata; checked against `max_meta_bytes` by [`Node::new`].
    pub fn with_meta(mut self, meta: impl Into<Vec<u8>>) -> Self {
        self.meta = meta.into();
        self
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn meta(&self) -> &[u8] {
        &self.meta
    }
}

/// One cluster member's protocol state machine.
pub struct Node {
    cfg: Config,
    me: Identity,
    /// This node as the cluster sees it; its incarnation only ever rises.
    local: Entry,
    table: Table,
    out: Outbox,
    rng: Rng,
    now: Instant,
    next_command: u64,
    events: VecDeque<Event>,
    /// Inputs are copied here before opening, because the codec decrypts in place.
    recv_buf: Vec<u8>,
    metrics: Metrics,
    /// Last sequence number used for a Ping.
    seq: u32,
    /// When the current probe round ends and the next starts.
    next_probe: Instant,
    probe: Option<Probe>,
    /// PingReqs being relayed, by the sequence number of this node's own Ping.
    relays: BTreeMap<u32, Relay>,
    /// Next gossip tick. Ticks with nothing queued are skipped without waking the driver.
    next_gossip: Instant,
    suspicions: BTreeMap<String, Suspicion>,
    sync: Sync,
    /// Lifeguard's local health multiplier; see [`Node::local_health`].
    health: u32,
    /// Cluster time and the nonces seen inside the replay window.
    replay: Replay,
    /// Whether this node has completed a join: a seed answered one of its own, it answered
    /// another node's, or it was handed its members with [`Node::add_member`]. Until then, and
    /// while a join is in flight, its replay floor moves at once with every time it adopts.
    joined: bool,
}

impl Node {
    /// A node that starts at `now`, drawing every random choice from `seed`.
    ///
    /// Production drivers must take `seed` from the OS RNG, since nonces are drawn from it.
    pub fn new(cfg: Config, me: Identity, now: Instant, seed: u64) -> Result<Self, ConfigError> {
        cfg.validate()?;
        if me.meta.len() > cfg.limits.max_meta_bytes {
            return Err(ConfigError {
                field: "meta",
                reason: "must be at most max_meta_bytes",
            });
        }
        let codec = cfg.codec().map_err(|_| ConfigError {
            field: "security",
            reason: "rejected by the codec",
        })?;
        let mut rng = Rng::new(seed);
        let nonces = rng.fork();
        // Stagger the first probe and gossip tick so nodes started together do not move in
        // lockstep.
        let next_probe = now + jitter(&mut rng, cfg.probe_interval);
        let next_gossip = now + jitter(&mut rng, cfg.gossip_interval);
        let mut first = |interval: core::time::Duration| {
            (!interval.is_zero()).then(|| now + jitter(&mut rng, interval))
        };
        let sync = Sync::new(first(cfg.push_pull_interval), first(cfg.reconnect_interval));
        let replay = Replay::new(replay::window(&cfg), now);
        let local = Entry {
            member: Member {
                name: me.name.clone(),
                addr: me.addr,
                meta: me.meta.clone(),
                state: State::Alive,
                incarnation: 0,
            },
            since: now,
            vmin: 1,
            vmax: WIRE_VERSION,
        };
        let mut node = Self {
            cfg,
            me,
            local,
            table: Table::default(),
            out: Outbox::new(codec, nonces),
            rng,
            now,
            next_command: 0,
            events: VecDeque::new(),
            recv_buf: Vec::new(),
            metrics: Metrics::default(),
            seq: 0,
            next_probe,
            probe: None,
            relays: BTreeMap::new(),
            next_gossip,
            suspicions: BTreeMap::new(),
            sync,
            health: 0,
            replay,
            joined: false,
        };
        node.out.stamp = node.replay.stamp(now);
        node.broadcast(node.local_alive());
        Ok(node)
    }

    /// Learns a member as Alive at incarnation 0 without contacting it, as a static member
    /// list would. Its metadata stays empty until it gossips a newer Alive. Does nothing if the
    /// name is this node's or already known.
    ///
    /// A node given its members this way counts as joined: it has no seed's reply to wait for,
    /// so a later cluster time it hears is a member running ahead, and its replay floor
    /// follows that gradually, as after a clock jump.
    pub fn add_member(
        &mut self,
        now: Instant,
        name: &str,
        addr: SocketAddr,
    ) -> Result<(), ConfigError> {
        self.advance(now);
        if NodeId::new(name).is_err() {
            return Err(ConfigError {
                field: "name",
                reason: "must be 1 to 64 bytes",
            });
        }
        self.joined = true;
        if name == self.local.member.name || self.table.get(name).is_some() {
            return Ok(());
        }
        let member = Member {
            name: name.to_owned(),
            addr,
            meta: Vec::new(),
            state: State::Alive,
            incarnation: 0,
        };
        self.events.push_back(Event::MemberJoined(member.clone()));
        self.table.insert(Entry {
            member,
            since: self.now,
            vmin: 1,
            vmax: WIRE_VERSION,
        });
        Ok(())
    }

    /// A UDP datagram arrived from `from`.
    pub fn handle_datagram(&mut self, now: Instant, from: SocketAddr, buf: &[u8]) {
        self.advance(now);
        // Replies go to the addresses inside the messages, which the AEAD authenticates; the
        // UDP source address is not.
        let _ = from;
        if buf.len() > self.cfg.limits.udp_max_payload {
            self.metrics.decode_errors += 1;
            return;
        }
        let stamp = self.check_stamp(buf);
        if let Stamp::Stale = stamp {
            self.metrics.replays_dropped += 1;
            return;
        }
        let mut scratch = std::mem::take(&mut self.recv_buf);
        scratch.clear();
        scratch.extend_from_slice(buf);
        match self.out.codec.open(PacketKind::Datagram, &mut scratch) {
            Ok(payload) => {
                if self.accept_stamp(&stamp) {
                    self.metrics.packets_received += 1;
                    self.process(&payload);
                }
            }
            Err(e) => self.count_error(&e),
        }
        self.recv_buf = scratch;
        self.check_leave();
    }

    /// Something happened on a TCP connection.
    ///
    /// A connection the driver accepted is answered on its first frame, a push-pull with this
    /// node's state or a Ping with an Ack, and then closed.
    pub fn handle_stream(&mut self, now: Instant, conn: StreamId, ev: StreamEvent<'_>) {
        self.advance(now);
        self.on_stream(conn, ev);
        self.check_leave();
    }

    /// The deadline from [`poll_timeout`](Self::poll_timeout) has passed.
    pub fn handle_timeout(&mut self, now: Instant) {
        self.advance(now);
        let now = self.now;
        self.relay_timers(now);
        self.probe_timers(now);
        self.suspicion_timers(now);
        self.sync_timers(now);
        if now >= self.next_gossip {
            self.gossip(now);
            let interval = self.cfg.gossip_interval;
            let missed = (now - self.next_gossip).as_nanos() / interval.as_nanos();
            let ticks = u32::try_from(missed + 1).unwrap_or(u32::MAX);
            self.next_gossip = self.next_gossip + interval * ticks;
        }
        self.check_leave();
    }

    /// Starts a command; its result arrives as [`Event::CommandDone`], at once for SetMeta
    /// and once the network has answered for Join and Leave.
    pub fn command(&mut self, now: Instant, cmd: Command) -> CommandId {
        self.advance(now);
        let id = CommandId::from_raw(self.next_command);
        self.next_command += 1;
        match cmd {
            Command::SetMeta(_) if self.has_left() => self.finish(id, Err(CommandError::Left)),
            Command::SetMeta(meta) if meta.len() > self.cfg.limits.max_meta_bytes => {
                self.finish(id, Err(CommandError::MetaTooLarge));
            }
            Command::SetMeta(meta) => {
                self.me.meta.clone_from(&meta);
                let local = &mut self.local.member;
                local.meta = meta;
                local.incarnation = local.incarnation.saturating_add(1);
                self.broadcast(self.local_alive());
                self.finish(id, Ok(CommandOutput::Done));
            }
            Command::InstallKey(key) => {
                let r = self.out.codec.install_key(key);
                self.finish_keyring(id, r);
            }
            Command::UseKey(key) => {
                let r = self.out.codec.use_key(&key);
                self.finish_keyring(id, r);
            }
            Command::RemoveKey(key) => {
                let r = self.out.codec.remove_key(&key);
                self.finish_keyring(id, r);
            }
            Command::Join { seeds } => self.join(id, seeds),
            Command::Leave => self.leave(id),
        }
        id
    }

    /// Ids of the keys this node can decrypt with, the one it encrypts with first. Empty when
    /// the node runs without encryption.
    pub fn key_ids(&self) -> Vec<KeyId> {
        self.out.codec.key_ids()
    }

    fn finish_keyring(&mut self, id: CommandId, result: Result<(), KeyringError>) {
        let result = match result {
            Ok(()) => Ok(CommandOutput::Done),
            Err(KeyringError::Plaintext) => Err(CommandError::NotEncrypted),
            Err(KeyringError::NotInstalled) => Err(CommandError::KeyNotInstalled),
            Err(KeyringError::InUse) => Err(CommandError::KeyInUse),
            Err(KeyringError::LastKey) => Err(CommandError::LastKey),
            // Refusals added later fail the command without a name of their own yet.
            Err(_) => Err(CommandError::NotEncrypted),
        };
        self.finish(id, result);
    }

    /// The next thing to send, if any.
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        self.out.transmits.pop_front()
    }

    /// The next event for the application, if any.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// When to call [`handle_timeout`](Self::handle_timeout), if ever.
    pub fn poll_timeout(&self) -> Option<Instant> {
        let mut t = self.probe_deadline();
        if let Some(s) = self.suspicion_deadline() {
            t = t.min(s);
        }
        if let Some(s) = self.sync_deadline() {
            t = t.min(s);
        }
        if !self.out.broadcasts.is_empty() {
            t = t.min(self.next_gossip);
        }
        Some(t)
    }

    pub fn identity(&self) -> &Identity {
        &self.me
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    /// This node as the cluster sees it.
    pub fn local(&self) -> &Member {
        &self.local.member
    }

    /// Alive and suspect members, this node first unless it has left.
    pub fn members(&self) -> impl Iterator<Item = &Member> {
        let me = Some(&self.local.member).filter(|m| m.state.is_live());
        me.into_iter().chain(
            self.table
                .iter()
                .map(|e| &e.member)
                .filter(|m| m.state.is_live()),
        )
    }

    /// Every member this node knows, tombstones included, this node first.
    pub fn all_members(&self) -> impl Iterator<Item = &Member> {
        std::iter::once(&self.local.member).chain(self.table.iter().map(|e| &e.member))
    }

    /// One member by name, including Dead and Left tombstones.
    pub fn member(&self, name: &str) -> Option<&Member> {
        if name == self.local.member.name {
            return Some(&self.local.member);
        }
        self.table.get(name).map(|e| &e.member)
    }

    /// Live members, this node included: the `n` in the timeout and retransmit formulas.
    fn cluster_size(&self) -> usize {
        self.table.live() + 1
    }

    fn advance(&mut self, now: Instant) {
        // Drivers may hand in the same instant twice but never go backwards; clamp if they do.
        self.now = self.now.max(now);
        self.replay.tick(self.now);
        self.out.stamp = self.replay.stamp(self.now);
    }

    /// Checks an encrypted packet's stamp against the replay window, before anything is
    /// decrypted.
    fn check_stamp(&self, buf: &[u8]) -> Stamp {
        if !self.out.codec.is_encrypted() {
            return Stamp::Unchecked;
        }
        // Bytes that are not a sealed packet fail to open, and are counted there.
        let Some(nonce) = sealed_nonce(buf) else {
            return Stamp::Unchecked;
        };
        if self.replay.is_stale(replay::stamp_of(&nonce)) {
            Stamp::Stale
        } else {
            Stamp::Fresh(nonce)
        }
    }

    /// Records the nonce of a packet that authenticated, catching up with its cluster time.
    /// False, and counted, if the packet is a copy of one already accepted.
    fn accept_stamp(&mut self, stamp: &Stamp) -> bool {
        let Stamp::Fresh(nonce) = stamp else {
            return true;
        };
        self.replay
            .set_settling(!self.joined || !self.sync.joins.is_empty());
        if !self.replay.accept(self.now, nonce) {
            self.metrics.replays_dropped += 1;
            return false;
        }
        self.out.stamp = self.replay.stamp(self.now);
        true
    }

    fn count_error(&mut self, e: &kinship_proto::DecodeError) {
        if e.is_auth_failure() {
            self.metrics.decrypt_failures += 1;
        } else {
            self.metrics.decode_errors += 1;
        }
    }

    /// Handles every message of an authenticated payload, in order.
    fn process(&mut self, payload: &Payload<'_>) {
        let now = self.now;
        for msg in payload.iter() {
            match msg {
                Message::Ping(p) => self.on_ping(&p),
                Message::PingReq(r) => self.on_ping_req(now, &r),
                Message::Ack { seq } => self.on_ack(seq),
                Message::Nack { seq } => self.on_nack(seq),
                Message::Alive(a) => self.on_alive(now, &a),
                Message::Suspect(s) => self.on_suspect(now, &s),
                Message::Dead(d) => self.on_dead(now, &d),
                // Push-pull runs over streams only.
                Message::PushPull(_) => {}
            }
        }
    }
}

/// What the replay window says about a packet before it is opened.
#[derive(Debug, Clone, Copy)]
enum Stamp {
    /// Plaintext, or not a sealed packet: nothing to check.
    Unchecked,
    /// Stamped before the replay window.
    Stale,
    /// Inside the window, with this nonce.
    Fresh([u8; kinship_proto::NONCE_LEN]),
}

/// A uniform delay in `[0, max)`.
fn jitter(rng: &mut Rng, max: core::time::Duration) -> core::time::Duration {
    let nanos = u64::try_from(max.as_nanos()).unwrap_or(u64::MAX);
    core::time::Duration::from_nanos(rng.below(nanos))
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Node")
            .field("name", &self.me.name)
            .field("addr", &self.me.addr)
            .field("now", &self.now)
            .field("incarnation", &self.local.member.incarnation)
            .field("members", &self.table.len())
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kinship_proto::{Codec, Message, Ping};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn node(security: Security) -> Node {
        let cfg = Config::local(security);
        Node::new(cfg, Identity::new("a", addr(1)).unwrap(), Instant::ZERO, 7).unwrap()
    }

    #[test]
    fn identity_validates_the_name() {
        assert!(Identity::new("", addr(1)).is_err());
        assert!(Identity::new("x".repeat(65), addr(1)).is_err());
        assert_eq!(Identity::new("ok", addr(1)).unwrap().name(), "ok");
    }

    #[test]
    fn new_rejects_invalid_config_and_meta() {
        let mut cfg = Config::lan(Security::InsecurePlaintext);
        cfg.probe_timeout = cfg.probe_interval * 2;
        let me = Identity::new("a", addr(1)).unwrap();
        assert_eq!(
            Node::new(cfg, me.clone(), Instant::ZERO, 0)
                .unwrap_err()
                .field,
            "probe_timeout"
        );
        let cfg = Config::lan(Security::InsecurePlaintext);
        let me = me.with_meta(vec![0; 513]);
        assert_eq!(
            Node::new(cfg, me, Instant::ZERO, 0).unwrap_err().field,
            "meta"
        );
    }

    #[test]
    fn counts_good_and_bad_datagrams() {
        let key = Key::from_bytes([3; 32]);
        let mut n = node(Security::Keys(vec![key.clone()]));
        let codec = Codec::encrypted(b"default", Limits::default(), vec![key]).unwrap();
        let mut pkt = Vec::new();
        let ping = Message::Ping(Ping {
            seq: 1,
            target: NodeId::new("a").unwrap(),
            source: NodeId::new("b").unwrap(),
            source_addr: addr(2),
        });
        codec
            .seal(PacketKind::Datagram, &[ping], &[9; 24], &mut pkt)
            .unwrap();
        n.handle_datagram(Instant::ZERO, addr(2), &pkt);
        assert_eq!(n.metrics().packets_received, 1);

        let last = pkt.len() - 1;
        pkt[last] ^= 1;
        n.handle_datagram(Instant::ZERO, addr(2), &pkt);
        assert_eq!(n.metrics().decrypt_failures, 1);

        n.handle_datagram(Instant::ZERO, addr(2), b"garbage");
        assert_eq!(n.metrics().decode_errors, 1);
    }

    /// A Ping sealed at cluster time `stamp` (milliseconds), with random bytes `tail`.
    fn stamped_ping(codec: &Codec, stamp: u64, tail: u8) -> Vec<u8> {
        let ping = Message::Ping(Ping {
            seq: 1,
            target: NodeId::new("a").unwrap(),
            source: NodeId::new("b").unwrap(),
            source_addr: addr(2),
        });
        let mut nonce = [tail; 24];
        nonce[..8].copy_from_slice(&stamp.to_be_bytes());
        let mut pkt = Vec::new();
        codec
            .seal(PacketKind::Datagram, &[ping], &nonce, &mut pkt)
            .unwrap();
        pkt
    }

    #[test]
    fn copies_and_stale_datagrams_are_dropped_as_replays() {
        let key = Key::from_bytes([3; 32]);
        let mut n = node(Security::Keys(vec![key.clone()]));
        let codec = Codec::encrypted(b"default", Limits::default(), vec![key]).unwrap();
        let acks = |n: &mut Node| std::iter::from_fn(|| n.poll_transmit()).count();
        let secs = |s: u64| Instant::ZERO + core::time::Duration::from_secs(s);
        // A member of a cluster that has been running for a minute, waking every second.
        n.add_member(Instant::ZERO, "b", addr(2)).unwrap();
        let run = |n: &mut Node, from: u64, to: u64| {
            for s in from..=to {
                n.handle_timeout(secs(s));
                acks(n);
            }
        };
        run(&mut n, 1, 60);
        let t = secs(60);

        let pkt = stamped_ping(&codec, 55_000, 1);
        n.handle_datagram(t, addr(2), &pkt);
        assert_eq!(acks(&mut n), 1, "a fresh Ping is answered");
        n.handle_datagram(t, addr(2), &pkt);
        assert_eq!(acks(&mut n), 0, "its copy is not");
        assert_eq!(n.metrics().replays_dropped, 1);

        // Sealed 31 s before this node's cluster time: dropped before it is decrypted.
        let old = stamped_ping(&codec, 29_000, 2);
        n.handle_datagram(t, addr(2), &old);
        assert_eq!(acks(&mut n), 0);
        assert_eq!(n.metrics().replays_dropped, 2);
        assert_eq!(n.metrics().packets_received, 1);
        assert_eq!(n.metrics().decrypt_failures, 0);

        // A member whose clock jumped two minutes ahead moves this node's cluster time
        // forward. Members still on the old timeline are heard while they catch up.
        let ahead = stamped_ping(&codec, 180_000, 3);
        n.handle_datagram(t, addr(2), &ahead);
        assert_eq!(acks(&mut n), 1);
        n.handle_datagram(t, addr(2), &stamped_ping(&codec, 60_000, 4));
        assert_eq!(acks(&mut n), 1, "the old timeline, a moment later");
        // Two minutes on, the floor has caught up, and that timeline is stale.
        run(&mut n, 61, 180);
        n.handle_datagram(secs(180), addr(2), &stamped_ping(&codec, 61_000, 5));
        assert_eq!(acks(&mut n), 0);
        assert_eq!(n.metrics().replays_dropped, 3);
    }

    #[test]
    fn until_it_has_joined_a_node_moves_its_floor_with_every_time_it_adopts() {
        let key = Key::from_bytes([3; 32]);
        let codec = Codec::encrypted(b"default", Limits::default(), vec![key.clone()]).unwrap();
        let secs = |s: u64| Instant::ZERO + core::time::Duration::from_secs(s);
        // Another node that has just started reaches this one first; then the cluster's time
        // arrives, an hour on; then a recording from ten minutes before that.
        let hear = |n: &mut Node| {
            n.handle_datagram(secs(1), addr(2), &stamped_ping(&codec, 2_000, 1));
            n.handle_datagram(secs(1), addr(2), &stamped_ping(&codec, 3_600_000, 2));
            n.handle_datagram(secs(1), addr(2), &stamped_ping(&codec, 3_000_000, 3));
            n.metrics().replays_dropped
        };
        let mut new = node(Security::Keys(vec![key.clone()]));
        assert_eq!(hear(&mut new), 1, "a node that has not joined refuses it");

        // A node handed its members has joined: the hour looks like a member's clock jump,
        // and the floor follows it gradually.
        let mut listed = node(Security::Keys(vec![key.clone()]));
        listed.add_member(Instant::ZERO, "b", addr(2)).unwrap();
        assert_eq!(hear(&mut listed), 0);

        // The same node with a join in flight takes the seed's time at once.
        let mut joining = node(Security::Keys(vec![key]));
        joining.add_member(Instant::ZERO, "b", addr(2)).unwrap();
        joining.command(
            Instant::ZERO,
            Command::Join {
                seeds: vec![addr(9)],
            },
        );
        assert_eq!(hear(&mut joining), 1);
    }

    #[test]
    fn stream_frames_are_opened() {
        let mut n = node(Security::InsecurePlaintext);
        let codec = Codec::insecure_plaintext(b"default", Limits::default()).unwrap();
        let mut frame = Vec::new();
        codec
            .seal(
                PacketKind::Stream,
                &[Message::Ack { seq: 4 }],
                &[0; 24],
                &mut frame,
            )
            .unwrap();
        let conn = StreamId::inbound(0);
        n.handle_stream(Instant::ZERO, conn, StreamEvent::Frame(&frame));
        n.handle_stream(Instant::ZERO, conn, StreamEvent::Closed);
        assert_eq!(n.metrics().packets_received, 1);
    }

    #[test]
    fn commands_complete_with_their_id() {
        let mut n = node(Security::InsecurePlaintext);
        let a = n.command(Instant::ZERO, Command::SetMeta(b"role=db".to_vec()));
        let b = n.command(Instant::ZERO, Command::SetMeta(vec![0; 513]));
        let c = n.command(Instant::ZERO, Command::Leave);
        assert_ne!(a, b);
        let d = n.command(Instant::ZERO, Command::SetMeta(Vec::new()));
        let done = |id, result| Some(Event::CommandDone { id, result });
        assert_eq!(n.poll_event(), done(a, Ok(CommandOutput::Done)));
        assert_eq!(n.poll_event(), done(b, Err(CommandError::MetaTooLarge)));
        // Alone, a node leaves at once, and then refuses to change.
        assert_eq!(n.poll_event(), done(c, Ok(CommandOutput::Done)));
        assert_eq!(n.poll_event(), done(d, Err(CommandError::Left)));
        assert_eq!(n.poll_event(), None);
        assert_eq!(n.identity().meta(), b"role=db");
        assert_eq!(n.local().meta, b"role=db");
        assert_eq!(n.local().incarnation, 1, "set_meta is a self-refutation");
        assert_eq!(n.local().state, State::Left);
        assert_eq!(n.members().count(), 0);
        // Alone, it has nobody to send to.
        assert_eq!(n.poll_transmit(), None);
    }

    fn plaintext() -> Codec {
        Codec::insecure_plaintext(b"default", Limits::default()).unwrap()
    }

    fn deliver(n: &mut Node, now: Instant, msgs: &[Message<'_>]) {
        let mut pkt = Vec::new();
        plaintext()
            .seal(PacketKind::Datagram, msgs, &[0; 24], &mut pkt)
            .unwrap();
        n.handle_datagram(now, addr(99), &pkt);
    }

    fn sent(n: &mut Node) -> Vec<(SocketAddr, Vec<u8>)> {
        std::iter::from_fn(|| n.poll_transmit())
            .map(|t| match t {
                Transmit::Datagram { to, mut payload } => {
                    let inner = plaintext()
                        .open(PacketKind::Datagram, &mut payload)
                        .map(|p| format!("{p:?}"))
                        .unwrap();
                    (to, inner.into_bytes())
                }
                other => panic!("unexpected {other:?}"),
            })
            .collect()
    }

    fn id(s: &str) -> NodeId<'_> {
        NodeId::new(s).unwrap()
    }

    fn alive(node: &str, inc: u32, port: u16) -> Message<'_> {
        Message::Alive(kinship_proto::Alive {
            inc,
            node: id(node),
            addr: addr(port),
            meta: b"",
            vmin: 1,
            vmax: 1,
        })
    }

    fn suspect<'a>(node: &'a str, inc: u32, from: &'a str) -> Message<'a> {
        Message::Suspect(kinship_proto::Suspect {
            inc,
            node: id(node),
            from: id(from),
        })
    }

    fn dead<'a>(node: &'a str, inc: u32, from: &'a str) -> Message<'a> {
        Message::Dead(kinship_proto::Dead {
            inc,
            node: id(node),
            from: id(from),
        })
    }

    fn events(n: &mut Node) -> Vec<Event> {
        std::iter::from_fn(|| n.poll_event()).collect()
    }

    fn kinds(n: &mut Node) -> Vec<&'static str> {
        events(n)
            .iter()
            .map(|e| match e {
                Event::MemberJoined(_) => "joined",
                Event::MemberSuspect(_) => "suspect",
                Event::MemberRecovered(_) => "recovered",
                Event::MemberDead(_) => "dead",
                Event::MemberLeft(_) => "left",
                Event::MemberUpdated { .. } => "updated",
                Event::NameConflict { .. } => "conflict",
                Event::CommandDone { .. } => "done",
            })
            .collect()
    }

    #[test]
    fn rumours_follow_incarnation_precedence() {
        let mut n = node(Security::InsecurePlaintext);
        let t = Instant::ZERO;
        n.add_member(t, "b", addr(2)).unwrap();
        assert_eq!(kinds(&mut n), ["joined"]);
        let state = |n: &Node| {
            let m = n.member("b").unwrap();
            (m.state, m.incarnation)
        };

        deliver(&mut n, t, &[suspect("b", 0, "c")]);
        assert_eq!(kinds(&mut n), ["suspect"]);
        assert_eq!(state(&n), (State::Suspect, 0));
        // Alive needs a higher incarnation to beat Suspect.
        deliver(&mut n, t, &[alive("b", 0, 2)]);
        assert_eq!(state(&n), (State::Suspect, 0));
        deliver(&mut n, t, &[alive("b", 1, 2)]);
        assert_eq!(kinds(&mut n), ["recovered"]);
        assert_eq!(state(&n), (State::Alive, 1));
        // Stale Suspect and Dead lose.
        deliver(&mut n, t, &[suspect("b", 0, "c"), dead("b", 0, "c")]);
        assert_eq!(state(&n), (State::Alive, 1));
        assert_eq!(kinds(&mut n), Vec::<&str>::new());
        // Dead wins at the same incarnation, and a tombstone yields only to a newer Alive.
        deliver(&mut n, t, &[dead("b", 1, "c")]);
        assert_eq!(kinds(&mut n), ["dead"]);
        deliver(&mut n, t, &[alive("b", 1, 2), suspect("b", 5, "c")]);
        assert_eq!(state(&n), (State::Dead, 1));
        deliver(&mut n, t, &[alive("b", 2, 2)]);
        assert_eq!(kinds(&mut n), ["joined"]);
        assert_eq!(state(&n), (State::Alive, 2));
        // Dead from the member itself means it left.
        deliver(&mut n, t, &[dead("b", 2, "b")]);
        assert_eq!(kinds(&mut n), ["left"]);
        assert_eq!(state(&n), (State::Left, 2));
        // Unknown members are not created from Suspect or Dead.
        deliver(&mut n, t, &[suspect("x", 0, "c"), dead("y", 0, "c")]);
        assert!(n.member("x").is_none() && n.member("y").is_none());
    }

    #[test]
    fn gossip_goes_to_live_and_recently_dead_members_never_to_those_that_left() {
        let mut n = node(Security::InsecurePlaintext);
        let t = Instant::ZERO;
        for (name, port) in [("b", 2), ("c", 3), ("d", 4)] {
            n.add_member(t, name, addr(port)).unwrap();
        }
        // c left, and d was declared dead.
        deliver(&mut n, t, &[dead("c", 0, "c"), dead("d", 0, "b")]);
        sent(&mut n);
        let targets = |n: &mut Node, now| {
            n.gossip(now);
            let mut to: Vec<SocketAddr> = sent(n).into_iter().map(|(to, _)| to).collect();
            to.sort();
            to
        };
        assert_eq!(targets(&mut n, t), [addr(2), addr(4)]);
        // Once d has been dead for gossip_to_the_dead, it is not sent to either.
        let later = t + n.config().gossip_to_the_dead;
        deliver(&mut n, later, &[alive("b", 1, 2)]);
        sent(&mut n);
        assert_eq!(targets(&mut n, later), [addr(2)]);
    }

    #[test]
    fn a_suspicion_at_a_newer_incarnation_restarts_the_timer() {
        let mut n = node(Security::InsecurePlaintext);
        let t0 = Instant::ZERO;
        for (name, port) in [("b", 2), ("c", 3), ("d", 4), ("e", 5)] {
            n.add_member(t0, name, addr(port)).unwrap();
        }
        deliver(&mut n, t0, &[suspect("b", 0, "c")]);
        let first = n.suspicions["b"].deadline;
        // b refuted at 1 and was suspected again; its Alive never reached us.
        let t1 = t0 + n.config().probe_interval;
        deliver(&mut n, t1, &[suspect("b", 1, "d")]);
        assert_eq!(n.member("b").unwrap().incarnation, 1);
        let s = &n.suspicions["b"];
        assert_eq!(s.deadline, first + (t1 - t0), "a fresh timer");
        assert_eq!(
            s.confirmations(),
            0,
            "confirmations of the old one do not carry over"
        );
    }

    #[test]
    fn rumours_about_self_are_refuted() {
        let mut n = node(Security::InsecurePlaintext);
        let t = Instant::ZERO;
        deliver(&mut n, t, &[suspect("a", 0, "c")]);
        assert_eq!(n.local().incarnation, 1);
        deliver(&mut n, t, &[dead("a", 4, "c")]);
        assert_eq!(n.local().incarnation, 5);
        // Stale rumours are ignored.
        deliver(&mut n, t, &[suspect("a", 3, "c")]);
        assert_eq!(n.local().incarnation, 5);
        assert_eq!(n.metrics().refutations, 2);
        assert_eq!(n.local().state, State::Alive);
        assert_eq!(kinds(&mut n), Vec::<&str>::new(), "no events about self");
        assert_eq!(n.local_health(), 2, "each refutation raises local health");
    }

    #[test]
    fn a_stale_rumour_about_this_node_queues_its_alive_again() {
        let mut n = node(Security::InsecurePlaintext);
        let t = Instant::ZERO;
        deliver(&mut n, t, &[suspect("a", 0, "c")]);
        assert_eq!(n.local().incarnation, 1);
        // The refutation has finished spreading, and c missed it.
        n.out.broadcasts.forget("a");
        let before = (n.local_health(), n.metrics().refutations);
        // c's buddy Ping: the stale suspicion first, then the Ping.
        let ping = Message::Ping(Ping {
            seq: 7,
            target: id("a"),
            source: id("c"),
            source_addr: addr(3),
        });
        deliver(&mut n, t, &[suspect("a", 0, "c"), ping]);
        let pkts = sent(&mut n);
        assert!(contains(&pkts, addr(3), "Ack { seq: 7 }"), "{pkts:?}");
        assert!(
            contains(&pkts, addr(3), r#"Alive(Alive { inc: 1, node: "a""#),
            "the Ack carries the refutation again: {pkts:?}"
        );
        assert_eq!(n.local().incarnation, 1);
        assert_eq!(
            (n.local_health(), n.metrics().refutations),
            before,
            "not a refutation"
        );
        // A stale Dead too.
        n.out.broadcasts.forget("a");
        deliver(&mut n, t, &[dead("a", 0, "c")]);
        assert!(n.out.broadcasts.contains("a"));
        // A node that left stays gone.
        n.command(t, Command::Leave);
        n.out.broadcasts.forget("a");
        deliver(&mut n, t, &[suspect("a", 0, "c"), dead("a", 0, "c")]);
        assert!(!n.out.broadcasts.contains("a"));
    }

    #[test]
    fn a_second_live_node_cannot_take_a_name() {
        let mut n = node(Security::InsecurePlaintext);
        let t = Instant::ZERO;
        n.add_member(t, "b", addr(2)).unwrap();
        events(&mut n);
        deliver(&mut n, t, &[alive("b", 3, 9), alive("a", 3, 9)]);
        let ev = events(&mut n);
        assert!(matches!(&ev[0], Event::NameConflict { member, other_addr }
            if member.name == "b" && *other_addr == addr(9)));
        assert!(matches!(&ev[1], Event::NameConflict { member, .. } if member.name == "a"));
        assert_eq!(n.member("b").unwrap().addr, addr(2));
        assert_eq!(n.local().incarnation, 0);
    }

    #[test]
    fn metadata_changes_are_reported() {
        let mut n = node(Security::InsecurePlaintext);
        let t = Instant::ZERO;
        n.add_member(t, "b", addr(2)).unwrap();
        events(&mut n);
        let a = Message::Alive(kinship_proto::Alive {
            inc: 1,
            node: id("b"),
            addr: addr(2),
            meta: b"zone=x",
            vmin: 1,
            vmax: 1,
        });
        deliver(&mut n, t, &[a]);
        let ev = events(&mut n);
        assert!(
            matches!(&ev[..], [Event::MemberUpdated { member, previous_meta }]
            if member.meta == b"zone=x" && previous_meta.is_empty())
        );
    }

    /// Runs `n`'s timers until `until`, returning what it sent.
    fn run_until(n: &mut Node, until: Instant) -> Vec<(SocketAddr, Vec<u8>)> {
        let mut out = Vec::new();
        while let Some(t) = n.poll_timeout().filter(|&t| t <= until) {
            n.handle_timeout(t);
            out.extend(sent(n));
        }
        out
    }

    fn contains(pkts: &[(SocketAddr, Vec<u8>)], to: SocketAddr, needle: &str) -> bool {
        pkts.iter()
            .any(|(a, p)| *a == to && String::from_utf8_lossy(p).contains(needle))
    }

    /// Fires `n`'s timers until `done` holds for an event, returning the packets sent and the
    /// time of that event.
    fn run_to_event(
        n: &mut Node,
        pkts: &mut Vec<(SocketAddr, Vec<u8>)>,
        done: impl Fn(&Event) -> bool,
    ) -> (Instant, Event) {
        loop {
            let t = n.poll_timeout().unwrap();
            n.handle_timeout(t);
            pkts.extend(sent(n));
            if let Some(e) = events(n).into_iter().find(|e| done(e)) {
                return (t, e);
            }
        }
    }

    #[test]
    fn silent_targets_are_probed_indirectly_then_suspected_then_declared_dead() {
        let mut n = node(Security::InsecurePlaintext);
        let t0 = Instant::ZERO;
        n.add_member(t0, "b", addr(2)).unwrap();
        n.add_member(t0, "c", addr(3)).unwrap();
        events(&mut n);
        let mut pkts = Vec::new();
        let (suspected_at, ev) =
            run_to_event(&mut n, &mut pkts, |e| matches!(e, Event::MemberSuspect(_)));
        let Event::MemberSuspect(m) = ev else {
            unreachable!()
        };
        let (target, relay) = if m.name == "b" {
            (addr(2), addr(3))
        } else {
            (addr(3), addr(2))
        };
        // A direct Ping, then a PingReq through the other member, then suspicion.
        assert!(contains(&pkts, target, "Ping("));
        assert!(contains(&pkts, relay, "PingReq("), "{pkts:?}");
        assert!(suspected_at <= t0 + n.config().probe_interval * 2);

        let mut pkts = Vec::new();
        let name = m.name.clone();
        let (dead_at, _) = run_to_event(
            &mut n,
            &mut pkts,
            |e| matches!(e, Event::MemberDead(d) if d.name == name),
        );
        // Nobody else can confirm, so the Lifeguard timeout stays at its maximum.
        assert_eq!(
            dead_at - suspected_at,
            suspicion::min_timeout(n.config(), 3) * n.config().suspicion_max_mult
        );
        assert!(contains(&pkts, relay, "Suspect("), "suspicion is gossiped");
        let mut pkts = Vec::new();
        let end = dead_at + n.config().probe_interval * 2;
        while let Some(t) = n.poll_timeout().filter(|&t| t <= end) {
            n.handle_timeout(t);
            pkts.extend(sent(&mut n));
        }
        assert!(contains(&pkts, relay, "Dead("), "death is gossiped");

        // The tombstone is reaped after dead_reclaim, at the end of a probe round, which the
        // failed rounds have stretched.
        assert!(n.local_health() > 0);
        let end = dead_at + n.config().dead_reclaim + n.probe_interval();
        while let Some(t) = n.poll_timeout().filter(|&t| t <= end) {
            n.handle_timeout(t);
        }
        assert!(n.member(&m.name).is_none());
    }

    #[test]
    fn acked_probes_raise_no_suspicion() {
        let mut n = node(Security::InsecurePlaintext);
        let t0 = Instant::ZERO;
        n.add_member(t0, "b", addr(2)).unwrap();
        events(&mut n);
        let interval = n.config().probe_interval;
        for round in 1..=5 {
            let end = t0 + interval * round;
            while let Some(now) = n.poll_timeout().filter(|&t| t <= end) {
                n.handle_timeout(now);
                let out: Vec<Transmit> = std::iter::from_fn(|| n.poll_transmit()).collect();
                for t in out {
                    let Transmit::Datagram { mut payload, .. } = t else {
                        continue;
                    };
                    let codec = plaintext();
                    let p = codec.open(PacketKind::Datagram, &mut payload).unwrap();
                    let seqs: Vec<u32> = p
                        .iter()
                        .filter_map(|m| match m {
                            Message::Ping(p) => Some(p.seq),
                            _ => None,
                        })
                        .collect();
                    for seq in seqs {
                        deliver(&mut n, now, &[Message::Ack { seq }]);
                    }
                }
            }
        }
        assert_eq!(n.metrics().probes_failed, 0);
        assert!(n.metrics().probes_sent >= 4);
        assert_eq!(events(&mut n), Vec::new());
    }

    /// A node whose probe rounds a test drives one at a time.
    struct Rounds {
        n: Node,
        /// What the round in progress has sent so far, still unanswered.
        pending: Vec<Transmit>,
    }

    impl Rounds {
        fn new(cfg: Config) -> Self {
            let me = Identity::new("a", addr(1)).unwrap();
            let mut n = Node::new(cfg, me, Instant::ZERO, 7).unwrap();
            for (name, port) in [("b", 2), ("c", 3), ("d", 4), ("e", 5)] {
                n.add_member(Instant::ZERO, name, addr(port)).unwrap();
            }
            events(&mut n);
            let mut r = Self {
                n,
                pending: Vec::new(),
            };
            // Up to the start of the first round.
            r.round(|_| None);
            r
        }

        /// Runs the round in progress to its end, delivering whatever `reply` returns for each
        /// message sent during it. The next round starts and its Ping waits in `pending`.
        fn round(&mut self, reply: impl Fn(&Message<'_>) -> Option<Message<'static>>) {
            let end = self.n.next_probe;
            let mut out = std::mem::take(&mut self.pending);
            let mut now = self.n.now;
            loop {
                for t in out.drain(..) {
                    let Transmit::Datagram { mut payload, .. } = t else {
                        continue;
                    };
                    let codec = plaintext();
                    let p = codec.open(PacketKind::Datagram, &mut payload).unwrap();
                    let replies: Vec<Message<'static>> =
                        p.iter().filter_map(|m| reply(&m)).collect();
                    if !replies.is_empty() {
                        deliver(&mut self.n, now, &replies);
                    }
                }
                let Some(t) = self.n.poll_timeout().filter(|&t| t <= end) else {
                    return;
                };
                now = t;
                self.n.handle_timeout(t);
                out.extend(std::iter::from_fn(|| self.n.poll_transmit()));
                if t == end {
                    self.pending = out;
                    return;
                }
            }
        }
    }

    #[test]
    fn local_health_follows_probe_outcomes() {
        let mut r = Rounds::new(Config::local(Security::InsecurePlaintext));
        // Every relay answers with a Nack: the target is down, not this node.
        r.round(|m| match m {
            Message::PingReq(req) => {
                assert!(req.want_nack);
                Some(Message::Nack { seq: req.seq })
            }
            _ => None,
        });
        assert_eq!(r.n.metrics().probes_failed, 1);
        assert_eq!(r.n.metrics().indirect_probes, 3);
        assert_eq!(r.n.local_health(), 0);
        // Silent relays: one point per relay. The suspect from the last round is not asked.
        r.round(|_| None);
        assert_eq!(r.n.metrics().probes_failed, 2);
        assert_eq!(r.n.metrics().missed_nacks, 2);
        assert_eq!(r.n.local_health(), 2);
        assert_eq!(
            r.n.next_probe - r.n.now,
            r.n.config().probe_interval * 3,
            "rounds stretch"
        );
        // An Ack brings it back down by one.
        r.round(|m| match m {
            Message::Ping(p) => Some(Message::Ack { seq: p.seq }),
            _ => None,
        });
        assert_eq!(r.n.metrics().probes_failed, 2);
        assert_eq!(r.n.local_health(), 1);
    }

    #[test]
    fn plain_swim_keeps_health_at_zero_and_asks_for_no_nacks() {
        let cfg = Config::local(Security::InsecurePlaintext).without_lifeguard();
        let mut r = Rounds::new(cfg);
        for _ in 0..3 {
            r.round(|m| {
                if let Message::PingReq(req) = m {
                    assert!(!req.want_nack);
                }
                None
            });
        }
        assert_eq!(r.n.metrics().probes_failed, 3);
        assert_eq!(r.n.local_health(), 0);
        assert_eq!(r.n.next_probe - r.n.now, r.n.config().probe_interval);
    }

    #[test]
    fn pings_to_a_suspect_carry_the_suspicion_first() {
        for buddy in [true, false] {
            let mut cfg = Config::local(Security::InsecurePlaintext);
            cfg.buddy_system = buddy;
            let mut n = node(Security::InsecurePlaintext);
            n.cfg = cfg;
            let t = Instant::ZERO;
            n.add_member(t, "b", addr(2)).unwrap();
            deliver(&mut n, t, &[suspect("b", 0, "c")]);
            assert_eq!(n.member("b").unwrap().state, State::Suspect);
            let mut pkts = Vec::new();
            while n.metrics().probes_sent == 0 {
                let t = n.poll_timeout().unwrap();
                n.handle_timeout(t);
                pkts.extend(sent(&mut n));
            }
            let ping = pkts
                .iter()
                .map(|(_, p)| String::from_utf8_lossy(p).into_owned())
                .find(|p| p.contains("Ping("))
                .unwrap();
            let own = r#"Suspect(Suspect { inc: 0, node: "b", from: "a" })"#;
            if buddy {
                let first = ping.find(own).expect(&ping);
                assert!(first < ping.find("Ping(").unwrap(), "{ping}");
            } else {
                assert!(!ping.contains(own), "{ping}");
            }
        }
    }

    #[test]
    fn relays_forward_acks_and_send_nacks() {
        let mut n = node(Security::InsecurePlaintext);
        let t = Instant::ZERO;
        let req = |seq| {
            Message::PingReq(kinship_proto::PingReq {
                seq,
                target: id("b"),
                target_addr: addr(2),
                requester_addr: addr(3),
                want_nack: true,
            })
        };
        deliver(&mut n, t, &[req(40)]);
        let pkts = sent(&mut n);
        assert!(contains(&pkts, addr(2), "Ping("));
        // Find our own sequence number in the Ping and answer it.
        let relay_seq = n.seq;
        deliver(&mut n, t, &[Message::Ack { seq: relay_seq }]);
        assert!(contains(&sent(&mut n), addr(3), "Ack { seq: 40 }"));

        deliver(&mut n, t, &[req(41)]);
        sent(&mut n);
        let timeout = n.config().probe_timeout;
        let pkts = run_until(&mut n, t + timeout);
        assert!(contains(&pkts, addr(3), "Nack { seq: 41 }"), "{pkts:?}");
        assert!(n.relays.is_empty());
    }

    #[test]
    fn relays_tell_the_requester_that_a_target_left() {
        let mut n = node(Security::InsecurePlaintext);
        let t = Instant::ZERO;
        n.add_member(t, "b", addr(2)).unwrap();
        deliver(&mut n, t, &[dead("b", 3, "b")]);
        assert_eq!(n.member("b").unwrap().state, State::Left);
        sent(&mut n);
        let req = Message::PingReq(kinship_proto::PingReq {
            seq: 9,
            target: id("b"),
            target_addr: addr(2),
            requester_addr: addr(3),
            want_nack: true,
        });
        deliver(&mut n, t, &[req]);
        let pkts = sent(&mut n);
        assert!(contains(&pkts, addr(3), "Dead(Dead { inc: 3"), "{pkts:?}");
        assert!(!contains(&pkts, addr(2), "Ping("), "{pkts:?}");
        assert!(n.relays.is_empty());
    }

    #[test]
    fn stream_ids_do_not_collide() {
        assert_ne!(StreamId::outbound(5), StreamId::inbound(5));
        assert!(StreamId::inbound(5).is_inbound());
        assert!(!StreamId::outbound(5).is_inbound());
        assert_eq!(StreamId::inbound(5).index(), 5);
        let id = StreamId::inbound(9);
        assert_eq!(StreamId::from_raw(id.to_raw()), id);
    }
}
