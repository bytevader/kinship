//! User messages in the simulator, between nodes of this version and, where a test says so,
//! nodes running the released kinship-core 0.3.0, which knows nothing of them (`docs/design.md`,
//! User messages):
//!
//! 1. Direct messages and broadcasts from random members at random times reach their members:
//!    a direct message at most once, a broadcast at most once on every node and never on its
//!    sender, and no node sends a copy of a broadcast more often than the retransmit rule
//!    allows. Messages too large for a datagram go over TCP and arrive whole.
//! 2. Limits: a sender refuses data over its own limits, and a node whose max_user_broadcast is
//!    lower than the sender's drops a broadcast over it, counts it and does not relay it.
//! 3. A node that restarts drops a message meant for its previous run, and a sender that has
//!    heard of the restart refuses one; one for the new run arrives.
//! 4. A 0.3.0 node in the cluster skips both message types: it counts no decode error,
//!    membership goes on as before, and the newer nodes still hear every broadcast.
//!
//! Each test runs a few fixed seeds; `KINSHIP_SEED=<seed>` replays one, and
//! `user_messages_thousand_seeds` runs 1,000 in release mode in CI.

mod common;

use std::cell::RefCell;
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::rc::Rc;

use common::{check_all, ms, secs, seeds};
use kinship_core::{
    Command, CommandError, CommandId, CommandOutput, Config, Event, Identity, Instant, Key, Limits,
    Node, Rng, Security, StreamEvent, StreamId, Transmit,
};
use kinship_core_0_3 as old;
use kinship_proto::{Codec, Message, PacketKind};
use kinship_sim::{
    Action, LinkConfig, NodeSpec, Scenario, Sim, SimNode, TraceConfig, WALL_CLOCK_AT_ZERO_MS,
    addr_of, name_of,
};
use serde::Serialize;

/// A message a node delivered to its application.
#[derive(Debug, Clone)]
struct Delivery {
    at: usize,
    from: String,
    data: Vec<u8>,
    broadcast: bool,
}

/// What the nodes of one run report, shared by all of them.
#[derive(Debug, Default)]
struct Record {
    delivered: Vec<Delivery>,
    /// Membership events: which node, what, and about whom.
    membership: Vec<(usize, &'static str, String)>,
    /// Command results, by node, in the order they finished.
    done: Vec<(usize, Result<CommandOutput, CommandError>)>,
    /// Datagrams each node sent with a copy of each broadcast, by (node, sender, seq).
    copies: BTreeMap<(usize, String, u64), u32>,
}

type Log = Rc<RefCell<Record>>;

enum Inner {
    New(Node),
    /// The released kinship-core 0.3.0.
    Old(old::Node),
}

/// A node of this version, or of 0.3.0, that reports into a shared [`Record`].
struct Peer {
    inner: Inner,
    index: usize,
    log: Log,
    /// Opens what this node sends, to count the copies of broadcasts in it.
    codec: Codec,
}

/// An event of either version, for the trace.
#[derive(Serialize)]
#[serde(untagged)]
enum PeerEvent {
    New(Event),
    Old(old::Event),
}

/// The key every node of the run of `seed` shares, drawn from the seed.
fn cluster_key(seed: u64) -> [u8; 32] {
    let mut key = [0; 32];
    // "keys" in ASCII, so that the key's stream is not the seed's own.
    Rng::new(seed ^ 0x6b65_7973).fill(&mut key);
    key
}

fn to_old(t: Instant) -> old::Instant {
    old::Instant::from_nanos(t.as_nanos())
}

fn stream_id(id: old::StreamId) -> StreamId {
    StreamId::from_raw(id.to_raw())
}

impl Peer {
    /// Node `spec`, on 0.3.0 if `on_0_3` and otherwise on this version with `tune` applied to
    /// its config. It knows every other node from the start, as a static member list would.
    fn new(
        spec: &NodeSpec,
        log: &Log,
        key: [u8; 32],
        on_0_3: bool,
        tune: &dyn Fn(usize, &mut Config),
    ) -> Self {
        let others: Vec<usize> = (0..spec.nodes).filter(|&j| j != spec.index).collect();
        let inner = if on_0_3 {
            let cfg = old::Config::lan(old::Security::Keys(vec![old::Key::from_bytes(key)]));
            let me = old::Identity::new(spec.name.clone(), spec.addr)
                .unwrap()
                .with_epoch(spec.epoch());
            let now = to_old(spec.now);
            let mut n = old::Node::new(cfg, me, now, spec.seed, &spec.nonce_key()).unwrap();
            for &j in &others {
                n.add_member(now, &name_of(j), addr_of(j)).unwrap();
            }
            while n.poll_event().is_some() {}
            Inner::Old(n)
        } else {
            let mut cfg = Config::lan(Security::Keys(vec![Key::from_bytes(key)]));
            tune(spec.index, &mut cfg);
            let me = Identity::new(spec.name.clone(), spec.addr)
                .unwrap()
                .with_epoch(spec.epoch());
            let mut n = Node::new(cfg, me, spec.now, spec.seed, &spec.nonce_key()).unwrap();
            for &j in &others {
                n.add_member(spec.now, &name_of(j), addr_of(j)).unwrap();
            }
            while n.poll_event().is_some() {}
            Inner::New(n)
        };
        let codec = Codec::encrypted(b"default", Limits::default(), vec![Key::from_bytes(key)])
            .expect("the run's key");
        Self {
            inner,
            index: spec.index,
            log: log.clone(),
            codec,
        }
    }

    fn node(&self) -> &Node {
        match &self.inner {
            Inner::New(n) => n,
            Inner::Old(_) => panic!("n{} runs 0.3.0", self.index),
        }
    }

    fn decode_errors(&self) -> u64 {
        match &self.inner {
            Inner::New(n) => n.metrics().decode_errors,
            Inner::Old(n) => n.metrics().decode_errors,
        }
    }

    /// Counts the broadcasts in a datagram this node sends.
    fn count_copies(&self, payload: &[u8]) {
        let mut buf = payload.to_vec();
        let Ok(p) = self.codec.open(PacketKind::Datagram, &mut buf) else {
            return;
        };
        let mut log = self.log.borrow_mut();
        for m in p.iter() {
            if let Message::UserBroadcast(b) = m {
                let key = (self.index, b.from.as_str().to_owned(), b.seq);
                *log.copies.entry(key).or_default() += 1;
            }
        }
    }
}

impl SimNode for Peer {
    type Command = Command;
    type Event = PeerEvent;

    fn handle_datagram(&mut self, now: Instant, from: SocketAddr, buf: &[u8]) {
        match &mut self.inner {
            Inner::New(n) => n.handle_datagram(now, from, buf),
            Inner::Old(n) => n.handle_datagram(to_old(now), from, buf),
        }
    }

    fn handle_stream(&mut self, now: Instant, conn: StreamId, ev: StreamEvent<'_>) {
        match &mut self.inner {
            Inner::New(n) => n.handle_stream(now, conn, ev),
            Inner::Old(n) => {
                let ev = match ev {
                    StreamEvent::Frame(f) => old::StreamEvent::Frame(f),
                    StreamEvent::Closed => old::StreamEvent::Closed,
                    StreamEvent::Failed => old::StreamEvent::Failed,
                };
                n.handle_stream(to_old(now), old::StreamId::from_raw(conn.to_raw()), ev);
            }
        }
    }

    fn handle_timeout(&mut self, now: Instant) {
        match &mut self.inner {
            Inner::New(n) => n.handle_timeout(now),
            Inner::Old(n) => n.handle_timeout(to_old(now)),
        }
    }

    fn command(&mut self, now: Instant, cmd: Command) -> CommandId {
        match &mut self.inner {
            Inner::New(n) => n.command(now, cmd),
            Inner::Old(n) => {
                let cmd = match cmd {
                    Command::Join { seeds } => old::Command::Join { seeds },
                    Command::Leave => old::Command::Leave,
                    Command::SetMeta(meta) => old::Command::SetMeta(meta),
                    // 0.3.0 has no user messages to send.
                    _ => return CommandId::from_raw(u64::MAX),
                };
                CommandId::from_raw(n.command(to_old(now), cmd).to_raw())
            }
        }
    }

    fn poll_transmit(&mut self) -> Option<Transmit> {
        match &mut self.inner {
            Inner::New(n) => {
                let t = n.poll_transmit()?;
                if let Transmit::Datagram { payload, .. } = &t {
                    self.count_copies(payload);
                }
                Some(t)
            }
            Inner::Old(n) => Some(match n.poll_transmit()? {
                old::Transmit::Datagram { to, payload } => Transmit::Datagram { to, payload },
                old::Transmit::Connect { conn, to } => Transmit::Connect {
                    conn: stream_id(conn),
                    to,
                },
                old::Transmit::Stream { conn, frame } => Transmit::Stream {
                    conn: stream_id(conn),
                    frame,
                },
                old::Transmit::Close { conn } => Transmit::Close {
                    conn: stream_id(conn),
                },
            }),
        }
    }

    fn poll_event(&mut self) -> Option<PeerEvent> {
        let at = self.index;
        match &mut self.inner {
            Inner::New(n) => {
                let e = n.poll_event()?;
                let mut log = self.log.borrow_mut();
                let member = match &e {
                    Event::UserMessage {
                        sender,
                        data,
                        broadcast,
                    } => {
                        log.delivered.push(Delivery {
                            at,
                            from: sender.name.clone(),
                            data: data.clone(),
                            broadcast: *broadcast,
                        });
                        None
                    }
                    Event::CommandDone { result, .. } => {
                        log.done.push((at, *result));
                        None
                    }
                    Event::MemberJoined(m) => Some(("joined", m)),
                    Event::MemberSuspect(m) => Some(("suspect", m)),
                    Event::MemberRecovered(m) => Some(("recovered", m)),
                    Event::MemberDead(m) => Some(("dead", m)),
                    Event::MemberLeft(m) => Some(("left", m)),
                    _ => None,
                };
                if let Some((kind, m)) = member {
                    log.membership.push((at, kind, m.name.clone()));
                }
                drop(log);
                Some(PeerEvent::New(e))
            }
            Inner::Old(n) => {
                let e = n.poll_event()?;
                let member = match &e {
                    old::Event::MemberJoined(m) => Some(("joined", m)),
                    old::Event::MemberSuspect(m) => Some(("suspect", m)),
                    old::Event::MemberRecovered(m) => Some(("recovered", m)),
                    old::Event::MemberDead(m) => Some(("dead", m)),
                    old::Event::MemberLeft(m) => Some(("left", m)),
                    _ => None,
                };
                if let Some((kind, m)) = member {
                    let name = m.name.clone();
                    self.log.borrow_mut().membership.push((at, kind, name));
                }
                Some(PeerEvent::Old(e))
            }
        }
    }

    fn poll_timeout(&self) -> Option<Instant> {
        match &self.inner {
            Inner::New(n) => n.poll_timeout(),
            Inner::Old(n) => n.poll_timeout().map(|t| Instant::from_nanos(t.as_nanos())),
        }
    }
}

fn send(node: usize, to: usize, epoch: u64, data: Vec<u8>) -> Action<Command> {
    let to = name_of(to);
    let cmd = Command::Send { to, epoch, data };
    Action::Command { node, cmd }
}

fn broadcast(node: usize, data: Vec<u8>) -> Action<Command> {
    let cmd = Command::Broadcast(data);
    Action::Command { node, cmd }
}

/// Runs `scenario` from `seed`: the last `on_0_3` nodes run 0.3.0, the others this version with
/// `tune` applied to their config.
fn run(
    seed: u64,
    scenario: Scenario<Command>,
    on_0_3: usize,
    tune: impl Fn(usize, &mut Config) + 'static,
) -> (Sim<Peer>, Log) {
    let key = cluster_key(seed);
    let log = Log::default();
    let shared = log.clone();
    let mut sim = Sim::new(seed, scenario, move |spec| {
        let old = spec.index >= spec.nodes - on_0_3;
        Peer::new(spec, &shared, key, old, &tune)
    });
    sim.run();
    (sim, log)
}

/// How often each node may send one broadcast in a cluster of `n` live members:
/// retransmit_mult × ceil(log10(n + 1)), with lan()'s retransmit_mult of 4.
fn retransmit_limit(n: usize) -> u32 {
    let mut digits = 0;
    let mut p = 1;
    while p < n + 1 {
        p *= 10;
        digits += 1;
    }
    4 * digits
}

/// Expected and actual deliveries of one run, by kind.
#[derive(Debug, Default, Clone, Copy)]
struct Outcome {
    broadcasts: (usize, usize),
    small: (usize, usize),
    large: (usize, usize),
}

impl std::ops::AddAssign for Outcome {
    fn add_assign(&mut self, o: Self) {
        let add = |a: &mut (usize, usize), b: (usize, usize)| {
            a.0 += b.0;
            a.1 += b.1;
        };
        add(&mut self.broadcasts, o.broadcasts);
        add(&mut self.small, o.small);
        add(&mut self.large, o.large);
    }
}

/// A run of `nodes`, the last `on_0_3` of them on 0.3.0, in which random nodes of this version
/// make four broadcasts and send six direct messages, every other one too large for a datagram,
/// at random times in the first ten seconds. Checks what must always hold, and returns how many
/// of the messages arrived.
fn traffic(seed: u64, nodes: usize, on_0_3: usize, link: LinkConfig) -> Result<Outcome, String> {
    let mut rng = Rng::new(seed);
    let new: Vec<usize> = (0..nodes - on_0_3).collect();
    let mut scenario = Scenario::new(nodes)
        .link(link)
        .trace(TraceConfig::OFF)
        .duration(secs(40));
    let mut broadcasts = Vec::new();
    for i in 0..4 {
        let from = new[rng.index(new.len())];
        let data = format!("broadcast {i} from n{from}").into_bytes();
        scenario = scenario.at(ms(1_000 + rng.below(9_000)), broadcast(from, data.clone()));
        broadcasts.push((from, data));
    }
    let mut direct = Vec::new();
    for i in 0..6 {
        let from = new[rng.index(new.len())];
        let to = (from + 1 + rng.index(new.len() - 1)) % new.len();
        let mut data = format!("message {i} from n{from} to n{to}").into_bytes();
        if i % 2 == 1 {
            data.resize(5_000, b'.');
        }
        scenario = scenario.at(
            ms(1_000 + rng.below(9_000)),
            send(from, to, 0, data.clone()),
        );
        direct.push((from, to, data));
    }
    let (sim, log) = run(seed, scenario, on_0_3, |_, _| {});
    let rec = log.borrow();
    let fail = |what: String| {
        Err(format!(
            "seed {seed}, {nodes} nodes, {on_0_3} on 0.3: {what}"
        ))
    };

    let mut times: BTreeMap<(usize, &[u8]), usize> = BTreeMap::new();
    for d in &rec.delivered {
        *times.entry((d.at, &d.data[..])).or_default() += 1;
    }
    if let Some(((at, data), n)) = times.iter().find(|&(_, &n)| n > 1) {
        return fail(format!(
            "n{at} delivered {:?} {n} times",
            String::from_utf8_lossy(data)
        ));
    }
    let mut out = Outcome::default();
    for (from, data) in &broadcasts {
        if times.contains_key(&(*from, &data[..])) {
            return fail(format!("n{from} delivered its own broadcast"));
        }
        let reached = new
            .iter()
            .filter(|&&i| i != *from && times.contains_key(&(i, &data[..])))
            .count();
        out.broadcasts.0 += new.len() - 1;
        out.broadcasts.1 += reached;
    }
    for (from, to, data) in &direct {
        let got = rec
            .delivered
            .iter()
            .find(|d| d.at == *to && d.data == *data);
        if let Some(d) = got {
            if d.from != name_of(*from) || d.broadcast {
                return fail(format!("n{to} got {d:?}"));
            }
        }
        let slot = if data.len() > 1_000 {
            &mut out.large
        } else {
            &mut out.small
        };
        slot.0 += 1;
        slot.1 += usize::from(got.is_some());
    }
    // Streams are reliable while both ends run, so every message sent over TCP arrives.
    if out.large.1 != out.large.0 {
        return fail(format!("{:?} of the large messages arrived", out.large));
    }
    if rec.done.iter().any(|(_, r)| r.is_err()) {
        return fail(format!("a send was refused: {:?}", rec.done));
    }
    let limit = retransmit_limit(nodes);
    if let Some(((node, from, seq), n)) = rec.copies.iter().find(|&(_, &n)| n > limit) {
        return fail(format!(
            "n{node} sent {from}'s broadcast {seq} {n} times, over {limit}"
        ));
    }
    for i in 0..nodes {
        let errors = sim.node(i).map_or(0, Peer::decode_errors);
        if errors > 0 {
            return fail(format!("n{i} counted {errors} decode errors"));
        }
    }
    Ok(out)
}

fn ratio((expected, got): (usize, usize)) -> f64 {
    if expected == 0 {
        1.0
    } else {
        got as f64 / expected as f64
    }
}

#[test]
fn messages_reach_their_members_once() {
    let outcomes = check_all(seeds(8), |seed| traffic(seed, 8, 0, LinkConfig::lan()));
    let mut total = Outcome::default();
    for o in outcomes {
        total += o;
    }
    // On a lossless link every direct message arrives. A broadcast reaches each member with the
    // probability a rumour does, and nothing repairs a miss, since push-pull carries membership
    // only: a member none of the others happened to pick never hears it.
    assert_eq!(total.small.1, total.small.0, "{total:?}");
    assert!(ratio(total.broadcasts) >= 0.98, "{total:?}");
}

#[test]
fn oversized_messages_are_refused_by_the_sender_and_dropped_by_a_stricter_receiver() {
    for seed in seeds(4) {
        let over_256 = vec![b'b'; 400];
        let scenario = Scenario::new(4)
            .link(LinkConfig::lan())
            .trace(TraceConfig::OFF)
            .duration(secs(20))
            .at(secs(2), broadcast(0, over_256.clone()))
            .at(secs(2), broadcast(1, over_256.clone()))
            .at(secs(2), send(1, 2, 0, vec![0; 64 * 1024 + 1]))
            .at(secs(2), send(1, 2, 0, vec![1; 64 * 1024]));
        // n0 allows larger broadcasts than everyone else.
        let tune = |i: usize, cfg: &mut Config| {
            if i == 0 {
                cfg.max_user_broadcast = 512;
            }
        };
        let (sim, log) = run(seed, scenario, 0, tune);
        let rec = log.borrow();
        let n1: Vec<_> = rec.done.iter().filter(|d| d.0 == 1).map(|d| d.1).collect();
        let too_large = Err(CommandError::MessageTooLarge);
        assert_eq!(
            n1,
            [too_large, too_large, Ok(CommandOutput::Done)],
            "seed {seed}"
        );
        assert!(
            rec.delivered.iter().all(|d| d.data != over_256),
            "seed {seed}"
        );
        for i in 1..4 {
            let m = sim.node(i).unwrap().node().metrics();
            assert!(m.user_messages_too_large >= 1, "seed {seed}: n{i} {m:?}");
        }
        let relayed = rec
            .copies
            .keys()
            .filter(|(node, from, _)| *node != 0 && from == "n0");
        assert_eq!(
            relayed.count(),
            0,
            "seed {seed}: nobody relays n0's broadcast"
        );
        let whole = vec![1; 64 * 1024];
        assert!(
            rec.delivered.iter().any(|d| d.at == 2 && d.data == whole),
            "seed {seed}: the largest message arrives whole"
        );
    }
}

#[test]
fn a_message_for_an_earlier_run_is_dropped_by_the_new_one() {
    let first_run = WALL_CLOCK_AT_ZERO_MS;
    for seed in seeds(4) {
        let scenario = Scenario::new(4)
            .link(LinkConfig::lan())
            .trace(TraceConfig::OFF)
            .duration(secs(30))
            .at(secs(5), Action::Restart(2))
            // At the same instant, before n0 can hear of the restart: for the run it holds.
            .at(secs(5), send(0, 2, 0, b"for the old run".to_vec()))
            // Once n0 knows: one for the old run is refused, one for any run arrives.
            .at(secs(15), send(0, 2, first_run, b"refused".to_vec()))
            .at(secs(15), send(0, 2, 0, b"for the new run".to_vec()));
        let (sim, log) = run(seed, scenario, 0, |_, _| {});
        let rec = log.borrow();
        let at_n2: Vec<&[u8]> = rec
            .delivered
            .iter()
            .filter(|d| d.at == 2)
            .map(|d| &d.data[..])
            .collect();
        assert_eq!(at_n2, [b"for the new run"], "seed {seed}");
        let n0: Vec<_> = rec.done.iter().filter(|d| d.0 == 0).map(|d| d.1).collect();
        let done = Ok(CommandOutput::Done);
        assert_eq!(
            n0,
            [done, Err(CommandError::NotAMember), done],
            "seed {seed}"
        );
        let new_run = sim.node(2).unwrap().node();
        assert_eq!(new_run.local().epoch, first_run + 5_000);
        assert_eq!(new_run.metrics().user_messages_dropped, 1, "seed {seed}");
    }
}

/// Five nodes, n4 on 0.3.0: two broadcasts, direct messages between newer nodes, and a small
/// and a large one to n4. Returns how many of the newer nodes' deliveries of the broadcasts
/// were expected and how many happened.
fn mixed(seed: u64) -> Result<(usize, usize), String> {
    let scenario = Scenario::new(5)
        .link(LinkConfig::lan())
        .trace(TraceConfig::OFF)
        .duration(secs(30))
        .at(secs(2), broadcast(0, b"b0".to_vec()))
        .at(secs(2), broadcast(1, b"b1".to_vec()))
        .at(secs(3), send(0, 4, 0, b"small, to 0.3".to_vec()))
        .at(secs(3), send(2, 4, 0, vec![7; 5_000]))
        .at(secs(3), send(3, 1, 0, b"small".to_vec()))
        .at(secs(3), send(1, 2, 0, vec![8; 5_000]));
    let (sim, log) = run(seed, scenario, 1, |_, _| {});
    let rec = log.borrow();
    let fail = |what: String| Err(format!("seed {seed}: {what}"));
    let count = |at: usize, data: &[u8]| {
        rec.delivered
            .iter()
            .filter(|d| d.at == at && d.data == data)
            .count()
    };
    let mut broadcasts = (0, 0);
    for (from, data) in [(0, &b"b0"[..]), (1, b"b1")] {
        for at in (0..4).filter(|&i| i != from) {
            if count(at, data) > 1 {
                return fail(format!(
                    "n{at} delivered {data:?} {} times",
                    count(at, data)
                ));
            }
            broadcasts.0 += 1;
            broadcasts.1 += count(at, data);
        }
    }
    if count(1, b"small") != 1 || count(2, &[8; 5_000]) != 1 {
        return fail("a message between newer nodes was lost".to_owned());
    }
    if rec.done.iter().any(|(_, r)| r.is_err()) {
        return fail(format!("a send was refused: {:?}", rec.done));
    }
    // Membership goes on as before: nobody is suspected, and n4 holds everyone alive.
    if let Some(e) = rec.membership.iter().find(|(_, kind, _)| *kind != "joined") {
        return fail(format!("{e:?}"));
    }
    let Some(Inner::Old(n4)) = sim.node(4).map(|p| &p.inner) else {
        return fail("n4 is not on 0.3.0".to_owned());
    };
    let m = n4.metrics();
    if m.decode_errors != 0 || m.decrypt_failures != 0 || m.packets_received == 0 {
        return fail(format!("n4 counted {m:?}"));
    }
    if n4.members().count() != 5 {
        return fail("n4 does not hold every member alive".to_owned());
    }
    // A frame n4 cannot read ends with its close, which the sender cannot tell from a delivery.
    let n2 = sim.node(2).unwrap().node().metrics();
    if n2.user_messages_dropped != 0 || n2.user_messages_sent != 1 {
        return fail(format!("n2 counted {n2:?}"));
    }
    Ok(broadcasts)
}

#[test]
fn a_0_3_node_in_the_cluster_skips_user_messages() {
    let reached = check_all(seeds(8), mixed);
    let total = reached.iter().fold((0, 0), |a, b| (a.0 + b.0, a.1 + b.1));
    // Copies sent to the 0.3.0 node are lost, so the newer nodes hear a broadcast a little less
    // surely than in a cluster of newer nodes alone.
    assert!(ratio(total) >= 0.9, "{total:?}");
}

/// The sweep CI runs: 1,000 seeds of random traffic in clusters of 5 to 16 nodes, a third of
/// them with nodes on 0.3.0, under loss, duplication and reordering, then the restart and the
/// 0.3.0 runs above. A failure prints its seed; replay it with `KINSHIP_SEED=<seed>`.
#[test]
#[ignore = "slow in debug builds; CI runs it with --release"]
fn user_messages_thousand_seeds() {
    let seeds = seeds(1000);
    let started = std::time::Instant::now();
    let outcomes = check_all(seeds.clone(), |seed| {
        let mut rng = Rng::new(seed ^ 0x7573_6572);
        let nodes = 5 + rng.index(12);
        let on_0_3 = if rng.index(3) == 0 {
            1 + rng.index(nodes / 2)
        } else {
            0
        };
        let loss = rng.below(3) as f64 / 100.0;
        let link = LinkConfig::lan()
            .with_loss(loss)
            .with_duplicate(0.01)
            .with_reorder(0.01, kinship_sim::Delay::Fixed(ms(5)));
        let out = traffic(seed, nodes, on_0_3, link)?;
        let five = mixed(seed)?;
        Ok((out, on_0_3 > 0, five))
    });
    let (mut all, mut pure, mut five) = (Outcome::default(), Outcome::default(), (0, 0));
    for (o, mixed, f) in &outcomes {
        all += *o;
        if !mixed {
            pure += *o;
        }
        five = (five.0 + f.0, five.1 + f.1);
    }
    println!(
        "{} seeds passed in {:?}: broadcasts reached {:.4} of their members, {:.4} in clusters without 0.3.0 nodes and {:.4} beside one in five; direct messages arrived {:.4} in a datagram and {:.4} over TCP",
        seeds.end - seeds.start,
        started.elapsed(),
        ratio(all.broadcasts),
        ratio(pure.broadcasts),
        ratio(five),
        ratio(all.small),
        ratio(all.large),
    );
    // Broadcasts and datagrams are best effort, and loss reaches up to 2% here; what goes over
    // TCP always arrives, and the rest at about the rate a rumour or a datagram does.
    assert!(ratio(pure.broadcasts) >= 0.98, "{pure:?}");
    assert!(ratio(all.broadcasts) >= 0.97, "{all:?}");
    assert!(ratio(five) >= 0.97, "{five:?}");
    assert!(ratio(all.small) >= 0.95, "{all:?}");
    assert_eq!(all.large.1, all.large.0, "{all:?}");
}
