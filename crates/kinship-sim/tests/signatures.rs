//! Mode `sign` (KI-01 Stages 2a and 2b, `docs/ki01-stage2.md`) in the simulator:
//!
//! 1. A mixed cluster of nodes on the released kinship-core 0.4.0, which knows nothing of
//!    identities, and nodes of this version in mode `sign` converges and detects a crash as an
//!    all-0.4 cluster does: no false death, every live node declares the crashed one dead within
//!    the analytic bound, and every live view ends right. The signing nodes end holding exactly
//!    the 0.4 nodes unsigned, and the 0.4 nodes count no decode error.
//! 2. Signing nodes join through a 0.4 seed and through a signing seed alike.
//! 3. The same mixed cluster, and one of signing nodes alone, deliver user messages and
//!    broadcasts as `tests/usermsg.rs` expects of a cluster of one version, every check passing.
//! 4. A run with every node in `sign` replays byte for byte, pinned like the SWIM trace.
//!
//! Mode `off` keeps the pinned SWIM trace of `tests/swim.rs` unchanged.

mod common;

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Duration;

use common::{Log, Observed, check_all, index_of, secs, seeds};
use kinship_core::{
    Command, CommandId, Config, Credentials, Event, Identity, Instant, Node, Rng, Signatures,
    SigningKey, StreamEvent, StreamId, Transmit,
};
use kinship_core_0_4 as old;
use kinship_proto::NodeId;
use kinship_proto::identity::Certificate;
use kinship_sim::{
    Action, LinkConfig, NodeSpec, Scenario, Sim, SimNode, TraceConfig, WALL_CLOCK_AT_ZERO_MS,
    addr_of, name_of,
};
use serde::Serialize;

const LABEL: &[u8] = b"default";
const DAY: u64 = 86_400;

/// The run's CA, drawn from its seed.
fn ca(seed: u64) -> SigningKey {
    let mut rng = Rng::new(seed ^ 0x6361);
    let mut key = [0; 32];
    rng.fill(&mut key);
    SigningKey::from_bytes(key)
}

/// Node `index`'s signing key in the run of `seed`.
fn member_key(seed: u64, index: usize) -> SigningKey {
    let mut rng = Rng::new(seed ^ 0x6d656d62 ^ ((index as u64) << 32));
    let mut key = [0; 32];
    rng.fill(&mut key);
    SigningKey::from_bytes(key)
}

/// `lan()` with encryption, in mode `sign` with node `index`'s key and a certificate valid for
/// a day either side of the simulator's wall clock.
fn signing_config(seed: u64, index: usize) -> Config {
    let key = member_key(seed, index);
    let now = WALL_CLOCK_AT_ZERO_MS / 1000;
    let name = name_of(index);
    let certificate = Certificate::issue(
        &ca(seed),
        LABEL,
        NodeId::new(&name).unwrap(),
        key.public_key(),
        now - DAY,
        now + DAY,
    )
    .unwrap()
    .encode();
    let mut cfg = common::config();
    cfg.signatures = Signatures::Sign(Credentials {
        signing_key: key,
        certificate,
        trust_anchors: vec![ca(seed).public_key()],
    });
    cfg
}

/// Membership events: when, who saw it, what, about whom.
type Events = Rc<RefCell<Vec<(Instant, usize, &'static str, String)>>>;

/// User messages delivered: by which node, from whom, the data, and whether it was broadcast.
type Deliveries = Rc<RefCell<Vec<(usize, String, Vec<u8>, bool)>>>;

enum Inner {
    New(Box<Node>),
    /// The released kinship-core 0.4.0.
    Old(Box<old::Node>),
}

/// A node of this version in mode `sign`, or of 0.4.0, that logs its membership events.
struct Peer {
    inner: Inner,
    index: usize,
    now: Instant,
    log: Events,
    delivered: Deliveries,
}

#[derive(Serialize)]
#[serde(untagged)]
enum PeerEvent {
    New(Event),
    Old(old::Event),
}

fn to_old(t: Instant) -> old::Instant {
    old::Instant::from_nanos(t.as_nanos())
}

impl Peer {
    /// Node `spec` of the run of `seed`: on 0.4.0 if `on_0_4`, otherwise signing. It knows the
    /// nodes `knows` accepts from the start, as a static member list would.
    fn new(
        spec: &NodeSpec,
        seed: u64,
        on_0_4: bool,
        log: &Events,
        knows: impl Fn(usize) -> bool,
    ) -> Self {
        let others: Vec<usize> = (0..spec.nodes)
            .filter(|&j| j != spec.index && knows(j))
            .collect();
        let inner = if on_0_4 {
            let key = old::Key::from_bytes([7; 32]);
            let cfg = old::Config::lan(old::Security::Keys(vec![key]));
            let me = old::Identity::new(spec.name.clone(), spec.addr)
                .unwrap()
                .with_epoch(spec.epoch());
            let now = to_old(spec.now);
            let mut n = old::Node::new(cfg, me, now, spec.seed, &spec.nonce_key()).unwrap();
            for &j in &others {
                n.add_member(now, &name_of(j), addr_of(j)).unwrap();
            }
            while n.poll_event().is_some() {}
            Inner::Old(Box::new(n))
        } else {
            let cfg = signing_config(seed, spec.index);
            let me = Identity::new(spec.name.clone(), spec.addr)
                .unwrap()
                .with_epoch(spec.epoch());
            let mut n = Node::new(cfg, me, spec.now, spec.seed, &spec.nonce_key()).unwrap();
            for &j in &others {
                n.add_member(spec.now, &name_of(j), addr_of(j)).unwrap();
            }
            while n.poll_event().is_some() {}
            Inner::New(Box::new(n))
        };
        Self {
            inner,
            index: spec.index,
            now: spec.now,
            log: log.clone(),
            delivered: Deliveries::default(),
        }
    }

    /// Reports the user messages this node delivers into `delivered`.
    fn reporting(mut self, delivered: &Deliveries) -> Self {
        self.delivered = delivered.clone();
        self
    }

    fn deliver(&self, sender: &str, data: &[u8], broadcast: bool) {
        let d = (self.index, sender.to_owned(), data.to_vec(), broadcast);
        self.delivered.borrow_mut().push(d);
    }

    /// Names of the live members this node holds, itself included.
    fn view(&self) -> BTreeSet<usize> {
        match &self.inner {
            Inner::New(n) => n.members().map(|m| index_of(&m.name)).collect(),
            Inner::Old(n) => n.members().map(|m| index_of(&m.name)).collect(),
        }
    }

    fn signing(&self) -> Option<&Node> {
        match &self.inner {
            Inner::New(n) => Some(n),
            Inner::Old(_) => None,
        }
    }

    fn decode_errors(&self) -> u64 {
        match &self.inner {
            Inner::New(n) => n.metrics().decode_errors,
            Inner::Old(n) => n.metrics().decode_errors,
        }
    }

    fn record(&self, what: &'static str, name: &str) {
        let at = (self.now, self.index, what, name.to_owned());
        self.log.borrow_mut().push(at);
    }
}

impl SimNode for Peer {
    type Command = Command;
    type Event = PeerEvent;

    fn handle_datagram(&mut self, now: Instant, from: SocketAddr, buf: &[u8]) {
        self.now = now;
        match &mut self.inner {
            Inner::New(n) => n.handle_datagram(now, from, buf),
            Inner::Old(n) => n.handle_datagram(to_old(now), from, buf),
        }
    }

    fn handle_stream(&mut self, now: Instant, conn: StreamId, ev: StreamEvent<'_>) {
        self.now = now;
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
        self.now = now;
        match &mut self.inner {
            Inner::New(n) => n.handle_timeout(now),
            Inner::Old(n) => n.handle_timeout(to_old(now)),
        }
    }

    fn command(&mut self, now: Instant, cmd: Command) -> CommandId {
        self.now = now;
        match &mut self.inner {
            Inner::New(n) => n.command(now, cmd),
            Inner::Old(n) => {
                let cmd = match cmd {
                    Command::Join { seeds } => old::Command::Join { seeds },
                    Command::Leave => old::Command::Leave,
                    Command::SetMeta(meta) => old::Command::SetMeta(meta),
                    Command::Send { to, epoch, data } => old::Command::Send { to, epoch, data },
                    Command::Broadcast(data) => old::Command::Broadcast(data),
                    _ => return CommandId::from_raw(u64::MAX),
                };
                CommandId::from_raw(n.command(to_old(now), cmd).to_raw())
            }
        }
    }

    fn poll_transmit(&mut self) -> Option<Transmit> {
        let stream = |id: old::StreamId| StreamId::from_raw(id.to_raw());
        match &mut self.inner {
            Inner::New(n) => n.poll_transmit(),
            Inner::Old(n) => Some(match n.poll_transmit()? {
                old::Transmit::Datagram { to, payload } => Transmit::Datagram { to, payload },
                old::Transmit::Connect { conn, to } => Transmit::Connect {
                    conn: stream(conn),
                    to,
                },
                old::Transmit::Stream { conn, frame } => Transmit::Stream {
                    conn: stream(conn),
                    frame,
                },
                old::Transmit::Close { conn } => Transmit::Close { conn: stream(conn) },
            }),
        }
    }

    fn poll_event(&mut self) -> Option<PeerEvent> {
        match &mut self.inner {
            Inner::New(n) => {
                let e = n.poll_event()?;
                if let Event::UserMessage {
                    sender,
                    data,
                    broadcast,
                } = &e
                {
                    self.deliver(&sender.name, data, *broadcast);
                }
                let member = match &e {
                    Event::MemberJoined(m) => Some(("joined", m)),
                    Event::MemberSuspect(m) => Some(("suspect", m)),
                    Event::MemberDead(m) => Some(("dead", m)),
                    Event::MemberLeft(m) => Some(("left", m)),
                    _ => None,
                };
                if let Some((what, m)) = member {
                    self.record(what, &m.name);
                }
                Some(PeerEvent::New(e))
            }
            Inner::Old(n) => {
                let e = n.poll_event()?;
                if let old::Event::UserMessage {
                    sender,
                    data,
                    broadcast,
                } = &e
                {
                    self.deliver(&sender.name, data, *broadcast);
                }
                let member = match &e {
                    old::Event::MemberJoined(m) => Some(("joined", m)),
                    old::Event::MemberSuspect(m) => Some(("suspect", m)),
                    old::Event::MemberDead(m) => Some(("dead", m)),
                    old::Event::MemberLeft(m) => Some(("left", m)),
                    _ => None,
                };
                if let Some((what, m)) = member {
                    self.record(what, &m.name);
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

/// The latest a crash can go undetected in a cluster of `n` on `lan()`, as `tests/swim.rs`
/// derives it: two passes of probes, the round's end, the minimum suspicion and two seconds.
fn detection_bound(n: usize) -> Duration {
    let cfg = common::config();
    let scale = (n as f64).log10().max(1.0);
    let suspicion = cfg.probe_interval.as_secs_f64() * f64::from(cfg.suspicion_mult) * scale;
    cfg.probe_interval * (2 * (n as u32 - 1) + 1)
        + Duration::from_millis((suspicion * 1000.0).ceil() as u64)
        + secs(2)
}

/// What one run measured.
#[derive(Debug, Default)]
struct Outcome {
    /// From the crash to each live node declaring it dead.
    detections: Vec<Duration>,
}

/// A run of `nodes`, the last `on_0_4` of them on 0.4.0 and the others signing, all knowing
/// each other from the start, with 1% loss, and a random node crashes between 10 and 20 s.
/// Checks no false death, detection within the bound, and at the end every live view right
/// and every signing node holding exactly the live 0.4 nodes unsigned.
fn crash(seed: u64, nodes: usize, on_0_4: usize) -> Result<Outcome, String> {
    let mut rng = Rng::new(seed);
    let victim = rng.index(nodes);
    let crash_at = secs(10) + Duration::from_millis(rng.below(10_000));
    // Three push-pull intervals past the detection bound: the proofs of members that never
    // heard each other directly spread by anti-entropy.
    let end = crash_at + detection_bound(nodes) + secs(90);
    let scenario = Scenario::new(nodes)
        .link(LinkConfig::lan().with_loss(0.01))
        .trace(TraceConfig::OFF)
        .duration(end)
        .at(crash_at, Action::Crash(victim));
    let log = Events::default();
    let shared = log.clone();
    let mut sim = Sim::new(seed, scenario, move |spec| {
        let on_0_4 = spec.index >= spec.nodes - on_0_4;
        Peer::new(spec, seed, on_0_4, &shared, |_| true)
    });
    sim.run();
    let fail = |what: String| {
        Err(format!(
            "seed {seed}, {nodes} nodes, {on_0_4} on 0.4: {what}"
        ))
    };
    let crashed = Instant::ZERO + crash_at;
    let victim_name = name_of(victim);
    let mut out = Outcome::default();
    for &(t, at, what, ref name) in log.borrow().iter() {
        if what == "dead" && *name != victim_name {
            return fail(format!("n{at} declared live {name} dead at {t:?}"));
        }
        if what == "dead" && t < crashed {
            return fail(format!("n{at} declared {name} dead before it crashed"));
        }
    }
    for o in (0..nodes).filter(|&o| o != victim) {
        let declared = log
            .borrow()
            .iter()
            .find(|e| e.1 == o && e.2 == "dead" && e.3 == victim_name)
            .map(|e| e.0);
        let Some(t) = declared else {
            return fail(format!("n{o} never declared {victim_name} dead"));
        };
        let took = t - crashed;
        if took > detection_bound(nodes) {
            return fail(format!("n{o} took {took:?} to declare {victim_name} dead"));
        }
        out.detections.push(took);
        let peer = sim.node(o).expect("alive");
        let want: BTreeSet<usize> = (0..nodes).filter(|&j| j != victim).collect();
        if peer.view() != want {
            return fail(format!("n{o} holds {:?}", peer.view()));
        }
        if let Some(n) = peer.signing() {
            let old_live = on_0_4 - usize::from(victim >= nodes - on_0_4);
            if n.metrics().unsigned_members != old_live as u64 {
                return fail(format!(
                    "n{o} holds {} members unsigned, expected the {old_live} on 0.4",
                    n.metrics().unsigned_members
                ));
            }
            if n.metrics().signatures_invalid != 0 || n.metrics().certificates_refused != 0 {
                return fail(format!("n{o}: {:?}", n.metrics()));
            }
        }
        if peer.decode_errors() != 0 {
            return fail(format!(
                "n{o} counted {} decode errors",
                peer.decode_errors()
            ));
        }
    }
    Ok(out)
}

fn summary(outcomes: &[Outcome]) -> (Duration, Duration) {
    let mut all: Vec<Duration> = outcomes.iter().flat_map(|o| o.detections.clone()).collect();
    all.sort();
    (all[all.len() / 2], *all.last().unwrap())
}

#[test]
fn a_mixed_cluster_of_0_4_and_signing_nodes_detects_a_crash_as_0_4_does() {
    const NODES: usize = 10;
    let seeds = seeds(12);
    let all_old = check_all(seeds.clone(), |seed| crash(seed, NODES, NODES));
    let mixed = check_all(seeds.clone(), |seed| crash(seed, NODES, 4));
    let all_new = check_all(seeds, |seed| crash(seed, NODES, 0));
    let (old_median, old_max) = summary(&all_old);
    let (mixed_median, mixed_max) = summary(&mixed);
    let (new_median, new_max) = summary(&all_new);
    println!(
        "detection, median and max: all 0.4 {old_median:?} {old_max:?}, mixed {mixed_median:?} \
         {mixed_max:?}, all signing {new_median:?} {new_max:?}"
    );
    // Signing changes no timer and no accusation rule in Stage 2a: the same rounds, the same
    // suspicions. Detection stays within the bound for every node, and the medians agree to
    // within a probe interval.
    let interval = common::config().probe_interval;
    assert!(
        mixed_median <= old_median + interval,
        "mixed {mixed_median:?}"
    );
    assert!(
        new_median <= old_median + interval,
        "signing {new_median:?}"
    );
}

/// A run in which signing node n0 knows nobody and joins at 1 s through `seed`, a 0.4 node
/// or a signing one; everyone else knows everyone but n0. It must end in every view, signed in
/// the signing nodes' own, and they in its.
fn join(seed: u64, through_0_4: bool) -> Result<(), String> {
    const NODES: usize = 6;
    let on_0_4 = 2;
    let seed_node = if through_0_4 { NODES - 1 } else { 1 };
    let scenario = Scenario::new(NODES)
        .link(LinkConfig::lan())
        .trace(TraceConfig::OFF)
        // Three push-pull intervals: the nodes given each other in a list, which may never
        // have heard each other directly, end signed too.
        .duration(secs(100))
        .at(
            secs(1),
            Action::Command {
                node: 0,
                cmd: Command::Join {
                    seeds: vec![addr_of(seed_node)],
                },
            },
        );
    let log = Events::default();
    let shared = log.clone();
    let mut sim = Sim::new(seed, scenario, move |spec| {
        let old = spec.index >= spec.nodes - on_0_4;
        let me = spec.index;
        let knows = move |j: usize| me != 0 && j != 0;
        Peer::new(spec, seed, old, &shared, knows)
    });
    sim.run();
    let fail = |what: String| Err(format!("seed {seed}, through 0.4 {through_0_4}: {what}"));
    let all: BTreeSet<usize> = (0..NODES).collect();
    for o in 0..NODES {
        let peer = sim.node(o).unwrap();
        if peer.view() != all {
            return fail(format!("n{o} holds {:?}", peer.view()));
        }
        if let Some(n) = peer.signing() {
            if n.metrics().unsigned_members != on_0_4 as u64 {
                return fail(format!("n{o}: {:?}", n.metrics()));
            }
        }
    }
    Ok(())
}

#[test]
fn signing_nodes_join_through_0_4_and_signing_seeds() {
    check_all(seeds(8), |seed| join(seed, true));
    check_all(seeds(8), |seed| join(seed, false));
}

/// Expected and actual deliveries of one run: broadcasts, direct messages in a datagram, and
/// direct messages over TCP.
#[derive(Debug, Default, Clone, Copy)]
struct Traffic {
    broadcasts: (usize, usize),
    small: (usize, usize),
    large: (usize, usize),
}

/// A run of `nodes`, the last `on_0_4` of them on 0.4.0 and the others signing, all knowing
/// each other from the start, on a lossless link, in which random nodes of either kind make
/// four broadcasts and send six direct messages, every other one too large for a datagram, at
/// random times in the first ten seconds, as `tests/usermsg.rs` runs them. Checks what must
/// always hold there, and that every check a signing node made passed.
fn messages(seed: u64, nodes: usize, on_0_4: usize) -> Result<Traffic, String> {
    let mut rng = Rng::new(seed);
    let mut scenario = Scenario::new(nodes)
        .link(LinkConfig::lan())
        .trace(TraceConfig::OFF)
        .duration(secs(40));
    let at = |rng: &mut Rng| Duration::from_millis(1_000 + rng.below(9_000));
    let mut broadcasts = Vec::new();
    for i in 0..4 {
        let from = rng.index(nodes);
        let data = format!("broadcast {i} from n{from}").into_bytes();
        let cmd = Command::Broadcast(data.clone());
        scenario = scenario.at(at(&mut rng), Action::Command { node: from, cmd });
        broadcasts.push((from, data));
    }
    let mut direct = Vec::new();
    for i in 0..6 {
        let from = rng.index(nodes);
        let to = (from + 1 + rng.index(nodes - 1)) % nodes;
        let mut data = format!("message {i} from n{from} to n{to}").into_bytes();
        if i % 2 == 1 {
            data.resize(5_000, b'.');
        }
        let cmd = Command::Send {
            to: name_of(to),
            epoch: 0,
            data: data.clone(),
        };
        scenario = scenario.at(at(&mut rng), Action::Command { node: from, cmd });
        direct.push((from, to, data));
    }
    let log = Events::default();
    let delivered = Deliveries::default();
    let (shared, report) = (log.clone(), delivered.clone());
    let mut sim = Sim::new(seed, scenario, move |spec| {
        let on_0_4 = spec.index >= spec.nodes - on_0_4;
        Peer::new(spec, seed, on_0_4, &shared, |_| true).reporting(&report)
    });
    sim.run();
    let fail = |what: String| {
        Err(format!(
            "seed {seed}, {nodes} nodes, {on_0_4} on 0.4: {what}"
        ))
    };
    let delivered = delivered.borrow();
    let mut times: std::collections::BTreeMap<(usize, &[u8]), usize> = Default::default();
    for (at, _, data, _) in delivered.iter() {
        *times.entry((*at, &data[..])).or_default() += 1;
    }
    if let Some(((at, data), n)) = times.iter().find(|&(_, &n)| n > 1) {
        let data = String::from_utf8_lossy(data);
        return fail(format!("n{at} delivered {data:?} {n} times"));
    }
    let mut out = Traffic::default();
    for (from, data) in &broadcasts {
        if times.contains_key(&(*from, &data[..])) {
            return fail(format!("n{from} delivered its own broadcast"));
        }
        let reached = (0..nodes)
            .filter(|&i| i != *from && times.contains_key(&(i, &data[..])))
            .count();
        out.broadcasts.0 += nodes - 1;
        out.broadcasts.1 += reached;
    }
    for (from, to, data) in &direct {
        let got = delivered.iter().find(|d| d.0 == *to && d.2 == *data);
        if let Some(d) = got {
            if d.1 != name_of(*from) || d.3 {
                return fail(format!("n{to} got {data:?} from {} as {}", d.1, d.3));
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
    for i in 0..nodes {
        let peer = sim.node(i).expect("no node crashes");
        if peer.decode_errors() != 0 {
            return fail(format!(
                "n{i} counted {} decode errors",
                peer.decode_errors()
            ));
        }
        if let Some(n) = peer.signing() {
            let m = n.metrics();
            if (
                m.signatures_invalid,
                m.certificates_refused,
                m.user_messages_dropped,
            ) != (0, 0, 0)
            {
                return fail(format!("n{i}: {m:?}"));
            }
        }
    }
    // Membership goes on as before: on a lossless link nobody is suspected.
    if let Some(e) = log.borrow().iter().find(|e| e.2 != "joined") {
        return fail(format!("{e:?}"));
    }
    Ok(out)
}

#[test]
fn a_mixed_cluster_of_0_4_and_signing_nodes_delivers_user_messages() {
    let mut total = Traffic::default();
    for (nodes, on_0_4) in [(8, 3), (8, 0)] {
        for t in check_all(seeds(8), |seed| messages(seed, nodes, on_0_4)) {
            for (a, b) in [
                (&mut total.broadcasts, t.broadcasts),
                (&mut total.small, t.small),
                (&mut total.large, t.large),
            ] {
                a.0 += b.0;
                a.1 += b.1;
            }
        }
    }
    // As tests/usermsg.rs expects of a cluster of one version: on a lossless link every direct
    // message arrives, signed between signing nodes and unsigned to and from 0.4 nodes, and a
    // broadcast reaches each member with the probability a rumour does.
    assert_eq!(total.small.1, total.small.0, "{total:?}");
    assert_eq!(total.large.1, total.large.0, "{total:?}");
    let (expected, got) = total.broadcasts;
    assert!(got as f64 >= 0.98 * expected as f64, "{total:?}");
}

#[test]
fn sign_trace_is_pinned_across_platforms() {
    // Ed25519 signatures are deterministic, and probe challenges come from each node's nonce
    // key, so a run with every node signing replays byte for byte too. Update the value only
    // when the protocol, the codec, signing or the simulator changes on purpose. Stage 2b
    // changed it: rounds to members held signed are version 2, with challenges and signed Acks
    // and Nacks, and their packets carry the signed rumours that went in a second datagram.
    let seed = 1;
    let scenario = Scenario::new(10)
        .link(LinkConfig::lan().with_loss(0.02))
        .trace(TraceConfig::ALL)
        .duration(secs(30))
        .at(secs(8), Action::Crash(3))
        .at(
            secs(12),
            Action::Command {
                node: 5,
                cmd: Command::SetMeta(b"zone=b".to_vec()),
            },
        )
        .at(secs(20), Action::Restart(3));
    let log: Log = Rc::default();
    let mut sim = Sim::new(seed, scenario, move |spec| {
        Observed::with_config(spec, signing_config(seed, spec.index), log.clone(), |_| {
            true
        })
    });
    let digest = sim.run().digest();
    for i in 0..10 {
        // Every signature checks, the metadata change and the restart included, and every node
        // but the one that restarted 10 s ago, given its members in a list, holds them signed.
        let m = sim.node(i).unwrap().node.metrics();
        let unsigned = if i == 3 { 0 } else { m.unsigned_members };
        assert_eq!(
            (m.signatures_invalid, m.certificates_refused, unsigned),
            (0, 0, 0),
            "n{i}: {m:?}"
        );
    }
    assert_eq!(digest, 0x5a25_2ea5_b273_8cd7, "trace digest changed");
}
