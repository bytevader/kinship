//! Clusters of this version beside the released kinship-core 0.5.0, the rolling upgrade
//! `docs/stability.md` promises. Both versions speak digest push-pull, so digests cross between
//! them both ways.
//!
//! Nodes join through one seed, of either version, then one node or a minority side is cut off
//! for longer than the suspicion timeout and healed, as the KP-06 sweep in `tests/sync.rs` does.
//! The run checks that:
//!
//! 1. every node holds every node before the cut, so a join through either version works;
//! 2. every node holds every node again after the heal, within the bound `tests/sync.rs` gives,
//!    or, where both sides reaped the tombstones a reconnect would use, after a join across;
//! 3. no node of either version counts a decode error;
//! 4. no node that was not cut off, of either version, declares a member that was not cut off
//!    dead, at any time (KP-06);
//! 5. digest exchanges, with a third frame of wanted records, open in both directions between
//!    the versions and within each.
//!
//! A second scenario does the upgrade itself: a cluster on 0.5.0 moves to this version one node
//! at a time, each crashing, restarting on the other version and joining through a node that has
//! not moved or has, and then rolls back the same way. After every step each node holds every
//! node at its current run, and no node has declared a member other than the one that moved dead.
//!
//! Quick tests run a few seeds; the ignored sweeps run 1,000, which CI runs with
//! `cargo test --release -p kinship-sim --test interop_0_5 -- --ignored --nocapture`.

mod common;

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::net::{IpAddr, SocketAddr};
use std::rc::Rc;
use std::time::Duration;

use common::{check_all, config, index_of, ms, secs, seeds};
use kinship_core::{
    Command, CommandId, Config, Event, Identity, Instant, Node, Rng, Security, StreamEvent,
    StreamId, Transmit,
};
use kinship_core_0_5 as old;
use kinship_proto::{Codec, Limits, PacketKind};
use kinship_sim::{
    Action, Delay, LinkConfig, NodeSet, NodeSpec, Scenario, Sim, SimNode, TraceConfig, addr_of,
};

/// An index into the tables of [`Tally`]: 0 for this version, 1 for 0.5.0.
const NEW: usize = 0;
const OLD: usize = 1;

/// What the runs saw. The tables go by the version that opened an exchange, then the version it
/// opened it to.
#[derive(Debug, Default, Clone, Copy)]
struct Tally {
    digests: [[u64; 2]; 2],
    /// Digest exchanges whose opener sent the records the answer asked for.
    third_frames: [[u64; 2]; 2],
    full: [[u64; 2]; 2],
    /// Runs that joined through a node of each version.
    joined_through: [u64; 2],
    /// Members the cut-off side declared dead before the heal, so that it had deaths to spread.
    split_deaths: u64,
    /// Runs where the cut-off side had to join, since no reconnect crossed in time.
    rejoined: u64,
}

impl Tally {
    fn add(&mut self, o: &Self) {
        for from in [NEW, OLD] {
            for to in [NEW, OLD] {
                self.digests[from][to] += o.digests[from][to];
                self.third_frames[from][to] += o.third_frames[from][to];
                self.full[from][to] += o.full[from][to];
            }
            self.joined_through[from] += o.joined_through[from];
        }
        self.split_deaths += o.split_deaths;
        self.rejoined += o.rejoined;
    }
}

/// What every node of one run shares: the codec to open their frames, which nodes are on 0.5.0,
/// what has been counted, and each death as (observer, member).
struct Shared {
    codec: Codec,
    /// Read when an instance starts, so a restart can bring a node up on the other version.
    on_0_5: RefCell<BTreeSet<usize>>,
    seen: RefCell<Tally>,
    deaths: RefCell<Vec<(usize, usize)>>,
}

impl Shared {
    fn version(&self, node: usize) -> usize {
        if self.on_0_5.borrow().contains(&node) {
            OLD
        } else {
            NEW
        }
    }
}

/// The codec the sweeps seal with, to open what nodes send.
fn codec() -> Codec {
    let Security::Keys(keys) = config().security else {
        unreachable!("the sweeps seal")
    };
    Codec::encrypted(config().cluster.as_bytes(), Limits::default(), keys).expect("the test key")
}

/// The simulator node at `addr`.
fn index_at(addr: SocketAddr) -> Option<usize> {
    match addr.ip() {
        IpAddr::V4(ip) => {
            let [_, a, b, c] = ip.octets();
            Some(((a as usize) << 16) | ((b as usize) << 8) | c as usize)
        }
        IpAddr::V6(_) => None,
    }
}

enum Inner {
    New(Box<Node>),
    /// The released kinship-core 0.5.0.
    Old(Box<old::Node>),
}

/// A node of this version or of 0.5.0 that files the exchanges it opens and the deaths it reports.
struct Peer {
    inner: Inner,
    index: usize,
    shared: Rc<Shared>,
    /// Connections this node opened: the node it opened each to, the frames sent so far, and
    /// whether the first was a digest.
    opened: BTreeMap<StreamId, (Option<usize>, u32, bool)>,
}

fn to_old(t: Instant) -> old::Instant {
    old::Instant::from_nanos(t.as_nanos())
}

impl Peer {
    fn new(spec: &NodeSpec, shared: &Rc<Shared>) -> Self {
        let on_0_5 = shared.on_0_5.borrow().contains(&spec.index);
        let inner = if on_0_5 {
            let Security::Keys(keys) = config().security else {
                unreachable!("the sweeps seal")
            };
            let key = old::Key::from_base64(&keys[0].to_base64()).expect("the test key");
            let cfg = old::Config::lan(old::Security::Keys(vec![key]));
            let me = old::Identity::new(spec.name.clone(), spec.addr)
                .unwrap()
                .with_epoch(spec.epoch());
            let n = old::Node::new(cfg, me, to_old(spec.now), spec.seed, &spec.nonce_key());
            Inner::Old(Box::new(n.unwrap()))
        } else {
            let me = Identity::new(spec.name.clone(), spec.addr)
                .unwrap()
                .with_epoch(spec.epoch());
            let n = Node::new(config(), me, spec.now, spec.seed, &spec.nonce_key()).unwrap();
            Inner::New(Box::new(n))
        };
        Self {
            inner,
            index: spec.index,
            shared: shared.clone(),
            opened: BTreeMap::new(),
        }
    }

    /// Files a frame this node writes on `conn`, if it opened it.
    fn file(&mut self, conn: StreamId, frame: &[u8]) {
        let Some((to, sent, digest)) = self.opened.get_mut(&conn) else {
            return;
        };
        let Some(to) = *to else {
            return;
        };
        let from = self.shared.version(self.index);
        let to = self.shared.version(to);
        *sent += 1;
        let mut seen = self.shared.seen.borrow_mut();
        if *sent > 1 {
            seen.third_frames[from][to] += u64::from(*digest);
            return;
        }
        let mut buf = frame[4..].to_vec();
        let Ok(payload) = self.shared.codec.open(PacketKind::Stream, &mut buf) else {
            return;
        };
        let kinds: Vec<u8> = payload.iter().map(|m| m.kind()).collect();
        if kinds.contains(&kinship_proto::kind::PUSH_PULL_DIGEST) {
            *digest = true;
            seen.digests[from][to] += 1;
        } else if kinds.contains(&kinship_proto::kind::PUSH_PULL) {
            seen.full[from][to] += 1;
        }
    }

    /// The live members this node holds, itself included.
    fn view(&self) -> BTreeSet<usize> {
        match &self.inner {
            Inner::New(n) => n.members().map(|m| index_of(&m.name)).collect(),
            Inner::Old(n) => n.members().map(|m| index_of(&m.name)).collect(),
        }
    }

    /// The live members this node holds, itself included, each with the epoch it holds it at.
    fn lives(&self) -> BTreeMap<usize, u64> {
        match &self.inner {
            Inner::New(n) => n.members().map(|m| (index_of(&m.name), m.epoch)).collect(),
            Inner::Old(n) => n.members().map(|m| (index_of(&m.name), m.epoch)).collect(),
        }
    }

    fn decode_errors(&self) -> u64 {
        match &self.inner {
            Inner::New(n) => n.metrics().decode_errors,
            Inner::Old(n) => n.metrics().decode_errors,
        }
    }
}

impl SimNode for Peer {
    type Command = Command;
    type Event = ();

    fn handle_datagram(&mut self, now: Instant, from: SocketAddr, buf: &[u8]) {
        match &mut self.inner {
            Inner::New(n) => n.handle_datagram(now, from, buf),
            Inner::Old(n) => n.handle_datagram(to_old(now), from, buf),
        }
    }

    fn handle_stream(&mut self, now: Instant, conn: StreamId, ev: StreamEvent<'_>) {
        if !matches!(ev, StreamEvent::Frame(_)) {
            self.opened.remove(&conn);
        }
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
                let Command::Join { seeds } = cmd else {
                    unreachable!("the runs only join")
                };
                let id = n.command(to_old(now), old::Command::Join { seeds });
                CommandId::from_raw(id.to_raw())
            }
        }
    }

    fn poll_transmit(&mut self) -> Option<Transmit> {
        let stream = |id: old::StreamId| StreamId::from_raw(id.to_raw());
        let t = match &mut self.inner {
            Inner::New(n) => n.poll_transmit()?,
            Inner::Old(n) => match n.poll_transmit()? {
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
            },
        };
        match &t {
            Transmit::Connect { conn, to } => {
                self.opened.insert(*conn, (index_at(*to), 0, false));
            }
            Transmit::Stream { conn, frame } => self.file(*conn, frame),
            Transmit::Close { conn } => {
                self.opened.remove(conn);
            }
            Transmit::Datagram { .. } => {}
        }
        Some(t)
    }

    fn poll_event(&mut self) -> Option<()> {
        let dead = match &mut self.inner {
            Inner::New(n) => match n.poll_event()? {
                Event::MemberDead(m) => Some(index_of(&m.name)),
                _ => None,
            },
            Inner::Old(n) => match n.poll_event()? {
                old::Event::MemberDead(m) => Some(index_of(&m.name)),
                _ => None,
            },
        };
        if let Some(member) = dead {
            self.shared.deaths.borrow_mut().push((self.index, member));
        }
        Some(())
    }

    fn poll_timeout(&self) -> Option<Instant> {
        match &self.inner {
            Inner::New(n) => n.poll_timeout(),
            Inner::Old(n) => n.poll_timeout().map(|t| Instant::from_nanos(t.as_nanos())),
        }
    }
}

/// `retransmit_mult x ceil(log10(n + 1))`, as the core computes it.
fn retransmit_limit(cfg: &Config, n: usize) -> u32 {
    let digits = (n as f64 + 1.0).log10().ceil() as u32;
    cfg.retransmit_mult * digits
}

/// How long a healed partition takes to reconverge, as `tests/sync.rs` derives it: a reconnect
/// across it, a probe round, the suspicion's gossip and the refutation's dissemination.
fn heal_bound(cfg: &Config, n: usize) -> Duration {
    let gossip = cfg.gossip_interval * retransmit_limit(cfg, n) + cfg.probe_interval * 2 + secs(1);
    cfg.reconnect_interval + cfg.probe_interval + gossip + gossip + cfg.push_pull_interval_for(n)
}

/// `suspicion_mult x max(1, log10 n) x probe_interval`, rounded up to the millisecond.
fn suspicion_timeout(cfg: &Config, n: usize) -> Duration {
    let scale = (n as f64).log10().max(1.0);
    let s = cfg.probe_interval.as_secs_f64() * f64::from(cfg.suspicion_mult) * scale;
    Duration::from_millis((s * 1000.0).ceil() as u64)
}

/// A random LAN link with up to 1% loss, sometimes 40 ms of latency, and a little duplication and
/// reordering, as the KP-06 sweep draws. Returns the link and its loss.
fn random_link(rng: &mut Rng) -> (LinkConfig, f64) {
    let loss = if rng.chance(0.2) {
        0.0
    } else {
        rng.next_f64() * 0.01
    };
    let mut link = LinkConfig::lan()
        .with_loss(loss)
        .with_duplicate(rng.next_f64() * 0.01)
        .with_reorder(
            rng.next_f64() * 0.02,
            Delay::Uniform {
                min: ms(1),
                max: ms(20),
            },
        );
    if rng.chance(0.2) {
        link = link.with_latency(Delay::Normal {
            mean: ms(40),
            std_dev: ms(10),
        });
    }
    (link, loss)
}

/// Steps `sim` until every node holds every node or `until` passes; returns whether they did.
fn converge(sim: &mut Sim<Peer>, nodes: usize, until: Instant) -> bool {
    let everyone: BTreeSet<usize> = (0..nodes).collect();
    loop {
        if (0..nodes).all(|o| sim.node(o).is_some_and(|n| n.view() == everyone)) {
            return true;
        }
        if sim.now() >= until {
            return false;
        }
        let next = (sim.now() + ms(250)).min(until);
        sim.run_until(next);
    }
}

/// Which nodes miss which members, for a failure's message.
fn missing(sim: &Sim<Peer>, nodes: usize) -> String {
    let everyone: BTreeSet<usize> = (0..nodes).collect();
    let bad: Vec<String> = (0..nodes)
        .filter_map(|o| {
            let view = sim.node(o).map(Peer::view).unwrap_or_default();
            let missing: Vec<usize> = everyone.difference(&view).copied().collect();
            (!missing.is_empty()).then(|| format!("n{o} misses {missing:?}"))
        })
        .take(5)
        .collect();
    bad.join("; ")
}

/// A run of `nodes`, the last `on_0_5` of them on 0.5.0, as the module describes.
fn mixed(seed: u64, nodes: usize, on_0_5: usize) -> Result<Tally, String> {
    let cfg = config();
    let mut rng = Rng::new(seed ^ 0x0069_6e74_6572_6f70);
    let via = rng.index(nodes);
    let (link, loss) = random_link(&mut rng);
    let size = if rng.chance(0.5) {
        1
    } else {
        2 + rng.index((nodes - 1) / 2 - 1)
    };
    let mut all: Vec<usize> = (0..nodes).collect();
    rng.shuffle(&mut all);
    let side: BTreeSet<usize> = all[..size].iter().copied().collect();
    let other: Vec<usize> = (0..nodes).filter(|n| !side.contains(n)).collect();
    let across = addr_of(other[0]);
    // Gossip of a join can miss a node, in a few seeds in 1,000 whatever the versions, so the cut
    // waits for a round of push-pull to catch those.
    let start = cfg.push_pull_interval_for(nodes) + ms(10_000 + rng.below(10_000));
    // From half the longest suspicion to half dead_reclaim past the longest, as in the KP-06
    // sweep: long enough for the cut-off side to declare deaths, and for tombstones to be reaped.
    let longest = suspicion_timeout(&cfg, nodes) * cfg.suspicion_max_mult;
    let low = longest / 2;
    let high = longest + cfg.dead_reclaim / 2;
    let length = low + ms(rng.below((high - low).as_millis() as u64));
    let healed = Instant::ZERO + start + length;
    let bound = heal_bound(&cfg, nodes);
    let mut scenario = Scenario::new(nodes)
        .duration(start + length + bound * 2 + longest + secs(5))
        .link(link)
        .trace(TraceConfig::OFF)
        .at(
            start,
            Action::Partition {
                a: NodeSet::new(side.iter().copied()),
                b: other.into(),
            },
        )
        .at(start + length, Action::Heal);
    for j in (0..nodes).filter(|&j| j != via) {
        let seeds = vec![addr_of(via)];
        let at = ms(rng.below(3_000));
        scenario = scenario.at(
            at,
            Action::Command {
                node: j,
                cmd: Command::Join { seeds },
            },
        );
    }
    let shared = Rc::new(Shared {
        codec: codec(),
        on_0_5: RefCell::new((nodes - on_0_5..nodes).collect()),
        seen: RefCell::default(),
        deaths: RefCell::default(),
    });
    let factory = shared.clone();
    let mut sim = Sim::new(seed, scenario, move |spec| Peer::new(spec, &factory));
    let fail = |msg: String| {
        Err(format!(
            "seed {seed}, {nodes} nodes, {on_0_5} on 0.5, joined through n{via}: {msg}\n\
             loss {loss:.4}, partition {start:?} for {length:?}, side {side:?}"
        ))
    };

    let before_cut = Instant::ZERO + (start - ms(1));
    sim.run_until(before_cut);
    if !converge(&mut sim, nodes, before_cut) {
        return fail(format!(
            "the joins did not converge before the cut: {}",
            missing(&sim, nodes)
        ));
    }
    sim.run_until(healed);
    let split_deaths = shared
        .deaths
        .borrow()
        .iter()
        .filter(|(o, m)| side.contains(o) && !side.contains(m))
        .count() as u64;
    let mut converged = converge(&mut sim, nodes, healed + bound);
    let rejoined = !converged;
    if rejoined {
        for &node in &side {
            let seeds = vec![across];
            sim.apply(Action::Command {
                node,
                cmd: Command::Join { seeds },
            });
        }
        converged = converge(&mut sim, nodes, healed + bound * 2);
    }
    if !converged {
        return fail(format!(
            "not reconverged {bound:?} after the heal and a rejoin"
        ));
    }
    sim.run();
    let end = sim.now();
    if !converge(&mut sim, nodes, end) {
        return fail("members missing at the end".into());
    }
    for o in 0..nodes {
        let errors = sim.node(o).map_or(0, Peer::decode_errors);
        if errors > 0 {
            return fail(format!("n{o} counted {errors} decode errors"));
        }
    }
    let false_deaths: Vec<String> = shared
        .deaths
        .borrow()
        .iter()
        .filter(|(o, m)| !side.contains(o) && !side.contains(m))
        .map(|(o, m)| format!("n{o} declared n{m} dead"))
        .collect();
    if !false_deaths.is_empty() {
        return fail(format!(
            "{} false deaths: {}",
            false_deaths.len(),
            false_deaths[..false_deaths.len().min(5)].join("; ")
        ));
    }
    let mut seen = *shared.seen.borrow();
    seen.joined_through[shared.version(via)] += 1;
    seen.split_deaths = split_deaths;
    seen.rejoined = u64::from(rejoined);
    Ok(seen)
}

/// Steps `sim` until every node holds every node at the run that node itself is in, or `until`
/// passes; returns whether they did.
fn settle(sim: &mut Sim<Peer>, nodes: usize, until: Instant) -> bool {
    loop {
        let views: Vec<BTreeMap<usize, u64>> = (0..nodes)
            .map(|o| sim.node(o).map(Peer::lives).unwrap_or_default())
            .collect();
        let own: BTreeMap<usize, u64> = (0..nodes)
            .filter_map(|o| views[o].get(&o).map(|&epoch| (o, epoch)))
            .collect();
        if own.len() == nodes && views.iter().all(|view| *view == own) {
            return true;
        }
        if sim.now() >= until {
            return false;
        }
        let next = (sim.now() + ms(250)).min(until);
        sim.run_until(next);
    }
}

/// A rolling upgrade of `nodes` from 0.5.0 to this version and a rollback, as the module describes.
fn rolling(seed: u64, nodes: usize) -> Result<(), String> {
    let cfg = config();
    // "rolling" in ASCII, so that the draws are not those of `mixed`.
    let mut rng = Rng::new(seed ^ 0x0072_6f6c_6c69_6e67);
    let (link, loss) = random_link(&mut rng);
    let mut scenario = Scenario::new(nodes)
        .duration(secs(24 * 3600))
        .link(link)
        .trace(TraceConfig::OFF);
    for j in 1..nodes {
        let seeds = vec![addr_of(0)];
        let at = ms(rng.below(3_000));
        scenario = scenario.at(
            at,
            Action::Command {
                node: j,
                cmd: Command::Join { seeds },
            },
        );
    }
    let shared = Rc::new(Shared {
        codec: codec(),
        on_0_5: RefCell::new((0..nodes).collect()),
        seen: RefCell::default(),
        deaths: RefCell::default(),
    });
    let factory = shared.clone();
    let mut sim = Sim::new(seed, scenario, move |spec| Peer::new(spec, &factory));
    let fail = |msg: String| Err(format!("seed {seed}, {nodes} nodes, loss {loss:.4}: {msg}"));

    let bound = heal_bound(&cfg, nodes);
    let start = Instant::ZERO + cfg.push_pull_interval_for(nodes) + secs(10);
    sim.run_until(start);
    if !settle(&mut sim, nodes, start + bound) {
        return fail(format!("0.5.0 did not converge: {}", missing(&sim, nodes)));
    }
    for upgrade in [true, false] {
        let mut order: Vec<usize> = (0..nodes).collect();
        rng.shuffle(&mut order);
        for node in order {
            let errors = sim.node(node).map_or(0, Peer::decode_errors);
            if errors > 0 {
                return fail(format!("n{node} counted {errors} decode errors"));
            }
            {
                let mut on_0_5 = shared.on_0_5.borrow_mut();
                if upgrade {
                    on_0_5.remove(&node);
                } else {
                    on_0_5.insert(node);
                }
            }
            let deaths = shared.deaths.borrow().len();
            sim.apply(Action::Crash(node));
            sim.run_for(ms(200 + rng.below(800)));
            sim.apply(Action::Restart(node));
            let via = (node + 1 + rng.index(nodes - 1)) % nodes;
            sim.apply(Action::Command {
                node,
                cmd: Command::Join {
                    seeds: vec![addr_of(via)],
                },
            });
            let until = sim.now() + bound;
            if !settle(&mut sim, nodes, until) {
                return fail(format!(
                    "upgrade {upgrade}: not settled {bound:?} after n{node} moved through n{via}: \
                     {}",
                    missing(&sim, nodes)
                ));
            }
            if let Some((o, m)) = shared.deaths.borrow()[deaths..]
                .iter()
                .find(|(_, m)| *m != node)
            {
                return fail(format!(
                    "upgrade {upgrade}: n{o} declared n{m} dead while n{node} moved"
                ));
            }
            sim.run_for(ms(rng.below(2_000)));
        }
    }
    for o in 0..nodes {
        let errors = sim.node(o).map_or(0, Peer::decode_errors);
        if errors > 0 {
            return fail(format!("n{o} counted {errors} decode errors"));
        }
    }
    Ok(())
}

/// The tallies of `runs`, summed, with one line that gives them, after checking that the runs
/// covered every pairing of versions.
fn summary(runs: &[Tally]) -> String {
    let mut sum = Tally::default();
    for r in runs {
        sum.add(r);
    }
    let line = format!(
        "digests new to new {}, new to 0.5 {}, 0.5 to new {}, 0.5 to 0.5 {}; third frames \
         {:?}; full exchanges {:?}; joined through new {}, through 0.5 {}; {} split deaths; {} \
         runs rejoined",
        sum.digests[NEW][NEW],
        sum.digests[NEW][OLD],
        sum.digests[OLD][NEW],
        sum.digests[OLD][OLD],
        sum.third_frames,
        sum.full,
        sum.joined_through[NEW],
        sum.joined_through[OLD],
        sum.split_deaths,
        sum.rejoined,
    );
    for from in [NEW, OLD] {
        for to in [NEW, OLD] {
            assert!(sum.digests[from][to] > 0, "{line}");
            assert!(sum.third_frames[from][to] > 0, "{line}");
        }
        assert!(sum.joined_through[from] > 0, "{line}");
    }
    assert!(sum.split_deaths > 0, "{line}");
    line
}

#[test]
fn clusters_with_0_5_exchange_digests_and_heal_without_false_deaths() {
    let runs = check_all(0..12, |seed| mixed(seed, 16, 4 + 4 * (seed as usize % 2)));
    println!("{}", summary(&runs));
}

#[test]
fn a_cluster_upgrades_from_0_5_and_rolls_back_one_node_at_a_time() {
    check_all(0..6, |seed| rolling(seed, 8));
}

/// 1,000 seeds of 10 nodes, each moved to this version and back.
#[test]
#[ignore = "slow in debug builds; CI runs it with --release"]
fn thousand_seeds_upgrade_from_0_5_and_roll_back() {
    let seeds = seeds(1000);
    let started = std::time::Instant::now();
    check_all(seeds.clone(), |seed| rolling(seed, 10));
    println!(
        "{} seeds x 10 nodes upgraded from 0.5.0 and rolled back in {:?}",
        seeds.end - seeds.start,
        started.elapsed()
    );
}

/// 1,000 seeds of 20 nodes, 5, 10 or 15 of them on 0.5.0.
#[test]
#[ignore = "slow in debug builds; CI runs it with --release"]
fn thousand_seeds_mixed_with_0_5() {
    let seeds = seeds(1000);
    let started = std::time::Instant::now();
    let runs = check_all(seeds.clone(), |seed| {
        mixed(seed, 20, 5 + 5 * (seed as usize % 3))
    });
    println!(
        "{} seeds x 20 nodes beside 0.5.0 reconverged in {:?}: {}",
        seeds.end - seeds.start,
        started.elapsed(),
        summary(&runs)
    );
}
