//! Digest push-pull (`docs/pushpull-digest.md`) in clusters of this version beside the released
//! kinship-core 0.4.0, which knows nothing of digests, so that digest and full exchanges meet.
//!
//! Nodes join one at a time through one seed, of either version, then a random part of the
//! cluster is cut off long enough for deaths and healed. The run checks that:
//!
//! 1. every node ends holding every node, within the bound `tests/sync.rs` gives a healed
//!    partition;
//! 2. no node of this version ever sends a digest to a 0.4 node, and no node of either version
//!    counts a decode error;
//! 3. digest exchanges between nodes of this version, some with a third frame of wanted records,
//!    and full exchanges with the 0.4 nodes, both ways, all happen.
//!
//! A quick test runs a few seeds; the ignored sweep runs 1,000, which CI runs with
//! `cargo test --release -p kinship-sim --test digest -- --ignored --nocapture`.

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
use kinship_core_0_4 as old;
use kinship_proto::{Codec, Limits, PacketKind};
use kinship_sim::{
    Action, LinkConfig, NodeSet, NodeSpec, Scenario, Sim, SimNode, TraceConfig, addr_of,
};

/// The exchanges seen, by how they started.
#[derive(Debug, Default, Clone, Copy)]
struct Exchanges {
    /// Digests from a node of this version to one of this version, and to a 0.4 node.
    digest_to_new: u64,
    digest_to_old: u64,
    /// Digest exchanges whose opener sent the records the answer asked for.
    third_frames: u64,
    /// Full push-pulls from a node of this version to one of this version, and to a 0.4 node.
    full_to_new: u64,
    full_to_old: u64,
    /// Full push-pulls a 0.4 node opened.
    full_from_old: u64,
}

impl Exchanges {
    fn add(&mut self, o: &Self) {
        self.digest_to_new += o.digest_to_new;
        self.digest_to_old += o.digest_to_old;
        self.third_frames += o.third_frames;
        self.full_to_new += o.full_to_new;
        self.full_to_old += o.full_to_old;
        self.full_from_old += o.full_from_old;
    }
}

/// What every node of one run shares: the codec to open their frames, which nodes are on 0.4,
/// and what has been counted.
struct Shared {
    codec: Codec,
    on_0_4: BTreeSet<usize>,
    seen: RefCell<Exchanges>,
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
    /// The released kinship-core 0.4.0.
    Old(Box<old::Node>),
}

/// A node of this version in mode `off`, or of 0.4.0, that files the exchanges it opens.
struct Peer {
    inner: Inner,
    shared: Rc<Shared>,
    /// Connections this node opened: the node it opened each to, and the frames sent so far.
    opened: BTreeMap<StreamId, (Option<usize>, u32, bool)>,
}

fn to_old(t: Instant) -> old::Instant {
    old::Instant::from_nanos(t.as_nanos())
}

impl Peer {
    fn new(spec: &NodeSpec, shared: &Rc<Shared>) -> Self {
        let inner = if shared.on_0_4.contains(&spec.index) {
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
            shared: shared.clone(),
            opened: BTreeMap::new(),
        }
    }

    /// Files a frame this node writes on `conn`, if it opened it.
    fn file(&mut self, conn: StreamId, frame: &[u8]) {
        let Some((to, sent, digest)) = self.opened.get_mut(&conn) else {
            return;
        };
        *sent += 1;
        let to_old = to.is_some_and(|j| self.shared.on_0_4.contains(&j));
        let mut seen = self.shared.seen.borrow_mut();
        if *sent > 1 {
            seen.third_frames += u64::from(*digest);
            return;
        }
        let mut buf = frame[4..].to_vec();
        let Ok(payload) = self.shared.codec.open(PacketKind::Stream, &mut buf) else {
            return;
        };
        let kinds: Vec<u8> = payload.iter().map(|m| m.kind()).collect();
        let is_new = matches!(self.inner, Inner::New(_));
        if kinds.contains(&kinship_proto::kind::PUSH_PULL_DIGEST) {
            *digest = true;
            match to_old {
                true => seen.digest_to_old += 1,
                false => seen.digest_to_new += 1,
            }
        } else if kinds.contains(&kinship_proto::kind::PUSH_PULL) {
            match (is_new, to_old) {
                (true, true) => seen.full_to_old += 1,
                (true, false) => seen.full_to_new += 1,
                (false, _) => seen.full_from_old += 1,
            }
        }
    }

    /// The live members this node holds, itself included.
    fn view(&self) -> BTreeSet<usize> {
        match &self.inner {
            Inner::New(n) => n.members().map(|m| index_of(&m.name)).collect(),
            Inner::Old(n) => n.members().map(|m| index_of(&m.name)).collect(),
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
        match &mut self.inner {
            Inner::New(n) => n.poll_event().map(|e: Event| drop(e)),
            Inner::Old(n) => n.poll_event().map(drop),
        }
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

/// A run of `nodes`, the last `on_0_4` of them on 0.4.0, as the module describes.
fn mixed(seed: u64, nodes: usize, on_0_4: usize) -> Result<Exchanges, String> {
    let cfg = config();
    let mut rng = Rng::new(seed ^ 0x6469_6765_7374);
    let via = rng.index(nodes);
    let loss = rng.next_f64() * 0.01;
    let start = ms(20_000 + rng.below(10_000));
    let length = ms(10_000 + rng.below(15_000));
    let mut all: Vec<usize> = (0..nodes).collect();
    rng.shuffle(&mut all);
    let side: BTreeSet<usize> = all[..1 + rng.index(nodes / 2)].iter().copied().collect();
    let other: Vec<usize> = (0..nodes).filter(|n| !side.contains(n)).collect();
    let healed = Instant::ZERO + start + length;
    let bound = heal_bound(&cfg, nodes);
    let mut scenario = Scenario::new(nodes)
        .duration(start + length + bound + secs(1))
        .link(LinkConfig::lan().with_loss(loss))
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
        on_0_4: (nodes - on_0_4..nodes).collect(),
        seen: RefCell::default(),
    });
    let factory = shared.clone();
    let mut sim = Sim::new(seed, scenario, move |spec| Peer::new(spec, &factory));
    let fail = |msg: String| {
        Err(format!(
            "seed {seed}, {nodes} nodes, {on_0_4} on 0.4, joined through n{via}: {msg}\n\
             loss {loss:.4}, partition {start:?} for {length:?}, side {side:?}"
        ))
    };
    let everyone: BTreeSet<usize> = (0..nodes).collect();
    sim.run_until(healed);
    let converged = loop {
        if (0..nodes).all(|o| sim.node(o).is_some_and(|n| n.view() == everyone)) {
            break true;
        }
        if sim.now() >= healed + bound {
            break false;
        }
        let next = (sim.now() + ms(250)).min(healed + bound);
        sim.run_until(next);
    };
    if !converged {
        let bad: Vec<String> = (0..nodes)
            .filter_map(|o| {
                let view = sim.node(o).map(Peer::view).unwrap_or_default();
                let missing: Vec<usize> = everyone.difference(&view).copied().collect();
                (!missing.is_empty()).then(|| format!("n{o} misses {missing:?}"))
            })
            .take(5)
            .collect();
        return fail(format!(
            "not reconverged {bound:?} after the heal: {}",
            bad.join("; ")
        ));
    }
    for o in 0..nodes {
        let errors = sim.node(o).map_or(0, Peer::decode_errors);
        if errors > 0 {
            return fail(format!("n{o} counted {errors} decode errors"));
        }
    }
    let seen = *shared.seen.borrow();
    if seen.digest_to_old > 0 {
        return fail(format!("{} digests went to 0.4 nodes", seen.digest_to_old));
    }
    Ok(seen)
}

/// The exchanges of `runs`, summed, as one line.
fn summary(runs: &[Exchanges]) -> (Exchanges, String) {
    let mut sum = Exchanges::default();
    for r in runs {
        sum.add(r);
    }
    let line = format!(
        "digests between new nodes {} ({} with a third frame), full to new {}, full to 0.4 {}, \
         full from 0.4 {}",
        sum.digest_to_new, sum.third_frames, sum.full_to_new, sum.full_to_old, sum.full_from_old
    );
    (sum, line)
}

#[test]
fn digest_and_full_exchanges_meet_in_mixed_clusters() {
    let runs = check_all(0..12, |seed| mixed(seed, 16, 4 + 4 * (seed as usize % 2)));
    let (sum, line) = summary(&runs);
    println!("{line}");
    assert!(sum.digest_to_new > 0 && sum.third_frames > 0, "{line}");
    assert!(sum.full_to_old > 0 && sum.full_from_old > 0, "{line}");
}

/// 1,000 seeds of 20 nodes, 5, 10 or 15 of them on 0.4.0.
#[test]
#[ignore = "slow in debug builds; CI runs it with --release"]
fn thousand_seeds_mixed_with_0_4() {
    let seeds = seeds(1000);
    let started = std::time::Instant::now();
    let runs = check_all(seeds.clone(), |seed| {
        mixed(seed, 20, 5 + 5 * (seed as usize % 3))
    });
    let (sum, line) = summary(&runs);
    println!(
        "{} seeds x 20 nodes beside 0.4.0 reconverged in {:?}: {line}",
        seeds.end - seeds.start,
        started.elapsed()
    );
    assert!(sum.digest_to_new > 0 && sum.full_to_old > 0, "{line}");
}
