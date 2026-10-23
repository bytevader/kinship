//! What mode `sign` costs (KI-01 Stage 2c, `docs/results/signed.md`): the bytes each node
//! sends a second, by what carries them, and the signatures it makes and checks, in the
//! clusters the plan estimated the cost for (`docs/ki01-per-member-keys.md`, Cost), run once in
//! mode `off` and once with every node of this version in mode `sign`.
//!
//! Every node opens what it sends and files each message under its carrier: probe messages,
//! rumours, the certificates ahead of Alives, of relayed Acks and of user messages, user
//! messages, announcements and each packet's header and tag. Push-pull frames are filed by
//! their version, and a version 1 exchange between two signing nodes is the second exchange of
//! a mixed view. A version 1 datagram sent beside a version 2 one, to a member that speaks
//! version 2, is counted again on its own. Frames are counted at the node that opened the
//! connection, both ways, so that a reply is filed with its request.
//!
//! `cargo test --release -p kinship-sim --test costs -- --ignored --nocapture --exact costs`
//! runs every cluster, each in a worker process, and writes `docs/results/signed-costs.csv`;
//! `KINSHIP_CLUSTERS` (names separated by `,`) runs some of them. `announcements` measures what
//! members send a node that joins a large signing cluster, and the largest burst one node sends.

mod common;

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use common::{Mode, ms, secs};
use kinship_core::{
    Command, CommandId, Config, Event, Identity, Instant, Node, Rng, Security, StreamEvent,
    StreamId, Transmit,
};
use kinship_core_0_4 as old;
use kinship_proto::{Codec, Limits, Message, PacketKind, VersionedPayload, v2};
use kinship_sim::{
    Action, Delay, LinkConfig, NodeSpec, Scenario, Sim, SimNode, TraceConfig, addr_of,
};

/// A 17-byte name for node `i`, as the plan's measurements used: `cache-0042-3f9a1c`.
fn long_name(i: usize) -> String {
    let tag = (i as u64 + 1).wrapping_mul(0x9e37_79b9_7f4a_7c15) >> 40;
    format!("cache-{i:04}-{tag:06x}")
}

/// The codec every node seals with, to open what they send.
fn codec() -> Codec {
    let cfg = common::config();
    let Security::Keys(keys) = cfg.security else {
        unreachable!("the sweeps seal")
    };
    Codec::encrypted(cfg.cluster.as_bytes(), Limits::default(), keys).expect("the test key")
}

/// One measured window of a run.
#[derive(Debug, Clone, Copy)]
struct Window {
    name: &'static str,
    from: Duration,
    to: Duration,
}

/// Bytes by window and carrier, for the whole cluster, and what the nodes did at each window's
/// edges.
#[derive(Debug, Default)]
struct Ledger {
    bytes: BTreeMap<(usize, &'static str), u64>,
    /// Announcements one node sent at one instant, the largest seen, and when.
    burst: (usize, Instant),
    /// (node, instant) of the announcements being counted into `burst`.
    current: (usize, Instant, usize),
    /// Announcement datagrams to each node, by when they were sent.
    announced_to: BTreeMap<usize, Vec<(Instant, usize)>>,
}

struct Shared {
    windows: Vec<Window>,
    signing: Vec<bool>,
    codec: Codec,
    ledger: RefCell<Ledger>,
}

impl Shared {
    fn window(&self, t: Instant) -> Option<usize> {
        let t = t - Instant::ZERO;
        self.windows.iter().position(|w| w.from <= t && t < w.to)
    }

    fn add(&self, w: usize, carrier: &'static str, bytes: usize) {
        *self
            .ledger
            .borrow_mut()
            .bytes
            .entry((w, carrier))
            .or_default() += bytes as u64;
    }

    /// Files the datagram node `from` sent to node `to` at `t`. Returns whether it was a version
    /// 1 one, and its length, for [`Meter`] to tell whether a version 2 one followed it.
    fn datagram(&self, from: usize, to: Option<usize>, payload: &[u8], t: Instant) -> Option<bool> {
        let mut buf = payload.to_vec();
        let opened = self.codec.open_versioned(PacketKind::Datagram, &mut buf);
        let w = self.window(t);
        let Ok(p) = opened else {
            if let Some(w) = w {
                self.add(w, "undecodable", payload.len());
            }
            return None;
        };
        let me = long_name(from);
        match p {
            VersionedPayload::V1(p) => {
                let Some(w) = w else { return Some(true) };
                let mut body = 0;
                for m in p.iter() {
                    let len = m.encoded_len();
                    body += len;
                    let carrier = match m {
                        Message::Ping(_) | Message::PingReq(_) | Message::Ack { .. } => {
                            "probes, v1"
                        }
                        Message::Nack { .. } => "probes, v1",
                        Message::Alive(_) | Message::Suspect(_) | Message::Dead(_) => "rumours, v1",
                        Message::UserMessage(_) | Message::UserBroadcast(_) => "user messages, v1",
                        _ => "other, v1",
                    };
                    self.add(w, carrier, len);
                }
                self.add(w, "headers, v1", payload.len() - body);
                if to.is_some_and(|j| self.signing[j] && self.signing[from]) {
                    self.add(w, "v1 datagrams to signing members", payload.len());
                }
                Some(true)
            }
            VersionedPayload::V2(p) => {
                let msgs: Vec<v2::Message<'_>> = p.iter().collect();
                let announcement = matches!(
                    &msgs[..],
                    [v2::Message::Certificate(c), v2::Message::Alive(a)]
                        if c.name().as_str() == me && a.alive.node.as_str() == me
                );
                if announcement {
                    let mut l = self.ledger.borrow_mut();
                    let (node, at, n) = l.current;
                    let n = if (node, at) == (from, t) { n + 1 } else { 1 };
                    l.current = (from, t, n);
                    if n > l.burst.0 {
                        l.burst = (n, t);
                    }
                    if let Some(j) = to {
                        l.announced_to
                            .entry(j)
                            .or_default()
                            .push((t, payload.len()));
                    }
                }
                let Some(w) = w else { return Some(false) };
                if announcement {
                    self.add(w, "announcements", payload.len());
                    return Some(false);
                }
                let mut body = 0;
                for (k, m) in msgs.iter().enumerate() {
                    let len = m.encoded_len();
                    body += len;
                    let carrier = match m {
                        v2::Message::Ping { .. }
                        | v2::Message::PingReq { .. }
                        | v2::Message::Ack { .. }
                        | v2::Message::Nack { .. } => "probes, v2",
                        v2::Message::Alive(_)
                        | v2::Message::Suspect { .. }
                        | v2::Message::Dead { .. } => "rumours, v2",
                        v2::Message::UserMessage { .. } | v2::Message::UserBroadcast { .. } => {
                            "user messages, v2"
                        }
                        v2::Message::Certificate(_) => match msgs.get(k + 1) {
                            Some(v2::Message::Alive(_)) => "certificates ahead of Alives",
                            Some(v2::Message::Ack { .. }) => "certificates ahead of Acks",
                            Some(
                                v2::Message::UserMessage { .. } | v2::Message::UserBroadcast { .. },
                            ) => "certificates ahead of user messages",
                            _ => "certificates, other",
                        },
                        _ => "other, v2",
                    };
                    self.add(w, carrier, len);
                }
                self.add(w, "headers, v2", payload.len() - body);
                Some(false)
            }
        }
    }

    /// Files a frame of `len` bytes, its length prefix included, on a connection `opener`
    /// opened to `peer`.
    fn frame(&self, opener: usize, peer: Option<usize>, frame: &[u8], len: usize, t: Instant) {
        let Some(w) = self.window(t) else { return };
        let mut buf = frame.to_vec();
        let carrier = match self.codec.open_versioned(PacketKind::Stream, &mut buf) {
            Ok(VersionedPayload::V2(p)) => {
                if p.iter().any(|m| matches!(m, v2::Message::PushPull(_))) {
                    "push-pull, v2"
                } else if p
                    .iter()
                    .any(|m| matches!(m, v2::Message::Ping { .. } | v2::Message::Ack { .. }))
                {
                    "TCP probes"
                } else {
                    "user frames"
                }
            }
            Ok(VersionedPayload::V1(p)) => {
                if p.iter().any(|m| matches!(m, Message::PushPull(_))) {
                    let both = self.signing[opener] && peer.is_some_and(|j| self.signing[j]);
                    if both {
                        "push-pull, v1 between signing nodes"
                    } else {
                        "push-pull, v1"
                    }
                } else if p
                    .iter()
                    .any(|m| matches!(m, Message::Ping(_) | Message::Ack { .. }))
                {
                    "TCP probes"
                } else {
                    "user frames"
                }
            }
            Err(_) => "undecodable",
        };
        self.add(w, carrier, len);
    }
}

enum Inner {
    New(Box<Node>),
    /// The released kinship-core 0.4.0.
    Old(Box<old::Node>),
}

fn to_old(t: Instant) -> old::Instant {
    old::Instant::from_nanos(t.as_nanos())
}

/// A node of this version, in the run's mode, or of 0.4.0, that files what it sends.
struct Meter {
    inner: Inner,
    index: usize,
    now: Instant,
    shared: Rc<Shared>,
    /// Connections this node opened, to which node.
    opened: BTreeMap<StreamId, Option<usize>>,
    /// The version 1 datagram this input sent last, to whom and how long, until a version 2
    /// one to the same member shows it went beside it.
    last_v1: Option<(SocketAddr, usize)>,
}

impl Meter {
    /// Node `spec`, on 0.4.0 if `on_0_4` and otherwise in `mode`, knowing the nodes `knows`
    /// accepts from the start, as a static member list would.
    fn new(
        spec: &NodeSpec,
        mode: Mode,
        on_0_4: bool,
        knows: impl Fn(usize) -> bool,
        shared: &Rc<Shared>,
    ) -> Self {
        let name = long_name(spec.index);
        let others: Vec<usize> = (0..spec.nodes)
            .filter(|&j| j != spec.index && knows(j))
            .collect();
        let inner = if on_0_4 {
            let cfg = common::config();
            let Security::Keys(keys) = cfg.security else {
                unreachable!()
            };
            let key = old::Key::from_base64(&keys[0].to_base64()).expect("the test key");
            let cfg = old::Config::lan(old::Security::Keys(vec![key]));
            let me = old::Identity::new(name, spec.addr)
                .unwrap()
                .with_epoch(spec.epoch());
            let now = to_old(spec.now);
            let mut n = old::Node::new(cfg, me, now, spec.seed, &spec.nonce_key()).unwrap();
            for &j in &others {
                n.add_member(now, &long_name(j), addr_of(j)).unwrap();
            }
            while n.poll_event().is_some() {}
            Inner::Old(Box::new(n))
        } else {
            let cfg = mode.config(spec, &name);
            let me = Identity::new(name, spec.addr)
                .unwrap()
                .with_epoch(spec.epoch());
            let mut n = Node::new(cfg, me, spec.now, spec.seed, &spec.nonce_key()).unwrap();
            for &j in &others {
                n.add_member(spec.now, &long_name(j), addr_of(j)).unwrap();
            }
            while n.poll_event().is_some() {}
            Inner::New(Box::new(n))
        };
        Self {
            inner,
            index: spec.index,
            now: spec.now,
            shared: shared.clone(),
            opened: BTreeMap::new(),
            last_v1: None,
        }
    }

    fn node(&self) -> Option<&Node> {
        match &self.inner {
            Inner::New(n) => Some(n),
            Inner::Old(_) => None,
        }
    }

    fn input(&mut self, now: Instant) {
        self.now = now;
        self.last_v1 = None;
    }
}

/// The node at `addr`, as [`addr_of`] numbers them.
fn index_at(addr: SocketAddr) -> Option<usize> {
    let SocketAddr::V4(a) = addr else { return None };
    let [_, a, b, c] = a.ip().octets();
    Some(usize::from(a) << 16 | usize::from(b) << 8 | usize::from(c))
}

impl SimNode for Meter {
    type Command = Command;
    type Event = ();

    fn handle_datagram(&mut self, now: Instant, from: SocketAddr, buf: &[u8]) {
        self.input(now);
        match &mut self.inner {
            Inner::New(n) => n.handle_datagram(now, from, buf),
            Inner::Old(n) => n.handle_datagram(to_old(now), from, buf),
        }
    }

    fn handle_stream(&mut self, now: Instant, conn: StreamId, ev: StreamEvent<'_>) {
        self.input(now);
        if let (StreamEvent::Frame(f), Some(&peer)) = (&ev, self.opened.get(&conn)) {
            self.shared.frame(self.index, peer, f, f.len() + 4, now);
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
        self.input(now);
        match &mut self.inner {
            Inner::New(n) => n.handle_timeout(now),
            Inner::Old(n) => n.handle_timeout(to_old(now)),
        }
    }

    fn command(&mut self, now: Instant, cmd: Command) -> CommandId {
        self.input(now);
        match &mut self.inner {
            Inner::New(n) => n.command(now, cmd),
            Inner::Old(n) => {
                let cmd = match cmd {
                    Command::Join { seeds } => old::Command::Join { seeds },
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
            Transmit::Datagram { to, payload } => {
                let j = index_at(*to);
                let v1 = self.shared.datagram(self.index, j, payload, self.now);
                if v1 == Some(false) {
                    // A version 2 datagram right behind a version 1 one to the same member:
                    // the version 1 one went beside it.
                    if let Some((addr, len)) = self.last_v1.take() {
                        let both = j.is_some_and(|j| self.shared.signing[j]);
                        if addr == *to && both && self.shared.signing[self.index] {
                            if let Some(w) = self.shared.window(self.now) {
                                self.shared.add(w, "v1 datagrams beside a v2 one", len);
                            }
                        }
                    }
                } else {
                    self.last_v1 = (v1 == Some(true)).then_some((*to, payload.len()));
                }
            }
            Transmit::Connect { conn, to } => {
                self.opened.insert(*conn, index_at(*to));
            }
            Transmit::Stream { conn, frame } => {
                if let Some(&peer) = self.opened.get(conn) {
                    self.shared
                        .frame(self.index, peer, &frame[4..], frame.len(), self.now);
                }
            }
            Transmit::Close { conn } => {
                self.opened.remove(conn);
            }
        }
        Some(t)
    }

    fn poll_event(&mut self) -> Option<()> {
        match &mut self.inner {
            Inner::New(n) => n.poll_event().map(|_: Event| ()),
            Inner::Old(n) => n.poll_event().map(|_| ()),
        }
    }

    fn poll_timeout(&self) -> Option<Instant> {
        match &self.inner {
            Inner::New(n) => n.poll_timeout(),
            Inner::Old(n) => n.poll_timeout().map(|t| Instant::from_nanos(t.as_nanos())),
        }
    }
}

/// One measured cluster.
#[derive(Debug, Clone, Copy)]
struct Cluster {
    name: &'static str,
    nodes: usize,
    /// The last this many nodes run 0.4.0.
    on_0_4: usize,
    /// Loss on every link, and the share of nodes that read every packet 0.5 to 2.5 s late.
    loss: f64,
    starved: f64,
    /// Each node of this version broadcasts once, and sends one direct message, every this
    /// often in the steady window.
    users: Option<Duration>,
    seed: u64,
}

/// The plan's clusters: on `lan()`, sealed, 17-byte names and 48 bytes of metadata, set by
/// every member between 1 and 5 s, a crash at 240 s, 330 s in all; stressed clusters add 1%
/// loss and starve 1% of the nodes. A mixed one has 10% of its nodes on 0.4.0, and one sends
/// user messages.
const CLUSTERS: &[Cluster] = &[
    Cluster {
        name: "100",
        nodes: 100,
        on_0_4: 0,
        loss: 0.0,
        starved: 0.0,
        users: None,
        seed: 0,
    },
    Cluster {
        name: "100-seed1",
        nodes: 100,
        on_0_4: 0,
        loss: 0.0,
        starved: 0.0,
        users: None,
        seed: 1,
    },
    Cluster {
        name: "100-stress",
        nodes: 100,
        on_0_4: 0,
        loss: 0.01,
        starved: 0.01,
        users: None,
        seed: 0,
    },
    Cluster {
        name: "100-mixed",
        nodes: 100,
        on_0_4: 10,
        loss: 0.0,
        starved: 0.0,
        users: None,
        seed: 0,
    },
    Cluster {
        name: "100-users",
        nodes: 100,
        on_0_4: 0,
        loss: 0.0,
        starved: 0.0,
        users: Some(Duration::from_secs(10)),
        seed: 0,
    },
    Cluster {
        name: "1000",
        nodes: 1000,
        on_0_4: 0,
        loss: 0.0,
        starved: 0.0,
        users: None,
        seed: 0,
    },
    Cluster {
        name: "1000-stress",
        nodes: 1000,
        on_0_4: 0,
        loss: 0.01,
        starved: 0.01,
        users: None,
        seed: 0,
    },
];

const WINDOWS: [Window; 2] = [
    Window {
        name: "burst",
        from: Duration::from_secs(5),
        to: Duration::from_secs(150),
    },
    Window {
        name: "steady",
        from: Duration::from_secs(150),
        to: Duration::from_secs(330),
    },
];

/// What one run of a cluster in one mode measured.
#[derive(Debug, Default)]
struct Measured {
    /// Bytes by window and carrier, for the whole cluster.
    bytes: BTreeMap<(usize, &'static str), u64>,
    /// Summed over the nodes of this version: signatures made and checked, and members held
    /// unsigned, at the start and the end of each window.
    made: Vec<u64>,
    checked: Vec<u64>,
    unsigned: Vec<u64>,
    /// The simulator's own count of datagram and frame bytes, for every window together.
    sim_bytes: u64,
}

fn run(c: Cluster, mode: Mode, windows: &[Window]) -> Measured {
    let n = c.nodes;
    let mut rng = Rng::new(c.seed ^ 0x636f_7374);
    let starved: BTreeSet<usize> = if c.starved > 0.0 {
        let k = ((n as f64 * c.starved).round() as usize).max(1);
        let mut all: Vec<usize> = (0..n - c.on_0_4).collect();
        rng.shuffle(&mut all);
        all.into_iter().take(k).collect()
    } else {
        BTreeSet::new()
    };
    let end = windows[windows.len() - 1].to;
    let mut scenario = Scenario::new(n)
        .link(LinkConfig::lan().with_loss(c.loss))
        .trace(TraceConfig::OFF)
        .duration(end);
    for i in 0..n {
        let meta = format!("zone=eu-west-1a;rack={i:04};tier=cache;v=2026.10;").into_bytes();
        let mut meta = meta;
        meta.resize(48, b'.');
        let at = ms(1_000 + rng.below(4_000));
        scenario = scenario.at(
            at,
            Action::Command {
                node: i,
                cmd: Command::SetMeta(meta),
            },
        );
    }
    let victim = loop {
        let v = rng.index(n - c.on_0_4);
        if !starved.contains(&v) {
            break v;
        }
    };
    scenario = scenario.at(secs(240), Action::Crash(victim));
    for &s in &starved {
        scenario = scenario.starved_node(
            s,
            Delay::Uniform {
                min: ms(500),
                max: ms(2500),
            },
        );
    }
    if let Some(every) = c.users {
        let senders: Vec<usize> = (0..n - c.on_0_4).filter(|&i| i != victim).collect();
        let steady = windows[windows.len() - 1];
        for &i in &senders {
            let mut t = steady.from + Duration::from_millis(rng.below(every.as_millis() as u64));
            while t + secs(5) < steady.to {
                let to = senders[rng.index(senders.len())];
                if to != i {
                    let data = format!("message from {i} at {t:?}").into_bytes();
                    let cmd = Command::Send {
                        to: long_name(to),
                        epoch: 0,
                        data,
                    };
                    scenario = scenario.at(t, Action::Command { node: i, cmd });
                }
                let data = format!("broadcast from {i} at {t:?}").into_bytes();
                let cmd = Command::Broadcast(data);
                scenario = scenario.at(t + ms(500), Action::Command { node: i, cmd });
                t += every;
            }
        }
    }
    let signing: Vec<bool> = (0..n)
        .map(|i| mode == Mode::Sign && i < n - c.on_0_4)
        .collect();
    let shared = Rc::new(Shared {
        windows: windows.to_vec(),
        signing,
        codec: codec(),
        ledger: RefCell::default(),
    });
    let factory = shared.clone();
    let on_0_4 = c.on_0_4;
    let mut sim = Sim::new(c.seed, scenario, move |spec| {
        let old = spec.index >= spec.nodes - on_0_4;
        Meter::new(spec, mode, old, |_| true, &factory)
    });
    let mut out = Measured::default();
    let sample = |sim: &Sim<Meter>, out: &mut Measured| {
        let nodes = (0..n).filter_map(|i| sim.node(i)).filter_map(Meter::node);
        let (mut made, mut checked, mut unsigned) = (0, 0, 0);
        for node in nodes {
            let m = node.metrics();
            made += m.signatures_made;
            checked += m.signatures_checked;
            unsigned += m.unsigned_members;
        }
        out.made.push(made);
        out.checked.push(checked);
        out.unsigned.push(unsigned);
    };
    let mut sim_bytes = 0;
    for &w in windows {
        sim.run_until(Instant::ZERO + w.from);
        let before = sim.stats().sent_bytes + sim.stats().stream_bytes;
        sample(&sim, &mut out);
        sim.run_until(Instant::ZERO + w.to);
        sim_bytes += sim.stats().sent_bytes + sim.stats().stream_bytes - before;
        sample(&sim, &mut out);
    }
    out.sim_bytes = sim_bytes;
    out.bytes = std::mem::take(&mut shared.ledger.borrow_mut().bytes);
    out
}

/// The rows of one cluster in one mode: per window, each carrier's bytes per node per second,
/// then the totals, the signatures made and checked per node per second, and the members held
/// unsigned at the window's end, summed over nodes.
fn rows(c: Cluster, mode: Mode, windows: &[Window], m: &Measured) -> String {
    let mut out = String::new();
    let mode_name = match mode {
        Mode::Off => "off",
        Mode::Sign => "sign",
    };
    let nodes = c.nodes as f64;
    let mut ours = 0;
    for (w, window) in windows.iter().enumerate() {
        let secs = (window.to - window.from).as_secs_f64();
        let per = |b: u64| b as f64 / nodes / secs;
        let mut total = 0;
        for (&(ww, carrier), &b) in &m.bytes {
            if ww != w {
                continue;
            }
            if !matches!(
                carrier,
                "v1 datagrams beside a v2 one" | "v1 datagrams to signing members"
            ) {
                total += b;
            }
            writeln!(
                out,
                "{},{mode_name},{},{carrier},{:.1}",
                c.name,
                window.name,
                per(b)
            )
            .unwrap();
        }
        ours += total;
        writeln!(
            out,
            "{},{mode_name},{},total,{:.1}",
            c.name,
            window.name,
            per(total)
        )
        .unwrap();
        let rate = |v: &[u64]| (v[2 * w + 1] - v[2 * w]) as f64 / nodes / secs;
        writeln!(
            out,
            "{},{mode_name},{},signatures made,{:.2}",
            c.name,
            window.name,
            rate(&m.made)
        )
        .unwrap();
        writeln!(
            out,
            "{},{mode_name},{},signatures checked,{:.2}",
            c.name,
            window.name,
            rate(&m.checked)
        )
        .unwrap();
        writeln!(
            out,
            "{},{mode_name},{},members held unsigned at the end,{}",
            c.name,
            window.name,
            m.unsigned[2 * w + 1]
        )
        .unwrap();
    }
    assert_eq!(
        ours, m.sim_bytes,
        "{}: every byte the simulator carried is filed",
        c.name
    );
    out
}

/// A small mixed cluster with user messages files every byte the simulator carried, opens
/// everything it files, and finds what each mode sends: in `sign`, version 2 probes and
/// rumours, certificates and the second push-pull exchange of a mixed view; in `off`, none.
#[test]
fn the_ledger_files_every_byte() {
    let c = Cluster {
        name: "small",
        nodes: 8,
        on_0_4: 2,
        loss: 0.0,
        starved: 0.0,
        users: Some(Duration::from_secs(5)),
        seed: 3,
    };
    let windows = [
        Window {
            name: "start",
            from: Duration::from_secs(1),
            to: Duration::from_secs(8),
        },
        Window {
            name: "on",
            from: Duration::from_secs(8),
            to: Duration::from_secs(25),
        },
    ];
    for mode in [Mode::Off, Mode::Sign] {
        let m = run(c, mode, &windows);
        // Panics unless the ledger adds up to the simulator's count.
        let rows = rows(c, mode, &windows, &m);
        assert!(!rows.contains("undecodable"), "{rows}");
        let has = |carrier: &str| m.bytes.keys().any(|k| k.1 == carrier);
        let signed = [
            "probes, v2",
            "rumours, v2",
            "certificates ahead of user messages",
            "user messages, v2",
            "push-pull, v2",
            "push-pull, v1 between signing nodes",
        ];
        for carrier in signed {
            assert_eq!(
                has(carrier),
                mode == Mode::Sign,
                "{carrier} in {mode:?}: {rows}"
            );
        }
        assert!(has("probes, v1") && has("push-pull, v1"), "{rows}");
    }
}

/// The worker process [`costs`] starts: runs the cluster in `KINSHIP_COSTS_WORKER` in both modes
/// and prints its rows. Does nothing without it.
#[test]
#[ignore = "started by the sweep"]
fn costs_worker() {
    let Ok(name) = std::env::var("KINSHIP_COSTS_WORKER") else {
        return;
    };
    let c = *CLUSTERS.iter().find(|c| c.name == name).expect("a cluster");
    for mode in [Mode::Off, Mode::Sign] {
        let m = run(c, mode, &WINDOWS);
        print!("{}", rows(c, mode, &WINDOWS, &m));
    }
}

/// What one join into a signing cluster measured.
#[derive(Debug)]
struct Join {
    /// Announcements the joiner received in the 30 s after it joined, and their bytes.
    count: usize,
    bytes: usize,
    /// The most of them sent in one gossip interval, and from the join to the last one.
    peak: usize,
    spread: Duration,
    /// The most announcements one node sent at one instant, anywhere in the run, and when.
    burst: (usize, Instant),
}

/// A cluster of `n` signing nodes that know each other from a static list, and a node that knows
/// nobody joins through one of them at `at`.
fn join(n: usize, seed: u64, at: Duration) -> Join {
    let joiner = n - 1;
    let scenario = Scenario::new(n)
        .link(LinkConfig::lan())
        .trace(TraceConfig::OFF)
        .duration(at + secs(30))
        .at(
            at,
            Action::Command {
                node: joiner,
                cmd: Command::Join {
                    seeds: vec![addr_of(0)],
                },
            },
        );
    let shared = Rc::new(Shared {
        windows: Vec::new(),
        signing: vec![true; n],
        codec: codec(),
        ledger: RefCell::default(),
    });
    let factory = shared.clone();
    let mut sim = Sim::new(seed, scenario, move |spec| {
        // The joiner knows nobody, and nobody knows the joiner.
        let me = spec.index;
        let knows = move |j: usize| me != joiner && j != joiner;
        Meter::new(spec, Mode::Sign, false, knows, &factory)
    });
    sim.run();
    let ledger = shared.ledger.borrow();
    let joined = Instant::ZERO + at;
    let got: Vec<(Instant, usize)> = ledger
        .announced_to
        .get(&joiner)
        .map(|v| v.iter().copied().filter(|(t, _)| *t >= joined).collect())
        .unwrap_or_default();
    let gossip = Config::lan(Security::InsecurePlaintext).gossip_interval;
    let mut per_tick: BTreeMap<u128, usize> = BTreeMap::new();
    for (t, _) in &got {
        *per_tick
            .entry((*t - joined).as_nanos() / gossip.as_nanos())
            .or_default() += 1;
    }
    Join {
        count: got.len(),
        bytes: got.iter().map(|g| g.1).sum(),
        peak: per_tick.values().copied().max().unwrap_or(0),
        spread: got.last().map_or(Duration::ZERO, |g| g.0 - joined),
        burst: ledger.burst,
    }
}

/// What members send a node that joins a large signing cluster, and the largest burst of
/// announcements one node sends at one instant, which a cluster started from static lists
/// makes.
#[test]
#[ignore = "a few minutes in release mode"]
fn announcements() {
    for n in [200, 1000] {
        let j = join(n, 0, secs(60));
        println!(
            "{n} nodes: the joiner received {} announcements, {} bytes, at most {} in one \
             gossip interval, the last {:?} after the join; one node sent at most {} at one \
             instant, at {:?}",
            j.count, j.bytes, j.peak, j.spread, j.burst.0, j.burst.1
        );
    }
}

fn csv_path() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/results/signed-costs.csv")
}

/// Runs every cluster in both modes, each cluster in a worker process, and writes the rows.
#[test]
#[ignore = "about half an hour in release mode"]
fn costs() {
    use std::process::{Command as Process, Stdio};
    let only = std::env::var("KINSHIP_CLUSTERS").ok();
    let wanted: Vec<Cluster> = CLUSTERS
        .iter()
        .copied()
        .filter(|c| {
            only.as_ref()
                .is_none_or(|o| o.split(',').any(|n| n == c.name))
        })
        .collect();
    let exe = std::env::current_exe().unwrap();
    let children: Vec<(Cluster, std::process::Child)> = wanted
        .iter()
        .map(|&c| {
            let child = Process::new(&exe)
                .args(["--ignored", "--nocapture", "--exact", "costs_worker"])
                .env("KINSHIP_COSTS_WORKER", c.name)
                .stdout(Stdio::piped())
                .spawn()
                .unwrap();
            (c, child)
        })
        .collect();
    let mut rows = BTreeMap::new();
    for (c, child) in children {
        let out = child.wait_with_output().unwrap();
        assert!(out.status.success(), "{} failed", c.name);
        let text = String::from_utf8(out.stdout).unwrap();
        let lines: String = text
            .lines()
            .filter(|l| l.starts_with(c.name) && l.matches(',').count() == 4)
            .map(|l| format!("{l}\n"))
            .collect();
        eprint!("{lines}");
        rows.insert(c.name, lines);
    }
    let path = csv_path();
    let mut csv = std::fs::read_to_string(&path)
        .unwrap_or_else(|_| "cluster,mode,window,carrier,bytes_per_node_s\n".to_owned());
    for (name, lines) in rows {
        // A cluster run again replaces its rows.
        let kept: String = csv
            .lines()
            .filter(|l| l.split(',').next() != Some(name))
            .map(|l| format!("{l}\n"))
            .collect();
        csv = kept + &lines;
    }
    std::fs::write(&path, csv).unwrap();
}
