//! The simulation engine: a virtual clock, an event queue and a seeded network.

use std::cmp::Ordering;
use std::collections::{BTreeMap, BinaryHeap, HashMap, VecDeque};
use std::net::SocketAddr;
use std::time::Duration;

use kinship_core::{Instant, Rng, StreamEvent, StreamId, Transmit};
use kinship_proto::FrameReader;
use serde::Serialize;

use crate::SimNode;
use crate::scenario::{Action, Delay, LinkConfig, LinkRule, NodeSet, Scenario};
use crate::trace::{DropReason, Record, Trace, TraceConfig, TraceNode, fnv1a};

/// Largest payload a UDP datagram can carry over IPv4.
const MAX_UDP: usize = 65_507;

/// The address the simulator gives node `index`: `10.x.y.z:7946`.
pub fn addr_of(index: usize) -> SocketAddr {
    let i = index as u32;
    SocketAddr::from(([10, (i >> 16) as u8, (i >> 8) as u8, i as u8], 7946))
}

/// The name the simulator gives node `index`: `n<index>`.
pub fn name_of(index: usize) -> String {
    format!("n{index}")
}

/// What a node factory needs to build one node.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct NodeSpec {
    pub index: usize,
    /// Number of nodes in the run.
    pub nodes: usize,
    pub name: String,
    pub addr: SocketAddr,
    /// This instance's seed, derived from the run's seed; a restart gets a new one.
    pub seed: u64,
    /// When this instance starts.
    pub now: Instant,
}

/// Counters for a run, kept whatever the trace records.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize)]
#[non_exhaustive]
pub struct Stats {
    pub sent: u64,
    pub delivered: u64,
    pub lost: u64,
    pub partitioned: u64,
    pub to_down_node: u64,
    pub no_route: u64,
    pub too_large: u64,
    pub duplicated: u64,
    pub timeouts: u64,
    pub commands: u64,
    pub events: u64,
    pub stream_frames: u64,
    pub stream_failures: u64,
}

/// A deterministic run of N nodes.
///
/// A run is fully defined by its seed and its [`Scenario`] (and the node code): the same pair
/// gives a byte-identical [`Trace`]. Every random draw comes from one RNG in event order, events
/// at the same instant run in the order they were scheduled, and nothing reads a real clock.
pub struct Sim<N: SimNode> {
    now: Instant,
    end: Instant,
    rng: Rng,
    queue: Queue<N::Command>,
    nodes: Vec<Slot<N>>,
    specs: Vec<NodeSpec>,
    addrs: HashMap<SocketAddr, usize>,
    factory: Box<dyn FnMut(&NodeSpec) -> N>,
    net: Net,
    conns: Conns,
    rec: Recorder,
    transmit_buf: Vec<Transmit>,
}

struct Slot<N: SimNode> {
    node: Option<N>,
    timer: Option<Instant>,
    timer_gen: u64,
    /// Inputs arriving before this wait in `backlog`; see [`Action::Pause`] and [`Action::Slow`].
    busy_until: Instant,
    backlog: VecDeque<Input<N::Command>>,
    wake_pending: bool,
    cost: Option<Delay>,
    /// Extra time each received packet waits before the node sees it; see [`Action::Starve`].
    starve: Option<Delay>,
    /// When the starved receive path hands over its last queued packet; packets stay in order.
    rx_free: Instant,
    /// Raised on every crash, so packets a dead instance had queued never reach its successor.
    life: u64,
    next_inbound: u64,
    /// How far this node's clock runs ahead of the shared one; see [`Action::ClockJump`].
    clock: Duration,
}

struct Net {
    default_link: LinkConfig,
    links: Vec<LinkRule>,
    blocks: Vec<(NodeSet, NodeSet)>,
    connect_timeout: Duration,
    max_stream_frame: usize,
    next_packet: u64,
}

impl Net {
    fn link(&self, from: usize, to: usize) -> &LinkConfig {
        self.links
            .iter()
            .rev()
            .find(|r| r.from.contains(from) && r.to.contains(to))
            .map_or(&self.default_link, |r| &r.link)
    }

    fn blocked(&self, from: usize, to: usize) -> bool {
        self.blocks
            .iter()
            .any(|(f, t)| f.contains(from) && t.contains(to))
    }
}

#[derive(Default)]
struct Conns {
    map: BTreeMap<u64, Conn>,
    ids: HashMap<(usize, StreamId), u64>,
    next: u64,
}

/// A simulated TCP connection. End 0 opened it, end 1 accepted it.
struct Conn {
    ends: [Option<End>; 2],
    /// Bytes arriving at end `i` are framed by `readers[i]`.
    readers: [FrameReader; 2],
    /// Latest delivery scheduled towards end `i`, which keeps each direction in order.
    last: [Instant; 2],
    failed: bool,
}

#[derive(Clone, Copy)]
struct End {
    node: usize,
    id: StreamId,
    /// The node has heard of this connection: always for the opener, after the first frame
    /// for the acceptor.
    known: bool,
    open: bool,
}

impl Conn {
    fn side_of(&self, node: usize, id: StreamId) -> usize {
        match self.ends[0] {
            Some(e) if e.node == node && e.id == id => 0,
            _ => 1,
        }
    }

    fn finished(&self) -> bool {
        self.ends.iter().all(|e| e.is_none_or(|e| !e.open))
    }
}

enum Input<C> {
    Datagram {
        from: SocketAddr,
        payload: Vec<u8>,
        packet: u64,
    },
    Timeout,
    StreamData {
        conn: u64,
        side: usize,
        bytes: Vec<u8>,
    },
    StreamEnd {
        conn: u64,
        side: usize,
        failed: bool,
    },
    Command(C),
}

enum Due<C> {
    Input {
        node: usize,
        input: Input<C>,
    },
    /// A packet a starved node's receive path is done with, for the instance `life`.
    Received {
        node: usize,
        life: u64,
        input: Input<C>,
    },
    Timer {
        node: usize,
        generation: u64,
    },
    Wake {
        node: usize,
    },
    Action(Action<C>),
}

struct Entry<C> {
    at: Instant,
    seq: u64,
    due: Due<C>,
}

impl<C> PartialEq for Entry<C> {
    fn eq(&self, other: &Self) -> bool {
        (self.at, self.seq) == (other.at, other.seq)
    }
}

impl<C> Eq for Entry<C> {}

impl<C> PartialOrd for Entry<C> {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl<C> Ord for Entry<C> {
    /// Reversed, so the max-heap pops the earliest entry, and the first scheduled among equals.
    fn cmp(&self, other: &Self) -> Ordering {
        (other.at, other.seq).cmp(&(self.at, self.seq))
    }
}

struct Queue<C> {
    heap: BinaryHeap<Entry<C>>,
    seq: u64,
}

impl<C> Queue<C> {
    fn push(&mut self, at: Instant, due: Due<C>) {
        self.heap.push(Entry {
            at,
            seq: self.seq,
            due,
        });
        self.seq += 1;
    }

    fn pop_until(&mut self, until: Instant) -> Option<Entry<C>> {
        if self.heap.peek()?.at > until {
            return None;
        }
        self.heap.pop()
    }
}

struct Recorder {
    cfg: TraceConfig,
    trace: Trace,
    stats: Stats,
}

impl Recorder {
    fn push(&mut self, on: bool, record: impl FnOnce() -> Record) {
        if on {
            self.trace.records.push(record());
        }
    }

    fn drop_packet(&mut self, t: Instant, packet: u64, reason: DropReason) {
        let s = &mut self.stats;
        match reason {
            DropReason::Loss => s.lost += 1,
            DropReason::Partition => s.partitioned += 1,
            DropReason::NodeDown => s.to_down_node += 1,
            DropReason::NoRoute => s.no_route += 1,
            DropReason::TooLarge => s.too_large += 1,
        }
        self.push(self.cfg.network, || Record::Drop { t, packet, reason });
    }

    fn event(&mut self, t: Instant, node: usize, event: &impl Serialize) {
        self.stats.events += 1;
        self.push(self.cfg.events, || Record::Event {
            t,
            node,
            event: serde_json::to_value(event).unwrap_or(serde_json::Value::Null),
        });
    }
}

impl<N: SimNode> Sim<N> {
    /// Builds every node with `factory` and schedules the scenario. Nothing runs until
    /// [`run`](Self::run) or [`run_until`](Self::run_until).
    pub fn new(
        seed: u64,
        scenario: Scenario<N::Command>,
        factory: impl FnMut(&NodeSpec) -> N + 'static,
    ) -> Self {
        let mut master = Rng::new(seed);
        let rng = master.fork();
        let specs: Vec<NodeSpec> = (0..scenario.nodes)
            .map(|index| NodeSpec {
                index,
                nodes: scenario.nodes,
                name: name_of(index),
                addr: addr_of(index),
                seed: master.next_u64(),
                now: Instant::ZERO,
            })
            .collect();
        let mut factory: Box<dyn FnMut(&NodeSpec) -> N> = Box::new(factory);
        let mut nodes: Vec<Slot<N>> = specs
            .iter()
            .map(|spec| Slot {
                node: Some(factory(spec)),
                timer: None,
                timer_gen: 0,
                busy_until: Instant::ZERO,
                backlog: VecDeque::new(),
                wake_pending: false,
                cost: None,
                starve: None,
                rx_free: Instant::ZERO,
                life: 0,
                next_inbound: 0,
                clock: Duration::ZERO,
            })
            .collect();
        for (node, cost) in scenario.slow {
            if let Some(slot) = nodes.get_mut(node) {
                slot.cost = Some(cost);
            }
        }
        for (node, delay) in scenario.starved {
            if let Some(slot) = nodes.get_mut(node) {
                slot.starve = Some(delay);
            }
        }
        let trace = Trace {
            format: Trace::FORMAT,
            seed,
            nodes: specs
                .iter()
                .map(|s| TraceNode {
                    index: s.index,
                    name: s.name.clone(),
                    addr: s.addr,
                })
                .collect(),
            records: Vec::new(),
        };
        let mut queue = Queue {
            heap: BinaryHeap::new(),
            seq: 0,
        };
        let mut actions = scenario.actions;
        actions.sort_by_key(|(at, _)| *at);
        for (at, action) in actions {
            queue.push(Instant::ZERO + at, Due::Action(action));
        }
        let mut sim = Self {
            now: Instant::ZERO,
            end: Instant::ZERO + scenario.duration,
            rng,
            queue,
            nodes,
            addrs: specs.iter().map(|s| (s.addr, s.index)).collect(),
            specs,
            factory,
            net: Net {
                default_link: scenario.link,
                links: scenario.links,
                blocks: Vec::new(),
                connect_timeout: scenario.connect_timeout,
                max_stream_frame: scenario.max_stream_frame,
                next_packet: 0,
            },
            conns: Conns::default(),
            rec: Recorder {
                cfg: scenario.trace,
                trace,
                stats: Stats::default(),
            },
            transmit_buf: Vec::new(),
        };
        for node in 0..sim.nodes.len() {
            sim.drain(node);
        }
        sim
    }

    /// Runs to the end of the scenario and returns the trace.
    pub fn run(&mut self) -> &Trace {
        self.run_until(self.end);
        &self.rec.trace
    }

    /// Processes everything due at or before `t`, then sets the clock to `t`.
    pub fn run_until(&mut self, t: Instant) {
        while let Some(entry) = self.queue.pop_until(t) {
            self.now = entry.at;
            self.dispatch(entry.due);
        }
        self.now = self.now.max(t);
    }

    /// Runs for `d` of simulated time from now.
    pub fn run_for(&mut self, d: Duration) {
        self.run_until(self.now + d);
    }

    pub fn now(&self) -> Instant {
        self.now
    }

    /// When the scenario ends.
    pub fn end(&self) -> Instant {
        self.end
    }

    /// Number of nodes, crashed ones included.
    pub fn len(&self) -> usize {
        self.nodes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.nodes.is_empty()
    }

    /// The node, or `None` while it is crashed.
    pub fn node(&self, index: usize) -> Option<&N> {
        self.nodes.get(index)?.node.as_ref()
    }

    pub fn spec(&self, index: usize) -> Option<&NodeSpec> {
        self.specs.get(index)
    }

    pub fn stats(&self) -> &Stats {
        &self.rec.stats
    }

    pub fn trace(&self) -> &Trace {
        &self.rec.trace
    }

    pub fn into_trace(self) -> Trace {
        self.rec.trace
    }

    /// Applies `action` now, as if the scenario had scheduled it.
    pub fn apply(&mut self, action: Action<N::Command>) {
        let t = self.now;
        self.rec.push(self.rec.cfg.actions, || Record::Action {
            t,
            action: action.describe(),
        });
        match action {
            Action::Partition { a, b } => {
                self.net.blocks.push((a.clone(), b.clone()));
                self.net.blocks.push((b, a));
            }
            Action::Block { from, to } => self.net.blocks.push((from, to)),
            Action::Heal => self.net.blocks.clear(),
            Action::SetLink { from, to, link } => self.net.links.push(LinkRule { from, to, link }),
            Action::ResetLinks => self.net.links.clear(),
            Action::Pause { node, duration } => {
                if let Some(slot) = self.nodes.get_mut(node) {
                    slot.busy_until = slot.busy_until.max(self.now + duration);
                }
            }
            Action::Slow { node, cost } => {
                if let Some(slot) = self.nodes.get_mut(node) {
                    slot.cost = cost;
                }
            }
            Action::Starve { node, delay } => {
                if let Some(slot) = self.nodes.get_mut(node) {
                    slot.starve = delay;
                }
            }
            Action::ClockJump { node, by } => {
                if let Some(slot) = self.nodes.get_mut(node) {
                    slot.clock = slot.clock.saturating_add(by);
                    // Its deadlines come earlier on the shared clock; reschedule the timer.
                    self.drain(node);
                }
            }
            Action::Crash(node) => self.crash(node),
            Action::Restart(node) => self.restart(node),
            Action::Command { node, cmd } => self.input(node, Input::Command(cmd)),
        }
    }

    fn dispatch(&mut self, due: Due<N::Command>) {
        match due {
            Due::Input { node, input } => self.receive(node, input),
            Due::Received { node, life, input } => {
                if self.nodes[node].life == life {
                    self.input(node, input);
                } else if let Input::Datagram { packet, .. } = input {
                    self.rec.drop_packet(self.now, packet, DropReason::NodeDown);
                }
            }
            Due::Timer { node, generation } => {
                if self.nodes[node].timer_gen == generation {
                    self.input(node, Input::Timeout);
                }
            }
            Due::Wake { node } => self.wake(node),
            Due::Action(action) => self.apply(action),
        }
    }

    /// A packet or stream event arrived for `node`. A starved node's receive path holds it for
    /// a while first, in arrival order.
    fn receive(&mut self, node: usize, input: Input<N::Command>) {
        let Some(slot) = self.nodes.get_mut(node) else {
            return;
        };
        let Some(delay) = &slot.starve else {
            self.input(node, input);
            return;
        };
        let at = (self.now + delay.sample(&mut self.rng)).max(slot.rx_free);
        slot.rx_free = at;
        let life = slot.life;
        self.queue.push(at, Due::Received { node, life, input });
    }

    /// Hands `input` to the node now, or queues it while the node is paused or busy.
    fn input(&mut self, node: usize, input: Input<N::Command>) {
        let Some(slot) = self.nodes.get_mut(node) else {
            return;
        };
        if slot.node.is_none() {
            if let Input::Datagram { packet, .. } = input {
                self.rec.drop_packet(self.now, packet, DropReason::NodeDown);
            }
            return;
        }
        if self.now < slot.busy_until || !slot.backlog.is_empty() {
            slot.backlog.push_back(input);
            if !slot.wake_pending {
                slot.wake_pending = true;
                self.queue.push(slot.busy_until, Due::Wake { node });
            }
            return;
        }
        self.process(node, input);
    }

    fn wake(&mut self, node: usize) {
        self.nodes[node].wake_pending = false;
        loop {
            let slot = &mut self.nodes[node];
            if slot.node.is_none() {
                slot.backlog.clear();
                return;
            }
            if self.now < slot.busy_until {
                if !slot.backlog.is_empty() {
                    slot.wake_pending = true;
                    self.queue.push(slot.busy_until, Due::Wake { node });
                }
                return;
            }
            let Some(input) = slot.backlog.pop_front() else {
                return;
            };
            self.process(node, input);
        }
    }

    fn process(&mut self, node: usize, input: Input<N::Command>) {
        let now = self.now;
        let local = now + self.nodes[node].clock;
        match input {
            Input::Datagram {
                from,
                payload,
                packet,
            } => {
                let Some(n) = self.nodes[node].node.as_mut() else {
                    return;
                };
                self.rec.stats.delivered += 1;
                self.rec.push(self.rec.cfg.network, || Record::Deliver {
                    t: now,
                    packet,
                    to: node,
                });
                n.handle_datagram(local, from, &payload);
            }
            Input::Timeout => {
                let Some(n) = self.nodes[node].node.as_mut() else {
                    return;
                };
                if n.poll_timeout().is_none_or(|d| d > local) {
                    return;
                }
                self.rec.stats.timeouts += 1;
                self.rec
                    .push(self.rec.cfg.timers, || Record::Timeout { t: now, node });
                n.handle_timeout(local);
            }
            Input::Command(cmd) => {
                let Some(n) = self.nodes[node].node.as_mut() else {
                    return;
                };
                let id = n.command(local, cmd);
                self.rec.stats.commands += 1;
                self.rec
                    .push(self.rec.cfg.events, || Record::Command { t: now, node, id });
            }
            Input::StreamData { conn, side, bytes } => self.stream_data(node, conn, side, &bytes),
            Input::StreamEnd { conn, side, failed } => self.stream_end(node, conn, side, failed),
        }
        let slot = &mut self.nodes[node];
        if let Some(cost) = &slot.cost {
            slot.busy_until = now + cost.sample(&mut self.rng);
        }
        self.drain(node);
    }

    /// Collects the node's transmits and events, and reschedules its timer.
    fn drain(&mut self, node: usize) {
        let now = self.now;
        let slot = &mut self.nodes[node];
        let Some(n) = slot.node.as_mut() else {
            return;
        };
        let mut transmits = std::mem::take(&mut self.transmit_buf);
        while let Some(t) = n.poll_transmit() {
            transmits.push(t);
        }
        while let Some(e) = n.poll_event() {
            self.rec.event(now, node, &e);
        }
        // The node's deadlines are on its own clock; the queue runs on the shared one.
        let deadline = n.poll_timeout().map(|d| behind(d, slot.clock));
        if deadline != slot.timer {
            slot.timer = deadline;
            slot.timer_gen += 1;
            if let Some(d) = deadline {
                let generation = slot.timer_gen;
                self.queue.push(d.max(now), Due::Timer { node, generation });
            }
        }
        for t in transmits.drain(..) {
            match t {
                Transmit::Datagram { to, payload } => self.send_datagram(node, to, payload),
                Transmit::Connect { conn, to } => self.connect(node, conn, to),
                Transmit::Stream { conn, frame } => self.stream_send(node, conn, frame),
                Transmit::Close { conn } => self.stream_close(node, conn),
            }
        }
        self.transmit_buf = transmits;
    }

    fn send_datagram(&mut self, from: usize, to: SocketAddr, payload: Vec<u8>) {
        let now = self.now;
        let packet = self.net.next_packet;
        self.net.next_packet += 1;
        let target = self.addrs.get(&to).copied();
        self.rec.stats.sent += 1;
        self.rec.push(self.rec.cfg.network, || Record::Send {
            t: now,
            packet,
            from,
            to: target,
            len: payload.len(),
            hash: fnv1a(&payload),
        });
        if payload.len() > MAX_UDP {
            return self.rec.drop_packet(now, packet, DropReason::TooLarge);
        }
        let Some(target) = target else {
            return self.rec.drop_packet(now, packet, DropReason::NoRoute);
        };
        if self.net.blocked(from, target) {
            return self.rec.drop_packet(now, packet, DropReason::Partition);
        }
        let link = self.net.link(from, target);
        if self.rng.chance(link.loss) {
            return self.rec.drop_packet(now, packet, DropReason::Loss);
        }
        let delay = datagram_delay(link, &mut self.rng);
        let duplicate = self
            .rng
            .chance(link.duplicate)
            .then(|| datagram_delay(link, &mut self.rng));
        let from = self.specs[from].addr;
        if let Some(delay) = duplicate {
            self.rec.stats.duplicated += 1;
            self.rec.push(self.rec.cfg.network, || Record::Duplicate {
                t: now,
                packet,
            });
            let input = Input::Datagram {
                from,
                payload: payload.clone(),
                packet,
            };
            self.queue.push(
                now + delay,
                Due::Input {
                    node: target,
                    input,
                },
            );
        }
        let input = Input::Datagram {
            from,
            payload,
            packet,
        };
        self.queue.push(
            now + delay,
            Due::Input {
                node: target,
                input,
            },
        );
    }

    fn connect(&mut self, from: usize, id: StreamId, to: SocketAddr) {
        let now = self.now;
        let target = self.addrs.get(&to).copied();
        self.rec.push(self.rec.cfg.streams, || Record::Connect {
            t: now,
            node: from,
            conn: id,
            to: target,
        });
        if self.conns.ids.contains_key(&(from, id)) {
            return;
        }
        let reachable = target.filter(|&t| {
            self.nodes[t].node.is_some() && !self.net.blocked(from, t) && !self.net.blocked(t, from)
        });
        let conn = self.conns.next;
        self.conns.next += 1;
        self.conns.ids.insert((from, id), conn);
        let opener = Some(End {
            node: from,
            id,
            known: true,
            open: true,
        });
        let max = self.net.max_stream_frame;
        let readers = [FrameReader::new(max), FrameReader::new(max)];
        let acceptor = reachable.map(|t| {
            let slot = &mut self.nodes[t];
            let id = StreamId::inbound(slot.next_inbound);
            slot.next_inbound += 1;
            self.conns.ids.insert((t, id), conn);
            End {
                node: t,
                id,
                known: false,
                open: true,
            }
        });
        let failed = acceptor.is_none();
        self.conns.map.insert(
            conn,
            Conn {
                ends: [opener, acceptor],
                readers,
                last: [now; 2],
                failed,
            },
        );
        if failed {
            self.fail_conn(conn);
        }
    }

    fn stream_send(&mut self, from: usize, id: StreamId, bytes: Vec<u8>) {
        let now = self.now;
        let Some(&conn) = self.conns.ids.get(&(from, id)) else {
            return;
        };
        let Some(c) = self.conns.map.get_mut(&conn) else {
            return;
        };
        if c.failed {
            return;
        }
        let peer = 1 - c.side_of(from, id);
        let Some(end) = c.ends[peer] else {
            return;
        };
        if !end.open {
            return;
        }
        if self.net.blocked(from, end.node) || self.nodes[end.node].node.is_none() {
            return self.fail_conn(conn);
        }
        self.rec.push(self.rec.cfg.streams, || Record::StreamSend {
            t: now,
            node: from,
            conn: id,
            len: bytes.len(),
            hash: fnv1a(&bytes),
        });
        let latency = self.net.link(from, end.node).latency.sample(&mut self.rng);
        let at = (now + latency).max(c.last[peer]);
        c.last[peer] = at;
        let input = Input::StreamData {
            conn,
            side: peer,
            bytes,
        };
        self.queue.push(
            at,
            Due::Input {
                node: end.node,
                input,
            },
        );
    }

    fn stream_close(&mut self, from: usize, id: StreamId) {
        let now = self.now;
        let Some(conn) = self.conns.ids.remove(&(from, id)) else {
            return;
        };
        self.rec.push(self.rec.cfg.streams, || Record::StreamClose {
            t: now,
            node: from,
            conn: id,
        });
        let Some(c) = self.conns.map.get_mut(&conn) else {
            return;
        };
        let side = c.side_of(from, id);
        if let Some(end) = c.ends[side].as_mut() {
            end.open = false;
        }
        let peer = c.ends[1 - side].filter(|e| e.open);
        match peer {
            Some(end) if !c.failed => {
                let latency = self.net.link(from, end.node).latency.sample(&mut self.rng);
                let at = (now + latency).max(c.last[1 - side]);
                c.last[1 - side] = at;
                let input = Input::StreamEnd {
                    conn,
                    side: 1 - side,
                    failed: false,
                };
                self.queue.push(
                    at,
                    Due::Input {
                        node: end.node,
                        input,
                    },
                );
            }
            _ => {
                if c.finished() {
                    self.conns.map.remove(&conn);
                }
            }
        }
    }

    /// Fails the connection: each open end hears `Failed` after the connect timeout.
    fn fail_conn(&mut self, conn: u64) {
        let Some(c) = self.conns.map.get_mut(&conn) else {
            return;
        };
        c.failed = true;
        self.rec.stats.stream_failures += 1;
        let at = self.now + self.net.connect_timeout;
        for (side, end) in c.ends.iter().enumerate() {
            if let Some(end) = end.filter(|e| e.open) {
                let input = Input::StreamEnd {
                    conn,
                    side,
                    failed: true,
                };
                self.queue.push(
                    at,
                    Due::Input {
                        node: end.node,
                        input,
                    },
                );
            }
        }
    }

    fn stream_data(&mut self, node: usize, conn: u64, side: usize, bytes: &[u8]) {
        let now = self.now;
        let Some(c) = self.conns.map.get_mut(&conn) else {
            return;
        };
        let Some(end) = c.ends[side].as_mut() else {
            return;
        };
        if !end.open || c.failed {
            return;
        }
        let reader = &mut c.readers[side];
        reader.push(bytes);
        let mut frames = Vec::new();
        let framing_failed = loop {
            match reader.next_frame() {
                Ok(Some(frame)) => frames.push(frame),
                Ok(None) => break false,
                Err(_) => break true,
            }
        };
        if !frames.is_empty() {
            end.known = true;
        }
        let id = end.id;
        let slot = &mut self.nodes[node];
        let local = now + slot.clock;
        let Some(n) = slot.node.as_mut() else {
            return;
        };
        for frame in &frames {
            self.rec.stats.stream_frames += 1;
            self.rec.push(self.rec.cfg.streams, || Record::StreamFrame {
                t: now,
                node,
                conn: id,
                len: frame.len(),
                hash: fnv1a(frame),
            });
            n.handle_stream(local, id, StreamEvent::Frame(frame));
        }
        if framing_failed {
            self.fail_conn(conn);
        }
    }

    fn stream_end(&mut self, node: usize, conn: u64, side: usize, failed: bool) {
        let now = self.now;
        let Some(c) = self.conns.map.get_mut(&conn) else {
            return;
        };
        let Some(end) = c.ends[side].as_mut() else {
            return;
        };
        let was_open = end.open;
        end.open = false;
        let (id, known) = (end.id, end.known);
        if c.finished() {
            self.conns.map.remove(&conn);
        }
        if !was_open {
            return;
        }
        self.conns.ids.remove(&(node, id));
        if !known {
            return;
        }
        let slot = &mut self.nodes[node];
        let local = now + slot.clock;
        let Some(n) = slot.node.as_mut() else {
            return;
        };
        if failed {
            self.rec
                .push(self.rec.cfg.streams, || Record::StreamFailed {
                    t: now,
                    node,
                    conn: id,
                });
            n.handle_stream(local, id, StreamEvent::Failed);
        } else {
            self.rec
                .push(self.rec.cfg.streams, || Record::StreamClosed {
                    t: now,
                    node,
                    conn: id,
                });
            n.handle_stream(local, id, StreamEvent::Closed);
        }
    }

    fn crash(&mut self, node: usize) {
        let Some(slot) = self.nodes.get_mut(node) else {
            return;
        };
        slot.node = None;
        slot.backlog.clear();
        slot.timer = None;
        slot.timer_gen += 1;
        slot.busy_until = self.now;
        slot.life += 1;
        slot.rx_free = self.now;
        // The crashed node's connections fail at the other end.
        let mut affected = Vec::new();
        for (&conn, c) in &mut self.conns.map {
            let mut hit = false;
            for end in c.ends.iter_mut().flatten() {
                if end.node == node && end.open {
                    end.open = false;
                    self.conns.ids.remove(&(node, end.id));
                    hit = true;
                }
            }
            if hit {
                affected.push(conn);
            }
        }
        for conn in affected {
            self.fail_conn(conn);
            if self.conns.map.get(&conn).is_some_and(Conn::finished) {
                self.conns.map.remove(&conn);
            }
        }
    }

    fn restart(&mut self, node: usize) {
        if node >= self.nodes.len() {
            return;
        }
        if self.nodes[node].node.is_some() {
            self.crash(node);
        }
        let spec = &mut self.specs[node];
        spec.seed = self.rng.next_u64();
        spec.now = self.now;
        let fresh = (self.factory)(spec);
        let slot = &mut self.nodes[node];
        slot.node = Some(fresh);
        slot.busy_until = self.now;
        // A new process starts on the shared clock.
        slot.clock = Duration::ZERO;
        self.drain(node);
    }
}

/// `t` moved back by `by`, as an instant on the shared clock of a node running `by` ahead.
fn behind(t: Instant, by: Duration) -> Instant {
    let by = u64::try_from(by.as_nanos()).unwrap_or(u64::MAX);
    Instant::from_nanos(t.as_nanos().saturating_sub(by))
}

fn datagram_delay(link: &LinkConfig, rng: &mut Rng) -> Duration {
    let mut delay = link.latency.sample(rng);
    if rng.chance(link.reorder) {
        delay += link.reorder_delay.sample(rng);
    }
    delay
}

impl<N: SimNode> std::fmt::Debug for Sim<N> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Sim")
            .field("now", &self.now)
            .field("end", &self.end)
            .field("nodes", &self.nodes.len())
            .field("stats", &self.rec.stats)
            .finish_non_exhaustive()
    }
}
