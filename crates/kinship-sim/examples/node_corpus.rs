//! Captures the seed corpus of the `node_input` fuzz target in `crates/kinship-core/fuzz`: real
//! traffic that node n0 receives in a simulated four-node cluster, once encrypted and once in
//! plaintext, written in the fuzz target's input format.
//!
//! ```text
//! cargo run -p kinship-sim --example node_corpus
//! ```
//!
//! It replaces every file in `crates/kinship-core/fuzz/corpus/node_input`. The run is seeded, so
//! the files only change when the protocol does.

use std::cell::RefCell;
use std::net::SocketAddr;
use std::path::Path;
use std::rc::Rc;
use std::time::Duration;

use kinship_core::{
    Command, CommandId, Config, Event, Identity, Instant, Key, Node, Security, StreamEvent,
    StreamId, Transmit,
};
use kinship_sim::{Action, LinkConfig, NodeSpec, Scenario, Sim, SimNode, TraceConfig, addr_of};

/// Small inputs run fast, and each still holds a few packets.
const FILE_BYTES: usize = 512;

/// Files kept per mode: every one with stream traffic, and evenly spaced others up to this.
const FILES_PER_MODE: usize = 32;

/// One operation of the fuzz target's input format; see `node_input.rs`.
enum Op {
    Datagram(Vec<u8>),
    Frame(u8, Vec<u8>),
    Closed(u8),
    Failed(u8),
    /// This many 100 ms steps pass, at most 31.
    Wait(u8),
}

impl Op {
    fn encode(&self, out: &mut Vec<u8>) {
        let with_body = |out: &mut Vec<u8>, code: u8, bytes: &[u8]| {
            out.push(code);
            out.extend_from_slice(&u16::try_from(bytes.len()).unwrap().to_be_bytes());
            out.extend_from_slice(bytes);
        };
        match self {
            Op::Datagram(b) => with_body(out, 0, b),
            Op::Frame(s, b) => with_body(out, (s << 3) | 1, b),
            Op::Closed(s) => out.push((s << 3) | 2),
            Op::Failed(s) => out.push((s << 3) | 3),
            Op::Wait(n) => out.push((n << 3) | 4),
        }
    }

    fn is_stream(&self) -> bool {
        matches!(self, Op::Frame(..) | Op::Closed(_) | Op::Failed(_))
    }
}

/// A core node that, for node 0, records every packet and stream event it is handed.
struct Recorder {
    node: Node,
    ops: Option<Rc<RefCell<Vec<Op>>>>,
    /// When the last recorded input arrived.
    last: Instant,
}

impl Recorder {
    fn record(&mut self, now: Instant, op: impl FnOnce() -> Op) {
        let Some(ops) = &self.ops else {
            return;
        };
        let mut ops = ops.borrow_mut();
        let mut steps = (now - self.last).as_millis() / 100;
        self.last = self.last + Duration::from_millis(100) * u32::try_from(steps).unwrap();
        while steps > 0 {
            let n = steps.min(31);
            ops.push(Op::Wait(u8::try_from(n).unwrap()));
            steps -= n;
        }
        ops.push(op());
    }
}

/// The fuzz target's stream argument: inbound connections below 16, and the node's own
/// outbound ones folded onto the two its join opens, so their replies reach a live exchange.
fn stream(id: StreamId) -> u8 {
    let i = u8::try_from(id.index() % 16).unwrap();
    if id.is_inbound() { i } else { 16 + i % 2 }
}

impl SimNode for Recorder {
    type Command = Command;
    type Event = Event;

    fn handle_datagram(&mut self, now: Instant, from: SocketAddr, buf: &[u8]) {
        self.record(now, || Op::Datagram(buf.to_vec()));
        self.node.handle_datagram(now, from, buf);
    }

    fn handle_stream(&mut self, now: Instant, conn: StreamId, ev: StreamEvent<'_>) {
        let s = stream(conn);
        self.record(now, || match ev {
            StreamEvent::Frame(f) => Op::Frame(s, f.to_vec()),
            StreamEvent::Closed => Op::Closed(s),
            StreamEvent::Failed => Op::Failed(s),
        });
        self.node.handle_stream(now, conn, ev);
    }

    fn handle_timeout(&mut self, now: Instant) {
        self.node.handle_timeout(now);
    }

    fn command(&mut self, now: Instant, cmd: Command) -> CommandId {
        self.node.command(now, cmd)
    }

    fn poll_transmit(&mut self) -> Option<Transmit> {
        self.node.poll_transmit()
    }

    fn poll_event(&mut self) -> Option<Event> {
        self.node.poll_event()
    }

    fn poll_timeout(&self) -> Option<Instant> {
        self.node.poll_timeout()
    }
}

/// Everything node 0 received in a run with `security`.
fn capture(security: &Security) -> Vec<Op> {
    let secs = Duration::from_secs;
    let join = |node: usize, seeds: &[usize]| Action::Command {
        node,
        cmd: Command::Join {
            seeds: seeds.iter().map(|&s| addr_of(s)).collect(),
        },
    };
    // Gossip with metadata, a crash with its suspicion, indirect probes and death, a restart
    // that joins through n0, and a leave.
    let scenario = Scenario::new(4)
        .duration(secs(60))
        .link(LinkConfig::lan().with_loss(0.02))
        .trace(TraceConfig::OFF)
        .at(Duration::ZERO, join(0, &[1, 2]))
        .at(
            secs(3),
            Action::Command {
                node: 2,
                cmd: Command::SetMeta(b"role=db".to_vec()),
            },
        )
        .at(secs(5), Action::Crash(3))
        .at(secs(40), Action::Restart(3))
        .at(secs(40), join(3, &[0]))
        .at(
            secs(50),
            Action::Command {
                node: 1,
                cmd: Command::Leave,
            },
        );
    let ops = Rc::new(RefCell::new(Vec::new()));
    let recorded = Rc::clone(&ops);
    let security = security.clone();
    let mut sim = Sim::new(7, scenario, move |spec: &NodeSpec| {
        let me = Identity::new(spec.name.clone(), spec.addr).unwrap();
        let cfg = Config::lan(security.clone());
        let mut node = Node::new(cfg, me, spec.now, spec.seed).unwrap();
        // A restarted node knows nobody until it joins.
        if spec.now == Instant::ZERO {
            for j in (0..spec.nodes).filter(|&j| j != spec.index) {
                node.add_member(spec.now, &format!("n{j}"), addr_of(j))
                    .unwrap();
            }
        }
        Recorder {
            node,
            ops: (spec.index == 0).then(|| Rc::clone(&recorded)),
            last: spec.now,
        }
    });
    sim.run();
    drop(sim);
    Rc::try_unwrap(ops).ok().unwrap().into_inner()
}

/// Splits `ops` into inputs of at most [`FILE_BYTES`], each starting with `mode`.
fn inputs(mode: u8, ops: &[Op]) -> Vec<(Vec<u8>, bool)> {
    let mut files = Vec::new();
    let mut cur = vec![mode];
    let mut streams = false;
    for op in ops {
        let mut bytes = Vec::new();
        op.encode(&mut bytes);
        if cur.len() > 1 && cur.len() + bytes.len() > FILE_BYTES {
            files.push((std::mem::replace(&mut cur, vec![mode]), streams));
            streams = false;
        }
        cur.extend_from_slice(&bytes);
        streams |= op.is_stream();
    }
    if cur.len() > 1 {
        files.push((cur, streams));
    }
    files
}

/// Every input with stream traffic, then evenly spaced others, up to [`FILES_PER_MODE`].
fn keep(all: Vec<(Vec<u8>, bool)>) -> Vec<Vec<u8>> {
    let with_streams = all.iter().filter(|f| f.1).count();
    let room = FILES_PER_MODE.saturating_sub(with_streams).max(1);
    let others = all.len() - with_streams;
    let every = others.div_ceil(room).max(1);
    let mut nth = 0;
    all.into_iter()
        .filter_map(|(bytes, streams)| {
            if streams {
                return Some(bytes);
            }
            nth += 1;
            ((nth - 1) % every == 0).then_some(bytes)
        })
        .collect()
}

fn main() -> std::io::Result<()> {
    let dir = Path::new(env!("CARGO_MANIFEST_DIR")).join("../kinship-core/fuzz/corpus/node_input");
    if dir.exists() {
        std::fs::remove_dir_all(&dir)?;
    }
    std::fs::create_dir_all(&dir)?;
    let modes = [
        (
            "encrypted",
            1,
            Security::Keys(vec![Key::from_bytes([7; 32])]),
        ),
        ("plaintext", 0, Security::InsecurePlaintext),
    ];
    for (label, mode, security) in modes {
        let ops = capture(&security);
        let files = keep(inputs(mode, &ops));
        for (i, bytes) in files.iter().enumerate() {
            std::fs::write(dir.join(format!("{label}-{i:02}")), bytes)?;
        }
        println!(
            "{label}: {} inputs from {} operations",
            files.len(),
            ops.len()
        );
    }
    Ok(())
}
