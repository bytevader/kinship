//! Lifeguard against plain SWIM: false positives and detection latency with CPU-starved nodes
//! under uniform packet loss.
//!
//! Every cell of the grid (cluster size x packet loss x share of starved nodes) runs the same
//! seeds twice, once with `Config::lan()` and once with `Config::lan().without_lifeguard()`, so
//! the two arms see the same starved nodes, the same crash and the same network draws until
//! their protocols diverge. Starved nodes read every packet late while their timers fire on
//! time ([`Action::Starve`]), as in the Lifeguard paper's slow-node experiments. Halfway in,
//! one healthy node crashes, to measure detection latency.
//!
//! ```text
//! cargo run --release -p kinship-sim --example lifeguard -- --seeds 200 --out docs/results
//! ```
//!
//! Writes `lifeguard.csv` into the output directory and prints a markdown table, SWIM first and
//! Lifeguard second in each cell, for `docs/results/lifeguard.md`.

use std::cell::RefCell;
use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::rc::Rc;
use std::sync::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use kinship_core::{
    Command, CommandId, Config, Event, Identity, Instant, Node, Rng, Security, StreamEvent,
    StreamId, Transmit,
};
use kinship_sim::{Action, Delay, LinkConfig, NodeSpec, Scenario, Sim, SimNode, TraceConfig};
use kinship_sim::{addr_of, name_of};

const NODES: [usize; 2] = [50, 200];
const LOSSES: [f64; 3] = [0.01, 0.03, 0.05];
const STARVED: [f64; 3] = [0.01, 0.05, 0.10];

const DURATION: Duration = Duration::from_secs(150);
const CRASH_AT: Duration = Duration::from_secs(60);

/// How late a starved node reads each packet: long enough that its Acks often miss the probe
/// round of whoever pinged it, and that it often reads its own Acks after its round ended.
fn starve_delay() -> Delay {
    Delay::Uniform {
        min: Duration::from_millis(500),
        max: Duration::from_millis(2500),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arm {
    Swim,
    Lifeguard,
}

impl Arm {
    fn name(self) -> &'static str {
        match self {
            Arm::Swim => "swim",
            Arm::Lifeguard => "lifeguard",
        }
    }

    fn config(self) -> Config {
        // Plaintext keeps the sweep fast; sealing does not change what the protocol does.
        let cfg = Config::lan(Security::InsecurePlaintext);
        match self {
            Arm::Swim => cfg.without_lifeguard(),
            Arm::Lifeguard => cfg,
        }
    }
}

#[derive(Debug, Clone, Copy)]
struct Cell {
    nodes: usize,
    loss: f64,
    starved: f64,
}

impl Cell {
    fn starved_nodes(&self) -> usize {
        ((self.nodes as f64 * self.starved).round() as usize).max(1)
    }
}

type Log = Rc<RefCell<Vec<(Instant, usize, Event)>>>;

/// A core node that knows every other node from the start and logs its events.
struct Logged {
    node: Node,
    index: usize,
    now: Instant,
    log: Log,
}

impl SimNode for Logged {
    type Command = Command;
    type Event = Event;

    fn handle_datagram(&mut self, now: Instant, from: SocketAddr, buf: &[u8]) {
        self.now = now;
        self.node.handle_datagram(now, from, buf);
    }

    fn handle_stream(&mut self, now: Instant, conn: StreamId, ev: StreamEvent<'_>) {
        self.now = now;
        self.node.handle_stream(now, conn, ev);
    }

    fn handle_timeout(&mut self, now: Instant) {
        self.now = now;
        self.node.handle_timeout(now);
    }

    fn command(&mut self, now: Instant, cmd: Command) -> CommandId {
        self.now = now;
        self.node.command(now, cmd)
    }

    fn poll_transmit(&mut self) -> Option<Transmit> {
        self.node.poll_transmit()
    }

    fn poll_event(&mut self) -> Option<Event> {
        let event = self.node.poll_event()?;
        self.log
            .borrow_mut()
            .push((self.now, self.index, event.clone()));
        Some(event)
    }

    fn poll_timeout(&self) -> Option<Instant> {
        self.node.poll_timeout()
    }
}

/// What one run measured.
///
/// A false death is a running member declared dead at some incarnation by at least one node;
/// the Dead rumour then spreads to everyone, so counting it once per observer would only scale
/// it by the cluster size. False suspicions are counted the same way.
#[derive(Debug, Default)]
struct Run {
    /// False deaths of healthy members.
    false_deaths: u64,
    /// False deaths of starved members.
    starved_deaths: u64,
    false_suspicions: u64,
    /// Time from the crash to each healthy observer declaring it dead.
    detections: Vec<Duration>,
    /// Healthy observers that never declared the crashed node dead.
    undetected: u64,
}

fn index_of(name: &str) -> usize {
    name[1..].parse().expect("simulator names are n<index>")
}

fn run(cell: Cell, arm: Arm, seed: u64) -> Run {
    let n = cell.nodes;
    let mut rng = Rng::new(seed ^ 0x4c49_4645_4755_4152);
    let mut order: Vec<usize> = (0..n).collect();
    rng.shuffle(&mut order);
    let k = cell.starved_nodes();
    let starved: BTreeSet<usize> = order[..k].iter().copied().collect();
    let crashed = order[k];

    let mut scenario = Scenario::new(n)
        .duration(DURATION)
        .link(LinkConfig::lan().with_loss(cell.loss))
        .trace(TraceConfig::OFF)
        .at(CRASH_AT, Action::Crash(crashed));
    for &s in &starved {
        scenario = scenario.starved_node(s, starve_delay());
    }

    let log: Log = Rc::default();
    let factory_log = log.clone();
    let cfg = arm.config();
    let mut sim = Sim::new(seed, scenario, move |spec: &NodeSpec| {
        let me = Identity::new(spec.name.clone(), spec.addr).expect("valid name");
        let mut node = Node::new(cfg.clone(), me, spec.now, spec.seed).expect("valid config");
        for j in (0..spec.nodes).filter(|&j| j != spec.index) {
            node.add_member(spec.now, &name_of(j), addr_of(j))
                .expect("valid name");
        }
        while node.poll_event().is_some() {}
        Logged {
            node,
            index: spec.index,
            now: spec.now,
            log: factory_log.clone(),
        }
    });
    sim.run();

    let crash = Instant::ZERO + CRASH_AT;
    let running = |j: usize, t: Instant| j != crashed || t < crash;
    let mut out = Run::default();
    let mut detected = vec![None; n];
    let (mut suspected, mut dead) = (BTreeSet::new(), BTreeSet::new());
    for (t, observer, event) in log.borrow().iter() {
        match event {
            Event::MemberSuspect(m) if running(index_of(&m.name), *t) => {
                suspected.insert((index_of(&m.name), m.incarnation));
            }
            Event::MemberDead(m) => {
                let j = index_of(&m.name);
                if running(j, *t) {
                    dead.insert((j, m.incarnation));
                } else if detected[*observer].is_none() {
                    detected[*observer] = Some(*t - crash);
                }
            }
            _ => {}
        }
    }
    out.false_suspicions = suspected.len() as u64;
    for (j, _) in dead {
        if starved.contains(&j) {
            out.starved_deaths += 1;
        } else {
            out.false_deaths += 1;
        }
    }
    for o in (0..n).filter(|o| *o != crashed && !starved.contains(o)) {
        match detected[o] {
            Some(d) => out.detections.push(d),
            None => out.undetected += 1,
        }
    }
    out
}

/// Totals of one cell and arm.
#[derive(Debug, Default)]
struct Totals {
    runs: u64,
    false_deaths: u64,
    starved_deaths: u64,
    runs_with_false_death: u64,
    false_suspicions: u64,
    detections: Vec<Duration>,
    undetected: u64,
}

impl Totals {
    fn add(&mut self, r: Run) {
        self.runs += 1;
        self.false_deaths += r.false_deaths;
        self.starved_deaths += r.starved_deaths;
        self.runs_with_false_death += u64::from(r.false_deaths + r.starved_deaths > 0);
        self.false_suspicions += r.false_suspicions;
        self.detections.extend(r.detections);
        self.undetected += r.undetected;
    }

    fn per_run(&self, x: u64) -> f64 {
        x as f64 / self.runs.max(1) as f64
    }

    /// False deaths of any member, starved or healthy, per run.
    fn deaths_per_run(&self) -> f64 {
        self.per_run(self.false_deaths + self.starved_deaths)
    }

    fn detection(&mut self, pct: usize) -> f64 {
        self.detections.sort_unstable();
        let d = &self.detections;
        if d.is_empty() {
            return f64::NAN;
        }
        d[(d.len() * pct / 100).min(d.len() - 1)].as_secs_f64()
    }

    fn detection_mean(&self) -> f64 {
        let d = &self.detections;
        d.iter().map(Duration::as_secs_f64).sum::<f64>() / d.len().max(1) as f64
    }
}

struct Args {
    seeds: u64,
    out: PathBuf,
    nodes: Vec<usize>,
}

fn args() -> Args {
    let mut a = Args {
        seeds: 200,
        out: PathBuf::from("docs/results"),
        nodes: NODES.to_vec(),
    };
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let value = it.next().unwrap_or_else(|| panic!("{flag} needs a value"));
        match flag.as_str() {
            "--seeds" => a.seeds = value.parse().expect("--seeds takes a number"),
            "--out" => a.out = PathBuf::from(value),
            "--nodes" => {
                a.nodes = value
                    .split(',')
                    .map(|v| v.parse().expect("--nodes takes a comma list"))
                    .collect();
            }
            _ => panic!("unknown flag {flag}; use --seeds, --out or --nodes"),
        }
    }
    a
}

fn main() {
    let args = args();
    let mut cells = Vec::new();
    for &nodes in &args.nodes {
        for &loss in &LOSSES {
            for &starved in &STARVED {
                cells.push(Cell {
                    nodes,
                    loss,
                    starved,
                });
            }
        }
    }
    let arms = [Arm::Swim, Arm::Lifeguard];
    let jobs: Vec<(usize, usize, u64)> = (0..cells.len())
        .flat_map(|c| (0..arms.len()).flat_map(move |a| (0..args.seeds).map(move |s| (c, a, s))))
        .collect();
    let totals: Mutex<Vec<Totals>> = Mutex::new(
        (0..cells.len() * arms.len())
            .map(|_| Totals::default())
            .collect(),
    );
    let next = AtomicUsize::new(0);
    let started = std::time::Instant::now();
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| {
                loop {
                    let i = next.fetch_add(1, Ordering::Relaxed);
                    let Some(&(c, a, seed)) = jobs.get(i) else {
                        break;
                    };
                    let r = run(cells[c], arms[a], seed);
                    totals.lock().expect("no panics")[c * arms.len() + a].add(r);
                    if (i + 1) % 500 == 0 {
                        eprintln!("{} of {} runs, {:?}", i + 1, jobs.len(), started.elapsed());
                    }
                }
            });
        }
    });
    let mut totals = totals.into_inner().expect("no panics");
    eprintln!("{} runs in {:?}", jobs.len(), started.elapsed());

    let mut csv = String::from(concat!(
        "nodes,loss,starved_share,starved_nodes,arm,runs,healthy_false_deaths,",
        "starved_false_deaths,runs_with_false_death,false_deaths_per_run,",
        "false_suspicions_per_run,detection_mean_s,detection_p50_s,detection_p99_s,undetected\n",
    ));
    for (c, cell) in cells.iter().enumerate() {
        for (a, arm) in arms.iter().enumerate() {
            let t = &mut totals[c * arms.len() + a];
            let (p50, p99) = (t.detection(50), t.detection(99));
            writeln!(
                csv,
                "{},{},{},{},{},{},{},{},{},{:.4},{:.2},{:.3},{:.3},{:.3},{}",
                cell.nodes,
                cell.loss,
                cell.starved,
                cell.starved_nodes(),
                arm.name(),
                t.runs,
                t.false_deaths,
                t.starved_deaths,
                t.runs_with_false_death,
                t.deaths_per_run(),
                t.per_run(t.false_suspicions),
                t.detection_mean(),
                p50,
                p99,
                t.undetected
            )
            .expect("writing to a String");
        }
    }

    let mut md = String::from(concat!(
        "| Nodes | Loss | Starved | False deaths per run | of healthy members | ",
        "False suspicions per run | Detection p50 (s) | Detection p99 (s) |\n",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n",
    ));
    let mut wins = 0;
    for (c, cell) in cells.iter().enumerate() {
        let i = c * arms.len();
        let (swim_fd, lg_fd) = (totals[i].deaths_per_run(), totals[i + 1].deaths_per_run());
        wins += usize::from(lg_fd < swim_fd);
        let healthy = (
            totals[i].per_run(totals[i].false_deaths),
            totals[i + 1].per_run(totals[i + 1].false_deaths),
        );
        let fs = (
            totals[i].per_run(totals[i].false_suspicions),
            totals[i + 1].per_run(totals[i + 1].false_suspicions),
        );
        let p50 = (totals[i].detection(50), totals[i + 1].detection(50));
        let p99 = (totals[i].detection(99), totals[i + 1].detection(99));
        writeln!(
            md,
            "| {} | {:.0}% | {} ({:.0}%) | {:.2} / {:.2} | {:.2} / {:.2} | {:.1} / {:.1} | {:.1} / {:.1} | {:.1} / {:.1} |",
            cell.nodes,
            cell.loss * 100.0,
            cell.starved_nodes(),
            cell.starved * 100.0,
            swim_fd,
            lg_fd,
            healthy.0,
            healthy.1,
            fs.0,
            fs.1,
            p50.0,
            p50.1,
            p99.0,
            p99.1,
        )
        .expect("writing to a String");
    }
    writeln!(
        md,
        "\nLifeguard had fewer false deaths per run than SWIM in {wins} of {} cells.",
        cells.len()
    )
    .expect("writing to a String");

    std::fs::create_dir_all(&args.out).expect("create the output directory");
    std::fs::write(args.out.join("lifeguard.csv"), csv).expect("write lifeguard.csv");
    print!("{md}");
}
