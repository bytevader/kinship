//! Tuning the timing presets: crash detection latency, false positives and bandwidth of
//! `lan()` and of variants that change its timing fields, under uniform packet loss and
//! CPU-starved nodes.
//!
//! The grid is the Lifeguard grid of `tests/lifeguard.rs` (starved nodes read every packet 0.5
//! to 2.5 s late, one healthy node crashes halfway in) with lossless cells added and 1,000-node
//! clusters. Every variant of a cell runs the same seeds, so each sees the same starved nodes
//! and the same crash.
//!
//! A variant is `lan` or a space-separated list of field changes, such as
//! `suspicion_mult=3 suspicion_max_mult=8`; durations are in milliseconds with an `ms` suffix.
//! Two ignored sweeps append to `docs/results/tuning.csv`, one row per cell and variant, as
//! soon as a cell finishes, and skip rows already there, so an interrupted sweep resumes:
//!
//! - `screen`: one field at a time, and the combinations that pointed to, at 50, 200 and
//!   1,000 nodes (see [`screen`] for the cells and seeds).
//! - `grid`: `lan` and the candidates the screen left, every cell at 50, 200 and 1,000 nodes.
//!
//! `cargo test --release -p kinship-sim --test tuning -- --ignored --nocapture --exact screen`,
//! then `grid`, then `verdict`, which applies the rule in [`verdict_table`] to the CSV.
//! `KINSHIP_SEEDS` sets the seeds per cell, `KINSHIP_NODES` runs one cluster size, and
//! `KINSHIP_VARIANTS` (variants separated by `;`) replaces the variant list. The state of the
//! tuning and what is left to run are in `docs/results/tuning.md`.

mod common;

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::fmt::Write as _;
use std::net::SocketAddr;
use std::path::PathBuf;
use std::rc::Rc;
use std::time::Duration;

use common::{check_all, index_of, ms, secs};
use kinship_core::{
    Command, CommandId, Config, Event, Identity, Instant, Key, Node, Rng, Security, StreamEvent,
    StreamId, Transmit,
};
use kinship_sim::{
    Action, Delay, LinkConfig, Scenario, Sim, SimNode, TraceConfig, addr_of, name_of,
};

const LOSSES: [f64; 4] = [0.0, 0.01, 0.03, 0.05];
const STARVED: [f64; 4] = [0.0, 0.01, 0.05, 0.10];

const DURATION: Duration = Duration::from_secs(120);
const CRASH_AT: Duration = Duration::from_secs(60);

/// One field of `lan()` moved at a time, in both directions where both are plausible.
const SCREEN: &[&str] = &[
    "lan",
    "probe_interval=500ms probe_timeout=250ms",
    "probe_interval=750ms probe_timeout=375ms",
    "probe_interval=1500ms probe_timeout=750ms",
    "probe_timeout=250ms",
    "probe_timeout=750ms",
    "suspicion_mult=2",
    "suspicion_mult=3",
    "suspicion_mult=5",
    "suspicion_max_mult=4",
    "suspicion_max_mult=8",
    "expected_confirmations=2",
    "expected_confirmations=5",
    "gossip_interval=100ms",
    "gossip_interval=400ms",
    "gossip_nodes=2",
    "gossip_nodes=5",
    "retransmit_mult=2",
    "retransmit_mult=6",
    // The shorter timeout of suspicion_mult=3, with the retransmits that removed every false
    // death at 50 nodes to win back the refutations it loses.
    "suspicion_mult=3 retransmit_mult=5",
    "suspicion_mult=3 retransmit_mult=6",
];

/// `lan()` and the combinations the screen pointed to.
const GRID: &[&str] = &["lan"];

/// Builds a variant's config from `lan()`. Sealed, as production runs, so packet sizes are the
/// real ones.
fn config(variant: &str) -> Config {
    let mut cfg = Config::lan(Security::Keys(vec![Key::from_bytes([7; 32])]));
    if variant == "lan" {
        return cfg;
    }
    for change in variant.split(' ') {
        let (field, value) = change
            .split_once('=')
            .unwrap_or_else(|| panic!("{variant}: {change} is not field=value"));
        let millis = || {
            let v = value
                .strip_suffix("ms")
                .unwrap_or_else(|| panic!("{change}: want ms"));
            ms(v.parse().unwrap())
        };
        let int = || -> u32 { value.parse().unwrap_or_else(|_| panic!("{change}")) };
        match field {
            "probe_interval" => cfg.probe_interval = millis(),
            "probe_timeout" => cfg.probe_timeout = millis(),
            "gossip_interval" => cfg.gossip_interval = millis(),
            "suspicion_mult" => cfg.suspicion_mult = int(),
            "suspicion_max_mult" => cfg.suspicion_max_mult = int(),
            "expected_confirmations" => cfg.expected_confirmations = int(),
            "retransmit_mult" => cfg.retransmit_mult = int(),
            "gossip_nodes" => cfg.gossip_nodes = int() as usize,
            _ => panic!("{variant}: unknown field {field}"),
        }
    }
    cfg.validate().unwrap_or_else(|e| panic!("{variant}: {e}"));
    cfg
}

/// How late a starved node reads each packet, as in `tests/lifeguard.rs`.
fn starve_delay() -> Delay {
    Delay::Uniform {
        min: ms(500),
        max: ms(2500),
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
        if self.starved == 0.0 {
            return 0;
        }
        ((self.nodes as f64 * self.starved).round() as usize).max(1)
    }

    fn key(&self) -> String {
        format!("{},{},{}", self.nodes, self.loss, self.starved)
    }
}

/// What one run measured, counted as in `tests/lifeguard.rs`: a false death or suspicion is a
/// running member declared dead or suspect at some incarnation by at least one node.
#[derive(Debug, Default)]
struct Run {
    healthy_deaths: u64,
    starved_deaths: u64,
    false_suspicions: u64,
    /// Time from the crash to each healthy observer declaring it dead.
    detections: Vec<Duration>,
    /// Healthy observers that never declared the crashed node dead.
    undetected: u64,
    udp_bytes: u64,
    tcp_bytes: u64,
}

/// What every node of a run reported, tallied as the events arrive: at 1,000 nodes a log of
/// every event would hold millions of them.
struct Tally {
    crashed: usize,
    crash: Instant,
    /// (member, incarnation) suspected or declared dead while it was running.
    suspected: BTreeSet<(usize, u32)>,
    dead: BTreeSet<(usize, u32)>,
    /// When each observer declared the crashed node dead.
    detected: Vec<Option<Instant>>,
}

impl Tally {
    fn record(&mut self, t: Instant, observer: usize, event: &Event) {
        let (Event::MemberSuspect(m) | Event::MemberDead(m)) = event else {
            return;
        };
        let j = index_of(&m.name);
        let running = j != self.crashed || t < self.crash;
        match event {
            Event::MemberSuspect(_) if running => {
                self.suspected.insert((j, m.incarnation));
            }
            Event::MemberDead(_) if running => {
                self.dead.insert((j, m.incarnation));
            }
            Event::MemberDead(_) => {
                self.detected[observer].get_or_insert(t);
            }
            _ => {}
        }
    }
}

/// A core node that feeds its events into the run's [`Tally`].
struct Counted {
    node: Node,
    index: usize,
    now: Instant,
    tally: Rc<RefCell<Tally>>,
}

impl SimNode for Counted {
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
        self.tally.borrow_mut().record(self.now, self.index, &event);
        Some(event)
    }

    fn poll_timeout(&self) -> Option<Instant> {
        self.node.poll_timeout()
    }
}

fn run(cell: Cell, cfg: &Config, seed: u64) -> Run {
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
    let crash = Instant::ZERO + CRASH_AT;
    let tally = Rc::new(RefCell::new(Tally {
        crashed,
        crash,
        suspected: BTreeSet::new(),
        dead: BTreeSet::new(),
        detected: vec![None; n],
    }));
    let factory_tally = tally.clone();
    let cfg = cfg.clone();
    let mut sim = Sim::new(seed, scenario, move |spec| {
        let me = Identity::new(&spec.name, spec.addr).unwrap();
        let mut node = Node::new(cfg.clone(), me, spec.now, spec.seed).unwrap();
        for j in (0..spec.nodes).filter(|&j| j != spec.index) {
            node.add_member(spec.now, &name_of(j), addr_of(j)).unwrap();
        }
        while node.poll_event().is_some() {}
        Counted {
            node,
            index: spec.index,
            now: spec.now,
            tally: factory_tally.clone(),
        }
    });
    sim.run();

    let tally = tally.borrow();
    let mut out = Run {
        false_suspicions: tally.suspected.len() as u64,
        udp_bytes: sim.stats().sent_bytes,
        tcp_bytes: sim.stats().stream_bytes,
        ..Run::default()
    };
    for &(j, _) in &tally.dead {
        if starved.contains(&j) {
            out.starved_deaths += 1;
        } else {
            out.healthy_deaths += 1;
        }
    }
    for o in (0..n).filter(|o| *o != crashed && !starved.contains(o)) {
        match tally.detected[o] {
            Some(t) => out.detections.push(t - crash),
            None => out.undetected += 1,
        }
    }
    out
}

impl Run {
    /// One line of a worker's output.
    fn to_line(&self, seed: u64) -> String {
        let mut line = format!(
            "run {seed} {} {} {} {} {} {}",
            self.healthy_deaths,
            self.starved_deaths,
            self.false_suspicions,
            self.undetected,
            self.udp_bytes,
            self.tcp_bytes
        );
        for d in &self.detections {
            write!(line, " {}", d.as_nanos()).unwrap();
        }
        line
    }

    fn from_line(line: &str) -> (u64, Self) {
        let mut f = line.split(' ').skip(1).map(|x| x.parse::<u64>().unwrap());
        let mut next = || f.next().unwrap();
        let seed = next();
        let mut run = Self {
            healthy_deaths: next(),
            starved_deaths: next(),
            false_suspicions: next(),
            undetected: next(),
            udp_bytes: next(),
            tcp_bytes: next(),
            detections: Vec::new(),
        };
        run.detections = f.map(Duration::from_nanos).collect();
        (seed, run)
    }
}

/// How long one worker may take before the sweep gives up on it: ten times the slowest run
/// seen while writing this, a 1,000-node cell with 10% starved nodes, per seed it was given.
const WORKER_BUDGET_PER_SEED: Duration = Duration::from_secs(3000);

/// Runs `seeds` of one cell and variant, each worker a separate process running its share of
/// the seeds one after another.
///
/// Processes rather than threads: on Windows, threads of one process running 1,000-node
/// simulations spend most of their time contending for the heap, and eight of them finish
/// fewer runs than one. A worker that fails or runs past its budget fails the sweep, naming
/// the first seed it had not finished.
fn run_seeds(cell: Cell, variant: &str, seeds: std::ops::Range<u64>) -> Vec<Run> {
    use std::io::BufRead as _;
    use std::process::{Command as Process, Stdio};

    let workers = std::thread::available_parallelism()
        .map_or(1, |n| n.get())
        .min(seeds.clone().count().max(1));
    let shares: Vec<Vec<u64>> = (0..workers)
        .map(|w| seeds.clone().skip(w).step_by(workers).collect())
        .collect();
    let exe = std::env::current_exe().unwrap();
    let results = std::sync::Mutex::new(Vec::new());
    std::thread::scope(|s| {
        for share in &shares {
            let (exe, results) = (&exe, &results);
            s.spawn(move || {
                let job = format!(
                    "{}|{}|{}|{variant}|{}",
                    cell.nodes,
                    cell.loss,
                    cell.starved,
                    share
                        .iter()
                        .map(u64::to_string)
                        .collect::<Vec<_>>()
                        .join(",")
                );
                let mut child = Process::new(exe)
                    .args(["--ignored", "--nocapture", "--exact", "worker"])
                    .env("KINSHIP_WORKER", &job)
                    .stdout(Stdio::piped())
                    .stderr(Stdio::piped())
                    .spawn()
                    .unwrap();
                let stdout = child.stdout.take().unwrap();
                let mut stderr = child.stderr.take().unwrap();
                let errors = std::thread::spawn(move || {
                    let mut s = String::new();
                    std::io::Read::read_to_string(&mut stderr, &mut s).unwrap();
                    s
                });
                let (tx, rx) = std::sync::mpsc::channel();
                std::thread::spawn(move || {
                    for line in std::io::BufReader::new(stdout).lines() {
                        let Ok(line) = line else { break };
                        if line.starts_with("run ") && tx.send(Run::from_line(&line)).is_err() {
                            break;
                        }
                    }
                });
                let deadline =
                    std::time::Instant::now() + WORKER_BUDGET_PER_SEED * share.len() as u32;
                let mut done = Vec::new();
                while done.len() < share.len() {
                    let left = deadline.saturating_duration_since(std::time::Instant::now());
                    match rx.recv_timeout(left) {
                        Ok(r) => done.push(r),
                        Err(_) => break,
                    }
                }
                if done.len() < share.len() {
                    let _ = child.kill();
                }
                let status = child.wait().unwrap();
                if let Some(seed) = share.get(done.len()) {
                    let (nodes, loss, starved) = (cell.nodes, cell.loss, cell.starved);
                    panic!(
                        "seed {seed} of `{variant}` in {cell:?} failed or ran past its budget \
                         ({status}); replay it with \
                         KINSHIP_WORKER=\"{nodes}|{loss}|{starved}|{variant}|{seed}\" \
                         cargo test --release -p kinship-sim --test tuning -- --ignored \
                         --exact worker\n{}",
                        errors.join().unwrap()
                    );
                }
                results.lock().unwrap().extend(done);
            });
        }
    });
    let mut results = results.into_inner().unwrap();
    results.sort_by_key(|r| r.0);
    results.into_iter().map(|r| r.1).collect()
}

/// The worker process [`run_seeds`] starts: runs the cell, variant and seeds in
/// `KINSHIP_WORKER` and prints one line per seed. Does nothing without it.
#[test]
#[ignore = "started by the sweeps"]
fn worker() {
    let Ok(job) = std::env::var("KINSHIP_WORKER") else {
        return;
    };
    let f: Vec<&str> = job.split('|').collect();
    let cell = Cell {
        nodes: f[0].parse().unwrap(),
        loss: f[1].parse().unwrap(),
        starved: f[2].parse().unwrap(),
    };
    let cfg = config(f[3]);
    for seed in f[4].split(',').map(|s| s.parse::<u64>().unwrap()) {
        let line = run(cell, &cfg, seed).to_line(seed);
        println!("{line}");
    }
}

/// Mean and sample standard deviation.
fn mean_sd(xs: &[f64]) -> (f64, f64) {
    let n = xs.len() as f64;
    let mean = xs.iter().sum::<f64>() / n.max(1.0);
    let var = xs.iter().map(|x| (x - mean).powi(2)).sum::<f64>() / (n - 1.0).max(1.0);
    (mean, var.sqrt())
}

/// One CSV row: the totals of one cell and variant.
fn csv_row(stage: &str, cell: Cell, variant: &str, runs: &[Run]) -> String {
    let deaths: Vec<f64> = runs
        .iter()
        .map(|r| (r.healthy_deaths + r.starved_deaths) as f64)
        .collect();
    let suspicions: Vec<f64> = runs.iter().map(|r| r.false_suspicions as f64).collect();
    let (deaths_mean, deaths_sd) = mean_sd(&deaths);
    let (susp_mean, susp_sd) = mean_sd(&suspicions);
    let mut d: Vec<Duration> = runs.iter().flat_map(|r| r.detections.clone()).collect();
    d.sort_unstable();
    let pct = |p: usize| {
        d.get((d.len() * p / 100).min(d.len().saturating_sub(1)))
            .map_or(f64::NAN, Duration::as_secs_f64)
    };
    let mean = d.iter().map(Duration::as_secs_f64).sum::<f64>() / d.len().max(1) as f64;
    let per_node_s =
        |bytes: u64| bytes as f64 / runs.len() as f64 / cell.nodes as f64 / DURATION.as_secs_f64();
    let udp: u64 = runs.iter().map(|r| r.udp_bytes).sum();
    let tcp: u64 = runs.iter().map(|r| r.tcp_bytes).sum();
    format!(
        "{stage},{},{},{},{},{variant},{},{},{},{},{deaths_mean:.4},{deaths_sd:.4},\
         {susp_mean:.2},{susp_sd:.2},{mean:.3},{:.3},{:.3},{:.3},{},{:.1},{:.1},{:.1}\n",
        cell.nodes,
        cell.loss,
        cell.starved,
        cell.starved_nodes(),
        runs.len(),
        runs.iter().map(|r| r.healthy_deaths).sum::<u64>(),
        runs.iter().map(|r| r.starved_deaths).sum::<u64>(),
        runs.iter()
            .filter(|r| r.healthy_deaths + r.starved_deaths > 0)
            .count(),
        pct(50),
        pct(99),
        d.last().map_or(f64::NAN, Duration::as_secs_f64),
        runs.iter().map(|r| r.undetected).sum::<u64>(),
        per_node_s(udp + tcp),
        per_node_s(udp),
        per_node_s(tcp),
    )
}

const CSV_HEADER: &str = concat!(
    "stage,nodes,loss,starved_share,starved_nodes,variant,runs,healthy_false_deaths,",
    "starved_false_deaths,runs_with_false_death,false_deaths_per_run,false_deaths_sd,",
    "false_suspicions_per_run,false_suspicions_sd,detection_mean_s,detection_p50_s,",
    "detection_p99_s,detection_max_s,undetected,bytes_per_node_s,udp_bytes_per_node_s,",
    "tcp_bytes_per_node_s\n",
);

/// A parsed CSV row.
#[derive(Debug, Clone)]
struct Row {
    stage: String,
    cell: String,
    variant: String,
    runs: f64,
    deaths: f64,
    deaths_sd: f64,
    suspicions: f64,
    suspicions_sd: f64,
    p50: f64,
    p99: f64,
    undetected: u64,
    bytes: f64,
}

impl Row {
    fn parse(line: &str) -> Self {
        let c: Vec<&str> = line.split(',').collect();
        let f = |i: usize| c[i].parse::<f64>().unwrap();
        Self {
            stage: c[0].to_owned(),
            cell: c[1..4].join(","),
            variant: c[5].to_owned(),
            runs: f(6),
            deaths: f(10),
            deaths_sd: f(11),
            suspicions: f(12),
            suspicions_sd: f(13),
            p50: f(15),
            p99: f(16),
            undetected: c[18].parse().unwrap(),
            bytes: f(19),
        }
    }

    fn key(&self) -> String {
        format!("{},{},{}", self.stage, self.cell, self.variant)
    }
}

fn csv_path() -> PathBuf {
    let dir = PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../../docs/results");
    std::fs::create_dir_all(&dir).unwrap();
    dir.join("tuning.csv")
}

fn variants(default: &[&str]) -> Vec<String> {
    match std::env::var("KINSHIP_VARIANTS") {
        Ok(v) => v.split(';').map(|s| s.trim().to_owned()).collect(),
        Err(_) => default.iter().map(|s| (*s).to_owned()).collect(),
    }
}

/// One cluster size of a sweep: the starved shares it covers and its seeds per cell.
struct Size {
    nodes: usize,
    starved: &'static [f64],
    seeds: u64,
}

/// Runs every cell of `sizes` for every variant, appending to the CSV and skipping rows
/// already there.
fn sweep(stage: &str, sizes: &[Size], variants: &[String]) {
    let only = common::env("KINSHIP_NODES");
    // Fail on a bad variant before the first cell rather than in a worker.
    for v in variants {
        config(v);
    }
    let path = csv_path();
    let mut csv = std::fs::read_to_string(&path).unwrap_or_else(|_| CSV_HEADER.to_owned());
    let done: BTreeSet<String> = csv.lines().skip(1).map(|l| Row::parse(l).key()).collect();
    let started = std::time::Instant::now();
    for size in sizes
        .iter()
        .filter(|s| only.is_none_or(|n| n == s.nodes as u64))
    {
        let seeds = common::seeds(size.seeds);
        for &starved in size.starved {
            for &loss in &LOSSES {
                let cell = Cell {
                    nodes: size.nodes,
                    loss,
                    starved,
                };
                for variant in variants {
                    if done.contains(&format!("{stage},{},{variant}", cell.key())) {
                        continue;
                    }
                    let runs = run_seeds(cell, variant, seeds.clone());
                    let row = csv_row(stage, cell, variant, &runs);
                    eprint!("{:>8.0?} {row}", started.elapsed());
                    csv.push_str(&row);
                    std::fs::write(&path, &csv).unwrap();
                }
            }
        }
    }
}

/// One field at a time: every cell at 50 and 200 nodes, and at 1,000 nodes the cells without
/// starved nodes or with 1% of them, since a 1,000-node run with 10% starved takes five
/// minutes.
#[test]
#[ignore = "about seven hours in release mode"]
fn screen() {
    let sizes = [
        Size {
            nodes: 50,
            starved: &STARVED,
            seeds: 100,
        },
        Size {
            nodes: 200,
            starved: &STARVED,
            seeds: 50,
        },
        Size {
            nodes: 1000,
            starved: &STARVED[..2],
            seeds: 16,
        },
    ];
    sweep("screen", &sizes, &variants(SCREEN));
}

/// `lan()` and the candidates, every cell at 50, 200 and 1,000 nodes.
#[test]
#[ignore = "about a day in release mode"]
fn grid() {
    let sizes = [
        Size {
            nodes: 50,
            starved: &STARVED,
            seeds: 200,
        },
        Size {
            nodes: 200,
            starved: &STARVED,
            seeds: 200,
        },
        Size {
            nodes: 1000,
            starved: &STARVED,
            seeds: 24,
        },
    ];
    sweep("grid", &sizes, &variants(GRID));
}

/// Whether a variant's cell is worse than `lan()`'s on a count with this mean and standard
/// deviation per run: higher, and by more than 1.645 standard errors (one-sided 5%), or above
/// zero where `lan()` saw none at all.
fn more(v: (f64, f64, f64), base: (f64, f64, f64)) -> bool {
    let ((vm, vsd, vn), (bm, bsd, bn)) = (v, base);
    if bm == 0.0 {
        return vm > 0.0;
    }
    let se = (vsd * vsd / vn + bsd * bsd / bn).sqrt();
    vm > bm && (vm - bm) > 1.645 * se
}

/// The rule a variant must pass to replace `lan()`: in every cell of its stage, a lower
/// detection p99 than `lan()`, no more false deaths or false suspicions (see [`more`]), no
/// more undetected crashes, and at most 10% more bytes per node per second.
fn verdict_table(csv: &str) -> String {
    let rows: Vec<Row> = csv.lines().skip(1).map(Row::parse).collect();
    let base: BTreeMap<(String, String), &Row> = rows
        .iter()
        .filter(|r| r.variant == "lan")
        .map(|r| ((r.stage.clone(), r.cell.clone()), r))
        .collect();
    let mut by_variant: BTreeMap<(String, String), Vec<(&Row, &Row)>> = BTreeMap::new();
    for r in rows.iter().filter(|r| r.variant != "lan") {
        if let Some(b) = base.get(&(r.stage.clone(), r.cell.clone())) {
            by_variant
                .entry((r.stage.clone(), r.variant.clone()))
                .or_default()
                .push((r, b));
        }
    }
    let mut out = String::from(concat!(
        "| Stage | Variant | Cells | p99 lower | Mean p99 change (s) | Worst p99 change (s) | ",
        "Mean p50 change (s) | More false deaths | More false suspicions | ",
        "Max bandwidth ratio | Qualifies |\n",
        "| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |\n",
    ));
    for ((stage, variant), pairs) in &by_variant {
        let cells = pairs.len();
        let lower = pairs.iter().filter(|(v, b)| v.p99 < b.p99).count();
        let dp99: Vec<f64> = pairs.iter().map(|(v, b)| v.p99 - b.p99).collect();
        let dp50: Vec<f64> = pairs.iter().map(|(v, b)| v.p50 - b.p50).collect();
        let worst = dp99.iter().copied().fold(f64::MIN, f64::max);
        let deaths = pairs
            .iter()
            .filter(|(v, b)| {
                more(
                    (v.deaths, v.deaths_sd, v.runs),
                    (b.deaths, b.deaths_sd, b.runs),
                )
            })
            .count();
        let suspicions = pairs
            .iter()
            .filter(|(v, b)| {
                more(
                    (v.suspicions, v.suspicions_sd, v.runs),
                    (b.suspicions, b.suspicions_sd, b.runs),
                )
            })
            .count();
        let undetected = pairs.iter().any(|(v, b)| v.undetected > b.undetected);
        let ratio = pairs
            .iter()
            .map(|(v, b)| v.bytes / b.bytes)
            .fold(0.0, f64::max);
        let qualifies =
            lower == cells && deaths == 0 && suspicions == 0 && !undetected && ratio <= 1.10;
        writeln!(
            out,
            "| {stage} | `{variant}` | {cells} | {lower} | {:+.3} | {worst:+.3} | {:+.3} | \
             {deaths} | {suspicions} | {ratio:.3} | {} |",
            mean_sd(&dp99).0,
            mean_sd(&dp50).0,
            if qualifies { "yes" } else { "no" },
        )
        .unwrap();
    }
    out
}

/// Prints which variants pass the rule, from `docs/results/tuning.csv`.
#[test]
#[ignore = "reads the CSV the sweeps write"]
fn verdict() {
    let csv = std::fs::read_to_string(csv_path()).expect("run the screen or grid sweep first");
    print!("{}", verdict_table(&csv));
}

/// Halving the probe interval doubles the probe traffic and shortens detection, which the
/// sweeps' bandwidth and latency columns depend on.
#[test]
fn faster_probes_cost_bytes_and_detect_sooner() {
    let cell = Cell {
        nodes: 20,
        loss: 0.0,
        starved: 0.0,
    };
    let measure = |variant: &str| {
        let cfg = config(variant);
        let runs = check_all(0..4, |seed| Ok(run(cell, &cfg, seed)));
        let bytes: u64 = runs.iter().map(|r| r.udp_bytes).sum();
        let mut d: Vec<Duration> = runs.into_iter().flat_map(|r| r.detections).collect();
        d.sort_unstable();
        (bytes, d[d.len() / 2], d)
    };
    let (slow_bytes, slow_p50, slow) = measure("lan");
    let (fast_bytes, fast_p50, fast) = measure("probe_interval=500ms probe_timeout=250ms");
    assert_eq!(slow.len(), 4 * 19);
    assert_eq!(fast.len(), 4 * 19);
    let ratio = fast_bytes as f64 / slow_bytes as f64;
    assert!((1.6..2.2).contains(&ratio), "byte ratio {ratio}");
    assert!(fast_p50 < slow_p50, "{fast_p50:?} vs {slow_p50:?}");
    assert!(*slow.last().unwrap() < secs(60));
}

#[test]
fn verdict_applies_the_rule() {
    let row = |variant: &str, deaths: &str, susp: &str, p99: &str, bytes: &str| {
        format!(
            "screen,50,0.01,0.05,3,{variant},100,0,0,0,{deaths},0.1,{susp},5.0,8,8,{p99},13,0,\
             {bytes},0,0\n"
        )
    };
    let csv = [
        CSV_HEADER.to_owned(),
        row("lan", "0.0100", "30.00", "12.0", "1000.0"),
        row("a", "0.0100", "30.10", "11.0", "1050.0"),
        row("b", "0.0100", "35.00", "11.0", "1050.0"),
        row("c", "0.0100", "30.00", "11.0", "1200.0"),
        row("d", "0.0100", "30.00", "12.5", "1000.0"),
    ]
    .concat();
    let table = verdict_table(&csv);
    let verdicts: Vec<(&str, &str)> = table
        .lines()
        .skip(2)
        .map(|l| {
            let c: Vec<&str> = l.split('|').map(str::trim).collect();
            (c[2], c[11])
        })
        .collect();
    assert_eq!(
        verdicts,
        [("`a`", "yes"), ("`b`", "no"), ("`c`", "no"), ("`d`", "no")]
    );
}
