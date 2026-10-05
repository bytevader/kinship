//! Lifeguard against plain SWIM: false positives and detection latency under uniform packet
//! loss, with and without CPU-starved nodes.
//!
//! Every cell of the grid (cluster size x loss x share of starved nodes) runs the same seeds in
//! three arms: `lan()` with Lifeguard, plain SWIM with the TCP fallback ping, and plain SWIM
//! without it. Arms share seeds, so they see the same starved nodes, the same crash and the same
//! network draws until their protocols diverge. Starved nodes read every packet late while their
//! timers fire on time ([`Action::Starve`]), as in the Lifeguard paper's slow-node experiments.
//! Halfway in, one healthy node crashes, to measure detection latency.
//!
//! The full grid writes `docs/results/lifeguard.csv` and prints a markdown table:
//! `cargo test --release -p kinship-sim --test lifeguard -- --ignored --nocapture`.
//! `KINSHIP_SEEDS` sets the seeds per cell (200) and `KINSHIP_NODES` runs one cluster size.

mod common;

use std::collections::BTreeSet;
use std::fmt::Write as _;
use std::rc::Rc;
use std::time::Duration;

use common::{Log, Observed, check_all, index_of, ms, secs, seeds};
use kinship_core::{Config, Event, Instant, Rng, Security};
use kinship_sim::{Action, Delay, LinkConfig, Scenario, Sim, TraceConfig};

const NODES: [usize; 2] = [50, 200];
const LOSSES: [f64; 3] = [0.01, 0.03, 0.05];
const STARVED: [f64; 4] = [0.0, 0.01, 0.05, 0.10];

const DURATION: Duration = Duration::from_secs(120);
const CRASH_AT: Duration = Duration::from_secs(60);

/// How late a starved node reads each packet: long enough that its Acks often miss the round of
/// whoever pinged it, and that it often reads its own Acks after its round has ended.
fn starve_delay() -> Delay {
    Delay::Uniform {
        min: ms(500),
        max: ms(2500),
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Arm {
    Lifeguard,
    Swim,
    SwimNoFallback,
}

const ARMS: [Arm; 3] = [Arm::Lifeguard, Arm::Swim, Arm::SwimNoFallback];

impl Arm {
    fn name(self) -> &'static str {
        match self {
            Arm::Lifeguard => "lifeguard",
            Arm::Swim => "swim",
            Arm::SwimNoFallback => "swim_no_tcp_fallback",
        }
    }

    fn config(self) -> Config {
        // Plaintext keeps the sweep fast; sealing does not change what the protocol does.
        let cfg = Config::lan(Security::InsecurePlaintext);
        match self {
            Arm::Lifeguard => cfg,
            Arm::Swim => cfg.without_lifeguard(),
            Arm::SwimNoFallback => Config {
                tcp_fallback_ping: false,
                ..cfg.without_lifeguard()
            },
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
        if self.starved == 0.0 {
            return 0;
        }
        ((self.nodes as f64 * self.starved).round() as usize).max(1)
    }
}

/// What one run measured.
///
/// A false death is a running member declared dead at some incarnation by at least one node.
/// The Dead rumour then spreads to everyone, so counting it once per observer would only scale
/// it by the cluster size. False suspicions are counted the same way.
#[derive(Debug, Default)]
struct Run {
    healthy_deaths: u64,
    starved_deaths: u64,
    false_suspicions: u64,
    /// Time from the crash to each healthy observer declaring it dead.
    detections: Vec<Duration>,
    /// Healthy observers that never declared the crashed node dead.
    undetected: u64,
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
    let mut sim = Sim::new(seed, scenario, move |spec| {
        Observed::with_config(spec, cfg.clone(), factory_log.clone(), |_| true)
    });
    sim.run();

    let crash = Instant::ZERO + CRASH_AT;
    let running = |j: usize, t: Instant| j != crashed || t < crash;
    let mut out = Run::default();
    let mut detected = vec![None; n];
    let (mut suspected, mut dead) = (BTreeSet::new(), BTreeSet::new());
    for s in log.borrow().iter() {
        match &s.event {
            Event::MemberSuspect(m) if running(index_of(&m.name), s.t) => {
                suspected.insert((index_of(&m.name), m.incarnation));
            }
            Event::MemberDead(m) => {
                let j = index_of(&m.name);
                if running(j, s.t) {
                    dead.insert((j, m.incarnation));
                } else if detected[s.observer].is_none() {
                    detected[s.observer] = Some(s.t - crash);
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
            out.healthy_deaths += 1;
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
    healthy_deaths: u64,
    starved_deaths: u64,
    runs_with_false_death: u64,
    false_suspicions: u64,
    detections: Vec<Duration>,
    undetected: u64,
}

impl Totals {
    fn new(runs: Vec<Run>) -> Self {
        let mut t = Self::default();
        for r in runs {
            t.runs += 1;
            t.healthy_deaths += r.healthy_deaths;
            t.starved_deaths += r.starved_deaths;
            t.runs_with_false_death += u64::from(r.healthy_deaths + r.starved_deaths > 0);
            t.false_suspicions += r.false_suspicions;
            t.detections.extend(r.detections);
            t.undetected += r.undetected;
        }
        t.detections.sort_unstable();
        t
    }

    fn per_run(&self, x: u64) -> f64 {
        x as f64 / self.runs.max(1) as f64
    }

    /// False deaths of any member, starved or healthy, per run.
    fn deaths(&self) -> f64 {
        self.per_run(self.healthy_deaths + self.starved_deaths)
    }

    fn detection(&self, pct: usize) -> f64 {
        let d = &self.detections;
        d.get((d.len() * pct / 100).min(d.len().saturating_sub(1)))
            .map_or(f64::NAN, Duration::as_secs_f64)
    }

    fn detection_mean(&self) -> f64 {
        let d = &self.detections;
        d.iter().map(Duration::as_secs_f64).sum::<f64>() / d.len().max(1) as f64
    }
}

fn grid(nodes: &[usize]) -> Vec<Cell> {
    let mut cells = Vec::new();
    for &nodes in nodes {
        for &starved in &STARVED {
            for &loss in &LOSSES {
                cells.push(Cell {
                    nodes,
                    loss,
                    starved,
                });
            }
        }
    }
    cells
}

/// Runs every arm of `cell` over `seeds`.
fn measure(cell: Cell, seeds: std::ops::Range<u64>) -> Vec<Totals> {
    ARMS.iter()
        .map(|&arm| Totals::new(check_all(seeds.clone(), |seed| Ok(run(cell, arm, seed)))))
        .collect()
}

fn csv(results: &[(Cell, Vec<Totals>)]) -> String {
    let mut out = String::from(concat!(
        "nodes,loss,starved_share,starved_nodes,arm,runs,healthy_false_deaths,",
        "starved_false_deaths,runs_with_false_death,false_deaths_per_run,",
        "false_suspicions_per_run,detection_mean_s,detection_p50_s,detection_p99_s,undetected\n",
    ));
    for (cell, arms) in results {
        for (arm, t) in ARMS.iter().zip(arms) {
            writeln!(
                out,
                "{},{},{},{},{},{},{},{},{},{:.4},{:.2},{:.3},{:.3},{:.3},{}",
                cell.nodes,
                cell.loss,
                cell.starved,
                cell.starved_nodes(),
                arm.name(),
                t.runs,
                t.healthy_deaths,
                t.starved_deaths,
                t.runs_with_false_death,
                t.deaths(),
                t.per_run(t.false_suspicions),
                t.detection_mean(),
                t.detection(50),
                t.detection(99),
                t.undetected
            )
            .unwrap();
        }
    }
    out
}

/// One row per cell, each column Lifeguard / SWIM / SWIM without the TCP fallback.
fn table(results: &[(Cell, Vec<Totals>)]) -> String {
    let mut out = String::from(concat!(
        "| Nodes | Starved | Loss | False deaths per run | Runs with a false death | ",
        "False suspicions per run | Detection p50 (s) | Detection p99 (s) |\n",
        "| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n",
    ));
    let three = |f: &dyn Fn(&Totals) -> String, arms: &[Totals]| {
        arms.iter().map(f).collect::<Vec<_>>().join(" / ")
    };
    for (cell, arms) in results {
        writeln!(
            out,
            "| {} | {} | {:.0}% | {} | {} | {} | {} | {} |",
            cell.nodes,
            cell.starved_nodes(),
            cell.loss * 100.0,
            three(&|t| format!("{:.2}", t.deaths()), arms),
            three(&|t| t.runs_with_false_death.to_string(), arms),
            three(&|t| format!("{:.0}", t.per_run(t.false_suspicions)), arms),
            three(&|t| format!("{:.1}", t.detection(50)), arms),
            three(&|t| format!("{:.1}", t.detection(99)), arms),
        )
        .unwrap();
    }
    out
}

/// A small cell where all three arms must see starvation, and Lifeguard must do no worse.
#[test]
fn lifeguard_beats_swim_with_a_starved_node() {
    let cell = Cell {
        nodes: 20,
        loss: 0.01,
        starved: 0.10,
    };
    let [lifeguard, swim, _] = <[Totals; 3]>::try_from(measure(cell, 0..8)).unwrap();
    assert!(
        swim.false_suspicions > 0,
        "starvation produced no suspicions"
    );
    assert!(lifeguard.false_suspicions < swim.false_suspicions);
    assert!(lifeguard.deaths() <= swim.deaths());
    assert_eq!(lifeguard.undetected, 0);
    assert!(lifeguard.detection(99) < secs(60).as_secs_f64());
}

/// The full grid behind `docs/results/lifeguard.md`.
#[test]
#[ignore = "about an hour in release mode"]
fn lifeguard_against_swim_grid() {
    let nodes = match common::env("KINSHIP_NODES") {
        Some(n) => vec![n as usize],
        None => NODES.to_vec(),
    };
    let seeds = seeds(200);
    let started = std::time::Instant::now();
    let mut results = Vec::new();
    for cell in grid(&nodes) {
        let arms = measure(cell, seeds.clone());
        eprintln!(
            "{cell:?}: false deaths per run {:.2} / {:.2} / {:.2}, {:?}",
            arms[0].deaths(),
            arms[1].deaths(),
            arms[2].deaths(),
            started.elapsed()
        );
        results.push((cell, arms));
    }
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../docs/results");
    std::fs::create_dir_all(&dir).unwrap();
    std::fs::write(dir.join("lifeguard.csv"), csv(&results)).unwrap();
    print!("{}", table(&results));
}
