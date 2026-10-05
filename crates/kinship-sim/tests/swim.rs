//! Seeded property tests of core SWIM over random scenarios.
//!
//! Each seed builds a random scenario (loss, latency, reordering, duplication, slow and paused
//! nodes, one-way link blocks, crashes, and sometimes a permanent partition), runs a cluster of
//! `kinship_core::Node`s through it, and checks:
//!
//! 1. no live node is declared dead, as long as loss stays within [`LOSS_TOLERANCE`] and no
//!    partition has started (in a partition a minority side can lose its own members, which
//!    only push-pull anti-entropy repairs);
//! 2. every crashed node, and every node across a partition, is declared dead by every live
//!    node within the analytic bound [`detection_bound`];
//! 3. without a partition, every live node ends with the same live set, which is exactly the
//!    nodes still running;
//! 4. no node ever sees an incarnation go down, its own or anyone else's.
//!
//! A failure prints its seed. Replay one with
//! `KINSHIP_SEED=<seed> cargo test --release -p kinship-sim --test swim -- --ignored --nocapture`.

mod common;

use std::collections::{BTreeMap, BTreeSet};
use std::rc::Rc;
use std::time::Duration;

use common::{Log, Observed, check_all, config, index_of, ms, secs, seeds};
use kinship_core::{Command, Config, Event, Instant, Rng};
use kinship_sim::{Action, Delay, LinkConfig, Scenario, Sim, TraceConfig, name_of};

/// Uniform packet loss up to this is within what core SWIM must tolerate without a false death.
const LOSS_TOLERANCE: f64 = 0.01;

/// Scenarios draw loss up to this. Above the tolerance false deaths are counted, not failures.
const MAX_LOSS: f64 = 0.05;

/// The random faults of one seed.
#[derive(Debug, Clone)]
struct Plan {
    nodes: usize,
    loss: f64,
    duplicate: f64,
    reorder: f64,
    latency_ms: u64,
    slow: Vec<(usize, Duration)>,
    pauses: Vec<(Duration, usize, Duration)>,
    blocks: Vec<(usize, usize)>,
    crashes: Vec<(Duration, usize)>,
    /// When the partition starts, and which nodes are on side A.
    partition: Option<(Duration, BTreeSet<usize>)>,
    duration: Duration,
}

/// `suspicion_mult x max(1, log10 n) x probe_interval`, rounded up to the millisecond.
fn suspicion_timeout(cfg: &Config, n: usize) -> Duration {
    let scale = (n as f64).log10().max(1.0);
    let s = cfg.probe_interval.as_secs_f64() * f64::from(cfg.suspicion_mult) * scale;
    Duration::from_millis((s * 1000.0).ceil() as u64)
}

/// The latest a failure can go undetected by a live node, in a cluster of `n`.
///
/// Every node probes every live member once per pass of its shuffled round-robin list, and a
/// pass is `n - 1` probe intervals, so from any moment the next probe of a given member comes
/// within two passes. That round fails at its end, one more interval. The suspicion then runs
/// for its timeout, unless a Dead rumour arrives first. Two seconds of slack cover network
/// latency, paused and slow nodes.
fn detection_bound(cfg: &Config, n: usize) -> Duration {
    let rounds = 2 * (n as u32 - 1) + 1;
    cfg.probe_interval * rounds + suspicion_timeout(cfg, n) + secs(2)
}

impl Plan {
    fn random(seed: u64, nodes: usize) -> Self {
        let mut rng = Rng::new(seed ^ 0x5157_494d_5345_4544);
        let pick = |rng: &mut Rng, k: usize| -> Vec<usize> {
            let mut all: Vec<usize> = (0..nodes).collect();
            rng.shuffle(&mut all);
            all.truncate(k.min(nodes));
            all
        };
        let at = |rng: &mut Rng, lo: u64, hi: u64| ms(lo * 1000 + rng.below((hi - lo) * 1000));

        let loss = if rng.chance(0.2) {
            0.0
        } else {
            rng.next_f64() * MAX_LOSS
        };
        let duplicate = rng.next_f64() * 0.01;
        let reorder = rng.next_f64() * 0.02;
        let latency_ms = if rng.chance(0.2) { 40 } else { 0 };

        let k = rng.index(3);
        let slow = pick(&mut rng, k)
            .into_iter()
            .map(|n| (n, Duration::from_micros(rng.below(2000))))
            .collect();
        let pauses = (0..rng.index(3))
            .map(|_| {
                let node = rng.index(nodes);
                (at(&mut rng, 2, 40), node, ms(rng.below(300)))
            })
            .collect();
        let blocks = (0..rng.index(3))
            .map(|_| {
                let from = rng.index(nodes);
                let to = (from + 1 + rng.index(nodes - 1)) % nodes;
                (from, to)
            })
            .collect();
        let k = rng.index(4);
        let crashed = pick(&mut rng, k);
        let crashes: Vec<(Duration, usize)> = crashed
            .into_iter()
            .map(|n| (at(&mut rng, 5, 30), n))
            .collect();
        let partition = rng.chance(0.15).then(|| {
            let size = 1 + rng.index(nodes / 2);
            let side = pick(&mut rng, size).into_iter().collect();
            (at(&mut rng, 5, 20), side)
        });

        let last = crashes
            .iter()
            .map(|c| c.0)
            .chain(partition.iter().map(|p| p.0))
            .max()
            .unwrap_or(secs(10));
        let duration = last + detection_bound(&config(), nodes) + secs(5);
        Self {
            nodes,
            loss,
            duplicate,
            reorder,
            latency_ms,
            slow,
            pauses,
            blocks,
            crashes,
            partition,
            duration,
        }
    }

    fn scenario(&self) -> Scenario<Command> {
        let latency = if self.latency_ms == 0 {
            LinkConfig::lan().latency
        } else {
            Delay::Normal {
                mean: ms(self.latency_ms),
                std_dev: ms(self.latency_ms / 4),
            }
        };
        let link = LinkConfig::lan()
            .with_latency(latency)
            .with_loss(self.loss)
            .with_duplicate(self.duplicate)
            .with_reorder(
                self.reorder,
                Delay::Uniform {
                    min: ms(1),
                    max: ms(20),
                },
            );
        let mut s = Scenario::new(self.nodes)
            .duration(self.duration)
            .link(link)
            .trace(TraceConfig::OFF);
        for &(node, cost) in &self.slow {
            s = s.slow_node(node, Delay::Fixed(cost));
        }
        for &(from, to) in &self.blocks {
            s = s.at(
                Duration::ZERO,
                Action::Block {
                    from: from.into(),
                    to: to.into(),
                },
            );
        }
        for &(t, node, duration) in &self.pauses {
            s = s.at(t, Action::Pause { node, duration });
        }
        for &(t, node) in &self.crashes {
            s = s.at(t, Action::Crash(node));
        }
        if let Some((t, side)) = &self.partition {
            let other: Vec<usize> = (0..self.nodes).filter(|n| !side.contains(n)).collect();
            s = s.at(
                *t,
                Action::Partition {
                    a: side.iter().copied().collect::<Vec<_>>().into(),
                    b: other.into(),
                },
            );
        }
        s
    }

    fn crashed_at(&self, node: usize) -> Option<Instant> {
        self.crashes
            .iter()
            .find(|c| c.1 == node)
            .map(|c| Instant::ZERO + c.0)
    }

    fn alive_at(&self, node: usize, t: Instant) -> bool {
        self.crashed_at(node).is_none_or(|c| t < c)
    }

    fn partitioned(&self, t: Instant) -> bool {
        self.partition
            .as_ref()
            .is_some_and(|(start, _)| t >= Instant::ZERO + *start)
    }

    /// Whether a partition separates `a` and `b` at `t`.
    fn split(&self, a: usize, b: usize, t: Instant) -> Option<Instant> {
        let (start, side) = self.partition.as_ref()?;
        let start = Instant::ZERO + *start;
        (t >= start && side.contains(&a) != side.contains(&b)).then_some(start)
    }
}

/// What one seed measured.
#[derive(Debug, Default, Clone)]
struct Outcome {
    /// Time from each failure (crash or partition) to each live node declaring it dead.
    detections: Vec<Duration>,
    suspicions: u64,
    refutations: u64,
    false_suspicions: u64,
    /// Live members a minority side of a partition declared dead.
    partition_deaths: u64,
    /// Live members declared dead under loss above [`LOSS_TOLERANCE`].
    lossy_deaths: u64,
}

/// Runs one seed and checks every property, returning the first violation.
fn check(seed: u64, nodes: usize) -> Result<Outcome, String> {
    let plan = Plan::random(seed, nodes);
    let log: Log = Rc::default();
    let factory_log = log.clone();
    let mut sim = Sim::new(seed, plan.scenario(), move |spec| {
        Observed::new(spec, factory_log.clone(), |_| true)
    });
    let fail = |msg: String| Err(format!("seed {seed}: {msg}\nplan: {plan:?}"));

    // Sample every node's view once a simulated second for incarnations that go down.
    let mut seen: Vec<Vec<u32>> = vec![vec![0; nodes]; nodes];
    let mut t = Instant::ZERO;
    while t < sim.end() {
        t = (t + secs(1)).min(sim.end());
        sim.run_until(t);
        for (o, row) in seen.iter_mut().enumerate() {
            let Some(n) = sim.node(o) else { continue };
            for m in n.node.all_members() {
                let j = index_of(&m.name);
                if m.incarnation < row[j] {
                    return fail(format!(
                        "{} saw {}'s incarnation go from {} to {} by {t:?}",
                        name_of(o),
                        m.name,
                        row[j],
                        m.incarnation
                    ));
                }
                row[j] = m.incarnation;
            }
        }
    }

    let log = log.borrow();
    let mut out = Outcome::default();
    // First death of each member at each observer.
    let mut dead_at: BTreeMap<(usize, usize), Instant> = BTreeMap::new();
    for s in log.iter() {
        let (m, verb) = match &s.event {
            Event::MemberDead(m) => (m, "dead"),
            Event::MemberLeft(m) => (m, "left"),
            Event::MemberSuspect(m) => {
                let j = index_of(&m.name);
                if plan.alive_at(j, s.t) && plan.split(s.observer, j, s.t).is_none() {
                    out.false_suspicions += 1;
                }
                continue;
            }
            _ => continue,
        };
        let j = index_of(&m.name);
        if verb == "left" {
            return fail(format!("{} saw {} leave", name_of(s.observer), m.name));
        }
        // A false death counts as detection of a later real failure: the member is already gone.
        dead_at.entry((s.observer, j)).or_insert(s.t);
        if plan.alive_at(j, s.t) && plan.split(s.observer, j, s.t).is_none() {
            if plan.partitioned(s.t) {
                // A minority side loses most of its relays and gossip targets until the
                // other side is declared dead, so SWIM may kill its own members; push-pull
                // anti-entropy is what repairs that.
                out.partition_deaths += 1;
                continue;
            }
            if plan.loss > LOSS_TOLERANCE {
                out.lossy_deaths += 1;
                continue;
            }
            return fail(format!(
                "{} declared live node {} dead at {:?} (loss {:.3})",
                name_of(s.observer),
                m.name,
                s.t,
                plan.loss
            ));
        }
    }

    // Every failure is detected by every live node within the bound.
    let bound = detection_bound(&config(), nodes);
    let end = sim.end();
    for o in (0..nodes).filter(|&o| plan.alive_at(o, end)) {
        for j in (0..nodes).filter(|&j| j != o) {
            let failed = match (plan.crashed_at(j), plan.split(o, j, end)) {
                (Some(c), Some(p)) => c.min(p),
                (Some(c), None) => c,
                (None, Some(p)) => p,
                (None, None) => continue,
            };
            match dead_at.get(&(o, j)) {
                // Declared dead before it failed: a false death, already accounted for.
                Some(&d) if d < failed => {}
                Some(&d) if d - failed <= bound => out.detections.push(d - failed),
                Some(&d) => {
                    return fail(format!(
                        "{} took {:?} to declare {} dead, over the bound {bound:?}",
                        name_of(o),
                        d - failed,
                        name_of(j)
                    ));
                }
                None => {
                    return fail(format!(
                        "{} never declared {} dead (failed at {failed:?})",
                        name_of(o),
                        name_of(j)
                    ));
                }
            }
        }
    }

    // Every live node converged on the same live set: the running nodes. Runs with a partition
    // or a false death are left out: a node that wrongly declared a member dead stops probing
    // it, and only push-pull anti-entropy brings the member back if the refutation missed it.
    for o in (0..nodes).filter(|&o| plan.alive_at(o, end)) {
        let n = &sim.node(o).expect("alive").node;
        out.suspicions += n.metrics().suspicions;
        out.refutations += n.metrics().refutations;
        if plan.partition.is_some() || out.lossy_deaths > 0 {
            continue;
        }
        let view: BTreeSet<usize> = n.members().map(|m| index_of(&m.name)).collect();
        let truth: BTreeSet<usize> = (0..nodes)
            .filter(|&j| plan.alive_at(j, end) && plan.split(o, j, end).is_none())
            .collect();
        if view != truth {
            return fail(format!(
                "{} ended with live set {view:?}, expected {truth:?}",
                name_of(o)
            ));
        }
    }
    Ok(out)
}

fn summarize(outcomes: &[Outcome]) -> String {
    let mut d: Vec<Duration> = outcomes.iter().flat_map(|o| o.detections.clone()).collect();
    d.sort_unstable();
    let pct = |p: usize| d.get((d.len() * p / 100).min(d.len().saturating_sub(1)));
    format!(
        "{} detections: p50 {:?}, p99 {:?}, max {:?}; {} suspicions ({} of live nodes), {} refutations, {} deaths inside a minority partition, {} under loss above the tolerance",
        d.len(),
        pct(50),
        pct(99),
        d.last(),
        outcomes.iter().map(|o| o.suspicions).sum::<u64>(),
        outcomes.iter().map(|o| o.false_suspicions).sum::<u64>(),
        outcomes.iter().map(|o| o.refutations).sum::<u64>(),
        outcomes.iter().map(|o| o.partition_deaths).sum::<u64>(),
        outcomes.iter().map(|o| o.lossy_deaths).sum::<u64>(),
    )
}

#[test]
fn swim_properties_hold_on_random_scenarios() {
    let outcomes = check_all(0..32, |seed| check(seed, 20));
    assert!(outcomes.iter().any(|o| !o.detections.is_empty()));
}

/// The week-6 gate: 1,000 seeds at 50 nodes. CI runs it in release mode with
/// `cargo test --release -p kinship-sim --test swim -- --ignored --nocapture`.
///
/// `KINSHIP_SEEDS` and `KINSHIP_NODES` change the sweep; `KINSHIP_SEED` replays one seed.
#[test]
#[ignore = "slow in debug builds; CI runs it with --release"]
fn thousand_seeds_fifty_nodes() {
    let nodes = common::env("KINSHIP_NODES").unwrap_or(50) as usize;
    let seeds = seeds(1000);
    let started = std::time::Instant::now();
    let outcomes = check_all(seeds.clone(), |seed| check(seed, nodes));
    println!(
        "{} seeds x {nodes} nodes passed in {:?}: {}",
        seeds.end - seeds.start,
        started.elapsed(),
        summarize(&outcomes)
    );
}

#[test]
fn same_seed_gives_identical_swim_traces() {
    let run = |seed| {
        let plan = Plan::random(seed, 10);
        let scenario = plan.scenario().trace(TraceConfig::ALL).duration(secs(30));
        let log: Log = Rc::default();
        let mut sim = Sim::new(seed, scenario, move |spec| {
            Observed::new(spec, log.clone(), |_| true)
        });
        sim.run().digest()
    };
    assert_eq!(run(3), run(3));
    assert_ne!(run(3), run(4));
}

#[test]
fn swim_trace_is_pinned_across_platforms() {
    // CI runs this on Linux, macOS and Windows, so a SWIM seed that fails anywhere replays
    // everywhere, encrypted bytes included. Update the value only when the protocol, the codec
    // or the simulator changes on purpose.
    let plan = Plan::random(1, 10);
    let scenario = plan.scenario().trace(TraceConfig::ALL).duration(secs(30));
    let log: Log = Rc::default();
    let mut sim = Sim::new(1, scenario, move |spec| {
        Observed::new(spec, log.clone(), |_| true)
    });
    assert_eq!(
        sim.run().digest(),
        0xaa2c_4eeb_3a3a_7e31,
        "trace digest changed"
    );
}
