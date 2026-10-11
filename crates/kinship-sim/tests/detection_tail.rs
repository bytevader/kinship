//! kill -9 at 100 nodes, joined as the chaos bench joins them: node 0 first, then the others
//! in waves of 25 that join through it, some seconds apart.
//!
//! A probe pass lasts as many rounds as it had members, so a node whose pass began while it
//! knew only the early waves would leave the later ones unprobed until the pass ended if
//! joiners waited for the next pass. A crash of a late joiner then waited for its first
//! suspicion and for its confirmations, which is the tail `docs/results/detection.md` measured
//! before joiners took a place in the current pass.
//!
//! The sweep prints detection percentiles:
//! `cargo test --release -p kinship-sim --test detection_tail -- --ignored --nocapture`.
//! `KINSHIP_SEEDS` sets the seeds (400), `WAVE_GAP_MS` the gap between waves (3000), and
//! `LAST_WAVE=0` draws the victim from every node rather than the last wave.

mod common;

use std::rc::Rc;
use std::time::Duration;

use common::{Log, Observed, check_all, env, index_of, ms, percentiles, secs, seeds};
use kinship_core::{Command, Event, Instant, Rng};
use kinship_sim::{Action, Delay, LinkConfig, Scenario, Sim, TraceConfig, addr_of};

const N: usize = 100;
const WAVE: usize = 25;
const SETTLE: Duration = Duration::from_secs(15);

/// From the crash, when the first node suspected the victim and when the first declared it
/// dead.
struct Run {
    suspected: Duration,
    dead: Duration,
}

fn run(seed: u64, gap: Duration, last_wave: bool) -> Result<Run, String> {
    let mut rng = Rng::new(seed ^ 0x5441_494c);
    let last = N - (N - 1) % WAVE;
    let victim = if last_wave {
        last + rng.index(N - last)
    } else {
        1 + rng.index(N - 1)
    };
    let waves = (N - 1).div_ceil(WAVE) as u32;
    let crash = gap * waves + secs(1) + SETTLE + ms(rng.index(1000) as u64);
    // The bench's netem: 2 ms +- 1 ms and 1% loss.
    let link = LinkConfig {
        latency: Delay::Uniform {
            min: ms(1),
            max: ms(3),
        },
        loss: 0.01,
        ..LinkConfig::ideal()
    };
    let mut scenario = Scenario::new(N)
        .duration(crash + secs(60))
        .link(link)
        .trace(TraceConfig::OFF)
        .at(crash, Action::Crash(victim));
    for i in 1..N {
        let wave = ((i - 1) / WAVE) as u32;
        let cmd = Command::Join {
            seeds: vec![addr_of(0)],
        };
        scenario = scenario.at(gap * (wave + 1), Action::Command { node: i, cmd });
    }
    let log: Log = Rc::default();
    let factory_log = log.clone();
    let mut sim = Sim::new(seed, scenario, move |spec| {
        Observed::new(spec, factory_log.clone(), |_| false)
    });
    sim.run();

    let crash = Instant::ZERO + crash;
    let first = |dead: bool| {
        log.borrow()
            .iter()
            .filter(|s| s.t >= crash)
            .filter(|s| match &s.event {
                Event::MemberSuspect(m) => !dead && index_of(&m.name) == victim,
                Event::MemberDead(m) => dead && index_of(&m.name) == victim,
                _ => false,
            })
            .map(|s| s.t - crash)
            .min()
    };
    match (first(false), first(true)) {
        (Some(suspected), Some(dead)) => Ok(Run { suspected, dead }),
        _ => Err(format!("seed {seed}: n{victim} was never declared dead")),
    }
}

/// A crashed late joiner is detected as fast as any other node: its first suspicion comes
/// within a few rounds, and confirmations bring the timeout down to the minimum of 8 s. Before
/// joiners were slotted into the current pass, 8 of the first 40 seeds took longer than 15 s.
#[test]
fn a_crashed_late_joiner_is_detected_in_time() {
    let runs = check_all(seeds(20), |seed| {
        let r = run(seed, secs(3), true)?;
        if r.dead > secs(15) {
            return Err(format!(
                "seed {seed}: suspected after {:?}, dead after {:?}",
                r.suspected, r.dead
            ));
        }
        Ok(r)
    });
    assert!(!runs.is_empty());
}

#[test]
#[ignore = "sweep; prints detection percentiles"]
fn late_joiner_detection_sweep() {
    let gap = ms(env("WAVE_GAP_MS").unwrap_or(3000));
    let last_wave = env("LAST_WAVE") != Some(0);
    let runs = check_all(seeds(400), |seed| run(seed, gap, last_wave));
    let suspected = runs.iter().map(|r| r.suspected).collect();
    let dead = runs.iter().map(|r| r.dead).collect();
    println!("first suspicion: {}", percentiles(suspected));
    println!("first death:     {}", percentiles(dead));
}
