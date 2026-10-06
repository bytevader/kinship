//! Seeded tests of runtime key rotation: a cluster that rotates one step at a time never notices,
//! and a node that falls behind looks dead until it catches up.
//!
//! 1. Every node walks install, use and remove, each step finished on every node before the
//!    next starts. Nobody is suspected or declared dead, no packet fails to decrypt, and the keys
//!    end where they should.
//! 2. One node skips the `use` step while its peers finish all three. The peers can no longer
//!    read it: they count `decrypt_failures` and declare it dead. When it catches up they
//!    reconverge on the full live set.
//!
//! Each property has a quick test over a few seeds and an ignored sweep over 1,000 that CI runs
//! with `cargo test --release -p kinship-sim --test keyring -- --ignored --nocapture`.
//! `KINSHIP_SEED=<seed>` replays one seed and `KINSHIP_SEEDS` changes the count.

mod common;

use std::collections::BTreeSet;
use std::rc::Rc;
use std::time::Duration;

use common::{Log, Observed, check_all, config, index_of, ms, percentiles, secs, seeds};
use kinship_core::{Command, Config, Event, Instant, Key, KeyId, Rng};
use kinship_sim::{Action, Delay, LinkConfig, Scenario, Sim, TraceConfig, name_of};

/// The key the cluster starts with and the key it rotates to.
fn old_key() -> Key {
    Key::from_bytes([7; 32])
}

fn new_key() -> Key {
    Key::from_bytes([8; 32])
}

fn ids(keys: &[Key]) -> Vec<KeyId> {
    keys.iter().map(Key::key_id).collect()
}

/// How long a step takes to finish on every node: each node runs it at its own random moment
/// within this window.
const STEP_WINDOW: Duration = Duration::from_millis(1_000);

/// The gap between steps: past the window, and long enough for every packet sealed before the
/// step to have been delivered, so no node drops a packet for a key a peer has just removed.
const STEP_GAP: Duration = Duration::from_secs(10);

/// A random lossless LAN link, sometimes with 40 ms latency, a little duplication and
/// reordering. Rotation must be invisible on any healthy network, so the tests keep loss out:
/// a suspicion would then mean the rotation caused it.
fn random_link(rng: &mut Rng) -> LinkConfig {
    let mut link = LinkConfig::lan()
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
    link
}

/// Same shape as the sync tests' bound: how long a rumour takes to reach every node.
fn dissemination_bound(cfg: &Config, n: usize) -> Duration {
    let digits = (n as f64 + 1.0).log10().ceil() as u32;
    let gossip =
        cfg.gossip_interval * (cfg.retransmit_mult * digits) + cfg.probe_interval * 2 + secs(1);
    gossip + cfg.push_pull_interval
}

/// How long a healed partition, or a node that caught up, takes to reconverge; see the sync
/// tests for the derivation.
fn heal_bound(cfg: &Config, n: usize) -> Duration {
    let gossip = dissemination_bound(cfg, n) - cfg.push_pull_interval;
    cfg.reconnect_interval + cfg.probe_interval + gossip + dissemination_bound(cfg, n)
}

/// The longest a failure can go undetected: two passes of the probe list and a round, the
/// suspicion timeout, and two seconds of slack.
fn detection_bound(cfg: &Config, n: usize) -> Duration {
    let scale = (n as f64).log10().max(1.0);
    let suspicion = cfg.probe_interval.as_secs_f64() * f64::from(cfg.suspicion_mult) * scale;
    let rounds = 2 * (n as u32 - 1) + 1;
    cfg.probe_interval * rounds + Duration::from_secs_f64(suspicion) + secs(2)
}

fn sim(seed: u64, scenario: Scenario<Command>) -> (Sim<Observed>, Log) {
    let log: Log = Rc::default();
    let factory_log = log.clone();
    let sim = Sim::new(seed, scenario, move |spec| {
        Observed::new(spec, factory_log.clone(), |_| true)
    });
    (sim, log)
}

fn live_set(sim: &Sim<Observed>, o: usize) -> BTreeSet<usize> {
    sim.node(o)
        .map(|n| n.node.members().map(|m| index_of(&m.name)).collect())
        .unwrap_or_default()
}

fn key_ids_of(sim: &Sim<Observed>, o: usize) -> Vec<KeyId> {
    sim.node(o).map(|n| n.node.key_ids()).unwrap_or_default()
}

/// Schedules `cmd` on each of `nodes` at a random moment in `[at, at + STEP_WINDOW)`.
fn step(
    mut scenario: Scenario<Command>,
    rng: &mut Rng,
    at: Duration,
    nodes: impl IntoIterator<Item = usize>,
    cmd: impl Fn() -> Command,
) -> Scenario<Command> {
    for node in nodes {
        let when = at + Duration::from_nanos(rng.below(STEP_WINDOW.as_nanos() as u64));
        scenario = scenario.at(when, Action::Command { node, cmd: cmd() });
    }
    scenario
}

/// Checks that every node's keys are `want`, naming the first that is not.
fn expect_keys(
    sim: &Sim<Observed>,
    nodes: impl IntoIterator<Item = usize>,
    want: &[KeyId],
    when: &str,
) -> Result<(), String> {
    for o in nodes {
        let got = key_ids_of(sim, o);
        if got != want {
            return Err(format!(
                "{} holds keys {got:?} {when}, want {want:?}",
                name_of(o)
            ));
        }
    }
    Ok(())
}

/// Every CommandDone a node logged, as (observer, ok).
fn command_results(log: &Log) -> Vec<(usize, bool)> {
    log.borrow()
        .iter()
        .filter_map(|s| match &s.event {
            Event::CommandDone { result, .. } => Some((s.observer, result.is_ok())),
            _ => None,
        })
        .collect()
}

// ---------------------------------------------------------------------------------------------
// 1. A cluster rotates through install, use and remove without a suspicion.

fn rotate(seed: u64, nodes: usize) -> Result<(), String> {
    let mut rng = Rng::new(seed ^ 0x4b45_5952);
    let link = random_link(&mut rng);
    let all = || 0..nodes;
    let t_install = secs(5);
    let t_use = t_install + STEP_GAP;
    let t_remove = t_use + STEP_GAP;
    let end = t_remove + STEP_GAP + secs(10);

    let mut scenario = Scenario::new(nodes)
        .duration(end)
        .link(link)
        .trace(TraceConfig::OFF);
    scenario = step(scenario, &mut rng, t_install, all(), || {
        Command::InstallKey(new_key())
    });
    scenario = step(scenario, &mut rng, t_use, all(), || {
        Command::UseKey(new_key())
    });
    scenario = step(scenario, &mut rng, t_remove, all(), || {
        Command::RemoveKey(old_key())
    });
    let (mut sim, log) = sim(seed, scenario);
    let fail = |msg: String| Err(format!("seed {seed}: {msg}"));

    // Each step is finished on every node before the next starts.
    let both = ids(&[old_key(), new_key()]);
    let swapped = ids(&[new_key(), old_key()]);
    let only_new = ids(&[new_key()]);
    expect_keys(&sim, all(), &ids(&[old_key()]), "before the rotation")?;
    sim.run_until(Instant::ZERO + t_install + STEP_WINDOW + ms(1));
    if let Err(e) = expect_keys(&sim, all(), &both, "after install") {
        return fail(e);
    }
    sim.run_until(Instant::ZERO + t_use + STEP_WINDOW + ms(1));
    if let Err(e) = expect_keys(&sim, all(), &swapped, "after use") {
        return fail(e);
    }
    sim.run_until(Instant::ZERO + t_remove + STEP_WINDOW + ms(1));
    if let Err(e) = expect_keys(&sim, all(), &only_new, "after remove") {
        return fail(e);
    }
    sim.run();

    for s in log.borrow().iter() {
        match &s.event {
            Event::MemberSuspect(m) | Event::MemberDead(m) | Event::MemberLeft(m) => {
                return fail(format!(
                    "{} reported {} as {:?} at {:?}",
                    name_of(s.observer),
                    m.name,
                    s.event,
                    s.t
                ));
            }
            _ => {}
        }
    }
    let results = command_results(&log);
    let ok = results.iter().filter(|r| r.1).count();
    if results.len() != 3 * nodes || ok != results.len() {
        return fail(format!(
            "{ok} of {} key commands succeeded, want {}",
            results.len(),
            3 * nodes
        ));
    }
    for o in all() {
        let node = sim.node(o).expect("the node runs");
        let m = node.node.metrics();
        if m.decrypt_failures != 0 || m.decode_errors != 0 || m.suspicions != 0 {
            return fail(format!(
                "{} counted {} decrypt failures, {} decode errors, {} suspicions",
                name_of(o),
                m.decrypt_failures,
                m.decode_errors,
                m.suspicions
            ));
        }
        if live_set(&sim, o).len() != nodes {
            return fail(format!(
                "{} ends with {} live",
                name_of(o),
                live_set(&sim, o).len()
            ));
        }
    }
    Ok(())
}

#[test]
fn rotating_every_node_never_raises_a_suspicion() {
    check_all(0..8, |seed| rotate(seed, 12));
}

#[test]
#[ignore = "slow in debug builds; CI runs it with --release"]
fn rotating_every_node_never_raises_a_suspicion_thousand_seeds() {
    let seeds = seeds(1000);
    check_all(seeds.clone(), |seed| rotate(seed, 50));
    println!(
        "rotate: {} seeds x 50 nodes, install, use, remove: no suspicions, no decrypt failures",
        seeds.end - seeds.start
    );
}

// ---------------------------------------------------------------------------------------------
// 2. A node that falls a step behind looks dead until it catches up.

#[derive(Debug, Default)]
struct Behind {
    /// From the laggard's catch-up to every node holding the full live set again.
    reconverged: Vec<Duration>,
}

fn fall_behind(seed: u64, nodes: usize) -> Result<Behind, String> {
    let cfg = config();
    let mut rng = Rng::new(seed ^ 0x4c41_4747);
    let link = random_link(&mut rng);
    let laggard = rng.index(nodes);
    let peers = || (0..nodes).filter(move |&o| o != laggard);
    let t_install = secs(5);
    let t_use = t_install + STEP_GAP;
    let t_remove = t_use + STEP_GAP;
    // The peers have no key the laggard seals with from the end of the remove step; give them
    // time to notice, then let it catch up.
    let t_dead = t_remove + STEP_WINDOW + detection_bound(&cfg, nodes);
    let t_catch_up = t_dead + secs(5);
    let end = t_catch_up + heal_bound(&cfg, nodes) + secs(10);

    let mut scenario = Scenario::new(nodes)
        .duration(end)
        .link(link)
        .trace(TraceConfig::OFF);
    scenario = step(scenario, &mut rng, t_install, 0..nodes, || {
        Command::InstallKey(new_key())
    });
    // The laggard misses `use`, and with it `remove`, which the key it still seals with forbids.
    scenario = step(scenario, &mut rng, t_use, peers(), || {
        Command::UseKey(new_key())
    });
    scenario = step(scenario, &mut rng, t_remove, peers(), || {
        Command::RemoveKey(old_key())
    });
    scenario = scenario
        .at(
            t_catch_up,
            Action::Command {
                node: laggard,
                cmd: Command::UseKey(new_key()),
            },
        )
        .at(
            t_catch_up + ms(1),
            Action::Command {
                node: laggard,
                cmd: Command::RemoveKey(old_key()),
            },
        );
    let (mut sim, log) = sim(seed, scenario);
    let fail = |msg: String| {
        Err(format!(
            "seed {seed}: {msg}\n{} falls behind among {nodes} nodes",
            name_of(laggard)
        ))
    };
    let name = name_of(laggard);

    // The peers finish the rotation; the laggard still seals with the old key.
    sim.run_until(Instant::ZERO + t_remove + STEP_WINDOW + ms(1));
    if let Err(e) = expect_keys(&sim, peers(), &ids(&[new_key()]), "after remove") {
        return fail(e);
    }
    if let Err(e) = expect_keys(
        &sim,
        [laggard],
        &ids(&[old_key(), new_key()]),
        "while it lags",
    ) {
        return fail(e);
    }

    // Every peer sees it die, because they can no longer read it.
    sim.run_until(Instant::ZERO + t_dead);
    let mut saw_dead = BTreeSet::new();
    for s in log.borrow().iter() {
        // The laggard reads its peers but they cannot read it, so its own probes go unanswered
        // and it declares them dead itself; that is its view, not a peer's.
        if s.observer == laggard {
            continue;
        }
        if let Event::MemberDead(m) = &s.event {
            if m.name != name {
                return fail(format!(
                    "{} declared {} dead, which has not lagged",
                    name_of(s.observer),
                    m.name
                ));
            }
            saw_dead.insert(s.observer);
        }
    }
    for o in peers() {
        if !saw_dead.contains(&o) {
            return fail(format!(
                "{} never reported the laggard dead by {t_dead:?}",
                name_of(o)
            ));
        }
    }
    let dropped: u64 = peers()
        .map(|o| sim.node(o).map_or(0, |n| n.node.metrics().decrypt_failures))
        .sum();
    if dropped == 0 {
        return fail("the peers counted no decrypt failures".to_owned());
    }
    let lag = sim.node(laggard).expect("the node runs");
    if lag.node.metrics().decrypt_failures != 0 {
        return fail(format!(
            "the laggard could not read its peers: {} decrypt failures",
            lag.node.metrics().decrypt_failures
        ));
    }

    // It catches up, and every node holds the full live set again.
    sim.run_until(Instant::ZERO + t_catch_up + ms(2));
    if let Err(e) = expect_keys(&sim, [laggard], &ids(&[new_key()]), "after it catches up") {
        return fail(e);
    }
    let caught_up = sim.now();
    let everyone: BTreeSet<usize> = (0..nodes).collect();
    let mut reconverged = None;
    while sim.now() < Instant::ZERO + end {
        if (0..nodes).all(|o| live_set(&sim, o) == everyone) {
            reconverged = Some(sim.now());
            break;
        }
        let next = sim.now() + ms(250);
        sim.run_until(next);
    }
    let Some(reconverged) = reconverged else {
        let short: Vec<String> = (0..nodes)
            .filter(|&o| live_set(&sim, o) != everyone)
            .map(|o| format!("{} sees {}", name_of(o), live_set(&sim, o).len()))
            .collect();
        return fail(format!(
            "no reconvergence within {:?} of the catch-up: {}",
            end - t_catch_up,
            short.join(", ")
        ));
    };
    let ok = command_results(&log)
        .into_iter()
        .filter(|r| !r.1)
        .collect::<Vec<_>>();
    if !ok.is_empty() {
        return fail(format!("key commands were refused: {ok:?}"));
    }
    Ok(Behind {
        reconverged: vec![reconverged - caught_up],
    })
}

#[test]
fn a_node_that_falls_behind_dies_and_rejoins() {
    check_all(0..8, |seed| fall_behind(seed, 10));
}

#[test]
#[ignore = "slow in debug builds; CI runs it with --release"]
fn a_node_that_falls_behind_dies_and_rejoins_thousand_seeds() {
    let seeds = seeds(1000);
    let runs = check_all(seeds.clone(), |seed| fall_behind(seed, 20));
    println!(
        "fall behind: {} seeds x 20 nodes, dead to every peer, then reconverged after the catch-up; reconvergence took {}",
        seeds.end - seeds.start,
        percentiles(runs.iter().flat_map(|r| r.reconverged.clone()).collect())
    );
}
