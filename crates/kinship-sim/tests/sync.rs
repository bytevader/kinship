//! Seeded property tests of the stream half of the protocol: push-pull, join, leave and
//! metadata, over random links.
//!
//! 1. A healed partition fully reconverges through reconnect push-pulls, within
//!    [`heal_bound`] of the heal.
//! 2. A node that leaves is never reported dead, and every other node hears that it left.
//! 3. A metadata update reaches every node within [`dissemination_bound`], and at least 99% of
//!    deliveries arrive by gossip alone, within [`gossip_bound`].
//! 4. A new node joining a 200-node cluster through its seeds converges within
//!    [`dissemination_bound`]: it knows every member, and every member knows it.
//!
//! Each property has a quick test over a few seeds and an ignored sweep over 1,000 that CI runs
//! with `cargo test --release -p kinship-sim --test sync -- --ignored --nocapture`.
//! `KINSHIP_SEED=<seed>` replays one seed and `KINSHIP_SEEDS` changes the count.

mod common;

use std::collections::BTreeSet;
use std::rc::Rc;
use std::time::Duration;

use common::{Log, Observed, check_all, config, index_of, ms, percentiles, secs, seeds};
use kinship_core::{Command, CommandOutput, Config, Event, Instant, Rng, State};
use kinship_sim::{Action, Delay, LinkConfig, NodeSet, Scenario, Sim, TraceConfig, name_of};

/// Loss core SWIM tolerates without a false death; runs that must have none stay within it.
const LOSS_TOLERANCE: f64 = 0.01;

/// The most loss the metadata runs draw, as in the SWIM sweep.
const MAX_LOSS: f64 = 0.05;

/// A random LAN link with loss up to `max_loss`, sometimes 40 ms of latency, and a little
/// duplication and reordering. Returns the link and its loss.
fn random_link(rng: &mut Rng, max_loss: f64) -> (LinkConfig, f64) {
    let loss = if rng.chance(0.2) {
        0.0
    } else {
        rng.next_f64() * max_loss
    };
    let mut link = LinkConfig::lan()
        .with_loss(loss)
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
    (link, loss)
}

fn pick(rng: &mut Rng, nodes: usize, k: usize) -> Vec<usize> {
    let mut all: Vec<usize> = (0..nodes).collect();
    rng.shuffle(&mut all);
    all.truncate(k);
    all
}

/// `retransmit_mult x ceil(log10(n + 1))`, as the core computes it.
fn retransmit_limit(cfg: &Config, n: usize) -> u32 {
    let digits = (n as f64 + 1.0).log10().ceil() as u32;
    cfg.retransmit_mult * digits
}

/// How long gossip takes to spread a rumour, with high probability. Each node that hears it
/// passes it on in its next `retransmit_limit` packets and sends gossip every
/// `gossip_interval`, so the rumour has run its course after that many gossip rounds. Two probe
/// intervals cover the piggybacked path, and a second covers latency.
///
/// Gossip is probabilistic: about `n x retransmit_limit` packets carry the rumour to random
/// members, so a given node is missed with probability near `exp(-retransmit_limit)`, a few in
/// ten thousand at 50 nodes. Push-pull is what catches those.
fn gossip_bound(cfg: &Config, n: usize) -> Duration {
    cfg.gossip_interval * retransmit_limit(cfg, n) + cfg.probe_interval * 2 + secs(1)
}

/// How long a rumour takes to reach every node: gossip, then for any node it missed, that
/// node's next push-pull, which it starts every `push_pull_interval` with a random member that
/// almost surely has the rumour.
fn dissemination_bound(cfg: &Config, n: usize) -> Duration {
    gossip_bound(cfg, n) + cfg.push_pull_interval
}

/// How long a healed partition takes to reconverge. Every node with a dead member push-pulls
/// with one of them every `reconnect_interval`, and the first exchange across the old
/// partition starts the cascade: each side suspects the members the other side declared dead,
/// they refute, and the refutations spread. That takes a probe round for the suspicion to reach
/// its target, the suspicion's gossip, and the refutation's dissemination.
fn heal_bound(cfg: &Config, n: usize) -> Duration {
    cfg.reconnect_interval + cfg.probe_interval + gossip_bound(cfg, n) + dissemination_bound(cfg, n)
}

/// The longest a failure can go undetected, as in the SWIM sweep: two passes of the probe list
/// and a round, the suspicion timeout, and two seconds of slack.
fn detection_bound(cfg: &Config, n: usize) -> Duration {
    let scale = (n as f64).log10().max(1.0);
    let suspicion = cfg.probe_interval.as_secs_f64() * f64::from(cfg.suspicion_mult) * scale;
    let rounds = 2 * (n as u32 - 1) + 1;
    cfg.probe_interval * rounds + Duration::from_secs_f64(suspicion) + secs(2)
}

/// Builds the sim, every node logging into the returned log.
fn sim(
    seed: u64,
    scenario: Scenario<Command>,
    knows: impl Fn(usize, usize) -> bool + 'static,
) -> (Sim<Observed>, Log) {
    let log: Log = Rc::default();
    let factory_log = log.clone();
    let sim = Sim::new(seed, scenario, move |spec| {
        let me = spec.index;
        Observed::new(spec, factory_log.clone(), |j| knows(me, j))
    });
    (sim, log)
}

/// The nodes `o` holds as Alive or Suspect, itself included.
fn live_set(sim: &Sim<Observed>, o: usize) -> BTreeSet<usize> {
    sim.node(o)
        .map(|n| n.node.members().map(|m| index_of(&m.name)).collect())
        .unwrap_or_default()
}

/// Steps the sim in `step`s until `done` holds or `until` passes. Returns when it held.
fn run_until_true(
    sim: &mut Sim<Observed>,
    step: Duration,
    until: Instant,
    mut done: impl FnMut(&Sim<Observed>) -> bool,
) -> Option<Instant> {
    loop {
        if done(sim) {
            return Some(sim.now());
        }
        if sim.now() >= until {
            return None;
        }
        let next = (sim.now() + step).min(until);
        sim.run_until(next);
    }
}

#[derive(Debug, Default)]
struct Measured {
    /// From the heal, the leave, the update or the join to the property holding everywhere.
    took: Vec<Duration>,
    /// Members declared dead while the partition stood, so the heal had something to repair.
    split_deaths: u64,
}

// ---------------------------------------------------------------------------------------------
// 1. A healed partition reconverges.

fn heal(seed: u64, nodes: usize) -> Result<Measured, String> {
    let cfg = config();
    let mut rng = Rng::new(seed ^ 0x4845_414c);
    let (link, loss) = random_link(&mut rng, LOSS_TOLERANCE);
    let start = ms(5_000 + rng.below(10_000));
    let length = ms(10_000 + rng.below(15_000));
    let size = 1 + rng.index(nodes / 2);
    let side: BTreeSet<usize> = pick(&mut rng, nodes, size).into_iter().collect();
    let other: Vec<usize> = (0..nodes).filter(|n| !side.contains(n)).collect();
    let healed = Instant::ZERO + start + length;
    let bound = heal_bound(&cfg, nodes);
    let scenario = Scenario::new(nodes)
        .duration(start + length + bound + secs(1))
        .link(link)
        .trace(TraceConfig::OFF)
        .at(
            start,
            Action::Partition {
                a: NodeSet::new(side.iter().copied()),
                b: other.into(),
            },
        )
        .at(start + length, Action::Heal);
    let (mut sim, log) = sim(seed, scenario, |_, _| true);
    let fail = |msg: String| {
        Err(format!(
            "seed {seed}: {msg}\nloss {loss:.4}, partition {start:?} for {length:?}, side {side:?}"
        ))
    };

    sim.run_until(healed);
    let split_deaths = log
        .borrow()
        .iter()
        .filter(|s| matches!(s.event, Event::MemberDead(_)))
        .count() as u64;
    let everyone: BTreeSet<usize> = (0..nodes).collect();
    let converged = run_until_true(&mut sim, ms(250), healed + bound, |sim| {
        (0..nodes).all(|o| live_set(sim, o) == everyone)
    });
    let Some(at) = converged else {
        let bad: Vec<String> = (0..nodes)
            .filter_map(|o| {
                let missing: Vec<usize> =
                    everyone.difference(&live_set(&sim, o)).copied().collect();
                (!missing.is_empty()).then(|| format!("{} misses {missing:?}", name_of(o)))
            })
            .take(5)
            .collect();
        return fail(format!(
            "not reconverged {bound:?} after the heal: {}",
            bad.join("; ")
        ));
    };
    Ok(Measured {
        took: vec![at - healed],
        split_deaths,
    })
}

#[test]
fn healed_partitions_reconverge() {
    let runs = check_all(0..8, |seed| heal(seed, 20));
    assert!(runs.iter().any(|r| r.split_deaths > 0));
}

#[test]
#[ignore = "slow in debug builds; CI runs it with --release"]
fn healed_partitions_reconverge_thousand_seeds() {
    let seeds = seeds(1000);
    let runs = check_all(seeds.clone(), |seed| heal(seed, 50));
    let with_deaths = runs.iter().filter(|r| r.split_deaths > 0).count();
    println!(
        "heal: {} seeds x 50 nodes reconverged ({} had deaths to repair): {}",
        seeds.end - seeds.start,
        with_deaths,
        percentiles(runs.iter().flat_map(|r| r.took.clone()).collect())
    );
}

// ---------------------------------------------------------------------------------------------
// 2. A node that left is never reported dead.

/// How long `leave()` waits by default before the driver closes the node anyway.
const LEAVE_TIMEOUT: Duration = Duration::from_secs(5);

fn leave(seed: u64, nodes: usize) -> Result<Measured, String> {
    let cfg = config();
    let mut rng = Rng::new(seed ^ 0x4c45_4156);
    let (link, loss) = random_link(&mut rng, LOSS_TOLERANCE);
    let leaver = rng.index(nodes);
    let at = ms(5_000 + rng.below(15_000));
    // Long enough for any node that missed the news to probe the leaver and declare it dead.
    let end = at + LEAVE_TIMEOUT + detection_bound(&cfg, nodes) + secs(5);
    let scenario = Scenario::new(nodes)
        .duration(end)
        .link(link)
        .trace(TraceConfig::OFF)
        .at(
            at,
            Action::Command {
                node: leaver,
                cmd: Command::Leave,
            },
        );
    let (mut sim, log) = sim(seed, scenario, |_, _| true);
    let fail = |msg: String| {
        Err(format!(
            "seed {seed}: {msg}\nloss {loss:.4}, {} leaves at {at:?}",
            name_of(leaver)
        ))
    };

    // Like a driver: leave(), wait for it, then close the node.
    let left = Instant::ZERO + at;
    sim.run_until(left);
    let done = run_until_true(&mut sim, ms(50), left + LEAVE_TIMEOUT, |_| {
        log.borrow().iter().any(|s| {
            s.observer == leaver
                && matches!(
                    s.event,
                    Event::CommandDone {
                        result: Ok(CommandOutput::Done),
                        ..
                    }
                )
        })
    });
    let Some(done) = done else {
        return fail(format!("leave took longer than {LEAVE_TIMEOUT:?}"));
    };
    sim.apply(Action::Crash(leaver));
    sim.run();

    let name = name_of(leaver);
    let mut heard = BTreeSet::new();
    for s in log.borrow().iter() {
        match &s.event {
            Event::MemberDead(m) if m.name == name => {
                return fail(format!(
                    "{} reported it dead at {:?}",
                    name_of(s.observer),
                    s.t
                ));
            }
            Event::MemberDead(m) => {
                return fail(format!(
                    "{} declared live node {} dead at {:?}",
                    name_of(s.observer),
                    m.name,
                    s.t
                ));
            }
            Event::MemberLeft(m) if m.name == name => {
                heard.insert(s.observer);
            }
            _ => {}
        }
    }
    for o in (0..nodes).filter(|&o| o != leaver) {
        if !heard.contains(&o) {
            return fail(format!("{} never heard that it left", name_of(o)));
        }
        let view = sim
            .node(o)
            .and_then(|n| n.node.member(&name).map(|m| m.state));
        if view.is_some_and(|s| s != State::Left) {
            return fail(format!("{} ends with it {view:?}", name_of(o)));
        }
    }
    Ok(Measured {
        took: vec![done - left],
        split_deaths: 0,
    })
}

#[test]
fn a_node_that_left_is_never_reported_dead() {
    check_all(0..8, |seed| leave(seed, 20));
}

#[test]
#[ignore = "slow in debug builds; CI runs it with --release"]
fn a_node_that_left_is_never_reported_dead_thousand_seeds() {
    let seeds = seeds(1000);
    let runs = check_all(seeds.clone(), |seed| leave(seed, 50));
    println!(
        "leave: {} seeds x 50 nodes, never reported dead; leave() took {}",
        seeds.end - seeds.start,
        percentiles(runs.iter().flat_map(|r| r.took.clone()).collect())
    );
}

// ---------------------------------------------------------------------------------------------
// 3. Metadata reaches every node.

fn metadata(seed: u64, nodes: usize) -> Result<Measured, String> {
    let cfg = config();
    let mut rng = Rng::new(seed ^ 0x4d45_5441);
    let (link, loss) = random_link(&mut rng, MAX_LOSS);
    let k = 1 + rng.index(3);
    let setters = pick(&mut rng, nodes, k);
    let mut updates: Vec<(Instant, usize, Vec<u8>)> = setters
        .iter()
        .map(|&n| {
            let at = Instant::ZERO + ms(5_000 + rng.below(30_000));
            let len = rng.index(cfg.limits.max_meta_bytes + 1);
            let mut meta = format!("v={seed}/{n};").into_bytes();
            meta.resize(len.max(meta.len()), b'x');
            (at, n, meta)
        })
        .collect();
    updates.sort();
    let bound = dissemination_bound(&cfg, nodes);
    let last = updates.last().map_or(Instant::ZERO, |u| u.0);
    let mut scenario = Scenario::new(nodes)
        .duration(last - Instant::ZERO + bound + secs(1))
        .link(link)
        .trace(TraceConfig::OFF);
    for (at, node, meta) in &updates {
        scenario = scenario.at(
            *at - Instant::ZERO,
            Action::Command {
                node: *node,
                cmd: Command::SetMeta(meta.clone()),
            },
        );
    }
    let (mut sim, _log) = sim(seed, scenario, |_, _| true);
    let fail = |msg: String| Err(format!("seed {seed}: {msg}\nloss {loss:.4}, {updates:?}"));

    // Every node, for every update, until it holds the new metadata.
    let mut pending: Vec<(Instant, usize, &[u8], BTreeSet<usize>)> = updates
        .iter()
        .map(|(at, n, meta)| (*at, *n, &meta[..], (0..nodes).filter(|o| o != n).collect()))
        .collect();
    let mut took = Vec::new();
    while sim.now() < sim.end() {
        if sim.now() >= last && pending.iter().all(|p| p.3.is_empty()) {
            break;
        }
        sim.run_for(ms(100));
        let now = sim.now();
        for (at, setter, meta, waiting) in &mut pending {
            if now < *at {
                continue;
            }
            let name = name_of(*setter);
            waiting.retain(|&o| {
                let view = sim.node(o).and_then(|n| n.node.member(&name));
                let has = view.is_some_and(|m| m.meta == *meta && m.state.is_live());
                if has {
                    took.push(now - *at);
                }
                !has
            });
            if let Some(&o) = waiting.first() {
                if now - *at > bound {
                    return fail(format!(
                        "{} lacks {name}'s metadata {bound:?} after the update",
                        name_of(o)
                    ));
                }
            }
        }
    }
    Ok(Measured {
        took,
        split_deaths: 0,
    })
}

/// Checks that gossip alone delivered at least 99% of the updates in `runs`, and returns the
/// share it did.
fn mostly_by_gossip(runs: &[Measured], nodes: usize) -> f64 {
    let bound = gossip_bound(&config(), nodes);
    let took: Vec<Duration> = runs.iter().flat_map(|r| r.took.clone()).collect();
    let fast = took.iter().filter(|&&d| d <= bound).count();
    let share = fast as f64 / took.len() as f64;
    assert!(
        share >= 0.99,
        "only {fast} of {} deliveries arrived within {bound:?}",
        took.len()
    );
    share
}

#[test]
fn metadata_updates_reach_every_node() {
    let runs = check_all(0..8, |seed| metadata(seed, 20));
    mostly_by_gossip(&runs, 20);
}

#[test]
#[ignore = "slow in debug builds; CI runs it with --release"]
fn metadata_updates_reach_every_node_thousand_seeds() {
    let seeds = seeds(1000);
    let runs = check_all(seeds.clone(), |seed| metadata(seed, 50));
    let share = mostly_by_gossip(&runs, 50);
    println!(
        "metadata: {} seeds x 50 nodes, every update reached every node within {:?}, {:.3}% \
         by gossip within {:?}: {}",
        seeds.end - seeds.start,
        dissemination_bound(&config(), 50),
        share * 100.0,
        gossip_bound(&config(), 50),
        percentiles(runs.iter().flat_map(|r| r.took.clone()).collect())
    );
}

// ---------------------------------------------------------------------------------------------
// 4. A new node joins a large cluster.

fn join(seed: u64, nodes: usize) -> Result<Measured, String> {
    let cfg = config();
    let mut rng = Rng::new(seed ^ 0x4a4f_494e);
    let (link, loss) = random_link(&mut rng, LOSS_TOLERANCE);
    // The last node is new: it knows nobody, and nobody knows it.
    let newcomer = nodes - 1;
    let k = 1 + rng.index(3);
    let seed_nodes = pick(&mut rng, newcomer, k);
    // Sometimes a seed is down, so the join has to do without it.
    let down = (seed_nodes.len() > 1 && rng.chance(0.5)).then(|| seed_nodes[0]);
    let at = ms(2_000 + rng.below(8_000));
    let bound = dissemination_bound(&cfg, nodes);
    let mut scenario = Scenario::new(nodes)
        .duration(at + bound + cfg.tcp_timeout + secs(1))
        .link(link)
        .trace(TraceConfig::OFF)
        .at(
            at,
            Action::Command {
                node: newcomer,
                cmd: Command::Join {
                    seeds: seed_nodes
                        .iter()
                        .map(|&s| kinship_sim::addr_of(s))
                        .collect(),
                },
            },
        );
    if let Some(d) = down {
        scenario = scenario.at(Duration::ZERO, Action::Crash(d));
    }
    let (mut sim, log) = sim(seed, scenario, move |me, j| me != newcomer && j != newcomer);
    let fail = |msg: String| {
        Err(format!(
            "seed {seed}: {msg}\nloss {loss:.4}, join at {at:?} via {seed_nodes:?}, down {down:?}"
        ))
    };

    let joined_at = Instant::ZERO + at;
    sim.run_until(joined_at);
    let running: BTreeSet<usize> = (0..nodes).filter(|&o| Some(o) != down).collect();
    let converged = run_until_true(&mut sim, ms(100), joined_at + bound, |sim| {
        live_set(sim, newcomer).is_superset(&running)
            && running
                .iter()
                .all(|&o| live_set(sim, o).contains(&newcomer))
    });
    let Some(t) = converged else {
        let missing: Vec<usize> = running
            .difference(&live_set(&sim, newcomer))
            .copied()
            .collect();
        let unaware = running
            .iter()
            .filter(|&&o| !live_set(&sim, o).contains(&newcomer))
            .count();
        return fail(format!(
            "not converged {bound:?} after the join: the newcomer misses {} members, {unaware} \
             members miss it",
            missing.len()
        ));
    };
    // A seed that is down holds the result back until its connect fails.
    let answered = || {
        log.borrow().iter().find_map(|s| match s.event {
            Event::CommandDone {
                result: Ok(CommandOutput::Joined { seeds }),
                ..
            } if s.observer == newcomer => Some(seeds),
            _ => None,
        })
    };
    let until = joined_at + cfg.tcp_timeout + secs(1);
    run_until_true(&mut sim, ms(100), until, |_| answered().is_some());
    let answered = answered();
    let expected = seed_nodes.len() - usize::from(down.is_some());
    if answered != Some(expected) {
        return fail(format!(
            "join reported {answered:?} seeds, expected {expected}"
        ));
    }
    Ok(Measured {
        took: vec![t - joined_at],
        split_deaths: 0,
    })
}

#[test]
fn a_new_node_joins_and_converges() {
    check_all(0..4, |seed| join(seed, 50));
}

#[test]
#[ignore = "slow in debug builds; CI runs it with --release"]
fn a_new_node_joins_a_200_node_cluster_thousand_seeds() {
    let seeds = seeds(1000);
    let runs = check_all(seeds.clone(), |seed| join(seed, 200));
    println!(
        "join: {} seeds, a new node joined 200 and converged: {}",
        seeds.end - seeds.start,
        percentiles(runs.iter().flat_map(|r| r.took.clone()).collect())
    );
}
