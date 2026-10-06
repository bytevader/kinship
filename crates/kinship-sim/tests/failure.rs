//! Seeded tests of the failure modes in `docs/design.md` that no other sweep covers.
//!
//! 1. A node that crashes and restarts with the same name starts again at incarnation 0. Its
//!    join's push-pull reply tells it the incarnation the cluster remembers, it refutes above
//!    it, and it ends Alive everywhere, without anyone reporting it dead after the restart. The
//!    restart comes either before anyone suspected it, or once every node holds its tombstone.
//! 2. A second live node that takes a member's name at another address never takes the name
//!    over: no node applies its Alive, NameConflict fires on both nodes that claim the name,
//!    each naming the other's address, and the original stays a member everywhere.
//! 3. A node whose clock jumps forward, alone or after a suspend, absorbs the jump: a probe
//!    round the jump cut short raises its local health and suspects a healthy target, which
//!    refutes, and no node is ever declared dead.
//! 4. A partition that outlasts `dead_reclaim` leaves no tombstones to reconnect to: after the
//!    heal the two sides stay apart, and one `join()` through a seed on the other side merges
//!    them again.
//!
//! Each property has a quick test over a few seeds and an ignored sweep over 1,000 that CI runs
//! with `cargo test --release -p kinship-sim --test failure -- --ignored --nocapture`.
//! `KINSHIP_SEED=<seed>` replays one seed and `KINSHIP_SEEDS` changes the count.

mod common;

use std::collections::BTreeSet;
use std::rc::Rc;
use std::time::Duration;

use common::{Log, Observed, check_all, config, index_of, ms, percentiles, secs, seeds};
use kinship_core::{Command, CommandOutput, Config, Event, Instant, Rng, State};
use kinship_sim::{
    Action, Delay, LinkConfig, NodeSpec, Scenario, Sim, TraceConfig, addr_of, name_of,
};

/// Loss core SWIM tolerates without a false death; runs that must have none stay within it.
const LOSS_TOLERANCE: f64 = 0.01;

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

fn pick(rng: &mut Rng, from: &[usize], k: usize) -> Vec<usize> {
    let mut all = from.to_vec();
    rng.shuffle(&mut all);
    all.truncate(k);
    all
}

/// `retransmit_mult x ceil(log10(n + 1))`, as the core computes it.
fn retransmit_limit(cfg: &Config, n: usize) -> u32 {
    let digits = (n as f64 + 1.0).log10().ceil() as u32;
    cfg.retransmit_mult * digits
}

/// How long a rumour takes to reach every node: gossip, then for any node it missed, that
/// node's next push-pull. The sync tests derive it.
fn dissemination_bound(cfg: &Config, n: usize) -> Duration {
    cfg.gossip_interval * retransmit_limit(cfg, n)
        + cfg.probe_interval * 2
        + secs(1)
        + cfg.push_pull_interval
}

/// `suspicion_mult x max(1, log10 n) x probe_interval`, rounded up to the millisecond.
fn suspicion_timeout(cfg: &Config, n: usize) -> Duration {
    let scale = (n as f64).log10().max(1.0);
    let s = cfg.probe_interval.as_secs_f64() * f64::from(cfg.suspicion_mult) * scale;
    Duration::from_millis((s * 1000.0).ceil() as u64)
}

/// The longest a suspicion can run: one started now that nobody refutes ends by then.
fn longest_suspicion(cfg: &Config, n: usize) -> Duration {
    suspicion_timeout(cfg, n) * cfg.suspicion_max_mult
}

/// The longest a crash can go undetected, as in the SWIM sweep: two passes of the probe list
/// and a round, the suspicion timeout, and two seconds of slack.
fn detection_bound(cfg: &Config, n: usize) -> Duration {
    let rounds = 2 * (n as u32 - 1) + 1;
    cfg.probe_interval * rounds + suspicion_timeout(cfg, n) + secs(2)
}

/// Builds the sim with `make` building each node, every node logging into the returned log.
fn sim(
    seed: u64,
    scenario: Scenario<Command>,
    make: impl Fn(&NodeSpec, Log) -> Observed + 'static,
) -> (Sim<Observed>, Log) {
    let log: Log = Rc::default();
    let factory_log = log.clone();
    let sim = Sim::new(seed, scenario, move |spec| make(spec, factory_log.clone()));
    (sim, log)
}

/// The nodes `o` holds as Alive or Suspect, itself included.
fn live_set(sim: &Sim<Observed>, o: usize) -> BTreeSet<usize> {
    sim.node(o)
        .map(|n| n.node.members().map(|m| index_of(&m.name)).collect())
        .unwrap_or_default()
}

/// How `o` sees the member called `name`: its state, incarnation and address.
fn view(sim: &Sim<Observed>, o: usize, name: &str) -> Option<(State, u32, std::net::SocketAddr)> {
    let m = sim.node(o)?.node.member(name)?;
    Some((m.state, m.incarnation, m.addr))
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

/// The first MemberDead in the log at or after `since`, as (observer, member, when).
fn first_death(log: &Log, since: Instant) -> Option<(usize, String, Instant)> {
    log.borrow().iter().find_map(|s| match &s.event {
        Event::MemberDead(m) if s.t >= since => Some((s.observer, m.name.clone(), s.t)),
        _ => None,
    })
}

#[derive(Debug, Default)]
struct Measured {
    /// From the restart, the conflicting join or the jump to the property holding everywhere.
    took: Vec<Duration>,
    /// The restart came after every node held the tombstone.
    tombstone: bool,
    /// Nodes that reported the name conflict.
    conflicts: usize,
    /// The jump ended a probe round before its Ack arrived.
    cut_short: bool,
}

// ---------------------------------------------------------------------------------------------
// 1. A node restarts with the same name.

fn restart(seed: u64, nodes: usize) -> Result<Measured, String> {
    let cfg = config();
    let mut rng = Rng::new(seed ^ 0x5245_5354);
    let (link, loss) = random_link(&mut rng, LOSS_TOLERANCE);
    let r = rng.index(nodes);
    let name = name_of(r);
    let others: Vec<usize> = (0..nodes).filter(|&o| o != r).collect();
    let k = 1 + rng.index(3);
    let seed_nodes = pick(&mut rng, &others, k);
    let tombstone = rng.chance(0.5);
    // Metadata changes raise its incarnation, so the restart has something to learn. They
    // finish spreading before the crash, so every node remembers the same incarnation.
    let changes = 1 + rng.index(4);
    let mut scenario = Scenario::new(nodes).link(link).trace(TraceConfig::OFF);
    for i in 0..changes {
        let meta = format!("v={i}").into_bytes();
        scenario = scenario.at(
            ms(1_000 + rng.below(4_000)),
            Action::Command {
                node: r,
                cmd: Command::SetMeta(meta),
            },
        );
    }
    let crash_at = Instant::ZERO + secs(5) + dissemination_bound(&cfg, nodes);
    // Without a tombstone, it comes back before its first suspicion could expire.
    let quick_by = crash_at + ms(rng.below(2_000));
    let settle = dissemination_bound(&cfg, nodes) + longest_suspicion(&cfg, nodes) + secs(5);
    let scenario = scenario.duration(
        crash_at - Instant::ZERO + detection_bound(&cfg, nodes) * 2 + cfg.tcp_timeout + settle,
    );
    // A restarted instance knows nobody: it joins through its seeds like a new node.
    let (mut sim, log) = sim(seed, scenario, |spec, log| {
        let fresh = spec.now == Instant::ZERO;
        Observed::new(spec, log, move |_| fresh)
    });
    let fail = |msg: String| {
        Err(format!(
            "seed {seed}: {msg}\nloss {loss:.4}, {name} restarts via {seed_nodes:?}, \
             tombstone {tombstone}"
        ))
    };

    sim.run_until(crash_at);
    let old = sim.node(r).map_or(0, |n| n.node.local().incarnation);
    if old < changes as u32 {
        return fail(format!("only reached incarnation {old} before the crash"));
    }
    if let Some((o, m, t)) = first_death(&log, Instant::ZERO) {
        return fail(format!(
            "{} declared live node {m} dead at {t:?}",
            name_of(o)
        ));
    }
    sim.apply(Action::Crash(r));

    if tombstone {
        // Every suspicion has run out: each node holds the tombstone, or already reaped it.
        let until = crash_at + detection_bound(&cfg, nodes) * 2;
        let all_dead = run_until_true(&mut sim, ms(100), until, |sim| {
            others
                .iter()
                .all(|&o| view(sim, o, &name).is_none_or(|v| v.0 == State::Dead))
        });
        if all_dead.is_none() {
            return fail(format!(
                "not dead everywhere {:?} after the crash",
                until - crash_at
            ));
        }
        let wait = sim.now() + ms(rng.below(3_000));
        sim.run_until(wait);
    } else {
        // Back before anyone suspects it, or as soon as someone does.
        run_until_true(&mut sim, ms(10), quick_by, |_| {
            log.borrow().iter().any(|s| {
                s.t >= crash_at && matches!(&s.event, Event::MemberSuspect(m) if m.name == name)
            })
        });
    }

    let restarted = sim.now();
    sim.apply(Action::Restart(r));
    sim.apply(Action::Command {
        node: r,
        cmd: Command::Join {
            seeds: seed_nodes.iter().map(|&s| addr_of(s)).collect(),
        },
    });
    if sim.node(r).map(|n| n.node.local().incarnation) != Some(0) {
        return fail("the restarted node does not start at incarnation 0".into());
    }
    let joined = || {
        log.borrow().iter().find_map(|s| match s.event {
            Event::CommandDone {
                result: Ok(CommandOutput::Joined { seeds }),
                ..
            } if s.observer == r && s.t >= restarted => Some(seeds),
            _ => None,
        })
    };
    let done = run_until_true(&mut sim, ms(10), restarted + cfg.tcp_timeout, |_| {
        joined().is_some()
    });
    if done.is_none() || joined() == Some(0) {
        return fail(format!("the join did not reach a seed: {:?}", joined()));
    }
    let learned = sim.node(r).map_or(0, |n| n.node.local().incarnation);
    if learned <= old {
        return fail(format!(
            "joined at incarnation {learned}, not above its old {old}"
        ));
    }

    let everyone: BTreeSet<usize> = (0..nodes).collect();
    let until = restarted + dissemination_bound(&cfg, nodes);
    let converged = run_until_true(&mut sim, ms(100), until, |sim| {
        live_set(sim, r) == everyone
            && others.iter().all(|&o| {
                view(sim, o, &name)
                    .is_some_and(|v| v.0 == State::Alive && v.1 > old && v.2 == addr_of(r))
            })
    });
    let Some(at) = converged else {
        let bad: Vec<String> = others
            .iter()
            .filter_map(|&o| {
                let v = view(&sim, o, &name);
                v.is_none_or(|v| v.0 != State::Alive || v.1 <= old)
                    .then(|| format!("{} holds {v:?}", name_of(o)))
            })
            .take(5)
            .collect();
        return fail(format!(
            "not Alive everywhere {:?} after the restart: {}; it sees {:?}",
            until - restarted,
            bad.join("; "),
            live_set(&sim, r)
        ));
    };
    // Long enough for any suspicion still running when it came back to have expired.
    sim.run_until(restarted + settle);
    for s in log.borrow().iter() {
        let Event::MemberDead(m) = &s.event else {
            continue;
        };
        // Only the crash itself may be reported, and only before the restart.
        let expected = tombstone && m.name == name && s.t >= crash_at && s.t < restarted;
        if !expected {
            return fail(format!(
                "{} reported {} dead at {:?}",
                name_of(s.observer),
                m.name,
                s.t
            ));
        }
    }
    for &o in &others {
        let v = view(&sim, o, &name);
        if v.is_none_or(|v| v.0 != State::Alive) {
            return fail(format!("{} ends with it {v:?}", name_of(o)));
        }
    }
    Ok(Measured {
        took: vec![at - restarted],
        tombstone,
        ..Measured::default()
    })
}

#[test]
fn a_restarted_node_learns_its_incarnation_and_rejoins() {
    let runs = check_all(0..8, |seed| restart(seed, 20));
    assert!(runs.iter().any(|r| r.tombstone) && runs.iter().any(|r| !r.tombstone));
}

#[test]
#[ignore = "slow in debug builds; CI runs it with --release"]
fn a_restarted_node_learns_its_incarnation_and_rejoins_thousand_seeds() {
    let seeds = seeds(1000);
    let runs = check_all(seeds.clone(), |seed| restart(seed, 50));
    let tombstones = runs.iter().filter(|r| r.tombstone).count();
    println!(
        "restart: {} seeds x 50 nodes ({tombstones} after the tombstone spread), never reported \
         dead after the restart, Alive everywhere: {}",
        seeds.end - seeds.start,
        percentiles(runs.iter().flat_map(|r| r.took.clone()).collect())
    );
}

// ---------------------------------------------------------------------------------------------
// 2. A second live node takes a member's name.

fn conflict(seed: u64, nodes: usize) -> Result<Measured, String> {
    let cfg = config();
    let mut rng = Rng::new(seed ^ 0x4e41_4d45);
    let (link, loss) = random_link(&mut rng, LOSS_TOLERANCE);
    // The last node is the impostor: it calls itself after a live member, at its own address.
    let impostor = nodes - 1;
    let victim = rng.index(impostor);
    let name = name_of(victim);
    let (original, other) = (addr_of(victim), addr_of(impostor));
    let members: Vec<usize> = (0..impostor).collect();
    let rest: Vec<usize> = members.iter().copied().filter(|&o| o != victim).collect();
    // It joins through the original, so both claimants meet, and maybe through others too.
    let mut seed_nodes = vec![victim];
    let k = rng.index(3);
    seed_nodes.extend(pick(&mut rng, &rest, k));
    // Sometimes it has raised its incarnation above the original's, so its Alive would win
    // on incarnation alone.
    let bumps = rng.index(4);
    let at = ms(5_000 + rng.below(10_000));
    let bound = dissemination_bound(&cfg, nodes);
    let mut scenario = Scenario::new(nodes)
        .duration(at + bound + secs(1))
        .link(link)
        .trace(TraceConfig::OFF);
    for i in 0..bumps {
        scenario = scenario.at(
            ms(1_000 + 100 * i as u64),
            Action::Command {
                node: impostor,
                cmd: Command::SetMeta(format!("bump={i}").into_bytes()),
            },
        );
    }
    let scenario = scenario.at(
        at,
        Action::Command {
            node: impostor,
            cmd: Command::Join {
                seeds: seed_nodes.iter().map(|&s| addr_of(s)).collect(),
            },
        },
    );
    let (mut sim, log) = sim(seed, scenario, move |spec, log| {
        if spec.index == impostor {
            Observed::with_name(spec, &name_of(victim), config(), log, |_| false)
        } else {
            Observed::new(spec, log, |j| j != impostor)
        }
    });
    let fail = |msg: String| {
        Err(format!(
            "seed {seed}: {msg}\nloss {loss:.4}, {} at {other} takes {name} at {original} via \
             {seed_nodes:?} at incarnation {bumps}",
            name_of(impostor)
        ))
    };

    let joined = Instant::ZERO + at;
    sim.run_until(joined);
    // Both claimants hear of each other through the join's push-pull.
    let both = run_until_true(&mut sim, ms(10), joined + cfg.tcp_timeout, |_| {
        let log = log.borrow();
        let saw = |o: usize| {
            log.iter()
                .any(|s| s.observer == o && matches!(s.event, Event::NameConflict { .. }))
        };
        saw(victim) && saw(impostor)
    });
    if both.is_none() {
        return fail("the claimants did not both report the conflict".into());
    }
    sim.run();

    let mut conflicts = BTreeSet::new();
    for s in log.borrow().iter() {
        let by = name_of(s.observer);
        match &s.event {
            Event::NameConflict { member, other_addr } => {
                // The impostor's own view is the losing claim; everyone else's is the original.
                let (mine, theirs) = if s.observer == impostor {
                    (other, original)
                } else {
                    (original, other)
                };
                if member.name != name || member.addr != mine || *other_addr != theirs {
                    return fail(format!(
                        "{by} reported {} at {} against {other_addr}",
                        member.name, member.addr
                    ));
                }
                conflicts.insert(s.observer);
            }
            Event::MemberDead(m) => {
                return fail(format!(
                    "{by} declared live node {} dead at {:?}",
                    m.name, s.t
                ));
            }
            Event::MemberJoined(m)
            | Event::MemberRecovered(m)
            | Event::MemberUpdated { member: m, .. }
                if s.observer != impostor && m.name == name && m.addr == other =>
            {
                return fail(format!("{by} applied {m:?} at {:?}", s.t));
            }
            _ => {}
        }
    }
    // The original keeps the name everywhere, its own view included, and stays a member.
    for &o in &members {
        let v = view(&sim, o, &name);
        if v.is_none_or(|v| v.0 != State::Alive || v.2 != original) {
            return fail(format!("{} ends with {name} as {v:?}", name_of(o)));
        }
    }
    Ok(Measured {
        took: vec![both.unwrap_or(joined) - joined],
        conflicts: conflicts.len(),
        ..Measured::default()
    })
}

#[test]
fn a_second_node_with_a_live_name_never_takes_it() {
    check_all(0..8, |seed| conflict(seed, 20));
}

#[test]
#[ignore = "slow in debug builds; CI runs it with --release"]
fn a_second_node_with_a_live_name_never_takes_it_thousand_seeds() {
    let seeds = seeds(1000);
    let runs = check_all(seeds.clone(), |seed| conflict(seed, 50));
    let reports: Vec<usize> = runs.iter().map(|r| r.conflicts).collect();
    println!(
        "name conflict: {} seeds x 50 nodes, the original kept its name everywhere; reported by \
         {} to {} nodes, both claimants within {}",
        seeds.end - seeds.start,
        reports.iter().min().unwrap_or(&0),
        reports.iter().max().unwrap_or(&0),
        percentiles(runs.iter().flat_map(|r| r.took.clone()).collect())
    );
}

// ---------------------------------------------------------------------------------------------
// 3. A node's clock jumps forward.

fn jump(seed: u64, nodes: usize) -> Result<Measured, String> {
    let cfg = config();
    let mut rng = Rng::new(seed ^ 0x4a55_4d50);
    // No loss, so any suspicion is the jump's doing.
    let (link, _) = random_link(&mut rng, 0.0);
    let j = rng.index(nodes);
    let by = ms(1_000 + rng.below(119_000));
    // Half the time the node is frozen first, as a suspended process is, and its clock jumps
    // when it resumes; otherwise the clock jumps while one of its Pings is in flight.
    let suspend = rng.chance(0.5).then(|| ms(100 + rng.below(1_900)));
    let start = Instant::ZERO + ms(5_000 + rng.below(10_000));
    let settle = dissemination_bound(&cfg, nodes) + longest_suspicion(&cfg, nodes) + secs(5);
    let scenario = Scenario::new(nodes)
        .duration(start - Instant::ZERO + secs(5) + settle)
        .link(link)
        .trace(TraceConfig::OFF);
    let (mut sim, log) = sim(seed, scenario, |spec, log| {
        Observed::new(spec, log, |_| true)
    });
    let fail = |msg: String| {
        Err(format!(
            "seed {seed}: {msg}\n{} jumps {by:?} at {start:?}, suspended {suspend:?}",
            name_of(j)
        ))
    };
    let counters = |sim: &Sim<Observed>| {
        let n = &sim.node(j).expect("never crashed").node;
        (n.metrics().probes_sent, n.metrics().probes_failed)
    };

    sim.run_until(start);
    match suspend {
        Some(d) => {
            sim.apply(Action::Pause {
                node: j,
                duration: d,
            });
            // The jump lands just before the node resumes, so it handles its backlog late.
            sim.run_until(Instant::from_nanos((start + d).as_nanos() - 1));
        }
        None => {
            let (sent, _) = counters(&sim);
            let until = start + cfg.probe_interval * (cfg.awareness_max + 1);
            if run_until_true(&mut sim, Duration::from_micros(50), until, |sim| {
                counters(sim).0 > sent
            })
            .is_none()
            {
                return fail("the node never started a probe round".into());
            }
        }
    }
    let jumped = sim.now();
    let (sent, failed) = counters(&sim);
    sim.apply(Action::ClockJump { node: j, by });
    // A round the jump cut short ends at once on the node's new clock, or as it resumes.
    sim.run_until(suspend.map_or(jumped, |d| start + d));
    let cut_short = counters(&sim).1 > failed;
    // The node logs at its own time, which now runs `by` ahead.
    let suspected = log.borrow().iter().find_map(|s| match &s.event {
        Event::MemberSuspect(m) if s.observer == j && s.t >= jumped + by => Some(m.name.clone()),
        _ => None,
    });
    let health = sim.node(j).map_or(0, |n| n.node.local_health());
    if cut_short && (health == 0 || suspected.is_none()) {
        return fail(format!(
            "a cut-short round left local health {health} and suspected {suspected:?}"
        ));
    }

    let until = jumped + dissemination_bound(&cfg, nodes);
    let all_alive = |sim: &Sim<Observed>| {
        (0..nodes).all(|o| {
            sim.node(o).is_some_and(|n| {
                n.node.members().count() == nodes
                    && n.node.members().all(|m| m.state == State::Alive)
            })
        })
    };
    let Some(at) = run_until_true(&mut sim, ms(100), until, all_alive) else {
        let bad: Vec<String> = (0..nodes)
            .filter_map(|o| {
                let n = &sim.node(o)?.node;
                let off: Vec<String> = n
                    .members()
                    .filter(|m| m.state != State::Alive)
                    .map(|m| m.name.clone())
                    .collect();
                (n.members().count() != nodes || !off.is_empty())
                    .then(|| format!("{} suspects {off:?}", name_of(o)))
            })
            .take(5)
            .collect();
        return fail(format!(
            "not all Alive {:?} after the jump: {}",
            until - jumped,
            bad.join("; ")
        ));
    };
    sim.run_until(jumped + settle);
    if let Some((o, m, t)) = first_death(&log, Instant::ZERO) {
        return fail(format!(
            "{} declared live node {m} dead at {t:?}",
            name_of(o)
        ));
    }
    if let Some(target) = &suspected {
        let refuted = sim
            .node(index_of(target))
            .map_or(0, |n| n.node.metrics().refutations);
        if refuted == 0 {
            return fail(format!("{target} was suspected but never refuted"));
        }
    }
    // It kept probing on its new clock, at most `awareness_max + 1` intervals per round.
    let rounds = counters(&sim).0 - sent;
    let expected = settle.as_secs() / u64::from(cfg.awareness_max + 1);
    if rounds < expected {
        return fail(format!("only {rounds} probe rounds after the jump"));
    }
    if !all_alive(&sim) {
        return fail("not all Alive at the end".into());
    }
    Ok(Measured {
        took: vec![at - jumped],
        cut_short,
        ..Measured::default()
    })
}

#[test]
fn a_clock_jump_is_absorbed_without_a_false_death() {
    let runs = check_all(0..8, |seed| jump(seed, 20));
    assert!(runs.iter().any(|r| r.cut_short));
}

#[test]
#[ignore = "slow in debug builds; CI runs it with --release"]
fn a_clock_jump_is_absorbed_without_a_false_death_thousand_seeds() {
    let seeds = seeds(1000);
    let runs = check_all(seeds.clone(), |seed| jump(seed, 50));
    let cut = runs.iter().filter(|r| r.cut_short).count();
    println!(
        "clock jump: {} seeds x 50 nodes, no false deaths; {cut} jumps cut a probe round short \
         and the target refuted; everyone Alive again within {}",
        seeds.end - seeds.start,
        percentiles(runs.iter().flat_map(|r| r.took.clone()).collect())
    );
}

// ---------------------------------------------------------------------------------------------
// 4. A partition outlasts the tombstones.

/// The longest a node on one side of a partition can take to declare a node on the other side
/// dead, as in the SWIM sweep: the minority side's missing Nacks stretch its rounds to
/// `awareness_max + 1` probe intervals, and few members are left to confirm a suspicion.
fn partition_bound(cfg: &Config, n: usize) -> Duration {
    let rounds = 2 * (n as u32 - 1) + 1;
    cfg.probe_interval * rounds * (cfg.awareness_max + 1) + longest_suspicion(cfg, n) + secs(2)
}

fn long_partition(seed: u64, nodes: usize) -> Result<Measured, String> {
    let cfg = config();
    let mut rng = Rng::new(seed ^ 0x4c4f_4e47);
    // No loss, so nobody loses a member of its own side: the split is the partition's alone.
    let (link, _) = random_link(&mut rng, 0.0);
    let all: Vec<usize> = (0..nodes).collect();
    let size = 1 + rng.index(nodes / 2);
    let side: BTreeSet<usize> = pick(&mut rng, &all, size).into_iter().collect();
    let other: Vec<usize> = all.iter().copied().filter(|n| !side.contains(n)).collect();
    let across = |o: usize| -> Vec<usize> {
        if side.contains(&o) {
            other.clone()
        } else {
            side.iter().copied().collect()
        }
    };
    // Some node joins through a seed on the other side, as a timer calling join() would.
    let joiner = rng.index(nodes);
    let seed_node = pick(&mut rng, &across(joiner), 1)[0];
    let start = ms(5_000 + rng.below(5_000));
    // Every node has declared the other side dead and reaped the tombstones by then.
    let forget_bound = partition_bound(&cfg, nodes)
        + cfg.dead_reclaim
        + cfg.probe_interval * (cfg.awareness_max + 1);
    let apart = cfg.reconnect_interval.max(cfg.push_pull_interval) * 2;
    // The join's two ends gossip what they learned, but the members their side already knew
    // are news only to the far side, which hears of them from the seed's own gossip and
    // otherwise from push-pull with a member that has. That can take a few rounds of
    // anti-entropy.
    let bound = dissemination_bound(&cfg, nodes) + cfg.push_pull_interval * 3;
    let scenario = Scenario::new(nodes)
        .duration(start + forget_bound + apart + bound + secs(1))
        .link(link)
        .trace(TraceConfig::OFF)
        .at(
            start,
            Action::Partition {
                a: side.iter().copied().collect::<Vec<_>>().into(),
                b: other.clone().into(),
            },
        );
    let (mut sim, log) = sim(seed, scenario, |spec, log| {
        Observed::new(spec, log, |_| true)
    });
    let fail = |msg: String| {
        Err(format!(
            "seed {seed}: {msg}\nside {side:?} split at {start:?}, {} joins via {}",
            name_of(joiner),
            name_of(seed_node)
        ))
    };
    let forgot = |sim: &Sim<Observed>| {
        all.iter().all(|&o| {
            across(o)
                .iter()
                .all(|&x| view(sim, o, &name_of(x)).is_none())
        })
    };

    let split = Instant::ZERO + start;
    sim.run_until(split);
    if run_until_true(&mut sim, secs(1), split + forget_bound, forgot).is_none() {
        return fail(format!(
            "the other side's tombstones not all reaped {forget_bound:?} after the split"
        ));
    }
    sim.apply(Action::Heal);
    let healed = sim.now();
    // Reconnects only go to tombstones, so nothing finds the other side on its own.
    sim.run_until(healed + apart);
    if !forgot(&sim) {
        return fail(format!(
            "the sides met within {apart:?} of the heal without a join"
        ));
    }
    sim.apply(Action::Command {
        node: joiner,
        cmd: Command::Join {
            seeds: vec![addr_of(seed_node)],
        },
    });
    let joined = sim.now();
    let everyone: BTreeSet<usize> = all.iter().copied().collect();
    let merged = run_until_true(&mut sim, ms(250), joined + bound, |sim| {
        all.iter().all(|&o| live_set(sim, o) == everyone)
    });
    let Some(at) = merged else {
        let bad: Vec<String> = all
            .iter()
            .filter_map(|&o| {
                let missing: Vec<usize> =
                    everyone.difference(&live_set(&sim, o)).copied().collect();
                (!missing.is_empty()).then(|| format!("{} misses {missing:?}", name_of(o)))
            })
            .take(5)
            .collect();
        return fail(format!(
            "not merged {bound:?} after the join: {}",
            bad.join("; ")
        ));
    };
    for s in log.borrow().iter() {
        if let Event::MemberDead(m) = &s.event {
            if side.contains(&s.observer) == side.contains(&index_of(&m.name)) {
                return fail(format!(
                    "{} declared {}, on its own side, dead at {:?}",
                    name_of(s.observer),
                    m.name,
                    s.t
                ));
            }
        }
    }
    Ok(Measured {
        took: vec![at - joined],
        ..Measured::default()
    })
}

#[test]
fn a_partition_longer_than_dead_reclaim_needs_a_join() {
    check_all(0..4, |seed| long_partition(seed, 20));
}

#[test]
#[ignore = "slow in debug builds; CI runs it with --release"]
fn a_partition_longer_than_dead_reclaim_needs_a_join_thousand_seeds() {
    let seeds = seeds(1000);
    let runs = check_all(seeds.clone(), |seed| long_partition(seed, 50));
    println!(
        "long partition: {} seeds x 50 nodes, the sides stayed apart after the heal until one \
         join merged them: {}",
        seeds.end - seeds.start,
        percentiles(runs.iter().flat_map(|r| r.took.clone()).collect())
    );
}
