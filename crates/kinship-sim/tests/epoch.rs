//! Epochs, which name each life of a member: a node that restarts starts a later life, which
//! replaces the old one whatever the incarnations, and nothing about an earlier life changes a
//! later one. `failure::a_restarted_node_replaces_its_old_life_at_a_lower_incarnation` covers
//! the restart itself; these cover the rest:
//!
//! 1. A member gossips rumours about a restarted member's earlier life, as a node that missed
//!    the restart or a recording would carry them, at incarnations far above the new life's:
//!    a Suspect and a Dead while the new life runs, then, once it has died, an Alive. None of
//!    them suspects, kills or brings back the new life. The same rumours about the current
//!    life do, which shows they were delivered.
//! 2. Nodes older than 0.3 share the cluster with newer ones. They drop the epoch from
//!    everything they receive, as an older decoder skips the field, and send none, so their
//!    members have epoch 0 everywhere. A newer node restarts at a lower incarnation, which
//!    they cannot see as a new life; it learns its old incarnation and refutes above it for
//!    them, and nobody declares it, or anyone, dead.
//!
//! Each test runs a few fixed seeds; `KINSHIP_SEED=<seed>` replays one, and the
//! `_thousand_seeds` sweeps run 1,000 in release mode in CI, once in mode `off` and once with
//! every node that has an epoch in mode `sign`.

mod common;

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Duration;

use common::{Log, Mode, Observed, check_all, config, ms, percentiles, secs, seeds};
use kinship_core::{
    Command, CommandId, Event, Instant, Key, Rng, State, StreamEvent, StreamId, Transmit,
};
use kinship_proto::{
    Alive, Codec, Dead, Message, NONCE_LEN, NodeId, PacketKind, PushPull, Record, Records, Suspect,
    sealed_nonce,
};
use kinship_sim::{
    Action, LinkConfig, NodeSpec, Scenario, Sim, SimNode, TraceConfig, addr_of, name_of,
};

/// A rumour a member forges about another, at an incarnation of the life `epoch`.
#[derive(Debug, Clone, Copy)]
enum Rumour {
    Alive { inc: u32, epoch: u64 },
    Suspect { inc: u32, epoch: u64 },
    Dead { inc: u32, epoch: u64 },
}

/// What the scenario tells a node to do.
#[derive(Debug, Clone)]
enum Cmd {
    Core(Command),
    /// Send every other node one datagram carrying `rumours` about node `about`, sealed with
    /// the cluster's key at this node's cluster time, as a member can.
    Forge {
        about: usize,
        rumours: Vec<Rumour>,
    },
}

/// A core node, running as 0.3 does or as a node older than 0.3 would.
struct Peer {
    inner: Observed,
    /// Starts without an epoch and drops the epoch from everything it receives, as a node
    /// older than 0.3 skips the bytes it does not know and so never sends any.
    old: bool,
    codec: Codec,
    index: usize,
    nodes: usize,
    /// The nonce of the last datagram this node sealed, whose cluster time forgeries reuse.
    last_nonce: Option<[u8; NONCE_LEN]>,
    forged: u64,
    queued: VecDeque<Transmit>,
}

impl Peer {
    /// Node `spec`, in `mode` unless it is `old`: a node older than 0.3 has no epoch, and so
    /// cannot sign.
    fn new(
        spec: &NodeSpec,
        log: Log,
        old: bool,
        mode: Mode,
        knows: impl Fn(usize) -> bool,
    ) -> Self {
        let mode = if old { Mode::Off } else { mode };
        let cfg = mode.config(spec, &spec.name);
        let codec = Codec::encrypted(
            cfg.cluster.as_bytes(),
            cfg.limits,
            vec![Key::from_bytes([7; 32])],
        )
        .expect("the test key");
        let epoch = if old { 0 } else { spec.epoch() };
        Self {
            inner: Observed::with_epoch(spec, &spec.name, epoch, cfg, log, knows),
            old,
            codec,
            index: spec.index,
            nodes: spec.nodes,
            last_nonce: None,
            forged: 0,
            queued: VecDeque::new(),
        }
    }

    fn forge(&mut self, about: usize, rumours: &[Rumour]) {
        let Some(mut nonce) = self.last_nonce else {
            return;
        };
        let (name, me) = (name_of(about), name_of(self.index));
        let id = |s| NodeId::new(s).expect("simulator names are valid");
        let msgs: Vec<Message<'_>> = rumours
            .iter()
            .map(|r| match *r {
                Rumour::Alive { inc, epoch } => Message::Alive(Alive {
                    inc,
                    node: id(&name),
                    addr: addr_of(about),
                    meta: b"",
                    vmin: 1,
                    vmax: 1,
                    epoch,
                }),
                Rumour::Suspect { inc, epoch } => Message::Suspect(Suspect {
                    inc,
                    node: id(&name),
                    from: id(&me),
                    epoch,
                }),
                Rumour::Dead { inc, epoch } => Message::Dead(Dead {
                    inc,
                    node: id(&name),
                    from: id(&me),
                    epoch,
                }),
            })
            .collect();
        for to in (0..self.nodes).filter(|&j| j != self.index) {
            // The node's own cluster time, and random bytes no nonce of its own has.
            self.forged += 1;
            nonce[8..16].copy_from_slice(&self.forged.to_be_bytes());
            nonce[16..].fill(0xf0);
            let mut payload = Vec::new();
            self.codec
                .seal(PacketKind::Datagram, &msgs, &nonce, &mut payload)
                .expect("rumours fit a datagram");
            self.queued.push_back(Transmit::Datagram {
                to: addr_of(to),
                payload,
            });
        }
    }
}

/// `packet` with every epoch it carries dropped, sealed again under its own nonce: what a node
/// older than 0.3 takes from it. One that does not open is left for the node to refuse.
fn without_epochs(codec: &Codec, kind: PacketKind, packet: &[u8]) -> Vec<u8> {
    let Some(nonce) = sealed_nonce(packet) else {
        return packet.to_vec();
    };
    let mut buf = packet.to_vec();
    let Ok(payload) = codec.open(kind, &mut buf) else {
        return packet.to_vec();
    };
    let msgs: Vec<Message<'_>> = payload.iter().collect();
    let records: Vec<Vec<Record<'_>>> = msgs
        .iter()
        .map(|m| match m {
            Message::PushPull(p) => p
                .records
                .iter()
                .map(|r| Record {
                    alive: Alive {
                        epoch: 0,
                        ..r.alive
                    },
                    ..r
                })
                .collect(),
            _ => Vec::new(),
        })
        .collect();
    let stripped: Vec<Message<'_>> = msgs
        .iter()
        .zip(&records)
        .map(|(m, recs)| match *m {
            Message::Alive(a) => Message::Alive(Alive { epoch: 0, ..a }),
            Message::Suspect(s) => Message::Suspect(Suspect { epoch: 0, ..s }),
            Message::Dead(d) => Message::Dead(Dead { epoch: 0, ..d }),
            Message::PushPull(p) => Message::PushPull(PushPull {
                records: Records::Slice(recs),
                ..p
            }),
            other => other,
        })
        .collect();
    let mut out = Vec::new();
    codec
        .seal(kind, &stripped, &nonce, &mut out)
        .expect("what opened seals again");
    out
}

impl SimNode for Peer {
    type Command = Cmd;
    type Event = Event;

    fn handle_datagram(&mut self, now: Instant, from: SocketAddr, buf: &[u8]) {
        if self.old {
            let buf = without_epochs(&self.codec, PacketKind::Datagram, buf);
            self.inner.handle_datagram(now, from, &buf);
        } else {
            self.inner.handle_datagram(now, from, buf);
        }
    }

    fn handle_stream(&mut self, now: Instant, conn: StreamId, ev: StreamEvent<'_>) {
        match ev {
            StreamEvent::Frame(frame) if self.old => {
                let frame = without_epochs(&self.codec, PacketKind::Stream, frame);
                self.inner
                    .handle_stream(now, conn, StreamEvent::Frame(&frame));
            }
            ev => self.inner.handle_stream(now, conn, ev),
        }
    }

    fn handle_timeout(&mut self, now: Instant) {
        self.inner.handle_timeout(now);
    }

    fn command(&mut self, now: Instant, cmd: Cmd) -> CommandId {
        match cmd {
            Cmd::Core(cmd) => self.inner.command(now, cmd),
            Cmd::Forge { about, rumours } => {
                self.forge(about, &rumours);
                CommandId::from_raw(u64::MAX)
            }
        }
    }

    fn poll_transmit(&mut self) -> Option<Transmit> {
        if let Some(t) = self.queued.pop_front() {
            return Some(t);
        }
        let t = self.inner.poll_transmit()?;
        if let Transmit::Datagram { payload, .. } = &t {
            self.last_nonce = sealed_nonce(payload).or(self.last_nonce);
        }
        Some(t)
    }

    fn poll_event(&mut self) -> Option<Event> {
        self.inner.poll_event()
    }

    fn poll_timeout(&self) -> Option<Instant> {
        self.inner.poll_timeout()
    }
}

/// How `o` holds node `j`: its state, epoch and incarnation.
fn held(sim: &Sim<Peer>, o: usize, j: usize) -> Option<(State, u64, u32)> {
    let m = sim.node(o)?.inner.node.member(&name_of(j))?;
    Some((m.state, m.epoch, m.incarnation))
}

/// Node `j`'s own view of itself: its epoch and incarnation.
fn local(sim: &Sim<Peer>, j: usize) -> (u64, u32) {
    sim.node(j).map_or((0, 0), |n| {
        (n.inner.node.local().epoch, n.inner.node.local().incarnation)
    })
}

/// Steps the sim in `step`s until `done` holds or `until` passes. Returns when it held.
fn run_until_true(
    sim: &mut Sim<Peer>,
    step: Duration,
    until: Instant,
    mut done: impl FnMut(&Sim<Peer>) -> bool,
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

/// Events about node `j` reported at or after `since`, as (observer, kind).
fn about(log: &Log, j: usize, since: Instant) -> Vec<(usize, &'static str)> {
    let name = name_of(j);
    log.borrow()
        .iter()
        .filter(|s| s.t >= since)
        .filter_map(|s| {
            let (kind, m) = match &s.event {
                Event::MemberJoined(m) => ("joined", m),
                Event::MemberSuspect(m) => ("suspect", m),
                Event::MemberRecovered(m) => ("recovered", m),
                Event::MemberDead(m) => ("dead", m),
                Event::MemberLeft(m) => ("left", m),
                _ => return None,
            };
            (m.name == name).then_some((s.observer, kind))
        })
        .collect()
}

fn at(t: Duration) -> Instant {
    Instant::ZERO + t
}

/// [`Mode::check`] for every running node; returns the members they hold unsigned.
fn signing(sim: &Sim<Peer>, mode: Mode, nodes: usize) -> Result<u64, String> {
    mode.check_all(
        (0..nodes)
            .filter_map(|o| sim.node(o))
            .map(|n| &n.inner.node),
    )
}

/// A sweep's summary of what [`stale`] or [`mixed`] returned.
fn summary(runs: Vec<(Duration, u64)>, mode: Mode) -> String {
    let unsigned: u64 = runs.iter().map(|r| r.1).sum();
    let took = percentiles(runs.into_iter().map(|r| r.0).collect());
    match mode {
        Mode::Off => took,
        Mode::Sign => format!("{took}; {unsigned} members held unsigned at the end"),
    }
}

/// A run of `nodes` nodes, those `old` picks running as before 0.3, in which `victim` changes
/// its metadata a few times and so reaches incarnation `changes` or more. Every first
/// instance knows every node, as a static member list would; a restarted one knows nobody
/// and joins.
fn cluster(
    seed: u64,
    nodes: usize,
    victim: usize,
    old: fn(usize) -> bool,
    mode: Mode,
    rng: &mut Rng,
) -> (Sim<Peer>, Log, u32) {
    let changes = 2 + rng.index(3) as u32;
    let mut scenario = Scenario::new(nodes)
        .link(LinkConfig::lan())
        .trace(TraceConfig::OFF)
        .duration(secs(600));
    for i in 0..changes {
        let meta = format!("v={i}").into_bytes();
        scenario = scenario.at(
            ms(500 + 700 * u64::from(i) + rng.below(500)),
            Action::Command {
                node: victim,
                cmd: Cmd::Core(Command::SetMeta(meta)),
            },
        );
    }
    let log: Log = Rc::default();
    let factory_log = log.clone();
    let sim = Sim::new(seed, scenario, move |spec: &NodeSpec| {
        let fresh = spec.now == Instant::ZERO;
        Peer::new(
            spec,
            factory_log.clone(),
            old(spec.index),
            mode,
            move |_| fresh,
        )
    });
    (sim, log, changes)
}

/// Crashes `victim`, restarts it a moment later, before its suspicion could run out, and has it
/// join through `seed_node`. Returns when it restarted.
fn restart(sim: &mut Sim<Peer>, victim: usize, seed_node: usize, rng: &mut Rng) -> Instant {
    sim.apply(Action::Crash(victim));
    sim.run_for(ms(200 + rng.below(800)));
    let restarted = sim.now();
    sim.apply(Action::Restart(victim));
    sim.apply(Action::Command {
        node: victim,
        cmd: Cmd::Core(Command::Join {
            seeds: vec![addr_of(seed_node)],
        }),
    });
    restarted
}

// ---------------------------------------------------------------------------------------------
// 1. Rumours about an earlier life.

const NODES: usize = 8;
const VICTIM: usize = 0;
/// The member that forges the rumours.
const LIAR: usize = 1;
const SEED_NODE: usize = 2;

fn stale(seed: u64, mode: Mode) -> Result<(Duration, u64), String> {
    let mut rng = Rng::new(seed ^ 0x4550_4f43);
    let (mut sim, log, changes) = cluster(seed, NODES, VICTIM, |_| false, mode, &mut rng);
    let fail = |msg: String| Err(format!("seed {seed}: {msg}"));
    let others = || (0..NODES).filter(|&o| o != VICTIM);

    sim.run_until(at(secs(10)));
    let (old_epoch, old_inc) = local(&sim, VICTIM);
    if old_inc < changes {
        return fail(format!(
            "only reached incarnation {old_inc} before the crash"
        ));
    }
    let restarted = restart(&mut sim, VICTIM, SEED_NODE, &mut rng);
    let (new_epoch, new_inc) = local(&sim, VICTIM);
    if new_epoch <= old_epoch || new_inc != 0 {
        return fail(format!(
            "restarted at epoch {new_epoch}, incarnation {new_inc}, after {old_epoch}"
        ));
    }
    let new_life = |sim: &Sim<Peer>, state| {
        others().all(|o| held(sim, o, VICTIM).is_some_and(|h| (h.0, h.1) == (state, new_epoch)))
    };
    // Gossip reaches nearly every node in a second; one that it misses, and that only sees the
    // new life answer its Pings, learns at its next push-pull.
    let until = restarted + config().push_pull_interval_for(NODES) * 2;
    let Some(took) = run_until_true(&mut sim, ms(100), until, |sim| new_life(sim, State::Alive))
    else {
        let views: Vec<String> = others()
            .map(|o| format!("{} {:?}", name_of(o), held(&sim, o, VICTIM)))
            .collect();
        let seen: Vec<_> = about(&log, VICTIM, restarted);
        return fail(format!(
            "the new life {new_epoch} never replaced the old one {old_epoch} everywhere: {}; {seen:?}",
            views.join(", ")
        ));
    };

    // The old life's suspicion and death, far above the new life's incarnation.
    let forged = sim.now();
    let inc = old_inc + 100;
    sim.apply(Action::Command {
        node: LIAR,
        cmd: Cmd::Forge {
            about: VICTIM,
            rumours: vec![
                Rumour::Suspect {
                    inc,
                    epoch: old_epoch,
                },
                Rumour::Dead {
                    inc,
                    epoch: old_epoch,
                },
            ],
        },
    });
    sim.run_for(secs(10));
    let seen = about(&log, VICTIM, forged);
    if !seen.is_empty() || !new_life(&sim, State::Alive) {
        return fail(format!(
            "the old life's Suspect and Dead were applied: {seen:?}"
        ));
    }
    // The same suspicion about the current life is applied, so those were delivered; the
    // new life refutes it.
    let control = sim.now();
    let inc = local(&sim, VICTIM).1;
    sim.apply(Action::Command {
        node: LIAR,
        cmd: Cmd::Forge {
            about: VICTIM,
            rumours: vec![Rumour::Suspect {
                inc,
                epoch: new_epoch,
            }],
        },
    });
    sim.run_for(secs(10));
    let seen = about(&log, VICTIM, control);
    if !seen.iter().any(|e| e.1 == "suspect") || seen.iter().any(|e| e.1 == "dead") {
        return fail(format!(
            "a Suspect about the current life was not applied and refuted: {seen:?}"
        ));
    }

    // Once the new life has died everywhere, the old life's Alive cannot bring it back, from
    // the member's own address and far above in incarnation.
    sim.apply(Action::Crash(VICTIM));
    let crashed = sim.now();
    if run_until_true(&mut sim, ms(100), crashed + secs(60), |sim| {
        new_life(sim, State::Dead)
    })
    .is_none()
    {
        let views: Vec<String> = others()
            .map(|o| format!("{} {:?}", name_of(o), held(&sim, o, VICTIM)))
            .collect();
        return fail(format!(
            "the new life {new_epoch} was not declared dead everywhere: {}",
            views.join(", ")
        ));
    }
    let forged = sim.now();
    sim.apply(Action::Command {
        node: LIAR,
        cmd: Cmd::Forge {
            about: VICTIM,
            rumours: vec![Rumour::Alive {
                inc: old_inc + 1_000,
                epoch: old_epoch,
            }],
        },
    });
    sim.run_for(secs(5));
    let seen = about(&log, VICTIM, forged);
    if !seen.is_empty() || !new_life(&sim, State::Dead) {
        return fail(format!("the old life's Alive brought it back: {seen:?}"));
    }
    // One for the dead life itself would, which shows that one was delivered.
    let control = sim.now();
    let inc = held(&sim, LIAR, VICTIM).map_or(0, |h| h.2) + 1;
    sim.apply(Action::Command {
        node: LIAR,
        cmd: Cmd::Forge {
            about: VICTIM,
            rumours: vec![Rumour::Alive {
                inc,
                epoch: new_epoch,
            }],
        },
    });
    sim.run_for(ms(500));
    if !about(&log, VICTIM, control).iter().any(|e| e.1 == "joined") {
        return fail("an Alive for the dead life itself was not applied".into());
    }
    match signing(&sim, mode, NODES) {
        Ok(unsigned) => Ok((took - restarted, unsigned)),
        Err(e) => fail(e),
    }
}

#[test]
fn rumours_about_an_earlier_life_neither_kill_nor_revive_the_later_one() {
    check_all(seeds(8), |seed| stale(seed, Mode::Off));
}

fn stale_sweep(mode: Mode) {
    let seeds = seeds(1000);
    let runs = check_all(seeds.clone(), |seed| stale(seed, mode));
    println!(
        "stale epochs: {} seeds x {NODES} nodes{}, the old life's Suspect, Dead and Alive \
         applied nowhere, the new life everywhere after: {}",
        seeds.end - seeds.start,
        mode.label(),
        summary(runs, mode)
    );
}

#[test]
#[ignore = "slow in debug builds; CI runs it with --release"]
fn rumours_about_an_earlier_life_neither_kill_nor_revive_the_later_one_thousand_seeds() {
    stale_sweep(Mode::Off);
}

/// In mode `sign` the liar's rumours are unsigned version 1 ones, which `sign` accepts as it
/// accepts a 0.4 node's.
#[test]
#[ignore = "slow in debug builds; CI runs it with --release"]
fn rumours_about_an_earlier_life_neither_kill_nor_revive_the_later_one_thousand_seeds_signed() {
    stale_sweep(Mode::Sign);
}

// ---------------------------------------------------------------------------------------------
// 2. Nodes older than 0.3 among newer ones.

const MIXED: usize = 10;
/// The nodes that run as before 0.3.
fn old(i: usize) -> bool {
    i % 2 == 1
}

fn mixed(seed: u64, mode: Mode) -> Result<(Duration, u64), String> {
    let mut rng = Rng::new(seed ^ 0x4d49_5845);
    let (mut sim, log, changes) = cluster(seed, MIXED, VICTIM, old, mode, &mut rng);
    let fail = |msg: String| Err(format!("seed {seed}: {msg}"));
    // Through a node of either version.
    let seed_node = 1 + rng.index(MIXED - 1);
    let others = || (0..MIXED).filter(|&o| o != VICTIM);

    sim.run_until(at(secs(10)));
    let (old_epoch, old_inc) = local(&sim, VICTIM);
    if old_inc < changes {
        return fail(format!(
            "only reached incarnation {old_inc} before the crash"
        ));
    }
    let restarted = restart(&mut sim, VICTIM, seed_node, &mut rng);
    let new_epoch = local(&sim, VICTIM).0;
    // Older nodes order lives by incarnation alone, so the new life must pass the old one's
    // there. A newer node holds the new life at its epoch, or, if the refutation reached it
    // only through older nodes, which drop the epoch, past the old life's incarnation under
    // the old epoch until its next push-pull with a newer node.
    let current = |sim: &Sim<Peer>, o: usize| {
        held(sim, o, VICTIM)
            .is_some_and(|h| h.0 == State::Alive && (h.2 > old_inc || !old(o) && h.1 == new_epoch))
    };
    let Some(took) = run_until_true(&mut sim, ms(100), restarted + secs(120), |sim| {
        others().all(|o| current(sim, o))
    }) else {
        let views: Vec<String> = others()
            .map(|o| format!("{} {:?}", name_of(o), held(&sim, o, VICTIM)))
            .collect();
        return fail(format!(
            "the restart through {} did not reach everyone: {} after {old_epoch}, {old_inc}",
            name_of(seed_node),
            views.join(", ")
        ));
    };
    sim.run_for(secs(60));

    if let Some(s) = log
        .borrow()
        .iter()
        .find(|s| matches!(s.event, Event::MemberDead(_)))
    {
        return fail(format!(
            "{} declared a member dead at {:?}: {:?}",
            name_of(s.observer),
            s.t,
            s.event
        ));
    }
    for o in others() {
        if !current(&sim, o) {
            return fail(format!(
                "{} ends with {:?}",
                name_of(o),
                held(&sim, o, VICTIM)
            ));
        }
    }
    // A member that sends no epoch has epoch 0, on every node, and an older node knows none.
    for o in 0..MIXED {
        for j in (0..MIXED).filter(|&j| j != o && (old(o) || old(j))) {
            let epoch = held(&sim, o, j).map(|h| h.1);
            if epoch != Some(0) {
                return fail(format!(
                    "{} holds {} at epoch {epoch:?}",
                    name_of(o),
                    name_of(j)
                ));
            }
        }
    }
    match signing(&sim, mode, MIXED) {
        Ok(unsigned) => Ok((took - restarted, unsigned)),
        Err(e) => fail(e),
    }
}

#[test]
fn older_nodes_without_epochs_mix_with_newer_ones() {
    check_all(seeds(8), |seed| mixed(seed, Mode::Off));
}

fn mixed_sweep(mode: Mode) {
    let seeds = seeds(1000);
    let runs = check_all(seeds.clone(), |seed| mixed(seed, mode));
    println!(
        "mixed versions: {} seeds x {MIXED} nodes, half without epochs{}, a restart \
         through either, no member declared dead, the new life everywhere after: {}",
        seeds.end - seeds.start,
        if mode == Mode::Sign {
            ", the rest in mode sign"
        } else {
            ""
        },
        summary(runs, mode)
    );
}

#[test]
#[ignore = "slow in debug builds; CI runs it with --release"]
fn older_nodes_without_epochs_mix_with_newer_ones_thousand_seeds() {
    mixed_sweep(Mode::Off);
}

/// The newer nodes in mode `sign`; the older ones have no epoch, and so cannot sign.
#[test]
#[ignore = "slow in debug builds; CI runs it with --release"]
fn older_nodes_without_epochs_mix_with_newer_ones_thousand_seeds_signed() {
    mixed_sweep(Mode::Sign);
}
