//! Replays of captured traffic by an attacker on the network who holds no key (SECURITY.md,
//! KS-01). The attacker records every datagram one node receives and later sends the recording
//! back to it, byte for byte. The packets still authenticate, so before cluster time stamps
//! they were applied again:
//!
//! 1. A member that left is resurrected once its tombstone is reaped: its old Alive arrives
//!    for a name the node no longer knows, and MemberJoined fires for a node that is gone.
//! 2. A member that crashed and came back under the same name after its tombstone was reaped
//!    restarts at incarnation 0, so the Dead rumours from its previous life win again, and
//!    the replay declares a live node dead.
//!
//! With the fix every replay older than the replay window is dropped before decryption and
//! counted under `replays_dropped`, and neither property can be broken. Each test runs a few
//! fixed seeds; `KINSHIP_SEED=<seed>` replays one.

mod common;

use std::rc::Rc;

use common::{Log, Observed, check_all, ms, secs, seeds};
use kinship_core::{Command, CommandId, Event, Instant, StreamEvent, StreamId, Transmit};
use kinship_sim::{Action, LinkConfig, NodeSpec, Scenario, Sim, SimNode, TraceConfig, name_of};

/// What the scenario tells a node to do.
#[derive(Debug, Clone)]
enum Cmd {
    Core(Command),
    /// Stop adding received datagrams to the recording.
    StopRecording,
    /// Hand the node every recorded datagram again, as the attacker would.
    Replay,
}

/// A node whose received datagrams an attacker records and can replay.
struct Tapped {
    inner: Observed,
    recording: bool,
    tape: Vec<(std::net::SocketAddr, Vec<u8>)>,
}

impl SimNode for Tapped {
    type Command = Cmd;
    type Event = Event;

    fn handle_datagram(&mut self, now: Instant, from: std::net::SocketAddr, buf: &[u8]) {
        if self.recording {
            self.tape.push((from, buf.to_vec()));
        }
        self.inner.handle_datagram(now, from, buf);
    }

    fn handle_stream(&mut self, now: Instant, conn: StreamId, ev: StreamEvent<'_>) {
        self.inner.handle_stream(now, conn, ev);
    }

    fn handle_timeout(&mut self, now: Instant) {
        self.inner.handle_timeout(now);
    }

    fn command(&mut self, now: Instant, cmd: Cmd) -> CommandId {
        match cmd {
            Cmd::Core(cmd) => self.inner.command(now, cmd),
            Cmd::StopRecording => {
                self.recording = false;
                CommandId::from_raw(u64::MAX)
            }
            Cmd::Replay => {
                for (from, buf) in &self.tape {
                    self.inner.handle_datagram(now, *from, buf);
                }
                CommandId::from_raw(u64::MAX)
            }
        }
    }

    fn poll_transmit(&mut self) -> Option<Transmit> {
        self.inner.poll_transmit()
    }

    fn poll_event(&mut self) -> Option<Event> {
        self.inner.poll_event()
    }

    fn poll_timeout(&self) -> Option<Instant> {
        self.inner.poll_timeout()
    }
}

const NODES: usize = 5;
/// The node the attacker taps.
const VICTIM: usize = 0;
/// The member whose old traffic is replayed.
const GONE: usize = 4;

fn sim(seed: u64, scenario: Scenario<Cmd>) -> (Sim<Tapped>, Log) {
    let log: Log = Rc::default();
    let factory_log = log.clone();
    let sim = Sim::new(seed, scenario, move |spec: &NodeSpec| Tapped {
        inner: Observed::new(spec, factory_log.clone(), |_| true),
        recording: spec.index == VICTIM,
        tape: Vec::new(),
    });
    (sim, log)
}

fn scenario() -> Scenario<Cmd> {
    Scenario::new(NODES)
        .link(LinkConfig::lan())
        .trace(TraceConfig::OFF)
}

/// Events about `name` that `observer` reported at or after `since`.
fn events_about(log: &Log, observer: usize, name: &str, since: Instant) -> Vec<(Instant, Event)> {
    log.borrow()
        .iter()
        .filter(|s| s.observer == observer && s.t >= since)
        .filter(|s| match &s.event {
            Event::MemberJoined(m)
            | Event::MemberSuspect(m)
            | Event::MemberDead(m)
            | Event::MemberLeft(m)
            | Event::MemberRecovered(m) => m.name == name,
            _ => false,
        })
        .map(|s| (s.t, s.event.clone()))
        .collect()
}

fn replays_dropped(sim: &Sim<Tapped>) -> u64 {
    sim.node(VICTIM)
        .map_or(0, |n| n.inner.node.metrics().replays_dropped)
}

// ---------------------------------------------------------------------------------------------
// 1. A member that left is not resurrected by its old Alive.

fn resurrection(seed: u64) -> Result<(), String> {
    let leave = secs(10);
    let replay = secs(80);
    let scenario = scenario()
        .duration(secs(110))
        .at(
            leave,
            Action::Command {
                node: GONE,
                cmd: Cmd::Core(Command::Leave),
            },
        )
        .at(
            leave + secs(2),
            Action::Command {
                node: VICTIM,
                cmd: Cmd::StopRecording,
            },
        )
        // The Left tombstone is reaped dead_reclaim (30 s) after the leave.
        .at(
            replay,
            Action::Command {
                node: VICTIM,
                cmd: Cmd::Replay,
            },
        );
    let (mut sim, log) = sim(seed, scenario);
    sim.run_until(Instant::ZERO + (replay - ms(1)));
    let name = name_of(GONE);
    if sim.node(VICTIM).unwrap().inner.node.member(&name).is_some() {
        return Err(format!(
            "seed {seed}: the tombstone of {name} was never reaped"
        ));
    }
    sim.run();
    let after = events_about(&log, VICTIM, &name, Instant::ZERO + replay);
    if !after.is_empty() {
        return Err(format!(
            "seed {seed}: the replay brought back {name}, which left: {after:?}"
        ));
    }
    if replays_dropped(&sim) == 0 {
        return Err(format!("seed {seed}: no replay was counted"));
    }
    Ok(())
}

#[test]
fn a_replayed_alive_never_resurrects_a_member_that_left() {
    check_all(seeds(8), resurrection);
}

// ---------------------------------------------------------------------------------------------
// 2. A member that restarted after its tombstone was reaped is not killed by old rumours.

fn restart(seed: u64) -> Result<(), String> {
    let crash = secs(5);
    let stop = secs(75);
    let restart = secs(90);
    let replay = secs(110);
    let scenario = scenario()
        .duration(secs(140))
        .at(crash, Action::Crash(GONE))
        .at(
            stop,
            Action::Command {
                node: VICTIM,
                cmd: Cmd::StopRecording,
            },
        )
        .at(restart, Action::Restart(GONE))
        .at(
            replay,
            Action::Command {
                node: VICTIM,
                cmd: Cmd::Replay,
            },
        );
    let (mut sim, log) = sim(seed, scenario);
    let name = name_of(GONE);
    sim.run_until(Instant::ZERO + (restart - ms(1)));
    let dead = log.borrow().iter().any(|s| {
        s.observer == VICTIM && matches!(&s.event, Event::MemberDead(m) if m.name == name)
    });
    if !dead {
        return Err(format!("seed {seed}: {name} was never declared dead"));
    }
    if sim.node(VICTIM).unwrap().inner.node.member(&name).is_some() {
        return Err(format!(
            "seed {seed}: the tombstone of {name} was never reaped"
        ));
    }
    sim.run_until(Instant::ZERO + (replay - ms(1)));
    let back = sim
        .node(VICTIM)
        .unwrap()
        .inner
        .node
        .member(&name)
        .map(|m| (m.state, m.incarnation));
    if back.is_none_or(|(state, _)| !state.is_live()) {
        return Err(format!("seed {seed}: {name} did not rejoin: {back:?}"));
    }
    sim.run();
    let after = events_about(&log, VICTIM, &name, Instant::ZERO + replay);
    let harmed: Vec<_> = after
        .iter()
        .filter(|(_, e)| {
            matches!(
                e,
                Event::MemberSuspect(_) | Event::MemberDead(_) | Event::MemberLeft(_)
            )
        })
        .collect();
    if !harmed.is_empty() {
        return Err(format!(
            "seed {seed}: the replay turned the restarted {name} against itself: {harmed:?}"
        ));
    }
    if replays_dropped(&sim) == 0 {
        return Err(format!("seed {seed}: no replay was counted"));
    }
    Ok(())
}

#[test]
fn a_replayed_rumour_never_kills_a_member_that_restarted() {
    check_all(seeds(8), restart);
}
