//! The chaos scenarios, and what each one asserts.
//!
//! Every scenario starts a fresh kinship cluster in the namespaces, waits until every node sees
//! every other alive, then injects its fault and watches every node's events:
//!
//! - `loss`: netem on every node with 1 to 5% loss, delay, jitter and reordering. No node may
//!   declare any member dead.
//! - `kill`: the same netem, then kill -9 of one node. Every live node must declare it dead
//!   within the analytic detection bound, and no other member may be declared dead.
//! - `udp-block`: an nftables rule drops one node's UDP in one direction, under netem without
//!   loss. No node may suspect it or declare anyone dead, and every other node's tcp_ping_acks
//!   must count the fallback pings that kept it alive.
//!
//! The parameters come from a seed, and a failure prints them with the command that replays
//! them. The network is real, so a replay repeats the parameters, not the packet schedule.

use std::fmt;
use std::path::Path;
use std::time::{Duration, Instant};

use serde_json::Value;

use crate::fleet::{Fleet, Impl, Kind, Launch, name};
use crate::netns::{Direction, Net, Netem};
use crate::stats::{Rng, detection_bound, percentile};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Scenario {
    Loss,
    Kill,
    UdpBlock,
}

impl Scenario {
    pub const ALL: [Self; 3] = [Self::Loss, Self::Kill, Self::UdpBlock];

    pub fn parse(text: &str) -> Result<Vec<Self>, String> {
        Ok(match text {
            "all" => Self::ALL.to_vec(),
            "loss" => vec![Self::Loss],
            "kill" => vec![Self::Kill],
            "udp-block" => vec![Self::UdpBlock],
            other => return Err(format!("unknown scenario {other}")),
        })
    }
}

impl fmt::Display for Scenario {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Loss => "loss",
            Self::Kill => "kill",
            Self::UdpBlock => "udp-block",
        })
    }
}

/// Everything a scenario run depends on.
#[derive(Debug, Clone)]
pub struct Params {
    pub scenario: Scenario,
    pub seed: u64,
    pub nodes: usize,
    pub duration: Duration,
    pub netem: Netem,
    /// Whether `--netem` set the netem rather than the seed.
    pub netem_given: bool,
    /// The node killed or blocked.
    pub target: usize,
    pub direction: Direction,
}

impl Params {
    pub fn draw(
        scenario: Scenario,
        seed: u64,
        nodes: usize,
        duration: Duration,
        netem: Option<Netem>,
    ) -> Self {
        let salt = match scenario {
            Scenario::Loss => 0x4c4f_5353,
            Scenario::Kill => 0x4b49_4c4c,
            Scenario::UdpBlock => 0x5544_5042,
        };
        let mut rng = Rng::new(seed ^ salt);
        let delay = rng.steps(1.0, 20.0, 1.0);
        let drawn = Netem {
            delay_ms: delay,
            jitter_ms: rng.steps(0.0, delay / 2.0, 0.5),
            loss_pct: match scenario {
                Scenario::Loss | Scenario::Kill => rng.steps(1.0, 5.0, 0.5),
                // The TCP fallback ping is what this scenario tests; loss on top would let a
                // TCP retransmission miss the round and blur what failed.
                Scenario::UdpBlock => 0.0,
            },
            reorder_pct: rng.steps(0.0, 25.0, 5.0),
        };
        Self {
            scenario,
            seed,
            nodes,
            duration,
            netem: netem.unwrap_or(drawn),
            netem_given: netem.is_some(),
            // Never the seed node, so the cluster keeps the node every other one joined.
            target: 1 + rng.below(nodes as u64 - 1) as usize,
            direction: if rng.below(2) == 0 {
                Direction::Inbound
            } else {
                Direction::Outbound
            },
        }
    }

    pub fn replay(&self) -> String {
        let mut cmd = format!(
            "chaos run --scenario {} --nodes {} --seed {} --duration {}",
            self.scenario,
            self.nodes,
            self.seed,
            self.duration.as_secs()
        );
        if self.netem_given {
            cmd += &format!(" --netem {}", self.netem);
        }
        cmd
    }
}

impl fmt::Display for Params {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "scenario={} seed={} nodes={} duration={}s netem={}",
            self.scenario,
            self.seed,
            self.nodes,
            self.duration.as_secs(),
            self.netem
        )?;
        match self.scenario {
            Scenario::Loss => Ok(()),
            Scenario::Kill => write!(f, " killed={}", name(self.target)),
            Scenario::UdpBlock => write!(
                f,
                " blocked={} direction={}",
                name(self.target),
                self.direction
            ),
        }
    }
}

/// The time a cluster of `n` gets to converge after its nodes start.
///
/// A join whose gossip was lost reaches a node only through push-pull, which memberlist
/// stretches with the cluster size: every 90 s at 100 nodes. This covers two of those.
pub fn converge_limit(n: usize) -> Duration {
    Duration::from_secs(30) + Duration::from_secs(2) * n as u32
}

/// Runs one scenario on `net` and returns a one-line summary, or why it failed.
pub async fn run(net: &Net, launch: &Launch, p: &Params, logs: &Path) -> Result<String, String> {
    if p.nodes < 3 {
        return Err("a scenario needs at least 3 nodes".to_owned());
    }
    let mut fleet = Fleet::new(Impl::Kinship, p.nodes, logs);
    let result = observe(net, launch, p, &mut fleet).await;
    fleet.stop().await;
    let reset = net.netem_all(&Netem::default()).await;
    let unblock = match p.scenario {
        Scenario::UdpBlock => net.unblock_udp(p.target).await,
        _ => Ok(()),
    };
    let summary = result?;
    reset?;
    unblock?;
    Ok(summary)
}

async fn observe(
    net: &Net,
    launch: &Launch,
    p: &Params,
    fleet: &mut Fleet,
) -> Result<String, String> {
    let cfg = kinship::Config::lan();
    let bound = detection_bound(cfg.core(), p.nodes);
    fleet.start(net, launch).await?;
    let took = fleet.converge(converge_limit(p.nodes)).await?;
    net.netem_all(&p.netem).await?;
    let start = Instant::now();
    let mut failures = Vec::new();
    let mut notes = vec![format!("converged in {:.1}s", took.as_secs_f64())];

    match p.scenario {
        Scenario::Loss => fleet.run_for(p.duration).await?,
        Scenario::Kill => {
            // Let the netem take hold before the kill.
            fleet.run_for(Duration::from_secs(5)).await?;
            let killed = fleet.kill(p.target).await?;
            let declared = |f: &Fleet| {
                f.live()
                    .iter()
                    .all(|&o| first(f, o, p.target, Kind::Dead, killed).is_some())
            };
            fleet.wait_for(bound, declared).await?;
            let mut latencies = Vec::new();
            for o in fleet.live() {
                match first(fleet, o, p.target, Kind::Dead, killed) {
                    Some(at) if at - killed <= bound => {
                        latencies.push((at - killed).as_secs_f64());
                    }
                    Some(at) => failures.push(format!(
                        "{} declared {} dead after {:.2}s, beyond the {}s bound",
                        name(o),
                        name(p.target),
                        (at - killed).as_secs_f64(),
                        bound.as_secs()
                    )),
                    None => failures.push(format!(
                        "{} did not declare {} dead within the {}s bound",
                        name(o),
                        name(p.target),
                        bound.as_secs()
                    )),
                }
            }
            if !latencies.is_empty() {
                latencies.sort_by(f64::total_cmp);
                notes.push(format!(
                    "detection p50 {:.2}s max {:.2}s (bound {}s)",
                    percentile(&latencies, 50.0),
                    percentile(&latencies, 100.0),
                    bound.as_secs()
                ));
            }
            // Keep watching for false deaths for the rest of the duration.
            if let Some(rest) = p.duration.checked_sub(start.elapsed()) {
                fleet.run_for(rest).await?;
            }
        }
        Scenario::UdpBlock => {
            if p.duration < bound {
                return Err(format!(
                    "udp-block needs --duration of at least {}s, so every node probes the \
                     blocked one",
                    bound.as_secs()
                ));
            }
            let before = fleet.collect_stats().await?;
            net.block_udp(p.target, p.direction).await?;
            let blocked = Instant::now();
            fleet.run_for(p.duration).await?;
            let after = fleet.collect_stats().await?;
            for r in fleet.log.iter().filter(|r| r.at >= blocked) {
                if r.member == p.target && matches!(r.kind, Kind::Suspect | Kind::Dead) {
                    failures.push(format!(
                        "{} reported the blocked {} {:?} after {:.2}s",
                        name(r.observer),
                        name(p.target),
                        r.kind,
                        (r.at - blocked).as_secs_f64()
                    ));
                }
            }
            let mut acks = Vec::new();
            for o in fleet.live().into_iter().filter(|&o| o != p.target) {
                let delta =
                    counter(&after[o], "tcp_ping_acks") - counter(&before[o], "tcp_ping_acks");
                acks.push(delta);
                if delta == 0 {
                    failures.push(format!(
                        "{}'s tcp_ping_acks did not move while {}'s UDP was blocked",
                        name(o),
                        name(p.target)
                    ));
                }
            }
            notes.push(format!("tcp_ping_acks per other node {acks:?}"));
            notes.push(format!(
                "blocked node local health {}",
                counter(&after[p.target], "local_health")
            ));
        }
    }

    // A death of anything but the killed node is a false death.
    for r in fleet.log.iter().filter(|r| r.at >= start) {
        let killed = p.scenario == Scenario::Kill && r.member == p.target;
        if matches!(r.kind, Kind::Dead | Kind::Left) && !killed {
            failures.push(format!(
                "false death: {} declared {} {:?} at {:.2}s",
                name(r.observer),
                name(r.member),
                r.kind,
                (r.at - start).as_secs_f64()
            ));
        }
    }
    let suspicions = fleet
        .log
        .iter()
        .filter(|r| r.at >= start && r.kind == Kind::Suspect)
        .count();
    notes.push(format!("{suspicions} suspicion events"));

    if failures.is_empty() {
        Ok(notes.join(", "))
    } else {
        failures.truncate(20);
        Err(failures.join("\n"))
    }
}

/// When `observer` first reported `kind` about `member` at or after `since`.
fn first(f: &Fleet, observer: usize, member: usize, kind: Kind, since: Instant) -> Option<Instant> {
    f.log
        .iter()
        .find(|r| r.observer == observer && r.member == member && r.kind == kind && r.at >= since)
        .map(|r| r.at)
}

fn counter(stats: &Option<Value>, key: &str) -> u64 {
    stats
        .as_ref()
        .and_then(|v| v.get(key))
        .and_then(Value::as_u64)
        .unwrap_or(0)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_seed_always_draws_the_same_parameters() {
        let d = Duration::from_secs(60);
        for s in Scenario::ALL {
            let a = Params::draw(s, 99, 5, d, None);
            let b = Params::draw(s, 99, 5, d, None);
            assert_eq!(a.to_string(), b.to_string());
            assert!((1..5).contains(&a.target));
            assert!(a.netem.loss_pct <= 5.0);
            assert!(a.netem.jitter_ms <= a.netem.delay_ms / 2.0);
        }
        let loss = Params::draw(Scenario::Loss, 99, 5, d, None);
        assert!(loss.netem.loss_pct >= 1.0);
        assert_eq!(
            Params::draw(Scenario::UdpBlock, 99, 5, d, None)
                .netem
                .loss_pct,
            0.0
        );
    }

    #[test]
    fn the_replay_command_names_every_input() {
        let netem = Netem::parse("loss=2%").unwrap();
        let p = Params::draw(Scenario::Kill, 7, 5, Duration::from_secs(90), Some(netem));
        assert_eq!(
            p.replay(),
            "chaos run --scenario kill --nodes 5 --seed 7 --duration 90 --netem \
             delay=0ms,jitter=0ms,loss=2%,reorder=0%"
        );
    }
}
