use std::time::Duration;

use kinship_core::{Command, Config, Identity, Instant, Node, Security};
use kinship_sim::{
    Action, Delay, DropReason, EchoCommand, EchoConfig, EchoNode, LinkConfig, Record, Scenario,
    Sim, TraceConfig,
};

fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

fn ms(m: u64) -> Duration {
    Duration::from_millis(m)
}

fn at(d: Duration) -> Instant {
    Instant::ZERO + d
}

fn run(seed: u64, scenario: Scenario<EchoCommand>, cfg: EchoConfig) -> Sim<EchoNode> {
    let mut sim = Sim::new(seed, scenario, move |spec| EchoNode::new(spec, &cfg));
    sim.run();
    sim
}

fn fast_echo() -> EchoConfig {
    EchoConfig {
        interval: ms(100),
        ..EchoConfig::default()
    }
}

/// Exercises every fault the network models.
fn eventful() -> Scenario<EchoCommand> {
    let tcp = |node, to| Action::Command {
        node,
        cmd: EchoCommand::TcpPing { to },
    };
    Scenario::new(20)
        .duration(secs(60))
        .link(
            LinkConfig::lan()
                .with_loss(0.02)
                .with_duplicate(0.01)
                .with_reorder(
                    0.02,
                    Delay::Uniform {
                        min: ms(1),
                        max: ms(20),
                    },
                ),
        )
        .link_between(0..2, 10..12, LinkConfig::wan())
        .slow_node(
            3,
            Delay::Uniform {
                min: ms(1),
                max: ms(5),
            },
        )
        .at(secs(5), tcp(0, 1))
        .at(
            secs(10),
            Action::Partition {
                a: (0..10).into(),
                b: (10..20).into(),
            },
        )
        .at(secs(12), tcp(0, 15))
        .at(secs(20), Action::Heal)
        .at(
            secs(25),
            Action::Block {
                from: 5.into(),
                to: 6.into(),
            },
        )
        .at(
            secs(30),
            Action::Pause {
                node: 7,
                duration: secs(3),
            },
        )
        .at(secs(35), Action::Crash(8))
        .at(secs(36), tcp(9, 8))
        .at(secs(45), Action::Restart(8))
        .at(
            secs(50),
            Action::Slow {
                node: 3,
                cost: None,
            },
        )
}

#[test]
fn same_seed_gives_byte_identical_traces() {
    let a = run(7, eventful(), EchoConfig::default());
    let b = run(7, eventful(), EchoConfig::default());
    let (ja, jb) = (a.trace().to_json(), b.trace().to_json());
    assert!(ja == jb, "same seed produced different traces");
    assert_eq!(a.stats(), b.stats());

    let c = run(8, eventful(), EchoConfig::default());
    assert_ne!(ja, c.trace().to_json());
}

#[test]
fn eventful_run_exercises_every_fault() {
    let sim = run(7, eventful(), EchoConfig::default());
    let s = sim.stats();
    assert!(s.delivered > 1000, "{s:?}");
    assert!(s.lost > 0, "{s:?}");
    assert!(s.duplicated > 0, "{s:?}");
    assert!(s.partitioned > 0, "{s:?}");
    assert!(s.to_down_node > 0, "{s:?}");
    assert!(s.stream_failures >= 2, "{s:?}");
    assert!(s.sent_bytes >= s.sent && s.stream_bytes > 0, "{s:?}");
    let events = event_values(&sim);
    assert!(events.iter().any(|e| e["type"] == "echoed"));
    assert!(events.iter().any(|e| e["type"] == "tcp_echoed"));
    assert_eq!(
        events.iter().filter(|e| e["type"] == "tcp_failed").count(),
        2
    );
    assert_eq!(sim.node(0).unwrap().bad_packets(), 0);
}

fn event_values(sim: &Sim<EchoNode>) -> Vec<serde_json::Value> {
    sim.trace()
        .records
        .iter()
        .filter_map(|r| match r {
            Record::Event { event, .. } => Some(event.clone()),
            _ => None,
        })
        .collect()
}

#[test]
fn trace_is_pinned_across_platforms() {
    // CI runs this on Linux, macOS and Windows, so a seed that fails anywhere replays
    // everywhere. Update the value only when the simulator or the echo node changes on purpose.
    let scenario = Scenario::new(4)
        .duration(secs(5))
        .link(
            LinkConfig::lan()
                .with_loss(0.1)
                .with_duplicate(0.05)
                .with_reorder(
                    0.1,
                    Delay::Normal {
                        mean: ms(5),
                        std_dev: ms(2),
                    },
                ),
        )
        .at(
            secs(2),
            Action::Command {
                node: 0,
                cmd: EchoCommand::TcpPing { to: 3 },
            },
        )
        .at(
            secs(3),
            Action::Pause {
                node: 1,
                duration: ms(700),
            },
        );
    let sim = run(1234, scenario, fast_echo());
    assert_eq!(
        sim.trace().digest(),
        0x6316_8316_8dce_af90,
        "trace digest changed"
    );
}

#[test]
fn partitions_drop_traffic_between_sides_only() {
    let sim = run(3, eventful(), EchoConfig::default());
    let side = |n: usize| n < 10;
    let window = at(secs(10))..at(secs(20));
    let mut crossing = Vec::new();
    let mut within = 0;
    for r in &sim.trace().records {
        if let Record::Send {
            t,
            packet,
            from,
            to: Some(to),
            ..
        } = *r
        {
            if window.contains(&t) {
                if side(from) != side(to) {
                    crossing.push(packet);
                } else {
                    within += 1;
                }
            }
        }
    }
    assert!(!crossing.is_empty() && within > 0);
    for packet in crossing {
        let dropped = sim.trace().records.iter().any(|r| {
            matches!(r, Record::Drop { packet: p, reason: DropReason::Partition, .. } if *p == packet)
        });
        assert!(dropped, "packet {packet} crossed the partition");
    }
}

#[test]
fn one_way_block_drops_one_direction() {
    let scenario = Scenario::new(2).duration(secs(10)).at(
        Duration::ZERO,
        Action::Block {
            from: 0.into(),
            to: 1.into(),
        },
    );
    let sim = run(1, scenario, fast_echo());
    let delivered_to = |node| {
        sim.trace()
            .records
            .iter()
            .filter(|r| matches!(r, Record::Deliver { to, .. } if *to == node))
            .count()
    };
    // Node 1's pings reach node 0, but node 0's pings and acks never reach node 1.
    assert!(delivered_to(0) > 50);
    assert_eq!(delivered_to(1), 0);
    assert!(event_values(&sim).is_empty());
}

/// Instants at which node `node` processed an input.
fn processing_times(sim: &Sim<EchoNode>, node: usize) -> Vec<Instant> {
    sim.trace()
        .records
        .iter()
        .filter_map(|r| match *r {
            Record::Deliver { t, to, .. } if to == node => Some(t),
            Record::Timeout { t, node: n } if n == node => Some(t),
            _ => None,
        })
        .collect()
}

#[test]
fn paused_node_handles_inputs_late_and_in_order() {
    let scenario = Scenario::new(2)
        .duration(secs(3))
        .link(LinkConfig::ideal())
        .at(
            secs(1),
            Action::Pause {
                node: 1,
                duration: ms(500),
            },
        );
    let sim = run(5, scenario, fast_echo());
    let times = processing_times(&sim, 1);
    let paused = at(secs(1))..at(ms(1500));
    assert!(
        times
            .iter()
            .all(|t| !paused.contains(t) || *t == at(secs(1)))
    );
    let backlog = times.iter().filter(|t| **t == at(ms(1500))).count();
    assert!(backlog >= 5, "only {backlog} inputs were held back");
    // Node 0's pings during the pause were answered late.
    let max_rtt = event_values(&sim)
        .iter()
        .filter_map(|e| e["rtt"].as_u64())
        .max()
        .unwrap();
    assert!(max_rtt >= ms(400).as_nanos() as u64, "max rtt {max_rtt}");
}

#[test]
fn slow_node_spaces_out_its_inputs() {
    let scenario = Scenario::new(3)
        .duration(secs(5))
        .link(LinkConfig::ideal())
        .slow_node(1, Delay::Fixed(ms(30)));
    let sim = run(5, scenario, fast_echo());
    let times = processing_times(&sim, 1);
    assert!(times.len() > 50);
    for pair in times.windows(2) {
        assert!(pair[1] - pair[0] >= ms(30), "{pair:?}");
    }
    // The fast nodes are not held up.
    let fast = processing_times(&sim, 0);
    assert!(fast.windows(2).any(|p| p[1] - p[0] < ms(30)));
}

#[test]
fn starved_node_reads_packets_late_but_keeps_its_timers() {
    let timeouts = |sim: &Sim<EchoNode>, node: usize| {
        sim.trace()
            .records
            .iter()
            .filter(|r| matches!(r, Record::Timeout { node: n, .. } if *n == node))
            .count()
    };
    let scenario = Scenario::new(2)
        .duration(secs(5))
        .link(LinkConfig::ideal())
        .starved_node(1, Delay::Fixed(ms(300)));
    let sim = run(5, scenario, fast_echo());
    // Node 0's pings were answered only after node 1's receive path caught up.
    let rtts: Vec<u64> = event_values(&sim)
        .iter()
        .filter_map(|e| e["rtt"].as_u64())
        .collect();
    assert!(!rtts.is_empty());
    assert!(
        rtts.iter().all(|&r| r >= ms(300).as_nanos() as u64),
        "{rtts:?}"
    );
    // Its timers fired as often as the healthy node's.
    let (fast, starved) = (timeouts(&sim, 0), timeouts(&sim, 1));
    assert!(
        starved > 40 && starved.abs_diff(fast) <= 2,
        "{fast} vs {starved}"
    );
}

#[test]
fn a_clock_jump_brings_timers_due_at_once_until_a_restart() {
    let tcp = Action::Command {
        node: 1,
        cmd: EchoCommand::TcpPing { to: 0 },
    };
    let scenario = Scenario::new(2)
        .duration(secs(5))
        .link(LinkConfig::ideal())
        .at(
            secs(1),
            Action::ClockJump {
                node: 1,
                by: secs(2),
            },
        )
        .at(secs(2), tcp)
        .at(secs(3), Action::Restart(1));
    let sim = run(5, scenario, fast_echo());
    let sends = |from: usize, during: std::ops::Range<Instant>| {
        sim.trace()
            .records
            .iter()
            .filter(|r| matches!(**r, Record::Send { t, from: f, .. } if f == from && during.contains(&t)))
            .count()
    };
    // Two seconds of 100 ms pings fall due the moment the clock jumps.
    assert!(sends(1, at(secs(1))..at(ms(1001))) >= 20);
    // Then it pings and answers at the usual pace, and a restarted node is back on the shared
    // clock: no burst.
    let second = at(ms(1500))..at(ms(2500));
    assert!(sends(1, second.clone()).abs_diff(sends(0, second)) <= 3);
    assert!(sends(1, at(secs(3))..at(ms(3100))) <= 3);
    // Both ends of every exchange agree on the time: on an ideal link nothing takes any.
    let rtts: Vec<u64> = event_values(&sim)
        .iter()
        .filter_map(|e| e["rtt"].as_u64())
        .collect();
    assert!(rtts.len() > 50 && rtts.iter().all(|&r| r == 0), "{rtts:?}");
    assert!(event_values(&sim).iter().any(|e| e["type"] == "tcp_echoed"));
}

#[test]
fn crashed_node_is_silent_until_restarted() {
    let scenario = Scenario::new(3)
        .duration(secs(6))
        .at(secs(2), Action::Crash(2))
        .at(secs(4), Action::Restart(2));
    let sim = run(9, scenario, fast_echo());
    let sends_from_2: Vec<Instant> = sim
        .trace()
        .records
        .iter()
        .filter_map(|r| match *r {
            Record::Send { t, from: 2, .. } => Some(t),
            _ => None,
        })
        .collect();
    let down = at(secs(2))..at(secs(4));
    assert!(sends_from_2.iter().any(|t| *t < down.start));
    assert!(sends_from_2.iter().any(|t| *t >= down.end));
    assert!(!sends_from_2.iter().any(|t| down.contains(t)));
    assert!(sim.stats().to_down_node > 0);
}

#[test]
fn streams_deliver_in_order_and_fail_when_unreachable() {
    let tcp = |node, to| Action::Command {
        node,
        cmd: EchoCommand::TcpPing { to },
    };
    let scenario = Scenario::new(3)
        .duration(secs(20))
        .at(secs(1), tcp(0, 1))
        .at(
            secs(2),
            Action::Partition {
                a: 0.into(),
                b: 1.into(),
            },
        )
        .at(secs(3), tcp(0, 1))
        .at(secs(8), Action::Heal)
        .at(secs(9), Action::Crash(2))
        .at(secs(10), tcp(0, 2));
    let sim = run(2, scenario, EchoConfig::default());
    let events: Vec<(Instant, serde_json::Value)> = sim
        .trace()
        .records
        .iter()
        .filter_map(|r| match r {
            Record::Event { t, event, .. } if event["type"] != "echoed" => {
                Some((*t, event.clone()))
            }
            _ => None,
        })
        .collect();
    let kinds: Vec<&str> = events
        .iter()
        .map(|(_, e)| e["type"].as_str().unwrap())
        .collect();
    assert_eq!(kinds, ["tcp_echoed", "tcp_failed", "tcp_failed"]);
    // Unreachable peers fail after the connect timeout, 3 s by default.
    assert_eq!(events[1].0, at(secs(6)));
    assert_eq!(events[2].0, at(secs(13)));
    let kinds: Vec<&str> = sim
        .trace()
        .records
        .iter()
        .filter_map(|r| match r {
            Record::Connect { .. } => Some("connect"),
            Record::StreamSend { .. } => Some("send"),
            Record::StreamFrame { .. } => Some("frame"),
            Record::StreamClose { .. } => Some("close"),
            Record::StreamClosed { .. } => Some("closed"),
            Record::StreamFailed { .. } => Some("failed"),
            _ => None,
        })
        .take(7)
        .collect();
    assert_eq!(
        kinds,
        [
            "connect", "send", "frame", "send", "frame", "close", "closed"
        ]
    );
}

#[test]
fn oversized_stream_frames_fail_the_connection() {
    let scenario = Scenario::new(2).duration(secs(10)).max_stream_frame(16).at(
        secs(1),
        Action::Command {
            node: 0,
            cmd: EchoCommand::TcpPing { to: 1 },
        },
    );
    let sim = run(4, scenario, EchoConfig::default());
    let events = event_values(&sim);
    assert!(events.iter().any(|e| e["type"] == "tcp_failed"));
    assert!(!events.iter().any(|e| e["type"] == "tcp_echoed"));
}

#[test]
fn trace_dumps_as_json() {
    let scenario = Scenario::new(3)
        .duration(secs(3))
        .at(secs(1), Action::Crash(2));
    let sim = run(11, scenario, fast_echo());
    let trace = sim.trace();
    let json = trace.to_json();
    let mut written = Vec::new();
    trace.write_json(&mut written).unwrap();
    assert_eq!(written, json.as_bytes());

    let v: serde_json::Value = serde_json::from_str(&json).unwrap();
    assert_eq!(v["format"], 1);
    assert_eq!(v["seed"], 11);
    assert_eq!(v["nodes"][2]["name"], "n2");
    assert_eq!(v["nodes"][2]["addr"], "10.0.0.2:7946");
    let records = v["records"].as_array().unwrap();
    assert!(
        records
            .iter()
            .all(|r| r["kind"].is_string() && r["t"].is_u64())
    );
    assert!(
        records
            .iter()
            .any(|r| r["kind"] == "action" && r["action"] == "crash 2")
    );
    assert!(
        records
            .iter()
            .any(|r| r["kind"] == "event" && r["event"]["type"] == "echoed")
    );
}

#[test]
fn trace_config_off_keeps_counters() {
    let scenario = Scenario::new(5).duration(secs(5)).trace(TraceConfig::OFF);
    let sim = run(1, scenario, fast_echo());
    assert!(sim.trace().records.is_empty());
    assert!(sim.stats().delivered > 100);
    assert!(sim.stats().events > 100);
}

#[test]
fn drives_the_core_node() {
    let scenario = Scenario::new(3).duration(secs(2)).at(
        secs(1),
        Action::Command {
            node: 1,
            cmd: Command::SetMeta(b"zone=a".to_vec()),
        },
    );
    let mut sim = Sim::new(1, scenario, |spec| {
        let cfg = Config::local(Security::InsecurePlaintext);
        let me = Identity::new(spec.name.clone(), spec.addr).unwrap();
        Node::new(cfg, me, spec.now, spec.seed).unwrap()
    });
    let json = sim.run().to_json();
    assert!(json.contains(r#""event":{"CommandDone":{"id":0,"result":{"Ok":"Done"}}}"#));
    assert_eq!(sim.node(1).unwrap().identity().meta(), b"zone=a");
}

/// 1,000 nodes for 10 simulated minutes. Run with
/// `cargo test --release -p kinship-sim --test sim -- --ignored --nocapture`.
#[test]
#[ignore = "slow in debug builds; CI runs it with --release"]
fn thousand_nodes_ten_minutes() {
    let scenario = Scenario::new(1000)
        .duration(secs(600))
        .link(LinkConfig::lan().with_loss(0.01))
        .trace(TraceConfig::OFF);
    let started = std::time::Instant::now();
    let sim = run(1, scenario, EchoConfig::default());
    let elapsed = started.elapsed();
    let s = sim.stats();
    println!("1000 nodes x 600 s simulated in {elapsed:?}: {s:?}");
    assert!(s.delivered > 1_000_000, "{s:?}");
    if !cfg!(debug_assertions) {
        assert!(elapsed < secs(60), "took {elapsed:?}");
    }
}
