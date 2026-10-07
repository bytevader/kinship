//! One kinship node under the chaos harness.
//!
//! It reports to the harness on stdout, one JSON object per line: `ready` with its pid once it
//! has started and joined, then `alive`, `suspect`, `dead` and `left` for every member event,
//! and `stats` when asked. It reads commands from stdin, `stats` and `quit`, and exits when
//! stdin closes, so a node never outlives the harness that started it.
//!
//! ```text
//! chaos-node --name n0 --bind 10.77.0.1:7946 --key BASE64
//! chaos-node --name n1 --bind 10.77.0.2:7946 --key BASE64 --seed 10.77.0.1:7946
//! ```

use std::io::Write;
use std::net::SocketAddr;

use kinship::{Cluster, Config, Event, Key, Member, State};
use serde_json::{Value, json};
use tokio::io::{AsyncBufReadExt, BufReader};
use tracing_subscriber::EnvFilter;

const USAGE: &str = "\
usage: chaos-node --name NAME --bind ADDR [options]

options:
  --seed ADDR              seed to join, repeatable
  --key BASE64             cluster key (32 bytes); without one the node runs in plaintext
  --preset lan|local|wan   timing preset (default: lan)
  --log FILTER             tracing filter for stderr (default: RUST_LOG, else warn)";

#[tokio::main(flavor = "current_thread")]
async fn main() {
    // sudo drops RUST_LOG on the way into the namespace, so the filter can come as an argument.
    let args: Vec<String> = std::env::args().skip(1).collect();
    let filter = match args.iter().position(|a| a == "--log") {
        Some(i) => args.get(i + 1).map(EnvFilter::new),
        None => EnvFilter::try_from_default_env().ok(),
    };
    tracing_subscriber::fmt()
        .with_writer(std::io::stderr)
        .with_ansi(false)
        .with_env_filter(filter.unwrap_or_else(|| EnvFilter::new("warn")))
        .init();
    let code = match run().await {
        Ok(()) => 0,
        Err(e) => {
            eprintln!("chaos-node: {e}");
            emit(&json!({ "ev": "error", "error": e }));
            1
        }
    };
    // The stdin reader sits on a blocking thread that the runtime would wait for on shutdown.
    std::process::exit(code);
}

async fn run() -> Result<(), String> {
    let cfg = parse(std::env::args().skip(1))?;
    let cluster = Cluster::start(cfg).await.map_err(|e| e.to_string())?;
    let local = cluster.local();
    // Subscribe before reading the table, so a member that joins in between shows up twice
    // rather than not at all.
    let mut events = cluster.events();
    emit(&json!({
        "ev": "ready",
        "pid": std::process::id(),
        "name": local.name,
        "addr": local.addr.to_string(),
    }));
    snapshot(&cluster);

    let mut stdin = BufReader::new(tokio::io::stdin()).lines();
    loop {
        tokio::select! {
            event = events.recv() => match event {
                Some(Event::EventsLost(n)) => {
                    emit(&json!({ "ev": "lost", "events": n }));
                    snapshot(&cluster);
                }
                Some(event) => report(event),
                None => break,
            },
            line = stdin.next_line() => match line {
                Ok(Some(cmd)) => match cmd.trim() {
                    "stats" => emit(&stats(&cluster)),
                    "quit" => break,
                    "" => {}
                    other => emit(&json!({ "ev": "error", "error": format!("unknown command {other}") })),
                },
                // The harness closed the pipe or died: do not linger in its namespace.
                Ok(None) | Err(_) => break,
            },
        }
    }
    cluster.close().await;
    Ok(())
}

/// Writes one line and flushes it: the harness times each event when the line arrives.
fn emit(value: &Value) {
    let mut out = std::io::stdout().lock();
    let _ = writeln!(out, "{value}");
    let _ = out.flush();
}

fn member(ev: &str, m: &Member) -> Value {
    json!({ "ev": ev, "member": m.name, "incarnation": m.incarnation })
}

fn report(event: Event) {
    match event {
        Event::MemberJoined(m) | Event::MemberRecovered(m) => emit(&member("alive", &m)),
        Event::MemberSuspect(m) => emit(&member("suspect", &m)),
        Event::MemberDead(m) => emit(&member("dead", &m)),
        Event::MemberLeft(m) => emit(&member("left", &m)),
        _ => {}
    }
}

/// Reports every other member's current state, at start and after events were lost.
fn snapshot(cluster: &Cluster) {
    let me = cluster.local().name;
    for m in cluster.members().iter().filter(|m| m.name != me) {
        let ev = match m.state {
            State::Alive => "alive",
            State::Suspect => "suspect",
            State::Dead => "dead",
            State::Left => "left",
        };
        emit(&member(ev, m));
    }
}

fn stats(cluster: &Cluster) -> Value {
    let s = cluster.stats();
    let m = &s.metrics;
    json!({
        "ev": "stats",
        "local_health": s.local_health,
        "probes_sent": m.probes_sent,
        "probes_failed": m.probes_failed,
        "indirect_probes": m.indirect_probes,
        "missed_nacks": m.missed_nacks,
        "suspicions": m.suspicions,
        "refutations": m.refutations,
        "tcp_pings": m.tcp_pings,
        "tcp_ping_acks": m.tcp_ping_acks,
        "push_pulls": m.push_pulls,
        "push_pull_failures": m.push_pull_failures,
        "decode_errors": m.decode_errors,
        "decrypt_failures": m.decrypt_failures,
        "replays_dropped": m.replays_dropped,
    })
}

fn parse(mut args: impl Iterator<Item = String>) -> Result<Config, String> {
    let mut preset = "lan".to_owned();
    let mut name = None;
    let mut bind = None;
    let mut key = None;
    let mut seeds = Vec::new();
    while let Some(arg) = args.next() {
        let mut value = |flag: &str| args.next().ok_or(format!("{flag} needs a value"));
        match arg.as_str() {
            "--name" => name = Some(value("--name")?),
            "--bind" => bind = Some(addr(&value("--bind")?)?),
            "--seed" => seeds.push(addr(&value("--seed")?)?),
            "--key" => {
                let text = value("--key")?;
                key = Some(Key::from_base64(&text).map_err(|e| format!("bad key: {e}"))?);
            }
            "--preset" => preset = value("--preset")?,
            "--log" => {
                value("--log")?;
            }
            other => return Err(format!("unknown argument {other}\n{USAGE}")),
        }
    }
    let (Some(name), Some(bind)) = (name, bind) else {
        return Err(USAGE.to_owned());
    };
    let cfg = match preset.as_str() {
        "lan" => Config::lan(),
        "wan" => Config::wan(),
        "local" => Config::local(),
        other => return Err(format!("unknown preset {other}")),
    };
    let cfg = cfg.with_name(name).with_bind(bind).with_seeds(seeds);
    Ok(match key {
        Some(key) => cfg.with_keys([key]),
        None => cfg.with_insecure_plaintext(true),
    })
}

fn addr(text: &str) -> Result<SocketAddr, String> {
    text.parse().map_err(|e| format!("bad address {text}: {e}"))
}
