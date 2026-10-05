//! Joins a cluster and logs every membership event until Ctrl-C, then leaves cleanly.
//!
//! ```text
//! cargo run -p kinship --example kinship-agent -- --bind 127.0.0.1:7946
//! cargo run -p kinship --example kinship-agent -- --bind 127.0.0.1:7947 127.0.0.1:7946
//! ```
//!
//! Seeds are positional `host:port` arguments. Beyond loopback, give the cluster key with
//! `--key` or `KINSHIP_KEY` (32 bytes, base64). `RUST_LOG` adjusts the log level.

use std::net::SocketAddr;
use std::process::ExitCode;
use std::time::Duration;

use kinship::{Cluster, Config, Event, Key, Member};
use tracing_subscriber::EnvFilter;

const USAGE: &str = "\
usage: kinship-agent [options] [seed host:port ...]

options:
  --preset lan|wan|local   timing preset (default: local)
  --name NAME              node name (default: host name plus 6 hex characters)
  --bind ADDR              UDP and TCP listen address, port 0 for any
  --advertise ADDR         address other nodes use to reach this one
  --cluster LABEL          cluster label (default: \"default\")
  --key BASE64             cluster key, repeatable; the first encrypts (also KINSHIP_KEY)
  --insecure               run without keys beyond loopback
  --meta TEXT              this node's metadata
  -h, --help               show this help";

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    match run().await {
        Ok(()) => ExitCode::SUCCESS,
        Err(e) => {
            eprintln!("kinship-agent: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run() -> Result<(), String> {
    let Some(cfg) = parse(std::env::args().skip(1)).await? else {
        println!("{USAGE}");
        return Ok(());
    };
    let cluster = Cluster::start(cfg).await.map_err(|e| e.to_string())?;
    let local = cluster.local();
    let names: Vec<String> = cluster.members().into_iter().map(|m| m.name).collect();
    tracing::info!(name = local.name, addr = %local.addr, members = ?names, "started");

    let mut events = cluster.events();
    loop {
        tokio::select! {
            event = events.recv() => match event {
                Some(event) => log(&cluster, event),
                None => break,
            },
            _ = tokio::signal::ctrl_c() => {
                tracing::info!("leaving");
                if let Err(e) = cluster.leave(Duration::from_secs(5)).await {
                    tracing::warn!(error = %e, "leave did not finish");
                }
                break;
            }
        }
    }
    cluster.close().await;
    Ok(())
}

fn log(cluster: &Cluster, event: Event) {
    let n = cluster.members().len();
    let show = |m: &Member| format!("{} {}", m.name, m.addr);
    match event {
        Event::MemberJoined(m) => tracing::info!(members = n, "joined: {}", show(&m)),
        Event::MemberSuspect(m) => tracing::warn!(members = n, "suspect: {}", show(&m)),
        Event::MemberRecovered(m) => tracing::info!(members = n, "recovered: {}", show(&m)),
        Event::MemberDead(m) => tracing::warn!(members = n, "dead: {}", show(&m)),
        Event::MemberLeft(m) => tracing::info!(members = n, "left: {}", show(&m)),
        Event::MemberUpdated { member, .. } => tracing::info!(
            members = n,
            meta = %String::from_utf8_lossy(&member.meta),
            "updated: {}",
            show(&member)
        ),
        Event::NameConflict { member, other_addr } => {
            tracing::error!(
                "name conflict: {} also claimed by {other_addr}",
                show(&member)
            );
        }
        Event::EventsLost(lost) => tracing::warn!(lost, members = n, "fell behind; resync"),
        other => tracing::info!("{other:?}"),
    }
}

/// The configuration the arguments describe, or `None` for `--help`.
async fn parse(mut args: impl Iterator<Item = String>) -> Result<Option<Config>, String> {
    let mut preset = "local".to_owned();
    let mut keys = Vec::new();
    let mut seeds = Vec::new();
    let mut edits: Vec<Box<dyn FnOnce(Config) -> Config>> = Vec::new();
    while let Some(arg) = args.next() {
        let mut value = |flag: &str| args.next().ok_or(format!("{flag} needs a value"));
        match arg.as_str() {
            "-h" | "--help" => return Ok(None),
            "--preset" => preset = value("--preset")?,
            "--name" => {
                let name = value("--name")?;
                edits.push(Box::new(move |c| c.with_name(name)));
            }
            "--bind" => {
                let addr = resolve(&value("--bind")?).await?;
                edits.push(Box::new(move |c| c.with_bind(addr)));
            }
            "--advertise" => {
                let addr = resolve(&value("--advertise")?).await?;
                edits.push(Box::new(move |c| c.with_advertise(addr)));
            }
            "--cluster" => {
                let label = value("--cluster")?;
                edits.push(Box::new(move |c| c.with_cluster(label)));
            }
            "--key" => keys.push(key(&value("--key")?)?),
            "--insecure" => edits.push(Box::new(|c| c.with_insecure_plaintext(true))),
            "--meta" => {
                let meta = value("--meta")?;
                edits.push(Box::new(move |c| c.with_meta(meta)));
            }
            flag if flag.starts_with('-') => return Err(format!("unknown option {flag}\n{USAGE}")),
            seed => seeds.push(resolve(seed).await?),
        }
    }
    if keys.is_empty() {
        if let Ok(k) = std::env::var("KINSHIP_KEY") {
            keys.push(key(&k)?);
        }
    }
    let cfg = match preset.as_str() {
        "lan" => Config::lan(),
        "wan" => Config::wan(),
        "local" => Config::local(),
        other => return Err(format!("unknown preset {other}")),
    };
    let cfg = edits.into_iter().fold(cfg, |c, edit| edit(c));
    Ok(Some(cfg.with_keys(keys).with_seeds(seeds)))
}

fn key(text: &str) -> Result<Key, String> {
    Key::from_base64(text).map_err(|e| format!("bad key: {e}"))
}

async fn resolve(addr: &str) -> Result<SocketAddr, String> {
    if let Ok(a) = addr.parse() {
        return Ok(a);
    }
    tokio::net::lookup_host(addr)
        .await
        .map_err(|e| format!("cannot resolve {addr}: {e}"))?
        .next()
        .ok_or(format!("no address for {addr}"))
}
