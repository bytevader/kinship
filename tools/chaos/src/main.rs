//! Chaos runs and detection latency for kinship on real sockets. Linux only, and the network
//! setup needs root (see `netns::Root`).
//!
//! ```text
//! chaos run [--scenario loss|kill|udp-block|all] [--nodes 5] [--seed N] [--duration 60]
//!           [--netem delay=5ms,jitter=1ms,loss=2%,reorder=10%]
//! chaos bench [--nodes 100] [--runs 20] [--impls kinship,memberlist] [--memberlist-bin PATH]
//!             [--netem SPEC] [--settle 15] [--seed N] [--run R] [--csv PATH]
//! chaos summarize PATH.csv
//! chaos cleanup
//! ```
//!
//! Common options: `--node-bin PATH` (default: `chaos-node` next to this binary) and
//! `--logs DIR` for each node's stderr (default: `target/chaos-logs`).

mod bench;
mod fleet;
mod netns;
mod scenario;
mod stats;

use std::collections::HashMap;
use std::path::PathBuf;
use std::process::ExitCode;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use fleet::{Impl, Launch};
use netns::{Net, Netem, Root};
use scenario::{Params, Scenario};

const USAGE: &str = "\
usage: chaos run [--scenario loss|kill|udp-block|all] [--nodes N] [--seed N] [--duration SECS]
                 [--netem SPEC]
       chaos bench [--nodes N] [--runs N] [--impls kinship,memberlist] [--memberlist-bin PATH]
                   [--netem SPEC] [--settle SECS] [--seed N] [--run R] [--csv PATH]
       chaos summarize PATH.csv
       chaos cleanup

common options: --node-bin PATH, --logs DIR, --preset lan|local|wan (kinship nodes)
SPEC: delay=5ms,jitter=1ms,loss=2%,reorder=10% (any subset), or none
Root commands run through sudo -n, or the command in CHAOS_SUDO.";

#[tokio::main]
async fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    match run(args).await {
        Ok(true) => ExitCode::SUCCESS,
        Ok(false) => ExitCode::FAILURE,
        Err(e) => {
            eprintln!("chaos: {e}");
            ExitCode::FAILURE
        }
    }
}

async fn run(args: Vec<String>) -> Result<bool, String> {
    let Some((command, rest)) = args.split_first() else {
        println!("{USAGE}");
        return Ok(true);
    };
    if command == "summarize" {
        let [path] = rest else {
            return Err(USAGE.to_owned());
        };
        let text = std::fs::read_to_string(path).map_err(|e| format!("cannot read {path}: {e}"))?;
        print!("{}", bench::summarize(&text)?);
        return Ok(true);
    }
    let opts = Opts::parse(rest)?;
    match command.as_str() {
        "run" => chaos(&opts).await,
        "bench" => bench(&opts).await,
        "cleanup" => {
            netns::cleanup(&Root::detect().await?).await?;
            Ok(true)
        }
        "-h" | "--help" | "help" => {
            println!("{USAGE}");
            Ok(true)
        }
        other => Err(format!("unknown command {other}\n{USAGE}")),
    }
}

async fn chaos(opts: &Opts) -> Result<bool, String> {
    let scenarios = Scenario::parse(opts.get("scenario").unwrap_or("all"))?;
    let nodes = opts.number("nodes", 5)? as usize;
    let seed = opts.seed()?;
    let duration = Duration::from_secs(opts.number("duration", 60)?);
    let netem = opts.get("netem").map(Netem::parse).transpose()?;
    let launch = opts.launch()?;
    let logs = opts.logs()?;

    let net = Net::create(Root::detect().await?, nodes).await?;
    let all = async {
        let mut passed = true;
        for s in scenarios {
            let p = Params::draw(s, seed, nodes, duration, netem);
            println!("chaos: {p}");
            match scenario::run(&net, &launch, &p, &logs).await {
                Ok(summary) => println!("chaos: ok {}: {summary}", p.scenario),
                Err(e) => {
                    passed = false;
                    println!(
                        "chaos: FAILED {p}\n{e}\nreplay with: {}\nnode logs: {}",
                        p.replay(),
                        logs.display()
                    );
                }
            }
        }
        Ok(passed)
    };
    let result = until_interrupted(all).await;
    net.destroy().await?;
    result
}

async fn bench(opts: &Opts) -> Result<bool, String> {
    let only_run = opts.get("run").map(|_| opts.number("run", 0)).transpose()?;
    let b = bench::Bench {
        nodes: opts.number("nodes", 100)? as usize,
        runs: only_run.map_or(opts.number("runs", 20)?, |r| r + 1),
        impls: opts
            .get("impls")
            .unwrap_or("kinship,memberlist")
            .split(',')
            .map(Impl::parse)
            .collect::<Result<_, _>>()?,
        netem: Netem::parse(opts.get("netem").unwrap_or("delay=2ms,jitter=1ms,loss=1%"))?,
        settle: Duration::from_secs(opts.number("settle", 15)?),
        seed: opts.seed()?,
        csv: PathBuf::from(opts.get("csv").unwrap_or("detection.csv")),
        only_run,
    };
    let launch = opts.launch()?;
    let logs = opts.logs()?;
    println!(
        "chaos: bench nodes={} runs={} impls={:?} netem={} settle={}s seed={} csv={}",
        b.nodes,
        b.runs,
        b.impls,
        b.netem,
        b.settle.as_secs(),
        b.seed,
        b.csv.display()
    );
    let net = Net::create(Root::detect().await?, b.nodes).await?;
    let result = until_interrupted(bench::run(&net, &launch, &b, &logs)).await;
    net.destroy().await?;
    result?;
    let text = std::fs::read_to_string(&b.csv).map_err(|e| e.to_string())?;
    print!("{}", bench::summarize(&text)?);
    Ok(true)
}

/// Runs `work` unless SIGINT or SIGTERM comes first, so the caller can still remove the
/// namespaces. Dropping `work` closes every node's stdin, and the nodes exit.
async fn until_interrupted<T>(work: impl Future<Output = Result<T, String>>) -> Result<T, String> {
    tokio::select! {
        result = work => result,
        signal = interrupted() => Err(format!("interrupted by {signal}")),
    }
}

async fn interrupted() -> &'static str {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                Ok(()) = tokio::signal::ctrl_c() => return "SIGINT",
                _ = term.recv() => return "SIGTERM",
            }
        }
    }
    match tokio::signal::ctrl_c().await {
        Ok(()) => "Ctrl-C",
        // No handler, so no interruption to wait for.
        Err(_) => std::future::pending().await,
    }
}

/// `--flag value` pairs.
struct Opts(HashMap<String, String>);

impl Opts {
    fn parse(args: &[String]) -> Result<Self, String> {
        let mut map = HashMap::new();
        let mut it = args.iter();
        while let Some(flag) = it.next() {
            let key = flag
                .strip_prefix("--")
                .ok_or(format!("unexpected argument {flag}\n{USAGE}"))?;
            let value = it.next().ok_or(format!("{flag} needs a value"))?;
            map.insert(key.to_owned(), value.clone());
        }
        Ok(Self(map))
    }

    fn get(&self, key: &str) -> Option<&str> {
        self.0.get(key).map(String::as_str)
    }

    fn number(&self, key: &str, default: u64) -> Result<u64, String> {
        self.get(key).map_or(Ok(default), |v| {
            v.parse().map_err(|_| format!("--{key} needs a number"))
        })
    }

    fn seed(&self) -> Result<u64, String> {
        match self.get("seed") {
            Some(_) => self.number("seed", 0),
            None => Ok(SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map_or(0, |d| d.as_nanos() as u64)),
        }
    }

    fn launch(&self) -> Result<Launch, String> {
        let kinship_bin = match self.get("node-bin") {
            Some(p) => PathBuf::from(p),
            None => std::env::current_exe()
                .map_err(|e| e.to_string())?
                .with_file_name("chaos-node"),
        };
        let absolute = |p: PathBuf| std::path::absolute(&p).map_err(|e| e.to_string());
        let key = kinship::generate_key().map_err(|e| format!("cannot draw a key: {e}"))?;
        Ok(Launch {
            kinship_bin: absolute(kinship_bin)?,
            memberlist_bin: self
                .get("memberlist-bin")
                .map(|p| absolute(PathBuf::from(p)))
                .transpose()?,
            key: key.to_base64(),
            preset: self.get("preset").unwrap_or("lan").to_owned(),
        })
    }

    fn logs(&self) -> Result<PathBuf, String> {
        let dir = PathBuf::from(self.get("logs").unwrap_or("target/chaos-logs"));
        std::fs::create_dir_all(&dir)
            .map_err(|e| format!("cannot create {}: {e}", dir.display()))?;
        Ok(dir)
    }
}
