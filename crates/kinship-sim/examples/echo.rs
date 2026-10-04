//! Runs a cluster of echo nodes and optionally dumps the trace as JSON.
//!
//! ```text
//! cargo run --release -p kinship-sim --example echo -- --nodes 1000 --secs 600
//! cargo run -p kinship-sim --example echo -- --nodes 5 --secs 10 --out trace.json
//! ```
//!
//! Flags: `--seed N`, `--nodes N`, `--secs N`, `--interval-ms N`, `--loss P`, `--plaintext`,
//! `--out PATH` (records the full trace; without it only counters are kept).

use std::time::{Duration, Instant};

use kinship_core::Security;
use kinship_sim::{EchoConfig, EchoNode, LinkConfig, Scenario, Sim, TraceConfig};

fn main() {
    let mut seed = 1;
    let mut nodes = 1000;
    let mut secs = 600;
    let mut interval_ms = 1000;
    let mut loss = 0.01;
    let mut plaintext = false;
    let mut out = None;
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let mut value = || args.next().unwrap_or_else(|| usage(&flag));
        match flag.as_str() {
            "--seed" => seed = parse(&value()),
            "--nodes" => nodes = parse(&value()),
            "--secs" => secs = parse(&value()),
            "--interval-ms" => interval_ms = parse(&value()),
            "--loss" => loss = parse(&value()),
            "--plaintext" => plaintext = true,
            "--out" => out = Some(value()),
            _ => usage(&flag),
        }
    }

    let trace = if out.is_some() {
        TraceConfig::ALL
    } else {
        TraceConfig::OFF
    };
    let scenario = Scenario::new(nodes)
        .duration(Duration::from_secs(secs))
        .link(LinkConfig::lan().with_loss(loss))
        .trace(trace);
    let mut cfg = EchoConfig {
        interval: Duration::from_millis(interval_ms),
        ..EchoConfig::default()
    };
    if plaintext {
        cfg.security = Security::InsecurePlaintext;
    }

    let started = Instant::now();
    let mut sim = Sim::new(seed, scenario, move |spec| EchoNode::new(spec, &cfg));
    sim.run();
    let elapsed = started.elapsed();
    println!("{nodes} nodes x {secs} s simulated in {elapsed:.2?}");
    println!("{:#?}", sim.stats());

    if let Some(path) = out {
        let file = std::fs::File::create(&path).expect("create trace file");
        sim.trace()
            .write_json(std::io::BufWriter::new(file))
            .expect("write trace");
        println!("trace written to {path}");
    }
}

fn parse<T: std::str::FromStr>(s: &str) -> T {
    s.parse()
        .unwrap_or_else(|_| panic!("cannot parse {s:?} as a number"))
}

fn usage(flag: &str) -> ! {
    eprintln!("unknown or incomplete flag {flag}; see the comment at the top of examples/echo.rs");
    std::process::exit(2);
}
