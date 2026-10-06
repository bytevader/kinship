//! Detection latency after kill -9, kinship against hashicorp/memberlist.
//!
//! Both run the same topology under the same netem, and each run kills the same node in both.
//! A run starts the cluster, waits until every node sees every other alive, lets it settle,
//! kills one node and times, for every live node, the gap from the kill to its dead event for
//! that node. Runs alternate between the implementations so both see the same host.
//!
//! Every row goes to a CSV as soon as its run ends, and a rerun skips the runs the CSV already
//! holds, so a long bench can resume. `chaos summarize` turns the CSV into the results table.

use std::collections::{BTreeMap, HashSet};
use std::fs::OpenOptions;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use crate::fleet::{Fleet, Impl, Kind, Launch, name};
use crate::netns::{Net, Netem};
use crate::scenario::converge_limit;
use crate::stats::{Rng, detection_bound, percentile};

const HEADER: &str = "impl,run,victim,observer,detect_s,false_deaths";

#[derive(Debug, Clone)]
pub struct Bench {
    pub nodes: usize,
    pub runs: u64,
    pub impls: Vec<Impl>,
    pub netem: Netem,
    pub settle: Duration,
    pub seed: u64,
    pub csv: PathBuf,
    /// Run only this one, to replay it.
    pub only_run: Option<u64>,
}

impl Bench {
    fn victim(&self, run: u64) -> usize {
        1 + Rng::new(self.seed.wrapping_add(run)).below(self.nodes as u64 - 1) as usize
    }

    fn describe(&self, imp: Impl, run: u64) -> String {
        format!(
            "bench impl={imp} run={run} seed={} nodes={} netem={} settle={}s killed={}; \
             replay with: chaos bench --impls {imp} --nodes {} --seed {} --run {run} --netem {} --settle {}",
            self.seed,
            self.nodes,
            self.netem,
            self.settle.as_secs(),
            name(self.victim(run)),
            self.nodes,
            self.seed,
            self.netem,
            self.settle.as_secs()
        )
    }
}

/// Runs every (implementation, run) pair the CSV does not hold yet.
pub async fn run(net: &Net, launch: &Launch, b: &Bench, logs: &Path) -> Result<(), String> {
    if b.nodes < 3 {
        return Err("the bench needs at least 3 nodes".to_owned());
    }
    let done = existing(&b.csv)?;
    let mut csv = OpenOptions::new()
        .create(true)
        .append(true)
        .open(&b.csv)
        .map_err(|e| format!("cannot open {}: {e}", b.csv.display()))?;
    if done.is_empty() {
        writeln!(csv, "{HEADER}").map_err(|e| e.to_string())?;
    }
    net.netem_all(&b.netem).await?;
    let result = runs(net, launch, b, logs, &done, &mut csv).await;
    let reset = net.netem_all(&Netem::default()).await;
    result?;
    reset
}

async fn runs(
    net: &Net,
    launch: &Launch,
    b: &Bench,
    logs: &Path,
    done: &HashSet<(String, u64)>,
    csv: &mut std::fs::File,
) -> Result<(), String> {
    for run in 0..b.runs {
        for &imp in &b.impls {
            if done.contains(&(imp.to_string(), run)) || b.only_run.is_some_and(|r| r != run) {
                continue;
            }
            let mut fleet = Fleet::new(imp, b.nodes, logs);
            let result = one(net, launch, b, run, &mut fleet).await;
            fleet.stop().await;
            let rows = result.map_err(|e| format!("{}\n{e}", b.describe(imp, run)))?;
            let mut text = String::new();
            for row in &rows.rows {
                text += &format!("{imp},{run},{},{row}\n", b.victim(run));
            }
            csv.write_all(text.as_bytes())
                .and_then(|()| csv.flush())
                .map_err(|e| format!("cannot write {}: {e}", b.csv.display()))?;
            eprintln!("{imp} run {run}: {}", rows.summary);
        }
    }
    Ok(())
}

struct Rows {
    /// `observer,detect_s,false_deaths`, `detect_s` empty when it never declared the victim
    /// dead.
    rows: Vec<String>,
    summary: String,
}

async fn one(
    net: &Net,
    launch: &Launch,
    b: &Bench,
    run: u64,
    fleet: &mut Fleet,
) -> Result<Rows, String> {
    let victim = b.victim(run);
    // memberlist runs DefaultLANConfig, whose timing is lan()'s, so one bound serves both.
    let bound = detection_bound(kinship::Config::lan().core(), b.nodes);
    fleet.start(net, launch).await?;
    let took = fleet.converge(converge_limit(b.nodes)).await?;
    let start = Instant::now();
    fleet.run_for(b.settle).await?;
    let killed = fleet.kill(victim).await?;
    let dead_at = |f: &Fleet, o: usize| {
        f.log
            .iter()
            .find(|r| {
                r.observer == o && r.member == victim && r.kind == Kind::Dead && r.at >= killed
            })
            .map(|r| r.at - killed)
    };
    fleet
        .wait_for(bound, |f| f.live().iter().all(|&o| dead_at(f, o).is_some()))
        .await?;
    let false_deaths = fleet
        .log
        .iter()
        .filter(|r| r.at >= start && r.member != victim && matches!(r.kind, Kind::Dead))
        .count();
    let mut rows = Vec::new();
    let mut detected = Vec::new();
    for o in fleet.live() {
        let d = dead_at(fleet, o);
        if let Some(d) = d {
            detected.push(d.as_secs_f64());
        }
        let cell = d.map_or(String::new(), |d| format!("{:.3}", d.as_secs_f64()));
        rows.push(format!("{},{cell},{false_deaths}", name(o)));
    }
    detected.sort_by(f64::total_cmp);
    let summary = if detected.is_empty() {
        format!("no node declared {} dead", name(victim))
    } else {
        format!(
            "converged in {:.1}s, {} of {} detected, p50 {:.2}s max {:.2}s, {false_deaths} false deaths",
            took.as_secs_f64(),
            detected.len(),
            rows.len(),
            percentile(&detected, 50.0),
            percentile(&detected, 100.0)
        )
    };
    Ok(Rows { rows, summary })
}

/// The (implementation, run) pairs already in the CSV.
fn existing(csv: &Path) -> Result<HashSet<(String, u64)>, String> {
    let text = match std::fs::read_to_string(csv) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(HashSet::new()),
        Err(e) => return Err(format!("cannot read {}: {e}", csv.display())),
    };
    let mut done = HashSet::new();
    for line in text.lines().skip(1) {
        let mut cells = line.split(',');
        if let (Some(imp), Some(run)) = (cells.next(), cells.next()) {
            let run = run
                .parse()
                .map_err(|_| format!("bad row in {}: {line}", csv.display()))?;
            done.insert((imp.to_owned(), run));
        }
    }
    Ok(done)
}

/// The results table for a bench CSV, in Markdown.
pub fn summarize(text: &str) -> Result<String, String> {
    #[derive(Default)]
    struct Acc {
        detections: Vec<f64>,
        undetected: usize,
        /// Per run: the slowest detection, or None if some node never detected the kill.
        runs: BTreeMap<u64, Option<f64>>,
        false_deaths: BTreeMap<u64, u64>,
    }
    let mut by: BTreeMap<String, Acc> = BTreeMap::new();
    let mut lines = text.lines();
    if lines.next() != Some(HEADER) {
        return Err(format!("expected the header {HEADER}"));
    }
    for line in lines.filter(|l| !l.is_empty()) {
        let c: Vec<&str> = line.split(',').collect();
        let [imp, run, _victim, _observer, detect, false_deaths] = c[..] else {
            return Err(format!("bad row: {line}"));
        };
        let bad = || format!("bad row: {line}");
        let run: u64 = run.parse().map_err(|_| bad())?;
        let acc = by.entry(imp.to_owned()).or_default();
        acc.false_deaths
            .insert(run, false_deaths.parse().map_err(|_| bad())?);
        let slowest = acc.runs.entry(run).or_insert(Some(0.0));
        if detect.is_empty() {
            acc.undetected += 1;
            *slowest = None;
        } else {
            let d: f64 = detect.parse().map_err(|_| bad())?;
            acc.detections.push(d);
            if let Some(s) = slowest {
                *s = s.max(d);
            }
        }
    }
    let mut out = String::from(
        "| Implementation | Runs | Detections | p50 (s) | p99 (s) | Max (s) | Every node, p50 (s) | Every node, max (s) | Undetected | False deaths |\n\
         | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |\n",
    );
    for (imp, mut acc) in by {
        acc.detections.sort_by(f64::total_cmp);
        let mut whole: Vec<f64> = acc.runs.values().flatten().copied().collect();
        whole.sort_by(f64::total_cmp);
        let p = |v: &[f64], q: f64| {
            if v.is_empty() {
                "-".to_owned()
            } else {
                format!("{:.3}", percentile(v, q))
            }
        };
        out += &format!(
            "| {imp} | {} | {} | {} | {} | {} | {} | {} | {} | {} |\n",
            acc.runs.len(),
            acc.detections.len(),
            p(&acc.detections, 50.0),
            p(&acc.detections, 99.0),
            p(&acc.detections, 100.0),
            p(&whole, 50.0),
            p(&whole, 100.0),
            acc.undetected,
            acc.false_deaths.values().sum::<u64>()
        );
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_summary_counts_runs_detections_and_misses() {
        let csv = format!(
            "{HEADER}\n\
             kinship,0,3,n0,5.000,0\n\
             kinship,0,3,n1,7.000,0\n\
             kinship,1,2,n0,4.000,1\n\
             kinship,1,2,n1,,1\n\
             memberlist,0,3,n0,6.000,0\n"
        );
        let table = summarize(&csv).unwrap();
        let rows: Vec<&str> = table.lines().skip(2).collect();
        assert_eq!(
            rows[0],
            "| kinship | 2 | 3 | 5.000 | 7.000 | 7.000 | 7.000 | 7.000 | 1 | 1 |"
        );
        assert_eq!(
            rows[1],
            "| memberlist | 1 | 1 | 6.000 | 6.000 | 6.000 | 6.000 | 6.000 | 0 | 0 |"
        );
    }

    #[test]
    fn victims_are_never_the_seed_and_repeat_per_run() {
        let b = Bench {
            nodes: 100,
            runs: 20,
            impls: vec![Impl::Kinship, Impl::Memberlist],
            netem: Netem::default(),
            settle: Duration::from_secs(15),
            seed: 1,
            csv: PathBuf::from("x.csv"),
            only_run: None,
        };
        for run in 0..50 {
            let v = b.victim(run);
            assert!((1..100).contains(&v));
            assert_eq!(v, b.victim(run));
        }
    }
}
