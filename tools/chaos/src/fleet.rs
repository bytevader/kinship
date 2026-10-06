//! The node processes of one run, and what each of them reports about the others.
//!
//! Both node programs, `chaos-node` for kinship and `memberlist-node` for hashicorp/memberlist,
//! speak the same line protocol on stdout (see `chaos-node.rs`), so one [`Fleet`] drives either.
//! Every line is timed when it arrives here: all nodes share this host's monotonic clock, and
//! the harness reads their pipes within milliseconds.

use std::fmt;
use std::path::{Path, PathBuf};
use std::process::Stdio;
use std::time::{Duration, Instant};

use serde_json::Value;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::process::{Child, ChildStdin, Command};
use tokio::sync::mpsc;

use crate::netns::{self, Net};

/// Which membership library a node runs.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum Impl {
    Kinship,
    Memberlist,
}

impl Impl {
    pub fn parse(text: &str) -> Result<Self, String> {
        match text {
            "kinship" => Ok(Self::Kinship),
            "memberlist" => Ok(Self::Memberlist),
            other => Err(format!("unknown implementation {other}")),
        }
    }
}

impl fmt::Display for Impl {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Kinship => "kinship",
            Self::Memberlist => "memberlist",
        })
    }
}

/// What a node says about another member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Kind {
    Alive,
    Suspect,
    Dead,
    Left,
}

/// One member event, as an observer reported it.
#[derive(Debug, Clone, Copy)]
pub struct Record {
    pub at: Instant,
    pub observer: usize,
    pub member: usize,
    pub kind: Kind,
}

/// Node `i`'s name.
pub fn name(i: usize) -> String {
    format!("n{i}")
}

fn index(name: &str) -> Option<usize> {
    name.strip_prefix('n')?.parse().ok()
}

enum Line {
    Ready(u32),
    Member(Kind, usize),
    Stats(Value),
    Error(String),
    Ignored,
    /// stdout closed: the node exited or was killed.
    Closed,
}

fn parse(text: &str) -> Line {
    let Ok(v) = serde_json::from_str::<Value>(text.trim()) else {
        return Line::Ignored;
    };
    let field = |k: &str| v.get(k).and_then(Value::as_str);
    let kind = match field("ev") {
        Some("ready") => {
            return match v.get("pid").and_then(Value::as_u64) {
                Some(pid) => Line::Ready(pid as u32),
                None => Line::Error(format!("ready without a pid: {text}")),
            };
        }
        Some("stats") => return Line::Stats(v),
        Some("error") => return Line::Error(field("error").unwrap_or(text).to_owned()),
        Some("alive") => Kind::Alive,
        Some("suspect") => Kind::Suspect,
        Some("dead") => Kind::Dead,
        Some("left") => Kind::Left,
        _ => return Line::Ignored,
    };
    match field("member").and_then(index) {
        Some(m) => Line::Member(kind, m),
        None => Line::Ignored,
    }
}

struct Msg {
    node: usize,
    at: Instant,
    line: Line,
}

struct Proc {
    child: Child,
    stdin: Option<ChildStdin>,
    pid: Option<u32>,
    /// Set by a kill, or when stdout closes.
    gone: bool,
}

/// The node processes of one run.
pub struct Fleet {
    pub imp: Impl,
    pub n: usize,
    procs: Vec<Option<Proc>>,
    tx: mpsc::UnboundedSender<Msg>,
    rx: mpsc::UnboundedReceiver<Msg>,
    /// What each observer last reported about each member.
    view: Vec<Vec<Option<Kind>>>,
    /// Every member event, in arrival order.
    pub log: Vec<Record>,
    stats: Vec<Option<Value>>,
    logs: PathBuf,
}

/// What a node needs to start.
#[derive(Debug, Clone)]
pub struct Launch {
    pub kinship_bin: PathBuf,
    pub memberlist_bin: Option<PathBuf>,
    pub key: String,
    /// kinship preset; memberlist always runs DefaultLANConfig.
    pub preset: String,
}

impl Fleet {
    pub fn new(imp: Impl, n: usize, logs: &Path) -> Self {
        let (tx, rx) = mpsc::unbounded_channel();
        Self {
            imp,
            n,
            procs: (0..n).map(|_| None).collect(),
            tx,
            rx,
            view: vec![vec![None; n]; n],
            log: Vec::new(),
            stats: vec![None; n],
            logs: logs.to_owned(),
        }
    }

    /// Starts every node, the first as the seed of the rest, and waits until each has
    /// reported ready.
    pub async fn start(&mut self, net: &Net, launch: &Launch) -> Result<(), String> {
        self.spawn(net, launch, 0)?;
        self.wait_ready(&[0], Duration::from_secs(30)).await?;
        // Waves keep a hundred joins from all landing on the seed in the same instant.
        let rest: Vec<usize> = (1..self.n).collect();
        for wave in rest.chunks(25) {
            for &i in wave {
                self.spawn(net, launch, i)?;
            }
            self.wait_ready(wave, Duration::from_secs(60)).await?;
        }
        Ok(())
    }

    fn spawn(&mut self, net: &Net, launch: &Launch, i: usize) -> Result<(), String> {
        let addr = netns::addr(i);
        let seed = netns::addr(0);
        let (bin, args) = match self.imp {
            Impl::Kinship => {
                let mut args = vec![
                    "--name".to_owned(),
                    name(i),
                    "--bind".to_owned(),
                    addr.to_string(),
                    "--key".to_owned(),
                    launch.key.clone(),
                    "--preset".to_owned(),
                    launch.preset.clone(),
                ];
                if i != 0 {
                    args.extend(["--seed".to_owned(), seed.to_string()]);
                }
                if let Ok(filter) = std::env::var("CHAOS_NODE_LOG") {
                    args.extend(["--log".to_owned(), filter]);
                }
                (&launch.kinship_bin, args)
            }
            Impl::Memberlist => {
                let bin = launch
                    .memberlist_bin
                    .as_ref()
                    .ok_or("memberlist runs need --memberlist-bin")?;
                let mut args = vec![
                    "-name".to_owned(),
                    name(i),
                    "-bind".to_owned(),
                    addr.to_string(),
                    "-key".to_owned(),
                    launch.key.clone(),
                ];
                if i != 0 {
                    args.extend(["-seed".to_owned(), seed.to_string()]);
                }
                (bin, args)
            }
        };
        let log_path = self.logs.join(format!("{}-{}.log", self.imp, name(i)));
        let log = std::fs::File::create(&log_path)
            .map_err(|e| format!("cannot create {}: {e}", log_path.display()))?;
        let mut child = net
            .root
            .in_node(i, &bin.to_string_lossy(), &args)
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(log)
            .spawn()
            .map_err(|e| format!("cannot start node {i}: {e}"))?;
        let stdout = child.stdout.take().expect("stdout is piped");
        let stdin = child.stdin.take();
        let tx = self.tx.clone();
        tokio::spawn(async move {
            let mut lines = BufReader::new(stdout).lines();
            while let Ok(Some(text)) = lines.next_line().await {
                let msg = Msg {
                    node: i,
                    at: Instant::now(),
                    line: parse(&text),
                };
                if tx.send(msg).is_err() {
                    return;
                }
            }
            let _ = tx.send(Msg {
                node: i,
                at: Instant::now(),
                line: Line::Closed,
            });
        });
        self.procs[i] = Some(Proc {
            child,
            stdin,
            pid: None,
            gone: false,
        });
        Ok(())
    }

    fn apply(&mut self, msg: Msg) -> Result<(), String> {
        let i = msg.node;
        match msg.line {
            Line::Ready(pid) => {
                if let Some(p) = self.procs[i].as_mut() {
                    p.pid = Some(pid);
                }
            }
            Line::Member(kind, m) if m < self.n && m != i => {
                self.view[i][m] = Some(kind);
                self.log.push(Record {
                    at: msg.at,
                    observer: i,
                    member: m,
                    kind,
                });
            }
            Line::Stats(v) => self.stats[i] = Some(v),
            Line::Error(e) => return Err(format!("node {i}: {e}")),
            Line::Closed => {
                let killed = self.procs[i].as_ref().is_none_or(|p| p.gone);
                if let Some(p) = self.procs[i].as_mut() {
                    p.gone = true;
                }
                if !killed {
                    return Err(format!(
                        "node {i} exited on its own; see {}",
                        self.logs
                            .join(format!("{}-{}.log", self.imp, name(i)))
                            .display()
                    ));
                }
            }
            Line::Member(..) | Line::Ignored => {}
        }
        Ok(())
    }

    /// Handles node output until `done` holds or `limit` passes; returns whether it held.
    pub async fn wait_for(
        &mut self,
        limit: Duration,
        mut done: impl FnMut(&Self) -> bool,
    ) -> Result<bool, String> {
        let deadline = tokio::time::Instant::now() + limit;
        loop {
            while let Ok(msg) = self.rx.try_recv() {
                self.apply(msg)?;
            }
            if done(self) {
                return Ok(true);
            }
            match tokio::time::timeout_at(deadline, self.rx.recv()).await {
                Ok(Some(msg)) => self.apply(msg)?,
                Ok(None) => unreachable!("the fleet holds a sender"),
                Err(_) => return Ok(done(self)),
            }
        }
    }

    /// Handles node output for `period`, failing early only if a node fails.
    pub async fn run_for(&mut self, period: Duration) -> Result<(), String> {
        self.wait_for(period, |_| false).await.map(|_| ())
    }

    async fn wait_ready(&mut self, nodes: &[usize], limit: Duration) -> Result<(), String> {
        let ready = |f: &Self| {
            nodes
                .iter()
                .all(|&i| f.procs[i].as_ref().is_some_and(|p| p.pid.is_some()))
        };
        if self.wait_for(limit, ready).await? {
            Ok(())
        } else {
            let late: Vec<usize> = nodes
                .iter()
                .copied()
                .filter(|&i| self.procs[i].as_ref().is_none_or(|p| p.pid.is_none()))
                .collect();
            Err(format!(
                "nodes {late:?} did not report ready within {limit:?}; logs in {}",
                self.logs.display()
            ))
        }
    }

    pub fn is_live(&self, i: usize) -> bool {
        self.procs[i].as_ref().is_some_and(|p| !p.gone)
    }

    pub fn live(&self) -> Vec<usize> {
        (0..self.n).filter(|&i| self.is_live(i)).collect()
    }

    /// Whether every live node sees every other live node alive.
    pub fn converged(&self) -> bool {
        let live = self.live();
        live.iter().all(|&o| {
            live.iter()
                .all(|&m| m == o || self.view[o][m] == Some(Kind::Alive))
        })
    }

    /// Waits until [`converged`](Self::converged), or fails after `limit` naming the nodes
    /// with the most incomplete views.
    pub async fn converge(&mut self, limit: Duration) -> Result<Duration, String> {
        let start = Instant::now();
        if self.wait_for(limit, Self::converged).await? {
            return Ok(start.elapsed());
        }
        let live = self.live();
        let mut short: Vec<(usize, usize)> = live
            .iter()
            .map(|&o| {
                let seen = live
                    .iter()
                    .filter(|&&m| m != o && self.view[o][m] == Some(Kind::Alive))
                    .count();
                (o, seen)
            })
            .filter(|&(_, seen)| seen + 1 < live.len())
            .collect();
        short.sort_by_key(|&(_, seen)| seen);
        short.truncate(5);
        Err(format!(
            "{} nodes did not converge within {limit:?}; fewest alive members seen (node, count): {short:?}",
            self.imp
        ))
    }

    /// Sends node `i` SIGKILL and returns when the signal went out.
    pub async fn kill(&mut self, i: usize) -> Result<Instant, String> {
        let p = self.procs[i]
            .as_mut()
            .ok_or(format!("node {i} is not running"))?;
        let pid = p.pid.ok_or(format!("node {i} has no pid yet"))?;
        p.gone = true;
        let at = Instant::now();
        // The node runs as this user, so this needs no root.
        let status = tokio::time::timeout(
            Duration::from_secs(10),
            Command::new("kill")
                .args(["-KILL", &pid.to_string()])
                .status(),
        )
        .await
        .map_err(|_| "kill did not return".to_owned())?
        .map_err(|e| format!("cannot run kill: {e}"))?;
        if !status.success() {
            return Err(format!("kill -9 {pid} (node {i}) failed: {status}"));
        }
        Ok(at)
    }

    /// Asks every live node for its stats and waits for all the answers.
    pub async fn collect_stats(&mut self) -> Result<Vec<Option<Value>>, String> {
        self.stats = vec![None; self.n];
        let live = self.live();
        for &i in &live {
            if let Some(stdin) = self.procs[i].as_mut().and_then(|p| p.stdin.as_mut()) {
                stdin
                    .write_all(b"stats\n")
                    .await
                    .map_err(|e| format!("node {i}: cannot ask for stats: {e}"))?;
            }
        }
        let answered = |f: &Self| live.iter().all(|&i| f.stats[i].is_some());
        if !self.wait_for(Duration::from_secs(10), answered).await? {
            return Err("not every node answered the stats request".to_owned());
        }
        Ok(self.stats.clone())
    }

    /// Stops every node at once: SIGKILL where the pid is known, then the launcher process.
    pub async fn stop(&mut self) {
        let mut stopping = tokio::task::JoinSet::new();
        for mut p in self.procs.iter_mut().filter_map(Option::take) {
            stopping.spawn(async move {
                drop(p.stdin.take());
                if let (Some(pid), false) = (p.pid, p.gone) {
                    let _ = tokio::time::timeout(
                        Duration::from_secs(5),
                        Command::new("kill")
                            .args(["-KILL", &pid.to_string()])
                            // It may have exited already, on the closed stdin.
                            .stderr(Stdio::null())
                            .status(),
                    )
                    .await;
                }
                if tokio::time::timeout(Duration::from_secs(5), p.child.wait())
                    .await
                    .is_err()
                {
                    let _ = p.child.kill().await;
                }
            });
        }
        while stopping.join_next().await.is_some() {}
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn lines_parse_into_events() {
        assert!(matches!(
            parse(r#"{"ev":"ready","pid":42,"name":"n0"}"#),
            Line::Ready(42)
        ));
        assert!(matches!(
            parse("{\"ev\":\"dead\",\"member\":\"n7\",\"incarnation\":2}\r"),
            Line::Member(Kind::Dead, 7)
        ));
        assert!(matches!(
            parse(r#"{"ev":"suspect","member":"other"}"#),
            Line::Ignored
        ));
        assert!(matches!(parse("not json"), Line::Ignored));
        assert!(matches!(
            parse(r#"{"ev":"error","error":"boom"}"#),
            Line::Error(e) if e == "boom"
        ));
    }
}
