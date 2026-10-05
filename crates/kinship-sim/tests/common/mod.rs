//! Helpers shared by the seeded property tests: a core node that logs its events, and a
//! parallel seed sweep that names the lowest failing seed.

#![allow(dead_code)]

use std::cell::RefCell;
use std::net::SocketAddr;
use std::rc::Rc;
use std::time::Duration;

use kinship_core::{
    Command, CommandId, Config, Event, Identity, Instant, Key, Node, Security, StreamEvent,
    StreamId, Transmit,
};
use kinship_sim::{NodeSpec, SimNode, addr_of, name_of};

pub fn secs(s: u64) -> Duration {
    Duration::from_secs(s)
}

pub fn ms(m: u64) -> Duration {
    Duration::from_millis(m)
}

/// `lan()` with encryption, as production runs.
pub fn config() -> Config {
    Config::lan(Security::Keys(vec![Key::from_bytes([7; 32])]))
}

/// One event a node reported, and when.
#[derive(Debug, Clone)]
pub struct Seen {
    pub t: Instant,
    pub observer: usize,
    pub event: Event,
}

pub type Log = Rc<RefCell<Vec<Seen>>>;

/// A core node that copies every event into a shared log, stamped with the time of the input
/// that produced it.
pub struct Observed {
    pub node: Node,
    index: usize,
    now: Instant,
    log: Log,
}

impl Observed {
    /// A node running [`config`] that starts out knowing the nodes `knows` accepts, as a static
    /// member list would, and logs into `log`.
    pub fn new(spec: &NodeSpec, log: Log, knows: impl Fn(usize) -> bool) -> Self {
        let me = Identity::new(spec.name.clone(), spec.addr).unwrap();
        let mut node = Node::new(config(), me, spec.now, spec.seed).unwrap();
        for j in (0..spec.nodes).filter(|&j| j != spec.index && knows(j)) {
            node.add_member(spec.now, &name_of(j), addr_of(j)).unwrap();
        }
        while node.poll_event().is_some() {}
        Self {
            node,
            index: spec.index,
            now: spec.now,
            log,
        }
    }
}

impl SimNode for Observed {
    type Command = Command;
    type Event = Event;

    fn handle_datagram(&mut self, now: Instant, from: SocketAddr, buf: &[u8]) {
        self.now = now;
        self.node.handle_datagram(now, from, buf);
    }

    fn handle_stream(&mut self, now: Instant, conn: StreamId, ev: StreamEvent<'_>) {
        self.now = now;
        self.node.handle_stream(now, conn, ev);
    }

    fn handle_timeout(&mut self, now: Instant) {
        self.now = now;
        self.node.handle_timeout(now);
    }

    fn command(&mut self, now: Instant, cmd: Command) -> CommandId {
        self.now = now;
        self.node.command(now, cmd)
    }

    fn poll_transmit(&mut self) -> Option<Transmit> {
        self.node.poll_transmit()
    }

    fn poll_event(&mut self) -> Option<Event> {
        let event = self.node.poll_event()?;
        self.log.borrow_mut().push(Seen {
            t: self.now,
            observer: self.index,
            event: event.clone(),
        });
        Some(event)
    }

    fn poll_timeout(&self) -> Option<Instant> {
        self.node.poll_timeout()
    }
}

pub fn index_of(name: &str) -> usize {
    name[1..].parse().expect("simulator names are n<index>")
}

pub fn env(name: &str) -> Option<u64> {
    std::env::var(name).ok().and_then(|v| v.parse().ok())
}

/// The seeds a sweep runs: `KINSHIP_SEED` replays one, `KINSHIP_SEEDS` sets the count.
pub fn seeds(default: u64) -> std::ops::Range<u64> {
    match env("KINSHIP_SEED") {
        Some(seed) => seed..seed + 1,
        None => 0..env("KINSHIP_SEEDS").unwrap_or(default),
    }
}

/// Runs `check` on every seed in parallel; panics naming the lowest failing seed.
pub fn check_all<T: Send>(
    seeds: std::ops::Range<u64>,
    check: impl Fn(u64) -> Result<T, String> + Sync,
) -> Vec<T> {
    let threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    let next = std::sync::atomic::AtomicU64::new(seeds.start);
    let results = std::sync::Mutex::new(Vec::new());
    std::thread::scope(|s| {
        for _ in 0..threads {
            s.spawn(|| {
                loop {
                    let seed = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                    if seed >= seeds.end {
                        break;
                    }
                    let r = check(seed);
                    results.lock().unwrap().push((seed, r));
                }
            });
        }
    });
    let mut results = results.into_inner().unwrap();
    results.sort_by_key(|r| r.0);
    let failures: Vec<&(u64, Result<T, String>)> =
        results.iter().filter(|r| r.1.is_err()).collect();
    if let Some((seed, Err(msg))) = failures.first() {
        let lines: Vec<&str> = failures
            .iter()
            .filter_map(|f| f.1.as_ref().err()?.lines().next())
            .take(20)
            .collect();
        panic!(
            "{} of {} seeds failed:\n{}\nfirst failing seed: {seed}\n{msg}",
            failures.len(),
            results.len(),
            lines.join("\n")
        );
    }
    results.into_iter().filter_map(|r| r.1.ok()).collect()
}

/// p50, p99 and max of `d`, for sweep summaries.
pub fn percentiles(mut d: Vec<Duration>) -> String {
    d.sort_unstable();
    let pct = |p: usize| d.get((d.len() * p / 100).min(d.len().saturating_sub(1)));
    format!("p50 {:?}, p99 {:?}, max {:?}", pct(50), pct(99), d.last())
}
