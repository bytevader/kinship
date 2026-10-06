//! The scenario builder: cluster size, link behaviour and a timeline of faults and commands.

use core::fmt;
use std::ops::Range;
use std::time::Duration;

use kinship_core::Rng;

use crate::trace::TraceConfig;

/// A random delay, sampled per packet.
///
/// Every distribution is computed with integer and basic floating-point arithmetic only, never
/// `ln` or `cos`, so samples are bit-identical on every platform and a seed that fails in CI
/// replays the same on a laptop.
#[derive(Debug, Clone, PartialEq)]
pub enum Delay {
    Fixed(Duration),
    /// Uniform in `[min, max]`.
    Uniform {
        min: Duration,
        max: Duration,
    },
    /// Approximately normal, clamped at zero (Irwin-Hall: the sum of 12 uniforms).
    Normal {
        mean: Duration,
        std_dev: Duration,
    },
}

impl Delay {
    pub const ZERO: Delay = Delay::Fixed(Duration::ZERO);

    pub(crate) fn sample(&self, rng: &mut Rng) -> Duration {
        match *self {
            Delay::Fixed(d) => d,
            Delay::Uniform { min, max } => {
                let lo = nanos(min);
                let hi = nanos(max).max(lo);
                Duration::from_nanos(lo + rng.below((hi - lo).saturating_add(1)))
            }
            Delay::Normal { mean, std_dev } => {
                let z = (0..12).map(|_| rng.next_f64()).sum::<f64>() - 6.0;
                let x = nanos(mean) as f64 + z * nanos(std_dev) as f64;
                Duration::from_nanos(if x > 0.0 { x as u64 } else { 0 })
            }
        }
    }
}

fn nanos(d: Duration) -> u64 {
    u64::try_from(d.as_nanos()).unwrap_or(u64::MAX)
}

/// How one direction of a link treats datagrams. Streams model TCP: they are reliable and
/// ordered, so they see only `latency` and partitions.
#[derive(Debug, Clone, PartialEq)]
pub struct LinkConfig {
    /// One-way delay of each datagram.
    pub latency: Delay,
    /// Probability a datagram is lost.
    pub loss: f64,
    /// Probability a datagram is delivered twice, each copy with its own latency.
    pub duplicate: f64,
    /// Probability a datagram is held back by an extra `reorder_delay`.
    pub reorder: f64,
    pub reorder_delay: Delay,
}

impl LinkConfig {
    /// Instant, lossless delivery.
    pub fn ideal() -> Self {
        Self {
            latency: Delay::ZERO,
            loss: 0.0,
            duplicate: 0.0,
            reorder: 0.0,
            reorder_delay: Delay::ZERO,
        }
    }

    /// One datacenter: about 0.5 ms one way, no loss.
    pub fn lan() -> Self {
        Self {
            latency: Delay::Normal {
                mean: Duration::from_micros(500),
                std_dev: Duration::from_micros(100),
            },
            reorder_delay: Delay::Uniform {
                min: Duration::ZERO,
                max: Duration::from_millis(2),
            },
            ..Self::ideal()
        }
    }

    /// Across regions: about 40 ms one way, with a little loss and reordering.
    pub fn wan() -> Self {
        Self {
            latency: Delay::Normal {
                mean: Duration::from_millis(40),
                std_dev: Duration::from_millis(10),
            },
            loss: 0.001,
            reorder: 0.001,
            reorder_delay: Delay::Uniform {
                min: Duration::ZERO,
                max: Duration::from_millis(20),
            },
            ..Self::ideal()
        }
    }

    pub fn with_latency(mut self, latency: Delay) -> Self {
        self.latency = latency;
        self
    }

    pub fn with_loss(mut self, p: f64) -> Self {
        self.loss = p;
        self
    }

    pub fn with_duplicate(mut self, p: f64) -> Self {
        self.duplicate = p;
        self
    }

    pub fn with_reorder(mut self, p: f64, delay: Delay) -> Self {
        self.reorder = p;
        self.reorder_delay = delay;
        self
    }
}

impl Default for LinkConfig {
    fn default() -> Self {
        Self::lan()
    }
}

/// A set of node indices, built from a range, a single index or a list.
#[derive(Clone, PartialEq, Eq, Default)]
pub struct NodeSet(Vec<usize>);

impl NodeSet {
    pub fn new(nodes: impl IntoIterator<Item = usize>) -> Self {
        let mut v: Vec<usize> = nodes.into_iter().collect();
        v.sort_unstable();
        v.dedup();
        Self(v)
    }

    pub fn contains(&self, node: usize) -> bool {
        self.0.binary_search(&node).is_ok()
    }

    pub fn iter(&self) -> impl Iterator<Item = usize> + '_ {
        self.0.iter().copied()
    }

    pub fn len(&self) -> usize {
        self.0.len()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }
}

impl From<Range<usize>> for NodeSet {
    fn from(r: Range<usize>) -> Self {
        Self(r.collect())
    }
}

impl From<usize> for NodeSet {
    fn from(node: usize) -> Self {
        Self(vec![node])
    }
}

impl From<Vec<usize>> for NodeSet {
    fn from(v: Vec<usize>) -> Self {
        Self::new(v)
    }
}

impl From<&[usize]> for NodeSet {
    fn from(v: &[usize]) -> Self {
        Self::new(v.iter().copied())
    }
}

impl<const N: usize> From<[usize; N]> for NodeSet {
    fn from(v: [usize; N]) -> Self {
        Self::new(v)
    }
}

/// Prints runs compactly, as in `0-4,7,9-12`.
impl fmt::Display for NodeSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let mut i = 0;
        let mut first = true;
        while i < self.0.len() {
            let start = self.0[i];
            let mut end = start;
            while i + 1 < self.0.len() && self.0[i + 1] == end + 1 {
                i += 1;
                end += 1;
            }
            if !first {
                f.write_str(",")?;
            }
            first = false;
            if start == end {
                write!(f, "{start}")?;
            } else {
                write!(f, "{start}-{end}")?;
            }
            i += 1;
        }
        Ok(())
    }
}

impl fmt::Debug for NodeSet {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "NodeSet({self})")
    }
}

/// Something that happens to the cluster at a point in the scenario.
#[derive(Debug, Clone)]
pub enum Action<C> {
    /// Drop everything between `a` and `b`, both ways.
    Partition { a: NodeSet, b: NodeSet },
    /// Drop everything from `from` to `to`, one way only.
    Block { from: NodeSet, to: NodeSet },
    /// Remove every partition and block.
    Heal,
    /// Use `link` for datagrams and streams from any of `from` to any of `to`. Later rules win.
    SetLink {
        from: NodeSet,
        to: NodeSet,
        link: LinkConfig,
    },
    /// Remove every link rule, including the scenario's own, leaving the default link.
    ResetLinks,
    /// Stop processing inputs on `node` for `duration`, as a GC pause or a stopped VM would.
    /// Inputs queue up and are handled, late and in order, when the pause ends.
    Pause { node: usize, duration: Duration },
    /// Make every input on `node` cost `cost` of processing time, so inputs queue behind each
    /// other as on a starved CPU. `None` makes the node fast again.
    Slow { node: usize, cost: Option<Delay> },
    /// Hold every packet and stream event `node` receives for `delay` before the node sees it,
    /// in arrival order, while its timers still fire on time: a starved receive path, as in the
    /// Lifeguard paper's slow-node experiments, where Acks are read only after the probe timed
    /// out. `None` makes the node fast again.
    Starve { node: usize, delay: Option<Delay> },
    /// Move `node`'s clock forward by `by`, as a suspend or a VM migration can: from now on the
    /// node sees every instant `by` later than the rest of the cluster, so its timers fall due
    /// at once and fire before any packet still in flight reaches it. Jumps add up; a restart
    /// starts the node on the shared clock again.
    ClockJump { node: usize, by: Duration },
    /// Kill the node: it loses all state, and its connections fail.
    Crash(usize),
    /// Start a fresh instance of the node, with a new seed. A running node is crashed first.
    Restart(usize),
    /// Hand the node an application command.
    Command { node: usize, cmd: C },
}

impl<C> Action<C> {
    pub(crate) fn describe(&self) -> String {
        match self {
            Action::Partition { a, b } => format!("partition {a} | {b}"),
            Action::Block { from, to } => format!("block {from} -> {to}"),
            Action::Heal => "heal".to_owned(),
            Action::SetLink { from, to, link } => format!("set_link {from} -> {to} {link:?}"),
            Action::ResetLinks => "reset_links".to_owned(),
            Action::Pause { node, duration } => format!("pause {node} for {duration:?}"),
            Action::Slow { node, cost } => format!("slow {node} {cost:?}"),
            Action::Starve { node, delay } => format!("starve {node} {delay:?}"),
            Action::ClockJump { node, by } => format!("clock_jump {node} by {by:?}"),
            Action::Crash(node) => format!("crash {node}"),
            Action::Restart(node) => format!("restart {node}"),
            Action::Command { node, .. } => format!("command {node}"),
        }
    }
}

#[derive(Debug, Clone)]
pub(crate) struct LinkRule {
    pub from: NodeSet,
    pub to: NodeSet,
    pub link: LinkConfig,
}

/// A complete description of a run, apart from its seed and the node implementation.
///
/// ```
/// use std::time::Duration;
/// use kinship_sim::{Action, LinkConfig, Scenario};
///
/// let secs = Duration::from_secs;
/// let scenario: Scenario = Scenario::new(10)
///     .duration(secs(60))
///     .link(LinkConfig::lan().with_loss(0.02))
///     .at(secs(10), Action::Partition { a: (0..5).into(), b: (5..10).into() })
///     .at(secs(20), Action::Heal)
///     .at(secs(30), Action::Pause { node: 3, duration: secs(2) })
///     .at(secs(40), Action::Crash(7));
/// ```
#[derive(Debug, Clone)]
pub struct Scenario<C = ()> {
    pub(crate) nodes: usize,
    pub(crate) duration: Duration,
    pub(crate) link: LinkConfig,
    pub(crate) links: Vec<LinkRule>,
    pub(crate) slow: Vec<(usize, Delay)>,
    pub(crate) starved: Vec<(usize, Delay)>,
    pub(crate) connect_timeout: Duration,
    pub(crate) max_stream_frame: usize,
    pub(crate) trace: TraceConfig,
    pub(crate) actions: Vec<(Duration, Action<C>)>,
}

impl<C> Scenario<C> {
    /// `nodes` nodes on [`LinkConfig::lan`] links, running for 60 simulated seconds.
    pub fn new(nodes: usize) -> Self {
        Self {
            nodes,
            duration: Duration::from_secs(60),
            link: LinkConfig::lan(),
            links: Vec::new(),
            slow: Vec::new(),
            starved: Vec::new(),
            connect_timeout: Duration::from_secs(3),
            max_stream_frame: kinship_core::Limits::DEFAULT_MAX_STREAM_FRAME,
            trace: TraceConfig::default(),
            actions: Vec::new(),
        }
    }

    /// Simulated time the run lasts.
    pub fn duration(mut self, d: Duration) -> Self {
        self.duration = d;
        self
    }

    /// The link every pair of nodes uses unless a rule says otherwise.
    pub fn link(mut self, link: LinkConfig) -> Self {
        self.link = link;
        self
    }

    /// Use `link` both ways between every node of `a` and every node of `b`.
    pub fn link_between(
        mut self,
        a: impl Into<NodeSet>,
        b: impl Into<NodeSet>,
        link: LinkConfig,
    ) -> Self {
        let (a, b) = (a.into(), b.into());
        self.links.push(LinkRule {
            from: a.clone(),
            to: b.clone(),
            link: link.clone(),
        });
        self.links.push(LinkRule {
            from: b,
            to: a,
            link,
        });
        self
    }

    /// Use `link` from every node of `from` to every node of `to`, one way only.
    pub fn link_from(
        mut self,
        from: impl Into<NodeSet>,
        to: impl Into<NodeSet>,
        link: LinkConfig,
    ) -> Self {
        self.links.push(LinkRule {
            from: from.into(),
            to: to.into(),
            link,
        });
        self
    }

    /// Make `node` slow from the start; see [`Action::Slow`].
    pub fn slow_node(mut self, node: usize, cost: Delay) -> Self {
        self.slow.push((node, cost));
        self
    }

    /// Starve `node` from the start; see [`Action::Starve`].
    pub fn starved_node(mut self, node: usize, delay: Delay) -> Self {
        self.starved.push((node, delay));
        self
    }

    /// How long a TCP connect or write to an unreachable peer takes to fail. Default 3 s.
    pub fn connect_timeout(mut self, d: Duration) -> Self {
        self.connect_timeout = d;
        self
    }

    /// Largest stream frame a receiver accepts before failing the connection. Default 8 MiB.
    pub fn max_stream_frame(mut self, bytes: usize) -> Self {
        self.max_stream_frame = bytes;
        self
    }

    /// What the trace records. Everything by default.
    pub fn trace(mut self, trace: TraceConfig) -> Self {
        self.trace = trace;
        self
    }

    /// Schedule `action` at `at` after the start. Actions at the same instant run in the order
    /// they were added.
    pub fn at(mut self, at: Duration, action: Action<C>) -> Self {
        self.actions.push((at, action));
        self
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn node_set_prints_runs() {
        assert_eq!(
            NodeSet::from(vec![9, 0, 1, 2, 4, 5, 9]).to_string(),
            "0-2,4-5,9"
        );
        assert_eq!(NodeSet::from(3).to_string(), "3");
        assert_eq!(NodeSet::default().to_string(), "");
        assert!(NodeSet::from(0..4).contains(3));
        assert!(!NodeSet::from(0..4).contains(4));
    }

    #[test]
    fn delays_stay_in_range() {
        let mut rng = Rng::new(1);
        let ms = Duration::from_millis;
        let uniform = Delay::Uniform {
            min: ms(1),
            max: ms(3),
        };
        let normal = Delay::Normal {
            mean: ms(1),
            std_dev: ms(5),
        };
        for _ in 0..1000 {
            let d = uniform.sample(&mut rng);
            assert!(d >= ms(1) && d <= ms(3));
            // Clamped at zero, never negative; Irwin-Hall stays within 6 sigma.
            assert!(normal.sample(&mut rng) <= ms(31));
        }
        assert_eq!(Delay::Fixed(ms(2)).sample(&mut rng), ms(2));
    }
}
