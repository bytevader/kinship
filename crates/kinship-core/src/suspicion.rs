//! Suspicion timers, and the integer-only logarithms that size timeouts and retransmits.
//!
//! With `dynamic_suspicion` a suspicion follows the Lifeguard formula from `docs/design.md`:
//! it starts at `T_max = suspicion_max_mult x T_min` and shrinks with each independent
//! confirmation `C` to `T_max - (T_max - T_min) x log(C + 1) / log(K + 1)`, reaching
//! `T_min = suspicion_mult x max(1, log10 n) x probe_interval` at `K` confirmations. `K` is
//! `expected_confirmations`, capped at `n - 2`, the members that could confirm at all. A slow
//! member gets the long timeout to refute in, while a real failure that many members see is
//! declared at the minimum. Without it the timeout is fixed at `T_min`, as in plain SWIM.
//!
//! Logarithms are computed in fixed point from integer operations only. `f64::log10` goes to
//! the platform's libm, whose last bit may differ between systems, and a timeout that differs
//! by a nanosecond is enough to make a simulator seed replay differently on another machine.

use core::time::Duration;

use kinship_proto::Dead;

use crate::Node;
use crate::broadcast::id;
use crate::config::Config;
use crate::member::State;
use crate::time::Instant;

/// A running suspicion of one member.
#[derive(Debug, Clone)]
pub(crate) struct Suspicion {
    pub deadline: Instant,
    start: Instant,
    min: Duration,
    max: Duration,
    /// Confirmations that bring the timeout down to `min`; 0 if it starts there.
    k: u32,
    /// Distinct members that reported the suspicion, the first reporter included; this node
    /// counts too when its own probe of the member fails. Empty for a suspicion learned from a
    /// push-pull, which names no reporter.
    reporters: Vec<String>,
}

impl Suspicion {
    /// A suspicion first reported by `from` in a cluster of `n` live members.
    pub fn new(cfg: &Config, n: usize, now: Instant, from: &str) -> Self {
        let mut s = Self::unreported(cfg, n, now);
        s.reporters.push(from.to_owned());
        s
    }

    /// A suspicion nobody has reported to this node: one a peer's push-pull carried, which
    /// does not say who saw the member fail. It runs like one just reported, at the maximum
    /// timeout, and the first member to report it later counts as its first reporter.
    pub fn unreported(cfg: &Config, n: usize, now: Instant) -> Self {
        let min = min_timeout(cfg, n);
        let k = if cfg.dynamic_suspicion {
            let others = u32::try_from(n.saturating_sub(2)).unwrap_or(u32::MAX);
            cfg.expected_confirmations.min(others)
        } else {
            0
        };
        let max = if k == 0 {
            min
        } else {
            min.saturating_mul(cfg.suspicion_max_mult)
        };
        Self {
            deadline: now + max,
            start: now,
            min,
            max,
            k,
            reporters: Vec::new(),
        }
    }

    /// Records that `from` also suspects the member, shortening the timeout. True if `from` is
    /// a new, independent confirmation.
    pub fn confirm(&mut self, from: &str) -> bool {
        if self.reporters.iter().any(|c| c == from) {
            return false;
        }
        self.reporters.push(from.to_owned());
        self.deadline = self.start + self.timeout();
        true
    }

    /// Independent confirmations after the first report.
    pub fn confirmations(&self) -> u32 {
        u32::try_from(self.reporters.len().saturating_sub(1)).unwrap_or(u32::MAX)
    }

    /// `max(T_min, T_max - (T_max - T_min) x log(C + 1) / log(K + 1))`.
    fn timeout(&self) -> Duration {
        let c = self.confirmations();
        if c >= self.k {
            return self.min;
        }
        let num = u128::from(log2_q32(u64::from(c) + 1)) << 32;
        let frac = num / u128::from(log2_q32(u64::from(self.k) + 1));
        let span = (self.max - self.min).as_nanos();
        let cut = u64::try_from((span * frac) >> 32).unwrap_or(u64::MAX);
        self.max
            .saturating_sub(Duration::from_nanos(cut))
            .max(self.min)
    }
}

impl Node {
    /// Declares dead every suspect whose timer ran out without a refutation.
    pub(crate) fn suspicion_timers(&mut self, now: Instant) {
        let due: Vec<String> = self
            .suspicions
            .iter()
            .filter(|(_, s)| s.deadline <= now)
            .map(|(name, _)| name.clone())
            .collect();
        let me = self.local.member.name.clone();
        for name in due {
            self.suspicions.remove(&name);
            let Some(e) = self.table.get(&name) else {
                continue;
            };
            if e.member.state != State::Suspect {
                continue;
            }
            let dead = Dead {
                inc: e.member.incarnation,
                node: id(&name),
                from: id(&me),
            };
            self.on_dead(now, &dead);
        }
    }

    pub(crate) fn suspicion_deadline(&self) -> Option<Instant> {
        self.suspicions.values().map(|s| s.deadline).min()
    }
}

/// `suspicion_mult x max(1, log10 n) x probe_interval`.
pub(crate) fn min_timeout(cfg: &Config, n: usize) -> Duration {
    let scale = log10_q32(n as u64).max(1 << 32);
    let nanos = cfg.probe_interval.as_nanos() * u128::from(cfg.suspicion_mult) * u128::from(scale);
    Duration::from_nanos(u64::try_from(nanos >> 32).unwrap_or(u64::MAX))
}

/// How many times each broadcast is sent: `retransmit_mult x ceil(log10(n + 1))`.
pub(crate) fn retransmit_limit(cfg: &Config, n: usize) -> u32 {
    cfg.retransmit_mult.saturating_mul(ceil_log10(n as u64 + 1))
}

/// `ceil(log10 x)`, with `ceil_log10(0) == 0`.
fn ceil_log10(x: u64) -> u32 {
    let mut d = 0;
    let mut p: u64 = 1;
    while p < x {
        d += 1;
        match p.checked_mul(10) {
            Some(next) => p = next,
            None => break,
        }
    }
    d
}

/// `log2 x` in fixed point with 32 fractional bits, for `x >= 1`; 0 for `x == 0`.
fn log2_q32(x: u64) -> u64 {
    if x == 0 {
        return 0;
    }
    let int = u64::from(63 - x.leading_zeros());
    // Normalise to y in [1, 2), held with 62 fractional bits.
    let mut y = (u128::from(x) << 62) >> int;
    let mut frac = 0u64;
    for bit in (0..32).rev() {
        // Squaring doubles the logarithm; when y reaches 2 the next bit is 1.
        y = (y * y) >> 62;
        if y >= 2 << 62 {
            y >>= 1;
            frac |= 1 << bit;
        }
    }
    (int << 32) | frac
}

/// `log10 x` in fixed point with 32 fractional bits.
fn log10_q32(x: u64) -> u64 {
    // log10(2) in Q32, rounded.
    const LOG10_2: u128 = 1_292_913_987;
    ((u128::from(log2_q32(x)) * LOG10_2) >> 32) as u64
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::Security;

    fn approx(q32: u64) -> f64 {
        q32 as f64 / (1u64 << 32) as f64
    }

    #[test]
    fn fixed_point_logs_match_floats() {
        for x in [1u64, 2, 3, 7, 10, 50, 99, 100, 1000, 12345, u64::MAX] {
            let want = (x as f64).log10();
            let got = approx(log10_q32(x));
            assert!((got - want).abs() < 1e-8, "log10({x}) = {got}, want {want}");
            let want = (x as f64).log2();
            let got = approx(log2_q32(x));
            assert!((got - want).abs() < 1e-8, "log2({x}) = {got}, want {want}");
        }
        assert_eq!(log2_q32(0), 0);
    }

    #[test]
    fn ceil_log10_counts_digits() {
        assert_eq!(ceil_log10(0), 0);
        assert_eq!(ceil_log10(1), 0);
        assert_eq!(ceil_log10(2), 1);
        assert_eq!(ceil_log10(10), 1);
        assert_eq!(ceil_log10(11), 2);
        assert_eq!(ceil_log10(51), 2);
        assert_eq!(ceil_log10(101), 3);
        assert_eq!(ceil_log10(u64::MAX), 20);
    }

    #[test]
    fn timeouts_follow_the_design_formulas() {
        let cfg = Config::lan(Security::InsecurePlaintext);
        // n <= 10 uses the floor of 1: 4 x 1 x 1 s.
        assert_eq!(min_timeout(&cfg, 1), Duration::from_secs(4));
        assert_eq!(min_timeout(&cfg, 10), Duration::from_secs(4));
        // 4 x log10(100) x 1 s.
        let t = min_timeout(&cfg, 100).as_secs_f64();
        assert!((t - 8.0).abs() < 1e-6, "{t}");
        let t = min_timeout(&cfg, 50).as_secs_f64();
        assert!((t - 4.0 * 50f64.log10()).abs() < 1e-6, "{t}");
        // 4 x ceil(log10(n + 1)).
        assert_eq!(retransmit_limit(&cfg, 1), 4);
        assert_eq!(retransmit_limit(&cfg, 9), 4);
        assert_eq!(retransmit_limit(&cfg, 50), 8);
        assert_eq!(retransmit_limit(&cfg, 100), 12);
    }

    #[test]
    fn confirmations_are_distinct() {
        let cfg = Config::lan(Security::InsecurePlaintext);
        let mut s = Suspicion::new(&cfg, 5, Instant::ZERO, "a");
        assert_eq!(s.confirmations(), 0);
        assert!(!s.confirm("a"));
        assert!(
            s.confirm("me"),
            "this node's own failed probe is independent"
        );
        assert!(!s.confirm("me"));
        assert!(s.confirm("b"));
        assert_eq!(s.confirmations(), 2);
    }

    #[test]
    fn dynamic_timeout_shrinks_from_max_to_min_with_confirmations() {
        let cfg = Config::lan(Security::InsecurePlaintext);
        let n = 100;
        let (min, max) = (min_timeout(&cfg, n), min_timeout(&cfg, n) * 6);
        let mut s = Suspicion::new(&cfg, n, Instant::ZERO, "a");
        assert_eq!(s.deadline, Instant::ZERO + max);
        let mut last = max;
        for (c, from) in ["b", "c", "d"].into_iter().enumerate() {
            s.confirm(from);
            let t = s.deadline - Instant::ZERO;
            // The design formula in floating point, to within a microsecond.
            let k = 3f64;
            let want = max.as_secs_f64()
                - (max - min).as_secs_f64() * ((c + 2) as f64).ln() / (k + 1.0).ln();
            let want = want.max(min.as_secs_f64());
            assert!((t.as_secs_f64() - want).abs() < 1e-6, "C={}: {t:?}", c + 1);
            assert!(t < last);
            last = t;
        }
        assert_eq!(last, min, "K = 3 confirmations reach the minimum");
        s.confirm("e");
        assert_eq!(s.deadline - Instant::ZERO, min);
    }

    #[test]
    fn small_clusters_and_plain_swim_start_at_the_minimum() {
        let cfg = Config::lan(Security::InsecurePlaintext);
        // With 3 live members only one other could confirm, so K is capped at 1.
        let mut s = Suspicion::new(&cfg, 3, Instant::ZERO, "a");
        assert_eq!(s.deadline - Instant::ZERO, min_timeout(&cfg, 3) * 6);
        s.confirm("b");
        assert_eq!(s.deadline - Instant::ZERO, min_timeout(&cfg, 3));
        // Two members: nobody else can confirm.
        let s = Suspicion::new(&cfg, 2, Instant::ZERO, "a");
        assert_eq!(s.deadline - Instant::ZERO, min_timeout(&cfg, 2));
        let cfg = cfg.without_lifeguard();
        let s = Suspicion::new(&cfg, 100, Instant::ZERO, "a");
        assert_eq!(s.deadline - Instant::ZERO, min_timeout(&cfg, 100));
    }
}
