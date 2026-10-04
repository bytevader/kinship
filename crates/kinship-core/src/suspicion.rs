//! Suspicion timers, and the integer-only logarithms that size timeouts and retransmits.
//!
//! The timeout is fixed at the Lifeguard minimum, `suspicion_mult x max(1, log10 n) x
//! probe_interval`. Confirmations from independent suspecters are already counted, so the
//! dynamic Lifeguard timeout can shrink from them without changing what is tracked.
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
    /// Distinct members other than this node that reported the suspicion.
    confirmations: Vec<String>,
}

impl Suspicion {
    /// A suspicion first reported by `from` in a cluster of `n` live members.
    pub fn new(cfg: &Config, n: usize, now: Instant, me: &str, from: &str) -> Self {
        let mut s = Self {
            deadline: now + min_timeout(cfg, n),
            confirmations: Vec::new(),
        };
        s.confirm(me, from);
        s
    }

    /// Records that `from` also suspects the member. True if `from` is a new, independent
    /// confirmation.
    pub fn confirm(&mut self, me: &str, from: &str) -> bool {
        if from == me || self.confirmations.iter().any(|c| c == from) {
            return false;
        }
        self.confirmations.push(from.to_owned());
        true
    }

    #[cfg(test)]
    pub fn confirmations(&self) -> usize {
        self.confirmations.len()
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
    fn confirmations_are_distinct_and_exclude_self() {
        let cfg = Config::lan(Security::InsecurePlaintext);
        let mut s = Suspicion::new(&cfg, 5, Instant::ZERO, "me", "a");
        assert_eq!(s.confirmations(), 1);
        assert!(!s.confirm("me", "a"));
        assert!(!s.confirm("me", "me"));
        assert!(s.confirm("me", "b"));
        assert_eq!(s.confirmations(), 2);
        let s = Suspicion::new(&cfg, 5, Instant::ZERO, "me", "me");
        assert_eq!(s.confirmations(), 0);
    }
}
