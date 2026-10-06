//! Small numeric helpers: a seeded RNG for scenario parameters, percentiles, and the analytic
//! detection bound the simulator holds kinship to.

use std::time::Duration;

/// SplitMix64: the scenario parameters only need to be reproducible from a seed.
#[derive(Debug, Clone)]
pub struct Rng(u64);

impl Rng {
    pub fn new(seed: u64) -> Self {
        Self(seed)
    }

    pub fn next_u64(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9e37_79b9_7f4a_7c15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
        z ^ (z >> 31)
    }

    /// Uniform in `0..n`.
    pub fn below(&mut self, n: u64) -> u64 {
        self.next_u64() % n
    }

    /// Uniform in `lo..=hi`, in steps of `step`.
    pub fn steps(&mut self, lo: f64, hi: f64, step: f64) -> f64 {
        let k = ((hi - lo) / step).round() as u64;
        let v = lo + step * self.below(k + 1) as f64;
        (v * 1000.0).round() / 1000.0
    }
}

/// Nearest-rank percentile of `sorted`, which must be sorted and not empty.
pub fn percentile(sorted: &[f64], p: f64) -> f64 {
    let rank = (p / 100.0 * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

/// The minimum suspicion timeout in a cluster of `n`, as the core computes it.
fn suspicion_timeout(cfg: &kinship::CoreConfig, n: usize) -> Duration {
    let scale = (n as f64).log10().max(1.0);
    let s = cfg.probe_interval.as_secs_f64() * f64::from(cfg.suspicion_mult) * scale;
    Duration::from_millis((s * 1000.0).ceil() as u64)
}

/// The latest a kill -9 can go undetected by a live node in a cluster of `n`: the bound of
/// `detection_bound` in kinship-sim's `swim` tests.
///
/// From any moment the next probe of a given member comes within two passes of the shuffled
/// round-robin list, `n - 1` probe intervals each, and that round fails one interval later.
/// Every live node's probe fails within those passes, so the Lifeguard confirmations arrive
/// and the suspicion runs for the minimum timeout. Two seconds of slack cover the network.
pub fn detection_bound(cfg: &kinship::CoreConfig, n: usize) -> Duration {
    let rounds = 2 * (n as u32 - 1) + 1;
    cfg.probe_interval * rounds + suspicion_timeout(cfg, n) + Duration::from_secs(2)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentiles_use_the_nearest_rank() {
        let v: Vec<f64> = (1..=100).map(f64::from).collect();
        assert_eq!(percentile(&v, 50.0), 50.0);
        assert_eq!(percentile(&v, 99.0), 99.0);
        assert_eq!(percentile(&v, 100.0), 100.0);
        assert_eq!(percentile(&[3.0], 99.0), 3.0);
        assert_eq!(percentile(&[1.0, 2.0], 0.0), 1.0);
    }

    #[test]
    fn the_bound_matches_the_simulator_on_lan() {
        let cfg = kinship::Config::lan();
        // 2 x 4 + 1 rounds of 1 s, a 4 s suspicion, 2 s of slack.
        assert_eq!(detection_bound(cfg.core(), 5), Duration::from_secs(15));
        // 199 rounds, 4 x log10(100) = 8 s of suspicion.
        assert_eq!(detection_bound(cfg.core(), 100), Duration::from_secs(209));
    }

    #[test]
    fn steps_stay_in_range() {
        let mut rng = Rng::new(7);
        for _ in 0..1000 {
            let v = rng.steps(1.0, 5.0, 0.5);
            assert!((1.0..=5.0).contains(&v));
            assert_eq!((v * 2.0).fract(), 0.0);
        }
    }
}
