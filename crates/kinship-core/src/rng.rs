//! A small seeded RNG, so that every random choice the core makes is reproducible.

/// xoshiro256** seeded through SplitMix64.
///
/// The core draws all its randomness (probe order, gossip targets, nonces) from one of these,
/// seeded by the driver: production seeds it from the OS, the simulator from the run's seed.
/// The output depends only on the seed and the sequence of calls, on every platform.
///
/// This is not a cryptographic RNG. Nonces drawn from it are unique per key with overwhelming
/// probability as long as the seed itself is random, which is what XChaCha20's 192-bit nonce
/// needs; production drivers must therefore seed it from the OS RNG.
#[derive(Clone)]
pub struct Rng {
    s: [u64; 4],
}

impl Rng {
    pub fn new(seed: u64) -> Self {
        let mut sm = seed;
        let mut next = || {
            sm = sm.wrapping_add(0x9e37_79b9_7f4a_7c15);
            let mut z = sm;
            z = (z ^ (z >> 30)).wrapping_mul(0xbf58_476d_1ce4_e5b9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94d0_49bb_1331_11eb);
            z ^ (z >> 31)
        };
        Self {
            s: [next(), next(), next(), next()],
        }
    }

    /// An independent generator seeded from this one.
    pub fn fork(&mut self) -> Self {
        Self::new(self.next_u64())
    }

    pub fn next_u64(&mut self) -> u64 {
        let result = self.s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = self.s[1] << 17;
        self.s[2] ^= self.s[0];
        self.s[3] ^= self.s[1];
        self.s[1] ^= self.s[2];
        self.s[0] ^= self.s[3];
        self.s[2] ^= t;
        self.s[3] = self.s[3].rotate_left(45);
        result
    }

    pub fn next_u32(&mut self) -> u32 {
        (self.next_u64() >> 32) as u32
    }

    /// A uniform value in `0..n`, without modulo bias. Returns 0 when `n` is 0.
    pub fn below(&mut self, n: u64) -> u64 {
        if n == 0 {
            return 0;
        }
        // Lemire's multiply-and-reject.
        let mut m = u128::from(self.next_u64()) * u128::from(n);
        if (m as u64) < n {
            let threshold = n.wrapping_neg() % n;
            while (m as u64) < threshold {
                m = u128::from(self.next_u64()) * u128::from(n);
            }
        }
        (m >> 64) as u64
    }

    /// A uniform index into a collection of `len` items. Returns 0 when `len` is 0.
    pub fn index(&mut self, len: usize) -> usize {
        self.below(len as u64) as usize
    }

    /// A uniform `f64` in `[0, 1)` with 53 bits of precision.
    pub fn next_f64(&mut self) -> f64 {
        (self.next_u64() >> 11) as f64 * (1.0 / (1u64 << 53) as f64)
    }

    /// True with probability `p`; `p <= 0` is never and `p >= 1` is always.
    pub fn chance(&mut self, p: f64) -> bool {
        if p <= 0.0 {
            false
        } else if p >= 1.0 {
            true
        } else {
            self.next_f64() < p
        }
    }

    pub fn fill(&mut self, out: &mut [u8]) {
        for chunk in out.chunks_mut(8) {
            let bytes = self.next_u64().to_le_bytes();
            chunk.copy_from_slice(&bytes[..chunk.len()]);
        }
    }

    /// Fisher-Yates shuffle.
    pub fn shuffle<T>(&mut self, items: &mut [T]) {
        for i in (1..items.len()).rev() {
            let j = self.index(i + 1);
            items.swap(i, j);
        }
    }
}

impl core::fmt::Debug for Rng {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("Rng")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn same_seed_same_stream() {
        let mut a = Rng::new(42);
        let mut b = Rng::new(42);
        for _ in 0..100 {
            assert_eq!(a.next_u64(), b.next_u64());
        }
        assert_ne!(Rng::new(1).next_u64(), Rng::new(2).next_u64());
    }

    #[test]
    fn output_is_pinned() {
        // Changing the generator changes every simulator seed; this pins it.
        let mut r = Rng::new(0);
        assert_eq!(r.next_u64(), 0x99ec_5f36_cb75_f2b4);
        assert_eq!(r.next_u64(), 0xbf6e_1f78_4956_452a);
    }

    #[test]
    fn below_stays_in_range() {
        let mut r = Rng::new(7);
        let mut seen = [0u32; 7];
        for _ in 0..7000 {
            seen[r.below(7) as usize] += 1;
        }
        assert!(seen.iter().all(|&n| n > 800), "{seen:?}");
        assert_eq!(r.below(0), 0);
        assert_eq!(r.below(1), 0);
    }

    #[test]
    fn unit_interval_and_chance() {
        let mut r = Rng::new(3);
        for _ in 0..1000 {
            let x = r.next_f64();
            assert!((0.0..1.0).contains(&x));
        }
        assert!(!r.chance(0.0));
        assert!(r.chance(1.0));
    }

    #[test]
    fn fill_and_shuffle() {
        let mut r = Rng::new(9);
        let mut buf = [0u8; 13];
        r.fill(&mut buf);
        assert!(buf.iter().any(|&b| b != 0));
        let mut v: Vec<u32> = (0..50).collect();
        r.shuffle(&mut v);
        let mut sorted = v.clone();
        sorted.sort_unstable();
        assert_eq!(sorted, (0..50).collect::<Vec<_>>());
        assert_ne!(v, sorted);
    }
}
