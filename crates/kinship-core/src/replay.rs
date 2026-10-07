//! Replay protection for encrypted packets, without a wall clock.
//!
//! Every sealed packet's 24-byte nonce starts with the sender's cluster time: milliseconds on a
//! clock the members keep in step by gossip, each adopting any later time it reads from an
//! authenticated packet. The other 16 bytes are random. A packet stamped below this node's
//! floor, normally the replay window behind its cluster time, is dropped before it is
//! decrypted, and a packet at or above the floor whose nonce was already seen is dropped after
//! it authenticates. A recording of the cluster's traffic is therefore useless once it is older
//! than the window, and a copy of a packet is useless at once.
//!
//! Cluster time is this node's monotonic clock plus an offset that only grows, so it needs no
//! synchronized wall clocks. A node that has heard nobody for longer than the window, such as a
//! freshly started one, is behind: its packets are dropped as stale until it reads a packet
//! from the cluster and catches up. A seed answers a stale join with only its own record, and
//! the joiner, now caught up, pushes and pulls again at once.
//!
//! Clocks can jump. When a member's clock jumps ahead, the others adopt its time as its packets
//! reach them, and until a node has adopted it, everything it sends looks old to those that
//! have. The floor therefore never jumps: it follows cluster time at up to twice the speed of
//! this node's own clock, and moves at most half a window on any one input, so for a while
//! after a jump, its own or another member's, packets from the old timeline still arrive. The nonces seen are kept down to
//! the floor, so copies stay refused all the while.

use core::time::Duration;
use std::collections::BTreeSet;

use kinship_proto::NONCE_LEN;

use crate::config::Config;
use crate::time::Instant;

/// Bytes of the nonce that carry the cluster time.
pub(crate) const STAMP_LEN: usize = 8;

/// Shortest replay window, whatever the timeouts: well past any delay a live packet sees.
const MIN_WINDOW: Duration = Duration::from_secs(30);

/// Nonces kept at most. Far above what a node receives in one window; past it the floor rises.
const MAX_SEEN: usize = 1 << 17;

/// The replay window for `cfg`: at least 30 s, and twice `tcp_timeout`, so a large frame sent
/// slowly but in time is never stale on arrival.
pub(crate) fn window(cfg: &Config) -> Duration {
    cfg.tcp_timeout.saturating_mul(2).max(MIN_WINDOW)
}

/// The cluster time a nonce was sealed at.
pub(crate) fn stamp_of(nonce: &[u8; NONCE_LEN]) -> u64 {
    let mut b = [0u8; STAMP_LEN];
    b.copy_from_slice(&nonce[..STAMP_LEN]);
    u64::from_be_bytes(b)
}

fn ms(d: Duration) -> u64 {
    u64::try_from(d.as_millis()).unwrap_or(u64::MAX)
}

/// This node's cluster clock and the nonces it accepted above its floor.
#[derive(Debug)]
pub(crate) struct Replay {
    /// Cluster time minus this node's clock, in milliseconds. Only ever grows.
    offset: u64,
    window: Duration,
    /// Packets stamped below this cluster time are stale. Only ever grows.
    floor: u64,
    /// When the floor last moved, on this node's clock.
    ticked: Instant,
    /// Whether this node has read the cluster time from any packet yet.
    synced: bool,
    /// Nonces accepted at or above the floor. Each starts with its big-endian stamp, so they
    /// sort by stamp.
    seen: BTreeSet<[u8; NONCE_LEN]>,
}

impl Replay {
    pub fn new(window: Duration, now: Instant) -> Self {
        Self {
            offset: 0,
            window,
            floor: 0,
            ticked: now,
            synced: false,
            seen: BTreeSet::new(),
        }
    }

    pub fn window(&self) -> Duration {
        self.window
    }

    pub fn window_ms(&self) -> u64 {
        ms(self.window)
    }

    /// Cluster time at `now`, in milliseconds.
    pub fn stamp(&self, now: Instant) -> u64 {
        (now.as_nanos() / 1_000_000).saturating_add(self.offset)
    }

    /// Moves the floor towards the window behind cluster time, at twice the speed of this
    /// node's clock and by at most half a window at once.
    pub fn tick(&mut self, now: Instant) {
        let elapsed = (now - self.ticked).min(self.window / 4);
        self.ticked = self.ticked.max(now);
        let target = self.stamp(now).saturating_sub(self.window_ms());
        let reach = self.floor.saturating_add(ms(elapsed).saturating_mul(2));
        self.raise_floor(target.min(reach));
    }

    fn raise_floor(&mut self, floor: u64) {
        if floor <= self.floor {
            return;
        }
        self.floor = floor;
        let mut from = [0u8; NONCE_LEN];
        from[..STAMP_LEN].copy_from_slice(&floor.to_be_bytes());
        self.seen = self.seen.split_off(&from);
    }

    /// Whether a packet stamped `stamp` is below the floor. Its stamp is not yet authentic: a
    /// forged one only gets an authentic packet dropped, which anyone on the path could do.
    pub fn is_stale(&self, stamp: u64) -> bool {
        stamp < self.floor
    }

    /// Records the nonce of a packet that authenticated and is not stale, and adopts its
    /// cluster time if that is ahead. False if the nonce was already seen: a replay.
    pub fn accept(&mut self, now: Instant, nonce: &[u8; NONCE_LEN]) -> bool {
        if !self.seen.insert(*nonce) {
            return false;
        }
        if self.seen.len() > MAX_SEEN {
            // Forget the oldest nonce, and refuse its stamp from now on.
            if let Some(oldest) = self.seen.pop_first() {
                self.raise_floor(stamp_of(&oldest).saturating_add(1));
            }
        }
        let stamp = stamp_of(nonce);
        let own = self.stamp(now);
        if stamp > own {
            self.offset = self.offset.saturating_add(stamp - own);
        }
        if !self.synced {
            // The first time this node hears the cluster it was simply behind, not jumped
            // over, so nothing older than the window is worth waiting for.
            self.synced = true;
            let target = self.stamp(now).saturating_sub(self.window_ms());
            self.raise_floor(target);
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn nonce(stamp: u64, tail: u8) -> [u8; NONCE_LEN] {
        let mut n = [tail; NONCE_LEN];
        n[..STAMP_LEN].copy_from_slice(&stamp.to_be_bytes());
        n
    }

    fn at(secs: u64) -> Instant {
        Instant::from_nanos(secs * 1_000_000_000)
    }

    fn replay() -> Replay {
        Replay::new(Duration::from_secs(30), Instant::ZERO)
    }

    /// Ticks once a second from `from` to `to`, as a busy node's inputs would.
    fn run(r: &mut Replay, from: u64, to: u64) {
        for s in from..=to {
            r.tick(at(s));
        }
    }

    #[test]
    fn a_copy_is_refused_inside_the_window_and_stale_after_it() {
        let mut r = replay();
        run(&mut r, 0, 5);
        let n = nonce(5_000, 1);
        assert!(!r.is_stale(stamp_of(&n)));
        assert!(r.accept(at(5), &n));
        assert!(!r.accept(at(6), &n), "a copy inside the window");
        run(&mut r, 6, 35);
        assert!(!r.is_stale(stamp_of(&n)));
        run(&mut r, 36, 36);
        assert!(r.is_stale(stamp_of(&n)), "older than the window");
        assert!(r.seen.is_empty(), "forgotten once below the floor");
    }

    #[test]
    fn the_first_packet_brings_a_new_node_up_to_date_at_once() {
        let mut r = replay();
        r.tick(at(1));
        assert_eq!(r.stamp(at(1)), 1_000);
        assert!(r.accept(at(1), &nonce(3_600_000, 1)));
        assert_eq!(r.stamp(at(1)), 3_600_000);
        assert_eq!(r.stamp(at(2)), 3_601_000);
        assert!(r.is_stale(3_000_000), "a recording from ten minutes before");
        assert!(r.accept(at(2), &nonce(3_590_000, 2)));
        assert_eq!(r.stamp(at(2)), 3_601_000, "never goes back");
    }

    #[test]
    fn after_a_jump_the_old_timeline_is_heard_for_a_while() {
        let mut r = replay();
        assert!(r.accept(at(0), &nonce(0, 1)));
        run(&mut r, 1, 100);
        // A member whose clock jumped 120 s ahead: this node adopts its time.
        assert!(r.accept(at(100), &nonce(220_000, 2)));
        run(&mut r, 100, 101);
        assert!(!r.is_stale(100_500), "a member that has not caught up yet");
        // The floor catches up a second per second and reaches the window again.
        run(&mut r, 102, 300);
        assert!(r.is_stale(100_500));
        assert!(!r.is_stale(300_000 + 120_000 - 30_000));
        assert!(r.is_stale(300_000 + 120_000 - 30_001));
    }

    #[test]
    fn a_clock_that_jumps_ahead_still_hears_the_others() {
        let mut r = replay();
        assert!(r.accept(at(0), &nonce(0, 1)));
        run(&mut r, 1, 100);
        // This node's own clock jumps 120 s: its floor moves half a window, not 120 s.
        r.tick(at(220));
        assert!(
            !r.is_stale(85_000),
            "what the others sent in the 15 s before"
        );
        assert!(r.is_stale(84_999));
    }

    #[test]
    fn past_the_cap_the_oldest_stamps_are_refused() {
        let mut r = replay();
        r.tick(at(1));
        for i in 0..=MAX_SEEN as u64 {
            let mut n = nonce(1_000 + i / 4, 0);
            n[STAMP_LEN..STAMP_LEN + 8].copy_from_slice(&i.to_be_bytes());
            assert!(r.accept(at(1), &n));
        }
        assert!(r.seen.len() <= MAX_SEEN);
        assert!(r.is_stale(1_000));
    }

    #[test]
    fn a_saturated_clock_still_bounds_the_nonces_kept() {
        let mut r = replay();
        for i in 0..=MAX_SEEN as u64 + 10 {
            let mut n = nonce(u64::MAX, 0);
            n[STAMP_LEN..STAMP_LEN + 8].copy_from_slice(&i.to_be_bytes());
            assert!(r.accept(at(1), &n));
        }
        assert_eq!(r.seen.len(), MAX_SEEN);
        assert_eq!(r.stamp(at(2)), u64::MAX);
    }

    #[test]
    fn the_window_is_at_least_thirty_seconds() {
        let mut cfg = Config::lan(crate::Security::InsecurePlaintext);
        assert_eq!(window(&cfg), Duration::from_secs(30));
        cfg.tcp_timeout = Duration::from_secs(40);
        assert_eq!(window(&cfg), Duration::from_secs(80));
    }
}
