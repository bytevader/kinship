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
//! have. The floor therefore does not jump with a short jump: it follows cluster time at up to
//! twice the speed of this node's own clock, and moves at most half a window on any one input,
//! so for a while after a jump, its own or another member's, packets from the old timeline
//! still arrive. The nonces seen are kept down to the floor, so copies stay refused all the
//! while.
//!
//! A jump longer than the lag limit, ten windows, is not waited for: the floor never falls more
//! than that limit behind the window behind cluster time, so a stamp far ahead, from a member
//! holding a key or from an honest node that kept running while the rest of the cluster
//! restarted, stretches the window by at most the limit (KI-06). Packets from members still on
//! the old timeline are then dropped until they hear the new one, which every packet carries.
//! Such a long jump is adopted at most once a window, and none longer than [`MAX_JUMP_MS`]:
//! packets that would make another are refused before they are decrypted, so that driving
//! cluster time to u64::MAX, where it would stop moving, takes years.
//!
//! A node that is still settling, one that has not completed a join or has a join in flight,
//! has no old timeline to wait for: the first packets it hears may come from another node that
//! has just started, and the cluster's real time arrives later, with a seed's reply. While it
//! settles, every time it adopts moves the floor straight to the window behind it, so a
//! recording older than that is refused as soon as the node hears the cluster. The node tells
//! this module when it is settling.

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

/// How far behind the window behind cluster time the floor may fall, in windows: five minutes
/// with the default window. Longer than any clock jump the floor is meant to absorb.
const MAX_LAG_WINDOWS: u32 = 10;

/// The furthest a packet's stamp may be ahead of cluster time, 2^40 ms, some 35 years: past any
/// honest gap between members, such as a node that kept running for years while the rest of
/// the cluster restarted. A packet stamped further ahead is refused before it is decrypted, so
/// one packet cannot bring cluster time near u64::MAX, where it would stop moving and stamps
/// could no longer tell old packets from new.
const MAX_JUMP_MS: u64 = 1 << 40;

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
    /// Whether this node has yet to complete a join, or has one in flight: every time it
    /// adopts then moves the floor at once.
    settling: bool,
    /// When this node last adopted a cluster time past the lag limit ahead of its own.
    long_jump: Option<Instant>,
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
            settling: false,
            long_jump: None,
            seen: BTreeSet::new(),
        }
    }

    /// Whether this node has yet to complete a join, or has one in flight.
    pub fn set_settling(&mut self, settling: bool) {
        self.settling = settling;
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
    /// node's clock and by at most half a window at once, but never leaves it more than the
    /// lag limit behind that.
    pub fn tick(&mut self, now: Instant) {
        let elapsed = (now - self.ticked).min(self.window / 4);
        self.ticked = self.ticked.max(now);
        let target = self.stamp(now).saturating_sub(self.window_ms());
        let reach = self.floor.saturating_add(ms(elapsed).saturating_mul(2));
        self.raise_floor(target.min(reach));
        self.limit_lag(now);
    }

    /// The most the floor may lag behind the window behind cluster time.
    fn max_lag_ms(&self) -> u64 {
        ms(self.window.saturating_mul(MAX_LAG_WINDOWS))
    }

    /// Raises the floor to the lag limit behind the window behind cluster time, if it is
    /// further behind: after a jump that long, it does not wait for the old timeline.
    fn limit_lag(&mut self, now: Instant) {
        let lag = self.window_ms().saturating_add(self.max_lag_ms());
        self.raise_floor(self.stamp(now).saturating_sub(lag));
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

    /// Whether a packet stamped `stamp` is further ahead of cluster time at `now` than this node
    /// may jump: more than [`MAX_JUMP_MS`], or, unless it is `settling`, past the lag limit
    /// within a window of the last jump that long. A settling node has yet to hear the
    /// cluster's time, which may come after a recording or a node that has just started. Like
    /// [`is_stale`](Self::is_stale), this reads a stamp that is not yet authentic, and a forged
    /// one only gets a packet dropped that would not authenticate.
    pub fn is_too_far_ahead(&self, now: Instant, stamp: u64, settling: bool) -> bool {
        let ahead = stamp.saturating_sub(self.stamp(now));
        let recent = self.long_jump.is_some_and(|t| now - t < self.window);
        ahead > MAX_JUMP_MS || (ahead > self.max_lag_ms() && recent && !settling)
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
        let adopted = stamp > own;
        if adopted {
            self.offset = self.offset.saturating_add(stamp - own);
            if stamp - own > self.max_lag_ms() {
                self.long_jump = Some(now);
            }
        }
        // The first time this node hears the cluster it was simply behind, not jumped over,
        // so nothing older than the window is worth waiting for. Nor is it while the node
        // settles: its first packet may have come from another node that had just started,
        // and the time it adopts now, from a seed's reply, is the cluster's.
        if !self.synced || (adopted && self.settling) {
            self.synced = true;
            let target = self.stamp(now).saturating_sub(self.window_ms());
            self.raise_floor(target);
        }
        if adopted {
            self.limit_lag(now);
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
    fn a_settling_node_moves_its_floor_with_every_time_it_adopts() {
        // A node restarted together with a peer: the peer's join request reaches it first,
        // sealed at the peer's own cluster time, two seconds.
        let mut r = replay();
        r.set_settling(true);
        run(&mut r, 0, 1);
        assert!(r.accept(at(1), &nonce(2_000, 1)));
        // Then the seed's reply brings the cluster's time, an hour on.
        assert!(r.accept(at(2), &nonce(3_600_000, 2)));
        assert!(
            r.is_stale(3_570_000 - 1),
            "older than the window behind the cluster"
        );
        assert!(!r.is_stale(3_570_000));
        // A later time, while it still settles, moves the floor at once too.
        assert!(r.accept(at(3), &nonce(7_200_000, 3)));
        assert!(r.is_stale(7_170_000 - 1));

        // Settled, the same first packets leave the floor behind, to follow at the speed of
        // this node's clock: what a member's clock jump needs. A jump of an hour, past the lag
        // limit, leaves it only that limit behind.
        let mut r = replay();
        run(&mut r, 0, 1);
        assert!(r.accept(at(1), &nonce(2_000, 1)));
        assert!(r.accept(at(2), &nonce(240_000, 2)));
        assert!(!r.is_stale(3_000));
        let mut r = replay();
        run(&mut r, 0, 1);
        assert!(r.accept(at(1), &nonce(2_000, 1)));
        assert!(r.accept(at(2), &nonce(3_600_000, 2)));
        assert!(r.is_stale(3_600_000 - 330_000 - 1));
        assert!(!r.is_stale(3_600_000 - 330_000));
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
    fn cluster_time_jumps_a_bounded_amount_and_far_only_once_a_window() {
        let mut r = replay();
        assert!(r.accept(at(0), &nonce(0, 1)));
        run(&mut r, 1, 100);
        let now = r.stamp(at(100));
        // Never more than MAX_JUMP_MS ahead, settling or not, so a packet cannot bring cluster
        // time near u64::MAX.
        assert!(r.is_too_far_ahead(at(100), now + MAX_JUMP_MS + 1, true));
        assert!(r.is_too_far_ahead(at(100), u64::MAX, false));
        assert!(!r.is_too_far_ahead(at(100), now + MAX_JUMP_MS, false));
        // A day ahead, such as a node that kept running while the cluster restarted.
        let day = 86_400_000;
        assert!(r.accept(at(100), &nonce(now + day, 2)));
        // Another jump past the lag limit waits a window; shorter ones do not.
        let lag = 10 * 30_000;
        let now = r.stamp(at(110));
        assert!(r.is_too_far_ahead(at(110), now + lag + 1, false));
        assert!(
            !r.is_too_far_ahead(at(110), now + lag + 1, true),
            "unless settling"
        );
        assert!(!r.is_too_far_ahead(at(110), now + lag, false));
        let now = r.stamp(at(130));
        assert!(!r.is_too_far_ahead(at(130), now + lag + 1, false));
        // Driving cluster time from a day to u64::MAX one long jump a window would take years.
        let windows = u64::MAX / MAX_JUMP_MS;
        assert!(windows * 30 > 10 * 365 * 24 * 3_600, "{windows} windows");
    }

    #[test]
    fn a_jump_past_the_lag_limit_is_not_waited_for() {
        let lag = 10 * 30_000;
        // A member stamps a packet ten years ahead: the floor moves at once to the lag limit
        // behind the window behind it, not half a window at a time.
        let mut r = replay();
        assert!(r.accept(at(0), &nonce(0, 1)));
        run(&mut r, 1, 100);
        let ahead = 10 * 365 * 24 * 3_600_000;
        assert!(r.accept(at(100), &nonce(ahead, 2)));
        assert!(r.is_stale(ahead - 30_000 - lag - 1));
        assert!(!r.is_stale(ahead - 30_000 - lag));
        // Within the lag limit, it then catches up as from any jump: a recording made a
        // second after the jump is refused once the lag limit and the window have passed.
        run(&mut r, 101, 100 + 330);
        assert!(r.is_stale(ahead + 1_000));

        // The same holds for this node's own clock.
        let mut r = replay();
        assert!(r.accept(at(0), &nonce(0, 1)));
        run(&mut r, 1, 100);
        r.tick(at(100 + 3_600));
        assert!(r.is_stale(100_000), "the old timeline, an hour behind");
        assert!(!r.is_stale(3_700_000 - 30_000 - lag));

        // A jump inside the limit is absorbed gradually, as before.
        let mut r = replay();
        assert!(r.accept(at(0), &nonce(0, 1)));
        run(&mut r, 1, 100);
        assert!(r.accept(at(100), &nonce(100_000 + 240_000, 2)));
        assert!(!r.is_stale(100_000), "a member that has not caught up yet");
    }

    #[test]
    fn the_window_is_at_least_thirty_seconds() {
        let mut cfg = Config::lan(crate::Security::InsecurePlaintext);
        assert_eq!(window(&cfg), Duration::from_secs(30));
        cfg.tcp_timeout = Duration::from_secs(40);
        assert_eq!(window(&cfg), Duration::from_secs(80));
    }
}
