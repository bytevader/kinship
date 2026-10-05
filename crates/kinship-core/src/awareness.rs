//! Lifeguard's local health multiplier (LHM): how much this node distrusts its own view.
//!
//! The score runs from 0 to `awareness_max`. It rises when this node's probes fail in ways that
//! point at itself rather than the target: a failed probe round, each PingReq relay that sent
//! neither an Ack nor a Nack, and each rumour about itself it had to refute. It falls by one
//! on every successful probe. Probe interval and probe timeout are both multiplied by
//! `score + 1`, so a node that is slow to read its own Acks probes less often and waits longer,
//! instead of accusing healthy members.

use core::time::Duration;

use crate::Node;

impl Node {
    /// The local health multiplier: 0 when healthy, up to `awareness_max`. Always 0 when
    /// `local_health` is off.
    pub fn local_health(&self) -> u32 {
        self.health
    }

    /// Moves the score by `delta`, within `0..=awareness_max`.
    pub(crate) fn health_delta(&mut self, delta: i64) {
        if !self.cfg.local_health {
            return;
        }
        let max = i64::from(self.cfg.awareness_max);
        let next = (i64::from(self.health) + delta).clamp(0, max);
        self.health = u32::try_from(next).unwrap_or(self.cfg.awareness_max);
    }

    /// `d` stretched by the local health multiplier, `d x (score + 1)`.
    pub(crate) fn scale_by_health(&self, d: Duration) -> Duration {
        d.saturating_mul(self.health.saturating_add(1))
    }
}

#[cfg(test)]
mod tests {
    use core::net::SocketAddr;

    use crate::{Config, Identity, Instant, Node, Security};

    fn node(cfg: Config) -> Node {
        let me = Identity::new("a", SocketAddr::from(([127, 0, 0, 1], 1))).unwrap();
        Node::new(cfg, me, Instant::ZERO, 1).unwrap()
    }

    #[test]
    fn score_stays_within_bounds_and_scales_timeouts() {
        let mut n = node(Config::lan(Security::InsecurePlaintext));
        n.health_delta(-1);
        assert_eq!(n.local_health(), 0);
        n.health_delta(3);
        assert_eq!(n.local_health(), 3);
        assert_eq!(n.probe_interval(), n.config().probe_interval * 4);
        assert_eq!(n.probe_timeout(), n.config().probe_timeout * 4);
        n.health_delta(100);
        assert_eq!(n.local_health(), n.config().awareness_max);
        n.health_delta(-2);
        assert_eq!(n.local_health(), n.config().awareness_max - 2);
    }

    #[test]
    fn score_is_fixed_at_zero_without_lifeguard() {
        let mut n = node(Config::lan(Security::InsecurePlaintext).without_lifeguard());
        n.health_delta(5);
        assert_eq!(n.local_health(), 0);
        assert_eq!(n.probe_interval(), n.config().probe_interval);
    }
}
