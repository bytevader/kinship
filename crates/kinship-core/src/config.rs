//! Protocol configuration, with the `lan()`, `wan()` and `local()` presets.

use core::fmt;
use core::time::Duration;

use kinship_proto::{Codec, Key, Limits, MAX_LABEL_LEN};

/// How packets are protected.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Security {
    /// XChaCha20-Poly1305 with these keys: the first seals, every key opens.
    Keys(Vec<Key>),
    /// No authentication or encryption. For tests, the simulator and loopback use only.
    InsecurePlaintext,
}

/// Everything the protocol needs to know that is not an input.
///
/// Field names and defaults follow the configuration tables in `docs/design.md`. Build one from
/// a preset, adjust fields, and [`Node::new`](crate::Node::new) validates it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    /// Cluster label bound into every packet; clusters with different labels ignore each other.
    pub cluster: String,
    pub security: Security,
    pub limits: Limits,

    pub probe_interval: Duration,
    pub probe_timeout: Duration,
    pub indirect_checks: usize,
    pub tcp_fallback_ping: bool,
    pub suspicion_mult: u32,
    pub suspicion_max_mult: u32,
    pub expected_confirmations: u32,
    pub awareness_max: u32,
    pub dead_reclaim: Duration,

    pub gossip_interval: Duration,
    pub gossip_nodes: usize,
    pub gossip_to_the_dead: Duration,
    pub retransmit_mult: u32,
    /// Zero disables periodic push-pull.
    pub push_pull_interval: Duration,
    /// Zero disables reconnect attempts to recently dead members.
    pub reconnect_interval: Duration,
    pub rejoin_interval: Duration,
    /// Bound on each TCP exchange: connect, write and the reply.
    pub tcp_timeout: Duration,
    /// Attempts per seed in a join. Retries back off from `probe_interval`, doubling each time.
    pub join_retries: u32,
}

impl Config {
    /// One datacenter or VPC: the default, starting from memberlist's LAN values.
    pub fn lan(security: Security) -> Self {
        Self {
            cluster: "default".to_owned(),
            security,
            limits: Limits::default(),
            probe_interval: Duration::from_secs(1),
            probe_timeout: Duration::from_millis(500),
            indirect_checks: 3,
            tcp_fallback_ping: true,
            suspicion_mult: 4,
            suspicion_max_mult: 6,
            expected_confirmations: 3,
            awareness_max: 8,
            dead_reclaim: Duration::from_secs(30),
            gossip_interval: Duration::from_millis(200),
            gossip_nodes: 3,
            gossip_to_the_dead: Duration::from_secs(30),
            retransmit_mult: 4,
            push_pull_interval: Duration::from_secs(30),
            reconnect_interval: Duration::from_secs(30),
            rejoin_interval: Duration::from_secs(60),
            tcp_timeout: Duration::from_secs(10),
            join_retries: 3,
        }
    }

    /// Nodes across regions or flaky links.
    pub fn wan(security: Security) -> Self {
        Self {
            probe_interval: Duration::from_secs(5),
            probe_timeout: Duration::from_secs(3),
            suspicion_mult: 6,
            push_pull_interval: Duration::from_secs(60),
            gossip_interval: Duration::from_millis(500),
            ..Self::lan(security)
        }
    }

    /// One host: tests, the simulator and the visualizer.
    pub fn local(security: Security) -> Self {
        Self {
            probe_interval: Duration::from_millis(200),
            probe_timeout: Duration::from_millis(100),
            suspicion_mult: 3,
            push_pull_interval: Duration::from_secs(15),
            gossip_interval: Duration::from_millis(200),
            tcp_fallback_ping: false,
            ..Self::lan(security)
        }
    }

    /// Checks fields that must hold together. Errors name the offending field.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let fail = |field, reason| Err(ConfigError { field, reason });
        if self.cluster.len() > MAX_LABEL_LEN {
            return fail("cluster", "must be at most 255 bytes");
        }
        if matches!(&self.security, Security::Keys(keys) if keys.is_empty()) {
            return fail("security", "needs at least one key");
        }
        if self.probe_interval.is_zero() {
            return fail("probe_interval", "must be positive");
        }
        if self.probe_timeout.is_zero() || self.probe_timeout >= self.probe_interval {
            return fail("probe_timeout", "must be positive and below probe_interval");
        }
        if self.gossip_interval.is_zero() || self.gossip_interval > self.probe_interval {
            return fail(
                "gossip_interval",
                "must be positive and at most probe_interval",
            );
        }
        if self.suspicion_mult == 0 {
            return fail("suspicion_mult", "must be positive");
        }
        if self.suspicion_max_mult < 1 {
            return fail("suspicion_max_mult", "must be at least 1");
        }
        if self.expected_confirmations == 0 {
            return fail("expected_confirmations", "must be positive");
        }
        if self.retransmit_mult == 0 {
            return fail("retransmit_mult", "must be positive");
        }
        if self.tcp_timeout.is_zero() {
            return fail("tcp_timeout", "must be positive");
        }
        if self.join_retries == 0 {
            return fail("join_retries", "must be at least 1");
        }
        if self.codec().is_err() {
            return fail("limits", "too small to hold the packet overhead");
        }
        Ok(())
    }

    pub(crate) fn codec(&self) -> Result<Codec, kinship_proto::ConfigError> {
        let label = self.cluster.as_bytes();
        match &self.security {
            Security::Keys(keys) => Codec::encrypted(label, self.limits, keys.clone()),
            Security::InsecurePlaintext => Codec::insecure_plaintext(label, self.limits),
        }
    }
}

/// A [`Config`] or [`Identity`](crate::Identity) field holds an unusable value.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ConfigError {
    pub field: &'static str,
    pub reason: &'static str,
}

impl fmt::Display for ConfigError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "invalid config: {} {}", self.field, self.reason)
    }
}

impl std::error::Error for ConfigError {}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn presets_are_valid() {
        let key = Security::Keys(vec![Key::from_bytes([1; 32])]);
        for cfg in [
            Config::lan(key.clone()),
            Config::wan(key.clone()),
            Config::local(Security::InsecurePlaintext),
        ] {
            assert_eq!(cfg.validate(), Ok(()));
        }
    }

    #[test]
    fn validation_names_the_field() {
        let mut cfg = Config::lan(Security::InsecurePlaintext);
        cfg.probe_timeout = cfg.probe_interval;
        assert_eq!(cfg.validate().unwrap_err().field, "probe_timeout");

        let cfg = Config::lan(Security::Keys(Vec::new()));
        assert_eq!(cfg.validate().unwrap_err().field, "security");

        let mut cfg = Config::lan(Security::InsecurePlaintext);
        cfg.cluster = "x".repeat(256);
        assert_eq!(cfg.validate().unwrap_err().field, "cluster");

        let mut cfg = Config::lan(Security::InsecurePlaintext);
        cfg.limits.udp_max_payload = 4;
        assert_eq!(cfg.validate().unwrap_err().field, "limits");
    }
}
