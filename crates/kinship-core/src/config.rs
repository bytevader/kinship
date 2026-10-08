//! Protocol configuration, with the `lan()`, `wan()` and `local()` presets.

use core::fmt;
use core::net::{Ipv6Addr, SocketAddr};
use core::time::Duration;

use kinship_proto::{Alive, Codec, Key, Limits, MAX_LABEL_LEN, Message, NodeId, Ping};

use crate::broadcast::{datagram_room, id};

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
    /// Lifeguard: stretch probe interval and timeout by the local health multiplier, which
    /// rises when this node's own probes go unanswered and falls when they succeed.
    pub local_health: bool,
    /// Lifeguard: ask PingReq relays for a Nack when the target is silent too, and count each
    /// relay that sends neither against local health.
    pub nacks: bool,
    /// Lifeguard: start each suspicion at `suspicion_max_mult` times the minimum timeout and
    /// shrink it toward the minimum as independent members confirm it.
    pub dynamic_suspicion: bool,
    /// Lifeguard: put a Suspect first in every Ping to a suspected member, so it hears the
    /// rumour on the next probe and refutes at once.
    pub buddy_system: bool,

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
            local_health: true,
            nacks: true,
            dynamic_suspicion: true,
            buddy_system: true,
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

    /// Turns off all four Lifeguard extensions, leaving plain SWIM with a fixed suspicion
    /// timeout at the Lifeguard minimum. For experiments and tests that compare the two.
    pub fn without_lifeguard(self) -> Self {
        Self {
            local_health: false,
            nacks: false,
            dynamic_suspicion: false,
            buddy_system: false,
            ..self
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
        let Ok(codec) = self.measuring_codec() else {
            return fail("limits", "too small to hold the packet overhead");
        };
        let room = datagram_room(&codec);
        if largest_probe_and_alive(self.limits.max_meta_bytes, room) > room {
            // A member whose own Alive never fits a datagram cannot refute over UDP. Name the
            // limit that was moved from its default.
            return if self.limits.udp_max_payload < Limits::DEFAULT_UDP_MAX_PAYLOAD {
                fail(
                    "udp_max_payload",
                    "must fit an Alive with max_meta_bytes of metadata beside a Ping",
                )
            } else {
                fail(
                    "max_meta_bytes",
                    "must leave an Alive that fits a udp_max_payload datagram beside a Ping",
                )
            };
        }
        Ok(())
    }

    /// A codec in this config's mode, to measure packets with. It holds a copy of the sealing
    /// key alone, which is zeroized when the codec is dropped at the end of validation.
    fn measuring_codec(&self) -> Result<Codec, kinship_proto::ConfigError> {
        let label = self.cluster.as_bytes();
        match &self.security {
            Security::Keys(keys) => Codec::encrypted(label, self.limits, keys[..1].to_vec()),
            Security::InsecurePlaintext => Codec::insecure_plaintext(label, self.limits),
        }
    }

    /// The codec this config describes, with its keys moved into it: what is left in
    /// `security` is an empty list of keys.
    pub(crate) fn take_codec(&mut self) -> Result<Codec, kinship_proto::ConfigError> {
        let label = self.cluster.as_bytes();
        match &mut self.security {
            Security::Keys(keys) => Codec::encrypted(label, self.limits, std::mem::take(keys)),
            Security::InsecurePlaintext => Codec::insecure_plaintext(label, self.limits),
        }
    }
}

/// Encoded size of the largest Ping and the largest Alive a node can hold: 64-byte names, an
/// IPv6 address and `max_meta` bytes of metadata, counted up to `cap` bytes of it.
fn largest_probe_and_alive(max_meta: usize, cap: usize) -> usize {
    let name = "n".repeat(NodeId::MAX_LEN);
    let addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0));
    // Metadata past the whole datagram can only fail too, and is not worth allocating.
    let meta = vec![0; max_meta.min(cap.saturating_add(1))];
    let ping = Message::Ping(Ping {
        seq: u32::MAX,
        target: id(&name),
        source: id(&name),
        source_addr: addr,
    });
    let alive = Message::Alive(Alive {
        inc: u32::MAX,
        node: id(&name),
        addr,
        meta: &meta,
        vmin: u8::MAX,
        vmax: u8::MAX,
    });
    ping.encoded_len() + alive.encoded_len()
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

    #[test]
    fn taking_the_codec_moves_the_keys_out_of_the_config() {
        let key = Key::from_bytes([1; 32]);
        let mut cfg = Config::lan(Security::Keys(vec![key.clone()]));
        assert_eq!(cfg.validate(), Ok(()));
        let codec = cfg.take_codec().unwrap();
        assert_eq!(codec.key_ids(), [key.key_id()]);
        assert_eq!(cfg.security, Security::Keys(Vec::new()));
        let mut plain = Config::lan(Security::InsecurePlaintext);
        assert!(!plain.take_codec().unwrap().is_encrypted());
        assert_eq!(plain.security, Security::InsecurePlaintext);
    }

    #[test]
    fn the_largest_alive_must_fit_a_datagram_beside_a_ping() {
        let key = Security::Keys(vec![Key::from_bytes([1; 32])]);
        // An Alive with 512 bytes of metadata, a 64-byte name and an IPv6 address is 607
        // bytes, the largest Ping 156; a sealed datagram adds 48 and the count reserve 2.
        let mut cfg = Config::lan(key.clone());
        cfg.limits.udp_max_payload = 813;
        assert_eq!(cfg.validate(), Ok(()));
        cfg.limits.udp_max_payload = 812;
        assert_eq!(cfg.validate().unwrap_err().field, "udp_max_payload");
        cfg.limits.udp_max_payload = 576;
        assert_eq!(cfg.validate().unwrap_err().field, "udp_max_payload");

        // With the default datagram, metadata is the limit to blame.
        let mut cfg = Config::lan(key);
        cfg.limits.max_meta_bytes = 1_099;
        assert_eq!(cfg.validate(), Ok(()));
        cfg.limits.max_meta_bytes = 1_100;
        assert_eq!(cfg.validate().unwrap_err().field, "max_meta_bytes");
        cfg.limits.max_meta_bytes = usize::MAX;
        assert_eq!(cfg.validate().unwrap_err().field, "max_meta_bytes");

        // Plaintext packets carry 12 bytes of header instead of 48.
        let mut cfg = Config::lan(Security::InsecurePlaintext);
        cfg.limits.udp_max_payload = 777;
        assert_eq!(cfg.validate(), Ok(()));
        cfg.limits.udp_max_payload = 776;
        assert_eq!(cfg.validate().unwrap_err().field, "udp_max_payload");
    }
}
