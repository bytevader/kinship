//! The [`Config`] builder: a preset, `with_*` setters, and validation in `Cluster::start`.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use kinship_net::{ConfigError, Key, Security, Settings};

/// Everything a [`Cluster`](crate::Cluster) needs, built from a preset with `with_*` setters.
///
/// The protocol fields live in a [`kinship_core::Config`](crate::CoreConfig), read with
/// [`core`](Self::core); the rest are the node's identity, network and limits. Nothing is
/// checked until [`Cluster::start`](crate::Cluster::start), which reports the first bad field
/// before any socket opens.
///
/// ```
/// use std::time::Duration;
/// use kinship::{Config, Key};
///
/// let cfg = Config::lan()
///     .with_name("worker-17")
///     .with_keys([Key::from_bytes([7; 32])])
///     .with_seeds(["10.0.0.5:7946".parse().unwrap()])
///     .with_probe_interval(Duration::from_secs(2))
///     .with_probe_timeout(Duration::from_secs(1));
/// assert!(cfg.core().local_health, "Lifeguard is on unless turned off");
/// assert!(!cfg.without_lifeguard().core().local_health);
/// ```
#[derive(Debug, Clone)]
pub struct Config {
    core: kinship_net::Config,
    name: Option<String>,
    bind: SocketAddr,
    advertise: Option<SocketAddr>,
    meta: Vec<u8>,
    seeds: Vec<SocketAddr>,
    keys: Vec<Key>,
    insecure_plaintext: bool,
    /// Set by [`Config::local`]: plaintext needs no opt-in while `bind` is loopback.
    loopback_plaintext: bool,
    max_inbound_streams: usize,
    event_buffer: usize,
}

/// Default port for UDP and TCP.
pub const DEFAULT_PORT: u16 = 7946;

macro_rules! core_setters {
    ($($(#[$doc:meta])* $with:ident => $($field:ident).+ : $ty:ty;)*) => {
        $(
            $(#[$doc])*
            pub fn $with(mut self, value: $ty) -> Self {
                self.core.$($field).+ = value;
                self
            }
        )*
    };
}

impl Config {
    fn preset(core: kinship_net::Config, bind: SocketAddr, loopback_plaintext: bool) -> Self {
        Self {
            core,
            name: None,
            bind,
            advertise: None,
            meta: Vec::new(),
            seeds: Vec::new(),
            keys: Vec::new(),
            insecure_plaintext: false,
            loopback_plaintext,
            max_inbound_streams: Settings::DEFAULT_MAX_INBOUND_STREAMS,
            event_buffer: Settings::DEFAULT_EVENT_BUFFER,
        }
    }

    /// One datacenter or VPC. Binds `0.0.0.0:7946` and needs keys.
    pub fn lan() -> Self {
        let bind = (Ipv4Addr::UNSPECIFIED, DEFAULT_PORT).into();
        Self::preset(
            kinship_net::Config::lan(Security::InsecurePlaintext),
            bind,
            false,
        )
    }

    /// Regions, edge sites and flaky links: slower probes and suspicion. Binds `0.0.0.0:7946`
    /// and needs keys.
    pub fn wan() -> Self {
        let bind = (Ipv4Addr::UNSPECIFIED, DEFAULT_PORT).into();
        Self::preset(
            kinship_net::Config::wan(Security::InsecurePlaintext),
            bind,
            false,
        )
    }

    /// Tests and demos on one host: fast probes, no TCP fallback ping. Binds `127.0.0.1:7946`
    /// and runs without keys while it binds loopback.
    pub fn local() -> Self {
        let bind = (Ipv4Addr::LOCALHOST, DEFAULT_PORT).into();
        Self::preset(
            kinship_net::Config::local(Security::InsecurePlaintext),
            bind,
            true,
        )
    }

    /// The protocol configuration. Its `security` is decided by `Cluster::start` from the keys.
    pub fn core(&self) -> &kinship_net::Config {
        &self.core
    }

    pub fn name(&self) -> Option<&str> {
        self.name.as_deref()
    }

    pub fn bind(&self) -> SocketAddr {
        self.bind
    }

    pub fn seeds(&self) -> &[SocketAddr] {
        &self.seeds
    }

    /// Unique in the cluster, 1 to 64 bytes. Defaults to the host name plus 6 random hex
    /// characters; a stable name survives restarts.
    pub fn with_name(mut self, name: impl Into<String>) -> Self {
        self.name = Some(name.into());
        self
    }

    /// UDP and TCP listen address. Port 0 picks a free port for both; read it back from
    /// `cluster.local().addr`.
    pub fn with_bind(mut self, bind: SocketAddr) -> Self {
        self.bind = bind;
        self
    }

    /// The address other members use to reach this node, for NAT, containers and wildcard
    /// binds. Defaults to the bind address, or for a wildcard bind the address of the default
    /// route.
    pub fn with_advertise(mut self, advertise: SocketAddr) -> Self {
        self.advertise = Some(advertise);
        self
    }

    /// Label bound into every packet; clusters with different labels ignore each other.
    pub fn with_cluster(mut self, cluster: impl Into<String>) -> Self {
        self.core.cluster = cluster.into();
        self
    }

    /// Initial metadata, at most `max_meta_bytes`.
    pub fn with_meta(mut self, meta: impl Into<Vec<u8>>) -> Self {
        self.meta = meta.into();
        self
    }

    /// Joined on start; a node that reaches none keeps retrying them in the background. The
    /// list may include this node itself.
    pub fn with_seeds(mut self, seeds: impl IntoIterator<Item = SocketAddr>) -> Self {
        self.seeds = seeds.into_iter().collect();
        self
    }

    /// The first key encrypts, every key decrypts.
    pub fn with_keys(mut self, keys: impl IntoIterator<Item = Key>) -> Self {
        self.keys = keys.into_iter().collect();
        self
    }

    /// Allows running without keys on any address. Logs a warning at startup.
    pub fn with_insecure_plaintext(mut self, insecure: bool) -> Self {
        self.insecure_plaintext = insecure;
        self
    }

    /// Concurrent inbound TCP exchanges; a new one beyond this drops the oldest.
    pub fn with_max_inbound_streams(mut self, n: usize) -> Self {
        self.max_inbound_streams = n;
        self
    }

    /// Events each subscription buffers before the oldest are dropped.
    pub fn with_event_buffer(mut self, n: usize) -> Self {
        self.event_buffer = n;
        self
    }

    /// Turns off all four Lifeguard extensions, leaving plain SWIM. For comparisons.
    pub fn without_lifeguard(mut self) -> Self {
        self.core = self.core.without_lifeguard();
        self
    }

    core_setters! {
        /// Time between probe rounds, times the local health multiplier plus one.
        with_probe_interval => probe_interval: Duration;
        /// Wait for a direct Ack, times the local health multiplier plus one.
        with_probe_timeout => probe_timeout: Duration;
        /// Relays asked to probe a silent member.
        with_indirect_checks => indirect_checks: usize;
        /// Also ping over TCP when UDP probes fail.
        with_tcp_fallback_ping => tcp_fallback_ping: bool;
        /// Scales the minimum suspicion timeout.
        with_suspicion_mult => suspicion_mult: u32;
        /// Maximum suspicion timeout as a multiple of the minimum.
        with_suspicion_max_mult => suspicion_max_mult: u32;
        /// K in the Lifeguard suspicion timeout formula.
        with_expected_confirmations => expected_confirmations: u32;
        /// Ceiling of the local health multiplier.
        with_awareness_max => awareness_max: u32;
        /// Lifeguard: stretch this node's probe interval and timeout when its own probes fail.
        with_local_health => local_health: bool;
        /// Lifeguard: ask relays for Nacks and count missing ones against local health.
        with_nacks => nacks: bool;
        /// Lifeguard: start suspicions long and shrink them as members confirm.
        with_dynamic_suspicion => dynamic_suspicion: bool;
        /// Lifeguard: Pings to a suspected member carry the suspicion first.
        with_buddy_system => buddy_system: bool;
        /// How long Dead and Left tombstones are kept.
        with_dead_reclaim => dead_reclaim: Duration;
        /// Time between dedicated gossip packets.
        with_gossip_interval => gossip_interval: Duration;
        /// Members each gossip packet goes to.
        with_gossip_nodes => gossip_nodes: usize;
        /// How long members declared dead still receive gossip; members that left receive none.
        with_gossip_to_the_dead => gossip_to_the_dead: Duration;
        /// Broadcast copies per log10(n + 1).
        with_retransmit_mult => retransmit_mult: u32;
        /// Anti-entropy period; zero disables it.
        with_push_pull_interval => push_pull_interval: Duration;
        /// Period of push-pulls with recently dead members; zero disables them.
        with_reconnect_interval => reconnect_interval: Duration;
        /// Period of push-pulls with each seed that is not a live member, which finds the
        /// cluster again after a node was cut off or a partition outlasted the tombstones; zero
        /// disables them.
        with_rejoin_interval => rejoin_interval: Duration;
        /// Bound on each TCP connect, write and read.
        with_tcp_timeout => tcp_timeout: Duration;
        /// Attempts per seed in a join, with exponential backoff from the probe interval.
        with_join_retries => join_retries: u32;
        /// Largest datagram sent, header and tag included.
        with_udp_max_payload => limits.udp_max_payload: usize;
        /// Largest TCP frame accepted.
        with_max_stream_frame => limits.max_stream_frame: usize;
        /// Metadata cap.
        with_max_meta_bytes => limits.max_meta_bytes: usize;
    }

    /// Checks every field and resolves the defaults: what to start and where to bind.
    pub(crate) fn build(self) -> Result<(Settings, SocketAddr), ConfigError> {
        let mut core = self.core;
        core.security = if !self.keys.is_empty() {
            Security::Keys(self.keys)
        } else if self.insecure_plaintext {
            tracing::warn!("running without encryption: insecure_plaintext is set");
            Security::InsecurePlaintext
        } else if self.loopback_plaintext && self.bind.ip().is_loopback() {
            Security::InsecurePlaintext
        } else {
            return Err(ConfigError {
                field: "keys",
                reason: "are required unless insecure_plaintext is set, or local() binds loopback",
            });
        };
        core.validate()?;
        let name = self.name.unwrap_or_else(kinship_net::default_name);
        // Checks the name the same way the node will, before any socket opens.
        kinship_net::Identity::new(name.as_str(), self.bind)?;
        let settings = Settings {
            core,
            name,
            advertise: self.advertise,
            meta: self.meta,
            seeds: self.seeds,
            max_inbound_streams: self.max_inbound_streams,
            event_buffer: self.event_buffer,
        };
        settings.validate()?;
        if settings.meta.len() > settings.core.limits.max_meta_bytes {
            return Err(ConfigError {
                field: "meta",
                reason: "must be at most max_meta_bytes",
            });
        }
        Ok((settings, self.bind))
    }
}

impl Default for Config {
    fn default() -> Self {
        Self::lan()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn keys_are_required_beyond_loopback() {
        let err = Config::lan().build().unwrap_err();
        assert_eq!(err.field, "keys");
        let lan = Config::lan().with_bind("127.0.0.1:0".parse().unwrap());
        assert_eq!(
            lan.build().unwrap_err().field,
            "keys",
            "only local() waives keys"
        );

        let (s, _) = Config::local().build().unwrap();
        assert_eq!(s.core.security, Security::InsecurePlaintext);
        let wide = Config::local().with_bind("0.0.0.0:0".parse().unwrap());
        assert_eq!(wide.clone().build().unwrap_err().field, "keys");
        assert!(wide.with_insecure_plaintext(true).build().is_ok());

        let key = Key::from_bytes([1; 32]);
        let (s, bind) = Config::lan().with_keys([key.clone()]).build().unwrap();
        assert_eq!(s.core.security, Security::Keys(vec![key]));
        assert_eq!(bind, "0.0.0.0:7946".parse().unwrap());
    }

    #[test]
    fn bad_fields_are_named_before_binding() {
        let cfg = Config::local().with_probe_timeout(Duration::from_secs(5));
        assert_eq!(cfg.build().unwrap_err().field, "probe_timeout");
        let cfg = Config::local().with_name("x".repeat(65));
        assert_eq!(cfg.build().unwrap_err().field, "name");
        let cfg = Config::local().with_event_buffer(0);
        assert_eq!(cfg.build().unwrap_err().field, "event_buffer");
        let cfg = Config::local().with_meta(vec![0; 513]);
        assert_eq!(cfg.build().unwrap_err().field, "meta");
    }

    #[test]
    fn setters_reach_the_core_and_lifeguard_stays_reachable() {
        let cfg = Config::wan()
            .with_cluster("edge")
            .with_nacks(false)
            .with_buddy_system(false)
            .with_max_meta_bytes(256)
            .with_rejoin_interval(Duration::ZERO);
        let core = cfg.core();
        assert_eq!(core.cluster, "edge");
        assert!(!core.nacks && !core.buddy_system);
        assert!(core.local_health && core.dynamic_suspicion);
        assert_eq!(core.limits.max_meta_bytes, 256);
        assert_eq!(core.probe_interval, Duration::from_secs(5));
        let plain = cfg.without_lifeguard();
        let core = plain.core();
        assert!(!core.local_health && !core.nacks && !core.dynamic_suspicion && !core.buddy_system);
    }
}
