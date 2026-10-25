//! Protocol configuration, with the `lan()`, `wan()` and `local()` presets.

use core::fmt;
use core::net::{Ipv6Addr, SocketAddr};
use core::time::Duration;

use kinship_proto::{
    Alive, Codec, Key, Limits, MAX_LABEL_LEN, Message, NodeId, PacketKind, Ping, PingReq,
    UserBroadcast, UserMessage,
};

use kinship_proto::identity::{Certificate, IdentityError};
use kinship_proto::v2::{self, SignedAlive};

use crate::broadcast::{COUNT_LEN, datagram_room, id};
use crate::signing::Signatures;

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
    /// Period of anti-entropy push-pull up to 32 live members; larger clusters stretch it as
    /// memberlist does ([`Config::push_pull_interval_for`]). Zero disables periodic push-pull.
    pub push_pull_interval: Duration,
    /// Zero disables reconnect attempts to recently dead members.
    pub reconnect_interval: Duration,
    pub rejoin_interval: Duration,
    /// Bound on each TCP exchange: connect, write and the reply.
    pub tcp_timeout: Duration,
    /// Attempts per seed in a join. Retries back off from `probe_interval`, doubling each time.
    pub join_retries: u32,
    /// Most members this node holds, itself and Dead and Left tombstones included. An Alive
    /// for a name it does not know is not admitted while the table is full; members it knows
    /// keep updating.
    pub max_members: usize,
    /// Most members new to this node that one datagram or one push-pull frame can add, shared
    /// by every Alive and record in it.
    pub max_new_members_per_packet: usize,
    /// Most data in one direct user message. One that does not fit a datagram goes over TCP,
    /// so this must fit a `max_stream_frame` frame.
    pub max_user_message: usize,
    /// Most data in one user broadcast, which must fit a datagram beside the largest Ping.
    pub max_user_broadcast: usize,
    /// Most user broadcasts a node holds to send, its own and those it relays; beyond it the
    /// one nearest to done is dropped and counted.
    pub user_broadcast_queue: usize,
    /// Per-member keys (KI-01): `Off`, the default, or `Sign` with this node's signing key,
    /// certificate and trust anchors. Experimental, planned for an opt-in release after 1.0;
    /// see `docs/ki01-stage2.md`.
    pub signatures: Signatures,
}

impl Config {
    pub const DEFAULT_MAX_USER_MESSAGE: usize = 64 * 1024;
    pub const DEFAULT_MAX_USER_BROADCAST: usize = 256;
    pub const DEFAULT_USER_BROADCAST_QUEUE: usize = 256;
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
            max_members: 8_192,
            max_new_members_per_packet: 1_024,
            max_user_message: Self::DEFAULT_MAX_USER_MESSAGE,
            max_user_broadcast: Self::DEFAULT_MAX_USER_BROADCAST,
            user_broadcast_queue: Self::DEFAULT_USER_BROADCAST_QUEUE,
            signatures: Signatures::Off,
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

    /// One host: tests, the simulator and demos.
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

    /// The period of anti-entropy push-pull with `members` live members, this node included:
    /// `push_pull_interval` up to [`PUSH_PULL_SCALE_THRESHOLD`] members, then memberlist's
    /// pushPullScale, `ceil(log2(members) - log2(32)) + 1` times it: twice at 33 to 64 members,
    /// four times at 200 and six at 1,000. Each push-pull sends the whole table, so a fixed
    /// period would make every node's share of the bytes grow with the cluster.
    pub fn push_pull_interval_for(&self, members: usize) -> Duration {
        self.push_pull_interval
            .saturating_mul(push_pull_scale(members))
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
        if self.max_members == 0 {
            return fail("max_members", "must be positive");
        }
        if self.max_new_members_per_packet == 0 {
            return fail("max_new_members_per_packet", "must be positive");
        }
        if self.user_broadcast_queue == 0 {
            return fail("user_broadcast_queue", "must be at least 1");
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
        if largest_ping() + largest_broadcast(self.max_user_broadcast, room) > room {
            return fail(
                "max_user_broadcast",
                "must fit a udp_max_payload datagram beside the largest Ping",
            );
        }
        let frame = codec
            .max_payload_len(PacketKind::Stream)
            .saturating_sub(COUNT_LEN);
        if largest_user_message(self.max_user_message, frame) > frame {
            return if self.limits.max_stream_frame < Limits::DEFAULT_MAX_STREAM_FRAME {
                fail("max_stream_frame", "must fit a max_user_message message")
            } else {
                fail("max_user_message", "must fit a max_stream_frame frame")
            };
        }
        self.validate_signatures(room, frame)
    }

    /// Checks what mode `sign` needs that does not depend on the node: encryption, a certificate
    /// for the signing key from a trust anchor for this cluster, and room in a datagram for a
    /// signed Alive behind its certificate, for a signed Alive or broadcast beside the largest
    /// version 2 probe message, and in a frame for a signed direct message. The node checks its
    /// name and its clock.
    fn validate_signatures(&self, room: usize, frame: usize) -> Result<(), ConfigError> {
        let fail = |field, reason| Err(ConfigError { field, reason });
        let Some(c) = self.signatures.credentials() else {
            return Ok(());
        };
        if self.security == Security::InsecurePlaintext {
            return fail("signatures", "need encryption");
        }
        if c.trust_anchors.is_empty() {
            return fail("trust_anchors", "needs at least one key");
        }
        let Ok(cert) = Certificate::decode(&c.certificate) else {
            return fail("certificate", "is not a certificate");
        };
        if cert.key() != c.signing_key.public_key() {
            return fail("certificate", "must be for signing_key");
        }
        // The CA and the cluster, at a time the certificate is valid: the clock is the node's.
        match cert.verify(
            &c.trust_anchors,
            self.cluster.as_bytes(),
            cert.not_before(),
            0,
        ) {
            Ok(()) => {}
            Err(IdentityError::WrongCluster) => {
                return fail("certificate", "is for another cluster");
            }
            Err(_) => return fail("certificate", "must be signed by one of trust_anchors"),
        }
        let alive = largest_signed_alive(self.limits.max_meta_bytes, room);
        if alive + LARGEST_CERTIFICATE > room {
            return if self.limits.udp_max_payload < Limits::DEFAULT_UDP_MAX_PAYLOAD {
                fail(
                    "udp_max_payload",
                    "must fit a signed Alive with max_meta_bytes of metadata and its certificate",
                )
            } else {
                fail(
                    "max_meta_bytes",
                    "must leave a signed Alive and its certificate that fit a datagram",
                )
            };
        }
        // A refutation rides the Ack of a version 2 round, as it rides a Ping's in version 1.
        if largest_v2_probe() + alive > room {
            return if self.limits.udp_max_payload < Limits::DEFAULT_UDP_MAX_PAYLOAD {
                fail(
                    "udp_max_payload",
                    "must fit a signed Alive with max_meta_bytes of metadata beside a signed Ack",
                )
            } else {
                fail(
                    "max_meta_bytes",
                    "must leave a signed Alive that fits a datagram beside a signed Ack",
                )
            };
        }
        // A signed broadcast goes behind its sender's certificate.
        let broadcast = signed_len(largest_broadcast(self.max_user_broadcast, room));
        if largest_v2_probe() + broadcast + LARGEST_CERTIFICATE > room {
            return fail(
                "max_user_broadcast",
                "must fit a udp_max_payload datagram, signed and behind a certificate, beside \
                 the largest Ping",
            );
        }
        if signed_len(largest_user_message(self.max_user_message, frame)) > frame {
            return if self.limits.max_stream_frame < Limits::DEFAULT_MAX_STREAM_FRAME {
                fail(
                    "max_stream_frame",
                    "must fit a signed max_user_message message",
                )
            } else {
                fail(
                    "max_user_message",
                    "must fit a max_stream_frame frame, signed",
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

/// Live members, this node included, up to which push-pull keeps `push_pull_interval`, as
/// memberlist's pushPullScaleThreshold.
pub const PUSH_PULL_SCALE_THRESHOLD: usize = 32;

/// memberlist's pushPullScale multiplier: 1 up to 32 members, then
/// `ceil(log2(members) - 5) + 1`, which is `ceil(log2(members)) - 4`.
fn push_pull_scale(members: usize) -> u32 {
    if members <= PUSH_PULL_SCALE_THRESHOLD {
        return 1;
    }
    // ceil(log2 n) for n > 1 is the bit length of n - 1.
    usize::BITS - (members - 1).leading_zeros() - 4
}

/// Encoded size of the largest Ping and the largest Alive a node can hold: 64-byte names, an
/// IPv6 address, an epoch and `max_meta` bytes of metadata, counted up to `cap` bytes of it.
fn largest_probe_and_alive(max_meta: usize, cap: usize) -> usize {
    largest_ping() + largest_alive(max_meta, cap)
}

/// A name as long as names go.
fn longest_name() -> String {
    "n".repeat(NodeId::MAX_LEN)
}

/// Encoded size of the largest Ping: 64-byte names and an IPv6 address.
fn largest_ping() -> usize {
    let name = longest_name();
    Message::Ping(Ping {
        seq: u32::MAX,
        target: id(&name),
        source: id(&name),
        source_addr: SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
    })
    .encoded_len()
}

/// Encoded size of the largest Alive a node can hold, its metadata counted up to `cap` bytes.
fn largest_alive(max_meta: usize, cap: usize) -> usize {
    let name = longest_name();
    // Metadata past the whole packet can only fail too, and is not worth allocating.
    let meta = vec![0; max_meta.min(cap.saturating_add(1))];
    Message::Alive(Alive {
        inc: u32::MAX,
        node: id(&name),
        addr: SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
        meta: &meta,
        vmin: u8::MAX,
        vmax: u8::MAX,
        epoch: u64::MAX,
    })
    .encoded_len()
}

/// Encoded size of the largest signed Alive, in version 2: a 64-byte name, an IPv6 address, an
/// epoch and `max_meta` bytes of metadata, counted up to `cap` bytes of it.
fn largest_signed_alive(max_meta: usize, cap: usize) -> usize {
    let name = longest_name();
    let meta = vec![0; max_meta.min(cap.saturating_add(1))];
    let alive = v2::Message::Alive(SignedAlive {
        alive: Alive {
            inc: u32::MAX,
            node: id(&name),
            addr: SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0)),
            meta: &meta,
            vmin: u8::MAX,
            vmax: u8::MAX,
            epoch: u64::MAX,
        },
        certificate_id: [0; 8],
        signature: [0; 64],
    });
    alive.encoded_len()
}

/// Encoded size of the largest version 2 probe message, which a datagram's signed rumours and
/// broadcasts ride beside: the largest of a relay's Ping, a PingReq, an Ack and a Nack, with
/// 64-byte names and IPv6 addresses.
fn largest_v2_probe() -> usize {
    let name = longest_name();
    let n = id(&name);
    let addr = SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0));
    let challenge = v2::ProbeChallenge::default();
    let (certificate_id, signature) = (Default::default(), [0; 64]);
    let probes = [
        v2::Message::Ping {
            ping: Ping {
                seq: u32::MAX,
                target: n,
                source: n,
                source_addr: addr,
            },
            source_epoch: u64::MAX,
            challenge,
            requester: Some(v2::Probe {
                requester: n,
                epoch: u64::MAX,
                seq: u32::MAX,
            }),
        },
        v2::Message::PingReq {
            request: PingReq {
                seq: u32::MAX,
                target: n,
                target_addr: addr,
                requester_addr: addr,
                want_nack: true,
            },
            requester: n,
            requester_epoch: u64::MAX,
            challenge,
        },
        v2::Message::Ack {
            seq: u32::MAX,
            target_epoch: u64::MAX,
            requester: n,
            requester_epoch: u64::MAX,
            target: n,
            challenge,
            certificate_id,
            signature,
        },
        v2::Message::Nack {
            seq: u32::MAX,
            relay: n,
            relay_epoch: u64::MAX,
            requester: n,
            requester_epoch: u64::MAX,
            target: n,
            challenge,
            certificate_id,
            signature,
        },
    ];
    probes
        .iter()
        .map(v2::Message::encoded_len)
        .max()
        .unwrap_or(0)
}

/// What a user message or broadcast of `len` encoded bytes takes signed: its certificate id
/// and signature, and a byte more of length.
fn signed_len(len: usize) -> usize {
    len + 8 + 64 + 1
}

/// A certificate message for a 64-byte name: its type, a two-byte length, and a body of the
/// version, issuer, cluster, name, key, validity and the CA's signature.
const LARGEST_CERTIFICATE: usize = 1 + 2 + (1 + 8 + 8 + 1 + NodeId::MAX_LEN + 32 + 8 + 8 + 64);

/// Encoded size of the largest user broadcast: a 64-byte name and `max_data` bytes of data,
/// counted up to `cap` bytes of it.
fn largest_broadcast(max_data: usize, cap: usize) -> usize {
    let name = longest_name();
    let data = vec![0; max_data.min(cap.saturating_add(1))];
    Message::UserBroadcast(UserBroadcast {
        from: id(&name),
        from_epoch: u64::MAX,
        seq: u64::MAX,
        data: &data,
    })
    .encoded_len()
}

/// Encoded size of the largest direct user message: 64-byte names and `max_data` bytes of
/// data, counted up to `cap` bytes of it.
fn largest_user_message(max_data: usize, cap: usize) -> usize {
    let name = longest_name();
    let data = vec![0; max_data.min(cap.saturating_add(1))];
    Message::UserMessage(UserMessage {
        to: id(&name),
        to_epoch: u64::MAX,
        from: id(&name),
        from_epoch: u64::MAX,
        data: &data,
    })
    .encoded_len()
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
    fn push_pull_stretches_with_the_cluster_as_memberlist_does() {
        let cfg = Config::lan(Security::InsecurePlaintext);
        let secs = |s| Duration::from_secs(s);
        for (members, interval) in [
            (0, 30),
            (1, 30),
            (10, 30),
            (32, 30),
            (33, 60),
            (64, 60),
            (65, 90),
            (100, 90),
            (128, 90),
            (200, 120),
            (512, 150),
            (1000, 180),
            (8192, 270),
        ] {
            assert_eq!(
                cfg.push_pull_interval_for(members),
                secs(interval),
                "{members}"
            );
        }
        // memberlist's float formula agrees everywhere it is exact.
        for members in 33..20_000usize {
            let m = ((members as f64).log2() - 32f64.log2()).ceil() + 1.0;
            assert_eq!(push_pull_scale(members), m as u32, "{members}");
        }
        assert_eq!(push_pull_scale(usize::MAX), 60);
        let off = Config {
            push_pull_interval: Duration::ZERO,
            ..cfg
        };
        assert_eq!(off.push_pull_interval_for(1000), Duration::ZERO);
    }

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
    fn member_limits_default_and_must_be_positive() {
        for cfg in [
            Config::lan(Security::InsecurePlaintext),
            Config::wan(Security::InsecurePlaintext),
            Config::local(Security::InsecurePlaintext),
        ] {
            assert_eq!(cfg.max_members, 8_192);
            assert_eq!(cfg.max_new_members_per_packet, 1_024);
        }
        let mut cfg = Config::lan(Security::InsecurePlaintext);
        cfg.max_members = 0;
        assert_eq!(cfg.validate().unwrap_err().field, "max_members");
        let mut cfg = Config::lan(Security::InsecurePlaintext);
        cfg.max_new_members_per_packet = 0;
        assert_eq!(
            cfg.validate().unwrap_err().field,
            "max_new_members_per_packet"
        );
        cfg.max_new_members_per_packet = 1;
        cfg.max_members = 1;
        assert_eq!(cfg.validate(), Ok(()), "a node alone is a valid table");
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
        // An Alive with 512 bytes of metadata, a 64-byte name, an IPv6 address and an epoch is
        // 615 bytes, the largest Ping 156; a sealed datagram adds 48 and the count reserve 2.
        let mut cfg = Config::lan(key.clone());
        cfg.limits.udp_max_payload = 821;
        assert_eq!(cfg.validate(), Ok(()));
        cfg.limits.udp_max_payload = 820;
        assert_eq!(cfg.validate().unwrap_err().field, "udp_max_payload");
        cfg.limits.udp_max_payload = 576;
        assert_eq!(cfg.validate().unwrap_err().field, "udp_max_payload");

        // With the default datagram, metadata is the limit to blame.
        let mut cfg = Config::lan(key);
        cfg.limits.max_meta_bytes = 1_091;
        assert_eq!(cfg.validate(), Ok(()));
        cfg.limits.max_meta_bytes = 1_092;
        assert_eq!(cfg.validate().unwrap_err().field, "max_meta_bytes");
        cfg.limits.max_meta_bytes = usize::MAX;
        assert_eq!(cfg.validate().unwrap_err().field, "max_meta_bytes");

        // Plaintext packets carry 12 bytes of header instead of 48.
        let mut cfg = Config::lan(Security::InsecurePlaintext);
        cfg.limits.udp_max_payload = 785;
        assert_eq!(cfg.validate(), Ok(()));
        cfg.limits.udp_max_payload = 784;
        assert_eq!(cfg.validate().unwrap_err().field, "udp_max_payload");
    }

    #[test]
    fn user_message_limits_default_and_must_fit_their_packets() {
        let key = Security::Keys(vec![Key::from_bytes([1; 32])]);
        for cfg in [
            Config::lan(key.clone()),
            Config::wan(key.clone()),
            Config::local(Security::InsecurePlaintext),
        ] {
            assert_eq!(
                (
                    cfg.max_user_message,
                    cfg.max_user_broadcast,
                    cfg.user_broadcast_queue
                ),
                (65_536, 256, 256)
            );
        }
        // A broadcast from a 64-byte name is 86 bytes besides its data, and must fit beside
        // the largest Ping, 156: 1,350 - 156 - 86 = 1,108 with the default datagram.
        let mut cfg = Config::lan(key.clone());
        cfg.max_user_broadcast = 1_108;
        assert_eq!(cfg.validate(), Ok(()));
        cfg.max_user_broadcast = 1_109;
        assert_eq!(cfg.validate().unwrap_err().field, "max_user_broadcast");
        // Even at the smallest datagram accepted, the default fits.
        let mut cfg = Config::lan(key.clone());
        cfg.limits.udp_max_payload = 821;
        assert_eq!(cfg.validate(), Ok(()));
        // A direct message must fit a frame, 48 bytes of it for the seal, 2 for the count and
        // 155 for the message besides its data; the limit moved from its default is named.
        let mut cfg = Config::lan(key.clone());
        cfg.max_user_message = cfg.limits.max_stream_frame - 48 - 2 - 155;
        assert_eq!(cfg.validate(), Ok(()));
        cfg.max_user_message += 1;
        assert_eq!(cfg.validate().unwrap_err().field, "max_user_message");
        let mut cfg = Config::lan(key.clone());
        cfg.limits.max_stream_frame = 64 * 1024;
        assert_eq!(cfg.validate().unwrap_err().field, "max_stream_frame");
        cfg.max_user_message = 32 * 1024;
        assert_eq!(cfg.validate(), Ok(()));
        let mut cfg = Config::lan(key);
        cfg.user_broadcast_queue = 0;
        assert_eq!(cfg.validate().unwrap_err().field, "user_broadcast_queue");
        cfg.user_broadcast_queue = 1;
        cfg.max_user_message = 0;
        cfg.max_user_broadcast = 0;
        assert_eq!(cfg.validate(), Ok(()), "empty messages only");
    }
}
