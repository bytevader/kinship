//! Counters the driver exports through `Cluster::stats()`.

/// Monotonic counters since the node started.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
#[non_exhaustive]
pub struct Metrics {
    /// Datagrams and stream frames that opened and parsed.
    pub packets_received: u64,
    /// Datagrams and stream frames that were malformed, oversized or for another cluster.
    pub decode_errors: u64,
    /// Packets whose key id matched but whose tag did not verify, or with an unknown key id.
    pub decrypt_failures: u64,
    /// Probe rounds started.
    pub probes_sent: u64,
    /// Probe rounds that ended without an Ack, direct or indirect.
    pub probes_failed: u64,
    /// PingReqs sent to relays.
    pub indirect_probes: u64,
    /// Relays of failed probe rounds that sent no Nack in time; each raised local health.
    pub missed_nacks: u64,
    /// Members this node moved to Suspect, on its own probes or on gossip.
    pub suspicions: u64,
    /// Rumours about this node that it refuted by raising its incarnation.
    pub refutations: u64,
    /// Pings for another name that reached this node's address.
    pub misdirected: u64,
    /// Alive messages ignored because a live member already holds the name.
    pub name_conflicts: u64,
    /// Push-pull exchanges this node started that completed: joins, anti-entropy, reconnects.
    pub push_pulls: u64,
    /// Push-pull exchanges this node started that failed or timed out.
    pub push_pull_failures: u64,
    /// Push-pull exchanges other nodes started that this node answered.
    pub push_pulls_served: u64,
    /// Push-pull replies refused because this node's state does not fit in `max_stream_frame`.
    pub state_too_large: u64,
    /// Fallback pings sent over TCP after a UDP probe went unanswered.
    pub tcp_pings: u64,
    /// Probe rounds saved by a TCP Ack: UDP to that member is failing while TCP works.
    pub tcp_ping_acks: u64,
}
