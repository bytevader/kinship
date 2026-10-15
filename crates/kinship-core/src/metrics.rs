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
    /// Encrypted packets dropped as replays: stamped older than the replay window, which is
    /// checked before decrypting, or a copy of a packet already accepted inside it. Also those
    /// stamped further ahead of cluster time than a node may jump, checked before decrypting.
    pub replays_dropped: u64,
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
    /// Alive messages ignored because a member already holds the name at another address: a
    /// live one, or a Dead or Left one whose tombstone is still kept.
    pub name_conflicts: u64,
    /// Members that came back in a later life, which replaced the one this node held: each is
    /// a restart, reported as MemberLeft for the old life, if it was live, and MemberJoined.
    pub restarts: u64,
    /// Alive messages and push-pull records about members new to this node that were not
    /// admitted, because the table held `max_members` or their packet had already added
    /// `max_new_members_per_packet`.
    pub members_refused: u64,
    /// Push-pull exchanges this node started that completed: joins, anti-entropy, reconnects.
    pub push_pulls: u64,
    /// Push-pull exchanges this node started that failed or timed out.
    pub push_pull_failures: u64,
    /// Push-pull exchanges other nodes started that this node answered.
    pub push_pulls_served: u64,
    /// Push-pull replies refused because this node's state does not fit in `max_stream_frame`.
    pub state_too_large: u64,
    /// Rumours dropped because they do not fit a datagram even alone. Validated limits keep
    /// every rumour small enough, so this stays at zero unless something is wrong.
    pub gossip_too_large: u64,
    /// Fallback pings sent over TCP after a UDP probe went unanswered.
    pub tcp_pings: u64,
    /// Probe rounds saved by a TCP Ack: UDP to that member is failing while TCP works.
    pub tcp_ping_acks: u64,
    /// Direct user messages written to a datagram or a connection, and broadcasts this node
    /// started.
    pub user_messages_sent: u64,
    /// User messages delivered to the application, direct and broadcast.
    pub user_messages_received: u64,
    /// User messages that arrived for another name or an earlier life of this node, or from a
    /// sender this node does not hold at that life; broadcasts too far behind their sender's
    /// latest to tell from copies; and direct messages whose connection failed or that waited
    /// for a member no longer held live.
    pub user_messages_dropped: u64,
    /// Sends refused for data over `max_user_message` or `max_user_broadcast`, and user
    /// messages received over them, which are dropped alone.
    pub user_messages_too_large: u64,
    /// Broadcasts dropped from a full queue, `user_broadcast_queue` long, and direct messages
    /// dropped while `max_stream_frame` bytes already waited for connections.
    pub user_queue_overflow: u64,
}
