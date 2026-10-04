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
}
