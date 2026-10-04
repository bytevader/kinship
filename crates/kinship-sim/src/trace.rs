//! The trace recorder: everything a run did, in order, dumpable as JSON.

use std::io;
use std::net::SocketAddr;

use kinship_core::{CommandId, Instant, StreamId};
use serde::{Serialize, Serializer};

/// What a trace records. Counters in [`Stats`](crate::Stats) are kept either way.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct TraceConfig {
    /// Datagram sends, deliveries, drops and duplicates.
    pub network: bool,
    /// Stream connects, sends, frames received, closes and failures.
    pub streams: bool,
    /// Timer expiries handled by nodes.
    pub timers: bool,
    /// Commands given to nodes and the events nodes emit.
    pub events: bool,
    /// Scenario actions as they fire.
    pub actions: bool,
}

impl TraceConfig {
    pub const ALL: Self = Self {
        network: true,
        streams: true,
        timers: true,
        events: true,
        actions: true,
    };

    /// Record nothing; for large runs that only need the counters.
    pub const OFF: Self = Self {
        network: false,
        streams: false,
        timers: false,
        events: false,
        actions: false,
    };
}

impl Default for TraceConfig {
    fn default() -> Self {
        Self::ALL
    }
}

/// Why a datagram was not delivered.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum DropReason {
    /// The link lost it.
    Loss,
    /// A partition or block covers the link.
    Partition,
    /// The destination had crashed when it arrived.
    NodeDown,
    /// No node has the destination address.
    NoRoute,
    /// Larger than a UDP datagram can be.
    TooLarge,
}

/// One thing that happened. Times are nanoseconds of simulated time; node fields are indices
/// into [`Trace::nodes`]; `hash` is the FNV-1a hash of the bytes, in hex.
#[derive(Debug, Clone, PartialEq, Serialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum Record {
    Send {
        t: Instant,
        packet: u64,
        from: usize,
        to: Option<usize>,
        len: usize,
        #[serde(serialize_with = "hex")]
        hash: u64,
    },
    Deliver {
        t: Instant,
        packet: u64,
        to: usize,
    },
    Drop {
        t: Instant,
        packet: u64,
        reason: DropReason,
    },
    Duplicate {
        t: Instant,
        packet: u64,
    },
    Timeout {
        t: Instant,
        node: usize,
    },
    Command {
        t: Instant,
        node: usize,
        id: CommandId,
    },
    Event {
        t: Instant,
        node: usize,
        event: serde_json::Value,
    },
    Connect {
        t: Instant,
        node: usize,
        conn: StreamId,
        to: Option<usize>,
    },
    StreamSend {
        t: Instant,
        node: usize,
        conn: StreamId,
        len: usize,
        #[serde(serialize_with = "hex")]
        hash: u64,
    },
    StreamFrame {
        t: Instant,
        node: usize,
        conn: StreamId,
        len: usize,
        #[serde(serialize_with = "hex")]
        hash: u64,
    },
    /// The node closed its end.
    StreamClose {
        t: Instant,
        node: usize,
        conn: StreamId,
    },
    /// The node was told the peer closed.
    StreamClosed {
        t: Instant,
        node: usize,
        conn: StreamId,
    },
    StreamFailed {
        t: Instant,
        node: usize,
        conn: StreamId,
    },
    Action {
        t: Instant,
        action: String,
    },
}

fn hex<S: Serializer>(v: &u64, s: S) -> Result<S::Ok, S::Error> {
    s.serialize_str(&format!("{v:016x}"))
}

/// A node as the trace names it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
pub struct TraceNode {
    pub index: usize,
    pub name: String,
    pub addr: SocketAddr,
}

/// A recorded run. The same seed and scenario always produce the same trace, byte for byte.
#[derive(Debug, Clone, PartialEq, Serialize)]
pub struct Trace {
    /// Version of this JSON layout.
    pub format: u32,
    pub seed: u64,
    pub nodes: Vec<TraceNode>,
    pub records: Vec<Record>,
}

impl Trace {
    pub const FORMAT: u32 = 1;

    pub fn to_json(&self) -> String {
        serde_json::to_string(self).expect("a trace always serializes")
    }

    pub fn write_json(&self, w: impl io::Write) -> io::Result<()> {
        serde_json::to_writer(w, self).map_err(io::Error::from)
    }

    /// FNV-1a hash of the JSON, a cheap fingerprint for comparing runs.
    pub fn digest(&self) -> u64 {
        fnv1a(self.to_json().as_bytes())
    }
}

pub(crate) fn fnv1a(bytes: &[u8]) -> u64 {
    let mut h: u64 = 0xcbf2_9ce4_8422_2325;
    for &b in bytes {
        h ^= u64::from(b);
        h = h.wrapping_mul(0x0000_0100_0000_01b3);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn fnv1a_matches_reference() {
        assert_eq!(fnv1a(b""), 0xcbf2_9ce4_8422_2325);
        assert_eq!(fnv1a(b"a"), 0xaf63_dc4c_8601_ec8c);
    }

    #[test]
    fn records_serialize_flat() {
        let r = Record::Send {
            t: Instant::from_nanos(5),
            packet: 1,
            from: 0,
            to: Some(2),
            len: 3,
            hash: 0xab,
        };
        assert_eq!(
            serde_json::to_string(&r).unwrap(),
            r#"{"kind":"send","t":5,"packet":1,"from":0,"to":2,"len":3,"hash":"00000000000000ab"}"#
        );
    }
}
