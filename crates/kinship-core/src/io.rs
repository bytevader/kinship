//! What crosses the boundary between the core and its driver.

use core::fmt;
use core::net::SocketAddr;

/// One TCP connection, as both the core and the driver name it.
///
/// Connections the core opens with [`Transmit::Connect`] get outbound ids, which the core
/// allocates. Connections the driver accepts get inbound ids, which the driver allocates with
/// [`StreamId::inbound`]; the core learns about an accepted connection from its first
/// [`StreamEvent::Frame`]. The two ranges cannot collide.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize), serde(transparent))]
pub struct StreamId(u64);

impl StreamId {
    const INBOUND: u64 = 1 << 63;

    /// The `index`th connection this side opened. Only the low 63 bits of `index` are used.
    pub const fn outbound(index: u64) -> Self {
        Self(index & !Self::INBOUND)
    }

    /// The `index`th connection this side accepted. Only the low 63 bits of `index` are used.
    pub const fn inbound(index: u64) -> Self {
        Self(index | Self::INBOUND)
    }

    pub const fn is_inbound(self) -> bool {
        self.0 & Self::INBOUND != 0
    }

    /// The index passed to [`outbound`](Self::outbound) or [`inbound`](Self::inbound).
    pub const fn index(self) -> u64 {
        self.0 & !Self::INBOUND
    }

    pub const fn to_raw(self) -> u64 {
        self.0
    }

    pub const fn from_raw(raw: u64) -> Self {
        Self(raw)
    }
}

impl fmt::Debug for StreamId {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let dir = if self.is_inbound() { "in" } else { "out" };
        write!(f, "StreamId({dir} {})", self.index())
    }
}

/// Something that happened on a TCP connection.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum StreamEvent<'a> {
    /// One complete frame, without its 4-byte length prefix. The driver splits the byte stream
    /// with [`kinship_proto::FrameReader`].
    Frame(&'a [u8]),
    /// The peer closed the connection cleanly.
    Closed,
    /// Connect refused or timed out, a reset, a framing error, or `tcp_timeout` expired.
    Failed,
}

/// Something the driver must do on the core's behalf. Payloads are already sealed.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Transmit {
    /// Send one UDP datagram.
    Datagram { to: SocketAddr, payload: Vec<u8> },
    /// Open a TCP connection; report failure with [`StreamEvent::Failed`].
    Connect { conn: StreamId, to: SocketAddr },
    /// Write bytes to a connection: one or more frames, each with its length prefix.
    Stream { conn: StreamId, frame: Vec<u8> },
    /// Close a connection. The core sends nothing more on it and expects no further events.
    Close { conn: StreamId },
}
