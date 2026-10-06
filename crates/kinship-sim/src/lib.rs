//! Deterministic network simulator for kinship-core.
//!
//! The simulator drives sans-IO nodes directly: it owns a virtual clock and a seeded network,
//! hands each node the real encoded bytes other nodes sent, and fires each node's timer when its
//! [`poll_timeout`](SimNode::poll_timeout) deadline comes up. Nothing reads a real clock, opens
//! a socket or draws from the OS, so a run is fully defined by its seed and its [`Scenario`], and
//! the same pair always gives a byte-identical [`Trace`].
//!
//! ```
//! use std::time::Duration;
//! use kinship_sim::{Action, EchoConfig, EchoNode, LinkConfig, Scenario, Sim};
//!
//! let scenario = Scenario::new(5)
//!     .duration(Duration::from_secs(10))
//!     .link(LinkConfig::lan().with_loss(0.05))
//!     .at(Duration::from_secs(3), Action::Crash(4));
//! let cfg = EchoConfig::default();
//! let mut sim = Sim::new(42, scenario, move |spec| EchoNode::new(spec, &cfg));
//! let json = sim.run().to_json();
//! assert!(json.contains("\"kind\":\"deliver\""));
//! ```
//!
//! The network models per-link latency distributions, loss, duplication and reordering,
//! symmetric and one-way partitions, crashed and restarted nodes, slow nodes whose inputs
//! are processed late (see [`Action::Pause`], [`Action::Slow`] and [`Action::Starve`]), and nodes
//! whose clock jumps ahead of the others ([`Action::ClockJump`]). Streams model TCP: reliable
//! and ordered, failing after a timeout when the peer is unreachable.

mod echo;
mod scenario;
mod sim;
mod trace;

use std::net::SocketAddr;

use kinship_core::{CommandId, Instant, StreamEvent, StreamId, Transmit};
use serde::Serialize;

pub use echo::{EchoCommand, EchoConfig, EchoEvent, EchoNode};
pub use scenario::{Action, Delay, LinkConfig, NodeSet, Scenario};
pub use sim::{NodeSpec, Sim, Stats, addr_of, name_of};
pub use trace::{DropReason, Record, Trace, TraceConfig, TraceNode};

/// A sans-IO node the simulator can drive: the same five inputs and three outputs as
/// [`kinship_core::Node`], with the command and event types left open so test nodes can bring
/// their own.
pub trait SimNode {
    type Command;
    type Event: Serialize;

    fn handle_datagram(&mut self, now: Instant, from: SocketAddr, buf: &[u8]);
    fn handle_stream(&mut self, now: Instant, conn: StreamId, ev: StreamEvent<'_>);
    fn handle_timeout(&mut self, now: Instant);
    fn command(&mut self, now: Instant, cmd: Self::Command) -> CommandId;
    fn poll_transmit(&mut self) -> Option<Transmit>;
    fn poll_event(&mut self) -> Option<Self::Event>;
    fn poll_timeout(&self) -> Option<Instant>;
}

impl SimNode for kinship_core::Node {
    type Command = kinship_core::Command;
    type Event = kinship_core::Event;

    fn handle_datagram(&mut self, now: Instant, from: SocketAddr, buf: &[u8]) {
        self.handle_datagram(now, from, buf);
    }

    fn handle_stream(&mut self, now: Instant, conn: StreamId, ev: StreamEvent<'_>) {
        self.handle_stream(now, conn, ev);
    }

    fn handle_timeout(&mut self, now: Instant) {
        self.handle_timeout(now);
    }

    fn command(&mut self, now: Instant, cmd: Self::Command) -> CommandId {
        self.command(now, cmd)
    }

    fn poll_transmit(&mut self) -> Option<Transmit> {
        self.poll_transmit()
    }

    fn poll_event(&mut self) -> Option<Self::Event> {
        self.poll_event()
    }

    fn poll_timeout(&self) -> Option<Instant> {
        self.poll_timeout()
    }
}
