//! SWIM membership and failure detection with Lifeguard, for Rust and Python.
//!
//! [`Cluster`] runs one node on the current tokio runtime: it binds UDP and TCP on one port,
//! joins the configured seeds and keeps the membership view current while the application reads
//! [`members`](Cluster::members) and listens to [`events`](Cluster::events).
//!
//! ```no_run
//! use kinship::{Cluster, Config, Event, Key};
//! use std::time::Duration;
//!
//! # async fn run() -> Result<(), Box<dyn std::error::Error>> {
//! let cfg = Config::lan()
//!     .with_name("worker-17")
//!     .with_keys([Key::from_base64(&std::env::var("KINSHIP_KEY")?)?])
//!     .with_seeds(["10.0.0.5:7946".parse()?]);
//! let cluster = Cluster::start(cfg).await?; // binds, joins seeds
//! let mut events = cluster.events();
//! while let Some(event) = events.recv().await {
//!     match event {
//!         Event::MemberDead(m) | Event::MemberLeft(m) => println!("{} is gone", m.name),
//!         Event::EventsLost(_) => println!("resync: {} members", cluster.members().len()),
//!         _ => {}
//!     }
//! }
//! cluster.leave(Duration::from_secs(5)).await?;
//! cluster.close().await;
//! # Ok(())
//! # }
//! ```

mod config;

use std::net::SocketAddr;
use std::time::Duration;

pub use config::{Config, DEFAULT_PORT};
/// The protocol half of [`Config`], from `kinship-core`.
pub use kinship_net::Config as CoreConfig;
pub use kinship_net::{
    ConfigError, Error, Event, Events, Key, KeyError, KeyId, Keyring, Member, Metrics, State,
    Stats, TokioTransport, Transport, WIRE_VERSION, generate_key, mem,
};

use kinship_net::Memberlist;

/// A running cluster member.
///
/// Reads never wait on the network. The protocol runs on its own task, so a slow consumer of
/// [`events`](Self::events) cannot make this node look dead. Dropping a `Cluster` stops the
/// node without telling anyone, like a crash; call [`leave`](Self::leave) and
/// [`close`](Self::close) to go cleanly.
#[derive(Debug)]
pub struct Cluster {
    inner: Memberlist,
}

impl Cluster {
    /// Validates `cfg`, binds UDP and TCP, starts the node and joins `cfg`'s seeds, skipping its
    /// own address.
    ///
    /// A bad field fails before any socket opens. A startup join that reaches no seed only
    /// logs a warning: the node starts alone and retries the seeds every `rejoin_interval`.
    pub async fn start(cfg: Config) -> Result<Self, Error> {
        let (settings, bind) = cfg.build()?;
        let transport = TokioTransport::bind(bind).await?;
        let inner = Memberlist::start(settings, transport).await?;
        Ok(Self { inner })
    }

    /// Like [`start`](Self::start) on a transport of your own; `cfg`'s bind address is unused.
    pub async fn start_with<T: Transport>(cfg: Config, transport: T) -> Result<Self, Error> {
        let (settings, _) = cfg.build()?;
        let inner = Memberlist::start(settings, transport).await?;
        Ok(Self { inner })
    }

    /// Push-pulls with each seed until one answers and returns how many answered. Fails with
    /// [`Error::JoinFailed`] if none did.
    pub async fn join(&self, seeds: impl IntoIterator<Item = SocketAddr>) -> Result<usize, Error> {
        self.inner.join(seeds).await
    }

    /// Alive and suspect members, this node included.
    pub fn members(&self) -> Vec<Member> {
        self.inner.members()
    }

    /// One member by name, including dead and left tombstones.
    pub fn member(&self, name: &str) -> Option<Member> {
        self.inner.member(name)
    }

    /// This node as the cluster sees it. Its `addr` is the advertised address.
    pub fn local(&self) -> Member {
        self.inner.local()
    }

    /// The address UDP and TCP are bound to, with the port the OS picked for port 0.
    pub fn local_addr(&self) -> SocketAddr {
        self.inner.local_addr()
    }

    /// A new, independent subscription to events, starting now.
    ///
    /// It buffers up to `event_buffer` events. A consumer that falls behind loses the oldest
    /// and reads [`Event::EventsLost`] next; resync from [`members`](Self::members) then.
    /// [`Events::recv`] returns `None` once the node has closed.
    pub fn events(&self) -> Events {
        self.inner.events()
    }

    /// Replaces this node's metadata and gossips it to the cluster.
    pub async fn set_meta(&self, meta: impl Into<Vec<u8>>) -> Result<(), Error> {
        self.inner.set_meta(meta).await
    }

    /// Protocol counters and the local health score.
    pub fn stats(&self) -> Stats {
        self.inner.stats()
    }

    /// Changes this node's keys at runtime: `install`, `use_key`, `remove` and `key_ids`. Each
    /// step acts on this node only, so run it on every node before starting the next; see
    /// [`Keyring`].
    pub fn keyring(&self) -> Keyring {
        self.inner.keyring()
    }

    /// Tells the cluster this node is leaving and waits, up to `timeout`, for the news to
    /// spread. Peers then report it as left, never dead.
    pub async fn leave(&self, timeout: Duration) -> Result<(), Error> {
        self.inner.leave(timeout).await
    }

    /// Stops the node and closes its sockets. Without [`leave`](Self::leave) first, peers see
    /// a crash.
    pub async fn close(&self) {
        self.inner.close().await;
    }

    /// Stops the node at once, as a crash would. For tests and fault injection.
    pub fn abort(&self) {
        self.inner.abort();
    }

    /// True once the node has stopped.
    pub fn is_closed(&self) -> bool {
        self.inner.is_closed()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_wire_version() {
        assert_eq!(WIRE_VERSION, 1);
    }
}
