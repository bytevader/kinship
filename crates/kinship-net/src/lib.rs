//! tokio UDP and TCP driver for kinship-core.
//!
//! [`Memberlist::start`] binds nothing itself: it takes a [`Transport`], usually a
//! [`TokioTransport`] bound with [`TokioTransport::bind`], builds the sans-IO
//! [`kinship_core::Node`] and spawns one actor task that owns it. The actor feeds the node every
//! datagram, stream frame, timer expiry and command, and after each input drains what the node
//! wants sent and what it has to report. Handles talk to the actor over a channel with oneshot
//! replies, read membership from a snapshot the actor publishes after every change, and receive
//! events through bounded per-subscription queues that never make the actor wait.
//!
//! The `kinship` crate wraps this as `Cluster`, with a builder for the configuration.

mod actor;
mod conn;
mod events;
pub mod mem;
mod transport;

use std::fmt;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};
use std::time::Duration;

use arc_swap::ArcSwap;
use tokio::sync::{mpsc, oneshot};
use tokio::task::{AbortHandle, JoinHandle};

pub use events::{Event, Events};
pub use kinship_core::{
    CommandError, Config, ConfigError, Identity, Key, KeyError, KeyId, Limits, Member, Metrics,
    Security, State, WIRE_VERSION,
};
pub use transport::{TokioTransport, Transport, default_advertise};

use crate::actor::{Actor, Clock, KeyChange, Request, Shared, Snapshot};
use crate::events::Hub;

/// Everything a node needs that the transport does not decide.
#[derive(Debug, Clone)]
pub struct Settings {
    /// The protocol configuration, with its security already chosen.
    pub core: Config,
    /// This node's name: 1 to 64 bytes of UTF-8, unique in the cluster.
    pub name: String,
    /// The address peers use to reach this node. `None` derives it from the transport's address
    /// with [`default_advertise`].
    pub advertise: Option<SocketAddr>,
    /// Initial metadata, at most `max_meta_bytes`.
    pub meta: Vec<u8>,
    /// Joined on start, and rejoined every `rejoin_interval` while the node has no live members.
    pub seeds: Vec<SocketAddr>,
    /// Inbound TCP connections served at once; a new one beyond this drops the oldest.
    pub max_inbound_streams: usize,
    /// Events each subscription holds before the oldest are dropped.
    pub event_buffer: usize,
}

impl Settings {
    pub const DEFAULT_MAX_INBOUND_STREAMS: usize = 64;
    pub const DEFAULT_EVENT_BUFFER: usize = 1024;

    /// Settings with no metadata, no seeds and the default limits.
    pub fn new(core: Config, name: impl Into<String>) -> Self {
        Self {
            core,
            name: name.into(),
            advertise: None,
            meta: Vec::new(),
            seeds: Vec::new(),
            max_inbound_streams: Self::DEFAULT_MAX_INBOUND_STREAMS,
            event_buffer: Self::DEFAULT_EVENT_BUFFER,
        }
    }

    /// Checks the fields the core does not; [`Memberlist::start`] calls it too.
    pub fn validate(&self) -> Result<(), ConfigError> {
        if self.max_inbound_streams == 0 {
            return Err(ConfigError {
                field: "max_inbound_streams",
                reason: "must be at least 1",
            });
        }
        if self.event_buffer == 0 {
            return Err(ConfigError {
                field: "event_buffer",
                reason: "must be at least 1",
            });
        }
        Ok(())
    }
}

/// Counters from the protocol core and this node's Lifeguard local health score.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
#[non_exhaustive]
pub struct Stats {
    pub metrics: Metrics,
    /// Lifeguard's local health multiplier: 0 when healthy, up to `awareness_max`.
    pub local_health: u32,
}

/// Why a call on a [`Memberlist`] failed.
#[derive(Debug)]
#[non_exhaustive]
pub enum Error {
    /// A configuration value is unusable; the error names the field.
    Config(ConfigError),
    /// Binding the sockets, or drawing the node's random seed, failed.
    Io(io::Error),
    /// No seed answered after `join_retries` attempts each.
    JoinFailed,
    /// Metadata is larger than `max_meta_bytes`.
    MetaTooLarge,
    /// This node has left the cluster.
    Left,
    /// `leave()` ran out of time before the news finished spreading. The node has left anyway.
    Timeout,
    /// The node was closed, or its actor stopped.
    Closed,
    /// A keyring call on a node that runs without encryption.
    NotEncrypted,
    /// `use` of a key that is not installed.
    KeyNotInstalled,
    /// `remove` of the key the node encrypts with.
    KeyInUse,
    /// `remove` of the only installed key.
    LastKey,
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Config(e) => e.fmt(f),
            Self::Io(e) => write!(f, "I/O error: {e}"),
            Self::JoinFailed => f.write_str("no seed answered"),
            Self::MetaTooLarge => f.write_str("metadata larger than max_meta_bytes"),
            Self::Left => f.write_str("this node has left the cluster"),
            Self::Timeout => f.write_str("timed out"),
            Self::Closed => f.write_str("the node is closed"),
            Self::NotEncrypted => f.write_str("this node runs without encryption and has no keys"),
            Self::KeyNotInstalled => f.write_str("key is not installed"),
            Self::KeyInUse => f.write_str("key is the one in use"),
            Self::LastKey => f.write_str("key is the last one installed"),
        }
    }
}

impl std::error::Error for Error {
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Self::Config(e) => Some(e),
            Self::Io(e) => Some(e),
            _ => None,
        }
    }
}

impl From<ConfigError> for Error {
    fn from(e: ConfigError) -> Self {
        Self::Config(e)
    }
}

impl From<io::Error> for Error {
    fn from(e: io::Error) -> Self {
        Self::Io(e)
    }
}

impl From<CommandError> for Error {
    fn from(e: CommandError) -> Self {
        match e {
            CommandError::MetaTooLarge => Self::MetaTooLarge,
            CommandError::JoinFailed => Self::JoinFailed,
            CommandError::Left => Self::Left,
            CommandError::NotEncrypted => Self::NotEncrypted,
            CommandError::KeyNotInstalled => Self::KeyNotInstalled,
            CommandError::KeyInUse => Self::KeyInUse,
            CommandError::LastKey => Self::LastKey,
            _ => Self::Closed,
        }
    }
}

/// Requests queued for the actor before senders wait.
const REQUEST_QUEUE: usize = 256;

/// A running node: the handle to its actor.
///
/// Reads ([`members`](Self::members), [`member`](Self::member), [`local`](Self::local),
/// [`stats`](Self::stats)) never wait on the actor. Calls that change the node go to the actor
/// and wait for its answer. Dropping the handle stops the node as [`abort`](Self::abort) does.
pub struct Memberlist {
    requests: mpsc::Sender<Request>,
    shared: Arc<Shared>,
    local_addr: SocketAddr,
    task: Mutex<Option<JoinHandle<()>>>,
    abort: AbortHandle,
}

impl Memberlist {
    /// Starts a node on `transport` and joins `settings.seeds`, skipping this node's own address.
    ///
    /// A startup join that reaches no seed only logs a warning: the node runs alone and retries
    /// every `rejoin_interval`. Must be called from within a tokio runtime, which runs the actor.
    pub async fn start<T: Transport>(settings: Settings, transport: T) -> Result<Self, Error> {
        let seeds = settings.seeds.clone();
        let ml = Self::spawn(settings, transport)?;
        if !seeds.is_empty() {
            match ml.join(seeds).await {
                Ok(n) => tracing::debug!(seeds = n, "joined"),
                Err(Error::Closed) => return Err(Error::Closed),
                Err(e) => {
                    tracing::warn!(error = %e, "startup join failed; retrying in the background")
                }
            }
        }
        Ok(ml)
    }

    fn spawn<T: Transport>(settings: Settings, transport: T) -> Result<Self, Error> {
        settings.validate()?;
        let local_addr = transport.local_addr();
        let advertise = settings
            .advertise
            .unwrap_or_else(|| default_advertise(local_addr));
        let me = kinship_core::Identity::new(settings.name, advertise)?.with_meta(settings.meta);
        // The core draws every nonce from this seed, so it must come from the OS.
        let seed = getrandom::u64().map_err(|e| Error::Io(io::Error::other(e.to_string())))?;
        let clock = Clock::new();
        let limits = conn::Limits {
            tcp_timeout: settings.core.tcp_timeout,
            max_stream_frame: settings.core.limits.max_stream_frame,
        };
        let rejoin_interval = settings.core.rejoin_interval;
        let node = kinship_core::Node::new(settings.core, me, clock.now(), seed)?;
        tracing::info!(name = node.local().name, addr = %advertise, bind = %local_addr, "node started");
        let shared = Arc::new(Shared {
            snapshot: ArcSwap::from_pointee(Snapshot::of(&node)),
            key_ids: ArcSwap::from_pointee(node.key_ids()),
            stats: Mutex::default(),
            hub: Hub::new(settings.event_buffer),
        });
        let (requests, rx) = mpsc::channel(REQUEST_QUEUE);
        let opts = actor::Options {
            limits,
            max_inbound_streams: settings.max_inbound_streams,
            seeds: settings.seeds,
            rejoin_interval,
        };
        let actor = Actor::new(
            node,
            clock,
            Arc::new(transport),
            Arc::clone(&shared),
            rx,
            opts,
        );
        let task = tokio::spawn(actor.run());
        Ok(Self {
            requests,
            shared,
            local_addr,
            abort: task.abort_handle(),
            task: Mutex::new(Some(task)),
        })
    }

    /// The address the transport is bound to; with port 0, the port the OS picked.
    pub fn local_addr(&self) -> SocketAddr {
        self.local_addr
    }

    /// This node as the cluster sees it.
    pub fn local(&self) -> Member {
        self.shared.snapshot.load().local().clone()
    }

    /// Alive and suspect members, this node included unless it has left.
    pub fn members(&self) -> Vec<Member> {
        let snapshot = self.shared.snapshot.load();
        snapshot
            .all
            .iter()
            .filter(|m| m.state.is_live())
            .cloned()
            .collect()
    }

    /// One member by name, including dead and left tombstones.
    pub fn member(&self, name: &str) -> Option<Member> {
        let snapshot = self.shared.snapshot.load();
        snapshot.all.iter().find(|m| m.name == name).cloned()
    }

    /// A new subscription to events, starting now. See [`Events`].
    pub fn events(&self) -> Events {
        self.shared.hub.subscribe()
    }

    /// Protocol counters and the local health score.
    pub fn stats(&self) -> Stats {
        self.shared.stats().clone()
    }

    /// Changes this node's keys at runtime. See [`Keyring`].
    pub fn keyring(&self) -> Keyring {
        Keyring {
            requests: self.requests.clone(),
            shared: Arc::clone(&self.shared),
        }
    }

    /// Push-pulls with every seed, retrying failed ones with backoff until one answers, and
    /// returns how many answered. This node's own address is skipped.
    pub async fn join(&self, seeds: impl IntoIterator<Item = SocketAddr>) -> Result<usize, Error> {
        let seeds = seeds.into_iter().collect();
        let rx = self.call(|reply| Request::Join { seeds, reply }).await?;
        rx.await.unwrap_or(Err(Error::Closed))
    }

    /// Replaces this node's metadata and gossips it. Returns once the change is queued.
    pub async fn set_meta(&self, meta: impl Into<Vec<u8>>) -> Result<(), Error> {
        let meta = meta.into();
        let rx = self.call(|reply| Request::SetMeta { meta, reply }).await?;
        rx.await.unwrap_or(Err(Error::Closed))
    }

    /// Tells the cluster this node is leaving and waits, up to `timeout`, until the news has
    /// been sent as often as any rumour is. The node then stops probing and never refutes, so it
    /// is reported as left, never dead. Call [`close`](Self::close) afterwards.
    pub async fn leave(&self, timeout: Duration) -> Result<(), Error> {
        let rx = self.call(|reply| Request::Leave { reply }).await?;
        match tokio::time::timeout(timeout, rx).await {
            Ok(r) => r.unwrap_or(Err(Error::Closed)),
            Err(_) => Err(Error::Timeout),
        }
    }

    /// Stops the node and closes its sockets, then returns. Without [`leave`](Self::leave)
    /// first, peers see a crash. Calling it again does nothing.
    pub async fn close(&self) {
        let (reply, done) = oneshot::channel();
        if self.requests.send(Request::Close { reply }).await.is_ok() {
            let _ = done.await;
        }
        let task = self.task().take();
        if let Some(task) = task {
            if let Err(e) = task.await {
                if e.is_panic() {
                    tracing::error!("the node's actor panicked");
                }
            }
        }
    }

    /// Stops the node at once, as if its process crashed: nothing is sent, sockets close, and
    /// peers detect the failure. For tests and fault injection.
    pub fn abort(&self) {
        // Dropping the handle detaches the task; the abort stops it. Taking it also tells Drop
        // that this stop was deliberate.
        drop(self.task().take());
        self.abort.abort();
    }

    /// True once the node has stopped, by [`close`](Self::close), [`abort`](Self::abort) or a
    /// panic in its actor.
    pub fn is_closed(&self) -> bool {
        self.requests.is_closed()
    }

    async fn call<R>(
        &self,
        make: impl FnOnce(oneshot::Sender<R>) -> Request,
    ) -> Result<oneshot::Receiver<R>, Error> {
        let (reply, rx) = oneshot::channel();
        self.requests
            .send(make(reply))
            .await
            .map_err(|_| Error::Closed)?;
        Ok(rx)
    }

    fn task(&self) -> std::sync::MutexGuard<'_, Option<JoinHandle<()>>> {
        self.task.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Runtime key rotation for one node, from [`Memberlist::keyring`].
///
/// Every call acts on this node only. To rotate a cluster, run each step on every node and wait
/// for it to finish everywhere before starting the next:
///
/// 1. [`install`](Self::install) the new key, so every node can read it;
/// 2. [`use_key`](Self::use_key) it, so every node sends with it;
/// 3. [`remove`](Self::remove) the old key.
///
/// A node that falls a step behind looks dead to its peers until it catches up, and they count
/// what they dropped as `decrypt_failures` in [`Stats`]. A node that runs without encryption
/// refuses every call with [`Error::NotEncrypted`]. Key ids are safe to log; key bytes never are.
///
/// A handle is cheap to clone and keeps working only while the node runs: calls on a closed node
/// fail with [`Error::Closed`].
#[derive(Clone)]
pub struct Keyring {
    requests: mpsc::Sender<Request>,
    shared: Arc<Shared>,
}

impl Keyring {
    /// Adds `key` to the keys this node can decrypt with. Does nothing if it is installed.
    pub async fn install(&self, key: Key) -> Result<(), Error> {
        self.change(KeyChange::Install(key)).await
    }

    /// Makes the installed `key` the one this node encrypts with. Every installed key still
    /// decrypts. Fails with [`Error::KeyNotInstalled`] for a key that was never installed.
    ///
    /// Named `use_key` because `use` is a Rust keyword; Python spells it `use`.
    pub async fn use_key(&self, key: Key) -> Result<(), Error> {
        self.change(KeyChange::Use(key)).await
    }

    /// Drops `key`. Fails with [`Error::KeyInUse`] for the key this node encrypts with and
    /// [`Error::LastKey`] for the only one; a key that is not installed is already gone.
    pub async fn remove(&self, key: Key) -> Result<(), Error> {
        self.change(KeyChange::Remove(key)).await
    }

    /// The ids of the installed keys, the one this node encrypts with first. Empty when the node
    /// runs without encryption. Never waits on the actor.
    pub fn key_ids(&self) -> Vec<KeyId> {
        self.shared.key_ids.load().as_ref().clone()
    }

    async fn change(&self, change: KeyChange) -> Result<(), Error> {
        let (reply, rx) = oneshot::channel();
        self.requests
            .send(Request::Keyring { change, reply })
            .await
            .map_err(|_| Error::Closed)?;
        rx.await.unwrap_or(Err(Error::Closed))
    }
}

impl fmt::Debug for Keyring {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Keyring")
            .field("key_ids", &self.key_ids())
            .finish()
    }
}

impl Drop for Memberlist {
    fn drop(&mut self) {
        if self.task().is_some() && !self.is_closed() {
            if self.local().state != State::Left {
                tracing::warn!("node dropped without leave() or close(); peers will see a crash");
            }
            self.abort.abort();
        }
    }
}

impl fmt::Debug for Memberlist {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("Memberlist")
            .field("local_addr", &self.local_addr)
            .field("closed", &self.is_closed())
            .finish_non_exhaustive()
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
