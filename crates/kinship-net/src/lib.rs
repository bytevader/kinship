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
mod seed;
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
pub use seed::{Seed, SeedError};
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
    /// Joined on start, and every `rejoin_interval` each one that is not a live member is
    /// push-pulled with again.
    pub seeds: Vec<SocketAddr>,
    /// Seeds that may be DNS names, joined and rejoined like `seeds`. Each name is looked up
    /// again at every join and rejoin, and every address it has, A and AAAA records alike, is a
    /// seed, so a name with several records, such as a Kubernetes headless Service, works as a
    /// seed list.
    pub seed_hosts: Vec<Seed>,
    /// How long a join looks names up again, with backoff, while no seed resolves. A start whose
    /// seeds stay unresolved this long fails with [`Error::Unresolved`]; once one resolves, the
    /// others are looked up again at every rejoin.
    pub resolve_timeout: Duration,
    /// Inbound TCP connections served at once. A new one beyond this drops the oldest of the
    /// source address with the most.
    pub max_inbound_streams: usize,
    /// Inbound TCP connections served at once from one source address. A new one beyond this
    /// drops that address's oldest.
    pub max_inbound_streams_per_ip: usize,
    /// Bytes of unauthenticated inbound frames that connections from one source address may
    /// hold at once, out of the twice `max_stream_frame` all inbound connections share. `None`
    /// is one largest frame: `max_stream_frame` and its 4-byte length prefix.
    pub max_inbound_bytes_per_ip: Option<usize>,
    /// How long an inbound TCP connection has to send the length prefix and the first 8 header
    /// bytes of its frame, or `tcp_timeout` if that is shorter.
    pub tcp_header_timeout: Duration,
    /// Events each subscription holds before the oldest are dropped.
    pub event_buffer: usize,
}

impl Settings {
    pub const DEFAULT_MAX_INBOUND_STREAMS: usize = 64;
    pub const DEFAULT_MAX_INBOUND_STREAMS_PER_IP: usize = 16;
    pub const DEFAULT_TCP_HEADER_TIMEOUT: Duration = Duration::from_secs(1);
    pub const DEFAULT_EVENT_BUFFER: usize = 1024;
    pub const DEFAULT_RESOLVE_TIMEOUT: Duration = Duration::from_secs(30);

    /// Settings with no metadata, no seeds and the default limits.
    pub fn new(core: Config, name: impl Into<String>) -> Self {
        Self {
            core,
            name: name.into(),
            advertise: None,
            meta: Vec::new(),
            seeds: Vec::new(),
            seed_hosts: Vec::new(),
            resolve_timeout: Self::DEFAULT_RESOLVE_TIMEOUT,
            max_inbound_streams: Self::DEFAULT_MAX_INBOUND_STREAMS,
            max_inbound_streams_per_ip: Self::DEFAULT_MAX_INBOUND_STREAMS_PER_IP,
            max_inbound_bytes_per_ip: None,
            tcp_header_timeout: Self::DEFAULT_TCP_HEADER_TIMEOUT,
            event_buffer: Self::DEFAULT_EVENT_BUFFER,
        }
    }

    /// Bytes of unauthenticated inbound frames one source address may hold:
    /// `max_inbound_bytes_per_ip`, or one largest frame.
    pub fn inbound_bytes_per_ip(&self) -> usize {
        self.max_inbound_bytes_per_ip.unwrap_or_else(|| {
            self.core
                .limits
                .max_stream_frame
                .saturating_add(FRAME_PREFIX_LEN)
        })
    }

    /// Checks the fields the core does not; [`Memberlist::start`] calls it too.
    pub fn validate(&self) -> Result<(), ConfigError> {
        let fail = |field, reason| Err(ConfigError { field, reason });
        if self.max_inbound_streams == 0 {
            return fail("max_inbound_streams", "must be at least 1");
        }
        if self.max_inbound_streams_per_ip == 0 {
            return fail("max_inbound_streams_per_ip", "must be at least 1");
        }
        let frame = self.core.limits.max_stream_frame;
        if self.inbound_bytes_per_ip() < frame.saturating_add(FRAME_PREFIX_LEN) {
            return fail(
                "max_inbound_bytes_per_ip",
                "must hold one max_stream_frame frame and its 4-byte length prefix",
            );
        }
        if self.tcp_header_timeout.is_zero() {
            return fail("tcp_header_timeout", "must be positive");
        }
        if self.event_buffer == 0 {
            return fail("event_buffer", "must be at least 1");
        }
        Ok(())
    }
}

/// The `u32` length prefix in front of every stream frame.
const FRAME_PREFIX_LEN: usize = 4;

/// `seeds` and `seed_hosts` as one list.
fn all_seeds(settings: &Settings) -> Vec<Seed> {
    let addrs = settings.seeds.iter().copied().map(Seed::Addr);
    addrs.chain(settings.seed_hosts.iter().cloned()).collect()
}

/// The epoch of this life of the node: milliseconds of the wall clock since the Unix epoch,
/// which a process that restarts later reads higher. This is the one read of the wall clock,
/// and it names the node rather than timing anything, so a jump cannot move a timer. A clock
/// that reads below an earlier life of the same name is caught by the core, which moves past
/// that life once it hears of it; one before 1970 reads as 1, since 0 means no epoch.
#[allow(clippy::disallowed_types, clippy::disallowed_methods)]
fn start_epoch() -> u64 {
    let since = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    u64::try_from(since.as_millis()).unwrap_or(u64::MAX).max(1)
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
    /// No seed resolved to an address within `resolve_timeout`.
    Unresolved,
    /// Metadata is larger than `max_meta_bytes`.
    MetaTooLarge,
    /// A user message is larger than `max_user_message`, or a broadcast than
    /// `max_user_broadcast`.
    MessageTooLarge,
    /// A user message for a name this node does not hold as a live member at that epoch: one
    /// it does not know, one that died or left, a run that has since restarted, or itself.
    NotAMember,
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
            Self::Unresolved => f.write_str("no seed resolved to an address"),
            Self::MetaTooLarge => f.write_str("metadata larger than max_meta_bytes"),
            Self::MessageTooLarge => {
                f.write_str("message larger than max_user_message or max_user_broadcast")
            }
            Self::NotAMember => f.write_str("not a live member at that epoch"),
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
            CommandError::MessageTooLarge => Self::MessageTooLarge,
            CommandError::NotAMember => Self::NotAMember,
            _ => Self::Closed,
        }
    }
}

/// A new random key: 32 bytes from the operating system's secure random source.
///
/// Give the same key to every node. Print it with [`Key::to_base64`] to hand it out, as
/// `python -m kinship keygen` does; never derive a key from a passphrase or a seeded RNG.
pub fn generate_key() -> io::Result<Key> {
    let mut bytes = [0u8; Key::LEN];
    let drawn = getrandom::fill(&mut bytes).map_err(|e| io::Error::other(e.to_string()));
    let key = drawn.map(|()| Key::from_bytes(bytes));
    zeroize::Zeroize::zeroize(&mut bytes);
    key
}

/// A node name for when none is configured: the host name plus 6 random hex characters, within
/// the 64-byte limit. Set a stable name instead if the node should keep its identity across
/// restarts.
pub fn default_name() -> String {
    let host = ["HOSTNAME", "COMPUTERNAME"]
        .iter()
        .find_map(|v| std::env::var(v).ok())
        .or_else(|| std::fs::read_to_string("/etc/hostname").ok())
        .map(|h| h.trim().to_owned())
        .filter(|h| !h.is_empty())
        .unwrap_or_else(|| "kinship".to_owned());
    let mut end = host.len().min(57);
    while !host.is_char_boundary(end) {
        end -= 1;
    }
    let suffix = getrandom::u32().unwrap_or_default() & 0xff_ffff;
    format!("{}-{suffix:06x}", &host[..end])
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
    resolve_timeout: Duration,
    task: Mutex<Option<JoinHandle<()>>>,
    abort: AbortHandle,
}

impl Memberlist {
    /// Starts a node on `transport` and joins `settings.seeds` and `settings.seed_hosts`,
    /// skipping this node's own address.
    ///
    /// A startup join that reaches no seed only logs a warning: the node runs alone and retries
    /// every `rejoin_interval`. Seed names that do not resolve are logged and looked up again,
    /// but if no seed resolves within `resolve_timeout` the node stops and start fails with
    /// [`Error::Unresolved`]. Must be called from within a tokio runtime, which runs the actor.
    pub async fn start<T: Transport>(settings: Settings, transport: T) -> Result<Self, Error> {
        let seeds = all_seeds(&settings);
        let ml = Self::spawn(settings, transport)?;
        if !seeds.is_empty() {
            match ml.join_seeds(seeds).await {
                Ok(n) => tracing::debug!(seeds = n, "joined"),
                Err(Error::Closed) => return Err(Error::Closed),
                Err(Error::Unresolved) => {
                    tracing::error!("no seed resolved; stopping");
                    ml.close().await;
                    return Err(Error::Unresolved);
                }
                Err(e) => {
                    tracing::warn!(error = %e, "startup join failed; retrying in the background")
                }
            }
        }
        Ok(ml)
    }

    fn spawn<T: Transport>(settings: Settings, transport: T) -> Result<Self, Error> {
        settings.validate()?;
        let seeds = all_seeds(&settings);
        let resolve_timeout = settings.resolve_timeout;
        let max_inbound_bytes_per_ip = settings.inbound_bytes_per_ip();
        let local_addr = transport.local_addr();
        let advertise = settings
            .advertise
            .unwrap_or_else(|| default_advertise(local_addr));
        let me = kinship_core::Identity::new(settings.name, advertise)?
            .with_meta(settings.meta)
            .with_epoch(start_epoch());
        // The core draws no randomness of its own: its protocol choices come from this seed and
        // the random bytes of its nonces from ChaCha20 under this key, both from the OS.
        let os = |e: getrandom::Error| Error::Io(io::Error::other(e.to_string()));
        let seed = getrandom::u64().map_err(os)?;
        let mut nonce_key = [0u8; 32];
        getrandom::fill(&mut nonce_key).map_err(os)?;
        let clock = Clock::new();
        let limits = conn::Limits {
            tcp_timeout: settings.core.tcp_timeout,
            max_stream_frame: settings.core.limits.max_stream_frame,
            header_timeout: settings.tcp_header_timeout,
        };
        let rejoin_interval = settings.core.rejoin_interval;
        let node = kinship_core::Node::new(settings.core, me, clock.now(), seed, &nonce_key);
        zeroize::Zeroize::zeroize(&mut nonce_key);
        let node = node?;
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
            max_inbound_streams_per_ip: settings.max_inbound_streams_per_ip,
            max_inbound_bytes_per_ip,
            seeds,
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
            resolve_timeout,
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
        self.join_seeds(seeds.into_iter().map(Seed::Addr)).await
    }

    /// [`join`](Self::join) with seeds that may be DNS names. Each name is looked up now, and
    /// every address it has is a seed. Names that do not resolve are logged and skipped; while
    /// none resolves and no seed is an address, they are looked up again with backoff for up to
    /// `resolve_timeout`, and then the join fails with [`Error::Unresolved`].
    pub async fn join_seeds(&self, seeds: impl IntoIterator<Item = Seed>) -> Result<usize, Error> {
        let seeds: Vec<Seed> = seeds.into_iter().collect();
        let seeds = seed::resolve_for_join(&seeds, self.resolve_timeout)
            .await
            .ok_or(Error::Unresolved)?;
        let rx = self.call(|reply| Request::Join { seeds, reply }).await?;
        rx.await.unwrap_or(Err(Error::Closed))
    }

    /// Replaces this node's metadata and gossips it. Returns once the change is queued.
    pub async fn set_meta(&self, meta: impl Into<Vec<u8>>) -> Result<(), Error> {
        let meta = meta.into();
        let rx = self.call(|reply| Request::SetMeta { meta, reply }).await?;
        rx.await.unwrap_or(Err(Error::Closed))
    }

    /// Sends `data` to the member `name` at its life `epoch`, or whichever life this node holds
    /// with epoch 0, and returns once it is handed to the network or queued for a connection.
    ///
    /// Best effort: one datagram when it fits, else a TCP connection, never acknowledged or
    /// retried. Fails with [`Error::MessageTooLarge`] over `max_user_message` and with
    /// [`Error::NotAMember`] unless this node holds that life of `name` as a live member.
    /// The receiver hears it as [`Event::UserMessage`].
    pub async fn send(
        &self,
        name: impl Into<String>,
        epoch: u64,
        data: impl Into<Vec<u8>>,
    ) -> Result<(), Error> {
        let (to, data) = (name.into(), data.into());
        let rx = self
            .call(|reply| Request::Send {
                to,
                epoch,
                data,
                reply,
            })
            .await?;
        rx.await.unwrap_or(Err(Error::Closed))
    }

    /// Queues `data` to be gossiped to every member, and returns once it is queued.
    ///
    /// Best effort, and at most once on each node, which hears it as [`Event::UserMessage`]
    /// with `broadcast` set; never this node. Fails with [`Error::MessageTooLarge`] over
    /// `max_user_broadcast`. A full queue drops the broadcast nearest to done and counts it
    /// in [`Stats`].
    pub async fn broadcast(&self, data: impl Into<Vec<u8>>) -> Result<(), Error> {
        let data = data.into();
        let rx = self
            .call(|reply| Request::Broadcast { data, reply })
            .await?;
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

    /// Makes the actor panic once it reaches this request, as a bug in it would. Not part of the
    /// API: it exists for the tests of how a failed node reports itself.
    #[cfg(any(test, feature = "test-hooks"))]
    #[doc(hidden)]
    pub fn panic_actor(&self) {
        let _ = self.requests.try_send(Request::Panic);
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

    #[test]
    fn default_names_are_valid_and_distinct() {
        let a = default_name();
        assert!(!a.is_empty() && a.len() <= 64, "{a}");
        assert_ne!(a, default_name());
    }

    #[tokio::test]
    async fn an_actor_panic_fails_pending_and_later_calls_and_marks_events_failed() {
        const WAIT: Duration = Duration::from_secs(10);
        let addr = |port: u8| SocketAddr::from(([10, 0, 0, port], 7946));
        let net = mem::MemNetwork::new();
        // A seed that never accepts, so a join with it waits for an answer.
        let _silent = net.bind(addr(9)).unwrap();
        let cfg = Config::local(Security::InsecurePlaintext);
        let transport = net.bind(addr(1)).unwrap();
        let ml = Memberlist::start(Settings::new(cfg, "a"), transport)
            .await
            .unwrap();
        let mut events = ml.events();
        let join = ml.join([addr(9)]);
        tokio::pin!(join);
        // One poll queues the join ahead of the panic.
        assert!(
            tokio::time::timeout(Duration::ZERO, &mut join)
                .await
                .is_err()
        );

        ml.panic_actor();
        let pending = tokio::time::timeout(WAIT, join).await.unwrap();
        assert!(matches!(pending, Err(Error::Closed)), "{pending:?}");
        assert_eq!(
            tokio::time::timeout(WAIT, events.recv()).await.unwrap(),
            None
        );
        assert!(events.failed());
        assert!(ml.is_closed());
        let later = ml.set_meta(b"x".to_vec()).await;
        assert!(matches!(later, Err(Error::Closed)), "{later:?}");
        let later = ml.keyring().install(Key::from_bytes([1; 32])).await;
        assert!(matches!(later, Err(Error::Closed)), "{later:?}");
        assert!(
            ml.events().failed(),
            "a later subscription sees the failure too"
        );
        ml.close().await;
    }

    #[test]
    fn generated_keys_are_random_and_round_trip() {
        let a = generate_key().unwrap();
        let b = generate_key().unwrap();
        assert_ne!(a, b);
        assert_eq!(Key::from_base64(&a.to_base64()), Ok(a));
    }
}
