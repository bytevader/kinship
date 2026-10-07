//! The actor: one task per node that owns the sans-IO [`Node`] and feeds it from the network.
//!
//! Its loop waits on the UDP socket, frames from connection tasks, new connections, commands and
//! a timer set to [`Node::poll_timeout`]. Whatever woke it, it then drains every datagram and
//! stream frame that is already readable before it lets a due timer fire. A node that is slow
//! to run would otherwise end a probe round, and suspect a healthy target, while that target's
//! Ack sat unread in its socket: the Lifeguard simulations showed exactly this, and Lifeguard's
//! local health only limits the damage. After every input it drains the node's transmits and
//! events, so replies leave at once even in the middle of a burst.

use std::collections::{HashMap, HashSet, VecDeque};
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use arc_swap::ArcSwap;
use kinship_core::{
    Command, CommandError, CommandId, CommandOutput, Instant, Key, KeyId, Member, Node, State,
    StreamEvent, StreamId, Transmit,
};
use tokio::sync::{mpsc, oneshot};
use tokio::task::{AbortHandle, JoinSet};
use tokio::time::{Instant as TokioInstant, sleep_until};

use crate::conn::{self, Budget, Report, Reports, Write};
use crate::events::{Event, Hub};
use crate::transport::Transport;
use crate::{Error, Stats};

/// Large enough for any UDP datagram, so an oversized one reaches the core whole and is counted
/// there instead of arriving truncated.
const MAX_DATAGRAM: usize = 65_536;

/// Inputs handled per wakeup before due timers run regardless. Far more than a socket buffer
/// holds, so it only matters under a flood that never lets up.
const MAX_BATCH: usize = 16_384;

/// How long the actor stops accepting connections after `accept` fails, for example because the
/// process ran out of file descriptors.
const ACCEPT_BACKOFF: Duration = Duration::from_millis(100);

/// How long the actor stops reading datagrams after the socket reports an unexpected error, so
/// a broken socket cannot spin it.
const RECV_BACKOFF: Duration = Duration::from_millis(10);

/// A request from a [`Memberlist`](crate::Memberlist) handle.
#[derive(Debug)]
pub(crate) enum Request {
    Join {
        seeds: Vec<SocketAddr>,
        reply: oneshot::Sender<Result<usize, Error>>,
    },
    Leave {
        reply: oneshot::Sender<Result<(), Error>>,
    },
    SetMeta {
        meta: Vec<u8>,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    Keyring {
        change: KeyChange,
        reply: oneshot::Sender<Result<(), Error>>,
    },
    Close {
        reply: oneshot::Sender<()>,
    },
    /// Makes the actor panic; see `Memberlist::panic_actor`.
    #[cfg(any(test, feature = "test-hooks"))]
    Panic,
}

/// A change to the node's keys.
#[derive(Debug)]
pub(crate) enum KeyChange {
    Install(Key),
    Use(Key),
    Remove(Key),
}

impl KeyChange {
    fn command(self) -> (Command, &'static str, KeyId) {
        match self {
            Self::Install(k) => {
                let id = k.key_id();
                (Command::InstallKey(k), "installed", id)
            }
            Self::Use(k) => {
                let id = k.key_id();
                (Command::UseKey(k), "now encrypting with", id)
            }
            Self::Remove(k) => {
                let id = k.key_id();
                (Command::RemoveKey(k), "removed", id)
            }
        }
    }
}

/// What the handles read without a round trip to the actor.
#[derive(Debug)]
pub(crate) struct Shared {
    pub snapshot: ArcSwap<Snapshot>,
    /// Ids of the installed keys, the one in use first; updated before a keyring call returns.
    pub key_ids: ArcSwap<Vec<KeyId>>,
    pub stats: Mutex<Stats>,
    pub hub: Hub,
}

impl Shared {
    pub fn stats(&self) -> MutexGuard<'_, Stats> {
        self.stats.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// Every member the node knows, tombstones included, this node first.
#[derive(Debug, Clone)]
pub(crate) struct Snapshot {
    pub all: Vec<Member>,
}

impl Snapshot {
    pub fn of(node: &Node) -> Self {
        Self {
            all: node.all_members().cloned().collect(),
        }
    }

    pub fn local(&self) -> &Member {
        &self.all[0]
    }
}

/// Maps tokio's clock onto the core's timeline, which starts when the node does.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Clock {
    start: TokioInstant,
}

impl Clock {
    pub fn new() -> Self {
        Self {
            start: TokioInstant::now(),
        }
    }

    pub fn now(&self) -> Instant {
        let elapsed = TokioInstant::now().saturating_duration_since(self.start);
        Instant::from_nanos(u64::try_from(elapsed.as_nanos()).unwrap_or(u64::MAX))
    }

    fn to_tokio(self, t: Instant) -> TokioInstant {
        self.start
            .checked_add(Duration::from_nanos(t.as_nanos()))
            .unwrap_or_else(far_future)
    }
}

fn far_future() -> TokioInstant {
    TokioInstant::now() + Duration::from_secs(365 * 24 * 3600)
}

/// A command waiting for its [`kinship_core::Event::CommandDone`].
#[derive(Debug)]
enum Pending {
    Join(oneshot::Sender<Result<usize, Error>>),
    Done(oneshot::Sender<Result<(), Error>>),
    /// A key change, logged by id once it has succeeded.
    Keyring {
        reply: oneshot::Sender<Result<(), Error>>,
        did: &'static str,
        key: KeyId,
    },
    /// A background rejoin started by the actor itself, while the node had no live member or
    /// not.
    Rejoin {
        alone: bool,
    },
}

/// A connection task the actor can write to and stop.
#[derive(Debug)]
struct Conn {
    writes: mpsc::UnboundedSender<Write>,
    abort: AbortHandle,
}

/// Everything the actor needs besides the node.
#[derive(Debug)]
pub(crate) struct Options {
    pub limits: conn::Limits,
    pub max_inbound_streams: usize,
    pub seeds: Vec<SocketAddr>,
    pub rejoin_interval: Duration,
}

pub(crate) struct Actor<T: Transport> {
    node: Node,
    clock: Clock,
    transport: Arc<T>,
    shared: Arc<Shared>,
    requests: mpsc::Receiver<Request>,
    reports_tx: Reports,
    reports: mpsc::UnboundedReceiver<(StreamId, Report)>,
    conns: HashMap<StreamId, Conn>,
    /// Inbound connections still running, oldest first.
    inbound: VecDeque<StreamId>,
    /// Bytes inbound connections may hold before their frames are handled.
    budget: Arc<Budget>,
    next_inbound: u64,
    tasks: JoinSet<()>,
    pending: HashMap<CommandId, Pending>,
    opts: Options,
    next_rejoin: Option<Instant>,
    rejoining: bool,
    accept_paused: Option<TokioInstant>,
    recv_paused: Option<TokioInstant>,
    /// Scratch for the events of one input.
    events: Vec<Event>,
}

/// What woke the actor.
enum Input<S> {
    Datagram(std::io::Result<(usize, SocketAddr)>),
    Report((StreamId, Report)),
    Accept(std::io::Result<(S, SocketAddr)>),
    Request(Option<Request>),
    Timer,
}

impl<T: Transport> Actor<T> {
    pub fn new(
        node: Node,
        clock: Clock,
        transport: Arc<T>,
        shared: Arc<Shared>,
        requests: mpsc::Receiver<Request>,
        opts: Options,
    ) -> Self {
        let (reports_tx, reports) = mpsc::unbounded_channel();
        let next_rejoin = (!opts.rejoin_interval.is_zero() && !opts.seeds.is_empty())
            .then(|| clock.now() + opts.rejoin_interval);
        Self {
            node,
            clock,
            transport,
            shared,
            requests,
            reports_tx,
            reports,
            conns: HashMap::new(),
            inbound: VecDeque::new(),
            budget: Budget::for_frames(opts.limits.max_stream_frame),
            next_inbound: 0,
            tasks: JoinSet::new(),
            pending: HashMap::new(),
            opts,
            next_rejoin,
            rejoining: false,
            accept_paused: None,
            recv_paused: None,
            events: Vec::new(),
        }
    }

    pub async fn run(mut self) {
        let mut buf = vec![0; MAX_DATAGRAM];
        let close = loop {
            let wake = self.wake_at();
            let reading = self.recv_paused.is_none();
            let accepting = self.accept_paused.is_none();
            let input = tokio::select! {
                biased;
                r = self.transport.recv_datagram(&mut buf), if reading => Input::Datagram(r),
                Some(r) = self.reports.recv() => Input::Report(r),
                r = self.transport.accept(), if accepting => Input::Accept(r),
                r = self.requests.recv() => Input::Request(r),
                () = sleep_until(wake) => Input::Timer,
            };
            match input {
                Input::Datagram(Ok((n, from))) => self.datagram(&buf[..n], from),
                Input::Datagram(Err(e)) => {
                    tracing::warn!(error = %e, "receiving a datagram failed");
                    self.recv_paused = Some(TokioInstant::now() + RECV_BACKOFF);
                }
                Input::Report((conn, r)) => self.report(conn, r),
                Input::Accept(Ok((stream, from))) => self.accept(stream, from),
                Input::Accept(Err(e)) => {
                    tracing::warn!(error = %e, "accepting a connection failed");
                    self.accept_paused = Some(TokioInstant::now() + ACCEPT_BACKOFF);
                }
                Input::Request(Some(Request::Close { reply })) => break Some(reply),
                Input::Request(Some(req)) => self.request(req),
                // Every handle is gone.
                Input::Request(None) => break None,
                Input::Timer => {}
            }
            self.drain(&mut buf);
            self.timers();
            self.publish_stats();
        };
        // Closes the sockets, stops the connection tasks and ends the event subscriptions
        // before the caller of close() hears back.
        drop(self);
        if let Some(reply) = close {
            let _ = reply.send(());
        }
    }

    /// The earliest instant something is due.
    fn wake_at(&self) -> TokioInstant {
        let core = [self.node.poll_timeout(), self.next_rejoin]
            .into_iter()
            .flatten()
            .min()
            .map(|t| self.clock.to_tokio(t));
        [core, self.accept_paused, self.recv_paused]
            .into_iter()
            .flatten()
            .min()
            .unwrap_or_else(far_future)
    }

    /// Hands the node every datagram and stream report that is already waiting.
    fn drain(&mut self, buf: &mut [u8]) {
        for _ in 0..MAX_BATCH {
            let mut any = false;
            if self.recv_paused.is_none() {
                match self.transport.try_recv_datagram(buf) {
                    Ok((n, from)) => {
                        self.datagram(&buf[..n], from);
                        any = true;
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {}
                    Err(e) => {
                        tracing::warn!(error = %e, "receiving a datagram failed");
                        self.recv_paused = Some(TokioInstant::now() + RECV_BACKOFF);
                    }
                }
            }
            if let Ok((conn, r)) = self.reports.try_recv() {
                self.report(conn, r);
                any = true;
            }
            if !any {
                return;
            }
        }
    }

    /// Runs the node's timers if they are due, then the rejoin check.
    fn timers(&mut self) {
        let now = self.clock.now();
        if self.node.poll_timeout().is_some_and(|t| t <= now) {
            self.node.handle_timeout(now);
            self.flush(true);
        }
        self.rejoin(now);
        let tokio_now = TokioInstant::now();
        if self.accept_paused.is_some_and(|t| t <= tokio_now) {
            self.accept_paused = None;
        }
        if self.recv_paused.is_some_and(|t| t <= tokio_now) {
            self.recv_paused = None;
        }
    }

    /// Every `rejoin_interval`, push-pulls with each configured seed that is not a live member.
    /// A node that started alone or was cut off finds the cluster again, and a seed on the far
    /// side of a partition that outlasted the tombstones merges the two sides.
    fn rejoin(&mut self, now: Instant) {
        let Some(at) = self.next_rejoin.filter(|&t| t <= now) else {
            return;
        };
        let interval = self.opts.rejoin_interval;
        let missed = (now - at).as_nanos() / interval.as_nanos();
        self.next_rejoin = Some(at + interval * u32::try_from(missed + 1).unwrap_or(u32::MAX));
        if self.rejoining || self.node.local().state == State::Left {
            return;
        }
        // This node is one of its own live members, so its own address is never a target.
        let live: HashSet<SocketAddr> = self.node.members().map(|m| m.addr).collect();
        let seeds: Vec<SocketAddr> = self
            .opts
            .seeds
            .iter()
            .copied()
            .filter(|s| !live.contains(s))
            .collect();
        if seeds.is_empty() {
            return;
        }
        let alone = live.len() == 1;
        tracing::debug!(
            seeds = seeds.len(),
            alone,
            "rejoining seeds that are not live members"
        );
        let id = self.node.command(now, Command::Join { seeds });
        self.pending.insert(id, Pending::Rejoin { alone });
        self.rejoining = true;
        self.flush(false);
    }

    fn datagram(&mut self, bytes: &[u8], from: SocketAddr) {
        let now = self.clock.now();
        self.node.handle_datagram(now, from, bytes);
        self.flush(false);
    }

    fn report(&mut self, conn: StreamId, report: Report) {
        let ev = match &report {
            Report::Frame { frame, .. } => StreamEvent::Frame(frame),
            Report::Closed => StreamEvent::Closed,
            Report::Failed => StreamEvent::Failed,
            Report::Done => {
                self.conns.remove(&conn);
                if conn.is_inbound() {
                    self.inbound.retain(|&c| c != conn);
                }
                while self.tasks.try_join_next().is_some() {}
                return;
            }
        };
        let now = self.clock.now();
        self.node.handle_stream(now, conn, ev);
        self.flush(false);
    }

    fn accept(&mut self, stream: T::Stream, from: SocketAddr) {
        if self.inbound.len() >= self.opts.max_inbound_streams {
            if let Some(oldest) = self.inbound.pop_front() {
                if let Some(c) = self.conns.remove(&oldest) {
                    c.abort.abort();
                }
                tracing::debug!(%from, "too many inbound connections; dropped the oldest");
            }
        }
        let conn = StreamId::inbound(self.next_inbound);
        self.next_inbound += 1;
        let (writes, rx) = mpsc::unbounded_channel();
        let task = conn::inbound(
            stream,
            conn,
            self.opts.limits,
            Arc::clone(&self.budget),
            rx,
            self.reports_tx.clone(),
        );
        let abort = self.tasks.spawn(task);
        self.conns.insert(conn, Conn { writes, abort });
        self.inbound.push_back(conn);
    }

    fn request(&mut self, req: Request) {
        let now = self.clock.now();
        let (cmd, pending) = match req {
            Request::Join { seeds, reply } => (Command::Join { seeds }, Pending::Join(reply)),
            Request::Leave { reply } => (Command::Leave, Pending::Done(reply)),
            Request::SetMeta { meta, reply } => (Command::SetMeta(meta), Pending::Done(reply)),
            Request::Keyring { change, reply } => {
                let (cmd, did, key) = change.command();
                (cmd, Pending::Keyring { reply, did, key })
            }
            Request::Close { .. } => unreachable!("handled by the loop"),
            #[cfg(any(test, feature = "test-hooks"))]
            Request::Panic => panic!("actor panic injected by a test"),
        };
        let keyring = matches!(pending, Pending::Keyring { .. });
        // Registered before the flush, which may already carry the result.
        let id = self.node.command(now, cmd);
        self.pending.insert(id, pending);
        if keyring {
            // Before the flush answers the caller, so key_ids() is current when the call returns.
            self.shared.key_ids.store(Arc::new(self.node.key_ids()));
        }
        self.flush(false);
    }

    /// Sends what the node wants sent, publishes what changed, and answers finished commands.
    fn flush(&mut self, timer: bool) {
        while let Some(t) = self.node.poll_transmit() {
            self.transmit(t);
        }
        let mut replies = Vec::new();
        let mut events = std::mem::take(&mut self.events);
        while let Some(e) = self.node.poll_event() {
            match e {
                kinship_core::Event::CommandDone { id, result } => {
                    if let Some(p) = self.pending.remove(&id) {
                        replies.push((p, result));
                    }
                }
                other => events.extend(Event::from_core(other)),
            }
        }
        let snapshot = self.shared.snapshot.load();
        // Tombstones expire on timers without an event, so the timers also check the count.
        let stale = !events.is_empty()
            || self.node.local() != snapshot.local()
            || (timer && self.node.all_members().count() != snapshot.all.len());
        if stale {
            self.shared
                .snapshot
                .store(Arc::new(Snapshot::of(&self.node)));
        }
        // The snapshot is current before anyone hears about the change.
        self.shared.hub.publish(&events);
        events.clear();
        self.events = events;
        for (pending, result) in replies {
            self.complete(pending, result);
        }
    }

    fn complete(&mut self, pending: Pending, result: Result<CommandOutput, CommandError>) {
        match pending {
            Pending::Join(reply) => {
                let r = match result {
                    Ok(CommandOutput::Joined { seeds }) => Ok(seeds),
                    Ok(_) => Ok(0),
                    Err(e) => Err(e.into()),
                };
                let _ = reply.send(r);
            }
            Pending::Done(reply) => {
                let _ = reply.send(result.map(drop).map_err(Error::from));
            }
            Pending::Keyring { reply, did, key } => {
                match &result {
                    Ok(_) => tracing::info!(%key, "keyring: {did} key"),
                    Err(e) => tracing::warn!(%key, error = %e, "keyring: change refused"),
                }
                let _ = reply.send(result.map(drop).map_err(Error::from));
            }
            Pending::Rejoin { alone } => {
                self.rejoining = false;
                match result {
                    Ok(_) if alone => tracing::info!("rejoined the cluster through the seeds"),
                    Ok(_) => tracing::debug!("push-pulled with seeds that were not live members"),
                    Err(e) => tracing::debug!(error = %e, "rejoin failed; trying again later"),
                }
            }
        }
    }

    fn transmit(&mut self, t: Transmit) {
        match t {
            Transmit::Datagram { to, payload } => {
                if let Err(e) = self.transport.send_datagram(to, &payload) {
                    tracing::trace!(%to, error = %e, "datagram not sent");
                }
            }
            Transmit::Connect { conn, to } => {
                let (writes, rx) = mpsc::unbounded_channel();
                let task = conn::outbound(
                    Arc::clone(&self.transport),
                    conn,
                    to,
                    self.opts.limits,
                    rx,
                    self.reports_tx.clone(),
                );
                let abort = self.tasks.spawn(task);
                self.conns.insert(conn, Conn { writes, abort });
            }
            Transmit::Stream { conn, frame } => {
                if let Some(c) = self.conns.get(&conn) {
                    let _ = c.writes.send(Write::Bytes(frame));
                }
            }
            // The entry stays until the task reports Done, so an inbound connection still
            // writing its answer counts against max_inbound_streams.
            Transmit::Close { conn } => {
                if let Some(c) = self.conns.get(&conn) {
                    let _ = c.writes.send(Write::Close);
                }
            }
        }
    }

    fn publish_stats(&mut self) {
        let mut stats = self.shared.stats();
        if stats.metrics != *self.node.metrics() {
            stats.metrics.clone_from(self.node.metrics());
        }
        stats.local_health = self.node.local_health();
    }
}

impl<T: Transport> Drop for Actor<T> {
    /// Runs on close, on abort and on a panic alike, so subscribers always see the end, and
    /// learn whether it came from a panic.
    fn drop(&mut self) {
        self.shared.hub.close(std::thread::panicking());
    }
}
