//! TCP exchanges, one task per connection.
//!
//! Connections are short-lived: the side that opened one writes a frame and waits for one frame
//! back, and the side that accepted it reads one frame, writes the core's answer and closes. A
//! digest push-pull takes one frame more: the side that accepted it answers the digest without
//! closing, and reads the records its answer asked for in a second frame. So an outbound task
//! hands the actor at most one frame, an inbound task at most two, and each then only writes
//! what the actor sends it until the actor closes. Every step is bounded by `tcp_timeout`:
//! connecting, each write, and the wait for each frame, so a peer that trickles bytes cannot
//! hold a connection open. A frame's length is checked against `max_stream_frame` as soon as
//! its prefix arrives, before anything is set aside for it.
//!
//! A frame can only be authenticated once it is complete, so the bytes of inbound frames are
//! held on behalf of peers nobody has verified yet. All inbound connections draw them from one
//! [`Budget`] of twice `max_stream_frame`, and the connections from each source address draw
//! them from that address's share of it, one largest frame by default. A read past its
//! address's share drops the connection. A read past the whole budget evicts connections of the
//! address holding the most, unless that is the reader's own, and waits for them to give their
//! bytes back. A peer without a key can fill its own share, but neither the node's memory nor
//! the room other addresses need.
//!
//! An inbound connection must also start like a frame for this node: its first 8 bytes after
//! the length prefix are checked against the node's [`HeaderCheck`] as soon as they arrive, and
//! a connection that has not sent them within `tcp_header_timeout` is dropped. A second frame
//! is checked the same way, within `tcp_timeout`, since the peer sends it only once it has read
//! the answer to the first.

use std::cmp::Reverse;
use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use arc_swap::ArcSwap;
use kinship_core::{HeaderCheck, StreamId};
use kinship_proto::{DecodeError, FrameReader, PacketKind};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::{Notify, mpsc};
use tokio::time::{Instant, sleep_until, timeout};

use crate::transport::Transport;

/// Bytes read from a socket per call.
const READ_CHUNK: usize = 16 * 1024;

/// What the actor tells a connection task.
#[derive(Debug)]
pub(crate) enum Write {
    /// Bytes to write: one or more frames with their length prefixes.
    Bytes(Vec<u8>),
    /// Finish writing what is queued, then close.
    Close,
}

/// Most frames an inbound connection hands the actor: the request, and after the answer to a
/// digest the records it asked for.
const INBOUND_FRAMES: usize = 2;

/// What a connection task tells the actor.
#[derive(Debug)]
pub(crate) enum Report {
    /// A frame this connection carries, without its length prefix.
    Frame {
        frame: Vec<u8>,
        /// For an inbound connection, its share of the budget, held until the actor is done.
        _held: Option<Held>,
    },
    /// The frame's header is not one for this node, so the connection was dropped before the
    /// rest arrived. Inbound connections only: the core never hears of the connection, only
    /// counts the refusal.
    Refused(DecodeError),
    /// The peer closed before sending a frame. Outbound connections only.
    Closed,
    /// Connect failed or timed out, a read or write failed or timed out, or framing failed,
    /// before a frame arrived. Outbound connections only.
    Failed,
    /// The task has ended; nothing more comes from this connection.
    Done,
}

pub(crate) type Reports = mpsc::UnboundedSender<(StreamId, Report)>;

/// Bytes that inbound connections may hold between them before their frames are handled, and
/// how much of that each source address may hold.
#[derive(Debug)]
pub(crate) struct Budget {
    per_ip: usize,
    holdings: Mutex<Holdings>,
    /// Woken whenever held bytes are given back.
    freed: Notify,
}

#[derive(Debug)]
struct Holdings {
    left: usize,
    /// Bytes of evicted connections that their tasks have not given back yet.
    releasing: usize,
    /// Counts every give-back, so that a reader can tell whether bytes came free since it looked.
    releases: u64,
    /// Bytes held per source address, those of evicted connections not counted.
    by_ip: HashMap<IpAddr, usize>,
    /// Every share, by the number it was opened under.
    shares: HashMap<u64, Share>,
    next_share: u64,
}

/// One inbound frame's part of the budget, the frame an inbound connection is reading or one it
/// handed the actor.
#[derive(Debug)]
struct Share {
    conn: StreamId,
    ip: IpAddr,
    bytes: usize,
    /// The frame is complete and waits for the actor, so it can no longer be taken back.
    complete: bool,
    evicted: bool,
    /// Tells the connection's task that it was evicted.
    kill: Arc<Notify>,
}

/// The outcome of asking the budget for more bytes.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Take {
    Granted,
    /// The connection must go: its address has used its share, no other address holds more
    /// that could make room, or it was evicted itself.
    Refused,
    /// Connections were evicted to make room: ask again once bytes are given back after this
    /// count of give-backs.
    Wait(u64),
}

impl Budget {
    /// `total` bytes in all, at most `per_ip` of them held for one source address.
    pub fn new(total: usize, per_ip: usize) -> Arc<Self> {
        Arc::new(Self {
            per_ip,
            holdings: Mutex::new(Holdings {
                left: total,
                releasing: 0,
                releases: 0,
                by_ip: HashMap::new(),
                shares: HashMap::new(),
                next_share: 0,
            }),
            freed: Notify::new(),
        })
    }

    /// Twice `max_stream_frame`, room for one largest frame while another is being read, with
    /// at most `per_ip` of it for one source address.
    pub fn for_frames(max_stream_frame: usize, per_ip: usize) -> Arc<Self> {
        Self::new(max_stream_frame.saturating_mul(2), per_ip)
    }

    /// Opens a share for the next frame of inbound connection `conn` from `ip`, holding
    /// nothing yet.
    pub fn open(self: &Arc<Self>, conn: StreamId, ip: IpAddr) -> Held {
        let kill = Arc::new(Notify::new());
        let share = Share {
            conn,
            ip,
            bytes: 0,
            complete: false,
            evicted: false,
            kill: Arc::clone(&kill),
        };
        let mut h = self.lock();
        let id = h.next_share;
        h.next_share += 1;
        h.shares.insert(id, share);
        drop(h);
        Held {
            budget: Arc::clone(self),
            share: id,
            kill,
        }
    }

    fn lock(&self) -> MutexGuard<'_, Holdings> {
        self.holdings.lock().unwrap_or_else(PoisonError::into_inner)
    }

    fn releases(&self) -> u64 {
        self.lock().releases
    }

    #[cfg(test)]
    fn left(&self) -> usize {
        self.lock().left
    }

    #[cfg(test)]
    fn held_by(&self, ip: IpAddr) -> usize {
        self.lock().by_ip.get(&ip).copied().unwrap_or(0)
    }
}

impl Holdings {
    fn held_by(&self, ip: IpAddr) -> usize {
        self.by_ip.get(&ip).copied().unwrap_or(0)
    }

    fn unhold(&mut self, ip: IpAddr, n: usize) {
        if let Some(held) = self.by_ip.get_mut(&ip) {
            *held -= n;
            if *held == 0 {
                self.by_ip.remove(&ip);
            }
        }
    }

    /// Evicts, from the address holding the most, its connection still reading that holds the
    /// most, the oldest among equals, if that address is not `ip` and holds more than `ip`
    /// does. False if there is none.
    fn evict_from_richest(&mut self, ip: IpAddr) -> bool {
        let mine = self.held_by(ip);
        let victim = self
            .shares
            .iter()
            .filter(|(_, s)| !s.evicted && !s.complete && s.bytes > 0 && s.ip != ip)
            .map(|(&id, s)| (self.held_by(s.ip), s.bytes, Reverse((s.conn, id))))
            .max()
            .filter(|&(richest, _, _)| richest > mine);
        let Some(share) = victim.and_then(|(_, _, Reverse((_, id)))| self.shares.get_mut(&id))
        else {
            return false;
        };
        share.evicted = true;
        share.kill.notify_one();
        let (victim_ip, bytes) = (share.ip, share.bytes);
        self.unhold(victim_ip, bytes);
        self.releasing += bytes;
        true
    }
}

/// An inbound frame's share of the [`Budget`], given back when dropped.
#[derive(Debug)]
pub(crate) struct Held {
    budget: Arc<Budget>,
    share: u64,
    kill: Arc<Notify>,
}

impl Held {
    /// Opens a share for the connection's next frame, from the same address.
    fn next(&self) -> Option<Held> {
        let (conn, ip) = self
            .budget
            .lock()
            .shares
            .get(&self.share)
            .map(|s| (s.conn, s.ip))?;
        Some(self.budget.open(conn, ip))
    }

    /// Takes `n` more bytes, or says why not.
    fn take(&self, n: usize) -> Take {
        let per_ip = self.budget.per_ip;
        let mut h = self.budget.lock();
        let Some(ip) = h
            .shares
            .get(&self.share)
            .filter(|s| !s.evicted)
            .map(|s| s.ip)
        else {
            return Take::Refused;
        };
        if h.held_by(ip).saturating_add(n) > per_ip {
            return Take::Refused;
        }
        if h.left >= n {
            h.left -= n;
            *h.by_ip.entry(ip).or_default() += n;
            if let Some(share) = h.shares.get_mut(&self.share) {
                share.bytes += n;
            }
            return Take::Granted;
        }
        while h.left + h.releasing < n {
            if !h.evict_from_richest(ip) {
                return Take::Refused;
            }
        }
        Take::Wait(h.releases)
    }

    /// The frame is complete: keeps only `n` of the bytes held, which can no longer be evicted.
    fn keep(&mut self, n: usize) {
        let mut h = self.budget.lock();
        let Some(share) = h.shares.get_mut(&self.share) else {
            return;
        };
        share.complete = true;
        let extra = share.bytes.saturating_sub(n);
        share.bytes -= extra;
        let (ip, evicted) = (share.ip, share.evicted);
        if evicted {
            h.releasing -= extra;
        } else {
            h.unhold(ip, extra);
        }
        h.left += extra;
        h.releases += 1;
        drop(h);
        self.budget.freed.notify_waiters();
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        let mut h = self.budget.lock();
        if let Some(share) = h.shares.remove(&self.share) {
            if share.evicted {
                h.releasing -= share.bytes;
            } else {
                h.unhold(share.ip, share.bytes);
            }
            h.left += share.bytes;
            h.releases += 1;
        }
        drop(h);
        self.budget.freed.notify_waiters();
    }
}

/// Takes `n` bytes for `held`, waiting while evicted connections give theirs back. False if they
/// cannot be had, or if this connection is evicted or runs out of time first.
async fn take(held: &Held, n: usize, deadline: Instant) -> bool {
    loop {
        let seen = match held.take(n) {
            Take::Granted => return true,
            Take::Refused => return false,
            Take::Wait(seen) => seen,
        };
        // Made before looking, so that a give-back after the look still wakes it.
        let freed = held.budget.freed.notified();
        if held.budget.releases() != seen {
            continue;
        }
        tokio::select! {
            () = freed => {}
            () = held.kill.notified() => return false,
            () = sleep_until(deadline) => return false,
        }
    }
}

/// Completes once `kill` is notified, and never without one.
async fn killed(kill: Option<&Notify>) {
    match kill {
        Some(kill) => kill.notified().await,
        None => std::future::pending().await,
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    pub tcp_timeout: Duration,
    pub max_stream_frame: usize,
    /// How long an inbound connection has to send the header of its frame.
    pub header_timeout: Duration,
}

/// What an inbound connection is held to beyond the limits every connection is.
#[derive(Debug)]
pub(crate) struct Inbound {
    /// Its share of the budget, which every byte it reads is taken from.
    pub held: Held,
    /// What its frame must start with: the node's header check, kept current by the actor.
    pub header: Arc<ArcSwap<HeaderCheck>>,
}

/// Opens a connection to `to` for the core and runs its exchange.
pub(crate) async fn outbound<T: Transport>(
    transport: Arc<T>,
    conn: StreamId,
    to: SocketAddr,
    limits: Limits,
    mut writes: mpsc::UnboundedReceiver<Write>,
    reports: Reports,
) {
    let connect = timeout(limits.tcp_timeout, transport.connect(to));
    tokio::pin!(connect);
    // The core queues its frame right after asking for the connection; hold it until connected.
    let mut queued = Vec::new();
    let stream = loop {
        tokio::select! {
            r = &mut connect => match r {
                Ok(Ok(stream)) => break stream,
                Ok(Err(e)) => {
                    tracing::debug!(%to, error = %e, "connect failed");
                    return finish(&reports, conn, Some(Report::Failed));
                }
                Err(_) => {
                    tracing::debug!(%to, "connect timed out");
                    return finish(&reports, conn, Some(Report::Failed));
                }
            },
            w = writes.recv() => match w {
                Some(Write::Bytes(b)) => queued.push(b),
                // The core gave up on this exchange before it connected.
                Some(Write::Close) | None => return finish(&reports, conn, None),
            },
        }
    };
    let outcome = exchange(stream, limits, None, queued, writes, &reports, conn).await;
    finish(&reports, conn, outcome.map(|o| o.report()));
}

/// Runs the exchange on a connection a peer opened. Until its first frame arrives the core does
/// not know the connection exists, so nothing but its frames is reported. The bytes it reads
/// come out of its share of the budget, and each frame must start with a header for this node.
pub(crate) async fn inbound<S>(
    stream: S,
    conn: StreamId,
    limits: Limits,
    inbound: Inbound,
    writes: mpsc::UnboundedReceiver<Write>,
    reports: Reports,
) where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    exchange(
        stream,
        limits,
        Some(inbound),
        Vec::new(),
        writes,
        &reports,
        conn,
    )
    .await;
    finish(&reports, conn, None);
}

fn finish(reports: &Reports, conn: StreamId, report: Option<Report>) {
    if let Some(r) = report {
        let _ = reports.send((conn, r));
    }
    let _ = reports.send((conn, Report::Done));
}

/// How an exchange ended before its first frame arrived.
#[derive(Debug, Clone, Copy)]
enum Outcome {
    Closed,
    Failed,
}

impl Outcome {
    fn report(self) -> Report {
        match self {
            Self::Closed => Report::Closed,
            Self::Failed => Report::Failed,
        }
    }
}

/// Reads one frame, or with `inbound` up to [`INBOUND_FRAMES`], and writes what the actor sends
/// until it says to close. Returns how the connection ended if that happened before the first
/// frame arrived. With `inbound`, every byte read is taken from the share of the budget of the
/// frame being read first, and each frame's header is checked as soon as it arrives.
async fn exchange<S>(
    stream: S,
    limits: Limits,
    inbound: Option<Inbound>,
    queued: Vec<Vec<u8>>,
    mut writes: mpsc::UnboundedReceiver<Write>,
    reports: &Reports,
    conn: StreamId,
) -> Option<Outcome>
where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    let (mut rd, mut wr) = tokio::io::split(stream);
    let t = limits.tcp_timeout;
    for bytes in queued {
        if !matches!(timeout(t, wr.write_all(&bytes)).await, Ok(Ok(()))) {
            return Some(Outcome::Failed);
        }
    }
    let (mut held, header) = match inbound {
        Some(i) => (Some(i.held), Some(i.header)),
        None => (None, None),
    };
    let most = if header.is_some() { INBOUND_FRAMES } else { 1 };
    let mut kill = held.as_ref().map(|h| Arc::clone(&h.kill));
    let mut reader = FrameReader::new(limits.max_stream_frame);
    let mut chunk = vec![0; READ_CHUNK];
    let mut frames = 0;
    // Before a frame: the frame must be complete by then. After the last: the actor must answer
    // by then; it does at once, so this only guards against a stuck exchange.
    let mut deadline = Instant::now() + limits.tcp_timeout;
    // The first inbound frame's header is due sooner; `None` once it has passed the check.
    let mut header_due = header
        .as_ref()
        .map(|_| deadline.min(Instant::now() + limits.header_timeout));
    // Whether the frame being read has passed the header check, which outbound ones skip.
    let mut checked = header.is_none();
    loop {
        tokio::select! {
            w = writes.recv() => match w {
                Some(Write::Bytes(b)) => {
                    if !matches!(timeout(t, wr.write_all(&b)).await, Ok(Ok(()))) {
                        return (frames == 0).then_some(Outcome::Failed);
                    }
                }
                Some(Write::Close) | None => {
                    let _ = timeout(t, wr.shutdown()).await;
                    return None;
                }
            },
            r = rd.read(&mut chunk), if frames < most => match r {
                Ok(0) => {
                    let outcome = if reader.finish().is_ok() { Outcome::Closed } else { Outcome::Failed };
                    return (frames == 0).then_some(outcome);
                }
                Ok(n) => {
                    if let Some(h) = &held {
                        if !take(h, n, deadline).await {
                            tracing::debug!(?conn, "no room in the inbound buffer for this address; dropping connection");
                            return (frames == 0).then_some(Outcome::Failed);
                        }
                    }
                    reader.push(&chunk[..n]);
                    // One read can finish a frame and start the next.
                    loop {
                        if let (Some(check), false) = (&header, checked) {
                            if let Some(head) = reader.head(HeaderCheck::LEN) {
                                if let Err(e) = check.load().check(PacketKind::Stream, head) {
                                    tracing::debug!(?conn, error = %e, "not a frame for this node; dropping connection");
                                    let _ = reports.send((conn, Report::Refused(e)));
                                    return (frames == 0).then_some(Outcome::Failed);
                                }
                                checked = true;
                                header_due = None;
                            }
                        }
                        match reader.next_frame() {
                            Ok(Some(_)) if !checked => {
                                tracing::debug!(?conn, "frame too short to hold a header; dropping connection");
                                let _ = reports.send((conn, Report::Refused(DecodeError::Truncated)));
                                return (frames == 0).then_some(Outcome::Failed);
                            }
                            Ok(Some(frame)) => {
                                frames += 1;
                                deadline = Instant::now() + limits.tcp_timeout;
                                // The next frame, if one may follow, is held against a share of
                                // its own, from the bytes already read past this one.
                                let next = held.as_ref().filter(|_| frames < most).and_then(Held::next);
                                let mut done = held.take();
                                if let Some(h) = &mut done {
                                    h.keep(frame.len());
                                }
                                let _ = reports.send((conn, Report::Frame { frame, _held: done }));
                                if frames == most {
                                    // The read side is done; release its buffers before waiting,
                                    // and hold only the frames against the budget until the
                                    // actor is done with them.
                                    chunk = Vec::new();
                                    reader = FrameReader::new(0);
                                    break;
                                }
                                if let Some(h) = &next {
                                    if !take(h, reader.buffered(), deadline).await {
                                        tracing::debug!(?conn, "no room in the inbound buffer for this address; dropping connection");
                                        return None;
                                    }
                                }
                                kill = next.as_ref().map(|h| Arc::clone(&h.kill));
                                held = next;
                                checked = header.is_none();
                            }
                            Ok(None) => break,
                            Err(e) => {
                                tracing::debug!(?conn, error = %e, "bad stream frame");
                                return (frames == 0).then_some(Outcome::Failed);
                            }
                        }
                    }
                }
                Err(_) => return (frames == 0).then_some(Outcome::Failed),
            },
            () = killed(kill.as_deref()), if frames < most => {
                tracing::debug!(?conn, "evicted to make room for another address's frame");
                return (frames == 0).then_some(Outcome::Failed);
            }
            () = sleep_until(header_due.unwrap_or(deadline)), if header_due.is_some() => {
                tracing::debug!(?conn, "no frame header in time; dropping connection");
                return Some(Outcome::Failed);
            }
            () = sleep_until(deadline) => {
                tracing::debug!(?conn, "stream timed out");
                return (frames == 0).then_some(Outcome::Failed);
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    const LIMITS: Limits = Limits {
        tcp_timeout: Duration::from_millis(200),
        max_stream_frame: 64,
        header_timeout: Duration::from_millis(100),
    };

    fn frame(body: &[u8]) -> Vec<u8> {
        let mut v = (body.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(body);
        v
    }

    fn ip(i: u8) -> IpAddr {
        IpAddr::from([10, 0, 0, i])
    }

    /// The plaintext codec of cluster "t", with the frame size of [`LIMITS`].
    fn codec() -> kinship_proto::Codec {
        let limits = kinship_proto::Limits {
            max_stream_frame: LIMITS.max_stream_frame,
            ..kinship_proto::Limits::default()
        };
        kinship_proto::Codec::insecure_plaintext(b"t", limits).unwrap()
    }

    /// A stream packet of `len` bytes for cluster "t": a real header, then filler.
    fn packet(len: usize) -> Vec<u8> {
        let mut p = Vec::new();
        let ack = kinship_proto::Message::Ack { seq: 1 };
        codec()
            .seal(PacketKind::Stream, &[ack], &[0; 24], &mut p)
            .unwrap();
        p.resize(len, 0x55);
        p
    }

    /// What inbound connection `conn` from address `from` is held to, in cluster "t".
    fn inbound_of(budget: &Arc<Budget>, conn: StreamId, from: u8) -> Inbound {
        Inbound {
            held: budget.open(conn, ip(from)),
            header: Arc::new(ArcSwap::from_pointee(codec().header_check())),
        }
    }

    async fn reports_of(rx: &mut mpsc::UnboundedReceiver<(StreamId, Report)>) -> Vec<&'static str> {
        let mut out = Vec::new();
        while let Some((_, r)) = rx.recv().await {
            out.push(match r {
                Report::Frame { .. } => "frame",
                Report::Refused(_) => "refused",
                Report::Closed => "closed",
                Report::Failed => "failed",
                Report::Done => "done",
            });
            if out.last() == Some(&"done") {
                break;
            }
        }
        out
    }

    #[tokio::test]
    async fn inbound_hands_over_at_most_two_frames_then_writes_the_answer_and_closes() {
        let (mut peer, ours) = duplex(1024);
        let (wtx, wrx) = mpsc::unbounded_channel();
        let (rtx, mut rrx) = mpsc::unbounded_channel();
        let budget = Budget::for_frames(LIMITS.max_stream_frame, 68);
        let conn = StreamId::inbound(0);
        let task = tokio::spawn(inbound(
            ours,
            conn,
            LIMITS,
            inbound_of(&budget, conn, 1),
            wrx,
            rtx,
        ));
        // Three frames in one write: the third is never read.
        let mut three = frame(&packet(20));
        three.extend(frame(&packet(24)));
        three.extend(frame(&packet(12)));
        peer.write_all(&three).await.unwrap();
        let (_, first) = rrx.recv().await.unwrap();
        assert!(matches!(&first, Report::Frame { frame, _held: Some(_) } if *frame == packet(20)));
        let (_, second) = rrx.recv().await.unwrap();
        assert!(matches!(&second, Report::Frame { frame, _held: Some(_) } if *frame == packet(24)));
        assert_eq!(budget.left(), 128 - 20 - 24, "only the frames stay held");
        drop((first, second));
        assert_eq!(budget.left(), 128);
        wtx.send(Write::Bytes(frame(b"ok"))).unwrap();
        wtx.send(Write::Close).unwrap();
        let mut answer = Vec::new();
        peer.read_to_end(&mut answer).await.unwrap();
        assert_eq!(answer, frame(b"ok"));
        assert_eq!(reports_of(&mut rrx).await, ["done"]);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn an_inbound_second_frame_follows_the_answer_and_is_checked_too() {
        let (mut peer, ours) = duplex(1024);
        let (wtx, wrx) = mpsc::unbounded_channel();
        let (rtx, mut rrx) = mpsc::unbounded_channel();
        let budget = Budget::for_frames(LIMITS.max_stream_frame, 68);
        let conn = StreamId::inbound(0);
        let task = tokio::spawn(inbound(
            ours,
            conn,
            LIMITS,
            inbound_of(&budget, conn, 1),
            wrx,
            rtx,
        ));
        // The digest, then its answer, then the records the answer asked for, which arrive
        // later than the first frame's header was due.
        peer.write_all(&frame(&packet(20))).await.unwrap();
        let (_, first) = rrx.recv().await.unwrap();
        assert!(matches!(first, Report::Frame { .. }));
        wtx.send(Write::Bytes(frame(b"answer"))).unwrap();
        let mut answer = vec![0; frame(b"answer").len()];
        peer.read_exact(&mut answer).await.unwrap();
        tokio::time::sleep(LIMITS.header_timeout + Duration::from_millis(20)).await;
        peer.write_all(&frame(&packet(30))).await.unwrap();
        let (_, second) = rrx.recv().await.unwrap();
        assert!(matches!(&second, Report::Frame { frame, .. } if *frame == packet(30)));
        wtx.send(Write::Close).unwrap();
        drop((first, second));
        assert_eq!(reports_of(&mut rrx).await, ["done"]);
        task.await.unwrap();

        // A second frame that is not one for this node is refused.
        let (mut peer, ours) = duplex(1024);
        let (_wtx, wrx) = mpsc::unbounded_channel();
        let (rtx, mut rrx) = mpsc::unbounded_channel();
        let task = tokio::spawn(inbound(
            ours,
            conn,
            LIMITS,
            inbound_of(&budget, conn, 1),
            wrx,
            rtx,
        ));
        let mut bytes = frame(&packet(20));
        bytes.extend(frame(&[0x55; 20]));
        peer.write_all(&bytes).await.unwrap();
        assert_eq!(reports_of(&mut rrx).await, ["frame", "refused", "done"]);
        task.await.unwrap();
        assert_eq!(budget.left(), 128);
    }

    #[tokio::test]
    async fn oversized_frames_fail_before_their_body_arrives() {
        let (mut peer, ours) = duplex(1024);
        let (_wtx, wrx) = mpsc::unbounded_channel();
        let (rtx, mut rrx) = mpsc::unbounded_channel();
        let conn = StreamId::outbound(0);
        let task = tokio::spawn(async move {
            let outcome = exchange(ours, LIMITS, None, Vec::new(), wrx, &rtx, conn).await;
            finish(&rtx, conn, outcome.map(Outcome::report));
        });
        peer.write_all(&65u32.to_be_bytes()).await.unwrap();
        assert_eq!(reports_of(&mut rrx).await, ["failed", "done"]);
        task.await.unwrap();
    }

    #[tokio::test]
    async fn a_silent_peer_times_out() {
        let (_peer, ours) = duplex(1024);
        let (_wtx, wrx) = mpsc::unbounded_channel();
        let (rtx, mut rrx) = mpsc::unbounded_channel();
        let conn = StreamId::outbound(1);
        let started = Instant::now();
        tokio::spawn(async move {
            let outcome = exchange(ours, LIMITS, None, Vec::new(), wrx, &rtx, conn).await;
            finish(&rtx, conn, outcome.map(Outcome::report));
        });
        assert_eq!(reports_of(&mut rrx).await, ["failed", "done"]);
        assert!(started.elapsed() >= LIMITS.tcp_timeout);
    }

    #[tokio::test]
    async fn a_trickling_peer_times_out_too() {
        let (mut peer, ours) = duplex(1024);
        let (_wtx, wrx) = mpsc::unbounded_channel();
        let (rtx, mut rrx) = mpsc::unbounded_channel();
        let conn = StreamId::outbound(2);
        tokio::spawn(async move {
            let outcome = exchange(ours, LIMITS, None, Vec::new(), wrx, &rtx, conn).await;
            finish(&rtx, conn, outcome.map(Outcome::report));
        });
        let trickle = tokio::spawn(async move {
            for b in frame(&[7; 32]) {
                if peer.write_all(&[b]).await.is_err() {
                    break;
                }
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        });
        assert_eq!(reports_of(&mut rrx).await, ["failed", "done"]);
        trickle.abort();
    }

    #[tokio::test]
    async fn an_address_holds_at_most_its_share_and_room_comes_from_the_address_holding_the_most() {
        let budget = Budget::new(100, 80);
        let c = StreamId::inbound;
        let a1 = budget.open(c(1), ip(1));
        let a2 = budget.open(c(2), ip(1));
        let b1 = budget.open(c(3), ip(2));
        assert_eq!(a1.take(50), Take::Granted);
        assert_eq!(a2.take(31), Take::Refused, "past address 1's share of 80");
        assert_eq!(a2.take(10), Take::Granted);
        assert_eq!(b1.take(30), Take::Granted);
        assert_eq!(budget.left(), 10);
        // Address 1 holds the most, so it takes no room from address 2.
        assert_eq!(a2.take(15), Take::Refused);
        assert_eq!(budget.held_by(ip(2)), 30);
        // Address 2 takes room from address 1, from the connection of 1 that holds the most,
        // and waits until that connection gives its bytes back.
        let Take::Wait(seen) = b1.take(15) else {
            panic!("no eviction");
        };
        assert_eq!(
            budget.held_by(ip(1)),
            10,
            "a1's 50 are no longer address 1's"
        );
        let told = tokio::time::timeout(Duration::ZERO, a1.kill.notified()).await;
        assert!(told.is_ok(), "a1's task is told to stop");
        assert_eq!(
            a1.take(1),
            Take::Refused,
            "an evicted connection takes no more"
        );
        assert_eq!(budget.releases(), seen);
        drop(a1);
        assert_ne!(budget.releases(), seen);
        assert_eq!(b1.take(15), Take::Granted);
        assert_eq!(budget.left(), 100 - 10 - 45);
        drop((a2, b1));
        assert_eq!(budget.left(), 100);
    }

    #[tokio::test]
    async fn an_inbound_read_past_its_address_share_drops_the_connection() {
        let budget = Budget::for_frames(LIMITS.max_stream_frame, 68);
        let other = budget.open(StreamId::inbound(9), ip(1));
        assert_eq!(other.take(30), Take::Granted);
        let (mut peer, ours) = duplex(1024);
        let (_wtx, wrx) = mpsc::unbounded_channel();
        let (rtx, mut rrx) = mpsc::unbounded_channel();
        let conn = StreamId::inbound(1);
        let held = inbound_of(&budget, conn, 1);
        let task = tokio::spawn(inbound(ours, conn, LIMITS, held, wrx, rtx));
        // 44 bytes more would leave address 1 holding 74, past its 68.
        peer.write_all(&frame(&packet(40))).await.unwrap();
        assert_eq!(reports_of(&mut rrx).await, ["done"]);
        task.await.unwrap();
        assert_eq!(
            budget.left(),
            128 - 30,
            "the dropped connection gave its share back"
        );
        drop(other);
        assert_eq!(budget.left(), 128);
    }

    #[tokio::test]
    async fn a_read_past_the_budget_evicts_a_partial_frame_of_the_address_holding_the_most() {
        let budget = Budget::for_frames(LIMITS.max_stream_frame, 68);
        let (rtx, mut rrx) = mpsc::unbounded_channel();
        let mut peers = Vec::new();
        for (i, from) in [(1, 2), (2, 3), (3, 4)] {
            let (peer, ours) = duplex(1024);
            let (wtx, wrx) = mpsc::unbounded_channel();
            let conn = StreamId::inbound(i);
            let held = inbound_of(&budget, conn, from);
            tokio::spawn(inbound(ours, conn, LIMITS, held, wrx, rtx.clone()));
            peers.push((peer, wtx));
        }
        // Addresses 2 and 3 send 44 bytes of a 68-byte frame each, leaving 40 of the 128.
        let partial = frame(&packet(64))[..44].to_vec();
        for (peer, _) in &mut peers[..2] {
            peer.write_all(&partial).await.unwrap();
        }
        while budget.left() > 40 {
            tokio::time::sleep(Duration::from_millis(1)).await;
        }
        // Address 4's whole 64-byte frame does not fit: one of them makes room for it.
        peers[2].0.write_all(&frame(&packet(60))).await.unwrap();
        let (conn, report) = loop {
            let (conn, r) = rrx.recv().await.unwrap();
            if matches!(r, Report::Frame { .. }) {
                break (conn, r);
            }
        };
        assert_eq!(conn, StreamId::inbound(3));
        assert!(matches!(&report, Report::Frame { frame, .. } if *frame == packet(60)));
        assert_eq!(budget.held_by(ip(2)) + budget.held_by(ip(3)), 44);
        assert_eq!(budget.left(), 128 - 44 - 60);
        drop(report);
        assert_eq!(budget.left(), 128 - 44);
    }

    #[tokio::test]
    async fn a_connection_without_a_header_for_this_node_is_dropped_early() {
        let limits = Limits {
            tcp_timeout: Duration::from_secs(10),
            ..LIMITS
        };
        let budget = Budget::for_frames(limits.max_stream_frame, 68);
        let start = |i: u64| {
            let (peer, ours) = duplex(1024);
            let (wtx, wrx) = mpsc::unbounded_channel();
            let (rtx, rrx) = mpsc::unbounded_channel();
            let conn = StreamId::inbound(i);
            let held = inbound_of(&budget, conn, 1);
            tokio::spawn(inbound(ours, conn, limits, held, wrx, rtx));
            (peer, wtx, rrx)
        };
        // Anything but a header for this node, as soon as its 8 bytes are in.
        let (mut peer, _wtx, mut rrx) = start(1);
        let mut foreign = packet(40);
        foreign[4] ^= 1;
        peer.write_all(&frame(&foreign)[..12]).await.unwrap();
        assert_eq!(reports_of(&mut rrx).await, ["refused", "done"]);
        // A frame too short to hold one.
        let (mut peer, _wtx, mut rrx) = start(2);
        peer.write_all(&frame(&packet(40)[..6])).await.unwrap();
        assert_eq!(reports_of(&mut rrx).await, ["refused", "done"]);
        // Silence, until the header is due rather than the frame.
        let (_peer, _wtx, mut rrx) = start(3);
        let started = Instant::now();
        assert_eq!(reports_of(&mut rrx).await, ["done"]);
        let took = started.elapsed();
        assert!(took >= limits.header_timeout, "{took:?}");
        assert!(took < limits.tcp_timeout / 2, "{took:?}");
        assert_eq!(budget.left(), 128);
    }

    #[tokio::test]
    async fn an_early_close_is_reported_as_closed() {
        let (peer, ours) = duplex(1024);
        let (_wtx, wrx) = mpsc::unbounded_channel();
        let (rtx, mut rrx) = mpsc::unbounded_channel();
        let conn = StreamId::outbound(3);
        drop(peer);
        let outcome = exchange(ours, LIMITS, None, Vec::new(), wrx, &rtx, conn).await;
        finish(&rtx, conn, outcome.map(Outcome::report));
        assert_eq!(reports_of(&mut rrx).await, ["closed", "done"]);
    }
}
