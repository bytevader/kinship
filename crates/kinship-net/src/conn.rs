//! TCP exchanges, one task per connection.
//!
//! Connections are short-lived: the side that opened one writes a frame and waits for one frame
//! back, and the side that accepted it reads one frame, writes the core's answer and closes. A
//! task therefore hands the actor at most one frame and then only writes what the actor sends
//! it. Every step is bounded by `tcp_timeout`: connecting, each write, and the wait for the
//! frame, so a peer that trickles bytes cannot hold a connection open. The frame's length is
//! checked against `max_stream_frame` as soon as its prefix arrives, before anything is set
//! aside for it.
//!
//! A frame can only be authenticated once it is complete, so the bytes of inbound frames are
//! held on behalf of peers nobody has verified yet. All inbound connections draw them from one
//! [`Budget`] of twice `max_stream_frame`, and a connection whose next read does not fit is
//! dropped: a peer without a key can fill the budget, but not the node's memory.

use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use kinship_core::StreamId;
use kinship_proto::FrameReader;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::sync::mpsc;
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

/// What a connection task tells the actor.
#[derive(Debug)]
pub(crate) enum Report {
    /// The one frame this connection carries, without its length prefix.
    Frame {
        frame: Vec<u8>,
        /// For an inbound connection, its share of the budget, held until the actor is done.
        _held: Option<Held>,
    },
    /// The peer closed before sending a frame. Outbound connections only.
    Closed,
    /// Connect failed or timed out, a read or write failed or timed out, or framing failed,
    /// before a frame arrived. Outbound connections only.
    Failed,
    /// The task has ended; nothing more comes from this connection.
    Done,
}

pub(crate) type Reports = mpsc::UnboundedSender<(StreamId, Report)>;

/// Bytes that inbound connections may hold between them before their frames are handled.
#[derive(Debug)]
pub(crate) struct Budget {
    left: AtomicUsize,
}

impl Budget {
    /// Twice `max_stream_frame`: room for one largest frame while another is being read.
    pub fn for_frames(max_stream_frame: usize) -> Arc<Self> {
        Arc::new(Self {
            left: AtomicUsize::new(max_stream_frame.saturating_mul(2)),
        })
    }

    /// Takes `n` more bytes for `held`, or returns false and takes nothing if they do not fit.
    fn take(self: &Arc<Self>, held: &mut Held, n: usize) -> bool {
        let fits = self
            .left
            .fetch_update(Ordering::AcqRel, Ordering::Acquire, |left| {
                left.checked_sub(n)
            })
            .is_ok();
        if fits {
            held.bytes += n;
        }
        fits
    }

    #[cfg(test)]
    fn left(&self) -> usize {
        self.left.load(Ordering::Acquire)
    }
}

/// A connection's share of the [`Budget`], given back when dropped.
#[derive(Debug)]
pub(crate) struct Held {
    budget: Arc<Budget>,
    bytes: usize,
}

impl Held {
    fn new(budget: Arc<Budget>) -> Self {
        Self { budget, bytes: 0 }
    }

    /// Keeps only `n` of the bytes held.
    fn keep(&mut self, n: usize) {
        let extra = self.bytes.saturating_sub(n);
        self.budget.left.fetch_add(extra, Ordering::AcqRel);
        self.bytes -= extra;
    }
}

impl Drop for Held {
    fn drop(&mut self) {
        self.budget.left.fetch_add(self.bytes, Ordering::AcqRel);
    }
}

#[derive(Debug, Clone, Copy)]
pub(crate) struct Limits {
    pub tcp_timeout: Duration,
    pub max_stream_frame: usize,
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
/// not know the connection exists, so nothing but that frame is reported. The bytes it reads
/// come out of `budget`.
pub(crate) async fn inbound<S>(
    stream: S,
    conn: StreamId,
    limits: Limits,
    budget: Arc<Budget>,
    writes: mpsc::UnboundedReceiver<Write>,
    reports: Reports,
) where
    S: AsyncRead + AsyncWrite + Send + Unpin,
{
    let held = Held::new(budget);
    exchange(
        stream,
        limits,
        Some(held),
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

/// How an exchange ended before its frame arrived.
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

/// Reads one frame and writes what the actor sends until it says to close. Returns how the
/// connection ended if that happened before the frame arrived. With `held`, every byte read is
/// taken from its budget first.
async fn exchange<S>(
    stream: S,
    limits: Limits,
    mut held: Option<Held>,
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
    let mut reader = FrameReader::new(limits.max_stream_frame);
    let mut chunk = vec![0; READ_CHUNK];
    let mut got_frame = false;
    // Before the frame: the frame must be complete by then. After it: the actor must answer by
    // then; it does at once, so this only guards against a stuck exchange.
    let mut deadline = Instant::now() + limits.tcp_timeout;
    loop {
        tokio::select! {
            w = writes.recv() => match w {
                Some(Write::Bytes(b)) => {
                    if !matches!(timeout(t, wr.write_all(&b)).await, Ok(Ok(()))) {
                        return (!got_frame).then_some(Outcome::Failed);
                    }
                }
                Some(Write::Close) | None => {
                    let _ = timeout(t, wr.shutdown()).await;
                    return None;
                }
            },
            r = rd.read(&mut chunk), if !got_frame => match r {
                Ok(0) => {
                    let outcome = if reader.finish().is_ok() { Outcome::Closed } else { Outcome::Failed };
                    return Some(outcome);
                }
                Ok(n) => {
                    if let Some(h) = &mut held {
                        if !Arc::clone(&h.budget).take(h, n) {
                            tracing::debug!(?conn, "inbound buffer budget spent; dropping connection");
                            return Some(Outcome::Failed);
                        }
                    }
                    reader.push(&chunk[..n]);
                    match reader.next_frame() {
                        Ok(Some(frame)) => {
                            got_frame = true;
                            deadline = Instant::now() + limits.tcp_timeout;
                            // The read side is done; release its buffers before waiting, and
                            // hold only the frame against the budget until the actor is done.
                            chunk = Vec::new();
                            reader = FrameReader::new(0);
                            let mut held = held.take();
                            if let Some(h) = &mut held {
                                h.keep(frame.len());
                            }
                            let _ = reports.send((conn, Report::Frame { frame, _held: held }));
                        }
                        Ok(None) => {}
                        Err(e) => {
                            tracing::debug!(?conn, error = %e, "bad stream frame");
                            return Some(Outcome::Failed);
                        }
                    }
                }
                Err(_) => return Some(Outcome::Failed),
            },
            () = sleep_until(deadline) => {
                tracing::debug!(?conn, "stream timed out");
                return (!got_frame).then_some(Outcome::Failed);
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
    };

    fn frame(body: &[u8]) -> Vec<u8> {
        let mut v = (body.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(body);
        v
    }

    async fn reports_of(rx: &mut mpsc::UnboundedReceiver<(StreamId, Report)>) -> Vec<&'static str> {
        let mut out = Vec::new();
        while let Some((_, r)) = rx.recv().await {
            out.push(match r {
                Report::Frame { .. } => "frame",
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
    async fn inbound_hands_over_one_frame_then_writes_the_answer_and_closes() {
        let (mut peer, ours) = duplex(1024);
        let (wtx, wrx) = mpsc::unbounded_channel();
        let (rtx, mut rrx) = mpsc::unbounded_channel();
        let budget = Budget::for_frames(LIMITS.max_stream_frame);
        let task = tokio::spawn(inbound(
            ours,
            StreamId::inbound(0),
            LIMITS,
            Arc::clone(&budget),
            wrx,
            rtx,
        ));
        let mut two = frame(b"abcd");
        two.extend(frame(b"efgh"));
        peer.write_all(&two).await.unwrap();
        let (_, first) = rrx.recv().await.unwrap();
        assert!(matches!(&first, Report::Frame { frame, _held: Some(_) } if frame == b"abcd"));
        assert_eq!(budget.left(), 128 - 4, "only the frame stays held");
        drop(first);
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
    async fn an_inbound_read_past_the_budget_drops_the_connection() {
        let budget = Budget::for_frames(LIMITS.max_stream_frame);
        let mut other = Held::new(Arc::clone(&budget));
        assert!(budget.take(&mut other, 100));
        let (mut peer, ours) = duplex(1024);
        let (_wtx, wrx) = mpsc::unbounded_channel();
        let (rtx, mut rrx) = mpsc::unbounded_channel();
        let conn = StreamId::inbound(1);
        let task = tokio::spawn(inbound(ours, conn, LIMITS, Arc::clone(&budget), wrx, rtx));
        peer.write_all(&frame(&[7; 40])).await.unwrap();
        assert_eq!(reports_of(&mut rrx).await, ["done"]);
        task.await.unwrap();
        assert_eq!(
            budget.left(),
            28,
            "the dropped connection gave its share back"
        );
        drop(other);
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
