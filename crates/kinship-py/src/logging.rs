//! Where tracing logs go: stderr by default, or a ring buffer that Python drains.
//!
//! The protocol thread only formats a line and pushes it under a short lock, never waiting for
//! the GIL. `kinship.log_to_python()` switches the buffer on and starts a drain in Python that
//! hands each record to the `kinship` logger.

use std::collections::VecDeque;
use std::fmt::Write as _;
use std::io::Write as _;
use std::sync::atomic::{AtomicBool, AtomicU8, Ordering};
use std::sync::{Condvar, Mutex, MutexGuard, PoisonError};
use std::time::Duration;

use pyo3::prelude::*;
use tokio::sync::Notify;
use tracing::field::{Field, Visit};
use tracing::level_filters::LevelFilter;
use tracing::span::{Attributes, Id, Record};
use tracing::subscriber::Interest;
use tracing::{Event, Level, Metadata, Subscriber};

use crate::errors::KError;
use crate::runtime::awaitable;

/// Records held for Python before the oldest are dropped.
const CAPACITY: usize = 4096;

/// Levels as small integers: 0 off, then error, warn, info, debug, trace.
fn level_rank(level: &Level) -> u8 {
    match *level {
        Level::ERROR => 1,
        Level::WARN => 2,
        Level::INFO => 3,
        Level::DEBUG => 4,
        Level::TRACE => 5,
    }
}

/// Python `logging` levels for each rank.
fn python_level(rank: u8) -> u8 {
    match rank {
        1 => 40,
        2 => 30,
        3 => 20,
        4 => 10,
        _ => 5,
    }
}

static TO_PYTHON: AtomicBool = AtomicBool::new(false);
/// The most verbose rank logged.
static MAX_RANK: AtomicU8 = AtomicU8::new(2);

struct Buffer {
    records: VecDeque<(u8, String, String)>,
    dropped: u64,
}

static BUFFER: Mutex<Buffer> = Mutex::new(Buffer {
    records: VecDeque::new(),
    dropped: 0,
});
static READY: Condvar = Condvar::new();
static NOTIFY: Notify = Notify::const_new();

fn buffer() -> MutexGuard<'static, Buffer> {
    BUFFER.lock().unwrap_or_else(PoisonError::into_inner)
}

/// The rank `KINSHIP_LOG` asks for, or warnings.
fn env_rank() -> u8 {
    let level = std::env::var("KINSHIP_LOG").unwrap_or_default();
    match level.trim().to_ascii_lowercase().as_str() {
        "off" => 0,
        "error" => 1,
        "info" => 3,
        "debug" => 4,
        "trace" => 5,
        _ => 2,
    }
}

fn set_rank(rank: u8) {
    MAX_RANK.store(rank, Ordering::Relaxed);
    tracing::callsite::rebuild_interest_cache();
}

/// Formats events and sends them where the current mode says.
struct Router;

impl Router {
    fn enabled_rank(rank: u8) -> bool {
        rank <= MAX_RANK.load(Ordering::Relaxed)
    }
}

#[derive(Default)]
struct Line {
    message: String,
    fields: String,
}

impl Visit for Line {
    fn record_str(&mut self, field: &Field, value: &str) {
        if field.name() == "message" {
            self.message.push_str(value);
        } else {
            let _ = write!(self.fields, " {}={value}", field.name());
        }
    }

    fn record_debug(&mut self, field: &Field, value: &dyn std::fmt::Debug) {
        if field.name() == "message" {
            let _ = write!(self.message, "{value:?}");
        } else {
            let _ = write!(self.fields, " {}={value:?}", field.name());
        }
    }
}

impl Subscriber for Router {
    fn register_callsite(&self, meta: &'static Metadata<'static>) -> Interest {
        if Self::enabled_rank(level_rank(meta.level())) {
            Interest::always()
        } else {
            Interest::never()
        }
    }

    fn enabled(&self, meta: &Metadata<'_>) -> bool {
        Self::enabled_rank(level_rank(meta.level()))
    }

    fn max_level_hint(&self) -> Option<LevelFilter> {
        Some(match MAX_RANK.load(Ordering::Relaxed) {
            0 => LevelFilter::OFF,
            1 => LevelFilter::ERROR,
            2 => LevelFilter::WARN,
            3 => LevelFilter::INFO,
            4 => LevelFilter::DEBUG,
            _ => LevelFilter::TRACE,
        })
    }

    fn new_span(&self, _: &Attributes<'_>) -> Id {
        Id::from_u64(1)
    }

    fn record(&self, _: &Id, _: &Record<'_>) {}

    fn record_follows_from(&self, _: &Id, _: &Id) {}

    fn event(&self, event: &Event<'_>) {
        let meta = event.metadata();
        let rank = level_rank(meta.level());
        let mut line = Line::default();
        event.record(&mut line);
        let message = line.message + &line.fields;
        if TO_PYTHON.load(Ordering::Relaxed) {
            let mut b = buffer();
            if b.records.len() == CAPACITY {
                b.records.pop_front();
                b.dropped += 1;
            }
            b.records
                .push_back((python_level(rank), meta.target().to_owned(), message));
            drop(b);
            READY.notify_all();
            NOTIFY.notify_one();
        } else {
            let _ = writeln!(
                std::io::stderr().lock(),
                "kinship {:>5} {}: {message}",
                meta.level(),
                meta.target()
            );
        }
    }

    fn enter(&self, _: &Id) {}

    fn exit(&self, _: &Id) {}
}

/// Installs the router as this extension's tracing subscriber, logging warnings and errors to
/// stderr, or the level `KINSHIP_LOG` names.
pub fn install() {
    MAX_RANK.store(env_rank(), Ordering::Relaxed);
    let _ = tracing::subscriber::set_global_default(Router);
}

/// A Python logging level as the most verbose rank to forward.
fn rank_of_python(level: i64) -> u8 {
    match level {
        ..=0 => 5,
        1..=5 => 5,
        6..=10 => 4,
        11..=20 => 3,
        21..=30 => 2,
        31..=50 => 1,
        _ => 0,
    }
}

/// Sends logs at `level` and above to the buffer instead of stderr.
#[pyfunction]
pub fn route_to_python(level: i64) {
    TO_PYTHON.store(true, Ordering::Relaxed);
    set_rank(rank_of_python(level));
}

/// Sends logs back to stderr at the `KINSHIP_LOG` level.
#[pyfunction]
pub fn route_to_stderr() {
    TO_PYTHON.store(false, Ordering::Relaxed);
    set_rank(env_rank());
}

/// Takes every buffered record as `(level, target, message)`, and how many were dropped since
/// the last call because the buffer was full.
#[pyfunction]
pub fn drain_logs() -> (Vec<(u8, String, String)>, u64) {
    let mut b = buffer();
    let records = b.records.drain(..).collect();
    (records, std::mem::take(&mut b.dropped))
}

fn pending() -> bool {
    let b = buffer();
    !b.records.is_empty() || b.dropped > 0
}

/// Resolves once a record is buffered.
#[pyfunction]
pub fn wait_logs(py: Python<'_>) -> PyResult<Bound<'_, PyAny>> {
    awaitable(py, async {
        while !pending() {
            NOTIFY.notified().await;
        }
        Ok::<_, KError>(())
    })
}

/// Blocks up to `timeout` seconds, with the GIL released, until a record is buffered; `True`
/// if one is.
#[pyfunction]
pub fn wait_logs_blocking(py: Python<'_>, timeout: f64) -> bool {
    let timeout = Duration::try_from_secs_f64(timeout).unwrap_or(Duration::ZERO);
    py.detach(|| {
        let b = buffer();
        let (b, _) = READY
            .wait_timeout_while(b, timeout, |b| b.records.is_empty() && b.dropped == 0)
            .unwrap_or_else(PoisonError::into_inner);
        !b.records.is_empty() || b.dropped > 0
    })
}
