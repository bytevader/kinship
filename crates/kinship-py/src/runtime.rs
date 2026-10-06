//! The kinship-owned tokio runtime, and the bridge that resolves asyncio futures on it.
//!
//! One runtime per process runs every node's actor on threads named `kinship-io`, so a blocked
//! asyncio loop or a long GIL hold never delays the protocol. It is built on first use with the
//! first config's `runtime_threads` workers. A forked child cannot use it, because fork copies
//! no threads: every handle records the PID that created it and refuses to run anywhere else,
//! and the child builds a runtime of its own if it starts clusters.

use std::cell::OnceCell;
use std::future::Future;
use std::pin::Pin;
use std::sync::mpsc;
use std::sync::{Mutex, PoisonError};
use std::time::Duration;

use pyo3::prelude::*;
use pyo3_async_runtimes::TaskLocals;
use pyo3_async_runtimes::generic::{self, ContextExt, Runtime as GenericRuntime};
use tokio::runtime::{Builder, Runtime};
use tokio::task::JoinHandle;

use crate::errors::{KError, Reply};

/// The runtime of this process, and the process that built it.
struct Current {
    runtime: &'static Runtime,
    pid: u32,
    threads: usize,
}

static CURRENT: Mutex<Option<Current>> = Mutex::new(None);

pub const DEFAULT_THREADS: usize = 1;

/// The runtime of this process, built with `threads` workers if it does not exist yet.
///
/// A runtime inherited across fork has no threads left; it is leaked, never dropped, because
/// dropping it would wait for threads that do not exist.
pub fn runtime(threads: Option<usize>) -> Result<&'static Runtime, KError> {
    let pid = std::process::id();
    let mut current = CURRENT.lock().unwrap_or_else(PoisonError::into_inner);
    if let Some(c) = current.as_ref().filter(|c| c.pid == pid) {
        if let Some(n) = threads.filter(|&n| n != c.threads) {
            tracing::warn!(
                requested = n,
                running = c.threads,
                "runtime_threads is set once per process; keeping the running value"
            );
        }
        return Ok(c.runtime);
    }
    let threads = threads.unwrap_or(DEFAULT_THREADS);
    let rt = Builder::new_multi_thread()
        .worker_threads(threads)
        .thread_name("kinship-io")
        .enable_all()
        .build()
        .map_err(|e| KError::Net(e.into()))?;
    let runtime: &'static Runtime = Box::leak(Box::new(rt));
    *current = Some(Current {
        runtime,
        pid,
        threads,
    });
    Ok(runtime)
}

/// The PID of the running process, for handles to check against the one that made them.
pub fn pid() -> u32 {
    std::process::id()
}

/// Fails with [`KError::Forked`] in any process but `owner`.
pub fn check_pid(owner: u32) -> Result<(), KError> {
    if owner == pid() {
        Ok(())
    } else {
        Err(KError::Forked)
    }
}

/// The kinship runtime as pyo3-async-runtimes sees it, so `future_into_py` resolves on it.
pub struct KinshipRuntime;

tokio::task_local! {
    static TASK_LOCALS: OnceCell<TaskLocals>;
}

fn current_runtime() -> &'static Runtime {
    // Every caller has resolved the runtime already, so building one here never happens on a
    // path that could have reported an error instead.
    runtime(None).expect("the kinship runtime could not be built")
}

impl GenericRuntime for KinshipRuntime {
    type JoinError = tokio::task::JoinError;
    type JoinHandle = JoinHandle<()>;

    fn spawn<F>(fut: F) -> Self::JoinHandle
    where
        F: Future<Output = ()> + Send + 'static,
    {
        current_runtime().spawn(fut)
    }

    fn spawn_blocking<F>(f: F) -> Self::JoinHandle
    where
        F: FnOnce() + Send + 'static,
    {
        current_runtime().spawn_blocking(f)
    }
}

impl ContextExt for KinshipRuntime {
    fn scope<F, R>(locals: TaskLocals, fut: F) -> Pin<Box<dyn Future<Output = R> + Send>>
    where
        F: Future<Output = R> + Send + 'static,
    {
        let cell = OnceCell::new();
        let _ = cell.set(locals);
        Box::pin(TASK_LOCALS.scope(cell, fut))
    }

    fn get_task_locals() -> Option<TaskLocals> {
        TASK_LOCALS
            .try_with(|c| c.get().cloned())
            .unwrap_or_default()
    }
}

/// Runs `fut` on the kinship runtime and returns an asyncio awaitable for its result. The
/// result becomes a Python object, or an exception, on a blocking-pool thread, never on a
/// thread that runs a node.
pub fn awaitable<'py, F, T>(py: Python<'py>, fut: F) -> PyResult<Bound<'py, PyAny>>
where
    F: Future<Output = Result<T, KError>> + Send + 'static,
    T: for<'a> IntoPyObject<'a> + Send + 'static,
{
    runtime(None).map_err(|e| e.into_pyerr(py))?;
    generic::future_into_py::<KinshipRuntime, _, _>(py, async move { Ok(Reply(fut.await)) })
}

/// How long a blocked caller sleeps between checks for Ctrl-C.
const SIGNAL_CHECK: Duration = Duration::from_millis(100);

/// Runs `fut` on the kinship runtime and blocks the calling thread until it finishes, or
/// until `timeout` passes, with the GIL released. Ctrl-C on the main thread cancels it.
pub fn block_on<F, T>(py: Python<'_>, timeout: Option<Duration>, fut: F) -> Result<T, KError>
where
    F: Future<Output = Result<T, KError>> + Send + 'static,
    T: Send + 'static,
{
    let rt = runtime(None)?;
    let (tx, rx) = mpsc::sync_channel(1);
    let task = rt.spawn(async move {
        let result = match timeout {
            Some(t) => tokio::time::timeout(t, fut)
                .await
                .unwrap_or(Err(KError::Timeout)),
            None => fut.await,
        };
        let _ = tx.send(result);
    });
    let mut rx = Some(rx);
    loop {
        // The receiver is not `Sync`, so it moves into the detached closure and back.
        let (received, back) = py.detach(move || {
            let rx = rx
                .take()
                .expect("the receiver is put back after every wait");
            (rx.recv_timeout(SIGNAL_CHECK), rx)
        });
        rx = Some(back);
        match received {
            Ok(result) => return result,
            Err(mpsc::RecvTimeoutError::Timeout) => {
                if let Err(e) = py.check_signals() {
                    task.abort();
                    return Err(KError::Py(e));
                }
            }
            Err(mpsc::RecvTimeoutError::Disconnected) => return Err(KError::Closed),
        }
    }
}

/// A float of seconds as a [`Duration`], for `timeout=` arguments.
pub fn seconds(field: &'static str, secs: f64) -> Result<Duration, KError> {
    Duration::try_from_secs_f64(secs)
        .map_err(|_| KError::BadArgument(field, "must be a non-negative number of seconds"))
}
