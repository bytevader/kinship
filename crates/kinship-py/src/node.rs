//! `_kinship.Node`: the handle to a running node, which the Python `Cluster` classes wrap.
//!
//! Every method comes in an async form, which returns an asyncio awaitable, and a blocking form
//! with a `_blocking` suffix, which waits with the GIL released. Reads never wait on the node.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use kinship_net::{Error, Event, Events, Key, Member, Memberlist, State, TokioTransport};
use kinship_proto::tags::{Tags, TagsError, encode_tags};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use pyo3::types::{PyDict, PyString};

use crate::config::{self, Config};
use crate::errors::{KError, finish};
use crate::runtime::{self, awaitable, block_on, check_pid, seconds};

/// A member as `(name, addr, state, incarnation, meta)`, with `state` 0 to 3 for alive,
/// suspect, dead and left, and `meta` as `(key, value)` pairs.
type RawMember = (String, String, u8, u32, Vec<(String, String)>);

/// An event as `(kind, member, previous_meta, other_addr, count)`.
type RawEvent = (
    &'static str,
    Option<RawMember>,
    Option<Vec<(String, String)>>,
    Option<String>,
    Option<u64>,
);

/// Metadata as tag pairs. Raw metadata that is not a tag list, from a Rust node that set
/// bytes of its own, reads as no tags.
fn meta_pairs(meta: &[u8]) -> Vec<(String, String)> {
    Tags::parse(meta)
        .map(|t| {
            t.iter()
                .map(|(k, v)| (k.to_owned(), v.to_owned()))
                .collect()
        })
        .unwrap_or_default()
}

fn raw_member(m: Member) -> RawMember {
    let state = match m.state {
        State::Alive => 0,
        State::Suspect => 1,
        State::Dead => 2,
        State::Left => 3,
    };
    (
        m.name,
        m.addr.to_string(),
        state,
        m.incarnation,
        meta_pairs(&m.meta),
    )
}

fn raw_event(e: Event) -> RawEvent {
    let member = |kind, m| (kind, Some(raw_member(m)), None, None, None);
    match e {
        Event::MemberJoined(m) => member("MemberJoined", m),
        Event::MemberSuspect(m) => member("MemberSuspect", m),
        Event::MemberRecovered(m) => member("MemberRecovered", m),
        Event::MemberDead(m) => member("MemberDead", m),
        Event::MemberLeft(m) => member("MemberLeft", m),
        Event::MemberUpdated {
            member,
            previous_meta,
        } => (
            "MemberUpdated",
            Some(raw_member(member)),
            Some(meta_pairs(&previous_meta)),
            None,
            None,
        ),
        Event::NameConflict { member, other_addr } => (
            "NameConflict",
            Some(raw_member(member)),
            None,
            Some(other_addr.to_string()),
            None,
        ),
        Event::EventsLost(n) => ("EventsLost", None, None, None, Some(n)),
        // A kind this binding does not know yet: report it as a loss so callers resync.
        _ => ("EventsLost", None, None, None, Some(1)),
    }
}

/// Everything the node's tasks share.
struct Inner {
    ml: Memberlist,
    seeds: Vec<SocketAddr>,
    max_meta: usize,
    /// Serializes metadata changes, so an `update_meta` merge never loses a concurrent one.
    meta_lock: tokio::sync::Mutex<()>,
}

impl Inner {
    async fn join(&self, seeds: Option<Vec<SocketAddr>>) -> Result<usize, KError> {
        let seeds = seeds.unwrap_or_else(|| self.seeds.clone());
        Ok(self.ml.join(seeds).await?)
    }

    fn encode(&self, pairs: &[(String, String)]) -> Result<Vec<u8>, KError> {
        let pairs = pairs.iter().map(|(k, v)| (k.as_str(), v.as_str()));
        encode_tags(pairs, self.max_meta).map_err(|e| match e {
            TagsError::TooLarge => KError::Net(Error::MetaTooLarge),
            _ => KError::BadArgument("meta", "keys must be non-empty"),
        })
    }

    async fn set_meta(&self, pairs: Vec<(String, String)>) -> Result<(), KError> {
        let meta = self.encode(&pairs)?;
        let _guard = self.meta_lock.lock().await;
        Ok(self.ml.set_meta(meta).await?)
    }

    async fn update_meta(&self, changes: Vec<(String, Option<String>)>) -> Result<(), KError> {
        let _guard = self.meta_lock.lock().await;
        let mut pairs = meta_pairs(&self.ml.local().meta);
        for (key, value) in changes {
            let at = pairs.iter().position(|(k, _)| *k == key);
            match (at, value) {
                (Some(i), Some(v)) => pairs[i].1 = v,
                (Some(i), None) => {
                    pairs.remove(i);
                }
                (None, Some(v)) => pairs.push((key, v)),
                (None, None) => {}
            }
        }
        let meta = self.encode(&pairs)?;
        Ok(self.ml.set_meta(meta).await?)
    }

    /// Leaves, waiting up to `timeout`; `true` if it ran out of time. Leaving twice is fine.
    async fn leave(&self, timeout: Duration) -> Result<bool, KError> {
        match self.ml.leave(timeout).await {
            Ok(()) | Err(Error::Left) => Ok(false),
            Err(Error::Timeout) => Ok(true),
            Err(e) => Err(e.into()),
        }
    }

    /// Leaves, then closes; `true` if the leave timed out. A node that is already closed or
    /// gone is simply closed. Callers spawn it, so it finishes even if they are cancelled.
    async fn shutdown(self: Arc<Self>, timeout: Duration) -> Result<bool, KError> {
        let timed_out = self.leave(timeout).await.unwrap_or(false);
        self.ml.close().await;
        Ok(timed_out)
    }

    async fn keyring(&self, change: KeyChange, key: Key) -> Result<(), KError> {
        let keyring = self.ml.keyring();
        let r = match change {
            KeyChange::Install => keyring.install(key).await,
            KeyChange::Use => keyring.use_key(key).await,
            KeyChange::Remove => keyring.remove(key).await,
        };
        Ok(r?)
    }
}

#[derive(Clone, Copy)]
enum KeyChange {
    Install,
    Use,
    Remove,
}

fn parse_seeds(seeds: Option<Vec<String>>) -> PyResult<Option<Vec<SocketAddr>>> {
    seeds
        .map(|seeds| {
            seeds
                .iter()
                .map(|s| {
                    s.trim().parse().map_err(|_| {
                        PyValueError::new_err(format!(
                            "seed {s:?} is not \"host:port\" with an IP address"
                        ))
                    })
                })
                .collect()
        })
        .transpose()
}

fn parse_key(v: &Bound<'_, PyAny>) -> PyResult<Key> {
    config::key(v)
        .ok_or_else(|| PyValueError::new_err("a key must be 32 bytes, or base64 text of 32 bytes"))
}

fn parse_meta(v: &Bound<'_, PyAny>) -> PyResult<Vec<(String, String)>> {
    config::tags(v).ok_or_else(|| PyValueError::new_err("meta must be a mapping of str to str"))
}

fn parse_changes(changes: &Bound<'_, PyDict>) -> PyResult<Vec<(String, Option<String>)>> {
    let mut out = Vec::new();
    for (k, v) in changes.iter() {
        let k: String = k.extract()?;
        let v = if v.is_none() {
            None
        } else {
            Some(
                v.cast::<PyString>()
                    .map_err(|_| {
                        PyValueError::new_err(format!("meta value for {k:?} must be a str or None"))
                    })?
                    .to_str()?
                    .to_owned(),
            )
        };
        out.push((k, v));
    }
    Ok(out)
}

fn timeout(t: Option<f64>) -> Result<Option<Duration>, KError> {
    t.map(|t| seconds("timeout", t)).transpose()
}

/// A running node. Created by `Node.start` or `Node.start_blocking`.
#[pyclass(frozen, module = "kinship._kinship")]
pub struct Node {
    /// Always set until the node is dropped. A node inherited across fork is leaked rather than
    /// dropped, since dropping it would touch a runtime whose threads no longer exist.
    inner: Option<Arc<Inner>>,
    pid: u32,
}

impl Node {
    fn inner(&self) -> Result<Arc<Inner>, KError> {
        check_pid(self.pid)?;
        self.inner.clone().ok_or(KError::Closed)
    }

    fn get(&self, py: Python<'_>) -> PyResult<Arc<Inner>> {
        finish(py, self.inner())
    }

    async fn spawn(fields: config::Fields) -> Result<Node, KError> {
        let (settings, bind) = fields.build(true)?;
        let seeds = settings.seeds.clone();
        let max_meta = settings.core.limits.max_meta_bytes;
        let transport = TokioTransport::bind(bind).await.map_err(Error::from)?;
        let ml = Memberlist::start(settings, transport).await?;
        Ok(Node {
            inner: Some(Arc::new(Inner {
                ml,
                seeds,
                max_meta,
                meta_lock: tokio::sync::Mutex::new(()),
            })),
            pid: runtime::pid(),
        })
    }

    fn change_key<'py>(
        &self,
        py: Python<'py>,
        change: KeyChange,
        key: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let key = parse_key(key)?;
        let inner = self.get(py)?;
        awaitable(py, async move { inner.keyring(change, key).await })
    }

    fn change_key_blocking(
        &self,
        py: Python<'_>,
        change: KeyChange,
        key: &Bound<'_, PyAny>,
        t: Option<f64>,
    ) -> PyResult<()> {
        let key = parse_key(key)?;
        let inner = self.get(py)?;
        let r = timeout(t)
            .and_then(|t| block_on(py, t, async move { inner.keyring(change, key).await }));
        finish(py, r)
    }
}

impl Drop for Node {
    fn drop(&mut self) {
        if self.pid != runtime::pid() {
            std::mem::forget(self.inner.take());
        }
    }
}

#[pymethods]
impl Node {
    /// Validates `cfg`, binds, starts the node and joins `cfg.seeds`. Resolves to a `Node`.
    #[staticmethod]
    fn start<'py>(py: Python<'py>, cfg: &Config) -> PyResult<Bound<'py, PyAny>> {
        let fields = cfg.fields().clone();
        finish(py, runtime::runtime(Some(fields.runtime_threads())))?;
        awaitable(py, Self::spawn(fields))
    }

    #[staticmethod]
    #[pyo3(signature = (cfg, timeout=None))]
    fn start_blocking(py: Python<'_>, cfg: &Config, timeout: Option<f64>) -> PyResult<Node> {
        let fields = cfg.fields().clone();
        finish(py, runtime::runtime(Some(fields.runtime_threads())))?;
        let r = self::timeout(timeout).and_then(|t| block_on(py, t, Self::spawn(fields)));
        finish(py, r)
    }

    #[pyo3(signature = (seeds=None))]
    fn join<'py>(
        &self,
        py: Python<'py>,
        seeds: Option<Vec<String>>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let seeds = parse_seeds(seeds)?;
        let inner = self.get(py)?;
        awaitable(py, async move { inner.join(seeds).await })
    }

    #[pyo3(signature = (seeds=None, timeout=None))]
    fn join_blocking(
        &self,
        py: Python<'_>,
        seeds: Option<Vec<String>>,
        timeout: Option<f64>,
    ) -> PyResult<usize> {
        let seeds = parse_seeds(seeds)?;
        let inner = self.get(py)?;
        let r = self::timeout(timeout)
            .and_then(|t| block_on(py, t, async move { inner.join(seeds).await }));
        finish(py, r)
    }

    fn members(&self, py: Python<'_>) -> PyResult<Vec<RawMember>> {
        Ok(self
            .get(py)?
            .ml
            .members()
            .into_iter()
            .map(raw_member)
            .collect())
    }

    fn member(&self, py: Python<'_>, name: &str) -> PyResult<Option<RawMember>> {
        Ok(self.get(py)?.ml.member(name).map(raw_member))
    }

    fn local(&self, py: Python<'_>) -> PyResult<RawMember> {
        Ok(raw_member(self.get(py)?.ml.local()))
    }

    /// The address UDP and TCP are bound to.
    fn local_addr(&self, py: Python<'_>) -> PyResult<String> {
        Ok(self.get(py)?.ml.local_addr().to_string())
    }

    fn stats<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyDict>> {
        let s = self.get(py)?.ml.stats();
        let m = &s.metrics;
        let d = PyDict::new(py);
        d.set_item("local_health", s.local_health)?;
        for (k, v) in [
            ("packets_received", m.packets_received),
            ("decode_errors", m.decode_errors),
            ("decrypt_failures", m.decrypt_failures),
            ("probes_sent", m.probes_sent),
            ("probes_failed", m.probes_failed),
            ("indirect_probes", m.indirect_probes),
            ("missed_nacks", m.missed_nacks),
            ("suspicions", m.suspicions),
            ("refutations", m.refutations),
            ("misdirected", m.misdirected),
            ("name_conflicts", m.name_conflicts),
            ("push_pulls", m.push_pulls),
            ("push_pull_failures", m.push_pull_failures),
            ("push_pulls_served", m.push_pulls_served),
            ("state_too_large", m.state_too_large),
            ("tcp_pings", m.tcp_pings),
            ("tcp_ping_acks", m.tcp_ping_acks),
        ] {
            d.set_item(k, v)?;
        }
        Ok(d)
    }

    /// A new subscription, starting now.
    fn events(&self, py: Python<'_>) -> PyResult<EventSub> {
        let events = self.get(py)?.ml.events();
        Ok(EventSub {
            events: Arc::new(tokio::sync::Mutex::new(events)),
            pid: self.pid,
        })
    }

    fn set_meta<'py>(
        &self,
        py: Python<'py>,
        meta: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let pairs = parse_meta(meta)?;
        let inner = self.get(py)?;
        awaitable(py, async move { inner.set_meta(pairs).await })
    }

    #[pyo3(signature = (meta, timeout=None))]
    fn set_meta_blocking(
        &self,
        py: Python<'_>,
        meta: &Bound<'_, PyAny>,
        timeout: Option<f64>,
    ) -> PyResult<()> {
        let pairs = parse_meta(meta)?;
        let inner = self.get(py)?;
        let r = self::timeout(timeout)
            .and_then(|t| block_on(py, t, async move { inner.set_meta(pairs).await }));
        finish(py, r)
    }

    fn update_meta<'py>(
        &self,
        py: Python<'py>,
        changes: &Bound<'py, PyDict>,
    ) -> PyResult<Bound<'py, PyAny>> {
        let changes = parse_changes(changes)?;
        let inner = self.get(py)?;
        awaitable(py, async move { inner.update_meta(changes).await })
    }

    #[pyo3(signature = (changes, timeout=None))]
    fn update_meta_blocking(
        &self,
        py: Python<'_>,
        changes: &Bound<'_, PyDict>,
        timeout: Option<f64>,
    ) -> PyResult<()> {
        let changes = parse_changes(changes)?;
        let inner = self.get(py)?;
        let r = self::timeout(timeout)
            .and_then(|t| block_on(py, t, async move { inner.update_meta(changes).await }));
        finish(py, r)
    }

    /// Resolves to `True` if the leave ran out of time.
    fn leave<'py>(&self, py: Python<'py>, timeout: f64) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.get(py)?;
        let t = finish(py, seconds("timeout", timeout))?;
        awaitable(py, async move { inner.leave(t).await })
    }

    fn leave_blocking(&self, py: Python<'_>, timeout: f64) -> PyResult<bool> {
        let inner = self.get(py)?;
        let t = finish(py, seconds("timeout", timeout))?;
        finish(py, block_on(py, None, async move { inner.leave(t).await }))
    }

    /// Closes the node; it finishes even if the awaiting task is cancelled.
    fn close<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.get(py)?;
        let rt = finish(py, runtime::runtime(None))?;
        let task = rt.spawn(async move { inner.ml.close().await });
        awaitable(py, async move { task.await.map_err(|_| KError::Closed) })
    }

    #[pyo3(signature = (timeout=None))]
    fn close_blocking(&self, py: Python<'_>, timeout: Option<f64>) -> PyResult<()> {
        let inner = self.get(py)?;
        let r = self::timeout(timeout).and_then(|t| {
            block_on(py, t, async move {
                inner.ml.close().await;
                Ok(())
            })
        });
        finish(py, r)
    }

    /// Leaves with `timeout`, then closes; both finish even if the awaiting task is cancelled.
    /// Resolves to `True` if the leave ran out of time.
    fn shutdown<'py>(&self, py: Python<'py>, timeout: f64) -> PyResult<Bound<'py, PyAny>> {
        let inner = self.get(py)?;
        let t = finish(py, seconds("timeout", timeout))?;
        let rt = finish(py, runtime::runtime(None))?;
        let task = rt.spawn(inner.shutdown(t));
        awaitable(py, async move { task.await.map_err(|_| KError::Closed)? })
    }

    fn shutdown_blocking(&self, py: Python<'_>, timeout: f64) -> PyResult<bool> {
        let inner = self.get(py)?;
        let t = finish(py, seconds("timeout", timeout))?;
        let rt = finish(py, runtime::runtime(None))?;
        let task = rt.spawn(inner.shutdown(t));
        finish(
            py,
            block_on(
                py,
                None,
                async move { task.await.map_err(|_| KError::Closed)? },
            ),
        )
    }

    fn is_closed(&self, py: Python<'_>) -> PyResult<bool> {
        Ok(self.get(py)?.ml.is_closed())
    }

    fn key_install<'py>(
        &self,
        py: Python<'py>,
        key: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.change_key(py, KeyChange::Install, key)
    }

    fn key_use<'py>(
        &self,
        py: Python<'py>,
        key: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.change_key(py, KeyChange::Use, key)
    }

    fn key_remove<'py>(
        &self,
        py: Python<'py>,
        key: &Bound<'py, PyAny>,
    ) -> PyResult<Bound<'py, PyAny>> {
        self.change_key(py, KeyChange::Remove, key)
    }

    #[pyo3(signature = (key, timeout=None))]
    fn key_install_blocking(
        &self,
        py: Python<'_>,
        key: &Bound<'_, PyAny>,
        timeout: Option<f64>,
    ) -> PyResult<()> {
        self.change_key_blocking(py, KeyChange::Install, key, timeout)
    }

    #[pyo3(signature = (key, timeout=None))]
    fn key_use_blocking(
        &self,
        py: Python<'_>,
        key: &Bound<'_, PyAny>,
        timeout: Option<f64>,
    ) -> PyResult<()> {
        self.change_key_blocking(py, KeyChange::Use, key, timeout)
    }

    #[pyo3(signature = (key, timeout=None))]
    fn key_remove_blocking(
        &self,
        py: Python<'_>,
        key: &Bound<'_, PyAny>,
        timeout: Option<f64>,
    ) -> PyResult<()> {
        self.change_key_blocking(py, KeyChange::Remove, key, timeout)
    }

    /// Ids of the installed keys, the one in use first, as 8 hex characters each.
    fn key_ids(&self, py: Python<'_>) -> PyResult<Vec<String>> {
        let ids = self.get(py)?.ml.keyring().key_ids();
        Ok(ids.iter().map(ToString::to_string).collect())
    }

    /// Not part of the API, and absent from the stubs: makes the node's actor panic, for the
    /// tests of how a failed node reports itself.
    #[pyo3(name = "_panic_actor")]
    fn panic_actor(&self, py: Python<'_>) -> PyResult<()> {
        self.get(py)?.ml.panic_actor();
        Ok(())
    }
}

/// One subscription to a node's events.
#[pyclass(frozen, module = "kinship._kinship")]
pub struct EventSub {
    events: Arc<tokio::sync::Mutex<Events>>,
    pid: u32,
}

/// What a wait for the next event found.
enum Next {
    Event(Event),
    End,
    Tick,
}

impl<'py> IntoPyObject<'py> for Next {
    type Target = PyAny;
    type Output = Bound<'py, PyAny>;
    type Error = PyErr;

    /// An event tuple, `None` at the end, or `False` when a timeout passed with no event.
    fn into_pyobject(self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        use pyo3::IntoPyObjectExt;
        match self {
            Next::Event(e) => raw_event(e).into_bound_py_any(py),
            Next::End => Ok(py.None().into_bound(py)),
            Next::Tick => false.into_bound_py_any(py),
        }
    }
}

async fn next(
    events: Arc<tokio::sync::Mutex<Events>>,
    wait: Option<Duration>,
) -> Result<Next, KError> {
    let mut events = events.lock().await;
    let received = match wait {
        Some(t) => match tokio::time::timeout(t, events.recv()).await {
            Ok(e) => e,
            Err(_) => return Ok(Next::Tick),
        },
        None => events.recv().await,
    };
    match received {
        Some(e) => Ok(Next::Event(e)),
        None if events.failed() => Err(KError::Failed),
        None => Ok(Next::End),
    }
}

#[pymethods]
impl EventSub {
    /// The next queued event, or `None` if none is queued or another reader is waiting.
    fn try_next(&self, py: Python<'_>) -> PyResult<Option<RawEvent>> {
        finish(py, check_pid(self.pid))?;
        let Ok(mut events) = self.events.try_lock() else {
            return Ok(None);
        };
        Ok(events.try_recv().map(raw_event))
    }

    /// Resolves to the next event, or `None` once the node has closed. Raises `KinshipClosed`
    /// if the node stopped on an internal error.
    fn next<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyAny>> {
        finish(py, check_pid(self.pid))?;
        let events = Arc::clone(&self.events);
        awaitable(py, next(events, None))
    }

    /// The next event, `None` once the node has closed, or `False` after `timeout` seconds
    /// with no event.
    #[pyo3(signature = (timeout=None))]
    fn next_blocking<'py>(
        &self,
        py: Python<'py>,
        timeout: Option<f64>,
    ) -> PyResult<Bound<'py, PyAny>> {
        finish(py, check_pid(self.pid))?;
        let wait = finish(py, self::timeout(timeout))?;
        let events = Arc::clone(&self.events);
        let n = finish(py, block_on(py, None, next(events, wait)))?;
        n.into_pyobject(py)
    }
}
