//! `kinship.Config`: a frozen preset with fields overridden by keyword, validated when built.

use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;

use kinship_net::{ConfigError, Identity, Key, Security, Settings};
use kinship_proto::tags::{TagsError, encode_tags};
use pyo3::IntoPyObjectExt;
use pyo3::exceptions::{PyAttributeError, PyTypeError};
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::{PyBool, PyBytes, PyDict, PyList, PyString, PyType};

use crate::errors::config_error;
use crate::runtime::DEFAULT_THREADS;

/// Default port for UDP and TCP.
const DEFAULT_PORT: u16 = 7946;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Preset {
    Lan,
    Wan,
    Local,
}

impl Preset {
    fn name(self) -> &'static str {
        match self {
            Self::Lan => "lan",
            Self::Wan => "wan",
            Self::Local => "local",
        }
    }
}

/// Every field of a config, with the defaults of its preset.
#[derive(Clone)]
pub struct Fields {
    preset: Preset,
    /// Protocol fields. `security` is decided from the keys when the node starts.
    core: kinship_net::Config,
    name: String,
    bind: SocketAddr,
    advertise: Option<SocketAddr>,
    meta: Vec<(String, String)>,
    seeds: Vec<SocketAddr>,
    keys: Vec<Key>,
    insecure_plaintext: bool,
    max_inbound_streams: usize,
    max_inbound_streams_per_ip: usize,
    max_inbound_bytes_per_ip: Option<usize>,
    tcp_header_timeout: Duration,
    event_buffer: usize,
    runtime_threads: usize,
}

impl Fields {
    fn preset(preset: Preset) -> Self {
        let plain = Security::InsecurePlaintext;
        let (core, ip) = match preset {
            Preset::Lan => (kinship_net::Config::lan(plain), Ipv4Addr::UNSPECIFIED),
            Preset::Wan => (kinship_net::Config::wan(plain), Ipv4Addr::UNSPECIFIED),
            Preset::Local => (kinship_net::Config::local(plain), Ipv4Addr::LOCALHOST),
        };
        Self {
            preset,
            core,
            name: kinship_net::default_name(),
            bind: (ip, DEFAULT_PORT).into(),
            advertise: None,
            meta: Vec::new(),
            seeds: Vec::new(),
            keys: Vec::new(),
            insecure_plaintext: false,
            max_inbound_streams: Settings::DEFAULT_MAX_INBOUND_STREAMS,
            max_inbound_streams_per_ip: Settings::DEFAULT_MAX_INBOUND_STREAMS_PER_IP,
            max_inbound_bytes_per_ip: None,
            tcp_header_timeout: Settings::DEFAULT_TCP_HEADER_TIMEOUT,
            event_buffer: Settings::DEFAULT_EVENT_BUFFER,
            runtime_threads: DEFAULT_THREADS,
        }
    }

    pub fn runtime_threads(&self) -> usize {
        self.runtime_threads
    }

    /// Checks every field together and resolves what the node needs: its settings and where to
    /// bind. `starting` logs the plaintext warning, which only a starting node should.
    pub fn build(&self, starting: bool) -> Result<(Settings, SocketAddr), ConfigError> {
        let fail = |field, reason| Err(ConfigError { field, reason });
        let mut core = self.core.clone();
        core.security = if !self.keys.is_empty() {
            Security::Keys(self.keys.clone())
        } else if self.insecure_plaintext {
            if starting {
                tracing::warn!("running without encryption: insecure_plaintext is set");
            }
            Security::InsecurePlaintext
        } else if self.preset == Preset::Local && self.bind.ip().is_loopback() {
            Security::InsecurePlaintext
        } else {
            return fail(
                "keys",
                "are required unless insecure_plaintext is set, or local() binds loopback",
            );
        };
        core.validate()?;
        Identity::new(self.name.as_str(), self.bind)?;
        let pairs = self.meta.iter().map(|(k, v)| (k.as_str(), v.as_str()));
        let meta = match encode_tags(pairs, core.limits.max_meta_bytes) {
            Ok(meta) => meta,
            Err(TagsError::TooLarge) => {
                return fail("meta", "must encode to at most max_meta_bytes");
            }
            Err(_) => return fail("meta", "keys must be non-empty"),
        };
        if self.runtime_threads == 0 {
            return fail("runtime_threads", "must be at least 1");
        }
        let settings = Settings {
            core,
            name: self.name.clone(),
            advertise: self.advertise,
            meta,
            seeds: self.seeds.clone(),
            max_inbound_streams: self.max_inbound_streams,
            max_inbound_streams_per_ip: self.max_inbound_streams_per_ip,
            max_inbound_bytes_per_ip: self.max_inbound_bytes_per_ip,
            tcp_header_timeout: self.tcp_header_timeout,
            event_buffer: self.event_buffer,
        };
        settings.validate()?;
        Ok((settings, self.bind))
    }

    /// Applies keyword overrides. A value of the wrong type or range names its field.
    fn apply(&mut self, py: Python<'_>, kwargs: Option<&Bound<'_, PyDict>>) -> PyResult<()> {
        let Some(kwargs) = kwargs else {
            return Ok(());
        };
        for (key, value) in kwargs.iter() {
            let key: String = key.extract()?;
            self.set(py, &key, &value)?;
        }
        Ok(())
    }

    fn set(&mut self, py: Python<'_>, field: &str, v: &Bound<'_, PyAny>) -> PyResult<()> {
        let c = &mut self.core;
        let bad = |reason: &str| config_error(py, field, reason);
        macro_rules! durations {
            ($($name:ident => $($path:ident).+),* $(,)?) => {
                match field {
                    $(stringify!($name) => {
                        c.$($path).+ = duration(py, v).ok_or_else(|| {
                            bad("must be seconds as a non-negative float, or a timedelta")
                        })?;
                        return Ok(());
                    })*
                    _ => {}
                }
            };
        }
        macro_rules! numbers {
            ($ty:ty; $($name:ident => $($path:ident).+),* $(,)?) => {
                match field {
                    $(stringify!($name) => {
                        c.$($path).+ = integer::<$ty>(v)
                            .ok_or_else(|| bad("must be a non-negative integer"))?;
                        return Ok(());
                    })*
                    _ => {}
                }
            };
        }
        macro_rules! flags {
            ($($name:ident => $($path:ident).+),* $(,)?) => {
                match field {
                    $(stringify!($name) => {
                        c.$($path).+ = flag(v).ok_or_else(|| bad("must be True or False"))?;
                        return Ok(());
                    })*
                    _ => {}
                }
            };
        }
        durations! {
            probe_interval => probe_interval,
            probe_timeout => probe_timeout,
            dead_reclaim => dead_reclaim,
            gossip_interval => gossip_interval,
            gossip_to_the_dead => gossip_to_the_dead,
            push_pull_interval => push_pull_interval,
            reconnect_interval => reconnect_interval,
            rejoin_interval => rejoin_interval,
            tcp_timeout => tcp_timeout,
        }
        numbers! { usize;
            indirect_checks => indirect_checks,
            gossip_nodes => gossip_nodes,
            udp_max_payload => limits.udp_max_payload,
            max_stream_frame => limits.max_stream_frame,
            max_meta_bytes => limits.max_meta_bytes,
        }
        numbers! { u32;
            suspicion_mult => suspicion_mult,
            suspicion_max_mult => suspicion_max_mult,
            expected_confirmations => expected_confirmations,
            awareness_max => awareness_max,
            retransmit_mult => retransmit_mult,
            join_retries => join_retries,
        }
        flags! {
            tcp_fallback_ping => tcp_fallback_ping,
            local_health => local_health,
            nacks => nacks,
            dynamic_suspicion => dynamic_suspicion,
            buddy_system => buddy_system,
        }
        let count = |v: &Bound<'_, PyAny>| {
            integer::<usize>(v).ok_or_else(|| bad("must be a non-negative integer"))
        };
        match field {
            "name" => {
                self.name = if v.is_none() {
                    kinship_net::default_name()
                } else {
                    v.extract().map_err(|_| bad("must be a string or None"))?
                }
            }
            "bind" => {
                self.bind =
                    addr(v).ok_or_else(|| bad("must be \"host:port\" with an IP address"))?
            }
            "advertise" => {
                self.advertise =
                    if v.is_none() {
                        None
                    } else {
                        Some(addr(v).ok_or_else(|| {
                            bad("must be \"host:port\" with an IP address, or None")
                        })?)
                    }
            }
            "cluster" => {
                self.core.cluster = v.extract().map_err(|_| bad("must be a string"))?;
            }
            "seeds" => {
                self.seeds = if v.is_none() {
                    Vec::new()
                } else {
                    let reason = "must be a list of \"host:port\" strings with IP addresses";
                    if v.is_instance_of::<PyString>() {
                        return Err(bad(reason));
                    }
                    let mut seeds = Vec::new();
                    for item in v.try_iter().map_err(|_| bad(reason))? {
                        seeds.push(addr(&item?).ok_or_else(|| bad(reason))?);
                    }
                    seeds
                }
            }
            "meta" => {
                self.meta = if v.is_none() {
                    Vec::new()
                } else {
                    tags(v).ok_or_else(|| bad("must be a mapping of str to str"))?
                }
            }
            "keys" => {
                self.keys = if v.is_none() {
                    Vec::new()
                } else {
                    let reason = "must be a list of 32-byte keys, as bytes or base64 text";
                    if v.is_instance_of::<PyString>() || v.is_instance_of::<PyBytes>() {
                        return Err(bad(reason));
                    }
                    let mut keys = Vec::new();
                    for item in v.try_iter().map_err(|_| bad(reason))? {
                        keys.push(key(&item?).ok_or_else(|| bad(reason))?);
                    }
                    keys
                }
            }
            "insecure_plaintext" => {
                self.insecure_plaintext = flag(v).ok_or_else(|| bad("must be True or False"))?
            }
            "max_inbound_streams" => self.max_inbound_streams = count(v)?,
            "max_inbound_streams_per_ip" => self.max_inbound_streams_per_ip = count(v)?,
            "max_inbound_bytes_per_ip" => {
                self.max_inbound_bytes_per_ip = if v.is_none() {
                    None
                } else {
                    Some(
                        integer::<usize>(v)
                            .ok_or_else(|| bad("must be a non-negative integer or None"))?,
                    )
                }
            }
            "tcp_header_timeout" => {
                self.tcp_header_timeout = duration(py, v)
                    .ok_or_else(|| bad("must be seconds as a non-negative float, or a timedelta"))?
            }
            "event_buffer" => self.event_buffer = count(v)?,
            "runtime_threads" => self.runtime_threads = count(v)?,
            _ => {
                return Err(PyTypeError::new_err(format!(
                    "unknown config field {field:?}"
                )));
            }
        }
        Ok(())
    }

    /// A field's value as Python sees it, or `None` for a name that is not a field.
    fn get(&self, py: Python<'_>, field: &str) -> PyResult<Option<Py<PyAny>>> {
        let c = &self.core;
        let secs = |d: Duration| d.as_secs_f64().into_py_any(py);
        let v = match field {
            "name" => self.name.clone().into_py_any(py),
            "bind" => self.bind.to_string().into_py_any(py),
            "advertise" => self.advertise.map(|a| a.to_string()).into_py_any(py),
            "cluster" => c.cluster.clone().into_py_any(py),
            "seeds" => self
                .seeds
                .iter()
                .map(ToString::to_string)
                .collect::<Vec<_>>()
                .into_py_any(py),
            "meta" => {
                let d = PyDict::new(py);
                for (k, v) in &self.meta {
                    d.set_item(k, v)?;
                }
                Ok(d.into_any().unbind())
            }
            "key_ids" => key_ids(&self.keys).into_py_any(py),
            "insecure_plaintext" => self.insecure_plaintext.into_py_any(py),
            "probe_interval" => secs(c.probe_interval),
            "probe_timeout" => secs(c.probe_timeout),
            "indirect_checks" => c.indirect_checks.into_py_any(py),
            "tcp_fallback_ping" => c.tcp_fallback_ping.into_py_any(py),
            "suspicion_mult" => c.suspicion_mult.into_py_any(py),
            "suspicion_max_mult" => c.suspicion_max_mult.into_py_any(py),
            "expected_confirmations" => c.expected_confirmations.into_py_any(py),
            "awareness_max" => c.awareness_max.into_py_any(py),
            "local_health" => c.local_health.into_py_any(py),
            "nacks" => c.nacks.into_py_any(py),
            "dynamic_suspicion" => c.dynamic_suspicion.into_py_any(py),
            "buddy_system" => c.buddy_system.into_py_any(py),
            "dead_reclaim" => secs(c.dead_reclaim),
            "gossip_interval" => secs(c.gossip_interval),
            "gossip_nodes" => c.gossip_nodes.into_py_any(py),
            "gossip_to_the_dead" => secs(c.gossip_to_the_dead),
            "retransmit_mult" => c.retransmit_mult.into_py_any(py),
            "push_pull_interval" => secs(c.push_pull_interval),
            "reconnect_interval" => secs(c.reconnect_interval),
            "rejoin_interval" => secs(c.rejoin_interval),
            "udp_max_payload" => c.limits.udp_max_payload.into_py_any(py),
            "max_stream_frame" => c.limits.max_stream_frame.into_py_any(py),
            "max_meta_bytes" => c.limits.max_meta_bytes.into_py_any(py),
            "tcp_timeout" => secs(c.tcp_timeout),
            "tcp_header_timeout" => secs(self.tcp_header_timeout),
            "max_inbound_streams" => self.max_inbound_streams.into_py_any(py),
            "max_inbound_streams_per_ip" => self.max_inbound_streams_per_ip.into_py_any(py),
            "max_inbound_bytes_per_ip" => self.max_inbound_bytes_per_ip.into_py_any(py),
            "join_retries" => c.join_retries.into_py_any(py),
            "event_buffer" => self.event_buffer.into_py_any(py),
            "runtime_threads" => self.runtime_threads.into_py_any(py),
            _ => return Ok(None),
        };
        v.map(Some)
    }
}

/// Readable fields, in the order `repr` and `dir` list them. `keys` is write-only; its ids
/// are readable as `key_ids`.
const FIELDS: &[&str] = &[
    "name",
    "bind",
    "advertise",
    "cluster",
    "seeds",
    "meta",
    "key_ids",
    "insecure_plaintext",
    "probe_interval",
    "probe_timeout",
    "indirect_checks",
    "tcp_fallback_ping",
    "suspicion_mult",
    "suspicion_max_mult",
    "expected_confirmations",
    "awareness_max",
    "local_health",
    "nacks",
    "dynamic_suspicion",
    "buddy_system",
    "dead_reclaim",
    "gossip_interval",
    "gossip_nodes",
    "gossip_to_the_dead",
    "retransmit_mult",
    "push_pull_interval",
    "reconnect_interval",
    "rejoin_interval",
    "udp_max_payload",
    "max_stream_frame",
    "max_meta_bytes",
    "tcp_timeout",
    "tcp_header_timeout",
    "max_inbound_streams",
    "max_inbound_streams_per_ip",
    "max_inbound_bytes_per_ip",
    "join_retries",
    "event_buffer",
    "runtime_threads",
];

/// Fields `repr` always shows; the rest only when they differ from the preset.
const ALWAYS_SHOWN: &[&str] = &["name", "bind", "cluster", "seeds", "key_ids"];

pub fn key_ids(keys: &[Key]) -> Vec<String> {
    keys.iter().map(|k| k.key_id().to_string()).collect()
}

fn flag(v: &Bound<'_, PyAny>) -> Option<bool> {
    v.cast::<PyBool>().ok().map(|b| b.is_true())
}

fn integer<T: for<'a, 'py> FromPyObject<'a, 'py>>(v: &Bound<'_, PyAny>) -> Option<T> {
    if v.is_instance_of::<PyBool>() {
        return None;
    }
    v.extract().ok()
}

static TIMEDELTA: PyOnceLock<Py<PyType>> = PyOnceLock::new();

/// Seconds as a float or int, or a `datetime.timedelta`. Negative and non-finite values fail.
pub fn duration(py: Python<'_>, v: &Bound<'_, PyAny>) -> Option<Duration> {
    if v.is_instance_of::<PyBool>() {
        return None;
    }
    let secs: f64 = match v.extract() {
        Ok(secs) => secs,
        Err(_) => {
            let timedelta = TIMEDELTA.import(py, "datetime", "timedelta").ok()?;
            if !v.is_instance(timedelta).ok()? {
                return None;
            }
            v.call_method0("total_seconds").ok()?.extract().ok()?
        }
    };
    Duration::try_from_secs_f64(secs).ok()
}

fn addr(v: &Bound<'_, PyAny>) -> Option<SocketAddr> {
    v.extract::<String>().ok()?.trim().parse().ok()
}

/// A 32-byte key from `bytes` or base64 text. Never echoes the input.
pub fn key(v: &Bound<'_, PyAny>) -> Option<Key> {
    if let Ok(b) = v.cast::<PyBytes>() {
        return Key::from_slice(b.as_bytes());
    }
    let text = v.cast::<PyString>().ok()?;
    Key::from_base64(text.to_str().ok()?).ok()
}

/// A `Mapping[str, str]` as tag pairs in iteration order.
pub fn tags(v: &Bound<'_, PyAny>) -> Option<Vec<(String, String)>> {
    let items = v.call_method0("items").ok()?;
    let mut out = Vec::new();
    for item in items.try_iter().ok()? {
        let (k, v): (String, String) = item.ok()?.extract().ok()?;
        out.push((k, v));
    }
    Some(out)
}

/// Settings for a cluster node, validated as a whole when built.
///
/// Pick a preset with `Config.lan()`, `Config.wan()` or `Config.local()` and override fields by
/// keyword. Configs are frozen; `replace()` returns a changed copy. Durations are seconds as a
/// float, or a `datetime.timedelta`. A bad value raises `ConfigError`, a `ValueError` naming the
/// field, before any socket opens.
#[pyclass(frozen, module = "kinship", name = "Config")]
pub struct Config {
    fields: Fields,
}

impl Config {
    fn create(
        py: Python<'_>,
        mut fields: Fields,
        kwargs: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        fields.apply(py, kwargs)?;
        fields
            .build(false)
            .map_err(|e| config_error(py, e.field, e.reason))?;
        Ok(Self { fields })
    }

    pub fn fields(&self) -> &Fields {
        &self.fields
    }
}

#[pymethods]
impl Config {
    /// The same as `Config.lan(**fields)`.
    #[new]
    #[pyo3(signature = (**fields))]
    fn new(py: Python<'_>, fields: Option<&Bound<'_, PyDict>>) -> PyResult<Self> {
        Self::create(py, Fields::preset(Preset::Lan), fields)
    }

    /// One datacenter or VPC. Binds `0.0.0.0:7946` and needs `keys`.
    #[classmethod]
    #[pyo3(signature = (**fields))]
    fn lan(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        fields: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        Self::create(py, Fields::preset(Preset::Lan), fields)
    }

    /// Regions, edge sites and flaky links: probes every 5 s with a 3 s timeout, slower
    /// suspicion and push-pull every 60 s. Binds `0.0.0.0:7946` and needs `keys`.
    #[classmethod]
    #[pyo3(signature = (**fields))]
    fn wan(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        fields: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        Self::create(py, Fields::preset(Preset::Wan), fields)
    }

    /// Tests and demos on one host: probes every 200 ms and no TCP fallback ping. Binds
    /// `127.0.0.1:7946` and runs without keys while it binds loopback.
    #[classmethod]
    #[pyo3(signature = (**fields))]
    fn local(
        _cls: &Bound<'_, PyType>,
        py: Python<'_>,
        fields: Option<&Bound<'_, PyDict>>,
    ) -> PyResult<Self> {
        Self::create(py, Fields::preset(Preset::Local), fields)
    }

    /// A copy with the given fields changed, validated like a new config.
    #[pyo3(signature = (**fields))]
    fn replace(&self, py: Python<'_>, fields: Option<&Bound<'_, PyDict>>) -> PyResult<Self> {
        Self::create(py, self.fields.clone(), fields)
    }

    /// The preset this config started from: `"lan"`, `"wan"` or `"local"`.
    #[getter]
    fn preset(&self) -> &'static str {
        self.fields.preset.name()
    }

    fn __getattr__(&self, py: Python<'_>, name: &str) -> PyResult<Py<PyAny>> {
        if name == "keys" {
            return Err(PyAttributeError::new_err(
                "keys are never readable from a config; read key_ids instead",
            ));
        }
        self.fields
            .get(py, name)?
            .ok_or_else(|| PyAttributeError::new_err(format!("Config has no field {name:?}")))
    }

    fn __dir__<'py>(&self, py: Python<'py>) -> PyResult<Bound<'py, PyList>> {
        let mut names: Vec<&str> = FIELDS.to_vec();
        names.extend(["preset", "replace", "lan", "wan", "local"]);
        PyList::new(py, names)
    }

    fn __repr__(&self, py: Python<'_>) -> PyResult<String> {
        let preset = Fields::preset(self.fields.preset);
        let mut parts = Vec::new();
        for &field in FIELDS {
            let value = self.fields.get(py, field)?.expect("listed fields exist");
            let value = value.bind(py);
            if field != "name" && !ALWAYS_SHOWN.contains(&field) {
                let default = preset.get(py, field)?.expect("listed fields exist");
                if value.eq(default.bind(py))? {
                    continue;
                }
            }
            parts.push(format!("{field}={}", value.repr()?));
        }
        Ok(format!(
            "Config.{}({})",
            self.fields.preset.name(),
            parts.join(", ")
        ))
    }
}
