//! Errors on the Rust side, and their Python exceptions.
//!
//! The exception classes live in `kinship._errors` so they can have more than one base (a
//! `ConfigError` is both a `KinshipError` and a `ValueError`). A [`KError`] travels without the
//! GIL and becomes a Python exception only once a thread that may take the GIL handles it.

use pyo3::IntoPyObjectExt;
use pyo3::exceptions::{PyTimeoutError, PyValueError};
use pyo3::prelude::*;
use pyo3::sync::PyOnceLock;
use pyo3::types::PyType;

/// Why a kinship call failed.
#[derive(Debug)]
pub enum KError {
    Net(kinship_net::Error),
    /// A blocking call ran out of `timeout`.
    Timeout,
    /// A handle was used in a process forked from the one that created it.
    Forked,
    /// The node stopped on an internal error.
    Failed,
    /// The node was closed or stopped.
    Closed,
    /// An argument that is not part of a config is unusable.
    BadArgument(&'static str, &'static str),
    /// Python raised while the call waited, such as `KeyboardInterrupt`.
    Py(PyErr),
}

impl From<kinship_net::Error> for KError {
    fn from(e: kinship_net::Error) -> Self {
        match e {
            kinship_net::Error::Closed => Self::Closed,
            kinship_net::Error::Timeout => Self::Timeout,
            e => Self::Net(e),
        }
    }
}

impl From<kinship_net::ConfigError> for KError {
    fn from(e: kinship_net::ConfigError) -> Self {
        Self::Net(e.into())
    }
}

static ERRORS: PyOnceLock<Py<PyModule>> = PyOnceLock::new();

fn class<'py>(py: Python<'py>, name: &str) -> PyResult<Bound<'py, PyType>> {
    let module = ERRORS.get_or_try_init(py, || py.import("kinship._errors").map(Bound::unbind))?;
    Ok(module.bind(py).getattr(name)?.cast_into()?)
}

/// A `kinship._errors` exception of class `name` with the given constructor arguments.
pub fn raise<A>(py: Python<'_>, name: &str, args: A) -> PyErr
where
    A: pyo3::PyErrArguments + Send + Sync + 'static,
{
    match class(py, name) {
        Ok(cls) => PyErr::from_type(cls, args),
        Err(e) => e,
    }
}

/// `ConfigError(message, field)`.
pub fn config_error(py: Python<'_>, field: &str, reason: &str) -> PyErr {
    raise(
        py,
        "ConfigError",
        (format!("{field} {reason}"), field.to_owned()),
    )
}

impl KError {
    pub fn into_pyerr(self, py: Python<'_>) -> PyErr {
        use kinship_net::Error as E;
        match self {
            Self::Net(E::Config(e)) => config_error(py, e.field, e.reason),
            Self::Net(E::Io(e)) => e.into(),
            Self::Net(E::JoinFailed) => raise(py, "JoinError", ("no seed answered",)),
            Self::Net(E::MetaTooLarge) => raise(
                py,
                "MetaTooLarge",
                ("encoded metadata is larger than max_meta_bytes",),
            ),
            Self::Net(E::Left) => raise(py, "KinshipClosed", ("this node has left the cluster",)),
            Self::Net(e @ (E::NotEncrypted | E::KeyNotInstalled | E::KeyInUse | E::LastKey)) => {
                raise(py, "KeyringError", (e.to_string(),))
            }
            Self::Net(e) => raise(py, "KinshipError", (e.to_string(),)),
            Self::Timeout => PyTimeoutError::new_err("timed out"),
            Self::Forked => raise(
                py,
                "KinshipClosed",
                ("this cluster was created in another process; \
                  create clusters after os.fork(), never before",),
            ),
            Self::Failed => raise(
                py,
                "KinshipClosed",
                ("the node stopped on an internal error",),
            ),
            Self::Closed => raise(py, "KinshipClosed", ("the cluster is closed",)),
            Self::BadArgument(field, reason) => PyValueError::new_err(format!("{field} {reason}")),
            Self::Py(e) => e,
        }
    }
}

/// A result that turns into a Python value, or raises, when pyo3-async-runtimes hands it to
/// asyncio. That happens on a blocking-pool thread that holds the GIL, so errors are built
/// there rather than on the thread that runs the protocol.
pub struct Reply<T>(pub Result<T, KError>);

impl<'py, T> IntoPyObject<'py> for Reply<T>
where
    T: IntoPyObject<'py>,
{
    type Target = PyAny;
    type Output = Bound<'py, PyAny>;
    type Error = PyErr;

    fn into_pyobject(self, py: Python<'py>) -> Result<Self::Output, Self::Error> {
        match self.0 {
            Ok(v) => v.into_bound_py_any(py),
            Err(e) => Err(e.into_pyerr(py)),
        }
    }
}

/// Converts a blocking call's result while the GIL is held.
pub fn finish<T>(py: Python<'_>, r: Result<T, KError>) -> PyResult<T> {
    r.map_err(|e| e.into_pyerr(py))
}
