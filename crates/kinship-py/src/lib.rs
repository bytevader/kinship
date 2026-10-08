//! PyO3 bindings for kinship. The compiled module is `kinship._kinship`; the `kinship` Python
//! package builds the public API on top of it.
//!
//! Nodes run on a kinship-owned tokio runtime (see [`runtime`]), so nothing on the protocol
//! path takes the GIL. Every pyclass is frozen and `Send + Sync` with no reliance on the GIL,
//! which makes the same code correct on free-threaded CPython.

mod config;
mod errors;
mod logging;
mod node;
mod runtime;

use pyo3::prelude::*;
use pyo3::types::PyString;

/// Wire format version spoken by this build.
#[pyfunction]
fn wire_version() -> u8 {
    kinship_net::WIRE_VERSION
}

/// A new random 32-byte key from the OS's secure random source, as padded base64. The Rust
/// copies are zeroized; the Python string, which Python cannot wipe, is the caller's to drop.
#[pyfunction]
fn generate_key(py: Python<'_>) -> PyResult<Bound<'_, PyString>> {
    kinship_net::generate_key()
        .map(|k| PyString::new(py, &k.to_base64()))
        .map_err(|e| errors::KError::Net(e.into()).into_pyerr(py))
}

#[pymodule(gil_used = false)]
fn _kinship(m: &Bound<'_, PyModule>) -> PyResult<()> {
    logging::install();
    m.add_class::<config::Config>()?;
    m.add_class::<node::Node>()?;
    m.add_class::<node::EventSub>()?;
    m.add_function(wrap_pyfunction!(wire_version, m)?)?;
    m.add_function(wrap_pyfunction!(generate_key, m)?)?;
    m.add_function(wrap_pyfunction!(logging::route_to_python, m)?)?;
    m.add_function(wrap_pyfunction!(logging::route_to_stderr, m)?)?;
    m.add_function(wrap_pyfunction!(logging::drain_logs, m)?)?;
    m.add_function(wrap_pyfunction!(logging::wait_logs, m)?)?;
    m.add_function(wrap_pyfunction!(logging::wait_logs_blocking, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
