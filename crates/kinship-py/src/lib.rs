//! PyO3 bindings for kinship. The compiled module is `kinship._kinship`.

use pyo3::prelude::*;

/// Wire format version spoken by this build.
#[pyfunction]
fn wire_version() -> u8 {
    kinship_net::WIRE_VERSION
}

#[pymodule]
fn _kinship(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_function(wrap_pyfunction!(wire_version, m)?)?;
    m.add("__version__", env!("CARGO_PKG_VERSION"))?;
    Ok(())
}
