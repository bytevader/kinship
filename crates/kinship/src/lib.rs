//! SWIM membership and failure detection with Lifeguard, for Rust and Python.

pub use kinship_net::WIRE_VERSION;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_wire_version() {
        assert_eq!(WIRE_VERSION, 1);
    }
}
