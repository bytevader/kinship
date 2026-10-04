//! tokio UDP and TCP driver for kinship-core.

pub use kinship_core::WIRE_VERSION;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_wire_version() {
        assert_eq!(WIRE_VERSION, 1);
    }
}
