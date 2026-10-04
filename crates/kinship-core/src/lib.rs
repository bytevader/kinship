//! Sans-IO SWIM and Lifeguard protocol state machine.

pub use kinship_proto::WIRE_VERSION;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn exposes_wire_version() {
        assert_eq!(WIRE_VERSION, 1);
    }
}
