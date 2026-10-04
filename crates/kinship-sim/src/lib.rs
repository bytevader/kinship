//! Deterministic network simulator for kinship-core.

#[cfg(test)]
mod tests {
    #[test]
    fn it_links_against_core() {
        assert_eq!(kinship_core::WIRE_VERSION, 1);
    }
}
