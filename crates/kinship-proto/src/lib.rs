//! Wire types, binary codec and AEAD framing for kinship.

/// Wire format version spoken by this build.
pub const WIRE_VERSION: u8 = 1;

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn wire_version_is_one() {
        assert_eq!(WIRE_VERSION, 1);
    }
}
