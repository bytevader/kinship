//! The metadata tag encoding: an ordered list of non-empty string keys with string values,
//! carried as the `meta` bytes of an Alive record.
//!
//! ```text
//! tags = (klen:varint key[klen] vlen:varint value[vlen])*
//! ```
//!
//! There is no count; the list runs to the end of the blob. Keys are unique, which the decoder
//! enforces. Rust callers that want raw bytes can ignore this module: the wire only sees opaque
//! `meta`.

use core::fmt;

use crate::error::DecodeError;
use crate::wire::{Reader, Sink};

/// Why a tag list could not be encoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[non_exhaustive]
pub enum TagsError {
    /// A key is empty.
    EmptyKey,
    /// Two entries share a key.
    DuplicateKey,
    /// The encoded list is longer than the allowed size.
    TooLarge,
}

impl fmt::Display for TagsError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::EmptyKey => f.write_str("empty tag key"),
            Self::DuplicateKey => f.write_str("duplicate tag key"),
            Self::TooLarge => f.write_str("encoded tags too large"),
        }
    }
}

impl std::error::Error for TagsError {}

/// Encodes `tags` in the given order. `max_len` is the largest encoded size accepted, normally
/// the `max_meta_bytes` config value.
pub fn encode_tags<'t>(
    tags: impl IntoIterator<Item = (&'t str, &'t str)>,
    max_len: usize,
) -> Result<Vec<u8>, TagsError> {
    let mut out = Vec::new();
    let mut seen: Vec<&str> = Vec::new();
    for (k, v) in tags {
        if k.is_empty() {
            return Err(TagsError::EmptyKey);
        }
        if seen.contains(&k) {
            return Err(TagsError::DuplicateKey);
        }
        seen.push(k);
        out.put_bytes(k.as_bytes());
        out.put_bytes(v.as_bytes());
        if out.len() > max_len {
            return Err(TagsError::TooLarge);
        }
    }
    Ok(out)
}

/// A validated tag list borrowed from metadata bytes.
#[derive(Clone, Copy, PartialEq, Eq)]
pub struct Tags<'a> {
    bytes: &'a [u8],
}

impl<'a> Tags<'a> {
    /// Validates `meta` as a tag list: well-formed lengths, UTF-8, non-empty unique keys.
    /// Empty metadata is a valid empty list.
    pub fn parse(meta: &'a [u8]) -> Result<Self, DecodeError> {
        let mut r = Reader::new(meta);
        let mut keys: Vec<&[u8]> = Vec::new();
        while !r.is_empty() {
            let key = r.bytes().map_err(|_| DecodeError::BadTags)?;
            let value = r.bytes().map_err(|_| DecodeError::BadTags)?;
            if key.is_empty()
                || core::str::from_utf8(key).is_err()
                || core::str::from_utf8(value).is_err()
                || keys.contains(&key)
            {
                return Err(DecodeError::BadTags);
            }
            keys.push(key);
        }
        Ok(Self { bytes: meta })
    }

    pub fn iter(&self) -> TagIter<'a> {
        TagIter {
            r: Reader::new(self.bytes),
        }
    }

    /// Looks a key up.
    pub fn get(&self, key: &str) -> Option<&'a str> {
        self.iter().find(|(k, _)| *k == key).map(|(_, v)| v)
    }

    pub fn len(&self) -> usize {
        self.iter().count()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl<'a> IntoIterator for Tags<'a> {
    type Item = (&'a str, &'a str);
    type IntoIter = TagIter<'a>;

    fn into_iter(self) -> TagIter<'a> {
        self.iter()
    }
}

impl fmt::Debug for Tags<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_map().entries(self.iter()).finish()
    }
}

/// Iterator over `(key, value)` pairs in wire order.
pub struct TagIter<'a> {
    r: Reader<'a>,
}

impl<'a> Iterator for TagIter<'a> {
    type Item = (&'a str, &'a str);

    fn next(&mut self) -> Option<Self::Item> {
        if self.r.is_empty() {
            return None;
        }
        // `Tags::parse` validated every entry, so these cannot fail.
        let k = core::str::from_utf8(self.r.bytes().ok()?).ok()?;
        let v = core::str::from_utf8(self.r.bytes().ok()?).ok()?;
        Some((k, v))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn round_trip_keeps_order() {
        let bytes = encode_tags([("role", "api"), ("zone", "eu-1"), ("empty", "")], 512).unwrap();
        let tags = Tags::parse(&bytes).unwrap();
        let got: Vec<_> = tags.iter().collect();
        assert_eq!(got, [("role", "api"), ("zone", "eu-1"), ("empty", "")]);
        assert_eq!(tags.get("zone"), Some("eu-1"));
        assert_eq!(tags.get("nope"), None);
        assert_eq!(tags.len(), 3);
    }

    #[test]
    fn empty_is_valid() {
        assert!(Tags::parse(&[]).unwrap().is_empty());
        assert_eq!(encode_tags([], 0).unwrap(), Vec::<u8>::new());
    }

    #[test]
    fn encoder_rejects_bad_input() {
        assert_eq!(encode_tags([("", "x")], 512), Err(TagsError::EmptyKey));
        assert_eq!(
            encode_tags([("a", "1"), ("a", "2")], 512),
            Err(TagsError::DuplicateKey)
        );
        assert_eq!(
            encode_tags([("key", "0123456789")], 8),
            Err(TagsError::TooLarge)
        );
    }

    #[test]
    fn decoder_rejects_bad_input() {
        for bad in [
            &[0x00, 0x00][..],                     // empty key
            &[0x01, b'a'],                         // missing value
            &[0x01, b'a', 0x05, b'x'],             // value overruns
            &[0x01, 0xff, 0x00],                   // key not UTF-8
            &[0x01, b'a', 0x01, 0xff],             // value not UTF-8
            &[0x01, b'a', 0x00, 0x01, b'a', 0x00], // duplicate key
        ] {
            assert_eq!(Tags::parse(bad), Err(DecodeError::BadTags), "{bad:02x?}");
        }
    }
}
