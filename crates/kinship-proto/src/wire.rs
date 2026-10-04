//! Primitive readers and writers shared by the codec modules.

use crate::error::DecodeError;

/// Destination for encoded bytes; lets one encoder both write and measure.
pub(crate) trait Sink {
    fn put(&mut self, bytes: &[u8]);

    fn put_u8(&mut self, b: u8) {
        self.put(&[b]);
    }

    fn put_u16(&mut self, v: u16) {
        self.put(&v.to_be_bytes());
    }

    fn put_u32(&mut self, v: u32) {
        self.put(&v.to_be_bytes());
    }

    fn put_varint(&mut self, mut v: u32) {
        while v >= 0x80 {
            self.put_u8((v & 0x7f) as u8 | 0x80);
            v >>= 7;
        }
        self.put_u8(v as u8);
    }

    /// A varint length followed by the bytes.
    fn put_bytes(&mut self, bytes: &[u8]) {
        self.put_varint(bytes.len() as u32);
        self.put(bytes);
    }
}

impl Sink for Vec<u8> {
    fn put(&mut self, bytes: &[u8]) {
        self.extend_from_slice(bytes);
    }
}

/// A sink that only counts.
#[derive(Default)]
pub(crate) struct Count(pub usize);

impl Sink for Count {
    fn put(&mut self, bytes: &[u8]) {
        self.0 += bytes.len();
    }
}

/// Encoded size of a varint.
pub(crate) fn varint_len(v: u32) -> usize {
    match v {
        0..=0x7f => 1,
        0x80..=0x3fff => 2,
        0x4000..=0x1f_ffff => 3,
        0x20_0000..=0x0fff_ffff => 4,
        _ => 5,
    }
}

/// A bounds-checked cursor over a borrowed slice. Every read either succeeds or returns
/// [`DecodeError::Truncated`]; nothing here can panic or allocate.
#[derive(Clone, Copy)]
pub(crate) struct Reader<'a> {
    buf: &'a [u8],
}

impl<'a> Reader<'a> {
    pub(crate) fn new(buf: &'a [u8]) -> Self {
        Self { buf }
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.buf.is_empty()
    }

    pub(crate) fn rest(&self) -> &'a [u8] {
        self.buf
    }

    pub(crate) fn take(&mut self, n: usize) -> Result<&'a [u8], DecodeError> {
        let (head, tail) = self.buf.split_at_checked(n).ok_or(DecodeError::Truncated)?;
        self.buf = tail;
        Ok(head)
    }

    pub(crate) fn array<const N: usize>(&mut self) -> Result<[u8; N], DecodeError> {
        let mut out = [0u8; N];
        out.copy_from_slice(self.take(N)?);
        Ok(out)
    }

    pub(crate) fn u8(&mut self) -> Result<u8, DecodeError> {
        Ok(self.array::<1>()?[0])
    }

    pub(crate) fn u16(&mut self) -> Result<u16, DecodeError> {
        Ok(u16::from_be_bytes(self.array()?))
    }

    pub(crate) fn u32(&mut self) -> Result<u32, DecodeError> {
        Ok(u32::from_be_bytes(self.array()?))
    }

    /// Reads a minimal LEB128 varint that fits a `u32`.
    pub(crate) fn varint(&mut self) -> Result<u32, DecodeError> {
        let mut value: u32 = 0;
        for i in 0..5 {
            let byte = self.u8().map_err(|_| DecodeError::BadVarint)?;
            let bits = u32::from(byte & 0x7f);
            if i == 4 && bits > 0x0f {
                return Err(DecodeError::BadVarint);
            }
            value |= bits << (7 * i);
            if byte & 0x80 == 0 {
                if i > 0 && bits == 0 {
                    return Err(DecodeError::BadVarint);
                }
                return Ok(value);
            }
        }
        Err(DecodeError::BadVarint)
    }

    /// Reads a varint length, then that many bytes.
    pub(crate) fn bytes(&mut self) -> Result<&'a [u8], DecodeError> {
        let len = self.varint()? as usize;
        self.take(len).map_err(|_| DecodeError::BadLength)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn enc(v: u32) -> Vec<u8> {
        let mut out = Vec::new();
        out.put_varint(v);
        out
    }

    #[test]
    fn varint_boundaries_round_trip() {
        for v in [
            0,
            1,
            127,
            128,
            16383,
            16384,
            0x1f_ffff,
            0x20_0000,
            0x0fff_ffff,
            0x1000_0000,
            u32::MAX,
        ] {
            let bytes = enc(v);
            assert_eq!(bytes.len(), varint_len(v), "len of {v}");
            let mut r = Reader::new(&bytes);
            assert_eq!(r.varint().unwrap(), v);
            assert!(r.is_empty());
        }
    }

    #[test]
    fn varint_rejects_non_minimal_and_overflow() {
        for bad in [
            &[0x80, 0x00][..],
            &[0xff, 0x00],
            &[0x80, 0x80, 0x80, 0x80, 0x00],
            &[0xff, 0xff, 0xff, 0xff, 0x1f],
            &[0x80, 0x80, 0x80, 0x80, 0x80, 0x01],
            &[0x80],
            &[],
        ] {
            assert_eq!(
                Reader::new(bad).varint(),
                Err(DecodeError::BadVarint),
                "{bad:02x?}"
            );
        }
    }

    #[test]
    fn take_past_end_is_truncated() {
        let mut r = Reader::new(&[1, 2]);
        assert_eq!(r.take(3), Err(DecodeError::Truncated));
        assert_eq!(r.take(2).unwrap(), &[1, 2]);
        assert_eq!(r.u8(), Err(DecodeError::Truncated));
    }
}
