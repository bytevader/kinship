//! Framing for TCP: each frame is a `u32` big-endian length followed by one packet.

use crate::error::DecodeError;

/// Smallest possible packet: magic, version and flags.
const MIN_FRAME: usize = 4;

/// Splits a TCP byte stream into frames without trusting the peer's length.
///
/// The declared length is compared with `max_frame` as soon as the 4-byte prefix is buffered,
/// before any space is set aside for the frame, and the buffer grows only as bytes really
/// arrive. A peer announcing 8 MiB therefore costs nothing until it sends 8 MiB.
///
/// Call [`push`](Self::push) with each chunk read from the socket, then
/// [`next_frame`](Self::next_frame) until it returns `Ok(None)`. After an error the reader is
/// poisoned: the connection should be closed.
#[derive(Debug)]
pub struct FrameReader {
    max_frame: usize,
    buf: Vec<u8>,
    pos: usize,
    failed: Option<DecodeError>,
}

impl FrameReader {
    /// `max_frame` bounds the packet inside a frame, not counting the length prefix.
    pub fn new(max_frame: usize) -> Self {
        Self {
            max_frame,
            buf: Vec::new(),
            pos: 0,
            failed: None,
        }
    }

    /// Appends bytes read from the stream. Ignored once the reader has failed.
    pub fn push(&mut self, data: &[u8]) {
        if self.failed.is_none() {
            self.buf.extend_from_slice(data);
        }
    }

    /// Returns the next complete frame (the packet without its prefix), or `Ok(None)` if more
    /// bytes are needed.
    pub fn next_frame(&mut self) -> Result<Option<Vec<u8>>, DecodeError> {
        if let Some(e) = self.failed {
            return Err(e);
        }
        let pending = &self.buf[self.pos..];
        let Some((prefix, rest)) = pending.split_first_chunk::<4>() else {
            return Ok(None);
        };
        let len = u32::from_be_bytes(*prefix) as usize;
        if len > self.max_frame {
            return Err(self.fail(DecodeError::TooLarge));
        }
        if len < MIN_FRAME {
            return Err(self.fail(DecodeError::Truncated));
        }
        let Some(frame) = rest.get(..len) else {
            return Ok(None);
        };
        let frame = frame.to_vec();
        self.pos += 4 + len;
        if self.pos == self.buf.len() {
            self.buf.clear();
            self.pos = 0;
        } else if self.pos >= self.buf.len() / 2 {
            self.buf.drain(..self.pos);
            self.pos = 0;
        }
        Ok(Some(frame))
    }

    fn fail(&mut self, e: DecodeError) -> DecodeError {
        self.failed = Some(e);
        self.buf = Vec::new();
        self.pos = 0;
        e
    }

    /// Bytes buffered but not yet returned as a frame.
    pub fn buffered(&self) -> usize {
        self.buf.len() - self.pos
    }

    /// Call when the peer closes: errors if it stopped in the middle of a frame.
    pub fn finish(&self) -> Result<(), DecodeError> {
        match (self.failed, self.buffered()) {
            (Some(e), _) => Err(e),
            (None, 0) => Ok(()),
            (None, _) => Err(DecodeError::Truncated),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn frame(payload: &[u8]) -> Vec<u8> {
        let mut v = (payload.len() as u32).to_be_bytes().to_vec();
        v.extend_from_slice(payload);
        v
    }

    #[test]
    fn reassembles_across_chunks() {
        let mut bytes = frame(b"abcdef");
        bytes.extend(frame(b"ghij"));
        let mut r = FrameReader::new(64);
        let mut got = Vec::new();
        for b in &bytes {
            r.push(core::slice::from_ref(b));
            while let Some(f) = r.next_frame().unwrap() {
                got.push(f);
            }
        }
        assert_eq!(got, [b"abcdef".to_vec(), b"ghij".to_vec()]);
        assert_eq!(r.buffered(), 0);
        assert_eq!(r.finish(), Ok(()));
    }

    #[test]
    fn two_frames_in_one_chunk() {
        let mut bytes = frame(b"abcd");
        bytes.extend(frame(b"efgh"));
        let mut r = FrameReader::new(64);
        r.push(&bytes);
        assert_eq!(r.next_frame().unwrap().unwrap(), b"abcd");
        assert_eq!(r.next_frame().unwrap().unwrap(), b"efgh");
        assert_eq!(r.next_frame().unwrap(), None);
    }

    #[test]
    fn oversized_prefix_fails_before_body_arrives() {
        let mut r = FrameReader::new(1024);
        r.push(&(1025u32).to_be_bytes());
        assert_eq!(r.next_frame(), Err(DecodeError::TooLarge));
        // Poisoned: later data is dropped and the error sticks.
        r.push(&[0; 100]);
        assert_eq!(r.buffered(), 0);
        assert_eq!(r.next_frame(), Err(DecodeError::TooLarge));
        assert_eq!(r.finish(), Err(DecodeError::TooLarge));
    }

    #[test]
    fn a_huge_claim_allocates_nothing() {
        let mut r = FrameReader::new(u32::MAX as usize);
        r.push(&u32::MAX.to_be_bytes());
        assert_eq!(r.next_frame(), Ok(None));
        assert!(r.buf.capacity() < 64);
    }

    #[test]
    fn tiny_frames_are_rejected() {
        for len in 0..MIN_FRAME as u32 {
            let mut r = FrameReader::new(64);
            r.push(&len.to_be_bytes());
            assert_eq!(r.next_frame(), Err(DecodeError::Truncated));
        }
    }

    #[test]
    fn eof_mid_frame_is_truncated() {
        let mut r = FrameReader::new(64);
        r.push(&frame(b"abcdef")[..7]);
        assert_eq!(r.next_frame(), Ok(None));
        assert_eq!(r.finish(), Err(DecodeError::Truncated));
    }
}
