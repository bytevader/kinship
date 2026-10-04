//! Feeds arbitrary bytes to the TCP receive path: framing, then packet decoding.
//!
//! The first byte picks how the rest is split into reads, so the reader sees every chunking.
#![no_main]

use kinship_proto::{Codec, FrameReader, Key, Limits, PacketKind};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let Some((&chunk, stream)) = data.split_first() else {
        return;
    };
    let chunk = usize::from(chunk % 64) + 1;
    let limits = Limits {
        max_stream_frame: 1 << 16,
        ..Limits::default()
    };
    let plain = Codec::insecure_plaintext(b"golden", limits).unwrap();
    let enc = Codec::encrypted(b"golden", limits, vec![Key::from_bytes([7; 32])]).unwrap();

    let mut reader = FrameReader::new(limits.max_stream_frame);
    let mut received = 0usize;
    for piece in stream.chunks(chunk) {
        reader.push(piece);
        received += piece.len();
        // The reader never holds more than it was given.
        assert!(reader.buffered() <= received);
        loop {
            match reader.next_frame() {
                Ok(Some(frame)) => {
                    assert!(frame.len() <= limits.max_stream_frame);
                    for codec in [&plain, &enc] {
                        let mut copy = frame.clone();
                        let _ = codec.open(PacketKind::Stream, &mut copy);
                        // The same bytes as an inner payload behind valid crypto.
                        let mut sealed = Vec::new();
                        if codec
                            .seal_raw(PacketKind::Stream, &frame, &[1; 24], &mut sealed)
                            .is_ok()
                        {
                            let _ = codec.open(PacketKind::Stream, &mut sealed);
                        }
                    }
                }
                Ok(None) => break,
                Err(_) => {
                    // Poisoned: the connection would be dropped here.
                    assert!(reader.next_frame().is_err());
                    return;
                }
            }
        }
    }
    let _ = reader.finish();
});
