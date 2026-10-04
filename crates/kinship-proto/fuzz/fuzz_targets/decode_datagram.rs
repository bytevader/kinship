//! Feeds arbitrary bytes to the datagram receive path in every mode.
//!
//! Three views of the same input:
//! 1. as a plaintext packet (label "golden", so golden vectors make good seeds),
//! 2. as an encrypted packet (exercises header checks; authentication will almost always fail),
//! 3. as the *inner payload* sealed under valid crypto, so the payload parser is reached on every
//!    run. The result must agree with parsing the bytes directly.
#![no_main]

use kinship_proto::{Codec, Key, Limits, Message, PacketKind, Payload};
use libfuzzer_sys::fuzz_target;

fn codecs() -> (Codec, Codec) {
    let limits = Limits::default();
    (
        Codec::insecure_plaintext(b"golden", limits).unwrap(),
        Codec::encrypted(
            b"golden",
            limits,
            vec![Key::from_bytes([7; 32]), Key::from_bytes([8; 32])],
        )
        .unwrap(),
    )
}

fuzz_target!(|data: &[u8]| {
    let (plain, enc) = codecs();

    for codec in [&plain, &enc] {
        let mut buf = data.to_vec();
        if let Ok(p) = codec.open(PacketKind::Datagram, &mut buf) {
            // Accepted packets must be fully iterable.
            assert_eq!(p.iter().count() + p.unknown(), p.count());
        }
    }

    // View 3: differential check against the bare payload parser.
    let limits = Limits::default();
    let direct = Payload::parse(data, &limits);
    for codec in [&plain, &enc] {
        let mut sealed = Vec::new();
        if codec
            .seal_raw(PacketKind::Datagram, data, &[9; 24], &mut sealed)
            .is_err()
        {
            // Only possible when the payload does not fit a datagram.
            assert!(data.len() > codec.max_payload_len(PacketKind::Datagram));
            continue;
        }
        let via = codec.open(PacketKind::Datagram, &mut sealed);
        match (&direct, &via) {
            (Ok(a), Ok(b)) => {
                assert_eq!(a.iter().collect::<Vec<_>>(), b.iter().collect::<Vec<_>>());
                assert_eq!(a.unknown(), b.unknown());
            }
            (Err(a), Err(b)) => assert_eq!(a, b),
            _ => panic!("direct {direct:?} vs sealed {via:?}"),
        }
    }

    // Accepted messages must survive a re-encode.
    if let Ok(p) = direct {
        if p.unknown() == 0 {
            let msgs: Vec<Message<'_>> = p.iter().collect();
            let mut out = Vec::new();
            if plain
                .seal(PacketKind::Stream, &msgs, &[0; 24], &mut out)
                .is_ok()
            {
                let again: Vec<_> = plain
                    .open(PacketKind::Stream, &mut out)
                    .unwrap()
                    .iter()
                    .collect();
                assert_eq!(again, msgs);
            }
        }
    }
});
