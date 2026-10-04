//! Feeds arbitrary bytes straight to the inner payload parser and the metadata tag parser.
#![no_main]

use kinship_proto::tags::{Tags, encode_tags};
use kinship_proto::{Codec, Limits, Message, PacketKind, Payload};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = Limits::default();

    if let Ok(p) = Payload::parse(data, &limits) {
        let msgs: Vec<Message<'_>> = p.iter().collect();
        assert_eq!(msgs.len() + p.unknown(), p.count());
        // Touch everything a consumer would: nested record lists and their metadata.
        for m in &msgs {
            let _ = m.encoded_len();
            match m {
                Message::PushPull(pp) => {
                    assert_eq!(pp.records.iter().count(), pp.records.len());
                    for rec in pp.records.iter() {
                        assert!(rec.alive.meta.len() <= limits.max_meta_bytes);
                        let _ = Tags::parse(rec.alive.meta).map(|t| t.iter().count());
                    }
                }
                Message::Alive(a) => {
                    assert!(a.meta.len() <= limits.max_meta_bytes);
                    let _ = Tags::parse(a.meta).map(|t| t.iter().count());
                }
                _ => {}
            }
        }
        // A payload with only known messages re-encodes to something that decodes the same.
        if p.unknown() == 0 {
            let codec = Codec::insecure_plaintext(b"", limits).unwrap();
            let mut out = Vec::new();
            if codec
                .seal(PacketKind::Stream, &msgs, &[0; 24], &mut out)
                .is_ok()
            {
                let again: Vec<_> = codec
                    .open(PacketKind::Stream, &mut out)
                    .unwrap()
                    .iter()
                    .collect();
                assert_eq!(again, msgs);
            }
        }
    }

    if let Ok(t) = Tags::parse(data) {
        let pairs: Vec<_> = t.iter().collect();
        assert_eq!(pairs.len(), t.len());
        let again = encode_tags(pairs.iter().copied(), usize::MAX).unwrap();
        assert_eq!(again, data, "tag encoding must be canonical");
    }
});
