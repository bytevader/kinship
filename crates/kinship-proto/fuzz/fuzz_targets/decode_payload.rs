//! Feeds arbitrary bytes straight to the inner payload parser and the metadata tag parser.
#![no_main]

use kinship_proto::tags::{Tags, encode_tags};
use kinship_proto::{Codec, Limits, Message, PacketKind, Payload, v2};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let limits = Limits::default();

    if let Ok(payload) = v2::Payload::parse(data, &limits) {
        let messages: Vec<_> = payload.iter().collect();
        assert_eq!(messages.len() + payload.unknown(), payload.count());
        for message in &messages {
            let _ = message.encoded_len();
            let nonce = matches!(message, v2::Message::UserMessage { .. }).then_some(&[7; 24]);
            let _ = message.signed_bytes(b"golden", nonce);
            if let v2::Message::PushPull(p) = message {
                assert_eq!(p.records.iter().count(), p.records.len());
                assert_eq!(
                    p.known_certificates.iter().count(),
                    p.known_certificates.len()
                );
                for record in p.records.iter() {
                    let _ = record.alive_message();
                    let _ = record.left_message();
                }
            }
        }
        if payload.unknown() == 0 {
            assert_eq!(v2::encode_payload(&messages, &limits).unwrap(), data);
        }
    }

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
                // User data is bounded by the payload alone; the core checks its own limits.
                Message::UserMessage(u) => {
                    assert!(u.data.len() < data.len());
                    assert!(!u.to.as_str().is_empty() && !u.from.as_str().is_empty());
                }
                Message::UserBroadcast(b) => {
                    assert!(b.data.len() < data.len());
                    assert!(!b.from.as_str().is_empty());
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
