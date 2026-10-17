//! Strict identity parsers, canonical encoders and signature verification.
#![no_main]

use kinship_proto::identity::{Certificate, PublicKey, Revocation, SigningKey};
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let ca = SigningKey::from_bytes([7; 32]);
    let anchors = [ca.public_key()];
    if let Ok(certificate) = Certificate::decode(data) {
        assert_eq!(certificate.encode(), data);
        let _ = certificate.id();
        let _ = certificate.signed_bytes();
        for (now, skew) in [(0, 0), (1, 300), (u64::MAX, 0), (u64::MAX, u64::MAX)] {
            let _ = certificate.verify(&anchors, b"golden", now, skew);
        }
    }
    if let Ok(revocation) = Revocation::decode(data) {
        assert_eq!(revocation.encode(), data);
        let _ = revocation.signed_bytes(b"golden");
        let certificate = Certificate::issue(
            &ca,
            b"golden",
            kinship_proto::NodeId::new("a").unwrap(),
            anchors[0],
            1,
            100,
        )
        .unwrap();
        let _ = revocation.verify_for(&certificate, &anchors, b"golden");
    }
    if let Some((public, rest)) = data.split_first_chunk::<32>() {
        if let Ok(key) = PublicKey::from_bytes(*public) {
            if let Some((signature, message)) = rest.split_first_chunk::<64>() {
                let _ = key.verify(message, signature);
            }
        }
    }
});
