use kinship_proto::NodeId;
use kinship_proto::identity::{Certificate, IdentityError, PublicKey, Revocation, SigningKey};

fn hex<const N: usize>(s: &str) -> [u8; N] {
    assert_eq!(s.len(), N * 2);
    core::array::from_fn(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
}

#[test]
fn rfc8032_vectors_through_wrappers() {
    for (seed, public, message, signature) in [
        (
            "9d61b19deffd5a60ba844af492ec2cc44449c5697b326919703bac031cae7f60",
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
            &b""[..],
            "e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e065224901555f\
             b8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b",
        ),
        (
            "4ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb",
            "3d4017c3e843895a92b70aa74d1b7ebc9c982ccf2ec4968cc0cd55f12af4660c",
            &b"\x72"[..],
            "92a009a9f0d4cab8720e820b5f642540a2b27b5416503f8fb3762223ebdb69da\
             085ac1e43e15996e458f3613d0f11d8c387b2eaeb4302aeeb00d291612bb0c00",
        ),
    ] {
        let key = SigningKey::from_bytes(hex(seed));
        let public = PublicKey::from_bytes(hex(public)).unwrap();
        assert_eq!(key.public_key(), public);
        assert_eq!(key.sign(message), hex::<64>(signature));
        public.verify(message, &hex(signature)).unwrap();
        assert!(public.verify(b"wrong message", &hex(signature)).is_err());
        assert_eq!(key.sign(message), key.sign(message));
    }
}

#[test]
fn keys_are_strict_and_secrets_are_redacted() {
    let a = SigningKey::from_bytes([7; 32]);
    assert!(a == SigningKey::from_slice(&[7; 32]).unwrap());
    assert!(a != SigningKey::from_bytes([8; 32]));
    assert!(SigningKey::from_slice(&[7; 31]).is_err());
    assert_eq!(format!("{a:?}"), "SigningKey(REDACTED)");
    for bytes in [[0; 32], [0xff; 32], {
        let mut identity = [0; 32];
        identity[0] = 1;
        identity
    }] {
        assert!(PublicKey::from_bytes(bytes).is_err());
    }
    let mut noncanonical = [0xff; 32];
    noncanonical[0] = 0xed;
    noncanonical[31] = 0x7f;
    assert!(PublicKey::from_bytes(noncanonical).is_err());
    assert!(a.public_key().verify(b"x", &[0; 64]).is_err());
    let mut signature = a.sign(b"x");
    signature[63] |= 0x80;
    assert!(
        a.public_key().verify(b"x", &signature).is_err(),
        "non-reduced S"
    );
    let mut signature = a.sign(b"x");
    signature[..32].fill(0);
    assert!(
        a.public_key().verify(b"x", &signature).is_err(),
        "small-order R"
    );
}

#[test]
fn validity_skew_does_not_wrap_at_integer_boundaries() {
    let ca = SigningKey::from_bytes([1; 32]);
    let c = Certificate::issue(
        &ca,
        b"c",
        NodeId::new("a").unwrap(),
        ca.public_key(),
        u64::MAX - 10,
        u64::MAX,
    )
    .unwrap();
    c.verify(&[ca.public_key()], b"c", u64::MAX, 1).unwrap();
    assert_eq!(
        c.verify(&[ca.public_key()], b"c", u64::MAX, 0),
        Err(IdentityError::Expired)
    );
    c.verify(&[ca.public_key()], b"c", 0, u64::MAX).unwrap();
}

#[test]
fn identity_fuzz_corpus_reaches_canonical_decoders() {
    let certificate = include_bytes!("../fuzz/corpus/decode_certificate/certificate");
    assert_eq!(
        Certificate::decode(certificate).unwrap().encode(),
        certificate
    );
    let revocation = include_bytes!("../fuzz/corpus/decode_certificate/revocation");
    assert_eq!(
        Revocation::decode(revocation).unwrap().encode(),
        *revocation
    );
}

#[test]
fn certificate_validation_and_canonical_domain() {
    let ca = SigningKey::from_bytes([1; 32]);
    let member = SigningKey::from_bytes([2; 32]);
    let cert = Certificate::issue(
        &ca,
        b"cluster",
        NodeId::new("cache-03").unwrap(),
        member.public_key(),
        1000,
        2000,
    )
    .unwrap();
    let bytes = cert.encode();
    assert_eq!(bytes.len(), 130 + "cache-03".len());
    assert_eq!(Certificate::decode(&bytes).unwrap(), cert);
    assert_eq!(Certificate::decode(&bytes).unwrap().encode(), bytes);
    let mut expected = b"kinship v2 \x0b".to_vec();
    expected.extend_from_slice(&blake3::hash(b"cluster").as_bytes()[..8]);
    expected.extend_from_slice(&bytes[..bytes.len() - 64]);
    assert_eq!(cert.signed_bytes(), expected);
    assert_eq!(cert.id(), blake3::hash(&bytes).as_bytes()[..8]);
    cert.verify(&[ca.public_key()], b"cluster", 1000, 0)
        .unwrap();
    cert.verify(&[ca.public_key()], b"cluster", 1999, 0)
        .unwrap();
    assert_eq!(
        cert.verify(&[ca.public_key()], b"cluster", 2000, 0),
        Err(IdentityError::Expired)
    );
    assert_eq!(
        cert.verify(&[ca.public_key()], b"cluster", 999, 0),
        Err(IdentityError::NotYetValid)
    );
    cert.verify(&[ca.public_key()], b"cluster", 700, 300)
        .unwrap();
    assert!(cert.verify(&[ca.public_key()], b"other", 1500, 0).is_err());
    assert!(
        cert.verify(&[member.public_key()], b"cluster", 1500, 0)
            .is_err()
    );
    for n in 0..bytes.len() {
        assert!(Certificate::decode(&bytes[..n]).is_err(), "prefix {n}");
    }
    let mut extra = bytes.clone();
    extra.push(0);
    assert!(Certificate::decode(&extra).is_err());
    for at in 0..bytes.len() {
        let mut altered = bytes.clone();
        altered[at] ^= 1;
        if let Ok(c) = Certificate::decode(&altered) {
            assert!(
                c.verify(&[ca.public_key()], b"cluster", 1500, 0).is_err(),
                "byte {at}"
            );
        }
    }
    assert!(
        Certificate::issue(
            &ca,
            b"cluster",
            NodeId::new("x").unwrap(),
            member.public_key(),
            2,
            2
        )
        .is_err()
    );
}

#[test]
fn revocations_bind_the_ca_cluster_certificate_and_retention() {
    let ca = SigningKey::from_bytes([1; 32]);
    let other = SigningKey::from_bytes([3; 32]);
    let cert = Certificate::issue(
        &ca,
        b"c",
        NodeId::new("n").unwrap(),
        other.public_key(),
        1,
        100,
    )
    .unwrap();
    let rev = Revocation::issue(&ca, b"c", &cert).unwrap();
    let bytes = rev.encode();
    assert_eq!(bytes.len(), 88);
    assert_eq!(Revocation::decode(&bytes).unwrap(), rev);
    rev.verify_for(&cert, &[ca.public_key()], b"c").unwrap();
    assert!(rev.verify_for(&cert, &[other.public_key()], b"c").is_err());
    assert!(rev.verify_for(&cert, &[ca.public_key()], b"other").is_err());
    assert!(Revocation::issue(&other, b"c", &cert).is_err());
    let next = Certificate::issue(&ca, b"c", cert.name(), cert.key(), 2, 101).unwrap();
    assert!(rev.verify_for(&next, &[ca.public_key()], b"c").is_err());
    for n in 0..88 {
        assert!(Revocation::decode(&bytes[..n]).is_err());
    }
    assert!(Revocation::decode(&[bytes.as_slice(), &[0]].concat()).is_err());
    for at in 0..bytes.len() {
        let mut altered = bytes;
        altered[at] ^= 1;
        if let Ok(r) = Revocation::decode(&altered) {
            assert!(r.verify_for(&cert, &[ca.public_key()], b"c").is_err());
        }
    }
}
