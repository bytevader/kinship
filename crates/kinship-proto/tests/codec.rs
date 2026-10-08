//! Behavioural tests of the codec: envelope checks, limits, forward compatibility.

use core::net::SocketAddr;

use kinship_proto::{
    Alive, Codec, DecodeError, EncodeError, FrameReader, Key, KeyError, Limits, Message, NodeId,
    PacketKind, Payload, Ping, PushPull, Record, Records, State, Suspect, kind,
};

const NONCE: [u8; 24] = [7; 24];

fn key(n: u8) -> Key {
    Key::from_bytes([n; 32])
}

fn enc(label: &[u8], keys: &[u8]) -> Codec {
    Codec::encrypted(
        label,
        Limits::default(),
        keys.iter().map(|&n| key(n)).collect(),
    )
    .unwrap()
}

fn plain(label: &[u8]) -> Codec {
    Codec::insecure_plaintext(label, Limits::default()).unwrap()
}

fn addr(s: &str) -> SocketAddr {
    s.parse().unwrap()
}

fn id(s: &str) -> NodeId<'_> {
    NodeId::new(s).unwrap()
}

fn ping() -> Message<'static> {
    Message::Ping(Ping {
        seq: 9,
        target: id("b"),
        source: id("a"),
        source_addr: addr("10.0.0.1:7946"),
    })
}

fn alive<'a>(name: &'a str, meta: &'a [u8]) -> Alive<'a> {
    Alive {
        inc: 3,
        node: id(name),
        addr: addr("[::1]:7946"),
        meta,
        vmin: 1,
        vmax: 1,
    }
}

fn seal(c: &Codec, kind: PacketKind, msgs: &[Message<'_>]) -> Vec<u8> {
    let mut out = Vec::new();
    c.seal(kind, msgs, &NONCE, &mut out).unwrap();
    out
}

fn open_all(c: &Codec, kind: PacketKind, bytes: &[u8]) -> Result<Vec<String>, DecodeError> {
    let mut buf = bytes.to_vec();
    let p = c.open(kind, &mut buf)?;
    Ok(p.iter().map(|m| format!("{m:?}")).collect())
}

#[test]
fn round_trips_in_every_mode() {
    let a = alive("n1", b"meta");
    let b = alive("n2", b"");
    let records = [
        Record {
            state: State::Alive,
            alive: a,
        },
        Record {
            state: State::Left,
            alive: b,
        },
    ];
    let msgs = [
        ping(),
        Message::Ack { seq: 1 },
        Message::Alive(a),
        Message::Suspect(Suspect {
            inc: 4,
            node: id("x"),
            from: id("y"),
        }),
        Message::PushPull(PushPull {
            join: true,
            records: Records::Slice(&records),
        }),
    ];
    for codec in [plain(b"c"), enc(b"c", &[1])] {
        for kind in [PacketKind::Datagram, PacketKind::Stream] {
            let bytes = seal(&codec, kind, &msgs);
            let mut buf = bytes.clone();
            let got: Vec<_> = codec.open(kind, &mut buf).unwrap().iter().collect();
            assert_eq!(got, msgs);
        }
    }
}

#[test]
fn overhead_is_48_encrypted_and_12_plain() {
    let m = [Message::Ack { seq: 1 }];
    let inner = 1 + m[0].encoded_len();
    assert_eq!(
        seal(&enc(b"", &[1]), PacketKind::Datagram, &m).len(),
        inner + 48
    );
    assert_eq!(
        seal(&plain(b""), PacketKind::Datagram, &m).len(),
        inner + 12
    );
    assert_eq!(enc(b"", &[1]).overhead(), 48);
    assert_eq!(plain(b"").overhead(), 12);
}

#[test]
fn encoded_len_matches_what_is_written() {
    let a = alive("n1", &[0; 100]);
    for m in [ping(), Message::Alive(a), Message::Nack { seq: u32::MAX }] {
        let bytes = seal(&plain(b""), PacketKind::Datagram, &[m]);
        assert_eq!(bytes.len(), 12 + 1 + m.encoded_len());
    }
}

#[test]
fn every_single_bit_flip_is_rejected() {
    let codec = enc(b"cluster", &[1]);
    let bytes = seal(
        &codec,
        PacketKind::Datagram,
        &[ping(), Message::Ack { seq: 2 }],
    );
    for bit in 0..bytes.len() * 8 {
        let mut bad = bytes.clone();
        bad[bit / 8] ^= 1 << (bit % 8);
        assert!(
            open_all(&codec, PacketKind::Datagram, &bad).is_err(),
            "bit {bit} accepted"
        );
    }
}

#[test]
fn every_truncation_is_rejected() {
    for codec in [plain(b"c"), enc(b"c", &[1])] {
        let bytes = seal(
            &codec,
            PacketKind::Datagram,
            &[ping(), Message::Ack { seq: 2 }],
        );
        for len in 0..bytes.len() {
            assert!(
                open_all(&codec, PacketKind::Datagram, &bytes[..len]).is_err(),
                "{len} of {} accepted",
                bytes.len()
            );
        }
    }
}

#[test]
fn failed_authentication_leaves_the_buffer_untouched() {
    let codec = enc(b"c", &[1]);
    let mut bytes = seal(&codec, PacketKind::Datagram, &[ping()]);
    let last = bytes.len() - 1;
    bytes[last] ^= 1;
    let before = bytes.clone();
    assert_eq!(
        codec.open(PacketKind::Datagram, &mut bytes).unwrap_err(),
        DecodeError::AuthFailed
    );
    assert_eq!(bytes, before);
}

#[test]
fn cluster_label_is_bound_in_both_modes() {
    let a = enc(b"alpha", &[1]);
    let b = enc(b"beta", &[1]);
    let bytes = seal(&a, PacketKind::Datagram, &[ping()]);
    assert_eq!(
        open_all(&b, PacketKind::Datagram, &bytes),
        Err(DecodeError::AuthFailed)
    );
    assert!(open_all(&a, PacketKind::Datagram, &bytes).is_ok());

    let a = plain(b"alpha");
    let b = plain(b"beta");
    let bytes = seal(&a, PacketKind::Datagram, &[ping()]);
    assert_eq!(
        open_all(&b, PacketKind::Datagram, &bytes),
        Err(DecodeError::WrongCluster)
    );
}

#[test]
fn encryption_mode_must_match() {
    let e = enc(b"c", &[1]);
    let p = plain(b"c");
    let from_e = seal(&e, PacketKind::Datagram, &[ping()]);
    let from_p = seal(&p, PacketKind::Datagram, &[ping()]);
    assert_eq!(
        open_all(&p, PacketKind::Datagram, &from_e),
        Err(DecodeError::EncryptionMismatch)
    );
    // No downgrade: an encrypting node never accepts a plaintext packet.
    assert_eq!(
        open_all(&e, PacketKind::Datagram, &from_p),
        Err(DecodeError::EncryptionMismatch)
    );
}

#[test]
fn datagram_and_stream_frames_do_not_cross() {
    for codec in [plain(b"c"), enc(b"c", &[1])] {
        let d = seal(&codec, PacketKind::Datagram, &[ping()]);
        let s = seal(&codec, PacketKind::Stream, &[ping()]);
        assert_eq!(
            open_all(&codec, PacketKind::Stream, &d),
            Err(DecodeError::WrongPacketKind)
        );
        assert_eq!(
            open_all(&codec, PacketKind::Datagram, &s),
            Err(DecodeError::WrongPacketKind)
        );
    }
}

#[test]
fn header_checks() {
    let codec = plain(b"c");
    let good = seal(&codec, PacketKind::Datagram, &[ping()]);

    let mut bad = good.clone();
    bad[0] = b'x';
    assert_eq!(
        open_all(&codec, PacketKind::Datagram, &bad),
        Err(DecodeError::BadMagic)
    );

    for v in [0u8, 2, 255] {
        let mut bad = good.clone();
        bad[2] = v;
        assert_eq!(
            open_all(&codec, PacketKind::Datagram, &bad),
            Err(DecodeError::UnsupportedVersion(v))
        );
    }

    for bit in 2..8 {
        let mut bad = good.clone();
        bad[3] |= 1 << bit;
        assert_eq!(
            open_all(&codec, PacketKind::Datagram, &bad),
            Err(DecodeError::ReservedFlags)
        );
    }

    assert_eq!(
        open_all(&codec, PacketKind::Datagram, &[]),
        Err(DecodeError::Truncated)
    );
    assert_eq!(
        open_all(&codec, PacketKind::Datagram, b"kn"),
        Err(DecodeError::Truncated)
    );
}

#[test]
fn keyring_semantics_first_seals_any_opens() {
    let old = enc(b"c", &[1]);
    let new = enc(b"c", &[2]);
    let both = enc(b"c", &[2, 1]);
    let from_old = seal(&old, PacketKind::Datagram, &[ping()]);
    let from_new = seal(&new, PacketKind::Datagram, &[ping()]);
    let from_both = seal(&both, PacketKind::Datagram, &[ping()]);

    assert!(open_all(&both, PacketKind::Datagram, &from_old).is_ok());
    assert!(open_all(&both, PacketKind::Datagram, &from_new).is_ok());
    assert_eq!(from_both, from_new, "keys[0] seals");
    assert!(matches!(
        open_all(&new, PacketKind::Datagram, &from_old),
        Err(DecodeError::UnknownKey(_))
    ));
    assert!(DecodeError::UnknownKey(0).is_auth_failure());
    assert!(DecodeError::AuthFailed.is_auth_failure());
    assert!(!DecodeError::BadMagic.is_auth_failure());
}

#[test]
fn wrong_key_with_matching_id_fails_authentication_not_lookup() {
    // Forge a packet that claims the right key id but was sealed with another key.
    let victim = enc(b"c", &[1]);
    let attacker = enc(b"c", &[9]);
    let mut forged = seal(&attacker, PacketKind::Datagram, &[ping()]);
    forged[4..8].copy_from_slice(&key(1).id().to_be_bytes());
    assert_eq!(
        open_all(&victim, PacketKind::Datagram, &forged),
        Err(DecodeError::AuthFailed)
    );
}

#[test]
fn a_header_check_passes_what_its_codec_could_open_and_nothing_else() {
    let both = enc(b"c", &[1, 2]);
    let check = both.header_check();
    for packet in [
        seal(&enc(b"c", &[1]), PacketKind::Stream, &[ping()]),
        seal(&enc(b"c", &[2]), PacketKind::Stream, &[ping()]),
    ] {
        assert_eq!(check.check(PacketKind::Stream, &packet[..8]), Ok(()));
        assert_eq!(
            check.check(PacketKind::Datagram, &packet),
            Err(DecodeError::WrongPacketKind)
        );
    }
    let other_key = seal(&enc(b"c", &[3]), PacketKind::Stream, &[ping()]);
    assert_eq!(
        check.check(PacketKind::Stream, &other_key),
        Err(DecodeError::UnknownKey(key(3).id()))
    );
    let plain_c = seal(&plain(b"c"), PacketKind::Stream, &[ping()]);
    assert_eq!(
        check.check(PacketKind::Stream, &plain_c),
        Err(DecodeError::EncryptionMismatch)
    );
    assert_eq!(
        check.check(PacketKind::Stream, &other_key[..7]),
        Err(DecodeError::Truncated)
    );
    let mut bad = seal(&enc(b"c", &[1]), PacketKind::Stream, &[ping()]);
    bad[0] = b'x';
    assert_eq!(
        check.check(PacketKind::Stream, &bad),
        Err(DecodeError::BadMagic)
    );

    // Plaintext checks the start of the label's hash in place of a key id.
    let check = plain(b"c").header_check();
    assert_eq!(check.check(PacketKind::Stream, &plain_c), Ok(()));
    let plain_d = seal(&plain(b"d"), PacketKind::Stream, &[ping()]);
    assert_eq!(
        check.check(PacketKind::Stream, &plain_d),
        Err(DecodeError::WrongCluster)
    );
    let sealed = seal(&enc(b"c", &[1]), PacketKind::Stream, &[ping()]);
    assert_eq!(
        check.check(PacketKind::Stream, &sealed),
        Err(DecodeError::EncryptionMismatch)
    );

    // A key installed later passes only once a new check is taken.
    let mut codec = enc(b"c", &[1]);
    let before = codec.header_check();
    codec.install_key(key(3)).unwrap();
    assert!(before.check(PacketKind::Stream, &other_key).is_err());
    assert_eq!(
        codec.header_check().check(PacketKind::Stream, &other_key),
        Ok(())
    );
}

#[test]
fn key_debug_never_prints_key_bytes() {
    let s = format!("{:?}", Key::from_bytes([0xAB; 32]));
    assert!(!s.to_lowercase().contains("abab"));
    assert!(s.starts_with("Key("));
    assert_eq!(Key::from_slice(&[0; 31]), None);
    assert!(Key::from_slice(&[0; 32]).is_some());
}

#[test]
fn keys_parse_from_base64() {
    let want = Key::from_bytes(core::array::from_fn(|i| i as u8));
    let text = "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=";
    assert_eq!(Key::from_base64(text), Ok(want.clone()));
    assert_eq!(Key::from_base64(&format!(" {text}\n")), Ok(want.clone()));
    assert_eq!(
        Key::from_base64(text.trim_end_matches('=')),
        Ok(want.clone())
    );
    assert_eq!(want.to_base64(), text);
    for fill in [0x00, 0xff, 0x5a] {
        let key = Key::from_bytes([fill; 32]);
        assert_eq!(Key::from_base64(&key.to_base64()), Ok(key));
    }

    let short = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA==";
    let long = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
    assert_eq!(Key::from_base64(short), Err(KeyError::WrongLength));
    assert_eq!(Key::from_base64(long), Err(KeyError::WrongLength));
    assert_eq!(Key::from_base64(""), Err(KeyError::WrongLength));
    for bad in [
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8===",
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh-=",
        "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh9=",
        "A",
    ] {
        assert_eq!(Key::from_base64(bad), Err(KeyError::NotBase64), "{bad}");
    }
}

#[test]
fn nonce_is_not_reused_by_the_codec() {
    // The caller picks the nonce; the codec must put exactly that nonce on the wire.
    let codec = enc(b"c", &[1]);
    let mut a = Vec::new();
    let mut b = Vec::new();
    codec
        .seal(PacketKind::Datagram, &[ping()], &[1; 24], &mut a)
        .unwrap();
    codec
        .seal(PacketKind::Datagram, &[ping()], &[2; 24], &mut b)
        .unwrap();
    assert_eq!(&a[8..32], &[1; 24]);
    assert_eq!(&b[8..32], &[2; 24]);
    assert_ne!(a[32..], b[32..], "different nonce, different ciphertext");
}

// ---- size limits -------------------------------------------------------------------------

#[test]
fn datagram_limit_is_total_size_and_enforced_on_seal() {
    let codec = enc(b"c", &[1]);
    let big = alive("n", &[0; 512]);
    let mut out = vec![0xEE];
    let mut n = 0;
    let mut msgs = Vec::new();
    loop {
        msgs.push(Message::Alive(big));
        let mut probe = Vec::new();
        match codec.seal(PacketKind::Datagram, &msgs, &NONCE, &mut probe) {
            Ok(()) => {
                assert!(probe.len() <= 1400);
                n += 1;
            }
            Err(e) => {
                assert_eq!(e, EncodeError::TooLarge);
                break;
            }
        }
    }
    assert!(n >= 1);
    msgs.pop();
    codec
        .seal(PacketKind::Datagram, &msgs, &NONCE, &mut out)
        .unwrap();
    assert_eq!(out[0], 0xEE, "existing bytes are preserved");

    msgs.push(Message::Alive(big));
    let before = out.clone();
    assert_eq!(
        codec.seal(PacketKind::Datagram, &msgs, &NONCE, &mut out),
        Err(EncodeError::TooLarge)
    );
    assert_eq!(out, before, "failed seal leaves out untouched");
}

#[test]
fn exactly_at_the_limit_is_accepted_and_one_over_is_not() {
    let limits = Limits {
        udp_max_payload: 300,
        ..Limits::default()
    };
    let codec = Codec::encrypted(b"c", limits, vec![key(1)]).unwrap();
    let meta = vec![0u8; 512];
    let mut largest = None;
    for n in 0..=512 {
        let a = alive("ab", &meta[..n]);
        let mut out = Vec::new();
        match codec.seal(PacketKind::Datagram, &[Message::Alive(a)], &NONCE, &mut out) {
            Ok(()) => largest = Some((n, out.len())),
            Err(e) => {
                assert_eq!(e, EncodeError::TooLarge);
                break;
            }
        }
    }
    let (n, len) = largest.unwrap();
    // Varint framing makes the size jump in steps, so the packet fills the limit to within one.
    assert!((299..=300).contains(&len), "largest packet is {len} bytes");
    let mut out = Vec::new();
    let over = alive("ab", &meta[..n + 1]);
    assert_eq!(
        codec.seal(
            PacketKind::Datagram,
            &[Message::Alive(over)],
            &NONCE,
            &mut out
        ),
        Err(EncodeError::TooLarge)
    );
    // Opening enforces the same limit on the wire.
    let mut buf = vec![0u8; 301];
    assert_eq!(
        codec.open(PacketKind::Datagram, &mut buf).unwrap_err(),
        DecodeError::TooLarge
    );
    let mut sealed = Vec::new();
    codec
        .seal(
            PacketKind::Datagram,
            &[Message::Alive(alive("ab", &meta[..n]))],
            &NONCE,
            &mut sealed,
        )
        .unwrap();
    assert!(codec.open(PacketKind::Datagram, &mut sealed).is_ok());
}

#[test]
fn oversized_input_is_rejected_before_any_parsing() {
    let codec = plain(b"c");
    let mut buf = vec![0u8; 1401];
    assert_eq!(
        codec.open(PacketKind::Datagram, &mut buf).unwrap_err(),
        DecodeError::TooLarge
    );
    // A stream frame may be bigger than a datagram.
    let mut buf = vec![0u8; 1401];
    assert_ne!(
        codec.open(PacketKind::Stream, &mut buf).unwrap_err(),
        DecodeError::TooLarge
    );
}

#[test]
fn metadata_cap_is_enforced_both_ways() {
    let codec = plain(b"c");
    let ok = alive("n", &[1; 512]);
    let too_big = alive("n", &[1; 513]);
    let mut out = Vec::new();
    codec
        .seal(PacketKind::Stream, &[Message::Alive(ok)], &NONCE, &mut out)
        .unwrap();
    assert_eq!(
        codec.seal(
            PacketKind::Stream,
            &[Message::Alive(too_big)],
            &NONCE,
            &mut out
        ),
        Err(EncodeError::MetaTooLarge)
    );
    // A lenient sender cannot get oversized metadata past a strict receiver.
    let lenient = Codec::insecure_plaintext(
        b"c",
        Limits {
            max_meta_bytes: 1024,
            ..Limits::default()
        },
    )
    .unwrap();
    let mut out = Vec::new();
    lenient
        .seal(
            PacketKind::Stream,
            &[Message::Alive(too_big)],
            &NONCE,
            &mut out,
        )
        .unwrap();
    assert_eq!(
        open_all(&codec, PacketKind::Stream, &out),
        Err(DecodeError::MetaTooLarge)
    );
}

#[test]
fn seal_rejects_empty_and_invalid_versions() {
    let codec = plain(b"c");
    let mut out = Vec::new();
    assert_eq!(
        codec.seal(PacketKind::Datagram, &[], &NONCE, &mut out),
        Err(EncodeError::Empty)
    );
    for (vmin, vmax) in [(0, 1), (2, 1)] {
        let a = Alive {
            vmin,
            vmax,
            ..alive("n", b"")
        };
        assert_eq!(
            codec.seal(PacketKind::Datagram, &[Message::Alive(a)], &NONCE, &mut out),
            Err(EncodeError::BadVersionRange)
        );
    }
}

#[test]
fn codec_config_is_validated() {
    assert!(Codec::encrypted(b"c", Limits::default(), vec![]).is_err());
    assert!(Codec::insecure_plaintext(&[0; 256], Limits::default()).is_err());
    assert!(Codec::insecure_plaintext(&[0; 255], Limits::default()).is_ok());
    let tiny = Limits {
        udp_max_payload: 40,
        ..Limits::default()
    };
    assert!(Codec::encrypted(b"c", tiny, vec![key(1)]).is_err());
    assert!(Codec::insecure_plaintext(b"c", tiny).is_ok());
}

// ---- forward compatibility ---------------------------------------------------------------

/// A payload of raw messages: `(type, body)` pairs.
fn raw_payload(msgs: &[(u8, &[u8])]) -> Vec<u8> {
    let mut v = vec![msgs.len() as u8];
    for (ty, body) in msgs {
        v.push(*ty);
        assert!(body.len() < 128);
        v.push(body.len() as u8);
        v.extend_from_slice(body);
    }
    v
}

fn parse_raw(inner: &[u8]) -> Result<Vec<Message<'_>>, DecodeError> {
    Ok(Payload::parse(inner, &Limits::default())?.iter().collect())
}

#[test]
fn unknown_message_types_are_skipped_in_place() {
    let ack = 5u32.to_be_bytes();
    let inner = raw_payload(&[
        (0x00, b"reserved zero"),
        (kind::ACK, &ack),
        (0x09, b"future"),
        (0x7f, b""),
        (0x80, b"user range"),
        (0xff, b"x"),
        (kind::NACK, &ack),
    ]);
    let p = Payload::parse(&inner, &Limits::default()).unwrap();
    assert_eq!(p.count(), 7);
    assert_eq!(p.unknown(), 5);
    assert_eq!(
        p.iter().collect::<Vec<_>>(),
        [Message::Ack { seq: 5 }, Message::Nack { seq: 5 }]
    );
}

#[test]
fn trailing_bytes_inside_a_known_body_are_ignored() {
    // An Ack from a newer version with an appended field.
    let mut body = 5u32.to_be_bytes().to_vec();
    body.extend_from_slice(b"appended field");
    let inner = raw_payload(&[(kind::ACK, &body)]);
    assert_eq!(parse_raw(&inner).unwrap(), [Message::Ack { seq: 5 }]);
}

#[test]
fn appended_fields_in_push_pull_records_are_ignored() {
    // One record with an extra trailing field, built by hand.
    let mut rec = vec![0u8]; // state Alive
    rec.extend_from_slice(&7u32.to_be_bytes()); // inc
    rec.extend_from_slice(&[1, b'n']); // node
    rec.extend_from_slice(&[4, 1, 2, 3, 4, 0x1e, 0xea]); // addr 1.2.3.4:7914
    rec.extend_from_slice(&[0]); // meta
    rec.extend_from_slice(&[1, 1]); // vmin vmax
    rec.extend_from_slice(b"future"); // appended
    let mut body = vec![1u8, 1]; // join, count
    body.push(rec.len() as u8);
    body.extend_from_slice(&rec);
    let inner = raw_payload(&[(kind::PUSH_PULL, &body)]);
    let msgs = parse_raw(&inner).unwrap();
    let Message::PushPull(pp) = msgs[0] else {
        panic!()
    };
    assert!(pp.join);
    let recs: Vec<_> = pp.records.iter().collect();
    assert_eq!(recs.len(), 1);
    assert_eq!(recs[0].alive.node.as_str(), "n");
    assert_eq!(recs[0].alive.addr, addr("1.2.3.4:7914"));
}

#[test]
fn short_known_bodies_are_errors_not_skips() {
    let inner = raw_payload(&[(kind::ACK, &[0, 0, 0])]);
    assert_eq!(parse_raw(&inner).unwrap_err(), DecodeError::Truncated);
}

#[test]
fn payload_structure_errors() {
    let l = Limits::default();
    let ack = 5u32.to_be_bytes();
    assert_eq!(Payload::parse(&[], &l).unwrap_err(), DecodeError::BadVarint);
    assert_eq!(
        Payload::parse(&[0], &l).unwrap_err(),
        DecodeError::EmptyPayload
    );
    // Count larger than the bytes could hold: rejected without walking.
    assert_eq!(
        Payload::parse(&[0xff, 0xff, 0xff, 0xff, 0x0f], &l).unwrap_err(),
        DecodeError::BadLength
    );
    assert_eq!(
        Payload::parse(&[3, 0x09, 0], &l).unwrap_err(),
        DecodeError::BadLength
    );
    // Body length overruns.
    assert_eq!(
        Payload::parse(&[1, 0x09, 5, 1], &l).unwrap_err(),
        DecodeError::BadLength
    );
    // Bytes after the last message.
    let mut inner = raw_payload(&[(kind::ACK, &ack)]);
    inner.push(0);
    assert_eq!(
        Payload::parse(&inner, &l).unwrap_err(),
        DecodeError::TrailingBytes
    );
}

#[test]
fn field_validation_errors() {
    let l = Limits::default();
    let mut ping_body = 1u32.to_be_bytes().to_vec();
    // target: empty name
    ping_body.extend_from_slice(&[0, 1, b'a', 4, 1, 2, 3, 4, 0, 80]);
    assert_eq!(
        Payload::parse(&raw_payload(&[(kind::PING, &ping_body)]), &l).unwrap_err(),
        DecodeError::BadNodeId
    );
    // target: invalid UTF-8
    let mut b = 1u32.to_be_bytes().to_vec();
    b.extend_from_slice(&[1, 0xff, 1, b'a', 4, 1, 2, 3, 4, 0, 80]);
    assert_eq!(
        Payload::parse(&raw_payload(&[(kind::PING, &b)]), &l).unwrap_err(),
        DecodeError::BadNodeId
    );
    // address family 5
    let mut b = 1u32.to_be_bytes().to_vec();
    b.extend_from_slice(&[1, b'a', 1, b'b', 5, 1, 2, 3, 4, 0, 80]);
    assert_eq!(
        Payload::parse(&raw_payload(&[(kind::PING, &b)]), &l).unwrap_err(),
        DecodeError::BadAddr
    );
    // want_nack = 2
    let mut b = 1u32.to_be_bytes().to_vec();
    b.extend_from_slice(&[1, b'a', 4, 1, 2, 3, 4, 0, 80, 4, 1, 2, 3, 4, 0, 80, 2]);
    assert_eq!(
        Payload::parse(&raw_payload(&[(kind::PING_REQ, &b)]), &l).unwrap_err(),
        DecodeError::BadBool
    );
    // push-pull state 4
    let mut rec = vec![4u8];
    rec.extend_from_slice(&[0; 4]);
    let body = [vec![0u8, 1, rec.len() as u8], rec].concat();
    assert_eq!(
        Payload::parse(&raw_payload(&[(kind::PUSH_PULL, &body)]), &l).unwrap_err(),
        DecodeError::BadState
    );
}

#[test]
fn node_id_validation() {
    assert!(NodeId::new("").is_err());
    assert!(NodeId::new(&"a".repeat(64)).is_ok());
    assert!(NodeId::new(&"a".repeat(65)).is_err());
    // 64 bytes of multi-byte characters is fine; 65 bytes is not, even with fewer characters.
    assert!(NodeId::new(&"é".repeat(32)).is_ok());
    assert!(NodeId::new(&format!("{}a", "é".repeat(32))).is_err());
}

#[test]
fn push_pull_with_a_huge_count_does_not_allocate_or_loop() {
    // count = u32::MAX with almost no bytes behind it.
    let body = [&[0u8][..], &[0xff, 0xff, 0xff, 0xff, 0x0f], &[0; 8]].concat();
    let inner = raw_payload(&[(kind::PUSH_PULL, &body)]);
    assert_eq!(parse_raw(&inner).unwrap_err(), DecodeError::BadLength);
}

// ---- stream framing ----------------------------------------------------------------------

#[test]
fn stream_frames_round_trip_through_the_reader() {
    for codec in [plain(b"c"), enc(b"c", &[1])] {
        let mut wire = Vec::new();
        codec
            .seal_stream_frame(&[ping()], &NONCE, &mut wire)
            .unwrap();
        codec
            .seal_stream_frame(&[Message::Ack { seq: 3 }], &NONCE, &mut wire)
            .unwrap();
        let mut reader = FrameReader::new(codec.limits().max_stream_frame);
        let mut seen = Vec::new();
        for chunk in wire.chunks(5) {
            reader.push(chunk);
            while let Some(mut frame) = reader.next_frame().unwrap() {
                let p = codec.open(PacketKind::Stream, &mut frame).unwrap();
                seen.push(p.iter().collect::<Vec<_>>().len());
            }
        }
        assert_eq!(seen, [1, 1]);
        assert_eq!(reader.finish(), Ok(()));
    }
}

#[test]
fn stream_frame_prefix_matches_packet_length() {
    let codec = enc(b"c", &[1]);
    let mut wire = vec![0xAA];
    codec
        .seal_stream_frame(&[ping()], &NONCE, &mut wire)
        .unwrap();
    let len = u32::from_be_bytes(wire[1..5].try_into().unwrap()) as usize;
    assert_eq!(wire.len(), 1 + 4 + len);
}

#[test]
fn oversized_stream_frame_is_refused_on_seal_and_leaves_out_alone() {
    let limits = Limits {
        max_stream_frame: 200,
        ..Limits::default()
    };
    let codec = Codec::encrypted(b"c", limits, vec![key(1)]).unwrap();
    let big = alive("n", &[0; 300]);
    let mut out = vec![1, 2, 3];
    assert_eq!(
        codec.seal_stream_frame(&[Message::Alive(big)], &NONCE, &mut out),
        Err(EncodeError::TooLarge)
    );
    assert_eq!(out, [1, 2, 3]);
}
