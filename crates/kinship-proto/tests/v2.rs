use kinship_proto::identity::{Certificate, Revocation, SigningKey};
use kinship_proto::{Codec, Key, Limits, NodeId, PacketKind, WireVersion, v2};

fn id(s: &str) -> NodeId<'_> {
    NodeId::new(s).unwrap()
}

fn alive() -> v2::SignedAlive<'static> {
    v2::SignedAlive {
        alive: kinship_proto::Alive {
            inc: 3,
            node: id("a"),
            addr: "127.0.0.1:7946".parse().unwrap(),
            meta: b"meta",
            vmin: 1,
            vmax: 2,
            epoch: 500,
        },
        certificate_id: [4; 8],
        signature: [5; 64],
    }
}

#[test]
fn oversized_bodies_and_payloads_are_rejected_before_allocation() {
    // A few MiB of shared input describes more than 4 GiB of wire data. No
    // encoder may truncate a u32 length or try allocating that output.
    let meta = vec![0; 1024 * 1024];
    let signed = v2::SignedAlive {
        alive: kinship_proto::Alive {
            meta: &meta,
            ..alive().alive
        },
        ..alive()
    };
    let records = vec![
        v2::Record {
            alive: signed,
            state: v2::RecordState::Alive
        };
        4096
    ];
    let limits = Limits {
        max_meta_bytes: meta.len(),
        ..Limits::default()
    };
    let large = v2::Message::PushPull(v2::PushPull {
        join: false,
        records: v2::Records::Slice(&records),
        known_certificates: v2::CertificateIds::Slice(&[]),
    });
    assert_eq!(
        v2::encode_payload(&[large], &limits),
        Err(kinship_proto::EncodeError::TooLarge)
    );

    let half = v2::Message::PushPull(v2::PushPull {
        join: false,
        records: v2::Records::Slice(&records[..2048]),
        known_certificates: v2::CertificateIds::Slice(&[]),
    });
    assert_eq!(
        v2::encode_payload(&[half, half], &limits),
        Err(kinship_proto::EncodeError::TooLarge)
    );
}

fn messages<'a>(
    records: &'a [v2::Record<'a>],
    ids: &'a [[u8; 8]],
    cert: Certificate<'a>,
    rev: Revocation,
) -> Vec<v2::Message<'a>> {
    vec![
        v2::Message::Ping {
            ping: kinship_proto::Ping {
                seq: 7,
                target: id("b"),
                source: id("a"),
                source_addr: "[::1]:7946".parse().unwrap(),
            },
            source_epoch: 500,
            challenge: [6; 16],
            requester: None,
        },
        v2::Message::Ping {
            ping: kinship_proto::Ping {
                seq: 8,
                target: id("b"),
                source: id("relay"),
                source_addr: "127.0.0.1:7946".parse().unwrap(),
            },
            source_epoch: 700,
            challenge: [6; 16],
            requester: Some(v2::Probe {
                requester: id("a"),
                epoch: 500,
                seq: 7,
            }),
        },
        v2::Message::PingReq {
            request: kinship_proto::PingReq {
                seq: 7,
                target: id("b"),
                target_addr: "[::1]:7946".parse().unwrap(),
                requester_addr: "127.0.0.1:7946".parse().unwrap(),
                want_nack: true,
            },
            requester: id("a"),
            requester_epoch: 500,
            challenge: [6; 16],
        },
        v2::Message::Ack {
            seq: 7,
            target_epoch: 600,
            requester: id("a"),
            requester_epoch: 500,
            target: id("b"),
            challenge: [6; 16],
            certificate_id: [4; 8],
            signature: [1; 64],
        },
        v2::Message::Nack {
            seq: 7,
            relay: id("relay"),
            relay_epoch: 700,
            requester: id("a"),
            requester_epoch: 500,
            target: id("b"),
            challenge: [6; 16],
            certificate_id: [4; 8],
            signature: [2; 64],
        },
        v2::Message::Alive(alive()),
        v2::Message::Suspect {
            suspect: kinship_proto::Suspect {
                inc: 4,
                node: id("b"),
                from: id("a"),
                epoch: 600,
            },
            at: 123,
            certificate_id: [4; 8],
            signature: [3; 64],
        },
        v2::Message::Dead {
            dead: kinship_proto::Dead {
                inc: 4,
                node: id("b"),
                from: id("a"),
                epoch: 600,
            },
            at: 124,
            certificate_id: [4; 8],
            signature: [4; 64],
        },
        v2::Message::Dead {
            dead: kinship_proto::Dead {
                inc: 5,
                node: id("a"),
                from: id("a"),
                epoch: 500,
            },
            at: 125,
            certificate_id: [4; 8],
            signature: [5; 64],
        },
        v2::Message::UserMessage {
            message: kinship_proto::UserMessage {
                to: id("b"),
                to_epoch: 600,
                from: id("a"),
                from_epoch: 500,
                data: b"hi",
            },
            certificate_id: [4; 8],
            signature: [6; 64],
        },
        v2::Message::UserBroadcast {
            broadcast: kinship_proto::UserBroadcast {
                from: id("a"),
                from_epoch: 500,
                seq: 9,
                data: b"all",
            },
            certificate_id: [4; 8],
            signature: [7; 64],
        },
        v2::Message::PushPull(v2::PushPull {
            join: true,
            records: v2::Records::Slice(records),
            known_certificates: v2::CertificateIds::Slice(ids),
        }),
        v2::Message::Certificate(cert),
        v2::Message::Revocation(rev),
    ]
}

#[test]
fn every_v2_field_round_trips_and_reencodes_canonically() {
    let ca = SigningKey::from_bytes([1; 32]);
    let cert = Certificate::issue(&ca, b"c", id("a"), ca.public_key(), 1, 2000).unwrap();
    let rev = Revocation::issue(&ca, b"c", &cert).unwrap();
    let records = [
        v2::RecordState::Alive,
        v2::RecordState::Suspect { inc: 4 },
        v2::RecordState::Dead { inc: 5 },
        v2::RecordState::Left {
            inc: 6,
            at: 30,
            certificate_id: [4; 8],
            signature: [9; 64],
        },
    ]
    .map(|state| v2::Record {
        alive: alive(),
        state,
    });
    let ids = [[1; 8], [2; 8]];
    let msgs = messages(&records, &ids, cert, rev);
    for encrypted in [false, true] {
        let codec = if encrypted {
            Codec::encrypted(b"c", Limits::default(), vec![Key::from_bytes([7; 32])]).unwrap()
        } else {
            Codec::insecure_plaintext(b"c", Limits::default()).unwrap()
        };
        for version in [WireVersion::V1, WireVersion::V2] {
            let mut packet = Vec::new();
            codec
                .seal_v2(version, PacketKind::Stream, &msgs, &[8; 24], &mut packet)
                .unwrap();
            assert_eq!(packet[2], version as u8);
            let mut copy = packet.clone();
            let decoded: Vec<_> = codec
                .open_v2(PacketKind::Stream, &mut copy)
                .unwrap()
                .iter()
                .collect();
            assert_eq!(decoded, msgs);
            let mut second = Vec::new();
            codec
                .seal_v2(version, PacketKind::Stream, &decoded, &[8; 24], &mut second)
                .unwrap();
            assert_eq!(second, packet);
            let mut framed = Vec::new();
            codec
                .seal_v2_stream_frame(version, &msgs, &[8; 24], &mut framed)
                .unwrap();
            assert_eq!(&framed[4..], packet);
            assert_eq!(
                u32::from_be_bytes(framed[..4].try_into().unwrap()) as usize,
                packet.len()
            );
        }
    }
}

#[test]
fn legacy_callers_still_emit_and_accept_only_v1() {
    let c = Codec::insecure_plaintext(b"c", Limits::default()).unwrap();
    assert_eq!(kinship_proto::WIRE_VERSION, 1);
    assert_eq!(kinship_proto::MAX_WIRE_VERSION, 2);
    let mut out = Vec::new();
    c.seal(
        PacketKind::Datagram,
        &[kinship_proto::Message::Ack { seq: 1 }],
        &[0; 24],
        &mut out,
    )
    .unwrap();
    assert_eq!(out[2], 1);
    out[2] = 2;
    assert!(c.open(PacketKind::Datagram, &mut out).is_err());
    assert!(c.header_check().check(PacketKind::Datagram, &out).is_err());
    assert!(
        c.header_check_versioned()
            .check(PacketKind::Datagram, &out)
            .is_ok()
    );
    assert!(
        c.open_v2(PacketKind::Datagram, &mut out).is_err(),
        "a v1 Ack is too short for v2"
    );
}

#[test]
fn signatures_cover_exact_domains_nonce_and_probe_bindings() {
    let key = SigningKey::from_bytes([1; 32]);
    let mut msg = v2::Message::Ack {
        seq: 7,
        target_epoch: 600,
        requester: id("a"),
        requester_epoch: 500,
        target: id("b"),
        challenge: [6; 16],
        certificate_id: [4; 8],
        signature: [0; 64],
    };
    let bytes = msg.signed_bytes(b"c", None).unwrap();
    let mut expected = b"kinship v2 \x03".to_vec();
    expected.extend_from_slice(&blake3::hash(b"c").as_bytes()[..8]);
    expected.extend_from_slice(&7u32.to_be_bytes());
    expected.extend_from_slice(&600u64.to_be_bytes());
    expected.extend_from_slice(b"\x01a");
    expected.extend_from_slice(&500u64.to_be_bytes());
    expected.extend_from_slice(b"\x01b");
    expected.extend_from_slice(&[6; 16]);
    expected.extend_from_slice(&[4; 8]);
    assert_eq!(bytes, expected);
    let signature = key.sign(&bytes);
    if let v2::Message::Ack { signature: sig, .. } = &mut msg {
        *sig = signature;
    }
    key.public_key()
        .verify(&msg.signed_bytes(b"c", None).unwrap(), &signature)
        .unwrap();
    for changed in [
        v2::Message::Ack {
            seq: 8,
            target_epoch: 600,
            requester: id("a"),
            requester_epoch: 500,
            target: id("b"),
            challenge: [6; 16],
            certificate_id: [4; 8],
            signature,
        },
        v2::Message::Ack {
            seq: 7,
            target_epoch: 601,
            requester: id("a"),
            requester_epoch: 500,
            target: id("b"),
            challenge: [6; 16],
            certificate_id: [4; 8],
            signature,
        },
        v2::Message::Ack {
            seq: 7,
            target_epoch: 600,
            requester: id("x"),
            requester_epoch: 500,
            target: id("b"),
            challenge: [6; 16],
            certificate_id: [4; 8],
            signature,
        },
        v2::Message::Ack {
            seq: 7,
            target_epoch: 600,
            requester: id("a"),
            requester_epoch: 501,
            target: id("b"),
            challenge: [6; 16],
            certificate_id: [4; 8],
            signature,
        },
        v2::Message::Ack {
            seq: 7,
            target_epoch: 600,
            requester: id("a"),
            requester_epoch: 500,
            target: id("x"),
            challenge: [6; 16],
            certificate_id: [4; 8],
            signature,
        },
        v2::Message::Ack {
            seq: 7,
            target_epoch: 600,
            requester: id("a"),
            requester_epoch: 500,
            target: id("b"),
            challenge: [6; 16],
            certificate_id: [9; 8],
            signature,
        },
    ] {
        assert!(
            key.public_key()
                .verify(&changed.signed_bytes(b"c", None).unwrap(), &signature)
                .is_err()
        );
    }
    assert!(
        key.public_key()
            .verify(&msg.signed_bytes(b"other", None).unwrap(), &signature)
            .is_err()
    );
    assert!(msg.signed_bytes(b"c", Some(&[0; 24])).is_err());
    let direct = v2::Message::UserMessage {
        message: kinship_proto::UserMessage {
            to: id("b"),
            to_epoch: 600,
            from: id("a"),
            from_epoch: 500,
            data: b"hi",
        },
        certificate_id: [4; 8],
        signature: [0; 64],
    };
    assert!(direct.signed_bytes(b"c", None).is_err());
    let signed = direct.signed_bytes(b"c", Some(&[1; 24])).unwrap();
    assert_eq!(&signed[signed.len() - 24..], &[1; 24]);
    let signature = key.sign(&signed);
    assert!(
        key.public_key()
            .verify(
                &direct.signed_bytes(b"c", Some(&[2; 24])).unwrap(),
                &signature
            )
            .is_err()
    );
}

#[test]
fn records_reconstruct_original_proofs() {
    let original = alive();
    let record = v2::Record {
        alive: original,
        state: v2::RecordState::Left {
            inc: 9,
            at: 123,
            certificate_id: [4; 8],
            signature: [8; 64],
        },
    };
    assert_eq!(record.alive_message(), v2::Message::Alive(original));
    assert_eq!(
        record.left_message(),
        Some(v2::Message::Dead {
            dead: kinship_proto::Dead {
                inc: 9,
                node: id("a"),
                from: id("a"),
                epoch: 500
            },
            at: 123,
            certificate_id: [4; 8],
            signature: [8; 64]
        })
    );
}

#[test]
fn renewal_with_the_same_key_does_not_reauthorize_old_statements() {
    let key = SigningKey::from_bytes([1; 32]);
    let old = Certificate::issue(&key, b"c", id("a"), key.public_key(), 1, 100).unwrap();
    let new = Certificate::issue(&key, b"c", id("a"), key.public_key(), 2, 101).unwrap();
    let broadcast = kinship_proto::UserBroadcast {
        from: id("a"),
        from_epoch: 500,
        seq: 7,
        data: b"x",
    };
    let old_message = v2::Message::UserBroadcast {
        broadcast,
        certificate_id: old.id(),
        signature: [0; 64],
    };
    let signature = key.sign(&old_message.signed_bytes(b"c", None).unwrap());
    let new_message = v2::Message::UserBroadcast {
        broadcast,
        certificate_id: new.id(),
        signature,
    };
    assert!(
        key.public_key()
            .verify(&new_message.signed_bytes(b"c", None).unwrap(), &signature)
            .is_err()
    );
}

#[test]
fn all_known_bodies_reject_truncation_and_trailing_bytes() {
    let ca = SigningKey::from_bytes([1; 32]);
    let cert = Certificate::issue(&ca, b"c", id("a"), ca.public_key(), 1, 2000).unwrap();
    let rev = Revocation::issue(&ca, b"c", &cert).unwrap();
    let records = [v2::Record {
        alive: alive(),
        state: v2::RecordState::Dead { inc: 4 },
    }];
    for msg in messages(&records, &[[0; 8]], cert, rev) {
        let encoded = v2::encode_payload(&[msg], &Limits::default()).unwrap();
        for n in 0..encoded.len() {
            assert!(
                v2::Payload::parse(&encoded[..n], &Limits::default()).is_err(),
                "kind {}, prefix {n}",
                msg.kind()
            );
        }
        // Widen the body length by one and append one byte. Even a fully framed known
        // message must not have two interpretations of the bytes that get signed.
        let body = &encoded[2..];
        let (length_bytes, length) = if body[0] < 128 {
            (1, usize::from(body[0]))
        } else {
            (2, usize::from(body[0] & 127) | (usize::from(body[1]) << 7))
        };
        let next = length + 1;
        let mut extra = vec![1, msg.kind()];
        if next >= 128 {
            extra.extend_from_slice(&[(next as u8 & 127) | 128, (next >> 7) as u8]);
        } else {
            extra.push(next as u8);
        }
        extra.extend_from_slice(&body[length_bytes..]);
        extra.push(0);
        assert!(
            v2::Payload::parse(&extra, &Limits::default()).is_err(),
            "kind {}",
            msg.kind()
        );
    }
    // Nonminimal count and length, bad bool, unknown type, malformed nested count.
    for bytes in [
        &b"\x81\x00\x20\x00"[..],
        &b"\x01\x20\x80\x00"[..],
        &b"\x01\x08\x03\x02\x00\x00"[..],
        &b"\x01\x08\x02\x00\xff"[..],
    ] {
        assert!(v2::Payload::parse(bytes, &Limits::default()).is_err());
    }
    let unknown = v2::Payload::parse(b"\x01\x20\x01\xff", &Limits::default()).unwrap();
    assert_eq!(unknown.unknown(), 1);
    assert_eq!(unknown.iter().count(), 0);
}

#[test]
fn released_0_4_reads_every_v1_field_of_extended_upgrade_packets() {
    use kinship_proto as current;
    use kinship_proto_0_4 as old;

    let ca = SigningKey::from_bytes([1; 32]);
    let cert = Certificate::issue(&ca, b"c", id("a"), ca.public_key(), 1, 2000).unwrap();
    let rev = Revocation::issue(&ca, b"c", &cert).unwrap();
    let records = [
        v2::RecordState::Alive,
        v2::RecordState::Suspect { inc: 4 },
        v2::RecordState::Dead { inc: 5 },
        v2::RecordState::Left {
            inc: 6,
            at: 30,
            certificate_id: [4; 8],
            signature: [9; 64],
        },
    ]
    .map(|state| v2::Record {
        alive: alive(),
        state,
    });
    let legacy_records: Vec<_> = records
        .iter()
        .map(|r| current::Record {
            state: match r.state {
                v2::RecordState::Alive => current::State::Alive,
                v2::RecordState::Suspect { .. } => current::State::Suspect,
                v2::RecordState::Dead { .. } => current::State::Dead,
                v2::RecordState::Left { .. } => current::State::Left,
            },
            alive: r.alive.alive,
        })
        .collect();
    let ids = [[1; 8], [2; 8]];
    let msgs = messages(&records, &ids, cert, rev);
    let expected: Vec<_> = msgs
        .iter()
        .filter_map(|m| match *m {
            v2::Message::Ping { ping, .. } => Some(current::Message::Ping(ping)),
            v2::Message::PingReq { request, .. } => Some(current::Message::PingReq(request)),
            v2::Message::Ack { seq, .. } => Some(current::Message::Ack { seq }),
            v2::Message::Nack { seq, .. } => Some(current::Message::Nack { seq }),
            v2::Message::Alive(a) => Some(current::Message::Alive(a.alive)),
            v2::Message::Suspect { suspect, .. } => Some(current::Message::Suspect(suspect)),
            v2::Message::Dead { dead, .. } => Some(current::Message::Dead(dead)),
            v2::Message::PushPull(p) => Some(current::Message::PushPull(current::PushPull {
                join: p.join,
                records: current::Records::Slice(&legacy_records),
            })),
            v2::Message::UserMessage { message, .. } => {
                Some(current::Message::UserMessage(message))
            }
            v2::Message::UserBroadcast { broadcast, .. } => {
                Some(current::Message::UserBroadcast(broadcast))
            }
            v2::Message::Certificate(_) | v2::Message::Revocation(_) => None,
        })
        .collect();
    for encrypted in [false, true] {
        let new_codec = if encrypted {
            Codec::encrypted(b"c", Limits::default(), vec![Key::from_bytes([7; 32])]).unwrap()
        } else {
            Codec::insecure_plaintext(b"c", Limits::default()).unwrap()
        };
        let old_codec = if encrypted {
            old::Codec::encrypted(
                b"c",
                old::Limits::default(),
                vec![old::Key::from_bytes([7; 32])],
            )
            .unwrap()
        } else {
            old::Codec::insecure_plaintext(b"c", old::Limits::default()).unwrap()
        };
        let mut packet = Vec::new();
        new_codec
            .seal_v2(
                WireVersion::V1,
                PacketKind::Stream,
                &msgs,
                &[8; 24],
                &mut packet,
            )
            .unwrap();
        let old_payload = old_codec
            .open(old::PacketKind::Stream, &mut packet)
            .unwrap();
        assert_eq!(old_payload.unknown(), 2);
        let decoded: Vec<_> = old_payload.iter().collect();
        assert_eq!(decoded.len(), expected.len());
        // These distinct crate types cannot compare directly. Their complete derived Debug
        // values include every v1 field and every nested record, so none is omitted here.
        assert_eq!(format!("{decoded:?}"), format!("{expected:?}"));
        let mut old_bytes = Vec::new();
        old_codec
            .seal(old::PacketKind::Stream, &decoded, &[8; 24], &mut old_bytes)
            .unwrap();
        let mut new_bytes = Vec::new();
        new_codec
            .seal(PacketKind::Stream, &expected, &[8; 24], &mut new_bytes)
            .unwrap();
        assert_eq!(
            new_bytes, old_bytes,
            "default v1 output must remain identical to released 0.4"
        );
        let mut versioned = new_bytes.clone();
        assert!(matches!(
            new_codec
                .open_versioned(PacketKind::Stream, &mut versioned)
                .unwrap(),
            current::VersionedPayload::V1(_)
        ));

        for message in &msgs {
            let mut packet = Vec::new();
            new_codec
                .seal_v2(
                    WireVersion::V1,
                    PacketKind::Datagram,
                    &[*message],
                    &[9; 24],
                    &mut packet,
                )
                .unwrap();
            let old_payload = old_codec
                .open(old::PacketKind::Datagram, &mut packet)
                .unwrap();
            assert_eq!(old_payload.count(), 1);
            assert_eq!(
                old_payload.unknown(),
                usize::from(matches!(
                    message,
                    v2::Message::Certificate(_) | v2::Message::Revocation(_)
                ))
            );
        }
    }
}

#[test]
fn versioned_packets_keep_proofs_and_authenticate_the_envelope_version() {
    let c = Codec::encrypted(b"c", Limits::default(), vec![Key::from_bytes([7; 32])]).unwrap();
    let msg = v2::Message::Alive(alive());
    let mut packet = Vec::new();
    c.seal_v2(
        WireVersion::V2,
        PacketKind::Datagram,
        &[msg],
        &[8; 24],
        &mut packet,
    )
    .unwrap();
    let mut copy = packet.clone();
    match c.open_versioned(PacketKind::Datagram, &mut copy).unwrap() {
        kinship_proto::VersionedPayload::V2(p) => assert_eq!(p.iter().collect::<Vec<_>>(), [msg]),
        _ => panic!("lost v2 proofs"),
    }
    packet[2] = 1;
    assert_eq!(
        c.open_v2(PacketKind::Datagram, &mut packet).map(|_| ()),
        Err(kinship_proto::DecodeError::AuthFailed)
    );
    let mut out = vec![42];
    let tiny = Codec::insecure_plaintext(
        b"c",
        Limits {
            udp_max_payload: 16,
            max_stream_frame: 16,
            ..Limits::default()
        },
    )
    .unwrap();
    assert!(
        tiny.seal_v2(
            WireVersion::V2,
            PacketKind::Datagram,
            &[msg],
            &[0; 24],
            &mut out
        )
        .is_err()
    );
    assert_eq!(out, [42]);
    assert!(
        tiny.seal_v2_stream_frame(WireVersion::V2, &[msg], &[0; 24], &mut out)
            .is_err()
    );
    assert_eq!(out, [42]);
}

#[test]
fn v2_fuzz_seeds_reach_both_the_payload_and_authenticated_datagram_paths() {
    let payload = include_bytes!("../fuzz/corpus/decode_payload/v2_broadcast");
    assert_eq!(
        payload,
        include_bytes!("../fuzz/corpus/decode_datagram/v2_broadcast_payload")
    );
    let parsed = v2::Payload::parse(payload, &Limits::default()).unwrap();
    let messages: Vec<_> = parsed.iter().collect();
    assert_eq!(messages.len(), 1);
    assert!(matches!(messages[0], v2::Message::UserBroadcast { .. }));
    assert_eq!(
        v2::encode_payload(&messages, &Limits::default()).unwrap(),
        payload
    );
    let c = Codec::encrypted(b"golden", Limits::default(), vec![Key::from_bytes([7; 32])]).unwrap();
    for version in [WireVersion::V1, WireVersion::V2] {
        let mut packet = Vec::new();
        c.seal_raw_at(
            version,
            PacketKind::Datagram,
            payload,
            &[9; 24],
            &mut packet,
        )
        .unwrap();
        assert_eq!(
            c.open_v2(PacketKind::Datagram, &mut packet)
                .unwrap()
                .iter()
                .collect::<Vec<_>>(),
            messages
        );
    }
}

#[test]
fn harvested_future_sequence_ack_cannot_answer_a_fresh_challenge() {
    let target_key = SigningKey::from_bytes([2; 32]);
    let harvested = v2::Message::Ack {
        seq: 1000,
        target_epoch: 600,
        requester: id("a"),
        requester_epoch: 500,
        target: id("b"),
        challenge: [1; 16],
        certificate_id: [4; 8],
        signature: [0; 64],
    };
    let signature = target_key.sign(&harvested.signed_bytes(b"c", None).unwrap());
    let fresh = v2::Message::Ack {
        seq: 1000,
        target_epoch: 600,
        requester: id("a"),
        requester_epoch: 500,
        target: id("b"),
        challenge: [2; 16],
        certificate_id: [4; 8],
        signature,
    };
    assert!(
        target_key
            .public_key()
            .verify(&fresh.signed_bytes(b"c", None).unwrap(), &signature)
            .is_err()
    );
    let nack = v2::Message::Nack {
        seq: 1000,
        relay: id("relay"),
        relay_epoch: 700,
        requester: id("a"),
        requester_epoch: 500,
        target: id("b"),
        challenge: [1; 16],
        certificate_id: [4; 8],
        signature: [0; 64],
    };
    let signature = target_key.sign(&nack.signed_bytes(b"c", None).unwrap());
    let fresh = v2::Message::Nack {
        seq: 1000,
        relay: id("relay"),
        relay_epoch: 700,
        requester: id("a"),
        requester_epoch: 500,
        target: id("b"),
        challenge: [2; 16],
        certificate_id: [4; 8],
        signature,
    };
    assert!(
        target_key
            .public_key()
            .verify(&fresh.signed_bytes(b"c", None).unwrap(), &signature)
            .is_err()
    );
}

proptest::proptest! {
    #![proptest_config(proptest::test_runner::Config::with_cases(64))]
    #[test]
    fn arbitrary_v2_payloads_never_panic_and_accepted_values_are_canonical(
        bytes in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..2048),
    ) {
        if let Ok(payload) = v2::Payload::parse(&bytes, &Limits::default()) {
            let messages: Vec<_> = payload.iter().collect();
            proptest::prop_assert_eq!(messages.len() + payload.unknown(), payload.count());
            if payload.unknown() == 0 {
                proptest::prop_assert_eq!(v2::encode_payload(&messages, &Limits::default()).unwrap(), bytes);
            }
        }
    }
    #[test]
    fn new_fields_have_one_encoding_per_value(
        seed in proptest::prelude::any::<[u8; 32]>(),
        signature in proptest::prelude::any::<[u8; 64]>(),
        challenge in proptest::prelude::any::<[u8; 16]>(),
        cert_id in proptest::prelude::any::<[u8; 8]>(),
        epoch in proptest::prelude::any::<u64>(),
        at in proptest::prelude::any::<u64>(),
        inc in proptest::prelude::any::<u32>(),
        seq in proptest::prelude::any::<u32>(),
        data in proptest::collection::vec(proptest::prelude::any::<u8>(), 0..512),
        name in ".{1,16}",
        ip in proptest::prelude::any::<[u8;16]>(),
    ) {
        let ca = SigningKey::from_bytes(seed);
        let node = id(&name);
        let cert = Certificate::issue(&ca, b"c", node, ca.public_key(), 0, u64::MAX).unwrap();
        let rev = Revocation::issue(&ca, b"c", &cert).unwrap();
        let original = v2::SignedAlive { alive: kinship_proto::Alive { node, inc, epoch, meta: &data, addr: std::net::SocketAddr::new(std::net::Ipv6Addr::from(ip).into(), seq as u16), vmin: 1, vmax: 2 }, certificate_id: cert_id, signature };
        let records = [v2::RecordState::Alive, v2::RecordState::Suspect { inc }, v2::RecordState::Dead { inc }, v2::RecordState::Left { inc, at, certificate_id: cert_id, signature }].map(|state| v2::Record { alive: original, state });
        let ids = [cert_id];
        let mut msgs = messages(&records, &ids, cert, rev);
        msgs.extend([
            v2::Message::Alive(original),
            v2::Message::Ack { seq, target_epoch: epoch, requester: node, requester_epoch: at, target: id("b"), challenge, certificate_id: cert_id, signature },
            v2::Message::Nack { seq, relay: node, relay_epoch: epoch, requester: id("b"), requester_epoch: at, target: node, challenge, certificate_id: cert_id, signature },
            v2::Message::Ping { ping: kinship_proto::Ping { seq, target: node, source: node, source_addr: original.alive.addr }, source_epoch: epoch, challenge, requester: Some(v2::Probe { requester: node, epoch: at, seq }) },
            v2::Message::PingReq { request: kinship_proto::PingReq { seq, target: node, target_addr: original.alive.addr, requester_addr: original.alive.addr, want_nack: seq % 2 == 0 }, requester: node, requester_epoch: epoch, challenge },
            v2::Message::Suspect { suspect: kinship_proto::Suspect { inc, node, from: id("b"), epoch }, at, certificate_id: cert_id, signature },
            v2::Message::Dead { dead: kinship_proto::Dead { inc, node, from: node, epoch }, at, certificate_id: cert_id, signature },
            v2::Message::UserMessage { message: kinship_proto::UserMessage { to: node, to_epoch: at, from: node, from_epoch: epoch, data: &data }, certificate_id: cert_id, signature },
            v2::Message::UserBroadcast { broadcast: kinship_proto::UserBroadcast { from: node, from_epoch: epoch, seq: at, data: &data }, certificate_id: cert_id, signature },
        ]);
        let encoded = v2::encode_payload(&msgs, &Limits::default()).unwrap();
        let decoded: Vec<_> = v2::Payload::parse(&encoded, &Limits::default()).unwrap().iter().collect();
        proptest::prop_assert_eq!(&decoded, &msgs);
        proptest::prop_assert_eq!(v2::encode_payload(&decoded, &Limits::default()).unwrap(), encoded);
        let cert_bytes = cert.encode();
        proptest::prop_assert_eq!(Certificate::decode(&cert_bytes).unwrap(), cert);
        proptest::prop_assert_eq!(Revocation::decode(&rev.encode()).unwrap(), rev);
    }
}
