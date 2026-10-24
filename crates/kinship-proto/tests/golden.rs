//! Golden-byte tests. These pin the version 1 wire format: if one fails, the format changed.
//! Do not "fix" a failure by regenerating the bytes; a deliberate change needs a new wire
//! version (or an append-only field), a docs/design.md update, and new vectors beside these.
//!
//! The encrypted vector was cross-checked against an independent XChaCha20-Poly1305 and BLAKE3
//! implementation (HChaCha20 plus ChaCha20-Poly1305 from the Python `cryptography` package, and
//! the `blake3` package).

use core::net::SocketAddr;

use kinship_proto::{
    Alive, Codec, Dead, Key, Limits, Message, NodeId, PacketKind, Ping, PingReq, PushPull, Record,
    Records, State, Suspect, UserBroadcast, UserMessage, tags,
};

fn unhex(s: &str) -> Vec<u8> {
    assert!(s.len().is_multiple_of(2));
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16).unwrap())
        .collect()
}

fn id(s: &str) -> NodeId<'_> {
    NodeId::new(s).unwrap()
}

fn v4() -> SocketAddr {
    "10.0.0.1:7946".parse().unwrap()
}

fn v6() -> SocketAddr {
    "[2001:db8::1]:7946".parse().unwrap()
}

const META: &[u8] = b"\x04role\x03api";

fn alive_a() -> Alive<'static> {
    Alive {
        inc: 3,
        node: id("node-a"),
        addr: v4(),
        meta: META,
        vmin: 1,
        vmax: 1,
        epoch: 0,
    }
}

fn plain() -> Codec {
    Codec::insecure_plaintext(b"golden", Limits::default()).unwrap()
}

// Plaintext header for label "golden": magic, version 1, flags 0, BLAKE3("golden")[..8].
const PLAIN_DGRAM: &str = "6b6e010068ca9baf17c67ef7";
const PLAIN_STREAM: &str = "6b6e010268ca9baf17c67ef7";

fn check(msgs: &[Message<'_>], kind: PacketKind, header: &str, payload: &str) {
    let expected = unhex(&format!("{header}{payload}"));
    let mut sealed = Vec::new();
    plain().seal(kind, msgs, &[0; 24], &mut sealed).unwrap();
    assert_eq!(sealed, expected, "encoding drifted");
    let mut buf = expected;
    let got: Vec<_> = plain().open(kind, &mut buf).unwrap().iter().collect();
    assert_eq!(got, msgs, "decoding drifted");
}

#[test]
fn ping() {
    let m = Message::Ping(Ping {
        seq: 0x0102_0304,
        target: id("b"),
        source: id("a"),
        source_addr: v4(),
    });
    check(
        &[m],
        PacketKind::Datagram,
        PLAIN_DGRAM,
        "01010f0102030401620161040a0000011f0a",
    );
}

#[test]
fn ping_req() {
    let m = Message::PingReq(PingReq {
        seq: 5,
        target: id("t"),
        target_addr: v6(),
        requester_addr: v4(),
        want_nack: true,
    });
    check(
        &[m],
        PacketKind::Datagram,
        PLAIN_DGRAM,
        "0102210000000501740620010db80000000000000000000000011f0a040a0000011f0a01",
    );
}

#[test]
fn ack_and_nack() {
    check(
        &[Message::Ack { seq: 6 }],
        PacketKind::Datagram,
        PLAIN_DGRAM,
        "01030400000006",
    );
    check(
        &[Message::Nack { seq: 7 }],
        PacketKind::Datagram,
        PLAIN_DGRAM,
        "01040400000007",
    );
}

#[test]
fn alive() {
    check(
        &[Message::Alive(alive_a())],
        PacketKind::Datagram,
        PLAIN_DGRAM,
        "01051e00000003066e6f64652d61040a0000011f0a0904726f6c65036170690101",
    );
}

#[test]
fn suspect_dead_and_left() {
    check(
        &[Message::Suspect(Suspect {
            inc: 4,
            node: id("x"),
            from: id("y"),
            epoch: 0,
        })],
        PacketKind::Datagram,
        PLAIN_DGRAM,
        "0106080000000401780179",
    );
    let left = Dead {
        inc: 5,
        node: id("x"),
        from: id("x"),
        epoch: 0,
    };
    assert!(left.is_left());
    check(
        &[Message::Dead(left)],
        PacketKind::Datagram,
        PLAIN_DGRAM,
        "0107080000000501780178",
    );
    assert!(
        !Dead {
            inc: 5,
            node: id("x"),
            from: id("y"),
            epoch: 0,
        }
        .is_left()
    );
}

/// 1,790,000,000,000 ms after the Unix epoch, in September 2026.
const EPOCH: u64 = 0x0000_01a0_c450_6c00;

#[test]
fn epochs_are_appended_to_alive_suspect_dead_and_records() {
    // Appended in 0.3 as a u64 after the version 1 fields; the vectors above, with epoch 0,
    // are the bytes those versions sent, and still decode.
    let alive = Alive {
        epoch: EPOCH,
        ..alive_a()
    };
    check(
        &[Message::Alive(alive)],
        PacketKind::Datagram,
        PLAIN_DGRAM,
        "01052600000003066e6f64652d61040a0000011f0a0904726f6c65036170690101000001a0c4506c00",
    );
    check(
        &[Message::Suspect(Suspect {
            inc: 4,
            node: id("x"),
            from: id("y"),
            epoch: EPOCH,
        })],
        PacketKind::Datagram,
        PLAIN_DGRAM,
        "0106100000000401780179000001a0c4506c00",
    );
    check(
        &[Message::Dead(Dead {
            inc: 5,
            node: id("x"),
            from: id("x"),
            epoch: EPOCH,
        })],
        PacketKind::Datagram,
        PLAIN_DGRAM,
        "0107100000000501780178000001a0c4506c00",
    );
    let recs = [Record {
        state: State::Alive,
        alive,
    }];
    check(
        &[Message::PushPull(PushPull {
            join: true,
            records: Records::Slice(&recs),
        })],
        PacketKind::Stream,
        PLAIN_STREAM,
        "01082a0101270000000003066e6f64652d61040a0000011f0a0904726f6c65036170690101\
         000001a0c4506c00",
    );
}

#[test]
fn push_pull() {
    let recs = [
        Record {
            state: State::Alive,
            alive: alive_a(),
        },
        Record {
            state: State::Dead,
            alive: Alive {
                inc: 9,
                node: id("b"),
                addr: v6(),
                meta: b"",
                vmin: 1,
                vmax: 2,
                epoch: 0,
            },
        },
    ];
    let m = Message::PushPull(PushPull {
        join: true,
        records: Records::Slice(&recs),
    });
    check(
        &[m],
        PacketKind::Stream,
        PLAIN_STREAM,
        "01084001021f0000000003066e6f64652d61040a0000011f0a0904726f6c650361706901011d02\
         0000000901620620010db80000000000000000000000011f0a000102",
    );
}

#[test]
fn several_messages_share_one_payload() {
    let msgs = [
        Message::Ping(Ping {
            seq: 0x0102_0304,
            target: id("b"),
            source: id("a"),
            source_addr: v4(),
        }),
        Message::PingReq(PingReq {
            seq: 5,
            target: id("t"),
            target_addr: v6(),
            requester_addr: v4(),
            want_nack: true,
        }),
    ];
    check(
        &msgs,
        PacketKind::Stream,
        PLAIN_STREAM,
        "02010f0102030401620161040a0000011f0a02210000000501740620010db80000000000000000000000011f0a\
         040a0000011f0a01",
    );
}

#[test]
fn encrypted_packet() {
    let key = Key::from_bytes(core::array::from_fn(|i| i as u8));
    assert_eq!(key.id(), 0xe528_e957);
    let codec = Codec::encrypted(b"golden", Limits::default(), vec![key]).unwrap();
    let nonce: [u8; 24] = core::array::from_fn(|i| 0x40 + i as u8);
    let msgs = [
        Message::Ping(Ping {
            seq: 0x0102_0304,
            target: id("b"),
            source: id("a"),
            source_addr: v4(),
        }),
        Message::Ack { seq: 6 },
    ];
    let expected = unhex(
        "6b6e0101e528e957404142434445464748494a4b4c4d4e4f5051525354555657\
         d6380a71d2e37d17edf5e6baa59c65938db0aec01359539c3d5776c58e799b03\
         8c64c3dc873d60ec",
    );
    let mut sealed = Vec::new();
    codec
        .seal(PacketKind::Datagram, &msgs, &nonce, &mut sealed)
        .unwrap();
    assert_eq!(sealed, expected, "encoding drifted");
    let mut buf = expected;
    let got: Vec<_> = codec
        .open(PacketKind::Datagram, &mut buf)
        .unwrap()
        .iter()
        .collect();
    assert_eq!(got, msgs, "decoding drifted");
}

#[test]
fn user_message() {
    let m = Message::UserMessage(UserMessage {
        to: id("b"),
        to_epoch: 1_790_000_000_000,
        from: id("a"),
        from_epoch: 1_790_000_000_001,
        data: b"hi",
    });
    check(
        &[m],
        PacketKind::Datagram,
        PLAIN_DGRAM,
        "0109170162000001a0c4506c000161000001a0c4506c01026869",
    );
    check(
        &[m],
        PacketKind::Stream,
        PLAIN_STREAM,
        "0109170162000001a0c4506c000161000001a0c4506c01026869",
    );
}

#[test]
fn user_broadcast() {
    let m = Message::UserBroadcast(UserBroadcast {
        from: id("a"),
        from_epoch: 1_790_000_000_001,
        seq: 7,
        data: b"x",
    });
    check(
        &[m],
        PacketKind::Datagram,
        PLAIN_DGRAM,
        "010a140161000001a0c4506c0100000000000000070178",
    );
}

#[test]
fn stream_frame_prefix() {
    let mut wire = Vec::new();
    plain()
        .seal_stream_frame(&[Message::Ack { seq: 6 }], &[0; 24], &mut wire)
        .unwrap();
    assert_eq!(
        wire,
        unhex(
            "00000013 6b6e010268ca9baf17c67ef7 01030400000006"
                .replace(' ', "")
                .as_str()
        )
    );
}

#[test]
fn tag_encoding() {
    let bytes = tags::encode_tags([("role", "api"), ("zone", "eu")], 512).unwrap();
    assert_eq!(
        bytes,
        unhex(
            "04726f6c6503617069047a6f6e650265 75"
                .replace(' ', "")
                .as_str()
        )
    );
}

#[test]
fn a_newer_peers_packet_still_decodes() {
    // Written by a hypothetical newer version: an unknown message type 0x20 first, then an Ack
    // whose body gained a trailing field. Hand-assembled, never produced by this code.
    let inner = unhex(
        "02 2003aabbcc 0308 00000006 deadbeef"
            .replace(' ', "")
            .as_str(),
    );
    let mut packet = unhex(PLAIN_DGRAM);
    packet.extend_from_slice(&inner);
    let mut buf = packet;
    let p = plain().open(PacketKind::Datagram, &mut buf).unwrap();
    assert_eq!(p.unknown(), 1);
    assert_eq!(p.iter().collect::<Vec<_>>(), [Message::Ack { seq: 6 }]);
}
