//! Property tests: round trips, canonical re-encoding, and "never panics" on arbitrary bytes.

use core::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

use kinship_proto::{
    Alive, Codec, Dead, FrameReader, Key, Limits, Message, NodeId, PacketKind, Payload, Ping,
    PingReq, PushPull, Record, Records, State, Suspect, tags,
};
use proptest::prelude::*;

// ---- owned models, borrowed into `Message` for each case ---------------------------------

#[derive(Debug, Clone)]
struct AliveM {
    inc: u32,
    node: String,
    addr: SocketAddr,
    meta: Vec<u8>,
    vmin: u8,
    vmax: u8,
}

#[derive(Debug, Clone)]
enum M {
    Ping {
        seq: u32,
        target: String,
        source: String,
        addr: SocketAddr,
    },
    PingReq {
        seq: u32,
        target: String,
        taddr: SocketAddr,
        raddr: SocketAddr,
        want_nack: bool,
    },
    Ack(u32),
    Nack(u32),
    Alive(AliveM),
    Suspect {
        inc: u32,
        node: String,
        from: String,
    },
    Dead {
        inc: u32,
        node: String,
        from: String,
    },
    PushPull {
        join: bool,
        recs: Vec<(u8, AliveM)>,
    },
}

fn name() -> impl Strategy<Value = String> {
    // 1 to 64 bytes of UTF-8, including multi-byte characters.
    prop::collection::vec(any::<char>(), 1..=64).prop_map(|cs| {
        let mut s = String::new();
        for c in cs {
            if s.len() + c.len_utf8() > 64 {
                break;
            }
            s.push(c);
        }
        s
    })
}

fn addr() -> impl Strategy<Value = SocketAddr> {
    prop_oneof![
        (any::<[u8; 4]>(), any::<u16>())
            .prop_map(|(ip, p)| SocketAddr::new(IpAddr::V4(Ipv4Addr::from(ip)), p)),
        (any::<[u8; 16]>(), any::<u16>())
            .prop_map(|(ip, p)| SocketAddr::new(IpAddr::V6(Ipv6Addr::from(ip)), p)),
    ]
}

fn alive_m() -> impl Strategy<Value = AliveM> {
    (
        any::<u32>(),
        name(),
        addr(),
        prop::collection::vec(any::<u8>(), 0..=512),
        1u8..=255,
    )
        .prop_flat_map(|(inc, node, addr, meta, vmin)| {
            (Just((inc, node, addr, meta, vmin)), vmin..=255)
        })
        .prop_map(|((inc, node, addr, meta, vmin), vmax)| AliveM {
            inc,
            node,
            addr,
            meta,
            vmin,
            vmax,
        })
}

fn msg() -> impl Strategy<Value = M> {
    prop_oneof![
        (any::<u32>(), name(), name(), addr()).prop_map(|(seq, target, source, addr)| M::Ping {
            seq,
            target,
            source,
            addr
        }),
        (any::<u32>(), name(), addr(), addr(), any::<bool>()).prop_map(
            |(seq, target, taddr, raddr, want_nack)| M::PingReq {
                seq,
                target,
                taddr,
                raddr,
                want_nack
            }
        ),
        any::<u32>().prop_map(M::Ack),
        any::<u32>().prop_map(M::Nack),
        alive_m().prop_map(M::Alive),
        (any::<u32>(), name(), name()).prop_map(|(inc, node, from)| M::Suspect { inc, node, from }),
        (any::<u32>(), name(), name()).prop_map(|(inc, node, from)| M::Dead { inc, node, from }),
        (
            any::<bool>(),
            prop::collection::vec((0u8..=3, alive_m()), 0..6)
        )
            .prop_map(|(join, recs)| M::PushPull { join, recs }),
    ]
}

fn state(b: u8) -> State {
    [State::Alive, State::Suspect, State::Dead, State::Left][b as usize]
}

fn alive_of(a: &AliveM) -> Alive<'_> {
    Alive {
        inc: a.inc,
        node: NodeId::new(&a.node).unwrap(),
        addr: a.addr,
        meta: &a.meta,
        vmin: a.vmin,
        vmax: a.vmax,
    }
}

fn id(s: &str) -> NodeId<'_> {
    NodeId::new(s).unwrap()
}

/// Builds borrowed messages from the models and hands them to `f`.
fn with_messages<R>(ms: &[M], f: impl FnOnce(&[Message<'_>]) -> R) -> R {
    let records: Vec<Vec<Record<'_>>> = ms
        .iter()
        .map(|m| match m {
            M::PushPull { recs, .. } => recs
                .iter()
                .map(|(s, a)| Record {
                    state: state(*s),
                    alive: alive_of(a),
                })
                .collect(),
            _ => Vec::new(),
        })
        .collect();
    let msgs: Vec<Message<'_>> = ms
        .iter()
        .zip(&records)
        .map(|(m, recs)| match m {
            M::Ping {
                seq,
                target,
                source,
                addr,
            } => Message::Ping(Ping {
                seq: *seq,
                target: id(target),
                source: id(source),
                source_addr: *addr,
            }),
            M::PingReq {
                seq,
                target,
                taddr,
                raddr,
                want_nack,
            } => Message::PingReq(PingReq {
                seq: *seq,
                target: id(target),
                target_addr: *taddr,
                requester_addr: *raddr,
                want_nack: *want_nack,
            }),
            M::Ack(seq) => Message::Ack { seq: *seq },
            M::Nack(seq) => Message::Nack { seq: *seq },
            M::Alive(a) => Message::Alive(alive_of(a)),
            M::Suspect { inc, node, from } => Message::Suspect(Suspect {
                inc: *inc,
                node: id(node),
                from: id(from),
            }),
            M::Dead { inc, node, from } => Message::Dead(Dead {
                inc: *inc,
                node: id(node),
                from: id(from),
            }),
            M::PushPull { join, .. } => Message::PushPull(PushPull {
                join: *join,
                records: Records::Slice(recs),
            }),
        })
        .collect();
    f(&msgs)
}

fn big_limits() -> Limits {
    Limits {
        udp_max_payload: 1 << 20,
        max_stream_frame: 1 << 24,
        ..Limits::default()
    }
}

fn codecs() -> [Codec; 2] {
    [
        Codec::insecure_plaintext(b"prop", big_limits()).unwrap(),
        Codec::encrypted(b"prop", big_limits(), vec![Key::from_bytes([5; 32])]).unwrap(),
    ]
}

proptest! {
    #![proptest_config(ProptestConfig::with_cases(256))]

    #[test]
    fn seal_then_open_returns_the_same_messages(
        ms in prop::collection::vec(msg(), 1..8),
        nonce in any::<[u8; 24]>(),
        stream in any::<bool>(),
    ) {
        let kind = if stream { PacketKind::Stream } else { PacketKind::Datagram };
        for codec in codecs() {
            with_messages(&ms, |msgs| {
                let mut bytes = Vec::new();
                codec.seal(kind, msgs, &nonce, &mut bytes).unwrap();
                prop_assert_eq!(bytes.len(), codec.overhead() + 1 + msgs.iter().map(Message::encoded_len).sum::<usize>());
                let payload = codec.open(kind, &mut bytes).unwrap();
                prop_assert_eq!(payload.count(), msgs.len());
                prop_assert_eq!(payload.unknown(), 0);
                let got: Vec<_> = payload.iter().collect();
                prop_assert_eq!(&got[..], msgs);
                Ok(())
            })?;
        }
    }

    #[test]
    fn re_encoding_a_decoded_payload_is_canonical(
        ms in prop::collection::vec(msg(), 1..6),
        nonce in any::<[u8; 24]>(),
    ) {
        let codec = Codec::insecure_plaintext(b"prop", big_limits()).unwrap();
        with_messages(&ms, |msgs| {
            let mut first = Vec::new();
            codec.seal(PacketKind::Stream, msgs, &nonce, &mut first).unwrap();
            let mut buf = first.clone();
            let decoded: Vec<_> = codec.open(PacketKind::Stream, &mut buf).unwrap().iter().collect();
            let mut second = Vec::new();
            codec.seal(PacketKind::Stream, &decoded, &nonce, &mut second).unwrap();
            prop_assert_eq!(first, second);
            Ok(())
        })?;
    }

    #[test]
    fn arbitrary_payload_bytes_never_panic_and_accepted_ones_re_encode(
        inner in prop::collection::vec(any::<u8>(), 0..2048),
    ) {
        if let Ok(p) = Payload::parse(&inner, &Limits::default()) {
            let msgs: Vec<_> = p.iter().collect();
            prop_assert_eq!(msgs.len() + p.unknown(), p.count());
            if p.unknown() == 0 {
                let codec = Codec::insecure_plaintext(b"", big_limits()).unwrap();
                let mut out = Vec::new();
                codec.seal(PacketKind::Stream, &msgs, &[0; 24], &mut out).unwrap();
                let mut buf = out;
                let again: Vec<_> = codec.open(PacketKind::Stream, &mut buf).unwrap().iter().collect();
                prop_assert_eq!(again, msgs);
            }
        }
    }

    #[test]
    fn arbitrary_packets_never_panic(
        bytes in prop::collection::vec(any::<u8>(), 0..2048),
        kind in any::<bool>(),
    ) {
        let kind = if kind { PacketKind::Stream } else { PacketKind::Datagram };
        for codec in codecs() {
            let mut buf = bytes.clone();
            let _ = codec.open(kind, &mut buf);
        }
    }

    #[test]
    fn arbitrary_bytes_behind_a_valid_header_never_panic(
        inner in prop::collection::vec(any::<u8>(), 0..2048),
        stream in any::<bool>(),
    ) {
        // Seal the garbage so it passes authentication and reaches the payload parser.
        let kind = if stream { PacketKind::Stream } else { PacketKind::Datagram };
        for codec in codecs() {
            let mut sealed = Vec::new();
            if codec.seal_raw(kind, &inner, &[3; 24], &mut sealed).is_ok() {
                let _ = codec.open(kind, &mut sealed);
            }
        }
    }

    #[test]
    fn any_corruption_of_an_encrypted_packet_is_rejected(
        ms in prop::collection::vec(msg(), 1..4),
        nonce in any::<[u8; 24]>(),
        at in any::<prop::sample::Index>(),
        xor in 1u8..=255,
    ) {
        let codec = &codecs()[1];
        with_messages(&ms, |msgs| {
            let mut bytes = Vec::new();
            codec.seal(PacketKind::Datagram, msgs, &nonce, &mut bytes).unwrap();
            let i = at.index(bytes.len());
            bytes[i] ^= xor;
            prop_assert!(codec.open(PacketKind::Datagram, &mut bytes).is_err());
            Ok(())
        })?;
    }

    #[test]
    fn frame_reader_is_independent_of_chunking(
        frames in prop::collection::vec(prop::collection::vec(any::<u8>(), 4..200), 0..6),
        cuts in prop::collection::vec(1usize..64, 1..40),
    ) {
        let mut wire = Vec::new();
        for f in &frames {
            wire.extend_from_slice(&(f.len() as u32).to_be_bytes());
            wire.extend_from_slice(f);
        }
        let mut reader = FrameReader::new(1 << 20);
        let mut got = Vec::new();
        let mut rest = &wire[..];
        let mut i = 0;
        while !rest.is_empty() {
            let n = cuts[i % cuts.len()].min(rest.len());
            i += 1;
            reader.push(&rest[..n]);
            rest = &rest[n..];
            while let Some(f) = reader.next_frame().unwrap() {
                got.push(f);
            }
        }
        prop_assert_eq!(got, frames);
        prop_assert!(reader.finish().is_ok());
    }

    #[test]
    fn frame_reader_never_panics_or_buffers_beyond_input(
        chunks in prop::collection::vec(prop::collection::vec(any::<u8>(), 0..64), 0..20),
        max in 4usize..512,
    ) {
        let mut reader = FrameReader::new(max);
        let mut total = 0;
        for c in &chunks {
            total += c.len();
            reader.push(c);
            while let Ok(Some(f)) = reader.next_frame() {
                prop_assert!(f.len() <= max);
            }
            prop_assert!(reader.buffered() <= total);
        }
    }

    #[test]
    fn tags_round_trip(
        entries in prop::collection::btree_map("[a-z0-9_.-]{1,12}", "\\PC{0,24}", 0..8),
    ) {
        let pairs: Vec<(&str, &str)> = entries.iter().map(|(k, v)| (k.as_str(), v.as_str())).collect();
        if let Ok(bytes) = tags::encode_tags(pairs.iter().copied(), 512) {
            let parsed = tags::Tags::parse(&bytes).unwrap();
            prop_assert_eq!(parsed.iter().collect::<Vec<_>>(), pairs);
        }
    }

    #[test]
    fn arbitrary_tag_bytes_never_panic(bytes in prop::collection::vec(any::<u8>(), 0..256)) {
        if let Ok(t) = tags::Tags::parse(&bytes) {
            let _ = t.iter().count();
        }
    }
}
