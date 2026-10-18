//! Mode `sign` (KI-01 Stage 2a, `docs/ki01-stage2.md`): for each statement a node signs,
//! Alive, Left, Suspect and Dead, and for push-pull records, a good signature is applied, a
//! bad one or one by the wrong signer is dropped and counted, a missing one (a version 1
//! packet) is accepted as unsigned, and a certificate that is expired, not yet valid, for
//! another cluster or from an unknown anchor is refused. Also the configuration checks, the
//! per-recipient wire version, the seeds' versions and the spreading of a large frame's checks.

use std::net::SocketAddr;
use std::time::Duration;

use kinship_core::{
    Command, Config, Credentials, Event, Identity, Instant, Key, Limits, Node, Security,
    Signatures, SigningKey, State, StreamEvent, StreamId, Transmit,
};
use kinship_proto::identity::{Certificate, CertificateId};
use kinship_proto::v2::{self, CertificateIds, Record, RecordState, Records, SignedAlive};
use kinship_proto::{Alive, Codec, Dead, Message, NodeId, PacketKind, Suspect, WireVersion};

/// The wall clock when the node under test starts, in milliseconds: September 2026.
const EPOCH: u64 = 1_790_000_000_000;
const NOW: u64 = EPOCH / 1000;
const DAY: u64 = 86_400;
const LABEL: &[u8] = b"default";

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn id(name: &str) -> NodeId<'_> {
    NodeId::new(name).unwrap()
}

fn cluster_key() -> Key {
    Key::from_bytes([3; 32])
}

fn ca() -> SigningKey {
    SigningKey::from_bytes([1; 32])
}

/// The signing key of member `name`, derived from its first byte.
fn member_key(name: &str) -> SigningKey {
    SigningKey::from_bytes([name.as_bytes()[0]; 32])
}

/// A certificate for `name`'s key, issued by `ca` for cluster `label`, valid from `nb` to `na`.
fn issue_with(ca: &SigningKey, label: &[u8], name: &str, nb: u64, na: u64) -> Vec<u8> {
    Certificate::issue(ca, label, id(name), member_key(name).public_key(), nb, na)
        .unwrap()
        .encode()
}

/// A certificate for `name` valid for a day either side of the start.
fn cert(name: &str) -> Vec<u8> {
    issue_with(&ca(), LABEL, name, NOW - DAY, NOW + DAY)
}

fn cert_id(bytes: &[u8]) -> CertificateId {
    Certificate::decode(bytes).unwrap().id()
}

fn signing_config(name: &str) -> Config {
    let mut cfg = Config::lan(Security::Keys(vec![cluster_key()]));
    cfg.signatures = Signatures::Sign(Credentials {
        signing_key: member_key(name),
        certificate: cert(name),
        trust_anchors: vec![ca().public_key()],
    });
    cfg
}

/// Node "a" in mode `sign`, started at the wall clock [`EPOCH`].
fn node() -> Node {
    node_with(signing_config("a"))
}

fn node_with(cfg: Config) -> Node {
    let me = Identity::new("a", addr(1)).unwrap().with_epoch(EPOCH);
    let mut n = Node::new(cfg, me, Instant::ZERO, 1, &[1; 32]).unwrap();
    while n.poll_event().is_some() {}
    while n.poll_transmit().is_some() {}
    n
}

/// A codec as the rest of the cluster has.
fn codec() -> Codec {
    Codec::encrypted(LABEL, Limits::default(), vec![cluster_key()]).unwrap()
}

/// Seals packets for node "a" with fresh nonces at cluster time 0.
struct Peer {
    codec: Codec,
    next: u64,
}

impl Peer {
    fn new() -> Self {
        Self {
            codec: codec(),
            next: 1,
        }
    }

    fn nonce(&mut self) -> [u8; 24] {
        let mut nonce = [0; 24];
        nonce[8..16].copy_from_slice(&self.next.to_be_bytes());
        self.next += 1;
        nonce
    }

    fn v2(&mut self, n: &mut Node, msgs: &[v2::Message<'_>]) {
        let nonce = self.nonce();
        let mut pkt = Vec::new();
        self.codec
            .seal_v2(
                WireVersion::V2,
                PacketKind::Datagram,
                msgs,
                &nonce,
                &mut pkt,
            )
            .unwrap();
        n.handle_datagram(Instant::ZERO, addr(99), &pkt);
    }

    fn v1(&mut self, n: &mut Node, msgs: &[Message<'_>]) {
        let nonce = self.nonce();
        let mut pkt = Vec::new();
        self.codec
            .seal(PacketKind::Datagram, msgs, &nonce, &mut pkt)
            .unwrap();
        n.handle_datagram(Instant::ZERO, addr(99), &pkt);
    }
}

/// The Alive of member `name`, at `port`, incarnation `inc`, started at `EPOCH - port`.
fn alive(name: &str, port: u16, inc: u32) -> Alive<'_> {
    Alive {
        inc,
        node: id(name),
        addr: addr(port),
        meta: b"",
        vmin: 1,
        vmax: 2,
        epoch: EPOCH - u64::from(port),
    }
}

/// Fills in `msg`'s signature by `key`.
fn sign<'a>(mut msg: v2::Message<'a>, key: &SigningKey) -> v2::Message<'a> {
    let sig = key.sign(&msg.signed_bytes(LABEL, None).unwrap());
    match &mut msg {
        v2::Message::Alive(a) => a.signature = sig,
        v2::Message::Suspect { signature, .. } | v2::Message::Dead { signature, .. } => {
            *signature = sig;
        }
        _ => unreachable!(),
    }
    msg
}

/// `a` signed by `key` under certificate `cert`.
fn signed_alive<'a>(a: Alive<'a>, cert: &[u8], key: &SigningKey) -> v2::Message<'a> {
    let msg = v2::Message::Alive(SignedAlive {
        alive: a,
        certificate_id: cert_id(cert),
        signature: [0; 64],
    });
    sign(msg, key)
}

fn signed_suspect<'a>(s: Suspect<'a>, cert: &[u8], key: &SigningKey) -> v2::Message<'a> {
    let msg = v2::Message::Suspect {
        suspect: s,
        at: 0,
        certificate_id: cert_id(cert),
        signature: [0; 64],
    };
    sign(msg, key)
}

fn signed_dead<'a>(d: Dead<'a>, cert: &[u8], key: &SigningKey) -> v2::Message<'a> {
    let msg = v2::Message::Dead {
        dead: d,
        at: 0,
        certificate_id: cert_id(cert),
        signature: [0; 64],
    };
    sign(msg, key)
}

/// `msg` with one bit of its signature flipped.
fn corrupt(mut msg: v2::Message<'_>) -> v2::Message<'_> {
    match &mut msg {
        v2::Message::Alive(a) => a.signature[0] ^= 1,
        v2::Message::Suspect { signature, .. } | v2::Message::Dead { signature, .. } => {
            signature[0] ^= 1;
        }
        _ => unreachable!(),
    }
    msg
}

fn certificate(bytes: &[u8]) -> v2::Message<'_> {
    v2::Message::Certificate(Certificate::decode(bytes).unwrap())
}

fn state(n: &Node, name: &str) -> Option<State> {
    n.member(name).map(|m| m.state)
}

fn events(n: &mut Node) -> Vec<Event> {
    std::iter::from_fn(|| n.poll_event()).collect()
}

/// The certificates that must be refused: expired, not yet valid, another cluster's, and one
/// from a CA no node trusts. Each is for `name`'s own key.
fn bad_certs(name: &str) -> [(&'static str, Vec<u8>); 4] {
    let other_ca = SigningKey::from_bytes([2; 32]);
    [
        (
            "expired",
            issue_with(&ca(), LABEL, name, NOW - 3 * DAY, NOW - DAY),
        ),
        (
            "not yet valid",
            issue_with(&ca(), LABEL, name, NOW + DAY, NOW + 3 * DAY),
        ),
        (
            "another cluster",
            issue_with(&ca(), b"other", name, NOW - DAY, NOW + DAY),
        ),
        (
            "unknown anchor",
            issue_with(&other_ca, LABEL, name, NOW - DAY, NOW + DAY),
        ),
    ]
}

/// A node that holds `name` at `port` from its signed Alive, its certificate with it.
fn knows(n: &mut Node, peer: &mut Peer, name: &str, port: u16) {
    let c = cert(name);
    let msg = signed_alive(alive(name, port, 0), &c, &member_key(name));
    peer.v2(n, &[certificate(&c), msg]);
    assert_eq!(state(n, name), Some(State::Alive), "{name} known");
}

/// A node that holds `name` at `port` from an unsigned Alive, without its certificate.
fn knows_unsigned(n: &mut Node, peer: &mut Peer, name: &str, port: u16) {
    peer.v1(n, &[Message::Alive(alive(name, port, 0))]);
    assert_eq!(state(n, name), Some(State::Alive), "{name} known");
}

#[test]
fn signed_alive_statements() {
    let b = cert("b");
    let key = member_key("b");

    // Good: the member joins, signed.
    let mut n = node();
    let mut peer = Peer::new();
    peer.v2(
        &mut n,
        &[certificate(&b), signed_alive(alive("b", 2, 0), &b, &key)],
    );
    assert_eq!(state(&n, "b"), Some(State::Alive));
    assert_eq!(n.metrics().unsigned_members, 0);
    assert_eq!(n.metrics().signatures_invalid, 0);

    // Bad: dropped and counted, never taken as unsigned.
    let mut n = node();
    let bad = corrupt(signed_alive(alive("b", 2, 0), &b, &key));
    peer.v2(&mut n, &[certificate(&b), bad]);
    assert_eq!(state(&n, "b"), None);
    assert_eq!(n.metrics().signatures_invalid, 1);

    // Missing: a version 1 Alive is accepted, and the member is unsigned.
    let mut n = node();
    knows_unsigned(&mut n, &mut peer, "b", 2);
    assert_eq!(n.metrics().unsigned_members, 1);
    // Its signed copy then attaches the proof it lacked.
    peer.v2(
        &mut n,
        &[certificate(&b), signed_alive(alive("b", 2, 0), &b, &key)],
    );
    assert_eq!(n.metrics().unsigned_members, 0);
    assert_eq!(events(&mut n).len(), 1, "joined once, nothing more");

    // Wrong signer: c's key under b's certificate, and b's Alive under c's certificate.
    let mut n = node();
    let c = cert("c");
    let forged = signed_alive(alive("b", 2, 0), &b, &member_key("c"));
    peer.v2(&mut n, &[certificate(&b), forged]);
    assert_eq!(n.metrics().signatures_invalid, 1);
    let forged = signed_alive(alive("b", 2, 0), &c, &member_key("c"));
    peer.v2(&mut n, &[certificate(&c), forged]);
    assert_eq!(
        n.metrics().certificates_refused,
        1,
        "c's certificate names c"
    );
    assert_eq!(state(&n, "b"), None);

    // Certificates that must be refused.
    for (what, bad) in bad_certs("b") {
        let mut n = node();
        peer.v2(
            &mut n,
            &[
                certificate(&bad),
                signed_alive(alive("b", 2, 0), &bad, &key),
            ],
        );
        assert_eq!(state(&n, "b"), None, "{what}");
        assert_eq!(n.metrics().certificates_refused, 1, "{what}");
    }

    // Without a certificate at hand it cannot be checked, and is dropped uncounted.
    let mut n = node();
    peer.v2(&mut n, &[signed_alive(alive("b", 2, 0), &b, &key)]);
    assert_eq!(state(&n, "b"), None);
    assert_eq!(n.metrics().signatures_invalid, 0);
}

#[test]
fn signed_left() {
    let b = cert("b");
    let key = member_key("b");
    let left = |inc| Dead {
        inc,
        node: id("b"),
        from: id("b"),
        epoch: EPOCH - 2,
    };
    let mut peer = Peer::new();

    let mut n = node();
    knows(&mut n, &mut peer, "b", 2);
    peer.v2(&mut n, &[corrupt(signed_dead(left(0), &b, &key))]);
    assert_eq!(state(&n, "b"), Some(State::Alive), "bad");
    assert_eq!(n.metrics().signatures_invalid, 1);
    peer.v2(&mut n, &[signed_dead(left(0), &b, &member_key("c"))]);
    assert_eq!(state(&n, "b"), Some(State::Alive), "wrong signer");
    assert_eq!(n.metrics().signatures_invalid, 2);
    peer.v2(&mut n, &[signed_dead(left(0), &b, &key)]);
    assert_eq!(state(&n, "b"), Some(State::Left), "good");

    let mut n = node();
    knows(&mut n, &mut peer, "b", 2);
    peer.v1(&mut n, &[Message::Dead(left(0))]);
    assert_eq!(
        state(&n, "b"),
        Some(State::Left),
        "missing: unsigned, accepted"
    );

    // A member held unsigned, whose Left brings a certificate that must be refused.
    for (what, bad) in bad_certs("b") {
        let mut n = node();
        knows_unsigned(&mut n, &mut peer, "b", 2);
        peer.v2(
            &mut n,
            &[certificate(&bad), signed_dead(left(0), &bad, &key)],
        );
        assert_eq!(state(&n, "b"), Some(State::Alive), "{what}");
        assert_eq!(n.metrics().certificates_refused, 1, "{what}");
    }
}

#[test]
fn signed_suspect_statements() {
    let c = cert("c");
    let key = member_key("c");
    let suspect = |inc| Suspect {
        inc,
        node: id("b"),
        from: id("c"),
        epoch: EPOCH - 2,
    };
    let mut peer = Peer::new();
    let mut n = node();
    knows(&mut n, &mut peer, "b", 2);
    knows(&mut n, &mut peer, "c", 3);

    peer.v2(&mut n, &[corrupt(signed_suspect(suspect(0), &c, &key))]);
    assert_eq!(state(&n, "b"), Some(State::Alive), "bad");
    assert_eq!(n.metrics().signatures_invalid, 1);
    peer.v2(&mut n, &[signed_suspect(suspect(0), &c, &member_key("b"))]);
    assert_eq!(state(&n, "b"), Some(State::Alive), "wrong signer");
    assert_eq!(n.metrics().signatures_invalid, 2);
    peer.v2(&mut n, &[signed_suspect(suspect(0), &c, &key)]);
    assert_eq!(state(&n, "b"), Some(State::Suspect), "good");

    let mut n = node();
    knows(&mut n, &mut peer, "b", 2);
    peer.v1(&mut n, &[Message::Suspect(suspect(0))]);
    assert_eq!(state(&n, "b"), Some(State::Suspect), "missing: unsigned");

    for (what, bad) in bad_certs("c") {
        let mut n = node();
        knows(&mut n, &mut peer, "b", 2);
        knows_unsigned(&mut n, &mut peer, "c", 3);
        peer.v2(
            &mut n,
            &[certificate(&bad), signed_suspect(suspect(0), &bad, &key)],
        );
        assert_eq!(state(&n, "b"), Some(State::Alive), "{what}");
        assert_eq!(n.metrics().certificates_refused, 1, "{what}");
    }

    // A reporter whose certificate expires while it is held: refused from then on. Its
    // accusation is about the node itself, which no probe of its own changes, and its
    // tombstone is kept, with its certificate, past the time it takes to die unanswered.
    let mut cfg = signing_config("a");
    cfg.dead_reclaim = Duration::from_secs(3_600);
    let mut n = node_with(cfg);
    let short = issue_with(&ca(), LABEL, "c", NOW - DAY, NOW + 60);
    peer.v2(
        &mut n,
        &[
            certificate(&short),
            signed_alive(alive("c", 3, 0), &short, &key),
        ],
    );
    assert_eq!(state(&n, "c"), Some(State::Alive));
    let later = Instant::ZERO + Duration::from_secs(60 + 301);
    n.handle_timeout(later);
    while n.poll_transmit().is_some() {}
    let about_me = Suspect {
        inc: 0,
        node: id("a"),
        from: id("c"),
        epoch: EPOCH,
    };
    let msg = signed_suspect(about_me, &short, &key);
    // Sealed at the node's cluster time, which has moved on.
    let mut nonce = peer.nonce();
    nonce[..8].copy_from_slice(&361_000u64.to_be_bytes());
    let mut pkt = Vec::new();
    peer.codec
        .seal_v2(
            WireVersion::V2,
            PacketKind::Datagram,
            &[msg],
            &nonce,
            &mut pkt,
        )
        .unwrap();
    n.handle_datagram(later, addr(3), &pkt);
    assert_eq!(n.metrics().certificates_refused, 1);
    assert_eq!(n.local().incarnation, 0, "not refuted");
}

#[test]
fn signed_dead_statements() {
    let c = cert("c");
    let key = member_key("c");
    let dead = |inc| Dead {
        inc,
        node: id("b"),
        from: id("c"),
        epoch: EPOCH - 2,
    };
    let mut peer = Peer::new();
    let mut n = node();
    knows(&mut n, &mut peer, "b", 2);
    knows(&mut n, &mut peer, "c", 3);

    peer.v2(&mut n, &[corrupt(signed_dead(dead(0), &c, &key))]);
    assert_eq!(state(&n, "b"), Some(State::Alive), "bad");
    peer.v2(&mut n, &[signed_dead(dead(0), &c, &member_key("b"))]);
    assert_eq!(state(&n, "b"), Some(State::Alive), "wrong signer");
    assert_eq!(n.metrics().signatures_invalid, 2);
    // Version 1 semantics until Stage 3: a third party's signed Dead kills at once.
    peer.v2(&mut n, &[signed_dead(dead(0), &c, &key)]);
    assert_eq!(state(&n, "b"), Some(State::Dead), "good");

    let mut n = node();
    knows(&mut n, &mut peer, "b", 2);
    peer.v1(&mut n, &[Message::Dead(dead(0))]);
    assert_eq!(state(&n, "b"), Some(State::Dead), "missing: unsigned");

    for (what, bad) in bad_certs("c") {
        let mut n = node();
        knows(&mut n, &mut peer, "b", 2);
        knows_unsigned(&mut n, &mut peer, "c", 3);
        peer.v2(
            &mut n,
            &[certificate(&bad), signed_dead(dead(0), &bad, &key)],
        );
        assert_eq!(state(&n, "b"), Some(State::Alive), "{what}");
        assert_eq!(n.metrics().certificates_refused, 1, "{what}");
    }
}

/// A version 2 push-pull request from "x" with `records`, the certificates `certs` beside it.
fn push_pull_frame(records: &[Record<'_>], certs: &[Vec<u8>], join: bool) -> Vec<u8> {
    let mut msgs: Vec<v2::Message<'_>> = certs.iter().map(|c| certificate(c)).collect();
    msgs.push(v2::Message::PushPull(v2::PushPull {
        join,
        records: Records::Slice(records),
        known_certificates: CertificateIds::Slice(&[]),
    }));
    let mut frame = Vec::new();
    codec()
        .seal_v2(
            WireVersion::V2,
            PacketKind::Stream,
            &msgs,
            &[0; 24],
            &mut frame,
        )
        .unwrap();
    frame
}

fn record<'a>(msg: v2::Message<'a>, state: RecordState) -> Record<'a> {
    let v2::Message::Alive(alive) = msg else {
        unreachable!()
    };
    Record { alive, state }
}

/// The frames `n` wrote, and whether it closed `conn`.
fn written(n: &mut Node) -> (Vec<Vec<u8>>, bool) {
    let mut frames = Vec::new();
    let mut closed = false;
    while let Some(t) = n.poll_transmit() {
        match t {
            Transmit::Stream { frame, .. } => frames.push(frame),
            Transmit::Close { .. } => closed = true,
            _ => {}
        }
    }
    (frames, closed)
}

#[test]
fn push_pull_record() {
    let names = ["b", "c", "d"];
    let certs: Vec<Vec<u8>> = names.iter().map(|n| cert(n)).collect();
    let alives: Vec<v2::Message<'_>> = names
        .iter()
        .zip(&certs)
        .zip(2u16..)
        .map(|((name, c), port)| signed_alive(alive(name, port, 0), c, &member_key(name)))
        .collect();
    let mut records: Vec<Record<'_>> = alives
        .iter()
        .map(|&m| record(m, RecordState::Alive))
        .collect();
    // One bad record, c's: it is dropped alone, and the rest of the frame merges.
    records[1].alive.signature[0] ^= 1;
    let mut n = node();
    let frame = push_pull_frame(&records, &certs, false);
    n.handle_stream(
        Instant::ZERO,
        StreamId::inbound(0),
        StreamEvent::Frame(&frame),
    );
    assert_eq!(state(&n, "b"), Some(State::Alive));
    assert_eq!(state(&n, "c"), None);
    assert_eq!(state(&n, "d"), Some(State::Alive));
    assert_eq!(n.metrics().signatures_invalid, 1);
    assert_eq!(n.metrics().push_pulls_served, 1);
    // Answered at version 2 with a's own record and the certificates x did not list.
    let (frames, closed) = written(&mut n);
    assert!(closed);
    let mut reply = frames[0][4..].to_vec();
    assert_eq!(reply[2], 2, "version 2");
    let payload = codec().open_v2(PacketKind::Stream, &mut reply).unwrap();
    let certs = payload
        .iter()
        .filter(|m| matches!(m, v2::Message::Certificate(_)))
        .count();
    let records = payload
        .iter()
        .find_map(|m| match m {
            v2::Message::PushPull(p) => Some(p.records.len()),
            _ => None,
        })
        .unwrap();
    assert_eq!(
        (records, certs),
        (3, 3),
        "a, b and d, with their certificates"
    );

    // A bad signature on a record that claims a member suspected is dropped alone too.
    let mut n = node();
    let mut peer = Peer::new();
    knows(&mut n, &mut peer, "b", 2);
    let mut claim = record(alives[0], RecordState::Suspect { inc: 0 });
    claim.alive.signature[0] ^= 1;
    let frame = push_pull_frame(&[claim], &[], false);
    n.handle_stream(
        Instant::ZERO,
        StreamId::inbound(0),
        StreamEvent::Frame(&frame),
    );
    assert_eq!(state(&n, "b"), Some(State::Alive));
    assert_eq!(n.metrics().signatures_invalid, 1);
}

#[test]
fn a_large_frame_spends_its_checks_over_several_inputs() {
    let names: Vec<String> = (0..100).map(|i| format!("m{i:03}")).collect();
    let keys: Vec<SigningKey> = (0..100u8)
        .map(|i| SigningKey::from_bytes([100 + i; 32]))
        .collect();
    let certs: Vec<Vec<u8>> = names
        .iter()
        .zip(&keys)
        .map(|(name, key)| {
            Certificate::issue(
                &ca(),
                LABEL,
                id(name),
                key.public_key(),
                NOW - DAY,
                NOW + DAY,
            )
            .unwrap()
            .encode()
        })
        .collect();
    let records: Vec<Record<'_>> = names
        .iter()
        .zip(&certs)
        .zip(&keys)
        .zip(1000u16..)
        .map(|(((name, c), key), port)| {
            record(
                signed_alive(alive(name, port, 0), c, key),
                RecordState::Alive,
            )
        })
        .collect();
    let mut n = node();
    let frame = push_pull_frame(&records, &certs, false);
    n.handle_stream(
        Instant::ZERO,
        StreamId::inbound(0),
        StreamEvent::Frame(&frame),
    );
    let held = |n: &Node| n.members().count() - 1;
    // A certificate and an Alive to check for each: 64 checks admit 32 members.
    assert_eq!(held(&n), 32);
    assert_eq!(
        n.poll_timeout(),
        Some(Instant::ZERO),
        "the rest wait for the next input"
    );
    let mut inputs = 1;
    while held(&n) < 100 {
        n.handle_timeout(Instant::ZERO);
        inputs += 1;
        assert!(inputs < 10);
    }
    assert_eq!(inputs, 4);
    assert_ne!(n.poll_timeout(), Some(Instant::ZERO));
    assert_eq!(n.metrics().unsigned_members, 0);
}

#[test]
fn signed_rumours_go_at_version_2_to_members_that_speak_it() {
    let mut n = node();
    let mut peer = Peer::new();
    knows(&mut n, &mut peer, "b", 2);
    // A member on 0.4, which speaks version 1 only.
    peer.v1(
        &mut n,
        &[Message::Alive(Alive {
            vmax: 1,
            ..alive("c", 3, 0)
        })],
    );
    while n.poll_transmit().is_some() {}
    // a suspects c on its own: a signed rumour.
    let s = Suspect {
        inc: 0,
        node: id("c"),
        from: id("b"),
        epoch: EPOCH - 3,
    };
    peer.v2(&mut n, &[signed_suspect(s, &cert("b"), &member_key("b"))]);
    let mut seen = Vec::new();
    let until = Instant::ZERO + Duration::from_secs(2);
    while let Some(t) = n.poll_timeout().filter(|&t| t <= until) {
        n.handle_timeout(t);
        while let Some(t) = n.poll_transmit() {
            if let Transmit::Datagram { to, payload } = t {
                seen.push((to, payload[2]));
            }
        }
    }
    let versions = |port| -> Vec<u8> {
        let mut v: Vec<u8> = seen
            .iter()
            .filter(|(to, _)| *to == addr(port))
            .map(|&(_, v)| v)
            .collect();
        v.sort();
        v.dedup();
        v
    };
    assert!(versions(2).contains(&2), "b speaks version 2: {seen:?}");
    assert_eq!(versions(3), [1], "c only ever gets version 1");
}

#[test]
fn seeds_are_tried_at_version_2_then_version_1() {
    let mut n = node();
    let cmd = n.command(
        Instant::ZERO,
        Command::Join {
            seeds: vec![addr(9)],
        },
    );
    let frames = |n: &mut Node| -> Vec<u8> {
        let mut versions = Vec::new();
        while let Some(t) = n.poll_transmit() {
            if let Transmit::Stream { frame, .. } = t {
                versions.push(frame[4 + 2]);
            }
        }
        versions
    };
    // The first attempt: the exchange of signed records, and the version 1 one beside it.
    assert_eq!(frames(&mut n), [2, 1]);
    // Both connections fail; the second attempt is at version 1 only, the third at both.
    let fail = |n: &mut Node, conns: std::ops::Range<u64>| {
        for c in conns {
            n.handle_stream(Instant::ZERO, StreamId::outbound(c), StreamEvent::Failed);
        }
    };
    // Runs the node until it writes frames again: the next attempt.
    let retry = |n: &mut Node| loop {
        let t = n.poll_timeout().unwrap();
        n.handle_timeout(t);
        let v = frames(n);
        if !v.is_empty() {
            break v;
        }
    };
    fail(&mut n, 0..2);
    assert_eq!(retry(&mut n), [1]);
    fail(&mut n, 2..3);
    assert_eq!(retry(&mut n), [2, 1]);
    fail(&mut n, 3..5);
    let done = events(&mut n)
        .into_iter()
        .any(|e| matches!(e, Event::CommandDone { id, result: Err(_) } if id == cmd));
    assert!(done, "three attempts, then the join fails");
}

#[test]
fn off_takes_no_version_2_packet() {
    let mut n = node_with(Config::lan(Security::Keys(vec![cluster_key()])));
    let mut peer = Peer::new();
    let b = cert("b");
    peer.v2(
        &mut n,
        &[
            certificate(&b),
            signed_alive(alive("b", 2, 0), &b, &member_key("b")),
        ],
    );
    assert_eq!(state(&n, "b"), None);
    assert_eq!(n.metrics().decode_errors, 1);
    assert_eq!(n.metrics().unsigned_members, 0);
    let mut head = Vec::new();
    peer.codec
        .seal_v2(
            WireVersion::V2,
            PacketKind::Stream,
            &[certificate(&b)],
            &[0; 24],
            &mut head,
        )
        .unwrap();
    assert!(n.header_check().check(PacketKind::Stream, &head).is_err());
    assert!(
        node()
            .header_check()
            .check(PacketKind::Stream, &head)
            .is_ok()
    );
}

#[test]
fn the_config_is_checked() {
    let field = |cfg: Config, me: Identity| {
        Node::new(cfg, me, Instant::ZERO, 1, &[1; 32])
            .map(|_| ())
            .unwrap_err()
            .field
    };
    let me = || Identity::new("a", addr(1)).unwrap().with_epoch(EPOCH);
    let with = |f: &dyn Fn(&mut Credentials)| {
        let mut cfg = signing_config("a");
        let Signatures::Sign(c) = &mut cfg.signatures else {
            unreachable!()
        };
        f(c);
        cfg
    };
    // Identities need encryption.
    let mut plain = signing_config("a");
    plain.security = Security::InsecurePlaintext;
    assert_eq!(field(plain, me()), "signatures");
    assert_eq!(
        field(with(&|c| c.trust_anchors.clear()), me()),
        "trust_anchors"
    );
    assert_eq!(
        field(with(&|c| c.certificate.truncate(10)), me()),
        "certificate"
    );
    assert_eq!(
        field(with(&|c| c.signing_key = member_key("z")), me()),
        "certificate",
        "the certificate is for another key"
    );
    for (what, bad) in bad_certs("a") {
        assert_eq!(
            field(with(&|c| c.certificate = bad.clone()), me()),
            "certificate",
            "{what}"
        );
    }
    // The node: an epoch, its own name, and the clock.
    assert_eq!(field(signing_config("a"), me().with_epoch(0)), "epoch");
    let b = Identity::new("b", addr(1)).unwrap().with_epoch(EPOCH);
    assert_eq!(field(signing_config("a"), b), "certificate");
    // A datagram too small for a signed Alive behind its certificate.
    let mut small = signing_config("a");
    small.limits.udp_max_payload = 900;
    assert_eq!(field(small, me()), "udp_max_payload");
    let ok = Node::new(signing_config("a"), me(), Instant::ZERO, 1, &[1; 32]).unwrap();
    assert_eq!(ok.local().epoch, EPOCH);
}
