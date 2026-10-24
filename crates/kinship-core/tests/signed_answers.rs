//! Mode `sign`, KI-01 Stage 2b (`docs/ki01-stage2.md`): probe answers, user messages and
//! broadcasts.
//!
//! For each of Ack, Nack, UserMessage and UserBroadcast: a good signature is taken, a bad one
//! and one by the wrong signer are dropped and counted, a missing one (version 1) is taken only
//! where mode `sign` takes unsigned statements, which an Ack or Nack of a version 2 round is
//! not, and a certificate that is expired, not yet valid, for another cluster or from an
//! unknown anchor is refused. Then, between real nodes: an Ack harvested from the live target
//! for a future round does not answer that round once the target crashed, a relay forwards the
//! target's Ack byte for byte and a relay's forged Ack is refused, a TCP fallback round is
//! answered with the round's own challenge, version 2 probe packets carry the signed rumours,
//! and a direct message signed over its packet's nonce arrives, once however often its proof
//! repeats in the packet. Last, three found by the 1,000-seed sweeps in mode `sign` (Stage
//! 2c): an Ack to a relay's Ping goes behind the target's certificate, a later life heard of
//! unsigned gets version 1 rounds, and a member back from the dead is relayed behind its
//! certificate.

use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;

use kinship_core::{
    Command, Config, Credentials, Event, Identity, Instant, Key, Limits, Metrics, Node, Rng,
    Security, Signatures, SigningKey, State, StreamEvent, StreamId, Transmit,
};
use kinship_proto::identity::{Certificate, CertificateId};
use kinship_proto::v2::{self, ProbeChallenge, SignedAlive};
use kinship_proto::{
    Alive, Codec, Message, NodeId, PacketKind, UserBroadcast, UserMessage, VersionedPayload,
    WireVersion,
};

/// The wall clock when the nodes start, in milliseconds: September 2026.
const EPOCH: u64 = 1_790_000_000_000;
const NOW: u64 = EPOCH / 1000;
const DAY: u64 = 86_400;
const LABEL: &[u8] = b"default";

/// `N` bytes drawn from the RNG seeded with `seed`, the same in every run.
fn drawn<const N: usize>(seed: u64) -> [u8; N] {
    let mut rng = Rng::new(seed);
    std::array::from_fn(|_| rng.next_u64().to_le_bytes()[0])
}

/// A seed for `name`, from its bytes.
fn seed_of(name: &str) -> u64 {
    name.bytes()
        .fold(0x6b69_6e73, |s, b| s.rotate_left(8) ^ u64::from(b))
}

fn addr(port: u16) -> SocketAddr {
    SocketAddr::from(([127, 0, 0, 1], port))
}

fn id(name: &str) -> NodeId<'_> {
    NodeId::new(name).unwrap()
}

fn cluster_key() -> Key {
    Key::from_bytes(drawn(0x6b65_7973))
}

fn ca() -> SigningKey {
    SigningKey::from_bytes(drawn(0xca))
}

/// The signing key of member `name`.
fn member_key(name: &str) -> SigningKey {
    SigningKey::from_bytes(drawn(seed_of(name)))
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

/// Why each of [`bad_certs`] is refused, in order.
const REFUSALS: [&str; 4] = [
    "expired",
    "not yet valid",
    "another cluster",
    "unknown anchor",
];

/// The certificates that must be refused, each for `name`'s own key, in the order of
/// [`REFUSALS`].
fn bad_certs(name: &str) -> [Vec<u8>; 4] {
    let other_ca = SigningKey::from_bytes(drawn(0xbad));
    [
        issue_with(&ca(), LABEL, name, NOW - 3 * DAY, NOW - DAY),
        issue_with(&ca(), LABEL, name, NOW + DAY, NOW + 3 * DAY),
        issue_with(&ca(), b"other", name, NOW - DAY, NOW + DAY),
        issue_with(&other_ca, LABEL, name, NOW - DAY, NOW + DAY),
    ]
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

/// Member `name` at `port`, in mode `sign`, started at the wall clock `EPOCH + port`.
fn signing_node(name: &str, port: u16) -> Node {
    let me = Identity::new(name, addr(port))
        .unwrap()
        .with_epoch(EPOCH + u64::from(port));
    let seed = seed_of(name);
    Node::new(signing_config(name), me, Instant::ZERO, seed, &drawn(seed)).unwrap()
}

/// The Alive member `name` at `port` signs at start.
fn alive(name: &str, port: u16) -> Alive<'_> {
    Alive {
        inc: 0,
        node: id(name),
        addr: addr(port),
        meta: b"",
        vmin: 1,
        vmax: 2,
        epoch: EPOCH + u64::from(port),
    }
}

fn codec() -> Codec {
    Codec::encrypted(LABEL, Limits::default(), vec![cluster_key()]).unwrap()
}

/// A nonce stamped at cluster time `ms`, numbered `n` after it.
fn nonce_at(ms: u64, n: u64) -> [u8; 24] {
    let (stamp, count) = (ms.to_be_bytes(), n.to_be_bytes());
    std::array::from_fn(|i| match i {
        0..8 => stamp[i],
        8..16 => count[i - 8],
        _ => 0,
    })
}

/// Fills in `msg`'s certificate id and signature: by `key`, under certificate `cert`, over
/// `nonce` for a direct message.
fn sign<'a>(
    mut msg: v2::Message<'a>,
    cert: &[u8],
    key: &SigningKey,
    nonce: Option<&[u8; 24]>,
) -> v2::Message<'a> {
    let cert = cert_id(cert);
    match &mut msg {
        v2::Message::Alive(a) => a.certificate_id = cert,
        v2::Message::Ack { certificate_id, .. }
        | v2::Message::Nack { certificate_id, .. }
        | v2::Message::UserMessage { certificate_id, .. }
        | v2::Message::UserBroadcast { certificate_id, .. } => *certificate_id = cert,
        _ => unreachable!(),
    }
    let sig = key.sign(&msg.signed_bytes(LABEL, nonce).unwrap());
    match &mut msg {
        v2::Message::Alive(a) => a.signature = sig,
        v2::Message::Ack { signature, .. }
        | v2::Message::Nack { signature, .. }
        | v2::Message::UserMessage { signature, .. }
        | v2::Message::UserBroadcast { signature, .. } => *signature = sig,
        _ => unreachable!(),
    }
    msg
}

/// `msg` with one bit of its signature flipped.
fn corrupt(mut msg: v2::Message<'_>) -> v2::Message<'_> {
    match &mut msg {
        v2::Message::Ack { signature, .. }
        | v2::Message::Nack { signature, .. }
        | v2::Message::UserMessage { signature, .. }
        | v2::Message::UserBroadcast { signature, .. } => signature[0] ^= 1,
        _ => unreachable!(),
    }
    msg
}

fn certificate(bytes: &[u8]) -> v2::Message<'_> {
    v2::Message::Certificate(Certificate::decode(bytes).unwrap())
}

/// The signed Alive of member `name` at `port`, behind its certificate.
fn introduction<'a>(name: &'a str, port: u16, c: &'a [u8]) -> [v2::Message<'a>; 2] {
    let unsigned = v2::Message::Alive(SignedAlive {
        alive: alive(name, port),
        certificate_id: CertificateId::default(),
        signature: [0; 64],
    });
    [certificate(c), sign(unsigned, c, &member_key(name), None)]
}

/// The messages of a datagram or frame a node sent: `Ok` with those of a version 2 packet,
/// `Err` with those of a version 1 one, as debug text.
fn opened(packet: &[u8], kind: PacketKind) -> Result<Vec<Vec<u8>>, Vec<String>> {
    let mut buf = packet.to_vec();
    match codec().open_versioned(kind, &mut buf).unwrap() {
        VersionedPayload::V2(p) => Ok(p
            .iter()
            .map(|m| v2::encode_payload(&[m], &Limits::default()).unwrap())
            .collect()),
        VersionedPayload::V1(p) => Err(p.iter().map(|m| format!("{m:?}")).collect()),
    }
}

/// Parses one message encoded alone by [`opened`].
fn parse(one: &[u8]) -> v2::Message<'_> {
    v2::Payload::parse(one, &Limits::default())
        .unwrap()
        .iter()
        .next()
        .unwrap()
}

/// A node under test with fake peers: it is handed packets the test builds and sends what it
/// would, which the test reads. Peers answer its version 2 Pings with their signed Acks,
/// except the silent ones.
struct Lone {
    node: Node,
    now: Instant,
    next: u64,
    sent: Vec<(SocketAddr, Vec<u8>)>,
    /// The peers that answer Pings, by port.
    answering: BTreeMap<u16, String>,
}

impl Lone {
    /// Node "a" at port 1, which holds every name in `peers` signed, at port 2 onwards; all
    /// but those in `silent` answer its Pings.
    fn new(peers: &[&str], silent: &[&str]) -> Self {
        let mut lone = Self {
            node: signing_node("a", 1),
            now: Instant::ZERO,
            next: 0,
            sent: Vec::new(),
            answering: BTreeMap::new(),
        };
        for (name, port) in peers.iter().zip(2u16..) {
            let c = cert(name);
            lone.v2(&introduction(name, port, &c));
            assert_eq!(lone.state(name), Some(State::Alive), "peer known");
            if !silent.contains(name) {
                lone.answering.insert(port, (*name).to_owned());
            }
        }
        lone
    }

    fn state(&self, name: &str) -> Option<State> {
        self.node.member(name).map(|m| m.state)
    }

    fn metrics(&self) -> Metrics {
        self.node.metrics().clone()
    }

    /// A fresh nonce at the node's cluster time.
    fn nonce(&mut self) -> [u8; 24] {
        self.next += 1;
        nonce_at(self.now.as_nanos() / 1_000_000, self.next)
    }

    fn v2(&mut self, msgs: &[v2::Message<'_>]) {
        let nonce = self.nonce();
        self.v2_at(msgs, &nonce);
    }

    fn v2_at(&mut self, msgs: &[v2::Message<'_>], nonce: &[u8; 24]) {
        let mut pkt = Vec::new();
        codec()
            .seal_v2(WireVersion::V2, PacketKind::Datagram, msgs, nonce, &mut pkt)
            .unwrap();
        self.node.handle_datagram(self.now, addr(99), &pkt);
        self.drain();
    }

    fn v1(&mut self, msgs: &[Message<'_>]) {
        let nonce = self.nonce();
        let mut pkt = Vec::new();
        codec()
            .seal(PacketKind::Datagram, msgs, &nonce, &mut pkt)
            .unwrap();
        self.node.handle_datagram(self.now, addr(99), &pkt);
        self.drain();
    }

    /// Keeps the datagrams the node sent, and answers the Pings to answering peers; streams are
    /// refused.
    fn drain(&mut self) {
        let mut pinged = Vec::new();
        while let Some(t) = self.node.poll_transmit() {
            match t {
                Transmit::Datagram { to, payload } => {
                    if let Some(name) = self.answering.get(&to.port()) {
                        let msgs = opened(&payload, PacketKind::Datagram).unwrap_or_default();
                        let pings = msgs.iter().map(|m| parse(m)).filter(is_ping);
                        pinged.extend(pings.map(|m| (round_of(&m), name.clone(), to.port())));
                    }
                    self.sent.push((to, payload));
                }
                Transmit::Connect { conn, .. } => {
                    self.node.handle_stream(self.now, conn, StreamEvent::Failed);
                }
                _ => {}
            }
        }
        for (r, name, port) in pinged {
            let answer = sign(ack(r, &name, port), &cert(&name), &member_key(&name), None);
            self.v2(&[answer]);
        }
    }

    /// Runs the node's timers until `until`.
    fn run(&mut self, until: Instant) {
        while let Some(t) = self.node.poll_timeout().filter(|&t| t <= until) {
            self.now = self.now.max(t);
            self.node.handle_timeout(self.now);
            self.drain();
        }
        self.now = self.now.max(until);
    }

    /// Runs until the node sends a version 2 message to `port` that `pick` accepts, and
    /// returns its encoding.
    fn until_sent(&mut self, port: u16, pick: impl Fn(&v2::Message<'_>) -> bool) -> Vec<u8> {
        let deadline = self.now + Duration::from_secs(30);
        loop {
            let found = self.sent.drain(..).find_map(|(to, payload)| {
                if to != addr(port) {
                    return None;
                }
                let msgs = opened(&payload, PacketKind::Datagram).ok()?;
                msgs.into_iter().find(|m| pick(&parse(m)))
            });
            if let Some(m) = found {
                return m;
            }
            let t = self.node.poll_timeout().unwrap();
            assert!(t <= deadline, "nothing sent to port {port}");
            self.now = self.now.max(t);
            self.node.handle_timeout(self.now);
            self.drain();
        }
    }

    /// Ends the round in progress.
    fn end_round(&mut self) {
        let end = self.now + self.node.config().probe_interval;
        self.run(end);
    }
}

/// The binding of a version 2 round, read off its Ping or PingReq.
#[derive(Debug, Clone, Copy)]
struct Round {
    seq: u32,
    epoch: u64,
    challenge: ProbeChallenge,
}

fn round_of(msg: &v2::Message<'_>) -> Round {
    match *msg {
        v2::Message::Ping {
            ping,
            source_epoch,
            challenge,
            requester: None,
        } => Round {
            seq: ping.seq,
            epoch: source_epoch,
            challenge,
        },
        v2::Message::PingReq {
            request,
            requester_epoch,
            challenge,
            ..
        } => Round {
            seq: request.seq,
            epoch: requester_epoch,
            challenge,
        },
        _ => unreachable!(),
    }
}

fn is_ping(m: &v2::Message<'_>) -> bool {
    matches!(m, v2::Message::Ping { .. })
}

fn is_ping_req(m: &v2::Message<'_>) -> bool {
    matches!(m, v2::Message::PingReq { .. })
}

/// The Ack that member `target` at `port` sends for round `r` of "a".
fn ack(r: Round, target: &str, port: u16) -> v2::Message<'_> {
    v2::Message::Ack {
        seq: r.seq,
        target_epoch: EPOCH + u64::from(port),
        requester: id("a"),
        requester_epoch: r.epoch,
        target: id(target),
        challenge: r.challenge,
        certificate_id: CertificateId::default(),
        signature: [0; 64],
    }
}

/// The Nack that relay `relay` at `port` sends for round `r` of "a" to target "b".
fn nack(r: Round, relay: &str, port: u16) -> v2::Message<'_> {
    v2::Message::Nack {
        seq: r.seq,
        relay: id(relay),
        relay_epoch: EPOCH + u64::from(port),
        requester: id("a"),
        requester_epoch: r.epoch,
        target: id("b"),
        challenge: r.challenge,
        certificate_id: CertificateId::default(),
        signature: [0; 64],
    }
}

#[test]
fn probes_to_a_member_that_signs_are_version_2_rounds() {
    let mut a = Lone::new(&["b"], &[]);
    let ping = a.until_sent(2, is_ping);
    let r = round_of(&parse(&ping));
    assert_eq!(r.epoch, EPOCH + 1);
    // The next round draws a new challenge.
    a.end_round();
    let next = round_of(&parse(&a.until_sent(2, is_ping)));
    assert_eq!(next.seq, r.seq + 1);
    assert_ne!(next.challenge, r.challenge);
}

#[test]
fn ack_statements() {
    let b = cert("b");
    let key = member_key("b");
    // Runs a round of "a" to "b", answered with what `answer` sends: the round is answered if
    // it ends with no failed probe.
    let round = |answer: &dyn Fn(&mut Lone, Round)| {
        let mut a = Lone::new(&["b"], &["b"]);
        let r = round_of(&parse(&a.until_sent(2, is_ping)));
        answer(&mut a, r);
        a.end_round();
        let m = a.metrics();
        (m.probes_failed == 0, m)
    };

    let (answered, m) = round(&|a, r| a.v2(&[sign(ack(r, "b", 2), &b, &key, None)]));
    assert!(answered, "good: {m:?}");

    let (answered, m) = round(&|a, r| a.v2(&[corrupt(sign(ack(r, "b", 2), &b, &key, None))]));
    assert!(!answered, "bad");
    assert_eq!(m.signatures_invalid, 1);

    // Missing: a version 1 Ack names a sequence number alone, and answers no version 2 round.
    let (answered, m) = round(&|a, r| a.v1(&[Message::Ack { seq: r.seq }]));
    assert!(!answered, "missing");
    assert_eq!(m.signatures_invalid, 0);

    let (answered, m) = round(&|a, r| a.v2(&[sign(ack(r, "b", 2), &b, &member_key("c"), None)]));
    assert!(!answered, "wrong signer");
    assert_eq!(m.signatures_invalid, 1);

    // Not this round's: another challenge, another sequence number, another requester epoch.
    // Dropped unchecked.
    for (what, f) in [
        (
            "challenge",
            (|r: &mut Round| r.challenge[0] ^= 1) as fn(&mut Round),
        ),
        ("seq", |r| r.seq += 1),
        ("epoch", |r| r.epoch += 1),
    ] {
        let (answered, m) = round(&|a, mut r| {
            f(&mut r);
            a.v2(&[sign(ack(r, "b", 2), &b, &key, None)]);
        });
        assert!(!answered, "another {what}");
        assert_eq!(m.signatures_invalid, 0, "another {what}");
    }

    let certs = bad_certs("b");
    for (i, what) in REFUSALS.into_iter().enumerate() {
        let bad = certs[i].clone();
        let (answered, m) = round(&|a, r| {
            a.v2(&[certificate(&bad), sign(ack(r, "b", 2), &bad, &key, None)]);
        });
        assert!(!answered, "{what}");
        assert_eq!(m.certificates_refused, 1, "{what}");
    }

    // Once answered, a copy costs nothing more.
    let (answered, m) = round(&|a, r| {
        let good = sign(ack(r, "b", 2), &b, &key, None);
        a.v2(&[good]);
        a.v2(&[corrupt(good)]);
    });
    assert!(answered);
    assert_eq!(m.signatures_invalid, 0, "the copy is not checked");
}

#[test]
fn nack_statements() {
    // "a" probes "b", which never answers, through relays "c" and "d". Returns the Nacks that
    // counted: of the two relays asked, the rest are missed.
    let round = |answer: &dyn Fn(&mut Lone, Round)| {
        let mut a = Lone::new(&["b", "c", "d"], &["b"]);
        let ping = round_of(&parse(&a.until_sent(2, is_ping)));
        let req = round_of(&parse(&a.until_sent(3, is_ping_req)));
        assert_eq!((req.seq, req.challenge), (ping.seq, ping.challenge));
        answer(&mut a, req);
        a.end_round();
        let m = a.metrics();
        assert_eq!(m.probes_failed, 1);
        (2 - m.missed_nacks, m)
    };
    let c = cert("c");
    let key = member_key("c");

    let (counted, m) = round(&|a, r| a.v2(&[sign(nack(r, "c", 3), &c, &key, None)]));
    assert_eq!(counted, 1, "good: {m:?}");

    // One Nack per relay asked, however often it comes.
    let (counted, m) = round(&|a, r| {
        let good = sign(nack(r, "c", 3), &c, &key, None);
        a.v2(&[good, good]);
        a.v2(&[good]);
        a.v2(&[corrupt(good)]);
    });
    assert_eq!(counted, 1, "once");
    assert_eq!(m.signatures_invalid, 0, "copies are not checked");
    let (counted, _) = round(&|a, r| {
        a.v2(&[sign(nack(r, "c", 3), &c, &key, None)]);
        a.v2(&[sign(nack(r, "d", 4), &cert("d"), &member_key("d"), None)]);
    });
    assert_eq!(counted, 2, "each relay once");
    // From a member that was not asked.
    let (counted, m) =
        round(&|a, r| a.v2(&[sign(nack(r, "b", 2), &cert("b"), &member_key("b"), None)]));
    assert_eq!(counted, 0, "not asked");
    assert_eq!(m.signatures_invalid, 0);

    let (counted, m) = round(&|a, r| a.v2(&[corrupt(sign(nack(r, "c", 3), &c, &key, None))]));
    assert_eq!(counted, 0, "bad");
    assert_eq!(m.signatures_invalid, 1);

    let (counted, m) = round(&|a, r| a.v1(&[Message::Nack { seq: r.seq }]));
    assert_eq!(
        counted, 0,
        "missing: a version 1 Nack counts in no version 2 round"
    );
    assert_eq!(m.signatures_invalid, 0);

    let (counted, m) = round(&|a, r| a.v2(&[sign(nack(r, "c", 3), &c, &member_key("d"), None)]));
    assert_eq!(counted, 0, "wrong signer");
    assert_eq!(m.signatures_invalid, 1);

    let certs = bad_certs("c");
    for (i, what) in REFUSALS.into_iter().enumerate() {
        let bad = certs[i].clone();
        let (counted, m) = round(&|a, r| {
            a.v2(&[certificate(&bad), sign(nack(r, "c", 3), &bad, &key, None)]);
        });
        assert_eq!(counted, 0, "{what}");
        assert_eq!(m.certificates_refused, 1, "{what}");
    }
}

/// A direct message from "b" at port 2 to "a".
fn direct(data: &[u8]) -> v2::Message<'_> {
    v2::Message::UserMessage {
        message: UserMessage {
            to: id("a"),
            to_epoch: EPOCH + 1,
            from: id("b"),
            from_epoch: EPOCH + 2,
            data,
        },
        certificate_id: CertificateId::default(),
        signature: [0; 64],
    }
}

/// Broadcast number `seq` from "b" at port 2.
fn broadcast(seq: u64, data: &[u8]) -> v2::Message<'_> {
    v2::Message::UserBroadcast {
        broadcast: UserBroadcast {
            from: id("b"),
            from_epoch: EPOCH + 2,
            seq,
            data,
        },
        certificate_id: CertificateId::default(),
        signature: [0; 64],
    }
}

fn delivered(n: &mut Node) -> Vec<Vec<u8>> {
    std::iter::from_fn(|| n.poll_event())
        .filter_map(|e| match e {
            Event::UserMessage { data, .. } => Some(data),
            _ => None,
        })
        .collect()
}

#[test]
fn user_message_statements() {
    let b = cert("b");
    let key = member_key("b");
    let fresh = || {
        let mut a = Lone::new(&["b"], &[]);
        delivered(&mut a.node);
        a
    };
    // Signed over the nonce of the packet that carries it.
    let bound = |a: &mut Lone, msgs: &dyn Fn(&[u8; 24]) -> Vec<v2::Message<'static>>| {
        let nonce = a.nonce();
        a.v2_at(&msgs(&nonce), &nonce);
        delivered(&mut a.node)
    };

    let mut a = fresh();
    let got = bound(&mut a, &|n| vec![sign(direct(b"hi"), &b, &key, Some(n))]);
    assert_eq!(got, [b"hi"], "good");
    assert_eq!(a.metrics().user_messages_received, 1);

    // A packet with the same proof three times delivers it once, with one check.
    let mut a = fresh();
    let got = bound(&mut a, &|n| vec![sign(direct(b"hi"), &b, &key, Some(n)); 3]);
    assert_eq!(got, [b"hi"], "repeated");
    let got = bound(&mut a, &|n| {
        vec![corrupt(sign(direct(b"hi"), &b, &key, Some(n))); 3]
    });
    assert!(got.is_empty());
    assert_eq!(a.metrics().signatures_invalid, 1, "one check for the three");

    let mut a = fresh();
    let got = bound(&mut a, &|n| {
        vec![corrupt(sign(direct(b"hi"), &b, &key, Some(n)))]
    });
    assert!(got.is_empty(), "bad");
    assert_eq!(a.metrics().signatures_invalid, 1);
    assert_eq!(a.metrics().user_messages_dropped, 1);

    // Signed over another packet's nonce: a recording moved into a fresh packet.
    let mut a = fresh();
    let other = nonce_at(0, 999);
    let got = bound(&mut a, &|_| {
        vec![sign(direct(b"hi"), &b, &key, Some(&other))]
    });
    assert!(got.is_empty(), "another nonce");
    assert_eq!(a.metrics().signatures_invalid, 1);

    // Missing: mode `sign` takes an unsigned message, from a version 1 packet.
    let mut a = fresh();
    let v2::Message::UserMessage { message, .. } = direct(b"hi") else {
        unreachable!()
    };
    a.v1(&[Message::UserMessage(message)]);
    assert_eq!(delivered(&mut a.node), [b"hi"], "missing");

    let mut a = fresh();
    let got = bound(&mut a, &|n| {
        vec![sign(direct(b"hi"), &b, &member_key("c"), Some(n))]
    });
    assert!(got.is_empty(), "wrong signer");
    assert_eq!(a.metrics().signatures_invalid, 1);

    let certs = bad_certs("b");
    for (i, what) in REFUSALS.into_iter().enumerate() {
        let bad = certs[i].clone();
        let mut a = fresh();
        let nonce = a.nonce();
        let msg = sign(direct(b"hi"), &bad, &key, Some(&nonce));
        a.v2_at(&[certificate(&bad), msg], &nonce);
        assert!(delivered(&mut a.node).is_empty(), "{what}");
        assert_eq!(a.metrics().certificates_refused, 1, "{what}");
    }
}

#[test]
fn user_broadcast_statements() {
    let b = cert("b");
    let key = member_key("b");
    let fresh = || {
        // "c" is there to relay to.
        let mut a = Lone::new(&["b", "c"], &[]);
        delivered(&mut a.node);
        a
    };
    // The broadcasts "a" relays to "c" within a few gossip ticks: Ok when signed.
    let relayed = |a: &mut Lone| {
        let until = a.now + Duration::from_secs(2);
        a.run(until);
        let mut out = Vec::new();
        for (to, payload) in a.sent.drain(..) {
            if to != addr(3) {
                continue;
            }
            match opened(&payload, PacketKind::Datagram) {
                Ok(msgs) => out.extend(
                    msgs.iter()
                        .filter(|m| matches!(parse(m), v2::Message::UserBroadcast { .. }))
                        .map(|_| Ok(())),
                ),
                Err(msgs) => out.extend(
                    msgs.iter()
                        .filter(|m| m.starts_with("UserBroadcast"))
                        .map(|_| Err(())),
                ),
            }
        }
        out.dedup();
        out
    };

    let mut a = fresh();
    a.v2(&[sign(broadcast(1, b"one"), &b, &key, None)]);
    assert_eq!(delivered(&mut a.node), [b"one"], "good");
    assert_eq!(relayed(&mut a), [Ok(())], "relayed signed");

    // Bad: neither delivered nor relayed nor remembered, so a good copy still counts.
    let mut a = fresh();
    a.v2(&[corrupt(sign(broadcast(1, b"one"), &b, &key, None))]);
    assert!(delivered(&mut a.node).is_empty(), "bad");
    assert_eq!(a.metrics().signatures_invalid, 1);
    assert!(relayed(&mut a).is_empty());
    a.v2(&[sign(broadcast(1, b"one"), &b, &key, None)]);
    assert_eq!(
        delivered(&mut a.node),
        [b"one"],
        "a good copy after a bad one"
    );
    // A copy of one already delivered costs no check.
    a.v2(&[corrupt(sign(broadcast(1, b"one"), &b, &key, None))]);
    assert_eq!(a.metrics().signatures_invalid, 1);

    // Missing: an unsigned broadcast from a version 1 packet is taken, and relayed unsigned.
    let mut a = fresh();
    let v2::Message::UserBroadcast {
        broadcast: plain, ..
    } = broadcast(1, b"one")
    else {
        unreachable!()
    };
    a.v1(&[Message::UserBroadcast(plain)]);
    assert_eq!(delivered(&mut a.node), [b"one"], "missing");
    assert_eq!(relayed(&mut a), [Err(())], "relayed unsigned");

    let mut a = fresh();
    a.v2(&[sign(broadcast(1, b"one"), &b, &member_key("c"), None)]);
    assert!(delivered(&mut a.node).is_empty(), "wrong signer");
    assert_eq!(a.metrics().signatures_invalid, 1);

    let certs = bad_certs("b");
    for (i, what) in REFUSALS.into_iter().enumerate() {
        let bad = certs[i].clone();
        let mut a = fresh();
        a.v2(&[
            certificate(&bad),
            sign(broadcast(1, b"one"), &bad, &key, None),
        ]);
        assert!(delivered(&mut a.node).is_empty(), "{what}");
        assert_eq!(a.metrics().certificates_refused, 1, "{what}");
        assert!(relayed(&mut a).is_empty(), "{what}");
    }
}

/// Real nodes on a network the test controls: node `i` is at port `i + 1`.
struct Net {
    nodes: Vec<Node>,
    now: Instant,
    /// Each end of a connection, mapped to the other end.
    conns: BTreeMap<(usize, StreamId), (usize, StreamId)>,
    accepted: u64,
    /// Datagrams from one node to another that are lost.
    lost: Vec<(usize, usize)>,
    /// Connections from one node to another that fail.
    refused: Vec<(usize, usize)>,
    crashed: Vec<usize>,
    /// Every datagram sent, lost or not: from, to, bytes.
    datagrams: Vec<(usize, usize, Vec<u8>)>,
    /// Every frame written: from, to, bytes without the length prefix.
    frames: Vec<(usize, usize, Vec<u8>)>,
}

impl Net {
    /// Signing nodes named `names`, each holding every other signed.
    fn new(names: &[&str]) -> Self {
        let mut nodes: Vec<Node> = names
            .iter()
            .zip(1u16..)
            .map(|(name, port)| signing_node(name, port))
            .collect();
        let mut next = 0;
        for (i, n) in nodes.iter_mut().enumerate() {
            for (j, (name, port)) in names.iter().zip(1u16..).enumerate() {
                if i == j {
                    continue;
                }
                next += 1;
                let c = cert(name);
                let mut pkt = Vec::new();
                codec()
                    .seal_v2(
                        WireVersion::V2,
                        PacketKind::Datagram,
                        &introduction(name, port, &c),
                        &nonce_at(0, next),
                        &mut pkt,
                    )
                    .unwrap();
                n.handle_datagram(Instant::ZERO, addr(port), &pkt);
            }
            while n.poll_event().is_some() {}
            while n.poll_transmit().is_some() {}
        }
        Self {
            nodes,
            now: Instant::ZERO,
            conns: BTreeMap::new(),
            accepted: 0,
            lost: Vec::new(),
            refused: Vec::new(),
            crashed: Vec::new(),
            datagrams: Vec::new(),
            frames: Vec::new(),
        }
    }

    fn index(to: SocketAddr) -> usize {
        usize::from(to.port() - 1)
    }

    fn pump(&mut self) {
        loop {
            let mut moved = false;
            for i in 0..self.nodes.len() {
                let out: Vec<Transmit> =
                    std::iter::from_fn(|| self.nodes[i].poll_transmit()).collect();
                for t in out {
                    moved = true;
                    self.deliver(i, t);
                }
            }
            if !moved {
                return;
            }
        }
    }

    fn deliver(&mut self, i: usize, t: Transmit) {
        let now = self.now;
        let from = self.nodes[i].local().addr;
        match t {
            Transmit::Datagram { to, payload } => {
                let j = Self::index(to);
                self.datagrams.push((i, j, payload.clone()));
                if !self.lost.contains(&(i, j)) && !self.crashed.contains(&j) {
                    self.nodes[j].handle_datagram(now, from, &payload);
                }
            }
            Transmit::Connect { conn, to } => {
                let j = Self::index(to);
                if self.refused.contains(&(i, j)) || self.crashed.contains(&j) {
                    self.nodes[i].handle_stream(now, conn, StreamEvent::Failed);
                    return;
                }
                let peer = StreamId::inbound(self.accepted);
                self.accepted += 1;
                self.conns.insert((i, conn), (j, peer));
                self.conns.insert((j, peer), (i, conn));
            }
            Transmit::Stream { conn, frame } => {
                if let Some(&(j, peer)) = self.conns.get(&(i, conn)) {
                    self.frames.push((i, j, frame[4..].to_vec()));
                    let ev = StreamEvent::Frame(&frame[4..]);
                    self.nodes[j].handle_stream(now, peer, ev);
                }
            }
            Transmit::Close { conn } => {
                if let Some((j, peer)) = self.conns.remove(&(i, conn)) {
                    self.conns.remove(&(j, peer));
                    self.nodes[j].handle_stream(now, peer, StreamEvent::Closed);
                }
            }
        }
    }

    /// Runs every node that has not crashed until `until`.
    fn run(&mut self, until: Instant) {
        loop {
            let next = (0..self.nodes.len())
                .filter(|i| !self.crashed.contains(i))
                .filter_map(|i| self.nodes[i].poll_timeout())
                .min();
            let Some(t) = next.filter(|&t| t <= until) else {
                break;
            };
            self.now = self.now.max(t);
            for i in 0..self.nodes.len() {
                let due = self.nodes[i].poll_timeout().is_some_and(|t| t <= self.now);
                if due && !self.crashed.contains(&i) {
                    self.nodes[i].handle_timeout(self.now);
                }
            }
            self.pump();
        }
        self.now = self.now.max(until);
    }

    fn command(&mut self, i: usize, cmd: Command) {
        self.nodes[i].command(self.now, cmd);
        self.pump();
    }

    /// The version 2 messages node `i` sent node `j` by datagram, each encoded alone.
    fn v2_sent(&self, i: usize, j: usize) -> Vec<Vec<u8>> {
        self.datagrams
            .iter()
            .filter(|(from, to, _)| (*from, *to) == (i, j))
            .filter_map(|(_, _, p)| opened(p, PacketKind::Datagram).ok())
            .flatten()
            .collect()
    }
}

fn secs(s: u64) -> Instant {
    Instant::ZERO + Duration::from_secs(s)
}

#[test]
fn an_ack_harvested_for_a_future_round_does_not_answer_it_after_the_target_crashed() {
    let mut net = Net::new(&["a", "b"]);
    net.run(secs(5));
    let (a, b) = (0, 1);
    assert_eq!(
        net.nodes[a].metrics().probes_failed,
        0,
        "b answers while it runs"
    );
    // The last round of a's that b answered, and its binding.
    let last = net
        .v2_sent(a, b)
        .iter()
        .map(|m| parse(m))
        .filter(is_ping)
        .map(|m| round_of(&m))
        .next_back()
        .unwrap();
    // A key holder asks the live b for its Ack to a's next round, with a challenge of its own.
    let harvest = Round {
        seq: last.seq + 1,
        challenge: drawn(0x6861_7276),
        ..last
    };
    let ping = v2::Message::Ping {
        ping: kinship_proto::Ping {
            seq: harvest.seq,
            target: id("b"),
            source: id("a"),
            source_addr: addr(1),
        },
        source_epoch: harvest.epoch,
        challenge: harvest.challenge,
        requester: None,
    };
    let stamp = net.now.as_nanos() / 1_000_000;
    let mut pkt = Vec::new();
    codec()
        .seal_v2(
            WireVersion::V2,
            PacketKind::Datagram,
            &[ping],
            &nonce_at(stamp, 1),
            &mut pkt,
        )
        .unwrap();
    net.nodes[b].handle_datagram(net.now, addr(99), &pkt);
    let harvested: Vec<Vec<u8>> = std::iter::from_fn(|| net.nodes[b].poll_transmit())
        .filter_map(|t| match t {
            Transmit::Datagram { to, payload } if to == addr(1) => Some(payload),
            _ => None,
        })
        .collect();
    let signed_ack = harvested.iter().any(|p| {
        opened(p, PacketKind::Datagram)
            .unwrap_or_default()
            .iter()
            .any(|m| matches!(parse(m), v2::Message::Ack { seq, .. } if seq == harvest.seq))
    });
    assert!(signed_ack, "b signed an Ack for a's future round");
    // b crashes, and the recorded Ack is handed to a as soon as its next round starts.
    net.crashed.push(b);
    let sent = net.datagrams.len();
    loop {
        let t = net.nodes[a].poll_timeout().unwrap();
        net.run(t);
        let pinged = net.datagrams[sent..]
            .iter()
            .filter(|(from, to, _)| (*from, *to) == (a, b))
            .any(|(_, _, p)| {
                opened(p, PacketKind::Datagram)
                    .unwrap_or_default()
                    .iter()
                    .any(|m| matches!(parse(m), v2::Message::Ping { ping, .. } if ping.seq == harvest.seq))
            });
        if pinged {
            break;
        }
    }
    let before = net.nodes[a].metrics().clone();
    for p in &harvested {
        net.nodes[a].handle_datagram(net.now, addr(2), p);
    }
    net.pump();
    let m = net.nodes[a].metrics().clone();
    assert!(
        m.packets_received > before.packets_received,
        "a fresh packet"
    );
    assert_eq!(
        m.signatures_invalid, 0,
        "and its Ack is not checked: another challenge"
    );
    // That round fails, and b is suspected and then declared dead.
    let end = net.now + net.nodes[a].config().probe_interval;
    net.run(end);
    let m = net.nodes[a].metrics().clone();
    assert_eq!(
        m.probes_failed,
        before.probes_failed + 1,
        "the round failed"
    );
    assert_eq!(net.nodes[a].member("b").unwrap().state, State::Suspect);
    let end = net.now + Duration::from_secs(20);
    net.run(end);
    let dead = std::iter::from_fn(|| net.nodes[a].poll_event())
        .any(|e| matches!(e, Event::MemberDead(m) if m.name == "b"));
    assert!(dead, "b is declared dead");
}

#[test]
fn a_relay_forwards_the_targets_ack_byte_for_byte() {
    let mut net = Net::new(&["a", "b", "c"]);
    let (a, b, c) = (0, 1, 2);
    // a cannot reach b, by UDP or TCP; c can.
    net.lost = vec![(a, b), (b, a)];
    net.refused = vec![(a, b)];
    net.run(secs(20));
    let m = net.nodes[a].metrics().clone();
    assert!(m.indirect_probes > 0, "{m:?}");
    assert_eq!(m.probes_failed, 0, "every round answered through c: {m:?}");
    assert_eq!(m.signatures_invalid, 0);
    // What b sent c and what c sent a are the same Acks: b's, to a's rounds.
    let acks = |i, j| -> Vec<Vec<u8>> {
        let to_a_from_b = |m: &v2::Message<'_>| {
            matches!(m, v2::Message::Ack { requester, target, .. }
                if requester.as_str() == "a" && target.as_str() == "b")
        };
        net.v2_sent(i, j)
            .into_iter()
            .filter(|m| to_a_from_b(&parse(m)))
            .collect()
    };
    let (from_b, to_a) = (acks(b, c), acks(c, a));
    assert!(!to_a.is_empty());
    assert!(
        to_a.iter().all(|m| from_b.contains(m)),
        "forwarded unchanged"
    );
    assert_eq!(net.nodes[a].member("b").unwrap().state, State::Alive);
}

#[test]
fn a_relays_forged_ack_is_refused() {
    let mut a = Lone::new(&["b", "c"], &["b"]);
    a.until_sent(2, is_ping);
    let r = round_of(&parse(&a.until_sent(3, is_ping_req)));
    // c answers for b with its own key, under b's certificate, then under its own.
    a.v2(&[sign(ack(r, "b", 2), &cert("b"), &member_key("c"), None)]);
    let c = cert("c");
    a.v2(&[
        certificate(&c),
        sign(ack(r, "b", 2), &c, &member_key("c"), None),
    ]);
    a.end_round();
    let m = a.metrics();
    assert_eq!(m.probes_failed, 1, "{m:?}");
    assert_eq!(m.signatures_invalid, 1);
    assert_eq!(m.certificates_refused, 1, "c's certificate names c");
    assert_eq!(a.state("b"), Some(State::Suspect));
}

#[test]
fn the_tcp_fallback_round_is_answered_with_the_rounds_challenge() {
    let mut net = Net::new(&["a", "b"]);
    let (a, b) = (0, 1);
    net.lost = vec![(a, b), (b, a)];
    net.run(secs(10));
    let m = net.nodes[a].metrics().clone();
    assert!(m.tcp_pings > 0, "{m:?}");
    assert_eq!(m.tcp_ping_acks, m.tcp_pings, "{m:?}");
    assert_eq!(m.probes_failed, 0, "{m:?}");
    // Every TCP Ping is a round's own UDP Ping, its sequence number and challenge.
    let pings = |encoded: Vec<Vec<u8>>| -> Vec<(u32, ProbeChallenge)> {
        encoded
            .iter()
            .map(|m| parse(m))
            .filter(is_ping)
            .map(|m| round_of(&m))
            .map(|r| (r.seq, r.challenge))
            .collect()
    };
    let udp = pings(net.v2_sent(a, b));
    let tcp = pings(
        net.frames
            .iter()
            .filter(|(from, to, _)| (*from, *to) == (a, b))
            .filter_map(|(_, _, f)| opened(f, PacketKind::Stream).ok())
            .flatten()
            .collect(),
    );
    assert_eq!(tcp.len() as u64, m.tcp_pings);
    assert!(tcp.iter().all(|r| udp.contains(r)), "{tcp:?} {udp:?}");
}

#[test]
fn version_2_probe_packets_carry_the_signed_rumours() {
    let mut net = Net::new(&["a", "b"]);
    let (a, b) = (0, 1);
    net.run(secs(3));
    net.datagrams.clear();
    net.command(a, Command::SetMeta(b"zone=b".to_vec()));
    net.run(secs(6));
    // Every datagram between them is version 2, and a's new Alive rode them.
    let v1 = net
        .datagrams
        .iter()
        .filter(|(i, j, p)| (*i, *j) == (a, b) && opened(p, PacketKind::Datagram).is_err())
        .count();
    assert_eq!(v1, 0, "no second, version 1 datagram");
    let rode_a_probe = net.datagrams.iter().any(|(i, j, p)| {
        let Ok(msgs) = opened(p, PacketKind::Datagram) else {
            return false;
        };
        let msgs: Vec<v2::Message<'_>> = msgs.iter().map(|m| parse(m)).collect();
        (*i, *j) == (a, b)
            && msgs
                .iter()
                .any(|m| matches!(m, v2::Message::Ping { .. } | v2::Message::Ack { .. }))
            && msgs
                .iter()
                .any(|m| matches!(m, v2::Message::Alive(sa) if sa.alive.meta == b"zone=b"))
    });
    assert!(rode_a_probe);
    assert_eq!(net.nodes[b].member("a").unwrap().meta, b"zone=b");

    // An unsigned rumour, about a member a holds from a version 1 packet, goes beside them in
    // a version 1 datagram.
    let mut pkt = Vec::new();
    let x = Alive {
        vmax: 1,
        ..alive("x", 9)
    };
    codec()
        .seal(
            PacketKind::Datagram,
            &[Message::Alive(x)],
            &nonce_at(6_000, 7),
            &mut pkt,
        )
        .unwrap();
    // Nothing runs at x's address.
    net.lost = vec![(a, 8), (b, 8)];
    net.refused = vec![(a, 8), (b, 8)];
    net.nodes[a].handle_datagram(net.now, addr(9), &pkt);
    net.datagrams.clear();
    net.run(secs(8));
    let unsigned = net.datagrams.iter().any(|(i, j, p)| {
        (*i, *j) == (a, b)
            && opened(p, PacketKind::Datagram)
                .err()
                .is_some_and(|msgs| msgs.iter().any(|m| m.contains(r#"node: "x""#)))
    });
    assert!(unsigned, "the unsigned Alive goes in version 1");
}

#[test]
fn direct_messages_and_broadcasts_between_signing_nodes() {
    let mut net = Net::new(&["a", "b", "c"]);
    let (a, b) = (0, 1);
    net.run(secs(2));
    for n in &mut net.nodes {
        delivered(n);
    }
    net.datagrams.clear();
    let send = |to: &str, data: Vec<u8>| Command::Send {
        to: to.to_owned(),
        epoch: 0,
        data,
    };
    net.command(a, send("b", b"small".to_vec()));
    net.command(a, send("b", vec![7; 5_000]));
    net.command(a, Command::Broadcast(b"all".to_vec()));
    net.run(secs(5));
    let got = delivered(&mut net.nodes[b]);
    assert!(
        got.contains(&b"small".to_vec()) && got.contains(&vec![7; 5_000]),
        "{got:?}"
    );
    assert!(got.contains(&b"all".to_vec()));
    assert!(delivered(&mut net.nodes[2]).contains(&b"all".to_vec()));
    // Each went signed: the small one in a datagram, the large one in a frame.
    let signed_direct = net.v2_sent(a, b).iter().any(|m| {
        matches!(parse(m), v2::Message::UserMessage { message, .. } if message.data == b"small")
    });
    assert!(signed_direct);
    let signed_frame = net.frames.iter().any(|(i, j, f)| {
        (*i, *j) == (a, b)
            && opened(f, PacketKind::Stream).is_ok_and(|msgs| {
                msgs.iter()
                    .any(|m| matches!(parse(m), v2::Message::UserMessage { .. }))
            })
    });
    assert!(signed_frame);
    for n in &net.nodes {
        let m = n.metrics();
        assert_eq!(
            (m.signatures_invalid, m.certificates_refused),
            (0, 0),
            "{m:?}"
        );
        assert_eq!(m.user_messages_dropped, 0, "{m:?}");
    }
}

/// The messages of the version 2 datagrams `a` sent to `port`, each datagram's in order.
fn v2_to(a: &Lone, port: u16) -> Vec<Vec<v2::Message<'static>>> {
    a.sent
        .iter()
        .filter(|(to, _)| *to == addr(port))
        .filter_map(|(_, p)| opened(p, PacketKind::Datagram).ok())
        .map(|msgs| {
            msgs.into_iter()
                .map(|m| parse(Box::leak(m.into_boxed_slice())))
                .collect()
        })
        .collect()
}

/// Found by the 1,000-seed sweeps in mode `sign`: a relay checks the target's Ack before it
/// forwards it, and a relay the prober chose may not hold the target's certificate. The target
/// answers a relay's Ping behind its own certificate, and a direct Ping without it.
#[test]
fn an_ack_to_a_relays_ping_goes_behind_the_targets_certificate() {
    let mut a = Lone::new(&["c"], &[]);
    // a's own first Alive, which carries its certificate, has been spread by now.
    a.run(secs(10));
    let ping = |requester: Option<v2::Probe<'static>>| v2::Message::Ping {
        ping: kinship_proto::Ping {
            seq: 7,
            target: id("a"),
            source: id("c"),
            source_addr: addr(2),
        },
        source_epoch: EPOCH + 2,
        challenge: drawn(0x7265_6c61),
        requester,
    };
    let relayed = v2::Probe {
        requester: id("b"),
        epoch: EPOCH + 3,
        seq: 41,
    };
    let head = |a: &mut Lone, msg| {
        a.sent.clear();
        a.v2(&[msg]);
        let packets = v2_to(a, 2);
        let acked = packets.into_iter().find(|p| {
            p.iter()
                .any(|m| matches!(m, v2::Message::Ack { challenge, .. } if *challenge == drawn(0x7265_6c61)))
        });
        acked.expect("a answered the Ping")
    };
    let to_relay = head(&mut a, ping(Some(relayed)));
    let own = cert_id(&cert("a"));
    assert!(
        matches!(to_relay[0], v2::Message::Certificate(c) if c.id() == own),
        "the certificate first"
    );
    assert!(matches!(
        to_relay[1],
        v2::Message::Ack { requester, seq: 41, .. } if requester.as_str() == "b"
    ));
    let direct = head(&mut a, ping(None));
    assert!(
        matches!(direct[0], v2::Message::Ack { seq: 7, .. }),
        "the Ack first"
    );
}

/// Found by the 1,000-seed sweeps in mode `sign`: a later life of a member, heard of unsigned,
/// may sign under another key than the earlier one, whose certificate the node held. Rounds to
/// it are version 1 until its own proof arrives, rather than version 2 rounds it can never
/// answer in a way the node can check.
#[test]
fn a_later_life_heard_of_unsigned_is_probed_in_version_1() {
    let mut a = Lone::new(&["b"], &[]);
    a.until_sent(2, is_ping);
    let later = EPOCH + 2 + 60_000;
    a.v1(&[Message::Alive(Alive {
        epoch: later,
        ..alive("b", 2)
    })]);
    assert_eq!(a.node.member("b").unwrap().epoch, later, "the later life");
    a.sent.clear();
    let deadline = a.now + Duration::from_secs(10);
    let first_ping = loop {
        let ping = a.sent.iter().find_map(|(to, p)| {
            if *to != addr(2) {
                return None;
            }
            match opened(p, PacketKind::Datagram) {
                Ok(msgs) => msgs.iter().any(|m| is_ping(&parse(m))).then_some(2),
                Err(msgs) => msgs.iter().any(|m| m.starts_with("Ping")).then_some(1),
            }
        });
        if let Some(version) = ping {
            break version;
        }
        let t = a.node.poll_timeout().unwrap();
        assert!(t <= deadline, "b was not probed");
        a.now = a.now.max(t);
        a.node.handle_timeout(a.now);
        a.drain();
    };
    assert_eq!(first_ping, 1, "a version 1 round");
    // The later life's own signed Alive, under its new key and certificate, brings version 2
    // rounds back.
    let key = SigningKey::from_bytes(drawn(seed_of("b") ^ 0x6c69_6665));
    let c = Certificate::issue(
        &ca(),
        LABEL,
        id("b"),
        key.public_key(),
        NOW - DAY,
        NOW + DAY,
    )
    .unwrap()
    .encode();
    let unsigned = v2::Message::Alive(SignedAlive {
        alive: Alive {
            epoch: later,
            ..alive("b", 2)
        },
        certificate_id: CertificateId::default(),
        signature: [0; 64],
    });
    a.v2(&[certificate(&c), sign(unsigned, &c, &key, None)]);
    assert_eq!(a.metrics().unsigned_members, 0);
    a.until_sent(2, is_ping);
    let m = a.metrics();
    assert_eq!(
        (m.signatures_invalid, m.certificates_refused),
        (0, 0),
        "{m:?}"
    );
}

/// Found by the 1,000-seed sweeps in mode `sign`: a member back from the dead is new again to
/// the nodes that reaped its tombstone, and they can check its Alive only behind its
/// certificate, so the node that revives it relays the Alive behind the certificate.
#[test]
fn a_revived_members_alive_is_relayed_behind_its_certificate() {
    let mut a = Lone::new(&["b", "c"], &[]);
    a.run(secs(10));
    a.v1(&[Message::Dead(kinship_proto::Dead {
        inc: 0,
        node: id("b"),
        from: id("c"),
        epoch: EPOCH + 2,
    })]);
    assert_eq!(a.state("b"), Some(State::Dead));
    let refuted = v2::Message::Alive(SignedAlive {
        alive: Alive {
            inc: 1,
            ..alive("b", 2)
        },
        certificate_id: CertificateId::default(),
        signature: [0; 64],
    });
    // The refutation comes without the certificate, which a still holds with the tombstone.
    a.sent.clear();
    a.v2(&[sign(refuted, &cert("b"), &member_key("b"), None)]);
    assert_eq!(a.state("b"), Some(State::Alive));
    let deadline = a.now + Duration::from_secs(10);
    let packet = loop {
        let found = v2_to(&a, 3).into_iter().find(|p| {
            p.iter()
                .any(|m| matches!(m, v2::Message::Alive(sa) if sa.alive.node.as_str() == "b"))
        });
        if let Some(p) = found {
            break p;
        }
        let t = a.node.poll_timeout().unwrap();
        assert!(t <= deadline, "the Alive was not relayed to c");
        a.now = a.now.max(t);
        a.node.handle_timeout(a.now);
        a.drain();
    };
    let at = packet
        .iter()
        .position(|m| matches!(m, v2::Message::Alive(sa) if sa.alive.node.as_str() == "b"))
        .unwrap();
    let theirs = cert_id(&cert("b"));
    assert!(
        at > 0 && matches!(packet[at - 1], v2::Message::Certificate(c) if c.id() == theirs),
        "behind b's certificate"
    );
}

/// The announcements in `a`'s datagrams, as the ports they went to: version 2 datagrams of
/// a's certificate and a's own Alive alone.
fn announcements(a: &Lone) -> Vec<u16> {
    let own = cert_id(&cert("a"));
    a.sent
        .iter()
        .filter(|(_, p)| {
            opened(p, PacketKind::Datagram).is_ok_and(|msgs| {
                let msgs: Vec<v2::Message<'_>> = msgs.iter().map(|m| parse(m)).collect();
                matches!(&msgs[..], [v2::Message::Certificate(c), v2::Message::Alive(sa)]
                    if c.id() == own && sa.alive.node.as_str() == "a")
            })
        })
        .map(|(to, _)| to.port())
        .collect()
}

/// A node that learns many members that speak version 2 at once, as from a join's version 1
/// exchange, announces itself to a few of them per gossip interval and to the rest in the
/// intervals that follow, each once.
#[test]
fn announcements_go_a_few_per_gossip_interval() {
    // By then a's own first Alive, behind its certificate, has been spread to b, and no gossip
    // looks like an announcement.
    let mut a = Lone::new(&["b"], &[]);
    a.run(secs(10));
    a.sent.clear();
    let names: Vec<String> = (0..10).map(|i| format!("x{i}")).collect();
    let alives: Vec<Message<'_>> = names
        .iter()
        .zip(20u16..)
        .map(|(name, port)| Message::Alive(alive(name, port)))
        .collect();
    a.v1(&alives);
    let first = announcements(&a).len();
    assert!(first <= 4, "{first} at once");
    let gossip = a.node.config().gossip_interval;
    a.run(a.now + gossip * 4);
    let mut ports = announcements(&a);
    ports.sort_unstable();
    assert_eq!(ports, (20u16..30).collect::<Vec<_>>(), "each once");
}

/// A member that speaks version 2 and probes this node in version 1 holds it without a current
/// certificate: this node announces itself to it.
#[test]
fn a_version_1_ping_from_a_signing_member_is_answered_with_an_announcement() {
    let mut a = Lone::new(&["b"], &[]);
    a.run(secs(1));
    a.sent.clear();
    a.v1(&[Message::Ping(kinship_proto::Ping {
        seq: 3,
        target: id("a"),
        source: id("b"),
        source_addr: addr(2),
    })]);
    assert_eq!(announcements(&a), [2]);
    // A version 2 Ping, under the certificate b holds, is answered with the Ack alone.
    a.sent.clear();
    a.v2(&[v2::Message::Ping {
        ping: kinship_proto::Ping {
            seq: 4,
            target: id("a"),
            source: id("b"),
            source_addr: addr(2),
        },
        source_epoch: EPOCH + 2,
        challenge: drawn(0x7069_6e67),
        requester: None,
    }]);
    assert!(announcements(&a).is_empty());
}

#[test]
fn a_signed_broadcast_must_fit_beside_the_largest_version_2_probe() {
    let mut cfg = signing_config("a");
    cfg.max_user_broadcast = 1_000;
    let me = Identity::new("a", addr(1)).unwrap().with_epoch(EPOCH);
    let err = Node::new(cfg, me, Instant::ZERO, 1, &drawn(1)).unwrap_err();
    assert_eq!(err.field, "max_user_broadcast");
    // In `off` the same limit is fine.
    let mut cfg = Config::lan(Security::Keys(vec![cluster_key()]));
    cfg.max_user_broadcast = 1_000;
    assert!(cfg.validate().is_ok());
}
