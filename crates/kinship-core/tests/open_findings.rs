//! Reproductions of the findings in SECURITY.md. A finding that is documented rather than fixed
//! has an ignored test that shows the behaviour as it is today and passes, ignored so that the
//! suite does not read as a guarantee; run them with
//! `cargo test -p kinship-core --test open_findings -- --ignored --nocapture`. A finding fixed
//! since keeps its test here, turned into one that asserts the fixed behaviour and runs with
//! the rest of the suite.

use std::net::SocketAddr;
use std::time::Duration;

use kinship_core::{Config, Event, Identity, Instant, Key, Node, Security, State, StreamEvent};
use kinship_core::{StreamId, Transmit};
use kinship_proto::{
    Alive, Codec, Dead, Limits, Message, NodeId, PacketKind, Ping, PingReq, PushPull, Record,
    Records,
};

fn addr(i: u8) -> SocketAddr {
    SocketAddr::from(([10, 0, 0, i], 7946))
}

fn key() -> Key {
    Key::from_bytes([9; 32])
}

fn codec() -> Codec {
    Codec::encrypted(b"default", Limits::default(), vec![key()]).unwrap()
}

fn id(name: &str) -> NodeId<'_> {
    NodeId::new(name).unwrap()
}

/// A node called `name` that knows the members `others`, all Alive at incarnation 0.
fn node(name: &str, me: u8, others: &[(&str, u8)], security: Security) -> Node {
    let identity = Identity::new(name, addr(me)).unwrap();
    let mut n = Node::new(Config::lan(security), identity, Instant::ZERO, 1, &[1; 32]).unwrap();
    for (other, i) in others {
        n.add_member(Instant::ZERO, other, addr(*i)).unwrap();
    }
    while n.poll_event().is_some() {}
    n
}

fn secure(name: &str, me: u8, others: &[(&str, u8)]) -> Node {
    node(name, me, others, Security::Keys(vec![key()]))
}

/// `msgs` sealed as a datagram from a member holding the key, stamped at cluster time 0.
fn sealed(msgs: &[Message<'_>], tail: u8) -> Vec<u8> {
    let mut nonce = [tail; 24];
    nonce[..8].copy_from_slice(&0u64.to_be_bytes());
    let mut pkt = Vec::new();
    codec()
        .seal(PacketKind::Datagram, msgs, &nonce, &mut pkt)
        .unwrap();
    pkt
}

fn drain(n: &mut Node) -> Vec<Transmit> {
    std::iter::from_fn(|| n.poll_transmit()).collect()
}

/// KI-01: one forged Dead from a member that holds the key kills any node everywhere it
/// arrives, at once, without a suspicion first.
#[test]
#[ignore = "reproduces an open finding in SECURITY.md"]
fn ki01_a_member_declares_any_node_dead_at_once() {
    let mut o = secure("o", 1, &[("b", 2), ("m", 3)]);
    let forged = Message::Dead(Dead {
        inc: 0,
        node: id("b"),
        from: id("m"),
    });
    o.handle_datagram(Instant::ZERO, addr(3), &sealed(&[forged], 1));
    let events: Vec<Event> = std::iter::from_fn(|| o.poll_event()).collect();
    assert!(
        matches!(events.as_slice(), [Event::MemberDead(m)] if m.name == "b"),
        "{events:?}"
    );
}

/// KI-02: a Dead at incarnation u32::MAX can never be refuted. The victim saturates at
/// u32::MAX, its Alive never beats the tombstone, and from then on no suspicion of it can be
/// refuted either, long after the attacker's key is gone.
#[test]
#[ignore = "reproduces an open finding in SECURITY.md"]
fn ki02_incarnation_max_cannot_be_refuted() {
    let mut victim = secure("v", 2, &[("o", 1)]);
    let mut o = secure("o", 1, &[("v", 2)]);
    let forged = Message::Dead(Dead {
        inc: u32::MAX,
        node: id("v"),
        from: id("m"),
    });
    let pkt = sealed(&[forged], 1);
    o.handle_datagram(Instant::ZERO, addr(3), &pkt);
    victim.handle_datagram(Instant::ZERO, addr(3), &pkt);
    assert_eq!(victim.local().incarnation, u32::MAX);
    // The victim's refutation reaches o and changes nothing.
    victim.handle_timeout(Instant::ZERO + Duration::from_millis(250));
    for t in drain(&mut victim) {
        if let Transmit::Datagram { to, payload } = t {
            if to == addr(1) {
                o.handle_datagram(Instant::ZERO, addr(2), &payload);
            }
        }
    }
    assert_eq!(o.member("v").map(|m| m.state), Some(State::Dead));
}

/// KI-03: Alive at a higher incarnation, from any member, moves a dead or left member's name to
/// the sender's address of choice. The real node, when it comes back, is the one in conflict.
#[test]
#[ignore = "reproduces an open finding in SECURITY.md"]
fn ki03_a_member_takes_over_the_name_of_a_dead_node() {
    let mut o = secure("o", 1, &[("b", 2)]);
    let dead = Message::Dead(Dead {
        inc: 0,
        node: id("b"),
        from: id("o2"),
    });
    let evil = SocketAddr::from(([192, 0, 2, 66], 7946));
    let alive = Message::Alive(Alive {
        inc: 1,
        node: id("b"),
        addr: evil,
        meta: b"",
        vmin: 1,
        vmax: 1,
    });
    o.handle_datagram(Instant::ZERO, addr(3), &sealed(&[dead, alive], 1));
    let b = o.member("b").unwrap();
    assert_eq!((b.state, b.addr), (State::Alive, evil));
}

/// KI-04: one push-pull frame of fake Alive records grows the member table by as many members,
/// and every one of them is gossiped on and probed. Prints how long the merge took.
#[test]
#[ignore = "reproduces an open finding in SECURITY.md"]
// The test measures how long the core takes, so it reads the clock the core never does.
#[allow(clippy::disallowed_types, clippy::disallowed_methods)]
fn ki04_one_push_pull_floods_the_member_table() {
    use std::time::Instant as Clock;
    const FAKE: usize = 20_000;
    let mut o = secure("o", 1, &[]);
    let names: Vec<String> = (0..FAKE).map(|i| format!("fake-{i:06}")).collect();
    let records: Vec<Record<'_>> = names
        .iter()
        .enumerate()
        .map(|(i, name)| Record {
            state: kinship_proto::State::Alive,
            alive: Alive {
                inc: 0,
                node: id(name),
                // Probes of fake members go wherever the attacker points them.
                addr: SocketAddr::from(([198, 51, 100, (i % 250) as u8], 53)),
                meta: b"",
                vmin: 1,
                vmax: 1,
            },
        })
        .collect();
    let msg = Message::PushPull(PushPull {
        join: false,
        records: Records::Slice(&records),
    });
    let mut frame = Vec::new();
    codec()
        .seal(PacketKind::Stream, &[msg], &[0; 24], &mut frame)
        .unwrap();
    let started = Clock::now();
    o.handle_stream(
        Instant::ZERO,
        StreamId::inbound(0),
        StreamEvent::Frame(&frame),
    );
    let took = started.elapsed();
    let joined = std::iter::from_fn(|| o.poll_event())
        .filter(|e| matches!(e, Event::MemberJoined(_)))
        .count();
    println!(
        "{FAKE} fake members from a {} KiB frame merged in {took:?}",
        frame.len() / 1024
    );
    assert_eq!(joined, FAKE);
    assert_eq!(o.members().count(), FAKE + 1);
}

/// KS-04, fixed: in plaintext mode anyone can forge a Ping whose reply address is a third
/// party's. The node used to answer it with an Ack carrying as much queued gossip as fit, 46
/// times the bytes it was sent. It now sends nothing to an address that is not a member's, so
/// neither a forged Ping nor a forged PingReq naming the victim reaches it.
#[test]
fn ks04_plaintext_sends_nothing_to_an_address_that_is_not_a_member() {
    let others: Vec<(String, u8)> = (2..40).map(|i| (format!("member-{i:02}"), i)).collect();
    let refs: Vec<(&str, u8)> = others.iter().map(|(n, i)| (n.as_str(), *i)).collect();
    let mut o = node("o", 1, &refs, Security::InsecurePlaintext);
    let plain = Codec::insecure_plaintext(b"default", Limits::default()).unwrap();
    let seal = |msgs: &[Message<'_>]| {
        let mut pkt = Vec::new();
        plain
            .seal(PacketKind::Datagram, msgs, &[0; 24], &mut pkt)
            .unwrap();
        pkt
    };
    // Some news to spread, as a busy cluster always has.
    for (name, i) in &others {
        let alive = Message::Alive(Alive {
            inc: 1,
            node: id(name),
            addr: addr(*i),
            meta: b"zone=eu-west-1;role=cache-node",
            vmin: 1,
            vmax: 1,
        });
        o.handle_datagram(Instant::ZERO, addr(200), &seal(&[alive]));
    }
    drain(&mut o);
    let victim = SocketAddr::from(([203, 0, 113, 9], 53));
    let ping = Message::Ping(Ping {
        seq: 1,
        target: id("o"),
        source: id("x"),
        source_addr: victim,
    });
    let req = |target_addr, requester_addr| {
        Message::PingReq(PingReq {
            seq: 2,
            target: id("member-02"),
            target_addr,
            requester_addr,
            want_nack: true,
        })
    };
    let forged = [
        seal(&[ping]),
        seal(&[req(addr(2), victim)]),
        seal(&[req(victim, addr(3))]),
    ];
    let from = SocketAddr::from(([198, 51, 100, 1], 1));
    let mut reflected = 0;
    for pkt in &forged {
        o.handle_datagram(Instant::ZERO, from, pkt);
        reflected += drain(&mut o)
            .iter()
            .map(|t| match t {
                Transmit::Datagram { to, payload } if *to == victim => payload.len(),
                _ => 0,
            })
            .sum::<usize>();
    }
    println!(
        "{} bytes in, {reflected} bytes to the victim",
        forged.iter().map(Vec::len).sum::<usize>()
    );
    assert_eq!(reflected, 0);

    // A member's Ping is still answered, with the gossip.
    let ping = Message::Ping(Ping {
        seq: 3,
        target: id("o"),
        source: id("member-02"),
        source_addr: addr(2),
    });
    o.handle_datagram(Instant::ZERO, addr(2), &seal(&[ping]));
    let answered: usize = drain(&mut o)
        .iter()
        .map(|t| match t {
            Transmit::Datagram { to, payload } if *to == addr(2) => payload.len(),
            _ => 0,
        })
        .sum();
    assert!(answered > forged[0].len() * 10, "{answered} bytes");
}

/// KS-05, fixed: a packet whose key id no installed key had was refused before any
/// cryptography, and one whose id matched cost a full tag check, so the time told a peer
/// without the key which key ids a node had installed. Both now cost one tag verification, and
/// their medians are within noise of each other. Prints the median time of each.
#[test]
// The test measures how long the codec takes, so it reads the clock the core never does.
#[allow(clippy::disallowed_types, clippy::disallowed_methods)]
fn ks05_key_id_lookup_timing() {
    use std::time::Instant as Clock;
    let installed = Codec::encrypted(
        b"default",
        Limits::default(),
        vec![key(), Key::from_bytes([10; 32])],
    )
    .unwrap();
    let ping = Message::Ping(Ping {
        seq: 1,
        target: id("o"),
        source: id("x"),
        source_addr: addr(2),
    });
    let mut known = Vec::new();
    Codec::encrypted(
        b"default",
        Limits::default(),
        vec![Key::from_bytes([10; 32])],
    )
    .unwrap()
    .seal(PacketKind::Datagram, &[ping], &[1; 24], &mut known)
    .unwrap();
    // Same packet, a tag that fails, and an id no key has.
    let last = known.len() - 1;
    known[last] ^= 1;
    let mut unknown = known.clone();
    unknown[4] ^= 0xff;
    let time = |pkt: &[u8]| {
        let mut buf = pkt.to_vec();
        let started = Clock::now();
        let r = installed.open(PacketKind::Datagram, &mut buf);
        let took = started.elapsed();
        assert!(r.is_err());
        took
    };
    // Taken in turns, so that a change in the machine's load falls on both alike.
    let (mut k, mut u): (Vec<Duration>, Vec<Duration>) =
        (0..5_001).map(|_| (time(&known), time(&unknown))).unzip();
    let median = |times: &mut Vec<Duration>| {
        times.sort_unstable();
        times[times.len() / 2]
    };
    let (k, u) = (median(&mut k), median(&mut u));
    println!("installed id: {k:?}, unknown id: {u:?}");
    let ratio = k.as_secs_f64() / u.as_secs_f64();
    assert!((0.75..4.0 / 3.0).contains(&ratio), "{ratio:.2}");
}

/// KS-06, fixed: the random bytes of a nonce came from xoshiro256**, whose outputs are linear in
/// its state. Each packet carries two consecutive outputs in nonce bytes 8 to 24, so a few
/// packets gave away the generator's state and every nonce the node would use. They now come
/// from ChaCha20 under a key of their own. The attack still recovers xoshiro, which drives
/// protocol choices, from six outputs; from a node's nonce bytes it recovers nothing that
/// predicts the next ones.
#[test]
fn ks06_nonce_bytes_do_not_give_away_the_generator() {
    let mut rng = kinship_core::Rng::new(0x5eed);
    let words: Vec<u64> = (0..8).map(|_| rng.next_u64()).collect();
    assert_eq!(
        xoshiro::predict(&words[..6]),
        Some([words[6], words[7]]),
        "the attack works"
    );

    let mut n = secure("o", 1, &[("b", 2), ("c", 3), ("d", 4)]);
    let mut words = Vec::new();
    let mut t = Instant::ZERO;
    while words.len() < 8 {
        t = n.poll_timeout().unwrap();
        n.handle_timeout(t);
        for transmit in drain(&mut n) {
            let sealed = match &transmit {
                Transmit::Datagram { payload, .. } => &payload[..],
                Transmit::Stream { frame, .. } => &frame[4..],
                _ => continue,
            };
            // Nonce bytes 8 to 24, after the 8 bytes of cluster time.
            for at in [16, 24] {
                words.push(u64::from_le_bytes(sealed[at..at + 8].try_into().unwrap()));
            }
        }
    }
    assert!(t < Instant::ZERO + Duration::from_secs(5));
    let predicted = xoshiro::predict(&words[..6]);
    assert_ne!(predicted, Some([words[6], words[7]]), "{words:x?}");
}

/// Recovering xoshiro256**'s state from its outputs: each output is an invertible function of
/// one state word, and the state moves by a linear map over GF(2), so 256 bits of outputs give
/// 256 linear equations in the 256 bits of the state.
mod xoshiro {
    /// A linear combination of the 256 bits of the starting state.
    type Bits = [u64; 4];
    /// A state word as 64 such combinations, bit 0 first.
    type Word = [Bits; 64];

    fn xor(a: &Word, b: &Word) -> Word {
        core::array::from_fn(|i| core::array::from_fn(|j| a[i][j] ^ b[i][j]))
    }

    fn shl(a: &Word, k: usize) -> Word {
        core::array::from_fn(|i| if i >= k { a[i - k] } else { [0; 4] })
    }

    fn rotl(a: &Word, k: usize) -> Word {
        core::array::from_fn(|i| a[(i + 64 - k) % 64])
    }

    fn inverse(a: u64) -> u64 {
        // Newton's iteration doubles the correct low bits of an odd number's inverse.
        let mut x = a;
        for _ in 0..6 {
            x = x.wrapping_mul(2u64.wrapping_sub(a.wrapping_mul(x)));
        }
        x
    }

    /// The state word an output came from: `rotl(s1 * 5, 7) * 9`, undone.
    fn s1_of(output: u64) -> u64 {
        output
            .wrapping_mul(inverse(9))
            .rotate_right(7)
            .wrapping_mul(inverse(5))
    }

    fn next(s: &mut [u64; 4]) -> u64 {
        let result = s[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = s[1] << 17;
        s[2] ^= s[0];
        s[3] ^= s[1];
        s[1] ^= s[2];
        s[0] ^= s[3];
        s[2] ^= t;
        s[3] = s[3].rotate_left(45);
        result
    }

    /// The two outputs that follow `outputs`, if exactly one state gives `outputs`.
    pub fn predict(outputs: &[u64]) -> Option<[u64; 2]> {
        let mut s: [Word; 4] = core::array::from_fn(|w| {
            core::array::from_fn(|i| {
                let mut bits = [0; 4];
                bits[w] = 1 << i;
                bits
            })
        });
        // Rows of coefficients, with the right-hand side in bit 0 of a fifth word.
        let mut rows: Vec<[u64; 5]> = Vec::new();
        for &out in outputs {
            let s1 = s1_of(out);
            for (i, bits) in s[1].iter().enumerate() {
                rows.push([bits[0], bits[1], bits[2], bits[3], (s1 >> i) & 1]);
            }
            let t = shl(&s[1], 17);
            s[2] = xor(&s[2], &s[0]);
            s[3] = xor(&s[3], &s[1]);
            s[1] = xor(&s[1], &s[2]);
            s[0] = xor(&s[0], &s[3]);
            s[2] = xor(&s[2], &t);
            s[3] = rotl(&s[3], 45);
        }
        // Gaussian elimination over GF(2).
        let mut state = [0u64; 4];
        let mut rank = 0;
        for col in 0..256 {
            let (w, b) = (col / 64, 1u64 << (col % 64));
            let pivot = (rank..rows.len()).find(|&r| rows[r][w] & b != 0)?;
            rows.swap(rank, pivot);
            let p = rows[rank];
            for (r, row) in rows.iter_mut().enumerate() {
                if r != rank && row[w] & b != 0 {
                    for k in 0..5 {
                        row[k] ^= p[k];
                    }
                }
            }
            rank += 1;
        }
        if rows[rank..].iter().any(|row| row[4] != 0) {
            return None;
        }
        for (col, row) in rows[..256].iter().enumerate() {
            state[col / 64] |= row[4] << (col % 64);
        }
        for _ in outputs {
            next(&mut state);
        }
        Some([next(&mut state), next(&mut state)])
    }
}

/// KS-07, fixed: a removed key stopped opening packets but stayed in memory, because the node
/// kept the config it started with, keys included, for as long as it ran. The keys now move
/// into the codec, the only place they live, and leave it when removed.
#[test]
fn ks07_a_removed_key_leaves_the_node() {
    let old = Key::from_bytes([10; 32]);
    let identity = Identity::new("o", addr(1)).unwrap();
    let cfg = Config::lan(Security::Keys(vec![key(), old.clone()]));
    let mut o = Node::new(cfg, identity, Instant::ZERO, 1, &[1; 32]).unwrap();
    assert_eq!(o.config().security, Security::Keys(Vec::new()));
    assert_eq!(o.key_ids(), [key().key_id(), old.key_id()]);
    o.command(Instant::ZERO, kinship_core::Command::RemoveKey(old.clone()));
    assert_eq!(o.key_ids(), [key().key_id()]);
    assert_eq!(o.config().security, Security::Keys(Vec::new()));
}

/// KI-06: a member that stamps a packet years ahead moves every node's cluster time with it,
/// and the replay floor then takes as long to catch up: until the nonces kept reach their cap,
/// a recording made after the jump stays acceptable for hours.
#[test]
#[ignore = "reproduces an open finding in SECURITY.md"]
fn ki06_a_member_far_ahead_stretches_the_replay_window() {
    const YEAR_MS: u64 = 365 * 24 * 3_600_000;
    let mut o = secure("o", 1, &[("b", 2)]);
    let at = |s: u64| Instant::ZERO + Duration::from_secs(s);
    for s in 1..=100 {
        o.handle_timeout(at(s));
        drain(&mut o);
    }
    let stamped = |stamp: u64, tail: u8| {
        let ping = Message::Ping(Ping {
            seq: 1,
            target: id("o"),
            source: id("b"),
            source_addr: addr(2),
        });
        let mut nonce = [tail; 24];
        nonce[..8].copy_from_slice(&stamp.to_be_bytes());
        let mut pkt = Vec::new();
        codec()
            .seal(PacketKind::Datagram, &[ping], &nonce, &mut pkt)
            .unwrap();
        pkt
    };
    // The node has heard the cluster, then the member's packet from ten years ahead.
    o.handle_datagram(at(100), addr(2), &stamped(100_000, 3));
    o.handle_datagram(at(100), addr(3), &stamped(10 * YEAR_MS, 1));
    drain(&mut o);
    // A Ping b sent to someone else a second later, recorded and replayed an hour on.
    let recording = stamped(10 * YEAR_MS + 1_000, 2);
    for s in (101..=3_700).step_by(5) {
        o.handle_timeout(at(s));
        drain(&mut o);
    }
    o.handle_datagram(at(3_700), addr(3), &recording);
    let answered = drain(&mut o)
        .iter()
        .any(|t| matches!(t, Transmit::Datagram { to, .. } if *to == addr(2)));
    assert!(
        answered,
        "the hour-old recording was refused: {:?}",
        o.metrics()
    );
}
