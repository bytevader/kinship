//! A node whose actor falls behind must still count the Acks that reached it in time.
//!
//! The test plays a peer `b` by hand. Every time the node probes it, `b` floods the node with
//! useless packets, sends the Ack after them, and then blocks the runtime thread for several
//! probe intervals, as a GC pause or a starved CPU would. When the actor runs again the round's
//! deadline has long passed and the Ack is still queued behind the flood. An actor that let the
//! timer fire before reading it would fail the round and suspect `b`.

use std::net::SocketAddr;
use std::time::Duration;

use kinship_net::mem::MemNetwork;
use kinship_net::{Config, Event, Memberlist, Security, Settings, TokioTransport, Transport};
use kinship_proto::{
    Alive, Codec, FrameReader, Limits, Message, NodeId, PacketKind, PushPull, Record, Records,
    State,
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(10);

fn codec() -> Codec {
    Codec::insecure_plaintext(b"default", Limits::default()).unwrap()
}

/// Answers the node's join on `b`'s listener with a table holding only `b`.
async fn serve_join<T: Transport>(b: &T) {
    let (mut stream, _) = timeout(WAIT, b.accept()).await.unwrap().unwrap();
    let mut reader = FrameReader::new(Limits::DEFAULT_MAX_STREAM_FRAME);
    let mut chunk = [0; 4096];
    let mut frame = loop {
        if let Some(f) = reader.next_frame().unwrap() {
            break f;
        }
        let n = timeout(WAIT, stream.read(&mut chunk))
            .await
            .unwrap()
            .unwrap();
        assert_ne!(n, 0, "the node hung up before sending its state");
        reader.push(&chunk[..n]);
    };
    let payload = codec().open(PacketKind::Stream, &mut frame).unwrap();
    assert!(
        payload
            .iter()
            .any(|m| matches!(m, Message::PushPull(p) if p.join))
    );
    let record = Record {
        state: State::Alive,
        alive: Alive {
            inc: 0,
            node: NodeId::new("b").unwrap(),
            addr: b.local_addr(),
            meta: b"",
            vmin: 1,
            vmax: 1,
        },
    };
    let reply = Message::PushPull(PushPull {
        join: false,
        records: Records::Slice(&[record]),
    });
    let mut out = Vec::new();
    codec()
        .seal_stream_frame(&[reply], &[0; 24], &mut out)
        .unwrap();
    stream.write_all(&out).await.unwrap();
    stream.shutdown().await.unwrap();
}

/// The sequence number of the Ping in a datagram the node sent to `b`, if it holds one.
fn ping_seq(datagram: &mut [u8]) -> Option<u32> {
    let payload = codec().open(PacketKind::Datagram, datagram).ok()?;
    payload.iter().find_map(|m| match m {
        Message::Ping(p) if p.target.as_str() == "b" => Some(p.seq),
        _ => None,
    })
}

fn datagram(msg: Message<'_>) -> Vec<u8> {
    let mut out = Vec::new();
    codec()
        .seal(PacketKind::Datagram, &[msg], &[0; 24], &mut out)
        .unwrap();
    out
}

async fn flood<T: Transport>(a: T, b: T, junk: u32, rounds: usize) {
    let cfg = Config::local(Security::InsecurePlaintext);
    let interval = cfg.probe_interval;
    let a_addr = a.local_addr();
    let node = Memberlist::start(Settings::new(cfg, "a"), a).await.unwrap();
    let mut events = node.events();
    let (joined, ()) = tokio::join!(node.join([b.local_addr()]), serve_join(&b));
    assert_eq!(joined.unwrap(), 1);

    let mut buf = vec![0; 65_536];
    let mut flooded = 0;
    while flooded < rounds {
        if let Some(e) = events.try_recv() {
            assert!(
                matches!(e, Event::MemberJoined(_)),
                "after {flooded} floods: {e:?}"
            );
        }
        let (n, _) = timeout(WAIT, b.recv_datagram(&mut buf))
            .await
            .expect("the node stopped probing b")
            .unwrap();
        let Some(seq) = ping_seq(&mut buf[..n]) else {
            continue;
        };
        for i in 0..junk {
            // Valid packets the node must open and parse, acking probes it never sent.
            let noise = datagram(Message::Ack { seq: seq ^ (i + 1) });
            b.send_datagram(a_addr, &noise).unwrap();
        }
        b.send_datagram(a_addr, &datagram(Message::Ack { seq }))
            .unwrap();
        // Freeze the runtime, and with it the actor, well past the end of the probe round.
        std::thread::sleep(interval * 3);
        flooded += 1;
    }
    // Let the actor read the last flood.
    tokio::time::sleep(interval).await;

    let stats = node.stats();
    assert_eq!(stats.metrics.probes_failed, 0, "{stats:?}");
    assert!(
        stats.metrics.packets_received >= u64::from(junk) * rounds as u64,
        "the flood did not arrive: {stats:?}"
    );
    assert_eq!(node.member("b").unwrap().state, kinship_net::State::Alive);
    while let Some(e) = events.try_recv() {
        assert!(
            matches!(e, Event::MemberJoined(_)),
            "unexpected event under flood: {e:?}"
        );
    }
    node.close().await;
}

#[tokio::test]
async fn a_flooded_actor_reads_acks_before_its_probe_timer() {
    let net = MemNetwork::new();
    let addr = |port| SocketAddr::from(([10, 0, 0, port], 7946));
    let a = net.bind(addr(1)).unwrap();
    let b = net.bind(addr(2)).unwrap();
    flood(a, b, 5_000, 6).await;
}

#[tokio::test]
async fn a_flooded_actor_reads_acks_before_its_probe_timer_over_udp() {
    let loopback = SocketAddr::from(([127, 0, 0, 1], 0));
    let a = TokioTransport::bind(loopback).await.unwrap();
    let b = TokioTransport::bind(loopback).await.unwrap();
    // Small enough to fit a default socket buffer on every OS, so nothing is lost to the kernel.
    flood(a, b, 150, 4).await;
}
