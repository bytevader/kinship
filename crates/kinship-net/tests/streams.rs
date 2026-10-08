//! Limits on inbound TCP: how many connections a node serves, how long it waits, what a
//! connection must start with, and how many bytes peers may make it hold.

use std::net::SocketAddr;
use std::time::Duration;

use kinship_net::mem::{MemNetwork, MemTransport};
use kinship_net::{Config, Key, Memberlist, Security, Settings, Transport};
use kinship_proto::{Codec, Limits, Message, PacketKind};
use tokio::io::{AsyncReadExt, AsyncWriteExt, DuplexStream};
use tokio::time::timeout;

const WAIT: Duration = Duration::from_secs(10);

fn addr(port: u8) -> SocketAddr {
    SocketAddr::from(([10, 0, 0, port], 7946))
}

fn settings(name: &str, tcp_timeout: Duration) -> Settings {
    let mut cfg = Config::local(Security::InsecurePlaintext);
    cfg.tcp_timeout = tcp_timeout;
    Settings::new(cfg, name)
}

/// True if the node closed `stream`; false if it is still open after a short wait.
async fn closed_by_node(stream: &mut DuplexStream) -> bool {
    let mut buf = [0; 16];
    matches!(
        timeout(Duration::from_millis(20), stream.read(&mut buf)).await,
        Ok(Ok(0) | Err(_))
    )
}

async fn node(net: &MemNetwork, port: u8, tcp_timeout: Duration) -> Memberlist {
    let t = net.bind(addr(port)).unwrap();
    Memberlist::start(settings(&format!("n{port}"), tcp_timeout), t)
        .await
        .unwrap()
}

async fn connect(peer: &MemTransport, to: SocketAddr) -> DuplexStream {
    timeout(WAIT, peer.connect(to)).await.unwrap().unwrap()
}

/// The length prefix of a frame of `len` bytes and the first 8 bytes of a stream packet sealed
/// by `codec`: what a frame for a node running `codec` starts with.
fn frame_start(codec: &Codec, len: usize) -> Vec<u8> {
    let mut packet = Vec::new();
    codec
        .seal(
            PacketKind::Stream,
            &[Message::Ack { seq: 1 }],
            &[0; 24],
            &mut packet,
        )
        .unwrap();
    let mut start = u32::try_from(len).unwrap().to_be_bytes().to_vec();
    start.extend_from_slice(&packet[..8]);
    start
}

/// The plaintext codec of the cluster the `local()` preset joins.
fn plaintext() -> Codec {
    Codec::insecure_plaintext(b"default", Limits::default()).unwrap()
}

#[tokio::test]
async fn inbound_connections_are_capped_per_address_then_taken_from_the_address_with_the_most() {
    let net = MemNetwork::new();
    let mut s = settings("n1", WAIT);
    // Idle connections send no header; give them time to be counted.
    s.tcp_header_timeout = WAIT;
    let a = Memberlist::start(s, net.bind(addr(1)).unwrap())
        .await
        .unwrap();
    // One address gets 16 connections: beyond that, its own oldest go.
    let x = net.bind(addr(9)).unwrap();
    let mut from_x = Vec::new();
    for _ in 0..20 {
        from_x.push(connect(&x, addr(1)).await);
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    for (i, s) in from_x.iter_mut().enumerate() {
        assert_eq!(closed_by_node(s).await, i < 4, "connection {i} from x");
    }
    // Three more addresses fill the 64.
    let mut others = Vec::new();
    for port in [10, 11, 12] {
        let t = net.bind(addr(port)).unwrap();
        for _ in 0..16 {
            others.push(connect(&t, addr(1)).await);
        }
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    // A real join still gets through. Every address has 16, so the one whose oldest
    // connection is oldest, x, gives up its oldest.
    let b = node(&net, 2, WAIT).await;
    assert_eq!(timeout(WAIT, b.join([addr(1)])).await.unwrap().unwrap(), 1);
    assert!(closed_by_node(&mut from_x[4]).await);
    assert!(!closed_by_node(&mut from_x[5]).await);
    a.close().await;
    b.close().await;
}

#[tokio::test]
async fn a_silent_connection_is_closed_after_tcp_timeout() {
    let net = MemNetwork::new();
    let a = node(&net, 1, Duration::from_millis(300)).await;
    let peer = net.bind(addr(9)).unwrap();
    let mut s = connect(&peer, addr(1)).await;
    assert!(!closed_by_node(&mut s).await);
    let mut buf = [0; 1];
    let n = timeout(WAIT, s.read(&mut buf)).await.unwrap().unwrap();
    assert_eq!(n, 0);
    a.close().await;
}

/// SECURITY.md, KS-03: a connection must start with the header of a frame for this node, with
/// an installed key's id, and send it within `tcp_header_timeout`.
#[tokio::test]
async fn a_connection_must_start_with_a_header_for_this_node() {
    let net = MemNetwork::new();
    let (old, new) = (Key::from_bytes([1; 32]), Key::from_bytes([2; 32]));
    let mut s = Settings::new(Config::local(Security::Keys(vec![old.clone()])), "n1");
    s.tcp_header_timeout = Duration::from_millis(300);
    let a = Memberlist::start(s, net.bind(addr(1)).unwrap())
        .await
        .unwrap();
    let peer = net.bind(addr(9)).unwrap();
    let sealed = |key: &Key| Codec::encrypted(b"default", Limits::default(), vec![key.clone()]);
    let start_with = |bytes: Vec<u8>| {
        let peer = &peer;
        async move {
            let mut s = connect(peer, addr(1)).await;
            s.write_all(&bytes).await.unwrap();
            s
        }
    };

    let mut ok = start_with(frame_start(&sealed(&old).unwrap(), 100)).await;
    let mut junk = start_with(vec![0x55; 12]).await;
    let mut plain = start_with(frame_start(&plaintext(), 100)).await;
    let mut unknown = start_with(frame_start(&sealed(&new).unwrap(), 100)).await;
    let mut silent = connect(&peer, addr(1)).await;
    assert!(closed_by_node(&mut junk).await);
    assert!(
        closed_by_node(&mut plain).await,
        "plaintext to an encrypting node"
    );
    assert!(closed_by_node(&mut unknown).await, "a key id not installed");
    assert!(!closed_by_node(&mut ok).await);
    assert!(!closed_by_node(&mut silent).await);
    // Counted as the node counts what it refuses itself: the unknown key as a decrypt failure.
    let counted = |a: &Memberlist| {
        let m = a.stats().metrics;
        (m.decrypt_failures, m.decode_errors)
    };
    let deadline = tokio::time::Instant::now() + WAIT;
    while counted(&a) != (1, 2) && tokio::time::Instant::now() < deadline {
        tokio::time::sleep(Duration::from_millis(5)).await;
    }
    assert_eq!(counted(&a), (1, 2));
    tokio::time::sleep(Duration::from_millis(400)).await;
    assert!(closed_by_node(&mut silent).await, "no header within 300 ms");
    assert!(
        !closed_by_node(&mut ok).await,
        "a header in time: up to tcp_timeout"
    );

    // A key installed later is accepted from then on.
    a.keyring().install(new.clone()).await.unwrap();
    let mut later = start_with(frame_start(&sealed(&new).unwrap(), 100)).await;
    assert!(!closed_by_node(&mut later).await);
    assert_eq!(a.stats().metrics.packets_received, 0);
    a.close().await;
}

#[tokio::test]
async fn an_oversized_frame_is_refused_from_its_length_prefix() {
    let net = MemNetwork::new();
    let a = node(&net, 1, WAIT).await;
    let peer = net.bind(addr(9)).unwrap();
    let mut s = connect(&peer, addr(1)).await;
    let too_big = u32::try_from(kinship_net::Limits::default().max_stream_frame + 1).unwrap();
    s.write_all(&too_big.to_be_bytes()).await.unwrap();
    let mut buf = [0; 1];
    let n = timeout(WAIT, s.read(&mut buf)).await.unwrap().unwrap();
    assert_eq!(n, 0, "the node hangs up without waiting for the body");
    assert_eq!(a.stats().metrics.packets_received, 0);
    a.close().await;
}

/// SECURITY.md, KS-02: a peer without a key announces frames of the largest allowed size on
/// many connections and sends most of each body. Every byte is held until the frame is
/// complete and fails to authenticate, so 64 connections pinned 64 x `max_stream_frame` (512
/// MiB by default). Inbound connections now share a budget of twice `max_stream_frame`: a
/// connection that would exceed it makes room by evicting another address's, or is dropped,
/// and never more than the budget is held.
#[tokio::test]
async fn inbound_connections_share_a_bounded_buffer() {
    const FRAME: usize = 1 << 20;
    let net = MemNetwork::new();
    let mut cfg = Config::local(Security::InsecurePlaintext);
    cfg.limits.max_stream_frame = FRAME;
    let t = net.bind(addr(1)).unwrap();
    let a = Memberlist::start(Settings::new(cfg, "n1"), t)
        .await
        .unwrap();
    let mut body = frame_start(&plaintext(), FRAME);
    body.resize(4 + FRAME * 3 / 5, 0x55);
    let mut conns = Vec::new();
    // Each from an address of its own, so that no address's share is the limit.
    for port in 20..28 {
        let peer = net.bind(addr(port)).unwrap();
        let mut s = connect(&peer, addr(1)).await;
        let _ = timeout(Duration::from_secs(2), s.write_all(&body)).await;
        conns.push((s, peer));
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    let mut open = 0;
    for (s, _) in &mut conns {
        if !closed_by_node(s).await {
            open += 1;
        }
    }
    // Three partial frames fit in two frames' worth; the rest were evicted or refused.
    assert!(open <= 3, "{open} of 8 partial frames held at once");
    assert!(open >= 1, "the budget refused everything");
    a.close().await;
}

/// SECURITY.md, KS-03: a peer without a key that fills the inbound budget with partial frames
/// used to make every real inbound exchange fail until `tcp_timeout` ended its connections. Now
/// one address holds at most one largest frame, and a frame that does not fit evicts a partial
/// frame of the address holding the most, so a join from another address gets through even
/// when three addresses together leave 10 bytes of the 2 MiB budget.
#[tokio::test]
async fn a_peer_that_fills_the_inbound_budget_cannot_refuse_a_real_join() {
    const FRAME: usize = 1 << 20;
    let net = MemNetwork::new();
    let mut cfg = Config::local(Security::InsecurePlaintext);
    cfg.limits.max_stream_frame = FRAME;
    let t = net.bind(addr(1)).unwrap();
    let a = Memberlist::start(Settings::new(cfg, "n1"), t)
        .await
        .unwrap();
    // Partial frames with a valid header, as a peer that has seen the cluster's traffic sends.
    let mut held = Vec::new();
    for (port, bytes) in [
        (7, 699_004),
        (8, 699_004),
        (9, 2 * FRAME - 2 * 699_004 - 10),
    ] {
        let peer = net.bind(addr(port)).unwrap();
        let mut s = connect(&peer, addr(1)).await;
        let mut partial = frame_start(&plaintext(), FRAME);
        partial.resize(bytes, 0x55);
        s.write_all(&partial).await.unwrap();
        held.push((s, peer));
    }
    tokio::time::sleep(Duration::from_millis(100)).await;
    for (s, _) in &mut held {
        assert!(!closed_by_node(s).await, "every address within its share");
    }
    let b = node(&net, 2, WAIT).await;
    let joined = timeout(WAIT, b.join([addr(1)])).await.unwrap();
    assert_eq!(joined.unwrap(), 1, "the join got through");
    let closed = {
        let mut n = 0;
        for (s, _) in &mut held {
            n += usize::from(closed_by_node(s).await);
        }
        n
    };
    assert_eq!(closed, 1, "one partial frame was evicted to make room");
    assert!(closed_by_node(&mut held[2].0).await, "the largest one");
    a.close().await;
    b.close().await;
}
