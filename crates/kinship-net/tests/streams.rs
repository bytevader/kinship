//! Limits on inbound TCP: how many connections a node serves, how long it waits, and how
//! large a frame it accepts.

use std::net::SocketAddr;
use std::time::Duration;

use kinship_net::mem::{MemNetwork, MemTransport};
use kinship_net::{Config, Memberlist, Security, Settings, Transport};
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

#[tokio::test]
async fn beyond_64_inbound_connections_the_oldest_are_dropped() {
    let net = MemNetwork::new();
    let a = node(&net, 1, WAIT).await;
    let peer = net.bind(addr(9)).unwrap();
    let mut idle = Vec::new();
    for _ in 0..70 {
        idle.push(connect(&peer, addr(1)).await);
    }
    // Let the node accept them all.
    tokio::time::sleep(Duration::from_millis(100)).await;
    for (i, s) in idle.iter_mut().enumerate() {
        assert_eq!(closed_by_node(s).await, i < 6, "connection {i}");
    }
    // A real join still gets through, and pushes out one more idle connection.
    let b = node(&net, 2, WAIT).await;
    assert_eq!(timeout(WAIT, b.join([addr(1)])).await.unwrap().unwrap(), 1);
    assert!(closed_by_node(&mut idle[6]).await);
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
