//! An in-memory [`Transport`] for tests: datagrams and streams between nodes in one process,
//! with no sockets.

use std::collections::HashMap;
use std::io;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, PoisonError};

use tokio::io::DuplexStream;
use tokio::sync::mpsc;

use crate::transport::Transport;

/// Datagrams queued for one endpoint before further ones are dropped, as a socket buffer would.
const QUEUE: usize = 65_536;

/// Bytes buffered in each direction of a stream.
const STREAM_BUFFER: usize = 64 * 1024;

/// A network of [`MemTransport`]s that reach each other by address.
#[derive(Debug, Clone, Default)]
pub struct MemNetwork {
    inner: Arc<Mutex<Hosts>>,
}

#[derive(Debug, Default)]
struct Hosts {
    by_addr: HashMap<SocketAddr, Host>,
    next_port: u16,
}

#[derive(Debug)]
struct Host {
    datagrams: mpsc::Sender<(Vec<u8>, SocketAddr)>,
    streams: mpsc::UnboundedSender<(DuplexStream, SocketAddr)>,
}

impl MemNetwork {
    pub fn new() -> Self {
        Self::default()
    }

    /// An endpoint at `addr`. Port 0 picks a free port, counting down from 65535.
    pub fn bind(&self, addr: SocketAddr) -> io::Result<MemTransport> {
        let mut hosts = self.hosts();
        let mut addr = addr;
        if addr.port() == 0 {
            loop {
                hosts.next_port = hosts.next_port.wrapping_sub(1);
                if hosts.next_port == 0 {
                    return Err(io::ErrorKind::AddrInUse.into());
                }
                addr.set_port(hosts.next_port);
                if !hosts.by_addr.contains_key(&addr) {
                    break;
                }
            }
        } else if hosts.by_addr.contains_key(&addr) {
            return Err(io::ErrorKind::AddrInUse.into());
        }
        let (dtx, drx) = mpsc::channel(QUEUE);
        let (stx, srx) = mpsc::unbounded_channel();
        hosts.by_addr.insert(
            addr,
            Host {
                datagrams: dtx,
                streams: stx,
            },
        );
        Ok(MemTransport {
            net: self.clone(),
            addr,
            datagrams: tokio::sync::Mutex::new(drx),
            streams: tokio::sync::Mutex::new(srx),
        })
    }

    fn hosts(&self) -> std::sync::MutexGuard<'_, Hosts> {
        self.inner.lock().unwrap_or_else(PoisonError::into_inner)
    }
}

/// One endpoint of a [`MemNetwork`]. Dropping it frees its address: datagrams to it vanish and
/// connections to it are refused.
#[derive(Debug)]
pub struct MemTransport {
    net: MemNetwork,
    addr: SocketAddr,
    datagrams: tokio::sync::Mutex<mpsc::Receiver<(Vec<u8>, SocketAddr)>>,
    streams: tokio::sync::Mutex<mpsc::UnboundedReceiver<(DuplexStream, SocketAddr)>>,
}

impl Drop for MemTransport {
    fn drop(&mut self) {
        self.net.hosts().by_addr.remove(&self.addr);
    }
}

fn copy_out(buf: &mut [u8], (data, from): (Vec<u8>, SocketAddr)) -> (usize, SocketAddr) {
    // Like a UDP socket, a datagram larger than the buffer is truncated.
    let n = data.len().min(buf.len());
    buf[..n].copy_from_slice(&data[..n]);
    (n, from)
}

impl Transport for MemTransport {
    type Stream = DuplexStream;

    fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    async fn recv_datagram(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut rx = self.datagrams.lock().await;
        match rx.recv().await {
            Some(d) => Ok(copy_out(buf, d)),
            None => Err(io::ErrorKind::NotConnected.into()),
        }
    }

    fn try_recv_datagram(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        let mut rx = self
            .datagrams
            .try_lock()
            .map_err(|_| io::Error::from(io::ErrorKind::WouldBlock))?;
        match rx.try_recv() {
            Ok(d) => Ok(copy_out(buf, d)),
            Err(_) => Err(io::ErrorKind::WouldBlock.into()),
        }
    }

    fn send_datagram(&self, to: SocketAddr, payload: &[u8]) -> io::Result<()> {
        let tx = self
            .net
            .hosts()
            .by_addr
            .get(&to)
            .map(|h| h.datagrams.clone());
        if let Some(tx) = tx {
            // A full queue drops the datagram, like a full socket buffer.
            let _ = tx.try_send((payload.to_vec(), self.addr));
        }
        Ok(())
    }

    async fn connect(&self, to: SocketAddr) -> io::Result<DuplexStream> {
        let tx = self.net.hosts().by_addr.get(&to).map(|h| h.streams.clone());
        let tx = tx.ok_or(io::ErrorKind::ConnectionRefused)?;
        let (ours, theirs) = tokio::io::duplex(STREAM_BUFFER);
        tx.send((theirs, self.addr))
            .map_err(|_| io::Error::from(io::ErrorKind::ConnectionRefused))?;
        Ok(ours)
    }

    async fn accept(&self) -> io::Result<(DuplexStream, SocketAddr)> {
        let mut rx = self.streams.lock().await;
        rx.recv()
            .await
            .ok_or_else(|| io::ErrorKind::NotConnected.into())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([10, 0, 0, 1], port))
    }

    #[tokio::test]
    async fn datagrams_and_streams_reach_the_bound_address() {
        let net = MemNetwork::new();
        let a = net.bind(addr(1)).unwrap();
        let b = net.bind(addr(0)).unwrap();
        assert_ne!(b.local_addr().port(), 0);
        assert!(net.bind(addr(1)).is_err());

        b.send_datagram(addr(1), b"hi").unwrap();
        let mut buf = [0; 8];
        assert_eq!(a.try_recv_datagram(&mut buf).unwrap(), (2, b.local_addr()));
        assert_eq!(
            a.try_recv_datagram(&mut buf).unwrap_err().kind(),
            io::ErrorKind::WouldBlock
        );

        let mut client = b.connect(addr(1)).await.unwrap();
        let (mut server, from) = a.accept().await.unwrap();
        assert_eq!(from, b.local_addr());
        client.write_all(b"abc").await.unwrap();
        let mut got = [0; 3];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"abc");

        drop(a);
        let err = b.connect(addr(1)).await.unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::ConnectionRefused);
        b.send_datagram(addr(1), b"lost").unwrap();
    }
}
