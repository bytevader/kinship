//! The sockets a node talks through: the [`Transport`] trait and its tokio implementation.

use std::future::Future;
use std::io;
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};

use socket2::{Domain, Protocol, SockRef, Socket, Type};
use tokio::io::{AsyncRead, AsyncWrite};
use tokio::net::{TcpListener, TcpStream, UdpSocket};

/// One node's datagram endpoint and stream listener, both on the same address.
///
/// The actor reads datagrams and accepts connections on its own task; each connection then runs
/// on a task of its own. [`TokioTransport`] is the default, and
/// [`MemNetwork`](crate::mem::MemNetwork) keeps everything in memory for tests. A QUIC or other
/// transport can be added without touching the protocol core.
pub trait Transport: Send + Sync + 'static {
    type Stream: AsyncRead + AsyncWrite + Send + Unpin + 'static;

    /// The address both endpoints are bound to, with the port the OS picked if it was 0.
    fn local_addr(&self) -> SocketAddr;

    /// Waits for the next datagram and copies it into `buf`, returning its length and sender.
    /// Must be cancel safe: dropping the future before it completes loses no datagram.
    fn recv_datagram(
        &self,
        buf: &mut [u8],
    ) -> impl Future<Output = io::Result<(usize, SocketAddr)>> + Send;

    /// The next datagram if one is already queued, or an error of kind
    /// [`WouldBlock`](io::ErrorKind::WouldBlock) if none is.
    fn try_recv_datagram(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)>;

    /// Sends one datagram without waiting. When the send buffer is full the datagram is dropped,
    /// as the network might drop it.
    fn send_datagram(&self, to: SocketAddr, payload: &[u8]) -> io::Result<()>;

    /// Opens a stream to `to`. The caller bounds it with `tcp_timeout`.
    fn connect(&self, to: SocketAddr) -> impl Future<Output = io::Result<Self::Stream>> + Send;

    /// Waits for the next inbound stream. Must be cancel safe.
    fn accept(&self) -> impl Future<Output = io::Result<(Self::Stream, SocketAddr)>> + Send;
}

/// Receive buffer requested for the UDP socket, so a burst of datagrams waits in the kernel
/// instead of being dropped while the actor is busy. The OS may grant less.
const UDP_RECV_BUFFER: usize = 4 * 1024 * 1024;

/// Attempts to find a port free for both UDP and TCP when binding port 0.
const BIND_ATTEMPTS: usize = 64;

/// UDP and TCP sockets from tokio, sharing one port.
#[derive(Debug)]
pub struct TokioTransport {
    udp: UdpSocket,
    tcp: TcpListener,
    addr: SocketAddr,
}

impl TokioTransport {
    /// Binds UDP and TCP to `addr`.
    ///
    /// With port 0 the OS picks a port for UDP and TCP is bound to the same one; if another
    /// socket already holds that port for TCP, both are dropped and a new port is tried. Read the
    /// result back with [`local_addr`](Transport::local_addr).
    pub async fn bind(addr: SocketAddr) -> io::Result<Self> {
        if addr.port() != 0 {
            let udp = udp_socket(addr)?;
            let tcp = tcp_listener(addr)?;
            return Ok(Self { udp, tcp, addr });
        }
        let mut last = None;
        for _ in 0..BIND_ATTEMPTS {
            let udp = udp_socket(addr)?;
            let addr = SocketAddr::new(addr.ip(), udp.local_addr()?.port());
            match tcp_listener(addr) {
                Ok(tcp) => return Ok(Self { udp, tcp, addr }),
                // Windows reports ports in an excluded range as access denied.
                Err(e) if is_conflict(&e) => last = Some(e),
                Err(e) => return Err(e),
            }
        }
        Err(last.unwrap_or_else(|| io::Error::from(io::ErrorKind::AddrInUse)))
    }
}

fn is_conflict(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::AddrInUse | io::ErrorKind::PermissionDenied
    )
}

fn udp_socket(addr: SocketAddr) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::for_address(addr), Type::DGRAM, Some(Protocol::UDP))?;
    // Best effort: the OS caps the size, and a smaller buffer still works.
    let _ = socket.set_recv_buffer_size(UDP_RECV_BUFFER);
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    UdpSocket::from_std(socket.into())
}

fn tcp_listener(addr: SocketAddr) -> io::Result<TcpListener> {
    let socket = Socket::new(Domain::for_address(addr), Type::STREAM, Some(Protocol::TCP))?;
    // Lets a restarted node rebind while old connections sit in TIME_WAIT. On Windows the same
    // option would let another process take the port, so it stays off there.
    #[cfg(not(windows))]
    socket.set_reuse_address(true)?;
    socket.set_nonblocking(true)?;
    socket.bind(&addr.into())?;
    socket.listen(1024)?;
    TcpListener::from_std(socket.into())
}

/// Errors a UDP socket reports for an earlier send rather than for this receive. Windows turns
/// an ICMP port unreachable from a peer that went away into a reset on the next receive.
fn is_stale(e: &io::Error) -> bool {
    matches!(
        e.kind(),
        io::ErrorKind::ConnectionReset
            | io::ErrorKind::ConnectionRefused
            | io::ErrorKind::Interrupted
    )
}

impl Transport for TokioTransport {
    type Stream = TcpStream;

    fn local_addr(&self) -> SocketAddr {
        self.addr
    }

    async fn recv_datagram(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        loop {
            match self.udp.recv_from(buf).await {
                Err(e) if is_stale(&e) => continue,
                r => return r,
            }
        }
    }

    fn try_recv_datagram(&self, buf: &mut [u8]) -> io::Result<(usize, SocketAddr)> {
        loop {
            match self.udp.try_recv_from(buf) {
                Err(e) if is_stale(&e) => continue,
                r => return r,
            }
        }
    }

    fn send_datagram(&self, to: SocketAddr, payload: &[u8]) -> io::Result<()> {
        // A direct non-blocking send. tokio's try_send_to refuses until the reactor has seen the
        // socket become writable, which would drop the first datagrams after binding.
        SockRef::from(&self.udp)
            .send_to(payload, &to.into())
            .map(drop)
    }

    async fn connect(&self, to: SocketAddr) -> io::Result<TcpStream> {
        let stream = TcpStream::connect(to).await?;
        stream.set_nodelay(true)?;
        Ok(stream)
    }

    async fn accept(&self) -> io::Result<(TcpStream, SocketAddr)> {
        let (stream, from) = self.tcp.accept().await?;
        stream.set_nodelay(true)?;
        Ok((stream, from))
    }
}

/// The address to advertise for a node bound to `bind`.
///
/// A wildcard bind is replaced by the address the OS would send from on its default route, found
/// by connecting a UDP socket, which sends nothing. Without a route it falls back to loopback,
/// and a node that other hosts must reach should set its advertise address explicitly.
pub fn default_advertise(bind: SocketAddr) -> SocketAddr {
    if !bind.ip().is_unspecified() {
        return bind;
    }
    let (any, probe): (SocketAddr, SocketAddr) = if bind.is_ipv4() {
        (
            (Ipv4Addr::UNSPECIFIED, 0).into(),
            (Ipv4Addr::new(8, 8, 8, 8), 53).into(),
        )
    } else {
        (
            (Ipv6Addr::UNSPECIFIED, 0).into(),
            (
                Ipv6Addr::new(0x2001, 0x4860, 0x4860, 0, 0, 0, 0, 0x8888),
                53,
            )
                .into(),
        )
    };
    let routed = std::net::UdpSocket::bind(any)
        .and_then(|s| s.connect(probe).and_then(|()| s.local_addr()))
        .map(|a| a.ip())
        .ok()
        .filter(|ip| !ip.is_unspecified());
    let ip = routed.unwrap_or(if bind.is_ipv4() {
        Ipv4Addr::LOCALHOST.into()
    } else {
        Ipv6Addr::LOCALHOST.into()
    });
    SocketAddr::new(ip, bind.port())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};

    fn loopback(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    #[tokio::test]
    async fn port_zero_binds_udp_and_tcp_to_one_port() {
        let a = TokioTransport::bind(loopback(0)).await.unwrap();
        let b = TokioTransport::bind(loopback(0)).await.unwrap();
        let addr = a.local_addr();
        assert_ne!(addr.port(), 0);
        assert_eq!(a.udp.local_addr().unwrap(), addr);
        assert_eq!(a.tcp.local_addr().unwrap(), addr);

        b.send_datagram(addr, b"hello").unwrap();
        let mut buf = [0; 16];
        let (n, from) = a.recv_datagram(&mut buf).await.unwrap();
        assert_eq!((&buf[..n], from), (&b"hello"[..], b.local_addr()));
        let err = a.try_recv_datagram(&mut buf).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::WouldBlock);

        let (client, server) = tokio::join!(b.connect(addr), a.accept());
        let (mut client, (mut server, _)) = (client.unwrap(), server.unwrap());
        client.write_all(b"ping").await.unwrap();
        let mut got = [0; 4];
        server.read_exact(&mut got).await.unwrap();
        assert_eq!(&got, b"ping");
    }

    #[tokio::test]
    async fn a_taken_port_is_an_error() {
        let a = TokioTransport::bind(loopback(0)).await.unwrap();
        let err = TokioTransport::bind(a.local_addr()).await.unwrap_err();
        assert!(is_conflict(&err), "{err:?}");
    }

    #[tokio::test]
    async fn port_zero_skips_ports_taken_for_tcp() {
        // Hold TCP on a range of ports, then bind UDP+TCP to port 0 many times: every result
        // must have both sockets on one port, never one of the held ones.
        let held: Vec<TcpListener> = hold_tcp_ports(16).await;
        let ports: Vec<u16> = held
            .iter()
            .map(|l| l.local_addr().unwrap().port())
            .collect();
        for _ in 0..16 {
            let t = TokioTransport::bind(loopback(0)).await.unwrap();
            assert!(!ports.contains(&t.local_addr().port()));
            assert_eq!(t.tcp.local_addr().unwrap().port(), t.local_addr().port());
        }
    }

    async fn hold_tcp_ports(n: usize) -> Vec<TcpListener> {
        let mut out = Vec::new();
        for _ in 0..n {
            out.push(TcpListener::bind(loopback(0)).await.unwrap());
        }
        out
    }

    #[test]
    fn advertise_keeps_specific_addresses() {
        assert_eq!(default_advertise(loopback(7946)), loopback(7946));
        let wildcard = default_advertise(SocketAddr::from(([0, 0, 0, 0], 7946)));
        assert!(!wildcard.ip().is_unspecified());
        assert_eq!(wildcard.port(), 7946);
    }
}
