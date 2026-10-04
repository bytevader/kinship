//! Sans-IO SWIM and Lifeguard protocol state machine.
//!
//! [`Node`] is the whole protocol with no sockets, clock, threads or randomness of its own. A
//! driver feeds it datagrams, stream events, timer expiries and commands, each with the current
//! [`Instant`], and then drains what it should send ([`Node::poll_transmit`]), what the
//! application should hear ([`Node::poll_event`]) and when to wake it next
//! ([`Node::poll_timeout`]). The same seed and the same inputs always give the same outputs,
//! byte for byte, which is what lets `kinship-sim` replay any run from its seed.
//!
//! Encryption happens inside the core: payloads in [`Transmit`] are already sealed, and inputs
//! are the raw bytes off the wire.

mod config;
mod event;
mod io;
mod metrics;
mod rng;
mod time;

use std::collections::VecDeque;
use std::net::SocketAddr;

use kinship_proto::{Codec, DecodeError, NodeId, PacketKind, Payload};

pub use config::{Config, ConfigError, Security};
pub use event::{Command, CommandError, CommandId, Event};
pub use io::{StreamEvent, StreamId, Transmit};
pub use kinship_proto::{Key, Limits, WIRE_VERSION};
pub use metrics::Metrics;
pub use rng::Rng;
pub use time::Instant;

/// Who this node is: its name, the address peers reach it on, and its metadata.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Identity {
    name: String,
    addr: SocketAddr,
    meta: Vec<u8>,
}

impl Identity {
    /// `name` must be 1 to 64 bytes of UTF-8 and unique in the cluster; `addr` is the advertised
    /// address, not necessarily the bind address.
    pub fn new(name: impl Into<String>, addr: SocketAddr) -> Result<Self, ConfigError> {
        let name = name.into();
        if NodeId::new(&name).is_err() {
            return Err(ConfigError {
                field: "name",
                reason: "must be 1 to 64 bytes",
            });
        }
        Ok(Self {
            name,
            addr,
            meta: Vec::new(),
        })
    }

    /// Initial metadata; checked against `max_meta_bytes` by [`Node::new`].
    pub fn with_meta(mut self, meta: impl Into<Vec<u8>>) -> Self {
        self.meta = meta.into();
        self
    }

    pub fn name(&self) -> &str {
        &self.name
    }

    pub fn addr(&self) -> SocketAddr {
        self.addr
    }

    pub fn meta(&self) -> &[u8] {
        &self.meta
    }
}

/// One cluster member's protocol state machine.
///
/// This is the API skeleton: inputs are authenticated and parsed, and commands complete, but no
/// SWIM logic runs yet, so it sends nothing.
pub struct Node {
    cfg: Config,
    me: Identity,
    codec: Codec,
    rng: Rng,
    now: Instant,
    next_command: u64,
    transmits: VecDeque<Transmit>,
    events: VecDeque<Event>,
    /// Inputs are copied here before opening, because the codec decrypts in place.
    recv_buf: Vec<u8>,
    metrics: Metrics,
}

impl Node {
    /// A node that starts at `now`, drawing every random choice from `seed`.
    ///
    /// Production drivers must take `seed` from the OS RNG, since nonces are drawn from it.
    pub fn new(cfg: Config, me: Identity, now: Instant, seed: u64) -> Result<Self, ConfigError> {
        cfg.validate()?;
        if me.meta.len() > cfg.limits.max_meta_bytes {
            return Err(ConfigError {
                field: "meta",
                reason: "must be at most max_meta_bytes",
            });
        }
        let codec = cfg.codec().map_err(|_| ConfigError {
            field: "security",
            reason: "rejected by the codec",
        })?;
        Ok(Self {
            cfg,
            me,
            codec,
            rng: Rng::new(seed),
            now,
            next_command: 0,
            transmits: VecDeque::new(),
            events: VecDeque::new(),
            recv_buf: Vec::new(),
            metrics: Metrics::default(),
        })
    }

    /// A UDP datagram arrived from `from`.
    pub fn handle_datagram(&mut self, now: Instant, from: SocketAddr, buf: &[u8]) {
        self.advance(now);
        let _ = from;
        let mut scratch = std::mem::take(&mut self.recv_buf);
        scratch.clear();
        scratch.extend_from_slice(buf);
        let opened = self.codec.open(PacketKind::Datagram, &mut scratch);
        self.receive(opened);
        self.recv_buf = scratch;
    }

    /// Something happened on a TCP connection.
    pub fn handle_stream(&mut self, now: Instant, conn: StreamId, ev: StreamEvent<'_>) {
        self.advance(now);
        let _ = conn;
        if let StreamEvent::Frame(frame) = ev {
            let mut scratch = std::mem::take(&mut self.recv_buf);
            scratch.clear();
            scratch.extend_from_slice(frame);
            let opened = self.codec.open(PacketKind::Stream, &mut scratch);
            self.receive(opened);
            self.recv_buf = scratch;
        }
    }

    /// The deadline from [`poll_timeout`](Self::poll_timeout) has passed.
    pub fn handle_timeout(&mut self, now: Instant) {
        self.advance(now);
    }

    /// Starts a command; its result arrives later as [`Event::CommandDone`].
    pub fn command(&mut self, now: Instant, cmd: Command) -> CommandId {
        self.advance(now);
        let id = CommandId::from_raw(self.next_command);
        self.next_command += 1;
        let result = match cmd {
            Command::SetMeta(meta) if meta.len() > self.cfg.limits.max_meta_bytes => {
                Err(CommandError::MetaTooLarge)
            }
            Command::SetMeta(meta) => {
                self.me.meta = meta;
                Ok(())
            }
            Command::Join { .. } | Command::Leave => Err(CommandError::Unsupported),
        };
        self.events.push_back(Event::CommandDone { id, result });
        id
    }

    /// The next thing to send, if any.
    pub fn poll_transmit(&mut self) -> Option<Transmit> {
        self.transmits.pop_front()
    }

    /// The next event for the application, if any.
    pub fn poll_event(&mut self) -> Option<Event> {
        self.events.pop_front()
    }

    /// When to call [`handle_timeout`](Self::handle_timeout), if ever.
    pub fn poll_timeout(&self) -> Option<Instant> {
        None
    }

    pub fn identity(&self) -> &Identity {
        &self.me
    }

    pub fn config(&self) -> &Config {
        &self.cfg
    }

    pub fn metrics(&self) -> &Metrics {
        &self.metrics
    }

    fn advance(&mut self, now: Instant) {
        // Drivers may hand in the same instant twice but never go backwards; clamp if they do.
        self.now = self.now.max(now);
    }

    fn receive(&mut self, opened: Result<Payload<'_>, DecodeError>) {
        match opened {
            Ok(_payload) => self.metrics.packets_received += 1,
            Err(e) if e.is_auth_failure() => self.metrics.decrypt_failures += 1,
            Err(_) => self.metrics.decode_errors += 1,
        }
    }

    /// Fresh nonce bytes for sealing a packet.
    #[allow(dead_code)]
    fn nonce(&mut self) -> [u8; kinship_proto::NONCE_LEN] {
        let mut nonce = [0; kinship_proto::NONCE_LEN];
        self.rng.fill(&mut nonce);
        nonce
    }
}

impl std::fmt::Debug for Node {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Node")
            .field("name", &self.me.name)
            .field("addr", &self.me.addr)
            .field("now", &self.now)
            .finish_non_exhaustive()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use kinship_proto::{Message, Ping};

    fn addr(port: u16) -> SocketAddr {
        SocketAddr::from(([127, 0, 0, 1], port))
    }

    fn node(security: Security) -> Node {
        let cfg = Config::local(security);
        Node::new(cfg, Identity::new("a", addr(1)).unwrap(), Instant::ZERO, 7).unwrap()
    }

    #[test]
    fn identity_validates_the_name() {
        assert!(Identity::new("", addr(1)).is_err());
        assert!(Identity::new("x".repeat(65), addr(1)).is_err());
        assert_eq!(Identity::new("ok", addr(1)).unwrap().name(), "ok");
    }

    #[test]
    fn new_rejects_invalid_config_and_meta() {
        let mut cfg = Config::lan(Security::InsecurePlaintext);
        cfg.probe_timeout = cfg.probe_interval * 2;
        let me = Identity::new("a", addr(1)).unwrap();
        assert_eq!(
            Node::new(cfg, me.clone(), Instant::ZERO, 0)
                .unwrap_err()
                .field,
            "probe_timeout"
        );
        let cfg = Config::lan(Security::InsecurePlaintext);
        let me = me.with_meta(vec![0; 513]);
        assert_eq!(
            Node::new(cfg, me, Instant::ZERO, 0).unwrap_err().field,
            "meta"
        );
    }

    #[test]
    fn counts_good_and_bad_datagrams() {
        let key = Key::from_bytes([3; 32]);
        let mut n = node(Security::Keys(vec![key.clone()]));
        let codec = Codec::encrypted(b"default", Limits::default(), vec![key]).unwrap();
        let mut pkt = Vec::new();
        let ping = Message::Ping(Ping {
            seq: 1,
            target: NodeId::new("a").unwrap(),
            source: NodeId::new("b").unwrap(),
            source_addr: addr(2),
        });
        codec
            .seal(PacketKind::Datagram, &[ping], &[9; 24], &mut pkt)
            .unwrap();
        n.handle_datagram(Instant::ZERO, addr(2), &pkt);
        assert_eq!(n.metrics().packets_received, 1);

        let last = pkt.len() - 1;
        pkt[last] ^= 1;
        n.handle_datagram(Instant::ZERO, addr(2), &pkt);
        assert_eq!(n.metrics().decrypt_failures, 1);

        n.handle_datagram(Instant::ZERO, addr(2), b"garbage");
        assert_eq!(n.metrics().decode_errors, 1);
    }

    #[test]
    fn stream_frames_are_opened() {
        let mut n = node(Security::InsecurePlaintext);
        let codec = Codec::insecure_plaintext(b"default", Limits::default()).unwrap();
        let mut frame = Vec::new();
        codec
            .seal(
                PacketKind::Stream,
                &[Message::Ack { seq: 4 }],
                &[0; 24],
                &mut frame,
            )
            .unwrap();
        let conn = StreamId::inbound(0);
        n.handle_stream(Instant::ZERO, conn, StreamEvent::Frame(&frame));
        n.handle_stream(Instant::ZERO, conn, StreamEvent::Closed);
        assert_eq!(n.metrics().packets_received, 1);
    }

    #[test]
    fn commands_complete_with_their_id() {
        let mut n = node(Security::InsecurePlaintext);
        let a = n.command(Instant::ZERO, Command::SetMeta(b"role=db".to_vec()));
        let b = n.command(Instant::ZERO, Command::SetMeta(vec![0; 513]));
        let c = n.command(Instant::ZERO, Command::Leave);
        assert_ne!(a, b);
        assert_eq!(
            n.poll_event(),
            Some(Event::CommandDone {
                id: a,
                result: Ok(())
            })
        );
        assert_eq!(
            n.poll_event(),
            Some(Event::CommandDone {
                id: b,
                result: Err(CommandError::MetaTooLarge)
            })
        );
        assert_eq!(
            n.poll_event(),
            Some(Event::CommandDone {
                id: c,
                result: Err(CommandError::Unsupported)
            })
        );
        assert_eq!(n.poll_event(), None);
        assert_eq!(n.identity().meta(), b"role=db");
        assert_eq!(n.poll_transmit(), None);
        assert_eq!(n.poll_timeout(), None);
    }

    #[test]
    fn stream_ids_do_not_collide() {
        assert_ne!(StreamId::outbound(5), StreamId::inbound(5));
        assert!(StreamId::inbound(5).is_inbound());
        assert!(!StreamId::outbound(5).is_inbound());
        assert_eq!(StreamId::inbound(5).index(), 5);
        let id = StreamId::inbound(9);
        assert_eq!(StreamId::from_raw(id.to_raw()), id);
    }
}
