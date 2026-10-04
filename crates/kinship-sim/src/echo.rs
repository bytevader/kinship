//! A trivial node for testing the simulator itself: it pings random peers and answers pings.

use std::collections::{BTreeMap, VecDeque};
use std::net::SocketAddr;
use std::time::Duration;

use kinship_core::{
    CommandId, Instant, Key, Limits, Rng, Security, StreamEvent, StreamId, Transmit,
};
use kinship_proto::{Codec, Message, NONCE_LEN, NodeId, PacketKind, Ping};
use serde::Serialize;

use crate::SimNode;
use crate::sim::{NodeSpec, addr_of, name_of};

/// How an [`EchoNode`] behaves.
#[derive(Debug, Clone)]
pub struct EchoConfig {
    /// Time between pings to a random peer.
    pub interval: Duration,
    pub security: Security,
}

impl Default for EchoConfig {
    /// One ping a second, sealed with a fixed key so the network carries real AEAD packets.
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(1),
            security: Security::Keys(vec![Key::from_bytes([0x5a; 32])]),
        }
    }
}

/// What the application can ask an [`EchoNode`] to do.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum EchoCommand {
    /// Ping node `to` over a TCP connection, then close it.
    TcpPing { to: usize },
}

/// What an [`EchoNode`] reports.
#[derive(Debug, Clone, PartialEq, Eq, Serialize)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum EchoEvent {
    /// A UDP ping was answered after `rtt` nanoseconds.
    Echoed { seq: u32, rtt: u64 },
    /// A TCP ping was answered after `rtt` nanoseconds.
    TcpEchoed { seq: u32, rtt: u64 },
    /// A TCP ping's connection failed or closed before the answer.
    TcpFailed { seq: u32 },
}

/// Pings a random peer every interval over UDP, answers every ping with an ack, and does the
/// same over TCP on command. It speaks the real wire format through [`Codec`], so the simulator
/// routes the same bytes production would.
pub struct EchoNode {
    index: usize,
    nodes: usize,
    name: String,
    addr: SocketAddr,
    codec: Codec,
    rng: Rng,
    interval: Duration,
    next_ping: Instant,
    seq: u32,
    pending: BTreeMap<u32, Instant>,
    tcp: BTreeMap<StreamId, (u32, Instant)>,
    next_conn: u64,
    next_command: u64,
    transmits: VecDeque<Transmit>,
    events: VecDeque<EchoEvent>,
    /// Inputs are copied here before opening, because the codec decrypts in place.
    buf: Vec<u8>,
    bad_packets: u64,
}

impl EchoNode {
    pub fn new(spec: &NodeSpec, cfg: &EchoConfig) -> Self {
        let codec = match &cfg.security {
            Security::Keys(keys) => Codec::encrypted(b"echo", Limits::default(), keys.clone()),
            Security::InsecurePlaintext => Codec::insecure_plaintext(b"echo", Limits::default()),
        }
        .expect("echo codec settings are valid");
        let mut rng = Rng::new(spec.seed);
        let interval_ns = u64::try_from(cfg.interval.as_nanos()).unwrap_or(u64::MAX);
        // Spread first pings over one interval so nodes do not fire in lockstep.
        let next_ping = spec.now + Duration::from_nanos(rng.below(interval_ns.max(1)));
        Self {
            index: spec.index,
            nodes: spec.nodes,
            name: spec.name.clone(),
            addr: spec.addr,
            codec,
            rng,
            interval: cfg.interval.max(Duration::from_nanos(1)),
            next_ping,
            seq: 0,
            pending: BTreeMap::new(),
            tcp: BTreeMap::new(),
            next_conn: 0,
            next_command: 0,
            transmits: VecDeque::new(),
            events: VecDeque::new(),
            buf: Vec::new(),
            bad_packets: 0,
        }
    }

    /// Packets that failed to open or parse.
    pub fn bad_packets(&self) -> u64 {
        self.bad_packets
    }

    fn random_peer(&mut self) -> Option<usize> {
        if self.nodes < 2 {
            return None;
        }
        let p = self.rng.index(self.nodes - 1);
        Some(if p >= self.index { p + 1 } else { p })
    }

    fn nonce(&mut self) -> [u8; NONCE_LEN] {
        let mut nonce = [0; NONCE_LEN];
        self.rng.fill(&mut nonce);
        nonce
    }

    fn seal(&mut self, kind: PacketKind, msg: Message<'_>) -> Vec<u8> {
        let nonce = self.nonce();
        let mut out = Vec::new();
        let sealed = match kind {
            PacketKind::Datagram => self.codec.seal(kind, &[msg], &nonce, &mut out),
            PacketKind::Stream => self.codec.seal_stream_frame(&[msg], &nonce, &mut out),
        };
        sealed.expect("echo messages fit a packet");
        out
    }

    fn ping(&mut self, seq: u32, target: &str, kind: PacketKind) -> Vec<u8> {
        let (name, addr) = (self.name.clone(), self.addr);
        let msg = Message::Ping(Ping {
            seq,
            target: NodeId::new(target).expect("simulator names are valid"),
            source: NodeId::new(&name).expect("simulator names are valid"),
            source_addr: addr,
        });
        self.seal(kind, msg)
    }
}

impl SimNode for EchoNode {
    type Command = EchoCommand;
    type Event = EchoEvent;

    fn handle_datagram(&mut self, now: Instant, _from: SocketAddr, buf: &[u8]) {
        let mut scratch = std::mem::take(&mut self.buf);
        scratch.clear();
        scratch.extend_from_slice(buf);
        let mut acks = Vec::new();
        match self.codec.open(PacketKind::Datagram, &mut scratch) {
            Ok(payload) => {
                for msg in payload {
                    match msg {
                        Message::Ping(p) if p.target.as_str() == self.name => {
                            acks.push((p.source_addr, p.seq));
                        }
                        Message::Ack { seq } => {
                            if let Some(sent) = self.pending.remove(&seq) {
                                let rtt = (now - sent).as_nanos() as u64;
                                self.events.push_back(EchoEvent::Echoed { seq, rtt });
                            }
                        }
                        _ => {}
                    }
                }
            }
            Err(_) => self.bad_packets += 1,
        }
        self.buf = scratch;
        for (to, seq) in acks {
            let payload = self.seal(PacketKind::Datagram, Message::Ack { seq });
            self.transmits.push_back(Transmit::Datagram { to, payload });
        }
    }

    fn handle_stream(&mut self, now: Instant, conn: StreamId, ev: StreamEvent<'_>) {
        let frame = match ev {
            StreamEvent::Frame(frame) => frame,
            StreamEvent::Closed | StreamEvent::Failed => {
                if let Some((seq, _)) = self.tcp.remove(&conn) {
                    self.events.push_back(EchoEvent::TcpFailed { seq });
                }
                return;
            }
        };
        let mut scratch = std::mem::take(&mut self.buf);
        scratch.clear();
        scratch.extend_from_slice(frame);
        let mut reply = None;
        let mut answered = false;
        match self.codec.open(PacketKind::Stream, &mut scratch) {
            Ok(payload) => {
                for msg in payload {
                    match msg {
                        Message::Ping(p) if p.target.as_str() == self.name => reply = Some(p.seq),
                        Message::Ack { seq } => {
                            if let Some((sent, at)) = self.tcp.remove(&conn).filter(|t| t.0 == seq)
                            {
                                let rtt = (now - at).as_nanos() as u64;
                                self.events
                                    .push_back(EchoEvent::TcpEchoed { seq: sent, rtt });
                                answered = true;
                            }
                        }
                        _ => {}
                    }
                }
            }
            Err(_) => self.bad_packets += 1,
        }
        self.buf = scratch;
        if let Some(seq) = reply {
            let frame = self.seal(PacketKind::Stream, Message::Ack { seq });
            self.transmits.push_back(Transmit::Stream { conn, frame });
        }
        if answered {
            self.transmits.push_back(Transmit::Close { conn });
        }
    }

    fn handle_timeout(&mut self, now: Instant) {
        while self.next_ping <= now {
            if let Some(peer) = self.random_peer() {
                self.seq = self.seq.wrapping_add(1);
                let seq = self.seq;
                let payload = self.ping(seq, &name_of(peer), PacketKind::Datagram);
                self.pending.insert(seq, now);
                self.transmits.push_back(Transmit::Datagram {
                    to: addr_of(peer),
                    payload,
                });
            }
            self.next_ping = self.next_ping + self.interval;
        }
        // Forget pings that will never be answered.
        let horizon = self.interval * 10;
        self.pending.retain(|_, sent| now - *sent < horizon);
    }

    fn command(&mut self, now: Instant, cmd: EchoCommand) -> CommandId {
        let id = CommandId::from_raw(self.next_command);
        self.next_command += 1;
        match cmd {
            EchoCommand::TcpPing { to } => {
                self.seq = self.seq.wrapping_add(1);
                let seq = self.seq;
                let conn = StreamId::outbound(self.next_conn);
                self.next_conn += 1;
                let frame = self.ping(seq, &name_of(to), PacketKind::Stream);
                self.tcp.insert(conn, (seq, now));
                self.transmits.push_back(Transmit::Connect {
                    conn,
                    to: addr_of(to),
                });
                self.transmits.push_back(Transmit::Stream { conn, frame });
            }
        }
        id
    }

    fn poll_transmit(&mut self) -> Option<Transmit> {
        self.transmits.pop_front()
    }

    fn poll_event(&mut self) -> Option<EchoEvent> {
        self.events.pop_front()
    }

    fn poll_timeout(&self) -> Option<Instant> {
        Some(self.next_ping)
    }
}
