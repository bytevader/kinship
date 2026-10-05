//! Probe rounds: a direct Ping, then PingReq through `indirect_checks` relays, then suspicion.
//! Also the relay side of PingReq, and answering Pings.

use core::net::SocketAddr;
use core::time::Duration;

use kinship_proto::{Dead, Message, Ping, PingReq, Suspect};

use crate::Node;
use crate::broadcast::id;
use crate::io::StreamId;
use crate::member::State;
use crate::time::Instant;

/// The probe round in progress.
#[derive(Debug, Clone)]
pub(crate) struct Probe {
    pub seq: u32,
    pub target: String,
    pub target_addr: SocketAddr,
    /// The target's incarnation when the round started; a failed round suspects it at this.
    pub inc: u32,
    /// When to give up on a direct Ack and ask relays.
    pub indirect_at: Instant,
    pub indirect_sent: bool,
    pub acked: bool,
    /// Relays that reported they could not reach the target either.
    pub nacks: u32,
    /// The TCP fallback ping, closed when the round ends.
    pub fallback: Option<StreamId>,
}

/// A PingReq this node is relaying. Its own Ping to the target went out with the sequence
/// number this is stored under.
#[derive(Debug, Clone)]
pub(crate) struct Relay {
    /// The requester's sequence number, echoed in the Ack or Nack sent back.
    pub seq: u32,
    pub requester: SocketAddr,
    pub nack_at: Option<Instant>,
    pub expires: Instant,
}

impl Node {
    /// Time between probe rounds. Lifeguard will scale this by the local health multiplier.
    pub(crate) fn probe_interval(&self) -> Duration {
        self.cfg.probe_interval
    }

    /// How long to wait for a direct Ack. Lifeguard will scale this too.
    pub(crate) fn probe_timeout(&self) -> Duration {
        self.cfg.probe_timeout
    }

    fn next_seq(&mut self) -> u32 {
        self.seq = self.seq.wrapping_add(1);
        self.seq
    }

    /// Drives the probe round: indirect probes once the direct timeout passes, and at the end
    /// of the round, suspicion of a silent target and the start of the next round.
    pub(crate) fn probe_timers(&mut self, now: Instant) {
        if let Some(p) = &self.probe {
            if !p.acked && !p.indirect_sent && now >= p.indirect_at && now < self.next_probe {
                self.send_indirect();
            }
        }
        if now < self.next_probe {
            return;
        }
        if let Some(p) = self.probe.take() {
            if let Some(conn) = p.fallback {
                self.close_stream(conn);
            }
            if !p.acked {
                self.metrics.probes_failed += 1;
                let me = self.local.member.name.clone();
                let suspect = Suspect {
                    inc: p.inc,
                    node: id(&p.target),
                    from: id(&me),
                };
                self.on_suspect(now, &suspect);
            }
        }
        self.table.reap(now, self.cfg.dead_reclaim);
        self.next_probe = now + self.probe_interval();
        self.start_probe(now);
    }

    fn start_probe(&mut self, now: Instant) {
        if self.has_left() {
            return;
        }
        let Some(target) = self.table.next_probe(&mut self.rng) else {
            return;
        };
        let (name, addr, inc) = (
            target.member.name.clone(),
            target.member.addr,
            target.member.incarnation,
        );
        let seq = self.next_seq();
        let ping = Message::Ping(Ping {
            seq,
            target: id(&name),
            source: id(&self.local.member.name),
            source_addr: self.local.member.addr,
        });
        let limit = self.retransmit_limit();
        self.out.send(addr, &[ping], Some(limit));
        self.metrics.probes_sent += 1;
        self.probe = Some(Probe {
            seq,
            target: name,
            target_addr: addr,
            inc,
            indirect_at: now + self.probe_timeout(),
            indirect_sent: false,
            acked: false,
            nacks: 0,
            fallback: None,
        });
    }

    fn send_indirect(&mut self) {
        let Some(p) = &mut self.probe else {
            return;
        };
        p.indirect_sent = true;
        let (seq, target, target_addr) = (p.seq, p.target.clone(), p.target_addr);
        let relays: Vec<SocketAddr> = self
            .table
            .random(self.cfg.indirect_checks, &mut self.rng, |e| {
                e.member.state == State::Alive && e.member.name != target
            })
            .into_iter()
            .map(|e| e.member.addr)
            .collect();
        let req = Message::PingReq(PingReq {
            seq,
            target: id(&target),
            target_addr,
            requester_addr: self.local.member.addr,
            want_nack: true,
        });
        let limit = self.retransmit_limit();
        for relay in relays {
            self.out.send(relay, &[req], Some(limit));
            self.metrics.indirect_probes += 1;
        }
        if self.cfg.tcp_fallback_ping {
            // The same Ping over TCP: a member whose UDP is filtered still answers here.
            let conn = self.tcp_ping(target_addr, &target, seq);
            if let Some(p) = &mut self.probe {
                p.fallback = Some(conn);
            }
        }
    }

    /// Answers a Ping addressed to this node.
    pub(crate) fn on_ping(&mut self, ping: &Ping<'_>) {
        if ping.target.as_str() != self.local.member.name {
            // Meant for a previous owner of this address.
            self.metrics.misdirected += 1;
            return;
        }
        let limit = self.retransmit_limit();
        let ack = Message::Ack { seq: ping.seq };
        self.out.send(ping.source_addr, &[ack], Some(limit));
    }

    /// Pings the target on the requester's behalf, unless this node knows the target left.
    pub(crate) fn on_ping_req(&mut self, now: Instant, req: &PingReq<'_>) {
        let left = self
            .table
            .get(req.target.as_str())
            .filter(|e| e.member.state == State::Left)
            .map(|e| e.member.incarnation);
        if let Some(inc) = left {
            // The requester missed the news and would soon declare the member dead; tell it
            // instead of probing a node that is gone.
            let news = Message::Dead(Dead {
                inc,
                node: req.target,
                from: req.target,
            });
            let limit = self.retransmit_limit();
            self.out.send(req.requester_addr, &[news], Some(limit));
            return;
        }
        let seq = self.next_seq();
        let ping = Message::Ping(Ping {
            seq,
            target: req.target,
            source: id(&self.local.member.name),
            source_addr: self.local.member.addr,
        });
        let limit = self.retransmit_limit();
        self.out.send(req.target_addr, &[ping], Some(limit));
        let timeout = self.probe_timeout();
        self.relays.insert(
            seq,
            Relay {
                seq: req.seq,
                requester: req.requester_addr,
                nack_at: req.want_nack.then(|| now + timeout * 4 / 5),
                expires: now + timeout,
            },
        );
    }

    pub(crate) fn on_ack(&mut self, seq: u32) {
        if let Some(p) = &mut self.probe {
            if p.seq == seq {
                p.acked = true;
                return;
            }
        }
        if let Some(relay) = self.relays.remove(&seq) {
            let limit = self.retransmit_limit();
            let ack = Message::Ack { seq: relay.seq };
            self.out.send(relay.requester, &[ack], Some(limit));
        }
    }

    pub(crate) fn on_nack(&mut self, seq: u32) {
        if let Some(p) = &mut self.probe {
            if p.seq == seq {
                p.nacks += 1;
            }
        }
    }

    /// Sends due Nacks and forgets relays whose target never answered.
    pub(crate) fn relay_timers(&mut self, now: Instant) {
        let mut nacks = Vec::new();
        self.relays.retain(|_, r| {
            if r.nack_at.is_some_and(|t| now >= t) {
                r.nack_at = None;
                nacks.push((r.requester, r.seq));
            }
            now < r.expires
        });
        for (to, seq) in nacks {
            self.out.send(to, &[Message::Nack { seq }], None);
        }
    }

    /// The earliest probe or relay deadline.
    pub(crate) fn probe_deadline(&self) -> Instant {
        let mut t = self.next_probe;
        if let Some(p) = &self.probe {
            if !p.acked && !p.indirect_sent {
                t = t.min(p.indirect_at);
            }
        }
        for r in self.relays.values() {
            t = t.min(r.nack_at.unwrap_or(r.expires));
        }
        t
    }
}
