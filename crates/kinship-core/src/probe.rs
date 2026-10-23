//! Probe rounds: a direct Ping, then PingReq through `indirect_checks` relays, then suspicion.
//! Also the relay side of PingReq, and answering Pings.
//!
//! Each round's outcome feeds Lifeguard's local health: an Ack lowers the score, a failed round
//! raises it by one per relay that stayed silent (or by one if no relay was asked or Nacks are
//! off). When every relay sends a Nack the round still fails, but the fault is the target's, so
//! the score does not move.
//!
//! In mode `sign` a round to a target that speaks version 2, and whose certificate this node
//! holds, is a version 2 round (`docs/ki01-stage2.md`, Probe versions per round): its Ping
//! carries a fresh challenge, its PingReqs name the requester, and only an Ack signed by the
//! target over the round's exact binding answers it, by whichever path it comes. Relays sign
//! their Nacks over the same binding, and each counts once. Every other round is the version 1
//! round, unchanged.

use core::net::SocketAddr;
use core::time::Duration;
use std::collections::BTreeMap;

use kinship_proto::identity::{Certificate, CertificateId};
use kinship_proto::v2::{self, ProbeChallenge};
use kinship_proto::{Dead, Message, Ping, PingReq, Suspect, WireVersion};

use crate::Node;
use crate::broadcast::id;
use crate::io::StreamId;
use crate::member::{Life, State, life};
use crate::signing::{PacketCerts, signed_dead, signed_suspect};
use crate::table::Entry;
use crate::time::Instant;

/// The probe round in progress.
#[derive(Debug, Clone)]
pub(crate) struct Probe {
    pub seq: u32,
    pub target: String,
    pub target_addr: SocketAddr,
    /// The target's incarnation and epoch when the round started; a failed round suspects
    /// that life at that incarnation.
    pub inc: u32,
    pub epoch: u64,
    /// When to give up on a direct Ack and ask relays.
    pub indirect_at: Instant,
    pub indirect_sent: bool,
    pub acked: bool,
    /// PingReqs sent, one per relay.
    pub relays: u32,
    /// Relays that reported they could not reach the target either.
    pub nacks: u32,
    /// The TCP fallback ping, closed when the round ends.
    pub fallback: Option<StreamId>,
    /// What a version 2 round adds; `None` for a version 1 round.
    pub signed: Option<Round>,
}

/// A version 2 probe round's binding beyond its sequence number and target.
#[derive(Debug, Clone)]
pub(crate) struct Round {
    pub challenge: ProbeChallenge,
    /// This node's epoch in the round's Ping, which its answers name.
    pub epoch: u64,
    /// The relays asked, by name, and whether a Nack from each has counted.
    pub relays: BTreeMap<String, bool>,
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
    /// The requester's round, for a version 2 PingReq: its Ack is correlated by that whole
    /// binding, not by this node's own sequence number.
    pub signed: Option<RelayRound>,
}

/// The binding of a version 2 round this node relays.
#[derive(Debug, Clone)]
pub(crate) struct RelayRound {
    pub requester: String,
    pub requester_epoch: u64,
    pub target: String,
    pub challenge: ProbeChallenge,
}

/// Whether member `e` advertises version 2.
fn speaks_v2(e: &Entry) -> bool {
    let two = WireVersion::V2 as u8;
    e.vmin <= two && two <= e.vmax
}

impl Node {
    /// Time between probe rounds, stretched by the local health multiplier.
    pub(crate) fn probe_interval(&self) -> Duration {
        self.scale_by_health(self.cfg.probe_interval)
    }

    /// How long to wait for a direct Ack, stretched by the local health multiplier.
    pub(crate) fn probe_timeout(&self) -> Duration {
        self.scale_by_health(self.cfg.probe_timeout)
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
            if p.acked {
                self.health_delta(-1);
            } else {
                self.metrics.probes_failed += 1;
                if self.cfg.nacks && p.relays > 0 {
                    let missed = p.relays.saturating_sub(p.nacks);
                    self.metrics.missed_nacks += u64::from(missed);
                    self.health_delta(i64::from(missed));
                } else {
                    self.health_delta(1);
                }
                let me = self.local.member.name.clone();
                let suspect = Suspect {
                    inc: p.inc,
                    node: id(&p.target),
                    from: id(&me),
                    epoch: p.epoch,
                };
                let proof = self.sign_suspect(&suspect);
                self.on_suspect(now, &suspect, proof);
            }
        }
        // A tombstone outlives the replay window, so no recording can bring its member back.
        let keep = self.cfg.dead_reclaim.max(self.replay.window());
        self.table.reap(now, keep);
        self.forget_reaped_senders();
        self.forget_reaped_certs();
        self.next_probe = now + self.probe_interval();
        self.start_probe(now);
    }

    /// Whether this node, in mode `sign`, holds a current certificate for member `name`. A
    /// round to a target that advertises version 2 and passes this is a version 2 round: its
    /// answers are the only ones this node can check.
    fn holds_current_cert(&self, name: &str) -> bool {
        self.keys
            .as_ref()
            .is_some_and(|k| k.current(name, k.unix_now(self.now)).is_some())
    }

    fn start_probe(&mut self, now: Instant) {
        if self.has_left() {
            return;
        }
        let Some(target) = self.table.next_probe(&mut self.rng) else {
            return;
        };
        let (name, addr, inc, epoch, suspected, v2) = (
            target.member.name.clone(),
            target.member.addr,
            target.member.incarnation,
            target.member.epoch,
            target.member.state == State::Suspect,
            speaks_v2(target),
        );
        let signed = v2 && self.holds_current_cert(&name);
        let seq = self.next_seq();
        let round = match self.keys.as_mut() {
            Some(keys) if signed => Some(Round {
                challenge: keys.challenge(),
                epoch: self.local.member.epoch,
                relays: BTreeMap::new(),
            }),
            _ => None,
        };
        let me = self.local.member.name.clone();
        let me = id(&me);
        let ping = Ping {
            seq,
            target: id(&name),
            source: me,
            source_addr: self.local.member.addr,
        };
        // The buddy system: a suspected target reads the rumour before the Ping, so its Ack
        // already carries the refutation.
        let buddy_msg = Suspect {
            inc,
            node: id(&name),
            from: me,
            epoch,
        };
        let buddy = suspected && self.cfg.buddy_system;
        let limit = self.retransmit_limit();
        // Only live members are probed.
        match &round {
            None => {
                let ping = Message::Ping(ping);
                let head = if buddy {
                    &[Message::Suspect(buddy_msg), ping][..]
                } else {
                    &[ping][..]
                };
                self.send_to(addr, true, Some(&name), head, Some(limit));
            }
            Some(r) => {
                let mut head = Vec::with_capacity(2);
                if buddy {
                    // Version 2 has no unsigned Suspect: the prober's own, signed.
                    head.extend(
                        self.sign_suspect(&buddy_msg)
                            .map(|proof| signed_suspect(&buddy_msg, &proof)),
                    );
                }
                head.push(v2::Message::Ping {
                    ping,
                    source_epoch: r.epoch,
                    challenge: r.challenge,
                    requester: None,
                });
                self.send_to_v2(addr, true, &head, Some(limit));
            }
        }
        self.metrics.probes_sent += 1;
        self.probe = Some(Probe {
            seq,
            target: name,
            target_addr: addr,
            inc,
            epoch,
            indirect_at: now + self.probe_timeout(),
            indirect_sent: false,
            acked: false,
            relays: 0,
            nacks: 0,
            fallback: None,
            signed: round,
        });
    }

    fn send_indirect(&mut self) {
        let Some(p) = &mut self.probe else {
            return;
        };
        p.indirect_sent = true;
        let (seq, target, target_addr) = (p.seq, p.target.clone(), p.target_addr);
        let signed = p.signed.as_ref().map(|r| (r.challenge, r.epoch));
        // A version 2 round asks only relays that speak version 2 and whose Nacks this node
        // can check.
        let keys = self.keys.as_deref();
        let unix = keys.map_or(0, |k| k.unix_now(self.now));
        let relays: Vec<(SocketAddr, String)> = self
            .table
            .random(self.cfg.indirect_checks, &mut self.rng, |e| {
                e.member.state == State::Alive
                    && e.member.name != target
                    && (signed.is_none()
                        || (speaks_v2(e)
                            && keys.is_some_and(|k| k.current(&e.member.name, unix).is_some())))
            })
            .into_iter()
            .map(|e| (e.member.addr, e.member.name.clone()))
            .collect();
        let request = PingReq {
            seq,
            target: id(&target),
            target_addr,
            requester_addr: self.local.member.addr,
            want_nack: self.cfg.nacks,
        };
        let me = self.local.member.name.clone();
        let limit = self.retransmit_limit();
        let asked = u32::try_from(relays.len()).unwrap_or(u32::MAX);
        for (relay, name) in &relays {
            match signed {
                None => {
                    let req = Message::PingReq(request);
                    self.send_to(*relay, true, Some(name), &[req], Some(limit));
                }
                Some((challenge, epoch)) => {
                    let req = v2::Message::PingReq {
                        request,
                        requester: id(&me),
                        requester_epoch: epoch,
                        challenge,
                    };
                    self.send_to_v2(*relay, true, &[req], Some(limit));
                }
            }
            self.metrics.indirect_probes += 1;
        }
        if let Some(p) = &mut self.probe {
            p.relays = asked;
            if let Some(r) = &mut p.signed {
                r.relays = relays.into_iter().map(|(_, name)| (name, false)).collect();
            }
        }
        if self.cfg.tcp_fallback_ping {
            // The same Ping over TCP: a member whose UDP is filtered still answers here.
            let conn = self.tcp_ping(target_addr, &target, seq, signed);
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
        let live = self.holds_live(ping.source.as_str());
        let source = Some(ping.source.as_str());
        self.send_to(ping.source_addr, live, source, &[ack], Some(limit));
    }

    /// The signed Ack that answers the version 2 Ping `msg` to this node: over the original
    /// requester's name, epoch and sequence number, a relay's Ping naming them, and the round's
    /// challenge. `None` if the Ping is not for this node, counted, or in mode `off`.
    pub(crate) fn signed_ack<'a>(
        &mut self,
        msg: &v2::Message<'a>,
        me: &'a str,
    ) -> Option<v2::Message<'a>> {
        let v2::Message::Ping {
            ping,
            source_epoch,
            challenge,
            requester,
        } = *msg
        else {
            return None;
        };
        if ping.target.as_str() != me {
            self.metrics.misdirected += 1;
            return None;
        }
        let (requester, requester_epoch, seq) = match requester {
            Some(p) => (p.requester, p.epoch, p.seq),
            None => (ping.source, source_epoch, ping.seq),
        };
        let ack = v2::Message::Ack {
            seq,
            target_epoch: self.local.member.epoch,
            requester,
            requester_epoch,
            target: id(me),
            challenge,
            certificate_id: CertificateId::default(),
            signature: [0; 64],
        };
        self.signed(ack, None)
    }

    /// Answers a version 2 Ping to this node with its signed Ack, with gossip. The Ack to a
    /// relay's Ping goes behind this node's certificate: the relay checks the Ack before it
    /// forwards it, and the prober that chose it could check the relay, not whether the relay
    /// holds this node's certificate.
    pub(crate) fn on_signed_ping(&mut self, msg: &v2::Message<'_>) {
        let v2::Message::Ping {
            ping, requester, ..
        } = *msg
        else {
            return;
        };
        let me = self.local.member.name.clone();
        let Some(ack) = self.signed_ack(msg, &me) else {
            return;
        };
        let cert = requester
            .and(self.keys.as_ref())
            .map(|k| k.own.bytes.clone());
        let mut head: Vec<v2::Message<'_>> = cert
            .as_deref()
            .and_then(|c| Certificate::decode(c).ok())
            .map(v2::Message::Certificate)
            .into_iter()
            .collect();
        head.push(ack);
        let limit = self.retransmit_limit();
        let live = self.holds_live(ping.source.as_str());
        self.send_to_v2(ping.source_addr, live, &head, Some(limit));
    }

    /// Pings the target on the requester's behalf, unless this node knows the target left. In
    /// plaintext mode a requester this node could not answer is ignored, and a target it may not
    /// send to is not pinged, so that its Nack answers for it.
    pub(crate) fn on_ping_req(&mut self, now: Instant, req: &PingReq<'_>) {
        if !self.may_send(req.requester_addr) {
            return;
        }
        let left = self
            .table
            .get(req.target.as_str())
            .filter(|e| e.member.state == State::Left)
            .map(|e| (e.member.incarnation, e.member.epoch));
        if let Some((inc, epoch)) = left {
            // The requester missed the news and would soon declare the member dead; tell it
            // instead of probing a node that is gone.
            let news = Message::Dead(Dead {
                inc,
                node: req.target,
                from: req.target,
                epoch,
            });
            let limit = self.retransmit_limit();
            // A PingReq names its requester by address only, so it is not counted as live.
            self.send_to(req.requester_addr, false, None, &[news], Some(limit));
            return;
        }
        let seq = self.next_seq();
        let me = self.local.member.name.clone();
        let ping = Message::Ping(Ping {
            seq,
            target: req.target,
            source: id(&me),
            source_addr: self.local.member.addr,
        });
        let limit = self.retransmit_limit();
        let live = self.holds_live(req.target.as_str());
        let target = Some(req.target.as_str());
        self.send_to(req.target_addr, live, target, &[ping], Some(limit));
        let nack_at = req.want_nack.then(|| now + self.nack_window());
        let expires = now + self.cfg.probe_timeout;
        self.relays.insert(
            seq,
            Relay {
                seq: req.seq,
                requester: req.requester_addr,
                nack_at,
                expires,
                signed: None,
            },
        );
    }

    /// How long a relay waits for the target before it sends its Nack: the requester's indirect
    /// phase lasts at least probe_interval - probe_timeout, and the Nack must land inside it,
    /// whatever this node's own health, or it counts as missing.
    fn nack_window(&self) -> Duration {
        let (interval, timeout) = (self.cfg.probe_interval, self.cfg.probe_timeout);
        timeout.min(interval.saturating_sub(timeout)) * 4 / 5
    }

    /// A version 2 PingReq: pings the target at the address this node holds for it, with this
    /// node's own sequence number and the requester's challenge, name, epoch and sequence
    /// number, and answers at the address it holds for the requester. A target that left is
    /// answered for with its signed Left, when this node kept it.
    pub(crate) fn on_signed_ping_req(&mut self, now: Instant, msg: &v2::Message<'_>) {
        let v2::Message::PingReq {
            request: req,
            requester,
            requester_epoch,
            challenge,
        } = *msg
        else {
            return;
        };
        // Names this node holds are answered at the addresses it holds for them.
        let held =
            |name: &str, addr: SocketAddr| self.table.get(name).map_or(addr, |e| e.member.addr);
        let to = held(requester.as_str(), req.requester_addr);
        let target_addr = held(req.target.as_str(), req.target_addr);
        let limit = self.retransmit_limit();
        let left = self
            .table
            .get(req.target.as_str())
            .filter(|e| e.member.state == State::Left)
            .map(|e| (e.member.incarnation, e.member.epoch, e.left));
        if let Some((inc, epoch, proof)) = left {
            let dead = Dead {
                inc,
                node: req.target,
                from: req.target,
                epoch,
            };
            match proof.filter(|p| p.inc == inc && p.epoch == epoch) {
                Some(p) => {
                    let news = signed_dead(&dead, &p.proof);
                    self.send_to_v2(to, false, &[news], Some(limit));
                }
                None => {
                    self.send_to(to, false, None, &[Message::Dead(dead)], Some(limit));
                }
            }
            return;
        }
        let seq = self.next_seq();
        let me = self.local.member.name.clone();
        let ping = v2::Message::Ping {
            ping: Ping {
                seq,
                target: req.target,
                source: id(&me),
                source_addr: self.local.member.addr,
            },
            source_epoch: self.local.member.epoch,
            challenge,
            requester: Some(v2::Probe {
                requester,
                epoch: requester_epoch,
                seq: req.seq,
            }),
        };
        let live = self.holds_live(req.target.as_str());
        self.send_to_v2(target_addr, live, &[ping], Some(limit));
        let nack_at = req.want_nack.then(|| now + self.nack_window());
        let expires = now + self.cfg.probe_timeout;
        self.relays.insert(
            seq,
            Relay {
                seq: req.seq,
                requester: to,
                nack_at,
                expires,
                signed: Some(RelayRound {
                    requester: requester.as_str().to_owned(),
                    requester_epoch,
                    target: req.target.as_str().to_owned(),
                    challenge,
                }),
            },
        );
    }

    pub(crate) fn on_ack(&mut self, seq: u32) {
        if let Some(p) = &mut self.probe {
            // A version 1 Ack names a sequence number alone, and answers no version 2 round.
            if p.seq == seq && p.signed.is_none() {
                p.acked = true;
                return;
            }
        }
        if self.relays.get(&seq).is_some_and(|r| r.signed.is_none()) {
            let relay = self.relays.remove(&seq).expect("looked up above");
            let limit = self.retransmit_limit();
            let ack = Message::Ack { seq: relay.seq };
            self.send_to(relay.requester, false, None, &[ack], Some(limit));
        }
    }

    pub(crate) fn on_nack(&mut self, seq: u32) {
        if let Some(p) = &mut self.probe {
            if p.seq == seq && p.signed.is_none() {
                p.nacks += 1;
            }
        }
    }

    /// A version 2 Ack: checked only when it matches the exact binding of the round this node
    /// runs, not answered yet, or of a round it relays and has not forwarded yet; dropped
    /// unchecked otherwise (rule 4). A relay forwards the target's Ack unchanged. True if it
    /// answered this node's own round.
    pub(crate) fn on_signed_ack(
        &mut self,
        msg: &v2::Message<'_>,
        packet: &PacketCerts<'_>,
    ) -> bool {
        let v2::Message::Ack {
            seq,
            target_epoch,
            requester,
            requester_epoch,
            target,
            challenge,
            certificate_id,
            ..
        } = *msg
        else {
            return false;
        };
        let mine = requester.as_str() == self.local.member.name
            && self.probe.as_ref().is_some_and(|p| {
                !p.acked
                    && p.seq == seq
                    && p.target == target.as_str()
                    && life(target_epoch, p.epoch) == Life::Same
                    && p.signed
                        .as_ref()
                        .is_some_and(|r| r.challenge == challenge && r.epoch == requester_epoch)
            });
        if mine {
            if self
                .check(msg, target.as_str(), certificate_id, packet)
                .is_none()
            {
                return false;
            }
            if let Some(p) = &mut self.probe {
                p.acked = true;
            }
            return true;
        }
        let relayed = self.relays.iter().find_map(|(&k, r)| {
            let s = r.signed.as_ref()?;
            (r.seq == seq
                && s.requester == requester.as_str()
                && s.requester_epoch == requester_epoch
                && s.target == target.as_str()
                && s.challenge == challenge)
                .then_some(k)
        });
        let Some(k) = relayed else {
            return false;
        };
        // A node relays only what it checked (rule 3).
        if self
            .check(msg, target.as_str(), certificate_id, packet)
            .is_none()
        {
            return false;
        }
        if let Some(relay) = self.relays.remove(&k) {
            self.send_to_v2(relay.requester, false, &[*msg], None);
        }
        false
    }

    /// A version 2 Nack: counted once, if it is for the round this node runs and from a relay
    /// it asked in that round, at the epoch it holds for it, whose Nack has not counted yet,
    /// and its signature checks. Anything else is dropped unchecked.
    pub(crate) fn on_signed_nack(&mut self, msg: &v2::Message<'_>, packet: &PacketCerts<'_>) {
        let v2::Message::Nack {
            seq,
            relay,
            relay_epoch,
            requester,
            requester_epoch,
            target,
            challenge,
            certificate_id,
            ..
        } = *msg
        else {
            return;
        };
        let held = self
            .table
            .get(relay.as_str())
            .is_some_and(|e| life(relay_epoch, e.member.epoch) == Life::Same);
        let fresh = held
            && requester.as_str() == self.local.member.name
            && self.probe.as_ref().is_some_and(|p| {
                p.seq == seq
                    && p.target == target.as_str()
                    && p.signed.as_ref().is_some_and(|r| {
                        r.challenge == challenge
                            && r.epoch == requester_epoch
                            && r.relays.get(relay.as_str()) == Some(&false)
                    })
            });
        if !fresh
            || self
                .check(msg, relay.as_str(), certificate_id, packet)
                .is_none()
        {
            return;
        }
        if let Some(p) = &mut self.probe {
            p.nacks += 1;
            if let Some(counted) = p
                .signed
                .as_mut()
                .and_then(|r| r.relays.get_mut(relay.as_str()))
            {
                *counted = true;
            }
        }
    }

    /// Sends due Nacks and forgets relays whose target never answered. The Nack of a version 2
    /// round is signed over its binding.
    pub(crate) fn relay_timers(&mut self, now: Instant) {
        let mut nacks = Vec::new();
        self.relays.retain(|_, r| {
            if r.nack_at.is_some_and(|t| now >= t) {
                r.nack_at = None;
                nacks.push((r.requester, r.seq, r.signed.clone()));
            }
            now < r.expires
        });
        let me = self.local.member.name.clone();
        for (to, seq, signed) in nacks {
            let Some(r) = signed else {
                self.send_to(to, false, None, &[Message::Nack { seq }], None);
                continue;
            };
            let nack = v2::Message::Nack {
                seq,
                relay: id(&me),
                relay_epoch: self.local.member.epoch,
                requester: id(&r.requester),
                requester_epoch: r.requester_epoch,
                target: id(&r.target),
                challenge: r.challenge,
                certificate_id: CertificateId::default(),
                signature: [0; 64],
            };
            if let Some(nack) = self.signed(nack, None) {
                self.send_to_v2(to, false, &[nack], None);
            }
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
