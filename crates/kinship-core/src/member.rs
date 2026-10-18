//! Members, their states, and the precedence rules that decide which rumour about a member wins.
//!
//! The rules follow the incarnation table in `docs/design.md`: an Alive wins only with a higher
//! incarnation, a Suspect wins over Alive at the same incarnation, Dead and Left win over Alive
//! and Suspect at the same incarnation, and tombstones yield only to a newer Alive. A rumour
//! about this node at or above its own incarnation is refuted by raising the incarnation past it
//! and gossiping Alive; one below it is answered by gossiping the same Alive again, since its
//! sender missed the refutation.
//!
//! "Higher" is serial number arithmetic (RFC 1982), see [`newer`]: incarnations wrap past
//! u32::MAX to 0, so no rumour, however high, leaves a member unable to refute it (KI-02).
//!
//! Above incarnations sits the member's epoch, which names one life of it: a process that
//! restarts with the same name starts a later life, see [`life`]. An Alive about a later life
//! than the one held replaces it whatever its incarnation, since a new process counts its
//! incarnations from 0 again; a rumour about an earlier life changes nothing, so the old life's
//! death cannot kill the new one, nor its Alives bring a dead member back. Where either side
//! does not know the epoch (0, from nodes older than 0.3), incarnations decide alone, as they
//! always did.

use core::net::SocketAddr;

use kinship_proto::{Alive, Dead, Message, Suspect};

use crate::broadcast::{Gossip, id};
use crate::event::Event;
use crate::signing::{AccusationProof, LeftProof, SignedBy};
use crate::table::Entry;
use crate::time::Instant;
use crate::{Node, suspicion::Suspicion};

/// Where a member stands in this node's view.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub enum State {
    Alive,
    /// Missed a probe; dead unless it refutes before the suspicion timeout.
    Suspect,
    /// Declared dead by the failure detector. Kept as a tombstone for `dead_reclaim`.
    Dead,
    /// Left on purpose. Kept as a tombstone for `dead_reclaim`.
    Left,
}

impl State {
    /// Alive or Suspect: still a member, still probed.
    pub fn is_live(self) -> bool {
        matches!(self, Self::Alive | Self::Suspect)
    }
}

/// One member as this node sees it.
#[derive(Debug, Clone, PartialEq, Eq)]
#[cfg_attr(feature = "serde", derive(serde::Serialize))]
pub struct Member {
    pub name: String,
    pub addr: SocketAddr,
    pub meta: Vec<u8>,
    pub state: State,
    /// Raised only by the member itself, on refutation or metadata change.
    pub incarnation: u32,
    /// Which life of the member this is: the milliseconds of its wall clock when its process
    /// started, raised past any earlier life of the same name it heard of, so a member that
    /// restarts comes back with a higher epoch. 0 when no epoch was heard, as from nodes
    /// older than 0.3.
    pub epoch: u64,
}

/// How the life a rumour names compares with the life a node holds for that member.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Life {
    /// The same life, or one whose epoch either side does not know: incarnations decide.
    Same,
    /// A later life: the member restarted since the life held.
    Later,
    /// An earlier life, which nothing can change any more.
    Earlier,
}

/// How the life of epoch `rumour` compares with the life of epoch `held`.
///
/// Epochs compare as serial numbers, as incarnations do (KI-02): whatever epoch a forged
/// rumour names, a member can start a later life than it, and honest epochs, wall-clock
/// milliseconds, are nowhere near 2^63 apart, so among them this is the plain order. Two
/// epochs exactly 2^63 apart are each earlier than the other. Epoch 0 means unknown.
pub(crate) fn life(rumour: u64, held: u64) -> Life {
    if rumour == held || rumour == 0 || held == 0 {
        Life::Same
    } else if (rumour.wrapping_sub(held) as i64) > 0 {
        Life::Later
    } else {
        Life::Earlier
    }
}

/// The first epoch past `epoch`, skipping 0, which means unknown.
pub(crate) fn epoch_past(epoch: u64) -> u64 {
    match epoch.wrapping_add(1) {
        0 => 1,
        e => e,
    }
}

/// Whether incarnation `a` is newer than `b`.
///
/// Incarnations are serial numbers (RFC 1982): they wrap from u32::MAX to 0, and `a` is newer
/// when it is less than 2^31 ahead of `b` around that ring. Every incarnation therefore has
/// newer ones, so a member can always refute, whatever incarnation a rumour names; and one
/// rumour moves a member's incarnation less than 2^31 ahead of what a node holds. Two
/// incarnations exactly 2^31 apart are neither newer than the other, and a rumour at either
/// loses to the other. Honest members raise their incarnation once per refutation or metadata
/// change, so they never come near 2^31 apart, and every comparison among them is the plain
/// one it was before incarnations wrapped.
pub(crate) fn newer(a: u32, b: u32) -> bool {
    // The difference as a signed number: positive when `a` is up to 2^31 - 1 ahead. Exactly
    // 2^31 is i32::MIN, so neither of two such incarnations is newer.
    (a.wrapping_sub(b) as i32) > 0
}

/// Whether incarnation `a` is `b` or newer than it.
pub(crate) fn at_least(a: u32, b: u32) -> bool {
    a == b || newer(a, b)
}

/// Whether this node, on learning that a member speaks version 2 from an Alive with `signed`,
/// sends it its own signed Alive: unless the Alive came in a version 2 push-pull, whose sender
/// spreads this node's record signed too.
fn announces(signed: Option<&SignedBy>) -> bool {
    signed.is_none_or(|s| !s.pulled)
}

/// How many members new to this node one datagram or push-pull frame may still add: created
/// once per packet, so every Alive and record in it shares `max_new_members_per_packet`.
#[derive(Debug, Clone, Copy)]
pub(crate) struct Admission {
    left: usize,
}

impl Admission {
    /// Whether the packet has added as many new members as it may.
    pub fn is_spent(&self) -> bool {
        self.left == 0
    }
}

impl Node {
    /// The admission budget of one packet.
    pub(crate) fn admission(&self) -> Admission {
        Admission {
            left: self.cfg.max_new_members_per_packet,
        }
    }

    /// Whether the table has room for one more member: it holds fewer than `max_members`,
    /// this node and tombstones included.
    pub(crate) fn has_room(&self) -> bool {
        self.table.len() + 1 < self.cfg.max_members
    }

    /// Takes one admission from `budget` if the table and the packet have room for a new
    /// member, and counts a refusal otherwise.
    fn admit(&mut self, budget: &mut Admission) -> bool {
        if budget.left == 0 || !self.has_room() {
            self.metrics.members_refused += 1;
            return false;
        }
        budget.left -= 1;
        true
    }

    /// An Alive about `a.node`. One about a member this node does not know adds it only if
    /// `budget` and the table have room (KI-04); one about a known member always applies.
    ///
    /// `signed` is its checked signature, from a version 2 packet; the member keeps it, and so
    /// does its rumour. An unsigned Alive that applies leaves the member unsigned, and a signed
    /// copy of the Alive already held gives it the proof it lacked.
    pub(crate) fn on_alive(
        &mut self,
        now: Instant,
        a: &Alive<'_>,
        budget: &mut Admission,
        signed: Option<SignedBy>,
    ) {
        let name = a.node.as_str();
        if name == self.local.member.name {
            if a.addr != self.local.member.addr {
                self.name_conflict(self.local.member.clone(), a.addr);
                return;
            }
            match life(a.epoch, self.local.member.epoch) {
                Life::Later => self.outlive(a.epoch, a.inc),
                // An older instance of this node, or a forgery: claim the name back.
                Life::Same if newer(a.inc, self.local.member.incarnation) => self.refute(a.inc),
                // An earlier life of this node, which this one's Alive replaces wherever it goes.
                Life::Same | Life::Earlier => {}
            }
            return;
        }
        let Some(entry) = self.table.get(name) else {
            if !self.admit(budget) {
                return;
            }
            let member = Member {
                name: name.to_owned(),
                addr: a.addr,
                meta: a.meta.to_vec(),
                state: State::Alive,
                incarnation: a.inc,
                epoch: a.epoch,
            };
            self.events.push_back(Event::MemberJoined(member.clone()));
            self.table.insert(Entry {
                member,
                since: now,
                vmin: a.vmin,
                vmax: a.vmax,
                proof: signed.as_ref().map(|s| s.proof),
                left: None,
            });
            let gossip = self.alive_gossip(a, signed.as_ref(), true);
            self.broadcast(gossip);
            if announces(signed.as_ref()) {
                self.announce_to(name);
            }
            return;
        };
        let old = &entry.member;
        let life = life(a.epoch, old.epoch);
        match life {
            // A stale life, however high its incarnation: a recording, or gossip from before the
            // member restarted. It cannot bring a dead member back.
            Life::Earlier => return,
            Life::Same if !newer(a.inc, old.incarnation) => {
                let (state, inc) = (old.state, old.incarnation);
                if old.epoch == 0
                    && a.epoch != 0
                    && a.inc == inc
                    && a.addr == old.addr
                    && state.is_live()
                {
                    // The Alive this node already applied, now with the epoch that a node older
                    // than 0.3 dropped when it passed it on. Nothing about the member changed.
                    let sign = self.keys.is_some();
                    let entry = self.table.update(name, state, inc, now);
                    entry.member.epoch = a.epoch;
                    // In mode `sign`, a member this node was given in a list, with no Alive yet,
                    // also takes the versions it speaks from this one.
                    let learned_v2 = sign && entry.vmax < 2 && a.vmax >= 2;
                    if sign {
                        entry.vmin = a.vmin;
                        entry.vmax = a.vmax;
                    }
                    if learned_v2 {
                        self.announce_to(name);
                    }
                }
                // A signed copy of the Alive held without a proof, as a 0.4 relay passes it on.
                let unsigned = self
                    .table
                    .get(name)
                    .is_some_and(|e| e.proof.is_none() && e.holds(a));
                if let Some(signed) = signed.filter(|_| unsigned) {
                    self.attach_proof(a, &signed);
                }
                return;
            }
            Life::Same | Life::Later => {}
        }
        if a.addr != old.addr {
            // Two nodes claim one name; the one we knew first keeps it. That holds for a Dead
            // or Left member too, until its tombstone is reaped, so that nobody can move the
            // name of a member that died or left to an address of their choosing (KI-03); a
            // member that really moved is admitted at its new address once it has been.
            let member = old.clone();
            self.name_conflict(member, a.addr);
            return;
        }
        if life == Life::Later {
            return self.restarted(now, a, signed);
        }
        let spoke_v2 = entry.vmax >= 2;
        let was = old.state;
        let previous_meta = (old.meta != a.meta).then(|| old.meta.clone());
        let entry = self.table.update(name, State::Alive, a.inc, now);
        entry.member.meta.clear();
        entry.member.meta.extend_from_slice(a.meta);
        entry.vmin = a.vmin;
        entry.vmax = a.vmax;
        if a.epoch != 0 {
            // New if this node first heard of the member through a node older than 0.3.
            entry.member.epoch = a.epoch;
        }
        entry.proof = signed
            .as_ref()
            .filter(|_| entry.member.epoch == a.epoch)
            .map(|s| s.proof);
        let member = entry.member.clone();
        self.suspicions.remove(name);
        match was {
            State::Dead | State::Left => self.events.push_back(Event::MemberJoined(member)),
            State::Suspect => {
                self.events
                    .push_back(Event::MemberRecovered(member.clone()));
                if let Some(previous_meta) = previous_meta {
                    self.events.push_back(Event::MemberUpdated {
                        member,
                        previous_meta,
                    });
                }
            }
            State::Alive => {
                if let Some(previous_meta) = previous_meta {
                    self.events.push_back(Event::MemberUpdated {
                        member,
                        previous_meta,
                    });
                }
            }
        }
        let gossip = self.alive_gossip(a, signed.as_ref(), false);
        self.broadcast(gossip);
        if !spoke_v2 && announces(signed.as_ref()) {
            self.announce_to(name);
        }
    }

    /// An Alive about a later life of a member this node holds: it restarted. The new life
    /// replaces the old one whatever the incarnations, since the new process counts its own
    /// from 0. The application hears the old life leave, unless it had already died or left,
    /// and the new one join, so that it sees a restart as two events.
    fn restarted(&mut self, now: Instant, a: &Alive<'_>, signed: Option<SignedBy>) {
        let name = a.node.as_str();
        let Some(old) = self.table.get(name).map(|e| e.member.clone()) else {
            return;
        };
        let entry = self.table.update(name, State::Alive, a.inc, now);
        entry.since = now;
        entry.member.epoch = a.epoch;
        entry.member.meta.clear();
        entry.member.meta.extend_from_slice(a.meta);
        entry.vmin = a.vmin;
        entry.vmax = a.vmax;
        entry.proof = signed.as_ref().map(|s| s.proof);
        let member = entry.member.clone();
        self.suspicions.remove(name);
        self.metrics.restarts += 1;
        if old.state.is_live() {
            self.events.push_back(Event::MemberLeft(Member {
                state: State::Left,
                ..old
            }));
        }
        self.events.push_back(Event::MemberJoined(member));
        let gossip = self.alive_gossip(a, signed.as_ref(), true);
        self.broadcast(gossip);
        if announces(signed.as_ref()) {
            self.announce_to(name);
        }
    }

    /// The rumour of an Alive this node applied: with its signature when it was signed, and
    /// with its certificate ahead of it when it starts a member or a life new to this node, or
    /// when the packet that brought it carried the certificate, as a relay passes it on.
    fn alive_gossip(&mut self, a: &Alive<'_>, signed: Option<&SignedBy>, new: bool) -> Gossip {
        let Some(s) = signed else {
            return Gossip::from_alive(a);
        };
        let cert = self
            .bind_cert(a.node.as_str(), s)
            .filter(|_| new || s.carried);
        Gossip::signed_alive(a, s.proof.cert, s.proof.sig, cert)
    }

    /// Gives the member the proof of the Alive it is held at, which it lacked, and the rumour
    /// of that Alive still being spread its signature.
    fn attach_proof(&mut self, a: &Alive<'_>, signed: &SignedBy) {
        let name = a.node.as_str();
        self.table.set_proof(name, Some(signed.proof));
        // The member's own word on the versions it speaks.
        let learned_v2 = self
            .table
            .set_versions(name, a.vmin, a.vmax)
            .is_some_and(|vmax| vmax < 2 && a.vmax >= 2);
        let cert = self.bind_cert(name, signed).filter(|_| signed.carried);
        self.out
            .broadcasts
            .attach(a, signed.proof.cert, signed.proof.sig, cert);
        if learned_v2 {
            self.announce_to(name);
        }
    }

    /// A Suspect about `s.node`, with its checked signature `proof` when it came signed.
    pub(crate) fn on_suspect(
        &mut self,
        now: Instant,
        s: &Suspect<'_>,
        proof: Option<AccusationProof>,
    ) {
        let name = s.node.as_str();
        if name == self.local.member.name {
            return self.about_self(s.inc, s.epoch);
        }
        let Some(entry) = self.table.get(name) else {
            return;
        };
        if life(s.epoch, entry.member.epoch) != Life::Same {
            // About an earlier life, which is gone, or a later one this node has not heard of
            // yet, which its Alive will bring.
            return;
        }
        let (state, inc) = (entry.member.state, entry.member.incarnation);
        let from = s.from.as_str();
        match state {
            State::Alive if at_least(s.inc, inc) => {
                let n = self.cluster_size();
                let member = self
                    .table
                    .update(name, State::Suspect, s.inc, now)
                    .member
                    .clone();
                self.suspicions
                    .insert(name.to_owned(), Suspicion::new(&self.cfg, n, now, from));
                self.metrics.suspicions += 1;
                self.events.push_back(Event::MemberSuspect(member));
                self.broadcast(Gossip::suspect(s, proof));
            }
            State::Suspect if newer(s.inc, inc) => {
                // The member refuted the old suspicion, even if its Alive has not reached us,
                // so this is a new one: a fresh timer and fresh confirmations.
                let n = self.cluster_size();
                self.table.update(name, State::Suspect, s.inc, now);
                self.suspicions
                    .insert(name.to_owned(), Suspicion::new(&self.cfg, n, now, from));
                self.broadcast(Gossip::suspect(s, proof));
            }
            State::Suspect if s.inc == inc => {
                let fresh = self
                    .suspicions
                    .get_mut(name)
                    .is_some_and(|sus| sus.confirm(from));
                if fresh {
                    self.broadcast(Gossip::suspect(s, proof));
                }
            }
            _ => {}
        }
    }

    /// A Dead about `d.node`, with its checked signature `proof` when it came signed; a signed
    /// Left is kept with the tombstone.
    pub(crate) fn on_dead(&mut self, now: Instant, d: &Dead<'_>, proof: Option<AccusationProof>) {
        let name = d.node.as_str();
        if name == self.local.member.name {
            return self.about_self(d.inc, d.epoch);
        }
        let Some(entry) = self.table.get(name) else {
            return;
        };
        if !entry.member.state.is_live()
            || life(d.epoch, entry.member.epoch) != Life::Same
            || !at_least(d.inc, entry.member.incarnation)
        {
            return;
        }
        let state = if d.is_left() {
            State::Left
        } else {
            State::Dead
        };
        let entry = self.table.update(name, state, d.inc, now);
        entry.left = proof.filter(|_| d.is_left()).map(|proof| LeftProof {
            inc: d.inc,
            epoch: d.epoch,
            proof,
        });
        let member = entry.member.clone();
        self.suspicions.remove(name);
        self.events.push_back(if d.is_left() {
            Event::MemberLeft(member)
        } else {
            Event::MemberDead(member)
        });
        self.broadcast(Gossip::dead(d, proof));
    }

    /// A peer's push-pull holds `name` as Suspect or Dead at `inc`.
    ///
    /// As in memberlist, either becomes a suspicion rather than a death: this node may have
    /// heard from the member more recently, and a suspicion lets the member refute, which is
    /// also how a reconnect heals a partition. Unlike memberlist, the suspicion is not this
    /// node's: it never saw the member fail, so it counts no reporter of its own and is not
    /// gossiped, which would make every other node count this one as an independent
    /// confirmation. A suspicion already running at that incarnation is left as it is. The
    /// member itself is told, as by the buddy system, so that it can refute. A record about
    /// another life of the member than the one held changes nothing.
    pub(crate) fn on_merged_suspicion(&mut self, now: Instant, name: &str, inc: u32, epoch: u64) {
        if name == self.local.member.name {
            return self.about_self(inc, epoch);
        }
        let Some(entry) = self.table.get(name) else {
            return;
        };
        if life(epoch, entry.member.epoch) != Life::Same {
            return;
        }
        let (state, addr) = (entry.member.state, entry.member.addr);
        match state {
            State::Alive if at_least(inc, entry.member.incarnation) => {}
            State::Suspect if newer(inc, entry.member.incarnation) => {}
            _ => return,
        }
        let n = self.cluster_size();
        let member = self
            .table
            .update(name, State::Suspect, inc, now)
            .member
            .clone();
        self.suspicions
            .insert(name.to_owned(), Suspicion::unreported(&self.cfg, n, now));
        if state == State::Alive {
            self.metrics.suspicions += 1;
            self.events.push_back(Event::MemberSuspect(member));
        }
        let me = self.local.member.name.clone();
        let suspect = Message::Suspect(Suspect {
            inc,
            node: id(name),
            from: id(&me),
            epoch,
        });
        let limit = self.retransmit_limit();
        self.send_to(addr, true, Some(name), &[suspect], Some(limit));
    }

    /// A Suspect or Dead about this node at `inc` of its life `epoch`. One about an earlier
    /// life is answered with this life's Alive, as a stale one is.
    fn about_self(&mut self, inc: u32, epoch: u64) {
        match life(epoch, self.local.member.epoch) {
            Life::Later => self.outlive(epoch, inc),
            Life::Same if at_least(inc, self.local.member.incarnation) => {
                // Others missed our Acks: likely this node is the slow one.
                self.health_delta(1);
                self.refute(inc);
            }
            Life::Same | Life::Earlier => self.reassert(),
        }
    }

    /// Moves this node past a later life of its own name that it heard of: an earlier instance
    /// whose wall clock ran ahead of this one's, or a forgery. Its epoch goes one past that
    /// life's, which every node takes as a restart, and its incarnation past that life's too,
    /// for nodes older than 0.3, which order by incarnation alone; then it gossips Alive.
    /// Counted as a refutation. A node that left stays gone.
    fn outlive(&mut self, epoch: u64, inc: u32) {
        if self.has_left() {
            return;
        }
        let me = &mut self.local.member;
        me.epoch = epoch_past(epoch);
        if at_least(inc, me.incarnation) {
            me.incarnation = inc.wrapping_add(1);
        }
        self.metrics.refutations += 1;
        // A new life: its first Alive carries the certificate, as a node's first one does.
        self.resign_local();
        self.broadcast(self.local_alive_announced());
    }

    /// Raises this node's incarnation past `seen`, which is its own or newer, and gossips
    /// Alive, unless it has left. Past u32::MAX the incarnation wraps to 0, which is newer.
    pub(crate) fn refute(&mut self, seen: u32) {
        if self.has_left() {
            // A node that left stays gone: an Alive now would undo its Left everywhere.
            return;
        }
        let me = &mut self.local.member;
        me.incarnation = seen.wrapping_add(1);
        self.metrics.refutations += 1;
        self.resign_local();
        self.broadcast(self.local_alive());
    }

    /// Answers a Suspect or Dead about this node below its incarnation: the sender missed the
    /// refutation, and only this node can repair that, so its Alive is queued again at the
    /// incarnation it already has, to ride the next packets, the Ack to a buddy Ping first.
    /// Not a refutation: the incarnation stays, local health does not move and nothing is
    /// counted. A node that left stays gone.
    fn reassert(&mut self) {
        if !self.has_left() {
            self.broadcast(self.local_alive());
        }
    }

    fn name_conflict(&mut self, member: Member, other_addr: SocketAddr) {
        self.metrics.name_conflicts += 1;
        self.events
            .push_back(Event::NameConflict { member, other_addr });
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn incarnations_compare_as_serial_numbers() {
        // The plain order, wherever honest members are.
        assert!(newer(1, 0) && newer(7_000, 6_999) && !newer(0, 1) && !newer(5, 5));
        assert!(at_least(5, 5) && at_least(6, 5) && !at_least(4, 5));
        // Past u32::MAX comes 0, which is newer: u32::MAX can be outbid.
        assert!(newer(0, u32::MAX) && !newer(u32::MAX, 0));
        assert!(newer(u32::MAX.wrapping_add(10), u32::MAX - 10));
        // Up to 2^31 - 1 ahead is newer; exactly 2^31 apart, neither is.
        let half = 1u32 << 31;
        assert!(newer(half - 1, 0) && !newer(0, half - 1));
        assert!(!newer(half, 0) && !newer(0, half));
        assert!(!at_least(half, 0) && !at_least(0, half));
        // A rumour more than 2^31 ahead reads as old, so it moves nothing.
        assert!(newer(0, half + 1) && !newer(half + 1, 0));
    }

    #[test]
    fn epochs_order_lives_and_zero_is_unknown() {
        assert_eq!(life(5, 5), Life::Same);
        assert_eq!(life(6, 5), Life::Later);
        assert_eq!(life(4, 5), Life::Earlier);
        // An epoch nobody sent defers to incarnations, on either side.
        assert_eq!(life(0, 5), Life::Same);
        assert_eq!(life(5, 0), Life::Same);
        // Serial numbers, as incarnations are: u64::MAX can be outlived, and a life 2^63 away
        // is earlier from both sides.
        assert_eq!(epoch_past(u64::MAX), 1, "0 is skipped");
        assert_eq!(life(epoch_past(u64::MAX), u64::MAX), Life::Later);
        assert_eq!(life((1 << 63) + 1, 1), Life::Earlier);
        assert_eq!(life(1, (1 << 63) + 1), Life::Earlier);
        assert_eq!(life(1 << 63, 1), Life::Later, "2^63 - 1 ahead");
        // Wall-clock milliseconds a restart apart are the plain order.
        assert_eq!(life(1_790_000_000_001, 1_790_000_000_000), Life::Later);
    }
}
