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

use core::net::SocketAddr;

use kinship_proto::{Alive, Dead, Message, Suspect};

use crate::broadcast::{Gossip, id};
use crate::event::Event;
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

/// How many members new to this node one datagram or push-pull frame may still add: created
/// once per packet, so every Alive and record in it shares `max_new_members_per_packet`.
#[derive(Debug)]
pub(crate) struct Admission {
    left: usize,
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
    pub(crate) fn on_alive(&mut self, now: Instant, a: &Alive<'_>, budget: &mut Admission) {
        let name = a.node.as_str();
        if name == self.local.member.name {
            if a.addr != self.local.member.addr {
                self.name_conflict(self.local.member.clone(), a.addr);
            } else if newer(a.inc, self.local.member.incarnation) {
                // An older instance of this node, or a forgery: claim the name back.
                self.refute(a.inc);
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
            };
            self.events.push_back(Event::MemberJoined(member.clone()));
            self.table.insert(Entry {
                member,
                since: now,
                vmin: a.vmin,
                vmax: a.vmax,
            });
            self.broadcast(Gossip::from_alive(a));
            return;
        };
        let old = &entry.member;
        if !newer(a.inc, old.incarnation) {
            return;
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
        let was = old.state;
        let previous_meta = (old.meta != a.meta).then(|| old.meta.clone());
        let entry = self.table.update(name, State::Alive, a.inc, now);
        entry.member.meta.clear();
        entry.member.meta.extend_from_slice(a.meta);
        entry.vmin = a.vmin;
        entry.vmax = a.vmax;
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
        self.broadcast(Gossip::from_alive(a));
    }

    pub(crate) fn on_suspect(&mut self, now: Instant, s: &Suspect<'_>) {
        let name = s.node.as_str();
        if name == self.local.member.name {
            return self.about_self(s.inc);
        }
        let Some(entry) = self.table.get(name) else {
            return;
        };
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
                self.broadcast(Gossip::from_suspect(s));
            }
            State::Suspect if newer(s.inc, inc) => {
                // The member refuted the old suspicion, even if its Alive has not reached us,
                // so this is a new one: a fresh timer and fresh confirmations.
                let n = self.cluster_size();
                self.table.update(name, State::Suspect, s.inc, now);
                self.suspicions
                    .insert(name.to_owned(), Suspicion::new(&self.cfg, n, now, from));
                self.broadcast(Gossip::from_suspect(s));
            }
            State::Suspect if s.inc == inc => {
                let fresh = self
                    .suspicions
                    .get_mut(name)
                    .is_some_and(|sus| sus.confirm(from));
                if fresh {
                    self.broadcast(Gossip::from_suspect(s));
                }
            }
            _ => {}
        }
    }

    pub(crate) fn on_dead(&mut self, now: Instant, d: &Dead<'_>) {
        let name = d.node.as_str();
        if name == self.local.member.name {
            return self.about_self(d.inc);
        }
        let Some(entry) = self.table.get(name) else {
            return;
        };
        if !entry.member.state.is_live() || !at_least(d.inc, entry.member.incarnation) {
            return;
        }
        let state = if d.is_left() {
            State::Left
        } else {
            State::Dead
        };
        let member = self.table.update(name, state, d.inc, now).member.clone();
        self.suspicions.remove(name);
        self.events.push_back(if d.is_left() {
            Event::MemberLeft(member)
        } else {
            Event::MemberDead(member)
        });
        self.broadcast(Gossip::from_dead(d));
    }

    /// A peer's push-pull holds `name` as Suspect or Dead at `inc`.
    ///
    /// As in memberlist, either becomes a suspicion rather than a death: this node may have
    /// heard from the member more recently, and a suspicion lets the member refute, which is
    /// also how a reconnect heals a partition. Unlike memberlist, the suspicion is not this
    /// node's: it never saw the member fail, so it counts no reporter of its own and is not
    /// gossiped, which would make every other node count this one as an independent
    /// confirmation. A suspicion already running at that incarnation is left as it is. The
    /// member itself is told, as by the buddy system, so that it can refute.
    pub(crate) fn on_merged_suspicion(&mut self, now: Instant, name: &str, inc: u32) {
        if name == self.local.member.name {
            return self.about_self(inc);
        }
        let Some(entry) = self.table.get(name) else {
            return;
        };
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
        });
        let limit = self.retransmit_limit();
        self.send_to(addr, true, &[suspect], Some(limit));
    }

    /// A Suspect or Dead about this node at `inc`.
    fn about_self(&mut self, inc: u32) {
        if at_least(inc, self.local.member.incarnation) {
            // Others missed our Acks: likely this node is the slow one.
            self.health_delta(1);
            self.refute(inc);
        } else {
            self.reassert();
        }
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
}
