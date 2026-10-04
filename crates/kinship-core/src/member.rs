//! Members, their states, and the precedence rules that decide which rumour about a member wins.
//!
//! The rules follow the incarnation table in `docs/design.md`: an Alive wins only with a higher
//! incarnation, a Suspect wins over Alive at the same incarnation, Dead and Left win over Alive
//! and Suspect at the same incarnation, and tombstones yield only to a newer Alive. A rumour
//! about this node at or above its own incarnation is refuted by raising the incarnation past it
//! and gossiping Alive.

use core::net::SocketAddr;

use kinship_proto::{Alive, Dead, Suspect};

use crate::broadcast::Gossip;
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

impl Node {
    pub(crate) fn on_alive(&mut self, now: Instant, a: &Alive<'_>) {
        let name = a.node.as_str();
        if name == self.local.member.name {
            if a.addr != self.local.member.addr {
                self.name_conflict(self.local.member.clone(), a.addr);
            } else if a.inc > self.local.member.incarnation {
                // An older instance of this node, or a forgery: claim the name back.
                self.refute(a.inc);
            }
            return;
        }
        let Some(entry) = self.table.get(name) else {
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
        if a.inc <= old.incarnation {
            return;
        }
        if old.state.is_live() && a.addr != old.addr {
            // Two live nodes claim one name; the one we knew first keeps it.
            let member = old.clone();
            self.name_conflict(member, a.addr);
            return;
        }
        let was = old.state;
        let previous_meta = (old.meta != a.meta).then(|| old.meta.clone());
        let entry = self.table.update(name, State::Alive, a.inc, now);
        entry.member.addr = a.addr;
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
            if s.inc >= self.local.member.incarnation {
                self.refute(s.inc);
            }
            return;
        }
        let Some(entry) = self.table.get(name) else {
            return;
        };
        let (state, inc) = (entry.member.state, entry.member.incarnation);
        let from = s.from.as_str();
        match state {
            State::Alive if s.inc >= inc => {
                let n = self.cluster_size();
                let member = self
                    .table
                    .update(name, State::Suspect, s.inc, now)
                    .member
                    .clone();
                self.suspicions.insert(
                    name.to_owned(),
                    Suspicion::new(&self.cfg, n, now, &self.local.member.name, from),
                );
                self.metrics.suspicions += 1;
                self.events.push_back(Event::MemberSuspect(member));
                self.broadcast(Gossip::from_suspect(s));
            }
            State::Suspect if s.inc >= inc => {
                if s.inc > inc {
                    // A newer suspicion: same timer, new incarnation.
                    self.table.update(name, State::Suspect, s.inc, now);
                }
                let fresh = self
                    .suspicions
                    .get_mut(name)
                    .is_some_and(|sus| sus.confirm(&self.local.member.name, from));
                if s.inc > inc || fresh {
                    self.broadcast(Gossip::from_suspect(s));
                }
            }
            _ => {}
        }
    }

    pub(crate) fn on_dead(&mut self, now: Instant, d: &Dead<'_>) {
        let name = d.node.as_str();
        if name == self.local.member.name {
            if d.inc >= self.local.member.incarnation {
                self.refute(d.inc);
            }
            return;
        }
        let Some(entry) = self.table.get(name) else {
            return;
        };
        if !entry.member.state.is_live() || d.inc < entry.member.incarnation {
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

    /// Raises this node's incarnation past `seen` and gossips Alive.
    pub(crate) fn refute(&mut self, seen: u32) {
        let me = &mut self.local.member;
        // At u32::MAX a rumour can no longer be outbid; the member stays as it is.
        me.incarnation = me.incarnation.max(seen.saturating_add(1));
        self.metrics.refutations += 1;
        self.broadcast(self.local_alive());
    }

    fn name_conflict(&mut self, member: Member, other_addr: SocketAddr) {
        self.metrics.name_conflicts += 1;
        self.events
            .push_back(Event::NameConflict { member, other_addr });
    }
}
