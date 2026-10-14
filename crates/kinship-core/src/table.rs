//! The member table and the shuffled round-robin probe order.

use core::net::SocketAddr;
use core::time::Duration;
use std::collections::BTreeMap;

use crate::member::{Member, State};
use crate::rng::Rng;
use crate::time::Instant;

/// A member plus what only the protocol needs to know about it.
#[derive(Debug, Clone)]
pub(crate) struct Entry {
    pub member: Member,
    /// When the member entered its current state.
    pub since: Instant,
    pub vmin: u8,
    pub vmax: u8,
}

/// Every member other than this node, live or tombstoned.
///
/// A `BTreeMap` rather than a `HashMap` because iteration order feeds random choices, and the
/// simulator needs it to be the same in every process.
#[derive(Debug, Default)]
pub(crate) struct Table {
    entries: BTreeMap<String, Entry>,
    /// How many entries have each address, so that whether an address is a member's is quick
    /// to tell.
    addrs: BTreeMap<SocketAddr, usize>,
    /// Members in Alive or Suspect.
    live: usize,
    /// Names to probe this pass, in shuffled order; `order[pos..]` are still to come.
    order: Vec<String>,
    pos: usize,
    /// Members that became live since the pass began, still to be slotted into it.
    joined: Vec<String>,
}

impl Table {
    pub fn get(&self, name: &str) -> Option<&Entry> {
        self.entries.get(name)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Entry> {
        self.entries.values()
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Members in Alive or Suspect, not counting this node.
    pub fn live(&self) -> usize {
        self.live
    }

    /// Adds a member that is not in the table.
    pub fn insert(&mut self, entry: Entry) {
        let live = entry.member.state.is_live();
        *self.addrs.entry(entry.member.addr).or_default() += 1;
        let name = entry.member.name.clone();
        let was_live = match self.entries.insert(name.clone(), entry) {
            Some(old) => {
                self.live -= usize::from(old.member.state.is_live());
                unindex(&mut self.addrs, old.member.addr);
                old.member.state.is_live()
            }
            None => false,
        };
        self.live += usize::from(live);
        if live && !was_live {
            self.joined.push(name);
        }
    }

    /// Whether any member in the table, tombstones included, has the address `addr`.
    pub fn has_addr(&self, addr: SocketAddr) -> bool {
        self.addrs.contains_key(&addr)
    }

    /// Moves a known member to `state` at `inc`, and returns it for further changes. A member
    /// keeps its address for as long as it is in the table, tombstone included (KI-03), which
    /// keeps addresses indexed; callers must not change it.
    ///
    /// # Panics
    ///
    /// If `name` is not in the table; callers look it up first.
    pub fn update(&mut self, name: &str, state: State, inc: u32, now: Instant) -> &mut Entry {
        let entry = self.entries.get_mut(name).expect("member was looked up");
        let m = &mut entry.member;
        match (m.state.is_live(), state.is_live()) {
            (true, false) => self.live -= 1,
            (false, true) => {
                self.live += 1;
                self.joined.push(name.to_owned());
            }
            _ => {}
        }
        if m.state != state {
            entry.since = now;
        }
        m.state = state;
        m.incarnation = inc;
        entry
    }

    /// Deletes tombstones that have been Dead or Left for at least `keep`.
    pub fn reap(&mut self, now: Instant, keep: Duration) {
        let addrs = &mut self.addrs;
        self.entries.retain(|_, e| {
            let kept = e.member.state.is_live() || now - e.since < keep;
            if !kept {
                unindex(addrs, e.member.addr);
            }
            kept
        });
    }

    /// The next member to probe: each live member once per pass, in an order reshuffled every
    /// pass. A member that becomes live during a pass takes a random place among the members
    /// still to come in it, as memberlist inserts one at a random offset: a pass lasts as many
    /// probe intervals as it had members, so one that began while this node knew few of them
    /// would otherwise leave every later joiner unprobed by it until the pass ends, and a crash
    /// of one of them would wait that long for its first suspicion and its confirmations.
    pub fn next_probe(&mut self, rng: &mut Rng) -> Option<&Entry> {
        let joined = std::mem::take(&mut self.joined);
        // An ended pass is rebuilt below from every live member.
        if self.pos < self.order.len() {
            for name in joined {
                if !self.order[self.pos..].contains(&name) {
                    let at = self.pos + rng.index(self.order.len() - self.pos + 1);
                    self.order.insert(at, name);
                }
            }
        }
        for _ in 0..2 {
            while let Some(name) = self.order.get(self.pos) {
                self.pos += 1;
                if let Some(e) = self.entries.get(name) {
                    if e.member.state.is_live() {
                        return Some(e);
                    }
                }
            }
            self.order.clear();
            self.order.extend(
                self.entries
                    .values()
                    .filter(|e| e.member.state.is_live())
                    .map(|e| e.member.name.clone()),
            );
            rng.shuffle(&mut self.order);
            self.pos = 0;
            self.joined.clear();
        }
        None
    }

    /// Up to `k` distinct entries matching `keep`, chosen uniformly at random.
    pub fn random<'a>(
        &'a self,
        k: usize,
        rng: &mut Rng,
        keep: impl Fn(&Entry) -> bool,
    ) -> Vec<&'a Entry> {
        let mut pool: Vec<&Entry> = self.entries.values().filter(|e| keep(e)).collect();
        let k = k.min(pool.len());
        // Partial Fisher-Yates: the first k slots end up a uniform sample.
        for i in 0..k {
            let j = i + rng.index(pool.len() - i);
            pool.swap(i, j);
        }
        pool.truncate(k);
        pool
    }
}

/// Counts one entry fewer at `addr`.
fn unindex(addrs: &mut BTreeMap<SocketAddr, usize>, addr: SocketAddr) {
    if let Some(n) = addrs.get_mut(&addr) {
        *n -= 1;
        if *n == 0 {
            addrs.remove(&addr);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn entry(name: &str, port: u16, state: State) -> Entry {
        Entry {
            member: Member {
                name: name.to_owned(),
                addr: SocketAddr::from(([127, 0, 0, 1], port)),
                meta: Vec::new(),
                state,
                incarnation: 0,
                epoch: 0,
            },
            since: Instant::ZERO,
            vmin: 1,
            vmax: 1,
        }
    }

    #[test]
    fn members_that_join_mid_pass_are_probed_in_it() {
        let mut rng = Rng::new(1);
        let mut t = Table::default();
        for (i, name) in ["a", "b", "c", "d"].into_iter().enumerate() {
            t.insert(entry(name, i as u16, State::Alive));
        }
        let mut probe = |t: &mut Table| t.next_probe(&mut rng).unwrap().member.name.clone();
        let mut pass = |t: &mut Table, first: Vec<String>, n: usize| {
            let mut p = first;
            p.extend((0..n).map(|_| probe(t)));
            p.sort();
            p
        };
        let all = ["a", "b", "c", "d", "e"];
        // A pass of four is under way when "e" joins: it is probed before that pass ends.
        let first = pass(&mut t, vec![], 1);
        t.insert(entry("e", 10, State::Alive));
        assert_eq!(pass(&mut t, first, 4), all);
        // The next pass has all five, each once.
        assert_eq!(pass(&mut t, vec![], 5), all);
        // A pass that began while "e" was dead takes it back when it revives.
        t.update("e", State::Dead, 0, Instant::ZERO);
        let first = pass(&mut t, vec![], 1);
        t.update("e", State::Alive, 1, Instant::ZERO);
        assert_eq!(pass(&mut t, first, 4), all);
        // Every member dies and revives one probe into a pass: those still to come keep their
        // one slot, and the one already probed gets another.
        pass(&mut t, vec![], 1);
        for name in all {
            t.update(name, State::Dead, 1, Instant::ZERO);
            t.update(name, State::Alive, 2, Instant::ZERO);
        }
        assert_eq!(pass(&mut t, vec![], 5), all);
    }

    #[test]
    fn member_addresses_are_indexed_through_replacements_and_reaping() {
        let at = |port| SocketAddr::from(([127, 0, 0, 1], port));
        let mut t = Table::default();
        t.insert(entry("a", 1, State::Alive));
        t.insert(entry("b", 1, State::Alive));
        assert!(t.has_addr(at(1)) && !t.has_addr(at(2)));
        // A replacement leaves the old address while another member still has it.
        t.insert(entry("a", 2, State::Alive));
        assert!(t.has_addr(at(1)) && t.has_addr(at(2)));
        t.insert(entry("b", 3, State::Alive));
        assert!(!t.has_addr(at(1)), "b's replacement took it away");
        // Tombstones keep their address until they are reaped.
        t.update("a", State::Dead, 0, Instant::ZERO);
        let later = Instant::ZERO + Duration::from_secs(1);
        t.reap(later, Duration::from_secs(2));
        assert!(t.has_addr(at(2)));
        t.reap(later, Duration::from_secs(1));
        assert!(!t.has_addr(at(2)) && t.has_addr(at(3)));
    }
}
