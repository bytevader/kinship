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
        if let Some(old) = self.entries.insert(entry.member.name.clone(), entry) {
            self.live -= usize::from(old.member.state.is_live());
            unindex(&mut self.addrs, old.member.addr);
        }
        self.live += usize::from(live);
    }

    /// Whether any member in the table, tombstones included, has the address `addr`.
    pub fn has_addr(&self, addr: SocketAddr) -> bool {
        self.addrs.contains_key(&addr)
    }

    /// Moves a known member to `addr`. Addresses change only here, which keeps them indexed.
    pub fn set_addr(&mut self, name: &str, addr: SocketAddr) {
        let Some(entry) = self.entries.get_mut(name) else {
            return;
        };
        if entry.member.addr != addr {
            unindex(&mut self.addrs, entry.member.addr);
            *self.addrs.entry(addr).or_default() += 1;
            entry.member.addr = addr;
        }
    }

    /// Moves a known member to `state` at `inc`, and returns it for further changes; its
    /// address changes only through [`set_addr`](Self::set_addr).
    ///
    /// # Panics
    ///
    /// If `name` is not in the table; callers look it up first.
    pub fn update(&mut self, name: &str, state: State, inc: u32, now: Instant) -> &mut Entry {
        let entry = self.entries.get_mut(name).expect("member was looked up");
        let m = &mut entry.member;
        match (m.state.is_live(), state.is_live()) {
            (true, false) => self.live -= 1,
            (false, true) => self.live += 1,
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
    /// pass. Members that joined during a pass wait for the next one.
    pub fn next_probe(&mut self, rng: &mut Rng) -> Option<&Entry> {
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
            },
            since: Instant::ZERO,
            vmin: 1,
            vmax: 1,
        }
    }

    #[test]
    fn member_addresses_are_indexed_through_moves_replacements_and_reaping() {
        let at = |port| SocketAddr::from(([127, 0, 0, 1], port));
        let mut t = Table::default();
        t.insert(entry("a", 1, State::Alive));
        t.insert(entry("b", 1, State::Alive));
        assert!(t.has_addr(at(1)) && !t.has_addr(at(2)));
        // A move leaves the old address while another member still has it.
        t.set_addr("a", at(2));
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
