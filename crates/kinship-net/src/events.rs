//! Events for the application, and the per-subscription queues that carry them.
//!
//! Every call to `events()` gets its own bounded queue, starting at the call. The actor never
//! waits on a subscriber: when a queue is full it drops the oldest event and counts it, and the
//! subscriber's next read is [`Event::EventsLost`] with that count.

use std::collections::VecDeque;
use std::net::SocketAddr;
use std::sync::{Arc, Mutex, MutexGuard, PoisonError, Weak};

use kinship_core::Member;
use tokio::sync::Notify;

/// Something the application should hear about. Member events never describe the local node;
/// [`NameConflict`](Self::NameConflict) may.
#[derive(Debug, Clone, PartialEq, Eq)]
#[non_exhaustive]
pub enum Event {
    /// A node is alive that was unknown, dead or left.
    MemberJoined(Member),
    /// A node missed its probes and is suspected.
    MemberSuspect(Member),
    /// A suspect node refuted the suspicion and is alive again.
    MemberRecovered(Member),
    /// A suspicion expired without a refutation.
    MemberDead(Member),
    /// A node left on purpose.
    MemberLeft(Member),
    /// A node changed its metadata.
    MemberUpdated {
        member: Member,
        previous_meta: Vec<u8>,
    },
    /// A node at `other_addr` claims the name of `member`, which keeps it.
    NameConflict {
        member: Member,
        other_addr: SocketAddr,
    },
    /// This subscriber fell behind and this many events were dropped, oldest first. Resync from
    /// `members()`.
    EventsLost(u64),
}

impl Event {
    /// The member event a core event reports, if it is one.
    pub(crate) fn from_core(e: kinship_core::Event) -> Option<Self> {
        use kinship_core::Event as E;
        Some(match e {
            E::MemberJoined(m) => Self::MemberJoined(m),
            E::MemberSuspect(m) => Self::MemberSuspect(m),
            E::MemberRecovered(m) => Self::MemberRecovered(m),
            E::MemberDead(m) => Self::MemberDead(m),
            E::MemberLeft(m) => Self::MemberLeft(m),
            E::MemberUpdated {
                member,
                previous_meta,
            } => Self::MemberUpdated {
                member,
                previous_meta,
            },
            E::NameConflict { member, other_addr } => Self::NameConflict { member, other_addr },
            _ => return None,
        })
    }
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(PoisonError::into_inner)
}

/// Fans events out to every live subscription.
#[derive(Debug)]
pub(crate) struct Hub {
    capacity: usize,
    inner: Mutex<HubState>,
}

#[derive(Debug, Default)]
struct HubState {
    subs: Vec<Weak<Sub>>,
    closed: bool,
}

#[derive(Debug, Default)]
struct Sub {
    queue: Mutex<Queue>,
    notify: Notify,
}

#[derive(Debug, Default)]
struct Queue {
    events: VecDeque<Event>,
    lost: u64,
    closed: bool,
}

impl Hub {
    /// Each subscription holds up to `capacity` events.
    pub fn new(capacity: usize) -> Self {
        Self {
            capacity: capacity.max(1),
            inner: Mutex::default(),
        }
    }

    /// A new subscription that sees every event published from now on.
    pub fn subscribe(&self) -> Events {
        let sub = Arc::new(Sub::default());
        let mut hub = lock(&self.inner);
        if hub.closed {
            lock(&sub.queue).closed = true;
        } else {
            hub.subs.push(Arc::downgrade(&sub));
        }
        Events { sub }
    }

    /// Queues `events` on every subscription, dropping the oldest from full ones. Never waits
    /// for a subscriber.
    pub fn publish(&self, events: &[Event]) {
        if events.is_empty() {
            return;
        }
        let mut hub = lock(&self.inner);
        hub.subs.retain(|weak| {
            let Some(sub) = weak.upgrade() else {
                return false;
            };
            let mut q = lock(&sub.queue);
            for e in events {
                if q.events.len() == self.capacity {
                    q.events.pop_front();
                    q.lost += 1;
                }
                q.events.push_back(e.clone());
            }
            drop(q);
            sub.notify.notify_one();
            true
        });
    }

    /// Ends every subscription once its queued events are read, including later ones.
    pub fn close(&self) {
        let mut hub = lock(&self.inner);
        hub.closed = true;
        for sub in hub.subs.drain(..).filter_map(|w| w.upgrade()) {
            lock(&sub.queue).closed = true;
            sub.notify.notify_one();
        }
    }
}

/// One subscription to a node's events, from [`Memberlist::events`](crate::Memberlist::events).
///
/// Holds up to `event_buffer` events. If the consumer falls behind, the oldest are dropped and
/// the next read is [`Event::EventsLost`].
#[derive(Debug)]
pub struct Events {
    sub: Arc<Sub>,
}

impl Events {
    /// The next event, waiting for one if none is queued. `None` once the node has closed and
    /// every queued event has been read.
    pub async fn recv(&mut self) -> Option<Event> {
        loop {
            match self.next() {
                Next::Event(e) => return Some(e),
                Next::Closed => return None,
                Next::Empty => self.sub.notify.notified().await,
            }
        }
    }

    /// The next event if one is queued, without waiting. `None` also after the node closed;
    /// tell the two apart with [`is_closed`](Self::is_closed).
    pub fn try_recv(&mut self) -> Option<Event> {
        match self.next() {
            Next::Event(e) => Some(e),
            Next::Closed | Next::Empty => None,
        }
    }

    /// True once the node has closed and every queued event has been read.
    pub fn is_closed(&self) -> bool {
        let q = lock(&self.sub.queue);
        q.closed && q.lost == 0 && q.events.is_empty()
    }

    fn next(&self) -> Next {
        let mut q = lock(&self.sub.queue);
        if q.lost > 0 {
            let lost = std::mem::take(&mut q.lost);
            return Next::Event(Event::EventsLost(lost));
        }
        match q.events.pop_front() {
            Some(e) => Next::Event(e),
            None if q.closed => Next::Closed,
            None => Next::Empty,
        }
    }
}

enum Next {
    Event(Event),
    Closed,
    Empty,
}

#[cfg(test)]
mod tests {
    use super::*;
    use kinship_core::State;

    fn member(name: &str) -> Member {
        Member {
            name: name.to_owned(),
            addr: SocketAddr::from(([127, 0, 0, 1], 1)),
            meta: Vec::new(),
            state: State::Alive,
            incarnation: 0,
        }
    }

    fn joined(i: usize) -> Event {
        Event::MemberJoined(member(&format!("n{i}")))
    }

    #[tokio::test]
    async fn subscriptions_start_at_the_call_and_end_on_close() {
        let hub = Hub::new(8);
        hub.publish(&[joined(0)]);
        let mut a = hub.subscribe();
        hub.publish(&[joined(1)]);
        let mut b = hub.subscribe();
        hub.publish(&[joined(2)]);
        assert_eq!(a.recv().await, Some(joined(1)));
        assert_eq!(a.recv().await, Some(joined(2)));
        assert_eq!(b.try_recv(), Some(joined(2)));
        assert_eq!(b.try_recv(), None);
        assert!(!b.is_closed());
        hub.close();
        hub.publish(&[joined(3)]);
        assert_eq!(a.recv().await, None);
        assert!(b.is_closed());
        assert_eq!(hub.subscribe().recv().await, None);
    }

    #[tokio::test]
    async fn a_full_queue_drops_the_oldest_and_reports_the_loss() {
        let hub = Hub::new(4);
        let mut slow = hub.subscribe();
        let mut fast = hub.subscribe();
        for i in 0..10 {
            hub.publish(&[joined(i)]);
            assert_eq!(fast.try_recv(), Some(joined(i)));
        }
        assert_eq!(slow.recv().await, Some(Event::EventsLost(6)));
        for i in 6..10 {
            assert_eq!(slow.recv().await, Some(joined(i)));
        }
        assert_eq!(slow.try_recv(), None);
        assert_eq!(fast.try_recv(), None);
    }

    #[tokio::test]
    async fn recv_wakes_when_an_event_arrives() {
        let hub = Arc::new(Hub::new(4));
        let mut events = hub.subscribe();
        let publisher = Arc::clone(&hub);
        let task = tokio::spawn(async move { events.recv().await });
        tokio::task::yield_now().await;
        publisher.publish(&[joined(7)]);
        assert_eq!(task.await.unwrap(), Some(joined(7)));
    }

    #[test]
    fn dropped_subscriptions_are_pruned() {
        let hub = Hub::new(4);
        drop(hub.subscribe());
        let _kept = hub.subscribe();
        hub.publish(&[joined(0)]);
        assert_eq!(lock(&hub.inner).subs.len(), 1);
    }
}
