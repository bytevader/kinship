//! Failing reproductions of the findings in `docs/review.md`, the review of kinship-core against
//! SWIM (Das, Gupta and Motivala, 2002), Lifeguard (Dadgar et al., 2017) and `docs/design.md`.
//!
//! Each test asserts what should hold, and failed when the review was written. A test whose
//! finding is still open is ignored, with the finding's id in the reason, so the suite stays
//! green; the fix removes the `#[ignore]`. Run the ignored ones with
//! `cargo test --release -p kinship-sim --test review -- --ignored --nocapture`. A failure names
//! its lowest failing seed, and `KINSHIP_SEED=<seed>` replays that one.

mod common;

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet};
use std::net::SocketAddr;
use std::rc::Rc;

use common::{Log, Observed, check_all, config, index_of, ms, secs, seeds};
use kinship_core::{
    Command, CommandId, CommandOutput, Event, Instant, Key, StreamEvent, StreamId, Transmit,
};
use kinship_proto::{Alive, Codec, Limits, Message, NodeId, PacketKind};
use kinship_sim::{
    Action, LinkConfig, NodeSpec, Scenario, Sim, SimNode, TraceConfig, addr_of, name_of,
};

/// Builds the sim with `make` building each node, every node logging into the returned log.
fn sim<N: SimNode + 'static>(
    seed: u64,
    scenario: Scenario<N::Command>,
    make: impl Fn(&NodeSpec, Log) -> N + 'static,
) -> (Sim<N>, Log) {
    let log: Log = Rc::default();
    let factory_log = log.clone();
    let sim = Sim::new(seed, scenario, move |spec| make(spec, factory_log.clone()));
    (sim, log)
}

/// Every MemberDead in the log, as (observer, member, when).
fn deaths(log: &Log) -> Vec<(usize, String, Instant)> {
    log.borrow()
        .iter()
        .filter_map(|s| match &s.event {
            Event::MemberDead(m) => Some((s.observer, m.name.clone(), s.t)),
            _ => None,
        })
        .collect()
}

/// Opens datagrams sealed with the key [`config`] uses, so a test can read what nodes say.
fn reader() -> Codec {
    Codec::encrypted(
        b"default",
        Limits::default(),
        vec![Key::from_bytes([7; 32])],
    )
    .expect("the test key opens")
}

/// Calls `each` on every message of a datagram `codec` can open.
fn read(codec: &Codec, payload: &[u8], mut each: impl FnMut(&Message<'_>)) {
    let mut buf = payload.to_vec();
    if let Ok(p) = codec.open(PacketKind::Datagram, &mut buf) {
        for m in p.iter() {
            each(&m);
        }
    }
}

// ---------------------------------------------------------------------------------------------
// KP-01: a restarted node whose first packet comes from another node that just started keeps its
// replay floor far behind cluster time, and accepts recordings far older than the window.

/// What the scenario tells a node to do: a core command, or the attacker's part.
#[derive(Debug, Clone)]
enum Tap {
    Core(Command),
    /// Start or stop adding the datagrams the victim receives to the attacker's tape.
    Record(bool),
    /// Hand the victim every datagram on the tape, byte for byte.
    Replay,
}

/// The attacker's recording. It lives outside the victim, so it survives the victim's restart.
#[derive(Debug, Default)]
struct Tape {
    on: bool,
    packets: Vec<(SocketAddr, Vec<u8>)>,
}

/// A node on its own process clock. kinship-net counts time from the moment its actor starts,
/// so a restarted process starts at zero; the simulator's restart hands the new instance the
/// shared clock instead, which hides that a new process is behind cluster time.
struct Process {
    inner: Observed,
    /// When this process started, on the simulator's clock.
    start: Instant,
    /// Set on the node the attacker taps.
    tape: Option<Rc<RefCell<Tape>>>,
}

impl Process {
    fn local(&self, now: Instant) -> Instant {
        Instant::from_nanos(now.as_nanos() - self.start.as_nanos())
    }
}

impl SimNode for Process {
    type Command = Tap;
    type Event = Event;

    fn handle_datagram(&mut self, now: Instant, from: SocketAddr, buf: &[u8]) {
        if let Some(tape) = &self.tape {
            let mut tape = tape.borrow_mut();
            if tape.on {
                tape.packets.push((from, buf.to_vec()));
            }
        }
        let now = self.local(now);
        self.inner.handle_datagram(now, from, buf);
    }

    fn handle_stream(&mut self, now: Instant, conn: StreamId, ev: StreamEvent<'_>) {
        let now = self.local(now);
        self.inner.handle_stream(now, conn, ev);
    }

    fn handle_timeout(&mut self, now: Instant) {
        let now = self.local(now);
        self.inner.handle_timeout(now);
    }

    fn command(&mut self, now: Instant, cmd: Tap) -> CommandId {
        let now = self.local(now);
        match cmd {
            Tap::Core(cmd) => self.inner.command(now, cmd),
            Tap::Record(on) => {
                if let Some(tape) = &self.tape {
                    tape.borrow_mut().on = on;
                }
                CommandId::from_raw(u64::MAX)
            }
            Tap::Replay => {
                let packets = self
                    .tape
                    .as_ref()
                    .map(|t| t.borrow().packets.clone())
                    .unwrap_or_default();
                for (from, buf) in packets {
                    self.inner.handle_datagram(now, from, &buf);
                }
                CommandId::from_raw(u64::MAX)
            }
        }
    }

    fn poll_transmit(&mut self) -> Option<Transmit> {
        self.inner.poll_transmit()
    }

    fn poll_event(&mut self) -> Option<Event> {
        self.inner.poll_event()
    }

    fn poll_timeout(&self) -> Option<Instant> {
        let start = self.start.as_nanos();
        self.inner
            .poll_timeout()
            .map(|t| Instant::from_nanos(t.as_nanos().saturating_add(start)))
    }
}

/// The node the attacker taps. It restarts together with [`KP01_PEER`].
const KP01_VICTIM: usize = 0;
/// Restarts with the victim; each lists the other as a seed, as two seed nodes do.
const KP01_PEER: usize = 1;
/// A seed that keeps running.
const KP01_SEED: usize = 2;
/// Changes its metadata while the attacker records, then leaves and stops.
const KP01_GONE: usize = 4;

fn kp01(seed: u64) -> Result<(), String> {
    let record = secs(290);
    let update = secs(295);
    let leave = secs(300);
    let restart = secs(600);
    let replay = secs(720);
    let cmd = |node, cmd| Action::Command { node, cmd };
    let join = |node, seeds: [usize; 2]| {
        let seeds = seeds.iter().map(|&s| addr_of(s)).collect();
        Action::Command {
            node,
            cmd: Tap::Core(Command::Join { seeds }),
        }
    };
    let scenario = Scenario::new(5)
        .duration(replay + secs(30))
        .link(LinkConfig::lan())
        .trace(TraceConfig::OFF)
        .at(record, cmd(KP01_VICTIM, Tap::Record(true)))
        .at(
            update,
            cmd(KP01_GONE, Tap::Core(Command::SetMeta(b"v=2".to_vec()))),
        )
        .at(leave, cmd(KP01_GONE, Tap::Core(Command::Leave)))
        .at(leave + secs(5), Action::Crash(KP01_GONE))
        .at(leave + secs(10), cmd(KP01_VICTIM, Tap::Record(false)))
        .at(restart, Action::Restart(KP01_VICTIM))
        .at(restart, Action::Restart(KP01_PEER))
        .at(restart, join(KP01_VICTIM, [KP01_PEER, KP01_SEED]))
        .at(restart, join(KP01_PEER, [KP01_VICTIM, KP01_SEED]))
        .at(replay, cmd(KP01_VICTIM, Tap::Replay));
    let tape = Rc::new(RefCell::new(Tape::default()));
    let factory_tape = tape.clone();
    let (mut sim, log) = sim(seed, scenario, move |spec, log| {
        // A first instance knows every member, as a static list would. A restarted process
        // starts its clock at zero, knows nobody, and joins.
        let restarted = spec.now != Instant::ZERO;
        let mut local = spec.clone();
        local.now = Instant::ZERO;
        Process {
            inner: Observed::new(&local, log, move |_| !restarted),
            start: spec.now,
            tape: (spec.index == KP01_VICTIM).then(|| factory_tape.clone()),
        }
    });
    let gone = name_of(KP01_GONE);
    let fail = |msg: String| Err(format!("seed {seed}: {msg}"));

    sim.run_until(Instant::ZERO + (replay - ms(1)));
    let joined = log.borrow().iter().any(|s| {
        s.observer == KP01_VICTIM
            && matches!(
                s.event,
                Event::CommandDone {
                    result: Ok(CommandOutput::Joined { seeds }),
                    ..
                } if seeds > 0
            )
    });
    let victim = &sim.node(KP01_VICTIM).expect("running").inner.node;
    if !joined || victim.member(&name_of(KP01_SEED)).is_none() {
        return fail("the restarted victim never joined".into());
    }
    if victim.member(&gone).is_some() {
        return fail(format!("the victim knew {gone} before the replay"));
    }
    if tape.borrow().packets.is_empty() {
        return fail("the attacker recorded nothing".into());
    }
    let before = victim.metrics().clone();
    let mark = log.borrow().len();

    sim.run_until(Instant::ZERO + replay);
    let after = sim
        .node(KP01_VICTIM)
        .expect("running")
        .inner
        .node
        .metrics()
        .clone();
    sim.run();
    let back: Vec<Event> = log.borrow()[mark..]
        .iter()
        .filter(|s| matches!(&s.event, Event::MemberJoined(m) if m.name == gone))
        .map(|s| s.event.clone())
        .collect();
    if !back.is_empty() {
        let observers: BTreeSet<usize> = log.borrow()[mark..]
            .iter()
            .filter(|s| matches!(&s.event, Event::MemberJoined(m) if m.name == gone))
            .map(|s| s.observer)
            .collect();
        return fail(format!(
            "{} restarted at {restart:?} and joined; at {replay:?} it accepted {} of {} recorded \
             datagrams sealed {:?} to {:?} earlier ({} dropped as replays), and {gone}, which \
             left at {leave:?}, joined again on nodes {observers:?}",
            name_of(KP01_VICTIM),
            after.packets_received - before.packets_received,
            tape.borrow().packets.len(),
            replay - (leave + secs(10)),
            replay - record,
            after.replays_dropped - before.replays_dropped,
        ));
    }
    Ok(())
}

#[test]
fn kp01_a_restarted_node_refuses_recordings_older_than_the_window() {
    check_all(seeds(8), kp01);
}

// ---------------------------------------------------------------------------------------------
// KP-02: leave() spends its retransmits on members it knows have left, so in a scale-down the
// last nodes to leave can be done having told no live member, which then reports them dead.

fn kp02(seed: u64) -> Result<(), String> {
    const NODES: usize = 10;
    // Scale from ten nodes to three: 3..10 leave a second apart, each closing as soon as its
    // leave() returns, as `async with Cluster` does.
    let leavers: Vec<usize> = (3..NODES).collect();
    let first = secs(20);
    let left_at = |i: usize| first + secs(i as u64);
    let end = left_at(leavers.len()) + secs(60);
    let mut scenario = Scenario::new(NODES)
        .duration(end)
        .link(LinkConfig::lan())
        .trace(TraceConfig::OFF);
    for (i, &node) in leavers.iter().enumerate() {
        scenario = scenario.at(
            left_at(i),
            Action::Command {
                node,
                cmd: Command::Leave,
            },
        );
    }
    let (mut sim, log) = sim(seed, scenario, |spec, log| {
        Observed::new(spec, log, |_| true)
    });

    let mut open: BTreeSet<usize> = leavers.iter().copied().collect();
    let mut seen = 0;
    while sim.now() < Instant::ZERO + end {
        let next = sim.now() + ms(10);
        sim.run_until(next);
        let done: Vec<usize> = log.borrow()[seen..]
            .iter()
            .filter(|s| {
                open.contains(&s.observer)
                    && matches!(
                        s.event,
                        Event::CommandDone {
                            result: Ok(CommandOutput::Done),
                            ..
                        }
                    )
            })
            .map(|s| s.observer)
            .collect();
        seen = log.borrow().len();
        for node in done {
            open.remove(&node);
            sim.apply(Action::Crash(node));
        }
    }
    if !open.is_empty() {
        return Err(format!("seed {seed}: {open:?} never finished leaving"));
    }

    if let Some((o, m, t)) = deaths(&log).into_iter().next() {
        let i = leavers.iter().position(|&l| l == index_of(&m));
        let when = i.map(|i| format!("; it left at {:?}, after {i} others had", left_at(i)));
        return Err(format!(
            "seed {seed}: {} reported {m} dead at {t:?}{}",
            name_of(o),
            when.unwrap_or_default()
        ));
    }
    for o in 0..3 {
        for &l in &leavers {
            let heard = log.borrow().iter().any(|s| {
                s.observer == o && matches!(&s.event, Event::MemberLeft(m) if m.name == name_of(l))
            });
            if !heard {
                return Err(format!(
                    "seed {seed}: {} never heard that {} left",
                    name_of(o),
                    name_of(l)
                ));
            }
        }
    }
    Ok(())
}

#[test]
fn kp02_nodes_that_leave_one_after_another_are_never_reported_dead() {
    check_all(seeds(16), kp02);
}

// ---------------------------------------------------------------------------------------------
// KP-03: Config accepts limits in which a member's own Alive cannot fit in a datagram. Such a
// member never refutes over UDP, so one short pause gets it declared dead.

/// The member with the most metadata the limits allow.
const KP03_FULL: usize = 5;

fn kp03(seed: u64) -> Result<(), String> {
    const NODES: usize = 10;
    const DATAGRAM: usize = 576;
    let mut cfg = config();
    // A smaller datagram, as for a path with a 576-byte MTU; every other field is lan(). Such
    // limits are refused, naming the field.
    cfg.limits.udp_max_payload = DATAGRAM;
    match cfg.validate() {
        Err(e) if e.field == "udp_max_payload" => {}
        other => {
            return Err(format!(
                "seed {seed}: a {DATAGRAM}-byte datagram, which cannot carry a full Alive, \
                 validated as {other:?}"
            ));
        }
    }
    // The smallest datagram the limits accept carries the member's Alive, so it survives.
    let datagram = (DATAGRAM..)
        .find(|&d| {
            cfg.limits.udp_max_payload = d;
            cfg.validate().is_ok()
        })
        .expect("the default datagram is valid");
    let meta = vec![b'x'; cfg.limits.max_meta_bytes];
    let name = name_of(KP03_FULL);
    let alive = Message::Alive(Alive {
        inc: 1,
        node: NodeId::new(&name).expect("valid"),
        addr: addr_of(KP03_FULL),
        meta: &meta,
        vmin: 1,
        vmax: 1,
    });
    let codec = Codec::encrypted(
        cfg.cluster.as_bytes(),
        cfg.limits,
        vec![Key::from_bytes([7; 32])],
    )
    .expect("valid limits");
    // Payload bytes a datagram has for its messages and their count.
    let room = codec.max_payload_len(PacketKind::Datagram);

    let pause = secs(20);
    let scenario = Scenario::new(NODES)
        .duration(pause + secs(60))
        .link(LinkConfig::lan())
        .trace(TraceConfig::OFF)
        .at(
            secs(1),
            Action::Command {
                node: KP03_FULL,
                cmd: Command::SetMeta(meta.clone()),
            },
        )
        // A three-second stall, such as a long GC pause, long enough to be suspected.
        .at(
            pause,
            Action::Pause {
                node: KP03_FULL,
                duration: secs(3),
            },
        );
    let (mut sim, log) = sim(seed, scenario, move |spec, log| {
        Observed::with_config(spec, cfg.clone(), log, |_| true)
    });
    sim.run();
    let first = log.borrow().iter().find_map(|s| match &s.event {
        Event::MemberDead(m) => Some((s.observer, m.clone(), s.t)),
        _ => None,
    });
    if let Some((o, m, t)) = first {
        let full = &sim.node(KP03_FULL).expect("never crashed").node;
        return Err(format!(
            "seed {seed}: {} declared {} dead at {t:?}, holding it at incarnation {}. {name} is \
             at {} after its metadata update and {} refutations; its Alive is {} bytes and a \
             {datagram}-byte datagram has {room} for its messages and their count",
            name_of(o),
            m.name,
            m.incarnation,
            full.local().incarnation,
            full.metrics().refutations,
            alive.encoded_len(),
        ));
    }
    Ok(())
}

#[test]
fn kp03_a_member_with_full_metadata_survives_a_pause() {
    check_all(seeds(8), kp03);
}

// ---------------------------------------------------------------------------------------------
// KP-04: a member drops a rumour about itself at an older incarnation without a word, so a node
// that missed its refutation keeps the stale suspicion. The buddy system's Ack carries nothing,
// and the node declares dead a member that answers its Pings.

/// The node whose inbound path fails for a few seconds.
const KP04_DEAF: usize = 0;

/// What a watched node's Pings that carried their target's suspicion became.
#[derive(Debug, Default)]
struct Buddy {
    /// Pings sent with a Suspect of their target ahead of them, by sequence number.
    sent: BTreeMap<u32, (String, Instant)>,
    /// Those the target answered itself: target, when sent, when answered.
    answered: Vec<(String, Instant, Instant)>,
}

/// A node whose datagrams the test reads, to see which buddy-system Pings were answered.
struct Watched {
    inner: Observed,
    codec: Codec,
    buddy: Rc<RefCell<Buddy>>,
    now: Instant,
}

impl SimNode for Watched {
    type Command = Command;
    type Event = Event;

    fn handle_datagram(&mut self, now: Instant, from: SocketAddr, buf: &[u8]) {
        self.now = now;
        let mut buddy = self.buddy.borrow_mut();
        read(&self.codec, buf, |m| {
            if let Message::Ack { seq } = m {
                let direct = buddy
                    .sent
                    .get(seq)
                    .is_some_and(|(to, _)| addr_of(index_of(to)) == from);
                if direct {
                    let (to, at) = buddy.sent.remove(seq).expect("present");
                    buddy.answered.push((to, at, now));
                }
            }
        });
        drop(buddy);
        self.inner.handle_datagram(now, from, buf);
    }

    fn handle_stream(&mut self, now: Instant, conn: StreamId, ev: StreamEvent<'_>) {
        self.now = now;
        self.inner.handle_stream(now, conn, ev);
    }

    fn handle_timeout(&mut self, now: Instant) {
        self.now = now;
        self.inner.handle_timeout(now);
    }

    fn command(&mut self, now: Instant, cmd: Command) -> CommandId {
        self.now = now;
        self.inner.command(now, cmd)
    }

    fn poll_transmit(&mut self) -> Option<Transmit> {
        let t = self.inner.poll_transmit()?;
        if let Transmit::Datagram { payload, .. } = &t {
            let (mut ping, mut suspects) = (None, Vec::new());
            read(&self.codec, payload, |m| match m {
                Message::Ping(p) => ping = Some((p.seq, p.target.as_str().to_owned())),
                Message::Suspect(s) => suspects.push(s.node.as_str().to_owned()),
                _ => {}
            });
            if let Some((seq, target)) = ping.filter(|(_, t)| suspects.contains(t)) {
                self.buddy.borrow_mut().sent.insert(seq, (target, self.now));
            }
        }
        Some(t)
    }

    fn poll_event(&mut self) -> Option<Event> {
        self.inner.poll_event()
    }

    fn poll_timeout(&self) -> Option<Instant> {
        self.inner.poll_timeout()
    }
}

fn kp04(seed: u64) -> Result<(), String> {
    const NODES: usize = 6;
    let outage = secs(20);
    let length = ms(3_500);
    let others: Vec<usize> = (0..NODES).filter(|&o| o != KP04_DEAF).collect();
    let scenario = Scenario::new(NODES)
        .duration(outage + secs(70))
        .link(LinkConfig::lan())
        .trace(TraceConfig::OFF)
        // The deaf node hears nothing for a few seconds: a NIC reset, a full receive queue.
        .at(
            outage,
            Action::Block {
                from: others.into(),
                to: KP04_DEAF.into(),
            },
        )
        .at(outage + length, Action::Heal);
    let buddy = Rc::new(RefCell::new(Buddy::default()));
    let factory_buddy = buddy.clone();
    let (mut sim, log) = sim(seed, scenario, move |spec, log| Watched {
        inner: Observed::new(spec, log, |_| true),
        codec: reader(),
        // Only the deaf node's Pings are of interest.
        buddy: if spec.index == KP04_DEAF {
            factory_buddy.clone()
        } else {
            Rc::default()
        },
        now: spec.now,
    });
    sim.run();

    let healed = Instant::ZERO + outage + length;
    for (o, m, t) in deaths(&log) {
        if o != KP04_DEAF {
            continue;
        }
        let answered: Vec<Instant> = buddy
            .borrow()
            .answered
            .iter()
            .filter(|(to, sent, _)| *to == m && *sent >= healed && *sent < t)
            .map(|(_, _, at)| *at)
            .collect();
        if answered.is_empty() {
            continue;
        }
        let refuted = sim
            .node(index_of(&m))
            .map(|n| n.inner.node.local().incarnation);
        return Err(format!(
            "seed {seed}: {} declared {m} dead at {t:?}, after {m} had answered its Pings that \
             carried the suspicion at {answered:?}; {m} was at incarnation {refuted:?}, above \
             the stale suspicion, so its Acks carried no refutation",
            name_of(KP04_DEAF)
        ));
    }
    Ok(())
}

#[test]
fn kp04_a_member_that_answers_the_buddy_ping_is_not_declared_dead() {
    check_all(seeds(32), kp04);
}

// ---------------------------------------------------------------------------------------------
// KP-05: merging a push-pull signs every suspicion in it with this node's own name, so others
// count a confirmation from a node that never probed the member.

/// Every node's PingReqs and the Suspects it signed, read off the wire.
#[derive(Debug, Default)]
struct Signed {
    /// Members each node asked relays to probe: its own direct probe of them went unanswered.
    asked: BTreeMap<usize, BTreeSet<String>>,
    /// Suspects a node signed with its own name about a member it never asked about.
    unbacked: Vec<(usize, String, Instant)>,
    /// When each node handled a stream frame: a push-pull it merged.
    frames: BTreeMap<usize, Vec<Instant>>,
}

/// A node whose outgoing datagrams the test reads.
struct Signer {
    inner: Observed,
    index: usize,
    codec: Codec,
    signed: Rc<RefCell<Signed>>,
    now: Instant,
}

impl SimNode for Signer {
    type Command = Command;
    type Event = Event;

    fn handle_datagram(&mut self, now: Instant, from: SocketAddr, buf: &[u8]) {
        self.now = now;
        self.inner.handle_datagram(now, from, buf);
    }

    fn handle_stream(&mut self, now: Instant, conn: StreamId, ev: StreamEvent<'_>) {
        self.now = now;
        if let StreamEvent::Frame(_) = ev {
            let mut signed = self.signed.borrow_mut();
            signed.frames.entry(self.index).or_default().push(now);
        }
        self.inner.handle_stream(now, conn, ev);
    }

    fn handle_timeout(&mut self, now: Instant) {
        self.now = now;
        self.inner.handle_timeout(now);
    }

    fn command(&mut self, now: Instant, cmd: Command) -> CommandId {
        self.now = now;
        self.inner.command(now, cmd)
    }

    fn poll_transmit(&mut self) -> Option<Transmit> {
        let t = self.inner.poll_transmit()?;
        if let Transmit::Datagram { to, payload } = &t {
            let me = name_of(self.index);
            let mut signed = self.signed.borrow_mut();
            let signed = &mut *signed;
            read(&self.codec, payload, |m| match m {
                Message::PingReq(r) => {
                    let asked = signed.asked.entry(self.index).or_default();
                    asked.insert(r.target.as_str().to_owned());
                }
                // A Suspect sent to the suspect itself is the buddy system, not gossip.
                Message::Suspect(s)
                    if s.from.as_str() == me && *to != addr_of(index_of(s.node.as_str())) =>
                {
                    let node = s.node.as_str();
                    let asked = signed
                        .asked
                        .get(&self.index)
                        .is_some_and(|a| a.contains(node));
                    if !asked {
                        signed
                            .unbacked
                            .push((self.index, node.to_owned(), self.now));
                    }
                }
                _ => {}
            });
        }
        Some(t)
    }

    fn poll_event(&mut self) -> Option<Event> {
        self.inner.poll_event()
    }

    fn poll_timeout(&self) -> Option<Instant> {
        self.inner.poll_timeout()
    }
}

fn kp05(seed: u64) -> Result<(), String> {
    const NODES: usize = 10;
    let crash = secs(20);
    let gone = NODES - 1;
    let scenario = Scenario::new(NODES)
        .duration(crash + secs(40))
        .link(LinkConfig::lan())
        .trace(TraceConfig::OFF)
        .at(crash, Action::Crash(gone));
    let signed = Rc::new(RefCell::new(Signed::default()));
    let factory_signed = signed.clone();
    let (mut sim, log) = sim(seed, scenario, move |spec, log| Signer {
        inner: Observed::new(spec, log, |_| true),
        index: spec.index,
        codec: reader(),
        signed: factory_signed.clone(),
        now: spec.now,
    });
    sim.run();
    let declared = deaths(&log)
        .iter()
        .filter(|(_, m, _)| *m == name_of(gone))
        .count();
    if declared < NODES - 1 {
        return Err(format!(
            "seed {seed}: setup: only {declared} nodes declared the crash"
        ));
    }
    let signed = signed.borrow();
    if let Some((o, m, t)) = signed.unbacked.first() {
        let merged = signed
            .frames
            .get(o)
            .and_then(|f| f.iter().rev().find(|&&f| f <= *t))
            .map_or("never".to_owned(), |f| format!("at {f:?}"));
        return Err(format!(
            "seed {seed}: {} gossiped Suspect({m}, from {}) at {t:?} without ever having probed \
             {m} unanswered; it last merged a push-pull frame {merged}. {} such Suspects in all",
            name_of(*o),
            name_of(*o),
            signed.unbacked.len()
        ));
    }
    Ok(())
}

#[test]
fn kp05_a_node_confirms_only_suspicions_its_own_probe_raised() {
    check_all(seeds(8), kp05);
}
