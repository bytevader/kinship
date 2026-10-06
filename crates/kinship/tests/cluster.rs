//! Clusters of real nodes on localhost: UDP and TCP sockets, the actor, and the protocol.
//!
//! Every wait is bounded, so a regression fails with a message instead of hanging CI.

use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use kinship::mem::MemNetwork;
use kinship::{Cluster, Config, Event, Events, Key, State};
use tokio::time::{Instant, sleep, timeout};

/// Upper bound on any single wait. Generous, because CI machines are slow and shared.
const WAIT: Duration = Duration::from_secs(30);

fn config(i: usize) -> Config {
    Config::local()
        .with_bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .with_name(format!("n{i}"))
}

async fn bounded<F: Future>(what: &str, fut: F) -> F::Output {
    match timeout(WAIT, fut).await {
        Ok(out) => out,
        Err(_) => panic!("timed out: {what}"),
    }
}

async fn wait_until(what: &str, mut done: impl FnMut() -> bool) {
    let deadline = Instant::now() + WAIT;
    while !done() {
        assert!(Instant::now() < deadline, "timed out waiting until {what}");
        sleep(Duration::from_millis(20)).await;
    }
}

/// True when `node` sees exactly `names` as members, all alive.
fn sees_alive(node: &Cluster, names: &[String]) -> bool {
    let members = node.members();
    members.len() == names.len()
        && members
            .iter()
            .all(|m| m.state == State::Alive && names.contains(&m.name))
}

/// Starts `n` nodes from `make`, each joining through the first, and waits until every node
/// sees every other one alive.
async fn start(n: usize, make: impl Fn(usize) -> Config) -> Vec<Cluster> {
    let first = bounded("start n0", Cluster::start(make(0))).await.unwrap();
    let seed = first.local().addr;
    let mut nodes = vec![first];
    for i in 1..n {
        let cfg = make(i).with_seeds([seed]);
        let node = bounded("start", Cluster::start(cfg)).await.unwrap();
        nodes.push(node);
    }
    let names: Vec<String> = (0..n).map(|i| format!("n{i}")).collect();
    wait_until("every node sees every other alive", || {
        nodes.iter().all(|c| sees_alive(c, &names))
    })
    .await;
    nodes
}

async fn close_all(nodes: &[Cluster]) {
    for node in nodes {
        bounded("close", node.close()).await;
    }
}

fn drain(events: &mut Events) -> Vec<Event> {
    std::iter::from_fn(|| events.try_recv()).collect()
}

fn about<'a>(events: &'a [Event], name: &'a str) -> impl Iterator<Item = &'a Event> + 'a {
    events.iter().filter(move |e| match e {
        Event::MemberJoined(m)
        | Event::MemberSuspect(m)
        | Event::MemberRecovered(m)
        | Event::MemberDead(m)
        | Event::MemberLeft(m) => m.name == name,
        Event::MemberUpdated { member, .. } => member.name == name,
        _ => false,
    })
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn twenty_nodes_join_through_one_seed() {
    let nodes = start(20, config).await;
    for node in &nodes {
        let local = node.local();
        assert_eq!(local.state, State::Alive);
        assert_eq!(local.addr, node.local_addr(), "port 0 is read back");
        assert_eq!(node.stats().metrics.decode_errors, 0);
    }
    close_all(&nodes).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_aborted_node_is_declared_dead() {
    let nodes = start(8, config).await;
    let (victim, survivors) = nodes.split_last().unwrap();
    let mut events: Vec<Events> = survivors.iter().map(Cluster::events).collect();
    victim.abort();

    wait_until("every survivor declares n7 dead", || {
        survivors
            .iter()
            .all(|c| c.member("n7").is_some_and(|m| m.state == State::Dead))
    })
    .await;
    for (node, events) in survivors.iter().zip(&mut events) {
        let events = drain(events);
        let n7: Vec<&Event> = about(&events, "n7").collect();
        assert!(
            n7.iter().any(|e| matches!(e, Event::MemberDead(_))),
            "{} saw {n7:?}",
            node.local().name
        );
        assert!(!node.members().iter().any(|m| m.name == "n7"));
    }
    // The survivors still agree on each other; any false suspicion along the way was refuted.
    let names: Vec<String> = (0..7).map(|i| format!("n{i}")).collect();
    wait_until("the survivors see each other alive", || {
        survivors.iter().all(|c| sees_alive(c, &names))
    })
    .await;
    close_all(survivors).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_node_that_leaves_is_never_reported_dead() {
    let nodes = start(6, config).await;
    let (leaver, stayers) = nodes.split_last().unwrap();
    let mut events: Vec<Events> = stayers.iter().map(Cluster::events).collect();

    bounded("leave", leaver.leave(Duration::from_secs(5)))
        .await
        .unwrap();
    bounded("close", leaver.close()).await;
    wait_until("every node sees n5 as left", || {
        stayers
            .iter()
            .all(|c| c.member("n5").is_some_and(|m| m.state == State::Left))
    })
    .await;
    // Longer than the longest suspicion timeout, so a death would have been declared by now.
    let cfg = config(0);
    let core = cfg.core();
    sleep(core.probe_interval * core.suspicion_mult * core.suspicion_max_mult * 2).await;

    for (node, events) in stayers.iter().zip(&mut events) {
        let events = drain(events);
        let n5: Vec<&Event> = about(&events, "n5").collect();
        assert!(
            n5.iter().any(|e| matches!(e, Event::MemberLeft(_))),
            "{} saw {n5:?}",
            node.local().name
        );
        assert!(
            !n5.iter().any(|e| matches!(e, Event::MemberDead(_))),
            "{} reported n5 dead: {n5:?}",
            node.local().name
        );
        assert_eq!(node.member("n5").unwrap().state, State::Left);
        assert_eq!(node.members().len(), 5);
    }
    close_all(stayers).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn metadata_reaches_every_node_encrypted() {
    let key = Key::from_bytes([42; 32]);
    let nodes = start(5, |i| config(i).with_keys([key.clone()])).await;
    let mut events: Vec<Events> = nodes.iter().map(Cluster::events).collect();

    bounded("set_meta", nodes[2].set_meta(b"role=db".to_vec()))
        .await
        .unwrap();
    assert_eq!(nodes[2].local().meta, b"role=db", "visible locally at once");
    wait_until("every node sees n2's metadata", || {
        nodes
            .iter()
            .all(|c| c.member("n2").is_some_and(|m| m.meta == b"role=db"))
    })
    .await;
    for (i, events) in events.iter_mut().enumerate() {
        let events = drain(events);
        let updated = about(&events, "n2").any(|e| {
            matches!(e, Event::MemberUpdated { member, previous_meta }
                if member.meta == b"role=db" && previous_meta.is_empty())
        });
        assert_eq!(updated, i != 2, "n{i}: {events:?}");
    }
    for node in &nodes {
        let stats = node.stats().metrics;
        assert_eq!(stats.decrypt_failures, 0);
        assert!(stats.packets_received > 0);
    }
    close_all(&nodes).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn clusters_with_different_keys_ignore_each_other() {
    let a = config(0).with_keys([Key::from_bytes([1; 32])]);
    let a = bounded("start a", Cluster::start(a)).await.unwrap();
    let b = config(1)
        .with_keys([Key::from_bytes([2; 32])])
        .with_join_retries(1);
    let b = bounded("start b", Cluster::start(b)).await.unwrap();
    let joined = bounded("join", b.join([a.local().addr])).await;
    assert!(
        matches!(joined, Err(kinship::Error::JoinFailed)),
        "{joined:?}"
    );
    assert_eq!(a.members().len(), 1);
    assert_eq!(b.members().len(), 1);
    wait_until("a counts b's packets as decrypt failures", || {
        a.stats().metrics.decrypt_failures > 0
    })
    .await;
    close_all(&[a, b]).await;
}

#[tokio::test]
async fn a_node_alone_rejoins_its_seeds_in_the_background() {
    let net = MemNetwork::new();
    let addr = |port| SocketAddr::from(([10, 0, 0, port], 7946));
    let fast = |i: usize| {
        config(i)
            .with_rejoin_interval(Duration::from_millis(300))
            .with_join_retries(1)
    };
    // The seed does not exist yet: the startup join fails, and b starts alone.
    let b = fast(1).with_seeds([addr(1)]);
    let b = Cluster::start_with(b, net.bind(addr(2)).unwrap());
    let b = bounded("start b", b).await.unwrap();
    assert_eq!(b.members().len(), 1);

    let a = Cluster::start_with(fast(0), net.bind(addr(1)).unwrap());
    let a = bounded("start a", a).await.unwrap();
    let names = ["n0".to_owned(), "n1".to_owned()];
    wait_until("b rejoins through its seed", || {
        sees_alive(&a, &names) && sees_alive(&b, &names)
    })
    .await;
    close_all(&[a, b]).await;
}

#[tokio::test]
async fn a_seed_that_is_not_a_member_is_rejoined() {
    let net = MemNetwork::new();
    let addr = |port| SocketAddr::from(([10, 0, 0, port], 7946));
    let fast = |i: usize| {
        config(i)
            .with_rejoin_interval(Duration::from_millis(300))
            .with_join_retries(1)
    };
    let b = Cluster::start_with(fast(1), net.bind(addr(2)).unwrap());
    let b = bounded("start b", b).await.unwrap();
    // c's seeds are a, which does not exist yet, and b: its startup join reaches only b.
    let c = fast(2).with_seeds([addr(1), addr(2)]);
    let c = Cluster::start_with(c, net.bind(addr(3)).unwrap());
    let c = bounded("start c", c).await.unwrap();
    let pair = ["n1".to_owned(), "n2".to_owned()];
    wait_until("c joins b", || {
        sees_alive(&b, &pair) && sees_alive(&c, &pair)
    })
    .await;

    // a has no seeds of its own, and c is not alone: only c's rejoin of a missing seed can
    // bring a in.
    let a = Cluster::start_with(fast(0), net.bind(addr(1)).unwrap());
    let a = bounded("start a", a).await.unwrap();
    let names = ["n0".to_owned(), "n1".to_owned(), "n2".to_owned()];
    wait_until("c rejoins its seed a", || {
        [&a, &b, &c].iter().all(|n| sees_alive(n, &names))
    })
    .await;
    close_all(&[a, b, c]).await;
}

#[tokio::test]
async fn calls_after_close_fail_and_event_streams_end() {
    let node = bounded("start", Cluster::start(config(0))).await.unwrap();
    let mut events = node.events();
    bounded("close", node.close()).await;
    assert!(node.is_closed());
    assert_eq!(bounded("recv", events.recv()).await, None);
    let err = node.set_meta(b"x".to_vec()).await.unwrap_err();
    assert!(matches!(err, kinship::Error::Closed), "{err:?}");
    assert_eq!(node.events().recv().await, None);
    bounded("close again", node.close()).await;
}
