//! Key rotation and a timed-out leave, on real nodes over localhost sockets.
//!
//! Every wait is bounded, so a regression fails with a message instead of hanging CI.

use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use kinship::{Cluster, Config, Error, Event, Events, Key, State};
use tokio::time::{Instant, sleep, timeout};

/// Upper bound on any single wait. Generous, because CI machines are slow and shared.
const WAIT: Duration = Duration::from_secs(30);

/// Time for packets sealed before a rotation step to arrive before the next step starts.
const SETTLE: Duration = Duration::from_millis(400);

/// Far too short for the news to spread. A ten-node cluster sends a rumour 8 times, to 3 members
/// at each 200 ms gossip tick, so a leave takes at least two ticks however coarse the timer is.
const TOO_SHORT: Duration = Duration::from_millis(1);

fn config(i: usize) -> Config {
    Config::local()
        .with_bind(SocketAddr::from(([127, 0, 0, 1], 0)))
        .with_name(format!("n{i}"))
}

fn key(n: u8) -> Key {
    Key::from_bytes([n; 32])
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
        nodes.push(bounded("start", Cluster::start(cfg)).await.unwrap());
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

fn ids_of(node: &Cluster) -> Vec<String> {
    node.keyring()
        .key_ids()
        .iter()
        .map(ToString::to_string)
        .collect()
}

fn ids(keys: &[Key]) -> Vec<String> {
    keys.iter().map(|k| k.key_id().to_string()).collect()
}

/// Waits until every node holds exactly `want`, in order.
async fn all_hold(nodes: &[Cluster], want: &[String], when: &str) {
    wait_until(when, || nodes.iter().all(|n| ids_of(n) == want)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rotating_a_cluster_keeps_every_node_alive() {
    let (old, new) = (key(1), key(2));
    let nodes = start(5, |i| config(i).with_keys([old.clone()])).await;
    let mut events: Vec<Events> = nodes.iter().map(Cluster::events).collect();
    let names: Vec<String> = (0..5).map(|i| format!("n{i}")).collect();
    for node in &nodes {
        assert_eq!(ids_of(node), ids(std::slice::from_ref(&old)));
        assert_eq!(
            ids_of(node)[0].len(),
            8,
            "key ids print as 8 hex characters"
        );
    }

    // Each step finishes on every node before the next starts.
    for node in &nodes {
        bounded("install", node.keyring().install(new.clone()))
            .await
            .unwrap();
    }
    all_hold(&nodes, &ids(&[old.clone(), new.clone()]), "install lands").await;
    sleep(SETTLE).await;
    for node in &nodes {
        bounded("use", node.keyring().use_key(new.clone()))
            .await
            .unwrap();
    }
    all_hold(&nodes, &ids(&[new.clone(), old.clone()]), "use lands").await;
    sleep(SETTLE).await;
    for node in &nodes {
        bounded("remove", node.keyring().remove(old.clone()))
            .await
            .unwrap();
    }
    all_hold(&nodes, &ids(std::slice::from_ref(&new)), "remove lands").await;

    // Several probe rounds on the new key alone.
    let probe = nodes[0].stats().metrics.probes_sent;
    wait_until("every node probes on the new key", || {
        nodes
            .iter()
            .all(|n| n.stats().metrics.probes_sent >= probe + 5)
    })
    .await;
    for (node, events) in nodes.iter().zip(&mut events) {
        let events = drain(events);
        let name = node.local().name;
        assert!(
            !events.iter().any(|e| matches!(e, Event::MemberDead(_))),
            "{name} saw a death during the rotation: {events:?}"
        );
        assert_eq!(node.stats().metrics.decrypt_failures, 0, "{name}");
        assert!(sees_alive(node, &names), "{name}");
    }

    // The old key is really gone: a node that only has it cannot join, and one with the new key
    // can.
    let seed = nodes[0].local().addr;
    let stale = config(8)
        .with_keys([old.clone()])
        .with_join_retries(1)
        .with_seeds([seed]);
    let stale = bounded("start stale", Cluster::start(stale)).await.unwrap();
    assert_eq!(
        stale.members().len(),
        1,
        "a node with only the old key stays alone"
    );
    let fresh = config(9).with_keys([new.clone()]).with_seeds([seed]);
    let fresh = bounded("start fresh", Cluster::start(fresh)).await.unwrap();
    wait_until("the new-key node joins", || fresh.members().len() == 6).await;
    close_all(&[stale, fresh]).await;
    close_all(&nodes).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn keyring_calls_refuse_what_they_must() {
    let (a, b) = (key(1), key(2));
    let node = Cluster::start(config(0).with_keys([a.clone()]))
        .await
        .unwrap();
    let ring = node.keyring();

    ring.install(b.clone()).await.unwrap();
    ring.install(b.clone()).await.unwrap();
    assert_eq!(ring.key_ids().len(), 2, "installing twice adds one key");
    let err = ring.use_key(key(3)).await.unwrap_err();
    assert!(matches!(err, Error::KeyNotInstalled), "{err:?}");
    let err = ring.remove(a.clone()).await.unwrap_err();
    assert!(matches!(err, Error::KeyInUse), "{err:?}");
    ring.use_key(b.clone()).await.unwrap();
    ring.remove(a.clone()).await.unwrap();
    let err = ring.remove(b.clone()).await.unwrap_err();
    assert!(matches!(err, Error::LastKey), "{err:?}");
    ring.remove(a).await.unwrap();
    assert_eq!(ring.key_ids(), [b.key_id()]);
    // The id prints as hex and the key bytes do not appear anywhere in the debug output.
    let shown = format!("{ring:?} {:?} {}", b, err);
    assert!(!shown.contains("0202"), "{shown}");
    close_all(&[node]).await;

    // A node without encryption has no keys to change.
    let plain = Cluster::start(config(1)).await.unwrap();
    let ring = plain.keyring();
    assert!(ring.key_ids().is_empty());
    for result in [
        ring.install(b.clone()).await,
        ring.use_key(b.clone()).await,
        ring.remove(b.clone()).await,
    ] {
        assert!(matches!(result, Err(Error::NotEncrypted)), "{result:?}");
    }
    close_all(&[plain]).await;

    // After close the handle fails instead of hanging.
    let err = ring.install(b).await.unwrap_err();
    assert!(matches!(err, Error::Closed), "{err:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_leave_that_times_out_still_leaves() {
    let nodes = start(10, config).await;
    let (leaver, stayers) = nodes.split_last().unwrap();
    let mut events: Vec<Events> = stayers.iter().map(Cluster::events).collect();

    // Far too short for the rumour to be sent as often as any rumour is.
    let err = leaver.leave(TOO_SHORT).await.unwrap_err();
    assert!(matches!(err, Error::Timeout), "{err:?}");

    // The node has left anyway: it says so, refuses to change, and stops probing.
    wait_until("the leaver is Left", || leaver.local().state == State::Left).await;
    let err = leaver.set_meta(b"too late".to_vec()).await.unwrap_err();
    assert!(matches!(err, Error::Left), "{err:?}");
    let left = leaver.stats();
    let incarnation = leaver.local().incarnation;
    sleep(Duration::from_millis(800)).await;
    let later = leaver.stats();
    assert_eq!(
        later.metrics.probes_sent, left.metrics.probes_sent,
        "it probes no more"
    );
    assert_eq!(later.metrics.refutations, left.metrics.refutations);
    assert_eq!(leaver.local().incarnation, incarnation, "it never refutes");

    bounded("close", leaver.close()).await;
    wait_until("every peer sees n9 as left", || {
        stayers
            .iter()
            .all(|c| c.member("n9").is_some_and(|m| m.state == State::Left))
    })
    .await;
    // Longer than the longest suspicion timeout, so a death would have been declared by now.
    let cfg = config(0);
    let core = cfg.core();
    sleep(core.probe_interval * core.suspicion_mult * core.suspicion_max_mult * 2).await;

    for (node, events) in stayers.iter().zip(&mut events) {
        let events = drain(events);
        let name = node.local().name;
        assert!(
            events
                .iter()
                .any(|e| matches!(e, Event::MemberLeft(m) if m.name == "n9")),
            "{name} never saw n9 leave: {events:?}"
        );
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, Event::MemberDead(m) if m.name == "n9")),
            "{name} reported n9 dead: {events:?}"
        );
        assert_eq!(node.member("n9").unwrap().state, State::Left);
        assert_eq!(node.members().len(), 9, "{name}");
    }
    close_all(stayers).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn closing_right_after_a_timed_out_leave_is_still_a_leave() {
    let nodes = start(10, config).await;
    let (leaver, stayers) = nodes.split_last().unwrap();
    let mut events: Vec<Events> = stayers.iter().map(Cluster::events).collect();

    // No time passes between the failed leave and the close, so only the news that left with the
    // leave itself can tell the peers. They pass it on to each other.
    let err = leaver.leave(TOO_SHORT).await.unwrap_err();
    assert!(matches!(err, Error::Timeout), "{err:?}");
    bounded("close", leaver.close()).await;

    wait_until("every peer sees n9 as left", || {
        stayers
            .iter()
            .all(|c| c.member("n9").is_some_and(|m| m.state == State::Left))
    })
    .await;
    let cfg = config(0);
    let core = cfg.core();
    sleep(core.probe_interval * core.suspicion_mult * core.suspicion_max_mult * 2).await;
    for (node, events) in stayers.iter().zip(&mut events) {
        let events = drain(events);
        let name = node.local().name;
        assert!(
            !events
                .iter()
                .any(|e| matches!(e, Event::MemberDead(m) if m.name == "n9")),
            "{name} reported n9 dead: {events:?}"
        );
        assert_eq!(node.member("n9").unwrap().state, State::Left, "{name}");
    }
    close_all(stayers).await;
}
