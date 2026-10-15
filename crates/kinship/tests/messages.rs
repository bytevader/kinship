//! User messages between real nodes on localhost: direct messages over UDP and TCP, broadcasts,
//! and the sends a node refuses.
//!
//! Every wait is bounded, so a regression fails with a message instead of hanging CI.

use std::future::Future;
use std::net::SocketAddr;
use std::time::Duration;

use kinship::{Cluster, Config, Error, Event, Events, Member, State, generate_key};
use tokio::time::{Instant, sleep, timeout};

/// Upper bound on any single wait. Generous, because CI machines are slow and shared.
const WAIT: Duration = Duration::from_secs(30);

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

/// Starts `n` encrypted nodes on loopback, each joining through the first, and waits until
/// every node sees every other one alive.
async fn start(n: usize) -> Vec<Cluster> {
    let key = generate_key().unwrap();
    let config = |i: usize| {
        Config::local()
            .with_bind(SocketAddr::from(([127, 0, 0, 1], 0)))
            .with_name(format!("n{i}"))
            .with_keys([key.clone()])
    };
    let first = bounded("start n0", Cluster::start(config(0)))
        .await
        .unwrap();
    let seed = first.local().addr;
    let mut nodes = vec![first];
    for i in 1..n {
        let node = bounded("start", Cluster::start(config(i).with_seeds([seed])))
            .await
            .unwrap();
        nodes.push(node);
    }
    wait_until("every node sees every other alive", || {
        nodes.iter().all(|c| {
            let members = c.members();
            members.len() == n && members.iter().all(|m| m.state == State::Alive)
        })
    })
    .await;
    nodes
}

async fn close_all(nodes: &[Cluster]) {
    for node in nodes {
        bounded("close", node.close()).await;
    }
}

/// The next user message on `events`, skipping membership events.
async fn next_message(events: &mut Events) -> (Member, Vec<u8>, bool) {
    loop {
        match bounded("a user message", events.recv()).await {
            Some(Event::UserMessage {
                sender,
                data,
                broadcast,
            }) => return (sender, data, broadcast),
            Some(_) => {}
            None => panic!("the node closed"),
        }
    }
}

fn messages(events: &mut Events) -> Vec<Vec<u8>> {
    std::iter::from_fn(|| events.try_recv())
        .filter_map(|e| match e {
            Event::UserMessage { data, .. } => Some(data),
            _ => None,
        })
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn members_send_small_and_large_messages_and_broadcasts() {
    let nodes = start(3).await;
    let mut events: Vec<Events> = nodes.iter().map(Cluster::events).collect();
    let n1 = nodes[0].member("n1").unwrap();

    // Small enough for a datagram.
    bounded("send", nodes[0].send(&n1, b"hello".to_vec()))
        .await
        .unwrap();
    let (sender, data, broadcast) = next_message(&mut events[1]).await;
    assert_eq!(
        (sender.name.as_str(), &data[..], broadcast),
        ("n0", &b"hello"[..], false)
    );
    assert_eq!(sender.epoch, nodes[0].local().epoch);

    // Too large for one: it goes over TCP, whole.
    let big: Vec<u8> = (0..20_000u32).map(|i| (i % 251) as u8).collect();
    bounded("send", nodes[0].send_to("n2", big.clone()))
        .await
        .unwrap();
    let (sender, data, broadcast) = next_message(&mut events[2]).await;
    assert_eq!((sender.name.as_str(), broadcast), ("n0", false));
    assert_eq!(data, big);

    // A broadcast reaches every other node once, and not its sender.
    bounded("broadcast", nodes[1].broadcast(b"drop user:42".to_vec()))
        .await
        .unwrap();
    for i in [0, 2] {
        let (sender, data, broadcast) = next_message(&mut events[i]).await;
        assert_eq!(
            (sender.name.as_str(), &data[..], broadcast),
            ("n1", &b"drop user:42"[..], true)
        );
    }
    // Long enough for every copy of it to have been sent.
    sleep(Duration::from_secs(2)).await;
    for e in &mut events {
        assert_eq!(messages(e), Vec::<Vec<u8>>::new(), "no copies");
    }
    let sent = nodes[0].stats().metrics;
    assert_eq!(sent.user_messages_sent, 2);
    let got: u64 = nodes
        .iter()
        .map(|n| n.stats().metrics.user_messages_received)
        .sum();
    assert_eq!(got, 4);
    for node in &nodes {
        let m = node.stats().metrics;
        assert_eq!((m.decode_errors, m.user_messages_dropped), (0, 0));
    }
    close_all(&nodes).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sends_to_strangers_old_runs_and_oversized_data_are_refused() {
    let nodes = start(2).await;
    let n1 = nodes[0].member("n1").unwrap();
    let send = |m: Member, data: Vec<u8>| {
        let node = &nodes[0];
        async move { node.send(&m, data).await }
    };
    let stranger = Member {
        name: "nobody".to_owned(),
        ..n1.clone()
    };
    assert!(matches!(
        send(stranger, vec![1]).await,
        Err(Error::NotAMember)
    ));
    let earlier = Member {
        epoch: n1.epoch - 1,
        ..n1.clone()
    };
    assert!(matches!(
        send(earlier, vec![1]).await,
        Err(Error::NotAMember)
    ));
    assert!(matches!(
        send(nodes[0].local(), vec![1]).await,
        Err(Error::NotAMember)
    ));
    let max = Config::local().core().max_user_message;
    assert!(matches!(
        send(n1.clone(), vec![0; max + 1]).await,
        Err(Error::MessageTooLarge)
    ));
    let max = Config::local().core().max_user_broadcast;
    assert!(matches!(
        nodes[0].broadcast(vec![0; max + 1]).await,
        Err(Error::MessageTooLarge)
    ));
    // Command replies can wake the caller before the actor publishes its stats.
    wait_until("both oversized messages are counted", || {
        nodes[0].stats().metrics.user_messages_too_large == 2
    })
    .await;
    // A member's own Member value, epoch included, is a valid recipient.
    assert!(send(n1, vec![1]).await.is_ok());
    // A node that left sends nothing more.
    let _ = bounded("leave", nodes[0].leave(Duration::from_secs(5))).await;
    assert!(matches!(
        nodes[0].broadcast(vec![1]).await,
        Err(Error::Left)
    ));
    close_all(&nodes).await;
}
