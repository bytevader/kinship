//! The keyring commands on a core node: each refusal, and what a successful change does to the
//! bytes the node sends and accepts.

use std::net::SocketAddr;

use kinship_core::{
    Command, CommandError, CommandId, CommandOutput, Config, Event, Identity, Instant, Key, KeyId,
    Node, Security, Transmit,
};

fn addr(i: u8) -> SocketAddr {
    SocketAddr::from(([10, 0, 0, i], 7946))
}

fn key(n: u8) -> Key {
    Key::from_bytes([n; 32])
}

fn node(security: Security, seed: u64) -> Node {
    let me = Identity::new("a", addr(1)).unwrap();
    let mut node = Node::new(
        Config::lan(security),
        me,
        Instant::ZERO,
        seed,
        &[seed as u8; 32],
    )
    .unwrap();
    node.add_member(Instant::ZERO, "b", addr(2)).unwrap();
    while node.poll_event().is_some() {}
    node
}

fn encrypted(keys: &[u8]) -> Node {
    node(Security::Keys(keys.iter().map(|&n| key(n)).collect()), 1)
}

/// Runs `cmd` and returns its result, which keyring commands report at once.
fn run(n: &mut Node, cmd: Command) -> Result<CommandOutput, CommandError> {
    let id = n.command(Instant::ZERO, cmd);
    let mut result = None;
    while let Some(e) = n.poll_event() {
        if let Event::CommandDone { id: got, result: r } = e {
            assert_eq!(got, id);
            result = Some(r);
        }
    }
    result.expect("a keyring command completes at once")
}

fn ids(n: &Node, keys: &[u8]) -> bool {
    n.key_ids()
        == keys
            .iter()
            .map(|&k| key(k).key_id())
            .collect::<Vec<KeyId>>()
}

/// The first datagram the node sends once its gossip timer fires.
fn first_datagram(n: &mut Node) -> Vec<u8> {
    n.handle_timeout(Instant::from_nanos(60_000_000_000));
    std::iter::from_fn(|| n.poll_transmit())
        .find_map(|t| match t {
            Transmit::Datagram { payload, .. } => Some(payload),
            _ => None,
        })
        .expect("the node sends a datagram")
}

#[test]
fn install_use_remove_walk_a_node_to_a_new_key() {
    let mut n = encrypted(&[1]);
    assert_eq!(
        run(&mut n, Command::InstallKey(key(2))),
        Ok(CommandOutput::Done)
    );
    assert!(ids(&n, &[1, 2]));
    assert_eq!(
        run(&mut n, Command::UseKey(key(2))),
        Ok(CommandOutput::Done)
    );
    assert!(ids(&n, &[2, 1]));
    assert_eq!(
        run(&mut n, Command::RemoveKey(key(1))),
        Ok(CommandOutput::Done)
    );
    assert!(ids(&n, &[2]));
}

#[test]
fn install_twice_does_nothing() {
    let mut n = encrypted(&[1]);
    for k in [2, 2, 1] {
        assert_eq!(
            run(&mut n, Command::InstallKey(key(k))),
            Ok(CommandOutput::Done)
        );
    }
    assert!(ids(&n, &[1, 2]));
}

#[test]
fn use_refuses_a_key_that_is_not_installed() {
    let mut n = encrypted(&[1]);
    assert_eq!(
        run(&mut n, Command::UseKey(key(2))),
        Err(CommandError::KeyNotInstalled)
    );
    assert!(ids(&n, &[1]));
}

#[test]
fn remove_refuses_the_key_in_use() {
    let mut n = encrypted(&[1, 2]);
    assert_eq!(
        run(&mut n, Command::RemoveKey(key(1))),
        Err(CommandError::KeyInUse)
    );
    assert!(ids(&n, &[1, 2]));
}

#[test]
fn remove_refuses_the_last_key() {
    let mut n = encrypted(&[1]);
    assert_eq!(
        run(&mut n, Command::RemoveKey(key(1))),
        Err(CommandError::LastKey)
    );
    assert!(ids(&n, &[1]));
}

#[test]
fn remove_of_a_key_that_is_not_installed_does_nothing() {
    let mut n = encrypted(&[1]);
    assert_eq!(
        run(&mut n, Command::RemoveKey(key(9))),
        Ok(CommandOutput::Done)
    );
    assert!(ids(&n, &[1]));
}

#[test]
fn a_plaintext_node_refuses_all_of_it() {
    let mut n = node(Security::InsecurePlaintext, 1);
    for cmd in [
        Command::InstallKey(key(1)),
        Command::UseKey(key(1)),
        Command::RemoveKey(key(1)),
    ] {
        assert_eq!(run(&mut n, cmd), Err(CommandError::NotEncrypted));
    }
    assert!(n.key_ids().is_empty());
}

#[test]
fn a_node_seals_with_the_key_in_use_and_opens_with_any_installed_key() {
    // Same seed, same inputs, so the bytes differ only by the key.
    let mut plain = encrypted(&[1]);
    let mut installed = encrypted(&[1]);
    run(&mut installed, Command::InstallKey(key(2))).unwrap();
    assert_eq!(
        first_datagram(&mut plain),
        first_datagram(&mut installed),
        "installing a key does not change what the node sends"
    );

    let mut old = encrypted(&[1]);
    let mut rotated = encrypted(&[1]);
    run(&mut rotated, Command::InstallKey(key(2))).unwrap();
    run(&mut rotated, Command::UseKey(key(2))).unwrap();
    let old_bytes = first_datagram(&mut old);
    let new_bytes = first_datagram(&mut rotated);
    assert_ne!(old_bytes, new_bytes);
    assert_eq!(new_bytes[4..8], key(2).id().to_be_bytes());

    // A node holding only the old key counts the new key's packets as decrypt failures; once
    // it installs the new key it reads them.
    let mut behind = encrypted(&[1]);
    behind.handle_datagram(Instant::ZERO, addr(9), &new_bytes);
    assert_eq!(behind.metrics().decrypt_failures, 1);
    assert_eq!(behind.metrics().packets_received, 0);
    run(&mut behind, Command::InstallKey(key(2))).unwrap();
    behind.handle_datagram(Instant::ZERO, addr(9), &new_bytes);
    assert_eq!(behind.metrics().packets_received, 1);
}

#[test]
fn rotation_is_deterministic() {
    let walk = |seed| {
        let mut n = node(Security::Keys(vec![key(1)]), seed);
        run(&mut n, Command::InstallKey(key(2))).unwrap();
        run(&mut n, Command::UseKey(key(2))).unwrap();
        first_datagram(&mut n)
    };
    assert_eq!(walk(7), walk(7));
}

#[test]
fn command_ids_keep_counting() {
    let mut n = encrypted(&[1]);
    let a: CommandId = n.command(Instant::ZERO, Command::InstallKey(key(2)));
    let b = n.command(Instant::ZERO, Command::UseKey(key(2)));
    assert_ne!(a, b);
}
