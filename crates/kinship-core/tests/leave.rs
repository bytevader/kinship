//! A node that leaves tells members at once, without waiting for the next gossip tick.

use std::net::SocketAddr;

use kinship_core::{Command, Config, Identity, Instant, Node, Security, Transmit};

fn addr(i: u8) -> SocketAddr {
    SocketAddr::from(([10, 0, 0, i], 7946))
}

#[test]
fn leave_sends_the_news_before_any_timer_fires() {
    let me = Identity::new("a", addr(1)).unwrap();
    let mut node = Node::new(
        Config::lan(Security::InsecurePlaintext),
        me,
        Instant::ZERO,
        1,
    )
    .unwrap();
    for i in 2..7u8 {
        node.add_member(Instant::ZERO, &format!("m{i}"), addr(i))
            .unwrap();
    }
    while node.poll_transmit().is_some() {}

    node.command(Instant::ZERO, Command::Leave);

    let sent: Vec<SocketAddr> = std::iter::from_fn(|| node.poll_transmit())
        .filter_map(|t| match t {
            Transmit::Datagram { to, .. } => Some(to),
            _ => None,
        })
        .collect();
    assert_eq!(
        sent.len(),
        node.config().gossip_nodes,
        "the Left rumour goes to gossip_nodes members at once"
    );
}
