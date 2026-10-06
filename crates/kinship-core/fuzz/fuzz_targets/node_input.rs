//! Feeds arbitrary datagrams, stream frames, stream ends and the passing of time to a node with
//! a few members, encrypted or not, and checks that it never panics, that its timers settle,
//! and that its metrics only ever count up.
//!
//! An input is a mode byte and then a list of operations, until the bytes run out:
//!
//! ```text
//! input = mode:u8 op*        mode bit 0: the node encrypts with key [7; 32], else plaintext
//! op    = code:u8 body       code & 7 picks the operation, code >> 3 is its argument s
//!   0, 5, 6, 7  a datagram:     len:u16be bytes
//!   1           a stream frame: len:u16be bytes, on stream s
//!   2           the peer closed stream s
//!   3           stream s failed
//!   4           s x 100 ms pass, and every timer due by then fires
//! ```
//!
//! Stream s is the node's inbound connection s for s below 16, else its outbound connection
//! s - 16; the node opens outbound 0 and 1 when it joins its first two members at the start.
//! The seed corpus is real traffic node n0 received in the simulator, captured with
//! `cargo run -p kinship-sim --example node_corpus`, so it opens under the same key and label.
#![no_main]

use std::net::SocketAddr;
use std::time::Duration;

use kinship_core::{Command, Config, Identity, Instant, Key, Node, Security, StreamEvent, StreamId};
use libfuzzer_sys::fuzz_target;

/// The simulator's address for node `i`, as in `kinship_sim::addr_of`.
fn addr(i: u8) -> SocketAddr {
    SocketAddr::from(([10, 0, 0, i], 7946))
}

/// Each counter, by name.
fn counters(node: &Node) -> Vec<(String, u64)> {
    let serde_json::Value::Object(map) = serde_json::to_value(node.metrics()).unwrap() else {
        unreachable!("metrics serialize as a map");
    };
    map.into_iter()
        .map(|(k, v)| (k, v.as_u64().expect("every metric is a count")))
        .collect()
}

/// Takes `n` bytes, or `None` if the input ends first.
fn take<'a>(data: &mut &'a [u8], n: usize) -> Option<&'a [u8]> {
    let (head, rest) = data.split_at_checked(n)?;
    *data = rest;
    Some(head)
}

fn body<'a>(data: &mut &'a [u8]) -> Option<&'a [u8]> {
    let len = take(data, 2)?;
    take(data, usize::from(u16::from_be_bytes([len[0], len[1]])))
}

fn stream(s: u8) -> StreamId {
    if s < 16 {
        StreamId::inbound(u64::from(s))
    } else {
        StreamId::outbound(u64::from(s - 16))
    }
}

fn drain(node: &mut Node) {
    while node.poll_transmit().is_some() {}
    while node.poll_event().is_some() {}
}

fuzz_target!(|data: &[u8]| {
    let Some((&mode, mut data)) = data.split_first() else {
        return;
    };
    let security = if mode & 1 == 1 {
        Security::Keys(vec![Key::from_bytes([7; 32])])
    } else {
        Security::InsecurePlaintext
    };
    let mut now = Instant::ZERO;
    let me = Identity::new("n0", addr(0)).unwrap();
    let mut node = Node::new(Config::lan(security), me, now, 0).unwrap();
    for i in 1..=3 {
        node.add_member(now, &format!("n{i}"), addr(i)).unwrap();
    }
    node.command(now, Command::Join { seeds: vec![addr(1), addr(2)] });
    drain(&mut node);

    let mut before = counters(&node);
    while let Some(&code) = data.first() {
        data = &data[1..];
        let s = code >> 3;
        match code & 7 {
            1 => {
                let Some(frame) = body(&mut data) else { break };
                node.handle_stream(now, stream(s), StreamEvent::Frame(frame));
            }
            2 => node.handle_stream(now, stream(s), StreamEvent::Closed),
            3 => node.handle_stream(now, stream(s), StreamEvent::Failed),
            4 => {
                now = now + Duration::from_millis(100) * u32::from(s);
                let mut fired = 0;
                while let Some(t) = node.poll_timeout().filter(|&t| t <= now) {
                    node.handle_timeout(t);
                    drain(&mut node);
                    fired += 1;
                    assert!(fired < 10_000, "timers due by {now:?} never settle");
                }
            }
            _ => {
                let Some(buf) = body(&mut data) else { break };
                node.handle_datagram(now, addr(1), buf);
            }
        }
        drain(&mut node);
        let after = counters(&node);
        for ((name, was), (_, is)) in before.iter().zip(&after) {
            assert!(is >= was, "{name} went from {was} to {is}");
        }
        before = after;
    }
});
