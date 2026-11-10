//! `docs/stability.md` as a test of the facade: every name the crate's root promises, with the
//! types it promises them with, and every default in `docs/design.md`, Configuration surface.
//! Tests build as a crate of their own, so they see the API as an application does, and a change
//! that breaks a 1.x application stops this file compiling or passing.

use std::net::SocketAddr;
use std::time::Duration;

use kinship::{
    Cluster, Config, ConfigError, DEFAULT_PORT, Error, Event, Events, Key, KeyError, KeyId,
    Keyring, Member, Metrics, Seed, SeedError, State, Stats, WIRE_VERSION, generate_key,
};

/// Every method of `Cluster`, `Events` and `Keyring`, with its types. Never run: it only has to
/// compile.
#[allow(dead_code)]
async fn cluster_surface(cfg: Config, member: &Member, key: Key, seed: Seed) -> Result<(), Error> {
    let cluster: Cluster = Cluster::start(cfg).await?;
    let addr: SocketAddr = cluster.local_addr();
    let _: usize = cluster.join([addr]).await?;
    let _: usize = cluster.join_seeds([seed]).await?;
    let _: Vec<Member> = cluster.members();
    let _: Option<Member> = cluster.member("a");
    let _: Member = cluster.local();
    let mut events: Events = cluster.events();
    let _: Option<Event> = events.recv().await;
    let _: Option<Event> = events.try_recv();
    let _: bool = events.is_closed();
    cluster.set_meta(b"role=cache".to_vec()).await?;
    cluster.send(member, b"data".to_vec()).await?;
    cluster.send_to("a", b"data".to_vec()).await?;
    cluster.broadcast(b"data".to_vec()).await?;
    let _: Stats = cluster.stats();
    let keyring: Keyring = cluster.keyring();
    keyring.install(key.clone()).await?;
    keyring.use_key(key.clone()).await?;
    keyring.remove(key).await?;
    let _: Vec<KeyId> = keyring.key_ids();
    cluster.leave(Duration::from_secs(5)).await?;
    cluster.close().await;
    cluster.abort();
    let _: bool = cluster.is_closed();
    Ok(())
}

/// Every event and its fields. A new event type arrives in a minor release, so the wildcard arm
/// is what the promise asks of an application.
#[allow(dead_code)]
fn read_event(event: Event) -> Option<Member> {
    match event {
        Event::MemberJoined(m)
        | Event::MemberSuspect(m)
        | Event::MemberRecovered(m)
        | Event::MemberDead(m)
        | Event::MemberLeft(m) => Some(m),
        Event::MemberUpdated {
            member,
            previous_meta,
        } => {
            let _: Vec<u8> = previous_meta;
            Some(member)
        }
        Event::NameConflict { member, other_addr } => {
            let _: SocketAddr = other_addr;
            Some(member)
        }
        Event::UserMessage {
            sender,
            data,
            broadcast,
        } => {
            let _: (Vec<u8>, bool) = (data, broadcast);
            Some(sender)
        }
        Event::EventsLost(count) => {
            let _: u64 = count;
            None
        }
        _ => None,
    }
}

/// Every error, with the wildcard arm a new one needs.
#[allow(dead_code)]
fn read_error(error: Error) -> &'static str {
    match error {
        Error::Config(ConfigError { field, .. }) => field,
        Error::Io(_) => "io",
        Error::JoinFailed => "join failed",
        Error::Unresolved => "unresolved",
        Error::MetaTooLarge => "meta too large",
        Error::MessageTooLarge => "message too large",
        Error::NotAMember => "not a member",
        Error::Left => "left",
        Error::Timeout => "timeout",
        Error::Closed => "closed",
        Error::NotEncrypted => "not encrypted",
        Error::KeyNotInstalled => "key not installed",
        Error::KeyInUse => "key in use",
        Error::LastKey => "last key",
        _ => "other",
    }
}

/// No wildcard arm: `State` keeps its four values.
#[allow(dead_code)]
fn read_state(state: State) -> u8 {
    match state {
        State::Alive => 0,
        State::Suspect => 1,
        State::Dead => 2,
        State::Left => 3,
    }
}

/// Every field of `Member`. It is `#[non_exhaustive]` and may gain fields in a minor release, so
/// an application reads members, clones them and changes a clone, but cannot build one with a
/// struct expression or `..` update; kinship-core's `Member` docs hold a test that it cannot.
#[allow(dead_code)]
fn read_member(member: &Member) -> (&str, SocketAddr, &[u8], State, u32, u64) {
    (
        member.name.as_str(),
        member.addr,
        member.meta.as_slice(),
        member.state,
        member.incarnation,
        member.epoch,
    )
}

#[allow(dead_code)]
fn edit_a_clone(member: &Member) -> Member {
    let mut other = member.clone();
    other.name = "b".to_owned();
    other.epoch += 1;
    other
}

#[allow(dead_code)]
fn read_seed(seed: &Seed) -> Option<(&str, u16)> {
    match seed {
        Seed::Addr(_) => None,
        Seed::Host { name, port } => Some((name.as_str(), *port)),
        _ => None,
    }
}

#[test]
fn the_constants_keep_their_values() {
    assert_eq!(DEFAULT_PORT, 7946);
    assert_eq!(WIRE_VERSION, 1);
}

#[test]
fn stats_keep_every_counter() {
    let stats = Stats::default();
    let _: u32 = stats.local_health;
    let m: Metrics = stats.metrics;
    let counters: [u64; 26] = [
        m.packets_received,
        m.decode_errors,
        m.decrypt_failures,
        m.replays_dropped,
        m.probes_sent,
        m.probes_failed,
        m.indirect_probes,
        m.missed_nacks,
        m.suspicions,
        m.refutations,
        m.misdirected,
        m.name_conflicts,
        m.restarts,
        m.members_refused,
        m.push_pulls,
        m.push_pull_failures,
        m.push_pulls_served,
        m.state_too_large,
        m.gossip_too_large,
        m.tcp_pings,
        m.tcp_ping_acks,
        m.user_messages_sent,
        m.user_messages_received,
        m.user_messages_dropped,
        m.user_messages_too_large,
        m.user_queue_overflow,
    ];
    assert_eq!(counters, [0; 26]);
}

#[test]
fn keys_and_seeds_parse_as_they_did() {
    let key: Key = generate_key().unwrap();
    assert_eq!(Key::from_base64(&key.to_base64()).unwrap(), key);
    assert_eq!(key.to_base64().len(), 44, "32 bytes as padded base64");
    let _: KeyId = key.key_id();
    assert_eq!(Key::from_base64("!"), Err(KeyError::NotBase64));
    assert_eq!(Key::from_base64("AAAA"), Err(KeyError::WrongLength));

    let name: Seed = "node-1:7946".parse().unwrap();
    assert_eq!(read_seed(&name), Some(("node-1", 7946)));
    let ip: Seed = "10.0.0.5:7946".parse().unwrap();
    assert_eq!(ip, Seed::Addr("10.0.0.5:7946".parse().unwrap()));
    let refused: Result<Seed, SeedError> = "node-1".parse();
    assert!(refused.is_err(), "the port is required");
}

#[test]
fn every_setter_keeps_its_name_and_type() {
    let d = Duration::from_secs(1);
    let cfg = Config::default()
        .with_name("a")
        .with_bind("127.0.0.1:0".parse().unwrap())
        .with_advertise("127.0.0.1:7946".parse().unwrap())
        .with_cluster("c")
        .with_meta(b"role=cache".to_vec())
        .with_seeds(["127.0.0.1:7946".parse().unwrap()])
        .with_seed_hosts(["node-1:7946".parse().unwrap()])
        .with_resolve_timeout(d)
        .with_keys([Key::from_bytes([7; 32])])
        .with_insecure_plaintext(false)
        .with_max_inbound_streams(64)
        .with_max_inbound_streams_per_ip(16)
        .with_max_inbound_bytes_per_ip(8 * 1024 * 1024 + 4)
        .with_tcp_header_timeout(d)
        .with_event_buffer(1024)
        .with_probe_interval(d)
        .with_probe_timeout(d / 2)
        .with_indirect_checks(3)
        .with_tcp_fallback_ping(true)
        .with_suspicion_mult(4)
        .with_suspicion_max_mult(6)
        .with_expected_confirmations(3)
        .with_awareness_max(8)
        .with_local_health(true)
        .with_nacks(true)
        .with_dynamic_suspicion(true)
        .with_buddy_system(true)
        .with_dead_reclaim(d * 30)
        .with_gossip_interval(d / 5)
        .with_gossip_nodes(3)
        .with_gossip_to_the_dead(d * 30)
        .with_retransmit_mult(4)
        .with_push_pull_interval(d * 30)
        .with_push_pull_scale(false)
        .with_push_pull_digest(true)
        .with_reconnect_interval(d * 30)
        .with_rejoin_interval(d * 60)
        .with_tcp_timeout(d * 10)
        .with_join_retries(3)
        .with_max_members(8_192)
        .with_max_new_members_per_packet(1_024)
        .with_max_user_message(64 * 1024)
        .with_max_user_broadcast(256)
        .with_user_broadcast_queue(256)
        .with_udp_max_payload(1_400)
        .with_max_stream_frame(8 * 1024 * 1024)
        .with_max_meta_bytes(512);
    assert_eq!(cfg.name(), Some("a"));
    assert_eq!(cfg.bind(), "127.0.0.1:0".parse().unwrap());
    assert_eq!(cfg.seeds().len(), 1);
    assert_eq!(cfg.seed_hosts().len(), 1);
    assert!(!cfg.without_lifeguard().core().local_health);
}

#[test]
fn lan_keeps_every_default_in_the_design_doc() {
    let cfg = Config::lan();
    assert_eq!(cfg.name(), None);
    assert_eq!(cfg.bind(), "0.0.0.0:7946".parse().unwrap());
    assert!(cfg.seeds().is_empty() && cfg.seed_hosts().is_empty());
    let c = cfg.core();
    let secs = Duration::from_secs;
    let ms = Duration::from_millis;
    assert_eq!(c.cluster, "default");
    assert_eq!(c.probe_interval, secs(1));
    assert_eq!(c.probe_timeout, ms(500));
    assert_eq!(c.indirect_checks, 3);
    assert!(c.tcp_fallback_ping);
    assert_eq!(c.suspicion_mult, 4);
    assert_eq!(c.suspicion_max_mult, 6);
    assert_eq!(c.expected_confirmations, 3);
    assert_eq!(c.awareness_max, 8);
    assert!(c.local_health && c.nacks && c.dynamic_suspicion && c.buddy_system);
    assert_eq!(c.dead_reclaim, secs(30));
    assert_eq!(c.gossip_interval, ms(200));
    assert_eq!(c.gossip_nodes, 3);
    assert_eq!(c.gossip_to_the_dead, secs(30));
    assert_eq!(c.retransmit_mult, 4);
    assert_eq!(c.push_pull_interval, secs(30));
    assert!(!c.push_pull_scale);
    assert!(c.push_pull_digest);
    assert_eq!(c.reconnect_interval, secs(30));
    assert_eq!(c.rejoin_interval, secs(60));
    assert_eq!(c.tcp_timeout, secs(10));
    assert_eq!(c.join_retries, 3);
    assert_eq!(c.max_members, 8_192);
    assert_eq!(c.max_new_members_per_packet, 1_024);
    assert_eq!(c.max_user_message, 64 * 1024);
    assert_eq!(c.max_user_broadcast, 256);
    assert_eq!(c.user_broadcast_queue, 256);
    assert_eq!(c.limits.udp_max_payload, 1_400);
    assert_eq!(c.limits.max_stream_frame, 8 * 1024 * 1024);
    assert_eq!(c.limits.max_meta_bytes, 512);
}

#[test]
fn wan_and_local_differ_from_lan_as_the_design_doc_says() {
    let secs = Duration::from_secs;
    let ms = Duration::from_millis;

    let wan = Config::wan();
    assert_eq!(wan.bind(), "0.0.0.0:7946".parse().unwrap());
    let c = wan.core();
    assert_eq!(c.probe_interval, secs(5));
    assert_eq!(c.probe_timeout, secs(3));
    assert_eq!(c.suspicion_mult, 6);
    assert_eq!(c.push_pull_interval, secs(60));
    assert_eq!(c.gossip_interval, ms(500));
    assert!(c.tcp_fallback_ping);

    let local = Config::local();
    assert_eq!(local.bind(), "127.0.0.1:7946".parse().unwrap());
    let c = local.core();
    assert_eq!(c.probe_interval, ms(200));
    assert_eq!(c.probe_timeout, ms(100));
    assert_eq!(c.suspicion_mult, 3);
    assert_eq!(c.push_pull_interval, secs(15));
    assert_eq!(c.gossip_interval, ms(200));
    assert!(!c.tcp_fallback_ping);

    // Nothing else differs.
    for cfg in [Config::wan(), Config::local()] {
        let c = cfg.core();
        let lan = Config::lan();
        let l = lan.core();
        assert_eq!(c.suspicion_max_mult, l.suspicion_max_mult);
        assert_eq!(c.dead_reclaim, l.dead_reclaim);
        assert_eq!(c.gossip_nodes, l.gossip_nodes);
        assert_eq!(c.reconnect_interval, l.reconnect_interval);
        assert_eq!(c.rejoin_interval, l.rejoin_interval);
        assert_eq!(c.tcp_timeout, l.tcp_timeout);
        assert_eq!(c.limits, l.limits);
    }
}
