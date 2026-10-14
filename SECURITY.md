# Security

Report a vulnerability privately, through a GitHub security advisory on this repository, rather than in a public issue.

This file holds kinship's threat model and the findings of the security audit of 2026-10-07, which looked at kinship first as an attacker on the network who holds no key, then as a compromised member that does. Findings marked Fixed were fixed in the same change or since, each with a Fix paragraph and what remains; the rest are documented here with a reproduction and the fix we recommend. The architecture is in `docs/design.md` and the public API in `README.md`.

## Threat model

### What kinship protects

- **Membership integrity.** Which members are alive, suspect, dead or gone, their addresses and their metadata, as every node sees them.
- **Failure detection.** Live members stay members, and dead ones are declared dead within the Lifeguard timeouts.
- **Confidentiality of membership traffic.** Names, addresses, metadata and protocol state are encrypted on the wire.
- **The keys.** 32-byte XChaCha20-Poly1305 keys, which never leave the process, are never logged, and inside a node live only in its codec (KS-07).

### Attackers

1. **A network attacker without a key.** It shares a network with the cluster. It can see, record, drop, delay, reorder and inject UDP datagrams, spoof their source address, open TCP connections to any member, and replay anything it recorded, at any later time and to any member. It does not hold a cluster key.
2. **A compromised member.** It holds a valid key and the cluster label, so every packet it seals authenticates. It can send any message about any member, at any rate.

Other processes on the same host count as network attackers, except in plaintext mode on loopback, where they are trusted (KS-04).

### Guarantees against an attacker without a key

- It cannot read traffic or forge, alter or truncate a packet: every datagram and stream frame is sealed with XChaCha20-Poly1305 over the header and the cluster label, the tag is checked in constant time, and nothing is decrypted or parsed before it verifies.
- A recording is useless once it is older than the replay window (30 s, or twice `tcp_timeout` if that is longer), and a copy of a packet is useless at once (KS-01). Tombstones outlive the window, so no recording can bring back a member that left or died.
- No reply goes to an address it chooses: replies go to addresses inside authenticated messages, never to a datagram's source address. A packet that does not authenticate gets no reply at all, and a stale push-pull that does gets at most the answering node's own record.
- What it sends costs bounded work and memory: header checks before any cryptography, one tag verification whether or not an installed key has the packet's key id (one per such key in the rare case that several share an id), frame lengths checked from their prefix, and at most twice `max_stream_frame` held for unauthenticated stream frames across all connections (KS-02).
- From one address it cannot keep a node from serving others over TCP: it gets at most 16 of the node's inbound connections and one largest frame's worth of the inbound buffer, a new connection when all are taken displaces the address with the most, and a connection that does not start with a header for this node within a second is dropped (KS-03).

A compromised member is outside these guarantees: see "What kinship does not protect against".

### Severity

| Severity | Meaning |
| --- | --- |
| Critical | An attacker without a key reads traffic, forges messages, or takes over membership at will. |
| High | An attacker without a key changes what members believe (false deaths, phantom members) or exhausts a node's memory; or a member holding a key can do it to every node at once. |
| Medium | Lasting or amplified damage from a member holding a key, availability loss without a key that needs sustained effort, or a weakness in an opt-in insecure mode. |
| Low | Defence in depth: information leaks, hardening, and gaps that need another failure to matter. |

## Findings

| ID | Severity | Attacker | Finding | Status |
| --- | --- | --- | --- | --- |
| KS-01 | High | no key | Recorded datagrams and push-pull frames were accepted again | Fixed |
| KS-02 | High | no key | Unauthenticated stream frames could pin 512 MiB | Fixed |
| KS-03 | Medium | no key | A connection flood evicted real inbound exchanges | Fixed |
| KS-04 | Medium | no key | Plaintext mode accepts forgeries, and reflected them 46x | Fixed |
| KS-05 | Low | no key | Key id lookup timing revealed installed keys | Fixed |
| KS-06 | Low | no key | Nonce bytes came from a non-cryptographic generator | Fixed |
| KS-07 | Low | local | Copies of keys outlived removal and drop | Fixed |
| KS-08 | Low | local | Key comparison was not constant time | Fixed |
| KS-09 | Info | no key | Traffic analysis | Accepted |
| KI-01 | High | member | Any member can declare any node dead, at once | Accepted |
| KI-02 | Medium | member | Incarnation u32::MAX evicts a name past the attacker's eviction | Fixed |
| KI-03 | Medium | member | Names of dead or future members can be taken over | Mitigated |
| KI-04 | Medium | member | Member table flooding: memory, quadratic CPU, redirected probes | Fixed |
| KI-05 | Low | member | Names and metadata are attacker-controlled strings | Open |
| KI-06 | Medium | member | A stamp far ahead stretches the replay window | Fixed |

Reproductions of open findings are ignored tests that pass while the finding stands: `cargo test --release -p kinship-core --test open_findings -- --ignored --nocapture`. A finding fixed since keeps its test, turned into one that asserts the fix and runs with the rest of the suite.

### KS-01 Recorded datagrams and push-pull frames were accepted again

**Severity:** High. **Status:** Fixed.

Packets carried no freshness, so a recording authenticated forever, and membership state only protects itself while a node remembers the incarnation a recording would have to beat. Replays did harm in four ways:

- **Resurrection.** Once a member's tombstone was reaped (30 s after it left or died), its recorded Alive was news again: MemberJoined fired for a node that was gone, and it was probed, suspected and declared dead again. Repeated every half minute, this keeps phantom members in `members()`, where rendezvous hashing routes keys to them.
- **False deaths after a restart.** A member that came back after its tombstone was reaped restarts at incarnation 0, so every recorded Suspect, Dead or Left from its previous life won again: the whole cluster saw MemberDead or MemberLeft for a live node.
- **Traffic driven by the attacker.** Each replayed Ping drew an Ack, and each replayed PingReq a Ping and a Nack, with piggybacked gossip up to `udp_max_payload`, all to members, at whatever rate the attacker replayed; each send also used up a rumour's retransmissions. A replayed push-pull frame drew the node's whole state, up to 8 MiB, and was merged.
- **Acks after a restart.** Probe sequence numbers start at 1 in every process, so after a member restarted, its previous life's recorded Acks matched its new probes and kept a dead target alive in its view.

**Reproduction:** `crates/kinship-sim/tests/replay.rs`, two simulator tests over 8 fixed seeds each. An attacker records what node n0 receives and plays it back later: after n4 leaves and its tombstone is reaped, the replay made n0 report `MemberJoined(n4)` (4 of 8 seeds failed before the fix); after n4 crashes, is reaped and restarts, the replay made n0 report `MemberSuspect(n4)` and `MemberDead(n4)` for the live node (8 of 8 failed). Unit tests: kinship-core `tests::copies_and_stale_datagrams_are_dropped_as_replays`, `sync::tests::recorded_push_pulls_are_answered_with_no_more_than_one_record`, `sync::tests::a_node_behind_cluster_time_joins_in_two_exchanges` and `replay::tests`.

**Fix:** the first 8 bytes of every nonce are now the sender's cluster time in milliseconds, and the other 16 stay random (`crates/kinship-core/src/replay.rs`). Cluster time is the node's monotonic clock plus an offset that only grows: each node adopts any later time it reads from an authenticated packet, so no synchronized wall clock is needed. A packet stamped below the node's floor, the replay window behind its cluster time, is dropped before it is decrypted; one above it whose nonce was already accepted is dropped after it authenticates. Both count under the new `replays_dropped` counter. Tombstones are kept for `dead_reclaim` or the window, whichever is longer. A node that has heard nobody for longer than the window (a fresh process, whose clock starts at zero) is stale: a seed answers its join with only its own record and merges nothing, and the joiner, which caught up from that reply, pushes and pulls again at once. The floor moves at most twice as fast as the node's own clock and half a window per input, so when a member's clock jumps ahead, packets from members still on the old timeline keep arriving while everyone catches up.

**What remains:**

- A node that has just started trusts the cluster time of the first packet it authenticates, so a recording delivered before it hears any live member is accepted, and can bring back a phantom member that the node then gossips. Until the node has completed a join, and while a join of its own is in flight, every later time it adopts moves its floor straight to the window behind it, so it refuses older recordings once it hears a live member, normally one round trip into its join. Before the fix for KP-01 in `docs/review.md`, only the first packet moved the floor: a node that first heard another node that had just started accepted recordings until its floor caught up with cluster time, which takes as long as the gap between them, not one round trip. A node whose join reached only such nodes, and that hears the rest of the cluster afterwards outside a join, still catches up that slowly. Low: the attacker has to deliver its recording before the node hears a live member, and needs a recording of a departed member.
- After a member's clock jumps ahead by D, the floor takes about D to catch up, and a recording made during that time is accepted by a node that did not see the original, for up to about (D + window) / 2 after it was made. Since the fix for KI-06, D counts only up to the lag limit, ten windows (five minutes by default): the floor follows a longer jump at once to that far behind. Monotonic clocks do not jump ahead in normal operation; KI-06 is the deliberate version.
- The nonces a node remembers are its own. A packet sent to one member can be replayed to another inside the window: the second member reads rumours it was about to hear anyway, or relays a PingReq once more.
- Plaintext mode has no replay protection (KS-04).
- In the simulator, the network's duplicated datagrams are now dropped as copies. They used to earn a second Ack, so the SWIM sweep counts more suspicions of live nodes (673 instead of 348, of 196,792) and the restart sweep's 99th percentile to converge rose from 1.4 s to 12.7 s; both stay inside their bounds.

### KS-02 Unauthenticated stream frames could pin 512 MiB

**Severity:** High. **Status:** Fixed.

A stream frame can only be authenticated once all of it has arrived. Each inbound connection buffered up to `max_stream_frame` (8 MiB) for a peer nobody had verified, then copied it to the actor through an unbounded channel. With 64 connections that is 512 MiB held for one peer without a key, and a frame already queued stayed queued when its connection was dropped as the oldest, so a fast sender could stack more behind it. That is enough to have the operating system kill a Python worker in a container.

**Reproduction:** kinship-net `streams::inbound_connections_share_a_bounded_buffer` opens 8 connections to a node with a 1 MiB `max_stream_frame` and sends 60% of a frame on each. Before the fix the node held all 8 partial frames.

**Fix:** inbound connections draw every byte they read from one budget of twice `max_stream_frame` (`conn::Budget` in kinship-net). A read that does not fit drops the connection. Once a frame is complete, the connection's read buffers are freed and only the frame stays charged, until the actor has handled it. Outbound connections are not charged: they are bounded by the exchanges the node itself starts.

### KS-03 A connection flood evicted real inbound exchanges

**Severity:** Medium. **Status:** Fixed.

Beyond `max_inbound_streams` (64) the node dropped its oldest inbound connection, and since KS-02 a connection whose read did not fit the budget was dropped too. A peer without a key that opened connections faster than real exchanges completed, or that filled the budget with partial frames, made the node fail every join through it, every push-pull other members started with it and every TCP fallback ping to it. UDP probing was unaffected, so nothing was declared dead, but joins, anti-entropy and the one-way-UDP failure mode depended on the attacker's restraint.

**Reproduction:** kinship-net `streams::a_peer_that_fills_the_inbound_budget_cannot_refuse_a_real_join`, which was the ignored `a_full_inbound_budget_refuses_a_real_join`: partial frames leave 10 bytes of the 2 MiB budget, less than any real frame, and a real node joins through the node. Before the fix the join failed for as long as the partial frames waited, up to `tcp_timeout`, and keeping that up cost twice `max_stream_frame` every `tcp_timeout`, 13 Mbit/s with the defaults. The test now sends the partial frames from three addresses, each within its share and with a valid header, and the join gets through. Unit tests: kinship-net `conn::tests::an_address_holds_at_most_its_share_and_room_comes_from_the_address_holding_the_most`, `conn::tests::a_read_past_the_budget_evicts_a_partial_frame_of_the_address_holding_the_most`, `conn::tests::a_connection_without_a_header_for_this_node_is_dropped_early` and `actor::tests::a_new_connection_evicts_its_own_address_first_then_the_address_with_the_most`; kinship-net `streams::inbound_connections_are_capped_per_address_then_taken_from_the_address_with_the_most` and `streams::a_connection_must_start_with_a_header_for_this_node`; kinship-proto `a_header_check_passes_what_its_codec_could_open_and_nothing_else`.

**Fix:** inbound connections are limited per source address, and an address that has used its share cannot take room from the others (`conn::Budget` and `actor::evict_for` in kinship-net):

- Connections: one address keeps at most `max_inbound_streams_per_ip` (16) at once, and a new one beyond that drops that address's oldest. Once all `max_inbound_streams` (64) are taken, a new connection drops the oldest of the address with the most, so a flood from one address only ever displaces itself.
- Bytes: the connections from one address hold at most `max_inbound_bytes_per_ip` of the budget, by default one largest frame, `max_stream_frame` and its 4-byte length prefix, and a read past that drops its connection. A read past the whole budget evicts the partial frame holding the most of the address holding the most, if that address holds more than the reader's, and waits until its task has given the bytes back, so the budget still bounds memory. Otherwise the reader is dropped.
- Header: the first 8 bytes of an inbound frame after its length prefix must be a header for this node, with the magic, version and flags of a stream frame in the node's mode and an installed key's id, or in plaintext mode the start of the label's hash. They are checked as soon as they arrive, against a `HeaderCheck` the actor takes from the core after every keyring command, and must arrive within `tcp_header_timeout` (1 s), or `tcp_timeout` if that is shorter. A connection that sends anything else is dropped at once, and one that sends nothing after that second rather than after `tcp_timeout`.

The three new limits are fields of the kinship and Python configs, validated with the others: `max_inbound_bytes_per_ip` must hold at least one largest frame.

**What remains:**

- A peer with many addresses gets a share for each: an IPv6 host can use a whole prefix, and a botnet has many hosts. Together they can still take every connection slot and the whole budget, and a real exchange is then evicted when its frame holds more than any one of their addresses does, such as a push-pull of a large member table. Addresses are counted one by one rather than by prefix, because the members of one IPv6 subnet share their prefix.
- Members behind one NAT address share that address's 16 connections and one frame's worth of bytes: when two of them send this node large frames at once, the second is dropped and its exchange fails, as one beyond `max_stream_frame` would.
- The header check passes anyone who has seen a packet of the cluster, since key ids and the label's hash are sent in the clear (KS-09). It shuts out peers that have not, such as scanners and nodes of other clusters, and makes the rest send a valid header within a second.
- Whether a connection survives its header tells a peer whether the node has a given key id installed. A peer can only ask about ids it already knows, since an id is 32 bits of a key's hash; see KS-05.

### KS-04 Plaintext mode accepts forgeries, and reflected them 46x

**Severity:** Medium. **Status:** Fixed; plaintext stays opt-in and unauthenticated.

With `insecure_plaintext=True`, or `Config.local()` on loopback, there is no authentication: anyone who can send to the port forges any message, so KS-01 and every member finding apply to everyone who can reach it. On loopback that is every local process and user, and every container that shares the network namespace, such as the sidecars of a Kubernetes pod. Plaintext was also a reflector: replies went to the addresses inside messages, so a forged Ping naming a victim as its source made the node send the victim an Ack with as much queued gossip as fit a datagram, and a forged PingReq sent the victim a Ping and a Nack.

**Reproduction:** `open_findings::ks04_plaintext_sends_nothing_to_an_address_that_is_not_a_member`, which was `ks04_plaintext_reflects_forged_pings_with_gossip`: a 30-byte forged Ping made a node with news to spread send 1,381 bytes to a third party, 46 times as much. Now neither that Ping nor a forged PingReq naming the victim as its requester or its target sends the victim anything, while a member's Ping still gets its Ack and the gossip. Unit tests: kinship-core `tests::in_plaintext_a_node_sends_only_to_members_it_knows_or_that_the_packet_announces` and `table::tests::member_addresses_are_indexed_through_replacements_and_reaping`.

**Fix:** in plaintext mode a node sends a datagram only to the address of a member it knows, tombstones included (`Node::may_send`, which every datagram passes). Gossip therefore rides only on packets to members, and an Ack, Nack, Ping or forwarded Ack for any other address is not sent. A PingReq from a requester it could not answer is ignored, and one for a target it may not ping gets only its Nack. A member that is new to the node, one that joined through another member a moment ago, announces itself with an Alive in the packets it sends, so while the node handles a packet, an address that an Alive in it announces counts as a member's, and the Ping ahead of that Alive is answered as it would be with encryption. The member table indexes addresses, so the check is one lookup. Encrypted mode is unchanged: only a member holding the key can make a node send.

**What remains:**

- Plaintext is still unauthenticated. A peer that first forges an Alive for an invented member at the victim's address makes that address a member's: the node then answers Pings naming it, with gossip, probes it and gossips it to the cluster, which probes it too, until the invented member is declared dead and its tombstone reaped. That costs a forged Alive for every invented member and shows on every node as a member that joined and died, but the reflection then runs at the forger's rate. KS-01 and every member finding (KI-01 to KI-06) still apply to anyone who can reach the port.
- A new member whose own packets do not carry its Alive, as in a large plaintext cluster where its queue of fresh rumours fills its first datagrams, is not answered until the node has heard of it from others. Its first probes can then go unanswered, so it suspects members that are fine, which refute, and its local health rises for a round or two.

### KS-05 Key id lookup timing revealed installed keys

**Severity:** Low. **Status:** Fixed.

A packet whose key id matched no installed key was refused before any cryptography; one whose id matched cost a tag verification. A peer without a key could therefore tell which key ids a node had installed, including a key installed for rotation and not yet used to send, which no sealed packet had revealed yet. The tag comparison itself was constant time, and decryption only ran after it. The lookup also hashed every installed key with BLAKE3 for every packet.

**Reproduction:** `open_findings::ks05_key_id_lookup_timing`, no longer ignored: in a release build the median `Codec::open` took 2.2 µs for an installed key id and 300 ns for an unknown one. Both now take 1.2 µs, timed in turns so that load falls on both alike, and the test fails if the two medians differ by a third. Unit tests: kinship-proto `packet::tests::ids_and_the_dummy_key_follow_every_change_of_keys` and `packet::tests::a_packet_with_an_unknown_key_id_is_refused_even_when_the_dummy_key_opens_it`.

**Fix:** the codec works out its keys' ids once, whenever its keys change, and keeps them beside the keys (`Keys` in `crates/kinship-proto/src/packet.rs`). A packet whose id no installed key has gets one tag verification all the same, with a dummy key that BLAKE3 derives from the sealing key, and is refused whatever the result, so it costs what a packet with an installed key's id and a bad tag costs. Only a holder of the sealing key could make a packet the dummy key opens.

**What remains:**

- A TCP connection whose header names a key id that is not installed is dropped as soon as its first 12 bytes arrive, while one naming an installed id stays open until its frame is complete or `tcp_timeout` (KS-03). A peer can therefore still tell whether a key id it already knows is installed, such as the id of a key the cluster used before a rotation. It cannot discover ids it does not know: an id is 32 bits of a key's hash and each guess costs a connection. This is the price of the header check, which shuts out peers that have never seen the cluster's traffic. Weighed again on 2026-10-11, the check stays: keeping a connection with an unknown key id open until its frame completes would hide whether an id is installed, but only ids the peer already knows, which it learned from the cluster's own packets, where ids are sent in the clear (KS-09); in exchange every peer without a key could hold a frame's worth of the inbound budget per address for `tcp_timeout`, ten times longer than the one second the header check allows, which is what KS-02 and KS-03 bound. The early drop is the better trade, and behaviour is unchanged.
- A packet whose id several installed keys share, which happens only when two keys' hashes start with the same 4 bytes, costs one verification per such key.

### KS-06 Nonce bytes came from a non-cryptographic generator

**Severity:** Low. **Status:** Fixed.

The random part of each nonce came from xoshiro256** seeded with 64 bits from the operating system, the generator that also drives protocol choices (in a separate stream). AEAD needs nonces that never repeat under a key, not unpredictable ones, so this was not exploitable, but uniqueness rested on 64 bits of entropy per process start rather than 128, and the generator's outputs are linear: the random bytes of a few packets gave away its state and every nonce the node would use.

**Reproduction:** `open_findings::ks06_nonce_bytes_do_not_give_away_the_generator`. Each packet carried two consecutive outputs in nonce bytes 8 to 24. Inverting the output function (multiply by the inverse of 9, rotate right by 7, multiply by the inverse of 5) yields the generator's `s[1]` word for each, and since its state transition is linear over GF(2), six of them determine the whole state by Gaussian elimination. The test runs that attack: it recovers a xoshiro generator from six outputs and predicts the next two, and against a node's first nonces it predicted the next ones exactly before the fix and predicts nothing since. Unit test: kinship-core `rng::tests::nonces_are_the_chacha20_keystream_of_their_key`.

**Fix:** the random bytes of every nonce now come from ChaCha20, with a 64-bit block counter so the stream never runs out, keyed with 32 bytes of their own (`rng::Nonces` in kinship-core). The core stays sans-IO: `Node::new` takes the nonce key from the driver beside the seed, kinship-net draws it from the operating system with the seed and zeroizes its copy, and kinship-sim derives it from each node's seed and so from the run's (`NodeSpec::nonce_key`). xoshiro still drives protocol choices, and `Node::new` still makes the draw from it that used to seed nonces, so every simulator seed makes the same protocol choices as before and still replays byte for byte. Only the bytes of sealed packets differ: the trace of the pinned SWIM run changed in every packet hash and in nothing else, and its digest in `swim::swim_trace_is_pinned_across_platforms` was updated.

**What remains:** nonces still carry the sender's cluster time in their first 8 bytes in the clear (KS-09). A process memory dump holds the nonce key along with the cluster keys.

### KS-07 Copies of keys outlived removal and drop

**Severity:** Low. **Status:** Fixed.

`Key` zeroized itself on drop, but copies outlived it. The node kept the `Config` it started with, keys included, for as long as it ran, so a key removed with `RemoveKey` was still in memory. Growing the key list reallocated without zeroizing the old buffer, moves by value left stack copies, `Key::to_base64` and `generate_key()` handed out base64 in a plain `String`, and in Python keys arrive as `bytes` or `str` objects that cannot be zeroized at all. A process memory dump or a core file therefore held every key the node had had.

**Reproduction:** `open_findings::ks07_a_removed_key_leaves_the_node`, which was the ignored `ks07_a_removed_key_stays_in_the_node_config`: the config the node keeps now holds no keys, before and after a `RemoveKey`, and the removed key is gone from the codec. Unit tests: kinship-proto `packet::tests::key_bytes_stay_where_they_are_when_keys_move` and kinship-core `config::tests::taking_the_codec_moves_the_keys_out_of_the_config`.

**Fix:**

- `Key` keeps its 32 bytes in a heap allocation of their own, so moving a key, or growing a list of keys, moves a pointer and leaves no copy of the bytes. `Key::from_slice` and `Key::from_base64` decode straight into that allocation, and `Key::from_bytes` zeroizes its own copy of its argument.
- `Node::new` moves the keys out of its `Config` into the codec, the only place they live from then on: the config the node keeps has an empty key list, and a key removed with `RemoveKey` is dropped, and zeroized, at once. `Config::validate` measures packets with a codec that holds a copy of the sealing key alone, zeroized as soon as validation ends.
- `Key::to_base64` returns a `Zeroizing<String>` written into its final allocation, and the Python `generate_key()` zeroizes the Rust copy once Python has its string. kinship-net zeroizes its copy of the nonce key (KS-06) once the node has it.
- README.md now tells Python applications to read keys from a file or the environment just before building the config, and to drop their references afterwards.

**What remains:**

- Python cannot zeroize `bytes` or `str`: a key passed in as one stays in the Python heap until that memory is reused. A Python `Config` also keeps the keys it was built with, zeroized only when the config is freed, and a `Cluster` keeps its config, so a key removed with `cluster.keyring.remove` stays in that config until both are gone.
- The Rust `kinship::Config` builder and `kinship_net::Settings` hold the keys until the node starts, and an application's own copies are its to drop.
- Keys are not locked in memory, so the operating system may write them to swap, and a dump of a running node still holds the keys installed at the time.

### KS-08 Key comparison was not constant time

**Severity:** Low. **Status:** Fixed.

`Key` derived `PartialEq`, a byte comparison that returns at the first difference. It ran only when the local caller installed, used or removed a key, against keys that caller supplied, so nobody else could time it.

**Reproduction:** none from the network; it was visible in `Key`'s derive. Unit test: kinship-proto `packet::tests::keys_are_equal_only_when_every_byte_is`.

**Fix:** `Key` implements `PartialEq` with `ctutils::CtEq`, which looks at every byte whatever it finds and turns the result into a `bool` only at the end. ctutils is RustCrypto's successor to `subtle` and was already in the dependency tree, through poly1305, so the fix adds no crate; `cargo deny check advisories bans sources` passes.

**What remains:** finding a key in the codec's list, to install, use or remove it, stops at the first key that matches, so the time can tell the position of a matching key in the list, though not anything about its bytes. Only the local caller can time it.

### KS-09 Traffic analysis

**Severity:** Info. **Status:** Accepted.

An observer without a key still sees each packet's key id, its cluster time stamp (which gives away how long the cluster has been running), packet sizes and timing, and the addresses that talk to each other. From these it can count members, tell probes from push-pull exchanges and see when a key rotation happens.

### KI-01 Any member can declare any node dead, at once

**Severity:** High. **Status:** Accepted: the design does not protect against a member that holds a key.

Rumours are not signed by their subject or their author, so a member that holds the key can send Suspect, Dead or Left about any node at its current incarnation and every node that hears it applies it at once. It can invent reporter names to bring a suspicion down to the minimum timeout, send Acks for probes it never forwarded (an Ack names only a sequence number) to keep a dead member alive in a prober's view, and answer PingReqs falsely. Removing it means rotating the key on every other node.

**Reproduction:** `open_findings::ki01_a_member_declares_any_node_dead_at_once`: one sealed Dead makes a node report MemberDead for a live member.

**Recommended fix:** per-member signing keys, with rumours about a member's own state (Alive, Left) signed by it and accusations attributed to their author, is the change that would make this a finding with a fix. It belongs in a later wire version.

### KI-02 Incarnation u32::MAX evicts a name past the attacker's eviction

**Severity:** Medium. **Status:** Fixed.

A Dead or Suspect at incarnation u32::MAX could not be refuted: the victim's incarnation saturated at u32::MAX, and its Alive never beat the tombstone. Once the tombstone was reaped the victim rejoined at u32::MAX, but from then on no ordinary suspicion of it, at u32::MAX, could be refuted either, so its first missed probe killed it again. The damage outlived the key rotation that removed the attacker, until the victim restarted and no node remembered it.

**Reproduction:** `open_findings::ki02_a_rumour_at_incarnation_max_is_refuted`, which was the ignored `ki02_incarnation_max_cannot_be_refuted`. An attacker kills the victim at 2^31 - 1, the most one rumour can now move an incarnation, and again once it has refuted, at u32::MAX; each time the victim refutes and a peer takes it back, the second time at incarnation 0. Then both rotate to a key the attacker lacks, and an ordinary suspicion is refuted as for any member. Before the fix the victim stayed at u32::MAX and the peer held it dead. Unit tests: kinship-core `member::tests::incarnations_compare_as_serial_numbers` and `tests::a_rumour_at_the_last_incarnation_is_refuted_past_it`.

**Fix:** incarnations are serial numbers (RFC 1982, `member::newer`): they wrap from u32::MAX to 0, and one is newer than another when it is less than 2^31 ahead of it around that ring. Every incarnation has newer ones, so a refutation, which sets the member's incarnation to the rumour's plus one, always beats the rumour; set_meta wraps too. Of the two recommendations this is the second, a new epoch that outranks old incarnations, with the epoch carried in the incarnation itself: wrapping starts the next lap, and the newest half of the ring outranks the rest. It also bounds how far one rumour moves an incarnation, below 2^31, which the first recommendation asked for. It was chosen over the other two designs:

- A bound per round on how far a rumour may raise an incarnation breaks legitimate catch-up. A member that changes its metadata every second is 86,400 incarnations ahead after a day, so a node that was partitioned for that day, or a member restarting after it, would refuse the real Alive and keep a stale view; and an attacker holding the key still reaches u32::MAX, only more slowly.
- An explicit epoch field would need a new wire field, and needs a bound or a size of its own, or it saturates as the incarnation did.

Serial numbers need no wire change and no state per member, and among honest members, whose incarnations never come near 2^31 apart, every comparison gives what it gave before. A rumour about this node 2^31 or more ahead of its incarnation reads as stale and is answered by sending its Alive again, as for any stale rumour (KP-04).

**What remains:**

- While it holds the key, an attacker still declares any member dead (KI-01), and can move it around the ring a rumour at a time. Recovery after the attacker is removed is immediate: the victim's next refutation beats whatever incarnation the attacker left.
- An attacker can leave nodes holding one member at incarnations 2^31 or more apart, so that no single refutation is newer for all of them. A node that then holds the member at a value its refutations cannot beat ignores its Alives, including metadata changes; if it suspects the member, the member answers with its Alive, which that node also ignores, so it declares the member dead, reports MemberDead for a live node once, and learns it again from a push-pull once the tombstone is reaped. As with any forged Alive at a higher incarnation (KI-01), a node holding the member Alive at such a value keeps an old view of it until that happens.
- From 0.3 each run of a member also has an epoch, which ranks above its incarnations (docs/design.md, Epochs). It compares as a serial number for the same reason, so no forged epoch leaves a member unable to start a later life: a node that hears its own name at a later epoch moves one past it and gossips that. While it holds the key, an attacker can therefore also forge a restart, an Alive at a later epoch from the member's own address, which every node applies whatever the incarnation: applications see MemberLeft and MemberJoined for a node that never restarted, and its fencing token (`Ring.fence`) changes, until the member hears the forgery and moves past it. Epochs 2^63 apart behave as incarnations 2^31 apart do above.

### KI-03 Names of dead or future members can be taken over

**Severity:** Medium. **Status:** Mitigated: tombstones keep their address; names never seen, and names whose tombstone was reaped, stay open until per-member keys.

An Alive with a higher incarnation was applied to a Dead or Left member whatever its address, so a member could move a dead node's name to an address of its choice; when the real node came back, it was the one reported in NameConflict. A member can likewise claim names before their owners start. Choosing names also chooses rendezvous hash weights, so it can claim the keys of its choice in `kinship.rendezvous.owner()`.

**Reproduction:** `open_findings::ki03_a_member_cannot_move_a_dead_node_to_another_address`, which was the ignored `ki03_a_member_takes_over_the_name_of_a_dead_node`: a forged Dead and then an Alive at a higher incarnation from another address moved a member's name there. Now the member stays Dead at its own address, the node reports a NameConflict naming the other address, and the real member then comes back at its own. Unit test: kinship-core `tests::a_tombstone_keeps_its_name_at_its_address_until_it_is_reaped`.

**Fix:** the wire-compatible half of the recommendation, until per-member keys exist. A Dead or Left member keeps its address for as long as its tombstone is kept, `dead_reclaim` or the replay window, whichever is longer: an Alive for it from any other address is not applied, whatever its incarnation, and is reported as a NameConflict and counted under `name_conflicts`, as an Alive for a live member's name from another address already was (`Node::on_alive`). No address in the member table ever changes now: a member is admitted at an address and keeps it until it is reaped.

The price is paid by an honest member that comes back at a new address, such as a container rescheduled with the same name and a new IP: until its tombstone is reaped, the others ignore its Alive and report a NameConflict, and it is admitted at the new address by the first exchange after that, normally within `dead_reclaim` and a `push_pull_interval`, a minute with the defaults. Before, it was taken back at once. A member that comes back at the same address, the usual restart, is taken back at once as before.

**What remains:**

- A name nobody holds can be claimed by any member at any address: one that has not started yet, and one whose tombstone was reaped. The real owner, when it arrives, is the one in NameConflict, on every node that heard the claim first. Binding a name to a key on first sight needs per-member keys (KI-01) and a new wire version.
- Names choose rendezvous hash weights, so a member that can invent names can claim the keys of its choice in `kinship.rendezvous.owner()`.
- Applications that act on a member by name, routing requests, assigning shards or trusting it with data, must check that its address, and any address taken from its metadata, is one they expect, from their own configuration or service discovery rather than from the cluster (README.md, KI-05). kinship reports membership; it does not authenticate who a member is.

### KI-04 Member table flooding: memory, quadratic CPU, redirected probes

**Severity:** Medium. **Status:** Fixed.

There was no cap on members. A member could gossip Alive for invented names, about 50 to a datagram and re-gossiped by everyone who heard them, or send one push-pull frame with up to 8 MiB of records, about 300,000. Every node then held and probed them, so the attacker could point the whole cluster's probe traffic at any address it listed as a member. Merging was also quadratic: each new rumour scanned the whole broadcast queue to replace its member's previous one. Push-pull replies soon exceeded `max_stream_frame`, so joins and anti-entropy failed cluster-wide (`state_too_large`). Clusters of tens of thousands of honest members hit the same quadratic cost when a node joined. The audit also said the actor publishes a full copy of the member list after every change; it does not: kinship-net's actor rebuilds its snapshot at most once per input, after the core has handled all of it.

**Reproduction:** `open_findings::ki04_one_push_pull_floods_the_member_table`, no longer ignored. One 546 KiB push-pull frame of 20,000 invented members took 7.8 s of a release build's CPU to merge, during which the node probed and answered nothing, and all 20,000 joined. With the defaults 1,024 of them now join, in 8 ms; a node configured for 20,000 members admits all of them in 39 ms, and the test fails if that takes half a second in a release build. Unit tests: kinship-core `tests::one_datagram_admits_at_most_its_share_of_new_members`, `tests::the_table_holds_at_most_max_members_this_node_and_tombstones_included`, `sync::tests::one_push_pull_frame_shares_one_admission_budget`, `config::tests::member_limits_default_and_must_be_positive`, `broadcast::tests::newer_gossip_replaces_older_about_the_same_member`, `broadcast::tests::a_lower_limit_drops_every_entry_that_reached_it`, `broadcast::tests::packing_skips_what_does_not_fit_and_takes_smaller_rumours_behind_it`, `broadcast::tests::rumours_to_the_live_count_only_sends_to_live_members` and `broadcast::tests::a_bulk_of_rumours_is_queued_and_replaced_in_log_time`; kinship `config::tests::bad_fields_are_named_before_binding`; Python `test_config.py`.

**Fix:** as recommended, in three parts.

- `max_members` (8,192) bounds the table: this node, live members and Dead and Left tombstones together. An Alive or push-pull record for a name the node does not know is admitted only while the table holds fewer, and `Node::add_member` refuses a new name beyond it with an error naming the field. Members the node already holds keep applying every update, tombstones included, and a reaped tombstone frees its place.
- `max_new_members_per_packet` (1,024) bounds what one packet adds: one budget per datagram or push-pull frame, shared by every Alive and record in it (`member::Admission`, created in `Node::process` and `Node::on_frame`). Only admissions spend it: news about known members and refused names do not. A refused name is not gossiped on, and every refusal counts under the new `members_refused` metric, which `stats()` reports in Rust and Python. Both limits are fields of the kinship and Python configs, validated as positive.
- The broadcast queue keeps its entries ordered by sends and then newest first, as before, and indexes them by member (`Broadcasts` in `broadcast.rs`), so replacing a member's rumour and counting a send cost O(log n), and packing a datagram stops once no rumour could fit what is left. Packets are packed exactly as before, skipping an entry that does not fit and taking smaller ones behind it, live-only rumours count only sends to live members, and every entry at or past the retransmit limit is dropped, including ones a fallen limit catches unsent; every simulator seed makes the same choices, and the pinned SWIM trace is unchanged.

With the defaults a full table, with 512 bytes of metadata, 64-byte names and IPv6 addresses for every member, is about 5 MB of push-pull, inside `max_stream_frame`.

**What remains:**

- A member can still fill the table with invented names, 1,024 per frame, and point every node's probes at addresses it lists until those members are declared dead and their tombstones reaped; it can keep sending them. Once the table is full, real new members are refused, and `members_refused` counts them, until it has room again. Removing the attacker still takes a key rotation (KI-01).
- An honest cluster larger than 1,024 members is learned 1,024 members per push-pull: a node joining one knows the rest only after further push-pulls and gossip, a few `push_pull_interval`s, unless `max_new_members_per_packet` is raised to the cluster's size. A cluster larger than 8,192 must raise `max_members` on every node, or nodes refuse members beyond it.
- The actor rebuilds its member snapshot, O(n), once for each input that changed membership, so a large table that changes in every packet costs O(n) per packet.

### KI-05 Names and metadata are attacker-controlled strings

**Severity:** Low. **Status:** Open; application guidance.

Names are any 1 to 64 bytes of UTF-8 and metadata any 512 bytes, so a member can use control characters, look-alike names and arbitrary values. The README's examples build URLs from `meta["http"]` and `meta["ws"]`, which a member can point anywhere. Tag lists that do not parse read as no tags in Python, so they cannot crash a reader.

**Recommended fix:** treat names and metadata as untrusted input in applications: escape them when logging, and check addresses taken from metadata against an allow-list. README.md's section on encryption and keys tells applications so.

### KI-06 A stamp far ahead stretches the replay window

**Severity:** Medium. **Status:** Fixed; introduced with the fix for KS-01.

Every node adopts the latest cluster time it authenticates, and the replay floor caught up only at the speed of the node's own clock, so that it could absorb clock jumps. A member that stamped a packet years ahead therefore left every node with a floor far behind its cluster time, and recordings made after that point were accepted by nodes that did not see the originals until the set of remembered nonces filled (131,072 entries, about 45 minutes at 50 packets a second) and pushed the floor up. Cluster time never goes back, so this outlived the attacker's eviction. A stamp at u64::MAX was worse: cluster time stopped there, every packet carried the same stamp, and only the remembered nonces told old packets from new, for as long as the cluster ran. As docs/review.md notes, no compromised member was needed: an honest node that kept running, cut off, while the rest of the cluster restarted moved every floor the same way when it came back.

**Reproduction:** `open_findings::ki06_a_member_far_ahead_stretches_the_replay_window_by_at_most_the_lag_limit`, which was the ignored `ki06_a_member_far_ahead_stretches_the_replay_window`: after a packet stamped ten years ahead, a recording made a second later was still accepted an hour on; it is now refused, as is a packet stamped further ahead than 2^40 ms. The honest case is kinship-sim `review::ki06_an_honest_node_far_ahead_stretches_the_window_by_at_most_the_lag_limit`: five nodes on process clocks; one is cut off for an hour while the other four restart and rejoin each other, then it joins them again. An attacker records what one node receives in the ten seconds after and replays it into another 400 s later. With the lag limit turned off, the replay was accepted whole in every seed (19 of 19 datagrams in seed 0); now none is, and all five nodes hold each other live with no death after the reunion settles. Unit tests: kinship-core `replay::tests::a_jump_past_the_lag_limit_is_not_waited_for`, `replay::tests::cluster_time_jumps_a_bounded_amount_and_far_only_once_a_window` and `replay::tests::a_settling_node_moves_its_floor_with_every_time_it_adopts`.

**Fix:** a limit on how far behind the floor may fall, and on how far cluster time may jump (`crates/kinship-core/src/replay.rs`).

- The floor never lags more than ten windows, five minutes by default, behind the window behind cluster time. A jump shorter than that is absorbed gradually as before, which keeps the clock-jump sweep's jumps of 1 to 120 s unchanged; after a longer one the floor moves at once to that limit behind the new time, so a recording is accepted at most the window plus the limit after it was made. Packets from members still on the old timeline are dropped until they hear the new one, which every packet carries, normally within a gossip round.
- A packet stamped more than 2^40 ms (some 35 years) ahead of cluster time is refused before it is decrypted, and so is one past the lag limit ahead within a window of the last such jump, unless the node is still joining and has yet to hear the cluster's time. Both count under `replays_dropped`. Driving cluster time to u64::MAX then takes 2^24 windows of the longest jump, about 16 years, or some 6 × 10^13 packets each jumping up to the lag limit, two years at a million packets a second, so the saturation above is out of reach.

This is not the recommended fix, cluster time per key id restarted with each new key, for three reasons. It does not cover the honest node far ahead, which needs no key change. A fresh timeline per key must start from something: from each node's own clock, the use step of every rotation makes cluster time jump by the spread of the nodes' process uptimes, days in a long-running cluster, which is KI-06 again, or drops packets if the floor follows at once; from the old key's time, it keeps the attacker's stamp. And once the floor cannot lag far and cluster time cannot saturate, a stamp the attacker left behind is only an offset, harmless after the rotation that removes it. Per-key timelines would also have to be looked up from the unauthenticated key id before decryption, and kept through rotations during a push-pull and through stale-reply recovery, for no gain left.

**What remains:**

- A recording is accepted for up to the window plus the lag limit after a jump past the limit, 5.5 minutes by default, by a node that did not see the original, rather than the window alone.
- While it holds a key, an attacker can keep pushing cluster time ahead, past the lag limit once a window and by up to the limit with every packet; each time, nodes drop the packets of members that have not caught up yet for about a gossip round, which can raise suspicions that are then refuted. That stops with its eviction. Cluster time never goes back, so the offset it reached stays, which costs nothing.
- An honest node far ahead that comes back has the same short effect: until the others have heard its time, it drops their packets and they drop each other's.

## What kinship does not protect against

- **A compromised member.** A node that holds a valid key can forge any rumour about any member (KI-01 to KI-06). Remove it by rotating the key on every other node: install a new key, use it, remove the old one.
- **Dropping and delaying traffic.** An attacker on the path that drops a member's packets makes it look dead, as a real failure would; that is what a failure detector reports. Partitions are healed when traffic flows again, not prevented.
- **Floods.** A peer without a key can fill a node's UDP socket or CPU with traffic that fails authentication, and one with many addresses can fill its inbound connection slots and buffer (KS-03). Each packet costs one tag verification and no reply.
- **Traffic analysis.** Sizes, timing, addresses, key ids and the cluster time stamp are visible (KS-09).
- **Plaintext mode.** `insecure_plaintext=True`, and `Config.local()` on loopback, trust everyone who can reach the port and have no replay protection. A node sends only to members it knows, so a forged packet cannot aim it at a third party, but a forged member can (KS-04).
- **The application's own decisions.** Split-brain decisions made during a partition, and a member that answers probes but is otherwise broken.
- **Key handling outside kinship.** Keys given to kinship as Python objects, or stored in files and environment variables, are the application's to protect (KS-07).
