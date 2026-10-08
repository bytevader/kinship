# Security

Report a vulnerability privately, through a GitHub security advisory on this repository, rather than in a public issue.

This file holds kinship's threat model and the findings of the security audit of 2026-10-07, which looked at kinship first as an attacker on the network who holds no key, then as a compromised member that does. Findings marked Fixed were fixed in the same change; the rest are documented here with a reproduction and the fix we recommend. The architecture is in `docs/design.md` and the public API in `README.md`.

## Threat model

### What kinship protects

- **Membership integrity.** Which members are alive, suspect, dead or gone, their addresses and their metadata, as every node sees them.
- **Failure detection.** Live members stay members, and dead ones are declared dead within the Lifeguard timeouts.
- **Confidentiality of membership traffic.** Names, addresses, metadata and protocol state are encrypted on the wire.
- **The keys.** 32-byte XChaCha20-Poly1305 keys, which never leave the process and are never logged.

### Attackers

1. **A network attacker without a key.** It shares a network with the cluster. It can see, record, drop, delay, reorder and inject UDP datagrams, spoof their source address, open TCP connections to any member, and replay anything it recorded, at any later time and to any member. It does not hold a cluster key.
2. **A compromised member.** It holds a valid key and the cluster label, so every packet it seals authenticates. It can send any message about any member, at any rate.

Other processes on the same host count as network attackers, except in plaintext mode on loopback, where they are trusted (KS-04).

### Guarantees against an attacker without a key

- It cannot read traffic or forge, alter or truncate a packet: every datagram and stream frame is sealed with XChaCha20-Poly1305 over the header and the cluster label, the tag is checked in constant time, and nothing is decrypted or parsed before it verifies.
- A recording is useless once it is older than the replay window (30 s, or twice `tcp_timeout` if that is longer), and a copy of a packet is useless at once (KS-01). Tombstones outlive the window, so no recording can bring back a member that left or died.
- No reply goes to an address it chooses: replies go to addresses inside authenticated messages, never to a datagram's source address. A packet that does not authenticate gets no reply at all, and a stale push-pull that does gets at most the answering node's own record.
- What it sends costs bounded work and memory: header checks before any cryptography, at most one tag verification per installed key with the packet's key id, frame lengths checked from their prefix, and at most twice `max_stream_frame` held for unauthenticated stream frames across all connections (KS-02).

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
| KS-03 | Medium | no key | A connection flood evicts real inbound exchanges | Open |
| KS-04 | Medium | no key | Plaintext mode accepts forgeries and reflects 46x | Open |
| KS-05 | Low | no key | Key id lookup timing reveals installed keys | Open |
| KS-06 | Low | no key | Nonce bytes come from a non-cryptographic generator | Open |
| KS-07 | Low | local | Copies of keys outlive removal and drop | Open |
| KS-08 | Low | local | Key comparison is not constant time | Open |
| KS-09 | Info | no key | Traffic analysis | Accepted |
| KI-01 | High | member | Any member can declare any node dead, at once | Accepted |
| KI-02 | Medium | member | Incarnation u32::MAX evicts a name past the attacker's eviction | Open |
| KI-03 | Medium | member | Names of dead or future members can be taken over | Open |
| KI-04 | Medium | member | Member table flooding: memory, quadratic CPU, redirected probes | Open |
| KI-05 | Low | member | Names and metadata are attacker-controlled strings | Open |
| KI-06 | Medium | member | A stamp far ahead stretches the replay window | Open |

Reproductions of open findings are ignored tests that pass while the finding stands: `cargo test --release -p kinship-core --test open_findings -- --ignored --nocapture`.

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
- After a member's clock jumps ahead by D, the floor takes about D to catch up, and a recording made during that time is accepted by a node that did not see the original, for up to about (D + window) / 2 after it was made. Monotonic clocks do not jump ahead in normal operation; KI-06 is the deliberate version.
- The nonces a node remembers are its own. A packet sent to one member can be replayed to another inside the window: the second member reads rumours it was about to hear anyway, or relays a PingReq once more.
- Plaintext mode has no replay protection (KS-04).
- In the simulator, the network's duplicated datagrams are now dropped as copies. They used to earn a second Ack, so the SWIM sweep counts more suspicions of live nodes (673 instead of 348, of 196,792) and the restart sweep's 99th percentile to converge rose from 1.4 s to 12.7 s; both stay inside their bounds.

### KS-02 Unauthenticated stream frames could pin 512 MiB

**Severity:** High. **Status:** Fixed.

A stream frame can only be authenticated once all of it has arrived. Each inbound connection buffered up to `max_stream_frame` (8 MiB) for a peer nobody had verified, then copied it to the actor through an unbounded channel. With 64 connections that is 512 MiB held for one peer without a key, and a frame already queued stayed queued when its connection was dropped as the oldest, so a fast sender could stack more behind it. That is enough to have the operating system kill a Python worker in a container.

**Reproduction:** kinship-net `streams::inbound_connections_share_a_bounded_buffer` opens 8 connections to a node with a 1 MiB `max_stream_frame` and sends 60% of a frame on each. Before the fix the node held all 8 partial frames.

**Fix:** inbound connections draw every byte they read from one budget of twice `max_stream_frame` (`conn::Budget` in kinship-net). A read that does not fit drops the connection. Once a frame is complete, the connection's read buffers are freed and only the frame stays charged, until the actor has handled it. Outbound connections are not charged: they are bounded by the exchanges the node itself starts.

### KS-03 A connection flood evicts real inbound exchanges

**Severity:** Medium. **Status:** Open.

Beyond `max_inbound_streams` (64) the node drops its oldest inbound connection, and since KS-02 a connection whose read does not fit the budget is dropped too. A peer without a key that opens connections faster than real exchanges complete, or that fills the budget with partial frames, makes this node fail every join through it, every push-pull other members start with it and every TCP fallback ping to it. UDP probing is unaffected, so nothing is declared dead, but joins, anti-entropy and the one-way-UDP failure mode depend on the attacker's restraint.

**Reproduction:** kinship-net `streams::a_full_inbound_budget_refuses_a_real_join` (ignored): three connections send partial frames that leave less of the budget than a real frame needs, and a real node's `join()` through the node fails for as long as they wait, up to `tcp_timeout`. Keeping it up costs twice `max_stream_frame` every `tcp_timeout`, 13 Mbit/s with the defaults. `streams::beyond_64_inbound_connections_the_oldest_are_dropped` shows connections evicting each other.

**Recommended fix:** cap concurrent connections and budget per source IP address, evict from the address holding the most, and drop a connection whose first 8 bytes are not a valid header for this node (magic, version, flags, an installed key id) within a second.

### KS-04 Plaintext mode accepts forgeries and reflects 46x

**Severity:** Medium. **Status:** Open; plaintext stays opt-in.

With `insecure_plaintext=True`, or `Config.local()` on loopback, there is no authentication: anyone who can send to the port forges any message, so KS-01 and every member finding apply to everyone who can reach it. On loopback that is every local process and user, and every container that shares the network namespace, such as the sidecars of a Kubernetes pod. Plaintext is also a reflector: replies go to the addresses inside messages, so a forged Ping naming a victim as its source makes the node send the victim an Ack with as much queued gossip as fits a datagram, and a forged PingReq sends the victim a Ping and a Nack.

**Reproduction:** `open_findings::ks04_plaintext_reflects_forged_pings_with_gossip`: a 30-byte forged Ping makes a node with news to spread send 1,381 bytes to a third party, 46 times as much.

**Recommended fix:** in plaintext mode, piggyback gossip only on packets to known member addresses, and send nothing to an address that is not a member.

### KS-05 Key id lookup timing reveals installed keys

**Severity:** Low. **Status:** Open.

A packet whose key id matches no installed key is refused before any cryptography; one whose id matches costs a tag verification. A peer without a key can therefore tell which key ids a node has installed, including a key installed for rotation and not yet used to send, which no sealed packet has revealed yet. The tag comparison itself is constant time, and decryption only runs after it. The lookup also hashes every installed key with BLAKE3 for every packet.

**Reproduction:** `open_findings::ks05_key_id_lookup_timing`: the median `Codec::open` takes 2.2 µs for an installed key id and 300 ns for an unknown one.

**Recommended fix:** compute key ids once when keys change, and run one tag verification with a dummy key when no installed key has the id.

### KS-06 Nonce bytes come from a non-cryptographic generator

**Severity:** Low. **Status:** Open.

The random part of each nonce comes from xoshiro256** seeded with 64 bits from the operating system, the generator that also drives protocol choices (in a separate stream). AEAD needs nonces that never repeat under a key, not unpredictable ones, so this is not exploitable today, but uniqueness rests on 64 bits of entropy per process start rather than 128, and the generator's outputs are linear: the random bytes of a few packets give away its state and every nonce the node will use.

**Reproduction:** each packet carries two consecutive outputs in nonce bytes 8 to 24. Inverting the output function (multiply by the inverse of 9, rotate right by 7, multiply by the inverse of 5) yields the generator's `s[1]` word for each, and a few of them determine the full state by linear algebra over GF(2), since its state transition is linear.

**Recommended fix:** take a separate 32-byte nonce seed from the operating system in `Node::new` and draw nonce bytes from ChaCha20 keyed with it, leaving xoshiro for protocol choices so that simulator runs stay reproducible.

### KS-07 Copies of keys outlive removal and drop

**Severity:** Low. **Status:** Open.

`Key` zeroizes itself on drop, but copies outlive it. The node keeps the `Config` it started with, keys included, for as long as it runs, so a key removed with `RemoveKey` is still in memory. Growing the key list reallocates without zeroizing the old buffer, moves by value leave stack copies, `Key::to_base64` and `generate_key()` hand out base64 in a plain `String`, and in Python keys arrive as `bytes` or `str` objects that cannot be zeroized at all. A process memory dump or a core file therefore holds every key the node has had.

**Reproduction:** `open_findings::ks07_a_removed_key_stays_in_the_node_config`.

**Recommended fix:** keep keys only in the codec, boxed so that moves do not copy them, strip them from the stored `Config`, and return base64 as `Zeroizing<String>`. In Python, read keys from a file or the environment just before building the config and drop the references afterwards.

### KS-08 Key comparison is not constant time

**Severity:** Low. **Status:** Open.

`Key` derives `PartialEq`, a byte comparison that returns at the first difference. It runs only when the local caller installs, uses or removes a key, against keys that caller supplies, so nobody else can time it.

**Reproduction:** none from the network; it is visible in `Key`'s derive.

**Recommended fix:** compare keys with a constant-time equality, for example `subtle::ConstantTimeEq`.

### KS-09 Traffic analysis

**Severity:** Info. **Status:** Accepted.

An observer without a key still sees each packet's key id, its cluster time stamp (which gives away how long the cluster has been running), packet sizes and timing, and the addresses that talk to each other. From these it can count members, tell probes from push-pull exchanges and see when a key rotation happens.

### KI-01 Any member can declare any node dead, at once

**Severity:** High. **Status:** Accepted: the design does not protect against a member that holds a key.

Rumours are not signed by their subject or their author, so a member that holds the key can send Suspect, Dead or Left about any node at its current incarnation and every node that hears it applies it at once. It can invent reporter names to bring a suspicion down to the minimum timeout, send Acks for probes it never forwarded (an Ack names only a sequence number) to keep a dead member alive in a prober's view, and answer PingReqs falsely. Removing it means rotating the key on every other node.

**Reproduction:** `open_findings::ki01_a_member_declares_any_node_dead_at_once`: one sealed Dead makes a node report MemberDead for a live member.

**Recommended fix:** per-member signing keys, with rumours about a member's own state (Alive, Left) signed by it and accusations attributed to their author, is the change that would make this a finding with a fix. It belongs in a later wire version.

### KI-02 Incarnation u32::MAX evicts a name past the attacker's eviction

**Severity:** Medium. **Status:** Open.

A Dead or Suspect at incarnation u32::MAX cannot be refuted: the victim's incarnation saturates at u32::MAX, and its Alive never beats the tombstone. Once the tombstone is reaped the victim rejoins at u32::MAX, but from then on no ordinary suspicion of it, at u32::MAX, can be refuted either, so its first missed probe kills it again. The damage outlives the key rotation that removes the attacker, until the victim restarts and no node remembers it.

**Reproduction:** `open_findings::ki02_incarnation_max_cannot_be_refuted`.

**Recommended fix:** refuse rumours that raise a member's incarnation by more than a bound per round, or let a member restart its incarnation under a new epoch that outranks any old incarnation.

### KI-03 Names of dead or future members can be taken over

**Severity:** Medium. **Status:** Open.

An Alive with a higher incarnation is applied to a Dead or Left member whatever its address, so a member can move a dead node's name to an address of its choice; when the real node comes back, it is the one reported in NameConflict. A member can likewise claim names before their owners start. Choosing names also chooses rendezvous hash weights, so it can claim the keys of its choice in `kinship.rendezvous.owner()`.

**Reproduction:** `open_findings::ki03_a_member_takes_over_the_name_of_a_dead_node`.

**Recommended fix:** with per-member keys (KI-01), bind a name to its key on first sight; until then, applications that route by name should also check addresses they expect.

### KI-04 Member table flooding: memory, quadratic CPU, redirected probes

**Severity:** Medium. **Status:** Open.

There is no cap on members. A member can gossip Alive for invented names, about 50 to a datagram and re-gossiped by everyone who hears them, or send one push-pull frame with up to 8 MiB of records. Every node then holds and probes them, so the attacker can point the whole cluster's probe traffic at any address it lists as a member. Merging is also quadratic: each new rumour scans the whole broadcast queue, and the actor publishes a full copy of the member list after every change. Push-pull replies soon exceed `max_stream_frame`, so joins and anti-entropy fail cluster-wide (`state_too_large`). Clusters of tens of thousands of honest members hit the same quadratic cost when a node joins.

**Reproduction:** `open_findings::ki04_one_push_pull_floods_the_member_table`: one 546 KiB frame of 20,000 invented members takes 13 s of a release build's CPU to merge, during which the node probes and answers nothing. A full 8 MiB frame holds about 300,000.

**Recommended fix:** a `max_members` limit, a broadcast queue keyed by member so a rumour replaces its predecessor in O(log n), and a limit on new members accepted from one packet.

### KI-05 Names and metadata are attacker-controlled strings

**Severity:** Low. **Status:** Open; application guidance.

Names are any 1 to 64 bytes of UTF-8 and metadata any 512 bytes, so a member can use control characters, look-alike names and arbitrary values. The README's examples build URLs from `meta["http"]` and `meta["ws"]`, which a member can point anywhere. Tag lists that do not parse read as no tags in Python, so they cannot crash a reader.

**Recommended fix:** treat names and metadata as untrusted input in applications: escape them when logging, and check addresses taken from metadata against an allow-list.

### KI-06 A stamp far ahead stretches the replay window

**Severity:** Medium. **Status:** Open; introduced with the fix for KS-01.

Every node adopts the latest cluster time it authenticates, and the replay floor catches up only at the speed of the node's own clock, so it can absorb clock jumps. A member that stamps a packet years ahead therefore leaves every node with a floor far behind its cluster time, and recordings made after that point are accepted by nodes that did not see the originals until the set of remembered nonces fills (131,072 entries, about 45 minutes at 50 packets a second) and pushes the floor up. Cluster time never goes back, so this outlives the attacker's eviction; replay protection returns as the floor catches up or the remembered nonces fill.

**Reproduction:** `open_findings::ki06_a_member_far_ahead_stretches_the_replay_window`: after a packet stamped ten years ahead, a recording made a second later is still accepted an hour on.

**Recommended fix:** keep cluster time per key id and start it again with each new key, so that a rotation that removes the attacker also discards its stamps.

## What kinship does not protect against

- **A compromised member.** A node that holds a valid key can forge any rumour about any member (KI-01 to KI-06). Remove it by rotating the key on every other node: install a new key, use it, remove the old one.
- **Dropping and delaying traffic.** An attacker on the path that drops a member's packets makes it look dead, as a real failure would; that is what a failure detector reports. Partitions are healed when traffic flows again, not prevented.
- **Floods.** A peer without a key can fill a node's UDP socket, CPU or inbound connection slots with traffic that fails authentication (KS-03). Each packet costs at most one tag verification per installed key with its key id, and no reply.
- **Traffic analysis.** Sizes, timing, addresses, key ids and the cluster time stamp are visible (KS-09).
- **Plaintext mode.** `insecure_plaintext=True`, and `Config.local()` on loopback, trust everyone who can reach the port, have no replay protection, and reflect forged Pings with gossip (KS-04).
- **The application's own decisions.** Split-brain decisions made during a partition, and a member that answers probes but is otherwise broken.
- **Key handling outside kinship.** Keys given to kinship as Python objects, or stored in files and environment variables, are the application's to protect (KS-07).
