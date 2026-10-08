# Protocol review

A review of `crates/kinship-core`, read line by line on 2026-10-07 against SWIM (Das, Gupta and Motivala, 2002), Lifeguard (Dadgar et al., 2017) and `docs/design.md`. It looked for incarnation bugs, timeout arithmetic, dissemination starvation, probe-order bias, Nack timing, tombstone and state leaks, the join and leave paths, and the replay window in `replay.rs`. Findings already open in SECURITY.md are not repeated. The review itself fixed nothing; the Status column records the fixes that followed, and each fixed finding says what changed.

Every finding has a simulator test in `crates/kinship-sim/tests/review.rs` that asserts what should hold and fails today. The tests are ignored, with the finding's id in the reason, so CI stays green; a fix removes the `#[ignore]`. Run them with

```
cargo test --release -p kinship-sim --test review -- --ignored --nocapture
```

A failure names its lowest failing seed, and `KINSHIP_SEED=<seed>` replays it. Each cause was confirmed with a control run, a throwaway patch that makes the test pass, or both; the patches are not committed. The seed counts below come from those runs, with `KINSHIP_SEEDS` raising the number of seeds.

## Severity

| Severity | Meaning |
| --- | --- |
| High | Membership goes wrong in ordinary operation, or an attacker without a key changes it. |
| Medium | A guarantee in design.md breaks in ordinary operation, or membership goes wrong under a valid configuration that is not the default. |
| Low | Goes wrong only after an unlucky combination of events, or weakens a margin without breaking a guarantee on its own. |

## Findings

| ID | Severity | Finding | Test | Status |
| --- | --- | --- | --- | --- |
| KP-01 | High | A new node that first hears another new node keeps its replay floor far behind cluster time | `kp01_a_restarted_node_refuses_recordings_older_than_the_window` | Fixed |
| KP-02 | Medium | leave() spends its sends on members that left, so nodes leaving in a scale-down are reported dead | `kp02_nodes_that_leave_one_after_another_are_never_reported_dead` | Fixed |
| KP-03 | Medium | Config accepts limits in which a member's own Alive never fits a datagram | `kp03_a_member_with_full_metadata_survives_a_pause` | Fixed |
| KP-04 | Low | A rumour about a node below its incarnation is dropped silently, so the buddy system cannot clear a stale suspicion | `kp04_a_member_that_answers_the_buddy_ping_is_not_declared_dead` | Fixed |
| KP-05 | Low | Merging a push-pull counts this node as an independent confirmation of every suspicion in it | `kp05_a_node_confirms_only_suspicions_its_own_probe_raised` | Open |

### KP-01 A new node that first hears another new node keeps its replay floor far behind cluster time

**Severity:** High. **Attacker:** no key. **Status:** Fixed.

`Replay::accept` (`crates/kinship-core/src/replay.rs:143`) moves the floor straight to the window behind cluster time only for the first packet a node authenticates. After that, `Replay::tick` (`replay.rs:102`) lets the floor follow cluster time at twice the node's own clock and half a window per input, which is what absorbs clock jumps. If the first packet comes from a node that is itself behind, such as another process that has just started, the floor stays near zero, and when the seed's reply then teaches the node the real cluster time T, the floor closes the gap only at real-time speed. Until it does, or until the 131,072 remembered nonces force it up (hours at ordinary packet rates), the node accepts every recording newer than its floor that it has not seen itself, which for a new process is every recording. The harm is KS-01's: phantom members, false deaths of members that restarted, and traffic the attacker drives.

The ordinary trigger is two seed nodes that restart within a round trip of each other and list each other as seeds. join() pushes and pulls with every seed at once, so each one's request reaches the other before the far seed's reply comes back. An attacker can force the same state on any restart by delivering one old recording before the seed's reply arrives. SECURITY.md lists that race under KS-01's "What remains" and rates it Low because "the window is one round trip at startup"; the window is in fact as long as the gap to cluster time.

The simulator's restart hands a new instance the shared clock, so none of the existing sweeps run a node that starts behind cluster time. The test wraps each node in a process clock that starts at zero, as kinship-net's does.

**Reproduction:** five nodes run for 600 s. An attacker records what n0 receives while n4 changes its metadata and leaves, around 300 s. At 600 s n0 and n1 restart as new processes and join through each other and n2. At 720 s, two minutes after n0 joined, the attacker replays the recording: n0 accepts every datagram, sealed 410 to 430 s earlier, and n4 joins again on all four running nodes. 8 of 8 seeds fail. With only n0 restarting, the same replay is dropped in 8 of 8 seeds. With only n0 restarting but one old recording delivered before its join, a replay 80 s after the join is accepted again in 8 of 8.

**Recommended fix:** move the floor to the window behind cluster time on every adoption while the node is younger than the window or has not completed a join, not only on the first. A throwaway patch that keeps snapping while the node is younger than the window makes the test pass and keeps every other core and simulator test green. Then correct the first "What remains" bullet of KS-01.

**Fix:** until a node has completed a join, and whenever a join of its own is in flight, every cluster time it adopts moves its floor straight to the window behind it (`Replay::accept`, told by `Node::accept_stamp`). A join is complete on both sides once a seed answers it, and a node handed its members with `add_member` counts as joined. In the test, n0's join is still waiting on n2 when n2's reply brings the cluster's time, so the floor follows it at once and the replay is dropped. The age condition was left out: it fails the clock-jump sweep in `failure.rs`, whose jumps land 5 to 15 s after start, in 2 of 1,000 seeds with a live node declared dead, because every node that adopts the jumped clock then drops the packets of those that have not adopted it yet. A node that has joined keeps the gradual floor at any age, and KS-01's first "What remains" bullet now describes what is left. Unit tests: kinship-core `replay::tests::a_settling_node_moves_its_floor_with_every_time_it_adopts` and `tests::until_it_has_joined_a_node_moves_its_floor_with_every_time_it_adopts`.

### KP-02 leave() spends its sends on members that left, so nodes leaving in a scale-down are reported dead

**Severity:** Medium. **Status:** Fixed.

`Node::gossip` (`broadcast.rs:311`) sends to live members and to every member whose state changed within `gossip_to_the_dead`, which includes members that left. design.md limits gossip to the dead, and memberlist sends only to alive, suspect and recently dead members: a dead member may be alive and need to refute, but one that left has closed. leave() (`sync.rs:472`) sends its Left rumour to `gossip_nodes` such targets at once, and `check_leave` (`sync.rs:488`) declares it done after `retransmit_limit` sends, counting sends to members that left, or are dead, like any other. When several nodes leave one after another, the last ones can spend every send on members that already left, return, and close having told no live member. The live members then probe them, suspect them and report MemberDead, which design.md's Failure modes table says a graceful leave never causes.

**Reproduction:** ten nodes. n3 to n9 leave a second apart, each closing as soon as its leave() returns. 3 of 16 seeds fail, 44 of 200: a survivor reports one of the last nodes to leave dead. With members that left removed from the gossip targets, 200 of 200 pass.

**Recommended fix:** gossip only to live members and to members dead for less than `gossip_to_the_dead`, as memberlist does. leave() should also count only the sends that went to members it holds alive, so that a leave whose sends all went to dead members is not done.

**Fix:** as recommended. `Node::gossip` sends to Alive and Suspect members and to members declared Dead less than `gossip_to_the_dead` ago, never to members that left. leave() queues its Left rumour so that only sends to members it holds live, Alive or Suspect, count towards `retransmit_limit` (`Broadcasts::push_to_live`); sends to the dead still go out, in case one of them is alive and refutes, but do not finish the leave. Suspect counts as live because it is still a member and usually alive, and because the leave already ends when no live member is left to tell; counting only Alive would let one suspected member hold a leave until its timeout. Packets whose recipient this node can only name by address, such as the Ack a relay forwards to a PingReq's requester, count as not live. Unit tests: kinship-core `tests::gossip_goes_to_live_and_recently_dead_members_never_to_those_that_left` and `sync::tests::a_leave_counts_only_sends_to_live_members`.

### KP-03 Config accepts limits in which a member's own Alive never fits a datagram

**Severity:** Medium: it needs a limit changed from its default, but then a live member is declared dead whenever it is suspected. **Status:** Fixed.

design.md says set_meta's 512-byte cap means "one Alive always fits in a datagram with room for a probe", but `Config::validate` (`config.rs:135`) only asks that a datagram hold the packet overhead and three bytes. An Alive with `max_meta_bytes` of metadata, a 64-byte name and an IPv6 address is 607 bytes, so with encryption any `udp_max_payload` below 657 (576, the IPv4 minimum, for one), or any `max_meta_bytes` above 1,255 with the default datagram, lets a member hold an Alive that no packet can carry. `Broadcasts::select` (`broadcast.rs:159`) skips it every time and `Broadcasts::sent` (`broadcast.rs:178`) never drops it, so the member's metadata never spreads by gossip, its refutations never leave it over UDP, and its gossip timer fires every `gossip_interval` for as long as it runs. Only push-pull carries its Alive.

It also leaves the cluster holding the member at an old incarnation: set_meta raised it locally and nobody heard. Suspicions then arrive below the member's own incarnation, and it ignores them (KP-04), so it does not even try to refute.

**Reproduction:** ten nodes with `udp_max_payload` 576 and every other field from `lan()`. n5 sets 512 bytes of metadata, then stalls for 3 s, as in a long GC pause. Its Alive is 533 bytes, and a 576-byte datagram has 528 for its messages and their count. In 8 of 8 seeds some node declares n5 dead within 10 s of the stall ending. The same run with the default 1,400-byte datagram passes 100 of 100 seeds.

**Recommended fix:** refuse limits under which an Alive with `max_meta_bytes` of metadata, a 64-byte name and an IPv6 address does not fit a datagram beside a Ping (the test passes when the config does not validate), or cap set_meta at what fits. Either way, drop and count a queued rumour that can never fit, rather than keeping it forever.

**Fix:** the first option. `Config::validate` measures the largest Alive the limits allow beside the largest Ping, both with 64-byte names and IPv6 addresses, against the room a sealed or plaintext datagram has for its messages, and refuses the limits otherwise. The error names `udp_max_payload` when it is below its default and `max_meta_bytes` otherwise, so with the default 512 bytes of metadata a sealed datagram needs at least 813 bytes, and with the default 1,400-byte datagram metadata can be at most 1,099 bytes. The kinship and Python configs call the same check, and no preset or existing test sets limits it refuses. A rumour too large for any datagram, which validated limits no longer allow, is dropped with anything older queued about its member and counted under the new `gossip_too_large` metric, which `stats()` reports in Rust and Python. The test now asserts that the 576-byte datagram is refused and runs its scenario at the smallest datagram that validates, where the member survives the pause. Unit tests: kinship-core `config::tests::the_largest_alive_must_fit_a_datagram_beside_a_ping` and `broadcast::tests::a_rumour_too_large_for_any_datagram_is_dropped_and_counted`; kinship `config::tests::bad_fields_are_named_before_binding`; Python `test_config.py::test_bad_fields_raise_config_error_naming_the_field`.

### KP-04 A rumour about a node below its incarnation is dropped silently, so the buddy system cannot clear a stale suspicion

**Severity:** Low: a node has to miss a refutation entirely, and no push-pull may reach it before its suspicion runs out. **Status:** Fixed.

`Node::on_suspect` and `Node::on_dead` (`member.rs:128` and `member.rs:179`) ignore a Suspect or Dead about this node below its incarnation. A node that still holds such a suspicion missed the refutation, and nothing tells it now. The buddy system puts the Suspect first in the Ping (`probe.rs:137`), the member ignores it, and its Ack carries nothing, so the prober declares dead a member that answers its Pings. design.md says the buddy system's Ack "already carries the refutation"; for a stale suspicion it does not. In SWIM the successful probe would clear the suspicion; with incarnations only the member can, so it has to refute again.

**Reproduction:** six nodes; n0 hears nothing for 3.5 s. Its probe round in progress fails and it suspects the target, which refutes at once, and the refutation has finished spreading before n0 hears again. n0 then pings the member with the suspicion first, gets direct Acks, and declares it dead when the suspicion runs out 24 s after it began, unless a push-pull repairs n0 first. 2 of 32 seeds fail, 11 of 200. With the member queuing its own Alive again when it hears a stale suspicion, 200 of 200 pass.

**Recommended fix:** when a node that has not left hears a Suspect or Dead about itself below its incarnation, queue its Alive at its current incarnation again, without raising local health. The Ack to a buddy Ping then carries the refutation.

**Fix:** as recommended, in `Node::on_suspect` and `Node::on_dead` (`Node::reassert`). The Alive replaces whatever is queued about the node with a fresh entry, so it goes first into the Ack's packet, and neither the incarnation, local health nor the `refutations` counter moves. Unit test: kinship-core `tests::a_stale_rumour_about_this_node_queues_its_alive_again`.

### KP-05 Merging a push-pull counts this node as an independent confirmation of every suspicion in it

**Severity:** Low.

`Node::merge` (`sync.rs:284`) turns a peer's Suspect or Dead record into a Suspect from this node (`sync.rs:303`). If this node already suspects the member, it counts itself as a fresh confirmation and gossips the Suspect under its own name; if not, it starts a suspicion with itself as the reporter and gossips that. Every other node then counts it as one more independent confirmation. Lifeguard shrinks the timeout only with independent suspicions, and design.md defines a confirmation as a Suspect "from a member that has not reported this suspicion yet, this node included when its own probe fails". A merge is not a probe, so anti-entropy alone can take a suspicion from the maximum timeout to the minimum and take away the time Lifeguard gives a slow member to refute. memberlist's merge does the same; it still diverges from the paper and from design.md.

**Reproduction:** ten nodes; n9 crashes. The test reads every node's datagrams with the cluster key and flags a Suspect that a node signs with its own name, sends to anyone but the suspect, about a member it never sent a PingReq for, that is, never probed without an answer. 2 of 8 seeds fail, 53 of 100, and each flagged Suspect goes out at the instant its node merged a push-pull frame. With suspicions from merges turned off, 100 of 100 pass.

**Recommended fix:** start a suspicion learned from a push-pull at the maximum timeout with no reporter that counts, and leave an existing suspicion as it is when a merge repeats it. Keep the conversion of Dead records into suspicions, which is what heals partitions.

## Divergences that are not bugs

- A probe round whose end passes while the node is not running, after a clock jump or a pause past the round, ends without its indirect phase (`probe.rs:71`): the target is suspected without a PingReq, and local health rises by one rather than by one per relay. SWIM suspects only after indirect probes fail. `crates/kinship-sim/tests/failure.rs` documents and tests this as the effect of a clock jump; design.md does not mention it.
- Members that join during a pass of the probe list wait for the next pass (`table.rs:90`), where SWIM inserts them at a random position. The worst case stays at 2n - 1 rounds, and only a comment in table.rs records the choice.
- A successful probe of a suspected member does not clear the suspicion; only an Alive at a higher incarnation does, as design.md's state diagram and incarnation table say and as memberlist does. KP-04 was the case where that let a live member die; since its fix the member sends its Alive again.
- A Dead loses to an Alive at a higher incarnation, where SWIM's Confirm overrides everything; local health follows memberlist's rules rather than adding one for every failed round; and K is capped at n - 2 where memberlist sets it to 0. design.md documents all three.
- design.md's transport table sends the TCP fallback ping "when the UDP probe and all indirect probes fail"; the code sends it alongside the indirect probes, as the sequence diagram above that table shows and as memberlist does.
- Every node advertises vmin and vmax, but nothing reads them: packets always go out at `WIRE_VERSION`, where design.md says a node sends the highest version every live member speaks. This is harmless while there is one version.

## Checked and found consistent

- Incarnation precedence for Alive, Suspect, Dead and Left, in gossip and in push-pull merges, follows design.md's table: no Dead overrides a newer Alive, stale rumours lose, and tombstones yield only to a higher Alive. A refutation raises the incarnation past the rumour, never happens after a leave, and raises local health only for Suspect and Dead. Saturation at u32::MAX is KI-02.
- The Lifeguard timeout: T_min, T_max, the cap of K at n - 2 and the fixed-point log2 and log10 match the floating-point formula, as the unit tests in `suspicion.rs` check. Confirmations count distinct reporters at one incarnation, and a higher incarnation starts a fresh timer. Instants and durations saturate, and the only arithmetic that can overflow needs configured values far outside any sensible range.
- Local health moves by the rules design.md states, stays within 0 to `awareness_max`, and scales both the probe interval and the probe timeout.
- Nack timing: a relay sends its Nack at 80% of the shortest indirect phase a healthy requester runs, from the unscaled configuration, so it lands in time for every preset with a round trip below the remaining fifth (100 ms on lan(), 400 ms on wan()).
- Probe order: every pass is a uniform shuffle of the live members, and relays, gossip targets and push-pull peers are uniform samples. No bias found.
- The broadcast queue packs least sent and newest first, then fills the remaining space first-fit, so large metadata does not crowd out small rumours that still fit; KP-03 is the case where the metadata itself never fits.
- Tombstones are reaped after `dead_reclaim` or the replay window, whichever is longer. Suspicions, relays, outbound streams, joins and remembered nonces all end, so nothing grows without bound beyond the member table itself (KI-04).
- join() retries with backoff only while no seed has answered, and finishes on the first answer once no attempt is in flight. A request a seed finds stale costs one more exchange, as design.md says.

## Note on an open finding

KI-06 does not need a compromised member. A node whose cluster time is far ahead for an honest reason moves every node's floor the same way: for instance one that kept running, cut off, while the rest of the cluster restarted and cluster time began again near zero, and that then rejoins. SECURITY.md's recommended fix, cluster time per key, does not cover that case.
