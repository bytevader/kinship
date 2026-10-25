# Push-pull scaled with the cluster

Anti-entropy push-pull sends the whole member table both ways, and every node started one every 30 s at any cluster size, so in a settled 1,000-node cluster it was 96% of the bytes in mode `off` (6.0 of 6.2 KB/s per node) and 83% in `sign` ([signed.md](signed.md#cost)). The period now stretches with the cluster as memberlist's pushPullScale does: `push_pull_interval` up to 32 live members, this node included, then `ceil(log2(n) - log2(32)) + 1` times it ([design](../design.md#join-and-push-pull)).

| Live members | Up to 32 | 33 to 64 | 65 to 128 | 129 to 256 | 257 to 512 | 513 to 1,024 | 8,192 |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Multiplier | 1 | 2 | 3 | 4 | 5 | 6 | 9 |
| Period with `lan()` | 30 s | 60 s | 90 s | 120 s | 150 s | 180 s | 270 s |

**Result.** In mode `off` a settled node sends 50% fewer bytes at 100 nodes (789 to 392 B/s) and 80% fewer at 1,000 (6,232 to 1,234 B/s); push-pull falls by the multiplier, to a third and a sixth. Detection is untouched: the 50-node SWIM sweep finds the same 197,363 detections at the same p50. What it costs is repair time where only push-pull repairs: at 50 nodes a healed partition's p99 goes from 21.8 s to 45.8 s and a rumour that gossip missed waits up to 59.7 s instead of 29.7 s, twice as long, as the doubled period predicts. Nothing changes up to 32 members: the pinned 10-node SWIM trace is the same, and so is every sweep of 20 nodes or fewer.

**Mode `sign` keeps the fixed period.** With the period scaled there too, the 1,000-seed sweeps in `sign` failed in ways `off` cannot, because signing nodes repair more through push-pull ([below](#mode-sign)). So the scaling applies in mode `off`, the default, as the brief's "in mode `off` first" asked, and signing nodes push-pull every `push_pull_interval` as before; their costs are those of [signed.md](signed.md#cost).

## The change

- `Config::push_pull_interval_for(members)` in kinship-core gives the period for a cluster size; `push_pull_interval` keeps its meaning as the base, and 0 still disables periodic push-pull.
- The node keeps when its last push-pull was due, and the next is due one period, for the live members it holds at that moment, after it. The deadline is derived again whenever the driver asks for the next timeout, so it follows the cluster as it grows or shrinks; a cluster that shrinks has its next push-pull pulled in, at once if it is already due. Missed ticks are skipped, as before.
- The first push-pull is still staggered within `push_pull_interval` of the start, so a node that starts with a 1,000-member static list still makes its first exchange within 30 s, as memberlist does.
- Reconnects to dead members stay on `reconnect_interval`, rejoins with seeds on `rejoin_interval`, and joins are unchanged.
- A node in mode `sign` keeps `push_pull_interval` at every size.
- The simulator's bounds that counted one push-pull period (`dissemination_bound` in the sync, failure and keyring tests, `settle_bound` in swim, the restart in epoch, the long partition in failure) now take the scaled period for the cluster they run.

## Sweeps

Every 1,000-seed sweep, in `off` on a 4-core Ryzen 5 3550H laptop, on this branch and on origin/main (1cdb6ec) for comparison, release build. Every one passes in both. The `_signed` twins are below.

| Sweep | Seeds x nodes | Period after | Passes | origin/main, s | This branch, s |
| --- | --- | ---: | --- | ---: | ---: |
| `swim` SWIM properties on random faults | 1,000 x 50 | 60 s | yes | 75 | 76 |
| `sync` a new node joins 200 | 1,000 x 200 | 120 s | yes | 57 | 58 |
| `sync` a node that left is never reported dead | 1,000 x 50 | 60 s | yes | 27 | 28 |
| `sync` a healed partition reconverges | 1,000 x 50 | 60 s | yes | 29 | 31 |
| `sync` metadata reaches every node | 1,000 x 50 | 60 s | yes | 9 | 9 |
| `epoch` nodes without epochs among newer ones | 1,000 x 10 | 30 s | yes | 4 | 4 |
| `epoch` rumours about an earlier life | 1,000 x 8 | 30 s | yes | 2 | 1 |
| `usermsg` user messages, beside 0.3.0 nodes | 1,000 x 5 to 16 | 30 s | yes | 3 | 3 |
| `failure` a clock jump | 1,000 x 50 | 60 s | yes | 20 | 26 |
| `failure` a partition longer than `dead_reclaim` | 1,000 x 50 | 60 s | yes | 72 | 84 |
| `failure` a restart at a lower incarnation | 1,000 x 50 | 60 s | yes | 32 | 42 |
| `failure` a restart without an epoch | 1,000 x 50 | 60 s | yes | 31 | 41 |
| `failure` a second node with a live name | 1,000 x 50 | 60 s | yes | 11 | 15 |
| `keyring` a node that falls behind | 1,000 x 20 | 30 s | yes | 8 | 8 |
| `keyring` rotating every node | 1,000 x 50 | 60 s | yes | 10 | 10 |

The failure sweeps run longer because their scenarios last as long as their bounds, which grew with the period.

### Mode `sign`

Every `_signed` twin passes on all 1,000 seeds with mode `sign` on the fixed period, on the laptop: `swim` 665 s, `sync` join 531 s, leave 356 s, heal 294 s, metadata 153 s, `epoch` 10 s and 17 s, `usermsg` 26 s, `failure` clock jump 370 s, long partition 772 s, restart 502 s, name conflict 254 s, `keyring` 86 s and 193 s. Their bounds grew with the scaled period, which signing nodes do not use, so they hold `sign` to looser bounds than `off`, never tighter.

With the period scaled in `sign` as well, three seeds failed, each a false death that `off` cannot have:

- **A member that left reported dead** (`sync` leave, seed 116 of 1,000). A node that started from a static list still held the leaver without its certificate, so it dropped the signed Left, kept probing the member, and declared it dead 64 s later. Signing nodes learn most certificates from version 2 push-pull records; with 30 s it had one before its suspicion ran out, with 60 s it did not. On the same seed origin/main ends with no member held unsigned.
- **A restart reported dead** (`failure` restart, seeds 554 and 209). Gossip missed the new life at one node, which learned of the restart only from its next push-pull, 51 s after it. Meanwhile it suspected the old life, and in mode `sign` the new life's Acks, signed under a key it did not hold yet, could not refute that suspicion, so the old life was declared dead 41 s after the restart. In `off` the new process answers the old life's Pings and nothing is suspected.

Keeping the base period only while a node held members unsigned fixed seeds 116 and 554, but not seed 209, whose node held every member signed. So mode `sign` keeps the fixed period at every size, and both failure modes are left to the KI-01 work that would remove them (Decisions).

### Repair

What the sweeps measure that push-pull repairs, `off`, 1,000 seeds at 50 nodes, where the period doubles from 30 to 60 s (p50, p99, max):

| What | origin/main | This branch |
| --- | --- | --- |
| A healed partition reconverges (`sync` heal) | 1.25 s, 21.75 s, 29.5 s | 1.25 s, 45.75 s, 57 s |
| Metadata reaches every node (`sync` metadata) | 75 ms, 375 ms, 29.7 s | 75 ms, 375 ms, 59.7 s |
| The deliveries gossip missed, of about 99,000 | 26: 14.4 s, 29.7 s, 29.7 s | 31: 34.7 s, 59.7 s, 59.7 s |
| A long partition, after the join that merges it (`failure`) | 8.75 s, 41.75 s, 62 s | 12 s, 58 s, 97.25 s |
| A restart at a lower incarnation, Alive everywhere (`failure`) | 210 ms, 2.01 s, 27.7 s | 210 ms, 2.41 s, 57.7 s |
| A restart without an epoch (`failure`) | 310 ms, 2.41 s, 27.7 s | 310 ms, 2.11 s, 57.7 s |

The tails double, the medians do not move: gossip still does nearly all the work (99.97% of the metadata deliveries within 4.6 s on both), and push-pull only catches what it missed. A healed partition is repaired by reconnects to dead members, still every 30 s, but the refutations the reconnect starts reach a node that missed them through push-pull. Detection, joins, leaves, name conflicts, clock jumps and the keyring sweeps change by nothing or within noise; the 20-node keyring sweep and the epoch sweeps of 8 and 10 nodes do not scale at all.

By the same bounds, a rumour gossip missed in a 200-node cluster waits up to 120 s, and up to 180 s at 1,000 nodes, against 30 s before. That is inferred from the period; the costs runs below show the 1,000-node tail.

## Cost

`crates/kinship-sim/tests/costs.rs` on its seven clusters ([signed.md](signed.md#cost) for the setup: `lan()`, sealed, 17-byte names, 48 bytes of metadata set by every member between 1 and 5 s, a crash at 240 s, every node starting from a static list of every other; burst 5 to 150 s, steady 150 to 330 s). It also records, for every node and member, when the member's new metadata reached the node. The rows are in [pushpull-costs.csv](pushpull-costs.csv); origin/main's `off` rows, rerun with the same harness, match [signed-costs.csv](signed-costs.csv) to the byte.

```bash
KINSHIP_COSTS_CSV=pushpull-costs.csv cargo test --release -p kinship-sim --test costs -- --ignored --nocapture --exact costs
```

Bytes per node per second, mode `off`, before (origin/main) and after:

| Cluster | Window | Push-pull before | After | Total before | After | Change |
| --- | --- | ---: | ---: | ---: | ---: | ---: |
| 100 | burst | 596 | 221 | 979 | 604 | -38% |
| 100 | steady | 598 | 200 | 789 | 392 | -50% |
| 100, seed 1 | steady | 599 | 200 | 784 | 412 | -47% |
| 100, stress | burst | 596 | 221 | 1,922 | 1,531 | -20% |
| 100, stress | steady | 599 | 200 | 1,666 | 1,263 | -24% |
| 100, 10 on 0.4.0 | steady | 598 | 240 | 799 | 433 | -46% |
| 100, user messages | steady | 599 | 200 | 7,963 | 7,583 | -5% |
| 1,000 | burst | 6,002 | 1,033 | 15,794 | 10,826 | -31% |
| 1,000 | steady | 5,999 | 1,001 | 6,232 | 1,234 | -80% |
| 1,000, stress | burst | 5,999 | 1,030 | 21,414 | 16,459 | -23% |
| 1,000, stress | steady | 5,999 | 1,001 | 12,683 | 7,666 | -40% |

Every other carrier, probes, rumours, headers and tags, TCP fallback pings and user messages, stays within noise; the rumours of `100, seed 1` move by 15 B/s with the order of events. Push-pull falls by the multiplier exactly, to a third at 100 nodes and a sixth at 1,000. The 0.4.0 nodes of the mixed cluster do not scale, so its push-pull is 240 B/s rather than 200. Under stress what remains is mostly the rumours about starved nodes, which this change does not touch, and with user messages it is the messages.

Metadata spread, every update to every node that holds it (p50, p99, max), and the share that took longer than gossip should (5.4 s at 100 nodes, 6.2 s at 1,000):

| Cluster | Before | After | Later than gossip |
| --- | --- | --- | ---: |
| 100 | 0.40 s, 0.76 s, 1.05 s | the same | 0 |
| 100, stress | 0.42 s, 0.75 s, 1.23 s | the same | 0 |
| 1,000 | 1.41 s, 13.9 s, 47.2 s | 1.41 s, 13.9 s, 47.7 s | 10.2% |
| 1,000, stress | 1.50 s, 14.6 s, 37.1 s | 1.50 s, 14.6 s, 54.5 s | 10.7% |

At 1,000 nodes every member's update in the same four seconds fills the gossip queues, so a tenth of the deliveries take longer than the gossip bound, before and after alike (repair p50 9 s); they arrive by gossip, slowly, not by push-pull, which is why the p99 does not move. Only the last stragglers, which waited for a push-pull, wait longer: 54.5 s against 37.1 s under stress.

Mode `sign` keeps the fixed period, so its costs are those of [signed.md](signed.md#cost). The harness confirms it: its `100` and `100, stress` clusters in `sign` on this branch give the 56 byte rows signed-costs.csv has for them, unchanged.

## Detection and false deaths

The tuning sweep's stage `pushpull` reruns `lan` and `epochs` on the screen's cells and seeds at 200 and 1,000 nodes ([tuning.md](tuning.md#setup)), where the period is 120 s and 180 s, and `pushpull_verdict` compares each row with the same cell and variant in stages `screen` and `signed` of [tuning.csv](tuning.csv). The `signed` variant would repeat its rows, since mode `sign` keeps the fixed period. It runs on the Mac; the result is added here when it arrives.

```bash
KINSHIP_NODES=200 cargo test --release -p kinship-sim --test tuning -- --ignored --nocapture --exact pushpull
KINSHIP_NODES=1000 cargo test --release -p kinship-sim --test tuning -- --ignored --nocapture --exact pushpull
cargo test --release -p kinship-sim --test tuning -- --ignored --nocapture --exact pushpull_verdict
```

These runs last 120 s and start from static lists, so each node makes its one staggered first push-pull and, at 200 and 1,000 nodes, no second; their bandwidth shows the start of a cluster, and [Cost](#cost) the steady state.

## Decisions

- **The stability rule.** [stability.md](../stability.md#configuration) lets a timing default change only with lower detection latency at every size, no more false deaths and at most 10% more bandwidth. This change moves no detection timer and cuts bandwidth; what it gives up is the repair tail above 32 members, which that rule does not measure. It is recorded in the CHANGELOG under Changed, and stability.md now says the scaling is part of `push_pull_interval`'s meaning.
- **Mode `sign` on the fixed period.** Scaling it too needs signing nodes to stop leaning on push-pull: certificates that spread by other means, and a way for a member's later life to refute a suspicion of its earlier one under a key the suspecting node does not hold yet. Both belong with KI-01, paused after Stage 2, and with a version 2 digest push-pull.
- **Next.** [Digest push-pull](../pushpull-digest.md) would take a settled 1,000-node node from 1,234 to about 410 B/s, by inference from record sizes.
