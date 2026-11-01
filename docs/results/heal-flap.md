# Partition-heal flap

After a partition heals, members that never stopped running went MemberDead and then MemberJoined on the side that was not cut off, and `kinship.ring` users moved their keys twice. The Compose demo showed it twice on 2026-10-13, with one node disconnected for 20 to 40 s; partitions of about 10 s did not. memberlist behaves the same way. The finding is KP-06 in [the protocol review](../review.md#kp-06-after-a-partition-heals-the-node-that-was-cut-off-gossips-the-deaths-it-declared-and-healthy-members-flap-dead).

**Result.** On origin/main, 429 of 1,000 seeds of a new sweep, which cuts off one node or a minority side for longer than the suspicion timeout and heals it, show a member that never stopped declared dead by a node that was not cut off; 111 of 250 in mode `sign`. With the fix none do: 1,000 seeds in mode `off` and 1,000 in mode `sign`, and 4,000 in `off` with the prototype it came from. Every existing 1,000-seed sweep in `off` passes, so do the `_signed` twins at 250 seeds, and crash detection in the tuning cells at 50 and 200 nodes is unchanged but for the tail of one cell. The cost is that a node which doubts its own view, mostly one on the minority side of a partition, declares the far side dead on its own timer only, which in the SWIM sweep moves detection across a partition from 13.4 to 15.5 s at the median and 166 to 217 s at the 99th percentile.

## Cause

The sweep's trace shows two ways a death crosses the heal, and the push-pull that heals the partition is neither: it already turns a peer's Dead record into a suspicion that is not gossiped.

1. **A suspicion that runs out after the heal.** The cut-off node suspects the members it cannot reach. Its Suspect rumours are spent on members it cannot reach, so the suspected members never hear of them, and its local health at the ceiling stretches its probe rounds to 9 s, so it does not probe them again before the suspicion ends. Once the partition heals, the suspicion runs out, from a fraction of a second to many seconds later, and the node gossips the fresh Dead to peers that can now hear it. A Dead wins over an Alive at the member's incarnation, so each peer marks the member dead until its refutation arrives. Seed 1, six nodes, n3 cut off for 33.3 s: n3's suspicion of n0, started 21 s before the heal, ends 3.0 s after it, and n2, n4 and n5 declare n0 dead in the same millisecond, then take it back when n0's refutation arrives. Seed 8, 50 nodes and a minority of 20: n39's suspicion of n20, started at the split, runs its full 40.8 s and ends 17.3 s after the heal, and 47 nodes declare n20 dead.
2. **A Dead declared just before the heal**, still being gossiped on the minority side when the heal lets it across. Seed 437, 50 nodes and a minority of 12: n19 declares n14 dead at the instant of the heal, at local health 0, and the Dead reaches the far side a millisecond later.

## Fix

A node that doubts its own view keeps the deaths it declares to itself (`Node::keep_dead` in `crates/kinship-core/src/suspicion.rs`, [design](../design.md#lifeguard)):

- A node doubts itself while its local health is above zero, or while it holds no more than half of the members it knows, itself included and members that left not, as Alive (`Node::doubts_itself`).
- A suspicion is doubted if the node doubted itself when it started, at the end of any probe round while it ran, or when local health rose (`Node::doubt`).
- A suspicion that ends doubted, or while the node doubts itself, applies its Dead on this node: MemberDead, a tombstone that push-pull carries as any other. It gossips nothing, and sends only the member a Suspect, as a merged suspicion does, so that the member refutes if it is alive and can hear.

The fix was chosen by running variants on the sweep's first version, whose cuts ended before any tombstone could be reaped and where origin/main failed 319 of 1,000 seeds. Each line gives the seeds that still had a false death:

| Variant | Seeds |
| --- | ---: |
| Local health at the ceiling when the suspicion ends; the Dead gossiped as a Suspect | 225 |
| No more than half held Alive when it ends; gossiped as a Suspect | 157 |
| Either of the two; gossiped as a Suspect | 119 |
| Local health above zero, or no more than half held Alive, when it ends; gossiped as a Suspect | 5 |
| Local health above zero at any time while it ran; gossiped as a Suspect | 7 |
| The same, but kept on the node and told to the member only | 7 |
| Kept; local health above zero at any time, or no more than half held Alive when it ends | 1 |
| Kept; either, at any time while it ran (the fix) | 0, and 0 of 6,000 |

Local health misses the minority side, whose own relays send the Nacks that keep its health at zero, and the share of members held Alive misses a lone node in a 50-node cluster, which has suspected only the few members its slow rounds reached. Checking only when the suspicion ends misses the suspicions of case 1 that end after the node regained contact. Gossiped as a Suspect, a doubted death still put suspicions on healthy nodes that counted the cut-off node as a confirmation, and in one seed such a suspicion, shortened by confirmations from several cut-off nodes, ran out before the member's refutation reached every node, since a heal floods the queues with refutations. With the marks kept for the whole suspicion, gossiping it as a Suspect also left no false death in 2,000 seeds of the final sweep, but up to twice the false suspicions on the side that was not cut off (59 per run at 50 nodes with one cut off, against 28). Keeping the Dead and telling the member is what a merged push-pull record already does.

What stays the same:

- **A real failure is declared.** A failed probe still gossips its Suspect, every node that hears it runs its own suspicion, and every node probes the member itself. A doubting node gives up only the shortcut by which its Dead ends the others' suspicions early; when every node doubts itself, as after more than half the cluster failed at once, each declares the failures when its own suspicion ends, at most T_max after it heard the first Suspect.
- **Convergence.** The doubting node's tombstone goes into push-pull, the peer merges it as an unreported suspicion and tells the member, so the partition heals as before: the sweep's reconvergence after the heal is 3.5 s at the median, 30.5 s at the 99th percentile.
- **Precedence and wire.** No rule of the incarnation table changes and no byte on the wire. Mode `sign` takes the same path; a kept Dead is not signed, since nothing sends it.

The other candidates: having a node that just regained contact hold back its Dead rumours until its next probe pass would not catch case 2, since the node never lost contact with its own side, and the "regained contact" moment is not visible to a minority node. Stretching the suspicion timeout by local health delays case 1 without removing it, misses minority nodes at health 0, and changes when a node that is merely slow declares anything. Telling the doubted node's own side apart is what the share of members held Alive does.

## The new sweep

`sync::a_healed_partition_declares_no_running_member_dead_thousand_seeds` and its `_signed` twin, which the `sim-sync` and `sim-signed` CI jobs run with the other `sync` sweeps:

```bash
cargo test --release -p kinship-sim --test sync -- --ignored --nocapture a_healed_partition
```

Half the seeds run 6 nodes, as the Compose demo does, half 50. Half cut off one node, half a minority of 2 to 24. Links have up to 1% loss, sometimes 40 ms of latency, and a little duplication and reordering. The cut lasts from half the longest suspicion (12 s at 6 nodes, 20.4 s at 50) to 15 s past it (39 s, 55.8 s), then heals. A reconnect heals it, or, where both sides have already reaped the tombstones it would use, a join from the cut-off side to a node on the other, as kinship-net's rejoin of its seeds would (1 to 8 seeds in 1,000). A false death is a MemberDead on a node that was not cut off about a member that was not either, at any time; false suspicions after the heal are counted beside. Every node must hold every member live within `heal_bound` of the heal, or of the join, and at the end.

| Runs | origin/main, `off` | This branch, `off` | origin/main, `sign`, 250 seeds | This branch, `sign` |
| --- | --- | --- | --- | --- |
| 6 nodes, one cut off | 417 false deaths in 98 of 249 runs | 0 | 99 in 26 of 69 | 0 in 249 runs |
| 6 nodes, a minority cut off | 291 in 83 of 263 | 0 | 87 in 20 of 58 | 0 in 263 |
| 50 nodes, one cut off | 8,179 in 100 of 248 | 0 | 1,761 in 23 of 56 | 0 in 248 |
| 50 nodes, a minority cut off | 14,105 in 148 of 240 | 0 | 4,118 in 42 of 67 | 0 in 240 |
| Seeds with a false death | 429 of 1,000 | 0 of 1,000 | 111 of 250 | 0 of 1,000 |

False suspicions after the heal, which the push-pull that heals the partition causes and the members refute, are about what they were: 847, 668, 6,880 and 18,175 on origin/main against 844, 629, 6,951 and 18,713, in the rows' order. Those are MemberSuspect events, and `Ring` keeps a suspect's keys. With the fix the prototype also passed seeds 0 to 3,999 in `off`.

`review::kp06_a_healed_partition_declares_no_running_member_dead` is the Compose demo's Partition in the simulator: six nodes on `lan()`, n3 cut off for 20 to 40 s. 19 of 32 seeds fail on origin/main, none on this branch.

## Existing sweeps

Every 1,000-seed sweep in `off` and every `_signed` twin at 250 seeds passes, on the 4-core Ryzen 5 3550H laptop, release build:

| File | `off`, s | `sign`, 250 seeds, s |
| --- | ---: | ---: |
| `sim` | 7 | |
| `swim` | 76 | 199 |
| `sync`, with the new sweep | 154 | 426 |
| `keyring` | 16 | 70 |
| `failure` | 148 | 402 |
| `epoch` | 4 | 7 |
| `usermsg` | 3 | 7 |
| `digest` | 9 | |

Against origin/main, as [digest.md](digest.md#sweeps) gives it (p50, p99, max, 1,000 seeds):

| What | origin/main | This branch |
| --- | --- | --- |
| A healed partition reconverges (`sync` heal) | 1.25 s, 18.25 s, 25.5 s | 1.25 s, 20.5 s, 28.75 s |
| Metadata reaches every node (`sync` metadata) | 75 ms, 374 ms, 29.4 s | 75 ms, 374 ms, 29.4 s |
| A long partition, after the join that merges it (`failure`) | 9.75 s, 42.25 s, 62 s | 8.75 s, 45.5 s, 64.25 s |
| A restart at a lower incarnation, Alive everywhere (`failure`) | 210 ms, 880 ms, 29.9 s | 210 ms, 880 ms, 29.9 s |
| `swim`: crash detections, 59,579 | 8.50 s, 12.30 s, 14.9 s | 8.51 s, 12.31 s, 17.6 s |
| `swim`: detections across a partition, 137,784 | 13.4 s, 166 s, 478 s | 15.5 s, 217 s, 473 s |

The `swim` rows split its 197,363 detections, all within their bounds on both, into crashes and failures across a partition (a node split from the observer, or failed while a partition started); its own summary gives p50 10.05 s on origin/main and 10.24 s here. Crash detection keeps its p50 and p99, and its slowest moves 2.7 s. Across a partition the side that doubts itself, the minority side, now waits for its own suspicions rather than the first one among its members to end, which `partition_bound` allows; a node on that side keeps the far side as Suspect rather than Dead somewhat longer, which keeps its ring's keys where they were. A healed partition's reconvergence is within its bound in every run.

**The pinned SWIM trace** changes, because a node in it doubts itself. In the 10-node run on seed 1, with 3.7% loss, n3's local health had risen while it suspected n9, so n3 no longer gossips n9's death; n8, n0, n5, n1, n6 and n7 each declare n9 when their own suspicion ends, at most 0.5 ms after n3's Dead used to reach them. The run has the same 34 events; only those six moved. The digest is 0xf9a7_2228_3681_b839, and 0xe848_2637_7439_2a45 with `KINSHIP_PUSH_PULL_DIGEST=0`.

## Tuning cells

`lan` on the screen's cells and seeds at 50 and 200 nodes (stage `heal` in [tuning.csv](tuning.csv), `heal_verdict` in `tests/tuning.rs`), against stage `screen`, half an hour on the laptop:

```bash
cargo test --release -p kinship-sim --test tuning -- --ignored --nocapture --exact heal
cargo test --release -p kinship-sim --test tuning -- --ignored --nocapture --exact heal_verdict
```

| Nodes | Cells | Bandwidth, mean | Bandwidth, worst | p50 change (s) | p99 change, mean (s) | p99 change, worst (s) | False deaths per run, before | After | Undetected |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 50 | 16 | 1.000 | 1.002 | +0.00 | +0.11 | +1.74 | 0.11 | 0.05 | 0, 0 |
| 200 | 16 | 1.000 | 1.001 | +0.00 | +0.01 | +0.07 | 0.00 | 0.00 | 0, 0 |

Detection p50 moves by at most 0.02 s in any cell. p99 is the same in 22 of the 32 cells and within 0.07 s in 9 more; in the cell with 5% loss and 10% starved nodes at 50, it goes from 13.57 to 15.31 s and the slowest from 13.82 to 15.98 s, with the mean 9.26 to 9.31 s: in a run or two the first node whose suspicion of the crashed member ended had doubted itself, a starved node or one that 5% loss had cost a Nack, and the others waited for their own. False deaths of starved nodes fall from 11 to 5 in the 1,600 runs at 50 nodes, since a starved node's verdicts now stay with it. Bandwidth does not change.

## Checks

On this branch: `cargo fmt --all --check`; clippy with WSL stable (`--workspace --all-targets --locked -D warnings`); `cargo +1.87 check --workspace --locked`; `cargo deny check advisories bans sources`; `cargo test --workspace --exclude kinship-py --locked --no-fail-fast`; `uv run maturin develop && uv run pytest` (113 passed, 3 skipped); and 120 s of the `node_input` fuzz target in WSL (12,818 runs, no crash). All pass.
