# Digest push-pull

A push-pull sends the whole member table both ways, about 90 bytes a record in the cost harness's clusters, although in a settled cluster the two sides agree on nearly every record. Scaling the period ([pushpull.md](pushpull.md)) sent the table less often but slowed repair and added false deaths at 200 nodes, so it stayed opt-in. Digest push-pull ([design](../design.md#digest-push-pull), [note](../pushpull-digest.md)) keeps the 30 s period and sends a 32-byte entry per member, then whole records only where the two sides differ. It is built for mode `off` and on by default (`push_pull_digest`).

**Result.** With the 30 s period, a settled node sends 62% fewer bytes at 100 nodes (789 to 303 B/s) and 79% fewer at 1,000 (6,232 to 1,304 B/s), as the design note inferred from record sizes (about 1,300). Push-pull itself falls to a sixth: 598 to 110 B/s at 100 nodes, 5,999 to 1,070 at 1,000. Every 1,000-seed sweep in `off` passes, and so does a new one in which digest and full exchanges meet in clusters beside released 0.4.0 nodes. The cost is one byte in every Alive, the flag that says a node speaks the digest; in the harness's 1,000-node burst it made gossip a little slower, for a reason particular to its record size (Cost). With `push_pull_scale` on top, a settled 1,000-node node sends 412 B/s, a fifteenth of the 6,232 it sent, again as inferred (about 410). Detection and false deaths in the tuning sweep are pending the run on the Mac (Detection and false deaths).

## What changed

- **Wire, version 1.** PushPullDigest (0x0D) and PushPullWants (0x0E), TCP only, and a `features` varint appended to Alive after the epoch, bit 0 for digest push-pull ([design](../design.md#inner-payload)). Features 0 are not written, so a node with `push_pull_digest` off sends the bytes 0.4 sends: the cost harness gives the 32 rows of its `100` and `1000` clusters in `off` exactly as [signed-costs.csv](signed-costs.csv) has them, and the pinned SWIM trace is the 0.4 one. kinship-proto's golden vectors pin the new bytes, and a test decodes them with the released kinship-proto 0.4.0, which reads every field of the new Alive and skips both new types.
- **Core.** A node in mode `off` with an epoch advertises the bit and starts a digest exchange for anti-entropy, a reconnect or a rejoin with a member it holds advertising it; joins, members without the bit (0.4 and older) and mode `sign` keep the full exchange. Every node answers a digest. The admission limit counts the names a node asks for, the replay rule answers a stale digest with one record, and a node keeps at most 1,024 connections waiting for the records it asked for, each for at most `tcp_timeout`.
- **kinship-net.** The driver read one frame on a connection it accepted, so the third frame never reached the node that asked for it. It now reads at most two, the second from its own share of the inbound budget and checked against the header check like the first. A test drives the whole exchange through the driver over the in-memory transport.
- **Config.** `push_pull_digest`, true by default: `Config::push_pull_digest` in kinship-core, `with_push_pull_digest` in the Rust facade, `push_pull_digest=` in Python.

The core holds itself to the full exchange: `a_digest_exchange_ends_where_a_full_one_does` runs 500 random pairs of tables, with every state, incarnations and lives, through both and finds every member where the full exchange leaves it. Where one side does not know a member's epoch, the two entries cannot be ordered and both records cross, which can leave the epoch known on the other side than a full exchange does (`with_unknown_epochs_a_digest_exchange_differs_only_in_what_is_unordered`). One thing arrives later than in a full exchange: when the opener holds the peer itself as Alive at a later incarnation than the peer's own, the peer refutes once the opener's record arrives, and the opener hears the refutation by gossip rather than in the answer.

## Sweeps

Every 1,000-seed sweep in `off`, with digest push-pull on as by default, on the 4-core Ryzen 5 3550H laptop, release build, on this branch. Every one passes. The times are per file, beside those origin/main gave on the same laptop ([pushpull.md](pushpull.md#sweeps)).

| File | Sweeps | Passes | origin/main, s | This branch, s |
| --- | --- | --- | ---: | ---: |
| `swim` | SWIM properties on random faults, 1,000 x 50 | yes | 75 | 77 |
| `sync` | join 200, leave, heal, metadata | yes | 122 | 126 |
| `epoch` | nodes without epochs, rumours about an earlier life | yes | 6 | 4 |
| `usermsg` | user messages beside 0.3.0 nodes | yes | 3 | 3 |
| `failure` | clock jump, long partition, restarts, name conflict | yes | 166 | 167 |
| `keyring` | a node that falls behind, rotating every node | yes | 18 | 18 |
| `sim` | 1,000 nodes for 600 s | yes |  | 5 |
| `digest` (new) | beside 0.4.0, 1,000 x 20 | yes |  | 8 |

```bash
cargo test --release -p kinship-sim --test digest -- --ignored --nocapture
```

**Beside 0.4.0.** `tests/digest.rs` starts 20 nodes, 5, 10 or 15 of them on the released kinship-core 0.4.0, joins them one at a time through one seed of either version, cuts a random part of the cluster off for 10 to 25 s and heals it. On all 1,000 seeds every node holds every node within the heal bound of `tests/sync.rs`, no node counts a decode error, and no digest ever goes to a 0.4 node. Between them the runs opened 8,034 digest exchanges between nodes of this version, 470 of them with a third frame of wanted records, and full exchanges both ways with the 0.4 nodes, 12,103 from this version and 27,572 from 0.4; 7,165 full exchanges between nodes of this version ran before one held the other with the flag, which a 0.4 relay drops when it passes an Alive on until a copy with it arrives. CI runs this sweep in a `sim-digest` job. The `usermsg` and `signatures` sweeps keep running 0.3.0 and 0.4.0 beside this version, and pass.

**Repair.** What push-pull repairs, 1,000 seeds at 50 nodes (p50, p99, max):

| What | origin/main | This branch |
| --- | --- | --- |
| A healed partition reconverges (`sync` heal) | 1.25 s, 21.75 s, 29.5 s | 1.25 s, 18.25 s, 25.5 s |
| Metadata reaches every node (`sync` metadata) | 75 ms, 375 ms, 29.7 s | 75 ms, 374 ms, 29.4 s |
| The deliveries gossip missed, of about 99,000 | 26: 14.4 s, 29.7 s, 29.7 s | 29: 17.4 s, 29.4 s, 29.4 s |
| A long partition, after the join that merges it (`failure`) | 8.75 s, 41.75 s, 62 s | 9.75 s, 42.25 s, 62 s |
| A restart at a lower incarnation, Alive everywhere (`failure`) | 210 ms, 2.01 s, 27.7 s | 210 ms, 880 ms, 29.9 s |
| A restart without an epoch (`failure`) | 310 ms, 2.41 s, 27.7 s | 310 ms, 2.41 s, 27.7 s |

The tails stay within the 30 s period, as they should: the digest repairs what the full exchange repaired, on the same schedule. The `swim` sweep finds the same 197,363 detections at the same p50 of 10.05 s as origin/main.

**The pinned SWIM trace** changes, as expected: every Alive is one byte longer. Of the first 362 datagrams of the 10-node run, before the first push-pull at 8.5 s, the 80 that carry an Alive grew by one byte and the rest are the same bytes; that push-pull became a digest exchange of 228, 166 and 169 bytes in place of 304 and 320. Its third frame draws one more latency from the simulator's random stream, so every later record moves; the run keeps its 34 events, but for which of two nodes learned a crashed node's epoch before it died. The pin is now 0x8b4a_8d9c_9a71_de4d, and with `KINSHIP_PUSH_PULL_DIGEST=0` the test checks the 0.4 one, 0x3dfb_cb2f_34fe_aa03.

## Cost

`crates/kinship-sim/tests/costs.rs` on its seven clusters ([signed.md](signed.md#cost) for the setup: `lan()`, sealed, 17-byte names, 48 bytes of metadata set by every member between 1 and 5 s, a crash at 240 s, every node starting from a static list of every other; burst 5 to 150 s, steady 150 to 330 s). Every frame of an exchange that started with a digest is filed as `push-pull digest v1`; full exchanges, with the 0.4.0 nodes of the mixed cluster and before a node holds a member with the flag, stay `push-pull v1`. The rows are in [digest-costs.csv](digest-costs.csv), and with the period scaled in [digest-scaled-costs.csv](digest-scaled-costs.csv). Eight minutes each on the laptop.

```bash
KINSHIP_MODES=off KINSHIP_COSTS_CSV=digest-costs.csv cargo test --release -p kinship-sim --test costs -- --ignored --nocapture --exact costs
KINSHIP_PUSH_PULL_SCALE=1 KINSHIP_MODES=off KINSHIP_COSTS_CSV=digest-scaled-costs.csv cargo test --release -p kinship-sim --test costs -- --ignored --nocapture --exact costs
```

Bytes per node per second, mode `off`: push-pull, then the whole node. Full exchange every 30 s is origin/main ([signed-costs.csv](signed-costs.csv)), full and scaled is `push_pull_scale` ([pushpull-costs.csv](pushpull-costs.csv)).

| Cluster | Window | Full, 30 s | Digest, 30 s | Full, scaled | Digest, scaled | Node: full, 30 s | Digest, 30 s | Full, scaled | Digest, scaled |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | burst | 596 | 109 | 221 | 41 | 979 | 525 | 604 | 456 |
| 100 | steady | 598 | 110 | 200 | 37 | 789 | 303 (-62%) | 392 | 234 (-70%) |
| 100, seed 1 | steady | 599 | 110 | 200 | 37 | 784 | 313 | 412 | 248 |
| 100, stress | burst | 596 | 109 | 221 | 41 | 1,922 | 1,555 | 1,531 | 1,472 |
| 100, stress | steady | 599 | 110 | 200 | 37 | 1,666 | 1,247 (-25%) | 1,263 | 1,099 (-34%) |
| 100, 10 on 0.4.0 | steady | 598 | 210 | 240 | 112 | 799 | 410 (-49%) | 433 | 312 (-61%) |
| 100, user messages | steady | 599 | 110 | 200 | 37 | 7,963 | 7,479 | 7,583 | 7,414 |
| 1,000 | burst | 6,002 | 1,187 | 1,033 | 300 | 15,794 | 11,137 | 10,826 | 10,251 |
| 1,000 | steady | 5,999 | 1,070 | 1,001 | 178 | 6,232 | 1,304 (-79%) | 1,234 | 412 (-93%) |
| 1,000, stress | burst | 5,999 | 1,193 | 1,030 | 305 | 21,414 | 16,730 | 16,459 | 15,924 |
| 1,000, stress | steady | 5,999 | 1,072 | 1,001 | 179 | 12,683 | 7,797 (-39%) | 7,666 | 6,979 (-45%) |

The design note's figures, inferred from record sizes, hold: push-pull with digests and the scaled period about 36 and 180 B/s (37 and 178 measured), a whole node about 230, 410 and 6,850 (234, 412, 6,979). In the settled cluster the digest is nearly all of what remains: an entry per member per exchange, both ways about 32 bytes a member every 30 s, and the occasional record. The mixed cluster saves less, since its 0.4.0 nodes exchange whole tables with everyone and everyone with them. Under stress and with user messages, the rumours about starved nodes and the messages are most of the bytes, as before.

Every other carrier stays within noise but the rumours and the headers of the datagrams that carry them, which the next section explains.

### The features byte

Every Alive, and every push-pull record, is one byte longer, and that byte moves the gossip of the 1,000-node burst, where every member's metadata changes within four seconds:

| 1,000 nodes, burst | origin/main | The byte alone | Digest |
| --- | ---: | ---: | ---: |
| Rumours, B/s per node | 9,338 | 9,476 | 9,476 |
| Datagram headers, B/s per node | 400 | 420 | 420 |
| Metadata spread p50, p99 | 1.41 s, 13.9 s | 1.49 s, 14.6 s | 1.50 s, 14.6 s |
| Deliveries later than gossip should be | 101,665 | 115,013 | 115,013 |
| Their repair, p50 | 8.97 s | 8.95 s | 8.97 s |

"The byte alone" is a run on a build that advertised the flag and never sent a digest, made for this comparison and not committed; it moves gossip exactly as the digest build does, so the digest exchange itself changes nothing there. The cause is the harness's record size: its Alive rumour is exactly 90 bytes (a 17-byte name, an IPv4 address, 48 bytes of metadata and an epoch), and a dedicated gossip datagram has 1,350 bytes of room, so fifteen fit exactly; at 91 bytes fourteen do, and a burst of 1,000 rumours takes 7% more packets to spread. With other sizes the byte costs about 1% of a rumour and rarely a whole one. The slow tail is unchanged: the deliveries gossip missed are repaired by push-pull at the same p50, and the last one arrives at 34.2 s with the digest, against 47.2 s before. Steady-state rumours do not move (43 B/s before and after at 1,000 nodes). At 100 nodes, where gossip is not full, the spread is the same at p50 and p99 (0.40 s and 0.76 s) and its maximum, still within the gossip bound, moves from 1.05 to 1.26 s.

A flag carried in a capability exchange at the start of each TCP connection, the alternative the design note weighed, would avoid the byte but cost a round trip per exchange; the byte is the smaller cost.

Metadata spread with digests, every update to every node that holds it (p50, p99, max), and the deliveries later than gossip should be (5.4 s at 100 nodes, 6.2 s at 1,000):

| Cluster | origin/main | Digest, 30 s | Digest, scaled | Later than gossip, digest |
| --- | --- | --- | --- | ---: |
| 100 | 0.40 s, 0.76 s, 1.05 s | 0.40 s, 0.76 s, 1.26 s | the same | 0 |
| 100, stress | 0.42 s, 0.75 s, 1.23 s | 0.42 s, 0.76 s, 1.99 s | the same | 0 |
| 1,000 | 1.41 s, 13.9 s, 47.2 s | 1.50 s, 14.6 s, 34.2 s | 1.50 s, 14.6 s, 55.5 s | 11.5% |
| 1,000, stress | 1.50 s, 14.6 s, 37.1 s | 1.55 s, 15.0 s, 38.2 s | 1.55 s, 15.0 s, 56.8 s | 12.0% |

With the period scaled, the stragglers wait for the longer period, as with full exchanges ([pushpull.md](pushpull.md#cost)): 55.5 s against 47.7 s.

## Detection and false deaths

Stage `digest` of the tuning sweep reruns `lan`, `epochs` and `epochs push_pull_scale=1` on the screen's cells and seeds at 200 and 1,000 nodes ([tuning.md](tuning.md#setup)), with digest push-pull on as by default, and `digest_verdict` compares each row with the same cell and variant with the full exchange: `lan` in stage `screen`, `epochs` in stage `signed`, the scaled one in stage `pushpull`; and the scaled period against the fixed one, both with digests. The `lan` variant's nodes have no epoch, so they never use the digest and should give the screen's rows exactly. It takes about three hours on the laptop, so it runs on the Mac; the result is added here when it arrives.

```bash
KINSHIP_NODES=200 cargo test --release -p kinship-sim --test tuning -- --ignored --nocapture --exact digest
KINSHIP_NODES=1000 cargo test --release -p kinship-sim --test tuning -- --ignored --nocapture --exact digest
cargo test --release -p kinship-sim --test tuning -- --ignored --nocapture --exact digest_verdict
```

These runs last 120 s and start from static lists, so a node learns that its members speak the digest from the Alives they gossip at the start, and makes its first exchange, staggered within 30 s, as a digest when it has.

## Is `push_pull_scale` still worth keeping?

On bytes, yes for large clusters. With digests, push-pull is still 82% of a settled 1,000-node node's 1,304 B/s, and the scaled period takes the node to 412 B/s; at 100 nodes the digest alone takes it to 303 B/s and the scaling adds a further 69 B/s of saving. What scaling costs is unchanged: the deliveries that gossip missed wait up to the longer period (55.5 s at 1,000 nodes against 34.2 s), and at 200 nodes the full exchange's scaled period added false deaths in the tuning sweep. Whether it still does with digests, which carry the same refutations on the same schedule, is what stage `digest` measures; until then it stays opt-in, as decided on 2026-10-31.
