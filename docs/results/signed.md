# Mode `sign`: sweeps, detection and cost

KI-01 Stage 2c ([plan](../ki01-per-member-keys.md), [notes](../ki01-stage2.md#implementation-stage-2c)) runs mode `sign` through every 1,000-seed simulator sweep, a signed variant of the tuning sweep, and a cost harness that files every byte by what carries it. Mode `off`, the default, is unchanged: it sends the bytes 0.4 sends, and the pinned SWIM trace stays as it was.

**Result.** With the fixes below, every sweep passes with every node signing, and signing detects a crash as fast as `off` and with as few false deaths. It costs more bytes than the plan estimated: 89% to 135% more per node in a settled cluster, against the plan's 71% to 90%, and 91% to 172% more while a cluster started from static lists spreads its certificates, as the tuning sweep's two minutes show at two to four and a half times. Push-pull is still most of it; at 1,000 nodes under stress the larger rumours add as much. Signed broadcasts cost three times their 0.4 bytes, more than half of it the certificate ahead of every copy. A node signs about one statement a second and checks 1 to 21, under 0.2% of a core.

## Sweeps

Each 1,000-seed sweep runs twice, in `off` and with every node of this version in `sign` (`_signed`), on the same seeds. In `sign` every node must also end with no signature that failed and no certificate refused. Nodes without an epoch cannot sign, so the restart without epochs runs in `off` only, and the older nodes of the mixed-version sweep stay in `off` beside signing ones.

```bash
cargo test --release -p kinship-sim --test swim -- --ignored --nocapture _signed
```

| Sweep | Seeds x nodes | Passes in `sign` | `off`, s | `sign`, s |
| --- | --- | --- | ---: | ---: |
| `swim` SWIM properties on random faults | 1,000 x 50 | yes | 8 | 91 |
| `sync` a new node joins 200 | 1,000 x 200 | yes | 6 | 76 |
| `sync` a node that left is never reported dead | 1,000 x 50 | yes | 3 | 49 |
| `sync` a healed partition reconverges | 1,000 x 50 | yes | 4 | 42 |
| `sync` metadata reaches every node | 1,000 x 50 | yes | 1 | 22 |
| `epoch` nodes without epochs among newer ones | 1,000 x 10 | yes | 0 | 2 |
| `epoch` rumours about an earlier life | 1,000 x 8 | yes | 0 | 3 |
| `usermsg` user messages, beside 0.3.0 nodes | 1,000 x 5 to 16 | yes | 1 | 4 |
| `failure` a clock jump | 1,000 x 50 | yes | 2 | 39 |
| `failure` a partition longer than `dead_reclaim` | 1,000 x 50 | yes | 8 | 92 |
| `failure` a restart at a lower incarnation | 1,000 x 50 | yes | 4 | 53 |
| `failure` a second node with a live name | 1,000 x 50 | yes | 2 | 27 |
| `keyring` a node that falls behind | 1,000 x 20 | yes | 1 | 13 |
| `keyring` rotating every node | 1,000 x 50 | yes | 1 | 27 |

Times on an M5 Pro, release build, on 3ac4990. Signing makes a sweep about ten times slower; the same sweeps took 76 s and 795 s for `swim` on a 4-core Ryzen 5 3550H laptop. GitHub's 4-core runners are slower still, so the existing `sim-*` jobs, 30 minutes each, skip the signed twins (`--skip _signed`) and a `sim-signed` job runs them, one job per file, at 250 seeds. The full 1,000 run with `KINSHIP_SEEDS` unset.

### What the sweeps found

Four failures, each fixed and tested in `crates/kinship-core/tests/signed_answers.rs`:

- **A relay could not forward an Ack it could not check.** `swim`, seeds 8, 27 and 51 of 64: with a one-way block between prober and target and 4% loss, the prober's rounds went through relays, the relays did not hold the target's certificate, and the target's Ack, which carried none, could not be checked and so was not forwarded (rule 3). The prober suspected a live member, which `off` never did on those seeds. An Ack to a relay's Ping now goes behind the target's certificate, about 150 bytes, in indirect rounds only.
- **A later life heard of unsigned kept the earlier life's certificate.** `epoch` rumours, seeds 5 and 11 of 16: a member restarted with a new key, and a node that heard of the new life in a version 1 packet still held the old life's certificate, so its rounds to the new life were version 2 rounds whose Acks it could never check. They failed and suspected the new life. The certificate now goes with the earlier life, and rounds stay version 1 until the new life's proof arrives.
- **A member back from the dead was relayed without its certificate.** `sync` heal, seed 16: after a partition healed, a node that had reaped a member's tombstone received the member's refutation without the certificate, which only an Alive new to the relaying node carried, and dropped it until its next push-pull, 30 s later. An Alive that revives a Dead or Left member now goes behind the certificate, as one that is new does.
- **Certificate gaps after a start from static lists.** `epoch` rumours, seed 499 of 1,000: a node that held the accusers without their certificates dropped their signed Deads of a crashed member, declared it dead only after its own suspicion ran out, and by then the others had reaped the tombstone. A node holds a static list's members without certificates until an Alive brings them, and an announcement went only when a node learned that a member speaks version 2. A member that speaks version 2 but probes this node in version 1 holds it without a current certificate, so a version 1 Ping from such a member now draws an announcement.

The sweeps in `sign` take longer to settle where they depend on certificates: a heal, a restart, a node that falls behind. They stay inside the bounds `off` is held to.

## Detection and false deaths

The tuning sweep's `signed` stage runs `lan()` with every node signing against `lan()` in `off`, both with epochs, on the screen's cells and seeds: 120 s, every node starting from a static list of every other, a crash at 60 s, 0% to 5% loss and 0% to 10% of the nodes starved ([tuning.md](tuning.md#setup)). The rows are in [tuning.csv](tuning.csv), stage `signed`; `signed_verdict` prints this:

```bash
cargo test --release -p kinship-sim --test tuning -- --ignored --nocapture --exact signed
cargo test --release -p kinship-sim --test tuning -- --ignored --nocapture --exact signed_verdict
```

Per size, averaged over the cells: bandwidth as signed over off, the change in detection p50 and p99, and false deaths and false suspicions per run summed over the cells.

| Nodes | Cells | Bandwidth, mean | Bandwidth, worst | p50 change (s) | p99 change, mean (s) | p99 change, worst (s) | False deaths per run, off | False deaths per run, sign | False suspicions per run, off | False suspicions per run, sign | Undetected |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 50 | 16 | 2.648 | 3.086 | -0.05 | +0.62 | +3.40 | 0.11 | 0.16 | 1010.7 | 1007.1 | 0 off, 0 sign |
| 200 | 16 | 3.295 | 3.927 | +0.08 | -0.08 | +1.77 | 0.00 | 0.00 | 3373.2 | 3355.2 | 0 off, 0 sign |
| 1000 | 8 | 3.896 | 4.533 | +0.08 | +0.10 | +0.35 | 0.00 | 0.00 | 1071.7 | 1062.1 | 0 off, 0 sign |

Every cell:

| Cell (nodes, loss, starved) | Bytes per node per second, off | Sign | Ratio | p50 off (s) | p50 sign (s) | p99 off (s) | p99 sign (s) | False deaths off | False deaths sign |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 50,0,0 | 251 | 776 | 3.086 | 8.34 | 8.34 | 11.44 | 11.44 | 0.00 | 0.00 |
| 50,0.01,0 | 268 | 817 | 3.050 | 8.46 | 8.52 | 12.39 | 14.16 | 0.00 | 0.00 |
| 50,0.03,0 | 301 | 899 | 2.991 | 8.51 | 8.37 | 11.77 | 14.99 | 0.00 | 0.00 |
| 50,0.05,0 | 333 | 973 | 2.924 | 8.43 | 8.47 | 11.73 | 12.66 | 0.00 | 0.00 |
| 50,0,0.01 | 738 | 1762 | 2.388 | 8.38 | 8.53 | 13.09 | 13.30 | 0.00 | 0.00 |
| 50,0.01,0.01 | 750 | 1798 | 2.398 | 8.64 | 8.53 | 11.51 | 14.69 | 0.00 | 0.00 |
| 50,0.03,0.01 | 777 | 1876 | 2.416 | 8.44 | 8.57 | 12.85 | 12.18 | 0.00 | 0.00 |
| 50,0.05,0.01 | 800 | 1928 | 2.412 | 8.61 | 8.56 | 11.95 | 12.40 | 0.00 | 0.02 |
| 50,0,0.05 | 1314 | 3276 | 2.493 | 8.50 | 8.79 | 13.38 | 11.61 | 0.01 | 0.02 |
| 50,0.01,0.05 | 1329 | 3298 | 2.481 | 8.65 | 8.38 | 13.70 | 12.97 | 0.00 | 0.00 |
| 50,0.03,0.05 | 1350 | 3354 | 2.485 | 8.84 | 8.77 | 13.21 | 13.82 | 0.01 | 0.02 |
| 50,0.05,0.05 | 1362 | 3396 | 2.493 | 8.62 | 8.66 | 13.94 | 13.50 | 0.01 | 0.01 |
| 50,0,0.1 | 1661 | 4484 | 2.699 | 8.75 | 8.86 | 12.78 | 16.18 | 0.01 | 0.00 |
| 50,0.01,0.1 | 1668 | 4483 | 2.688 | 8.91 | 8.44 | 16.86 | 13.42 | 0.00 | 0.00 |
| 50,0.03,0.1 | 1678 | 4511 | 2.689 | 8.92 | 8.69 | 12.13 | 14.52 | 0.03 | 0.02 |
| 50,0.05,0.1 | 1685 | 4511 | 2.677 | 8.93 | 8.68 | 13.57 | 14.45 | 0.04 | 0.07 |
| 200,0,0 | 534 | 2099 | 3.927 | 10.80 | 10.80 | 15.82 | 15.82 | 0.00 | 0.00 |
| 200,0.01,0 | 551 | 2156 | 3.912 | 10.79 | 10.80 | 15.82 | 15.82 | 0.00 | 0.00 |
| 200,0.03,0 | 584 | 2246 | 3.849 | 10.80 | 10.80 | 15.82 | 15.82 | 0.00 | 0.00 |
| 200,0.05,0 | 613 | 2317 | 3.780 | 10.80 | 10.73 | 15.82 | 15.82 | 0.00 | 0.00 |
| 200,0,0.01 | 1564 | 4244 | 2.713 | 11.12 | 11.15 | 15.63 | 15.61 | 0.00 | 0.00 |
| 200,0.01,0.01 | 1583 | 4303 | 2.719 | 11.10 | 11.07 | 15.60 | 15.60 | 0.00 | 0.00 |
| 200,0.03,0.01 | 1611 | 4387 | 2.723 | 10.97 | 11.21 | 15.58 | 15.61 | 0.00 | 0.00 |
| 200,0.05,0.01 | 1639 | 4440 | 2.708 | 11.21 | 11.12 | 15.57 | 15.60 | 0.00 | 0.00 |
| 200,0,0.05 | 3267 | 10412 | 3.187 | 11.22 | 11.25 | 14.94 | 14.97 | 0.00 | 0.00 |
| 200,0.01,0.05 | 3276 | 10471 | 3.197 | 11.30 | 11.16 | 15.00 | 14.28 | 0.00 | 0.00 |
| 200,0.03,0.05 | 3313 | 10499 | 3.169 | 11.22 | 11.64 | 15.96 | 15.00 | 0.00 | 0.00 |
| 200,0.05,0.05 | 3330 | 10523 | 3.160 | 10.99 | 11.19 | 15.60 | 15.03 | 0.00 | 0.00 |
| 200,0,0.1 | 5148 | 17597 | 3.418 | 11.15 | 11.55 | 14.44 | 14.31 | 0.00 | 0.00 |
| 200,0.01,0.1 | 5141 | 17659 | 3.435 | 11.28 | 11.54 | 14.91 | 16.68 | 0.00 | 0.00 |
| 200,0.03,0.1 | 5147 | 17610 | 3.421 | 11.52 | 11.40 | 16.73 | 15.21 | 0.00 | 0.00 |
| 200,0.05,0.1 | 5129 | 17475 | 3.407 | 10.92 | 11.03 | 16.04 | 16.82 | 0.00 | 0.00 |
| 1000,0,0 | 1854 | 8292 | 4.473 | 13.77 | 13.74 | 16.96 | 17.06 | 0.00 | 0.00 |
| 1000,0.01,0 | 1869 | 8473 | 4.533 | 13.77 | 13.95 | 16.96 | 17.06 | 0.00 | 0.00 |
| 1000,0.03,0 | 1901 | 8571 | 4.509 | 13.77 | 13.78 | 16.96 | 17.15 | 0.00 | 0.00 |
| 1000,0.05,0 | 1929 | 8646 | 4.481 | 13.77 | 13.93 | 16.96 | 17.31 | 0.00 | 0.00 |
| 1000,0,0.01 | 4907 | 16140 | 3.289 | 14.11 | 14.12 | 20.01 | 20.07 | 0.00 | 0.00 |
| 1000,0.01,0.01 | 4928 | 16309 | 3.310 | 14.12 | 14.14 | 20.00 | 20.00 | 0.00 | 0.00 |
| 1000,0.03,0.01 | 4972 | 16377 | 3.294 | 14.05 | 14.17 | 20.00 | 20.00 | 0.00 | 0.00 |
| 1000,0.05,0.01 | 5005 | 16430 | 3.283 | 14.02 | 14.19 | 20.04 | 20.07 | 0.00 | 0.00 |

Signing moves no timer, and detection is the same: the median within 0.1 s at every size, and p99 within the noise of single cells (tuning.md: up to 2.2 s for neutral changes). False deaths, all of starved nodes at 50 nodes, are 0.16 per run summed over the 16 cells against 0.11 in `off`, and none at 200 or 1,000 nodes in either mode. No crash went undetected.

The bandwidth is what these runs show most, two to four and a half times `off`, but they are short and start from static lists: they measure the first two minutes of a signing cluster, while its members exchange certificates. [Cost](#cost) separates that from the steady state.

## Cost

`crates/kinship-sim/tests/costs.rs` runs the clusters the plan estimated the cost for ([section 5](../ki01-per-member-keys.md#bandwidth)) once in `off` and once with every node of this version signing, and opens every packet each node sends to file each message under what carries it. As in the plan: `lan()`, sealed, 17-byte names, 48 bytes of metadata set by every member between 1 and 5 s, a crash at 240 s, 330 s in all, every node starting from a static list of every other. The burst window, 5 to 150 s, holds the spreading of every member's new metadata and, in `sign`, of every member's certificate; the steady window is 150 to 330 s. Stress adds 1% loss on every link and starves 1% of the nodes. Two clusters are new: one with 10 of its 100 nodes on the released 0.4.0, a mixed view, and one where every node broadcasts once and sends one direct message every 10 s of the steady window. Frames are counted at the node that opened the connection, so a reply is filed with its request, and the carriers add up to the simulator's own count of bytes to within 0.5%. The rows are in [signed-costs.csv](signed-costs.csv).

```bash
cargo test --release -p kinship-sim --test costs -- --ignored --nocapture --exact costs
```

Bytes per node per second, every datagram and frame sent, and the statements each node signed and the signatures it checked per second (M5 Pro, 3ac4990, 24 minutes):

| Cluster | Window | `off` | `sign` | More | Signs | Checks | Plan |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 100 | burst | 979 | 2,648 | +170% | 1.00 | 1.09 | +75% |
| 100 | steady | 789 | 1,514 | +92% | 0.99 | 1.01 | +74% |
| 100, seed 1 | burst | 979 | 2,667 | +172% | 1.00 | 1.13 | |
| 100, seed 1 | steady | 784 | 1,524 | +94% | 0.99 | 1.02 | |
| 100, stress | burst | 1,922 | 4,412 | +130% | 1.14 | 2.13 | |
| 100, stress | steady | 1,666 | 3,146 | +89% | 1.12 | 2.04 | +71% |
| 100, 10 on 0.4.0 | burst | 979 | 2,418 | +147% | 0.81 | 0.87 | |
| 100, 10 on 0.4.0 | steady | 799 | 1,780 | +123% | 0.80 | 0.82 | |
| 100, user messages | steady | 7,963 | 21,631 | +172% | 1.18 | 10.54 | |
| 1,000 | burst | 15,794 | 39,190 | +148% | 0.94 | 12.93 | +78% |
| 1,000 | steady | 6,232 | 13,353 | +114% | 1.00 | 1.07 | +79% |
| 1,000, stress | burst | 21,414 | 40,815 | +91% | 1.08 | 21.07 | +86% |
| 1,000, stress | steady | 12,683 | 29,864 | +135% | 1.14 | 9.79 | +90% |

By carrier, in the steady window (`off` / `sign`):

| Carrier | 100 | 100, stress | 100, 10 on 0.4.0 | 100, user messages | 1,000 | 1,000, stress |
| --- | ---: | ---: | ---: | ---: | ---: | ---: |
| Probe messages | 55 / 220 | 63 / 255 | 55 / 189 | 55 / 220 | 55 / 221 | 63 / 259 |
| Rumours | 21 / 61 | 525 / 1,257 | 26 / 50 | 25 / 49 | 43 / 1,001 | 5,769 / 14,938 |
| Certificates ahead of Alives | - / 0 | - / 3 | - / 0 | - / 0 | - / 806 | - / 2,665 |
| Certificates ahead of relayed Acks | - / 0 | - / 12 | - / 0 | - / 0 | - / 0 | - / 13 |
| Push-pull, version 2, and version 1 with 0.4 nodes | 598 / 1,114 | 599 / 1,114 | 598 / 929 | 599 / 1,112 | 5,999 / 11,130 | 5,999 / 11,135 |
| The second, version 1 exchange between signing nodes | - / 0 | - / 0 | - / 490 | - / 0 | - / 0 | - / 0 |
| User messages | - | - | - | 6,473 / 9,331 | - | - |
| Certificates ahead of user messages | - | - | - | - / 10,088 | - | - |
| Headers and tags | 116 / 119 | 476 / 500 | 121 / 123 | 811 / 831 | 135 / 195 | 849 / 849 |
| TCP fallback pings | - | 3 / 6 | - | - | - | 3 / 6 |

And in the burst window, where `sign` adds the start of a signing cluster:

| Carrier | 100 | 100, stress | 100, 10 on 0.4.0 | 1,000 | 1,000, stress |
| --- | ---: | ---: | ---: | ---: | ---: |
| Rumours | 223 / 678 | 763 / 1,939 | 223 / 470 | 9,338 / 13,572 | 14,499 / 18,478 |
| Certificates ahead of Alives | - / 462 | - / 522 | - / 250 | - / 9,846 | - / 6,339 |
| Announcements | - / 10 | - / 11 | - / 2 | - / 2,236 | - / 2,237 |
| Push-pull, version 2, and version 1 with 0.4 nodes | 596 / 1,107 | 596 / 1,107 | 596 / 912 | 6,002 / 10,634 | 5,999 / 10,570 |
| The second, version 1 exchange between signing nodes | - / 31 | - / 26 | - / 470 | - / 1,771 | - / 1,965 |
| Version 1 datagrams beside a version 2 one | - / 2 | - / 7 | - / 11 | - / 2,649 | - / 2,843 |

The last row counts whole datagrams already filed under their contents above: the version 1 packets that went beside version 2 ones to signing members, with rumours a node still held unsigned.

Where the bytes go:

- **Push-pull** is most of it in every cluster, and the plan had it right: each record grows from about 90 bytes to 162 and a reply carries the certificates the request did not list, 516 more bytes per node per second at 100 nodes (plan: 517) and 5,131 at 1,000 (plan: 5,200).
- **Probe messages** add 165 bytes a second per node, against the plan's 72: the version 2 Ping is 74 bytes (49) and the Ack 147 (6), since Stage 1 added explicit names, the challenge and the certificate id.
- **Rumours under stress** cost more than the plan's sketch: 9.2 KB/s per node more at 1,000 nodes, against 6.5. The false suspicions of starved nodes and their refutations are many, and each signed Suspect or Alive is 72 bytes longer.
- **Certificates ahead of Alives** come with every Alive that starts a member, a life or, since the fix above, a revival, and every relay that received one with its certificate passes both on. In a settled cluster they are 0 at 100 nodes and 0.8 KB/s at 1,000, 2.7 KB/s under stress, where starved nodes that some members declared dead come back. The plan counted them only at a join.
- **The second push-pull exchange** costs nothing once every member holds every other signed, and 490 bytes per node per second in the mixed view, 82% of 0.4's whole push-pull, as long as the 0.4 nodes remain.
- **Version 1 datagrams beside version 2 ones** are 0 to 1.4 bytes per node per second in a settled cluster; in the start of a 1,000-node cluster, 2.6 KB/s, while members are still held unsigned.
- **Announcements** are what the start of a cluster from static lists costs: each node announces itself once to each member, 2.2 KB/s per node over the burst window at 1,000 nodes, nothing once settled.
- **User messages.** With one broadcast and one direct message per node every 10 s, user messages cost 6.5 KB/s per node in `off` and 19.4 KB/s in `sign`, of which 10.1 KB/s is the certificate that goes ahead of every broadcast copy, more than the signed messages themselves.
- **CPU.** A node signs about one statement a second, mostly its Acks, and checks about one a second in a calm cluster, 2 to 10 under stress, 13 to 21 while a 1,000-node cluster spreads its certificates and 10.5 with the user messages. At the 82 µs a check costs, that is under 0.2% of a core.

## Announcements

`announcements` in `tests/costs.rs` starts a signing cluster from static lists, has a node that knows nobody join it through one seed at 60 s, and counts the announcements it receives in the next 30 s, and the most any node sends at one instant:

```bash
cargo test --release -p kinship-sim --test costs -- --ignored --nocapture --exact announcements
```

| Cluster | Received by the joiner | Most in one gossip interval | Last, after the join | Most one node sent at one instant |
| --- | ---: | ---: | ---: | ---: |
| 200, without the cap | 198, 62 KB | 198 | 0.09 s | 127 |
| 200, with the cap | 199, 62 KB | 199 | 0.15 s | 8 |
| 1,000, without the cap | 998, 312 KB | 998 | 0.20 s | 896 |
| 1,000, with the cap | 998, 312 KB | 65 | 28 s | 8 |

The burst one node sent was material: a joiner that learns the cluster through its version 1 exchange learns every member at once, and announced itself to 896 of them in the same instant. With the cap, at most four go per gossip interval; eight at one instant is the end of one interval's budget and the start of the next. What a joiner receives is one announcement from each member that learns of it from gossip, about 312 bytes each; the cap spreads them only where members already have announcements queued, as at 1,000 nodes, still settling from their own start. In a settled cluster a joiner of 1,000 would, by the 200-node run, receive its 312 KB within a gossip interval or two, beside the join's own reply of about the same size; that is inferred, not measured. The rows without the cap are from 2df23f1, before it.

## Recommendations

Not implemented here. Accepted by Nikola on 2026-10-24, as recorded in [the Stage 2 notes](../ki01-stage2.md#decisions-stage-2c): the measured bandwidth for the opt-in mode; push-pull made cheaper in mode `off` first, by scaling its interval with the cluster as memberlist does, with digest push-pull designed but not yet built; the certificate on every broadcast copy to be revisited later; and KI-01 paused after Stage 2, with Stages 3 to 5 after 1.0.

1. **Revisit the certificate on every broadcast copy.** It doubles what broadcasts cost, 10.1 KB/s per node beside 9.3 KB/s of signed messages in the user-message cluster. It was there because members of a cluster started from static lists lacked each other's certificates for minutes (Stage 2b, decision 2). The announcement drawn by a version 1 Ping now closes that gap within a probe pass, so the certificate could go only on a broadcast's first copies, or only until the sender has seen a member probe it in version 2. Measure broadcast reach in the static-list cluster of eight without it before deciding.
2. **Digest push-pull is the larger lever, for its own sake more than for the second exchange.** Push-pull is 83% of a settled 1,000-node signing cluster's bytes, 11.1 KB/s per node, of which signing adds 5.1 KB/s. The second exchange costs nothing once every member signs and 490 bytes a second at 100 nodes while 0.4 nodes remain, which an upgrade ends; it alone does not call for the remedy. A digest exchange (about 20 bytes a record where the two sides agree) would cut both the signed records and today's version 1 ones, at every cluster size. Recommended before mode `sign` is offered for clusters of hundreds of nodes, not as a Stage 2 prerequisite.
3. **Skip announcements a joiner does not need.** A joiner learns the cluster signed from its seed's version 2 reply, yet every member that learns of it from gossip announces itself, about 312 KB at 1,000 nodes. A member could skip the announcement when it learned of the joiner from a signed Alive and leave the rare gap to the announcement a version 1 Ping draws.
4. **Accept the start-up cost of static lists, or document it.** For its first two minutes a signing cluster started from static lists sends two to four and a half times what `off` does, mostly certificates, announcements and the second push-pull exchange; it settles to the steady figures above. Joining through seeds instead of static lists should spread the certificates through push-pull replies instead; that is inferred, not measured.
