# Lifeguard against plain SWIM

Simulated with `kinship-sim`, 200 seeds per cell, at 50 and 200 nodes. The raw numbers are in [lifeguard.csv](lifeguard.csv). To rerun the grid (about three and a quarter hours on 8 cores; it resumes from the CSV, so delete the CSV to start over):

```bash
cargo test --release -p kinship-sim --test lifeguard -- --ignored --nocapture
```

## Result

Lifeguard had fewer false deaths than both SWIM arms in every one of the 18 cells with starved nodes. Across those cells, 108 of 3,600 Lifeguard runs had any false death, against 2,253 for SWIM and 2,220 for SWIM without the TCP fallback. At 200 nodes Lifeguard had no false deaths at all except 0.02 per run in two cells with 10% of nodes starved, where SWIM had 0.95 and 1.1. False suspicions dropped four to five times in every starved cell.

With loss alone there was nothing to separate. Lifeguard and SWIM with the TCP fallback ping had no false deaths in any loss-only cell. SWIM without the fallback had a handful: 8 runs out of 200 at 50 nodes and 5% loss, and 2 runs at 200 nodes. That matches the 1,000-seed SWIM suite, where since Task 9 the TCP fallback alone almost removes false deaths caused by loss. The starved-node cells carry the comparison.

Detection latency is the cost. Lifeguard starts a suspicion at six times the minimum timeout and drops to the minimum only once three other members confirm it. A crashed node is probed by many members, so confirmations arrive fast: median detection stays within half a second of plain SWIM in every cell, and the 99th percentile is at most 2.5 s longer, at 200 nodes with starved nodes.

## Setup

- **Arms.** `Config::lan()` with all four Lifeguard extensions (local health, Nacks, dynamic suspicion, buddy system); `Config::lan().without_lifeguard()`, which is plain SWIM with the TCP fallback ping; and the same with `tcp_fallback_ping = false`. All three arms run the same seeds, so each one sees the same starved nodes, the same crash and the same network draws until the protocols diverge.
- **Loss.** 1%, 3% and 5% uniform packet loss on every link, on top of the `lan()` link latency.
- **Starved nodes.** 0%, 1%, 5% and 10% of the cluster, at least one node when the share is not zero. A starved node reads every packet it receives 0.5 to 2.5 s late, in order, while its timers fire on time (`Action::Starve`). This is the slow-node model of the Lifeguard paper: the node's probe timer fires before it has read the Ack, so it suspects healthy members, and its own Acks reach other nodes too late.
- **Run.** 120 simulated seconds per run. At 60 s one healthy node crashes; detection latency is the time from the crash until each healthy node declares it dead.

## Metrics

- **False deaths per run.** A running member declared dead at some incarnation by at least one node, counted once per (member, incarnation): the Dead rumour then spreads to every node, so counting it per observer would only multiply it by the cluster size. The CSV splits this into deaths of healthy and of starved members.
- **Runs with a false death.** Out of 200.
- **False suspicions per run.** Suspicion episodes about running members, counted the same way.
- **Detection p50 and p99.** Over every healthy node's time to declare the crashed node dead, in seconds. The CSV's `undetected` column counts healthy nodes that never declared it dead within the run. It is 0 for Lifeguard everywhere and at most 2 per 200 runs for SWIM. In those runs the node had already falsely declared the member dead before it crashed, so no new Dead event followed the crash.

## Table

Each cell reads Lifeguard / SWIM / SWIM without the TCP fallback.

| Nodes | Starved | Loss | False deaths per run | Runs with a false death | False suspicions per run | Detection p50 (s) | Detection p99 (s) |
| ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| 50 | 0 | 1% | 0.0000 / 0.0000 / 0.0000 | 0 / 0 / 0 | 0.00 / 0.00 / 0.01 | 8.457 / 8.607 / 8.503 | 12.392 / 12.928 / 12.360 |
| 50 | 0 | 3% | 0.0000 / 0.0000 / 0.0000 | 0 / 0 / 0 | 0.00 / 0.00 / 0.58 | 8.423 / 8.462 / 8.558 | 11.740 / 11.912 / 12.071 |
| 50 | 0 | 5% | 0.0000 / 0.0000 / 0.0400 | 0 / 0 / 8 | 0.00 / 0.00 / 3.67 | 8.433 / 8.563 / 8.435 | 11.735 / 12.489 / 12.433 |
| 50 | 1 | 1% | 0.0100 / 0.9250 / 0.9000 | 2 / 119 / 114 | 30.28 / 145.31 / 145.57 | 8.573 / 8.430 / 8.481 | 12.583 / 11.553 / 12.211 |
| 50 | 1 | 3% | 0.0000 / 1.3150 / 1.2450 | 0 / 149 / 131 | 30.24 / 145.24 / 146.22 | 8.531 / 8.607 / 8.591 | 12.280 / 12.293 / 13.182 |
| 50 | 1 | 5% | 0.0200 / 1.6100 / 1.4950 | 4 / 158 / 159 | 30.43 / 145.32 / 149.49 | 8.562 / 8.609 / 8.462 | 12.193 / 13.451 / 11.412 |
| 50 | 3 | 1% | 0.0500 / 2.2900 / 2.3800 | 9 / 177 / 176 | 84.44 / 374.23 / 373.92 | 8.673 / 8.499 / 8.534 | 12.295 / 12.607 / 11.819 |
| 50 | 3 | 3% | 0.0450 / 3.0600 / 2.7950 | 9 / 195 / 192 | 84.25 / 373.21 / 375.40 | 8.648 / 8.533 / 8.593 | 12.823 / 12.387 / 12.023 |
| 50 | 3 | 5% | 0.0700 / 3.5350 / 3.8350 | 14 / 192 / 197 | 83.77 / 373.24 / 377.99 | 8.610 / 8.501 / 8.557 | 12.540 / 11.926 / 12.448 |
| 50 | 5 | 1% | 0.0600 / 3.2600 / 3.3300 | 12 / 195 / 191 | 135.63 / 545.00 / 546.12 | 8.657 / 8.607 / 8.588 | 13.025 / 12.447 / 12.673 |
| 50 | 5 | 3% | 0.0900 / 4.2100 / 4.0800 | 17 / 196 / 194 | 134.94 / 543.77 / 546.48 | 8.733 / 8.540 / 8.584 | 13.294 / 12.401 / 14.530 |
| 50 | 5 | 5% | 0.1800 / 4.4750 / 4.7600 | 34 / 197 / 199 | 134.65 / 544.03 / 549.18 | 8.836 / 8.545 / 8.518 | 13.972 / 11.620 / 12.769 |
| 200 | 0 | 1% | 0.0000 / 0.0000 / 0.0000 | 0 / 0 / 0 | 0.00 / 0.00 / 0.04 | 10.897 / 10.897 / 10.887 | 14.110 / 14.110 / 14.110 |
| 200 | 0 | 3% | 0.0000 / 0.0000 / 0.0000 | 0 / 0 / 0 | 0.00 / 0.00 / 2.02 | 10.875 / 10.872 / 10.887 | 14.110 / 14.110 / 14.110 |
| 200 | 0 | 5% | 0.0000 / 0.0000 / 0.0100 | 0 / 0 / 2 | 0.00 / 0.00 / 15.03 | 10.872 / 10.870 / 10.906 | 14.110 / 13.531 / 13.531 |
| 200 | 2 | 1% | 0.0000 / 0.1150 / 0.1200 | 0 / 20 / 22 | 55.62 / 282.78 / 283.33 | 11.189 / 11.251 / 11.259 | 15.248 / 15.234 / 15.225 |
| 200 | 2 | 3% | 0.0000 / 0.1600 / 0.1450 | 0 / 26 / 27 | 55.48 / 282.87 / 285.31 | 11.153 / 11.248 / 11.218 | 15.492 / 15.236 / 15.100 |
| 200 | 2 | 5% | 0.0000 / 0.2900 / 0.2650 | 0 / 53 / 42 | 55.43 / 282.82 / 297.67 | 11.173 / 11.240 / 11.239 | 15.486 / 15.224 / 15.249 |
| 200 | 10 | 1% | 0.0000 / 0.3900 / 0.5500 | 0 / 62 / 72 | 267.31 / 1221.70 / 1224.28 | 11.269 / 11.143 / 11.160 | 16.366 / 15.068 / 15.075 |
| 200 | 10 | 3% | 0.0000 / 0.6150 / 0.6050 | 0 / 89 / 86 | 266.43 / 1221.57 / 1226.45 | 11.275 / 11.173 / 11.133 | 16.437 / 15.151 / 15.172 |
| 200 | 10 | 5% | 0.0000 / 0.9450 / 0.8300 | 0 / 111 / 105 | 265.86 / 1221.48 / 1238.34 | 11.276 / 11.139 / 11.134 | 16.292 / 15.089 / 15.065 |
| 200 | 20 | 1% | 0.0000 / 0.5900 / 0.5900 | 0 / 80 / 84 | 516.56 / 2076.56 / 2082.07 | 11.299 / 10.979 / 10.960 | 15.511 / 14.087 / 14.108 |
| 200 | 20 | 3% | 0.0200 / 0.9450 / 0.8550 | 3 / 106 / 108 | 514.60 / 2076.74 / 2084.11 | 11.285 / 10.935 / 10.943 | 15.500 / 14.066 / 14.074 |
| 200 | 20 | 5% | 0.0200 / 1.1000 / 1.0150 | 4 / 128 / 121 | 512.14 / 2074.53 / 2095.58 | 11.335 / 10.891 / 10.950 | 16.568 / 14.070 / 14.074 |

## Why plain SWIM loses healthy members

In plain SWIM most false deaths hit healthy members, not the starved ones. A starved node misreads every round's Ack, so it accuses a different healthy member each probe interval and floods the cluster with suspicions. Each one has to be refuted by the accused member before every other node's minimum timeout runs out (6.8 s at 50 nodes, 9.2 s at 200), and with hundreds of suspicions per run a few refutations lose that race. That explanation is inferred from which nodes declared the deaths (healthy observers, with the accusation started by a starved node), not traced message by message.

Lifeguard removes the cause rather than the symptom. The starved node's missed Acks and missing Nacks raise its local health score, which stretches its probe interval and timeout up to nine times, so it stops accusing healthy members after a few rounds. False suspicions drop about fourfold, and the suspicions that remain start at the long timeout.

## A fix found on the way

Running these experiments exposed a SWIM bug that both arms now carry the fix for. A suspicion at a higher incarnation used to keep the old timer. A member that had already refuted, but whose Alive had not yet reached some node, could then be killed by a timer that started before the refutation. A higher-incarnation Suspect now starts a fresh suspicion with a fresh timer, as the incarnation table in `docs/design.md` says.
