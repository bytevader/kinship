# Tuning the timing presets

**Status: parked, `lan()` unchanged.** This is an interim report. The one-field screen is complete at 50 nodes and covers 10 of 16 cells at 200 nodes; the 1,000-node screen and the full grid have not run. [What is left](#what-is-left) lists the remaining runs.

Simulated with `kinship-sim`. The raw numbers are in [tuning.csv](tuning.csv), one row per stage, cell and variant. The sweeps resume from the CSV, so rerunning a command finishes what is missing and skips what is there:

```bash
cargo test --release -p kinship-sim --test tuning -- --ignored --nocapture --exact screen
cargo test --release -p kinship-sim --test tuning -- --ignored --nocapture --exact grid
cargo test --release -p kinship-sim --test tuning -- --ignored --nocapture --exact verdict
```

On a 4-core, 8-thread Ryzen 5 3550H laptop, the 50-node screen took 46 minutes for 19 variants and the two combinations 6 minutes. At 200 nodes and 50 seeds a cell takes about 15 s per variant without starved nodes and 70 s with 5% starved, so the whole 200-node screen takes an estimated 5 to 6 hours, and the 1,000-node screen another 3.5. A single 1,000-node run takes 18 s with no starved nodes and about 5 minutes with 10% starved, so the full grid at 1,000 nodes is estimated at 2 to 3 hours per variant at 24 seeds.

## Result so far

No variant qualifies, so `lan()` keeps memberlist's values. Every change that lowers detection latency costs something the rule forbids:

- **suspicion_mult 3** lowers p50 by 1.9 s and p99 by 1.6 s at 50 nodes, and lowers p99 in every cell. It also adds false deaths in 11 of 26 cells, almost all of them starved nodes that could not refute inside the shorter timeout. At 200 nodes it has 0.06 false deaths per run where `lan()` has none.
- **probe_interval 750 ms** (probe_timeout 375 ms) lowers p99 by 3.4 s at 50 nodes and 4.7 s at 200, but adds false deaths at 50 nodes and false suspicions in 18 cells, because more probes per second mean more accusations by starved nodes. It needs 18% more bandwidth at 50 nodes and 11% at 200.
- **gossip_nodes 5** and **gossip_interval 100 ms** spread the Dead rumour faster, but need 27% and 44% more bandwidth at 50 nodes, and add false suspicions.
- **suspicion_mult 3 with retransmit_mult 5** is the nearest miss. At 50 nodes it lowers p50 by 1.7 s, needs at most 7.9% more bandwidth, and adds false deaths in only one cell: 10% starved, 3% loss, where it has 0.17 per run against 0.08 for `lan()`. With **retransmit_mult 6** it adds no false deaths, but needs 13.4% more bandwidth.

## What the screen showed

- **False deaths are mostly starved nodes losing the refutation race.** At 50 nodes, 60 of the 61 false deaths `lan()` had across all cells were of starved members. Many members suspect a starved node at once, so its timeout drops to the minimum, and its refutation has to reach everyone before that runs out. More retransmits win the race: retransmit_mult 6 removed every false death in every cell screened, and retransmit_mult 2 multiplied them by 40.
- **suspicion_max_mult and expected_confirmations made no difference** to detection or bandwidth in any cell, and moved false deaths only by a few per hundred runs either way. A crashed node is confirmed by many probers within a few seconds, so its suspicion reaches the minimum timeout whatever K is. A healthy member accused by one starved node refutes long before the maximum. suspicion_max_mult 8 gave results identical to `lan()` in every cell: no suspicion ever ran as long as the old maximum, and a timer that never fires changes nothing.
- **probe_timeout between 250 and 750 ms made no difference** beyond noise.
- **Bandwidth depends on the cell.** Without starved nodes or loss, a node sends 245 B/s at 50 nodes and 490 B/s at 200. At 1,000 nodes it sends 1,640 B/s, of which 1,400 B/s is the 30 s TCP push-pull of the full member table (an 8-seed run). With 10% starved nodes, gossip about their false suspicions dominates: 1,560 B/s at 50 nodes, about 4,800 B/s at 200 (an 8-seed run), and about 21 KB/s at 1,000 nodes (a single run). So retransmit and gossip settings cost the most exactly where false suspicions are most frequent.
- **Detection p99 is noisy at 100 seeds.** All healthy nodes of a run detect the crash within a fraction of a second of each other, so the p99 over every node and run is close to the slowest of about 100 runs. Neutral changes such as probe_timeout 250 ms moved p99 by up to 2.6 s either way in single cells. Only changes that move p50 by a second or more, suspicion_mult and probe_interval, lower p99 in every cell.

## The rule

A variant replaces `lan()` only if, in every cell, compared with `lan()` on the same seeds (`verdict_table` in `crates/kinship-sim/tests/tuning.rs`):

- its detection p99 is lower;
- it has no more false deaths and no more false suspicions per run. A count is worse when it is higher by more than 1.645 standard errors (one-sided 5%), or above zero where `lan()` had none, so that noise in the hundreds of false suspicions of a starved cell does not reject a neutral change, while any false death in a cell that had none does;
- it leaves no more crashes undetected;
- it sends at most 10% more bytes per node per second, UDP and TCP together.

## Setup

- **Grid.** The Lifeguard grid of [lifeguard.md](lifeguard.md) with lossless cells added: 0%, 1%, 3% and 5% uniform loss on every link, and 0%, 1%, 5% and 10% of the nodes starved (at least one when the share is not zero), at 50, 200 and 1,000 nodes. A starved node reads every packet 0.5 to 2.5 s late, in order, while its timers fire on time.
- **Run.** 120 simulated seconds. Every node starts knowing every other. At 60 s one healthy node crashes. Each variant of a cell runs the same seeds, so it sees the same starved nodes and the same crash.
- **Variants.** `lan()` with one field moved at a time, in both directions where both are plausible: probe_interval 500, 750 and 1,500 ms (probe_timeout half of it), probe_timeout 250 and 750 ms, suspicion_mult 2, 3 and 5, suspicion_max_mult 4 and 8, expected_confirmations 2 and 5, gossip_interval 100 and 400 ms, gossip_nodes 2 and 5, retransmit_mult 2 and 6. Then suspicion_mult 3 with retransmit_mult 5 and 6.
- **Sealing.** Packets are sealed with a 32-byte key, as in production, so the byte counts include the AEAD overhead. Plaintext would undercount: in one 500-node run sealed UDP bytes were 2.2 times the plaintext ones.
- **Seeds.** 100 per cell at 50 nodes and 50 at 200 nodes in the screen. 16 at 1,000 nodes, only in cells without starved nodes or with 1%. The grid uses 200, 200 and 24.

## Metrics

- **Detection p50 and p99.** Over every healthy node's time from the crash to declaring it dead, nearest-rank, in seconds.
- **False deaths and false suspicions per run.** A running member declared dead, or suspected, at some incarnation by at least one node, counted once per (member, incarnation), as in [lifeguard.md](lifeguard.md).
- **Bytes per node per second.** Every datagram payload sent, lost or not, plus every TCP frame, divided by the nodes and the 120 s. These are the simulator's new `Stats::sent_bytes` and `Stats::stream_bytes` counters.

## Table

Averages over the cells of each size in the screen, against `lan()` on the same cells. False deaths are summed per run across the cells. Bandwidth is the variant's bytes per node per second over `lan()`'s, averaged and at its worst cell. At 200 nodes these are the 10 cells the screen finished for every variant: no starved nodes, 1% starved, and 5% starved without loss and with 1% loss.

| Nodes | Variant | False deaths per run, sum | False suspicions per run | Detection p50 (s) | Detection p99 (s) | Bandwidth, mean | Bandwidth, worst |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 50 | `lan` | 0.61 | 62.4 | 8.61 | 12.94 | 1.000 | 1.000 |
| 50 | `probe_interval=500ms probe_timeout=250ms` | 24.27 | 82.6 | 4.36 | 6.46 | 1.406 | 1.572 |
| 50 | `probe_interval=750ms probe_timeout=375ms` | 1.90 | 70.4 | 6.48 | 9.54 | 1.141 | 1.181 |
| 50 | `probe_interval=1500ms probe_timeout=750ms` | 0.17 | 49.9 | 12.88 | 19.13 | 0.832 | 0.902 |
| 50 | `probe_timeout=250ms` | 0.72 | 62.5 | 8.62 | 12.75 | 1.003 | 1.009 |
| 50 | `probe_timeout=750ms` | 0.90 | 63.2 | 8.60 | 12.92 | 1.001 | 1.007 |
| 50 | `suspicion_mult=2` | 33.37 | 62.4 | 5.22 | 9.36 | 0.977 | 0.999 |
| 50 | `suspicion_mult=3` | 3.44 | 62.4 | 6.90 | 11.34 | 0.988 | 1.000 |
| 50 | `suspicion_mult=5` | 0.11 | 62.4 | 10.31 | 14.71 | 1.011 | 1.040 |
| 50 | `suspicion_max_mult=4` | 0.65 | 62.4 | 8.60 | 12.94 | 1.000 | 1.000 |
| 50 | `suspicion_max_mult=8` | 0.61 | 62.4 | 8.61 | 12.94 | 1.000 | 1.000 |
| 50 | `expected_confirmations=2` | 0.68 | 62.4 | 8.61 | 12.94 | 1.000 | 1.000 |
| 50 | `expected_confirmations=5` | 0.50 | 62.4 | 8.61 | 12.94 | 1.000 | 1.000 |
| 50 | `gossip_interval=100ms` | 0.48 | 64.6 | 8.58 | 12.70 | 1.279 | 1.436 |
| 50 | `gossip_interval=400ms` | 0.72 | 59.4 | 8.68 | 12.81 | 0.775 | 0.948 |
| 50 | `gossip_nodes=2` | 0.80 | 61.0 | 8.64 | 13.15 | 0.861 | 0.969 |
| 50 | `gossip_nodes=5` | 0.53 | 63.9 | 8.58 | 12.47 | 1.177 | 1.267 |
| 50 | `retransmit_mult=2` | 24.41 | 63.2 | 8.60 | 12.56 | 0.801 | 0.942 |
| 50 | `retransmit_mult=6` | 0.00 | 62.2 | 8.60 | 13.06 | 1.104 | 1.142 |
| 50 | `suspicion_mult=3 retransmit_mult=5` | 0.62 | 62.3 | 6.88 | 11.42 | 1.049 | 1.079 |
| 50 | `suspicion_mult=3 retransmit_mult=6` | 0.13 | 62.1 | 6.90 | 11.36 | 1.090 | 1.134 |
| 200 | `lan` | 0.00 | 75.9 | 11.00 | 15.72 | 1.000 | 1.000 |
| 200 | `probe_interval=500ms probe_timeout=250ms` | 0.90 | 98.3 | 5.58 | 7.23 | 1.245 | 1.312 |
| 200 | `probe_interval=750ms probe_timeout=375ms` | 0.00 | 84.9 | 8.26 | 11.00 | 1.082 | 1.114 |
| 200 | `probe_interval=1500ms probe_timeout=750ms` | 0.00 | 61.5 | 16.53 | 21.79 | 0.913 | 0.990 |
| 200 | `probe_timeout=250ms` | 0.00 | 76.0 | 11.03 | 15.55 | 1.001 | 1.004 |
| 200 | `probe_timeout=750ms` | 0.00 | 76.2 | 11.03 | 15.57 | 1.001 | 1.006 |
| 200 | `suspicion_mult=2` | 0.92 | 75.9 | 6.40 | 11.11 | 0.967 | 0.997 |
| 200 | `suspicion_mult=3` | 0.06 | 75.8 | 8.70 | 13.41 | 0.984 | 0.998 |
| 200 | `suspicion_mult=5` | 0.00 | 75.8 | 13.30 | 18.02 | 1.016 | 1.038 |
| 200 | `suspicion_max_mult=4` | 0.02 | 75.9 | 11.00 | 15.72 | 1.000 | 1.000 |
| 200 | `suspicion_max_mult=8` | 0.00 | 75.9 | 11.00 | 15.72 | 1.000 | 1.000 |
| 200 | `expected_confirmations=2` | 0.04 | 75.9 | 11.00 | 15.72 | 1.000 | 1.000 |
| 200 | `expected_confirmations=5` | 0.00 | 75.9 | 11.00 | 15.72 | 1.000 | 1.000 |
| 200 | `gossip_interval=100ms` | 0.00 | 78.7 | 11.01 | 14.25 | 1.392 | 1.594 |
| 200 | `gossip_interval=400ms` | 0.00 | 71.1 | 11.08 | 13.87 | 0.786 | 0.934 |
| 200 | `gossip_nodes=2` | 0.02 | 73.5 | 11.08 | 15.69 | 0.859 | 0.956 |
| 200 | `gossip_nodes=5` | 0.00 | 77.6 | 11.12 | 14.28 | 1.261 | 1.393 |
| 200 | `retransmit_mult=2` | 2.26 | 76.3 | 10.94 | 14.02 | 0.933 | 0.982 |
| 200 | `retransmit_mult=6` | 0.00 | 75.7 | 11.00 | 15.54 | 1.043 | 1.092 |

`verdict` prints the per-cell verdict for every variant: how many cells lower p99, the cells with more false deaths or false suspicions, and the worst bandwidth ratio.

## What is left

The task to finish before 0.1:

1. Finish the screen: run the `screen` command above. It resumes with the 6 missing 200-node cells (5% starved with 3% and 5% loss, and 10% starved), adds the two combinations to the 10 finished ones, and then runs the 1,000-node cells, an estimated 6 to 7 hours in all.
2. Run the two combinations at 200 and 1,000 nodes. They are already in the screen's list. At 200 nodes `retransmit_mult=6` costs only 9% more bandwidth at worst, because push-pull is a larger share of the bytes there. So `suspicion_mult=3 retransmit_mult=6` may pass the bandwidth limit at 200 and 1,000 nodes even though it fails it at 50.
3. If a variant passes the screen at every size, add it to `GRID` in `crates/kinship-sim/tests/tuning.rs` and run `grid`, which repeats every cell with more seeds: 200 at 50 and 200 nodes, 24 at 1,000. Change `lan()` only if `verdict` says the grid variant qualifies.
4. If `lan()` changes: rerun `chaos bench --nodes 100 --runs 30 --seed 14` in WSL and add the numbers to [detection.md](detection.md) beside the old ones, then update the crash row of the Failure modes table, the preset and Failure detection tables in `docs/design.md`, the README, and the Python `Config` docs and stubs. If nothing qualifies, replace the status line at the top of this report with that conclusion and the numbers.
5. Worth deciding before the grid: whether "lower detection p99" should mean lower in every cell, as `verdict` checks now, or lower on average with p50 lower in every cell, given how noisy a p99 over about 100 runs is.
