# Tuning the timing presets

**Status: done, `lan()` unchanged.** No variant passes [the rule](#the-rule) at every cluster size, so `lan()` keeps memberlist's LAN values. The one-field screen and the two combinations ran on every cell at 50 and 200 nodes and on the cells without starved nodes or with 1% at 1,000, on main with the fixes for KI-02, KI-03, KI-04 and KI-06 (#21) and the probe-order fix (#22). The grid did not run, because it repeats only variants that pass the screen at every size.

Simulated with `kinship-sim`. The raw numbers are in [tuning.csv](tuning.csv), one row per stage, cell and variant. The sweeps resume from the CSV, so rerunning a command finishes what is missing and skips what is there:

```bash
cargo test --release -p kinship-sim --test tuning -- --ignored --nocapture --exact screen
cargo test --release -p kinship-sim --test tuning -- --ignored --nocapture --exact grid
cargo test --release -p kinship-sim --test tuning -- --ignored --nocapture --exact verdict
```

`KINSHIP_NODES=1000` runs one cluster size, so sizes can run on different machines and their rows be concatenated: the simulator gives byte-identical rows on x86-64 Windows and arm64 macOS (checked on the 16 `lan` cells at 50 nodes). On a 4-core, 8-thread Ryzen 5 3550H laptop the 50-node screen took 64 minutes and the 200-node screen 6.7 hours, a cell with 10% starved nodes about 2 minutes per variant. The 1,000-node screen took 1 hour 50 minutes on an M5 Pro.

## Result

No variant qualifies. Every change that lowers detection latency costs something the rule forbids, at least at one cluster size:

- **suspicion_mult 3 with retransmit_mult 5**, the nearest miss, lowers p50 by 2.1 s and p99 by 1.8 s on average, and passes at 1,000 nodes: p99 3.0 s lower in all 8 cells, no false deaths, at most 6.8% more bandwidth. It fails at 50 nodes, where it raises p99 in 5 of 16 cells, adds false deaths in 3 cells (0.01 to 0.04 per run where `lan()` had none) and needs 12.4% more bandwidth, and at 200 nodes, where it needs 13.0% more with 10% of the nodes starved and raises p99 in one of those cells.
- **suspicion_mult 3 with retransmit_mult 6** adds false deaths in only one cell (50 nodes, 10% starved, 1% loss: 0.01 per run against none), but needs up to 22.5% more bandwidth at 50 nodes, 24.5% at 200 and 13.1% at 1,000.
- **suspicion_mult 3** alone lowers p99 in 38 of 40 cells at no bandwidth cost, but adds false deaths in 10 cells, 9 of them at 50 nodes: 63 false deaths across the screen, all of starved nodes, where `lan()` had 11.
- **probe_interval 750 ms** (probe_timeout 375 ms) lowers p99 in every cell, by 4.1 s on average, but adds false deaths in 7 cells and false suspicions in 28, and needs up to 22.8% more bandwidth.
- **gossip_interval 400 ms** and **gossip_nodes 2** lower p99 in every 1,000-node cell, by 1 to 2 s, with less bandwidth, and pass the rule at that size. At 50 and 200 nodes they raise p99 in about half the cells and add a false death in one or two.

Changing the rule would not change this. With "lower detection p99" read as lower on average, with p50 lower in every cell (the open question of the interim report), six variants pass the latency test, and each of them adds false deaths or needs more than 10% more bandwidth.

## What the screen showed

- **False deaths are starved nodes losing the refutation race.** Of 4,005 false deaths across every variant and cell, 3,980 were of starved members. Many members suspect a starved node at once, so its timeout drops to the minimum, and its refutation has to reach everyone before that runs out. More retransmits win the race: retransmit_mult 6 had no false death in any cell, and retransmit_mult 2 had 666 where `lan()` had 11.
- **The fixes made `lan()` safer.** Summed over the 16 cells at 50 nodes, `lan()` has 0.11 false deaths per run, against 0.61 in the interim screen before #21 and #22. At 200 and 1,000 nodes it has none. That leaves less room for a faster variant, since a false death in a cell where `lan()` has none fails the rule.
- **Retransmits cost the most where they are needed.** In the interim screen, which had not reached the starved 200-node cells, retransmit_mult 6 needed at most 9% more bandwidth at 200 nodes. With 10% of the nodes starved it needs 24.6%, because gossip about their false suspicions dominates the traffic there.
- **suspicion_max_mult made no difference**, and expected_confirmations little. A crashed node is confirmed by many probers within a few seconds, so its suspicion reaches the minimum timeout whatever K is, though with K 5 it takes a moment longer: p50 0.2 s and p99 0.7 s later on average, and lower p99 in no cell. suspicion_max_mult 8 gave results identical to `lan()` in every cell: a timer that never fires changes nothing.
- **probe_timeout between 250 and 750 ms made no difference** beyond noise.
- **Bandwidth depends on the cell.** Without starved nodes or loss, `lan()` sends 226 B/s per node at 50 nodes, 459 B/s at 200 and 1,611 B/s at 1,000, of which 1,396 B/s is the 30 s TCP push-pull of the full member table. With starved nodes, gossip about their false suspicions dominates: 1,400 B/s at 50 nodes and 3,850 B/s at 200 with 10% starved, and 3,930 B/s at 1,000 with 1%.
- **Detection p99 is noisy.** All healthy nodes of a run detect the crash within a fraction of a second of each other, so the p99 over every node and run is close to the slowest of 16 to 100 runs. Neutral changes such as probe_timeout 250 ms moved p99 by up to 2.2 s in single cells. Only changes that move p50 by a second or more, suspicion_mult and probe_interval, lower p99 almost everywhere.

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
- **Seeds.** 100 per cell at 50 nodes and 50 at 200 nodes. 16 at 1,000 nodes, only in cells without starved nodes or with 1%, since a 1,000-node run with 10% starved takes minutes.

## Metrics

- **Detection p50 and p99.** Over every healthy node's time from the crash to declaring it dead, nearest-rank, in seconds.
- **False deaths and false suspicions per run.** A running member declared dead, or suspected, at some incarnation by at least one node, counted once per (member, incarnation), as in [lifeguard.md](lifeguard.md).
- **Bytes per node per second.** Every datagram payload sent, lost or not, plus every TCP frame, divided by the nodes and the 120 s. These are the simulator's `Stats::sent_bytes` and `Stats::stream_bytes` counters.

## Table

Averages over the cells of each size, against `lan()` on the same cells: 16 at 50 and 200 nodes, 8 at 1,000. False deaths are summed per run across the cells. Bandwidth is the variant's bytes per node per second over `lan()`'s, averaged and at its worst cell.

| Nodes | Variant | False deaths per run, sum | False suspicions per run | Detection p50 (s) | Detection p99 (s) | Bandwidth, mean | Bandwidth, worst |
| ---: | --- | ---: | ---: | ---: | ---: | ---: | ---: |
| 50 | `lan` | 0.11 | 63.2 | 8.62 | 12.89 | 1.000 | 1.000 |
| 50 | `probe_interval=500ms probe_timeout=250ms` | 15.64 | 82.9 | 4.38 | 6.43 | 1.500 | 1.631 |
| 50 | `probe_interval=750ms probe_timeout=375ms` | 0.41 | 70.9 | 6.49 | 9.95 | 1.178 | 1.228 |
| 50 | `probe_interval=1500ms probe_timeout=750ms` | 0.03 | 50.4 | 12.87 | 20.28 | 0.784 | 0.835 |
| 50 | `probe_timeout=250ms` | 0.08 | 63.2 | 8.64 | 12.76 | 1.005 | 1.009 |
| 50 | `probe_timeout=750ms` | 0.04 | 63.7 | 8.57 | 13.25 | 1.001 | 1.007 |
| 50 | `suspicion_mult=2` | 10.74 | 63.2 | 5.60 | 10.62 | 0.986 | 1.001 |
| 50 | `suspicion_mult=3` | 0.62 | 63.2 | 7.02 | 11.78 | 0.993 | 1.000 |
| 50 | `suspicion_mult=5` | 0.01 | 63.1 | 10.29 | 14.41 | 1.008 | 1.028 |
| 50 | `suspicion_max_mult=4` | 0.13 | 63.2 | 8.62 | 12.87 | 1.000 | 1.000 |
| 50 | `suspicion_max_mult=8` | 0.11 | 63.2 | 8.62 | 12.89 | 1.000 | 1.000 |
| 50 | `expected_confirmations=2` | 0.21 | 63.2 | 8.60 | 12.71 | 1.000 | 1.001 |
| 50 | `expected_confirmations=5` | 0.01 | 63.2 | 8.87 | 13.87 | 1.000 | 1.002 |
| 50 | `gossip_interval=100ms` | 0.06 | 65.3 | 8.58 | 13.00 | 1.179 | 1.356 |
| 50 | `gossip_interval=400ms` | 0.11 | 59.9 | 8.71 | 13.30 | 0.827 | 0.977 |
| 50 | `gossip_nodes=2` | 0.13 | 61.5 | 8.67 | 12.99 | 0.895 | 0.988 |
| 50 | `gossip_nodes=5` | 0.07 | 64.6 | 8.62 | 13.29 | 1.127 | 1.228 |
| 50 | `retransmit_mult=2` | 5.73 | 64.1 | 8.64 | 12.99 | 0.773 | 0.948 |
| 50 | `retransmit_mult=6` | 0.00 | 62.5 | 8.62 | 13.10 | 1.147 | 1.230 |
| 50 | `suspicion_mult=3 retransmit_mult=5` | 0.16 | 62.8 | 7.01 | 11.95 | 1.075 | 1.124 |
| 50 | `suspicion_mult=3 retransmit_mult=6` | 0.04 | 62.6 | 7.01 | 11.82 | 1.137 | 1.225 |
| 200 | `lan` | 0.00 | 210.8 | 11.07 | 15.58 | 1.000 | 1.000 |
| 200 | `probe_interval=500ms probe_timeout=250ms` | 5.30 | 279.3 | 5.61 | 7.53 | 1.371 | 1.520 |
| 200 | `probe_interval=750ms probe_timeout=375ms` | 0.04 | 237.3 | 8.31 | 11.41 | 1.132 | 1.179 |
| 200 | `probe_interval=1500ms probe_timeout=750ms` | 0.00 | 170.8 | 16.55 | 21.74 | 0.844 | 0.929 |
| 200 | `probe_timeout=250ms` | 0.00 | 211.2 | 11.15 | 15.24 | 1.002 | 1.006 |
| 200 | `probe_timeout=750ms` | 0.00 | 214.0 | 11.12 | 15.11 | 1.003 | 1.014 |
| 200 | `suspicion_mult=2` | 3.92 | 210.8 | 6.79 | 12.08 | 0.988 | 1.000 |
| 200 | `suspicion_mult=3` | 0.02 | 210.9 | 8.87 | 13.35 | 0.994 | 1.000 |
| 200 | `suspicion_mult=5` | 0.00 | 210.9 | 13.37 | 17.88 | 1.006 | 1.023 |
| 200 | `suspicion_max_mult=4` | 0.02 | 210.8 | 11.07 | 15.58 | 1.000 | 1.000 |
| 200 | `suspicion_max_mult=8` | 0.00 | 210.8 | 11.07 | 15.58 | 1.000 | 1.000 |
| 200 | `expected_confirmations=2` | 0.00 | 210.8 | 11.07 | 15.58 | 1.000 | 1.000 |
| 200 | `expected_confirmations=5` | 0.00 | 210.8 | 11.21 | 16.24 | 1.000 | 1.001 |
| 200 | `gossip_interval=100ms` | 0.00 | 218.8 | 11.06 | 14.55 | 1.229 | 1.361 |
| 200 | `gossip_interval=400ms` | 0.02 | 198.3 | 11.21 | 14.86 | 0.819 | 0.977 |
| 200 | `gossip_nodes=2` | 0.00 | 204.7 | 11.20 | 15.60 | 0.889 | 0.986 |
| 200 | `gossip_nodes=5` | 0.02 | 216.0 | 11.15 | 14.48 | 1.158 | 1.241 |
| 200 | `retransmit_mult=2` | 1.86 | 212.3 | 11.03 | 14.92 | 0.800 | 0.959 |
| 200 | `retransmit_mult=6` | 0.00 | 210.5 | 11.16 | 15.39 | 1.143 | 1.246 |
| 200 | `suspicion_mult=3 retransmit_mult=5` | 0.00 | 210.8 | 8.87 | 13.44 | 1.070 | 1.130 |
| 200 | `suspicion_mult=3 retransmit_mult=6` | 0.00 | 210.5 | 8.92 | 13.38 | 1.136 | 1.245 |
| 1,000 | `lan` | 0.00 | 134.0 | 13.92 | 18.49 | 1.000 | 1.000 |
| 1,000 | `probe_interval=500ms probe_timeout=250ms` | 0.00 | 176.4 | 7.08 | 8.85 | 1.176 | 1.298 |
| 1,000 | `probe_interval=750ms probe_timeout=375ms` | 0.00 | 150.4 | 10.41 | 12.46 | 1.063 | 1.105 |
| 1,000 | `probe_interval=1500ms probe_timeout=750ms` | 0.00 | 108.5 | 20.29 | 24.14 | 0.928 | 0.981 |
| 1,000 | `probe_timeout=250ms` | 0.00 | 134.2 | 13.95 | 18.49 | 1.000 | 1.003 |
| 1,000 | `probe_timeout=750ms` | 0.00 | 136.0 | 13.92 | 18.49 | 1.001 | 1.009 |
| 1,000 | `suspicion_mult=2` | 0.06 | 134.2 | 8.06 | 12.49 | 0.987 | 0.995 |
| 1,000 | `suspicion_mult=3` | 0.00 | 133.9 | 10.92 | 15.48 | 0.993 | 0.997 |
| 1,000 | `suspicion_mult=5` | 0.00 | 134.1 | 16.92 | 21.49 | 1.006 | 1.010 |
| 1,000 | `suspicion_max_mult=4` | 0.00 | 134.0 | 13.92 | 18.49 | 1.000 | 1.000 |
| 1,000 | `suspicion_max_mult=8` | 0.00 | 134.0 | 13.92 | 18.49 | 1.000 | 1.000 |
| 1,000 | `expected_confirmations=2` | 0.00 | 134.0 | 13.92 | 18.49 | 1.000 | 1.000 |
| 1,000 | `expected_confirmations=5` | 0.00 | 133.9 | 14.06 | 18.49 | 1.000 | 1.000 |
| 1,000 | `gossip_interval=100ms` | 0.00 | 139.8 | 14.17 | 16.84 | 1.134 | 1.265 |
| 1,000 | `gossip_interval=400ms` | 0.00 | 125.9 | 14.18 | 17.46 | 0.902 | 0.984 |
| 1,000 | `gossip_nodes=2` | 0.00 | 129.7 | 14.00 | 16.35 | 0.940 | 0.991 |
| 1,000 | `gossip_nodes=5` | 0.00 | 137.3 | 14.07 | 16.95 | 1.095 | 1.179 |
| 1,000 | `retransmit_mult=2` | 0.00 | 135.2 | 13.97 | 15.77 | 0.900 | 0.980 |
| 1,000 | `retransmit_mult=6` | 0.00 | 133.9 | 13.95 | 18.48 | 1.073 | 1.135 |
| 1,000 | `suspicion_mult=3 retransmit_mult=5` | 0.00 | 133.8 | 10.95 | 15.49 | 1.031 | 1.068 |
| 1,000 | `suspicion_mult=3 retransmit_mult=6` | 0.00 | 133.9 | 10.95 | 15.48 | 1.065 | 1.131 |

`verdict` prints the per-cell verdict for every variant, over all 40 cells: how many cells lower p99, the cells with more false deaths or false suspicions, and the worst bandwidth ratio.

| Stage | Variant | Cells | p99 lower | Mean p99 change (s) | Worst p99 change (s) | Mean p50 change (s) | More false deaths | More false suspicions | Max bandwidth ratio | Qualifies |
| --- | --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | --- |
| screen | `expected_confirmations=2` | 40 | 7 | -0.074 | +0.000 | -0.008 | 2 | 0 | 1.001 | no |
| screen | `expected_confirmations=5` | 40 | 0 | +0.652 | +2.183 | +0.179 | 0 | 0 | 1.002 | no |
| screen | `gossip_interval=100ms` | 40 | 29 | -0.698 | +2.809 | +0.027 | 2 | 26 | 1.361 | no |
| screen | `gossip_interval=400ms` | 40 | 25 | -0.331 | +2.609 | +0.141 | 2 | 0 | 0.984 | no |
| screen | `gossip_nodes=2` | 40 | 22 | -0.381 | +2.905 | +0.086 | 1 | 0 | 0.991 | no |
| screen | `gossip_nodes=5` | 40 | 26 | -0.587 | +4.818 | +0.061 | 3 | 26 | 1.241 | no |
| screen | `probe_interval=1500ms probe_timeout=750ms` | 40 | 0 | +6.549 | +11.447 | +5.165 | 0 | 0 | 0.981 | no |
| screen | `probe_interval=500ms probe_timeout=250ms` | 40 | 40 | -7.735 | -5.066 | -5.248 | 23 | 28 | 1.631 | no |
| screen | `probe_interval=750ms probe_timeout=375ms` | 40 | 40 | -4.054 | -1.086 | -2.660 | 7 | 28 | 1.228 | no |
| screen | `probe_timeout=250ms` | 40 | 15 | -0.191 | +2.152 | +0.045 | 3 | 2 | 1.009 | no |
| screen | `probe_timeout=750ms` | 40 | 12 | -0.042 | +2.159 | -0.004 | 3 | 15 | 1.014 | no |
| screen | `retransmit_mult=2` | 40 | 26 | -0.771 | +3.076 | -0.000 | 23 | 19 | 0.980 | no |
| screen | `retransmit_mult=6` | 40 | 18 | +0.007 | +3.506 | +0.039 | 0 | 0 | 1.246 | no |
| screen | `suspicion_max_mult=4` | 40 | 2 | -0.010 | +0.000 | -0.000 | 1 | 0 | 1.000 | no |
| screen | `suspicion_max_mult=8` | 40 | 0 | +0.000 | +0.000 | +0.000 | 0 | 0 | 1.000 | no |
| screen | `suspicion_mult=2` | 40 | 40 | -3.512 | -0.144 | -4.095 | 25 | 1 | 1.001 | no |
| screen | `suspicion_mult=3` | 40 | 38 | -1.938 | +0.090 | -2.120 | 10 | 0 | 1.000 | no |
| screen | `suspicion_mult=3 retransmit_mult=5` | 40 | 34 | -1.836 | +1.702 | -2.121 | 3 | 1 | 1.130 | no |
| screen | `suspicion_mult=3 retransmit_mult=6` | 40 | 38 | -1.910 | +1.807 | -2.103 | 1 | 0 | 1.245 | no |
| screen | `suspicion_mult=5` | 40 | 1 | +2.129 | +3.004 | +2.187 | 0 | 0 | 1.028 | no |

## What would change it

The rule rejects every faster variant at 50 or 200 nodes, mostly on false deaths of starved nodes and on the bandwidth of the retransmits that prevent them. Two things could change that, and neither is planned for 0.1:

- **A preset for large clusters.** suspicion_mult 3 with retransmit_mult 5 passes every 1,000-node cell. It would need its own grid run at 1,000 nodes with 24 seeds and every starved share, and a chaos bench at that size.
- **A cheaper refutation.** A starved node loses because its Alive must outrun a timeout that many accusers shorten at once. A change that lets it refute sooner, rather than one that sends every rumour more often, would let suspicion_mult 3 keep its latency without the false deaths.
