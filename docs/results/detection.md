# Detection latency against memberlist

kill -9 of one node in a 100-node cluster, 30 runs each for kinship and hashicorp/memberlist, on real sockets. The raw numbers are in [detection.csv](detection.csv), one row per live node per run. To rerun the comparison (about an hour on 8 cores; it resumes from the CSV, so delete the CSV to start over), on Linux with root through `sudo -n` or `CHAOS_SUDO` (see [tools/chaos](../../tools/chaos/README.md)):

```bash
cargo build --release -p kinship-chaos
(cd tools/memberlist-bench && go build -o ../../target/memberlist-node .)
target/release/chaos bench --nodes 100 --runs 30 --seed 14 \
  --memberlist-bin target/memberlist-node --csv docs/results/detection.csv
target/release/chaos summarize docs/results/detection.csv
```

The `Detection latency` workflow runs the same command, 20 runs by default, every Monday and on demand, and attaches the CSV.

## Result

kinship and memberlist detect a kill -9 equally fast. Over 2,970 detections each, kinship's median is 9.52 s against 9.86 s, its 99th percentile 12.50 s against 11.98 s, and its maximum 12.57 s against 12.11 s. Every live node declared the killed node dead in every run, and neither had a false death. Paired run by run, kinship's median was lower in 20 of 30 runs, by 0.18 s on average.

That is what the shared timing predicts: both run memberlist's LAN values, and kinship's `lan()` preset copies them. With 99 probers, someone probes the killed node within about a second. That round fails a second later, and the suspicion then waits for the minimum timeout, 4 × log10(100) × 1 s = 8 s, because the other probers' confirmations arrive well inside it. About 9.5 s in all, and the spread above that comes from how long the first probe takes to come round. The analytic bound the `kill` chaos scenario and the simulator hold kinship to is 209 s at 100 nodes; it covers the worst order of probes, not the typical one.

Where they differ is how fast the Dead rumour reaches everyone. Within a run, kinship's slowest node trails its fastest by 0.09 s at the median and 0.25 s at most; memberlist's by 0.38 s and 0.52 s. So "every node" times sit closer to the first detection for kinship.

## Setup

- **Topology.** 100 processes, each in its own network namespace with a veth on one bridge, as `tools/chaos` builds it. Both implementations ran in the same namespaces, the runs interleaved (kinship run 0, memberlist run 0, kinship run 1, ...), and each run killed the same node in both, drawn from seed 14.
- **Network.** tc netem on every node's egress: 2 ms delay, 1 ms jitter, 1% loss, for the whole bench, joins included.
- **kinship.** `chaos-node` with `Config::lan()` and a 32-byte key.
- **memberlist.** v0.7.0, `memberlist.DefaultLANConfig()` with the same key as `SecretKey`, built with Go 1.26.
- **Run.** Start node 0, then the other 99 in waves of 25 joining it; wait until every node reports every other alive; settle 15 s; kill -9 one node other than node 0. A run ends when every live node has declared it dead, or at the 209 s bound.
- **Host.** WSL2 on Windows 11, Linux 6.18, 8 vCPUs, 7 GB.

## Metrics

- **Detection.** For each live node, the time from the kill to its dead event for the killed node: kinship's `MemberDead`, memberlist's `NotifyLeave` with the node in `StateDead`. Both node programs print the event as a line on stdout, and the harness times the line when it arrives, so both carry the same few milliseconds of pipe latency. p50, p99 and max are nearest-rank over every (run, node) pair.
- **Every node.** Per run, the time until the last live node declared it dead; p50 and max over the 30 runs.
- **Undetected.** Live nodes that never declared the killed node dead within the bound.
- **False deaths.** Dead events about any other node, from the end of convergence to the end of the run.

## Table

| Implementation | Runs | Detections | p50 (s) | p99 (s) | Max (s) | Every node, p50 (s) | Every node, max (s) | Undetected | False deaths |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| kinship | 30 | 2970 | 9.522 | 12.500 | 12.568 | 9.587 | 12.568 | 0 | 0 |
| memberlist | 30 | 2970 | 9.857 | 11.980 | 12.106 | 10.020 | 12.106 | 0 | 0 |

## Convergence

Not measured as a result, but visible in the run log: kinship's 100 nodes saw each other within 1 s in 28 runs and within 6.5 s in all 30. memberlist did so within 2 s in 28 runs; in the other two one node missed a join whose gossip was lost and caught up only at its next push-pull, which memberlist stretches to every 90 s at 100 nodes, after 54 s and 101 s. A first attempt at the bench gave up on convergence after 80 s and stopped on one such run; the limit is now 230 s, and the runs before it were kept, since convergence happens before the kill and is not part of what is timed.
