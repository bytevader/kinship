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

Refreshed on 2026-10-11 against the fixes for KI-02, KI-03, KI-04 and KI-06 (`detection.csv`), with the same command run on unchanged main the same morning as a control. kinship and memberlist detect a kill -9 in the same median time, about 9.7 s against 9.8 s, in every run of all three benches below; every live node declared the killed node dead in every run, and neither had a false death. Where they differ is the tail: in today's two runs kinship's slowest runs took 14 to 24 s where memberlist's took 12 to 13 s.

| Bench | kinship p50 / p99 / max (s) | memberlist p50 / p99 / max (s) | kinship's run median lower in | by, on average |
| --- | --- | --- | --- | --- |
| 2026-10-11, with the fixes | 9.695 / 16.342 / 16.392 | 9.827 / 13.346 / 13.443 | 16 of 30 runs | -0.67 s |
| 2026-10-11, unchanged main (control) | 9.679 / 23.843 / 24.181 | 9.803 / 12.339 / 12.589 | 14 of 30 runs | -0.98 s |
| 2026-10-08, published before the fixes | 9.522 / 12.500 / 12.568 | 9.857 / 11.980 / 12.106 | 20 of 30 runs | +0.18 s |

The fixes do not move detection: the control on unchanged main has the same median and a longer tail, and every 1,000-seed simulator sweep gives the same numbers with and without them, since they change no choice an honest run makes (`member-findings-validation.md`). The wider tail is in both of today's runs and not in the published one, so it comes from the environment of the day or the run's luck, not from the change; today's runs were built with the WSL default nightly toolchain. In the slow runs every node detects within a fraction of a second of the others, so the delay is in when the first suspicion starts, not in spreading the Dead; finding out why some runs take that long to start one is open, and the four slowest kinship runs of each CSV are where to look (runs 10, 14, 24 and 25 with the fixes, 10, 14, 18 and 20 on main). The control's CSV is not kept in the repository; the bench resumes from a CSV, so rerunning it on main with a fresh one reproduces it.

That is what the shared timing predicts: both run memberlist's LAN values, and kinship's `lan()` preset copies them. With 99 probers, someone probes the killed node within about a second. That round fails a second later, and the suspicion then waits for the minimum timeout, 4 × log10(100) × 1 s = 8 s, because the other probers' confirmations arrive well inside it. About 9.5 s in all, and the spread above that comes from how long the first probe takes to come round. The analytic bound the `kill` chaos scenario and the simulator hold kinship to is 209 s at 100 nodes; it covers the worst order of probes, not the typical one.

Where they differ is how fast the Dead rumour reaches everyone. Within a run, kinship's slowest node trails its fastest by 0.08 s at the median and 0.28 s at most; memberlist's by 0.37 s and 0.51 s (0.09 and 0.25 s against 0.38 and 0.52 s in the published run). So "every node" times sit closer to the first detection for kinship.

## Setup

- **Topology.** 100 processes, each in its own network namespace with a veth on one bridge, as `tools/chaos` builds it. Both implementations ran in the same namespaces, the runs interleaved (kinship run 0, memberlist run 0, kinship run 1, ...), and each run killed the same node in both, drawn from seed 14.
- **Network.** tc netem on every node's egress: 2 ms delay, 1 ms jitter, 1% loss, for the whole bench, joins included.
- **kinship.** `chaos-node` with `Config::lan()` and a 32-byte key, built in release with the WSL default toolchain, rustc 1.101.0-nightly, for the 2026-10-11 runs.
- **memberlist.** v0.7.0, `memberlist.DefaultLANConfig()` with the same key as `SecretKey`, built with Go 1.26.
- **Run.** Start node 0, then the other 99 in waves of 25 joining it; wait until every node reports every other alive; settle 15 s; kill -9 one node other than node 0. A run ends when every live node has declared it dead, or at the 209 s bound.
- **Host.** WSL2 on Windows 11, Linux 6.18, 8 vCPUs, 7 GB.

## Metrics

- **Detection.** For each live node, the time from the kill to its dead event for the killed node: kinship's `MemberDead`, memberlist's `NotifyLeave` with the node in `StateDead`. Both node programs print the event as a line on stdout, and the harness times the line when it arrives, so both carry the same few milliseconds of pipe latency. p50, p99 and max are nearest-rank over every (run, node) pair.
- **Every node.** Per run, the time until the last live node declared it dead; p50 and max over the 30 runs.
- **Undetected.** Live nodes that never declared the killed node dead within the bound.
- **False deaths.** Dead events about any other node, from the end of convergence to the end of the run.

## Table

With the fixes, 2026-10-11, the run in `detection.csv`:

| Implementation | Runs | Detections | p50 (s) | p99 (s) | Max (s) | Every node, p50 (s) | Every node, max (s) | Undetected | False deaths |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| kinship | 30 | 2970 | 9.695 | 16.342 | 16.392 | 9.786 | 16.392 | 0 | 0 |
| memberlist | 30 | 2970 | 9.827 | 13.346 | 13.443 | 9.988 | 13.443 | 0 | 0 |

Unchanged main, the same morning:

| Implementation | Runs | Detections | p50 (s) | p99 (s) | Max (s) | Every node, p50 (s) | Every node, max (s) | Undetected | False deaths |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| kinship | 30 | 2970 | 9.679 | 23.843 | 24.181 | 9.785 | 24.181 | 0 | 0 |
| memberlist | 30 | 2970 | 9.803 | 12.339 | 12.589 | 9.945 | 12.589 | 0 | 0 |

Published on 2026-10-08, before the fixes:

| Implementation | Runs | Detections | p50 (s) | p99 (s) | Max (s) | Every node, p50 (s) | Every node, max (s) | Undetected | False deaths |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| kinship | 30 | 2970 | 9.522 | 12.500 | 12.568 | 9.587 | 12.568 | 0 | 0 |
| memberlist | 30 | 2970 | 9.857 | 11.980 | 12.106 | 10.020 | 12.106 | 0 | 0 |

## Convergence

Not measured as a result, but visible in the run log. With the fixes, kinship's 100 nodes saw each other within 1.4 s in every run; memberlist's within 2 s in 28 runs, and after 91 s and 93 s in the other two, when a node missed a join whose gossip was lost and caught up only at its next push-pull, which memberlist stretches to every 90 s at 100 nodes. On unchanged main the same morning kinship converged within 0.8 s in all but one run, which took 20 s, and memberlist at most 109.5 s. In the published run kinship converged within 6.5 s in all 30 runs and memberlist after 54 s and 101 s in its two slow ones. A first attempt at that bench gave up on convergence after 80 s and stopped on one such run; the limit is now 230 s. Convergence happens before the kill and is not part of what is timed.
