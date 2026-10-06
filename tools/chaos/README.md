# Chaos harness

Runs kinship nodes as separate processes on real sockets, each in its own Linux network namespace on a bridge, and injects faults with tc netem and nftables. Linux only. `chaos run` holds kinship to what the simulator asserts; `chaos bench` measures kill -9 detection latency against hashicorp/memberlist, whose node lives in [`../memberlist-bench`](../memberlist-bench).

## Scenarios

`chaos run` starts a fresh cluster for each scenario, waits until every node sees every other alive, then:

| Scenario | Fault | Passes when |
| --- | --- | --- |
| `loss` | netem on every node: 1 to 5% loss, 1 to 20 ms delay, jitter, reordering | no node declares any member dead |
| `kill` | the same netem, then kill -9 of one node | every live node declares it dead within the analytic detection bound of kinship-sim's `swim` tests, and no other member dies |
| `udp-block` | nftables drops one node's UDP, inbound or outbound, under netem without loss | no node suspects it or declares anyone dead, and every other node's `tcp_ping_acks` counts the TCP fallback pings that kept it alive |

The parameters come from `--seed`. A failure prints the scenario, its parameters and the command that replays them; the network is real, so a replay repeats the parameters, not the packet schedule.

## Running it

```bash
cargo build --release -p kinship-chaos
target/release/chaos run --nodes 5 --duration 60            # every scenario, as CI runs it
target/release/chaos run --scenario kill --nodes 5 --seed 7  # one scenario, replayed

cd tools/memberlist-bench && go build -o ../../target/memberlist-node . && cd ../..
target/release/chaos bench --nodes 100 --runs 20 --seed 14 \
  --memberlist-bin target/memberlist-node --csv docs/results/detection.csv
target/release/chaos summarize docs/results/detection.csv
target/release/chaos cleanup                                 # after a crash
```

It needs `ip`, `tc`, `nft` and `setpriv`. Only the network setup, the faults and `ip netns exec` run as root, through `sudo -n`, or through the command in `CHAOS_SUDO` (in WSL without passwordless sudo, `CHAOS_SUDO="wsl.exe -d <distro> -u root --"`). The nodes drop back to your user with setpriv. A run also raises the kernel's shared ARP table limits (`net.ipv4.neigh.default.gc_thresh*`) when the cluster needs more than they allow, and puts them back at the end, including after Ctrl-C.

Each node's stderr goes to `--logs` (default `target/chaos-logs`); `CHAOS_NODE_LOG=kinship_net=debug` raises kinship's log level there.
