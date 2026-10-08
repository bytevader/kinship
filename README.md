# kinship

kinship tells every Python process in a cluster which peers are alive, suspect, dead or gone, within seconds and with no coordinator to run. It is SWIM with the full Lifeguard extensions, written in Rust and run on its own thread, so a blocked event loop or a long GIL hold never makes a healthy node look dead. Gossip is encrypted by default, and every run of the protocol core can be replayed from a seed.

Use it when you are building your own distributed piece (a sharded cache, a job scheduler, a WebSocket fleet, a pool of edge boxes) and you need membership, not consensus. kinship does not elect leaders, store data or give you agreement during a partition.

## Install

```bash
pip install kinship
```

Wheels cover CPython 3.11 and later (abi3) plus free-threaded 3.14t, on Linux (x86_64, aarch64), macOS (arm64, x86_64) and Windows (x86_64). No Rust toolchain is needed.

```bash
cargo add kinship        # tokio runtime and Cluster handle
cargo add kinship-core   # the sans-IO protocol state machine only
```

The Rust crates need Rust 1.85 or later.

## Quickstart

Save this as `demo.py`:

```python
import asyncio, sys, kinship

async def main(port: int, seeds: list[str]) -> None:
    cfg = kinship.Config.local(bind=f"127.0.0.1:{port}", seeds=seeds)
    async with kinship.Cluster(cfg) as cluster:
        async for event in cluster.events():
            print(event, sorted(m.name for m in cluster.members()))

port, *seeds = sys.argv[1:]
asyncio.run(main(int(port), [f"127.0.0.1:{s}" for s in seeds]))
```

Run it in three terminals, then press Ctrl-C in one of them:

```bash
python demo.py 7946
python demo.py 7947 7946
python demo.py 7948 7946
```

```text
MemberJoined(laptop-4be1c9) ['laptop-4be1c9', 'laptop-a07f3e', 'laptop-d2913b']
MemberLeft(laptop-d2913b) ['laptop-4be1c9', 'laptop-a07f3e']
```

Kill a process with `kill -9` instead and you see `MemberSuspect`, then `MemberDead` a few seconds later. `Config.local()` runs without encryption because it only binds loopback. Anything that leaves the host needs a key, as below.

## Going beyond one machine

```bash
python -m kinship keygen     # prints a base64 32-byte key; give the same key to every node
```

```python
cfg = kinship.Config.lan(
    name="cache-07",                     # stable names survive restarts
    keys=[os.environ["KINSHIP_KEY"]],
    seeds=["10.0.0.5:7946", "10.0.0.6:7946"],
    cluster="cache-prod",                # clusters with other labels ignore you
)
```

Every node can share the same seed list, including itself. A seed that is down or is the node itself is skipped, and a node that reaches no seed starts alone and keeps retrying in the background.

## How membership works

Each node probes one peer per round. A peer that misses its probe becomes **suspect**, and the suspicion spreads by gossip. The suspect node hears the rumour and refutes it if it is alive; otherwise it becomes **dead** a few seconds later. A node that shuts down cleanly becomes **left** instead of dead. Views are eventually consistent: two nodes can disagree for a few gossip rounds, and a partition gives you two groups that each think the other is dead until it heals.

## Cluster

```python
async with kinship.Cluster(cfg) as cluster:   # binds, then joins cfg.seeds
    ...
# on exit: leave(timeout=5.0), then close()
```

| Call | Returns | What it does |
| --- | --- | --- |
| `await cluster.join(seeds=None)` | `int` | Push-pull with each seed until one answers; returns how many answered. Raises `JoinError` if none did. With no argument it uses `cfg.seeds`. |
| `cluster.members()` | `list[Member]` | Alive and suspect members, the local node included. Never waits on the network. |
| `cluster.member(name)` | `Member \| None` | One member by name, including dead and left tombstones. |
| `cluster.local` | `Member` | This node as the cluster sees it. |
| `cluster.events()` | `EventStream` | A new async iterator of events; see below. |
| `await cluster.set_meta(meta)` | `None` | Replace this node's metadata and gossip it. |
| `await cluster.update_meta(**changes)` | `None` | Change some metadata keys; a value of `None` deletes the key. |
| `cluster.keyring` | `Keyring` | Runtime key rotation on this node; see Encryption. |
| `cluster.stats()` | `Stats` | Counters: local health score, probes, suspicions raised and refuted, `decrypt_failures`, `decode_errors`, `replays_dropped`. |
| `await cluster.leave(timeout=5.0)` | `None` | Tell the cluster this node is leaving and wait for it to spread. |
| `await cluster.close()` | `None` | Stop the node and close sockets. Without `leave()` first, peers see a crash. |

If you cannot use `async with`, call `await cluster.start()` yourself and `await cluster.close()` in a `finally`.

A `Member` is frozen and hashable by name:

| Field | Type | Meaning |
| --- | --- | --- |
| `name` | `str` | Unique node name, 1 to 64 UTF-8 bytes |
| `addr` | `str` | Gossip address, `"10.0.0.5:7946"` or `"[fd00::5]:7946"` |
| `state` | `kinship.State` | `ALIVE`, `SUSPECT`, `DEAD` or `LEFT` |
| `incarnation` | `int` | Raised only by the member itself, on refutation or metadata change |
| `meta` | `Mapping[str, str]` | Metadata tags, read-only |

## Events

```python
async for event in cluster.events():
    match event:
        case kinship.MemberJoined(member=m):
            ring.add(m)
        case kinship.MemberSuspect(member=m):
            log.warning("%s is not answering", m.name)
        case kinship.MemberDead(member=m) | kinship.MemberLeft(member=m):
            ring.remove(m)
        case kinship.MemberUpdated(member=m, previous_meta=old):
            ring.update(m)
        case kinship.EventsLost(count=n):
            ring.rebuild(cluster.members())
```

| Event | Fields | When |
| --- | --- | --- |
| `MemberJoined` | `member` | A node is alive that was unknown, dead or left |
| `MemberSuspect` | `member` | A node missed its probes and is suspected |
| `MemberRecovered` | `member` | A suspect node refuted the suspicion and is alive again |
| `MemberDead` | `member` | A suspicion expired without a refutation |
| `MemberLeft` | `member` | A node left on purpose |
| `MemberUpdated` | `member`, `previous_meta` | A node changed its metadata |
| `NameConflict` | `member`, `other_addr` | Two live nodes claim the same name; the newer one is ignored |
| `EventsLost` | `count` | Your consumer fell behind and `count` events were dropped |

Events never describe the local node, except `NameConflict`. Each call to `events()` is an independent subscription that starts at the moment of the call, not at the first `await`, so nothing is missed between `events()` and the loop. Every subscription buffers up to `event_buffer` events (1,024). When a slow consumer fills it, kinship drops the oldest events and your next read is `EventsLost(n)`; call `cluster.members()` and resync. The protocol never waits for you.

The iterator ends when the cluster closes. If the node stopped because of an internal error, it raises `KinshipClosed` instead.

## Metadata

Every node carries a few string tags that all other nodes can read, for facts such as role, zone, version, an application port or a load hint.

```python
cfg = kinship.Config.lan(..., meta={"role": "cache", "zone": "eu-1", "http": "10.0.0.7:8080"})

await cluster.update_meta(role="draining")       # merge
await cluster.set_meta({"role": "cache"})        # replace
zone = cluster.member("cache-03").meta["zone"]  # read anyone's
```

Encoded tags must fit in 512 bytes; a larger value raises `kinship.MetaTooLarge`, a `ValueError`. A change reaches every node in a few gossip rounds, under a second on `lan()` at 100 nodes, and other nodes see it as `MemberUpdated`. Ten quick updates cost one broadcast, because only the newest value is gossiped. Larger application state belongs in your own channel; use metadata to find it.

## Configuration

Pick a preset and override fields by name. Presets differ only in timing.

| Preset | Use it for | Changes from `lan()` |
| --- | --- | --- |
| `Config.lan()` | One datacenter or VPC | none |
| `Config.wan()` | Regions, edge sites, flaky links | probes every 5 s with a 3 s timeout, slower suspicion, push-pull every 60 s |
| `Config.local()` | Tests, demos, the visualizer | probes every 200 ms, loopback only, plaintext allowed, no TCP fallback ping |

```python
cfg = kinship.Config.wan(keys=[key], probe_interval=4.0)
cfg2 = cfg.replace(name="edge-12")    # configs are frozen
```

Durations are seconds as `float`, or a `datetime.timedelta`. Every field is validated when the config is built, so `kinship.ConfigError` (a `ValueError` that names the field) fires before any socket opens. The full field list lives in the configuration reference; the ones you are most likely to set are `name`, `bind`, `advertise`, `cluster`, `seeds`, `meta`, `keys` and `event_buffer`. Use `bind="0.0.0.0:0"` to let the OS pick a port when several processes share a host, and read it back from `cluster.local.addr`.

## Encryption and keys

Every packet and stream is sealed with XChaCha20-Poly1305 and bound to your cluster label. A node without the key cannot read, join or inject anything, and packets it recorded are refused when it plays them back. Keys are 32 bytes, given as `bytes` or base64 text, and never logged. The threat model and what kinship does not protect against are in [SECURITY.md](SECURITY.md).

The first key in `keys` encrypts; every key in the list decrypts. Rotate with no downtime in three steps, each run on every node:

```python
await cluster.keyring.install(new_key)   # 1. every node can now read the new key
await cluster.keyring.use(new_key)       # 2. every node sends with it
await cluster.keyring.remove(old_key)    # 3. the old key is gone
print(cluster.keyring.key_ids())         # ['9f3a01c2', ...], safe to log
```

Finish each step on every node before starting the next. A node that falls behind looks dead to the others until it catches up, and `cluster.stats().decrypt_failures` counts what it dropped. Changing `keys` in your config and restarting nodes one by one does the same thing.

Inside the node, keys live in one place and are wiped from memory when removed or when the node closes. Python cannot wipe a `bytes` or `str`, so a key you hold as one stays in memory until Python reuses it: read it from a file or the environment just before you build the config, pass it straight in, and drop your references to it afterwards. The config keeps its keys until it is freed, and a cluster keeps its config.

To run without encryption beyond loopback, set `insecure_plaintext=True`; kinship logs a warning at startup. Without encryption anyone who can reach the port can forge membership, so use it only where everything that can reach the port is trusted. A plaintext node sends only to members it knows, so a forged packet cannot make it send traffic to a third party.

## Logs, fork and threads

kinship runs its protocol on one background thread per process. Logs go to stderr until you call `kinship.log_to_python()`, which routes them to the `kinship` logger. Create clusters after `os.fork()`, never before; using a cluster in a forked child raises `KinshipClosed`. The API is safe to share across threads and works on free-threaded Python.

## Sync code: Flask, Django, Celery

`kinship.blocking` has the same API without `async`. The protocol still runs on kinship's own thread, so a slow request handler cannot make the node look dead.

```python
from kinship.blocking import Cluster

cluster = Cluster(cfg).start()           # binds and joins cfg.seeds, then returns
atexit.register(cluster.close)           # close() runs leave() first

owner = rendezvous.owner(key, cluster.members())
for event in cluster.events(timeout=1.0):   # yields None on each timeout tick
    ...
```

Methods that wait on the network (`join`, `set_meta`, `update_meta`, `leave`, `close` and the keyring calls) block the calling thread and accept `timeout=`. Read events from a dedicated thread. Under Celery or gunicorn's prefork model, start the cluster in the worker after the fork (`worker_process_init`, `post_fork`), and give each worker its own port with `bind="0.0.0.0:0"`.

# Examples

Three of the four examples decide which node owns a key with `kinship.rendezvous.owner(key, members)`. It uses rendezvous (highest random weight) hashing with a stable hash, so every process agrees on the owner, and only the keys of a node that joins or leaves move. Never use Python's built-in `hash()` for this: it differs between processes.

## Sharded cache

Every node holds the keys it owns and fetches the rest from their owner over HTTP. The owner's HTTP address travels in metadata.

```python
import kinship
from kinship.rendezvous import owner

class ShardedCache:
    def __init__(self, cluster: kinship.Cluster, http: aiohttp.ClientSession) -> None:
        self.cluster, self.http, self.data = cluster, http, {}

    async def get(self, key: str) -> bytes | None:
        node = owner(key, self.cluster.members())
        if node.name == self.cluster.local.name:
            return self.data.get(key)
        async with self.http.get(f"http://{node.meta['http']}/cache/{key}") as resp:
            return await resp.read() if resp.status == 200 else None

    async def drop_moved_keys(self) -> None:
        async for event in self.cluster.events():
            if isinstance(event, (kinship.MemberJoined, kinship.EventsLost)):
                me, members = self.cluster.local.name, self.cluster.members()
                for key in [k for k in self.data if owner(k, members).name != me]:
                    del self.data[key]
```

`members()` includes suspect nodes on purpose. A node that is only slow keeps its keys, so a brief stall does not reshuffle the cache; its keys move only once it is dead or has left.

## Single-run cron

Each scheduled job runs on the one alive node that owns the job's name, so jobs spread across the fleet and move when their node dies.

```python
MIN_NODES = 3   # below this, assume we have not found the cluster yet

async def nightly(cluster: kinship.Cluster) -> None:
    while True:
        await sleep_until(hour=2)
        alive = [m for m in cluster.members() if m.state is kinship.State.ALIVE]
        if len(alive) < MIN_NODES:
            continue
        if owner("nightly-report", alive).name == cluster.local.name:
            await build_report(run_id=today())   # must be idempotent on run_id
```

This is best effort, not a lock. During a partition, or for the second or two while views disagree, two nodes can both believe they own a job, so the job must be safe to run twice or take a database lock keyed on `run_id`. The `MIN_NODES` check stops a node that started cut off from the cluster from running every job alone.

## WebSocket room routing

All sockets for one chat room live on the same server, so a message to the room never crosses the network. A client that lands on the wrong server is told where to go.

```python
rooms: dict[str, set[ServerConnection]] = defaultdict(set)

async def handler(ws: ServerConnection) -> None:
    room = ws.request.path.removeprefix("/rooms/")
    node = owner(room, cluster.members())
    if node.name != cluster.local.name:
        await ws.close(4001, node.meta["ws"])   # client reconnects to this URL
        return
    rooms[room].add(ws)
    try:
        async for message in ws:
            broadcast(rooms[room], message)
    finally:
        rooms[room].discard(ws)

async def rebalance() -> None:
    async for event in cluster.events():
        if isinstance(event, (kinship.MemberJoined, kinship.MemberDead,
                              kinship.MemberLeft, kinship.EventsLost)):
            members = cluster.members()
            for room, sockets in list(rooms.items()):
                target = owner(room, members)
                if target.name != cluster.local.name:
                    for ws in list(sockets):
                        await ws.close(4001, target.meta["ws"])
```

Each server advertises its public URL with `meta={"ws": "wss://ws-3.example.com"}`. When a server joins, only the rooms it now owns move to it; when one dies, its clients reconnect and land on the new owners.

## Edge fleet over flaky links

Store gateways join a cluster whose seeds are two regional hubs. A dashboard on each hub shows which stores are up, degraded or down.

```python
cfg = kinship.Config.wan(
    name=os.environ["STORE_ID"],                         # "store-0412", stable across reboots
    bind="100.64.12.7:7946",                             # overlay address, see below
    keys=[Path("/etc/kinship/key").read_text().strip()],
    seeds=["100.64.0.1:7946", "100.64.0.2:7946"],
    cluster="stores-prod",
    meta={"site": "lisbon-2", "sw": VERSION},
)

status: dict[str, kinship.State] = {}

async def track(cluster: kinship.Cluster) -> None:
    events = cluster.events()                      # subscribe first, then read the snapshot
    status.update({m.name: m.state for m in cluster.members()})
    async for event in events:
        match event:
            case kinship.EventsLost():
                status.update({m.name: m.state for m in cluster.members()})
            case kinship.NameConflict(member=m, other_addr=addr):
                alert(f"two boxes claim {m.name}: {m.addr} and {addr}")
            case _:
                status[event.member.name] = event.member.state   # SUSPECT shows as degraded
```

`wan()` probes less often and waits longer before declaring a store dead, and Lifeguard keeps a store whose CPU is pegged from being reported dead. A store that drops off for an hour shows as dead; when its link returns it keeps retrying its seeds in the background and rejoins without a restart. Every node must reach every other node's advertised address over UDP and TCP, so stores behind NAT should run on an overlay network such as WireGuard or Tailscale and bind to that address.

# Rust

The Python package is a thin layer over two Rust crates you can use directly.

## kinship: the tokio handle

```rust
use kinship::{Cluster, Config, Event, Key};
use std::time::Duration;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cfg = Config::lan()
        .with_name("worker-17")
        .with_keys([Key::from_base64(&std::env::var("KINSHIP_KEY")?)?])
        .with_seeds(["10.0.0.5:7946".parse()?]);
    let cluster = Cluster::start(cfg).await?;     // binds, joins seeds
    let mut events = cluster.events();
    while let Some(event) = events.recv().await {
        match event {
            Event::MemberDead(m) | Event::MemberLeft(m) => println!("{} is gone", m.name),
            Event::EventsLost(_) => println!("resync: {} members", cluster.members().len()),
            _ => {}
        }
    }
    cluster.leave(Duration::from_secs(5)).await?;
    Ok(())
}
```

The Rust and Python APIs share names: `Cluster`, `Config::lan()`, `members()`, `events()`, `set_meta()`, `keyring()`, `leave()`, `close()`. The Rust keyring has `install`, `use_key` (`use` is a keyword), `remove` and `key_ids`. `Config` is built with `with_*` setters so new fields can be added without a breaking release, and it is validated by `Cluster::start`. `Event` is `#[non_exhaustive]`.

The `kinship-agent` example joins a cluster from seeds on the command line and logs every event until Ctrl-C, when it leaves:

```bash
cargo run -p kinship --example kinship-agent -- --bind 127.0.0.1:7946
cargo run -p kinship --example kinship-agent -- --bind 127.0.0.1:7947 127.0.0.1:7946
```

## kinship-core: sans-IO SWIM

`kinship-core` is the whole protocol with no sockets, clocks, threads or randomness of its own. You feed it bytes and the time, and it tells you what to send and when to wake it. Use it to run SWIM on your own runtime, an embedded event loop or a simulator.

```rust
use kinship_core::{Command, Config, Event, Identity, Instant, Node, StreamEvent, Transmit};

// Both from the OS RNG: the seed for protocol choices, 32 bytes for the nonces' ChaCha20 key.
let mut node = Node::new(cfg, Identity::new("a", my_addr)?, Instant::ZERO, seed, &nonce_key)?;
let join = node.command(now, Command::Join { seeds: vec![seed_addr] });   // a CommandId

// Feed every input with the current time:
node.handle_datagram(now, from, &buf);
node.handle_stream(now, conn, StreamEvent::Frame(&frame));
node.handle_stream(now, conn, StreamEvent::Failed);   // connect refused, timeout, reset
node.handle_timeout(now);

// Then drain the outputs:
while let Some(t) = node.poll_transmit() {
    match t {
        Transmit::Datagram { to, payload } => udp_send(to, &payload),
        Transmit::Connect { conn, to } => tcp_connect(conn, to),
        Transmit::Stream { conn, frame } => tcp_send(conn, &frame),
        Transmit::Close { conn } => tcp_close(conn),
    }
}
while let Some(event) = node.poll_event() {
    match event {
        Event::CommandDone { id, result } if id == join => println!("joined: {result:?}"),
        other => handle(other),
    }
}
let wake_at: Option<Instant> = node.poll_timeout();
```

The same seed, nonce key and inputs always give the same outputs, byte for byte, which is how `kinship-sim` replays any failure from its seed, from which it derives both. Encryption happens inside the core, so the bytes in `payload` and `frame` are already sealed.
