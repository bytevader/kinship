# Changelog

All notable changes to kinship are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The finding ids (KS-, KI-, KP-) refer to [SECURITY.md](SECURITY.md) and [docs/review.md](docs/review.md).

## [Unreleased]

### Added

- **`kinship.ring`.** `Ring(cluster, where=...)` keeps rendezvous ownership in step with membership, over the members whose metadata matches `where` or a predicate, on `kinship.Cluster` and `kinship.blocking.Cluster`: `owner()`, `replicas()`, `members()`, and `moved()` for the keys that changed owner between two snapshots. Suspect members keep their keys; `new_work=True` skips them for routing new requests. `changes()` yields `RingChanged(added, removed, suspect, recovered, members)` from the cluster's events, including metadata updates that flip a `where` match, and resyncs after `EventsLost`.
- **FastAPI integration.** `kinship.contrib.fastapi`, behind the `kinship[fastapi]` extra: `cluster_lifespan()` runs a cluster for the app's lifetime on `app.state.cluster` and leaves on shutdown, `get_cluster` and `get_ring(where=...)` are dependencies, and `cluster_router()` serves `GET /members` and `GET /stats`. The core package gains no dependency.
- **Example.** `examples/fastapi_app.py`: a sharded cache as three FastAPI apps in one process, driven through httpx's ASGI transport.

## [0.1.1] - 2026-10-13

### Added

- **Seeds by DNS name.** A seed's host can be a DNS name as well as an IP address, so `"node-1:7946"` in docker compose and a Kubernetes headless Service such as `"kinship.default.svc.cluster.local:7946"` work as seeds. Names are looked up again at every join and every `rejoin_interval` retry, and every address a name returns, A and AAAA alike, is a seed. Python takes names wherever it takes seeds (`Config(seeds=...)` and `join()`); Rust adds `Seed`, `Config::with_seed_hosts`, `Cluster::join_seeds` and `Memberlist::join_seeds`, and `kinship-agent` takes names on its command line. The core still sees only addresses: lookups happen in `kinship-net`.
- **`resolve_timeout`** (30 s): how long a join keeps looking seed names up while none resolves. A name that does not resolve is logged and looked up again; a start fails, with `JoinError` in Python and `Error::Unresolved` in Rust, only if no seed resolved within it.
- **musllinux wheels.** abi3 wheels for musllinux_1_2 on x86_64 and aarch64, so Alpine installs a wheel instead of building the sdist. CI builds and tests them in Alpine on every pull request.
- **Release smoke test.** After the upload, `release.yml` installs the release from PyPI on Linux, macOS and Windows and runs `examples/quickstart.py` as two nodes (`tools/smoke_quickstart.py`).

### Changed

- `kinship-agent` no longer resolves a seed name once at startup and keeps its first address; it passes the name on, so the node follows it.

## [0.1.0] - 2026-10-12

The first release.

### Added

- **Protocol.** SWIM membership and failure detection: randomized round-robin probes, indirect probes through relays, suspicion, incarnation numbers, and gossip piggybacked on every packet, with push-pull state exchange over TCP for joins, periodic anti-entropy and reconnects to recently dead members, and a TCP fallback ping when UDP probes go unanswered.
- **Lifeguard.** Local health that stretches a slow node's own timeouts, Nacks from relays, suspicion timeouts that shrink as independent members confirm them, and the buddy system, each behind its own config flag.
- **Graceful leave.** `leave()` gossips Left at once and waits until it has reached live members; members that left are never reported dead, even when several leave one after another.
- **Metadata.** Up to 512 bytes per member, gossiped as part of its Alive; Python sees it as string tags with `set_meta` and `update_meta`, Rust as raw bytes too.
- **Configuration.** `lan()`, `wan()` and `local()` presets with every field overridable and validated before any socket opens, including limits that keep a member's own Alive inside a datagram, the inbound connection limits, and `rejoin_interval`, which keeps retrying configured seeds that are not live members.
- **Encryption.** XChaCha20-Poly1305 on every datagram and stream frame, bound to the cluster label, with runtime key rotation (`keyring.install`, `use`, `remove`, `key_ids`) and `generate_key()` / `python -m kinship keygen`.
- **Replay protection.** Every nonce carries the sender's cluster time, kept in step by gossip without synchronized wall clocks; recorded packets older than the replay window and copies inside it are dropped.
- **Member limits.** `max_members` (8,192) and `max_new_members_per_packet` (1,024) bound the member table and what one packet can add, with refusals counted in `members_refused`.
- **Python package.** `kinship.Cluster` for asyncio and `kinship.blocking.Cluster` for synchronous code, frozen `Config` and `Member` types, an events iterator with per-subscription buffers and `EventsLost`, `stats()`, `kinship.rendezvous.owner()` and `owners()`, and a bridge from Rust logs to `logging`. abi3 wheels for CPython 3.11 and later, and free-threaded 3.14t.
- **Examples.** Runnable scripts in `examples/`: a three-terminal quickstart, key ownership with rendezvous hashing, a job that fails over to another node, and the blocking API routing around a draining node. `tests/test_examples.py` runs them.
- **Rust crates.** `kinship` (the tokio `Cluster` handle and `kinship-agent` example), `kinship-core` (the sans-IO protocol state machine, which reads no clock, socket or randomness of its own), `kinship-net` (the tokio UDP and TCP driver) and `kinship-proto` (wire format and codec).
- **Testing.** A deterministic simulator that replays any run from its seed, with 1,000-seed sweeps for detection, partitions, joins, leaves, restarts, name conflicts, clock jumps and key rotation; a chaos harness that runs nodes in Linux network namespaces under tc netem and nftables; cargo-fuzz targets for the decoders and the node; and a kill -9 detection bench against hashicorp/memberlist at 100 nodes (`docs/results/detection.md`).

### Security

From the audit of 2026-10-07 and the protocol review of the same day. Each finding's reproduction is now a test that asserts the fix.

- **KS-01:** recorded datagrams and push-pull frames were accepted again; nonces now carry cluster time and a replay window.
- **KS-02:** unauthenticated stream frames could pin 512 MiB; inbound frames share a budget of twice `max_stream_frame`.
- **KS-03:** a connection flood from a peer without a key evicted real exchanges; connections and bytes are capped per source address, and a frame must start with a valid header within a second.
- **KS-04:** plaintext mode reflected forged pings at third parties 46-fold; a plaintext node now sends only to members' addresses.
- **KS-05:** the time to refuse a packet told which key ids were installed; an unknown id now costs the same tag verification.
- **KS-06:** nonce bytes came from a non-cryptographic generator; they now come from ChaCha20 under a key of their own.
- **KS-07:** copies of keys outlived their removal; keys live only in the codec, boxed, and are zeroized when removed.
- **KS-08:** key comparison was not constant time; it now is.
- **KI-02:** a rumour at incarnation u32::MAX could never be refuted, even after the attacker's key was removed; incarnations now wrap and compare as serial numbers.
- **KI-03:** a member could move a dead or departed member's name to another address; a tombstone now keeps its address until it is reaped. Names never seen stay claimable until per-member keys exist.
- **KI-04:** a member could flood every node's member table, and merging was quadratic; the table and each packet's additions are capped, and the broadcast queue is indexed by member.
- **KI-06:** a stamp far ahead stretched the replay window for hours, and an honest node that outlived a cluster restart did the same; the replay floor now lags at most ten windows, and cluster time cannot be driven to its end.
- **KP-01 to KP-05:** protocol review fixes: the replay floor of a node that has not joined, leaves counting only sends to live members, limits that fit a full Alive in a datagram, refuting stale rumours about oneself again, and merged suspicions that count no reporter.

### Known issues

- **KI-01:** any member holding the key can declare any node dead. Accepted for 0.1; per-member signing keys need a new wire version.
- **KI-05:** names and metadata are strings members choose; treat them as untrusted input.
- **KS-09:** an observer without the key still sees packet sizes, timing, addresses, key ids and cluster time.

[Unreleased]: https://github.com/bytevader/kinship/compare/v0.1.1...HEAD
[0.1.1]: https://github.com/bytevader/kinship/releases/tag/v0.1.1
[0.1.0]: https://github.com/bytevader/kinship/releases/tag/v0.1.0
