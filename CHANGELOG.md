# Changelog

All notable changes to kinship are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The finding ids (KS-, KI-, KP-) refer to [SECURITY.md](SECURITY.md) and [docs/review.md](docs/review.md).

## [Unreleased]

### Added

- **User messages.** `send(member, data)` sends bytes to one member: in one datagram when they fit, and over TCP otherwise, up to `max_user_message` (64 KiB). `broadcast(data)` gossips up to `max_user_broadcast` (256 bytes) to every member, beside the membership rumours and with their retransmit rule, membership always first, and every node delivers it at most once, told apart by sender, epoch and number. Receivers read both from `events()` as `UserMessage(sender, data, broadcast)`, in Python and Rust, with `EventsLost` unchanged. A `Member` names one run of a node, so a message for a run that has since restarted is refused by a sender that knows, and dropped by the new run otherwise. Messages are best effort and never acknowledged; README "Messages" and docs/design.md "User messages" give the guarantees. On `kinship.Cluster` and `kinship.blocking.Cluster`, the Rust `Cluster` (`send`, `send_to`, `broadcast`) and `kinship_net::Memberlist`; the sans-IO core takes `Command::Send` and `Command::Broadcast`.
- `kinship.MessageTooLarge`, a `ValueError`, and `kinship.NotAMember`, a `LookupError`; Rust `Error::MessageTooLarge` and `Error::NotAMember`.
- Config fields `max_user_message` (64 KiB), `max_user_broadcast` (256 bytes) and `user_broadcast_queue` (256), validated with the other limits.
- Stats counters `user_messages_sent`, `user_messages_received`, `user_messages_dropped`, `user_messages_too_large` and `user_queue_overflow`.
- `examples/messages.py`: a broadcast every other node hears once, and a request answered with a direct message too large for a datagram.
- Simulator tests that run the released kinship-core 0.3.0 beside this version, and a 1,000-seed sweep of user messages in CI.

### Changed

- **Wire format.** User messages take types 0x09 (UserMessage) and 0x0A (UserBroadcast) from the reserved range; 0x0B to 0x7F stay reserved. No other message changes, so a node that sends no user messages sends the bytes 0.3 does, and the wire version stays 1. Nodes on 0.3 or older skip both types as types they do not know, without counting a decode error: they neither deliver nor pass on user messages.
- `events()` can yield `UserMessage`, which carries `sender` rather than `member`, so code that reads `event.member` from every event but `EventsLost` should match on the event's type, as `kinship.ring` now does.
- A config whose `max_stream_frame` cannot hold a `max_user_message` message, below about 64 KiB, is refused naming `max_stream_frame`; lower `max_user_message` with it.
- Rust: `Message`, `Command`, `CommandError` and `Event` have new variants, and `Config` and `Metrics` new fields.
- The `node_input` fuzz corpus is regenerated, since it predated epochs, and gains inputs with user messages; operation 7 of the target now has the node send them.

## [0.3.0] - 2026-10-14

### Added

- **Member epochs.** Each node picks an epoch when it starts, the wall clock's milliseconds since the Unix epoch, and `Member.epoch` exposes it in Rust and Python, so `(name, epoch)` tells one run of a node from the next. A node that restarts under the same name comes back at a later epoch, which replaces the old run on every node at once, even at a lower incarnation: applications see `MemberLeft` for the old run, unless it had already died or left, then `MemberJoined` for the new one, and `stats().restarts` counts them. Rumours about an earlier run, at any incarnation, change nothing, so the old run's death cannot kill the new one and its Alive cannot bring a dead member back. A node whose clock reads behind its last run's epoch moves past it when its join tells it about that run. Members of nodes older than 0.3 have epoch 0, and between them incarnations decide as before. Rust drivers of `kinship-core` pass the epoch with `Identity::with_epoch`; `kinship-net` picks it.
- **`Ring.fence(key, *, new_work=False)`** returns `(owner_name, epoch)`, a fencing token for writes: a member that applies a write accepts it only while its own `fence(key)` matches, which refuses writes meant for another owner or for an earlier run of this one. The README's "Fencing writes" section shows the pattern, and how a store outside the cluster keeps the last token per key.
- **Compose demo.** Node cards show when each node's current run started; a **Bounce** fault exits a node and has Docker start it again at once, so peers replace the old run with the new one without declaring it dead; forwarded writes carry the owner's fencing token, and the dashboard counts the writes an owner refused as fenced.

### Changed

- **Wire format.** Alive, Suspect and Dead, and push-pull records, append the epoch as a u64 after their version 1 fields; epoch 0 is not sent. Older nodes skip it as an appended field, so 0.2 and 0.3 nodes run in one cluster, with the epoch-less rules among the rumours older nodes pass on. The wire version stays 1.
- The limits check counts the epoch in the largest Alive: with 512 bytes of metadata an encrypted datagram must now be at least 821 bytes (was 813), and with the default 1,400-byte datagram `max_meta_bytes` can be at most 1,091 (was 1,099).
- `Ring.moved()` counts a key whose owner restarted, the same name at a new epoch, as moved, since the new run has none of the old one's state, and `Ring.changes()` reports such a restart as the old run removed and the new one added, also after `EventsLost`.
- `GET /members` from `cluster_router()` includes each member's `epoch`.
- Rust: `Member` and the core's `Alive`, `Suspect` and `Dead` messages have a new `epoch` field, and `Metrics` a new `restarts` counter.

## [0.2.0] - 2026-10-13

### Added

- **Compose cache demo.** `deploy/compose/`: a source-built FastAPI cache cluster, live key ownership and membership dashboard, load generator, and opt-in Docker fault controls with timer recovery.
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

[Unreleased]: https://github.com/bytevader/kinship/compare/v0.3.0...HEAD
[0.3.0]: https://github.com/bytevader/kinship/releases/tag/v0.3.0
[0.2.0]: https://github.com/bytevader/kinship/releases/tag/v0.2.0
[0.1.1]: https://github.com/bytevader/kinship/releases/tag/v0.1.1
[0.1.0]: https://github.com/bytevader/kinship/releases/tag/v0.1.0
