# Changelog

All notable changes to kinship are recorded here. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and versions follow [Semantic Versioning](https://semver.org/spec/v2.0.0.html). The finding ids (KS-, KI-, KP-) refer to [SECURITY.md](SECURITY.md) and [docs/review.md](docs/review.md).

## [Unreleased]

## [1.0.0] - 2026-11-10

The first stable release. The protocol and the code are those of 0.5.0; what changes is what kinship promises. [docs/stability.md](docs/stability.md) is now the policy in force: what every 1.x release keeps, what stays unstable, and how anything promised is deprecated.

**Upgrading from 0.5.0.** Upgrade one node at a time: 0.5.0 and 1.0.0 nodes work in one cluster, and you can roll back the same way. The wire format, every default and the Python API do not change, so Python applications only change the version they ask for. The simulator holds this: kinship-sim's `interop_0_5::thousand_seeds_upgrade_from_0_5_and_roll_back` (CI job `sim-interop-0-5`) moves 1,000 clusters of 10 nodes from the released kinship-core 0.5.0 to this version and back, one node at a time, with no false death and no decode error, and `thousand_seeds_mixed_with_0_5` runs mixed clusters through a partition and its heal. Rust applications should check four things:

- **The crates' versions split.** `kinship` is 1.0.0, and kinship-proto, kinship-core and kinship-net are 0.6.0. Change `kinship = "0.5"` to `kinship = "1"`. Their APIs have not changed since 0.5.0 but for `Member`, below, so a direct dependency on them only needs the new version.
- **`Member` may gain fields.** It is now `#[non_exhaustive]`, in the facade and in kinship-core, so a 1.x minor release can add a field. Its fields stay public: read them, or clone a member and change the clone, but code that built a `Member` with a struct expression or `..` update no longer compiles.
- **Exact pins.** Each published crate now asks for the exact versions of the others, so a project that uses kinship-core, kinship-net or kinship-proto beside `kinship` must ask for the versions that `kinship` release pins, `=0.6.0` for 1.0.0, or Cargo will not resolve it.
- **What is unstable.** kinship-proto, kinship-core and kinship-net can change in any release. So can what the `kinship` crate re-exports from them for advanced use: `CoreConfig`, `Transport`, `TokioTransport`, `mem`, `Cluster::start_with` and `Config::core`. The counters of the experimental mode `sign` in `Metrics` can too.

### Added

- **Tests of the promises.** `tests/test_stability.py` and `crates/kinship/tests/stability.rs` hold the Python API and the Rust facade to `docs/stability.md`: public names, parameters, error hierarchy, fields, metrics series, stubs and every preset value. `interop_0_5` gains the rolling upgrade and rollback above.
- **API reference.** README.md lists every `Stats` counter, `rendezvous.owners` and `rendezvous.weight`, `cluster.config`, `ring.matches`, `ring.cluster`, `__version__` and `wire_version()`, and `docs/design.md` lists `rejoin_interval`, each of which the promise covers.

### Changed

- **Versions, as above.** `release.yml` publishes each crate at its own version, and refuses a tag whose crates do not pin each other exactly.
- **`Member` is `#[non_exhaustive]`**, as above, so that `docs/stability.md` can let it gain fields in a minor release, as the Python `Member` already may.
- The Python package's classifier moves from Alpha to `Development Status :: 5 - Production/Stable`.
- `ctutils` 0.4.7 in `Cargo.lock`.

### Fixed

- **Docs that had fallen behind the code.** `docs/design.md` said the core had no signing yet, and left `tcp_fallback_ping` and the bind address out of `local()`. `with_udp_max_payload` gave the old 813-byte floor, now 822. README's event loop examples now show the wildcard arm the promise asks for. The docstrings of `MemberLeft` and `NameConflict` now say what the README says. SECURITY.md's command for the open findings used `-p kinship-core`, which Cargo calls ambiguous.

### Security

- No code changes for a finding. KI-01, that any member holding the key can declare any node dead, stays **Accepted**: per-member keys are planned as an opt-in in a 1.x minor release, which `docs/stability.md` allows. KI-05, that names and metadata are strings a member controls, moves from Open to **Accepted**, as application guidance: applications treat them as untrusted input, as README.md says. See SECURITY.md.
- **Supported versions.** SECURITY.md now says which releases get security fixes: the latest 1.x minor release.

## [0.5.0] - 2026-11-01

**Upgrading from 0.4.0.** Upgrade one node at a time: 0.4.0 and 0.5.0 nodes work in one cluster. A 0.5 node sends a digest only to members that advertise it, so it keeps the full push-pull with 0.4 nodes, and 0.4 nodes skip the byte 0.5 appends to Alive. The simulator holds this: kinship-sim's `digest::thousand_seeds_mixed_with_0_4` (CI job `sim-digest`) runs 1,000 clusters of 20 nodes, 5, 10 or 15 of them on the released kinship-core 0.4.0, through joins, a partition and its heal, and every node ends holding every node, neither version counts a decode error, and no digest reaches a 0.4 node; `digest::digest_and_full_exchanges_meet_in_mixed_clusters` runs a few of those seeds in `cargo test`, and kinship-proto's `released_0_4_reads_the_new_alive_and_skips_digest_messages` decodes the new bytes with the released kinship-proto 0.4.0. The Python API and the `kinship` facade only gain settings. Check a config set at the old limits (one byte less room, below), code that uses kinship-proto or kinship-core directly, and a driver of kinship-core of your own. The KP-06 fix works on 0.5 nodes: a 0.4 node that a partition cut off still gossips its deaths when the partition heals.

### Added

- **Digest push-pull, on by default.** Anti-entropy, reconnects and rejoins with a member that advertises it send a digest of every member held, 32 bytes for a 17-byte name, and whole records only where the two sides differ, on one connection in up to three frames. A settled 1,000-node cluster sends 1.3 KB/s per node instead of 6.2 with the default 30 s period, 100 nodes 0.3 KB/s instead of 0.8, and each side ends with what a full exchange leaves it. Joins, 0.4 nodes and the experimental mode `sign` keep the full exchange. `Config(push_pull_digest=False)` in Python, `with_push_pull_digest(false)` in Rust or `Config::push_pull_digest` in kinship-core turns it off, and the node then sends the bytes 0.4 sent. The wire version stays 1: two new TCP-only types, PushPullDigest (0x0D) and PushPullWants (0x0E), and a `features` varint after the Alive epoch, whose bit 0 advertises the digest. See `docs/results/digest.md` and `docs/design.md` (Digest push-pull).
- **`push_pull_scale`, opt-in.** Stretches the push-pull period beyond 32 live members as memberlist's pushPullScale does: 90 s at 100 members and 180 s at 1,000 with `lan()`. With the digest, a settled 1,000-node node then sends 0.4 KB/s, but a rumour that gossip missed waits longer for its repair, and in the simulator's tuning sweep at 200 nodes that gave false deaths the fixed period does not (2 in 800 runs with the digest), so it is off and every default is unchanged. `Config(push_pull_scale=True)`, `with_push_pull_scale(true)` or `Config::push_pull_scale`; mode `sign` ignores it. `kinship_core::Config::push_pull_interval_for` gives the period for a cluster size. See `docs/results/pushpull.md`.
- **Experimental KI-01 mode `sign`, kinship-core only.** `Config::signatures` is `Signatures::Off`, the default, or `Signatures::Sign(Credentials)`: a member Ed25519 key, its certificate from a cluster CA and the trust anchors. A signing node signs every Alive, Left, Suspect and Dead it authors, its probe answers, Nacks, direct messages and broadcasts, checks those it receives against certificates, drops what fails, and speaks version 2 to members that advertise it and version 1 to the rest. Unsigned statements are still accepted, so nothing is enforced and **KI-01 remains Accepted**; the facade and Python expose none of it. Every 1,000-seed simulator sweep passes with every node in `sign`, which detects failures as `off` does; the bytes it costs are in `docs/results/signed.md`. kinship-proto gains `identity` (keys, certificates, revocations) and the `v2` codec; `WIRE_VERSION` stays 1 and `MAX_WIRE_VERSION` is 2. New kinship-core counters `signatures_made`, `signatures_checked`, `signatures_invalid`, `certificates_refused` and the gauge `unsigned_members`. Mode `off` sends the bytes 0.4 sends. See `docs/ki01-stage1.md` and `docs/ki01-stage2.md`.
- **Plans for 1.0 and KI-01.** `docs/stability.md` proposes what 1.0 promises, what stays unstable and a deprecation policy; `docs/ki01-per-member-keys.md` plans per-member keys through to enforcement, after 1.0.
- **Compose demo messages.** Cache nodes hand moved keys to their new owner with `cluster.send` on Drain, Undrain and joins, so they stay warm, and a Flush action clears every cache with `cluster.broadcast`. See `deploy/compose/README.md`.

### Changed

- **Every Alive is one byte longer** with `push_pull_digest` on, for the features field. The limits check counts that byte whatever the setting, since a node relays other members' Alives: with 512 bytes of metadata an encrypted datagram must be at least 822 bytes (was 821), and with the default datagram `max_meta_bytes` can be at most 1,090 (was 1,091). A config at the old limit now fails validation with `ConfigError`.
- **kinship-net reads a second frame on a connection it accepted**, the records a digest's answer asked for, from its own share of the inbound budget and checked against the node's header like the first. A driver of kinship-core of your own must do the same: when the core answers a frame on an accepted connection without closing it, pass the peer's next frame to the core too.
- **Breaking 0.x API changes in kinship-proto and kinship-core.** kinship-proto: `Alive` gains `features` and `Message` gains `PushPullDigest` and `PushPullWants`. kinship-core: `Config` gains `push_pull_digest`, `push_pull_scale` and `signatures`, and `Metrics` the counters above. Code that builds these without `..` or matches `Message` exhaustively has to change. The Python API and the `kinship` facade are unchanged but for the new settings.
- **Minimum Rust version 1.87**, from 1.85, for `ctutils` 0.4.5. The Compose demo builds with Rust 1.87.0.
- The simulator's pinned SWIM trace changes, for the features byte and the KP-06 fix.

### Fixed

- **No false deaths after a partition heals (KP-06).** The nodes a partition cut off declared the members across it dead and gossiped those deaths once it healed, so members that never stopped went MemberDead and then MemberJoined, and `kinship.ring` moved their keys twice; the Compose demo's Partition showed it. A node that doubted its own view while it suspected a member, its local health above zero or no more than half of the members it knows held Alive, now keeps that death to itself and sends only the member a Suspect to refute. Other nodes still declare a real failure through their own probes. In the simulator 429 of 1,000 seeds that cut off one node or a minority showed a false death, and none do now, in mode `off` or `sign`; the minority side declares the far side later. The precedence rules and the wire are unchanged. See `docs/results/heal-flap.md`.

### Security

- **RUSTSEC-2026-0385.** `ctutils` 0.4.2 generated masks and compared `u128` values in time that could depend on the data; kinship-proto now requires 0.4.5.

## [0.4.0] - 2026-10-15

### Added

- **User messages.** `send(member, data)` sends bytes to one member: in one datagram when they fit, and over TCP otherwise, up to `max_user_message` (64 KiB). `broadcast(data)` gossips up to `max_user_broadcast` (256 bytes) to every member, beside the membership rumours and with their retransmit rule, membership always first, and every node delivers it at most once, told apart by sender, epoch and number. Receivers read both from `events()` as `UserMessage(sender, data, broadcast)`, in Python and Rust, with `EventsLost` unchanged. A `Member` names one run of a node, so a message for a run that has since restarted is refused by a sender that knows, and dropped by the new run otherwise. Messages are best effort and never acknowledged; README "Messages" and docs/design.md "User messages" give the guarantees. On `kinship.Cluster` and `kinship.blocking.Cluster`, the Rust `Cluster` (`send`, `send_to`, `broadcast`) and `kinship_net::Memberlist`; the sans-IO core takes `Command::Send` and `Command::Broadcast`.
- `kinship.MessageTooLarge`, a `ValueError`, and `kinship.NotAMember`, a `LookupError`; Rust `Error::MessageTooLarge` and `Error::NotAMember`.
- Config fields `max_user_message` (64 KiB), `max_user_broadcast` (256 bytes) and `user_broadcast_queue` (256), validated with the other limits.
- Stats counters `user_messages_sent`, `user_messages_received`, `user_messages_dropped`, `user_messages_too_large` and `user_queue_overflow`, which `kinship.metrics` exports as it does every counter.
- `examples/messages.py`: a broadcast every other node hears once, and a request answered with a direct message too large for a datagram.
- Simulator tests that run the released kinship-core 0.3.0 beside this version, and a 1,000-seed sweep of user messages in CI.
- **Prometheus metrics.** Dependency-free `kinship.metrics.prometheus_text(cluster)` exports every protocol counter, the local health gauge and membership counts for async and blocking clusters. `cluster_router(metrics=True)` opts into a Prometheus text endpoint at `/cluster/metrics` (or the configured prefix).
- **Demo monitoring.** Optional `docker-compose.monitoring.yml` adds Prometheus and Grafana to the five-node Compose demo, with automatic source builds, per-node scraping and a provisioned cluster dashboard for membership views, health, probes and failure activity.
- **armv7 wheels.** Linux abi3 wheels for manylinux_2_28 and musllinux_1_2, with musllinux tests under QEMU in Alpine.

### Changed

- **Wire format.** User messages take types 0x09 (UserMessage) and 0x0A (UserBroadcast) from the reserved range; 0x0B to 0x7F stay reserved. No other message changes, so a node that sends no user messages sends the bytes 0.3 does, and the wire version stays 1. Nodes on 0.3 or older skip both types as types they do not know, without counting a decode error: they neither deliver nor pass on user messages.
- `events()` can yield `UserMessage`, which carries `sender` rather than `member`, so code that reads `event.member` from every event but `EventsLost` should match on the event's type, as `kinship.ring` now does.
- A config whose `max_stream_frame` cannot hold a `max_user_message` message, below about 64 KiB, is refused naming `max_stream_frame`; lower `max_user_message` with it.
- Rust: `Message`, `Command`, `CommandError` and `Event` have new variants, and `Config` and `Metrics` new fields.
- The `node_input` fuzz corpus is regenerated, since it predated epochs, and gains inputs with user messages; operation 7 of the target now has the node send them.

### Fixed

- Replace references to the unimplemented visualizer with the Compose demo dashboard or existing test and demo uses.

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

[Unreleased]: https://github.com/bytevader/kinship/compare/v1.0.0...HEAD
[1.0.0]: https://github.com/bytevader/kinship/compare/v0.5.0...v1.0.0
[0.5.0]: https://github.com/bytevader/kinship/compare/v0.4.0...v0.5.0
[0.4.0]: https://github.com/bytevader/kinship/releases/tag/v0.4.0
[0.3.0]: https://github.com/bytevader/kinship/releases/tag/v0.3.0
[0.2.0]: https://github.com/bytevader/kinship/releases/tag/v0.2.0
[0.1.1]: https://github.com/bytevader/kinship/releases/tag/v0.1.1
[0.1.0]: https://github.com/bytevader/kinship/releases/tag/v0.1.0
