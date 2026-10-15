# Stability

What kinship 1.0 will promise, what it leaves free to change, and how it retires what it promised. This is the policy proposed for 1.0; until then a 0.x minor release may still break the API. Where this file and a release's CHANGELOG entry disagree, the CHANGELOG records what actually happened and this file is corrected.

## What 1.0 promises

Every 1.x release keeps the promises below. A change that breaks one waits for 2.0, apart from the security exception under [Deprecation policy](#deprecation-policy).

### Python API

The promise covers every name in `__all__` of these modules, with the signatures, return types, exceptions and behaviour that README.md documents:

| Module | Public names |
| --- | --- |
| `kinship` | `Cluster`, `Config`, `EventStream`, `Keyring`, `Member`, `State`, `Stats`, the events, the errors, `blocking`, `rendezvous`, `log_to_python`, `wire_version`, `__version__` |
| `kinship.blocking` | `Cluster`, `EventStream`, `Keyring` |
| `kinship.ring` | `Ring`, `RingChanged` |
| `kinship.rendezvous` | `owner`, `owners`, `weight` |
| `kinship.metrics` | `prometheus_text` |
| `kinship.contrib.fastapi` | `cluster_lifespan`, `cluster_router`, `get_cluster`, `get_ring` |

In particular:

- **Calls.** Parameters keep their names, order and defaults, and keyword-only parameters stay keyword-only. New parameters are added with defaults that keep today's behaviour, keyword-only.
- **Errors.** The hierarchy stays: every kinship error is a `KinshipError`, `ConfigError` and `MetaTooLarge` and `MessageTooLarge` are also `ValueError`s, `NotAMember` a `LookupError`, and `ConfigError.field` names the field. The text of an error message is not promised.
- **Types.** `Member`, the event classes and `Stats` keep their fields, types and meaning. They may gain fields. `State` keeps its four values.
- **Hashing.** `kinship.rendezvous` weights are BLAKE2b with the person string `kinship-hrw-v1`, and stay so: a different hash would move every key in every application's shards. A new hash would come under a new name beside the old one.
- **Fencing.** `Ring.fence()` keeps returning `(owner_name, epoch)`, and a node that restarts keeps coming back at a later epoch, so a token taken by one run never passes for the next.
- **Metrics.** The counters `stats()` returns and the series `prometheus_text` writes (`kinship_<counter>_total`, `kinship_local_health`, `kinship_members{state=...}`) keep their names and meaning. New ones may appear.
- **Command line.** `python -m kinship keygen` keeps printing one 32-byte key as padded base64.
- **Typing.** The package ships `py.typed` and its stubs; a stub may become more precise, never incompatible with code that type-checked before.
- **Platforms.** The wheels README.md lists under Install: abi3 for CPython 3.11 and later, free-threaded 3.14t, on Linux, macOS and Windows, and armv7 Linux. A platform or Python version is dropped only as the deprecation policy below says.

### Rust facade

The `kinship` crate follows Semantic Versioning as Rust reads it. The promise covers what the crate's root exports: `Cluster` and its methods, `Config` and its `with_*` setters, `DEFAULT_PORT`, `Event`, `Events`, `Member`, `State`, `Stats`, `Metrics`, `Error`, `ConfigError`, `Key`, `KeyError`, `KeyId`, `Keyring`, `Seed`, `SeedError`, `generate_key` and `WIRE_VERSION`.

- `Event`, `Error`, `Seed`, `Stats` and `Metrics` are `#[non_exhaustive]`, so new variants and fields arrive in minor releases. Match with a wildcard arm.
- `Config` gains fields only through new `with_*` setters, whose defaults keep today's behaviour, and it is validated by `Cluster::start` as now.
- These types are defined in kinship-net and kinship-core and re-exported. The promise is about the types as `kinship` exports them; see [What stays unstable](#what-stays-unstable) for the crates themselves.
- The minimum supported Rust version can rise in a minor release, never in a patch release, and never to a Rust release less than six months old. The CHANGELOG names every rise.

### Wire format

- 1.0 speaks wire version 1 as `docs/design.md` specifies it under Wire format: the outer header, the AEAD and its associated data, cluster time in the nonce and the replay window, the inner payload grammar, every message type from 0x01 to 0x0A with its fields, the metadata tag encoding in `kinship_proto::tags`, and the default port 7946.
- Every 1.x release interoperates with every other 1.x release, and with 0.3 and 0.4, in one cluster: a rolling upgrade, or a rollback, one node at a time, never needs the cluster to stop. An opt-in setting can narrow this on purpose, as requiring signatures would shut out nodes that cannot sign; with every opt-in off, it holds. The simulator tests that run a released kinship-core beside the current one hold each release to this.
- Version 1 changes only as it always has: new fields appended to a message, which older nodes skip, and new message types from the reserved range, which older nodes skip as types they do not know. A node that uses no new feature sends the bytes the previous release did.
- A new wire version, such as version 2 for per-member keys (`docs/ki01-per-member-keys.md`), may arrive in a 1.x minor release only as an opt-in that negotiates down to version 1 with nodes that do not speak it. Dropping version 1 takes a major release, and the last 1.x minor release before it speaks both, so that a cluster can always upgrade one node at a time.

### Configuration

- Every field keeps its name in Python and Rust, its unit (seconds as `float` or `timedelta` in Python, `Duration` in Rust, bytes for sizes) and its meaning.
- The presets `lan()`, `wan()` and `local()` keep the values in `docs/design.md`, Configuration surface, and so does every default. A default changes only in a minor release, with a CHANGELOG entry under Changed that says why, and a timing default only with the evidence `docs/results/tuning.md` asks for: lower detection latency at every cluster size, with no more false deaths and at most 10% more bandwidth.
- Validation may refuse a combination it accepted before only when that combination could not work, as the fix for KP-03 refused limits under which a member's own Alive never fits a datagram. The error names the field.

### Events

- The events in README.md, Events, keep their fields and the conditions that fire them: `MemberJoined`, `MemberSuspect`, `MemberRecovered`, `MemberDead`, `MemberLeft` (including a restart, followed by `MemberJoined` with the new epoch), `MemberUpdated`, `NameConflict`, `UserMessage` and `EventsLost`.
- Each `events()` call stays its own subscription, starting at the call, with `event_buffer` events of room, dropping the oldest when full and saying so with `EventsLost`. Events never describe the local node, except `NameConflict`.
- New event types may arrive in a minor release. Python code should ignore events it does not know, with a `case _:` arm in a `match`, and Rust code needs a wildcard arm anyway.
- Message delivery keeps its guarantees: best effort, at most once with encryption, never to the sender.

## What stays unstable

These may change in any release, minor or patch, with a CHANGELOG entry but without deprecation:

- **kinship-core**, the sans-IO `Node`: its `Command`, `Event`, `Transmit`, `Config` and `Metrics` types and every other item. The README section on kinship-core shows how to drive it, and it will keep working that way where it can, but a protocol change may need a new input or output, and the core is where it lands first.
- **kinship-net**: `Memberlist`, the actor, the `Transport` trait, the in-memory transport in `mem` and the `CoreConfig` that `kinship` re-exports for advanced use. A custom transport is an experiment, not a promise.
- **kinship-proto**: the codec, `Codec`, `FrameReader`, the message structs and error types. The bytes on the wire are promised above; the Rust API that produces them is not.
- **kinship-sim** and **tools/chaos**: the simulator, its scenarios and trace format, the pinned SWIM trace digest, and every result and seed in `docs/results`. They are not published, and a fix to the core may change any number they report.
- **Python internals**: every module and name that starts with an underscore, including `kinship._kinship`, the reprs of objects, and log messages, their levels and their targets.
- **The test-hooks feature**, the fuzz targets and their corpora, the examples, and the Compose demo in `deploy/compose`.
- **Performance**: detection latency, bandwidth, memory and CPU are measured and published, not promised. A release may trade one for another within the rule in `docs/results/tuning.md`.
- **Opt-in features marked experimental** in the CHANGELOG when they ship, such as per-member keys while their plan is in progress.

The published crates have one version today. For 1.0, either the internal crates keep 0.x versions of their own and `kinship` 1.x pins the exact ones it was built with, or they move to 1.0 with it and say in their documentation that their API is outside the promise. The first is what Cargo users read correctly; the choice is open.

## Deprecation policy

- **What is deprecated.** Anything the 1.0 promise covers, before it is removed or changed incompatibly. Unstable items change without notice.
- **How.** In a minor release, with a CHANGELOG entry under Deprecated that names the replacement. Python raises `DeprecationWarning` where the deprecated name, parameter or config field is used, and a deprecated config field keeps working. Rust marks the item `#[deprecated(since = "1.x.0", note = "...")]`. README.md and docs/design.md describe the replacement and mention the old name only where it is deprecated.
- **How long.** A deprecated item stays for at least two minor releases and six months, whichever is longer, and goes only in a major release. A major release removes only what a 1.x release deprecated.
- **Wire.** A wire version is never deprecated before its successor has been the default for a whole minor release. The upgrade path is always: every node to the last minor release, which speaks both versions, then every node to the major release.
- **Python versions.** Support for a CPython version ends in the first minor release after its end of life, announced in the release before.
- **Security exception.** A fix for a security finding (SECURITY.md) may change behaviour in a minor or patch release without a deprecation period, when keeping the old behaviour would keep the vulnerability: refusing a packet or a config that used to be accepted, for instance. The CHANGELOG entry links the finding and says what to change.
