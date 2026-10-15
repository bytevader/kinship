# AGENTS.md

**kinship** is an open-source SWIM cluster membership and failure detection library with Lifeguard: a sans-IO Rust core, a tokio driver, and an asyncio Python API (PyO3, maturin). Think HashiCorp memberlist for Python. Owner: Nikola (`bytevader`).

## Status

0.1.0 shipped on 2026-10-12, 0.1.1 and 0.2.0 on 2026-10-13, 0.3.0 on 2026-10-14, and 0.4.0, which adds user messages and broadcasts, Prometheus metrics with an optional Prometheus and Grafana stack for the Compose demo, and armv7 wheels, on 2026-10-15. Since then the Compose demo hands keys off warm with `send` and flushes caches with `broadcast` (`CHANGELOG.md`, Unreleased). Pushing a `v*` tag runs `.github/workflows/release.yml`, which publishes the wheels (manylinux, musllinux, macOS, Windows) and sdist to PyPI, smoke-tests the PyPI release on Linux, macOS and Windows, and publishes the crates to crates.io.

- Done: core protocol, join/leave/push-pull, tokio driver, Python bindings, keyring rotation, failure-mode tests.
- At 100 nodes, kill -9 detection matches memberlist at the median (9.73 s vs 9.81 s on 2026-10-11) and nearly at the tail (13.3 s vs 12.2 s at most), since members that join mid-pass are probed in that pass; the `Detection latency` workflow on a GitHub runner (20 runs, 2026-10-11) agrees, 12.3 s vs 12.2 s at most. See `docs/results/detection.md`.
- Protocol review fixes KP-01..KP-05 (`docs/review.md`) and security fixes KS-01..KS-08 (`SECURITY.md`) are merged.
- Compromised-member findings KI-02, KI-04 and KI-06 are fixed and KI-03 is mitigated; their reproductions in `crates/kinship-core/tests/open_findings.rs` now assert the fixes. KS-09 and KI-01 are accepted, and KI-05 is application guidance.
- Member epochs, one per run of a node, let a restart replace the old run at any incarnation (`docs/design.md`, Epochs); `Ring.fence()` provides tokens from those epochs, and the Compose demo's Bounce fault demonstrates a restart.
- Timing preset tuning is done: no variant beats `lan()` at every cluster size without false deaths or more than 10% bandwidth, so `lan()` keeps memberlist's values; see `docs/results/tuning.md`.
- User messages (0.4): `send(member, data)` and `broadcast(data)`, delivered as `UserMessage` events, on wire types 0x09 and 0x0A (`docs/design.md`, User messages). With none sent, the wire bytes and the pinned SWIM trace are those of 0.3. Broadcasts reach about 99.8% of members in the simulator, with nothing to repair a miss.

## Where to look

- `docs/design.md`: architecture and design decisions. `README.md`: the public API contract.
- `crates/kinship-proto`: wire types, codec, AEAD framing.
- `crates/kinship-core`: sans-IO protocol state machine (`Node`). It never touches a clock, socket or RNG. User messages live in `user.rs`, their broadcast queue beside the membership queue in `broadcast.rs`.
- `crates/kinship-sim`: deterministic simulator. Its `usermsg` tests run the released kinship-core 0.3.0, a dev-dependency renamed `kinship-core-0-3`, beside this version.
- `crates/kinship-net`: tokio UDP and TCP driver.
- `crates/kinship-py`: PyO3 bindings, module `kinship._kinship`. `crates/kinship`: public Rust facade.
- `python/kinship`: Python package. `tests/`: pytest. `examples/`: runnable Python examples, run by `tests/test_examples.py`.
- `python/kinship/ring.py`: `Ring` and `RingChanged`, key ownership over `rendezvous` that follows membership events, and `Ring.fence()` tokens from member epochs. `python/kinship/contrib/fastapi.py`: `cluster_lifespan`, `get_cluster`, `get_ring` and `cluster_router`, behind the `kinship[fastapi]` extra; the core package has no Python dependencies, and FastAPI tests skip when fastapi is not installed.
- `docs/assets`: the logo (`logo.svg`, `logo.png`), the README banners (`banner-light.png`, `banner-dark.png`, loaded from `main`) and the GitHub social preview.
- `tools/smoke_quickstart.py`: the post-publish smoke test, which runs `examples/quickstart.py` as two nodes against an installed kinship.
- `tools/chaos`: chaos harness and detection bench (Linux namespaces, tc netem, nftables). `tools/memberlist-bench`: the Go memberlist node for the bench.
- Fuzz targets: `crates/kinship-proto/fuzz` (`decode_datagram`, `decode_payload`, `decode_stream_frame`) and `crates/kinship-core/fuzz` (`node_input`).
- Seeds may be DNS names (`kinship_net::Seed`); kinship-net looks them up at every join and rejoin (`crates/kinship-net/src/seed.rs`), never the core.
- CI (`.github/workflows/ci.yml`): lint, cargo test, coverage (Rust with the bindings under pytest, plus Python; `coverage-badge` publishes `coverage.json` for the README badge to the `badges` branch on pushes to main), `sim-*` jobs (1,000 seeds each), chaos, cargo deny, MSRV, `fuzz smoke (<target>)`, wheels, musllinux wheels tested in Alpine. `detection.yml`: the weekly memberlist bench. `release.yml`: runs on `v*` tags only.
- Released by `release.yml`: the `kinship` package to PyPI, then the crates `kinship-proto`, `kinship-core`, `kinship-net` and `kinship` to crates.io, in that order. `kinship-sim`, `kinship-py`, `kinship-chaos` and the fuzz crates have `publish = false`.

## Commands

```bash
cargo test --workspace --exclude kinship-py   # kinship-py needs a Python to link; pytest covers it
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings
uv sync && uv run maturin develop && uv run pytest
uv run maturin develop --features test-hooks  # tests/test_panic.py needs this; release wheels leave it off
uv run ruff check . && uv run ruff format --check .
```

## Working rules

- Rust 1.85+, edition 2024. Python 3.11+, abi3 wheels plus free-threaded 3.14t.
- Keep clippy (`-D warnings`), `cargo fmt` and `ruff format` clean.
- Commits are authored as `bytevader` only, one-line message, no AI or Co-Authored-By trailers.
- Branches use `feature/`, `fix/`, `chore/`, `docs/` or `test/` prefixes. Never push to `main`; Nikola opens PRs himself.
- Check the current branch right before committing.
- Fixed nonces in tests and fuzz targets are intentional.
