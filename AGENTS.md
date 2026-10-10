# AGENTS.md

**kinship** is an open-source SWIM cluster membership and failure detection library with Lifeguard: a sans-IO Rust core, a tokio driver, and an asyncio Python API (PyO3, maturin). Think HashiCorp memberlist for Python. Owner: Nikola (`bytevader`).

## Status

Feature-complete for 0.1 and in hardening.

- Done: core protocol, join/leave/push-pull, tokio driver, Python bindings, keyring rotation, failure-mode tests.
- At 100 nodes, kill -9 detection matches memberlist (median 9.52 s vs 9.86 s), see `docs/results/detection.md`.
- Protocol review fixes KP-01..KP-05 (`docs/review.md`) and security fixes KS-01..KS-08 (`SECURITY.md`) are merged.
- Not fixed: KS-09 and KI-01 are accepted; KI-02..KI-06 (attacks by a compromised member) are open, with reproductions in `crates/kinship-core/tests/open_findings.rs`.
- Timing preset tuning is parked on `feature/tuned-presets`; `docs/results/tuning.md` lists what is left.
- Before 0.1, run the `Detection latency` workflow (`.github/workflows/detection.yml`) by hand.

## Where to look

- `docs/design.md`: architecture and design decisions. `README.md`: the public API contract.
- `crates/kinship-proto`: wire types, codec, AEAD framing.
- `crates/kinship-core`: sans-IO protocol state machine (`Node`). It never touches a clock, socket or RNG.
- `crates/kinship-sim`: deterministic simulator.
- `crates/kinship-net`: tokio UDP and TCP driver.
- `crates/kinship-py`: PyO3 bindings, module `kinship._kinship`. `crates/kinship`: public Rust facade.
- `python/kinship`: Python package. `tests/`: pytest.
- `tools/chaos`: chaos harness and detection bench (Linux namespaces, tc netem, nftables). `tools/memberlist-bench`: the Go memberlist node for the bench.
- Fuzz targets: `crates/kinship-proto/fuzz` (`decode_datagram`, `decode_payload`, `decode_stream_frame`) and `crates/kinship-core/fuzz` (`node_input`).
- CI (`.github/workflows/ci.yml`): lint, cargo test, `sim-*` jobs (1,000 seeds each), chaos, cargo deny, MSRV, `fuzz smoke (<target>)`, wheels.

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
