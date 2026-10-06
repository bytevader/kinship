# kinship

SWIM membership with Lifeguard: a sans-IO Rust core with a tokio driver and a Python (PyO3, maturin) package. Read `docs/design.md` for the architecture and `README.md` for the public API contract.

## Commands

```bash
cargo build --workspace
cargo test --workspace --exclude kinship-py   # kinship-py needs a Python to link; it is covered by pytest
cargo fmt --all
cargo clippy --workspace --all-targets -- -D warnings

uv sync                                       # creates .venv with maturin, pytest, ruff
uv run maturin develop                        # builds and installs the extension (abi3)
uv run maturin develop --no-default-features  # same, without abi3 (needed on free-threaded 3.14t)
uv run pytest
uv run maturin develop --features test-hooks  # adds the private panic hook tests/test_panic.py needs
uv run ruff check . && uv run ruff format --check .

pre-commit run --all-files                    # ruff, ruff format, cargo fmt, clippy
```

## Layout

- `crates/kinship-proto`: wire types, codec, AEAD framing
- `crates/kinship-core`: sans-IO protocol state machine
- `crates/kinship-sim`: deterministic simulator (the core never touches a clock, socket or RNG)
- `crates/kinship-net`: tokio UDP and TCP driver
- `crates/kinship-py`: PyO3 bindings, module `kinship._kinship`
- `crates/kinship`: public Rust facade
- `python/kinship`: Python package, `tests/`: pytest

## Rules

- Rust 1.85+, edition 2024. Python 3.11+, abi3 wheels plus free-threaded 3.14t (no abi3 there).
- Clippy runs with `-D warnings`; keep `cargo fmt` and `ruff format` clean.
- Commit messages: one line, no body.
