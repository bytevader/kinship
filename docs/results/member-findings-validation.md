# Member findings validation

Work starts from main `ccf0e9c67077f1f88b9a91e94fe8f9dd3359416c` on 2026-10-10,
on branch `fix/member-findings`. The baseline below ran on unchanged main; the
validation further down ran on the branch with the fixes for KI-04, KI-02, KI-06
and KI-03 in place.

## Part 0: main CI

The reported failed check after PR #19 is not present in the current GitHub
Actions records. [The PR #19 merge run](https://github.com/bytevader/kinship/actions/runs/37798973489)
passed all 28 jobs. The only change between that commit (`318cec3`) and current
main is `AGENTS.md`.

[Current main's run](https://github.com/bytevader/kinship/actions/runs/38065744800)
was cancelled on its first attempt: all 28 jobs concluded cancelled, with no
failed job. Cancellation is not evidence of a test flake. Attempt 2 was started
through GitHub Actions during this investigation and completed successfully.
There is no Part 0 code fix to make.

Fresh local baseline checks:

- Windows `cargo test --workspace --exclude kinship-py`: passed outside the
  sandbox. The sandboxed run timed out in five localhost cluster tests; all
  eight tests in that binary passed outside the sandbox, followed by the full
  workspace suite. No timeout or test assertion was changed.
- `cargo fmt --all --check`: passed.
- Ubuntu WSL stable `cargo clippy --workspace --all-targets -- -D warnings`:
  passed.
- Ubuntu WSL stable `cargo clippy -p kinship-py --features test-hooks -- -D warnings`:
  passed.
- Windows `uv run maturin develop`, followed by `uv run pytest`: 65 passed,
  3 expected skips (two Windows fork tests and the test requiring panic hooks).
- `uv run maturin develop --features test-hooks`, followed by
  `KINSHIP_TEST_HOOKS=1 uv run pytest tests/test_panic.py`: 1 passed.
- `uv run ruff check .` and `uv run ruff format --check .`: passed.

The sandbox also refused uv interpreter-cache writes; Python checks passed
after rerunning outside it. WSL must explicitly select `Ubuntu-26.04`, since
the default distribution is Docker Desktop. These are execution-environment
restrictions, not repository defects.

All five release baseline suites (sim, swim, sync, keyring and failure) passed.
The original KI-04 reproduction merged 20,000 records from a 546 KiB frame in
7.828420274 seconds. The 1,000-node, 600-second simulator scale test passed in
9.096682309 seconds, sending 1,193,993 packets and delivering 1,182,127.

The fresh 1,000-seed SWIM sweep passed: 197,363 detections, p50
10.047927355 seconds, p99 142.602558641 seconds, maximum 477.945497289 seconds;
195,870 suspicions, 558 of live members, and 16 refutations. These match the
handoff baseline. The sync and keyring suites also passed: partition healing
p50/p99/max 1.25/16.25/25 seconds; join convergence into 200 nodes
300 ms/1 s/1.1 s; graceful leave 150/350/400 ms. Key rotation produced no
suspicions or decrypt failures; a member left behind by rotation reconverged
at p50/p99/max 9/27.25/39.25 seconds.

Failure sweeps (1,000 seeds each) also passed. Clock-jump recovery p50/p99/max
was 300 ms/800 ms/21.2 s with no false deaths and 484 cut-round refutations;
restart recovery was 310 ms/2.01 s/27.68 s with no dead events after restart;
long-partition reconnect was 5/36/65.5 s. Name conflicts were retained
everywhere, reported at 2..14 nodes, with both claimants observed at
p50/p99/max 10/100/120 ms.

WSL nightly fuzz baseline, 60-second smokes on copies of the seed corpora:
decode_datagram (54,008 runs/63 s), decode_payload (12,252 runs/64 s) and
decode_stream_frame (27,076 runs/62 s) exited zero. The first node_input run
was interrupted around 29 seconds; its log is kept as
`fuzz-node_input-interrupted.log` and it is not counted. Rerun on 2026-10-11
on the same unchanged main, node_input exited zero after 23,102 runs in 63 s.
The checked-in seed corpora hash the same after the runs as before (`cmp`
exit 0), so the smokes did not touch them. Logs and copied corpora are under
`C:\projects\kinship\target\member-findings-baseline`; the two `fuzz/Cargo.lock`
files cargo-fuzz generated in main were copied to its `fuzz-lockfiles` folder
and removed from the checkout.

## Validation of the fixes

All on the branch with the fixes, 2026-10-11. Logs are under
`target/member-findings-validation` in the worktree.

- Windows `cargo test --workspace --exclude kinship-py`: 289 passed, 0 failed,
  18 ignored, the 1,000-seed sweeps run below and KI-01's reproduction among
  them.
- `cargo fmt --all --check`: passed.
- Ubuntu WSL `cargo clippy --workspace --all-targets -- -D warnings` and
  `cargo clippy -p kinship-py --features test-hooks --all-targets -- -D warnings`:
  passed.
- Windows `uv run maturin develop --features test-hooks`, then `uv run pytest`:
  69 passed, 2 skipped (the two Windows fork tests). With `KINSHIP_TEST_HOOKS=1`,
  `tests/test_panic.py`: 1 passed. `ruff check` and `ruff format --check`: passed.
- The kinship-core `open_findings` suite runs unignored for KI-02, KI-03, KI-04
  and KI-06; only KI-01, accepted, stays ignored. The simulator `review` suite,
  including the new KI-06 honest-node test, passed in release.

KI-04's reproduction, one 546 KiB push-pull frame of 20,000 invented members:

| Build | Default limits | Configured for 20,000 |
| --- | --- | --- |
| Baseline, WSL release | all 20,000 admitted in 7.828 s | (no limits existed) |
| Fix, Windows release | 1,024 admitted in 8 ms | 20,000 admitted in 39 ms |
| Fix, WSL release, during other work | 1,024 admitted in 13 ms | 20,000 admitted in 79 ms |

The five CI release suites, 1,000 seeds each, all passed with every number the
same as the baseline: the fixes change no choice an honest run makes, and the
pinned SWIM trace is unchanged.

| Suite | Baseline | With the fixes |
| --- | --- | --- |
| sim scale, 1,000 nodes x 600 s | sent 1,193,993, delivered 1,182,127 | the same |
| SWIM, 50 nodes | 197,363 detections; p50 10.048 s, p99 142.603 s, max 477.945 s; 558 suspicions of live nodes, 16 refutations | the same |
| metadata | p50/p99/max 75 ms/375 ms/29.667 s; 99.973% by gossip within 4.6 s | the same |
| graceful leave | 150/350/400 ms | the same |
| partition heal | 1.25/16.25/25 s | the same |
| join into 200 nodes | 300 ms/1 s/1.1 s | the same |
| key rotation | no suspicions, no decrypt failures | the same |
| member left behind by rotation | 9/27.25/39.25 s | the same |
| name conflict | kept everywhere, reported at 2..14 nodes, 10/100/120 ms | the same |
| clock jump | no false deaths, 484 cut-round refutations, 300 ms/800 ms/21.2 s | the same |
| restart | 481 after the tombstone, never dead after restart, 310 ms/2.01 s/27.68 s | the same |
| long partition | 5/36/65.5 s | the same |

The sim scale wall time was 8.18 s against 9.10 s; it varies with the machine's
load and is not a result.

Fuzz smokes on the fixes, 60 seconds each on fresh copies of the seed corpora,
all exited zero: decode_datagram 295,081 runs, decode_payload 2,357,029,
decode_stream_frame 330,412, node_input 29,143. The seed corpora hash the same
before and after. Run counts depend on the machine's load at the time and are
not comparable with the baseline's.

## Detection latency

The 100-node kill -9 bench against memberlist ran locally, as the `Detection
latency` workflow would but on the uncommitted fixes: 30 runs each, seed 14,
the published setup in `detection.md`, in WSL with root through `wsl -u root`.
The same command ran on unchanged main straight after, as a control.

| Bench | kinship p50 / p99 / max (s) | memberlist p50 / p99 / max (s) |
| --- | --- | --- |
| With the fixes | 9.695 / 16.342 / 16.392 | 9.827 / 13.346 / 13.443 |
| Unchanged main, same morning | 9.679 / 23.843 / 24.181 | 9.803 / 12.339 / 12.589 |
| Published 2026-10-08 | 9.522 / 12.500 / 12.568 | 9.857 / 11.980 / 12.106 |

Medians agree everywhere, with no undetected kill and no false death. kinship's
tail is heavier than memberlist's in both of today's runs, the control included,
so it does not come from the fixes; `detection.md` records it as open.
`detection.csv` now holds the run with the fixes.
