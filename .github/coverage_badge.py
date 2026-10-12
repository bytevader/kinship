"""Combines Rust and Python line coverage into one shields.io endpoint badge.

    python .github/coverage_badge.py RUST_LCOV PYTHON_JSON BADGE_JSON

RUST_LCOV comes from `cargo llvm-cov report --lcov` and covers every crate kinship ships, the
PyO3 bindings included, as exercised by cargo test and pytest together. PYTHON_JSON is
coverage.py's JSON report for the `kinship` package. Prints a Markdown summary for the job.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path


def lcov_lines(path: Path) -> tuple[int, int]:
    hit = found = 0
    for line in path.read_text().splitlines():
        if line.startswith("LH:"):
            hit += int(line[3:])
        elif line.startswith("LF:"):
            found += int(line[3:])
    return hit, found


def color(percent: float) -> str:
    for floor, name in ((90, "brightgreen"), (80, "green"), (70, "yellow"), (60, "orange")):
        if percent >= floor:
            return name
    return "red"


def main() -> None:
    rust_lcov, python_json, badge = (Path(arg) for arg in sys.argv[1:4])
    rust_hit, rust_found = lcov_lines(rust_lcov)
    totals = json.loads(python_json.read_text())["totals"]
    py_hit, py_found = totals["covered_lines"], totals["num_statements"]
    percent = 100 * (rust_hit + py_hit) / (rust_found + py_found)
    # Rounded down, so the badge never claims more than was measured.
    shield = {
        "schemaVersion": 1,
        "label": "coverage",
        "message": f"{int(percent)}%",
        "color": color(percent),
    }
    badge.write_text(json.dumps(shield))
    print("| Code | Lines covered | Coverage |")
    print("| --- | ---: | ---: |")
    for name, hit, found in (
        ("Rust crates and bindings", rust_hit, rust_found),
        ("Python package", py_hit, py_found),
        ("Total", rust_hit + py_hit, rust_found + py_found),
    ):
        print(f"| {name} | {hit} / {found} | {100 * hit / found:.1f}% |")


if __name__ == "__main__":
    main()
