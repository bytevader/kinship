"""The runnable examples in examples/ still run and still show what they claim."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

EXAMPLES = Path(__file__).resolve().parent.parent / "examples"


def run(name: str) -> str:
    result = subprocess.run(
        [sys.executable, str(EXAMPLES / name)],
        capture_output=True,
        text=True,
        timeout=120,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    return result.stdout


@pytest.mark.skipif(not EXAMPLES.is_dir(), reason="examples/ is not shipped in the sdist")
class TestExamples:
    def test_sharded_keys_moves_only_the_departed_nodes_keys(self) -> None:
        out = run("sharded_keys.py")
        assert "node-a sees MemberLeft(node-d)" in out
        assert "node-a sees MemberDead(node-c)" in out
        after_leave, after_crash = out.split("After node-d left:")[1].split("After node-c crashed:")
        assert "moved from node-c" not in after_leave and "moved from node-d" in after_leave
        assert "moved from node-d" not in after_crash and "moved from node-c" in after_crash

    def test_failover_job_moves_to_another_node(self) -> None:
        out = run("failover_job.py")
        crashed = out.split(" crashes")[0].split()[-1]
        moved_to = out.split("the job moved to ")[1].split()[0]
        assert moved_to != crashed

    def test_sync_workers_route_around_a_draining_node(self) -> None:
        out = run("sync_workers.py")
        before, after = out.split("node-a routes new requests around node-b:")
        assert "node-b changed serving -> draining" in before
        assert "-> node-b" not in after
