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

    def test_fastapi_app_routes_keys_to_their_owner(self) -> None:
        pytest.importorskip("fastapi")
        pytest.importorskip("httpx")
        out = run("fastapi_app.py")
        stored = dict(
            line.split(" stored on ") for line in out.splitlines() if " stored on " in line
        )
        assert len(stored) == 9 and set(stored.values()) == {"node-a", "node-b", "node-c"}
        assert "removed=['node-c']" in out
        moved = [line.split() for line in out.splitlines() if " moved from " in line]
        assert moved and all(words[3] == "node-c" for words in moved)
        assert {words[0] for words in moved} == {
            key.strip() for key, node in stored.items() if node == "node-c"
        }
        assert ": 404, " in out

    def test_messages_reach_their_members_once_large_ones_over_tcp(self) -> None:
        out = run("messages.py")
        got = [line for line in out.splitlines() if " got a " in line]
        broadcasts = [line.split()[0] for line in got if "broadcast from node-a" in line]
        assert sorted(broadcasts) == ["node-b", "node-c"], "once each, and not node-a"
        assert any(line.startswith("node-c got a message from node-b: b'report?'") for line in got)
        reply = next(line for line in got if line.startswith("node-b got a message from node-c"))
        assert reply.endswith(", 8890 bytes"), "more than a datagram holds"
        assert "node-b: 1 sent, 2 received" in out

    def test_sync_workers_route_around_a_draining_node(self) -> None:
        out = run("sync_workers.py")
        before, after = out.split("node-a routes new requests around node-b:")
        assert "node-b changed serving -> draining" in before
        assert "-> node-b" not in after
