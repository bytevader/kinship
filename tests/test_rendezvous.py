import itertools
import random

import pytest

import kinship
from kinship.rendezvous import owner, owners, weight

NODES = ["node-a", "node-b", "node-c", "node-d"]


def test_fixed_vectors() -> None:
    """These values must never change: every process, platform and Python version agrees."""
    assert weight("user:42", "node-a") == 0xFDD5D90B693C9A10
    assert weight(b"", "") == 0xE44B0C9120B1B9EF
    assert weight("ключ", "узел") == 0xD2339C4153AD9505
    assert weight("user:42", "node-a") == weight(b"user:42", "node-a")
    assert owners("user:42", NODES, 4) == ["node-a", "node-c", "node-d", "node-b"]
    assert owners("nightly-report", NODES, 4) == ["node-b", "node-a", "node-d", "node-c"]
    assert owners("room/lobby", NODES, 4) == ["node-a", "node-b", "node-d", "node-c"]
    assert owners(b"\x00\xff", NODES, 4) == ["node-b", "node-a", "node-c", "node-d"]


def test_owner_ignores_member_order_and_accepts_members() -> None:
    members = [kinship.Member(n, "127.0.0.1:1", kinship.State.ALIVE, 0) for n in NODES]
    for perm in itertools.permutations(members):
        assert owner("user:42", perm).name == "node-a"
    assert [m.name for m in owners("user:42", members, 2)] == ["node-a", "node-c"]
    assert owners("user:42", members, 0) == []
    assert len(owners("user:42", members, 10)) == 4


def test_only_the_keys_of_a_changed_node_move() -> None:
    rng = random.Random(7)
    keys = [f"key-{rng.random()}" for _ in range(2000)]
    before = {k: owner(k, NODES) for k in keys}
    grown = [*NODES, "node-e"]
    after = {k: owner(k, grown) for k in keys}
    moved = [k for k in keys if before[k] != after[k]]
    assert all(after[k] == "node-e" for k in moved)
    assert 250 < len(moved) < 550, "about a fifth of the keys move to the new node"
    shrunk = [n for n in NODES if n != "node-b"]
    for k in keys:
        if before[k] != "node-b":
            assert owner(k, shrunk) == before[k]


def test_errors() -> None:
    with pytest.raises(ValueError):
        owner("k", [])
    with pytest.raises(ValueError):
        owners("k", NODES, -1)
    with pytest.raises(TypeError):
        owner(42, NODES)  # type: ignore[arg-type]
