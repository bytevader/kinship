"""Rendezvous (highest random weight) hashing: which member owns a key.

Every process that sees the same members picks the same owner, and when a member joins or
leaves only the keys it gains or loses move. The weight of a member for a key is the first 8
bytes of BLAKE2b over the member's name and the key, a hash that is the same in every process,
on every platform and in every Python version. Python's built-in ``hash()`` is not: it is
salted per process.

    owner("user:42", cluster.members())        # the Member that owns the key
    owners("user:42", cluster.members(), 3)    # the 3 best, owner first, for replicas
"""

from __future__ import annotations

import hashlib
from collections.abc import Iterable
from typing import Protocol, TypeVar

__all__ = ["owner", "owners", "weight"]

_PERSON = b"kinship-hrw-v1"


class _Named(Protocol):
    @property
    def name(self) -> str: ...


T = TypeVar("T", bound="_Named | str")


def _bytes(value: str | bytes) -> bytes:
    if isinstance(value, str):
        return value.encode()
    if isinstance(value, bytes | bytearray | memoryview):
        return bytes(value)
    raise TypeError(f"keys and names must be str or bytes, not {type(value).__name__}")


def weight(key: str | bytes, name: str) -> int:
    """The 64-bit weight of the member called ``name`` for ``key``. ``str`` values hash as
    their UTF-8 bytes."""
    n = _bytes(name)
    h = hashlib.blake2b(digest_size=8, person=_PERSON)
    h.update(len(n).to_bytes(4, "big"))
    h.update(n)
    h.update(_bytes(key))
    return int.from_bytes(h.digest(), "big")


def _name(member: _Named | str) -> str:
    return member if isinstance(member, str) else member.name


def _ranked(key: str | bytes, members: Iterable[T]) -> list[T]:
    k = _bytes(key)
    scored = [(weight(k, _name(m)), _name(m), m) for m in members]
    # Ties on weight, which need a 64-bit collision, fall back to the name.
    scored.sort(key=lambda s: (s[0], s[1]), reverse=True)
    return [m for _, _, m in scored]


def owner(key: str | bytes, members: Iterable[T]) -> T:
    """The member that owns ``key``: the one with the highest weight. ``members`` holds
    ``Member`` objects, anything else with a ``name``, or names. Raises ``ValueError`` if it is
    empty."""
    best: T | None = None
    best_score: tuple[int, str] | None = None
    k = _bytes(key)
    for m in members:
        name = _name(m)
        score = (weight(k, name), name)
        if best_score is None or score > best_score:
            best, best_score = m, score
    if best_score is None:
        raise ValueError("no members to own the key")
    return best  # type: ignore[return-value]


def owners(key: str | bytes, members: Iterable[T], n: int) -> list[T]:
    """The ``n`` members with the highest weight for ``key``, owner first: where to put
    replicas. Fewer if there are fewer members."""
    if n < 0:
        raise ValueError("n must be at least 0")
    return _ranked(key, members)[:n]
