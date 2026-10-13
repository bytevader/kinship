"""Ownership that follows membership: which member owns a key, kept current as nodes come and go.

A ``Ring`` wraps a started ``kinship.Cluster`` or ``kinship.blocking.Cluster`` and answers
"who owns this key?" from the cluster's live view, with ``kinship.rendezvous`` hashing. Every
process that sees the same members agrees on the owner, and when a member joins or goes only
the keys it gains or loses move.

    ring = Ring(cluster, where={"role": "cache"})
    ring.owner("user:42")                     # the Member that owns the key
    ring.replicas("user:42", 3)               # the 3 best, owner first
    ring.owner("user:42", new_work=True)      # skips a suspect owner, for routing new requests

    before = ring.members()
    async for change in ring.changes():       # on kinship.blocking.Cluster: a plain for loop
        for key, (old, new) in ring.moved(my_keys, before, change.members).items():
            ...
        before = change.members

Suspect members keep their keys, so a node that only stalls causes no reshuffle; dead and
departed members own nothing.
"""

from __future__ import annotations

import contextlib
import time
from collections.abc import AsyncIterator, Callable, Iterable, Iterator, Mapping
from dataclasses import dataclass
from datetime import timedelta
from operator import attrgetter
from typing import Generic, TypeAlias, TypeVar, overload

from kinship import blocking, rendezvous
from kinship._cluster import Cluster, _seconds
from kinship._errors import KinshipClosed
from kinship._types import Event, EventsLost, Member, NameConflict, State

__all__ = ["Ring", "RingChanged"]

#: Which members a ring uses: metadata that must match exactly, or a predicate on ``Member``.
Where: TypeAlias = Mapping[str, str] | Callable[[Member], bool] | None

C = TypeVar("C", Cluster, blocking.Cluster)
K = TypeVar("K", str, bytes)

_LIVE = (State.ALIVE, State.SUSPECT)
_by_name = attrgetter("name")


def _names(members: Iterable[Member]) -> list[str]:
    return [m.name for m in members]


@dataclass(frozen=True, slots=True, repr=False)
class RingChanged:
    """The ring's members changed. Each field is a tuple of ``Member`` sorted by name.

    ``added`` and ``removed`` own keys now or no longer. ``suspect`` members missed their
    probes but keep their keys; ``recovered`` ones refuted the suspicion. ``members`` is the
    ring's new snapshot, the same as ``Ring.members()`` at this point, to pass to
    ``Ring.moved()``.
    """

    added: tuple[Member, ...]
    removed: tuple[Member, ...]
    suspect: tuple[Member, ...]
    recovered: tuple[Member, ...]
    members: tuple[Member, ...]

    def __repr__(self) -> str:
        return (
            f"RingChanged(added={_names(self.added)}, removed={_names(self.removed)}, "
            f"suspect={_names(self.suspect)}, recovered={_names(self.recovered)}, "
            f"members={_names(self.members)})"
        )


class Ring(Generic[C]):
    """Key ownership over the members of a cluster that match ``where``.

    ``where`` is a dict of metadata that a member must carry with exactly these values, such
    as ``{"role": "api"}``, or a predicate that takes a ``Member``. Without it every member
    counts. The cluster must be started before the ring is used; the ring reads it on every
    call and holds no state of its own, so it is safe to share across tasks and threads.
    """

    __slots__ = ("_cluster", "_where")

    def __init__(self, cluster: C, *, where: Where = None) -> None:
        if isinstance(where, Mapping):
            self._where: dict[str, str] | Callable[[Member], bool] | None = dict(where)
        elif where is None or callable(where):
            self._where = where
        else:
            raise TypeError(f"where must be a dict or a callable, not {type(where).__name__}")
        self._cluster = cluster

    @property
    def cluster(self) -> C:
        """The cluster this ring reads."""
        return self._cluster

    def matches(self, member: Member) -> bool:
        """Whether ``member`` belongs on this ring: alive or suspect, and matching ``where``."""
        if member.state not in _LIVE:
            return False
        where = self._where
        if where is None:
            return True
        if isinstance(where, dict):
            meta = member.meta
            return all(meta.get(k) == v for k, v in where.items())
        return bool(where(member))

    def members(self) -> tuple[Member, ...]:
        """The members on the ring now, alive and suspect, sorted by name."""
        return tuple(sorted(filter(self.matches, self._cluster.members()), key=_by_name))

    def _candidates(self, new_work: bool) -> list[Member]:
        members = filter(self.matches, self._cluster.members())
        if new_work:
            return [m for m in members if m.state is State.ALIVE]
        return list(members)

    def owner(self, key: str | bytes, *, new_work: bool = False) -> Member:
        """The member that owns ``key``. Suspect members keep their keys; with
        ``new_work=True`` a suspect owner is skipped, so new requests go to the member that
        would take its keys over if it died. Raises ``LookupError`` if no member qualifies."""
        candidates = self._candidates(new_work)
        if not candidates:
            raise LookupError("no member on the ring" + (" is alive" if new_work else ""))
        return rendezvous.owner(key, candidates)

    def replicas(self, key: str | bytes, n: int, *, new_work: bool = False) -> list[Member]:
        """The ``n`` members with the highest weight for ``key``, owner first: where to put
        replicas. Fewer if fewer members qualify. ``new_work=True`` skips suspect members."""
        return rendezvous.owners(key, self._candidates(new_work), n)

    def moved(
        self,
        keys: Iterable[K],
        before: Iterable[Member],
        after: Iterable[Member],
    ) -> dict[K, tuple[Member | None, Member | None]]:
        """Which of ``keys`` changed owner between two snapshots, as ``{key: (old_owner,
        new_owner)}``. ``before`` and ``after`` are ``members()`` snapshots or
        ``RingChanged.members``; members that do not belong on this ring are ignored. An
        owner is ``None`` when its snapshot has no members. Keys that kept their owner are
        left out."""
        old = [m for m in before if self.matches(m)]
        new = [m for m in after if self.matches(m)]
        moved: dict[K, tuple[Member | None, Member | None]] = {}
        for key in keys:
            was = rendezvous.owner(key, old) if old else None
            now = rendezvous.owner(key, new) if new else None
            if (was.name if was else None) != (now.name if now else None):
                moved[key] = (was, now)
        return moved

    @overload
    def changes(self: Ring[Cluster]) -> AsyncIterator[RingChanged]: ...
    @overload
    def changes(
        self: Ring[blocking.Cluster], timeout: float | timedelta | None = None
    ) -> Iterator[RingChanged | None]: ...
    def changes(
        self, timeout: float | timedelta | None = None
    ) -> AsyncIterator[RingChanged] | Iterator[RingChanged | None]:
        """A new, independent iterator of ring changes, starting now, built on the cluster's
        ``events()``.

        It yields a ``RingChanged`` whenever a member on the ring joins or goes, becomes
        suspect or recovers, or changes its metadata so that it starts or stops matching
        ``where``. Other events are skipped. After ``EventsLost`` it re-reads the members and
        always yields, since lost events may have moved keys. On ``kinship.Cluster`` it is an
        async iterator. On ``kinship.blocking.Cluster`` it is a blocking iterator that, with a
        ``timeout``, yields ``None`` whenever that long passes without a change. It ends
        when the cluster closes.

        Events never describe the local node, so a change to this node's own metadata
        reaches the iterator with the next event, or the next ``None`` tick.
        """
        cluster = self._cluster
        if isinstance(cluster, blocking.Cluster):
            seconds = _seconds(timeout)
            sync_events = cluster.events(timeout=seconds)
            return _Changes(sync_events, _Tracker(self), seconds)
        if timeout is not None:
            raise TypeError("timeout= is for kinship.blocking.Cluster; use asyncio.timeout()")
        return _AsyncChanges(cluster.events(), _Tracker(self))

    def __repr__(self) -> str:
        return f"Ring(where={self._where!r})"


class _Tracker:
    """The ring's members as one subscription has seen them, updated event by event."""

    __slots__ = ("_members", "_ring")

    def __init__(self, ring: Ring[Cluster] | Ring[blocking.Cluster]) -> None:
        # Called after the subscription starts, so nothing falls between the two. Events
        # that the snapshot already reflects change nothing when applied again.
        self._ring = ring
        self._members = {m.name: m for m in ring.members()}

    def apply(self, event: Event | None) -> RingChanged | None:
        if isinstance(event, EventsLost):
            return self._resync()
        added: list[Member] = []
        removed: list[Member] = []
        suspect: list[Member] = []
        recovered: list[Member] = []
        lists = (added, removed, suspect, recovered)
        if event is not None and not isinstance(event, NameConflict):
            self._update(event.member, *lists)
        # No event describes this node, so its own metadata is checked on every wake.
        with contextlib.suppress(KinshipClosed):
            self._update(self._ring.cluster.local, *lists)
        if not any(lists):
            return None
        return self._changed(*lists)

    def _update(
        self,
        member: Member,
        added: list[Member],
        removed: list[Member],
        suspect: list[Member],
        recovered: list[Member],
    ) -> None:
        old = self._members.get(member.name)
        if self._ring.matches(member):
            self._members[member.name] = member
            if old is None:
                added.append(member)
            elif old.state is State.ALIVE and member.state is State.SUSPECT:
                suspect.append(member)
            elif old.state is State.SUSPECT and member.state is State.ALIVE:
                recovered.append(member)
        elif old is not None:
            del self._members[member.name]
            removed.append(member)

    def _resync(self) -> RingChanged:
        old = self._members
        new = {m.name: m for m in self._ring.members()}
        self._members = new
        both = old.keys() & new.keys()
        return self._changed(
            [m for name, m in new.items() if name not in old],
            [m for name, m in old.items() if name not in new],
            [new[n] for n in both if old[n].state is State.ALIVE and new[n].state is State.SUSPECT],
            [new[n] for n in both if old[n].state is State.SUSPECT and new[n].state is State.ALIVE],
        )

    def _changed(
        self,
        added: list[Member],
        removed: list[Member],
        suspect: list[Member],
        recovered: list[Member],
    ) -> RingChanged:
        return RingChanged(
            tuple(sorted(added, key=_by_name)),
            tuple(sorted(removed, key=_by_name)),
            tuple(sorted(suspect, key=_by_name)),
            tuple(sorted(recovered, key=_by_name)),
            tuple(sorted(self._members.values(), key=_by_name)),
        )


class _AsyncChanges:
    __slots__ = ("_events", "_tracker")

    def __init__(self, events: AsyncIterator[Event], tracker: _Tracker) -> None:
        self._events = events
        self._tracker = tracker

    def __aiter__(self) -> _AsyncChanges:
        return self

    async def __anext__(self) -> RingChanged:
        async for event in self._events:
            change = self._tracker.apply(event)
            if change is not None:
                return change
        raise StopAsyncIteration


class _Changes:
    __slots__ = ("_events", "_last", "_timeout", "_tracker")

    def __init__(
        self, events: Iterator[Event | None], tracker: _Tracker, timeout: float | None
    ) -> None:
        self._events = events
        self._tracker = tracker
        self._timeout = timeout
        self._last = time.monotonic()

    def __iter__(self) -> _Changes:
        return self

    def __next__(self) -> RingChanged | None:
        for event in self._events:
            change = self._tracker.apply(event)
            now = time.monotonic()
            if change is not None:
                self._last = now
                return change
            # A stream of events that change nothing must not hold back the timeout tick.
            if event is None or (self._timeout is not None and now - self._last >= self._timeout):
                self._last = now
                return None
        raise StopIteration
