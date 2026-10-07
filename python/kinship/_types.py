"""Members, states, events and stats: frozen values built from the extension's raw tuples."""

from __future__ import annotations

import enum
from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Any, TypeAlias

_EMPTY: Mapping[str, str] = MappingProxyType({})


class State(enum.Enum):
    """A member's state as this node sees it."""

    ALIVE = 0
    SUSPECT = 1
    DEAD = 2
    LEFT = 3

    def __repr__(self) -> str:
        return f"State.{self.name}"


_STATES = tuple(State)


@dataclass(frozen=True, slots=True, eq=True, repr=False)
class Member:
    """One cluster member. Frozen, hashable by name, with read-only ``meta``."""

    name: str
    addr: str
    state: State
    incarnation: int
    meta: Mapping[str, str] = field(default_factory=lambda: _EMPTY)

    def __hash__(self) -> int:
        return hash(self.name)

    def __repr__(self) -> str:
        return (
            f"Member(name={self.name!r}, addr={self.addr!r}, state={self.state!r}, "
            f"incarnation={self.incarnation}, meta={dict(self.meta)!r})"
        )


def _meta(pairs: list[tuple[str, str]]) -> Mapping[str, str]:
    return MappingProxyType(dict(pairs)) if pairs else _EMPTY


def _member(raw: tuple[str, str, int, int, list[tuple[str, str]]]) -> Member:
    name, addr, state, incarnation, meta = raw
    return Member(name, addr, _STATES[state], incarnation, _meta(meta))


@dataclass(frozen=True, slots=True)
class MemberJoined:
    """A node is alive that was unknown, dead or left."""

    member: Member

    def __repr__(self) -> str:
        return f"MemberJoined({self.member.name})"


@dataclass(frozen=True, slots=True)
class MemberSuspect:
    """A node missed its probes and is suspected."""

    member: Member

    def __repr__(self) -> str:
        return f"MemberSuspect({self.member.name})"


@dataclass(frozen=True, slots=True)
class MemberRecovered:
    """A suspect node refuted the suspicion and is alive again."""

    member: Member

    def __repr__(self) -> str:
        return f"MemberRecovered({self.member.name})"


@dataclass(frozen=True, slots=True)
class MemberDead:
    """A suspicion expired without a refutation."""

    member: Member

    def __repr__(self) -> str:
        return f"MemberDead({self.member.name})"


@dataclass(frozen=True, slots=True)
class MemberLeft:
    """A node left on purpose."""

    member: Member

    def __repr__(self) -> str:
        return f"MemberLeft({self.member.name})"


@dataclass(frozen=True, slots=True)
class MemberUpdated:
    """A node changed its metadata."""

    member: Member
    previous_meta: Mapping[str, str]

    def __repr__(self) -> str:
        return f"MemberUpdated({self.member.name})"


@dataclass(frozen=True, slots=True)
class NameConflict:
    """Two live nodes claim the same name; the newer one, at ``other_addr``, is ignored."""

    member: Member
    other_addr: str

    def __repr__(self) -> str:
        return f"NameConflict({self.member.name}, {self.other_addr})"


@dataclass(frozen=True, slots=True)
class EventsLost:
    """The consumer fell behind and ``count`` events were dropped; resync from ``members()``."""

    count: int

    def __repr__(self) -> str:
        return f"EventsLost({self.count})"


Event: TypeAlias = (
    MemberJoined
    | MemberSuspect
    | MemberRecovered
    | MemberDead
    | MemberLeft
    | MemberUpdated
    | NameConflict
    | EventsLost
)

_MEMBER_EVENTS: dict[str, Any] = {
    "MemberJoined": MemberJoined,
    "MemberSuspect": MemberSuspect,
    "MemberRecovered": MemberRecovered,
    "MemberDead": MemberDead,
    "MemberLeft": MemberLeft,
}


def _event(raw: tuple[Any, ...]) -> Event:
    kind, member, previous_meta, other_addr, count = raw
    if kind == "EventsLost":
        return EventsLost(count)
    m = _member(member)
    if kind == "MemberUpdated":
        return MemberUpdated(m, _meta(previous_meta))
    if kind == "NameConflict":
        return NameConflict(m, other_addr)
    cls = _MEMBER_EVENTS[kind]
    event: Event = cls(m)
    return event


@dataclass(frozen=True, slots=True)
class Stats:
    """Counters from the protocol and this node's Lifeguard local health score."""

    local_health: int
    packets_received: int
    decode_errors: int
    decrypt_failures: int
    replays_dropped: int
    probes_sent: int
    probes_failed: int
    indirect_probes: int
    missed_nacks: int
    suspicions: int
    refutations: int
    misdirected: int
    name_conflicts: int
    push_pulls: int
    push_pull_failures: int
    push_pulls_served: int
    state_too_large: int
    tcp_pings: int
    tcp_ping_acks: int
