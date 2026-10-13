import asyncio
import threading
from collections.abc import Callable
from typing import Any

import pytest

import kinship
from conftest import WAIT, local, names, wait_until, wait_until_sync
from kinship import blocking, rendezvous
from kinship.ring import Ring, RingChanged

ALIVE, SUSPECT, DEAD, LEFT = kinship.State
KEYS = [f"user:{i}" for i in range(200)]


def member(name: str, state: kinship.State = ALIVE, **meta: str) -> kinship.Member:
    return kinship.Member(name, "127.0.0.1:1", state, 0, meta)


class FakeCluster:
    """Just enough of kinship.Cluster for a Ring: members(), local and events()."""

    def __init__(self, *members: kinship.Member) -> None:
        self.view = {m.name: m for m in members}
        self.local = members[0]
        self.script: list[tuple[Callable[[], None], Any]] = []

    def members(self) -> list[kinship.Member]:
        return list(self.view.values())

    def set(self, m: kinship.Member) -> None:
        if m.name == self.local.name:
            self.local = m
        if m.state in (ALIVE, SUSPECT):
            self.view[m.name] = m
        else:
            self.view.pop(m.name, None)

    def emit(self, kind: type[Any], m: kinship.Member, *fields: Any) -> None:
        """Queues an event about `m`, which the view reflects by the time it is read."""
        self.script.append((lambda: self.set(m), kind(m, *fields)))

    def lose(self, m: kinship.Member, count: int) -> None:
        """Changes the view to hold `m` and queues EventsLost instead of its event."""
        self.script.append((lambda: self.set(m), kinship.EventsLost(count)))

    def events(self) -> "FakeEvents":
        return FakeEvents(self.script)


class FakeEvents:
    def __init__(self, script: list[tuple[Callable[[], None], Any]]) -> None:
        self._script = iter(script)

    def __aiter__(self) -> "FakeEvents":
        return self

    async def __anext__(self) -> Any:
        for apply, event in self._script:
            apply()
            return event
        raise StopAsyncIteration


def ring_names(members: tuple[kinship.Member, ...] | list[kinship.Member]) -> list[str]:
    return [m.name for m in members]


def test_owner_and_replicas_use_rendezvous() -> None:
    nodes = [member(n) for n in ("node-d", "node-a", "node-c", "node-b")]
    ring = Ring(FakeCluster(*nodes))
    assert ring_names(ring.members()) == ["node-a", "node-b", "node-c", "node-d"]
    assert isinstance(ring.members(), tuple)
    for key in [*KEYS[:50], b"\x00\xff", "ключ"]:
        assert ring.owner(key) == rendezvous.owner(key, nodes)
        assert ring.replicas(key, 3) == rendezvous.owners(key, nodes, 3)
    assert ring.owner("user:42").name == "node-a"
    assert ring_names(ring.replicas("user:42", 10)) == ["node-a", "node-c", "node-d", "node-b"]
    assert ring.replicas("user:42", 0) == []
    with pytest.raises(ValueError):
        ring.replicas("user:42", -1)
    with pytest.raises(TypeError):
        ring.owner(42)  # type: ignore[arg-type]


def test_where_dict_and_predicate() -> None:
    cluster = FakeCluster(
        member("api-1", role="api", zone="eu"),
        member("api-2", role="api", zone="us"),
        member("worker-1", role="worker", zone="eu"),
        member("bare"),
    )
    where = {"role": "api"}
    api = Ring(cluster, where=where)
    where["role"] = "worker"  # the ring keeps its own copy
    assert ring_names(api.members()) == ["api-1", "api-2"]
    assert ring_names(Ring(cluster, where={"role": "api", "zone": "eu"}).members()) == ["api-1"]
    assert Ring(cluster, where={"role": "db"}).members() == ()
    eu = Ring(cluster, where=lambda m: m.meta.get("zone") == "eu")
    assert ring_names(eu.members()) == ["api-1", "worker-1"]
    assert ring_names(Ring(cluster).members()) == ["api-1", "api-2", "bare", "worker-1"]
    for key in KEYS[:50]:
        assert api.owner(key).meta["role"] == "api"
    with pytest.raises(TypeError):
        Ring(cluster, where="role=api")  # type: ignore[arg-type]
    with pytest.raises(LookupError):
        Ring(cluster, where={"role": "db"}).owner("user:1")
    assert Ring(cluster, where={"role": "db"}).replicas("user:1", 3) == []


def test_suspect_keeps_its_keys_and_new_work_skips_it() -> None:
    alive = [member(n) for n in ("node-a", "node-b", "node-c")]
    stalled = member("node-d", SUSPECT)
    ring = Ring(FakeCluster(*alive, stalled))
    owned = [k for k in KEYS if rendezvous.owner(k, [*alive, member("node-d")]).name == "node-d"]
    assert owned
    for key in owned:
        assert ring.owner(key) is stalled
        assert ring.owner(key, new_work=True) == rendezvous.owner(key, alive)
        assert ring.owner(key, new_work=True) == ring.replicas(key, 2)[1]
        assert stalled not in ring.replicas(key, 4, new_work=True)
    assert ring.moved(KEYS, [*alive, member("node-d")], ring.members()) == {}

    with pytest.raises(LookupError):
        Ring(FakeCluster(member("node-a", SUSPECT))).owner("user:1", new_work=True)
    assert Ring(FakeCluster(member("node-a", SUSPECT))).owner("user:1").name == "node-a"


def test_dead_and_left_members_never_own_anything() -> None:
    # The cluster never lists them, but a snapshot or a fake might.
    ring = Ring(FakeCluster(member("node-a"), member("node-b", DEAD), member("node-c", LEFT)))
    assert ring_names(ring.members()) == ["node-a"]
    assert all(ring.owner(k).name == "node-a" for k in KEYS)
    assert not ring.matches(member("node-b", DEAD))


def test_moved_lists_only_keys_that_changed_owner() -> None:
    four = [member(n) for n in ("node-a", "node-b", "node-c", "node-d")]
    ring = Ring(FakeCluster(*four))
    three = four[:3]
    moved = ring.moved(KEYS, four, three)
    assert moved
    for key, (old, new) in moved.items():
        assert old is not None and old.name == "node-d"
        assert new == rendezvous.owner(key, three)
    gone = {k for k in KEYS if rendezvous.owner(k, four).name == "node-d"}
    assert set(moved) == gone

    # A join takes keys from everyone else, and only those.
    joined = ring.moved(KEYS, three, four)
    assert set(joined) == gone and all(new.name == "node-d" for _, new in joined.values())

    assert ring.moved(KEYS, four, four) == {}
    assert ring.moved([b"raw"], [], three) == {b"raw": (None, rendezvous.owner(b"raw", three))}
    assert ring.moved(["k"], [], []) == {}
    # Members that do not belong on the ring are ignored.
    api = Ring(FakeCluster(*four), where={"role": "api"})
    assert api.moved(KEYS, four, three) == {}


async def test_changes_follows_events() -> None:
    cluster = FakeCluster(
        member("node-a", role="api"), member("node-b", role="api"), member("node-c")
    )
    ring = Ring(cluster, where={"role": "api"})
    emit = cluster.emit
    emit(kinship.MemberJoined, member("node-e"))  # not on the ring
    emit(kinship.MemberJoined, member("node-d", role="api"))
    emit(kinship.MemberSuspect, member("node-b", SUSPECT, role="api"))
    emit(kinship.MemberRecovered, member("node-b", role="api"))
    emit(kinship.MemberUpdated, member("node-b", role="worker"), {"role": "api"})
    emit(kinship.MemberUpdated, member("node-c", role="api"), {})
    emit(kinship.MemberUpdated, member("node-c", role="api", zone="eu"), {"role": "api"})
    emit(kinship.MemberDead, member("node-d", DEAD, role="api"))
    emit(kinship.MemberLeft, member("node-c", LEFT, role="api"))
    changes = ring.changes()
    seen = [change async for change in changes]

    def summary(ch: RingChanged) -> tuple[list[str], ...]:
        return tuple(ring_names(x) for x in (ch.added, ch.removed, ch.suspect, ch.recovered))

    assert [summary(ch) for ch in seen] == [
        (["node-d"], [], [], []),
        ([], [], ["node-b"], []),
        ([], [], [], ["node-b"]),
        ([], ["node-b"], [], []),
        (["node-c"], [], [], []),
        ([], ["node-d"], [], []),
        ([], ["node-c"], [], []),
    ]
    assert [ring_names(ch.members) for ch in seen] == [
        ["node-a", "node-b", "node-d"],
        ["node-a", "node-b", "node-d"],
        ["node-a", "node-b", "node-d"],
        ["node-a", "node-d"],
        ["node-a", "node-c", "node-d"],
        ["node-a", "node-c"],
        ["node-a"],
    ]
    assert seen[1].suspect[0].state is SUSPECT and seen[1].members[1].state is SUSPECT
    assert seen[-1].members == ring.members()
    assert "added=['node-d']" in repr(seen[0])


async def test_changes_resyncs_after_events_lost_and_sees_its_own_metadata() -> None:
    cluster = FakeCluster(member("node-a", role="api"), member("node-b", role="api"))
    ring = Ring(cluster, where={"role": "api"})
    # node-c joins and node-b becomes suspect, but their events are lost. A resync always
    # yields, even when it finds nothing new.
    cluster.lose(member("node-c", role="api"), 2)
    cluster.lose(member("node-b", SUSPECT, role="api"), 1)
    cluster.lose(member("node-a", role="api"), 5)
    # This node marks itself draining. No event describes it, so the next event carries it.
    draining = member("node-a", role="draining")
    conflict = kinship.NameConflict(member("node-b", role="api"), "127.0.0.1:2")
    cluster.script.append((lambda: cluster.set(draining), conflict))
    seen = [ch async for ch in ring.changes()]
    assert len(seen) == 4
    assert [(ring_names(ch.added), ring_names(ch.suspect)) for ch in seen[:3]] == [
        (["node-c"], []),
        ([], ["node-b"]),
        ([], []),
    ]
    assert ring_names(seen[2].members) == ["node-a", "node-b", "node-c"]
    assert ring_names(seen[3].removed) == ["node-a"]
    assert ring_names(seen[3].members) == ["node-b", "node-c"]
    with pytest.raises(TypeError):
        ring.changes(timeout=1.0)  # type: ignore[call-overload]


async def test_ring_on_three_loopback_nodes() -> None:
    a = await kinship.Cluster(local(name="node-a", meta={"role": "api"})).start()
    nodes = [a]
    try:
        seeds = [a.local.addr]
        for name, role in (("node-b", "api"), ("node-c", "worker")):
            cfg = local(name=name, seeds=seeds, meta={"role": role})
            nodes.append(await kinship.Cluster(cfg).start())
        await wait_until(lambda: all(len(n.members()) == 3 for n in nodes))
        ring = Ring(a, where={"role": "api"})
        assert ring_names(ring.members()) == ["node-a", "node-b"]
        changes = ring.changes()
        before = ring.members()

        async def next_change() -> RingChanged:
            return await asyncio.wait_for(anext(changes), WAIT)

        # A worker that turns into an api node joins the ring.
        await nodes[2].update_meta(role="api")
        change = await next_change()
        assert ring_names(change.added) == ["node-c"]
        assert change.members == ring.members()
        moved = ring.moved(KEYS, before, change.members)
        assert moved and all(new.name == "node-c" for _, new in moved.values())
        assert all(ring.owner(k).name == "node-c" for k in moved)

        # A crash: suspect first, keeping its keys, then gone.
        c = nodes.pop()
        owned = [k for k in KEYS if ring.owner(k).name == "node-c"]
        await c.close()
        change = await next_change()
        assert ring_names(change.suspect) == ["node-c"]
        assert all(ring.owner(k).name == "node-c" for k in owned)
        assert all(ring.owner(k, new_work=True).name != "node-c" for k in owned)
        change = await next_change()
        assert ring_names(change.removed) == ["node-c"]
        assert ring_names(change.members) == ["node-a", "node-b"]
        assert set(ring.moved(KEYS, before, change.members)) == set()
    finally:
        for node in nodes:
            await node.close()


def test_ring_on_blocking_clusters() -> None:
    with (
        blocking.Cluster(local(meta={"role": "api"})) as a,
        blocking.Cluster(local(seeds=[a.local.addr], meta={"role": "api"})) as b,
    ):
        wait_until_sync(lambda: names(a) == names(b) == {a.local.name, b.local.name})
        ring = Ring(a, where={"role": "api"})
        assert ring.owner("user:1") in ring.members()
        changes = ring.changes(timeout=0.1)
        assert next(changes) is None  # a tick with nothing to report
        seen: list[RingChanged] = []
        reader = threading.Thread(
            target=lambda: seen.extend(ch for ch in changes if ch is not None), daemon=True
        )
        reader.start()
        b.update_meta(role="worker")
        wait_until_sync(lambda: bool(seen))
        assert ring_names(seen[0].removed) == [b.local.name]
        assert ring_names(seen[0].members) == [a.local.name]
    reader.join(WAIT)
    assert not reader.is_alive()  # the iterator ends when the cluster closes
