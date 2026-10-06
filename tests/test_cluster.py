import asyncio
import contextlib
import logging
import time

import pytest

import kinship
from conftest import (
    WAIT,
    cluster_of,
    drain,
    local,
    names,
    next_event,
    next_matching,
    wait_until,
)


async def test_quickstart_join_crash_and_leave() -> None:
    """The README quickstart with 3 nodes: they join, a close without leave reads as dead,
    and a leave reads as left."""
    a = await kinship.Cluster(local()).start()
    try:
        events = a.events()
        seeds = [a.local.addr]
        b = await kinship.Cluster(local(seeds=seeds)).start()
        c = await kinship.Cluster(local(seeds=seeds)).start()
        joined = {(await next_matching(events, kinship.MemberJoined)).member.name for _ in "bc"}
        assert joined == {b.local.name, c.local.name}
        everyone = {a.local.name, b.local.name, c.local.name}
        await wait_until(lambda: names(a) == names(b) == names(c) == everyone)

        await c.close()
        dead = await next_matching(events, kinship.MemberDead, c.local.name)
        assert dead.member.state is kinship.State.DEAD
        assert c.local.name not in names(a)
        tombstone = a.member(c.local.name)
        assert tombstone is not None and tombstone.state is kinship.State.DEAD

        await b.leave()
        await b.close()
        left = await next_matching(events, kinship.MemberLeft, b.local.name)
        assert left.member.state is kinship.State.LEFT
        assert names(a) == {a.local.name}
    finally:
        await a.close()


async def test_members_local_and_tombstones() -> None:
    async with cluster_of(2) as (a, b):
        me = a.local
        assert me.state is kinship.State.ALIVE and me.addr.startswith("127.0.0.1:")
        assert me in a.members()
        seen = a.member(b.local.name)
        assert seen is not None and seen.state is kinship.State.ALIVE
        assert hash(seen) == hash(b.local) and seen.addr == b.local.addr
        assert a.member("nobody") is None
        with pytest.raises(TypeError):
            a.member(b.local.name).meta["x"] = "y"  # type: ignore[index]


async def test_each_events_call_is_its_own_subscription_from_the_call() -> None:
    async with kinship.Cluster(local()) as a:
        early = a.events()
        b = await kinship.Cluster(local(seeds=[a.local.addr])).start()
        await wait_until(lambda: b.local.name in names(a))
        late = a.events()  # created after b joined, before anyone awaits it
        c = await kinship.Cluster(local(seeds=[a.local.addr])).start()
        try:
            assert (await next_event(early)).member.name == b.local.name
            assert (await next_event(early)).member.name == c.local.name
            assert (await next_event(late)).member.name == c.local.name
        finally:
            await b.close()
            await c.close()


async def test_the_event_iterator_ends_when_the_cluster_closes() -> None:
    a = await kinship.Cluster(local()).start()
    events = a.events()
    await a.close()
    got = await asyncio.wait_for(_collect(events), WAIT)
    assert got == []
    assert await asyncio.wait_for(_collect(a.events()), WAIT) == []
    with pytest.raises(kinship.KinshipClosed):
        await a.set_meta({"k": "v"})
    await a.close()  # closing twice does nothing


async def _collect(events: kinship.EventStream) -> list[kinship.Event]:
    return [e async for e in events]


async def test_join_raises_when_no_seed_answers_but_startup_only_warns() -> None:
    probe = await kinship.Cluster(local()).start()
    dead_seed = probe.local.addr
    await probe.close()
    cfg = local(seeds=[dead_seed], join_retries=1)
    async with kinship.Cluster(cfg) as lonely:  # startup join failure only logs
        assert names(lonely) == {lonely.local.name}
        with pytest.raises(kinship.JoinError):
            await asyncio.wait_for(lonely.join(), WAIT)
        with pytest.raises(TypeError):
            await lonely.join(dead_seed)  # type: ignore[arg-type]


async def test_events_lost_after_a_slow_consumer() -> None:
    async with kinship.Cluster(local(event_buffer=4)) as a:
        slow = a.events()
        async with kinship.Cluster(local(seeds=[a.local.addr])) as b:
            name = b.local.name
            await wait_until(lambda: name in names(a))
            for i in range(10):
                await b.update_meta(n=str(i))
                await wait_until(lambda i=i: a.member(name).meta.get("n") == str(i))
            lost = await next_event(slow)
            assert isinstance(lost, kinship.EventsLost)
            assert lost.count >= 7  # 1 join and 10 updates into a buffer of 4
            rest = [await next_event(slow) for _ in range(4)]
            assert all(isinstance(e, kinship.MemberUpdated) for e in rest)
            assert rest[-1].member.meta["n"] == "9"


async def test_metadata_set_update_and_limits() -> None:
    async with cluster_of(2, meta={"role": "cache", "zone": "eu-1"}) as (a, b):
        events = a.events()
        name = b.local.name
        assert a.member(name).meta == {"role": "cache", "zone": "eu-1"}

        await b.update_meta(role="draining", zone=None, http="127.0.0.1:8080")
        assert b.local.meta == {"role": "draining", "http": "127.0.0.1:8080"}
        updated = await next_matching(events, kinship.MemberUpdated, name)
        assert updated.previous_meta == {"role": "cache", "zone": "eu-1"}
        assert updated.member.meta == {"role": "draining", "http": "127.0.0.1:8080"}
        match updated:
            case kinship.MemberUpdated(member=m, previous_meta=old):
                assert m.name == name and old["role"] == "cache"
            case _:
                pytest.fail("match_args do not match the README example")

        await b.set_meta({"role": "cache"})
        await wait_until(lambda: a.member(name).meta == {"role": "cache"})
        incarnation = a.member(name).incarnation
        assert incarnation >= 2, "each change raises the incarnation"

        with pytest.raises(kinship.MetaTooLarge):
            await b.set_meta({"blob": "x" * 600})
        with pytest.raises(ValueError):
            await b.update_meta(blob="x" * 600)
        assert b.local.meta == {"role": "cache"}, "a refused change leaves the metadata alone"


async def test_concurrent_updates_are_never_lost() -> None:
    async with kinship.Cluster(local()) as a:
        await asyncio.gather(*(a.update_meta(**{f"k{i}": str(i)}) for i in range(20)))
        assert a.local.meta == {f"k{i}": str(i) for i in range(20)}


async def test_leave_timing_out_logs_and_does_not_raise(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.WARNING, logger="kinship")
    async with cluster_of(3) as (a, _, c):
        events = a.events()
        await c.leave(timeout=0.001)
        assert any("timed out" in r.getMessage() for r in caplog.records)
        await next_matching(events, kinship.MemberLeft, c.local.name)
        await c.leave(timeout=1.0)  # leaving twice is fine
        await c.close()


async def test_aexit_leaves_on_cancellation() -> None:
    async with kinship.Cluster(local()) as a:
        events = a.events()
        started = asyncio.Event()
        names_seen: list[str] = []

        async def member() -> None:
            async with kinship.Cluster(local(seeds=[a.local.addr])) as b:
                names_seen.append(b.local.name)
                started.set()
                await asyncio.sleep(3600)

        task = asyncio.create_task(member())
        await asyncio.wait_for(started.wait(), WAIT)
        await next_matching(events, kinship.MemberJoined, names_seen[0])
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await asyncio.wait_for(task, WAIT)
        await next_matching(events, kinship.MemberLeft, names_seen[0])


async def test_aexit_never_masks_the_block_exception() -> None:
    with pytest.raises(KeyError):
        async with kinship.Cluster(local()) as a:
            await a.close()
            raise KeyError("mine")


async def test_blocked_event_loop_causes_no_false_deaths() -> None:
    """The week 10 gate: a handler blocks the event loop for 10 s while the cluster runs, and
    nobody is suspected or declared dead."""
    async with cluster_of(3) as nodes:
        streams = [n.events() for n in nodes]
        everyone = {n.local.name for n in nodes}

        def handler() -> None:
            time.sleep(10)

        before = time.monotonic()
        handler()  # holds the loop; kinship keeps probing on its own thread
        assert time.monotonic() - before >= 10
        await asyncio.sleep(1.0)  # let anything the protocol decided arrive

        for node, stream in zip(nodes, streams, strict=True):
            assert names(node) == everyone
            seen = await drain(stream)
            bad = [
                e
                for e in seen
                if isinstance(e, kinship.MemberSuspect | kinship.MemberDead | kinship.EventsLost)
            ]
            assert bad == [], f"{node.local.name} saw {seen}"
            assert node.stats().probes_sent > 0


async def test_stats_count_probes() -> None:
    async with cluster_of(2) as (a, _):
        await wait_until(lambda: a.stats().probes_sent >= 3)
        stats = a.stats()
        assert stats.decrypt_failures == 0 and stats.decode_errors == 0
        assert stats.local_health >= 0


async def test_calls_before_start_explain_themselves() -> None:
    cluster = kinship.Cluster(local())
    with pytest.raises(RuntimeError, match="not started"):
        cluster.members()
    assert "not started" in repr(cluster)
    with pytest.raises(TypeError):
        kinship.Cluster({"bind": "127.0.0.1:0"})  # type: ignore[arg-type]
