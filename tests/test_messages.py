"""User messages between loopback clusters: direct messages over UDP and TCP, broadcasts, the
sends a node refuses, the counters, a slow reader, kinship.ring, and the blocking API."""

import asyncio
import dataclasses
import os
import time
from collections.abc import AsyncIterator

import pytest

import kinship
from conftest import WAIT, cluster_of, drain, local, names, wait_until, wait_until_sync
from kinship import blocking
from kinship.ring import Ring


async def next_message(stream: AsyncIterator[kinship.Event]) -> kinship.UserMessage:
    """Reads until a user message arrives, skipping membership events."""

    async def find() -> kinship.UserMessage:
        async for event in stream:
            if isinstance(event, kinship.UserMessage):
                return event
        raise AssertionError("stream ended before a UserMessage")

    return await asyncio.wait_for(find(), WAIT)


def messages(events: list[kinship.Event]) -> list[kinship.UserMessage]:
    return [e for e in events if isinstance(e, kinship.UserMessage)]


async def test_a_direct_message_reaches_its_member() -> None:
    async with cluster_of(2) as (a, b):
        events = b.events()
        to_b = a.member(b.local.name)
        assert to_b is not None
        await a.send(to_b, b"hello")
        msg = await next_message(events)
        assert (msg.data, msg.broadcast) == (b"hello", False)
        assert (msg.sender.name, msg.sender.epoch) == (a.local.name, a.local.epoch)
        assert repr(msg) == f"UserMessage(message from {a.local.name}, 5 bytes)"
        # A name alone goes to whichever run a holds, and bytearray data is fine.
        await a.send(b.local.name, bytearray(b"by name"))
        assert (await next_message(events)).data == b"by name"
        assert a.stats().user_messages_sent == 2
        stats = b.stats()
        assert (stats.user_messages_received, stats.user_messages_dropped) == (2, 0)


async def test_a_large_message_goes_over_tcp_whole() -> None:
    async with cluster_of(2, keys=[os.urandom(32)]) as (a, b):
        events = b.events()
        data = os.urandom(50_000)
        await a.send(b.local.name, data)
        msg = await next_message(events)
        assert msg.data == data and msg.sender.name == a.local.name
        assert b.stats().decrypt_failures == 0


async def test_a_broadcast_reaches_every_other_member_once() -> None:
    async with cluster_of(3) as nodes:
        streams = [n.events() for n in nodes]
        sender = nodes[0].local.name
        await nodes[0].broadcast(b"drop user:42")
        for stream in streams[1:]:
            msg = await next_message(stream)
            assert (msg.sender.name, msg.data, msg.broadcast) == (sender, b"drop user:42", True)
        # Every copy has been sent by now: still once each, and none for the sender.
        await asyncio.sleep(1.5)
        for stream in streams:
            assert messages(await drain(stream, quiet=0.3)) == []
        assert nodes[0].stats().user_messages_sent == 1
        assert sum(n.stats().user_messages_received for n in nodes) == 2


async def test_sends_are_refused_for_strangers_and_oversized_data() -> None:
    async with cluster_of(2) as (a, b):
        with pytest.raises(kinship.NotAMember):
            await a.send("nobody", b"x")
        with pytest.raises(kinship.NotAMember):
            await a.send(a.local, b"x")
        held = a.member(b.local.name)
        assert held is not None
        with pytest.raises(kinship.NotAMember):
            await a.send(dataclasses.replace(held, epoch=held.epoch - 1), b"x")
        assert issubclass(kinship.NotAMember, LookupError)
        with pytest.raises(kinship.MessageTooLarge):
            await a.send(b.local.name, bytes(a.config.max_user_message + 1))
        with pytest.raises(kinship.MessageTooLarge):
            await a.broadcast(bytes(a.config.max_user_broadcast + 1))
        assert issubclass(kinship.MessageTooLarge, ValueError)
        assert a.stats().user_messages_too_large == 2
        with pytest.raises(TypeError):
            await a.send(b.local.name, "text")  # type: ignore[arg-type]
        with pytest.raises(TypeError):
            await a.send(42, b"x")  # type: ignore[arg-type]
        await a.leave()
        with pytest.raises(kinship.KinshipClosed):
            await a.broadcast(b"x")


async def test_a_slow_reader_loses_messages_as_events_lost() -> None:
    async with cluster_of(2, event_buffer=4) as (a, b):
        events = b.events()
        for i in range(10):
            await a.send(b.local.name, bytes([i]))
        await wait_until(lambda: b.stats().user_messages_received == 10)
        got = await drain(events)
        assert got[0] == kinship.EventsLost(6)
        assert len(messages(got[1:])) == 4


async def test_a_ring_skips_user_messages() -> None:
    async with cluster_of(2) as (a, b):
        changes = Ring(a).changes()
        await b.broadcast(b"x")
        await b.send(a.local.name, b"y")
        await wait_until(lambda: a.stats().user_messages_received == 2)
        c = await kinship.Cluster(local(seeds=[a.local.addr])).start()
        try:
            change = await asyncio.wait_for(anext(changes), WAIT)
            assert [m.name for m in change.added] == [c.local.name]
        finally:
            await c.close()


def test_the_blocking_api_sends_and_broadcasts() -> None:
    with blocking.Cluster(local()) as a, blocking.Cluster(local(seeds=[a.local.addr])) as b:
        wait_until_sync(lambda: names(a) == names(b) == {a.local.name, b.local.name})
        events = b.events(timeout=0.1)
        a.send(b.local.name, b"sync", timeout=5)
        a.broadcast(b"all", timeout=5.0)
        got = []
        deadline = time.monotonic() + WAIT
        for event in events:
            if isinstance(event, kinship.UserMessage):
                got.append((event.data, event.broadcast))
            if len(got) == 2 or time.monotonic() > deadline:
                break
        assert sorted(got) == [(b"all", True), (b"sync", False)]
        with pytest.raises(kinship.NotAMember):
            a.send("nobody", b"x")


def test_message_limits_are_config_fields() -> None:
    cfg = kinship.Config.local()
    assert (cfg.max_user_message, cfg.max_user_broadcast, cfg.user_broadcast_queue) == (
        65_536,
        256,
        256,
    )
    cfg = cfg.replace(max_user_message=1_000_000, max_user_broadcast=1_000, user_broadcast_queue=8)
    assert (cfg.max_user_message, cfg.max_user_broadcast, cfg.user_broadcast_queue) == (
        1_000_000,
        1_000,
        8,
    )
    assert "max_user_broadcast=1000" in repr(cfg)
    for fields, field in [
        ({"max_user_broadcast": 2_000}, "max_user_broadcast"),
        ({"max_user_message": 64 << 20}, "max_user_message"),
        ({"max_stream_frame": 32_768}, "max_stream_frame"),
        ({"user_broadcast_queue": 0}, "user_broadcast_queue"),
        ({"max_user_message": -1}, "max_user_message"),
    ]:
        with pytest.raises(kinship.ConfigError) as err:
            kinship.Config.local(**fields)
        assert err.value.field == field
