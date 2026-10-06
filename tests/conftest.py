"""Helpers shared by the tests. Every wait is bounded, so a broken build fails, never hangs."""

from __future__ import annotations

import asyncio
import time
from collections.abc import AsyncIterator, Callable
from contextlib import AsyncExitStack, asynccontextmanager
from typing import Any

import kinship

#: Upper bound for any one condition in a test, generous for slow CI runners.
WAIT = 20.0


def local(**fields: Any) -> kinship.Config:
    """A loopback config on a port the OS picks."""
    return kinship.Config.local(bind="127.0.0.1:0", **fields)


async def wait_until(predicate: Callable[[], bool], timeout: float = WAIT) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError(f"condition not met within {timeout} s")
        await asyncio.sleep(0.05)


def wait_until_sync(predicate: Callable[[], bool], timeout: float = WAIT) -> None:
    deadline = time.monotonic() + timeout
    while not predicate():
        if time.monotonic() > deadline:
            raise AssertionError(f"condition not met within {timeout} s")
        time.sleep(0.05)


async def next_event(stream: kinship.EventStream, timeout: float = WAIT) -> kinship.Event:
    return await asyncio.wait_for(anext(stream), timeout)


async def next_matching(
    stream: kinship.EventStream,
    kind: type[Any],
    name: str | None = None,
    timeout: float = WAIT,
) -> Any:
    """Reads until an event of `kind` about `name` arrives, skipping others."""

    async def find() -> Any:
        async for event in stream:
            if isinstance(event, kind) and (name is None or event.member.name == name):
                return event
        raise AssertionError(f"stream ended before {kind.__name__}")

    return await asyncio.wait_for(find(), timeout)


async def drain(stream: kinship.EventStream, quiet: float = 0.5) -> list[kinship.Event]:
    """Every event that arrives until `quiet` seconds pass without one."""
    events = []
    while True:
        try:
            events.append(await asyncio.wait_for(anext(stream), quiet))
        except TimeoutError:
            return events


def names(cluster: kinship.Cluster | kinship.blocking.Cluster) -> set[str]:
    return {m.name for m in cluster.members()}


@asynccontextmanager
async def cluster_of(n: int, **fields: Any) -> AsyncIterator[list[kinship.Cluster]]:
    """`n` started nodes that have all seen each other, closed on exit."""
    async with AsyncExitStack() as stack:
        first = await stack.enter_async_context(kinship.Cluster(local(**fields)))
        nodes = [first]
        for _ in range(n - 1):
            cfg = local(seeds=[first.local.addr], **fields)
            nodes.append(await stack.enter_async_context(kinship.Cluster(cfg)))
        everyone = {c.local.name for c in nodes}
        await wait_until(lambda: all(names(c) == everyone for c in nodes))
        yield nodes
