"""The asyncio ``Cluster`` and the parts it shares with ``kinship.blocking``."""

from __future__ import annotations

import logging
from collections.abc import Iterable, Mapping
from datetime import timedelta
from types import TracebackType
from typing import Self

from kinship import _kinship
from kinship._errors import KinshipClosed
from kinship._types import Event, Member, Stats, _event, _member

log = logging.getLogger("kinship")

#: How long ``async with`` and ``blocking.Cluster.close()`` wait for a leave to spread.
LEAVE_TIMEOUT = 5.0


def _seconds(value: float | timedelta | None) -> float | None:
    if value is None:
        return None
    if isinstance(value, timedelta):
        return value.total_seconds()
    if isinstance(value, bool) or not isinstance(value, int | float):
        raise TypeError(f"timeout must be seconds as a float or a timedelta, not {value!r}")
    return float(value)


def _warn_leave_timeout(timeout: float) -> None:
    log.warning(
        "leave() timed out after %.1f s before the news finished spreading; "
        "this node has left anyway",
        timeout,
    )


class _Base:
    """Reads shared by the asyncio and blocking clusters. None of them waits on the network."""

    __slots__ = ("_cfg", "_node")

    def __init__(self, cfg: _kinship.Config) -> None:
        if not isinstance(cfg, _kinship.Config):
            raise TypeError(f"expected a kinship.Config, not {type(cfg).__name__}")
        self._cfg = cfg
        self._node: _kinship.Node | None = None

    @property
    def config(self) -> _kinship.Config:
        """The config this cluster was created with."""
        return self._cfg

    @property
    def _running(self) -> _kinship.Node:
        node = self._node
        if node is None:
            raise RuntimeError("the cluster is not started; use `async with` or call start()")
        return node

    def _started(self, node: _kinship.Node) -> None:
        if self._node is not None:
            raise RuntimeError("the cluster is already started")
        self._node = node

    def members(self) -> list[Member]:
        """Alive and suspect members, this node included."""
        return [_member(m) for m in self._running.members()]

    def member(self, name: str) -> Member | None:
        """One member by name, including dead and left tombstones."""
        raw = self._running.member(name)
        return None if raw is None else _member(raw)

    @property
    def local(self) -> Member:
        """This node as the cluster sees it. ``local.addr`` holds the port the OS picked."""
        return _member(self._running.local())

    def stats(self) -> Stats:
        """Protocol counters and the local health score."""
        return Stats(**self._running.stats())

    def __repr__(self) -> str:
        node = self._node
        if node is None:
            return f"<{type(self).__module__}.{type(self).__qualname__} not started>"
        try:
            local = node.local()
        except Exception:
            return f"<{type(self).__module__}.{type(self).__qualname__} closed>"
        return f"<{type(self).__module__}.{type(self).__qualname__} {local[0]} at {local[1]}>"


class EventStream:
    """An independent subscription to a cluster's events, as an async iterator.

    It starts when ``events()`` is called and buffers up to ``event_buffer`` events. A consumer
    that falls behind loses the oldest and reads ``EventsLost`` next. The iterator ends when the
    cluster closes, and raises ``KinshipClosed`` if the node stopped on an internal error.
    """

    __slots__ = ("_sub",)

    def __init__(self, sub: _kinship.EventSub) -> None:
        self._sub = sub

    def __aiter__(self) -> EventStream:
        return self

    async def __anext__(self) -> Event:
        raw = self._sub.try_next()
        if raw is None:
            raw = await self._sub.next()
            if raw is None:
                raise StopAsyncIteration
        return _event(raw)


class Keyring:
    """Runtime key rotation on this node.

    Each call acts on this node only. To rotate a cluster, run each step on every node and
    let it finish everywhere before starting the next: ``install`` the new key, ``use`` it,
    then ``remove`` the old one. Keys are 32 bytes, given as ``bytes`` or base64 text, and are
    never logged or shown.
    """

    __slots__ = ("_node",)

    def __init__(self, node: _kinship.Node) -> None:
        self._node = node

    async def install(self, key: bytes | str) -> None:
        """Lets this node decrypt with ``key``. Installing it twice does nothing."""
        await self._node.key_install(key)

    async def use(self, key: bytes | str) -> None:
        """Makes the installed ``key`` the one this node encrypts with."""
        await self._node.key_use(key)

    async def remove(self, key: bytes | str) -> None:
        """Drops ``key``. Refuses the key in use and the last key."""
        await self._node.key_remove(key)

    def key_ids(self) -> list[str]:
        """Ids of the installed keys, the one in use first, as 8 hex characters. Safe to log."""
        return self._node.key_ids()

    def __repr__(self) -> str:
        return f"Keyring(key_ids={self.key_ids()!r})"


class Cluster(_Base):
    """A cluster member on asyncio.

    ``async with Cluster(cfg)`` binds and joins ``cfg.seeds``, and on exit leaves with a 5 s
    timeout, then closes, even when the block is cancelled. Without ``async with``, call
    ``await start()`` and ``await close()`` in a ``finally``.
    """

    __slots__ = ()

    async def start(self) -> Self:
        """Binds, starts the node and joins ``cfg.seeds``, skipping its own address. A startup
        join that reaches no seed only logs a warning; the node keeps retrying in the background.
        """
        self._started(await _kinship.Node.start(self._cfg))
        return self

    async def __aenter__(self) -> Self:
        return await self.start()

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        node = self._node
        if node is None:
            return
        # Leave and close run on kinship's own thread and finish even if this await is
        # cancelled. Nothing here raises, so the block's own exception is never masked.
        try:
            if await node.shutdown(LEAVE_TIMEOUT):
                _warn_leave_timeout(LEAVE_TIMEOUT)
        except KinshipClosed:
            pass

    async def join(self, seeds: Iterable[str] | None = None) -> int:
        """Push-pulls with each seed until one answers; returns how many answered. Raises
        ``JoinError`` if none did. With no argument it uses ``cfg.seeds``."""
        node = self._running
        return await node.join(None if seeds is None else _seed_list(seeds))

    def events(self) -> EventStream:
        """A new, independent async iterator of events, starting now."""
        return EventStream(self._running.events())

    @property
    def keyring(self) -> Keyring:
        """Runtime key rotation on this node."""
        return Keyring(self._running)

    async def set_meta(self, meta: Mapping[str, str]) -> None:
        """Replaces this node's metadata and gossips it. Raises ``MetaTooLarge`` over
        ``max_meta_bytes`` encoded."""
        await self._running.set_meta(meta)

    async def update_meta(self, **changes: str | None) -> None:
        """Changes some metadata keys; a value of ``None`` deletes the key."""
        await self._running.update_meta(changes)

    async def leave(self, timeout: float | timedelta = LEAVE_TIMEOUT) -> None:
        """Tells the cluster this node is leaving and waits up to ``timeout`` for the news to
        spread. On timeout it logs a warning and returns; the node has left either way."""
        seconds = _seconds(timeout)
        assert seconds is not None
        if await self._running.leave(seconds):
            _warn_leave_timeout(seconds)

    async def close(self) -> None:
        """Stops the node and closes its sockets. Without ``leave()`` first, peers see a crash.
        Closing again does nothing."""
        await self._running.close()


def _seed_list(seeds: Iterable[str]) -> list[str]:
    if isinstance(seeds, str):
        raise TypeError("seeds must be a list of 'host:port' strings, not one string")
    return list(seeds)
