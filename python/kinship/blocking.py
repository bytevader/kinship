"""The same cluster API without ``async``, for Flask, Django, Celery and other sync code.

The protocol still runs on kinship's own thread, so a slow request handler cannot make the node
look dead. Calls that wait on the network block the calling thread with the GIL released and
accept ``timeout=`` (seconds, or a ``timedelta``); they raise ``TimeoutError`` when it passes,
except ``leave()``, which logs a warning and returns. Read events from a dedicated thread.

    cluster = Cluster(cfg).start()           # binds and joins cfg.seeds, then returns
    atexit.register(cluster.close)           # close() runs leave() first
    for event in cluster.events(timeout=1.0):   # yields None on each timeout tick
        ...
"""

from __future__ import annotations

import contextlib
from collections.abc import Iterable, Mapping
from datetime import timedelta
from types import TracebackType
from typing import Self

from kinship import _kinship
from kinship._cluster import LEAVE_TIMEOUT, _Base, _seconds, _seed_list, _warn_leave_timeout
from kinship._errors import KinshipClosed
from kinship._types import Event, _event

__all__ = ["Cluster", "EventStream", "Keyring"]

Timeout = float | timedelta | None


class EventStream:
    """An independent subscription to a cluster's events, as a blocking iterator.

    It starts when ``events()`` is called. With a ``timeout``, it yields ``None`` each time that
    many seconds pass with no event, so the reading thread can check for shutdown. The iterator
    ends when the cluster closes, and raises ``KinshipClosed`` if the node stopped on an error.
    """

    __slots__ = ("_sub", "_timeout")

    def __init__(self, sub: _kinship.EventSub, timeout: float | None) -> None:
        self._sub = sub
        self._timeout = timeout

    def __iter__(self) -> EventStream:
        return self

    def __next__(self) -> Event | None:
        raw = self._sub.try_next()
        if raw is None:
            raw = self._sub.next_blocking(self._timeout)
            if raw is None:
                raise StopIteration
            if raw is False:
                return None
        return _event(raw)


class Keyring:
    """Runtime key rotation on this node; see ``kinship.Cluster.keyring``."""

    __slots__ = ("_node",)

    def __init__(self, node: _kinship.Node) -> None:
        self._node = node

    def install(self, key: bytes | str, *, timeout: Timeout = None) -> None:
        """Lets this node decrypt with ``key``. Installing it twice does nothing."""
        self._node.key_install_blocking(key, _seconds(timeout))

    def use(self, key: bytes | str, *, timeout: Timeout = None) -> None:
        """Makes the installed ``key`` the one this node encrypts with."""
        self._node.key_use_blocking(key, _seconds(timeout))

    def remove(self, key: bytes | str, *, timeout: Timeout = None) -> None:
        """Drops ``key``. Refuses the key in use and the last key."""
        self._node.key_remove_blocking(key, _seconds(timeout))

    def key_ids(self) -> list[str]:
        """Ids of the installed keys, the one in use first, as 8 hex characters. Safe to log."""
        return self._node.key_ids()

    def __repr__(self) -> str:
        return f"Keyring(key_ids={self.key_ids()!r})"


class Cluster(_Base):
    """A cluster member for sync code. Safe to share across threads.

    ``with Cluster(cfg) as cluster:`` starts it and, on exit, runs ``close()``.
    """

    __slots__ = ()

    def start(self, *, timeout: Timeout = None) -> Self:
        """Binds, starts the node and joins ``cfg.seeds``, then returns this cluster. A
        startup join that reaches no seed only logs a warning."""
        self._started(_kinship.Node.start_blocking(self._cfg, _seconds(timeout)))
        return self

    def __enter__(self) -> Self:
        return self.start()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        if self._node is not None:
            with contextlib.suppress(KinshipClosed):
                self.close()

    def join(self, seeds: Iterable[str] | None = None, *, timeout: Timeout = None) -> int:
        """Push-pulls with each seed until one answers; returns how many answered. Raises
        ``JoinError`` if none did. With no argument it uses ``cfg.seeds``."""
        node = self._running
        return node.join_blocking(None if seeds is None else _seed_list(seeds), _seconds(timeout))

    def events(self, timeout: Timeout = None) -> EventStream:
        """A new, independent iterator of events, starting now. With ``timeout``, it yields
        ``None`` whenever that long passes without an event."""
        return EventStream(self._running.events(), _seconds(timeout))

    @property
    def keyring(self) -> Keyring:
        """Runtime key rotation on this node."""
        return Keyring(self._running)

    def set_meta(self, meta: Mapping[str, str], *, timeout: Timeout = None) -> None:
        """Replaces this node's metadata and gossips it."""
        self._running.set_meta_blocking(meta, _seconds(timeout))

    def update_meta(self, *, timeout: Timeout = None, **changes: str | None) -> None:
        """Changes some metadata keys; a value of ``None`` deletes the key."""
        self._running.update_meta_blocking(changes, _seconds(timeout))

    def leave(self, timeout: float | timedelta = LEAVE_TIMEOUT) -> None:
        """Tells the cluster this node is leaving and waits up to ``timeout`` for the news to
        spread. On timeout it logs a warning and returns; the node has left either way."""
        seconds = _seconds(timeout)
        assert seconds is not None
        if self._running.leave_blocking(seconds):
            _warn_leave_timeout(seconds)

    def close(self, timeout: float | timedelta = LEAVE_TIMEOUT) -> None:
        """Leaves, waiting up to ``timeout``, then stops the node and closes its sockets. Both
        finish on kinship's thread even if this thread is interrupted. Closing again does
        nothing."""
        seconds = _seconds(timeout)
        assert seconds is not None
        if self._running.shutdown_blocking(seconds):
            _warn_leave_timeout(seconds)
