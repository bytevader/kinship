"""``log_to_python()``: route kinship's Rust logs to the ``kinship`` logger.

The protocol thread pushes each record into a bounded ring buffer and never waits for the GIL.
An asyncio task drains it into ``logging``; with no running event loop, a daemon thread does.
"""

from __future__ import annotations

import asyncio
import contextlib
import logging
import threading

from kinship import _kinship

__all__ = ["log_to_python"]

_logger = logging.getLogger("kinship")
_lock = threading.Lock()
_task: asyncio.Task[None] | None = None
_thread: threading.Thread | None = None


def _emit() -> None:
    records, dropped = _kinship.drain_logs()
    if dropped:
        _logger.warning("%d kinship log records were dropped; the drain fell behind", dropped)
    for level, target, message in records:
        if _logger.isEnabledFor(level):
            _logger.log(level, "%s", message, extra={"rust_target": target})


async def _drain_forever() -> None:
    try:
        while True:
            await _kinship.wait_logs()
            _emit()
    finally:
        _emit()
        if _task is asyncio.current_task():
            # The loop is going away; keep records flowing from a thread instead.
            _start_thread()


def _drain_thread() -> None:
    while True:
        _kinship.wait_logs_blocking(1.0)
        _emit()


def _start_thread() -> None:
    global _thread
    with _lock:
        if _thread is None or not _thread.is_alive():
            _thread = threading.Thread(target=_drain_thread, name="kinship-logs", daemon=True)
            _thread.start()


def log_to_python(level: int | None = None) -> None:
    """Send kinship's logs to the ``kinship`` logger instead of stderr.

    Records at ``level`` and above are forwarded; by default, the ``kinship`` logger's
    effective level when this is called. Call it from a coroutine to drain the logs with a task
    on the running event loop, or from sync code to drain them with a daemon thread.
    """
    global _task
    if level is None:
        level = _logger.getEffectiveLevel()
    _kinship.route_to_python(level)
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        _start_thread()
        return
    with _lock:
        old = _task
        if old is not None and not old.done() and old.get_loop() is loop:
            return
        _task = loop.create_task(_drain_forever(), name="kinship-logs")
    if old is not None and not old.done():
        # The old task belongs to another loop, which may run on another thread.
        with contextlib.suppress(RuntimeError):
            old.get_loop().call_soon_threadsafe(old.cancel)
