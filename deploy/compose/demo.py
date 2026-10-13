"""Compose workers and an ASGI dashboard that participates in the same cluster."""

from __future__ import annotations

import asyncio
import contextlib
import json
import logging
import os
import signal
import socket
from collections import deque
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path

from starlette.applications import Starlette
from starlette.requests import Request
from starlette.responses import HTMLResponse, StreamingResponse
from starlette.routing import Route

import kinship


def config() -> kinship.Config:
    # Binding the container's address also advertises a routable address to peers.
    address = socket.gethostbyname(socket.gethostname())
    return kinship.Config.lan(
        name=os.environ["NODE_NAME"],
        bind=f"{address}:7946",
        seeds=["node-1:7946"],
        meta={"role": os.environ["ROLE"], "zone": os.environ["ZONE"]},
        insecure_plaintext=True,
    )


def member_record(member: kinship.Member) -> dict:
    return {
        "name": member.name,
        "addr": member.addr,
        "state": member.state.name,
        "incarnation": member.incarnation,
        "meta": dict(member.meta),
    }


class View:
    """One event consumer; bounded history and coalesced snapshots for slow browsers."""

    def __init__(self, cluster: kinship.Cluster):
        self.cluster = cluster
        self.members: dict[str, dict] = {}
        self.log: deque[dict] = deque(maxlen=200)
        self.clients: set[asyncio.Queue] = set()
        self.revision = 0

    def resync(self) -> None:
        # members() excludes tombstones. Refresh known names with member() and retain
        # their last state after expiry so failures remain visible in this demo.
        for name in list(self.members):
            member = self.cluster.member(name)
            if member is not None:
                self.members[name] = member_record(member)
            elif self.members[name]["state"] in {"ALIVE", "SUSPECT"}:
                # A lost event and expired tombstone leave the outcome unknown.
                del self.members[name]
        for member in self.cluster.members():
            self.members[member.name] = member_record(member)

    def snapshot(self) -> str:
        return json.dumps(
            {
                "revision": self.revision,
                "members": sorted(self.members.values(), key=lambda m: m["name"]),
                "log": list(self.log),
            }
        )

    async def consume(self, events) -> None:
        async for event in events:
            entry = {
                "time": datetime.now(UTC).isoformat(timespec="milliseconds"),
                "kind": type(event).__name__,
            }
            if isinstance(event, kinship.EventsLost):
                self.resync()
                entry["detail"] = f"{event.count} events lost; refreshed membership"
            else:
                member = event.member
                self.members[member.name] = member_record(member)
                entry["detail"] = f"{member.name} → {member.state.name}"
                if isinstance(event, kinship.NameConflict):
                    entry["detail"] += f" (conflicting address {event.other_addr})"
            self.log.append(entry)
            self.revision += 1
            payload = self.snapshot()
            for queue in self.clients:
                if queue.full():
                    queue.get_nowait()
                queue.put_nowait(payload)


@asynccontextmanager
async def lifespan(app: Starlette):
    async with kinship.Cluster(config()) as cluster:
        events = cluster.events()  # Subscribe before reading the initial snapshot.
        view = View(cluster)
        view.resync()
        app.state.view = view
        task = asyncio.create_task(view.consume(events))
        try:
            yield
        finally:
            task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await task


async def page(request: Request) -> HTMLResponse:
    return HTMLResponse(Path(__file__).with_name("dashboard.html").read_text(encoding="utf-8"))


async def stream(request: Request) -> StreamingResponse:
    view = request.app.state.view

    async def updates():
        queue: asyncio.Queue[str] = asyncio.Queue(maxsize=1)
        view.clients.add(queue)
        try:
            yield f"data: {view.snapshot()}\n\n"
            while True:
                try:
                    payload = await asyncio.wait_for(queue.get(), timeout=15)
                except TimeoutError:
                    yield ": keepalive\n\n"
                else:
                    yield f"data: {payload}\n\n"
        finally:
            view.clients.discard(queue)

    return StreamingResponse(
        updates(),
        media_type="text/event-stream",
        headers={"Cache-Control": "no-cache", "X-Accel-Buffering": "no"},
    )


app = Starlette(routes=[Route("/", page), Route("/events", stream)], lifespan=lifespan)


async def worker() -> None:
    stopped = asyncio.Event()
    loop = asyncio.get_running_loop()
    for sig in (signal.SIGINT, signal.SIGTERM):
        loop.add_signal_handler(sig, stopped.set)
    async with kinship.Cluster(config()) as cluster:
        logging.info("%s listening at %s", cluster.local.name, cluster.local.addr)
        await stopped.wait()  # Context exit gossips LEFT before closing sockets.


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)
    asyncio.run(worker())
