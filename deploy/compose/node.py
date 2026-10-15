"""A small, volatile cache node with deliberate failure controls for the local demo."""

from __future__ import annotations

import asyncio
import json
import logging
import math
import os
import time
from base64 import b64decode, b64encode
from contextlib import asynccontextmanager, suppress
from typing import Annotated
from urllib.parse import quote
from uuid import uuid4

import httpx
from common import BOUNCE_MARKER, URLS, config
from fastapi import BackgroundTasks, Body, Depends, FastAPI, HTTPException, Query, Request
from fastapi.responses import Response

import kinship
from kinship.contrib.fastapi import cluster_lifespan, cluster_router, get_cluster, get_ring
from kinship.ring import Ring

HOP_HEADER = "x-kinship-cache-hop"
#: The fencing token of a forwarded write: the owner it was sent to, and that owner's epoch.
FENCE_HEADER = "x-kinship-fence"
MAX_HOPS = 3
MAX_KEY_BYTES = 256
MAX_VALUE_BYTES = 16_384
MAX_CACHE_KEYS = 256
cache_ring = get_ring(where={"role": "cache"})
CacheRing = Annotated[Ring, Depends(cache_ring)]
log = logging.getLogger("uvicorn.error")
MAX_USER_MESSAGE = 64 * 1024


def wall_time(value) -> float | None:
    if isinstance(value, bool) or not isinstance(value, int | float):
        return None
    try:
        value = float(value)
    except OverflowError:
        return None
    return value if math.isfinite(value) else None


class CacheMessages:
    """Demo commands only: handoff fills holes, never replaces a local write."""

    def __init__(self, data: dict[str, str], name: str):
        self.data, self.name = data, name
        self.flush_ids: set[str] = set()
        # Every value here was written after `since`: this run's start or the last clear.
        # `flushed_at` is when the latest flush this node applied was issued. Both are
        # wall-clock times, which Compose containers share with their host.
        self.since = time.time()
        self.flushed_at = 0.0
        self.stats = {"handed_off": 0, "received": 0, "last_flush_id": None, "flushes": 0}

    @staticmethod
    def encode(command: dict) -> bytes:
        return json.dumps(command, separators=(",", ":"), ensure_ascii=False).encode()

    @classmethod
    def handoff_payload(cls, entries: list, since: float = 0.0) -> bytes:
        # Bound expansion even for values full of JSON control characters.
        return cls.encode(
            {
                "type": "handoff",
                "since": since,
                "entries": [[k, b64encode(v.encode()).decode()] for k, v in entries],
            }
        )

    def clear(self) -> None:
        self.data.clear()
        self.since = time.time()

    async def handoff(self, cluster, ring: Ring, before: tuple, after: tuple) -> None:
        since = self.since
        moved = ring.moved(tuple(self.data), before, after)
        groups: dict[str, tuple[kinship.Member, list]] = {}
        for key, value in tuple(self.data.items()):
            try:
                owner = ring.owner(key)
                # Keep temporary writes here while the normal owner is SUSPECT.
                if owner.name == self.name or ring.owner(key, new_work=True).name == self.name:
                    continue
            except LookupError:
                self.data.pop(key, None)
                continue
            # Also transfer fallback values on recovery, even without a normal-owner move.
            if key in moved or owner.name != self.name:
                groups.setdefault(owner.name, (owner, []))[1].append([key, value])

        async def send(owner, entries):
            if since != self.since:
                return  # A flush or refutation cleared the entries this handoff captured.
            payload = self.handoff_payload(entries, since)
            try:
                await cluster.send(owner, payload)
            except kinship.KinshipError as exc:
                log.info("%s handoff to %s lost: %s", self.name, owner.name, exc)
            else:
                self.stats["handed_off"] += len(entries)
                log.info("%s handed off %d keys to %s", self.name, len(entries), owner.name)
            for key, value in entries:
                # send() yields: a write or ring change may have happened meanwhile.
                with suppress(LookupError):
                    if (
                        ring.owner(key).name == self.name
                        or ring.owner(key, new_work=True).name == self.name
                    ):
                        continue
                if self.data.get(key) == value:
                    self.data.pop(key, None)

        for owner, entries in groups.values():
            batch = []
            for entry in entries:
                if batch and len(self.handoff_payload([*batch, entry], since)) > MAX_USER_MESSAGE:
                    await send(owner, batch)
                    batch = []
                batch.append(entry)
            if batch:
                await send(owner, batch)

    def flush(self, flush_id: str, at: float | None = None) -> None:
        if flush_id in self.flush_ids:
            return
        self.flush_ids.add(flush_id)
        self.clear()
        # A flush issued "later" than this node's clock could refuse every handoff.
        at = self.since if at is None else min(at, self.since)
        self.flushed_at = max(self.flushed_at, at)
        self.stats["last_flush_id"] = flush_id
        self.stats["flushes"] += 1
        log.info("%s applied flush %s", self.name, flush_id)

    def receive(self, payload: bytes, ring: Ring, *, broadcast: bool) -> None:
        try:
            command = json.loads(payload)
        except (ValueError, UnicodeError, RecursionError):
            return
        if not isinstance(command, dict):
            return
        if command.get("type") == "flush" and broadcast:
            flush_id = command.get("id")
            if isinstance(flush_id, str) and 0 < len(flush_id) <= 64:
                self.flush(flush_id, wall_time(command.get("at")))
        elif command.get("type") == "handoff" and not broadcast:
            since = wall_time(command.get("since"))
            if since is None or since < self.flushed_at:
                return  # Values written before a flush must not refill the cache.
            entries = command.get("entries")
            if not isinstance(entries, list):
                return
            received = 0
            for entry in entries:
                if not isinstance(entry, list) or len(entry) != 2:
                    continue
                key, value = entry
                if not isinstance(key, str) or not isinstance(value, str):
                    continue
                try:
                    value = b64decode(value, validate=True).decode()
                    key_size, value_size = len(key.encode()), len(value.encode())
                except (ValueError, UnicodeError):
                    continue
                if not 0 < key_size <= MAX_KEY_BYTES or value_size > MAX_VALUE_BYTES:
                    continue
                with suppress(LookupError):
                    if (
                        ring.owner(key).name == self.name
                        and key not in self.data
                        and len(self.data) < MAX_CACHE_KEYS
                    ):
                        self.data[key] = value
                        received += 1
            self.stats["received"] += received
            if received:
                log.info("%s received %d warm keys", self.name, received)


async def watch_ring(
    messages: CacheMessages, cluster, ring: Ring, before: tuple, changes, refresh
) -> None:
    async for change in changes:
        refresh()
        await messages.handoff(cluster, ring, before, change.members)
        before = change.members


async def watch_messages(messages: CacheMessages, ring: Ring, events, refresh) -> None:
    async for event in events:
        if isinstance(event, kinship.UserMessage):
            refresh()
            messages.receive(event.data, ring, broadcast=event.broadcast)


def create_app(name: str | None = None) -> FastAPI:
    name = name or os.environ.get("NODE_NAME", os.environ.get("NAME", "node-1"))

    @asynccontextmanager
    async def lifespan(app: FastAPI):
        async with (
            cluster_lifespan(config)(app),
            httpx.AsyncClient(timeout=3.0, follow_redirects=False, trust_env=False) as http,
        ):
            app.state.http = http
            app.state.incarnation = app.state.cluster.local.incarnation
            ring = Ring(app.state.cluster, where={"role": "cache"})
            # Subscribe before taking the snapshot, so no membership change is lost.
            changes = ring.changes()
            events = app.state.cluster.events()
            tasks = [
                asyncio.create_task(
                    watch_ring(
                        messages, app.state.cluster, ring, ring.members(), changes, owned_values
                    )
                ),
                asyncio.create_task(watch_messages(messages, ring, events, owned_values)),
            ]
            try:
                yield
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)

    app = FastAPI(lifespan=lifespan)
    router = (
        cluster_router(metrics=True)
        if os.environ.get("KINSHIP_METRICS") == "1"
        else cluster_router()
    )
    app.include_router(router)
    data: dict[str, str] = {}
    app.state.data = data
    messages = CacheMessages(data, name)
    app.state.messages = messages

    def owned_values() -> dict[str, str]:
        # A paused or partitioned node keeps its values, but while peers suspected it or
        # declared it dead, writes went to other owners. It refuted that by raising its
        # incarnation, so drop everything rather than serve values that may be stale.
        incarnation = app.state.cluster.local.incarnation
        if incarnation != app.state.incarnation:
            messages.clear()
            app.state.incarnation = incarnation
        return data

    def check_fence(request: Request, ring: Ring, key: str) -> None:
        """Refuses a forwarded write meant for another owner, or for another run of this one:
        a peer that has not seen this node restart still holds its old epoch."""
        token = request.headers.get(FENCE_HEADER)
        if token is None:
            return
        owner, _, epoch = token.rpartition("/")
        try:
            sent = (owner, int(epoch))
        except ValueError:
            raise HTTPException(400, "invalid fencing token") from None
        try:
            here = ring.fence(key, new_work=True)
        except LookupError:
            raise HTTPException(503, "no eligible cache owner") from None
        if sent != here:
            raise HTTPException(
                409, f"fenced: the write was for {owner} at epoch {epoch}, this node sees {here}"
            )

    async def route(request: Request, ring: Ring, key: str, *, new_work: bool):
        if not key or len(key.encode()) > MAX_KEY_BYTES:
            raise HTTPException(413, "key must be 1..256 bytes")
        try:
            hops = int(request.headers.get(HOP_HEADER, "0"))
            if hops < 0:
                raise ValueError
        except ValueError:
            raise HTTPException(400, "invalid forwarding hop count") from None
        if hops >= MAX_HOPS:
            raise HTTPException(503, "owners disagree; forwarding hop limit reached")
        try:
            owner = ring.owner(key, new_work=new_work)
        except LookupError:
            raise HTTPException(503, "no eligible cache owner") from None
        if owner.name == name:
            if request.method == "PUT":
                check_fence(request, ring, key)
            return None
        # Metadata belongs to the peer. Never forward to an arbitrary URL it supplied.
        expected = URLS.get(owner.name)
        if expected is None or owner.meta.get("url") != expected:
            raise HTTPException(503, "owner has no valid demo URL")
        headers = {HOP_HEADER: str(hops + 1), "content-type": "application/json"}
        if request.method == "PUT":
            # The owner applies the write only if it is that owner in that run.
            fenced_owner, epoch = ring.fence(key, new_work=True)
            headers[FENCE_HEADER] = f"{fenced_owner}/{epoch}"
        try:
            response = await app.state.http.request(
                request.method,
                expected + "/kv/" + quote(key, safe=""),
                content=await request.body() if request.method == "PUT" else None,
                headers=headers,
            )
        except httpx.HTTPError:
            raise HTTPException(503, f"cache owner {owner.name} is unavailable") from None
        return Response(
            response.content,
            status_code=response.status_code,
            media_type=response.headers.get("content-type", "application/json"),
        )

    @app.put("/kv/{key:path}", response_model=None)
    async def put(key: str, value: Annotated[str, Body()], request: Request, ring: CacheRing):
        if len(value.encode()) > MAX_VALUE_BYTES:
            raise HTTPException(413, "value exceeds 16 KiB")
        forwarded = await route(request, ring, key, new_work=True)
        if forwarded is not None:
            return forwarded
        values = owned_values()
        if key not in values and len(values) >= MAX_CACHE_KEYS:
            # Bound memory while keeping the demo's 64 generated keys well within capacity.
            values.pop(next(iter(values)))
        values[key] = value
        return {"key": key, "node": name}

    @app.get("/kv/{key:path}", response_model=None)
    async def get(key: str, request: Request, ring: CacheRing):
        forwarded = await route(request, ring, key, new_work=False)
        if forwarded is not None:
            return forwarded
        values = owned_values()
        if key not in values:
            raise HTTPException(404, f"{key} is not cached on {name}")
        return {"key": key, "value": values[key], "node": name}

    @app.post("/fault/stall")
    async def stall(seconds: Annotated[float, Query(ge=1, le=60)] = 20):
        # Blocks the ASGI event loop; kinship's Rust protocol thread remains responsive.
        time.sleep(seconds)
        return {"node": name, "stalled_seconds": seconds}

    @app.post("/fault/crash")
    async def crash(background: BackgroundTasks):
        background.add_task(os._exit, 1)
        return {"node": name, "action": "crash"}

    @app.post("/fault/bounce")
    async def bounce(background: BackgroundTasks):
        # Exit without leaving, and have the next run skip the startup delay: it comes back
        # with a later epoch while peers still hold the old run, and replaces it at once.
        BOUNCE_MARKER.touch()
        background.add_task(os._exit, 1)
        return {"node": name, "action": "bounce"}

    @app.post("/fault/leave")
    async def leave(request: Request, background: BackgroundTasks):
        cluster = await get_cluster(request)
        await cluster.leave()
        data.clear()
        background.add_task(os._exit, 0)
        return {"node": name, "action": "leave"}

    @app.post("/fault/drain")
    async def drain(request: Request, ring: CacheRing):
        cluster = await get_cluster(request)
        owned_values()
        before = ring.members()
        await cluster.update_meta(role="draining")
        # The local node emits no event about itself; hand off explicitly.
        await messages.handoff(cluster, ring, before, ring.members())
        return {"node": name, "role": "draining"}

    @app.post("/fault/undrain")
    async def undrain(request: Request):
        cluster = await get_cluster(request)
        await cluster.update_meta(role="cache")
        return {"node": name, "role": "cache"}

    @app.post("/fault/flush")
    async def flush(request: Request):
        cluster = await get_cluster(request)
        flush_id = uuid4().hex
        at = time.time()
        await cluster.broadcast(messages.encode({"type": "flush", "id": flush_id, "at": at}))
        # kinship never delivers a node's own broadcast back to it.
        messages.flush(flush_id, at)
        return {"node": name, "flush_id": flush_id}

    @app.get("/cache/stats")
    async def cache_stats():
        return messages.stats

    return app


app = create_app()
