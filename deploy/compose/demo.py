"""Membership, cache ownership and fault controls, streamed to a plain JS page."""

from __future__ import annotations

import asyncio
import contextlib
import json
import random
import time
from collections import deque
from contextlib import asynccontextmanager
from datetime import UTC, datetime
from pathlib import Path
from urllib.parse import urlsplit

import httpx
from common import KEYS, NAMES, URLS, config
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, StreamingResponse
from faults import FAULT_ACTIONS, ChaosScheduler, FaultController
from pydantic import BaseModel, Field
from starlette.middleware.trustedhost import TrustedHostMiddleware

import kinship
from kinship.contrib.fastapi import cluster_lifespan, cluster_router
from kinship.ring import Ring

LIVE_STATES = {"ALIVE", "SUSPECT"}


def member_record(member: kinship.Member) -> dict:
    return {
        "name": member.name,
        "addr": member.addr,
        "state": member.state.name,
        "incarnation": member.incarnation,
        "epoch": member.epoch,
        "meta": dict(member.meta),
    }


class View:
    """One bounded event history, with coalesced snapshots for slow browsers."""

    def __init__(self, cluster, ring=None):
        self.cluster = cluster
        self.ring = ring if ring is not None else Ring(cluster, where={"role": "cache"})
        self.members: dict[str, dict] = {}
        self.log: deque[dict] = deque(maxlen=200)
        self.clients: set[asyncio.Queue] = set()
        self.revision = 0
        self.counts = {"successes": 0, "misses": 0, "errors": 0, "unreachable": 0, "fenced": 0}
        # The run of each node last seen, to tell a restart from a node coming back.
        self.epochs: dict[str, int] = {}
        self.member_counts: dict[str, dict] = {}
        self.moved_at: dict[str, int] = {}
        self.load_enabled = False
        self.primed = False
        self.controller = None
        self.scheduler = None
        self.control_lock = asyncio.Lock()

    def resync(self) -> None:
        for member in self.cluster.members():
            self.epochs.setdefault(member.name, member.epoch)
        for name in list(self.members):
            member = self.cluster.member(name)
            if member is not None:
                self.members[name] = member_record(member)
            elif self.members[name]["state"] in {"ALIVE", "SUSPECT"}:
                del self.members[name]
        for member in self.cluster.members():
            self.members[member.name] = member_record(member)

    def keys(self) -> list[dict]:
        result = []
        for key in KEYS:
            owner = write_owner = None
            with contextlib.suppress(LookupError):
                owner = self.ring.owner(key)
            with contextlib.suppress(LookupError):
                write_owner = self.ring.owner(key, new_work=True)
            result.append(
                {
                    "key": key,
                    "owner": owner.name if owner else None,
                    "state": owner.state.name if owner else None,
                    "write_owner": write_owner.name if write_owner else None,
                    "moved_at": self.moved_at.get(key, 0),
                }
            )
        return result

    def snapshot(self) -> str:
        active = self.scheduler.active if self.scheduler else None
        if active:
            active = {**active, "automatic": True}
        elif self.controller and self.controller.reservations:
            name, reservation = next(iter(self.controller.reservations.items()))
            active = {
                "node": name,
                "action": reservation["action"],
                # Docker treats a kill as a manual stop, so on-failure doesn't restart it.
                "automatic": reservation["action"] in {"stall", "crash", "bounce"}
                or reservation.get("phase") == "recovering",
            }
        return json.dumps(
            {
                "revision": self.revision,
                "members": sorted(self.members.values(), key=lambda m: m["name"]),
                "log": list(self.log),
                "keys": self.keys(),
                "counts": self.counts,
                "member_counts": self.member_counts,
                "docker_enabled": bool(self.controller and self.controller.docker_enabled),
                "load_enabled": self.load_enabled,
                "primed": self.primed,
                "chaos_enabled": bool(self.scheduler and self.scheduler.enabled),
                "active_fault": active,
            }
        )

    def publish(self) -> None:
        self.revision += 1
        payload = self.snapshot()
        for queue in self.clients:
            if queue.full():
                queue.get_nowait()
            queue.put_nowait(payload)

    def add_log(self, kind: str, detail: str, style: str = "fault") -> None:
        self.log.append(
            {
                "time": datetime.now(UTC).isoformat(timespec="milliseconds"),
                "kind": kind,
                "detail": detail,
                "style": style,
            }
        )
        self.publish()

    async def consume(self, events) -> None:
        async for event in events:
            if isinstance(event, kinship.EventsLost):
                self.resync()
                detail = f"{event.count} events lost; refreshed membership"
            else:
                member = event.member
                self.members[member.name] = member_record(member)
                detail = f"{member.name} → {member.state.name}"
                if isinstance(event, kinship.NameConflict):
                    detail += f" (conflicting address {event.other_addr})"
            self.add_log(type(event).__name__, detail, "membership")
            if isinstance(event, kinship.MemberJoined):
                self.new_run(event.member)

    def new_run(self, member: kinship.Member) -> None:
        """Logs a node that joined in a run it was not in before: it restarted."""
        before = self.epochs.get(member.name)
        self.epochs[member.name] = member.epoch
        if before and member.epoch and member.epoch != before:
            started = datetime.fromtimestamp(member.epoch / 1000, UTC).strftime("%H:%M:%S")
            self.add_log(
                "Restart",
                f"{member.name} is a new run, started {started} UTC (epoch {before} → "
                f"{member.epoch}); its old run is gone, whatever its incarnation was",
                "membership",
            )

    async def ring_changes(self, changes, before) -> None:
        async for change in changes:
            moved = self.ring.moved(KEYS, before, change.members)
            now = int(time.time() * 1000)
            for key in moved:
                self.moved_at[key] = now
            before = change.members
            self.add_log("RingChanged", f"{len(moved)} / {len(KEYS)} keys moved", "ring")


async def poll_members(view: View, http: httpx.AsyncClient) -> None:
    async def count(name):
        generation = view.controller.poll_token(name)
        try:
            response = await http.get(URLS[name] + "/cluster/members")
            response.raise_for_status()
            members = response.json()
            if not isinstance(members, list):
                raise ValueError("expected member list")
        except (httpx.HTTPError, ValueError):
            previous = view.member_counts.get(name, {})
            return name, {"count": previous.get("count"), "reachable": False}
        local = next((m for m in members if m["name"] == name), None)
        if local and local["state"] == "ALIVE" and local["meta"].get("role") == "cache":
            # Automatic restart/rejoin has recovered a manually crashed node.
            view.controller.mark_reachable(name, generation)
        return name, {"count": len(members), "reachable": True}

    while True:
        view.member_counts.update(await asyncio.gather(*(count(name) for name in NAMES)))
        view.member_counts["dashboard"] = {
            "count": len(view.cluster.members()),
            "reachable": True,
        }
        try:
            response = await http.get("http://chaos:9000/health")
            view.controller.docker_enabled = response.status_code == 200
        except httpx.HTTPError:
            view.controller.docker_enabled = False
        view.resync()
        view.publish()
        await asyncio.sleep(2)


def entry_node(view: View) -> str:
    """Pick a node to send a request to, skipping those this dashboard already sees down."""
    live = [name for name in NAMES if view.members.get(name, {}).get("state") in LIVE_STATES]
    return random.choice(live or NAMES)


async def load_generator(view: View, http: httpx.AsyncClient) -> None:
    async def operation(method, key):
        url = URLS[entry_node(view)] + "/kv/" + key
        try:
            response = await http.request(
                method, url, **({"json": f"value-{time.time_ns()}"} if method == "PUT" else {})
            )
            if response.status_code == 404:
                view.counts["misses"] += 1
            elif response.status_code == 409:
                # A forwarded write carried the fencing token of an owner's earlier run.
                view.counts["fenced"] += 1
            elif 200 <= response.status_code < 300:
                view.counts["successes"] += 1
            else:
                # The node answered, but the key's owner did not (or no owner was eligible).
                view.counts["errors"] += 1
        except httpx.HTTPError:
            # The node itself did not answer: stalled, paused, cut off, or not yet known down.
            view.counts["unreachable"] += 1
        view.publish()

    while True:
        if not view.load_enabled:
            await asyncio.sleep(0.2)
            continue
        if not view.primed:
            # Wait for the initial ring before warming it; do this only once so
            # subsequent crashes leave observable cold keys instead of rewarming.
            if len(view.ring.members()) < len(NAMES):
                await asyncio.sleep(0.2)
                continue
            for key in KEYS:
                if not view.load_enabled:
                    break
                await operation("PUT", key)
            else:
                view.primed = True
                view.add_log("Load", "Initial 64-key warmup complete")
            continue
        await operation("GET", random.choice(KEYS))
        if random.random() < 0.25 and view.load_enabled:
            await operation("PUT", random.choice(KEYS))
        await asyncio.sleep(0.2)


async def chaos_loop(scheduler: ChaosScheduler) -> None:
    while True:
        await scheduler.tick()
        await asyncio.sleep(0.25)


@asynccontextmanager
async def lifespan(app: FastAPI):
    async with cluster_lifespan(config)(app):
        cluster = app.state.cluster
        ring = Ring(cluster, where={"role": "cache"})
        events, changes = cluster.events(), ring.changes()
        before = ring.members()
        async with httpx.AsyncClient(timeout=2, trust_env=False) as http:
            view = View(cluster, ring)
            view.controller = FaultController(http, view.add_log)
            view.scheduler = ChaosScheduler(view.controller)
            view.resync()
            app.state.view = view
            tasks = [
                asyncio.create_task(view.consume(events)),
                asyncio.create_task(view.ring_changes(changes, before)),
                asyncio.create_task(poll_members(view, http)),
                asyncio.create_task(load_generator(view, http)),
                asyncio.create_task(chaos_loop(view.scheduler)),
            ]
            try:
                yield
            finally:
                for task in tasks:
                    task.cancel()
                await asyncio.gather(*tasks, return_exceptions=True)
                with contextlib.suppress(Exception):
                    await view.scheduler.set_enabled(False)
                await view.controller.close()


app = FastAPI(lifespan=lifespan)
# A DNS-rebinding page reaches 127.0.0.1:8080 under its own host name; refuse it.
app.add_middleware(TrustedHostMiddleware, allowed_hosts=["localhost", "127.0.0.1"])
app.include_router(cluster_router())


@app.middleware("http")
async def same_origin_controls(request: Request, call_next):
    # The controls need no body or secret, so any page open in the browser could POST a
    # plain form to them. Browsers send Origin on every POST; refuse other sites.
    origin = request.headers.get("origin")
    if (
        request.method != "GET"
        and origin is not None
        and urlsplit(origin).netloc != request.headers.get("host")
    ):
        return JSONResponse({"detail": "cross-origin request refused"}, status_code=403)
    return await call_next(request)


@app.get("/", response_class=HTMLResponse)
async def page():
    return Path(__file__).with_name("dashboard.html").read_text(encoding="utf-8")


@app.get("/events")
async def stream(request: Request):
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


class Toggle(BaseModel):
    enabled: bool
    interval: float = Field(default=20, ge=5, le=300)


@app.post("/control/load")
async def load_control(toggle: Toggle, request: Request):
    view = request.app.state.view
    view.load_enabled = toggle.enabled
    view.add_log("Load", "Started" if toggle.enabled else "Stopped")
    return {"enabled": view.load_enabled}


@app.post("/control/chaos")
async def chaos_control(toggle: Toggle, request: Request):
    view = request.app.state.view
    async with view.control_lock:
        await view.scheduler.set_enabled(toggle.enabled, interval=toggle.interval)
    view.add_log("Chaos", f"{'Started' if toggle.enabled else 'Stopped'} ({toggle.interval:g}s)")
    view.publish()
    return {"enabled": view.scheduler.enabled}


@app.post("/control/fault/{node}/{action}")
async def fault_control(node: str, action: str, request: Request):
    async with request.app.state.view.control_lock:
        return await apply_fault(node, action, request)


async def apply_fault(node: str, action: str, request: Request):
    view = request.app.state.view
    starts_fault = action in FAULT_ACTIONS or (
        action == "restart" and node not in view.controller.reservations
    )
    if starts_fault and (view.scheduler.enabled or view.scheduler.active):
        raise HTTPException(409, "Disable random chaos and wait for recovery before manual faults")
    if starts_fault and view.controller.unavailable_nodes:
        raise HTTPException(409, "Recover the current fault before applying another")
    try:
        result = await view.controller.apply(node, action)
    except ValueError as error:
        raise HTTPException(400, str(error)) from error
    except (httpx.HTTPError, RuntimeError) as error:
        view.add_log("FaultError", f"{node}: {action} failed ({type(error).__name__})")
        raise HTTPException(503, "Fault could not be applied; see event log") from error
    view.publish()
    return result
