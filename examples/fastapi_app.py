"""A sharded cache behind FastAPI: each key lives on the node that owns it.

Starts three FastAPI apps in this process, each running its own kinship node through
``cluster_lifespan``. A request for a key that another node owns is redirected to the owner,
whose URL travels in metadata. No server is needed: the script drives the apps
in-process through httpx's ASGI transport. Then one node leaves, and ``Ring.changes()`` and
``Ring.moved()`` show which keys moved with it.

    pip install "kinship[fastapi]" httpx
    python examples/fastapi_app.py
"""

from __future__ import annotations

import asyncio
from contextlib import AsyncExitStack
from typing import Annotated
from urllib.parse import quote

import httpx
from fastapi import Body, Depends, FastAPI, HTTPException
from fastapi.responses import RedirectResponse

import kinship
from kinship.contrib.fastapi import cluster_lifespan, cluster_router, get_ring
from kinship.ring import Ring

KEYS = [f"user:{i}" for i in range(1, 10)]
NAMES = ["node-a", "node-b", "node-c"]
CacheRing = Annotated[Ring, Depends(get_ring(where={"role": "cache"}))]
#: Every node's base URL. Members write their own metadata, so an owner's URL is checked
#: against the ones you expect before a client is sent there.
URLS = {f"http://{name}" for name in NAMES}


def make_app(name: str, seeds: list[str]) -> FastAPI:
    """One cache node. ``seeds`` is read at startup, so it can be filled in after this call."""

    def config() -> kinship.Config:
        # In production: Config.lan(keys=[...], seeds=[...], bind="0.0.0.0:7946") and a "url"
        # that clients can reach, such as "https://cache-7.example.com".
        meta = {"role": "cache", "url": f"http://{name}"}
        return kinship.Config.local(name=name, bind="127.0.0.1:0", seeds=seeds, meta=meta)

    app = FastAPI(lifespan=cluster_lifespan(config))
    app.include_router(cluster_router())  # protect it, or leave it off, in production
    data: dict[str, str] = {}

    def elsewhere(ring: Ring, key: str) -> RedirectResponse | None:
        # new_work=True: while the owner is suspect, send new writes to the node that would
        # take its keys over, instead of waiting on a node that may be dead.
        node = ring.owner(key, new_work=True)
        if node.name == name:
            return None
        url = node.meta.get("url")
        if url not in URLS:
            raise HTTPException(503, f"{node.name} has no known URL")
        return RedirectResponse(url + "/cache/" + quote(key, safe=""), status_code=307)

    @app.put("/cache/{key}", response_model=None)
    async def put(
        key: str, value: Annotated[str, Body()], ring: CacheRing
    ) -> dict[str, str] | RedirectResponse:
        if redirect := elsewhere(ring, key):
            return redirect
        data[key] = value
        return {"key": key, "node": name}

    @app.get("/cache/{key}", response_model=None)
    async def get(key: str, ring: CacheRing) -> dict[str, str] | RedirectResponse:
        if redirect := elsewhere(ring, key):
            return redirect
        if key not in data:
            raise HTTPException(404, f"{key} is not cached on {name}")
        return {"key": key, "value": data[key], "node": name}

    return app


async def main() -> None:
    seeds: list[str] = []
    apps = {name: make_app(name, seeds) for name in NAMES}
    mounts = {f"http://{name}": httpx.ASGITransport(app=app) for name, app in apps.items()}
    async with AsyncExitStack() as stack:
        http = await stack.enter_async_context(
            httpx.AsyncClient(mounts=mounts, follow_redirects=True)
        )
        first = apps["node-a"]
        await stack.enter_async_context(first.router.lifespan_context(first))
        seeds.append(first.state.cluster.local.addr)
        await stack.enter_async_context(apps["node-b"].router.lifespan_context(apps["node-b"]))
        leaving = AsyncExitStack()
        stack.push_async_callback(leaving.aclose)
        await leaving.enter_async_context(apps["node-c"].router.lifespan_context(apps["node-c"]))

        # Until every node has seen every other, they can disagree on owners.
        while any(len(app.state.cluster.members()) < len(NAMES) for app in apps.values()):
            await asyncio.sleep(0.05)
        ring = Ring(first.state.cluster, where={"role": "cache"})

        print("PUT every key through node-a:")
        for key in KEYS:
            resp = await http.put(f"http://node-a/cache/{key}", json=f"value of {key}")
            print(f"  {key:<7} stored on {resp.json()['node']}")

        print("\nGET through node-b:")
        for key in KEYS[:3]:
            resp = await http.get(f"http://node-b/cache/{key}")
            print(f"  {key:<7} {resp.json()['value']!r} from {resp.json()['node']}")

        resp = await http.get("http://node-b/cluster/members")
        print("\nGET /cluster/members:", [(m["name"], m["state"]) for m in resp.json()])

        before = ring.members()
        changes = ring.changes()
        print("\nnode-c leaves")
        await leaving.aclose()
        change = await asyncio.wait_for(anext(changes), 20)
        print(f"  node-a sees {change!r}")
        moved = ring.moved(KEYS, before, change.members)
        for key, (old, new) in moved.items():
            assert old is not None and new is not None  # both snapshots have members
            print(f"  {key:<7} moved from {old.name} to {new.name}")
        print(f"  {len(KEYS) - len(moved)} of {len(KEYS)} keys stayed where they were")

        # The new owner starts cold: a cache refills a moved key from its source.
        key = next(iter(moved))
        resp = await http.get(f"http://node-a/cache/{key}")
        print(f"\nGET {key} now: {resp.status_code}, {resp.json()['detail']}")


if __name__ == "__main__":
    asyncio.run(main())
