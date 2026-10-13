"""FastAPI integration: a cluster node that lives as long as the app, and dependencies for it.

Install it with ``pip install "kinship[fastapi]"``.

    app = FastAPI(lifespan=cluster_lifespan(lambda: Config.lan(keys=[key], seeds=seeds)))

    @app.get("/cache/{key}")
    async def get(key: str, ring: Annotated[Ring, Depends(get_ring(where={"role": "cache"}))]):
        node = ring.owner(key)
        ...

Each server worker process runs its own node: with several workers, give each its own gossip
port (``bind="0.0.0.0:0"``) and its own name, by passing a function that builds the config in
the worker rather than one config built before the fork.
"""

import dataclasses
from collections.abc import AsyncIterator, Awaitable, Callable, Hashable, Mapping
from contextlib import AbstractAsyncContextManager, asynccontextmanager, suppress
from datetime import timedelta
from typing import Annotated

try:
    from fastapi import APIRouter, Depends, FastAPI
    from fastapi.requests import HTTPConnection
    from pydantic import BaseModel
except ImportError as e:  # pragma: no cover
    raise ImportError(
        'kinship.contrib.fastapi needs FastAPI; install it with pip install "kinship[fastapi]"'
    ) from e

from kinship._cluster import LEAVE_TIMEOUT, Cluster
from kinship._errors import KinshipClosed
from kinship._kinship import Config
from kinship.ring import Ring, Where

__all__ = ["cluster_lifespan", "cluster_router", "get_cluster", "get_ring"]


def cluster_lifespan(
    config: Config | Callable[[], Config],
    *,
    leave_timeout: float | timedelta = LEAVE_TIMEOUT,
) -> Callable[[FastAPI], AbstractAsyncContextManager[None]]:
    """A lifespan for ``FastAPI(lifespan=...)`` that runs a ``kinship.Cluster`` with the app.

    On startup it builds the config, calling ``config`` if it is a function, starts the
    cluster and stores it on ``app.state.cluster``. On shutdown it calls ``leave()``, waiting
    up to ``leave_timeout`` for the news to spread, then ``close()``.

    Each server worker process runs this lifespan and so its own node. With several workers,
    each needs its own gossip port and name: pass a function, so the config is built in the
    worker, with ``bind="0.0.0.0:0"`` and either no ``name`` (the default adds a random suffix
    to the host name) or one that includes the process id.

    To run it next to a lifespan of your own, enter it from yours:
    ``async with cluster_lifespan(cfg)(app): yield``.
    """
    if not isinstance(config, Config) and not callable(config):
        raise TypeError(f"expected a kinship.Config or a function, not {type(config).__name__}")

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        cfg = config if isinstance(config, Config) else config()
        cluster = await Cluster(cfg).start()
        app.state.cluster = cluster
        try:
            yield
        finally:
            try:
                with suppress(KinshipClosed):
                    await cluster.leave(leave_timeout)
            finally:
                with suppress(KinshipClosed):
                    await cluster.close()

    return lifespan


async def get_cluster(conn: HTTPConnection) -> Cluster:
    """A dependency that returns the app's cluster, ``app.state.cluster``. Works in HTTP and
    WebSocket routes."""
    try:
        cluster: Cluster = conn.app.state.cluster
    except AttributeError:
        raise RuntimeError(
            "app.state.cluster is not set; create the app with "
            "FastAPI(lifespan=cluster_lifespan(...))"
        ) from None
    return cluster


def _where_key(where: Where) -> Hashable:
    if where is None:
        return None
    if isinstance(where, Mapping):
        return ("meta", frozenset(where.items()))
    if callable(where):
        return ("predicate", where)
    raise TypeError(f"where must be a dict or a callable, not {type(where).__name__}")


def get_ring(where: Where = None) -> Callable[[HTTPConnection], Awaitable[Ring[Cluster]]]:
    """A dependency that returns a ``kinship.ring.Ring`` over the app's cluster, with only the
    members that match ``where``.

    The ring is built once per ``where`` and app, on first use, and shared by every request
    after that; calling ``get_ring`` again with an equal dict gives the same ring.
    """
    key = _where_key(where)

    async def ring(conn: HTTPConnection) -> Ring[Cluster]:
        cluster = await get_cluster(conn)
        state = conn.app.state
        rings: dict[Hashable, Ring[Cluster]] | None = getattr(state, "kinship_rings", None)
        if rings is None:
            rings = state.kinship_rings = {}
        found = rings.get(key)
        if found is None or found.cluster is not cluster:
            found = rings[key] = Ring(cluster, where=where)
        return found

    return ring


class MemberInfo(BaseModel):
    """One member as ``GET /members`` lists it."""

    name: str
    addr: str
    state: str
    meta: dict[str, str]


def cluster_router(prefix: str = "/cluster") -> APIRouter:
    """A router with ``GET {prefix}/members``, the alive and suspect members with their name,
    address, state and metadata, and ``GET {prefix}/stats``, this node's protocol counters.

    These expose member addresses and metadata. In production, protect them, for example
    with ``app.include_router(cluster_router(), dependencies=[Depends(admin_only)])``, or
    leave them off.
    """
    router = APIRouter(prefix=prefix, tags=["cluster"])

    @router.get("/members")
    async def members(cluster: Annotated[Cluster, Depends(get_cluster)]) -> list[MemberInfo]:
        return [
            MemberInfo(name=m.name, addr=m.addr, state=m.state.name, meta=dict(m.meta))
            for m in sorted(cluster.members(), key=lambda m: m.name)
        ]

    @router.get("/stats")
    async def stats(cluster: Annotated[Cluster, Depends(get_cluster)]) -> dict[str, int]:
        return dataclasses.asdict(cluster.stats())

    return router
