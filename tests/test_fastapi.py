from typing import Annotated

import pytest

fastapi = pytest.importorskip("fastapi")
httpx = pytest.importorskip("httpx")

import kinship  # noqa: E402
from conftest import local, next_matching, wait_until  # noqa: E402
from kinship.contrib.fastapi import (  # noqa: E402
    cluster_lifespan,
    cluster_router,
    get_cluster,
    get_ring,
)
from kinship.ring import Ring  # noqa: E402

Depends = fastapi.Depends


def client(app: "fastapi.FastAPI") -> "httpx.AsyncClient":
    return httpx.AsyncClient(transport=httpx.ASGITransport(app=app), base_url="http://app")


async def test_lifespan_starts_the_cluster_and_leaves_on_shutdown() -> None:
    async with kinship.Cluster(local()) as peer:
        built = []

        def config() -> kinship.Config:
            built.append(1)
            return local(seeds=[peer.local.addr], meta={"role": "api"})

        app = fastapi.FastAPI(lifespan=cluster_lifespan(config, leave_timeout=2.0))
        app.include_router(cluster_router())
        events = peer.events()
        assert built == []  # the config is built at startup, in the worker
        async with app.router.lifespan_context(app), client(app) as http:
            cluster = app.state.cluster
            assert isinstance(cluster, kinship.Cluster) and built == [1]
            await wait_until(lambda: len(cluster.members()) == 2)

            resp = await http.get("/cluster/members")
            assert resp.status_code == 200
            body = resp.json()
            assert [m["name"] for m in body] == sorted([cluster.local.name, peer.local.name])
            me = next(m for m in body if m["name"] == cluster.local.name)
            assert me == {
                "name": cluster.local.name,
                "addr": cluster.local.addr,
                "state": "ALIVE",
                "epoch": cluster.local.epoch,
                "meta": {"role": "api"},
            }
            assert cluster.local.epoch > 0

            resp = await http.get("/cluster/stats")
            assert resp.status_code == 200
            assert resp.json()["local_health"] == 0
            assert set(resp.json()) == set(kinship.Stats.__dataclass_fields__)

        # leave() ran before close(): the peer sees a departure, not a crash.
        left = await next_matching(events, kinship.MemberLeft, cluster.local.name)
        assert left.member.state is kinship.State.LEFT
        with pytest.raises(kinship.KinshipClosed):
            await cluster.update_meta(role="gone")  # and close() ran after it


async def test_get_cluster_and_get_ring() -> None:
    app = fastapi.FastAPI(lifespan=cluster_lifespan(local(meta={"role": "api"})))
    rings: list[Ring] = []

    @app.get("/owner/{key}")
    async def owner(
        key: str,
        cluster: Annotated[kinship.Cluster, Depends(get_cluster)],
        ring: Annotated[Ring, Depends(get_ring(where={"role": "api"}))],
        same: Annotated[Ring, Depends(get_ring(where={"role": "api"}))],
        workers: Annotated[Ring, Depends(get_ring(where={"role": "worker"}))],
        everyone: Annotated[Ring, Depends(get_ring())],
    ) -> dict[str, str | None]:
        rings.extend([ring, same, workers, everyone])
        assert ring.cluster is cluster
        return {
            "owner": ring.owner(key).name,
            "worker": workers.replicas(key, 1)[0].name if workers.members() else None,
        }

    async with app.router.lifespan_context(app), client(app) as http:
        name = app.state.cluster.local.name
        for key in ("user:1", "user:2"):
            resp = await http.get(f"/owner/{key}")
            assert resp.json() == {"owner": name, "worker": None}
    ring, same, workers, everyone = rings[:4]
    assert ring is same and ring is not workers and everyone is not ring
    assert rings[4:] == rings[:4]  # built once, not per request
    assert len(app.state.kinship_rings) == 3


async def test_get_ring_follows_a_new_cluster() -> None:
    app = fastapi.FastAPI(lifespan=cluster_lifespan(local))
    seen: list[Ring] = []

    @app.get("/")
    async def root(ring: Annotated[Ring, Depends(get_ring())]) -> str:
        seen.append(ring)
        return ring.owner("k").name

    for _ in range(2):
        async with app.router.lifespan_context(app), client(app) as http:
            assert (await http.get("/")).json() == app.state.cluster.local.name
    assert seen[0] is not seen[1] and seen[1].cluster is app.state.cluster


async def test_misuse_is_reported() -> None:
    with pytest.raises(TypeError):
        cluster_lifespan("127.0.0.1:7946")  # type: ignore[arg-type]
    with pytest.raises(TypeError):
        get_ring(where="role=api")  # type: ignore[arg-type]

    app = fastapi.FastAPI()  # no cluster_lifespan
    app.include_router(cluster_router(prefix="/ops"))
    async with client(app) as http:
        with pytest.raises(RuntimeError, match="cluster_lifespan"):
            await http.get("/ops/members")
        assert (await http.get("/cluster/members")).status_code == 404


@pytest.mark.parametrize("prefix", ["/cluster", "", "/ops"])
async def test_metrics_route_is_opt_in(prefix: str) -> None:
    from kinship.metrics import prometheus_text

    app = fastapi.FastAPI(lifespan=cluster_lifespan(local(name="metrics-api")))
    app.include_router(cluster_router(prefix=prefix, metrics=True))
    async with app.router.lifespan_context(app), client(app) as http:
        response = await http.get(f"{prefix}/metrics")
        assert response.status_code == 200
        assert response.headers["content-type"] == "text/plain; version=0.0.4; charset=utf-8"
        assert response.text == prometheus_text(app.state.cluster)
        assert (await http.get(f"{prefix}/members")).status_code == 200
        assert (await http.get(f"{prefix}/stats")).status_code == 200


async def test_metrics_route_is_disabled_by_default() -> None:
    app = fastapi.FastAPI()
    app.include_router(cluster_router())
    async with client(app) as http:
        assert (await http.get("/cluster/metrics")).status_code == 404
