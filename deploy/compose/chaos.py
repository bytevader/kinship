"""Internal opt-in Docker socket helper, scoped to this demo's cache nodes."""

import json
from contextlib import asynccontextmanager

import httpx
from fastapi import FastAPI, HTTPException
from faults import DOCKER_ACTIONS, validate

PROJECT = "kinship-demo"
NETWORK = "kinship-demo_membership"


class DockerHelper:
    def __init__(self, http: httpx.AsyncClient):
        self.http = http

    async def _get(self, path, **kwargs):
        response = await self.http.get(path, **kwargs)
        response.raise_for_status()
        return response.json()

    async def _post(self, path, **kwargs):
        response = await self.http.post(path, **kwargs)
        response.raise_for_status()

    async def apply(self, node: str, action: str) -> dict:
        validate(node, action)
        if action not in DOCKER_ACTIONS:
            raise ValueError("Only Docker fault actions are supported here")
        expected = {"com.docker.compose.project": PROJECT, "com.docker.compose.service": node}
        containers = await self._get(
            "/containers/json",
            params={
                "all": "true",
                "filters": json.dumps({"label": [f"{k}={v}" for k, v in expected.items()]}),
            },
        )
        if len(containers) != 1 or any(
            containers[0].get("Labels", {}).get(k) != v for k, v in expected.items()
        ):
            raise ValueError("Expected exactly one verified demo container")
        container_id = containers[0]["Id"]
        if not container_id.isalnum():
            raise ValueError("Invalid container ID")
        container = await self._get(f"/containers/{container_id}/json")
        if container.get("Id") != container_id or any(
            container.get("Config", {}).get("Labels", {}).get(k) != v for k, v in expected.items()
        ):
            raise ValueError("Container Compose labels do not match")
        state = container.get("State", {})
        if action in {"disconnect", "connect"}:
            network = await self._get(f"/networks/{NETWORK}")
            labels = network.get("Labels", {})
            if (
                network.get("Name") != NETWORK
                or labels.get("com.docker.compose.project") != PROJECT
                or labels.get("com.docker.compose.network") != "membership"
            ):
                raise ValueError("Membership network Compose labels do not match")
            network_id = network["Id"]
            if not network_id.isalnum():
                raise ValueError("Invalid network ID")
            attached = NETWORK in container.get("NetworkSettings", {}).get("Networks", {})
            if action == "connect" and not attached:
                await self._post(
                    f"/networks/{network_id}/connect",
                    json={"Container": container_id, "EndpointConfig": {"Aliases": [node]}},
                )
            elif action == "disconnect" and attached:
                await self._post(
                    f"/networks/{network_id}/disconnect",
                    json={"Container": container_id, "Force": True},
                )
        else:
            if action in {"start", "restart"} and state.get("Paused"):
                await self._post(f"/containers/{container_id}/unpause")
            if (action == "pause" and state.get("Paused")) or (
                action == "unpause" and not state.get("Paused")
            ):
                return {"ok": True, "node": node, "action": action}
            if action != "start" or not state.get("Running"):
                kwargs = {"params": {"signal": "SIGKILL"}} if action == "kill" else {}
                await self._post(f"/containers/{container_id}/{action}", **kwargs)
        return {"ok": True, "node": node, "action": action}


@asynccontextmanager
async def lifespan(app):
    async with httpx.AsyncClient(
        base_url="http://docker",
        transport=httpx.AsyncHTTPTransport(uds="/var/run/docker.sock"),
        timeout=20,
    ) as http:
        app.state.helper = DockerHelper(http)
        yield


app = FastAPI(lifespan=lifespan)


@app.get("/health")
async def health():
    try:
        response = await app.state.helper.http.get("/_ping")
        response.raise_for_status()
    except httpx.HTTPError as exc:
        raise HTTPException(503, "Docker socket unavailable") from exc
    return {"ok": True}


@app.post("/fault/{node}/{action}")
async def fault(node: str, action: str):
    try:
        return await app.state.helper.apply(node, action)
    except ValueError as exc:
        raise HTTPException(400, str(exc)) from exc
    except httpx.HTTPError as exc:
        raise HTTPException(502, "Docker API action failed") from exc
