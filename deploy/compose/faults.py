"""Allowlisted demo faults and a recovery-first random chaos scheduler."""

from __future__ import annotations

import asyncio
import random
import time

import httpx

NAMES = tuple(f"node-{i}" for i in range(1, 6))
APP_ACTIONS = frozenset({"stall", "crash", "bounce", "leave", "drain", "undrain"})
FAULT_ACTIONS = APP_ACTIONS - {"undrain"} | {"pause", "kill", "disconnect"}
DOCKER_ACTIONS = frozenset(
    {"pause", "unpause", "kill", "restart", "start", "disconnect", "connect"}
)
RECOVERY = {
    "drain": "undrain",
    "pause": "unpause",
    "kill": "start",
    "disconnect": "connect",
    "leave": "start",
    "crash": "start",
    "bounce": "start",
}


def validate(node: str, action: str) -> None:
    if node not in NAMES or action not in APP_ACTIONS | DOCKER_ACTIONS:
        raise ValueError("Unknown demo node or fault action")


class FaultController:
    def __init__(
        self, http: httpx.AsyncClient, log, docker_enabled: bool = False, clock=time.monotonic
    ):
        self.http = http
        self.log = log
        self.docker_enabled = docker_enabled
        self.tasks: set[asyncio.Task] = set()
        self.unavailable_nodes: set[str] = set()
        self.reservations: dict[str, dict] = {}
        self.generation = 0
        self.clock = clock

    def release(self, node: str, generation: int) -> None:
        current = self.reservations.get(node)
        if current and current["generation"] == generation:
            self.reservations.pop(node)
            self.unavailable_nodes.discard(node)

    def poll_token(self, node: str) -> int | None:
        current = self.reservations.get(node)
        return current["generation"] if current else None

    def mark_reachable(self, node: str, generation: int | None) -> None:
        current = self.reservations.get(node)
        # A fresh ALIVE self-report releases the slot after a recovery from here, or once the
        # fault is old enough that the node must have come back, including after a recovery
        # outside the dashboard such as `docker compose start node-3`.
        if (
            current
            and generation == current["generation"]
            and (current.get("phase") == "recovering" or self.clock() - current["started"] >= 15)
        ):
            self.release(node, generation)

    async def _request(self, node: str, action: str) -> dict:
        url = (
            f"http://chaos:9000/fault/{node}/{action}"
            if action in DOCKER_ACTIONS
            else f"http://{node}:8000/fault/{action}"
        )
        # Docker restart can include a graceful stop; leave() itself can take 5s.
        timeout = 25 if action == "stall" or action in DOCKER_ACTIONS else 10
        response = await self.http.post(url, timeout=timeout)
        response.raise_for_status()
        return response.json() if response.content else {"ok": True}

    async def _stall(self, node: str, generation: int) -> None:
        try:
            await self._request(node, "stall")
        except (httpx.HTTPError, ValueError) as exc:
            self.log("fault_error", f"{node} stall: {exc}")
        else:
            self.log("recovery", f"{node}: stall finished")
        finally:
            self.release(node, generation)

    async def apply(self, node: str, action: str) -> dict:
        validate(node, action)
        if action in DOCKER_ACTIONS and not self.docker_enabled:
            raise ValueError("Docker chaos helper is unavailable; enable the chaos profile")
        current = self.reservations.get(node)
        starts_fault = action in FAULT_ACTIONS or (action == "restart" and current is None)
        if starts_fault:
            if self.unavailable_nodes:
                raise ValueError("Recover the existing fault first")
            self.generation += 1
            self.reservations[node] = {
                "generation": self.generation,
                "action": action,
                "started": self.clock(),
                "phase": "faulted",
            }
            self.unavailable_nodes.add(node)
        self.log("fault", f"{node}: {action} requested")
        if action == "stall":
            task = asyncio.create_task(self._stall(node, self.reservations[node]["generation"]))
            self.tasks.add(task)
            task.add_done_callback(self.tasks.discard)
            result = {"ok": True, "scheduled": True}
        else:
            result = await self._request(node, action)
            current = self.reservations.get(node)
            if current and (
                action == RECOVERY.get(current["action"])
                or (
                    action == "restart"
                    and current["action"]
                    in {"stall", "crash", "bounce", "kill", "leave", "drain", "pause"}
                )
            ):
                # A successful Docker start isn't HTTP readiness: the worker has
                # a startup delay. Invalidate old polls and hold the slot until
                # the recovery-first scheduler or a fresh self-report confirms it.
                self.generation += 1
                current["generation"] = self.generation
                current["phase"] = "recovering"
            elif current and action == "restart" and current["action"] == "restart":
                self.generation += 1
                current["generation"] = self.generation
                current["phase"] = "recovering"
        self.log("fault_applied", f"{node}: {action}")
        return {**result, "node": node, "action": action}

    async def close(self) -> None:
        tasks = tuple(self.tasks)
        for task in tasks:
            task.cancel()
        await asyncio.gather(*tasks, return_exceptions=True)


class ChaosScheduler:
    def __init__(
        self,
        controller: FaultController,
        clock=time.monotonic,
        chooser=random.choice,
        interval=20,
        recovery_delay=20,
    ):
        self.controller = controller
        self.clock = clock
        self.chooser = chooser
        self.interval = interval
        self.recovery_delay = min(20, max(1, recovery_delay))
        self.enabled = False
        self.active: dict | None = None
        self.next_at = clock() + interval
        self._lock = asyncio.Lock()

    async def set_enabled(self, enabled: bool, interval: float = 20) -> None:
        if not 5 <= interval <= 300:
            raise ValueError("Chaos interval must be between 5 and 300 seconds")
        async with self._lock:
            self.interval = interval
            self.enabled = enabled
            self.next_at = self.clock() + interval
            if not enabled and self.active:
                self.active["recover_at"] = self.clock()
                await self._recover()

    async def _recover(self) -> None:
        active = self.active
        if active is None:
            return
        recovery = RECOVERY.get(active["action"])
        try:
            if recovery:
                # Apply the recovery once; later retries only wait for the API to be ready.
                if not active.get("recovery_applied"):
                    await self.controller.apply(active["node"], recovery)
                    active["recovery_applied"] = True
                response = await self.controller.http.get(
                    f"http://{active['node']}:8000/cluster/members", timeout=1
                )
                response.raise_for_status()  # Startup must finish before the slot is reused.
                self.controller.mark_reachable(
                    active["node"], self.controller.poll_token(active["node"])
                )
            elif active["node"] in self.controller.unavailable_nodes:
                return  # Stall's background request has not completed yet.
        except (httpx.HTTPError, ValueError) as exc:
            if not active.get("recovery_applied"):
                self.controller.log("recovery_error", f"{active['node']}: {exc}; will retry")
            elif not active.get("waiting_logged"):
                # A started worker sleeps before it serves HTTP; say so once, not every retry.
                active["waiting_logged"] = True
                self.controller.log("recovery", f"{active['node']}: waiting for its API")
            active["recover_at"] = self.clock() + 2
            return
        if recovery:  # The controller logs a stall's end itself.
            self.controller.log("recovery", f"{active['node']}: {recovery}")
        self.active = None
        # Preserve the interval from fault application, while recovery still
        # prevents another fault from starting before the slot is clear.
        self.next_at = max(self.clock(), self.next_at)

    async def tick(self) -> None:
        async with self._lock:
            now = self.clock()
            if self.active:
                if now >= self.active["recover_at"]:
                    await self._recover()
                return
            if not self.enabled or now < self.next_at:
                return
            if self.controller.unavailable_nodes:
                return  # Manual faults also occupy the one-fault budget.
            candidates = [node for node in NAMES if node not in self.controller.unavailable_nodes]
            if not candidates:
                return
            actions = ["stall", "drain"]
            if self.controller.docker_enabled:
                actions += ["pause", "kill", "disconnect", "leave", "crash", "bounce"]
            node, action = self.chooser(candidates), self.chooser(actions)
            # Reserve the slot before IO: even an ambiguous transport failure may
            # have applied the fault. Recovery must succeed before another starts.
            self.active = {"node": node, "action": action, "recover_at": now + self.recovery_delay}
            self.next_at = now + self.interval
            try:
                await self.controller.apply(node, action)
            except (httpx.HTTPError, ValueError) as exc:
                self.controller.log("fault_error", f"{node}: {exc}")
