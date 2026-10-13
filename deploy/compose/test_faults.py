"""Fault recovery and Docker API scoping tests; no daemon required."""

import asyncio
import json
import unittest

import httpx
from chaos import DockerHelper
from faults import ChaosScheduler, FaultController, validate


class ValidationTests(unittest.TestCase):
    def test_allowlist(self):
        for name in ("node-0", "dashboard", "node-1/kill", "node-1;id", "node-10"):
            with self.assertRaises(ValueError):
                validate(name, "pause")
        for action in ("exec", "pause?x", "kill/SIGTERM", ""):
            with self.assertRaises(ValueError):
                validate("node-1", action)
        validate("node-5", "drain")


class SchedulerTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.now = 0
        self.calls = []
        self.fail = False
        self.fail_readiness = False

        def handler(request):
            if request.method == "GET":
                return httpx.Response(503 if self.fail or self.fail_readiness else 200, json=[])
            self.calls.append(request.url.path)
            return httpx.Response(503 if self.fail else 200, json={"ok": True})

        self.http = httpx.AsyncClient(transport=httpx.MockTransport(handler))
        self.controller = FaultController(self.http, lambda *_: None)
        self.scheduler = ChaosScheduler(
            self.controller,
            clock=lambda: self.now,
            chooser=lambda items: next((x for x in items if x == "drain"), items[0]),
            recovery_delay=10,
        )

    async def asyncTearDown(self):
        await self.controller.close()
        await self.http.aclose()

    async def test_timer_and_no_overlap(self):
        await self.scheduler.set_enabled(True)
        await self.scheduler.tick()
        self.now = 20
        await self.scheduler.tick()
        self.assertEqual(self.scheduler.active["action"], "drain")
        self.now = 25
        await self.scheduler.tick()
        self.assertEqual(len(self.calls), 1)
        self.now = 30
        await self.scheduler.tick()
        self.assertIsNone(self.scheduler.active)
        self.assertEqual(self.calls, ["/fault/drain", "/fault/undrain"])
        self.assertEqual(self.scheduler.next_at, 40)

    async def test_disable_retries_failed_recovery(self):
        await self.scheduler.set_enabled(True)
        self.now = 20
        await self.scheduler.tick()
        self.fail = True
        await self.scheduler.set_enabled(False)
        self.assertIsNotNone(self.scheduler.active)
        self.fail = False
        self.now += 2
        await self.scheduler.tick()
        self.assertIsNone(self.scheduler.active)
        self.assertFalse(self.scheduler.enabled)

    async def test_manual_fault_blocks_random_fault(self):
        await self.controller.apply("node-1", "drain")
        await self.scheduler.set_enabled(True)
        self.now = 20
        await self.scheduler.tick()
        self.assertIsNone(self.scheduler.active)
        self.assertEqual(len(self.calls), 1)
        await self.controller.apply("node-1", "undrain")
        self.controller.mark_reachable("node-1", self.controller.poll_token("node-1"))
        await self.scheduler.tick()
        self.assertEqual(self.scheduler.active["node"], "node-1")

    async def test_recovered_container_must_be_http_ready_before_next_fault(self):
        await self.scheduler.set_enabled(True)
        self.now = 20
        await self.scheduler.tick()
        self.fail_readiness = True
        self.now = 30
        await self.scheduler.tick()
        self.assertIsNotNone(self.scheduler.active)
        self.now = 31
        await self.scheduler.tick()
        self.assertEqual(self.calls, ["/fault/drain", "/fault/undrain"])
        self.fail_readiness = False
        self.now = 32
        await self.scheduler.tick()
        self.assertIsNone(self.scheduler.active)


class DockerTests(unittest.IsolatedAsyncioTestCase):
    async def test_inspect_and_network_labels_and_kill_signal(self):
        labels = {
            "com.docker.compose.project": "kinship-demo",
            "com.docker.compose.service": "node-1",
        }
        network_labels = {
            "com.docker.compose.project": "kinship-demo",
            "com.docker.compose.network": "membership",
        }
        calls = []
        inspected_labels = dict(labels)

        def handler(request):
            calls.append(request)
            if request.url.path == "/containers/json":
                filters = json.loads(request.url.params["filters"])
                self.assertIn("com.docker.compose.project=kinship-demo", filters["label"])
                self.assertIn("com.docker.compose.service=node-1", filters["label"])
                self.assertEqual(request.url.params["all"], "true")
                return httpx.Response(200, json=[{"Id": "abc", "Labels": labels}])
            if request.url.path == "/containers/abc/json":
                return httpx.Response(
                    200,
                    json={"Id": "abc", "Config": {"Labels": inspected_labels}},
                )
            if request.url.path == "/networks/kinship-demo_membership":
                return httpx.Response(
                    200,
                    json={"Id": "net", "Name": "kinship-demo_membership", "Labels": network_labels},
                )
            return httpx.Response(204)

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://docker"
        ) as http:
            helper = DockerHelper(http)
            await helper.apply("node-1", "kill")
            self.assertEqual(calls[-1].url.params["signal"], "SIGKILL")
            inspected_labels["com.docker.compose.project"] = "other"
            with self.assertRaises(ValueError):
                await helper.apply("node-1", "kill")
            inspected_labels.update(labels)
            network_labels["com.docker.compose.network"] = "control"
            with self.assertRaises(ValueError):
                await helper.apply("node-1", "connect")
            self.assertFalse(any(r.url.path == "/networks/net/connect" for r in calls))

    async def test_verified_connect_alias_and_paused_restart(self):
        calls = []
        labels = {
            "com.docker.compose.project": "kinship-demo",
            "com.docker.compose.service": "node-1",
        }
        network_labels = {
            "com.docker.compose.project": "kinship-demo",
            "com.docker.compose.network": "membership",
        }

        def handler(request):
            calls.append(request)
            path = request.url.path
            if path == "/containers/json":
                return httpx.Response(200, json=[{"Id": "abc", "Labels": labels}])
            if path == "/containers/abc/json":
                return httpx.Response(
                    200,
                    json={
                        "Id": "abc",
                        "Config": {"Labels": labels},
                        "State": {"Paused": True},
                        "NetworkSettings": {"Networks": {}},
                    },
                )
            if path == "/networks/kinship-demo_membership":
                return httpx.Response(
                    200,
                    json={"Id": "net", "Name": "kinship-demo_membership", "Labels": network_labels},
                )
            return httpx.Response(204)

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://docker"
        ) as http:
            helper = DockerHelper(http)
            await helper.apply("node-1", "connect")
            self.assertIn(b'"Aliases":["node-1"]', calls[-1].content)
            await helper.apply("node-1", "restart")
            self.assertEqual(
                [r.url.path for r in calls[-2:]],
                ["/containers/abc/unpause", "/containers/abc/restart"],
            )

    async def test_foreign_container_rejected(self):
        def handler(request):
            return httpx.Response(200, json=[{"Id": "foreign", "Labels": {}}])

        async with httpx.AsyncClient(
            transport=httpx.MockTransport(handler), base_url="http://docker"
        ) as http:
            with self.assertRaises(ValueError):
                await DockerHelper(http).apply("node-1", "kill")


class BackgroundTests(unittest.IsolatedAsyncioTestCase):
    async def test_ambiguous_fault_timeout_retains_recovery_reservation(self):
        def handler(request):
            raise httpx.ReadTimeout("response lost after fault", request=request)

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            controller = FaultController(http, lambda *_: None)
            with self.assertRaises(httpx.ReadTimeout):
                await controller.apply("node-1", "drain")
            self.assertIn("node-1", controller.unavailable_nodes)
            self.assertEqual(controller.reservations["node-1"]["action"], "drain")

    async def test_only_fresh_crash_poll_clears_the_matching_reservation(self):
        now = 0
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"ok": True}))
        ) as http:
            controller = FaultController(
                http, lambda *_: None, docker_enabled=True, clock=lambda: now
            )
            stale = controller.poll_token("node-1")
            await controller.apply("node-1", "crash")
            current = controller.poll_token("node-1")
            now = 30
            controller.mark_reachable("node-1", stale)
            self.assertIn("node-1", controller.unavailable_nodes)
            controller.mark_reachable("node-1", current)
            self.assertNotIn("node-1", controller.unavailable_nodes)
            await controller.apply("node-1", "pause")
            controller.mark_reachable("node-1", controller.poll_token("node-1"))
            self.assertIn("node-1", controller.unavailable_nodes)
            await controller.apply("node-1", "connect")  # Wrong recovery must not clear pause.
            self.assertIn("node-1", controller.unavailable_nodes)
            await controller.apply("node-1", "unpause")
            self.assertIn("node-1", controller.unavailable_nodes)
            controller.mark_reachable("node-1", controller.poll_token("node-1"))
            self.assertNotIn("node-1", controller.unavailable_nodes)

    async def test_manual_start_waits_for_ready_and_restart_cannot_overlap(self):
        async with httpx.AsyncClient(
            transport=httpx.MockTransport(lambda request: httpx.Response(200, json={"ok": True}))
        ) as http:
            controller = FaultController(http, lambda *_: None, docker_enabled=True)
            await controller.apply("node-1", "leave")
            before = controller.poll_token("node-1")
            await controller.apply("node-1", "start")
            self.assertIn("node-1", controller.unavailable_nodes)
            controller.mark_reachable("node-1", before)
            self.assertIn("node-1", controller.unavailable_nodes)
            with self.assertRaises(ValueError):
                await controller.apply("node-2", "restart")
            controller.mark_reachable("node-1", controller.poll_token("node-1"))
            reserved_generation = controller.generation + 1
            await controller.apply("node-2", "restart")
            self.assertIn("node-2", controller.unavailable_nodes)
            controller.mark_reachable("node-2", reserved_generation)
            self.assertIn("node-2", controller.unavailable_nodes)
            controller.mark_reachable("node-2", controller.poll_token("node-2"))
            self.assertFalse(controller.unavailable_nodes)

    async def test_stall_returns_immediately_and_retains_recovery_slot(self):
        started = asyncio.Event()
        release = asyncio.Event()

        async def handler(request):
            self.assertGreater(request.extensions["timeout"]["read"], 20)
            started.set()
            await release.wait()
            return httpx.Response(200, json={"ok": True})

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            controller = FaultController(http, lambda *_: None)
            scheduler = ChaosScheduler(controller, clock=lambda: 40, chooser=lambda xs: xs[0])
            await scheduler.set_enabled(True)
            scheduler.next_at = 0
            await scheduler.tick()
            await asyncio.wait_for(started.wait(), 1)
            await scheduler.set_enabled(False)
            self.assertIsNotNone(scheduler.active)
            release.set()
            await asyncio.gather(*controller.tasks)
            await scheduler.tick()
            self.assertIsNone(scheduler.active)
            await controller.close()

    async def test_shutdown_cancels_stall(self):
        started = asyncio.Event()

        async def handler(request):
            started.set()
            await asyncio.Event().wait()

        async with httpx.AsyncClient(transport=httpx.MockTransport(handler)) as http:
            controller = FaultController(http, lambda *_: None)
            result = await controller.apply("node-1", "stall")
            self.assertTrue(result["scheduled"])
            await started.wait()
            await controller.close()
            self.assertFalse(controller.tasks)
            self.assertFalse(controller.unavailable_nodes)


if __name__ == "__main__":
    unittest.main()
