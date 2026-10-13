"""Cache routing tests; run with ``python -m unittest test_node`` in the demo image."""

import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch
from urllib.parse import quote

import httpx
from common import config
from node import HOP_HEADER, MAX_HOPS, cache_ring, create_app, drop_moved, watch_ring


def member(name="node-1", url=None):
    return SimpleNamespace(name=name, meta={"url": url or f"http://{name}:8000"})


class ConfigTests(unittest.TestCase):
    def test_bind_uses_route_to_membership_seed_and_keeps_hostname_seeds(self):
        udp = MagicMock()
        udp.__enter__.return_value = udp
        udp.getsockname.return_value = ("172.20.0.9", 43123)
        with (
            patch.dict("os.environ", {"NODE_NAME": "dashboard", "ROLE": "dashboard"}),
            patch("common.time.sleep"),
            patch("common.socket.gethostbyname", return_value="172.20.0.2") as resolve,
            patch("common.socket.socket", return_value=udp),
            patch("common.kinship.Config") as cfg,
        ):
            config()
        resolve.assert_called_once_with("node-1")
        udp.connect.assert_called_once_with(("172.20.0.2", 7946))
        udp.send.assert_not_called()
        kwargs = cfg.lan.call_args.kwargs
        self.assertEqual(kwargs["bind"], "172.20.0.9:7946")
        self.assertEqual(kwargs["seeds"], ["node-1:7946", "node-2:7946", "node-3:7946"])
        self.assertNotIn("url", kwargs["meta"])

    def test_tries_next_peer_when_first_seed_cannot_resolve(self):
        udp = MagicMock()
        udp.__enter__.return_value = udp
        udp.getsockname.return_value = ("172.20.0.9", 43123)
        with (
            patch("common.time.sleep"),
            patch("common.socket.gethostbyname", side_effect=[OSError("DNS"), "172.20.0.3"]),
            patch("common.socket.socket", return_value=udp),
            patch("common.kinship.Config") as cfg,
        ):
            config()
        udp.connect.assert_called_once_with(("172.20.0.3", 7946))
        self.assertEqual(cfg.lan.call_args.kwargs["bind"], "172.20.0.9:7946")

    def test_no_peer_route_fails_instead_of_binding_dashboard_control_network(self):
        with (
            patch.dict("os.environ", {"NODE_NAME": "dashboard", "ROLE": "dashboard"}),
            patch("common.time.sleep"),
            patch("common.socket.gethostbyname", side_effect=OSError("DNS")),
            self.assertRaisesRegex(RuntimeError, "membership network"),
        ):
            config()


class FakeRing:
    def __init__(self):
        self.read_owner = member()
        self.write_owner = member()
        self.calls = []
        self.movement = {}
        self.snapshot = (member(),)

    def owner(self, key, *, new_work=False):
        self.calls.append((key, new_work))
        result = self.write_owner if new_work else self.read_owner
        if result is None:
            raise LookupError("empty ring")
        return result

    def members(self):
        return self.snapshot

    def moved(self, keys, before, after):
        return {key: owners for key, owners in self.movement.items() if key in keys}


class NodeTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.app = create_app("node-1")
        self.ring = FakeRing()
        self.app.dependency_overrides[cache_ring] = lambda: self.ring
        self.client = httpx.AsyncClient(
            transport=httpx.ASGITransport(app=self.app), base_url="http://node-1:8000"
        )
        self.forwarded = []

        def upstream(request):
            self.forwarded.append(request)
            return httpx.Response(200, json={"node": "node-2", "value": "forwarded"})

        self.app.state.http = httpx.AsyncClient(transport=httpx.MockTransport(upstream))

    async def asyncTearDown(self):
        await self.client.aclose()
        await self.app.state.http.aclose()

    async def test_writes_skip_suspects_but_reads_keep_the_owner(self):
        response = await self.client.put("/kv/key-01", json="value")
        self.assertEqual(response.status_code, 200)
        response = await self.client.get("/kv/key-01")
        self.assertEqual(response.json()["value"], "value")
        self.assertEqual(self.ring.calls, [("key-01", True), ("key-01", False)])
        self.ring.write_owner = member("node-2")
        await self.client.put("/kv/key-01", json="fresh")
        self.assertEqual(len(self.forwarded), 1)
        self.assertEqual((await self.client.get("/kv/key-01")).json()["node"], "node-1")

    async def test_owner_url_must_match_the_expected_name(self):
        for owner in (
            member("node-2", "http://attacker.invalid:8000"),
            member("node-2", "http://node-3:8000"),
            member("unknown", "http://node-2:8000"),
        ):
            self.ring.read_owner = owner
            self.assertEqual((await self.client.get("/kv/key-01")).status_code, 503)
        self.assertEqual(self.forwarded, [])

    async def test_forwarding_quotes_keys_and_counts_hops(self):
        self.ring.read_owner = member("node-2")
        key = "path/with ?#% unicode-é"
        response = await self.client.get("/kv/" + quote(key, safe=""))
        self.assertEqual(response.status_code, 200)
        request = self.forwarded[0]
        self.assertEqual(request.url.raw_path.decode(), "/kv/" + quote(key, safe=""))
        self.assertEqual(request.headers[HOP_HEADER], "1")
        response = await self.client.get("/kv/key-01", headers={HOP_HEADER: str(MAX_HOPS)})
        self.assertEqual(response.status_code, 503)
        for hops in ("-1", "bad"):
            response = await self.client.get("/kv/key-01", headers={HOP_HEADER: hops})
            self.assertEqual(response.status_code, 400)
        self.assertEqual(len(self.forwarded), 1)

    async def test_empty_ring_and_missing_value(self):
        self.assertEqual((await self.client.get("/kv/missing")).status_code, 404)
        self.ring.read_owner = self.ring.write_owner = None
        self.assertEqual((await self.client.get("/kv/key-01")).status_code, 503)
        self.assertEqual((await self.client.put("/kv/key-01", json="v")).status_code, 503)

    async def test_local_drain_drops_values_immediately(self):
        calls = []

        async def update_meta(**changes):
            calls.append(changes)

        self.app.state.cluster = SimpleNamespace(update_meta=update_meta)
        self.app.state.data["key-01"] = "v"
        response = await self.client.post("/fault/drain")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(self.app.state.data, {})
        self.assertEqual(calls, [{"role": "draining"}])
        response = await self.client.post("/fault/undrain")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(calls[-1], {"role": "cache"})

    async def test_drops_only_keys_that_no_longer_belong_locally(self):
        data = {"stay": "v", "move": "v", "lost": "v"}
        self.ring.movement = {
            "move": (member(), member("node-2")),
            "lost": (member(), None),
        }
        drop_moved(data, self.ring, "node-1", (), ())
        self.assertEqual(data, {"stay": "v"})

    async def test_values_and_keys_are_bounded(self):
        response = await self.client.put("/kv/key-01", json="x" * 16385)
        self.assertEqual(response.status_code, 413)
        response = await self.client.put("/kv/" + "x" * 257, json="v")
        self.assertEqual(response.status_code, 413)
        self.assertEqual(self.app.state.data, {})

    async def test_ring_changes_evict_moved_local_keys(self):
        data = {"key-01": "v"}
        self.ring.movement = {"key-01": (member(), member("node-2"))}

        async def changes():
            yield SimpleNamespace(members=(member("node-2"),))

        await watch_ring(data, self.ring, "node-1", (member(),), changes())
        self.assertEqual(data, {})

    async def test_recovery_evicts_temporary_write_fallback_without_normal_move(self):
        data = {"key-01": "temporary"}
        self.ring.read_owner = member("node-2")
        self.ring.write_owner = member("node-2")
        self.ring.movement = {}  # SUSPECT -> ALIVE retained the same normal owner.

        async def changes():
            yield SimpleNamespace(members=(member("node-2"),))

        await watch_ring(data, self.ring, "node-1", (member("node-2"),), changes())
        self.assertEqual(data, {})


if __name__ == "__main__":
    unittest.main()
