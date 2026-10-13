"""Run with the image's dependencies: see the local README."""

import asyncio
import json
import unittest
from types import SimpleNamespace

import httpx
from common import NAMES
from demo import View, app, entry_node, member_record, stream

import kinship


def member(name="node-3", state=kinship.State.ALIVE):
    return kinship.Member(name, "172.18.0.4:7946", state, 0, {"role": "worker", "zone": "b"})


class Cluster:
    def __init__(self, *members):
        self.records = {m.name: m for m in members}

    def member(self, name):
        return self.records.get(name)

    def members(self):
        return [
            m
            for m in self.records.values()
            if m.state in {kinship.State.ALIVE, kinship.State.SUSPECT}
        ]


async def events(*values):
    for value in values:
        yield value


class ViewTests(unittest.IsolatedAsyncioTestCase):
    async def test_suspect_ownership_and_movement_are_in_sse_snapshot(self):
        old = member(state=kinship.State.SUSPECT)
        fallback = member("node-4")

        class FakeRing:
            def owner(self, key, *, new_work=False):
                return fallback if new_work else old

            def moved(self, keys, before, after):
                return {"key-00": (old, fallback)}

        view = View(Cluster(old, fallback), FakeRing())
        view.resync()
        snapshot = json.loads(view.snapshot())
        self.assertEqual(len(snapshot["keys"]), 64)
        self.assertEqual(snapshot["keys"][0]["owner"], "node-3")
        self.assertEqual(snapshot["keys"][0]["state"], "SUSPECT")
        self.assertEqual(snapshot["keys"][0]["write_owner"], "node-4")

        async def changes():
            yield SimpleNamespace(members=(fallback,))

        await view.ring_changes(changes(), (old, fallback))
        self.assertGreater(json.loads(view.snapshot())["keys"][0]["moved_at"], 0)
        self.assertEqual(view.log[-1]["kind"], "RingChanged")
        self.assertEqual(view.log[-1]["style"], "ring")

    async def test_dead_and_left_remain_visible_then_rejoin_replaces_them(self):
        view = View(Cluster(member()))
        view.resync()
        await view.consume(events(kinship.MemberDead(member(state=kinship.State.DEAD))))
        view.cluster.records.clear()  # Tombstone eventually expires.
        view.resync()
        self.assertEqual(view.members["node-3"]["state"], "DEAD")
        await view.consume(events(kinship.MemberLeft(member(state=kinship.State.LEFT))))
        view.resync()
        self.assertEqual(view.members["node-3"]["state"], "LEFT")
        await view.consume(events(kinship.MemberJoined(member())))
        self.assertEqual(view.members["node-3"]["state"], "ALIVE")
        self.assertEqual(view.members["node-3"]["meta"]["role"], "worker")

    async def test_slow_browser_gets_latest_snapshot_and_bounded_history(self):
        view = View(Cluster())
        queue = asyncio.Queue(maxsize=1)
        view.clients.add(queue)
        await view.consume(events(*(kinship.MemberJoined(member()) for _ in range(205))))
        self.assertEqual(queue.qsize(), 1)
        snapshot = json.loads(queue.get_nowait())
        self.assertEqual(snapshot["revision"], 205)
        self.assertEqual(len(snapshot["log"]), 200)
        self.assertTrue(snapshot["log"][-1]["time"].endswith("+00:00"))

    async def test_events_lost_refreshes_known_tombstones_and_new_members(self):
        view = View(Cluster())
        view.members["node-3"] = member_record(member())
        view.cluster.records = {
            "node-3": member(state=kinship.State.DEAD),
            "node-4": member("node-4"),
        }
        await view.consume(events(kinship.EventsLost(8)))
        self.assertEqual(view.members["node-3"]["state"], "DEAD")
        self.assertEqual(view.members["node-4"]["state"], "ALIVE")
        self.assertIn("8 events lost", view.log[-1]["detail"])

    async def test_sse_reconnect_snapshot_and_disconnect_cleanup(self):
        view = View(Cluster(member("dashboard")))
        view.resync()
        request = SimpleNamespace(app=SimpleNamespace(state=SimpleNamespace(view=view)))
        response = await stream(request)
        iterator = response.body_iterator
        try:
            first = await anext(iterator)
            self.assertTrue(first.startswith("data: "))
            self.assertTrue(first.endswith("\n\n"))
            self.assertEqual(json.loads(first[6:])["members"][0]["name"], "dashboard")
            self.assertEqual(len(view.clients), 1)
            await view.consume(events(kinship.MemberJoined(member())))
            update = json.loads((await anext(iterator))[6:])
            self.assertEqual(len(update["members"]), 2)
        finally:
            await iterator.aclose()
        self.assertEqual(len(view.clients), 0)


class EntryNodeTests(unittest.TestCase):
    def test_load_skips_nodes_seen_dead_or_left(self):
        view = View(Cluster())
        view.members = {
            "node-1": {"state": "DEAD"},
            "node-2": {"state": "LEFT"},
            "node-3": {"state": "SUSPECT"},
        }
        # node-4 and node-5 are not known yet, so only node-3 is a live entry.
        self.assertEqual({entry_node(view) for _ in range(50)}, {"node-3"})
        view.members = {}
        self.assertTrue({entry_node(view) for _ in range(200)} <= set(NAMES))


class ControlOriginTests(unittest.IsolatedAsyncioTestCase):
    async def test_other_sites_and_rebound_hosts_cannot_drive_faults(self):
        # Every request here is refused before a handler, so the app needs no lifespan.
        transport = httpx.ASGITransport(app=app)
        async with httpx.AsyncClient(transport=transport, base_url="http://localhost:8080") as http:
            response = await http.post(
                "/control/fault/node-3/kill", headers={"origin": "https://example.com"}
            )
            self.assertEqual(response.status_code, 403)
            response = await http.post("/control/fault/node-3/kill", headers={"origin": "null"})
            self.assertEqual(response.status_code, 403)
            self.assertEqual((await http.get("/")).status_code, 200)
        async with httpx.AsyncClient(
            transport=transport, base_url="http://rebound.test:8080"
        ) as http:
            self.assertEqual((await http.get("/")).status_code, 400)
            response = await http.post(
                "/control/fault/node-3/kill", headers={"origin": "http://rebound.test:8080"}
            )
            self.assertEqual(response.status_code, 400)


if __name__ == "__main__":
    unittest.main()
