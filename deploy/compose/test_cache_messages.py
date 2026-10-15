"""Cache handoff and flush commands over kinship user messages."""

import json
import unittest
from types import SimpleNamespace
from unittest.mock import AsyncMock

from node import CacheMessages, watch_messages
from test_node import FakeRing, member


class MessageTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.data = {}
        self.messages = CacheMessages(self.data, "node-1")
        self.ring = FakeRing()
        self.cluster = SimpleNamespace(send=AsyncMock())

    async def test_handoff_batches_encoded_bytes_and_drops_only_moved_keys(self):
        self.data.update({f"key-{i}": "\x00" * 16384 for i in range(20)})
        self.data["stay"] = "v"
        self.ring.movement = {k: (member(), member("node-2")) for k in self.data if k != "stay"}
        await self.messages.handoff(self.cluster, self.ring, (), ())
        self.assertEqual(self.data, {"stay": "v"})
        self.assertGreater(self.cluster.send.await_count, 1)
        entries = []
        for call in self.cluster.send.await_args_list:
            target, payload = call.args
            self.assertEqual(target.name, "node-2")
            self.assertLessEqual(len(payload), 65536)
            entries.extend(json.loads(payload)["entries"])
        self.assertEqual(len(entries), 20)
        self.assertEqual(self.messages.stats["handed_off"], 20)

    async def test_failed_send_is_cold_and_does_not_stop_other_handoffs(self):
        import kinship

        self.data.update(a="v", b="v")
        self.ring.movement = {"a": (member(), member("node-2")), "b": (member(), member("node-3"))}
        self.cluster.send.side_effect = [kinship.NotAMember("gone"), None]
        await self.messages.handoff(self.cluster, self.ring, (), ())
        self.assertEqual(self.data, {})
        self.assertEqual(self.cluster.send.await_count, 2)
        self.assertEqual(self.messages.stats["handed_off"], 1)

    def test_receives_only_currently_owned_absent_values(self):
        payload = CacheMessages.handoff_payload([["key", "old"]])
        self.ring.read_owner = member("node-2")
        self.messages.receive(payload, self.ring, broadcast=False)
        self.assertEqual(self.data, {})
        self.ring.read_owner = member()
        self.data["key"] = "fresh put"
        self.messages.receive(payload, self.ring, broadcast=False)
        self.assertEqual(self.data["key"], "fresh put")
        self.data.clear()
        self.messages.receive(payload, self.ring, broadcast=False)
        self.messages.receive(payload, self.ring, broadcast=False)
        self.assertEqual(self.data, {"key": "old"})
        self.assertEqual(self.messages.stats["received"], 1)

    def test_flush_ids_are_applied_once_even_out_of_order(self):
        for flush_id in ("a", "b", "a", "b"):
            self.data["key"] = "written since last flush"
            self.messages.receive(
                json.dumps({"type": "flush", "id": flush_id}).encode(), self.ring, broadcast=True
            )
            if flush_id == "b" and self.messages.stats["flushes"] == 1:
                self.fail("second distinct flush was ignored")
        self.assertEqual(self.messages.stats["flushes"], 2)
        self.assertEqual(self.messages.stats["last_flush_id"], "b")
        self.assertIn("key", self.data)

    def test_malformed_or_wrong_kind_messages_are_ignored(self):
        self.data["key"] = "v"
        for payload in (
            b"junk",
            b"[]",
            b"[" * 2000 + b"0" + b"]" * 2000,
            b'{"type":"handoff","entries":[[1,2]]}',
            b'{"type":"flush","id":[]}',
        ):
            self.messages.receive(payload, self.ring, broadcast=False)
            self.messages.receive(payload, self.ring, broadcast=True)
        self.assertEqual(self.data, {"key": "v"})

    async def test_events_deliver_handoff_and_flush_beside_membership(self):
        import kinship

        refresh = []

        async def events():
            yield kinship.EventsLost(1)
            yield kinship.UserMessage(
                member("node-2"), CacheMessages.handoff_payload([["key", "warm"]]), False
            )

        await watch_messages(self.messages, self.ring, events(), lambda: refresh.append(True))
        self.assertEqual(self.data, {"key": "warm"})
        self.assertEqual(refresh, [True])

    def test_empty_ring_and_capacity_do_not_accept_handoff(self):
        payload = CacheMessages.handoff_payload([["key", "warm"]])
        self.ring.read_owner = None
        self.messages.receive(payload, self.ring, broadcast=False)
        self.assertEqual(self.data, {})
        self.ring.read_owner = member()
        self.data.update({str(i): "v" for i in range(256)})
        self.messages.receive(payload, self.ring, broadcast=False)
        self.assertNotIn("key", self.data)

    async def test_a_write_during_send_is_not_evicted(self):
        self.data["key"] = "old"
        self.ring.read_owner = self.ring.write_owner = member("node-2")

        async def send(*args):
            self.data["key"] = "fresh"

        self.cluster.send.side_effect = send
        await self.messages.handoff(self.cluster, self.ring, (), ())
        self.assertEqual(self.data, {"key": "fresh"})

    async def test_flush_during_handoff_cannot_resurrect_pre_flush_values(self):
        self.data.update({str(i): "x" * 16384 for i in range(6)})
        self.ring.read_owner = self.ring.write_owner = member("node-2")
        target = CacheMessages({}, "node-2")
        target_ring = FakeRing()
        target_ring.read_owner = member("node-2")

        async def send(owner, payload):
            self.messages.flush("flush-1")
            target.flush("flush-1")
            target.receive(payload, target_ring, broadcast=False)

        self.cluster.send.side_effect = send
        await self.messages.handoff(self.cluster, self.ring, (), ())
        self.assertEqual(target.data, {})
        self.assertEqual(self.data, {})
        self.assertEqual(self.cluster.send.await_count, 1)

    def test_handoff_after_flush_requires_same_flush_view(self):
        self.messages.flush("flush-1")
        old_payload = CacheMessages.handoff_payload([["key", "old"]])
        self.messages.receive(old_payload, self.ring, broadcast=False)
        self.assertEqual(self.data, {})
        payload = CacheMessages.handoff_payload([["key", "new"]], "flush-1")
        self.messages.receive(payload, self.ring, broadcast=False)
        self.assertEqual(self.data, {"key": "new"})


if __name__ == "__main__":
    unittest.main()
