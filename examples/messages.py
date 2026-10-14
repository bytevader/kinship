"""Members talk to each other through the cluster itself, with no HTTP endpoint between them.

Three nodes in this process. node-a broadcasts a cache invalidation, which every other node
hears once. node-b asks node-c for a report, and node-c answers with a direct message too large
for a datagram, which goes over TCP: a request and its reply are two messages.

    python examples/messages.py

Messages are best effort and never acknowledged, so a real application retries a request that
gets no reply in time.
"""

from __future__ import annotations

import asyncio

import kinship


async def serve(
    cluster: kinship.Cluster,
    events: kinship.EventStream,
    replied: asyncio.Event,
) -> None:
    """Prints every message that arrives, and answers a request for the report."""
    me = cluster.local.name
    async for event in events:
        if not isinstance(event, kinship.UserMessage):
            continue
        kind = "broadcast" if event.broadcast else "message"
        start, size = event.data[:20], len(event.data)
        print(f"{me} got a {kind} from {event.sender.name}: {start!r}, {size} bytes")
        if event.data == b"report?":
            report = b"".join(b"line %d\n" % i for i in range(1_000))
            await cluster.send(event.sender, report)
        elif event.data.startswith(b"line 0\n"):
            replied.set()


async def main() -> None:
    first = await kinship.Cluster(kinship.Config.local(name="node-a", bind="127.0.0.1:0")).start()
    nodes = [first]
    try:
        for name in ("node-b", "node-c"):
            cfg = kinship.Config.local(name=name, bind="127.0.0.1:0", seeds=[first.local.addr])
            nodes.append(await kinship.Cluster(cfg).start())
        while any(len(node.members()) != 3 for node in nodes):
            await asyncio.sleep(0.05)

        replied = asyncio.Event()
        tasks = [asyncio.create_task(serve(n, n.events(), replied)) for n in nodes]
        a, b, c = nodes
        await a.broadcast(b"invalidate user:42")
        await asyncio.sleep(1)

        node_c = b.member(c.local.name)
        assert node_c is not None
        await b.send(node_c, b"report?")
        await asyncio.wait_for(replied.wait(), 10)
        await asyncio.sleep(0.5)
        for node in nodes:
            stats = node.stats()
            print(
                f"{node.local.name}: {stats.user_messages_sent} sent, "
                f"{stats.user_messages_received} received"
            )
        for task in tasks:
            task.cancel()
    finally:
        for node in nodes:
            await node.close()


if __name__ == "__main__":
    asyncio.run(main())
