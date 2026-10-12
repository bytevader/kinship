"""Which node owns which key, and what moves when a node goes.

Starts four nodes in this process, spreads twelve keys over them with rendezvous hashing, then
has one node leave cleanly and another crash. Only the keys of the node that went move; every
other key stays where it was, which is what lets a sharded cache keep its hit rate.

    python examples/sharded_keys.py
"""

from __future__ import annotations

import asyncio
import time

import kinship
from kinship.rendezvous import owner

KEYS = [f"user:{i}" for i in range(1, 13)]


def owners(cluster: kinship.Cluster) -> dict[str, str]:
    # members() includes suspect nodes on purpose: a node that is only slow keeps its keys.
    members = cluster.members()
    return {key: owner(key, members).name for key in KEYS}


def show(title: str, now: dict[str, str], before: dict[str, str] | None = None) -> None:
    print(f"\n{title}")
    for key, name in now.items():
        was = f"  <- moved from {before[key]}" if before and before[key] != name else ""
        print(f"  {key:<8} {name}{was}")
    if before:
        moved = sum(before[key] != now[key] for key in KEYS)
        print(f"  {moved} of {len(KEYS)} keys moved")


async def wait_until_converged(nodes: list[kinship.Cluster]) -> None:
    while any(len(node.members()) != len(nodes) for node in nodes):
        await asyncio.sleep(0.05)


async def watch(events: kinship.EventStream, name: str, until: type, start: float) -> None:
    """Prints what node-a hears about `name` until an event of type `until` arrives."""
    async for event in events:
        if isinstance(event, kinship.EventsLost) or event.member.name != name:
            continue
        print(f"  node-a sees {event!r} after {time.monotonic() - start:.1f} s")
        if isinstance(event, until):
            return


async def main() -> None:
    first = await kinship.Cluster(kinship.Config.local(name="node-a", bind="127.0.0.1:0")).start()
    nodes = [first]
    try:
        for name in ("node-b", "node-c", "node-d"):
            cfg = kinship.Config.local(name=name, bind="127.0.0.1:0", seeds=[first.local.addr])
            nodes.append(await kinship.Cluster(cfg).start())
        await asyncio.wait_for(wait_until_converged(nodes), 20)
        events = first.events()
        before = owners(first)
        show("Four nodes:", before)

        # A clean leave: the others hear MemberLeft at once and never treat it as a failure.
        leaving = nodes.pop()
        print(f"\n{leaving.local.name} leaves")
        start = time.monotonic()
        await leaving.leave()
        await leaving.close()
        await asyncio.wait_for(watch(events, "node-d", kinship.MemberLeft, start), 20)
        after = owners(first)
        show("After node-d left:", after, before)

        # A crash: close without leaving looks like kill -9. Probes fail, the node is suspected,
        # and it is declared dead once the suspicion times out without a refutation.
        crashed = nodes.pop()
        print(f"\n{crashed.local.name} crashes")
        start = time.monotonic()
        await crashed.close()
        await asyncio.wait_for(watch(events, "node-c", kinship.MemberDead, start), 30)
        show("After node-c crashed:", owners(first), after)
    finally:
        for node in nodes:
            await node.close()


if __name__ == "__main__":
    asyncio.run(main())
