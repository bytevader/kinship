"""A job that runs on exactly one node, and moves when that node dies.

Three nodes in this process each tick twice a second. On every tick, the node that owns the job
among the alive members runs it; the others do nothing. Then the owner crashes, and once the
others stop seeing it as alive, the next owner picks the job up on its own.

    python examples/failover_job.py

This is best effort, not a lock: for the moment two nodes disagree about who is alive, both can
run the job, so a real job should be idempotent or take a lock keyed on its run.
"""

from __future__ import annotations

import asyncio
import time

import kinship
from kinship.rendezvous import owner

JOB = "nightly-report"
TICK = 0.5


async def scheduler(cluster: kinship.Cluster, start: float, ran_by: list[str]) -> None:
    me = cluster.local.name
    while True:
        alive = [m for m in cluster.members() if m.state is kinship.State.ALIVE]
        if owner(JOB, alive).name == me:
            print(f"{time.monotonic() - start:6.1f}s  {me} runs {JOB}")
            ran_by.append(me)
        await asyncio.sleep(TICK)


async def main() -> None:
    first = await kinship.Cluster(kinship.Config.local(name="node-a", bind="127.0.0.1:0")).start()
    nodes = [first]
    try:
        for name in ("node-b", "node-c"):
            cfg = kinship.Config.local(name=name, bind="127.0.0.1:0", seeds=[first.local.addr])
            nodes.append(await kinship.Cluster(cfg).start())
        while any(len(node.members()) != 3 for node in nodes):
            await asyncio.sleep(0.05)

        start = time.monotonic()
        ran_by: list[str] = []
        tasks = {
            node.local.name: asyncio.create_task(scheduler(node, start, ran_by)) for node in nodes
        }
        await asyncio.sleep(2)

        victim = next(node for node in nodes if node.local.name == ran_by[-1])
        name = victim.local.name
        print(f"{time.monotonic() - start:6.1f}s  {name} crashes")
        tasks.pop(name).cancel()
        nodes.remove(victim)
        await victim.close()  # no leave(): to the others this is a crash

        # Wait for the job to run somewhere else, then let it tick a few more times.
        while ran_by[-1] == name:
            await asyncio.sleep(0.05)
        print(f"         the job moved to {ran_by[-1]} without anyone electing a leader")
        await asyncio.sleep(1.5)
        for task in tasks.values():
            task.cancel()
    finally:
        for node in nodes:
            await node.close()


if __name__ == "__main__":
    asyncio.run(main())
