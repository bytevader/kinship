"""Three terminals, one cluster: watch nodes join, leave and crash.

Start a node on a port, and point every other node at it:

    python examples/quickstart.py 7946
    python examples/quickstart.py 7947 7946
    python examples/quickstart.py 7948 7946

Press Ctrl-C in one terminal and the others print MemberLeft. Kill one with ``kill -9`` (or close
its window) and they print MemberSuspect, then MemberDead a few seconds later.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import time

import kinship


async def main(port: int, seeds: list[int]) -> None:
    cfg = kinship.Config.local(
        bind=f"127.0.0.1:{port}",
        seeds=[f"127.0.0.1:{seed}" for seed in seeds],
    )
    start = time.monotonic()
    async with kinship.Cluster(cfg) as cluster:  # on exit: leave, then close
        events = cluster.events()  # subscribe first, so nothing falls between snapshot and loop
        members = ", ".join(sorted(m.name for m in cluster.members()))
        print(f"{cluster.local.name} is up on {cluster.local.addr}; Ctrl-C to leave")
        print(f"{time.monotonic() - start:7.1f}s  {'joined':<36} members: {members}")
        async for event in events:
            members = ", ".join(sorted(m.name for m in cluster.members()))
            print(f"{time.monotonic() - start:7.1f}s  {event!r:<36} members: {members}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("port", type=int, help="UDP and TCP port for this node")
    parser.add_argument("seeds", type=int, nargs="*", help="ports of nodes to join")
    args = parser.parse_args()
    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main(args.port, args.seeds))
