"""Metadata and the blocking API, for Flask, Django, Celery or plain threads.

Three nodes advertise a role and an HTTP address in their metadata. node-a routes requests to
the owner of each key among the members that serve traffic. Then node-b marks itself as draining,
node-a hears it as MemberUpdated on its event thread, and new requests stop going to node-b.

    python examples/sync_workers.py

Everything here is plain synchronous code. The protocol still runs on kinship's own thread, so
a slow request handler cannot make a node look dead.
"""

from __future__ import annotations

import threading

import kinship
from kinship.blocking import Cluster
from kinship.rendezvous import owner

REQUESTS = ["cart:17", "cart:42", "cart:99", "user:7", "user:8", "user:9"]


def start(name: str, port: int, seeds: list[str]) -> Cluster:
    cfg = kinship.Config.local(
        name=name,
        bind="127.0.0.1:0",
        seeds=seeds,
        meta={"role": "serving", "http": f"127.0.0.1:{port}"},
    )
    return Cluster(cfg).start()  # binds, joins the seeds, then returns


def route(cluster: Cluster) -> None:
    serving = [m for m in cluster.members() if m.meta.get("role") == "serving"]
    for key in REQUESTS:
        node = owner(key, serving)
        print(f"  {key:<8} -> {node.name} at http://{node.meta['http']}")


def log_events(cluster: Cluster, updated: threading.Event) -> None:
    # The iterator ends when the cluster closes; a timeout tick yields None.
    for event in cluster.events(timeout=1.0):
        if isinstance(event, kinship.MemberUpdated):
            old, new = dict(event.previous_meta), dict(event.member.meta)
            print(f"\n  event thread: {event.member.name} changed {old['role']} -> {new['role']}")
            updated.set()


def main() -> None:
    a = start("node-a", 8001, [])
    nodes = [a, start("node-b", 8002, [a.local.addr]), start("node-c", 8003, [a.local.addr])]
    try:
        while any(len(node.members()) != 3 for node in nodes):
            threading.Event().wait(0.05)
        updated = threading.Event()
        threading.Thread(target=log_events, args=(a, updated), daemon=True).start()

        print("node-a routes requests over three serving nodes:")
        route(a)

        nodes[1].update_meta(role="draining")  # gossiped to everyone within a few rounds
        if not updated.wait(timeout=20):
            raise SystemExit("node-a never heard that node-b is draining")
        print("\nnode-a routes new requests around node-b:")
        route(a)
    finally:
        for node in nodes:
            node.close()  # close() runs leave() first


if __name__ == "__main__":
    main()
