"""Dependency-free Prometheus text exposition for async and blocking clusters."""

from __future__ import annotations

from collections import Counter
from dataclasses import fields
from typing import TYPE_CHECKING

from kinship._types import State, Stats

if TYPE_CHECKING:
    from kinship import Cluster, blocking

__all__ = ["prometheus_text"]


def prometheus_text(cluster: Cluster | blocking.Cluster) -> str:
    """Export protocol counters, local health and membership in Prometheus text format.

    Every sample has a ``node`` label naming the local member. Member counts reflect
    ``cluster.members()``: dead and left tombstones are excluded by the Cluster APIs,
    so those states have zero counts. Counters reset when the node restarts.
    """
    node = cluster.local.name.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n")
    labels = f'node="{node}"'
    stats = cluster.stats()
    lines = []
    for field in fields(Stats):
        gauge = field.name == "local_health"
        name = "kinship_local_health" if gauge else f"kinship_{field.name}_total"
        description = (
            "This node's Lifeguard local health score."
            if gauge
            else f"Total {field.name.replace('_', ' ')} since this node started."
        )
        lines.extend(
            [
                f"# HELP {name} {description}",
                f"# TYPE {name} {'gauge' if gauge else 'counter'}",
                f"{name}{{{labels}}} {getattr(stats, field.name)}",
            ]
        )
    counts = Counter(member.state for member in cluster.members())
    lines.extend(
        [
            "# HELP kinship_members Members returned by cluster.members(), by state.",
            "# TYPE kinship_members gauge",
        ]
    )
    lines.extend(
        f'kinship_members{{{labels},state="{state.name.lower()}"}} {counts[state]}'
        for state in State
    )
    return "\n".join(lines) + "\n"
