import re
from dataclasses import fields, make_dataclass
from types import SimpleNamespace
from typing import cast

import pytest

import kinship
from conftest import local
from kinship import blocking
from kinship import metrics as metrics_module
from kinship.metrics import prometheus_text


def parse_metrics(text: str) -> dict[str, list[tuple[str, int]]]:
    """Check the exposition one line at a time, retaining labels and integer samples."""
    help_names = set()
    types = {}
    samples: dict[str, list[tuple[str, int]]] = {}
    assert text.endswith("\n")
    for line in text.splitlines():
        if line.startswith("# HELP "):
            _, _, name, description = line.split(" ", 3)
            assert description and name not in help_names
            help_names.add(name)
        elif line.startswith("# TYPE "):
            _, _, name, kind = line.split(" ")
            assert kind == (
                "gauge" if name in {"kinship_local_health", "kinship_members"} else "counter"
            )
            assert name not in types
            types[name] = kind
        else:
            match = re.fullmatch(r"(kinship_[a-z_]+)\{(.*)\} (-?\d+)", line)
            assert match is not None, line
            name, labels, value = match.groups()
            assert name in help_names and name in types
            samples.setdefault(name, []).append((labels, int(value)))
        assert re.fullmatch(r"kinship_[a-z_]+", name)
    expected = {
        "kinship_local_health" if f.name == "local_health" else f"kinship_{f.name}_total"
        for f in fields(kinship.Stats)
    } | {"kinship_members"}
    assert set(samples) == help_names == set(types) == expected
    return samples


def check_cluster(cluster: kinship.Cluster | blocking.Cluster) -> None:
    samples = parse_metrics(prometheus_text(cluster))
    label = f'node="{cluster.local.name}"'
    for field in fields(kinship.Stats):
        name = (
            "kinship_local_health"
            if field.name == "local_health"
            else f"kinship_{field.name}_total"
        )
        assert len(samples[name]) == 1
        assert samples[name][0][0] == label
        assert samples[name][0][1] >= 0
    assert samples["kinship_members"] == [
        (f'{label},state="{state}"', count)
        for state, count in [("alive", 1), ("suspect", 0), ("dead", 0), ("left", 0)]
    ]


async def test_async_cluster_metrics() -> None:
    async with kinship.Cluster(local(name="metrics-async")) as cluster:
        check_cluster(cluster)


def test_blocking_cluster_metrics() -> None:
    with blocking.Cluster(local(name="metrics-blocking")) as cluster:
        check_cluster(cluster)


@pytest.mark.parametrize(
    ("name", "label"),
    [
        ('node"with\\escapes', 'node="node\\"with\\\\escapes"'),
        ("node\nwith-newline", 'node="node\\nwith-newline"'),
    ],
)
async def test_node_label_escaping(name: str, label: str) -> None:
    async with kinship.Cluster(local(name=name)) as cluster:
        samples = parse_metrics(prometheus_text(cluster))
        for entries in samples.values():
            assert all(labels.startswith(label) for labels, _ in entries)


def test_snapshot_values_and_membership_counts() -> None:
    stats = kinship.Stats(**{field.name: i for i, field in enumerate(fields(kinship.Stats))})
    members = [
        kinship.Member(str(i), "127.0.0.1:7946", state, 0)
        for i, state in enumerate(
            [kinship.State.ALIVE, kinship.State.ALIVE, kinship.State.SUSPECT, kinship.State.LEFT]
        )
    ]
    snapshot = cast(
        kinship.Cluster,
        SimpleNamespace(local=members[0], stats=lambda: stats, members=lambda: members),
    )
    samples = parse_metrics(prometheus_text(snapshot))
    for i, field in enumerate(fields(kinship.Stats)):
        name = (
            "kinship_local_health"
            if field.name == "local_health"
            else f"kinship_{field.name}_total"
        )
        assert samples[name] == [('node="0"', i)]
    assert samples["kinship_members"] == [
        ('node="0",state="alive"', 2),
        ('node="0",state="suspect"', 1),
        ('node="0",state="dead"', 0),
        ('node="0",state="left"', 1),
    ]


def test_new_stats_fields_are_automatically_exported(monkeypatch: pytest.MonkeyPatch) -> None:
    extended = make_dataclass(
        "ExtendedStats", [("future_counter", int)], bases=(kinship.Stats,), frozen=True
    )
    stats = extended(
        **dict.fromkeys((field.name for field in fields(kinship.Stats)), 0),
        future_counter=9007199254740993,
    )
    snapshot = cast(
        kinship.Cluster,
        SimpleNamespace(
            local=kinship.Member("future", "127.0.0.1:7946", kinship.State.ALIVE, 0),
            stats=lambda: stats,
            members=list,
        ),
    )
    monkeypatch.setattr(metrics_module, "Stats", extended)
    text = prometheus_text(snapshot)
    assert "# HELP kinship_future_counter_total " in text
    assert "# TYPE kinship_future_counter_total counter\n" in text
    assert 'kinship_future_counter_total{node="future"} 9007199254740993\n' in text
    assert 'kinship_members{node="future",state="alive"} 0\n' in text
