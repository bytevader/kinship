"""``docs/stability.md`` as tests: a 1.x release that breaks one of its promises fails here.

New names, new fields and new keyword-only parameters with defaults are allowed, so a new
parameter extends its line in ``CALLS`` and nothing else here has to change.
"""

from __future__ import annotations

import ast
import dataclasses
import inspect
from collections.abc import Callable
from datetime import timedelta
from pathlib import Path
from typing import Any

import pytest

import kinship
from conftest import cluster_of, drain, local, next_matching, wait_until
from kinship import blocking, metrics, rendezvous, ring

KEY = bytes(range(32))

PUBLIC_NAMES: dict[Any, set[str]] = {
    kinship: {
        "Cluster",
        "Config",
        "ConfigError",
        "Event",
        "EventStream",
        "EventsLost",
        "JoinError",
        "Keyring",
        "KeyringError",
        "KinshipClosed",
        "KinshipError",
        "Member",
        "MemberDead",
        "MemberJoined",
        "MemberLeft",
        "MemberRecovered",
        "MemberSuspect",
        "MemberUpdated",
        "MessageTooLarge",
        "MetaTooLarge",
        "NameConflict",
        "NotAMember",
        "State",
        "Stats",
        "UserMessage",
        "__version__",
        "blocking",
        "log_to_python",
        "rendezvous",
        "wire_version",
    },
    blocking: {"Cluster", "EventStream", "Keyring"},
    ring: {"Ring", "RingChanged"},
    rendezvous: {"owner", "owners", "weight"},
    metrics: {"prometheus_text"},
}


@pytest.mark.parametrize("module", PUBLIC_NAMES, ids=lambda m: m.__name__)
def test_every_promised_name_is_public(module: Any) -> None:
    assert PUBLIC_NAMES[module] <= set(module.__all__)
    for name in PUBLIC_NAMES[module]:
        assert hasattr(module, name), name


def params(fn: Callable[..., Any]) -> str:
    """A signature without its annotations: names, order, defaults and keyword-only markers."""
    out = []
    star = False
    for p in inspect.signature(fn).parameters.values():
        if p.kind is p.KEYWORD_ONLY and not star:
            star = True
            out.append("*")
        if p.kind is p.VAR_KEYWORD:
            out.append(f"**{p.name}")
        elif p.kind is p.VAR_POSITIONAL:
            out.append(f"*{p.name}")
        elif p.default is p.empty:
            out.append(p.name)
        else:
            out.append(f"{p.name}={p.default!r}")
    return ", ".join(out)


CALLS: list[tuple[Callable[..., Any], str]] = [
    (kinship.Cluster.__init__, "self, cfg"),
    (kinship.Cluster.start, "self"),
    (kinship.Cluster.join, "self, seeds=None"),
    (kinship.Cluster.members, "self"),
    (kinship.Cluster.member, "self, name"),
    (kinship.Cluster.stats, "self"),
    (kinship.Cluster.events, "self"),
    (kinship.Cluster.set_meta, "self, meta"),
    (kinship.Cluster.update_meta, "self, **changes"),
    (kinship.Cluster.send, "self, member, data"),
    (kinship.Cluster.broadcast, "self, data"),
    (kinship.Cluster.leave, "self, timeout=5.0"),
    (kinship.Cluster.close, "self"),
    (kinship.Keyring.install, "self, key"),
    (kinship.Keyring.use, "self, key"),
    (kinship.Keyring.remove, "self, key"),
    (kinship.Keyring.key_ids, "self"),
    (kinship.log_to_python, "level=None"),
    (kinship.wire_version, ""),
    (blocking.Cluster.__init__, "self, cfg"),
    (blocking.Cluster.start, "self, *, timeout=None"),
    (blocking.Cluster.join, "self, seeds=None, *, timeout=None"),
    (blocking.Cluster.members, "self"),
    (blocking.Cluster.member, "self, name"),
    (blocking.Cluster.stats, "self"),
    (blocking.Cluster.events, "self, timeout=None"),
    (blocking.Cluster.set_meta, "self, meta, *, timeout=None"),
    (blocking.Cluster.update_meta, "self, *, timeout=None, **changes"),
    (blocking.Cluster.send, "self, member, data, *, timeout=None"),
    (blocking.Cluster.broadcast, "self, data, *, timeout=None"),
    (blocking.Cluster.leave, "self, timeout=5.0"),
    (blocking.Cluster.close, "self, timeout=5.0"),
    (blocking.Keyring.install, "self, key, *, timeout=None"),
    (blocking.Keyring.use, "self, key, *, timeout=None"),
    (blocking.Keyring.remove, "self, key, *, timeout=None"),
    (blocking.Keyring.key_ids, "self"),
    (ring.Ring.__init__, "self, cluster, *, where=None"),
    (ring.Ring.matches, "self, member"),
    (ring.Ring.members, "self"),
    (ring.Ring.owner, "self, key, *, new_work=False"),
    (ring.Ring.replicas, "self, key, n, *, new_work=False"),
    (ring.Ring.fence, "self, key, *, new_work=False"),
    (ring.Ring.moved, "self, keys, before, after"),
    (ring.Ring.changes, "self, timeout=None"),
    (rendezvous.owner, "key, members"),
    (rendezvous.owners, "key, members, n"),
    (rendezvous.weight, "key, name"),
    (metrics.prometheus_text, "cluster"),
]


@pytest.mark.parametrize("fn, expected", CALLS, ids=lambda c: getattr(c, "__qualname__", None))
def test_calls_keep_their_parameters(fn: Callable[..., Any], expected: str) -> None:
    assert params(fn) == expected


@pytest.mark.parametrize("cluster", [kinship.Cluster, blocking.Cluster], ids=["async", "blocking"])
def test_clusters_keep_their_properties(cluster: type) -> None:
    for name in ("local", "config", "keyring"):
        assert isinstance(inspect.getattr_static(cluster, name), property), name


def test_the_fastapi_integration_keeps_its_parameters() -> None:
    fastapi = pytest.importorskip("kinship.contrib.fastapi", exc_type=ImportError)
    assert {"cluster_lifespan", "cluster_router", "get_cluster", "get_ring"} <= set(fastapi.__all__)
    assert params(fastapi.cluster_lifespan) == "config, *, leave_timeout=5.0"
    assert params(fastapi.cluster_router) == "prefix='/cluster', *, metrics=False"
    assert params(fastapi.get_cluster) == "conn"
    assert params(fastapi.get_ring) == "where=None"


def test_the_error_hierarchy_stays() -> None:
    for error in (
        kinship.ConfigError,
        kinship.JoinError,
        kinship.KeyringError,
        kinship.KinshipClosed,
        kinship.MessageTooLarge,
        kinship.MetaTooLarge,
        kinship.NotAMember,
    ):
        assert issubclass(error, kinship.KinshipError), error
    for error in (kinship.ConfigError, kinship.MetaTooLarge, kinship.MessageTooLarge):
        assert issubclass(error, ValueError), error
    assert issubclass(kinship.NotAMember, LookupError)
    with pytest.raises(kinship.ConfigError) as caught:
        kinship.Config.local(probe_interval=-1.0)
    assert caught.value.field == "probe_interval"


def field_names(cls: type) -> list[str]:
    return [f.name for f in dataclasses.fields(cls)]


STATS = [
    "local_health",
    "packets_received",
    "decode_errors",
    "decrypt_failures",
    "replays_dropped",
    "probes_sent",
    "probes_failed",
    "indirect_probes",
    "missed_nacks",
    "suspicions",
    "refutations",
    "misdirected",
    "name_conflicts",
    "restarts",
    "members_refused",
    "push_pulls",
    "push_pull_failures",
    "push_pulls_served",
    "state_too_large",
    "gossip_too_large",
    "tcp_pings",
    "tcp_ping_acks",
    "user_messages_sent",
    "user_messages_received",
    "user_messages_dropped",
    "user_messages_too_large",
    "user_queue_overflow",
]


def test_types_keep_their_fields() -> None:
    def has(cls: type, *names: str) -> bool:
        return field_names(cls)[: len(names)] == list(names)

    assert has(kinship.Member, "name", "addr", "state", "incarnation", "meta", "epoch")
    assert has(ring.RingChanged, "added", "removed", "suspect", "recovered", "members")
    for event in (
        kinship.MemberJoined,
        kinship.MemberSuspect,
        kinship.MemberRecovered,
        kinship.MemberDead,
        kinship.MemberLeft,
    ):
        assert has(event, "member"), event
    assert has(kinship.MemberUpdated, "member", "previous_meta")
    assert has(kinship.NameConflict, "member", "other_addr")
    assert has(kinship.UserMessage, "sender", "data", "broadcast")
    assert has(kinship.EventsLost, "count")
    assert set(STATS) <= set(field_names(kinship.Stats))
    assert [s.name for s in kinship.State] == ["ALIVE", "SUSPECT", "DEAD", "LEFT"]


async def test_metrics_keep_their_series() -> None:
    async with cluster_of(1) as [node]:
        text = metrics.prometheus_text(node)
    assert "\nkinship_local_health{node=" in text
    for counter in STATS[1:]:
        assert f"\nkinship_{counter}_total{{node=" in text, counter
    for state in ("alive", "suspect", "dead", "left"):
        assert f',state="{state}"}} ' in text, state
    assert "\nkinship_members{node=" in text


LAN: dict[str, Any] = {
    "bind": "0.0.0.0:7946",
    "advertise": None,
    "cluster": "default",
    "seeds": [],
    "resolve_timeout": 30.0,
    "meta": {},
    "insecure_plaintext": False,
    "probe_interval": 1.0,
    "probe_timeout": 0.5,
    "indirect_checks": 3,
    "tcp_fallback_ping": True,
    "suspicion_mult": 4,
    "suspicion_max_mult": 6,
    "expected_confirmations": 3,
    "awareness_max": 8,
    "local_health": True,
    "nacks": True,
    "dynamic_suspicion": True,
    "buddy_system": True,
    "dead_reclaim": 30.0,
    "gossip_interval": 0.2,
    "gossip_nodes": 3,
    "gossip_to_the_dead": 30.0,
    "retransmit_mult": 4,
    "push_pull_interval": 30.0,
    "push_pull_scale": False,
    "push_pull_digest": True,
    "reconnect_interval": 30.0,
    "rejoin_interval": 60.0,
    "udp_max_payload": 1400,
    "max_stream_frame": 8 * 1024 * 1024,
    "max_meta_bytes": 512,
    "tcp_timeout": 10.0,
    "tcp_header_timeout": 1.0,
    "max_inbound_streams": 64,
    "max_inbound_streams_per_ip": 16,
    "max_inbound_bytes_per_ip": None,
    "join_retries": 3,
    "max_members": 8192,
    "max_new_members_per_packet": 1024,
    "max_user_message": 64 * 1024,
    "max_user_broadcast": 256,
    "user_broadcast_queue": 256,
    "event_buffer": 1024,
    "runtime_threads": 1,
}
WAN = {
    "probe_interval": 5.0,
    "probe_timeout": 3.0,
    "suspicion_mult": 6,
    "push_pull_interval": 60.0,
    "gossip_interval": 0.5,
}
LOCAL = {
    "bind": "127.0.0.1:7946",
    "probe_interval": 0.2,
    "probe_timeout": 0.1,
    "suspicion_mult": 3,
    "push_pull_interval": 15.0,
    "tcp_fallback_ping": False,
}


@pytest.mark.parametrize(
    "build, changes",
    [
        (lambda: kinship.Config.lan(keys=[KEY]), {}),
        (lambda: kinship.Config.wan(keys=[KEY]), WAN),
        (lambda: kinship.Config.local(), LOCAL),
    ],
    ids=["lan", "wan", "local"],
)
def test_presets_keep_the_values_in_the_design_doc(
    build: Callable[[], kinship.Config], changes: dict[str, Any]
) -> None:
    cfg = build()
    for field, value in {**LAN, **changes}.items():
        expected = pytest.approx(value) if isinstance(value, float) else value
        assert getattr(cfg, field) == expected, field


def test_durations_take_seconds_or_a_timedelta_and_sizes_take_bytes() -> None:
    cfg = kinship.Config.local(probe_interval=timedelta(seconds=2), max_meta_bytes=256)
    assert cfg.probe_interval == 2.0
    assert cfg.max_meta_bytes == 256


def package_file(name: str) -> Path:
    return Path(kinship.__file__).parent / name


def test_the_package_ships_its_types() -> None:
    assert package_file("py.typed").is_file()
    assert package_file("_kinship.pyi").is_file()


def test_the_stub_lists_every_config_field() -> None:
    tree = ast.parse(package_file("_kinship.pyi").read_text(encoding="utf-8"))
    config = next(n for n in tree.body if isinstance(n, ast.ClassDef) and n.name == "Config")
    stubbed = {n.target.id for n in config.body if isinstance(n, ast.AnnAssign)}
    assert set(LAN) | {"name", "key_ids"} == stubbed
    cfg = kinship.Config.local()
    for field in stubbed:
        assert hasattr(cfg, field), field


async def test_events_never_describe_the_local_node() -> None:
    async with cluster_of(1) as [first]:
        stream = first.events()
        async with kinship.Cluster(local(seeds=[first.local.addr])) as second:
            name = second.local.name
            await next_matching(stream, kinship.MemberJoined, name)
            await first.update_meta(role="first")
            await second.update_meta(role="second")
            await next_matching(stream, kinship.MemberUpdated, name)
            await first.broadcast(b"from the first node")
            await wait_until(lambda: first.stats().probes_sent > 2)
        await next_matching(stream, kinship.MemberLeft, name)
        events = await drain(stream)
        me = first.local.name
        for event in events:
            assert getattr(event, "member", None) is None or event.member.name != me, event
            assert not isinstance(event, kinship.UserMessage), event
