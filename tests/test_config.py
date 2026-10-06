import base64
import dataclasses
from datetime import timedelta

import pytest

import kinship

KEY = bytes(range(32))


def test_presets_differ_only_in_timing() -> None:
    lan = kinship.Config.lan(keys=[KEY])
    wan = kinship.Config.wan(keys=[KEY])
    local = kinship.Config.local()
    assert (lan.preset, wan.preset, local.preset) == ("lan", "wan", "local")
    assert (lan.probe_interval, lan.probe_timeout) == (1.0, 0.5)
    assert (wan.probe_interval, wan.probe_timeout, wan.push_pull_interval) == (5.0, 3.0, 60.0)
    assert local.probe_interval == pytest.approx(0.2)
    assert lan.tcp_fallback_ping and not local.tcp_fallback_ping
    assert lan.bind == "0.0.0.0:7946" and local.bind == "127.0.0.1:7946"
    assert lan.event_buffer == 1024 and lan.max_meta_bytes == 512 and lan.runtime_threads == 1
    assert kinship.Config(keys=[KEY]).preset == "lan"


def test_fields_are_set_by_keyword_and_configs_are_frozen() -> None:
    cfg = kinship.Config.wan(
        keys=[KEY],
        name="edge-12",
        probe_interval=4.0,
        dead_reclaim=timedelta(minutes=2),
        seeds=["10.0.0.5:7946", "[fd00::5]:7946"],
        meta={"role": "cache", "zone": "eu-1"},
        cluster="stores-prod",
    )
    assert cfg.name == "edge-12"
    assert cfg.probe_interval == 4.0
    assert cfg.dead_reclaim == 120.0
    assert cfg.seeds == ["10.0.0.5:7946", "[fd00::5]:7946"]
    assert cfg.meta == {"role": "cache", "zone": "eu-1"}
    assert cfg.cluster == "stores-prod"
    with pytest.raises(AttributeError):
        cfg.name = "other"  # type: ignore[misc]

    moved = cfg.replace(name="edge-13", probe_interval=timedelta(seconds=6))
    assert (moved.name, moved.probe_interval, moved.cluster) == ("edge-13", 6.0, "stores-prod")
    assert cfg.name == "edge-12", "replace() returns a copy"


def test_default_names_are_generated_once_per_config() -> None:
    a, b = kinship.Config.local(), kinship.Config.local()
    assert a.name != b.name
    assert a.replace(probe_interval=0.3).name == a.name
    assert a.replace(name=None).name != a.name


@pytest.mark.parametrize(
    ("fields", "field"),
    [
        ({"probe_timeout": 5.0}, "probe_timeout"),
        ({"probe_interval": -1.0}, "probe_interval"),
        ({"probe_interval": "1s"}, "probe_interval"),
        ({"gossip_interval": 2.0}, "gossip_interval"),
        ({"name": "x" * 65}, "name"),
        ({"name": ""}, "name"),
        ({"bind": "localhost"}, "bind"),
        ({"seeds": "127.0.0.1:1"}, "seeds"),
        ({"seeds": ["nowhere"]}, "seeds"),
        ({"event_buffer": 0}, "event_buffer"),
        ({"event_buffer": True}, "event_buffer"),
        ({"indirect_checks": -1}, "indirect_checks"),
        ({"nacks": 1}, "nacks"),
        ({"meta": {"k": "v" * 600}}, "meta"),
        ({"meta": {"": "v"}}, "meta"),
        ({"meta": {"k": 1}}, "meta"),
        ({"keys": [b"short"]}, "keys"),
        ({"keys": ["not base64!"]}, "keys"),
        ({"keys": KEY}, "keys"),
        ({"runtime_threads": 0}, "runtime_threads"),
        ({"cluster": "c" * 256}, "cluster"),
    ],
)
def test_bad_fields_raise_config_error_naming_the_field(fields: dict, field: str) -> None:
    with pytest.raises(kinship.ConfigError) as err:
        kinship.Config.local(**fields)
    assert err.value.field == field
    assert field in str(err.value)
    assert isinstance(err.value, ValueError)


def test_unknown_fields_are_a_type_error() -> None:
    with pytest.raises(TypeError, match="probe_intervall"):
        kinship.Config.local(probe_intervall=1.0)


def test_keys_are_required_beyond_loopback() -> None:
    with pytest.raises(kinship.ConfigError) as err:
        kinship.Config.lan()
    assert err.value.field == "keys"
    with pytest.raises(kinship.ConfigError):
        kinship.Config.lan(bind="127.0.0.1:0")
    with pytest.raises(kinship.ConfigError):
        kinship.Config.local(bind="0.0.0.0:0")
    assert kinship.Config.local(bind="0.0.0.0:0", insecure_plaintext=True)
    assert kinship.Config.lan(keys=[base64.b64encode(KEY).decode()])


def test_keys_are_never_shown() -> None:
    text = base64.b64encode(KEY).decode()
    cfg = kinship.Config.lan(keys=[KEY, text.rstrip("=")])
    shown = repr(cfg)
    assert text not in shown and KEY.hex() not in shown
    assert len(cfg.key_ids) == 2 and cfg.key_ids[0] == cfg.key_ids[1]
    assert all(len(i) == 8 and int(i, 16) >= 0 for i in cfg.key_ids)
    assert cfg.key_ids[0] in shown
    with pytest.raises(AttributeError):
        _ = cfg.keys
    with pytest.raises(kinship.ConfigError) as err:
        kinship.Config.lan(keys=[text[:-4]])
    assert text[:-4] not in str(err.value)


def test_repr_shows_changed_fields() -> None:
    cfg = kinship.Config.local(name="a", probe_interval=0.3)
    assert repr(cfg).startswith("Config.local(name='a'")
    assert "probe_interval=0.3" in repr(cfg)
    assert "probe_timeout" not in repr(cfg)


def test_stats_and_member_types_are_frozen() -> None:
    m = kinship.Member("a", "127.0.0.1:1", kinship.State.ALIVE, 0)
    with pytest.raises(dataclasses.FrozenInstanceError):
        m.name = "b"  # type: ignore[misc]
    assert hash(m) == hash("a")
    assert {m, dataclasses.replace(m, state=kinship.State.SUSPECT)} != {m}
    assert kinship.MemberJoined.__match_args__ == ("member",)
    assert kinship.MemberUpdated.__match_args__ == ("member", "previous_meta")
    assert kinship.NameConflict.__match_args__ == ("member", "other_addr")
    assert kinship.EventsLost.__match_args__ == ("count",)
    assert repr(kinship.MemberJoined(m)) == "MemberJoined(a)"
