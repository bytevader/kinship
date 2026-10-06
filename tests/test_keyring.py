import asyncio
import base64
import os

import pytest

import kinship
from conftest import cluster_of, drain, local, names, wait_until
from kinship import _kinship


def key_id(cfg_key: bytes) -> str:
    return kinship.Config.lan(keys=[cfg_key]).key_ids[0]


async def test_three_step_rotation_across_three_nodes() -> None:
    old, new = os.urandom(32), base64.b64encode(os.urandom(32)).decode()
    async with cluster_of(3, keys=[old]) as nodes:
        streams = [n.events() for n in nodes]
        everyone = {n.local.name for n in nodes}
        for step in ("install", "use", "remove"):
            arg = old if step == "remove" else new
            await asyncio.gather(*(getattr(n.keyring, step)(arg) for n in nodes))
            await asyncio.sleep(1.0)  # let packets sealed before the step land
            assert all(names(n) == everyone for n in nodes), step

        assert all(n.keyring.key_ids() == [key_id(base64.b64decode(new))] for n in nodes)
        for node, stream in zip(nodes, streams, strict=True):
            seen = await drain(stream)
            dead = [e for e in seen if isinstance(e, kinship.MemberDead)]
            assert dead == [], f"{node.local.name} saw {seen}"
        # Still talking with only the new key.
        await nodes[1].update_meta(rotated="yes")
        await wait_until(lambda: nodes[0].member(nodes[1].local.name).meta.get("rotated") == "yes")


async def test_keyring_refusals_and_bad_keys() -> None:
    a, b = os.urandom(32), os.urandom(32)
    async with kinship.Cluster(local(keys=[a])) as node:
        ring = node.keyring
        assert ring.key_ids() == [key_id(a)]
        with pytest.raises(kinship.KeyringError):
            await ring.use(b)
        with pytest.raises(kinship.KeyringError):
            await ring.remove(a)
        await ring.install(b)
        await ring.install(b)  # installing twice does nothing
        assert ring.key_ids() == [key_id(a), key_id(b)]
        await ring.remove(os.urandom(32))  # not installed: already gone
        with pytest.raises(ValueError, match="32 bytes"):
            await ring.install(b"short")
        assert a.hex() not in repr(ring) and repr(ring).startswith("Keyring(")

    async with kinship.Cluster(local()) as plain:
        with pytest.raises(kinship.KeyringError):
            await plain.keyring.install(a)
        assert plain.keyring.key_ids() == []


async def test_nodes_with_another_key_cannot_join() -> None:
    async with kinship.Cluster(local(keys=[os.urandom(32)])) as a:
        cfg = local(keys=[os.urandom(32)], seeds=[a.local.addr], join_retries=1, tcp_timeout=1.0)
        async with kinship.Cluster(cfg) as outsider:
            with pytest.raises(kinship.JoinError):
                await asyncio.wait_for(outsider.join(), 20)
            assert names(a) == {a.local.name}
        assert a.stats().decrypt_failures > 0


def test_keygen_prints_a_fresh_32_byte_key() -> None:
    import subprocess
    import sys

    def keygen() -> str:
        out = subprocess.run(
            [sys.executable, "-m", "kinship", "keygen"],
            capture_output=True,
            text=True,
            timeout=60,
            check=True,
        )
        return out.stdout.strip()

    first, second = keygen(), keygen()
    assert len(base64.b64decode(first, validate=True)) == 32
    assert len(base64.b64decode(second, validate=True)) == 32
    assert first != second
    assert kinship.Config.lan(keys=[first]).key_ids
    assert len(base64.b64decode(_kinship.generate_key())) == 32
