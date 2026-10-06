"""A panic inside the node's actor, through a private hook that only builds with the
`test-hooks` feature have: `uv run maturin develop --features test-hooks`. Release wheels leave
it out, so the test skips there unless KINSHIP_TEST_HOOKS=1 says the hook must be present."""

import os

import pytest

import kinship
from conftest import local, next_event
from kinship import _kinship

HOOKED = hasattr(_kinship.Node, "_panic_actor")

if os.environ.get("KINSHIP_TEST_HOOKS") == "1" and not HOOKED:
    raise RuntimeError("KINSHIP_TEST_HOOKS=1 but this build has no test hooks")

pytestmark = pytest.mark.skipif(not HOOKED, reason="needs a build with --features test-hooks")


async def test_an_actor_panic_ends_the_event_iterator_with_kinship_closed() -> None:
    a = await kinship.Cluster(local()).start()
    events = a.events()
    a._node._panic_actor()  # type: ignore[union-attr,attr-defined]  # private, not in the stubs
    with pytest.raises(kinship.KinshipClosed):
        await next_event(events)
    with pytest.raises(kinship.KinshipClosed):
        await next_event(a.events())
    with pytest.raises(kinship.KinshipClosed):
        await a.set_meta({"k": "v"})
    await a.close()  # closing a failed cluster does not raise
