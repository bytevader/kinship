import os
import socket
import sys
import threading
import time
import warnings
from collections.abc import Callable

import pytest

import kinship
from conftest import WAIT, local, names, wait_until_sync
from kinship import blocking


def test_blocking_api_from_several_threads() -> None:
    with blocking.Cluster(local()) as a, blocking.Cluster(local(seeds=[a.local.addr])) as b:
        wait_until_sync(lambda: names(a) == names(b) == {a.local.name, b.local.name})
        stop = threading.Event()
        errors: list[BaseException] = []
        updates: list[kinship.MemberUpdated] = []
        ticks = 0

        def guard(fn):
            def run() -> None:
                try:
                    fn()
                except BaseException as e:
                    errors.append(e)

            return run

        @guard
        def reader() -> None:
            nonlocal ticks
            for event in a.events(timeout=0.1):
                if event is None:
                    ticks += 1
                    if stop.is_set():
                        return
                elif isinstance(event, kinship.MemberUpdated):
                    updates.append(event)

        @guard
        def poller() -> None:
            while not stop.is_set():
                assert a.local.name in names(a)
                a.member(b.local.name)
                a.stats()
                a.keyring.key_ids()

        @guard
        def writer() -> None:
            for i in range(10):
                b.update_meta(n=str(i), timeout=WAIT)
            b.set_meta({"n": "done"}, timeout=WAIT)

        threads = [threading.Thread(target=f) for f in (reader, poller, poller, writer)]
        for t in threads:
            t.start()
        threads[-1].join(WAIT)
        wait_until_sync(lambda: a.member(b.local.name).meta.get("n") == "done")
        wait_until_sync(lambda: any(u.member.meta.get("n") == "done" for u in updates))
        stop.set()
        for t in threads:
            t.join(WAIT)
            assert not t.is_alive()
        assert errors == []
        assert ticks > 0


def test_blocking_close_leaves_first_and_timeouts_raise() -> None:
    with blocking.Cluster(local()) as a:
        events = a.events(timeout=0.2)
        b = blocking.Cluster(local(seeds=[a.local.addr])).start(timeout=WAIT)
        wait_until_sync(lambda: b.local.name in names(a))
        # A seed that accepts the connection and never answers keeps join() waiting.
        with socket.create_server(("127.0.0.1", 0)) as silent:
            seed = f"127.0.0.1:{silent.getsockname()[1]}"
            with pytest.raises(TimeoutError):
                b.join([seed], timeout=0.3)
        b.close()
        deadline = time.monotonic() + WAIT
        for event in events:
            assert time.monotonic() < deadline
            if isinstance(event, kinship.MemberLeft):
                assert event.member.name == b.local.name
                break
        b.close()  # closing again does nothing
        with pytest.raises(kinship.KinshipClosed):
            b.update_meta(x="y")


def test_blocking_keyring_and_events_end_on_close() -> None:
    key = os.urandom(32)
    a = blocking.Cluster(local(keys=[key])).start()
    events = a.events()
    new = os.urandom(32)
    a.keyring.install(new, timeout=WAIT)
    a.keyring.use(new, timeout=WAIT)
    a.keyring.remove(key, timeout=WAIT)
    assert len(a.keyring.key_ids()) == 1
    a.close()
    assert list(events) == []


def in_forked_child(steps: list[tuple[str, Callable[[], object]]]) -> tuple[int, list[str]]:
    """Runs `steps` in a forked child and returns its exit code and the steps it finished.

    Each step passes by raising nothing; the child exits 0 only if every step passed.
    """
    read, write = os.pipe()
    with warnings.catch_warnings():
        warnings.simplefilter("ignore", DeprecationWarning)  # fork with threads running
        pid = os.fork()
    if pid == 0:  # pragma: no cover - runs in the child
        code = 1
        try:
            os.close(read)
            for name, step in steps:
                step()
                os.write(write, f"{name}\n".encode())
            code = 0
        except BaseException as e:
            os.write(write, f"error in next step: {e!r}\n".encode())
        finally:
            os._exit(code)
    os.close(write)
    deadline = time.monotonic() + WAIT
    while True:
        done, status = os.waitpid(pid, os.WNOHANG)
        if done:
            break
        if time.monotonic() > deadline:
            os.kill(pid, 9)
            pytest.fail("the forked child hung")
        time.sleep(0.05)
    with os.fdopen(read) as out:
        finished = out.read().splitlines()
    return os.waitstatus_to_exitcode(status), finished


def raises_closed(call: Callable[[], object]) -> Callable[[], None]:
    def step() -> None:
        with pytest.raises(kinship.KinshipClosed):
            call()

    return step


@pytest.mark.skipif(sys.platform == "win32", reason="Windows has no fork")
def test_a_forked_child_raises_instead_of_hanging() -> None:
    with blocking.Cluster(local()) as parent:
        stream = parent.events()
        steps = [
            ("members", raises_closed(parent.members)),
            ("update_meta", raises_closed(lambda: parent.update_meta(x="y", timeout=1.0))),
            ("events", raises_closed(lambda: next(stream))),
        ]
        code, finished = in_forked_child(steps)
        assert (code, finished) == (0, [name for name, _ in steps])
        assert parent.local.name in names(parent), "the parent is unaffected"


@pytest.mark.skipif(
    sys.platform != "linux", reason="fork without exec is only safe on Linux, not macOS"
)
def test_a_forked_child_can_start_its_own_cluster() -> None:
    def start_one() -> None:
        with blocking.Cluster(local()) as child:
            assert child.local.name in names(child)

    with blocking.Cluster(local()):
        code, finished = in_forked_child([("start", start_one)])
        assert (code, finished) == (0, ["start"])
