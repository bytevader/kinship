import logging
import time
from collections.abc import Iterator

import pytest

import kinship
from conftest import wait_until
from kinship import _kinship


@pytest.fixture
def python_logs() -> Iterator[None]:
    yield
    _kinship.route_to_stderr()


async def test_logs_reach_the_kinship_logger(
    caplog: pytest.LogCaptureFixture, python_logs: None
) -> None:
    caplog.set_level(logging.WARNING, logger="kinship")
    kinship.log_to_python()
    cfg = kinship.Config.lan(bind="127.0.0.1:0", insecure_plaintext=True)
    async with kinship.Cluster(cfg):
        await wait_until(
            lambda: any("without encryption" in r.getMessage() for r in caplog.records)
        )
    record = next(r for r in caplog.records if "without encryption" in r.getMessage())
    assert record.name == "kinship" and record.levelno == logging.WARNING
    assert "kinship" in record.rust_target  # type: ignore[attr-defined]


def test_logs_drain_from_a_thread_without_an_event_loop(
    caplog: pytest.LogCaptureFixture, python_logs: None
) -> None:
    caplog.set_level(logging.INFO, logger="kinship")
    kinship.log_to_python()
    with kinship.blocking.Cluster(kinship.Config.local(bind="127.0.0.1:0")) as c:
        name = c.local.name

    deadline = time.monotonic() + 20
    while not any("node started" in r.getMessage() for r in caplog.records):
        assert time.monotonic() < deadline, "no log record arrived"
        time.sleep(0.05)
    assert any(name in r.getMessage() for r in caplog.records)
