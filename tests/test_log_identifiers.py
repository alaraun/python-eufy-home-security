"""No identifier in any log record, wire dumps included, across the library's main flows."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Iterator

import pytest

from eufy_home_security import GuardMode
from eufy_home_security._logging import set_wire_logging
from eufy_home_security.events import EventSource, SecurityEvent
from eufy_home_security.p2p.xzyh import FrameCipher
from eufy_home_security.storage import MemoryStore
from eufy_home_security.testing import SYNTHETIC, FakeCloud, FakeStation, build_eufy_security

RECORD_ID = 2023101500001
THUMB = "/zx/hdd_data0/Camera00/202310/20231015120000/snapshort.jpg"

FORBIDDEN = (
    SYNTHETIC.station_sn,
    SYNTHETIC.camera_sn,
    SYNTHETIC.did,
    SYNTHETIC.did.split("-", 1)[1],  # the DID's number and suffix
    SYNTHETIC.account_id,
    SYNTHETIC.email,
    SYNTHETIC.password,
    SYNTHETIC.disk_serial,
    SYNTHETIC.disk_label,
    "Home Base",  # the fake cloud's station name
    "Front",  # the fake camera's name
    "/zx/",
)


@pytest.fixture
def wire_on() -> Iterator[None]:
    set_wire_logging(True)
    try:
        yield
    finally:
        set_wire_logging(False)


async def _run_flows() -> None:
    """Device refresh, parameter dumps, an arm, a push, storage, a still, a history
    lookup and a live open, on the shipped fakes."""
    fake = FakeStation()
    fake.params[255][1224] = "63"
    fake.rows = [{"record_id": RECORD_ID, "device_sn": SYNTHETIC.camera_sn, "thumb_path": THUMB}]
    fake.images[THUMB] = b"\xff\xd8thumb\xff\xd9"
    await fake.start()
    try:
        eufy = build_eufy_security(
            email=SYNTHETIC.email,
            store=MemoryStore(),
            cloud=FakeCloud.for_stations(fake),
            stations={fake.serial: fake},
        )
        await eufy.async_discover(refresh=True)
        await eufy.async_start(push=False)
        station = eufy.stations[fake.serial]
        await station.async_set_guard_mode(GuardMode.HOME)
        await station.session.async_get_params()  # reports the changed 1224
        fake.push_camera_event(3102, cipher=FrameCipher.GCM)
        await asyncio.sleep(0.1)
        await station.async_get_storage()
        event = SecurityEvent(
            source=EventSource.P2P,
            station_sn=SYNTHETIC.station_sn,
            device_sn=SYNTHETIC.camera_sn,
            channel=0,
            record_id=RECORD_ID,
        )
        await station.async_event_thumbnail(event)
        async with await station.session.async_open_live(0) as stream:
            await anext(stream)
        await eufy.async_close()
    finally:
        fake.stop()


def _leaks(caplog: pytest.LogCaptureFixture) -> list[tuple[str, str]]:
    return [
        (needle, record.getMessage())
        for record in caplog.records
        for needle in FORBIDDEN
        if needle in record.getMessage()
    ]


@pytest.mark.usefixtures("wire_on")
async def test_no_identifier_in_any_log_record(caplog: pytest.LogCaptureFixture) -> None:
    caplog.set_level(logging.DEBUG, logger="eufy_home_security")
    await _run_flows()
    assert _leaks(caplog) == []
    assert any(
        "param ch255/1224" in r.getMessage() and " / " in r.getMessage() for r in caplog.records
    )


@pytest.mark.usefixtures("wire_on")
async def test_leak_check_sees_unmasked_keys(
    caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Guards the test above: with key masking off, identifiers do reach the log."""
    monkeypatch.setattr("eufy_home_security._logging.IDENTIFYING_KEYS", frozenset())
    caplog.set_level(logging.DEBUG, logger="eufy_home_security")
    await _run_flows()
    assert _leaks(caplog)
