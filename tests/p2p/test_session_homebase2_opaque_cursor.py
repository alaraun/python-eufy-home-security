"""Opaque HomeBase 2 recording IDs can be paged with an explicit day hint."""

from datetime import date
from types import SimpleNamespace

import pytest

from eufy_home_security.p2p.session import StationSession
from eufy_home_security.station import Station

CAMERA = "T8210TESTDEVICE"
OPAQUE_ID = 2818608
DAY = date(2026, 10, 25)


@pytest.mark.asyncio
async def test_session_opaque_id_resumes_on_explicit_day() -> None:
    seen: list[tuple[date, int | None]] = []

    async def capture(day: date, *_args: object, **kwargs: object) -> None:
        seen.append((day, kwargs["start_id"]))

    fake = SimpleNamespace(serial="T8010TESTSTATION", _history_day=capture)
    rows = await StationSession.async_list_history(
        fake,
        "20261024",
        "20261026",
        count=10,
        before=OPAQUE_ID,
        before_day=DAY,
        device_sn=CAMERA,
        page_size=50,
    )
    assert rows == []
    assert seen
    assert seen[0] == (DAY, OPAQUE_ID)
    assert all(day <= DAY for day, _ in seen)


@pytest.mark.asyncio
async def test_session_opaque_id_requires_day() -> None:
    fake = SimpleNamespace(serial="T8010TESTSTATION")
    with pytest.raises(ValueError, match="carries no day"):
        await StationSession.async_list_history(
            fake,
            "20261025",
            count=10,
            before=OPAQUE_ID,
            page_size=50,
        )


@pytest.mark.asyncio
async def test_station_forwards_opaque_id_and_real_day() -> None:
    captured: list[object] = []

    async def capture(_start: str, _end: str, **kwargs: object) -> list[object]:
        captured.append(kwargs)
        return []

    fake = SimpleNamespace(
        channel_for=lambda _sn: 5,
        is_standalone=False,
        devices=[SimpleNamespace(device_sn=CAMERA)],
        session=SimpleNamespace(async_list_history=capture),
    )
    rows = await Station.async_list_recordings(
        fake,
        CAMERA,
        days=7,
        limit=10,
        before=OPAQUE_ID,
        before_day=DAY,
    )
    assert rows == []
    assert len(captured) == 1
    assert captured[0]["before"] == OPAQUE_ID
    assert captured[0]["before_day"] == DAY
    assert captured[0]["device_sn"] == CAMERA
