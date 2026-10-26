"""Native HomeBase 2 (T8010) history filtering, with other stations unchanged."""

import asyncio
from datetime import date
from types import SimpleNamespace

import pytest

from eufy_home_security.p2p import session as p2p_session
from eufy_home_security.p2p.session import StationSession
from eufy_home_security.station import Station

CAMERA = "T8210TESTDEVICE"


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("station_sn", "verb", "native_camera"),
    [
        ("T8010TESTSTATION", "local", CAMERA),
        ("T8410TESTDEVICE", "local", None),
        ("T8030TESTSTATION", "history", None),
    ],
)
async def test_only_homebase2_forwards_native_camera_filter(
    monkeypatch: pytest.MonkeyPatch,
    station_sn: str,
    verb: str,
    native_camera: str | None,
) -> None:
    observed: list[str | None] = []

    async def capture_day(*_args: object, **kwargs: object) -> None:
        observed.append(kwargs["device_sn"] if isinstance(kwargs["device_sn"], str) else None)

    query_verb = (
        p2p_session.DB_QUERY_LOCAL_EVENTS if verb == "local" else p2p_session.DB_QUERY_HISTORY
    )
    monkeypatch.setattr(p2p_session, "history_query_verb", lambda _sn: query_verb)
    fake = SimpleNamespace(serial=station_sn, _history_day=capture_day)

    rows = await StationSession.async_list_history(fake, "20261025", device_sn=CAMERA, page_size=50)

    assert rows == []
    assert observed == [native_camera]


@pytest.mark.asyncio
async def test_history_day_forwards_camera_to_every_page() -> None:
    captured: list[str | None] = []

    async def page(
        _day: date, _cursor: int, _page_size: int, _timeout: float | None, **kwargs: object
    ) -> tuple[list[object], None]:
        sn = kwargs["device_sn"]
        captured.append(sn if isinstance(sn, str) else None)
        return [], None

    fake = SimpleNamespace(_history_page=page, _log_name="test")
    rows: list[object] = []
    await StationSession._history_day(
        fake,
        date(2026, 10, 25),
        rows,
        set(),
        verb=p2p_session.DB_QUERY_LOCAL_EVENTS,
        count=10,
        keep=None,
        device_sn=CAMERA,
        page_size=50,
        timeout=1.0,
    )
    assert captured == [CAMERA]
    assert rows == []


@pytest.mark.asyncio
@pytest.mark.parametrize("camera", [CAMERA, None])
async def test_native_request_includes_camera_only_when_requested(
    monkeypatch: pytest.MonkeyPatch, camera: str | None
) -> None:
    sent: list[dict[str, object]] = []

    async def connected() -> None:
        return None

    async def request(send: object, _match: object, **_kwargs: object) -> tuple[list[object], None]:
        assert callable(send)
        send()
        return [], None

    def device_message(
        _account: str, _command: int, payload: dict[str, object], *, channel: int
    ) -> dict[str, object]:
        assert channel == p2p_session.STATION_CHANNEL
        return payload

    monkeypatch.setattr(p2p_session, "device_msg", device_message)
    fake = SimpleNamespace(
        async_connect=connected,
        _require_creds=lambda: SimpleNamespace(account_id="ACCOUNT"),
        _send_secure=sent.append,
        _require_transport=lambda: None,
        _history_lock=asyncio.Lock(),
        _request=request,
        _log_name="test",
    )

    await StationSession._history_page(
        fake,
        date(2026, 10, 25),
        0,
        50,
        1.0,
        verb=p2p_session.DB_QUERY_LOCAL_EVENTS,
        device_sn=camera,
    )

    assert len(sent) == 1
    payload = sent[0]
    assert payload["cmd"] == p2p_session.DB_QUERY_LOCAL_EVENTS
    nested = payload["payload"]
    assert isinstance(nested, dict)
    assert nested.get("device_info") == ([{"device_sn": CAMERA}] if camera else None)
    assert nested["count"] == 50


@pytest.mark.asyncio
async def test_station_recording_listing_forwards_camera_and_keeps_local_filter() -> None:
    observed: list[str | None] = []

    async def list_history(_start: str, _end: str, **kwargs: object) -> list[object]:
        sn = kwargs["device_sn"]
        observed.append(sn if isinstance(sn, str) else None)
        assert callable(kwargs["keep"])
        return []

    fake = SimpleNamespace(
        channel_for=lambda _sn: 5,
        is_standalone=False,
        devices=[SimpleNamespace(device_sn=CAMERA)],
        session=SimpleNamespace(async_list_history=list_history),
    )
    rows = await Station.async_list_recordings(fake, CAMERA, days=1, limit=5)
    assert rows == []
    assert observed == [CAMERA]
