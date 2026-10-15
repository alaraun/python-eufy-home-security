"""Station configuration writes: custom modes, schedule, cross-camera tracking."""

from __future__ import annotations

import time
from collections.abc import AsyncIterator, Awaitable, Callable

import pytest

from eufy_home_security import station as station_module
from eufy_home_security.devices.station_config_support import StationFeature
from eufy_home_security.devices.support import Evidence, Support
from eufy_home_security.exceptions import (
    CommandNotAppliedError,
    ConfigChangedError,
    ModeInUseError,
    UnsupportedError,
)
from eufy_home_security.models import GuardMode
from eufy_home_security.p2p import session as session_module
from eufy_home_security.p2p.session import P2PCredentials, StationSession
from eufy_home_security.station import Station
from eufy_home_security.station_config import ModeInfo
from eufy_home_security.testing import SYNTHETIC
from eufy_home_security.testing.station import FakeStation
from tests.test_station_config import CAMERA, STATION, _cloud_entry, mode_list, schedule

ACCOUNT = SYNTHETIC.account_id
LISTED = mode_list((1, "Home", 1), (0, "Away", 0), (3, "Night watch", 6))
"""The mode list of a HomeBase 3 with Custom 1 named "Night watch"."""


@pytest.fixture
async def fake() -> AsyncIterator[FakeStation]:
    station = FakeStation()
    station.params[255][1224] = "1"
    await station.start()
    yield station
    station.stop()


@pytest.fixture
async def station(fake: FakeStation) -> AsyncIterator[Station]:
    """The synthetic HomeBase 3 whose cloud copy carries the mode list, as on hardware."""

    async def credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(ACCOUNT, "user", fake.ecc_private_key_hex)

    session = StationSession(
        SYNTHETIC.station_sn, credentials, host="127.0.0.1", port=fake.discovery_port
    )
    st = Station(STATION, session, sub_devices=[CAMERA])
    st.apply_cloud_device(_cloud_entry({1256: LISTED}))
    yield st
    await st.async_close()


def sent(fake: FakeStation, frame: int) -> list[bytes]:
    """The body of every ``frame`` write the fake received, as sent."""
    return [body for ftype, body in fake.config_frames_received if ftype == frame]


# ── custom modes ─────────────────────────────────────────────────────────────


async def test_create_writes_the_whole_list_and_shows_the_mode_at_once(
    station: Station, fake: FakeStation
) -> None:
    info = await station.async_create_custom_mode("Garden")

    assert info == ModeInfo(code=GuardMode.CUSTOM_2, name="Garden", icon=7, custom=True)
    assert sent(fake, 1256) == [
        (
            '{"account_id":"' + ACCOUNT + '","mode_id":4,"modes":['
            '{"iconType":1,"mode":1,"title":"Home"},'
            '{"iconType":0,"mode":0,"title":"Away"},'
            '{"iconType":6,"mode":3,"title":"Night watch"},'
            '{"detail":"","iconType":7,"mode":4,"mode_action":67108873,"title":"Garden"}'
            '],"operate_type":100}'
        ).encode()
    ]
    # The dump does not carry 1256 and the cloud copy still holds the old list: the
    # library shows its own write until the cloud's copy changes after it.
    config = station.config
    assert config is not None
    assert config.mode_name(GuardMode.CUSTOM_2) == "Garden"
    station.apply_cloud_device(_cloud_entry({1256: LISTED}))  # the same stale copy
    assert station.config is not None
    assert station.config.is_defined(GuardMode.CUSTOM_2)


async def test_a_newer_cloud_copy_replaces_the_own_write(station: Station) -> None:
    await station.async_create_custom_mode("Garden")
    later = mode_list((1, "Home", 1), (0, "Away", 0), (3, "Night watch", 6), (5, "Lake", 2))
    entry = _cloud_entry({1256: later})
    entry.raw["params"][0]["update_time"] = time.time() + 60
    station.apply_cloud_device(entry)
    config = station.config
    assert config is not None
    assert not config.is_defined(GuardMode.CUSTOM_2)
    assert config.mode_name(GuardMode.CUSTOM_3) == "Lake"


async def test_rename_and_delete_write_modify_and_delete_bodies(
    station: Station, fake: FakeStation
) -> None:
    info = await station.async_rename_custom_mode("custom_1", " Night ", icon=2)
    assert info == ModeInfo(code=GuardMode.CUSTOM_1, name="Night", icon=2, custom=True)
    await station.async_delete_custom_mode(GuardMode.CUSTOM_1)

    assert sent(fake, 1256) == [
        (
            '{"account_id":"' + ACCOUNT + '","mode_id":3,"modes":['
            '{"iconType":1,"mode":1,"title":"Home"},'
            '{"iconType":0,"mode":0,"title":"Away"},'
            '{"iconType":2,"mode":3,"title":"Night"}'
            '],"operate_type":102}'
        ).encode(),
        (
            '{"account_id":"' + ACCOUNT + '","mode_id":3,"modes":['
            '{"iconType":1,"mode":1,"title":"Home"},'
            '{"iconType":0,"mode":0,"title":"Away"}'
            '],"operate_type":101}'
        ).encode(),
    ]
    config = station.config
    assert config is not None
    assert not config.is_defined(GuardMode.CUSTOM_1)


ModeWrite = Callable[[Station], Awaitable[object]]
FULL = mode_list((3, "A", 1), (4, "B", 1), (5, "C", 1))


@pytest.mark.parametrize(
    ("write", "cloud", "station_params", "error", "match"),
    [
        (lambda s: s.async_create_custom_mode(""), {}, {}, ValueError, "empty"),
        (lambda s: s.async_create_custom_mode("x" * 31), {}, {}, ValueError, "at most 30"),
        (lambda s: s.async_create_custom_mode("Away"), {}, {}, ValueError, "already used"),
        (lambda s: s.async_create_custom_mode("Night watch"), {}, {}, ValueError, "already"),
        (lambda s: s.async_create_custom_mode("D", icon=8), {}, {}, ValueError, "icon"),
        (lambda s: s.async_create_custom_mode("D"), {1256: FULL}, {}, ValueError, "all three"),
        (lambda s: s.async_rename_custom_mode("home", "X"), {}, {}, ValueError, "only custom"),
        (lambda s: s.async_rename_custom_mode(5, "X"), {}, {}, ValueError, "does not exist"),
        (lambda s: s.async_delete_custom_mode("away"), {}, {}, ValueError, "only custom"),
        (lambda s: s.async_delete_custom_mode(4), {}, {}, ValueError, "does not exist"),
        (
            lambda s: s.async_delete_custom_mode(3),
            {},
            {1224: "3"},
            ModeInUseError,
            "Night watch is the station's current mode",
        ),
        (
            lambda s: s.async_delete_custom_mode(3),
            {1254: schedule((1, 8, 17, 3))},
            {},
            ModeInUseError,
            "Night watch is used by the schedule",
        ),
        (
            lambda s: s.async_delete_custom_mode(3),
            {},
            {1257: "3"},
            ModeInUseError,
            "outside its time slots",
        ),
        (
            lambda s: s.async_create_custom_mode("D"),
            {1256: "not base64!"},
            {},
            UnsupportedError,
            "cannot be read",
        ),
    ],
)
async def test_mode_list_refusals_send_nothing(
    *,
    station: Station,
    fake: FakeStation,
    write: ModeWrite,
    cloud: dict[int, str],
    station_params: dict[int, str],
    error: type[Exception],
    match: str,
) -> None:
    station.apply_cloud_device(_cloud_entry({1256: LISTED, **cloud}))
    fake.params[255].update(station_params)
    with pytest.raises(error, match=match):
        await write(station)
    assert fake.config_frames_received == []


async def test_a_mode_list_no_source_carries_is_not_overwritten(fake: FakeStation) -> None:
    async def credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(ACCOUNT, "user", fake.ecc_private_key_hex)

    session = StationSession(
        SYNTHETIC.station_sn, credentials, host="127.0.0.1", port=fake.discovery_port
    )
    st = Station(STATION, session, sub_devices=[CAMERA])  # no cloud copy
    try:
        with pytest.raises(UnsupportedError, match="not known yet"):
            await st.async_create_custom_mode("Garden")
    finally:
        await st.async_close()
    assert fake.config_frames_received == []


async def test_unknown_support_refuses_before_any_traffic(
    station: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unknown(self: Station, feature: StationFeature) -> Evidence:
        return Evidence(Support.UNKNOWN, "not on record")

    monkeypatch.setattr(Station, "config_support", unknown)
    with pytest.raises(UnsupportedError, match="custom_modes is not supported"):
        await station.async_create_custom_mode("Garden")
    assert fake.param_queries == 0


async def test_a_stale_revision_sends_nothing(station: Station, fake: FakeStation) -> None:
    config = await station.async_get_config()
    fake.params[255][1224] = "0"  # changed elsewhere
    with pytest.raises(ConfigChangedError) as caught:
        await station.async_create_custom_mode("Garden", expect_revision=config.revision)
    assert caught.value.config.guard_mode is GuardMode.AWAY
    assert fake.config_frames_received == []

    fresh = await station.async_get_config()
    await station.async_create_custom_mode("Garden", expect_revision=fresh.revision)
    assert len(fake.config_frames_received) == 1


async def test_a_dump_that_carries_the_list_is_the_read_back(
    station: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake.params[255][1256] = LISTED
    await station.async_create_custom_mode("Garden")
    assert fake.params[255][1256] == fake.stored_config[1256]

    monkeypatch.setattr(station_module, "READBACK_DELAY", 0)
    fake.apply_settings = False  # receipted, never stored
    with pytest.raises(CommandNotAppliedError, match="1256 not confirmed"):
        await station.async_rename_custom_mode(4, "Yard")


async def test_an_unanswered_write_the_dump_cannot_confirm_is_not_applied(
    station: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(session_module, "COMMAND_TIMEOUT", 0.3)
    fake.config_receipt_code = None
    with pytest.raises(CommandNotAppliedError, match="nothing confirms the write"):
        await station.async_create_custom_mode("Garden")
    config = station.config
    assert config is not None
    assert not config.is_defined(GuardMode.CUSTOM_2)  # not shown as written
