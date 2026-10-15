"""Station configuration writes: custom modes, schedule, cross-camera tracking."""

from __future__ import annotations

import dataclasses
import datetime as dt
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
from eufy_home_security.p2p.station_config_codecs import Schedule, ScheduleSlot, Weekday
from eufy_home_security.station import Station
from eufy_home_security.station_config import ModeInfo
from eufy_home_security.testing import SYNTHETIC
from eufy_home_security.testing.station import FakeStation
from tests.test_station_config import CAMERA, STATION, _cloud_entry, b64, mode_list, schedule

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


# ── schedule ─────────────────────────────────────────────────────────────────


def week(*slots: tuple[int, int, int, GuardMode]) -> Schedule:
    """A schedule of ``(weekday, start hour, end hour, mode)`` slots."""
    return Schedule(
        account_id=None,
        slots=tuple(ScheduleSlot(Weekday(w), dt.time(s), dt.time(e), m) for w, s, e, m in slots),
    )


async def test_set_schedule_writes_the_whole_table_and_shows_it_at_once(
    station: Station, fake: FakeStation
) -> None:
    station.apply_cloud_device(_cloud_entry({1256: LISTED, 1254: schedule((1, 8, 17, 0))}))
    new = week((1, 8, 17, GuardMode.AWAY), (2, 22, 23, GuardMode.CUSTOM_1))

    written, default = await station.async_set_schedule(new)

    assert sent(fake, 1254) == [
        (
            '{"account_id":"' + ACCOUNT + '","schedules":['
            '{"end_h":17,"end_m":0,"mode_id":0,"start_h":8,"start_m":0,"week":1},'
            '{"end_h":23,"end_m":0,"mode_id":3,"start_h":22,"start_m":0,"week":2}]}'
        ).encode()
    ]
    assert written is not None
    assert written.slots == new.slots
    assert default is None  # the fake's dump carries no 1257
    assert fake.ecb_received == []
    config = station.config
    assert config is not None
    assert config.schedule == written


async def test_a_changed_default_is_the_scalar_1257_write_read_back(
    station: Station, fake: FakeStation
) -> None:
    fake.params[255][1257] = "63"
    _, default = await station.async_set_schedule(week(), default_mode="home")
    assert default is GuardMode.HOME
    assert fake.ecb_received == [(1257, 255, 1)]
    assert fake.params[255][1257] == "1"
    assert sent(fake, 1254) == [('{"account_id":"' + ACCOUNT + '","schedules":[]}').encode()]


async def test_an_unchanged_schedule_and_default_send_nothing(
    station: Station, fake: FakeStation
) -> None:
    fake.params[255][1257] = "63"
    station.apply_cloud_device(_cloud_entry({1256: LISTED, 1254: schedule((1, 8, 17, 0))}))
    await station.async_set_schedule(week((1, 8, 17, GuardMode.AWAY)), default_mode="disarmed")
    assert fake.config_frames_received == []
    assert fake.ecb_received == []


@pytest.mark.parametrize(
    ("schedule_", "default", "match"),
    [
        (week((1, 8, 9, GuardMode.CUSTOM_2)), None, "do not exist: custom_2"),
        (week(), GuardMode.CUSTOM_3, "Custom 3 is a mode the station does not have"),
        (week(), GuardMode.SCHEDULE, "cannot be schedule"),
        ([], None, "must be a Schedule"),
    ],
)
async def test_schedule_refusals_send_nothing(
    station: Station, fake: FakeStation, schedule_: Schedule, default: GuardMode | None, match: str
) -> None:
    with pytest.raises(ValueError, match=match):
        await station.async_set_schedule(schedule_, default_mode=default)
    assert fake.config_frames_received == []
    assert fake.ecb_received == []


async def test_schedule_unknown_support_and_stale_revision_send_nothing(
    station: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = await station.async_get_config()
    fake.params[255][1224] = "0"
    with pytest.raises(ConfigChangedError):
        await station.async_set_schedule(week(), expect_revision=config.revision)

    def unknown(self: Station, feature: StationFeature) -> Evidence:
        return Evidence(Support.UNKNOWN, "not on record")

    monkeypatch.setattr(Station, "config_support", unknown)
    with pytest.raises(UnsupportedError, match="schedule is not supported"):
        await station.async_set_schedule(week())
    assert fake.config_frames_received == []


# ── cross-camera tracking ────────────────────────────────────────────────────

CAMERA_2 = dataclasses.replace(CAMERA, device_sn="T8160P2000067891", name="Back", channel=1)
SENSOR = dataclasses.replace(
    CAMERA, device_sn="T8910P0000000001", device_type=10, name="Path", channel=16
)
FOREIGN_CAMERA = "T8160P2000067892"


@pytest.fixture
async def hub(fake: FakeStation) -> AsyncIterator[Station]:
    """The synthetic HomeBase 3 with two cameras and a motion sensor."""
    fake.reply_to_settings = True  # a 1350 setting answered with code 0

    async def credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(ACCOUNT, "user", fake.ecc_private_key_hex)

    session = StationSession(
        SYNTHETIC.station_sn, credentials, host="127.0.0.1", port=fake.discovery_port
    )
    st = Station(STATION, session, sub_devices=[CAMERA, CAMERA_2, SENSOR])
    yield st
    await st.async_close()


def tracking_writes(fake: FakeStation) -> list[tuple[int, object]]:
    return [(c["cmd"], c["payload"]) for c in fake.received if c["cmd"] in (1072, 1073)]


async def test_choose_tracking_cameras_writes_the_list_and_reads_it_back(
    hub: Station, fake: FakeStation
) -> None:
    assert await hub.async_set_cross_camera_cameras([CAMERA_2.device_sn]) == (CAMERA_2.device_sn,)
    assert await hub.async_set_cross_camera_cameras(None) == (
        CAMERA.device_sn,
        CAMERA_2.device_sn,
    )
    await hub.async_set_cross_camera_cameras(None)  # already held: nothing sent
    assert tracking_writes(fake) == [
        (1072, [CAMERA_2.device_sn]),
        (1072, [CAMERA.device_sn, CAMERA_2.device_sn]),
    ]
    assert fake.params[255][1072] == b64([CAMERA.device_sn, CAMERA_2.device_sn])
    assert fake.received[-1]["mChannel"] == 255  # the station itself


async def test_tracking_groups_write_the_whole_list(hub: Station, fake: FakeStation) -> None:
    groups = await hub.async_set_cross_camera_groups([[CAMERA.device_sn, CAMERA_2.device_sn]])
    assert groups == ((CAMERA.device_sn, CAMERA_2.device_sn),)
    assert await hub.async_set_cross_camera_groups([]) == ()
    assert tracking_writes(fake) == [
        (1073, [{"value": [CAMERA.device_sn, CAMERA_2.device_sn]}]),
        (1073, []),
    ]
    config = hub.config
    assert config is not None
    assert config.cross_camera is not None
    assert config.cross_camera.groups == ()


async def test_a_tracking_write_the_dump_does_not_show_is_not_applied(
    hub: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(station_module, "READBACK_DELAY", 0)
    fake.params[255][1072] = b64([CAMERA.device_sn])
    fake.apply_settings = False
    with pytest.raises(CommandNotAppliedError, match="1072 not confirmed"):
        await hub.async_set_cross_camera_cameras([CAMERA_2.device_sn])


CrossWrite = Callable[[Station], Awaitable[object]]


@pytest.mark.parametrize(
    ("write", "error", "match"),
    [
        (
            lambda s: s.async_set_cross_camera_cameras([FOREIGN_CAMERA]),
            UnsupportedError,
            "is not a camera paired",
        ),
        (
            lambda s: s.async_set_cross_camera_cameras([SENSOR.device_sn]),
            UnsupportedError,
            "is not a camera paired",
        ),
        (lambda s: s.async_set_cross_camera_cameras([]), ValueError, "at least one camera"),
        (
            lambda s: s.async_set_cross_camera_cameras([CAMERA.device_sn] * 2),
            ValueError,
            "listed twice",
        ),
        (lambda s: s.async_set_cross_camera_cameras(CAMERA.device_sn), ValueError, "not one"),
        (
            lambda s: s.async_set_cross_camera_groups([[CAMERA.device_sn], [CAMERA.device_sn]]),
            ValueError,
            "one tracking group only",
        ),
        (
            lambda s: s.async_set_cross_camera_groups([[CAMERA.device_sn, FOREIGN_CAMERA]]),
            UnsupportedError,
            "is not a camera paired",
        ),
        (lambda s: s.async_set_cross_camera_groups([[]]), ValueError, "at least one camera"),
    ],
)
async def test_cross_camera_refusals_send_nothing(
    hub: Station, fake: FakeStation, write: CrossWrite, error: type[Exception], match: str
) -> None:
    with pytest.raises(error, match=match):
        await write(hub)
    assert fake.received == []
    assert fake.param_queries == 0


async def test_cross_camera_unknown_support_and_stale_revision_send_nothing(
    hub: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    config = await hub.async_get_config()
    fake.params[255][1224] = "0"
    with pytest.raises(ConfigChangedError):
        await hub.async_set_cross_camera_groups([], expect_revision=config.revision)

    def groups_unknown(self: Station, feature: StationFeature) -> Evidence:
        known = feature is not StationFeature.CROSS_CAMERA_GROUPS
        return Evidence(Support.DECLARED if known else Support.UNKNOWN, "test")

    monkeypatch.setattr(Station, "config_support", groups_unknown)
    with pytest.raises(UnsupportedError, match="cross_camera_groups is not supported"):
        await hub.async_set_cross_camera_groups([])
    assert tracking_writes(fake) == []


# ── guard mode and bulk mode-table refusals ──────────────────────────────────


async def test_a_custom_mode_the_known_list_lacks_is_not_set(
    station: Station, fake: FakeStation
) -> None:
    await station.async_update()
    with pytest.raises(UnsupportedError, match="has no Custom 2") as err:
        await station.async_set_guard_mode("custom_2")
    assert err.value.device_sn == station.serial
    assert [c for c in fake.received if c["cmd"] == 1224] == []
    assert await station.async_set_guard_mode("custom_1") is GuardMode.CUSTOM_1


async def test_bulk_mode_table_writes_need_known_support(
    station: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unknown(self: Station, feature: StationFeature) -> Evidence:
        return Evidence(Support.UNKNOWN, "not on record")

    monkeypatch.setattr(Station, "config_support", unknown)
    with pytest.raises(UnsupportedError, match="mode_tables is not supported"):
        await station.async_set_mode_actions("away", {CAMERA.device_sn: {"record": True}})
    with pytest.raises(UnsupportedError, match="mode_delays is not supported"):
        await station.async_set_mode_delays("away", entry_s=30)
    assert fake.param_queries == 0
    assert fake.mode_tables_received == []
