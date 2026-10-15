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
from eufy_home_security.models import GuardMode, ValueSource
from eufy_home_security.p2p import session as session_module
from eufy_home_security.p2p.session import CommandOutcome, P2PCredentials, StationSession
from eufy_home_security.p2p.station_config_codecs import Schedule, ScheduleSlot, Weekday
from eufy_home_security.station import Station
from eufy_home_security.station_config import ModeInfo
from eufy_home_security.testing import SYNTHETIC
from eufy_home_security.testing.station import FakeStation
from tests.test_station_config import (
    CAMERA,
    STATION,
    _cloud_entry,
    b64,
    mode_list,
    pro_alarm_table,
    schedule,
)

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


async def test_a_card_resending_a_slot_to_midnight_changes_nothing(
    station: Station, fake: FakeStation
) -> None:
    """The app's 23:59 reads as an end of 00:00; the same slots back send nothing, and an
    edit next to them keeps the 23:59 as stored."""
    stored = {"end_h": 23, "end_m": 59, "mode_id": 0, "start_h": 22, "start_m": 0, "week": 5}
    station.apply_cloud_device(
        _cloud_entry({1256: LISTED, 1254: b64({"account_id": ACCOUNT, "schedules": [stored]})})
    )
    config = await station.async_get_config()
    assert config.schedule is not None
    (slot,) = config.schedule.slots
    assert (slot.end, slot.ends_at_midnight) == (dt.time(0), True)
    card = ScheduleSlot(Weekday(slot.weekday), slot.start, dt.time(0), slot.mode)
    await station.async_set_schedule(Schedule(account_id=None, slots=(card,)))
    assert fake.config_frames_received == []
    extra = ScheduleSlot(Weekday.MONDAY, dt.time(8), dt.time(9), GuardMode.HOME)
    await station.async_set_schedule(Schedule(account_id=None, slots=(card, extra)))
    assert (
        b'{"end_h":23,"end_m":59,"mode_id":0,"start_h":22,"start_m":0,"week":5}'
        in (sent(fake, 1254)[0])
    )


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
    both = (CAMERA.device_sn, CAMERA_2.device_sn)
    assert await hub.async_set_cross_camera_cameras(both) == both
    assert await hub.async_set_cross_camera_cameras(None) == both  # held: nothing sent
    assert tracking_writes(fake) == [(1072, list(both))]
    assert fake.params[255][1072] == b64([CAMERA.device_sn, CAMERA_2.device_sn])
    assert fake.received[-1]["mChannel"] == 255  # the station itself


async def test_a_paired_doorbell_can_be_tracked_and_a_sensor_cannot(
    hub: Station, fake: FakeStation
) -> None:
    doorbell = dataclasses.replace(CAMERA, device_sn="T8210P0000000001", device_type=7, channel=2)
    st = Station(STATION, hub.session, sub_devices=[SENSOR, doorbell, CAMERA])
    assert st.cross_camera_eligible() == (CAMERA.device_sn, doorbell.device_sn)
    assert await st.async_set_cross_camera_cameras(None) == st.cross_camera_eligible()
    with pytest.raises(UnsupportedError, match="that cross-camera tracking can follow") as err:
        await st.async_set_cross_camera_groups([[CAMERA.device_sn, SENSOR.device_sn]])
    assert err.value.device_sn == SENSOR.device_sn
    assert tracking_writes(fake) == [(1072, [CAMERA.device_sn, doorbell.device_sn])]


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
        await hub.async_set_cross_camera_cameras([CAMERA_2.device_sn, CAMERA.device_sn])


async def test_tracking_needs_two_cameras_as_the_app_does(hub: Station, fake: FakeStation) -> None:
    with pytest.raises(ValueError, match="at least 2 cameras"):
        await hub.async_set_cross_camera_cameras([CAMERA.device_sn])
    lone = Station(STATION, hub.session, sub_devices=[CAMERA, SENSOR])
    with pytest.raises(UnsupportedError, match="fewer than 2 cameras") as err:
        await lone.async_set_cross_camera_cameras(None)
    assert err.value.device_sn == SYNTHETIC.station_sn
    assert tracking_writes(fake) == []


CrossWrite = Callable[[Station], Awaitable[object]]


@pytest.mark.parametrize(
    ("write", "error", "match"),
    [
        (
            lambda s: s.async_set_cross_camera_cameras([FOREIGN_CAMERA]),
            UnsupportedError,
            "is not a camera or doorbell paired",
        ),
        (
            lambda s: s.async_set_cross_camera_cameras([SENSOR.device_sn]),
            UnsupportedError,
            "is not a camera or doorbell paired",
        ),
        (lambda s: s.async_set_cross_camera_cameras([]), ValueError, "at least 2 cameras"),
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
            "is not a camera or doorbell paired",
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


async def _station_of(fake: FakeStation, pn: str) -> Station:
    async def credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(ACCOUNT, "user", fake.ecc_private_key_hex)

    session = StationSession(
        SYNTHETIC.station_sn, credentials, host="127.0.0.1", port=fake.discovery_port
    )
    return Station(dataclasses.replace(STATION, raw={"device_new_pn": pn}), session)


@pytest.mark.parametrize(
    ("pn", "reason"),
    [("T8N00", "WebRTC"), ("T9000", "WebRTC"), ("T7000", "no thing description")],
)
async def test_guard_mode_of_a_model_graded_unknown_is_refused_before_sending(
    fake: FakeStation, pn: str, reason: str
) -> None:
    st = await _station_of(fake, pn)
    try:
        with pytest.raises(UnsupportedError, match=reason) as err:
            await st.async_set_guard_mode("away")
    finally:
        await st.async_close()
    assert err.value.device_sn == st.serial
    assert fake.received == []
    assert fake.param_queries == 0


@pytest.mark.parametrize("pn", ["T8030", "T8024", "T9999", "T8170"])
async def test_guard_mode_of_a_declared_or_unlisted_model_is_sent(
    fake: FakeStation, pn: str
) -> None:
    """A model graded verified or declared, or one the station table does not list (an
    unknown code, a standalone camera), is written as before."""
    st = await _station_of(fake, pn)
    try:
        assert await st.async_set_guard_mode("home") is GuardMode.HOME
    finally:
        await st.async_close()
    assert [c["cmd"] for c in fake.received] == [1224]


async def test_bulk_mode_table_writes_need_known_support(
    station: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    def unknown(self: Station, feature: StationFeature) -> Evidence:
        return Evidence(Support.UNKNOWN, "not on record")

    product_code = Station._product_code

    def off_record(self: Station, serial: str) -> str | None:
        # A station of no model on record lists every per-mode setting.
        return None if serial == self.serial else product_code(self, serial)

    monkeypatch.setattr(Station, "config_support", unknown)
    monkeypatch.setattr(Station, "_product_code", off_record)
    with pytest.raises(UnsupportedError, match="mode_tables is not supported"):
        await station.async_set_mode_actions("away", {CAMERA.device_sn: {"record": True}})
    with pytest.raises(UnsupportedError, match="mode_delays is not supported"):
        await station.async_set_mode_delays("away", entry_s=30)
    with pytest.raises(UnsupportedError, match="mode_tables is not supported"):
        await station.async_set_mode_action("away", "record", True, device_sn=CAMERA.device_sn)
    with pytest.raises(UnsupportedError, match="mode_tables is not supported"):
        await station.async_set_setting("camera_action_away", 1, channel=0)
    with pytest.raises(UnsupportedError, match="mode_delays is not supported"):
        await station.async_set_setting("alarm_delay_away", 30, channel=0)
    assert fake.param_queries == 0
    assert fake.mode_tables_received == []


# ── pro-alarm mode tables (61300-61309) ──────────────────────────────────────

PRO_ALARM_STORE = {0: 61301, 1: 61300, 3: 61307, 4: 61308, 5: 61309}
AWAY_TABLE = pro_alarm_table(0, {0: 9}, alarm=([0], 30))
HOME_TABLE = pro_alarm_table(1, {0: 1}, alarm=([], 0))


@pytest.fixture
async def pro_alarm(fake: FakeStation, monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[Station]:
    """A synthetic T8024 whose camera reports no per-mode params: Away is stored in its
    dump (61301), Home only in the cloud list (61300)."""
    monkeypatch.setattr(station_module, "READBACK_DELAY", 0)
    fake.mode_table_store = PRO_ALARM_STORE
    fake.params[255][61301] = AWAY_TABLE

    async def credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(ACCOUNT, "user", fake.ecc_private_key_hex)

    session = StationSession(
        SYNTHETIC.station_sn, credentials, host="127.0.0.1", port=fake.discovery_port
    )
    hub = dataclasses.replace(STATION, raw={"device_new_pn": "T8024"})
    st = Station(hub, session, sub_devices=[CAMERA])
    st.apply_cloud_device(_cloud_entry({61301: AWAY_TABLE, 61300: HOME_TABLE}, pn="T8024"))
    yield st
    await st.async_close()


def _body(mode: int, action: int, alarm: tuple[list[int], int]) -> dict[str, object]:
    return {
        "account_id": ACCOUNT,
        "mode_id": mode,
        "devices": [{"device_channel": 0, "action": action}],
        "count_down_alarm": {"channel_list": alarm[0], "delay_time": alarm[1]},
        "count_down_arm": {"channel_list": [], "delay_time": 0},
        "siren_sensor_action": [{"device_channel": 0, "action": 0}],
    }


async def test_a_pro_alarm_write_edits_the_stored_table_and_the_dump_confirms_it(
    pro_alarm: Station, fake: FakeStation
) -> None:
    camera = CAMERA.device_sn
    table = await pro_alarm.async_set_mode_actions("away", {camera: {"camera_siren": True}})
    assert fake.mode_tables_received == [_body(0, 11, ([0], 30))]
    assert fake.params[255][61301] == fake.stored_config[61301] != AWAY_TABLE
    assert (dict(table.actions), dict(table.alarm_delays)) == ({0: 11}, {0: 30})
    config = pro_alarm.config
    assert config is not None
    away = config.mode_tables[GuardMode.AWAY]
    assert away is not None
    assert [(d.action, d.alarm_delay) for d in away.devices] == [(11, 30)]
    state = pro_alarm.state
    assert state is not None
    assert state.setting("camera_action_away", device_sn=camera) == 11


async def test_a_pro_alarm_table_the_dump_lacks_is_confirmed_by_the_receipt(
    pro_alarm: Station, fake: FakeStation
) -> None:
    """Home lives in the cloud list only: the zero receipt confirms the write and the sent
    body shows at once."""
    camera = CAMERA.device_sn
    mask = await pro_alarm.async_set_mode_action("home", "camera_siren", True, device_sn=camera)
    assert mask == 3
    assert fake.mode_tables_received == [_body(1, 3, ([], 0))]
    assert 61300 not in fake.params[255]
    assert 61300 in fake.stored_config
    config = pro_alarm.config
    assert config is not None
    home = config.mode_tables[GuardMode.HOME]
    assert home is not None
    assert [d.action for d in home.devices] == [3]
    assert config.sources["mode_tables.home"] is ValueSource.P2P

    outcome = await pro_alarm.async_set_setting("camera_action_home", 1, device_sn=camera)
    assert outcome is CommandOutcome.APPLIED
    assert fake.mode_tables_received[-1] == _body(1, 1, ([], 0))


async def test_a_pro_alarm_write_the_dump_does_not_show_is_not_applied(
    pro_alarm: Station, fake: FakeStation
) -> None:
    fake.apply_settings = False  # receipted, never stored
    with pytest.raises(CommandNotAppliedError, match="61301 not confirmed"):
        await pro_alarm.async_set_mode_actions("away", {CAMERA.device_sn: {"camera_siren": True}})


async def test_a_pro_alarm_station_offers_no_delays(pro_alarm: Station, fake: FakeStation) -> None:
    """The eufy app shows no entry or exit delay on a pro-alarm station."""
    with pytest.raises(UnsupportedError, match="arming_support_arm_delay false"):
        await pro_alarm.async_set_mode_delays("away", entry_s=60)
    with pytest.raises(UnsupportedError, match="unknown setting 'alarm_delay_home'"):
        await pro_alarm.async_set_setting("alarm_delay_home", 30, device_sn=CAMERA.device_sn)
    assert pro_alarm.has_setting("alarm_delay_home", CAMERA.device_sn) is False
    assert fake.mode_tables_received == []


@pytest.mark.parametrize(
    ("station_params", "cloud", "match"),
    [
        ({}, {}, "stores no away mode table .*1239.*no source carries"),
        ({61301: b64({"mode_id": 0})}, {}, "stored away mode table cannot be read"),
        (
            {
                61301: b64(
                    {
                        **_body(0, 9, ([], 0)),
                        "siren_sensor_action": [{"device_channel": 0, "action": 1}],
                    }
                )
            },
            {},
            "siren accessory",
        ),
    ],
)
async def test_pro_alarm_writes_without_a_usable_table_send_nothing(
    *,
    pro_alarm: Station,
    fake: FakeStation,
    station_params: dict[int, str],
    cloud: dict[int, str],
    match: str,
) -> None:
    del fake.params[255][61301]
    fake.params[255].update(station_params)
    pro_alarm.apply_cloud_device(_cloud_entry(cloud, pn="T8024"))
    with pytest.raises(UnsupportedError, match=match):
        await pro_alarm.async_set_mode_actions("away", {CAMERA.device_sn: {"record": True}})
    assert fake.mode_tables_received == []


async def test_a_homebase_3_never_writes_from_a_stored_copy(
    station: Station, fake: FakeStation
) -> None:
    """The HomeBase 3 path is unchanged: without the devices' params its stored copy
    (1158) does not stand in for the table."""
    away = b64({**_body(0, 9, ([], 0)), "account_id": ACCOUNT})
    station.apply_cloud_device(_cloud_entry({1256: LISTED, 1158: away}))
    fake.params[255][61301] = AWAY_TABLE
    with pytest.raises(UnsupportedError, match=r"\(no device reports param 1239\)$"):
        await station.async_set_mode_actions("away", {CAMERA.device_sn: {"record": True}})
    assert fake.mode_tables_received == []


async def test_a_pro_alarm_station_whose_devices_report_their_params_writes_as_before(
    pro_alarm: Station, fake: FakeStation
) -> None:
    """The field shape of a T8024: the camera reports 1239; the table comes from it and
    the per-device read-back confirms it, the stored copy untouched."""
    fake.mode_table_store = None
    fake.params[0].update({1239: "5", 1167: "0", 1172: "0"})
    mask = await pro_alarm.async_set_mode_action(
        "away", "camera_siren", True, device_sn=CAMERA.device_sn
    )
    assert mask == 7
    assert fake.mode_tables_received == [_body(0, 7, ([], 0))]
    assert fake.params[0][1239] == "7"
    assert fake.params[255][61301] == AWAY_TABLE
