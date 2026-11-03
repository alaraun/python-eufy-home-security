from __future__ import annotations

import base64
import dataclasses
import json
from collections.abc import AsyncIterator

import pytest

from eufy_home_security.cloud.models import CloudDevice
from eufy_home_security.detection_delivery import (
    DetectionDelivery,
    DetectionDeliveryReport,
    detection_delivery,
    table_mode,
)
from eufy_home_security.events import Event, StationConfigChanged
from eufy_home_security.models import STATION_CHANNEL, GuardMode
from eufy_home_security.p2p.params import ParamDump
from eufy_home_security.p2p.session import P2PCredentials, StationSession
from eufy_home_security.station import Station
from eufy_home_security.station_config import StationConfig, build_station_config
from eufy_home_security.testing import SYNTHETIC
from eufy_home_security.testing.station import FakeStation

HUB = CloudDevice(
    device_sn=SYNTHETIC.station_sn,
    device_type=18,
    name="Home Base",
    p2p_did=SYNTHETIC.did,
    main_sw_version="3.8.7.4",
)
CAMERA = CloudDevice(
    device_sn=SYNTHETIC.camera_sn,
    device_type=19,
    name="Front",
    station_sn=SYNTHETIC.station_sn,
    channel=0,
)
INDOOR_SN = "T8417P0000000001"
BATTERY_SN = "T8162P0000000001"
SENSOR_SN = "T8910P0000000001"
KEYPAD_SN = "T8960P0000000001"
DOORBELL_SN = "T8210P0000000001"


def _paired(serial: str, device_type: int, channel: int) -> CloudDevice:
    return CloudDevice(
        device_sn=serial,
        device_type=device_type,
        name="paired",
        station_sn=SYNTHETIC.station_sn,
        channel=channel,
    )


INDOOR = _paired(INDOOR_SN, 105, 1)
BATTERY = _paired(BATTERY_SN, 26, 2)
SENSOR = _paired(SENSOR_SN, 10, 16)
KEYPAD = _paired(KEYPAD_SN, 11, 17)
DOORBELL = _paired(DOORBELL_SN, 7, 3)


def _b64(obj: object) -> str:
    return base64.b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode()


def _stored_table(mode: int, actions: dict[int, int]) -> str:
    """A stored mode table (1157-1161, 1177) of ``actions``, delays off."""
    return _b64(
        {
            "account_id": SYNTHETIC.account_id,
            "mode_id": mode,
            "devices": [{"device_channel": ch, "action": a} for ch, a in actions.items()],
            "count_down_alarm": {"channel_list": [], "delay_time": 0},
            "count_down_arm": {"channel_list": [], "delay_time": 0},
            "siren_sensor_action": [{"device_channel": ch, "action": 0} for ch in actions],
        }
    )


_CUSTOM_1_LISTED = _b64(
    {
        "account_id": SYNTHETIC.account_id,
        "mode_id": 3,
        "modes": [{"iconType": 6, "mode": 3, "title": "Night watch"}],
    }
)


def _offline(device: CloudDevice = HUB, sub_devices: tuple[CloudDevice, ...] = ()) -> Station:
    async def no_credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        raise AssertionError("not connecting")

    session = StationSession(device.device_sn, no_credentials, host=None)
    return Station(device, session, sub_devices=sub_devices)


def _config(
    station: dict[int, str], blocks: dict[int, dict[int, str]] | None = None
) -> StationConfig:
    """The configuration of the synthetic HomeBase 3 from its own block and device blocks."""
    dump = ParamDump()
    dump.ingest(
        {
            "params": [
                {"dev_type": dev, "param_type": pid, "param_value": value}
                for dev, params in {STATION_CHANNEL: station, **(blocks or {})}.items()
                for pid, value in params.items()
            ]
        }
    )
    hub = _offline(sub_devices=(CAMERA, INDOOR, BATTERY))
    return build_station_config(hub._state(dump))


# Two cameras behind a HomeBase 3: Away records and notifies (9), Home records only (1).
_HB3 = _config({1224: "0"}, {0: {1239: "9", 1225: "1"}, 1: {1239: "9", 1225: "1"}})


def _report(
    config: StationConfig | None,
    mode: GuardMode | int | None,
    serial: str = SYNTHETIC.camera_sn,
    *,
    notification_action: bool = True,
) -> DetectionDeliveryReport:
    return detection_delivery(
        config, serial, mode=mode, has_notification_action=notification_action
    )


# ── the rule ─────────────────────────────────────────────────────────────────


def test_a_camera_whose_action_notifies_in_the_mode_in_force_is_sent() -> None:
    report = _report(_HB3, GuardMode.AWAY)
    assert report.delivery is DetectionDelivery.SENT
    assert (report.mode, report.action) == (GuardMode.AWAY, 9)
    assert report.sending_modes == (GuardMode.AWAY,)


def test_a_camera_whose_action_lacks_notification_is_not_sent_in_that_mode() -> None:
    report = _report(_HB3, GuardMode.HOME, INDOOR_SN)
    assert report.delivery is DetectionDelivery.NOT_SENT_IN_MODE
    assert (report.mode, report.action) == (GuardMode.HOME, 1)
    assert report.sending_modes == (GuardMode.AWAY,)
    assert "Notification is off in Home" in report.reason


def test_bits_other_than_notification_do_not_count() -> None:
    """143 without 8 sounds every alarm and records, but sends nothing."""
    config = _config({1224: "0"}, {0: {1239: str(143 & ~8)}})
    assert _report(config, GuardMode.AWAY).delivery is DetectionDelivery.NOT_SENT_IN_MODE
    config = _config({1224: "0"}, {0: {1239: "8"}})
    assert _report(config, GuardMode.AWAY).delivery is DetectionDelivery.SENT


def test_a_device_the_reported_table_lacks_reads_as_notifying() -> None:
    """As the eufy app reads a missing action: on."""
    report = _report(_HB3, GuardMode.HOME, BATTERY_SN)
    assert report.delivery is DetectionDelivery.SENT
    assert report.action is None
    assert report.sending_modes == (GuardMode.HOME, GuardMode.AWAY)
    assert "read as on" in report.reason


def test_a_stored_table_names_a_device_without_a_block_by_the_cloud_channel() -> None:
    """A battery camera whose block the dump lacks is graded from the stored tables."""
    config = _config(
        {
            1224: "0",
            1158: _stored_table(int(GuardMode.AWAY), {0: 9, 2: 1}),
            1157: _stored_table(int(GuardMode.HOME), {0: 1, 2: 9}),
        },
        {0: {1101: "100"}},
    )
    report = _report(config, GuardMode.AWAY, BATTERY_SN)
    assert report.delivery is DetectionDelivery.NOT_SENT_IN_MODE
    assert report.action == 1
    assert report.sending_modes == (GuardMode.HOME,)


def test_a_mode_without_a_reported_table_is_unknown_and_never_sends() -> None:
    config = _config({1224: "3", 1256: _CUSTOM_1_LISTED}, {0: {1239: "9", 1225: "1"}})
    assert config.mode_tables[GuardMode.CUSTOM_1] is None
    report = _report(config, GuardMode.CUSTOM_1)
    assert report.delivery is DetectionDelivery.UNKNOWN
    assert report.action is None
    assert report.sending_modes == (GuardMode.AWAY,)
    assert "reports no Night watch table" in report.reason


def test_a_custom_mode_with_notification_is_sent_and_listed_in_the_app_order() -> None:
    config = _config({1224: "3", 1256: _CUSTOM_1_LISTED}, {0: {1239: "9", 1225: "9", 1148: "9"}})
    report = _report(config, GuardMode.CUSTOM_1)
    assert report.delivery is DetectionDelivery.SENT
    assert report.sending_modes == (GuardMode.HOME, GuardMode.AWAY, GuardMode.CUSTOM_1)


@pytest.mark.parametrize("mode", [GuardMode.OFF, GuardMode.DISARMED])
def test_off_and_disarmed_read_the_disarmed_table(mode: GuardMode) -> None:
    config = _config(
        {1224: str(int(mode)), 1177: _stored_table(63, {0: 0, 1: 8})}, {0: {1239: "9"}}
    )
    camera = _report(config, mode)
    assert camera.delivery is DetectionDelivery.NOT_SENT_IN_MODE
    assert (camera.mode, camera.action) == (mode, 0)
    indoor = _report(config, mode, INDOOR_SN)
    assert indoor.delivery is DetectionDelivery.SENT
    assert indoor.sending_modes == (GuardMode.AWAY, GuardMode.DISARMED)


@pytest.mark.parametrize(
    ("mode", "why"),
    [
        (None, "not known"),
        (GuardMode.SCHEDULE, "no per-device actions"),
        (GuardMode.GEOFENCE, "no per-device actions"),
        (99, "no per-device actions"),
    ],
)
def test_a_mode_in_force_without_actions_is_unknown(mode: GuardMode | int | None, why: str) -> None:
    report = _report(_HB3, mode)
    assert report.delivery is DetectionDelivery.UNKNOWN
    assert report.mode == mode
    assert why in report.reason
    assert report.sending_modes == (GuardMode.AWAY,)


def test_without_a_configuration_everything_is_unknown() -> None:
    report = _report(None, GuardMode.AWAY)
    assert report.delivery is DetectionDelivery.UNKNOWN
    assert report.sending_modes == ()
    assert "not known yet" in report.reason


def test_a_device_without_a_notification_action_is_unknown() -> None:
    report = _report(_HB3, GuardMode.HOME, notification_action=False)
    assert report.delivery is DetectionDelivery.UNKNOWN
    assert report.action is None
    assert report.sending_modes == ()


@pytest.mark.parametrize(
    ("mode", "table"),
    [
        (GuardMode.AWAY, GuardMode.AWAY),
        (GuardMode.HOME, GuardMode.HOME),
        (GuardMode.CUSTOM_3, GuardMode.CUSTOM_3),
        (GuardMode.DISARMED, GuardMode.DISARMED),
        (GuardMode.OFF, GuardMode.DISARMED),
        (GuardMode.SCHEDULE, None),
        (GuardMode.GEOFENCE, None),
        (7, None),
    ],
)
def test_table_mode(mode: GuardMode | int, table: GuardMode | None) -> None:
    assert table_mode(mode) is table


# ── Station.detection_delivery ───────────────────────────────────────────────


@pytest.fixture
async def fake() -> AsyncIterator[FakeStation]:
    station = FakeStation()
    station.params[STATION_CHANNEL][1224] = "1"
    station.params[0] = {1239: "9", 1225: "1"}
    station.params[1] = {1239: "9", 1225: "1"}
    station.params[16] = {1239: "8", 1225: "0"}
    station.params[17] = {1101: "100"}
    station.params[3] = {1239: "9", 1225: "1"}
    await station.start()
    yield station
    station.stop()


@pytest.fixture
async def station(fake: FakeStation) -> AsyncIterator[Station]:
    async def credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", fake.ecc_private_key_hex)

    session = StationSession(
        SYNTHETIC.station_sn, credentials, host="127.0.0.1", port=fake.discovery_port
    )
    st = Station(HUB, session, sub_devices=[CAMERA, INDOOR, SENSOR, KEYPAD, DOORBELL])
    yield st
    await st.async_close()


async def test_every_paired_device_with_a_notification_action_is_graded(
    station: Station,
) -> None:
    await station.async_update()
    grades = {
        sn: station.detection_delivery(sn).delivery
        for sn in (
            SYNTHETIC.camera_sn,
            INDOOR_SN,
            SENSOR_SN,
            DOORBELL_SN,
            KEYPAD_SN,
            SYNTHETIC.station_sn,
        )
    }
    assert grades == {
        SYNTHETIC.camera_sn: DetectionDelivery.NOT_SENT_IN_MODE,
        INDOOR_SN: DetectionDelivery.NOT_SENT_IN_MODE,
        SENSOR_SN: DetectionDelivery.NOT_SENT_IN_MODE,
        DOORBELL_SN: DetectionDelivery.NOT_SENT_IN_MODE,
        KEYPAD_SN: DetectionDelivery.UNKNOWN,
        SYNTHETIC.station_sn: DetectionDelivery.UNKNOWN,
    }
    assert station.detection_delivery(SENSOR_SN).sending_modes == (GuardMode.AWAY,)
    assert station.detection_delivery(DOORBELL_SN).sending_modes == (GuardMode.AWAY,)


async def test_a_configuration_built_once_grades_every_device(station: Station) -> None:
    await station.async_update()
    config = station.config
    assert config is not None
    station.session.note_guard_mode(GuardMode.AWAY)
    for sn in (SYNTHETIC.camera_sn, DOORBELL_SN):
        assert station.detection_delivery(sn, config=config) == station.detection_delivery(sn)
    stale = dataclasses.replace(config, mode_tables={})
    report = station.detection_delivery(SYNTHETIC.camera_sn, config=stale)
    assert report.delivery is DetectionDelivery.UNKNOWN


async def test_a_device_not_paired_here_is_unknown(station: Station) -> None:
    await station.async_update()
    report = station.detection_delivery(BATTERY_SN)
    assert report == DetectionDeliveryReport(
        device_sn=BATTERY_SN,
        delivery=DetectionDelivery.UNKNOWN,
        mode=None,
        action=None,
        sending_modes=(),
        reason="the device is not paired to this station",
    )


async def test_an_action_change_emits_a_config_change_and_flips_the_report(
    station: Station, fake: FakeStation
) -> None:
    await station.async_update()
    events: list[Event] = []
    station.subscribe(events.append)
    fake.params[0][1225] = "9"
    await station.async_update()
    [changed] = [e for e in events if isinstance(e, StationConfigChanged)]
    assert "mode_tables" in changed.fields
    report = station.detection_delivery(SYNTHETIC.camera_sn)
    assert (report.delivery, report.action) == (DetectionDelivery.SENT, 9)
    assert report.sending_modes == (GuardMode.HOME, GuardMode.AWAY)


async def test_the_mode_the_session_last_saw_wins_over_the_last_dump(station: Station) -> None:
    """A mode report or push moves the mode in force before the next dump does."""
    await station.async_update()
    config = station.config
    assert config is not None
    assert config.effective_mode is GuardMode.HOME
    station.session.note_guard_mode(GuardMode.AWAY)
    report = station.detection_delivery(SYNTHETIC.camera_sn)
    assert (report.mode, report.delivery) == (GuardMode.AWAY, DetectionDelivery.SENT)


def test_without_a_state_a_paired_camera_is_unknown() -> None:
    report = _offline(sub_devices=(CAMERA,)).detection_delivery(SYNTHETIC.camera_sn)
    assert report.delivery is DetectionDelivery.UNKNOWN
    assert "not known yet" in report.reason


def test_the_mode_falls_back_to_the_configurations() -> None:
    """Before the session saw a mode, the configuration's (the cloud copy) answers."""
    hub = _offline(
        dataclasses.replace(
            HUB,
            raw={"params": [{"param_type": 1224, "param_value": "0", "update_time": 1.7e9}]},
        ),
        sub_devices=(CAMERA,),
    )
    dump = ParamDump()
    dump.ingest(
        {
            "params": [
                {"dev_type": 0, "param_type": 1239, "param_value": "9"},
                {"dev_type": STATION_CHANNEL, "param_type": 1135, "param_value": "0"},
            ]
        }
    )
    hub.apply_cloud_device(hub.device)
    hub.session._param_state.merge_dump(dump, "test", 0.0)
    assert hub.session.active_mode is None
    report = hub.detection_delivery(SYNTHETIC.camera_sn)
    assert (report.mode, report.delivery) == (GuardMode.AWAY, DetectionDelivery.SENT)


def test_a_standalone_camera_without_a_reported_table_is_unknown() -> None:
    serial = "T8170P0000000000"
    device = CloudDevice(
        device_sn=serial,
        station_sn=serial,
        p2p_did=SYNTHETIC.did,
        device_type=48,
        channel=0,
        name="standalone",
    )
    st = _offline(device)
    dump = ParamDump()
    dump.ingest({"params": [{"dev_type": STATION_CHANNEL, "param_type": 1224, "param_value": "0"}]})
    st.session._param_state.merge_dump(dump, "test", 0.0)
    report = st.detection_delivery(serial)
    assert report.delivery is DetectionDelivery.UNKNOWN
    assert report.mode is GuardMode.AWAY
    assert "reports no Away table" in report.reason
