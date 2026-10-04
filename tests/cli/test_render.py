from __future__ import annotations

import dataclasses
import json
from datetime import UTC, datetime
from typing import Any

from eufy_home_security.cli import render
from eufy_home_security.cli.render import render_network
from eufy_home_security.cloud.models import CloudDevice
from eufy_home_security.devices.recipes import PresetPosition
from eufy_home_security.events import (
    AccountMismatch,
    AlarmChanged,
    AlarmStopSource,
    CameraBusyChanged,
    CloudProblem,
    ConnectionChanged,
    CredentialsRefreshed,
    DevicesChanged,
    EventSource,
    GuardModeChanged,
    ParamChanged,
    PresetsChanged,
    PushChanged,
    SecurityEvent,
    StationStateChanged,
    StorageChanged,
    ZoomChanged,
)
from eufy_home_security.exceptions import CommunicationError, SessionReplacedError
from eufy_home_security.models import FrameCipher, GuardMode
from eufy_home_security.network import HostSource, LanPath
from eufy_home_security.p2p.did import Did
from eufy_home_security.p2p.discovery import DiscoveredStation
from eufy_home_security.p2p.storage_info import parse_storage_info
from eufy_home_security.station import StationState, SubDeviceState
from eufy_home_security.testing import SYNTHETIC
from eufy_home_security.testing.station import synthetic_storage_body

NOW = datetime(2026, 1, 2, 3, 4, 5, tzinfo=UTC)


def _state(**overrides: object) -> StationState:
    camera = SubDeviceState(
        channel=0,
        serial=SYNTHETIC.camera_sn,
        name="Front",
        battery=87,
        wifi_rssi=-52,
        firmware="3.4.3.0",
        params={1101: "87", 1142: "-52"},
    )
    base: dict[str, object] = {
        "serial": SYNTHETIC.station_sn,
        "guard_mode": GuardMode.HOME,
        "firmware": "3.8.7.4",
        "devices": {0: camera},
        "params": {1224: "1", 1176: SYNTHETIC.station_ip, 1190: "42"},
    }
    base.update(overrides)
    return StationState(**base)  # type: ignore[arg-type]


def test_device_list_and_state_events_render_and_serialise() -> None:
    changed = DevicesChanged(station_sn=SYNTHETIC.station_sn, added=(SYNTHETIC.camera_sn,))
    assert (
        render.render_event(changed, now=NOW, show_serials=False)
        == "[03:04:05] T8030***2345 paired devices changed: added T8160***7890"
    )
    snapshot = StationStateChanged(station_sn=SYNTHETIC.station_sn, state=_state())
    line = render.render_event(snapshot, now=NOW, show_serials=False)
    assert line.startswith("[03:04:05] T8030***2345 state: guard mode")
    assert line.endswith("1 device(s)")
    data = json.loads(json.dumps(render.event_json(snapshot)))
    assert data["type"] == "StationStateChanged"
    assert data["state"]["devices"]["0"]["battery"] == 87


def test_storage_events_render_and_serialise() -> None:
    body = synthetic_storage_body()
    body["hdd_info"]["parted_status"] = 2
    changed = StorageChanged(station_sn=SYNTHETIC.station_sn, storage=parse_storage_info(body))
    assert render.render_event(changed, now=NOW, show_serials=False) == (
        "[03:04:05] T8030***2345 storage: disk 14.16 GB used of 232.89 GB FORMATTING"
    )
    del body["hdd_info"]
    bare = StorageChanged(station_sn=SYNTHETIC.station_sn, storage=parse_storage_info(body))
    assert render.render_event(bare, now=NOW, show_serials=False).endswith("storage: no disk")
    assert "Disk:          none reported" in render.render_storage(bare.storage, name="Home Base")
    data = json.loads(json.dumps(render.event_json(changed)))
    assert data["storage"]["disk"]["parted_status"] == 2


def test_serials_are_redacted_unless_asked() -> None:
    assert render.fmt_serial(SYNTHETIC.station_sn, False) == "T8030***2345"
    assert render.fmt_serial(SYNTHETIC.station_sn, True) == SYNTHETIC.station_sn
    assert render.fmt_serial(None, True) == "?"


def test_status_card() -> None:
    text = render.render_status(
        _state(), name="Home Base", host=SYNTHETIC.station_ip, show_serials=False
    )
    assert text.splitlines()[0] == 'HomeBase 3 (S380) "Home Base"  T8030***2345'
    assert "  Firmware:    3.8.7.4" in text
    assert "  Guard mode:  Home (1)" in text
    assert f"  Address:     {SYNTHETIC.station_ip}" in text
    assert "eMMC" in text
    assert "42%" in text
    assert (
        '  • ch 0  "Front"  T8160***7890  eufyCam 3 (S330)  battery 87%  RSSI -52 dBm  fw 3.4.3.0'
        in text
    )
    assert SYNTHETIC.station_sn not in text


def test_status_card_names_cloud_listed_and_newer_models() -> None:
    from eufy_home_security import ModelStatus  # noqa: PLC0415

    models = {
        "T9999": ModelStatus("T9999", "cloud-listed", None, 3),
        "T8160": ModelStatus("T8160", "bundled", 123, 124),
        "T8030": ModelStatus("T8030", "bundled", 50, 50),
    }
    text = render.render_status(_state(), name="x", host=None, show_serials=False, models=models)
    assert text.splitlines()[-2:] == [
        "  T8160: vendor data newer than bundled (td 124 > 123)",
        "  T9999: not in bundled data: settings listed read-only",
    ]
    assert "T8030:" not in text


def test_status_card_marks_an_offline_device_and_its_values_as_last_known() -> None:
    sensor = SubDeviceState(
        channel=16,
        serial=None,
        name="Path",
        battery=30,
        sub1g_rssi=-76,
        firmware=None,
        online=False,
        params={1131: "0", 1101: "30", 1141: "-76"},
    )
    coded = dataclasses.replace(sensor, channel=17, name="Gate", offline_code=3)
    state = _state(devices={16: sensor, 17: coded})
    text = render.render_status(state, name="x", host=None, show_serials=False)
    assert '  • ch 16  "Path"  OFFLINE  last battery 30%  last RSSI -76 dBm' in text
    assert '  • ch 17  "Gate"  OFFLINE (code 3)  last battery 30%' in text
    data = render.status_json(state, name="x")
    assert (data["devices"]["16"]["online"], data["devices"]["17"]["offline_code"]) == (False, 3)


def test_status_card_shows_charging_source_and_low_battery() -> None:
    camera = SubDeviceState(
        channel=1,
        serial=None,
        name="Yard",
        battery=93,
        firmware=None,
        power_source=4,
        solar_intensity=7,
        siren_actions={GuardMode.AWAY: 1},
        params={},
    )
    plugged = dataclasses.replace(camera, channel=2, name="Door", power_source=0)
    sensor = dataclasses.replace(
        camera, channel=16, name="Path", power_source=None, low_battery=True
    )
    state = _state(devices={1: camera, 2: plugged, 16: sensor})
    text = render.render_status(state, name="x", host=None, show_serials=False)
    assert '  • ch 1  "Yard"  battery 93%  charging (solar) (4)' in text
    assert '  • ch 2  "Door"  battery 93%  not charging (0)' in text
    assert '  • ch 16  "Path"  battery 93%  LOW BATTERY' in text
    data = render.status_json(state, name="x")["devices"]["1"]
    assert (data["charging"], data["solar_charging"], data["solar_intensity"]) == (True, True, 7)
    assert data["siren_actions"] == {"away": 1}


def test_status_card_unknown_mode_and_no_devices() -> None:
    text = render.render_status(
        _state(guard_mode=99, devices={}, firmware=None), name="x", host=None, show_serials=True
    )
    assert "Guard mode:  unknown code 99" in text
    assert "Firmware:    unknown" in text
    assert "Address" not in text
    assert "•" not in text


def test_raw_params_use_catalog_names() -> None:
    text = render.render_raw_params(_state())
    assert "=== station (dev_type 255) — 3 params ===" in text
    assert "1224" in text
    assert "SET_ARMING" in text
    assert "=== device (dev_type 0) — 2 params ===" in text
    assert "GET_BATTERY" in text


def test_status_json_is_serialisable_and_unredacted() -> None:
    data = render.status_json(_state(), name="Home Base")
    text = json.dumps(data)
    assert SYNTHETIC.station_sn in text
    assert SYNTHETIC.camera_sn in text
    assert data["guard_mode"] == "home"


def test_devices_listing() -> None:
    devices = [
        CloudDevice(device_sn=SYNTHETIC.station_sn, device_type=18, name="Home Base"),
        CloudDevice(
            device_sn=SYNTHETIC.camera_sn,
            device_type=19,
            name="Front",
            station_sn=SYNTHETIC.station_sn,
            channel=0,
        ),
        CloudDevice(device_sn="T9999P2000000001", device_type=1, name="Mystery"),
    ]
    text = render.render_devices(devices, show_serials=False)
    assert "HomeBase 3" in text
    assert "eufyCam 3" in text
    assert "T9999***0001" in text
    assert SYNTHETIC.station_sn not in text


def test_discovered() -> None:
    text = render.render_discovered(
        [DiscoveredStation(ip=SYNTHETIC.station_ip, port=12345, did=Did.parse(SYNTHETIC.did))]
    )
    assert SYNTHETIC.station_ip in text
    assert SYNTHETIC.did in text
    assert "No station" in render.render_discovered([])


def test_events_listing_media_and_station_rows() -> None:
    rows: list[dict[str, Any]] = [
        {
            "device_sn": SYNTHETIC.camera_sn,
            "start_time": 1_700_000_000_000,
            "video_type": 3,
            "thumb_path": "/zx/thumb.jpg",
            "storage_path": "/zx/clip.zxvideo",
        },
        {
            "station_sn": SYNTHETIC.station_sn,
            "create_time": 1_700_000_100,
            "str_extra": json.dumps({"msg_type": 9, "arm_mode": 0, "user_name": "someone"}),
        },
        {"str_extra": "not json"},
    ]
    text = render.render_events(rows, "20260101", "20260102", show_serials=False)
    assert text.startswith("3 record(s), 20260101 to 20260102:")
    assert "type 3" in text
    assert "thumb: /zx/thumb.jpg" in text
    assert "video: /zx/clip.zxvideo" in text
    assert "arming · Away (0) · by someone" in text
    assert "(station event)" in text
    assert SYNTHETIC.camera_sn not in text
    assert "Fetch a still" in text  # a media row was present
    assert "No records" in render.render_events([], "20260101", "20260102", show_serials=False)


def test_render_entities_lists_the_picture_library() -> None:
    rows: list[dict[str, Any]] = [
        {
            "reid_id": 2760,
            "reid_name": "stranger14",
            "person_id": 17,
            "recognize_cnt": 4,
            "create_time": "2024-08-12 08:30:49",  # hygiene: ok
            "reid_picture_content": "/zx/aidata/ai_feature_picture/reidpic/17/x.jpg",
        },
        {
            "person_id": 53,
            "name": "stranger44",
            "relation": "family",
            "update_time": "2026-09-09",  # hygiene: ok
        },
    ]
    text = render.render_entities(rows, "body pictures")
    assert text.startswith("2 body pictures:")
    assert "stranger14 · person 17 · seen 4x" in text
    assert "picture: /zx/aidata/ai_feature_picture/reidpic/17/x.jpg" in text
    assert "stranger44 · person 53 · family" in text
    assert "Fetch a picture" in text  # the picture path is fetchable
    assert render.render_entities([], "recognised people") == "No recognised people on the station."


def test_events_does_not_render_picture_db_rows_as_events() -> None:
    # picture-DB rows have no device/media/str_extra, so events shows them plainly, not as a library
    rows: list[dict[str, Any]] = [{"person_id": 17, "reid_name": "x", "create_time": 1_700_000_000}]
    text = render.render_events(rows, "20240101", "20261231", show_serials=False)
    assert "person 17" not in text  # entity rendering is not mixed into events


def test_events_audit_only_explains_scope() -> None:
    rows: list[dict[str, Any]] = [
        {
            "station_sn": SYNTHETIC.station_sn,
            "create_time": 1_700_000_100,
            "str_extra": json.dumps({"msg_type": 9, "arm_mode": 0, "user_name": "someone"}),
        }
    ]
    text = render.render_events(rows, "20260101", "20260102", show_serials=False)
    assert "Fetch a still" not in text  # nothing to fetch
    assert "monitor" in text
    assert "cloud plan" in text


def test_event_lines() -> None:
    push = SecurityEvent(
        source=EventSource.P2P,
        device_sn=SYNTHETIC.camera_sn,
        device_name="Front",
        channel=0,
        msg_type=18,
        event_type=3102,
        thumb_path="/zx/t.jpg",
    )
    line = render.render_event(push, now=NOW, show_serials=False)
    assert line == '[03:04:05] p2p: person detection  "Front" T8160***7890  ch 0  thumb /zx/t.jpg'
    ecb = dataclasses.replace(push, frame_cipher=FrameCipher.ECB)
    assert render.render_event(ecb, now=NOW, show_serials=False).startswith(
        "[03:04:05] p2p: person detection  unauthenticated (ECB)  "
    )
    cloud = SecurityEvent(
        source=EventSource.CLOUD, station_sn=SYNTHETIC.station_sn, msg_type=9, guard_mode=63
    )
    assert "guard mode Disarmed (63)" in render.render_event(cloud, now=NOW, show_serials=False)
    arm = dataclasses.replace(cloud, arming_user=1, rejected_fields=frozenset({"thumb_path"}))
    assert render.render_event(arm, now=NOW, show_serials=False).endswith(
        "guard mode Disarmed (63)  by keypad  rejected thumb_path"
    )
    alarm = SecurityEvent(source=EventSource.CLOUD, msg_type=10, alarm_type=3)
    assert "alarm triggered" in render.render_event(alarm, now=NOW, show_serials=False)
    assert (
        render.render_event(
            GuardModeChanged(
                station_sn=SYNTHETIC.station_sn, mode=GuardMode.AWAY, source=EventSource.P2P
            ),
            now=NOW,
            show_serials=False,
        )
        == "[03:04:05] p2p: guard mode Away (0)  T8030***2345"
    )
    stopped = AlarmChanged(
        station_sn=SYNTHETIC.station_sn,
        alarming=False,
        source=EventSource.P2P,
        channel=255,
        event_type=16,
        stop_source=AlarmStopSource.APP,
    )
    assert render.render_event(stopped, now=NOW, show_serials=False) == (
        "[03:04:05] p2p: alarm ended  ch 255  type 16  stopped from app  T8030***2345"
    )
    schedule = GuardModeChanged(
        station_sn=SYNTHETIC.station_sn,
        mode=GuardMode.SCHEDULE,
        active_mode=GuardMode.HOME,
        source=EventSource.CLOUD,
    )
    assert "guard mode Schedule (2) (in force Home (1))" in render.render_event(
        schedule, now=NOW, show_serials=False
    )
    assert (
        render.render_event(
            ParamChanged(
                station_sn=SYNTHETIC.station_sn, channel=0, param_id=1101, old="87", new="86"
            ),
            now=NOW,
            show_serials=False,
        )
        == "[03:04:05] param ch 0 1101 GET_BATTERY: 87 → 86"
    )
    assert (
        render.render_event(
            ConnectionChanged(station_sn=SYNTHETIC.station_sn, connected=False, reason="closed"),
            now=NOW,
            show_serials=True,
        )
        == f"[03:04:05] {SYNTHETIC.station_sn} disconnected (closed)"
    )
    assert (
        render.render_event(
            CloudProblem(error=SessionReplacedError("kicked"), station_sn=SYNTHETIC.station_sn),
            now=NOW,
            show_serials=False,
        )
        == "[03:04:05] cloud problem: SessionReplacedError: kicked  T8030***2345"
    )
    assert (
        render.render_event(
            CredentialsRefreshed(
                station_sn=SYNTHETIC.station_sn, cipher=True, owner_id=False, login=True
            ),
            now=NOW,
            show_serials=False,
        )
        == "[03:04:05] T8030***2345 credentials refreshed (cipher, login)"
    )
    enrichment = dataclasses.replace(push, enriches=True)
    assert render.render_event(enrichment, now=NOW, show_serials=False).endswith(
        "thumb /zx/t.jpg  (adds media to an event already shown)"
    )
    assert render.render_event(
        AccountMismatch(station_sn=SYNTHETIC.station_sn), now=NOW, show_serials=False
    ) == (
        "[03:04:05] T8030***2345 account mismatch: the station stamps another account id "
        "than commands carry; commands may be ignored"
    )
    assert (
        render.render_event(PushChanged(running=True), now=NOW, show_serials=False)
        == "[03:04:05] cloud push listening"
    )
    assert (
        render.render_event(
            PushChanged(running=False, error=CommunicationError("down")),
            now=NOW,
            show_serials=False,
        )
        == "[03:04:05] cloud push not listening: CommunicationError: down"
    )


def test_event_json_round_trips() -> None:
    push = SecurityEvent(
        source=EventSource.CLOUD,
        station_sn=SYNTHETIC.station_sn,
        device_sn=SYNTHETIC.camera_sn,
        event_time_ms=1_700_000_000_000,
        guard_mode=1,
        push_id="span",
        raw={"k": 1},
    )
    data = json.loads(json.dumps(render.event_json(push)))
    assert data["source"] == "cloud"
    assert (data["push_id"], data["dedupe_key"], data["enriches"]) == (
        "span",
        f"{SYNTHETIC.camera_sn}:1700000000:",
        False,
    )
    alarm = SecurityEvent(
        source=EventSource.CLOUD,
        msg_type=10,
        alarm_type=16,
        rejected_fields=frozenset({"video_path"}),
    )
    data = json.loads(json.dumps(render.event_json(alarm)))
    assert (data["scope"], data["alarm_phase"], data["arming_source"]) == (
        "station",
        "stopped",
        None,
    )
    assert data["rejected_fields"] == ["video_path"]


def test_data_uri_and_image_description() -> None:
    blob, ext = render.decode_data_uri("data:image/png;base64,iVBORw0KGgo=")
    assert blob.startswith(b"\x89PNG")
    assert ext == ".png"
    assert "JPEG" in render.describe_image(b"\xff\xd8\xff" + b"\x00" * 10)


def test_render_network_advises_per_warning() -> None:
    paths = [
        LanPath(
            serial="T8030P2000012345",
            name="Base",
            host=None,
            host_source=HostSource.BROADCAST,
            cloud_ip=None,
            observed_ip=None,
            local_port=0,
            answered=False,
        ),
        LanPath(
            serial="T8400P2000000001",
            name="Hall",
            host="192.168.1.9",
            host_source=HostSource.CONFIGURED,
            cloud_ip="192.168.1.8",
            observed_ip=None,
            local_port=32109,
        ),
    ]
    out = render_network(paths, show_serials=False)
    assert "Base: no LAN address is known" in out
    assert "--local-port 32110" in out  # 32109 is taken by Hall
    assert "Base: did not answer LAN discovery" in out
    assert (
        "Hall: the configured address 192.168.1.9 is not where the station is (192.168.1.8)" in out
    )
    assert "Hall: allow UDP from 192.168.1.9 to this host's port 32109" in out
    assert "fixed IP (a DHCP reservation)" in out
    found = LanPath(
        serial="T8030P2000012345",
        name="Base",
        host=None,
        host_source=HostSource.BROADCAST,
        cloud_ip=None,
        observed_ip="192.168.1.5",
        local_port=0,
        answered=True,
    )
    out = render_network([found], show_serials=False)
    assert "Base: found only by broadcast (at 192.168.1.5)" in out
    assert "--host 192.168.1.5" in out
    assert "allow all UDP from 192.168.1.5" in out
    assert render_network([], show_serials=False) == "The account has no station."


def test_camera_busy_and_presets_changed_render_and_serialise() -> None:
    busy = CameraBusyChanged(
        station_sn=SYNTHETIC.station_sn, device_sn=SYNTHETIC.camera_sn, busy=True
    )
    assert render.render_event(busy, now=NOW, show_serials=False).endswith("capturing")

    not_busy = CameraBusyChanged(
        station_sn=SYNTHETIC.station_sn, device_sn=SYNTHETIC.camera_sn, busy=False
    )
    assert render.render_event(not_busy, now=NOW, show_serials=False).endswith("free")

    data = json.loads(json.dumps(render.event_json(busy)))
    assert data["type"] == "CameraBusyChanged"
    assert data["busy"] is True

    presets_event = PresetsChanged(
        station_sn=SYNTHETIC.station_sn,
        device_sn=SYNTHETIC.camera_sn,
        presets=(
            PresetPosition(index=1, enabled=True, zoom=1, is_default=False),
            PresetPosition(index=2, enabled=False, zoom=1, is_default=False),
        ),
    )
    assert render.render_event(presets_event, now=NOW, show_serials=False).endswith("presets: 1")

    data_p = json.loads(json.dumps(render.event_json(presets_event)))
    assert data_p["type"] == "PresetsChanged"


def test_zoom_changed_renders_and_serialises() -> None:
    event = ZoomChanged(station_sn=SYNTHETIC.station_sn, device_sn=SYNTHETIC.camera_sn, zoom=2.5)
    assert render.render_event(event, now=NOW, show_serials=False).endswith("zoom: 2.5x")
    data = json.loads(json.dumps(render.event_json(event)))
    assert (data["type"], data["zoom"]) == ("ZoomChanged", 2.5)
