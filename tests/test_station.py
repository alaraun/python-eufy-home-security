from __future__ import annotations

import asyncio
import base64
import dataclasses
import json
import math
import time
from collections.abc import AsyncIterator, Callable
from datetime import UTC, datetime, timedelta
from typing import Any

import pytest

import eufy_home_security.p2p.session as session_mod
import eufy_home_security.station as station_mod
from eufy_home_security.cloud.models import CloudDevice
from eufy_home_security.devices.model_settings import (
    Setting,
    SettingKind,
    mode_table_settings,
    settings_of,
)
from eufy_home_security.devices.recipes import MAX_PRESET_SLOTS, PanTilt, PresetPosition
from eufy_home_security.devices.settings import Scope
from eufy_home_security.devices.types import DeviceKind
from eufy_home_security.events import (
    CameraBusyChanged,
    DevicesChanged,
    Event,
    EventSource,
    HistoryRecord,
    PresetsChanged,
    SecurityEvent,
    StationStateChanged,
    ZoomChanged,
)
from eufy_home_security.exceptions import (
    CommandNotAppliedError,
    CommandRejectedError,
    CommandUnsupportedError,
    DeviceBusyError,
    DeviceTimeoutError,
    LiveStreamLimitError,
    PresetSlotsFullError,
    RecordNotFoundError,
    StillNotWrittenError,
    UnsupportedError,
)
from eufy_home_security.images import HEVC_CONTENT_TYPE, JPEG_CONTENT_TYPE, CameraImage, ImageSource
from eufy_home_security.models import STATION_CHANNEL, GuardMode
from eufy_home_security.network import HostSource
from eufy_home_security.p2p import session as session_module
from eufy_home_security.p2p.did import static_key
from eufy_home_security.p2p.media import MediaFrame, MediaKind, StillFormat
from eufy_home_security.p2p.messages import HISTORY_RECORD_COUNTER, STANDALONE_RECEIPT_LEN
from eufy_home_security.p2p.params import ParamDump
from eufy_home_security.p2p.session import (
    PARAM_SETTLE,
    CommandOutcome,
    P2PCredentials,
    StationSession,
)
from eufy_home_security.p2p.xzyh import FrameType
from eufy_home_security.station import (
    Station,
    StationState,
    _still_time,
    station_block_aliases,
    station_channels,
)
from eufy_home_security.storage import MemoryStore, SessionCache
from eufy_home_security.testing import SYNTHETIC
from eufy_home_security.testing.station import (
    MEDIA_KEYFRAME,
    MEDIA_RECORDING_PFRAME,
    FakeStation,
    v1_still,
)

STATION = CloudDevice(
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


@pytest.fixture
async def fake() -> AsyncIterator[FakeStation]:
    station = FakeStation()
    station.params[255][1224] = "63"
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
    st = Station(STATION, session, sub_devices=[CAMERA])
    yield st
    await st.async_close()


async def test_update_builds_a_snapshot(station: Station) -> None:
    assert station.channels == {0}
    started = time.monotonic()
    state = await station.async_update()
    assert time.monotonic() - started < PARAM_SETTLE / 2  # the camera's channel reported
    assert state.guard_mode is GuardMode.DISARMED
    assert state.firmware == "3.8.7.4"
    camera = state.devices[0]
    assert (camera.serial, camera.name, camera.battery, camera.rssi) == (
        SYNTHETIC.camera_sn,
        "Front",
        87,
        -52,
    )
    assert station.model is not None
    assert station.model.name.startswith("HomeBase 3")


async def test_state_carries_the_selected_and_the_effective_mode(
    station: Station, fake: FakeStation
) -> None:
    fake.params[255][1224] = "1"
    assert (await station.async_update()).active_mode is GuardMode.HOME  # no 1151: the same
    fake.params[255] |= {1224: "2", 1151: "63"}
    state = await station.async_update()
    assert (state.guard_mode, state.active_mode) == (GuardMode.SCHEDULE, GuardMode.DISARMED)


async def test_reported_off_is_a_disarm(station: Station, fake: FakeStation) -> None:
    fake.params[255][1224] = "6"
    state = await station.async_update()
    assert state.guard_mode is GuardMode.OFF
    assert state.guard_mode.is_disarmed


async def test_connected_follows_the_connection_events(station: Station) -> None:
    before = station.connected
    await station.async_update()
    up = station.connected
    error = station.last_error
    await station.async_close()
    assert (before, up, station.connected) == (False, True, False)
    assert error is None


async def test_stats_are_json_safe_and_carry_no_identifier(
    station: Station, fake: FakeStation
) -> None:
    await station.async_update()
    fake.push_camera_event()
    async with asyncio.timeout(3):
        while not station.stats().events_by_type:
            await asyncio.sleep(0.02)
    text = json.dumps(dataclasses.asdict(station.stats()))
    for identifier in (
        SYNTHETIC.station_sn,
        SYNTHETIC.camera_sn,
        SYNTHETIC.did,
        SYNTHETIC.account_id,
        SYNTHETIC.station_ip,
        "127.0.0.1",
    ):
        assert identifier not in text


async def test_guard_mode_accepts_names(station: Station, fake: FakeStation) -> None:
    assert await station.async_set_guard_mode("home") is GuardMode.HOME
    assert fake.guard_mode == GuardMode.HOME


# ── settings: writes ──────────────────────────────────────────────────────────────

CAMERA_CH1 = dataclasses.replace(CAMERA, channel=1)


@pytest.fixture
async def child(fake: FakeStation) -> AsyncIterator[Station]:
    """A T8030 with the synthetic T8160 paired on channel 1; settings writes answered."""
    fake.params[1] = fake.params.pop(0)
    fake.reply_to_settings = True

    async def credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", fake.ecc_private_key_hex)

    session = StationSession(
        SYNTHETIC.station_sn, credentials, host="127.0.0.1", port=fake.discovery_port
    )
    st = Station(STATION, session, sub_devices=[CAMERA_CH1])
    await st.async_update()
    yield st
    await st.async_close()


def _cached(station: Station, channel: int, param: int) -> str | None:
    state = station.state
    assert state is not None
    block = state.params if channel == STATION_CHANNEL else state.devices[channel].params
    return block.get(param)


@pytest.mark.parametrize(
    ("write", "sent", "cached"),
    [
        (("power_manager_mode", 3), ((1246, 1, 2), None), (1246, "2")),
        (("speaker_volume", 2), ((1230, 1, 100), None), (1230, "100")),
        (("nightvision_type", 2), (None, (1277, {"night_sion": 2, "channel": 1})), (1277, "2")),
    ],
    ids=["ecb", "ecb-mapped", "1350"],
)
async def test_a_paired_device_write_goes_out_on_its_codecs_path(
    child: Station,
    fake: FakeStation,
    write: tuple[str, object],
    sent: tuple[tuple[int, int, int] | None, tuple[int, dict[str, int]] | None],
    cached: tuple[int, str],
) -> None:
    ecb, gcm = sent
    fake.apply_settings = False  # only the library's own cache update can show the value
    outcome = await child.async_set_setting(*write, device_sn=SYNTHETIC.camera_sn)
    assert outcome is CommandOutcome.APPLIED
    assert fake.ecb_received[-1:] == ([ecb] if ecb else [])
    commands = [(r["cmd"], r["payload"]) for r in fake.received if r["cmd"] != 1224]
    assert commands == ([gcm] if gcm else [])
    if gcm:
        assert fake.received[-1]["mChannel"] == 1
    assert _cached(child, 1, cached[0]) == cached[1]


async def test_a_shared_bit_write_keeps_the_other_bits(child: Station, fake: FakeStation) -> None:
    """notification_ignore_switch is bit 256 of 1283, whose other bits hold the
    mode-switch notifications: the write reads the mask and sends it with one bit moved."""
    fake.params[STATION_CHANNEL][1283] = "208"
    await child.async_set_setting("notification_ignore_switch", True)
    last = fake.received[-1]
    assert (last["cmd"], last["payload"]) == (1283, {"arm_push_mode": 464})
    fake.params[STATION_CHANNEL][1283] = "464"
    await child.async_set_setting("notification_ignore_switch", False)
    assert fake.received[-1]["payload"] == {"arm_push_mode": 208}


async def test_a_shared_bit_write_without_the_current_mask_sends_nothing(
    child: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(station_mod, "READBACK_DELAY", 0.0)
    fake.params[STATION_CHANNEL].pop(1283, None)
    sent = len(fake.received)
    with pytest.raises(CommandNotAppliedError, match="blind"):
        await child.async_set_setting("notification_ignore_switch", True)
    assert all(r["cmd"] != 1283 for r in fake.received[sent:])


async def test_a_flag_write_moves_one_member(child: Station, fake: FakeStation) -> None:
    """detection_type_set members are bits of 1298; 196623 = human, vehicle, pet plus
    the face bits no member of this key names, which stay."""
    camera: dict[str, Any] = {"device_sn": SYNTHETIC.camera_sn}
    fake.params[1][1298] = "196623"
    state = await child.async_update()
    setting = child.setting("detection_type_set", **camera)
    assert setting.decode_flags(state.devices[1].params[1298])[0] == frozenset({"1", "2", "3"})
    mask = await child.async_set_flag("detection_type_set", "3", False, **camera)
    assert mask == 196615
    assert fake.received[-1]["payload"] == {"ai_detect_type": 196615, "channel": 1}
    with pytest.raises(ValueError, match="unknown flag"):
        await child.async_set_flag("detection_type_set", "9", True, **camera)
    with pytest.raises(UnsupportedError, match="not a writable flags"):
        await child.async_set_flag("power_manager_mode", "1", True, **camera)


async def test_the_hubs_own_setting_goes_out_on_255(child: Station, fake: FakeStation) -> None:
    for target in ({}, {"channel": STATION_CHANNEL}, {"device_sn": SYNTHETIC.station_sn}):
        outcome = await child.async_set_setting("prompt_volume_value", 20, **target)
        assert outcome is CommandOutcome.APPLIED
        last = fake.received[-1]
        assert (last["cmd"], last["mChannel"], last["payload"]) == (1292, 255, {"value": 20})
    assert _cached(child, STATION_CHANNEL, 1292) == "20"


async def test_refused_writes_send_nothing(child: Station, fake: FakeStation) -> None:
    camera: dict[str, Any] = {"device_sn": SYNTHETIC.camera_sn}
    with pytest.raises(UnsupportedError, match="unknown setting"):
        await child.async_set_setting("party_mode", 1, **camera)
    with pytest.raises(UnsupportedError, match=r"not writable: .*cloud request"):
        await child.async_set_setting("device_name", "Porch", **camera)
    with pytest.raises(UnsupportedError, match="not writable: guard mode"):
        await child.async_set_setting("arming_selected_mode", 1)
    with pytest.raises(ValueError, match="not one of"):
        await child.async_set_setting("power_manager_mode", 2, **camera)
    with pytest.raises(ValueError, match="at most one"):
        await child.async_set_setting("power_manager_mode", 3, channel=1, **camera)
    with pytest.raises(UnsupportedError, match="not paired"):
        await child.async_set_setting("power_manager_mode", 3, device_sn="T8160P2000099999")
    with pytest.raises(UnsupportedError, match="no paired device on channel 7"):
        await child.async_set_setting("power_manager_mode", 3, channel=7)
    assert fake.ecb_received == []
    assert [r for r in fake.received if r["cmd"] != 1224] == []


async def test_a_rejected_write_raises_and_leaves_the_cache(
    child: Station, fake: FakeStation
) -> None:
    camera: dict[str, Any] = {"device_sn": SYNTHETIC.camera_sn}
    fake.unhandled_commands = {1277}
    with pytest.raises(CommandUnsupportedError):
        await child.async_set_setting("nightvision_type", 2, **camera)
    fake.account_id = "another-account"  # the ECB result code is then -104
    with pytest.raises(CommandRejectedError):
        await child.async_set_setting("power_manager_mode", 3, **camera)
    assert _cached(child, 1, 1277) is None
    assert _cached(child, 1, 1246) is None


async def test_snapshot_is_one_keyframe_live_or_recorded(
    station: Station, fake: FakeStation
) -> None:
    assert await station.async_snapshot(SYNTHETIC.camera_sn) == MEDIA_KEYFRAME
    assert await station.async_snapshot(channel=0, recording="/zx/clip.zxvideo") == MEDIA_KEYFRAME
    opens = [o for o in fake.received if o["cmd"] in (1003, 1025)]
    assert [(o["cmd"], o["mChannel"]) for o in opens] == [(1003, 0), (1025, 0)]
    assert fake.conn_inits == 2  # the recording played on a short-lived session
    assert station.stats().trigger_frame_sessions == 1


async def test_overlapping_snapshots_each_return_a_keyframe(
    station: Station, fake: FakeStation
) -> None:
    both = await asyncio.gather(
        station.async_snapshot(SYNTHETIC.camera_sn, wait=True),
        station.async_snapshot(channel=0, wait=True),
    )
    assert list(both) == [MEDIA_KEYFRAME, MEDIA_KEYFRAME]
    assert fake.opened_while_streaming == [False, False]


async def test_a_live_still_beside_a_live_view_takes_an_extra_session(
    station: Station, fake: FakeStation
) -> None:
    """On a HomeBase a live still is a live open: the view keeps the slot and streams on."""
    async with await station.async_open_live(SYNTHETIC.camera_sn) as view:
        async for frame in view:
            if frame.is_keyframe:
                break
        assert station.media_slot_camera == SYNTHETIC.camera_sn
        assert await station.async_snapshot(SYNTHETIC.camera_sn) == MEDIA_KEYFRAME
        stats = station.stats()
        assert (stats.extra_live_sessions, stats.media_slot_channel) == (1, 0)
        sent = fake.media_frames_sent
        async with asyncio.timeout(3):
            async for _frame in view:
                if fake.media_frames_sent > sent:
                    break
        assert fake.live_opens == [0, 0]


async def test_a_live_still_at_the_session_budget_raises_or_waits(
    station: Station, fake: FakeStation
) -> None:
    station.max_sessions = session_module.MIN_STATION_SESSIONS  # one live stream
    view = await station.async_open_live(SYNTHETIC.camera_sn)
    with pytest.raises(LiveStreamLimitError):
        await station.async_snapshot(SYNTHETIC.camera_sn)
    waiting = asyncio.create_task(station.async_snapshot(SYNTHETIC.camera_sn, wait=True))
    await asyncio.sleep(0.1)
    assert not waiting.done()
    await view.aclose()
    assert await asyncio.wait_for(waiting, 5) == MEDIA_KEYFRAME
    assert station.stats().extra_live_sessions == 0


async def test_a_live_camera_image_at_the_session_budget_waits_unless_told_not_to(
    station: Station, fake: FakeStation
) -> None:
    """``async_camera_image(LIVE)`` waits for a stream to end by default; with
    ``wait=False`` it raises at once and leaves the camera free."""
    station.max_sessions = session_module.MIN_STATION_SESSIONS  # one live stream
    view = await station.async_open_live(SYNTHETIC.camera_sn)
    with pytest.raises(LiveStreamLimitError):
        async with asyncio.timeout(1):  # well under the first-frame timeout
            await station.async_camera_image(SYNTHETIC.camera_sn, ImageSource.LIVE, wait=False)
    assert not station.is_capturing(SYNTHETIC.camera_sn)
    assert station.stats().extra_live_sessions == 0
    waiting = asyncio.create_task(station.async_camera_image(SYNTHETIC.camera_sn, ImageSource.LIVE))
    await asyncio.sleep(0.1)
    assert not waiting.done()
    await view.aclose()
    image = await asyncio.wait_for(waiting, 5)
    assert (image.source, image.data) == (ImageSource.LIVE, MEDIA_KEYFRAME)
    assert fake.live_opens == [0, 0]


async def test_a_preset_image_at_the_session_budget_raises_unless_told_to_wait(
    station: Station, fake: FakeStation
) -> None:
    """``async_preset_image`` raises at the budget by default, after its go-to; with
    ``wait=True`` it waits for a stream to end."""
    ptz = dataclasses.replace(CAMERA, device_sn=_T8170_SN, device_type=18)
    hub = Station(station.device, station.session, sub_devices=[ptz])
    hub.max_sessions = session_module.MIN_STATION_SESSIONS  # one live stream
    view = await hub.async_open_live(_T8170_SN)
    with pytest.raises(LiveStreamLimitError):
        async with asyncio.timeout(1):  # well under the first-frame timeout
            await hub.async_preset_image(_T8170_SN, 1, settle=0)
    assert not hub.is_capturing(_T8170_SN)
    assert hub.stats().extra_live_sessions == 0
    waiting = asyncio.create_task(hub.async_preset_image(_T8170_SN, 1, settle=0, wait=True))
    await asyncio.sleep(0.1)
    assert not waiting.done()
    await view.aclose()
    image = await asyncio.wait_for(waiting, 5)
    assert (image.preset, image.data) == (1, MEDIA_KEYFRAME)
    assert fake.preset_gotos == [1, 1]


async def test_event_trigger_frame_addresses_the_events_camera(
    station: Station, fake: FakeStation
) -> None:
    event = SecurityEvent(
        source=EventSource.P2P,
        station_sn=SYNTHETIC.station_sn,
        device_sn=SYNTHETIC.camera_sn,
        channel=5,  # the paired serial's channel wins
        video_path="/zx/clip.zxvideo",
    )
    assert await station.async_event_trigger_frame(event) == MEDIA_KEYFRAME
    by_channel = dataclasses.replace(event, device_sn=None, channel=0)
    assert await station.async_event_trigger_frame(by_channel, trailing_frames=1) == (
        MEDIA_KEYFRAME + MEDIA_RECORDING_PFRAME
    )
    opens = [(o["cmd"], o["mChannel"]) for o in fake.received]
    for unusable, reason in (
        (dataclasses.replace(event, video_path=None), "no recording"),
        (dataclasses.replace(event, station_sn="T8030P2000099999"), "belongs to"),
        (dataclasses.replace(event, device_sn=None, channel=None), "no camera"),
    ):
        with pytest.raises(UnsupportedError, match=reason):
            await station.async_event_trigger_frame(unusable)
    assert opens == [(1025, 0), (1025, 0)]
    assert [(o["cmd"], o["mChannel"]) for o in fake.received] == opens  # nothing sent


async def test_fetch_still_labels_the_format(station: Station, fake: FakeStation) -> None:
    fake.images["/zx/t.jpg"] = b"v8_eufysecurity" + b"\x00" * 8
    still = await station.async_fetch_still("/zx/t.jpg")
    assert (still.format, still.is_image) == (StillFormat.V8, False)


async def test_event_thumbnail_fetches_thumb_path_without_history_queries(
    station: Station, fake: FakeStation
) -> None:
    fake.images["/zx/push.jpg"] = b"\xff\xd8JFIF\x00\x01\x02"
    event = SecurityEvent(
        source=EventSource.P2P,
        station_sn=SYNTHETIC.station_sn,
        device_sn=SYNTHETIC.camera_sn,
        thumb_path="/zx/push.jpg",
    )
    still = await station.async_event_thumbnail(event)
    assert (still.path, still.is_image) == ("/zx/push.jpg", True)
    assert fake.history_queries == []


async def test_event_thumbnail_fetches_thumb_path_from_history_by_record_id(
    station: Station, fake: FakeStation
) -> None:
    fake.images["/zx/hdd_data0/Camera00/20260916/snapshort.jpg"] = b"\xff\xd8JFIF..."
    fake.rows = [
        {
            "record_id": 20260916 * HISTORY_RECORD_COUNTER + 43,
            "device_sn": SYNTHETIC.camera_sn,
            "thumb_path": "/zx/hdd_data0/Camera00/20260916/other1.jpg",
        },
        {
            "record_id": 20260916 * HISTORY_RECORD_COUNTER + 42,
            "device_sn": SYNTHETIC.camera_sn,
            "thumb_path": "/zx/hdd_data0/Camera00/20260916/snapshort.jpg",
        },
        {
            "record_id": 20260916 * HISTORY_RECORD_COUNTER + 41,
            "device_sn": SYNTHETIC.camera_sn,
            "thumb_path": "/zx/hdd_data0/Camera00/20260916/other2.jpg",
        },
    ]
    event = SecurityEvent(
        source=EventSource.P2P,
        station_sn=SYNTHETIC.station_sn,
        device_sn=SYNTHETIC.camera_sn,
        record_id=20260916 * HISTORY_RECORD_COUNTER + 42,
    )
    still = await station.async_event_thumbnail(event)
    assert (still.path, still.is_image) == ("/zx/hdd_data0/Camera00/20260916/snapshort.jpg", True)
    assert len(fake.history_queries) == 1
    q = fake.history_queries[0]
    assert (q["start_date"], q["start_id"], q["count"]) == ("20260916", event.record_id, 2)


async def test_event_thumbnail_rejects_unsupported_events_without_sending(
    station: Station, fake: FakeStation
) -> None:
    sent_before = len(fake.received)
    for kwargs in (
        {"station_sn": "T8030P2000099999", "thumb_path": "/zx/t.jpg"},
        {"station_sn": SYNTHETIC.station_sn, "thumb_path": None, "record_id": None},
        {"station_sn": SYNTHETIC.station_sn, "thumb_path": None, "record_id": 0},
        {"station_sn": SYNTHETIC.station_sn, "thumb_path": None, "record_id": 42},
        {"station_sn": SYNTHETIC.station_sn, "thumb_path": None, "record_id": 2026139900001},
        {"station_sn": SYNTHETIC.station_sn, "thumb_path": None, "record_id": 2026023000001},
    ):
        event = SecurityEvent(source=EventSource.P2P, **kwargs)
        with pytest.raises(UnsupportedError):
            await station.async_event_thumbnail(event)
    assert len(fake.received) == sent_before
    assert fake.history_queries == []


async def test_event_thumbnail_reports_record_not_found(
    station: Station, fake: FakeStation
) -> None:
    fake.rows = [
        {
            "record_id": 20260916 * HISTORY_RECORD_COUNTER + 42,
            "device_sn": "T8160P2000099999",
            "thumb_path": "/zx/t.jpg",
        },
        {
            "record_id": 20260916 * HISTORY_RECORD_COUNTER + 43,
            "device_sn": SYNTHETIC.camera_sn,
        },
        {
            "record_id": 20260916 * HISTORY_RECORD_COUNTER + 44,
            "device_sn": SYNTHETIC.camera_sn,
            "thumb_path": "/etc/passwd",
        },
        {
            "record_id": 20260916 * HISTORY_RECORD_COUNTER + 45,
            "device_sn": SYNTHETIC.camera_sn,
            "thumb_path": "/zx/../../t.jpg",
        },
        {
            "record_id": 20260916 * HISTORY_RECORD_COUNTER + 46,
            "device_sn": SYNTHETIC.camera_sn,
            "thumb_path": "/zx/t.mp4",
        },
    ]
    for counter, not_yet in (
        (41, True),  # missing: the row comes later
        (42, False),  # wrong device
        (43, True),  # no thumb_path: the still comes later
        (44, False),  # invalid path
        (45, False),  # path traversal
        (46, False),  # not .jpg
    ):
        event = SecurityEvent(
            source=EventSource.P2P,
            station_sn=SYNTHETIC.station_sn,
            device_sn=SYNTHETIC.camera_sn,
            record_id=20260916 * HISTORY_RECORD_COUNTER + counter,
        )
        with pytest.raises(RecordNotFoundError) as info:
            await station.async_event_thumbnail(event)
        assert isinstance(info.value, StillNotWrittenError) is not_yet, counter
    assert not [o for o in fake.received if o["cmd"] == 1308]  # no still was fetched


async def test_media_needs_exactly_one_target(station: Station) -> None:
    with pytest.raises(ValueError, match="exactly one"):
        await station.async_open_live()
    with pytest.raises(ValueError, match="exactly one"):
        await station.async_open_recording("/zx/clip.zxvideo", SYNTHETIC.camera_sn, channel=0)


async def test_media_slot_camera_names_the_camera_holding_the_slot(
    station: Station, fake: FakeStation
) -> None:
    """media_slot_camera resolves the slot channel to a camera serial; None when free."""
    await station.async_update()
    free = station.media_slot_camera  # local snapshot: asserting the property is None
    assert free is None  # would poison every later read of it (mypy)
    stream = await station.async_open_live(SYNTHETIC.camera_sn)
    try:
        async for frame in stream:
            if frame.is_keyframe:
                break
        assert station.media_slot_camera == SYNTHETIC.camera_sn
    finally:
        await stream.aclose()
    async with asyncio.timeout(3.0):
        while station.media_slot_camera is not None:
            await asyncio.sleep(0.02)


async def test_storage_is_the_sessions_record(station: Station) -> None:
    before = station.storage
    info = await station.async_get_storage(timeout=3.0)
    assert (before, station.storage) == (None, info)
    emmc = info.emmc
    assert emmc is not None
    assert emmc.wear_percent == 2


def _snapshots(events: list[Event]) -> list[StationState]:
    return [e.state for e in events if isinstance(e, StationStateChanged)]


# Station block first, then the sub-device block after the settle window would have
# closed on the first frame alone: still one snapshot, after the second frame.
@pytest.mark.parametrize("sub_blocks_after", [None, PARAM_SETTLE + 0.3])
async def test_a_pushed_dump_emits_one_snapshot_only_when_it_changes(
    station: Station, fake: FakeStation, sub_blocks_after: float | None
) -> None:
    await station.async_update()
    events: list[Event] = []
    station.subscribe(events.append)
    fake.sub_blocks_after = sub_blocks_after
    fake.params[0][1101] = "55"
    fake.send_param_dump()
    await asyncio.sleep(0.3)
    assert _snapshots(events) == []  # the dump is still settling
    await asyncio.sleep(PARAM_SETTLE + 1.6)
    fake.send_param_dump()  # identical: nothing to report
    await asyncio.sleep(PARAM_SETTLE + 1.6)
    snapshots = _snapshots(events)
    assert len(snapshots) == 1
    assert snapshots[0].devices[0].battery == 55
    assert station.state == snapshots[0]


async def test_a_full_read_without_a_device_block_drops_that_device(
    station: Station, fake: FakeStation
) -> None:
    fake.params[1] = {1101: "40"}
    assert set((await station.async_update()).devices) == {0, 1}
    events: list[Event] = []
    station.subscribe(events.append)
    del fake.params[1]
    state = await station.async_update()
    assert set(state.devices) == {0}
    assert _snapshots(events) == [state]


def _unconnected_station(*, host: str | None, local_ip: str | None, local_port: int) -> Station:
    async def no_credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        raise AssertionError("not connecting")

    session = StationSession(SYNTHETIC.station_sn, no_credentials, host=host, local_port=local_port)
    device = CloudDevice(
        device_sn=SYNTHETIC.station_sn,
        device_type=18,
        name="HB",
        p2p_did=SYNTHETIC.did,
        local_ip=local_ip,
    )
    return Station(device, session)


@pytest.mark.parametrize(
    ("host", "local_ip", "source"),
    [
        ("192.168.1.20", "192.168.1.20", HostSource.CLOUD),
        ("192.168.1.21", "192.168.1.20", HostSource.CONFIGURED),
        (None, "88.196.8.222", HostSource.BROADCAST),  # a WAN local_ip is no LAN address
    ],
)
def test_lan_path_says_where_the_address_came_from(
    host: str | None, local_ip: str, source: HostSource
) -> None:
    path = _unconnected_station(host=host, local_ip=local_ip, local_port=32109).lan_path
    assert path.host_source is source
    assert path.host == host
    assert path.local_port == 32109
    assert path.observed_ip is None


# ── typed diagnostics from a synthetic dump (Station._state) ─────────────────

SENSOR_SN = "T8910P0000000001"
DAY_MS = 86_400_000
NOW_MS = 1_780_000_000_000


def _state_of(
    blocks: dict[int, dict[int, str]],
    *,
    sub_devices: tuple[CloudDevice, ...] = (),
    meta: dict[str, str] | None = None,
    cloud_sec_firmware: str | None = None,
) -> StationState:
    dump = ParamDump()
    dump.ingest(
        {
            **(meta or {}),
            "params": [
                {"dev_type": dev, "param_type": pid, "param_value": value}
                for dev, params in blocks.items()
                for pid, value in params.items()
            ],
        }
    )
    station = _unconnected_station(host=None, local_ip=None, local_port=0)
    device = dataclasses.replace(station.device, sec_sw_version=cloud_sec_firmware)
    return Station(device, station.session, sub_devices=sub_devices)._state(dump)


def _sub_device_blocks() -> dict[int, dict[int, str]]:
    return {
        0: {1142: "-58", 1141: "0", 1400: "0"},
        16: {1141: "-76", 1605: str(NOW_MS - 8 * DAY_MS), 1601: "1"},
        255: {1224: "0"},
    }


CAM_A, CAM_B, CAM_C = SYNTHETIC.camera_sn, "T8160P2000067891", "T8160P2000067892"


def _camera(serial: str, channel: int) -> CloudDevice:
    return CloudDevice(
        device_sn=serial,
        device_type=19,
        name="Cam",
        station_sn=SYNTHETIC.station_sn,
        channel=channel,
    )


def _listed_blocks(listed: list[str]) -> dict[int, dict[int, str]]:
    """Three camera blocks, a sensor block, and station param 1072 = ``listed``."""
    blob = base64.b64encode(json.dumps(listed).encode()).decode()
    return {
        0: {1400: "0"},
        1: {1400: "0"},
        2: {1400: "0"},
        16: {1601: "1"},
        255: {1224: "0", 1072: blob},
    }


def test_a_channel_the_cloud_lacks_takes_its_serial_from_anchored_1072() -> None:
    state = _state_of(
        _listed_blocks([CAM_A, CAM_B, CAM_C]), sub_devices=(_camera(CAM_A, 0), _camera(CAM_C, 2))
    )
    assert [(d.serial, d.serial_source) for d in state.devices.values()] == [
        (CAM_A, "cloud"),
        (CAM_B, "param_1072"),
        (CAM_C, "cloud"),
        (None, None),  # the sensor is neither in 1072 nor a camera slot
    ]


@pytest.mark.parametrize(
    ("listed", "sub_devices"),
    [
        pytest.param(
            [CAM_C, CAM_B, CAM_A], (_camera(CAM_A, 0), _camera(CAM_C, 2)), id="out-of-order"
        ),
        pytest.param([CAM_A, CAM_B, CAM_C], (), id="no-anchor"),
        pytest.param([CAM_A, CAM_B], (_camera(CAM_A, 0),), id="fewer-serials-than-cameras"),
    ],
)
def test_1072_is_not_used_without_consistent_anchors(
    listed: list[str], sub_devices: tuple[CloudDevice, ...]
) -> None:
    state = _state_of(_listed_blocks(listed), sub_devices=sub_devices)
    assert state.devices[1].serial is None
    assert all(d.serial_source != "param_1072" for d in state.devices.values())


def test_two_cloud_devices_on_one_channel_leave_its_serial_unknown(
    caplog: pytest.LogCaptureFixture,
) -> None:
    base = _unconnected_station(host=None, local_ip=None, local_port=0)
    station = Station(base.device, base.session, sub_devices=[_camera(CAM_A, 0), _camera(CAM_B, 0)])
    dump = ParamDump()
    dump.ingest({"params": [{"dev_type": 0, "param_type": 1101, "param_value": "80"}]})
    with caplog.at_level("WARNING", logger="eufy_home_security.station"):
        first = station._state(dump)
        station._state(dump)
    assert (first.devices[0].serial, first.devices[0].serial_source) == (None, None)
    warnings = [r for r in caplog.records if "more than one device on channel 0" in r.getMessage()]
    assert len(warnings) == 1


def test_updating_paired_devices_reports_what_was_added_removed_or_moved() -> None:
    base = _unconnected_station(host=None, local_ip=None, local_port=0)
    station = Station(base.device, base.session, sub_devices=[_camera(CAM_A, 0), _camera(CAM_B, 1)])
    events: list[Event] = []
    station.subscribe(events.append)
    assert station.update_sub_devices([_camera(CAM_A, 0), _camera(CAM_B, 1)]) is None
    changed = station.update_sub_devices([_camera(CAM_B, 2), _camera(CAM_C, 1)])
    assert changed == DevicesChanged(
        station_sn=station.serial, added=(CAM_C,), removed=(CAM_A,), moved=(CAM_B,)
    )
    assert events == [changed]
    assert station.session.expect_channels == {1, 2}


def test_camera_signal_is_wifi_and_kind_comes_from_markers() -> None:
    camera = _state_of(_sub_device_blocks()).devices[0]
    assert (camera.rssi, camera.wifi_rssi, camera.sub1g_rssi) == (-58, -58, None)
    assert camera.kind is DeviceKind.CAMERA
    assert camera.pir_event_ms is None
    assert not camera.pir_quiet_for(now_ms=NOW_MS, max_age_s=0)


def test_sensor_signal_is_sub1g_and_pir_time_is_opt_in() -> None:
    sensor = _state_of(_sub_device_blocks()).devices[16]
    assert (sensor.rssi, sensor.wifi_rssi, sensor.sub1g_rssi) == (-76, None, -76)
    assert sensor.kind is DeviceKind.SENSOR
    assert sensor.pir_event_ms == NOW_MS - 8 * DAY_MS
    assert sensor.pir_quiet_for(now_ms=NOW_MS, max_age_s=7 * 86400)
    assert not sensor.pir_quiet_for(now_ms=NOW_MS, max_age_s=9 * 86400)
    with pytest.raises(ValueError, match="negative"):
        sensor.pir_quiet_for(now_ms=NOW_MS, max_age_s=-1)


@pytest.mark.parametrize(
    ("raw", "online", "code"),
    [("1", True, None), ("0", False, None), ("3", False, 3), ("255", False, 255)],
)
def test_param_1131_says_whether_a_sub_device_still_reports(
    raw: str, online: bool, code: int | None
) -> None:
    device = _state_of({0: {1131: raw}}).devices[0]
    assert (device.online, device.offline_code) == (online, code)


def test_a_block_without_1131_says_nothing_about_being_online() -> None:
    device = _state_of({0: {1101: "50"}}).devices[0]
    assert (device.online, device.offline_code) == (None, None)


def test_camera_power_manager_figures_come_from_the_block() -> None:
    blocks = {0: {1400: "0", 1138: "21", 1191: "1041", 1192: "39209", 1193: "20192"}}
    camera = _state_of(blocks).devices[0]
    assert camera.battery_temperature == 21
    assert (camera.working_days, camera.detected_events, camera.recorded_events) == (
        1041,
        39209,
        20192,
    )


@pytest.mark.parametrize(
    ("raw", "charging", "solar"),
    [
        ("0", False, False),
        ("1", True, False),  # USB
        ("2", False, False),
        ("3", True, False),  # AC
        ("4", True, True),  # built-in solar
        ("5", True, True),  # USB and built-in solar
        ("6", True, True),  # external panel (T8160 thing description)
        ("8", True, True),  # external panel (other models)
        ("12", True, True),  # external and built-in solar
    ],
)
def test_power_source_says_whether_and_how_a_camera_charges(
    raw: str, charging: bool, solar: bool
) -> None:
    camera = _state_of({0: {1400: "0", 2111: raw, 1309: "7"}}).devices[0]
    assert camera.power_source == int(raw)
    assert (camera.charging, camera.solar_charging) == (charging, solar)
    assert camera.solar_intensity == 7


def test_unreported_power_source_says_nothing_about_charging() -> None:
    camera = _state_of({0: {1400: "0", 2111: "x"}}).devices[0]
    assert (camera.power_source, camera.charging, camera.solar_charging) == (None, None, None)


def test_siren_actions_are_keyed_by_mode_and_keep_only_reported_modes() -> None:
    camera = _state_of({0: {1400: "0", 1509: "1", 1510: "0", 1513: "x"}}).devices[0]
    assert camera.siren_actions == {GuardMode.AWAY: 1, GuardMode.HOME: 0}


@pytest.mark.parametrize(("raw", "low"), [("0", False), ("1", True), ("2", None), ("x", None)])
def test_sensor_low_battery_flag(raw: str, low: bool | None) -> None:
    sensor = _state_of({16: {1601: raw, 1609: "8"}}).devices[16]
    assert sensor.low_battery is low
    assert sensor.pir_sensitivity_raw == 8


def test_an_offline_sensor_keeps_serving_its_last_battery_and_signal() -> None:
    """The shape verified on hardware: the station answers for a sensor that stopped
    reporting long ago, still quoting 30 % and -76 dBm, and only 1131 separates it from
    the two cameras that are present."""
    state = _state_of(
        {
            0: {1131: "1", 1142: "-61", 1101: "90", 1400: "0"},
            1: {1131: "1", 1142: "-59", 1101: "97", 1400: "0"},
            16: {1131: "0", 1141: "-76", 1101: "30", 1601: "1"},
        }
    )
    assert [state.devices[c].online for c in (0, 1, 16)] == [True, True, False]
    sensor = state.devices[16]
    assert (sensor.battery, sensor.rssi) == (30, -76)  # the frozen last report


def test_coverage_names_a_setting_the_block_never_reported() -> None:
    """Pinned on the T8030's `time_format_set` (1253), left out of the station block."""
    state = _state_of({255: {1224: "0", 1216: "Hub", 1292: "20"}})
    station = state.coverage()[0]
    assert station.channel == STATION_CHANNEL
    assert station.has_settings
    assert "time_format_set" in station.unreported
    assert "prompt_volume_value" in station.reported
    assert not station.complete


def test_coverage_counts_a_reported_setting_and_ignores_parsed_state() -> None:
    state = _state_of(
        {0: {1131: "1", 1101: "80", 1214: "0", 9999: "x"}},
        sub_devices=(_camera(CAM_A, 0),),
    )
    camera = next(c for c in state.coverage() if c.channel == 0)
    assert "watermark_set" in camera.reported
    # 1131 and 1101 are read into the state itself, so only the unread 9999 is left.
    assert camera.unread == (9999,)
    assert camera.online is True


def test_coverage_counts_the_active_mode_as_parsed_state() -> None:
    state = _state_of({255: {1224: "2", 1151: "1", 9999: "x"}})
    station = state.coverage()[0]
    assert state.active_mode is GuardMode.HOME
    assert station.unread == (9999,)


def test_coverage_claims_nothing_for_an_unknown_model() -> None:
    state = _state_of({3: {1101: "50", 1214: "0"}})
    block = next(c for c in state.coverage() if c.channel == 3)
    assert not block.has_settings
    assert (block.reported, block.unreported) == ((), ())
    assert block.unread == (1214,)  # 1101 is parsed state; 1214 is read nowhere


def test_catalogued_serial_decides_kind_over_markers() -> None:
    sensor = CloudDevice(
        device_sn=SENSOR_SN, device_type=10, name="Path", station_sn=SYNTHETIC.station_sn, channel=0
    )
    state = _state_of(_sub_device_blocks(), sub_devices=(sensor,))
    assert state.devices[0].kind is DeviceKind.SENSOR  # the camera markers are ignored


@pytest.mark.parametrize("raw", ["1780000000", "0", "-5", "soon", "99999999999999"])
def test_implausible_pir_time_is_dropped(raw: str) -> None:
    assert _state_of({16: {1605: raw}}).devices[16].pir_event_ms is None


def test_unmarked_block_has_no_kind() -> None:
    assert _state_of({3: {1101: "50"}}).devices[3].kind is None


def test_station_diagnostics_without_a_disk() -> None:
    state = _state_of(
        {255: {1189: "0", 1190: "12", 1176: "192.0.2.10", 1216: " Home "}},
        meta={"sec_sw_version": "1.4.0.8"},
        cloud_sec_firmware="1.0.0.0",
    )
    assert state.emmc_used_percent == 12
    assert state.lan_ip == "192.0.2.10"
    assert state.name == "Home"
    assert state.sec_firmware == "1.4.0.8"


def test_station_diagnostics_fall_back_or_stay_unknown() -> None:
    state = _state_of(
        {255: {1189: "45", 1190: "0", 1176: "host.example/x"}}, cloud_sec_firmware="1.0.0.0"
    )
    assert state.emmc_used_percent == 0  # a real value, not "none"
    assert state.lan_ip is None
    assert state.name == "HB"  # the cloud name
    assert state.sec_firmware == "1.0.0.0"
    bare = _state_of({255: {1189: "250", 1176: "::"}})
    assert bare.emmc_used_percent is None
    assert bare.lan_ip is None


@pytest.mark.parametrize(("raw", "ok"), [("0", True), ("25", True), ("1", False), ("x", None)])
def test_station_storage_status_and_subsystem_firmware(raw: str, ok: bool | None) -> None:
    state = _state_of({255: {1135: raw, 1102: "9752", 5006: "0.0.6.0", 5012: " ", 5010: "0.0.5.7"}})
    assert state.storage_ok is ok
    assert state.sd_info == 9752
    assert state.subsystem_firmware == {5006: "0.0.6.0", 5010: "0.0.5.7"}


def test_coverage_counts_the_power_and_storage_fields_as_parsed_state() -> None:
    state = _state_of(
        {
            0: {1400: "0", 1138: "21", 1191: "1", 1192: "2", 1193: "3", 2111: "4", 1309: "0"},
            16: {1601: "0", 1609: "8", 1509: "0", 1513: "0"},
            255: {1224: "0", 1102: "1", 1135: "0", 5006: "1", 5012: "1"},
        }
    )
    # 1400 only marks the block as a camera; nothing reads its value.
    assert [(cov.channel, cov.unread) for cov in state.coverage()] == [
        (STATION_CHANNEL, ()),
        (0, (1400,)),
        (16, ()),
    ]


# ── settings: what applies, current values ─────────────────────────────────────

_T8170_SN = "T8170P0000000000"


def _hub_with(*devices: CloudDevice) -> Station:
    station = _unconnected_station(host=None, local_ip=None, local_port=0)
    return Station(station.device, station.session, sub_devices=devices)


def _standalone_t8170() -> Station:
    device = CloudDevice(
        device_sn=_T8170_SN,
        station_sn=_T8170_SN,
        p2p_did=SYNTHETIC.did,
        device_type=48,
        channel=0,
        name="standalone",
    )
    station = _unconnected_station(host=None, local_ip=None, local_port=0)
    return Station(device, station.session)


def test_settings_for_lists_the_model_then_the_mode_tables() -> None:
    sensor = CloudDevice(
        device_sn=SENSOR_SN,
        device_type=10,
        name="Path",
        station_sn=SYNTHETIC.station_sn,
        channel=16,
    )
    unknown = dataclasses.replace(sensor, device_sn="T9999P0000000002", channel=3)
    hub = _hub_with(CAMERA, sensor, unknown)
    camera = hub.settings_for(SYNTHETIC.camera_sn)
    own = settings_of("T8160")
    modes = mode_table_settings(Scope.CAMERA)
    assert camera[len(own) :] == modes
    assert {s.key for s in camera[: len(own)]} == set(own)
    # no T8160 setting has a group: (page, order, key) decides
    orders = [(s.page is None, s.page or "", s.order is None, s.order or 0, s.key) for s in camera]
    assert orders[: len(own)] == sorted(orders[: len(own)])
    assert camera[0].page == "AboutDevice"
    assert {s.key for s in hub.settings_for()} == set(settings_of("T8030"))  # no mode tables
    assert hub.settings_for(SYNTHETIC.station_sn) == hub.settings_for()
    assert hub.settings_for(SENSOR_SN)[-len(modes) :] == mode_table_settings(Scope.SENSOR)
    assert hub.settings_for("T9999P0000000002") == ()  # no settings file
    with pytest.raises(UnsupportedError, match="not paired"):
        hub.settings_for("T8160P2000099999")
    standalone = _standalone_t8170()
    assert {s.key for s in standalone.settings_for()} == set(settings_of("T8170"))
    assert standalone.settings_for(_T8170_SN) == standalone.settings_for()


def test_settings_sort_by_group_page_order_key() -> None:
    def make(key: str, group: str | None, order: int | None, page: str | None = None) -> Setting:
        return Setting(
            key=key,
            product_code="",
            name=key,
            kind=SettingKind.BOOL,
            group=group,
            order=order,
            page=page,
        )

    settings = [
        make("z", None, None),
        make("b", "second", 1),
        make("a", "first", 2),
        make("c", "first", 0),
        make("d", None, 0),
        make("y", None, None, "Video"),
        make("x", None, None, "Audio"),
        make("w", None, 5, "Audio"),
        make("e", "first", 1, "Audio"),
    ]
    ordered = station_mod._sorted_settings({s.key: s for s in settings})
    # "first" ranks first because its lowest order (c, 0) comes before "second"'s (b, 1);
    # inside a group a page sorts before no page, pages by name, then order and key.
    assert [s.key for s in ordered] == ["e", "c", "a", "b", "w", "x", "y", "d", "z"]


def test_setting_returns_the_listed_object_per_target() -> None:
    hub = _hub_with(CAMERA)
    by_channel = hub.setting("watermark_set", channel=0)
    listed = next(s for s in hub.settings_for(SYNTHETIC.camera_sn) if s.key == "watermark_set")
    assert by_channel is listed
    assert hub.setting("watermark_set", device_sn=SYNTHETIC.camera_sn) is listed
    with pytest.raises(UnsupportedError, match="unknown setting"):
        hub.setting("watermark_set")  # the station (T8030) has no such key
    with pytest.raises(UnsupportedError, match="no paired device on channel 7"):
        hub.setting("watermark_set", channel=7)
    with pytest.raises(ValueError, match="at most one"):
        hub.setting("watermark_set", device_sn=SYNTHETIC.camera_sn, channel=0)


def _settings_state() -> StationState:
    sensor = CloudDevice(
        device_sn=SENSOR_SN,
        device_type=10,
        name="Path",
        station_sn=SYNTHETIC.station_sn,
        channel=16,
    )
    return _state_of(
        {
            0: {1246: "2", 1251: "0", 1230: "90", 1400: "0"},
            16: {1166: "0", 1601: "1"},
            255: {1292: "20"},
        },
        sub_devices=(CAMERA, sensor),
    )


def test_setting_reads_the_public_value_by_channel_or_serial() -> None:
    state = _settings_state()
    assert state.setting("power_manager_mode", channel=0) == 3
    assert state.setting("power_manager_mode", device_sn=SYNTHETIC.camera_sn) == 3
    assert state.devices[0].setting("power_manager_mode") == 3
    assert state.setting("motion_stop_end_early", channel=0) is True
    assert state.setting("speaker_volume", channel=0) == 0  # 90 is the low volume
    assert state.setting("prompt_volume_value") == 20  # the station block, channel 255
    assert state.setting("prompt_volume_value", channel=255) == 20
    assert state.setting("alarm_delay_home", channel=16) == 0  # a real 0, not "absent"
    assert state.setting("alarm_delay_home", device_sn=SENSOR_SN) == 0


def test_setting_is_none_when_absent_never_a_default() -> None:
    state = _settings_state()
    assert state.setting("watermark_set", channel=0) is None
    assert state.devices[0].setting("alarm_delay_home") is None
    assert state.setting("device_name", channel=0) is None  # not readable
    absent = _state_of({255: {1224: "0"}}, sub_devices=(CAMERA,))  # no block for the camera
    assert absent.setting("watermark_set", device_sn=SYNTHETIC.camera_sn) is None
    assert absent.setting("watermark_set", channel=0) is None


def test_setting_refuses_a_key_the_device_does_not_have() -> None:
    state = _settings_state()
    with pytest.raises(UnsupportedError, match="unknown setting"):
        state.setting("party_mode", channel=0)
    with pytest.raises(UnsupportedError, match="unknown setting"):
        state.setting("alarm_delay_home")  # the station carries no mode-table setting
    with pytest.raises(UnsupportedError, match="unknown setting"):
        state.setting("watermark_set", channel=16)  # a camera setting on the sensor
    with pytest.raises(UnsupportedError, match="unknown setting"):
        state.setting("watermark_set", channel=7)  # no device on that channel
    with pytest.raises(UnsupportedError, match="unknown setting"):
        state.setting("watermark_set", device_sn="T8160P2000099999")  # not paired
    with pytest.raises(UnsupportedError, match="unknown setting"):
        _state_of({3: {1101: "50"}}).devices[3].setting("watermark_set")  # unknown model
    with pytest.raises(ValueError, match="at most one"):
        state.setting("power_manager_mode", device_sn=SYNTHETIC.camera_sn, channel=0)


def test_a_standalone_device_reads_its_own_settings() -> None:
    # The session files a standalone block under 255 and its own channel alike.
    state = _standalone_t8170()._state(_dump_of({0: {6014: "1"}, 255: {6014: "1"}}))
    assert state.devices[0].setting("led_on_off") is True
    assert state.setting("led_on_off", device_sn=_T8170_SN) is True
    assert state.setting("led_on_off") is True


def _mode_table_blocks(fake: FakeStation) -> None:
    """The synthetic camera (0) and a motion sensor known only by its markers (16)."""
    fake.params[0].update({1400: "0", 1239: "9", 1167: "0", 1172: "0", 1225: "1", 1166: "30"})
    fake.params[16] = {1601: "1", 1239: "8", 1167: "0", 1172: "0", 1225: "0", 1166: "30"}


async def test_mode_action_write_sends_the_whole_table(station: Station, fake: FakeStation) -> None:
    _mode_table_blocks(fake)
    mask = await station.async_set_mode_action(
        "away", "camera_siren", True, device_sn=SYNTHETIC.camera_sn
    )
    assert mask == 11
    assert fake.mode_tables_received == [
        {
            "account_id": SYNTHETIC.account_id,
            "mode_id": 0,
            "devices": [
                {"device_channel": 16, "action": 8},
                {"device_channel": 0, "action": 11},
            ],
            "count_down_alarm": {"channel_list": [], "delay_time": 0},
            "count_down_arm": {"channel_list": [], "delay_time": 0},
            "siren_sensor_action": [
                {"device_channel": 16, "action": 0},
                {"device_channel": 0, "action": 0},
            ],
        }
    ]
    assert (fake.params[0][1239], fake.params[16][1239]) == ("11", "8")
    assert fake.received == []  # no DeviceMsgBean: the table is its own frame type
    assert await station.async_set_mode_action("away", "camera_siren", True, channel=0) == 11
    assert len(fake.mode_tables_received) == 1  # already on: nothing written


async def test_a_delay_write_moves_every_device_that_has_it_on(
    station: Station, fake: FakeStation
) -> None:
    _mode_table_blocks(fake)
    fake.params[0][1166] = "0"
    assert (
        await station.async_set_setting("alarm_delay_home", 45, channel=0) is CommandOutcome.APPLIED
    )
    table = fake.mode_tables_received[-1]
    assert (table["mode_id"], table["count_down_alarm"]) == (
        1,
        {"channel_list": [16, 0], "delay_time": 45},
    )
    assert table["devices"] == [
        {"device_channel": 16, "action": 0},
        {"device_channel": 0, "action": 1},
    ]
    assert (fake.params[0][1166], fake.params[16][1166]) == ("45", "45")


async def test_a_mode_table_is_confirmed_by_read_back_not_the_receipt(
    station: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(session_module, "MODE_TABLE_READBACK_DELAY", 0.0)
    _mode_table_blocks(fake)
    fake.apply_settings = False  # a zero receipt, and nothing changes
    with pytest.raises(
        CommandNotAppliedError, match=r"channel 0 param 1239 \(camera_action_away\): wrote 11"
    ):
        await station.async_set_mode_action("away", "camera_siren", True, channel=0)
    fake.mode_table_receipt_code = -104
    with pytest.raises(CommandRejectedError, match="code -104"):
        await station.async_set_mode_action("away", "camera_siren", True, channel=0)


async def test_mode_table_refusals_send_nothing(station: Station, fake: FakeStation) -> None:
    _mode_table_blocks(fake)
    with pytest.raises(UnsupportedError, match="no per-device actions"):
        await station.async_set_mode_action("schedule", "record", True, channel=0)
    with pytest.raises(UnsupportedError, match="known flags"):
        await station.async_set_mode_action("away", "motion_sensor_respond", True, channel=0)
    with pytest.raises(UnsupportedError, match="unknown setting"):
        await station.async_set_setting("sensor_action_away", 12, channel=0)
    fake.params[16][1172] = "60"  # the Away leaving delay differs between devices
    fake.params[0][1172] = "30"
    with pytest.raises(UnsupportedError, match="differs between devices"):
        await station.async_set_setting("camera_action_away", 3, channel=0)
    fake.params[3] = {1239: "1"}  # a block of no known kind: maybe a siren accessory
    with pytest.raises(UnsupportedError, match="no known device kind"):
        await station.async_set_setting("camera_action_away", 3, channel=0)
    with pytest.raises(ValueError, match="exactly one"):
        await station.async_set_mode_action("away", "record", True)
    assert fake.mode_tables_received == []


async def test_async_event_image_thumbnail_returns_jpeg(
    station: Station, fake: FakeStation
) -> None:
    fake.images["/zx/push.jpg"] = b"\xff\xd8JFIF\x00\x01\x02"
    event = SecurityEvent(
        source=EventSource.P2P,
        station_sn=SYNTHETIC.station_sn,
        device_sn=SYNTHETIC.camera_sn,
        thumb_path="/zx/push.jpg",
        record_id=20260916 * HISTORY_RECORD_COUNTER + 42,
    )
    image = await station.async_event_image(event, source=ImageSource.THUMBNAIL)
    assert image.source is ImageSource.THUMBNAIL
    assert image.device_sn == SYNTHETIC.camera_sn
    assert image.data == b"\xff\xd8JFIF\x00\x01\x02"
    assert image.content_type == JPEG_CONTENT_TYPE
    assert image.record_id == 20260916 * HISTORY_RECORD_COUNTER + 42


async def test_async_event_image_thumbnail_rejects_obfuscated_stills(
    station: Station, fake: FakeStation
) -> None:
    fake.images["/zx/push.jpg"] = b"v8_eufysecurity" + b"\x00" * 8
    event = SecurityEvent(
        source=EventSource.P2P,
        station_sn=SYNTHETIC.station_sn,
        device_sn=SYNTHETIC.camera_sn,
        thumb_path="/zx/push.jpg",
    )
    with pytest.raises(UnsupportedError, match="not a JPEG"):
        await station.async_event_image(event, source=ImageSource.THUMBNAIL)


async def test_async_event_image_trigger_frame_returns_hevc_keyframe(
    station: Station, fake: FakeStation
) -> None:
    event = SecurityEvent(
        source=EventSource.P2P,
        station_sn=SYNTHETIC.station_sn,
        device_sn=None,
        channel=0,
        video_path="/zx/clip.zxvideo",
        record_id=20260916 * HISTORY_RECORD_COUNTER + 42,
    )
    image = await station.async_event_image(event, source=ImageSource.TRIGGER_FRAME)
    assert image.source is ImageSource.TRIGGER_FRAME
    assert image.device_sn == SYNTHETIC.camera_sn
    assert image.data == MEDIA_KEYFRAME
    assert image.content_type == HEVC_CONTENT_TYPE
    assert image.record_id == 20260916 * HISTORY_RECORD_COUNTER + 42


async def test_async_event_image_live_opens_the_camera(station: Station, fake: FakeStation) -> None:
    event = SecurityEvent(
        source=EventSource.P2P,
        station_sn=SYNTHETIC.station_sn,
        device_sn=SYNTHETIC.camera_sn,
    )
    image = await station.async_event_image(event, source=ImageSource.LIVE)
    assert image.source is ImageSource.LIVE
    assert image.device_sn == SYNTHETIC.camera_sn
    assert image.data == MEDIA_KEYFRAME
    assert image.content_type == HEVC_CONTENT_TYPE
    assert image.record_id is None

    opens = [o for o in fake.received if o["cmd"] == 1003]
    assert len(opens) == 1
    assert opens[0]["mChannel"] == 0


async def test_async_event_image_rejects_events_naming_no_paired_camera(
    station: Station,
) -> None:
    event = SecurityEvent(
        source=EventSource.P2P,
        station_sn=SYNTHETIC.station_sn,
        device_sn=None,
        channel=5,  # Unpaired channel
    )
    with pytest.raises(UnsupportedError, match="names no camera paired"):
        await station.async_event_image(event)
    event_no_camera = SecurityEvent(
        source=EventSource.P2P,
        station_sn=SYNTHETIC.station_sn,
        device_sn=None,
        channel=None,
    )
    with pytest.raises(UnsupportedError, match="names no camera paired"):
        await station.async_event_image(event_no_camera)


async def test_async_camera_image_trigger_frame_plays_newest_recording(
    station: Station, fake: FakeStation
) -> None:
    today_dt = datetime.now().astimezone().date()
    today = today_dt.strftime("%Y%m%d")
    today_int = int(today)
    fake.rows = [
        {
            "record_id": today_int * HISTORY_RECORD_COUNTER + 45,
            "device_sn": "T8160P2000099999",
            "storage_path": "/zx/other.zxvideo",
            "start_time": "2026-09-16 12:05:00",  # hygiene: ok
        },
        {
            "record_id": today_int * HISTORY_RECORD_COUNTER + 44,
            "device_sn": SYNTHETIC.camera_sn,
            "start_time": "2026-09-16 12:04:00",  # hygiene: ok
        },
        {
            "record_id": today_int * HISTORY_RECORD_COUNTER + 46,
            "device_sn": SYNTHETIC.camera_sn,
            "storage_path": "/zx/../escape.zxvideo",
        },
        {
            "record_id": today_int * HISTORY_RECORD_COUNTER + 43,
            "device_sn": SYNTHETIC.camera_sn,
            "storage_path": "/zx/wanted.zxvideo",
            "start_time": "2026-09-16 12:03:00",  # hygiene: ok
        },
        {
            "record_id": today_int * HISTORY_RECORD_COUNTER + 42,
            "device_sn": SYNTHETIC.camera_sn,
            "storage_path": "/zx/older.zxvideo",
            "start_time": "2026-09-16 12:02:00",  # hygiene: ok
        },
    ]
    image = await station.async_camera_image(SYNTHETIC.camera_sn, source=ImageSource.TRIGGER_FRAME)
    assert image.source is ImageSource.TRIGGER_FRAME
    assert image.device_sn == SYNTHETIC.camera_sn
    assert image.data == MEDIA_KEYFRAME
    assert image.content_type == HEVC_CONTENT_TYPE
    assert image.record_id == today_int * HISTORY_RECORD_COUNTER + 43
    assert image.recorded_at == "2026-09-16 12:03:00"  # hygiene: ok

    opens = [o for o in fake.received if o["cmd"] == 1025]
    assert len(opens) == 1
    assert opens[0]["mChannel"] == 0
    assert "wanted.zxvideo" in str(opens[0]["payload"])


async def test_async_camera_image_thumbnail_returns_newest_thumbnail(
    station: Station, fake: FakeStation
) -> None:
    today_dt = datetime.now().astimezone().date()
    today = today_dt.strftime("%Y%m%d")
    today_int = int(today)
    fake.images["/zx/wanted.jpg"] = b"\xff\xd8JFIF\x00\x01\x02"
    fake.rows = [
        {
            "record_id": today_int * HISTORY_RECORD_COUNTER + 44,
            "device_sn": SYNTHETIC.camera_sn,
        },
        {
            "record_id": today_int * HISTORY_RECORD_COUNTER + 43,
            "device_sn": SYNTHETIC.camera_sn,
            "thumb_path": "/zx/wanted.jpg",
            "start_time": "2026-09-16 12:03:00",  # hygiene: ok
        },
    ]
    image = await station.async_camera_image(SYNTHETIC.camera_sn, source=ImageSource.THUMBNAIL)
    assert image.source is ImageSource.THUMBNAIL
    assert image.data == b"\xff\xd8JFIF\x00\x01\x02"
    assert image.content_type == JPEG_CONTENT_TYPE
    assert image.record_id == today_int * HISTORY_RECORD_COUNTER + 43
    assert image.recorded_at == "2026-09-16 12:03:00"  # hygiene: ok


async def test_async_camera_image_searches_history_day_by_day(
    station: Station, fake: FakeStation
) -> None:
    today_dt = datetime.now().astimezone().date()
    two_days_ago_dt = today_dt - timedelta(days=2)
    two_days_ago = int(two_days_ago_dt.strftime("%Y%m%d"))

    fake.images["/zx/found.jpg"] = b"\xff\xd8JFIF..."
    fake.rows = [
        {
            "record_id": two_days_ago * HISTORY_RECORD_COUNTER + 42,
            "device_sn": SYNTHETIC.camera_sn,
            "thumb_path": "/zx/found.jpg",
            "start_time": "2026-09-14 12:02:00",  # hygiene: ok
        }
    ]

    image = await station.async_camera_image(
        SYNTHETIC.camera_sn, source=ImageSource.THUMBNAIL, days=5
    )
    assert image.record_id == two_days_ago * HISTORY_RECORD_COUNTER + 42

    days_queried = [q["start_date"] for q in fake.history_queries]
    assert days_queried == [
        today_dt.strftime("%Y%m%d"),
        (today_dt - timedelta(days=1)).strftime("%Y%m%d"),
        (today_dt - timedelta(days=2)).strftime("%Y%m%d"),
    ]


async def test_async_camera_image_raises_when_no_usable_row_in_window(
    station: Station, fake: FakeStation
) -> None:
    today_dt = datetime.now().astimezone().date()
    two_days_ago_dt = today_dt - timedelta(days=2)
    two_days_ago = int(two_days_ago_dt.strftime("%Y%m%d"))

    fake.rows = [
        {
            "record_id": two_days_ago * HISTORY_RECORD_COUNTER + 42,
            "device_sn": SYNTHETIC.camera_sn,
            "thumb_path": "/zx/found.jpg",
            "start_time": "2026-09-14 12:02:00",  # hygiene: ok
        }
    ]

    with pytest.raises(RecordNotFoundError, match="last 2 day"):
        await station.async_camera_image(SYNTHETIC.camera_sn, source=ImageSource.THUMBNAIL, days=2)

    assert len(fake.history_queries) == 2


async def test_async_camera_image_live_does_not_query_history(
    station: Station, fake: FakeStation
) -> None:
    image = await station.async_camera_image(SYNTHETIC.camera_sn, source=ImageSource.LIVE)
    assert image.source is ImageSource.LIVE
    assert image.data == MEDIA_KEYFRAME
    assert not fake.history_queries


async def test_async_camera_image_rejects_unpaired_and_invalid_days(
    station: Station, fake: FakeStation
) -> None:
    sent_before = len(fake.received)
    with pytest.raises(ValueError, match="days must be at least 1"):
        await station.async_camera_image(SYNTHETIC.camera_sn, days=0)
    with pytest.raises(UnsupportedError, match="not paired"):
        await station.async_camera_image("T8160P2000099999")
    assert len(fake.received) == sent_before


async def test_event_thumbnail_passes_timeout_to_history_query(
    station: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    event = SecurityEvent(
        source=EventSource.P2P,
        station_sn=SYNTHETIC.station_sn,
        device_sn=SYNTHETIC.camera_sn,
        record_id=2026091600042,
    )

    passed: dict[str, Any] = {}
    history_record = station.session.async_history_record

    async def spy(record_id: int, **kwargs: Any) -> HistoryRecord | None:
        passed.update(kwargs)
        return await history_record(record_id, **kwargs)

    monkeypatch.setattr(station.session, "async_history_record", spy)
    with pytest.raises(RecordNotFoundError):  # the fake has no rows
        await station.async_event_thumbnail(event, timeout=4.2)
    assert passed == {"timeout": 4.2}


async def test_a_standalone_station_is_its_own_device_on_its_channel() -> None:
    serial = "T8170" + SYNTHETIC.station_sn[5:]
    device = CloudDevice(
        device_sn=serial,
        station_sn=serial,
        p2p_did="TST-1234",
        device_type=48,
        channel=0,
        name="standalone",
    )
    fake = FakeStation(params={48: {1224: "1", 1101: "51"}})
    await fake.start()

    async def creds(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", fake.ecc_private_key_hex)

    session = StationSession(
        device.device_sn,
        creds,
        host="127.0.0.1",
        port=fake.discovery_port,
        block_aliases=station_block_aliases(device),
        expect_channels=station_channels(device, ()),
    )
    station = Station(device, session)

    try:
        assert station.is_standalone is True
        assert station.channels == frozenset({0})
        assert station.channel_for(serial) == 0
        assert station.sub_device(serial) is device

        state = await station.async_update()

        assert state.devices[0].serial == serial
        assert state.guard_mode == 1
        assert state.params == state.devices[0].params

        homebase = CloudDevice(
            device_sn="T8030XYZ",
            station_sn=None,
            device_type=0,
            channel=None,
            name="homebase",
        )
        assert not homebase.is_standalone
        assert station_block_aliases(homebase) == {}
    finally:
        await station.session.async_close()
        fake.stop()


@pytest.fixture
async def on_demand_pair() -> AsyncIterator[tuple[Station, FakeStation]]:
    sn = "T8170P0000000000"
    fake = FakeStation(
        serial=sn,
        guard_mode=1,
        receipt_len=STANDALONE_RECEIPT_LEN,
        params={48: {1224: "1", 1101: "51"}},
    )
    await fake.start()

    async def credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", fake.ecc_private_key_hex)

    device = CloudDevice(
        device_sn=sn,
        device_type=48,
        name="Solo",
        p2p_did="EUPRAMA-123456-ABCDE",
        station_sn=sn,
        channel=0,
    )
    session = StationSession(
        sn,
        credentials,
        host="127.0.0.1",
        port=fake.discovery_port,
        on_demand=True,
        block_aliases={48: (255, 0)},
    )
    st = Station(device, session, sub_devices=[])
    yield st, fake
    await st.async_close()
    fake.stop()


async def test_on_demand_async_update_no_state_connects(
    on_demand_pair: tuple[Station, FakeStation],
) -> None:
    on_demand_station, fake = on_demand_pair
    assert on_demand_station.state is None
    await on_demand_station.async_update()
    assert fake.conn_inits == 1


async def test_on_demand_async_update_with_state_returns_it(
    on_demand_pair: tuple[Station, FakeStation],
) -> None:
    on_demand_station, fake = on_demand_pair
    # fake ingest
    cloud_dev = CloudDevice(
        device_sn="T8170P0000000000",
        device_type=48,
        name="Solo",
        p2p_did=SYNTHETIC.did,
        station_sn="T8170P0000000000",
        channel=0,
        raw={"params": [{"param_type": 1101, "param_value": "87", "update_time": 1600000000.0}]},
    )
    count = on_demand_station.apply_cloud_device(cloud_dev)
    assert count == 1
    assert on_demand_station.state is not None
    assert on_demand_station.state.devices[0].battery == 87

    # async_update should not connect
    await on_demand_station.async_update()
    assert fake.conn_inits == 0

    # wake=True should connect
    await on_demand_station.async_update(wake=True)
    assert fake.conn_inits == 1


def _snapshot(mode: GuardMode, updated_at: float) -> CloudDevice:
    """The cloud's device-list entry of the on-demand pair's T8170, with ``mode`` as 1224."""
    return CloudDevice(
        device_sn="T8170P0000000000",
        device_type=48,
        name="Solo",
        p2p_did=SYNTHETIC.did,
        station_sn="T8170P0000000000",
        channel=0,
        raw={
            "params": [
                {"param_type": 1224, "param_value": str(int(mode)), "update_time": updated_at}
            ]
        },
    )


async def test_on_demand_confirmed_arm_is_the_state_until_a_newer_snapshot(
    on_demand_pair: tuple[Station, FakeStation],
) -> None:
    station, fake = on_demand_pair
    station.apply_cloud_device(_snapshot(GuardMode.HOME, 1.7e9))
    assert station.state is not None
    assert station.state.guard_mode == GuardMode.HOME

    before = time.time()
    assert await station.async_set_guard_mode(GuardMode.AWAY) == GuardMode.AWAY
    assert fake.conn_inits == 1

    assert station.state is not None
    assert station.state.guard_mode == GuardMode.AWAY
    assert (await station.async_update()).guard_mode == GuardMode.AWAY
    assert fake.conn_inits == 1  # the poll did not wake it

    # A snapshot dated before the arm is older news: the confirmed mode stays.
    assert station.apply_cloud_device(_snapshot(GuardMode.HOME, before - 60)) == 0
    assert (await station.async_update()).guard_mode == GuardMode.AWAY

    # One dated after it (a change made elsewhere since) wins.
    assert station.apply_cloud_device(_snapshot(GuardMode.HOME, time.time() + 60)) == 1
    assert (await station.async_update()).guard_mode == GuardMode.HOME


async def test_fake_standalone_arm_lands_in_its_device_type_block(
    on_demand_pair: tuple[Station, FakeStation],
) -> None:
    station, fake = on_demand_pair
    await station.async_set_guard_mode(GuardMode.AWAY)

    assert fake.params[48][1224] == str(int(GuardMode.AWAY))
    assert STATION_CHANNEL not in fake.params  # a T8170 dump has no 255 block
    assert (await station.async_update(wake=True)).guard_mode == GuardMode.AWAY


def test_apply_cloud_device(on_demand_pair: tuple[Station, FakeStation]) -> None:
    on_demand_station, _ = on_demand_pair
    # Ignores device of another serial
    other = CloudDevice(
        device_sn="OTHER",
        device_type=48,
        name="Other",
        raw={"params": [{"param_type": 1101, "param_value": "87"}]},
    )
    assert on_demand_station.apply_cloud_device(other) == 0

    # Standalone device filed under its device_type
    dev = CloudDevice(
        device_sn="T8170P0000000000",
        device_type=48,
        name="Solo",
        raw={"params": [{"param_type": 1224, "param_value": "1"}]},
    )
    on_demand_station.apply_cloud_device(dev)
    # block aliases apply to the session
    assert on_demand_station.session.params[(255, 1224)] == "1"


def test_connects_on_demand_mirrors_session(
    on_demand_pair: tuple[Station, FakeStation], station: Station
) -> None:
    on_demand_station, _ = on_demand_pair
    assert on_demand_station.connects_on_demand is True
    assert station.connects_on_demand is False


def test_station_devices_hub_vs_standalone(
    on_demand_pair: tuple[Station, FakeStation], station: Station
) -> None:
    on_demand_station, _ = on_demand_pair
    assert station.devices == (CAMERA,)
    assert on_demand_station.devices == (on_demand_station.device,)


async def _standalone(fake: FakeStation, serial: str) -> Station:
    """A standalone camera ``serial`` that is its own station, on ``fake``."""
    fake.serial = serial
    fake.static_key = static_key(serial, fake.did)

    async def credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", fake.ecc_private_key_hex)

    session = StationSession(serial, credentials, host="127.0.0.1", port=fake.discovery_port)
    device = CloudDevice(
        device_sn=serial,
        device_type=18,
        name="PTZ",
        p2p_did=SYNTHETIC.did,
        station_sn=serial,
    )
    station = Station(device, session)
    await station.async_update()
    return station


@pytest.fixture
async def standalone_station(fake: FakeStation) -> AsyncIterator[Station]:
    station = await _standalone(fake, "T8170P2000054321")
    yield station
    await station.async_close()


_T8410_SN = "T8410P2000054321"


@pytest.fixture
async def t8410_station(fake: FakeStation) -> AsyncIterator[Station]:
    """A standalone T8410: pan/tilt without presets, its handler's own recipes."""
    station = await _standalone(fake, _T8410_SN)
    yield station
    await station.async_close()


async def test_a_standalone_cameras_writes_go_to_its_own_channel(
    standalone_station: Station, fake: FakeStation
) -> None:
    # Addressed as the station itself (channel 255, no target, or its own serial), a
    # standalone camera's settings are sent on its own channel (0 here), never on 255:
    # the 1700 subheader's channel and the 1350 payload's `channel` field both name 0.
    serial = standalone_station.serial
    for target in ({"channel": STATION_CHANNEL}, {}, {"device_sn": serial}):
        fake.params.get(0, {}).pop(6014, None)
        outcome = await standalone_station.async_set_setting("led_on_off", True, **target)
        assert outcome is CommandOutcome.DELIVERED  # a bare 1700 receipt
        assert fake.params[0][6014] == "1"  # filed under the 1700 subheader's channel
        assert 6014 not in fake.params.get(STATION_CHANNEL, {})
    assert fake.doorbell_payloads[-1] == {"commandType": 6014, "data": {"value": 1}}
    await standalone_station.async_set_setting("ptz_turn_speed", 3)  # speed 3 of 5
    assert fake.doorbell_payloads[-1]["data"]["value"] == 3
    fake.reply_to_settings = True  # a result for the 1350 write, not the 6 s receipt wait
    await standalone_station.async_set_setting("nightvision_type", 2, channel=STATION_CHANNEL)
    assert fake.received[-1]["cmd"] == 1277
    assert fake.received[-1]["payload"] == {"channel": 0, "night_sion": 2}
    await standalone_station.async_set_setting("timezone_set", "Europe/Helsinki")
    helsinki = "EET-2EEST,M3.5.0/3,M10.5.0/4|1.1386"
    assert fake.string_commands_received[-1] == (1215, 0, helsinki)
    assert fake.params[0][1215] == helsinki
    state = standalone_station.state
    assert state is not None
    assert state.setting("timezone_set", channel=0) == "Europe/Helsinki"


async def test_async_preset_image_standalone(
    standalone_station: Station, fake: FakeStation
) -> None:
    events: list[Event] = []
    standalone_station.subscribe(events.append)

    assert not standalone_station.is_capturing("T8170P2000054321")
    img_task = asyncio.create_task(
        standalone_station.async_preset_image("T8170P2000054321", 1, settle=0.1)
    )
    await asyncio.sleep(0.05)

    assert standalone_station.is_capturing("T8170P2000054321")

    busy_events = [e for e in events if isinstance(e, CameraBusyChanged)]
    assert busy_events
    assert busy_events[-1].busy is True

    img = await img_task
    assert isinstance(img, CameraImage)
    assert img.source == ImageSource.LIVE
    assert img.preset == 1
    assert img.content_type == "video/hevc"
    assert not standalone_station.is_capturing("T8170P2000054321")

    assert fake.preset_gotos == [1]

    busy_events = [e for e in events if isinstance(e, CameraBusyChanged)]
    assert busy_events[-1].busy is False


async def test_async_preset_image_busy_errors(
    standalone_station: Station, fake: FakeStation
) -> None:
    img_task = asyncio.create_task(
        standalone_station.async_preset_image("T8170P2000054321", 1, settle=0.3)
    )
    await asyncio.sleep(0.05)

    with pytest.raises(DeviceBusyError):
        await standalone_station.async_preset_image("T8170P2000054321", 2)

    img_task2 = asyncio.create_task(
        standalone_station.async_preset_image("T8170P2000054321", 1, settle=0.3)
    )
    img1 = await img_task
    img2 = await img_task2
    assert img1 is img2

    img_task3 = asyncio.create_task(
        standalone_station.async_preset_image("T8170P2000054321", 1, settle=0.3)
    )
    await asyncio.sleep(0.05)
    with pytest.raises(DeviceBusyError):
        await standalone_station.async_camera_image("T8170P2000054321", source=ImageSource.LIVE)

    await img_task3


async def test_async_preset_image_unsupported(station: Station, fake: FakeStation) -> None:
    with pytest.raises(UnsupportedError):
        await station.async_preset_image(SYNTHETIC.camera_sn, 1)


async def test_async_preset_image_disabled_slot(
    standalone_station: Station, fake: FakeStation
) -> None:
    await standalone_station.async_refresh_presets("T8170P2000054321")
    with pytest.raises(UnsupportedError):
        await standalone_station.async_preset_image("T8170P2000054321", 5)

    assert fake.preset_gotos == []


async def test_async_preset_image_timeout(
    standalone_station: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:

    monkeypatch.setattr(session_mod, "MEDIA_PING_INTERVAL", 9999)
    monkeypatch.setattr(session_mod, "MEDIA_IDLE_TIMEOUT", 0.1)
    monkeypatch.setattr(station_mod, "PRESET_STREAM_IDLE_SECONDS", 0.1)
    fake.live_ends_unpinged_after = 0.05

    with pytest.raises(DeviceTimeoutError):
        await standalone_station.async_preset_image("T8170P2000054321", 1, settle=0.5)


async def test_presets_refresh_and_cache(standalone_station: Station, fake: FakeStation) -> None:

    cache = SessionCache(MemoryStore(), "test@example.com")
    standalone_station._cache = cache

    assert standalone_station.presets("T8170P2000054321") is None
    events: list[Event] = []
    standalone_station.subscribe(events.append)

    presets_list = await standalone_station.async_refresh_presets("T8170P2000054321")
    assert len(presets_list) == 10
    assert standalone_station.presets("T8170P2000054321") == presets_list

    preset_events = [e for e in events if isinstance(e, PresetsChanged)]
    assert len(preset_events) == 1

    await standalone_station.async_refresh_presets("T8170P2000054321")
    preset_events = [e for e in events if isinstance(e, PresetsChanged)]
    assert len(preset_events) == 1

    device2 = CloudDevice(
        device_sn="T8170P2000054321",
        device_type=18,
        name="PTZ",
        p2p_did=SYNTHETIC.did,
        station_sn="T8170P2000054321",
    )
    station2 = Station(device2, standalone_station.session, cache=cache)
    await station2.async_update()

    assert station2.presets("T8170P2000054321") == presets_list


async def test_pan_tilt_sends_direction(standalone_station: Station, fake: FakeStation) -> None:
    await standalone_station.async_pan_tilt("T8170P2000054321", PanTilt.LEFT, settle=0)
    await standalone_station.async_pan_tilt("T8170P2000054321", PanTilt.UP, settle=0)

    assert fake.pan_tilts == [PanTilt.LEFT, PanTilt.UP]
    body = next(b for b in fake.doorbell_payloads if b.get("commandType") == 6030)
    assert body["data"] == {"cmd_type": 1, "rotate_type": 1, "zoom": 1, "ivalue": -1}


async def test_a_t8410_pan_tilt_sends_its_handlers_bare_step(
    t8410_station: Station, fake: FakeStation
) -> None:
    await t8410_station.async_pan_tilt(_T8410_SN, PanTilt.RIGHT, settle=0)

    assert fake.pan_tilts == [PanTilt.RIGHT]
    body = next(b for b in fake.doorbell_payloads if b.get("commandType") == 6030)
    assert body["data"] == {"cmd_type": 1, "rotate_type": 2}


async def test_a_t8410_live_open_leaves_out_ext_value(
    t8410_station: Station, fake: FakeStation
) -> None:
    stream = await t8410_station.async_open_live(_T8410_SN)
    async with stream:
        await anext(aiter(stream))

    (body,) = [b["data"] for b in fake.doorbell_payloads if b.get("commandType") == 1000]
    assert "extValue" not in body
    assert body["ivalue"] == 1
    assert fake.live_opens == [0]


async def test_a_t8170_live_open_keeps_ext_value(
    standalone_station: Station, fake: FakeStation
) -> None:
    stream = await standalone_station.async_open_live("T8170P2000054321")
    async with stream:
        await anext(aiter(stream))

    (body,) = [b["data"] for b in fake.doorbell_payloads if b.get("commandType") == 1000]
    assert body["extValue"] == 1000


async def test_a_t8410_refuses_every_slot_call_before_sending(
    t8410_station: Station, fake: FakeStation
) -> None:
    """PTZ_CONTROL without PTZ_PRESETS: a slot store, delete or picture is refused."""
    for call in (
        t8410_station.async_store_preset(_T8410_SN, 1),
        t8410_station.async_delete_preset(_T8410_SN, 1),
        t8410_station.async_preset_picture(_T8410_SN, 1),
        t8410_station.async_save_preset(_T8410_SN),
    ):
        with pytest.raises(UnsupportedError, match="presets"):
            await call

    assert fake.doorbell_payloads == []


async def _until(condition: Callable[[], bool], timeout: float = 2.0) -> None:
    deadline = time.monotonic() + timeout
    while not condition():
        assert time.monotonic() < deadline, "condition not met in time"
        await asyncio.sleep(0.01)


async def test_set_zoom_sends_6203_and_the_echo_sets_the_zoom(
    standalone_station: Station, fake: FakeStation
) -> None:
    events: list[Event] = []
    standalone_station.subscribe(events.append)
    assert standalone_station.zoom("T8170P2000054321") is None

    await standalone_station.async_set_zoom("T8170P2000054321", 2.5)

    assert fake.zoom_writes == [2.5]
    index, body = next(
        (i, o) for i, o in reversed(list(enumerate(fake.received))) if o.get("cmd") == 6203
    )
    assert body["payload"] == {
        "x": 0,
        "y": 0,
        "w": 0,
        "h": 0,
        "offset": False,
        "orgZoom": 0,
        "dstZoom": 2.5,
    }
    # A standalone camera is channel 0, so its subheader byte stays 0.
    assert body["mChannel"] == 0
    assert fake.received_header_channels[index] == 0
    await _until(lambda: standalone_station.zoom("T8170P2000054321") == 2.5)
    zooms = [e for e in events if isinstance(e, ZoomChanged)]
    assert zooms == [
        ZoomChanged(station_sn="T8170P2000054321", device_sn="T8170P2000054321", zoom=2.5)
    ]


async def test_an_unsolicited_zoom_report_counts_and_0_means_1x(
    standalone_station: Station, fake: FakeStation
) -> None:
    """The camera reports ``{"dstZoom": 0}`` after a go-to or a live open; 0 is 1x."""
    events: list[Event] = []
    standalone_station.subscribe(events.append)

    fake.send_zoom_report(0)
    await _until(lambda: standalone_station.zoom("T8170P2000054321") == 1.0)
    fake.send_zoom_report(1)
    fake.send_zoom_report(3)
    await _until(lambda: standalone_station.zoom("T8170P2000054321") == 3.0)

    assert [e.zoom for e in events if isinstance(e, ZoomChanged)] == [1.0, 3.0]


async def test_zoom_returns_to_1x_when_the_link_drops(
    standalone_station: Station, fake: FakeStation
) -> None:
    """A camera that went idle has returned to 1x; the reset is announced."""
    events: list[Event] = []
    standalone_station.subscribe(events.append)
    await standalone_station.async_set_zoom("T8170P2000054321", 4)
    await _until(lambda: standalone_station.zoom("T8170P2000054321") == 4.0)

    fake.send_close()
    await _until(lambda: standalone_station.zoom("T8170P2000054321") == 1.0)

    assert [e.zoom for e in events if isinstance(e, ZoomChanged)] == [4.0, 1.0]


async def test_a_zoom_report_on_another_channel_is_ignored(
    standalone_station: Station, fake: FakeStation
) -> None:
    events: list[Event] = []
    standalone_station.subscribe(events.append)
    fake.send_json(
        FrameType.NOTIFY_PAYLOAD, {"cmd": 6203, "mChannel": 5, "payload": {"dstZoom": 2}}, channel=2
    )
    fake.send_zoom_report(3)
    await _until(lambda: standalone_station.zoom("T8170P2000054321") == 3.0)

    assert [e.zoom for e in events if isinstance(e, ZoomChanged)] == [3.0]


@pytest.mark.parametrize("zoom", [0.5, 0, 12.5, math.nan, math.inf])
async def test_set_zoom_out_of_range_sends_nothing(
    standalone_station: Station, fake: FakeStation, zoom: float
) -> None:
    with pytest.raises(ValueError, match="zoom"):
        await standalone_station.async_set_zoom("T8170P2000054321", zoom)
    assert fake.zoom_writes == []


async def test_set_zoom_unsupported(station: Station, fake: FakeStation) -> None:
    with pytest.raises(UnsupportedError):
        await station.async_set_zoom(SYNTHETIC.camera_sn, 2)
    assert fake.zoom_writes == []


PAIRED_PTZ = CloudDevice(
    device_sn="T8170P2000054321",
    device_type=48,
    name="PTZ",
    station_sn=SYNTHETIC.station_sn,
    channel=2,
)


@pytest.fixture
async def paired_ptz(fake: FakeStation) -> AsyncIterator[Station]:
    """A T8030 with a T8170 paired on channel 2, which it passes 1350 commands on to only
    under that subheader channel."""
    fake.params[2] = fake.params.pop(0)
    fake.relayed_channels = {2}

    async def credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", fake.ecc_private_key_hex)

    session = StationSession(
        SYNTHETIC.station_sn, credentials, host="127.0.0.1", port=fake.discovery_port
    )
    st = Station(STATION, session, sub_devices=[PAIRED_PTZ])
    await st.async_update()
    yield st
    await st.async_close()


async def test_set_zoom_of_a_paired_camera_names_its_channel_in_the_subheader(
    paired_ptz: Station, fake: FakeStation
) -> None:
    await paired_ptz.async_set_zoom(PAIRED_PTZ.device_sn, 4)

    assert fake.zoom_writes == [4]
    assert fake.received_header_channels[-1] == 2
    await _until(lambda: paired_ptz.zoom(PAIRED_PTZ.device_sn) == 4.0)


async def test_set_zoom_of_a_paired_camera_under_subheader_0_is_not_handled(
    paired_ptz: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The HomeBase answers -108 and the camera never sees the zoom."""
    monkeypatch.setattr(session_module, "_command_header_channel", lambda channel: 0)

    with pytest.raises(CommandUnsupportedError):
        await paired_ptz.async_set_zoom(PAIRED_PTZ.device_sn, 4)

    assert fake.zoom_writes == []
    assert paired_ptz.zoom(PAIRED_PTZ.device_sn) is None


async def test_set_zoom_refused_in_dual_view(
    standalone_station: Station, fake: FakeStation
) -> None:
    """The app offers zoom only in single view (6243 = 0)."""
    fake.params.setdefault(0, {})[6243] = "12"
    await standalone_station.async_update()

    with pytest.raises(UnsupportedError, match="dual view"):
        await standalone_station.async_set_zoom("T8170P2000054321", 2)
    assert fake.zoom_writes == []


async def test_pan_tilt_unsupported(station: Station, fake: FakeStation) -> None:
    with pytest.raises(UnsupportedError):
        await station.async_pan_tilt(SYNTHETIC.camera_sn, PanTilt.LEFT, settle=0)


async def test_goto_preset_turns_without_opening_a_stream(
    standalone_station: Station, fake: FakeStation
) -> None:
    await standalone_station.async_goto_preset("T8170P2000054321", 2, settle=0)

    assert fake.preset_gotos == [2]
    assert fake.gotos_while_streaming == [False]
    assert fake.live_opens == []


async def test_goto_preset_keeps_a_running_live_stream(
    standalone_station: Station, fake: FakeStation
) -> None:
    """A go-to while the camera streams turns it and leaves the stream running."""
    stream = await standalone_station.async_open_live("T8170P2000054321")
    async with stream:
        await anext(aiter(stream))
        await standalone_station.async_goto_preset("T8170P2000054321", 2, settle=0)
        before = fake.media_frames_sent
        async with asyncio.timeout(5):
            while fake.media_frames_sent <= before:
                await anext(aiter(stream))
        assert not stream.closed

    assert fake.gotos_while_streaming == [True]
    assert fake.live_opens == [0]


async def test_goto_preset_and_live_open_at_a_preset_unsupported(
    station: Station, fake: FakeStation
) -> None:
    with pytest.raises(UnsupportedError):
        await station.async_goto_preset(SYNTHETIC.camera_sn, 1, settle=0)
    with pytest.raises(UnsupportedError):
        await station.async_open_live(SYNTHETIC.camera_sn, preset=1)

    assert fake.preset_gotos == []
    assert fake.live_opens == []


async def test_settle_none_is_the_library_default_read_at_call_time(
    standalone_station: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """``settle=None`` resolves the module constant when called, so a caller can pass
    "the default" through and a test can shorten it by patching the constant."""
    monkeypatch.setattr(station_mod, "PTZ_SETTLE_SECONDS", 0.01)
    monkeypatch.setattr(station_mod, "PRESET_SETTLE_SECONDS", 0.01)

    async with asyncio.timeout(3):
        await standalone_station.async_pan_tilt("T8170P2000054321", PanTilt.LEFT, settle=None)
        await standalone_station.async_goto_preset("T8170P2000054321", 1, settle=None)
        await standalone_station.async_goto_preset("T8170P2000054321", 2)
        image = await standalone_station.async_preset_image("T8170P2000054321", 1, settle=None)

    assert image.preset == 1
    assert fake.preset_gotos == [1, 2, 1]


async def test_goto_preset_refuses_an_empty_slot(
    standalone_station: Station, fake: FakeStation
) -> None:
    await standalone_station.async_refresh_presets("T8170P2000054321")
    with pytest.raises(UnsupportedError):
        await standalone_station.async_goto_preset("T8170P2000054321", 5, settle=0)

    assert fake.preset_gotos == []


async def test_open_live_at_a_preset_turns_then_opens(
    standalone_station: Station, fake: FakeStation
) -> None:
    stream = await standalone_station.async_open_live("T8170P2000054321", preset=2)
    async with stream:
        await anext(aiter(stream))

    commands = [b["commandType"] for b in fake.doorbell_payloads]
    assert commands.index(6035) < commands.index(1000)
    assert fake.preset_gotos == [2]
    assert fake.gotos_while_streaming == [False]
    assert fake.live_opens == [0]


async def test_open_live_at_a_preset_refuses_before_sending(
    standalone_station: Station, fake: FakeStation
) -> None:
    with pytest.raises(ValueError, match="device_sn"):
        await standalone_station.async_open_live(channel=0, preset=2)
    await standalone_station.async_refresh_presets("T8170P2000054321")
    with pytest.raises(UnsupportedError):
        await standalone_station.async_open_live("T8170P2000054321", preset=5)

    assert fake.preset_gotos == []
    assert fake.live_opens == []


async def test_store_preset_reads_back(standalone_station: Station, fake: FakeStation) -> None:
    slots = await standalone_station.async_store_preset("T8170P2000054321", 3)

    assert fake.preset_stores == [3]
    assert next(s for s in slots if s.index == 3).enabled
    assert standalone_station.presets("T8170P2000054321") == slots


async def test_store_preset_full_camera_raises(
    standalone_station: Station, fake: FakeStation
) -> None:
    """A full camera receipts the store and keeps its slots: the read-back must catch it."""
    for point in fake.preset_points:
        point["enable"] = int(point["index"] < MAX_PRESET_SLOTS)

    with pytest.raises(CommandNotAppliedError):
        await standalone_station.async_store_preset("T8170P2000054321", 7)

    assert fake.preset_stores == [7]
    assert not any(p["index"] == 7 and p["enable"] for p in fake.preset_points)


async def test_delete_preset_frees_the_slot(standalone_station: Station, fake: FakeStation) -> None:
    slots = await standalone_station.async_delete_preset("T8170P2000054321", 2)

    assert fake.preset_deletes == [2]
    assert not next(s for s in slots if s.index == 2).enabled


async def test_delete_of_the_default_slot_leaves_no_default(
    standalone_station: Station, fake: FakeStation
) -> None:
    """Deleting the default slot clears its default flag: no default until one is set."""
    await standalone_station.async_refresh_presets("T8170P2000054321")
    events: list[Event] = []
    standalone_station.subscribe(events.append)

    await standalone_station.async_delete_preset("T8170P2000054321", 0)

    assert standalone_station.default_preset("T8170P2000054321") is None
    changed = [e for e in events if isinstance(e, PresetsChanged)]
    assert len(changed) == 1
    assert not any(s.is_default for s in changed[0].presets)


def _stores(fake: FakeStation) -> list[dict[str, Any]]:
    return [b["data"] for b in fake.doorbell_payloads if b.get("commandType") == 6032]


def _reads(fake: FakeStation) -> int:
    return len([b for b in fake.doorbell_payloads if b.get("commandType") == 6034])


async def test_save_preset_stores_into_the_lowest_free_slot(
    standalone_station: Station, fake: FakeStation
) -> None:
    events: list[Event] = []
    standalone_station.subscribe(events.append)
    assert standalone_station.free_preset("T8170P2000054321") is None

    saved = await standalone_station.async_save_preset("T8170P2000054321")

    assert saved == PresetPosition(index=3, enabled=True, zoom=1, is_default=False)
    assert fake.preset_stores == [3]
    assert fake.default_preset_sets == []
    assert standalone_station.default_preset("T8170P2000054321") == 0
    assert standalone_station.free_preset("T8170P2000054321") == 4
    assert any(
        isinstance(e, PresetsChanged) and any(s.index == 3 and s.enabled for s in e.presets)
        for e in events
    )


async def test_save_preset_rereads_the_slots_before_choosing(
    standalone_station: Station, fake: FakeStation
) -> None:
    """A slot stored elsewhere since the last read is never overwritten by a free-slot save."""
    await standalone_station.async_refresh_presets("T8170P2000054321")
    fake.preset_points[3]["enable"] = 1

    saved = await standalone_station.async_save_preset("T8170P2000054321")

    assert saved.index == 4
    assert fake.preset_stores == [4]


async def test_save_preset_refuses_a_full_cache_before_sending(
    standalone_station: Station, fake: FakeStation
) -> None:
    for point in fake.preset_points:
        point["enable"] = int(point["index"] < MAX_PRESET_SLOTS)
    await standalone_station.async_refresh_presets("T8170P2000054321")
    reads = _reads(fake)
    assert standalone_station.free_preset("T8170P2000054321") is None

    for preset in (None, 7):
        with pytest.raises(CommandNotAppliedError, match="delete one first"):
            await standalone_station.async_save_preset("T8170P2000054321", preset=preset)

    assert fake.preset_stores == []
    assert _reads(fake) == reads


async def test_save_preset_refuses_a_camera_found_full_by_the_read(
    standalone_station: Station, fake: FakeStation
) -> None:
    for point in fake.preset_points:
        point["enable"] = int(point["index"] < MAX_PRESET_SLOTS)

    with pytest.raises(CommandNotAppliedError, match="delete one first") as err:
        await standalone_station.async_save_preset("T8170P2000054321")

    assert err.value.command == 6032
    assert standalone_station.free_preset("T8170P2000054321") is None
    assert fake.preset_stores == []


async def test_full_camera_raises_preset_slots_full_with_the_slots(
    standalone_station: Station, fake: FakeStation
) -> None:
    """A full camera raises PresetSlotsFullError carrying the cap and the slots in use."""
    for point in fake.preset_points:
        point["enable"] = int(point["index"] < MAX_PRESET_SLOTS)

    with pytest.raises(PresetSlotsFullError) as err:
        await standalone_station.async_save_preset("T8170P2000054321")

    assert err.value.slots == MAX_PRESET_SLOTS
    assert err.value.in_use == tuple(range(MAX_PRESET_SLOTS))
    assert isinstance(err.value, CommandNotAppliedError)
    assert fake.preset_stores == []


async def test_save_preset_make_default_not_applied_keeps_the_store(
    standalone_station: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A default write that does not take raises for 6242; the stored slot stays."""
    original_on_command = fake._on_command

    def drop_6242(obj: dict[str, Any], subheader: bytes) -> None:
        if obj.get("cmd") != 6242:
            original_on_command(obj, subheader)

    monkeypatch.setattr(fake, "_on_command", drop_6242)

    with pytest.raises(CommandNotAppliedError) as err:
        await standalone_station.async_save_preset("T8170P2000054321", make_default=True)

    assert err.value.command == 6242
    slots = standalone_station.presets("T8170P2000054321")
    assert slots is not None
    assert next(s for s in slots if s.index == 3).enabled
    assert standalone_station.default_preset("T8170P2000054321") == 0


async def test_save_preset_restores_an_enabled_slot_when_named(
    standalone_station: Station, fake: FakeStation
) -> None:
    """A named slot is stored as asked, in use or not; a full camera still re-stores one."""
    for point in fake.preset_points:
        point["enable"] = int(point["index"] < MAX_PRESET_SLOTS)
    await standalone_station.async_refresh_presets("T8170P2000054321")

    saved = await standalone_station.async_save_preset("T8170P2000054321", preset=2)

    assert saved.index == 2
    assert saved.enabled
    assert fake.preset_stores == [2]


async def test_save_preset_make_default(standalone_station: Station, fake: FakeStation) -> None:
    saved = await standalone_station.async_save_preset(
        "T8170P2000054321", make_default=True, confirm=True
    )

    assert saved == PresetPosition(index=3, enabled=True, zoom=1, is_default=True)
    assert _stores(fake) == [{"settingstate": 1, "value": 3}]
    assert fake.default_preset_sets == [(3, 1)]
    assert standalone_station.default_preset("T8170P2000054321") == 3


async def test_save_preset_rejects_a_slot_outside_the_camera(
    standalone_station: Station, fake: FakeStation
) -> None:
    await standalone_station.async_refresh_presets("T8170P2000054321")

    for preset in (-1, 10):
        with pytest.raises(UnsupportedError):
            await standalone_station.async_save_preset("T8170P2000054321", preset=preset)

    assert fake.preset_stores == []


async def test_save_preset_unsupported_model(station: Station, fake: FakeStation) -> None:
    with pytest.raises(UnsupportedError):
        await station.async_save_preset(SYNTHETIC.camera_sn)
    assert fake.doorbell_payloads == []


async def test_preset_edits_reject_a_slot_outside_the_camera(
    standalone_station: Station, fake: FakeStation
) -> None:
    await standalone_station.async_refresh_presets("T8170P2000054321")
    for call in (
        standalone_station.async_store_preset("T8170P2000054321", 99),
        standalone_station.async_delete_preset("T8170P2000054321", -1),
        standalone_station.async_preset_picture("T8170P2000054321", 42),
    ):
        with pytest.raises(UnsupportedError):
            await call

    assert fake.preset_stores == []
    assert fake.preset_deletes == []
    assert fake.preset_picture_requests == []


async def test_preset_picture_returns_the_stored_jpeg(
    standalone_station: Station, fake: FakeStation
) -> None:
    fake.preset_pictures[1] = b"\xff\xd8JFIF\x00\x01\x02"

    assert await standalone_station.async_preset_picture("T8170P2000054321", 1) == (
        b"\xff\xd8JFIF\x00\x01\x02"
    )
    assert fake.preset_picture_requests == [1]


async def test_preset_picture_of_an_empty_slot_is_none(
    standalone_station: Station, fake: FakeStation
) -> None:
    """An empty slot answers an empty string; that is an answer, not a protocol error."""
    assert await standalone_station.async_preset_picture("T8170P2000054321", 4) is None


async def test_preset_command_retries_while_the_camera_moves(
    standalone_station: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Receipt code 1 means "still moving", so the recipe is re-sent, not given up on."""
    monkeypatch.setattr(station_mod, "PTZ_BUSY_DELAY", 0.0)
    codes = iter([1, 1, 0])
    monkeypatch.setattr(fake, "doorbell_receipt_code", lambda: next(codes, 0))

    slots = await standalone_station.async_refresh_presets("T8170P2000054321")

    assert len(slots) == 10
    assert len([b for b in fake.doorbell_payloads if b.get("commandType") == 6034]) == 3


async def test_preset_command_gives_up_after_too_many_busy_answers(
    standalone_station: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(station_mod, "PTZ_BUSY_DELAY", 0.0)
    monkeypatch.setattr(fake, "doorbell_receipt_code", lambda: 1)

    with pytest.raises(CommandRejectedError) as err:
        await standalone_station.async_refresh_presets("T8170P2000054321")

    assert err.value.code == 1
    sent = [b for b in fake.doorbell_payloads if b.get("commandType") == 6034]
    assert len(sent) == station_mod.PTZ_BUSY_ATTEMPTS


async def test_preset_command_does_not_retry_another_code(
    standalone_station: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(fake, "doorbell_receipt_code", lambda: -1)

    with pytest.raises(CommandRejectedError) as err:
        await standalone_station.async_refresh_presets("T8170P2000054321")

    assert err.value.code == -1
    assert len([b for b in fake.doorbell_payloads if b.get("commandType") == 6034]) == 1


async def test_live_camera_image_rereads_presets_ptz(
    standalone_station: Station, fake: FakeStation
) -> None:
    events: list[Event] = []
    standalone_station.subscribe(events.append)

    await standalone_station.async_camera_image("T8170P2000054321", source=ImageSource.LIVE)
    preset_events = [e for e in events if isinstance(e, PresetsChanged)]
    assert len(preset_events) == 1


async def test_live_camera_image_no_presets_t8160(station: Station, fake: FakeStation) -> None:
    events: list[Event] = []
    station.subscribe(events.append)

    await station.async_camera_image(SYNTHETIC.camera_sn, source=ImageSource.LIVE)
    preset_events = [e for e in events if isinstance(e, PresetsChanged)]
    assert len(preset_events) == 0


async def test_fresh_keyframe_logic(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(station_mod, "FRESH_KEYFRAME_WINDOW", 0.1)

    class FakeStream:
        def __init__(self, frames: list[MediaFrame], delays: list[float]):
            self.frames = frames
            self.delays = delays
            self.idx = 0

        def __aiter__(self) -> FakeStream:
            return self

        async def __anext__(self) -> MediaFrame:
            if self.idx >= len(self.frames):
                raise StopAsyncIteration
            frame = self.frames[self.idx]
            delay = self.delays[self.idx]
            self.idx += 1
            await asyncio.sleep(delay)
            return frame

    f1 = MediaFrame(kind=MediaKind.VIDEO, data=b"1", is_keyframe=True)
    f2 = MediaFrame(kind=MediaKind.VIDEO, data=b"2", is_keyframe=True)

    stream1 = FakeStream([f1, f2], [0, 0.05])
    res1 = await station_mod._fresh_keyframe(stream1)  # type: ignore[arg-type]
    assert res1 == b"2"

    stream2 = FakeStream([f1, f2], [0, 0.2])
    res2 = await station_mod._fresh_keyframe(stream2)  # type: ignore[arg-type]
    assert res2 == b"1"


class _TimedStream:
    """Frames as ``(delay before it, frame)``; ends after the last one."""

    def __init__(self, frames: list[tuple[float, MediaFrame]]) -> None:
        self._frames = list(frames)

    def __aiter__(self) -> _TimedStream:
        return self

    async def __anext__(self) -> MediaFrame:
        if not self._frames:
            raise StopAsyncIteration
        delay, frame = self._frames.pop(0)
        await asyncio.sleep(delay)
        return frame


def _key(tag: bytes, width: int, height: int) -> MediaFrame:
    return MediaFrame(kind=MediaKind.VIDEO, data=tag, is_keyframe=True, width=width, height=height)


def _p(width: int, height: int) -> MediaFrame:
    return MediaFrame(kind=MediaKind.VIDEO, data=b"p", width=width, height=height)


async def test_a_held_size_keyframe_waits_out_the_climb() -> None:
    """A woken T8170's climb: the keyframe that opened the size the stream settled on."""
    climb = [
        (0.0, _key(b"stale", 2880, 1616)),  # replayed from the previous stream
        (0.0, _key(b"720", 1280, 720)),
        (0.02, _p(1280, 720)),
        (0.02, _key(b"1080", 1920, 1080)),
        (0.02, _p(1920, 1080)),
        (0.02, _key(b"full", 2880, 1616)),
        (0.02, _p(2880, 1616)),
        (0.02, _key(b"full-later", 2880, 1616)),
        (0.2, _p(2880, 1616)),
    ]
    frame = await station_mod._held_size_keyframe(_TimedStream(climb), 0.1, 5.0)  # type: ignore[arg-type]
    assert (frame.data, frame.width, frame.height) == (b"full", 2880, 1616)


async def test_a_held_size_keyframe_is_bounded_and_keeps_the_largest() -> None:
    """Sizes that never hold: the bound ends the wait with the largest one seen."""
    flapping = [(0.0, _key(b"a", 1280, 720))]
    for n in range(40):
        size = (1920, 1080) if n % 2 else (1280, 720)
        flapping.append((0.02, _key(b"big" if n % 2 else b"a", *size)))
    started = time.monotonic()
    frame = await station_mod._held_size_keyframe(_TimedStream(flapping), 0.1, 0.3)  # type: ignore[arg-type]
    assert time.monotonic() - started < 0.6
    assert (frame.width, frame.height) == (1920, 1080)


async def test_a_held_size_keyframe_returns_what_it_has_when_the_stream_ends() -> None:
    frames = [(0.0, _key(b"720", 1280, 720)), (0.0, _key(b"1080", 1920, 1080))]
    frame = await station_mod._held_size_keyframe(_TimedStream(frames), 5.0, 30.0)  # type: ignore[arg-type]
    assert frame.data == b"1080"
    with pytest.raises(DeviceTimeoutError):
        await station_mod._held_size_keyframe(_TimedStream([(0.0, _p(1, 1))]), 5.0, 30.0)  # type: ignore[arg-type]


async def test_a_live_image_carries_its_size_and_full_resolution_waits_for_it(
    standalone_station: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(station_mod, "SETTLE_STANDALONE", 0.1)
    fake.live_keyframe_sizes = [(1280, 720), (1920, 1080), (2880, 1616)]
    sn = "T8170P2000054321"
    first = await standalone_station.async_camera_image(sn, ImageSource.LIVE)
    assert first.width is not None
    assert (first.width, first.height) != (2880, 1616)  # a rung of the climb
    full = await standalone_station.async_camera_image(sn, ImageSource.LIVE, full_resolution=True)
    assert (full.width, full.height) == (2880, 1616)
    assert full.data == MEDIA_KEYFRAME
    event = _standalone_detection(datetime.now().astimezone())
    hd = await standalone_station.async_event_image(event, ImageSource.LIVE, full_resolution=True)
    assert (hd.source, hd.width, hd.height) == (ImageSource.LIVE, 2880, 1616)


async def test_a_standalone_detection_has_no_trigger_frame(
    standalone_station: Station, fake: FakeStation
) -> None:
    event = dataclasses.replace(
        _standalone_detection(datetime.now().astimezone()),
        video_path="/zx/hdd_data0/Camera00/clip.zxvideo",
    )
    with pytest.raises(UnsupportedError, match=r"(?i)standalone.*trigger"):
        await standalone_station.async_event_image(event, ImageSource.TRIGGER_FRAME)
    assert fake.conn_inits == 1  # no short-lived session was opened


def test_image_sources_available(station: Station, standalone_station: Station) -> None:
    assert station.image_sources(SYNTHETIC.camera_sn) == tuple(ImageSource)
    assert standalone_station.image_sources("T8170P2000054321") == (
        ImageSource.THUMBNAIL,
        ImageSource.LIVE,
    )
    with pytest.raises(UnsupportedError):
        station.image_sources("T8160P2000000000")


async def test_standalone_async_camera_image_trigger_frame_raises(
    standalone_station: Station, fake: FakeStation
) -> None:
    with pytest.raises(UnsupportedError, match=r"(?i)standalone.*trigger"):
        await standalone_station.async_camera_image("T8170P2000054321", ImageSource.TRIGGER_FRAME)
    assert fake.event_count_queries == 0


async def test_standalone_async_camera_image_thumbnail(
    standalone_station: Station, fake: FakeStation
) -> None:
    path = "/media/mmcblk0p1/Camera00/event/202609/20260917/20260917223859_snapshot.jpg"
    fake.event_summaries = {
        "T8170P2000054321": {
            "event_count": 3,
            "crop_hb3_path": path,
            "crop_cloud_path": "",
        }
    }
    image = b"\xff\xd8\xff\xe0" + bytes(400) + b"\xff\xd9"
    wrapped = v1_still(image, "T8170P2000054321", did=SYNTHETIC.did)
    fake.images[path] = wrapped

    cam_img = await standalone_station.async_camera_image("T8170P2000054321", ImageSource.THUMBNAIL)
    assert cam_img.source is ImageSource.THUMBNAIL
    assert cam_img.data == image
    assert cam_img.content_type == JPEG_CONTENT_TYPE
    assert cam_img.recorded_at == "2026-09-17 22:38:59"  # hygiene: ok
    assert cam_img.record_id is None


async def test_standalone_async_camera_image_thumbnail_no_event(
    standalone_station: Station, fake: FakeStation
) -> None:
    with pytest.raises(RecordNotFoundError):
        await standalone_station.async_camera_image("T8170P2000054321", ImageSource.THUMBNAIL)

    path = "/media/mmcblk0p1/Camera00/event/202609/20260917/20260917223859_snapshot.jpg"
    fake.event_summaries = {
        "T8170P2000054321": {
            "event_count": 3,
            "crop_hb3_path": path,
            "crop_cloud_path": "",
        }
    }
    fake.images[path] = b"v8_eufysecurity\x00\x01" + bytes(400)
    with pytest.raises(UnsupportedError, match="not a JPEG"):
        await standalone_station.async_camera_image("T8170P2000054321", ImageSource.THUMBNAIL)


def _standalone_detection(at: datetime) -> SecurityEvent:
    return SecurityEvent(
        source=EventSource.CLOUD,
        station_sn="T8170P2000054321",
        device_sn="T8170P2000054321",
        msg_type=18,
        event_type=3102,
        event_time_ms=int(at.timestamp() * 1000),
    )


@pytest.mark.parametrize(
    ("still_after", "outcome"),
    [(2.0, "image"), (-1.0, "image"), (-5.0, "not written yet"), (90.0, "replaced")],
)
async def test_a_standalone_detection_gets_its_own_still(
    standalone_station: Station, fake: FakeStation, still_after: float, outcome: str
) -> None:
    """The newest still counts as the detection's only within the window around it."""
    trigger = datetime(2026, 10, 2, 20, 48, 50).astimezone()
    taken = trigger + timedelta(seconds=still_after)
    path = f"/media/mmcblk0p1/Camera00/event/{taken:%Y%m%d%H%M%S}_snapshot.jpg"
    fake.event_summaries = {
        "T8170P2000054321": {"event_count": 3, "crop_hb3_path": path, "crop_cloud_path": ""}
    }
    image = b"\xff\xd8\xff\xe0" + bytes(400) + b"\xff\xd9"
    fake.images[path] = v1_still(image, "T8170P2000054321", did=SYNTHETIC.did)
    event = _standalone_detection(trigger)
    if outcome == "image":
        cam_img = await standalone_station.async_event_image(event, ImageSource.THUMBNAIL)
        assert cam_img.data == image
        assert cam_img.content_type == JPEG_CONTENT_TYPE
    else:
        with pytest.raises(RecordNotFoundError, match=outcome) as info:
            await standalone_station.async_event_image(event, ImageSource.THUMBNAIL)
        # Only a still older than the event is "ask again later".
        assert isinstance(info.value, StillNotWrittenError) is (outcome == "not written yet")
        if isinstance(info.value, StillNotWrittenError):
            assert info.value.offset == pytest.approx(still_after, abs=1.0)


async def test_a_standalone_detection_still_is_read_in_the_device_zone(
    standalone_station: Station, fake: FakeStation
) -> None:
    """The still's name is the device's local second, in the zone it reports."""
    fake.params.setdefault(0, {})[1215] = "JST-9|1.1307"  # Asia/Tokyo
    await standalone_station.session.async_get_params()
    trigger = datetime(2026, 10, 2, 11, 48, 50, tzinfo=UTC)
    tokyo_name = "20261002204852"  # 2 s later, Tokyo time
    path = f"/media/mmcblk0p1/Camera00/event/{tokyo_name}_snapshot.jpg"
    fake.event_summaries = {
        "T8170P2000054321": {"event_count": 1, "crop_hb3_path": path, "crop_cloud_path": ""}
    }
    image = b"\xff\xd8\xff\xe0" + bytes(400) + b"\xff\xd9"
    fake.images[path] = v1_still(image, "T8170P2000054321", did=SYNTHETIC.did)
    cam_img = await standalone_station.async_event_image(
        _standalone_detection(trigger), ImageSource.THUMBNAIL
    )
    assert cam_img.data == image


async def test_a_standalone_detection_without_a_time_is_refused(
    standalone_station: Station, fake: FakeStation
) -> None:
    event = SecurityEvent(source=EventSource.CLOUD, device_sn="T8170P2000054321")
    with pytest.raises(UnsupportedError, match="no time"):
        await standalone_station.async_event_thumbnail(event)
    assert fake.event_count_queries == 0


def test_still_time() -> None:
    assert (
        _still_time("/media/mmcblk0p1/Camera00/event/202609/20260917/20260917223859_snapshot.jpg")
        == "2026-09-17 22:38:59"  # hygiene: ok
    )
    assert _still_time("/zx/push.jpg") is None
    assert _still_time("/x/2026091722385_snapshot.jpg") is None


async def test_default_preset_returns_the_default_slot(
    standalone_station: Station, fake: FakeStation
) -> None:
    assert standalone_station.default_preset("T8170P2000054321") is None
    await standalone_station.async_refresh_presets("T8170P2000054321")
    assert standalone_station.default_preset("T8170P2000054321") == 0
    # For a serial not paired, returns None
    assert standalone_station.default_preset("T0000P2000054321") is None


async def test_async_set_default_preset_sets_slot_and_emits_event(
    standalone_station: Station, fake: FakeStation
) -> None:
    # The preset slots must be known before a default can be set.
    await standalone_station.async_refresh_presets("T8170P2000054321")

    events: list[Event] = []
    standalone_station.subscribe(events.append)

    slots = await standalone_station.async_set_default_preset("T8170P2000054321", 2)
    default_slot = next((s for s in slots if s.index == 2), None)
    assert default_slot is not None
    assert default_slot.is_default is True

    assert standalone_station.default_preset("T8170P2000054321") == 2
    assert fake.default_preset_sets == [(2, 0)]
    assert fake.preset_gotos[-1:] == [2]

    preset_events = [e for e in events if isinstance(e, PresetsChanged)]
    assert len(preset_events) > 0


async def test_async_set_default_preset_passes_confirm_flag(
    standalone_station: Station, fake: FakeStation
) -> None:
    await standalone_station.async_refresh_presets("T8170P2000054321")
    await standalone_station.async_set_default_preset("T8170P2000054321", 1, confirm=True)
    assert fake.default_preset_sets == [(1, 1)]


async def test_async_set_default_preset_raises_for_disabled_slot(
    standalone_station: Station, fake: FakeStation
) -> None:
    await standalone_station.async_refresh_presets("T8170P2000054321")
    with pytest.raises(UnsupportedError):
        await standalone_station.async_set_default_preset("T8170P2000054321", 5)
    assert fake.default_preset_sets == []


async def test_async_set_default_preset_raises_on_non_ptz_camera(
    station: Station, fake: FakeStation
) -> None:
    with pytest.raises(UnsupportedError):
        await station.async_set_default_preset(SYNTHETIC.camera_sn, 1)


async def test_moving_the_camera_during_a_capture_is_refused(
    standalone_station: Station, fake: FakeStation
) -> None:
    """A default-preset write, a pan/tilt step, a go-to, a live open at a preset or a zoom
    would change the view being captured: each raises DeviceBusyError and sends nothing."""
    await standalone_station.async_refresh_presets("T8170P2000054321")
    capture = asyncio.create_task(
        standalone_station.async_preset_image("T8170P2000054321", 1, settle=0.3)
    )
    await asyncio.sleep(0.05)

    with pytest.raises(DeviceBusyError):
        await standalone_station.async_set_default_preset("T8170P2000054321", 2)
    with pytest.raises(DeviceBusyError):
        await standalone_station.async_pan_tilt("T8170P2000054321", PanTilt.LEFT, settle=0)
    with pytest.raises(DeviceBusyError):
        await standalone_station.async_goto_preset("T8170P2000054321", 2, settle=0)
    with pytest.raises(DeviceBusyError):
        await standalone_station.async_open_live("T8170P2000054321", preset=2)
    with pytest.raises(DeviceBusyError):
        await standalone_station.async_set_zoom("T8170P2000054321", 2)
    with pytest.raises(DeviceBusyError):
        await standalone_station.async_store_preset("T8170P2000054321", 3)
    with pytest.raises(DeviceBusyError):
        await standalone_station.async_save_preset("T8170P2000054321")

    await capture
    assert fake.preset_stores == []
    assert fake.zoom_writes == []
    assert fake.default_preset_sets == []
    assert fake.preset_gotos == [1]
    assert [b for b in fake.doorbell_payloads if b.get("commandType") == 6030] == []


async def test_async_set_default_preset_raises_if_not_applied(
    standalone_station: Station, fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    await standalone_station.async_refresh_presets("T8170P2000054321")

    original_on_command = fake._on_command

    def wrapped_on_command(obj: dict[str, Any], subheader: bytes) -> None:
        if obj.get("cmd") == 6242:
            return
        original_on_command(obj, subheader)

    monkeypatch.setattr(fake, "_on_command", wrapped_on_command)

    with pytest.raises(CommandNotAppliedError):
        await standalone_station.async_set_default_preset("T8170P2000054321", 2)


async def test_async_get_storage_routes_to_sd_info_on_standalone_station(
    standalone_station: Station, fake: FakeStation
) -> None:
    fake.sd_info = (0, 8000, 2000)
    info = await standalone_station.async_get_storage()
    assert info.emmc is not None
    assert info.emmc.used_percent == 75.0
    assert info.emmc.size_mib == 8000
    assert info.disk is None
    assert standalone_station.storage == info


async def test_async_get_storage_on_homebase_retains_1307_path(
    station: Station, fake: FakeStation
) -> None:
    info = await station.async_get_storage()
    assert info.disk is not None
    assert info.disk.used_mib == 14500  # synthetic_storage_body()'s default
    assert station.storage == info


# ── Standalone writes and per-view reports ─────────────────────────────────────


def _per_view_quality(mode_0: int, mode_1: int = 0) -> str:
    """A T8170's 2730 report, as the camera sends it: base64 JSON, one quality per view."""
    report = {"mode_0": {"quality": mode_0}, "mode_1": {"quality": mode_1}, "cur_mode": 0}
    return base64.b64encode(json.dumps(report).encode()).decode()


@pytest.mark.parametrize(
    ("view_mode", "expected"), [("0", 1), (None, 1), ("12", 6)], ids=["single", "absent", "dual"]
)
def test_a_per_view_quality_report_reads_as_the_current_view(
    view_mode: str | None, expected: int
) -> None:
    params = {2730: _per_view_quality(3, 1)}
    if view_mode is not None:
        params[6243] = view_mode
    state = _standalone_t8170()._state(_dump_of({0: params}))
    assert state.devices[0].setting("live_streaming_resolution") == expected


@pytest.mark.parametrize("raw", ["not base64!", base64.b64encode(b"[1]").decode(), ""])
def test_an_undecodable_quality_report_reads_as_unknown(raw: str) -> None:
    state = _standalone_t8170()._state(_dump_of({0: {2730: raw}}))
    assert state.devices[0].setting("live_streaming_resolution") is None


async def test_a_t8170_quality_write_reads_back_through_its_per_view_report(
    on_demand_pair: tuple[Station, FakeStation],
) -> None:
    station, fake = on_demand_pair
    fake.params[0] = {2730: _per_view_quality(3), 6243: "0"}
    fake.reply_to_settings = True
    await station.async_set_setting("live_streaming_resolution", 2)  # Full HD
    assert fake.received[-1]["payload"] == {
        "quality": 2,
        "mode": 0,
        "primary_view": 0,
        "channel": 0,
    }
    report = json.loads(base64.b64decode(fake.params[0][2730]))
    assert report["mode_0"] == {"quality": 2}
    assert report["mode_1"] == {"quality": 0}  # the other view is untouched
    state = station.state
    assert state is not None
    assert state.setting("live_streaming_resolution") == 2  # the cached write
    assert (await station.async_update()).setting("live_streaming_resolution") == 2  # the dump


def _dump_of(blocks: dict[int, dict[int, str]]) -> ParamDump:
    dump = ParamDump()
    dump.ingest(
        {
            "params": [
                {"dev_type": dev, "param_type": pid, "param_value": value}
                for dev, params in blocks.items()
                for pid, value in params.items()
            ]
        }
    )
    return dump
