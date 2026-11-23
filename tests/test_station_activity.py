"""Counter activity tests, including a real station session with a loopback fake."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import replace
from datetime import UTC

import pytest

from eufy_home_security.cloud.models import CloudDevice
from eufy_home_security.devices.types import model_for_serial
from eufy_home_security.events import (
    ConnectionChanged,
    DetectedEventsCounted,
    DisconnectCause,
    Event,
    RecordedEventsCounted,
    StationStateChanged,
)
from eufy_home_security.models import PARAM_DETECTED_EVENTS, PARAM_RECORDED_EVENTS
from eufy_home_security.p2p import session as session_module
from eufy_home_security.p2p.messages import STANDALONE_RECEIPT_LEN
from eufy_home_security.p2p.session import P2PCredentials, StationSession
from eufy_home_security.station import Station, StationState, SubDeviceState
from eufy_home_security.station.activity import StationActivity
from eufy_home_security.testing import SYNTHETIC, FakeStation

CAMERA = SYNTHETIC.camera_sn
STATION = SYNTHETIC.homebase2_station_sn


class FakeActivityStation:
    serial = STATION


def state(
    detected: int | None,
    recorded: int | None,
    *,
    online: bool | None = True,
    serial: str | None = CAMERA,
) -> StationState:
    return StationState(
        serial=STATION,
        guard_mode=None,
        firmware=None,
        params={},
        devices={
            0: SubDeviceState(
                channel=0,
                serial=serial,
                name=None,
                battery=None,
                firmware=None,
                params={},
                online=online,
                detected_events=detected,
                recorded_events=recorded,
            )
        },
    )


def test_both_counters_emit_one_aggregate_event_each() -> None:
    emitted: list[DetectedEventsCounted | RecordedEventsCounted] = []
    activity = StationActivity(FakeActivityStation(), emitted.append)
    activity.observe(state(100, 50))
    activity.observe(state(103, 52))
    activity.observe(state(103, 52))
    assert [type(event) for event in emitted] == [DetectedEventsCounted, RecordedEventsCounted]
    assert [event.count for event in emitted] == [3, 2]
    assert [event.device_sn for event in emitted] == [CAMERA, CAMERA]
    assert all(event.observed_at.tzinfo is UTC for event in emitted)


def test_two_cameras_on_the_same_station_keep_independent_counter_deltas() -> None:
    """Only the camera whose own counter changed produces the corresponding event."""
    camera = "T8113" + CAMERA[5:]  # synthetic eufyCam 2C, as tested on HomeBase 2
    doorbell = "T8210" + CAMERA[5:]  # synthetic battery video doorbell

    def both(
        cam_detected: int,
        cam_recorded: int,
        bell_detected: int,
        bell_recorded: int,
    ) -> StationState:
        cam = state(cam_detected, cam_recorded, serial=camera)
        bell = state(bell_detected, bell_recorded, serial=doorbell)
        return replace(
            cam,
            devices={0: cam.devices[0], 1: replace(bell.devices[0], channel=1)},
        )

    emitted: list[DetectedEventsCounted | RecordedEventsCounted] = []
    activity = StationActivity(FakeActivityStation(), emitted.append)
    activity.observe(both(10, 5, 20, 7))  # both baselines
    assert emitted == []

    activity.observe(both(12, 5, 20, 10))
    activity.observe(both(12, 8, 24, 10))
    activity.observe(both(12, 8, 24, 10))  # unchanged, never emit twice
    assert {e.station_sn for e in emitted} == {STATION}
    assert [(type(e), e.device_sn, e.count) for e in emitted] == [
        (DetectedEventsCounted, camera, 2),
        (RecordedEventsCounted, doorbell, 3),
        (RecordedEventsCounted, camera, 3),
        (DetectedEventsCounted, doorbell, 4),
    ]


def test_single_counter_change_does_not_trigger_other_event() -> None:
    emitted: list[DetectedEventsCounted | RecordedEventsCounted] = []
    activity = StationActivity(FakeActivityStation(), emitted.append)
    activity.observe(state(1, 1))
    activity.observe(state(2, 1))
    assert [type(event) for event in emitted] == [DetectedEventsCounted]
    activity.observe(state(2, 2))
    assert [type(event) for event in emitted] == [DetectedEventsCounted, RecordedEventsCounted]


def test_resets_offline_missing_and_startup_do_not_fire() -> None:
    emitted: list[DetectedEventsCounted | RecordedEventsCounted] = []
    activity = StationActivity(FakeActivityStation(), emitted.append)
    activity.observe(state(10, 10))
    activity.observe(state(1, 1))  # counter reset; rebaseline
    activity.observe(state(None, None))
    activity.observe(state(2, 2))  # first numeric after missing; rebaseline
    activity.observe(state(99, 99, online=False))
    activity.observe(state(3, 3))  # first good value after offline; rebaseline
    activity.observe(state(3, 3))
    assert emitted == []
    activity.observe(state(4, 3))
    assert len(emitted) == 1


def test_disappearing_and_unidentified_devices_do_not_create_events() -> None:
    emitted: list[DetectedEventsCounted | RecordedEventsCounted] = []
    activity = StationActivity(FakeActivityStation(), emitted.append)
    activity.observe(state(10, 10))
    activity.observe(state(11, 11, serial=None))
    activity.observe(state(20, 20))  # missing device first reappears; baseline
    assert emitted == []


@pytest.mark.parametrize(
    ("prefix", "camera_capable"),
    [("T8160", True), ("T8113", True), ("T8210", True), ("T8910", False)],
)
def test_only_camera_capable_devices_produce_counted_activity(
    prefix: str, camera_capable: bool
) -> None:
    """Existing model categories include video doorbells, but exclude PIR sensors."""
    serial = prefix + CAMERA[5:]  # use a synthetic serial's fictitious suffix
    emitted: list[DetectedEventsCounted | RecordedEventsCounted] = []
    activity = StationActivity(FakeActivityStation(), emitted.append)

    activity.observe(state(10, 5, serial=serial))
    activity.observe(state(11, 6, serial=serial))
    expected = [DetectedEventsCounted, RecordedEventsCounted] if camera_capable else []
    assert [type(event) for event in emitted] == expected
    assert all(event.device_sn == serial for event in emitted)


def test_uncatalogued_device_reporting_camera_counters_is_observed() -> None:
    """A new camera model need not be in the bundled catalogue first."""
    serial = "T9ZZZ" + CAMERA[5:]
    assert model_for_serial(serial) is None

    emitted: list[DetectedEventsCounted | RecordedEventsCounted] = []
    activity = StationActivity(FakeActivityStation(), emitted.append)

    activity.observe(state(10, None, serial=serial))
    activity.observe(state(13, None, serial=serial))

    assert [(type(e), e.station_sn, e.device_sn, e.count) for e in emitted] == [
        (DetectedEventsCounted, STATION, serial, 3),
    ]


def test_unknown_online_status_is_eligible_but_explicit_offline_is_not() -> None:
    """No parameter 1131 is not the same as a reported-offline camera."""
    emitted: list[DetectedEventsCounted | RecordedEventsCounted] = []
    activity = StationActivity(FakeActivityStation(), emitted.append)
    activity.observe(state(10, 2, online=None))
    activity.observe(state(12, 3, online=None))
    assert [(type(e), e.count) for e in emitted] == [
        (DetectedEventsCounted, 2),
        (RecordedEventsCounted, 1),
    ]

    activity.observe(state(99, 99, online=False))
    activity.observe(state(100, 100, online=None))  # baseline after explicit offline
    assert len(emitted) == 2
    activity.observe(state(101, 100, online=None))
    assert [(type(e), e.count) for e in emitted] == [
        (DetectedEventsCounted, 2),
        (RecordedEventsCounted, 1),
        (DetectedEventsCounted, 1),
    ]


async def test_a_closed_observer_ignores_counters_until_reopened() -> None:
    """Closing disables counter observation; reopening establishes a new baseline."""
    emitted: list[DetectedEventsCounted | RecordedEventsCounted] = []
    activity = StationActivity(FakeActivityStation(), emitted.append)

    activity.observe(state(10, 10))
    await activity.close()
    activity.observe(state(12, 12))
    activity.observe(state(14, 14))  # would emit if the closed guard were removed
    assert emitted == []

    activity.reopen()
    activity.observe(state(20, 20))
    assert emitted == []
    activity.observe(state(22, 21))
    assert [(type(event), event.count) for event in emitted] == [
        (DetectedEventsCounted, 2),
        (RecordedEventsCounted, 1),
    ]


def test_synchronous_observation_needs_no_running_loop() -> None:
    emitted: list[DetectedEventsCounted | RecordedEventsCounted] = []
    activity = StationActivity(FakeActivityStation(), emitted.append)
    activity.observe(state(5, 5))  # synchronous: no running event loop needed
    activity.observe(state(6, 6))
    assert [(type(e), e.count) for e in emitted] == [
        (DetectedEventsCounted, 1),
        (RecordedEventsCounted, 1),
    ]


STATION_DEVICE = CloudDevice(
    device_sn=SYNTHETIC.station_sn,
    device_type=18,
    name="Synthetic HomeBase",
    p2p_did=SYNTHETIC.did,
    main_sw_version="3.8.7.4",
)
CAMERA_DEVICE = CloudDevice(
    device_sn=SYNTHETIC.camera_sn,
    device_type=19,
    name="Synthetic camera",
    station_sn=SYNTHETIC.station_sn,
    channel=0,
)


@pytest.fixture
async def station_and_fake() -> AsyncIterator[tuple[Station, FakeStation]]:
    fake = FakeStation()
    await fake.start()

    async def credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", fake.ecc_private_key_hex)

    session = StationSession(
        SYNTHETIC.station_sn, credentials, host="127.0.0.1", port=fake.discovery_port
    )
    station = Station(STATION_DEVICE, session, sub_devices=[CAMERA_DEVICE])
    try:
        yield station, fake
    finally:
        await station.async_close()
        fake.stop()


async def test_station_start_reopens_the_activity_observer(
    station_and_fake: tuple[Station, FakeStation],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Station startup reopens an observer closed before startup."""
    station, _ = station_and_fake
    emitted: list[Event] = []
    station.subscribe(emitted.append)

    async def load_settings(self: Station) -> None:
        pass

    async def start_session(self: StationSession) -> None:
        pass

    monkeypatch.setattr(Station, "async_load_settings", load_settings)
    monkeypatch.setattr(StationSession, "async_start", start_session)

    await station._activity.close()
    await station.async_start()
    station._activity.observe(state(10, 5))
    station._activity.observe(state(12, 6))

    counted = [e for e in emitted if isinstance(e, (DetectedEventsCounted, RecordedEventsCounted))]
    assert [(type(e), e.station_sn, e.device_sn, e.count) for e in counted] == [
        (DetectedEventsCounted, station.serial, CAMERA, 2),
        (RecordedEventsCounted, station.serial, CAMERA, 1),
    ]


async def test_station_close_disables_further_activity_observations(
    station_and_fake: tuple[Station, FakeStation],
) -> None:
    """Station shutdown closes the observer, even if a later snapshot is processed."""
    station, _ = station_and_fake
    emitted: list[Event] = []
    station.subscribe(emitted.append)

    station._activity.observe(state(10, 5))
    await station.async_close()
    station._activity.observe(state(12, 6))
    station._activity.observe(state(14, 7))

    assert not any(isinstance(e, (DetectedEventsCounted, RecordedEventsCounted)) for e in emitted)


async def test_station_reconnect_rebaselines_counters_even_after_an_unchanged_dump(
    station_and_fake: tuple[Station, FakeStation],
) -> None:
    """A dropped link loses the baseline, including when the next state is identical."""
    station, fake = station_and_fake
    fake.params[0][PARAM_DETECTED_EVENTS] = "10"
    fake.params[0][PARAM_RECORDED_EVENTS] = "5"
    events: list[Event] = []
    station.subscribe(events.append)

    def detected_counts() -> list[int]:
        return [event.count for event in events if isinstance(event, DetectedEventsCounted)]

    def recorded_counts() -> list[int]:
        return [event.count for event in events if isinstance(event, RecordedEventsCounted)]

    async def wait_for_disconnect(count: int) -> None:
        async with asyncio.timeout(8):
            while (
                sum(
                    isinstance(event, ConnectionChanged) and not event.connected for event in events
                )
                < count
            ):
                await asyncio.sleep(0.02)

    await station.async_update()
    fake.params[0][PARAM_DETECTED_EVENTS] = "11"
    fake.params[0][PARAM_RECORDED_EVENTS] = "7"
    await station.async_update()
    assert detected_counts() == [1]
    assert recorded_counts() == [2]

    fake.send_close()
    await wait_for_disconnect(1)
    fake.params[0][PARAM_DETECTED_EVENTS] = "50"
    fake.params[0][PARAM_RECORDED_EVENTS] = "40"
    await station.async_update()  # first post-outage values are baselines
    assert detected_counts() == [1]
    assert recorded_counts() == [2]

    fake.params[0][PARAM_DETECTED_EVENTS] = "52"
    fake.params[0][PARAM_RECORDED_EVENTS] = "43"
    await station.async_update()
    assert detected_counts() == [1, 2]
    assert recorded_counts() == [2, 3]

    fake.send_close()
    await wait_for_disconnect(2)
    await station.async_update()  # identical to the last StationStateChanged
    assert detected_counts() == [1, 2]
    assert recorded_counts() == [2, 3]
    fake.params[0][PARAM_DETECTED_EVENTS] = "53"
    fake.params[0][PARAM_RECORDED_EVENTS] = "44"
    await station.async_update()
    assert detected_counts() == [1, 2, 1]
    assert recorded_counts() == [2, 3, 1]
    assert fake.history_queries == []  # counter observations never read history


async def test_counter_activity_uses_existing_parameter_read_not_cloud(
    station_and_fake: tuple[Station, FakeStation],
) -> None:
    station, fake = station_and_fake
    fake.params[0][PARAM_DETECTED_EVENTS] = "100"
    fake.params[0][PARAM_RECORDED_EVENTS] = "50"
    events: list[Event] = []
    station.subscribe(events.append)

    await station.async_update()  # first reading is a baseline
    assert not any(isinstance(e, (DetectedEventsCounted, RecordedEventsCounted)) for e in events)

    fake.params[0][PARAM_DETECTED_EVENTS] = "103"
    await station.async_update()
    motions = [e for e in events if isinstance(e, DetectedEventsCounted)]
    assert len(motions) == 1
    assert motions[0].count == 3
    assert not any(isinstance(e, RecordedEventsCounted) for e in events)

    fake.params[0][PARAM_RECORDED_EVENTS] = "52"
    await station.async_update()
    recordings = [e for e in events if isinstance(e, RecordedEventsCounted)]
    assert len(recordings) == 1
    assert recordings[0].count == 2
    assert any(isinstance(e, StationStateChanged) for e in events)

    await station.async_update()
    assert len([e for e in events if isinstance(e, DetectedEventsCounted)]) == 1
    assert len([e for e in events if isinstance(e, RecordedEventsCounted)]) == 1
    assert fake.history_queries == []  # no 10011/10017 history requests


SOLO = "T8170" + CAMERA[5:]


def solo_snapshot(detected: int, updated_at: float) -> CloudDevice:
    """Cloud snapshot of a standalone camera with a detected-events counter."""
    return CloudDevice(
        device_sn=SOLO,
        device_type=48,
        name="Synthetic solo camera",
        p2p_did=SYNTHETIC.did,
        station_sn=SOLO,
        channel=0,
        raw={
            "params": [
                {
                    "param_type": PARAM_DETECTED_EVENTS,
                    "param_value": str(detected),
                    "update_time": updated_at,
                }
            ]
        },
    )


async def test_an_idle_close_of_an_on_demand_link_keeps_the_baselines(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An on-demand link closing while idle must preserve the counter baseline."""
    monkeypatch.setattr(session_module, "_IDLE_CHECK_EVERY", 0.05)
    fake = FakeStation(
        serial=SOLO,
        guard_mode=1,
        receipt_len=STANDALONE_RECEIPT_LEN,
        params={48: {1224: "1"}},
    )
    await fake.start()

    async def credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", fake.ecc_private_key_hex)

    session = StationSession(
        SOLO,
        credentials,
        host="127.0.0.1",
        port=fake.discovery_port,
        on_demand=True,
        idle_close=0.1,
        block_aliases={48: (255, 0)},
    )
    station = Station(solo_snapshot(0, 1.0), session, sub_devices=[])
    events: list[Event] = []
    station.subscribe(events.append)
    try:
        await station.async_start()
        station.apply_cloud_device(solo_snapshot(10, 1_600_000_000.0))
        await station.async_update(wake=True)

        async with asyncio.timeout(5):
            while not any(
                isinstance(e, ConnectionChanged) and e.cause is DisconnectCause.IDLE for e in events
            ):
                await asyncio.sleep(0.02)

        station.apply_cloud_device(solo_snapshot(13, 1_600_000_100.0))
        counted = [e for e in events if isinstance(e, DetectedEventsCounted)]
        assert [(e.station_sn, e.device_sn, e.count) for e in counted] == [(SOLO, SOLO, 3)]
    finally:
        await station.async_close()
        fake.stop()
