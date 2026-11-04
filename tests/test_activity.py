"""Counter activity tests, including a real station session with a loopback fake."""

from __future__ import annotations

import asyncio
from collections.abc import AsyncIterator
from dataclasses import replace
from datetime import UTC

import pytest

from eufy_home_security.cloud.models import CloudDevice
from eufy_home_security.events import (
    ConnectionChanged,
    DetectionType,
    Event,
    EventSource,
    MotionDetected,
    MotionRecorded,
    SecurityEvent,
    StationStateChanged,
)
from eufy_home_security.models import PARAM_DETECTED_EVENTS, PARAM_RECORDED_EVENTS
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
    emitted: list[MotionDetected | MotionRecorded] = []
    activity = StationActivity(FakeActivityStation(), emitted.append)
    activity.observe(state(100, 50))
    activity.observe(state(103, 52))
    activity.observe(state(103, 52))
    assert [type(event) for event in emitted] == [MotionDetected, MotionRecorded]
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

    emitted: list[MotionDetected | MotionRecorded] = []
    activity = StationActivity(FakeActivityStation(), emitted.append)
    activity.observe(both(10, 5, 20, 7))  # both baselines
    assert emitted == []

    activity.observe(both(12, 5, 20, 10))
    activity.observe(both(12, 8, 24, 10))
    activity.observe(both(12, 8, 24, 10))  # unchanged, never emit twice
    assert [(type(e), e.device_sn, e.count) for e in emitted] == [
        (MotionDetected, camera, 2),
        (MotionRecorded, doorbell, 3),
        (MotionRecorded, camera, 3),
        (MotionDetected, doorbell, 4),
    ]


def test_single_counter_change_does_not_trigger_other_event() -> None:
    emitted: list[MotionDetected | MotionRecorded] = []
    activity = StationActivity(FakeActivityStation(), emitted.append)
    activity.observe(state(1, 1))
    activity.observe(state(2, 1))
    assert [type(event) for event in emitted] == [MotionDetected]
    activity.observe(state(2, 2))
    assert [type(event) for event in emitted] == [MotionDetected, MotionRecorded]


def test_resets_offline_missing_and_startup_do_not_fire() -> None:
    emitted: list[MotionDetected | MotionRecorded] = []
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
    emitted: list[MotionDetected | MotionRecorded] = []
    activity = StationActivity(FakeActivityStation(), emitted.append)
    activity.observe(state(10, 10))
    activity.observe(state(11, 11, serial=None))
    activity.observe(state(20, 20))  # missing device first reappears; baseline
    assert emitted == []


@pytest.mark.parametrize(
    ("prefix", "camera_capable"),
    [("T8160", True), ("T8113", True), ("T8210", True), ("T8910", False)],
)
def test_only_camera_capable_devices_produce_motion_activity(
    prefix: str, camera_capable: bool
) -> None:
    """Existing model categories include video doorbells, but exclude PIR sensors."""
    serial = prefix + CAMERA[5:]  # use a synthetic serial's fictitious suffix
    emitted: list[MotionDetected | MotionRecorded] = []
    activity = StationActivity(FakeActivityStation(), emitted.append)

    activity.observe(state(10, 5, serial=serial))
    activity.observe(state(11, 6, serial=serial))
    expected = [MotionDetected, MotionRecorded] if camera_capable else []
    assert [type(event) for event in emitted] == expected
    assert all(event.device_sn == serial for event in emitted)

    activity.reopen()
    emitted.clear()
    activity.observe(state(None, None, serial=serial))
    activity.on_security_event(
        SecurityEvent(
            source=EventSource.P2P,
            station_sn=STATION,
            device_sn=serial,
            msg_type=14 if prefix == "T8910" else 18,
            event_type=int(DetectionType.MOTION),
        )
    )
    assert [type(event) for event in emitted] == ([MotionDetected] if camera_capable else [])


def test_unknown_online_status_is_eligible_but_explicit_offline_is_not() -> None:
    """No parameter 1131 is not the same as a reported-offline camera."""
    emitted: list[MotionDetected | MotionRecorded] = []
    activity = StationActivity(FakeActivityStation(), emitted.append)
    activity.observe(state(10, 2, online=None))
    activity.observe(state(12, 3, online=None))
    assert [(type(e), e.count) for e in emitted] == [
        (MotionDetected, 2),
        (MotionRecorded, 1),
    ]

    activity.observe(state(99, 99, online=False))
    activity.observe(state(100, 100, online=None))  # baseline after explicit offline
    assert len(emitted) == 2
    activity.observe(state(101, 100, online=None))
    assert [(type(e), e.count) for e in emitted] == [
        (MotionDetected, 2),
        (MotionRecorded, 1),
        (MotionDetected, 1),
    ]

    activity.reopen()
    emitted.clear()
    activity.observe(state(None, None, online=None))
    activity.on_security_event(
        SecurityEvent(
            source=EventSource.P2P,
            station_sn=STATION,
            device_sn=CAMERA,
            event_type=int(DetectionType.MOTION),
        )
    )
    assert len(emitted) == 1
    assert isinstance(emitted[0], MotionDetected)
    assert emitted[0].source == "push"


def test_push_is_fallback_only_when_counter_missing() -> None:
    emitted: list[MotionDetected | MotionRecorded] = []
    activity = StationActivity(FakeActivityStation(), emitted.append)
    activity.observe(state(None, 3))
    event = SecurityEvent(
        source=EventSource.P2P,
        station_sn=STATION,
        device_sn=CAMERA,
        event_type=int(DetectionType.PERSON),
    )
    activity.on_security_event(event)
    assert len(emitted) == 1
    assert isinstance(emitted[0], MotionDetected)
    assert (emitted[0].source, emitted[0].count) == ("push", 1)
    activity.observe(state(10, 3))  # new counter appears: baseline only
    activity.on_security_event(event)
    assert len(emitted) == 1
    activity.observe(state(11, 3))
    assert len(emitted) == 2
    assert isinstance(emitted[-1], MotionDetected)
    assert emitted[-1].source == "counter"


@pytest.mark.parametrize(
    "event_type",
    [DetectionType.DOORBELL_PRESS, DetectionType.SOUND, DetectionType.CRYING, None],
)
def test_push_fallback_rejects_non_motion_camera_notifications(
    event_type: DetectionType | None,
) -> None:
    """A doorbell press, sound, cry, or unknown type is not motion activity."""
    emitted: list[MotionDetected | MotionRecorded] = []
    activity = StationActivity(FakeActivityStation(), emitted.append)
    activity.observe(state(None, None))  # camera known, detection counter unavailable
    event = SecurityEvent(
        source=EventSource.P2P,
        station_sn=STATION,
        device_sn=CAMERA,
        msg_type=18,
        event_type=None if event_type is None else int(event_type),
    )
    activity.on_security_event(event)
    assert emitted == []

    # A real motion notification still passes through the same fallback.
    activity.on_security_event(replace(event, event_type=int(DetectionType.MOTION)))
    assert len(emitted) == 1
    assert isinstance(emitted[0], MotionDetected)
    assert (emitted[0].source, emitted[0].count) == ("push", 1)


def test_push_ignores_enrichments_unpaired_and_offline() -> None:
    emitted: list[MotionDetected | MotionRecorded] = []
    activity = StationActivity(FakeActivityStation(), emitted.append)
    event = SecurityEvent(
        source=EventSource.P2P,
        station_sn=STATION,
        device_sn=CAMERA,
        event_type=int(DetectionType.MOTION),
    )
    activity.on_security_event(event)  # no state yet
    activity.observe(state(None, None, online=False))
    activity.on_security_event(event)  # offline
    activity.observe(state(None, None))
    activity.on_security_event(
        SecurityEvent(
            source=EventSource.P2P,
            station_sn=STATION,
            device_sn="not-paired",
            event_type=int(DetectionType.MOTION),
        )
    )
    activity.on_security_event(
        SecurityEvent(
            source=EventSource.P2P,
            station_sn=SYNTHETIC.station_sn,
            device_sn=CAMERA,
            event_type=int(DetectionType.MOTION),
        )
    )  # a different station, despite the matching camera
    activity.on_security_event(
        SecurityEvent(
            source=EventSource.P2P,
            station_sn=STATION,
            device_sn=CAMERA,
            event_type=int(DetectionType.MOTION),
            enriches=True,
        )
    )
    assert emitted == []
    activity.on_security_event(event)
    assert len(emitted) == 1


async def test_a_closed_observer_ignores_counters_and_pushes_until_reopened() -> None:
    """Closing disables both observation paths; reopening starts from a baseline."""
    emitted: list[MotionDetected | MotionRecorded] = []
    activity = StationActivity(FakeActivityStation(), emitted.append)

    activity.observe(state(None, None))
    await activity.close()

    event = SecurityEvent(
        source=EventSource.P2P,
        station_sn=STATION,
        device_sn=CAMERA,
        event_type=int(DetectionType.MOTION),
    )

    activity.on_security_event(event)
    activity.observe(state(10, 10))
    assert emitted == []

    activity.reopen()
    activity.observe(state(None, None))
    activity.on_security_event(event)

    assert len(emitted) == 1
    assert isinstance(emitted[0], MotionDetected)
    assert (emitted[0].source, emitted[0].count) == ("push", 1)


def test_synchronous_observation_and_restart() -> None:
    emitted: list[MotionDetected | MotionRecorded] = []
    activity = StationActivity(FakeActivityStation(), emitted.append)
    activity.observe(state(5, 5))  # synchronous: no running event loop needed
    activity.observe(state(6, 6))
    assert len(emitted) == 2
    activity.reopen()
    activity.observe(state(100, 100))  # baseline again after restart
    assert len(emitted) == 2


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
        return [event.count for event in events if isinstance(event, MotionDetected)]

    def recorded_counts() -> list[int]:
        return [event.count for event in events if isinstance(event, MotionRecorded)]

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
    assert not any(isinstance(e, (MotionDetected, MotionRecorded)) for e in events)

    fake.params[0][PARAM_DETECTED_EVENTS] = "103"
    await station.async_update()
    motions = [e for e in events if isinstance(e, MotionDetected)]
    assert len(motions) == 1
    assert (motions[0].source, motions[0].count) == ("counter", 3)
    assert not any(isinstance(e, MotionRecorded) for e in events)

    fake.params[0][PARAM_RECORDED_EVENTS] = "52"
    await station.async_update()
    recordings = [e for e in events if isinstance(e, MotionRecorded)]
    assert len(recordings) == 1
    assert recordings[0].count == 2
    assert any(isinstance(e, StationStateChanged) for e in events)

    await station.async_update()
    assert len([e for e in events if isinstance(e, MotionDetected)]) == 1
    assert len([e for e in events if isinstance(e, MotionRecorded)]) == 1
    assert fake.history_queries == []  # no 10011/10017 history requests
