"""Hardware-reported T8910 FCM motion classification regression tests."""

import base64
import json

import pytest

from eufy_home_security.events import DetectionType, PushMessageType, SecurityEvent
from eufy_home_security.push.decode import decode_push

NOW = 1792799978000


def _event(
    *, msg_type: int = 14, sensor_open: str | int | None = "1", event_type: int | None = None
) -> SecurityEvent:
    payload = {
        "a": msg_type,
        "s": "T8910EXAMPLE",
        "n": "Test PIR",
        "e": sensor_open,
        "t": str(NOW // 1000 - 2),
    }
    if event_type is not None:
        payload["event_type"] = event_type
    return decode_push(
        {
            "app_tab": "eufy_security",
            "type": "10",
            "station_sn": "T8010EXAMPLE",
            "device_sn": "T8910EXAMPLE",
            "event_time": str(NOW // 1000 - 2),
            "payload": base64.b64encode(json.dumps(payload).encode()).decode(),
        },
        now_ms=lambda: NOW,
    )


def test_t8910_motion_trigger() -> None:
    event = _event()
    assert event.msg_type == PushMessageType.MOTION_SENSOR
    assert event.sensor_open == 1
    assert event.detection is DetectionType.MOTION
    assert event.detection_evidence is not None


@pytest.mark.parametrize("value", ["0", 0])
def test_t8910_clear_is_not_another_detection(value: str | int) -> None:
    assert _event(sensor_open=value).detection is None


@pytest.mark.parametrize("value", [None, "invalid", -1])
def test_missing_or_unknown_sensor_state_is_not_motion(value: str | int | None) -> None:
    assert _event(sensor_open=value).detection is None


def test_non_motion_message_does_not_gain_pir_classification() -> None:
    assert _event(msg_type=3, sensor_open="1").detection is None


def test_camera_motion_classification_not_changed() -> None:
    assert _event(msg_type=1, sensor_open=None, event_type=3101).detection is DetectionType.MOTION
