"""Alarm frames (0x04B1 tone, 0x04B2 siren, 0x0578 light)."""

from __future__ import annotations

import struct

import pytest

from eufy_home_security.events import AlarmChanged, AlarmStopSource, EventSource
from eufy_home_security.p2p.alarm import AlarmFrame, decode_alarm_frame
from eufy_home_security.p2p.xzyh import Frame, FrameCipher, FrameType
from eufy_home_security.testing import SYNTHETIC


def _frame(ftype: int, channel: int) -> Frame:
    return Frame(ftype, bytes([FrameCipher.GCM, 0x3F, channel, 2, 0, 0x12]), b"")


def _u32(*values: int) -> bytes:
    return struct.pack(f"<{len(values)}I", *values)


@pytest.mark.parametrize(
    ("ftype", "channel", "plain", "decoded"),
    [
        (FrameType.ALARM_TONE_NOTIFY, 1, _u32(3, 30), AlarmFrame(1201, 1, (3, 30))),
        (FrameType.SIREN_NOTIFY, 1, _u32(25, 30), AlarmFrame(1202, 1, (25, 30))),
        (FrameType.LIGHT_NOTIFY, 1, _u32(1), AlarmFrame(1400, 1, (1,))),
        (FrameType.ALARM_TONE_NOTIFY, 255, _u32(16, 0) + b"\x00", AlarmFrame(1201, 255, (16, 0))),
        (FrameType.ALARM_TONE_NOTIFY, 1, _u32(3), None),  # too short
        (FrameType.ALARM_MODE_NOTIFY, 255, _u32(0, 0), None),  # not an alarm frame
    ],
)
def test_decode_alarm_frame(
    ftype: int, channel: int, plain: bytes, decoded: AlarmFrame | None
) -> None:
    assert decode_alarm_frame(_frame(ftype, channel), plain) == decoded


def test_a_frame_without_a_channel_byte_is_not_decoded() -> None:
    frame = Frame(FrameType.LIGHT_NOTIFY, b"\x08\x00", b"")
    assert decode_alarm_frame(frame, _u32(1)) is None


def test_the_cached_value_is_the_first_u32() -> None:
    assert AlarmFrame(1201, 1, (3, 30)).value == "3"
    assert AlarmFrame(1400, 1, (0,)).value == "0"


def _change(**fields: object) -> AlarmChanged:
    return AlarmChanged(
        station_sn=SYNTHETIC.station_sn,
        source=EventSource.P2P,
        **fields,  # type: ignore[arg-type]
    )


@pytest.mark.parametrize(
    ("frame", "change"),
    [
        (
            AlarmFrame(1201, 1, (3, 30)),
            _change(alarming=True, channel=1, event_type=3, duration_s=30),
        ),
        (AlarmFrame(1201, 0, (0, 0)), _change(alarming=False, channel=0)),
        (
            AlarmFrame(1201, 255, (16, 0)),
            _change(alarming=False, channel=255, event_type=16, stop_source=AlarmStopSource.APP),
        ),
        (AlarmFrame(1201, 1, (3, 0)), _change(alarming=True, channel=1, event_type=3)),
        (AlarmFrame(1202, 1, (25, 30)), None),  # the siren is not the alarm's state
        (AlarmFrame(1400, 1, (1,)), None),
    ],
)
def test_the_tone_frame_is_the_alarm_state(frame: AlarmFrame, change: AlarmChanged | None) -> None:
    assert frame.alarm_change(SYNTHETIC.station_sn) == change
