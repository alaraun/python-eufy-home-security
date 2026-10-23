"""Decoding the station's alarm frames: tone, siren and light.

Every session on a station receives these, whoever triggered or stopped the alarm.
The frame type is the parameter id (the app's ``CommandType``), subheader byte 2 is
the channel (255 = the station), and the decrypted body is little-endian u32 values:

========================  =======  =========================  =============================
frame                     param    body                       meaning
========================  =======  =========================  =============================
``0x04B1`` alarm tone     1201     ``[event_type, seconds]``  ``[3, 30]`` on the triggering
                                                              camera's channel: the alarm
                                                              started (30 s); ``[0, 0]``:
                                                              ended (timeout, disarm);
                                                              ``[16, 0]`` on 255: stopped
                                                              from the app
``0x04B2`` camera siren   1202     ``[event_type, seconds]``  ``[25, 30]`` on, ``[0, 0]`` off
``0x0578`` camera light   1400     ``[state]``                1 on, 0 off (also 0 at each
                                                              detection and periodically)
========================  =======  =========================  =============================

A tone or siren frame reports its alarm off when the event type is one of
:data:`ALARM_OFF_TYPES` (0 ended, 1 stopped by the device, 15/16/17 stopped from a
keypad, the app or the HomeBase) and on for any other type, as the eufy app reads them.
As a state (:attr:`AlarmFrame.alarm_state`), the app takes an off type only with no
time left and an on type only with time left; it ignores the other frames.

Arming and disarming also send ``[0, 0]`` tone and siren frames on each channel. The
station sends them under GCM; the session refuses ECB copies once a session key exists
(they would be forgeable state). This module is pure: the session decrypts.
"""

from __future__ import annotations

import struct
from collections.abc import Mapping
from dataclasses import dataclass
from datetime import datetime
from types import MappingProxyType
from typing import Final

from ..events import ALARM_OFF_TYPES, AlarmChanged, AlarmStopSource, EventSource
from .xzyh import Frame, FrameType

#: The alarm frame types, each with the number of u32 values its body carries.
ALARM_FRAME_VALUES: Final[Mapping[int, int]] = MappingProxyType(
    {FrameType.ALARM_TONE_NOTIFY: 2, FrameType.SIREN_NOTIFY: 2, FrameType.LIGHT_NOTIFY: 1}
)
_CHANNEL_BYTE: Final = 2


@dataclass(frozen=True, slots=True)
class AlarmFrame:
    """One decoded alarm frame."""

    param_id: int
    """The frame type, which is the parameter id (1201, 1202 or 1400)."""
    channel: int
    values: tuple[int, ...]

    @property
    def value(self) -> str:
        """The parameter value the session caches: the first u32, as a decimal string
        (the event type of a tone or siren frame, the light state)."""
        return str(self.values[0])

    @property
    def alarm_on(self) -> bool:
        """Whether a tone or siren frame reports its alarm on: an event type outside
        :data:`ALARM_OFF_TYPES`."""
        return self.values[0] not in ALARM_OFF_TYPES

    @property
    def seconds_left(self) -> int:
        """A tone or siren frame's time left in seconds; a value above 1000 is read as
        milliseconds, as the eufy app does."""
        seconds = self.values[1]
        return seconds // 1000 if seconds > 1000 else seconds

    @property
    def alarm_state(self) -> bool | None:
        """The state a tone or siren frame sets, as the eufy app reads it: off for an
        off type (:attr:`alarm_on` False) with no time left, on for an on type with time
        left, None (no change) for the rest (``[10, 0]``, ``[16, 5]``)."""
        left = self.values[1]
        if self.alarm_on:
            return True if left > 0 else None
        return False if left == 0 else None

    def alarm_change(self, station_sn: str, *, at: datetime) -> AlarmChanged | None:
        """The alarm state an alarm-tone frame (1201) reports; None for other frames.

        An event type that :attr:`alarm_on` reads on starts the alarm (``duration_s``
        from the seconds, None when 0); any other ends it, an
        :class:`~..events.AlarmStopSource` (16 from the app) naming its source. ``at``
        is when the frame arrived (the frame carries no time of its own). Emit it only on
        a transition: arming sends ``[0, 0]`` on every channel.
        """
        if self.param_id != FrameType.ALARM_TONE_NOTIFY:
            return None
        event_type, seconds = self.values
        try:
            stop: AlarmStopSource | None = AlarmStopSource(event_type)
        except ValueError:
            stop = None
        alarming = self.alarm_on
        return AlarmChanged(
            station_sn=station_sn,
            alarming=alarming,
            source=EventSource.P2P,
            channel=self.channel,
            event_type=event_type or None,
            duration_s=(seconds or None) if alarming else None,
            stop_source=stop,
            at=at,
        )


def decode_alarm_frame(frame: Frame, plain: bytes) -> AlarmFrame | None:
    """Decode an alarm frame's decrypted body; None when ``frame`` is not one or the
    body or subheader is too short. Bytes past the expected values are ignored."""
    count = ALARM_FRAME_VALUES.get(frame.type)
    if count is None or len(frame.subheader) <= _CHANNEL_BYTE or len(plain) < 4 * count:
        return None
    values = struct.unpack_from(f"<{count}I", plain)
    return AlarmFrame(frame.type, frame.subheader[_CHANNEL_BYTE], tuple(values))
