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

Arming and disarming also send ``[0, 0]`` tone and siren frames on each channel. The
station sends them under GCM; the session refuses ECB copies once a session key exists
(they would be forgeable state). This module is pure: the session decrypts.
"""

from __future__ import annotations

import struct
from collections.abc import Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from ..events import AlarmChanged, AlarmStopSource, EventSource
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

    def alarm_change(self, station_sn: str) -> AlarmChanged | None:
        """The alarm state an alarm-tone frame (1201) reports; None for other frames.

        A non-zero event type that is not an :class:`~..events.AlarmStopSource` starts
        the alarm (``duration_s`` from the seconds, None when 0); 0 ends it, and a stop
        code (16 from the app) ends it naming its source. Emit it only on a transition:
        arming sends ``[0, 0]`` on every channel.
        """
        if self.param_id != FrameType.ALARM_TONE_NOTIFY:
            return None
        event_type, seconds = self.values
        try:
            stop: AlarmStopSource | None = AlarmStopSource(event_type)
        except ValueError:
            stop = None
        alarming = event_type != 0 and stop is None
        return AlarmChanged(
            station_sn=station_sn,
            alarming=alarming,
            source=EventSource.P2P,
            channel=self.channel,
            event_type=event_type or None,
            duration_s=(seconds or None) if alarming else None,
            stop_source=stop,
        )


def decode_alarm_frame(frame: Frame, plain: bytes) -> AlarmFrame | None:
    """Decode an alarm frame's decrypted body; None when ``frame`` is not one or the
    body or subheader is too short. Bytes past the expected values are ignored."""
    count = ALARM_FRAME_VALUES.get(frame.type)
    if count is None or len(frame.subheader) <= _CHANNEL_BYTE or len(plain) < 4 * count:
        return None
    values = struct.unpack_from(f"<{count}I", plain)
    return AlarmFrame(frame.type, frame.subheader[_CHANNEL_BYTE], tuple(values))
