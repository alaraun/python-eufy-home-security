"""XZYH application framing inside the DRW data stream.

Once DRW chunks are reassembled in order they form a byte stream of ``XZYH``
records::

    "XZYH"(4) | type u16le | len u32le | subheader 6B | payload[len]

``type`` names the application frame (CONN_INIT, a parameter notify, a command
result, a video frame, …). The subheader's first byte is a *per-frame* cipher
tag — 0x01 = AES-128-ECB under the static key, 0x08 = AES-256-GCM under the
session key — and it must be read per frame, never assumed for the session: the
same station sends the same event under 0x01 to one client and 0x08 to another.

:class:`StreamDecoder` turns the ordered chunk deliveries of one channel into a
stream of complete frames. It is incremental and ordered: it buffers
out-of-order chunks until they are contiguous, ignores duplicates and 16-bit
index wraparound, and emits each frame exactly once — a repeated frame (say, a
return to the same guard mode) is a new frame, not a duplicate.

A header whose length exceeds :data:`MAX_FRAME_LEN` is treated as a false
``XZYH`` match inside other data: the decoder skips one byte and scans on, so a
corrupt length can never stall the channel waiting for bytes that will not come.
"""

from __future__ import annotations

import logging
import struct
from dataclasses import dataclass
from enum import IntEnum

from .._logging import LogThrottle
from ..exceptions import ProtocolError

# Canonical in models; the redundant alias is the explicit re-export mypy --strict needs.
from ..models import FrameCipher as FrameCipher  # noqa: PLC0414

_LOGGER = logging.getLogger(__name__)

MAGIC = b"XZYH"
HEADER_LEN = 16

#: Largest payload a frame header may declare. The biggest real frames are 4K
#: HEVC keyframes of up to about 1 MiB; 8 MiB leaves ample headroom while bounding
#: what one false or corrupt header can make the decoder wait for.
MAX_FRAME_LEN = 8 * 1024 * 1024

#: Half the 16-bit index ring: indices within this distance ahead of the next
#: expected one are future chunks to buffer; the rest are old retransmits.
_INDEX_WINDOW = 0x8000


class FrameType(IntEnum):
    """XZYH frame type (== the app's ``CommandType`` for the same concept)."""

    STOP_REALTIME_MEDIA = 0x03EC
    """1004 sent bare (four zero bytes): stops a standalone device's live stream."""
    CONN_INIT = 0x044C
    PARAM_NOTIFY = 0x044F
    RECORD_PLAY_CTRL = 0x0402
    DEV_STATUS = 0x0473
    """1139 ``PING``: the app's empty keepalive and the station's answer.

    The app sends it every 3 s to a standalone device and about every 20 s to a HomeBase 3.
    """
    ALARM_MODE_NOTIFY = 0x047F
    ALARM_TONE_NOTIFY = 0x04B1
    """1201 ``SET_TONE_FILE``: the station's alarm tone (see :mod:`.alarm`)."""
    SIREN_NOTIFY = 0x04B2
    """1202 ``SET_DEVS_TONE_FILE``: a camera's siren."""
    VIDEO_FRAME = 0x0514
    AUDIO_FRAME = 0x0515
    DB_SYNC = 0x051A
    MEDIA_DOWNLOAD = 0x051C
    CMD_TRANSFER = 0x0546
    NOTIFY_PAYLOAD = 0x0547
    LIGHT_NOTIFY = 0x0578
    """1400 ``FLOODLIGHT_MANUAL_SWITCH``: a camera's light."""
    DOORBELL_PAYLOAD = 0x06A4
    """1700 ``DOORBELL_SET_PAYLOAD``: ``{"commandType": sub-command, "data": params}``,
    a standalone device's command wrapper (see :mod:`..devices.recipes`)."""
    BATTERY_STATUS = 0x083F
    """2111, the handlers' name (app enum ``SUB1G_REP_UNPLUG_POWER_LINE``); seen from the
    station when a session ends, its body undecoded."""


@dataclass(frozen=True, slots=True)
class Frame:
    """One decoded XZYH frame."""

    type: int
    subheader: bytes
    payload: bytes

    @property
    def cipher(self) -> int | None:
        """The frame's cipher tag (subheader byte 0), or None when absent."""
        return self.subheader[0] if self.subheader else None


def encode_frame(frame_type: int, payload: bytes, subheader: bytes) -> bytes:
    """Frame one XZYH record. ``subheader`` must be 6 bytes."""
    if len(subheader) != HEADER_LEN - 10:
        raise ProtocolError(f"XZYH subheader must be 6 bytes, got {len(subheader)}")
    return MAGIC + struct.pack("<HI", frame_type & 0xFFFF, len(payload)) + subheader + payload


class StreamDecoder:
    """Ordered, incremental XZYH frame reassembly for one DRW channel."""

    __slots__ = (
        "_buf",
        "_expected",
        "_initial",
        "_max_frame_len",
        "_max_pending",
        "_pending",
        "_pending_bytes",
        "_throttle",
    )

    def __init__(
        self,
        *,
        first_index: int | None = 0,
        max_pending: int = 4096,
        max_frame_len: int = MAX_FRAME_LEN,
    ) -> None:
        """``first_index`` None adopts the first index seen; else it is expected first.

        ``max_frame_len`` bounds the payload length a header may declare (see
        :data:`MAX_FRAME_LEN`); the reassembly buffer never holds more than one
        header plus that many bytes once the complete frames are extracted.
        """
        self._initial = None if first_index is None else first_index & 0xFFFF
        self._max_pending = max_pending
        self._max_frame_len = max_frame_len
        self._expected: int | None = self._initial
        self._pending: dict[int, bytes] = {}
        self._pending_bytes = 0
        self._buf = bytearray()
        self._throttle = LogThrottle()

    def reset(self) -> None:
        """Drop all buffered state (a new session restarts channel indices)."""
        self._expected = self._initial
        self._pending.clear()
        self._pending_bytes = 0
        self._buf.clear()

    def feed(self, index: int, data: bytes) -> list[Frame]:
        """Add one DRW chunk; return every frame that is now complete, in order."""
        index &= 0xFFFF
        if self._expected is None:
            self._expected = index
        distance = (index - self._expected) & 0xFFFF
        if distance >= _INDEX_WINDOW:
            # An index behind the next expected one: a retransmit of a chunk
            # already consumed. Ignore it.
            if self._throttle.should_log("stale-index"):
                _LOGGER.debug(
                    "dropping DRW idx%d: already consumed (expecting idx%d)", index, self._expected
                )
            return []
        if index in self._pending:
            if self._throttle.should_log("duplicate-index"):
                _LOGGER.debug("dropping duplicate DRW idx%d", index)
        elif distance and self._throttle.should_log("out-of-order"):
            _LOGGER.debug("DRW idx%d ahead of idx%d; buffering", index, self._expected)
        if index not in self._pending:
            self._pending[index] = data
            self._pending_bytes += len(data)
            if len(self._pending) > self._max_pending:
                raise ProtocolError(
                    f"XZYH reassembly exceeded {self._max_pending} pending chunks "
                    "(a lost chunk, or a corrupt index stream)"
                )
            # The chunk count alone does not bound memory: a chunk is a whole UDP
            # payload, so thousands of them are hundreds of megabytes. One lost chunk
            # on the media channel — routine on UDP — makes everything after it queue
            # here, and a session holds one decoder per channel byte off the wire.
            # The budget allows a whole frame plus the chunk that carries its tail, so
            # a legitimate frame at the length limit still reassembles.
            budget = HEADER_LEN + self._max_frame_len + len(data)
            if self._pending_bytes > budget:
                raise ProtocolError(
                    f"XZYH reassembly buffered more than {budget} bytes while waiting "
                    "for a lost chunk"
                )
        while self._expected in self._pending:
            self._pending_bytes -= len(self._pending[self._expected])
            self._buf += self._pending.pop(self._expected)
            self._expected = (self._expected + 1) & 0xFFFF
        frames = self._extract()
        if len(self._buf) > HEADER_LEN + self._max_frame_len:
            # Unreachable while _extract keeps its invariant; a hard stop rather
            # than unbounded growth if it ever does not, so the session resets.
            raise ProtocolError(
                f"XZYH reassembly buffer exceeded {HEADER_LEN + self._max_frame_len} bytes"
            )
        return frames

    def _extract(self) -> list[Frame]:
        out: list[Frame] = []
        buf = self._buf
        while True:
            if len(buf) < 4:
                break
            if bytes(buf[:4]) != MAGIC:
                if not self._resync():
                    break
                continue
            if len(buf) < HEADER_LEN:
                break
            frame_type = struct.unpack_from("<H", buf, 4)[0]
            length = struct.unpack_from("<I", buf, 6)[0]
            if length > self._max_frame_len:
                # No real frame is this large: the magic was a false match (or the
                # header is corrupt). Skip it and scan for the next boundary.
                if self._throttle.should_log("oversize"):
                    _LOGGER.warning(
                        "XZYH header declares %d bytes (max %d); resyncing",
                        length,
                        self._max_frame_len,
                    )
                del buf[:1]
                continue
            if len(buf) < HEADER_LEN + length:
                break
            subheader = bytes(buf[10:HEADER_LEN])
            payload = bytes(buf[HEADER_LEN : HEADER_LEN + length])
            out.append(Frame(type=frame_type, subheader=subheader, payload=payload))
            del buf[: HEADER_LEN + length]
        return out

    def _resync(self) -> bool:
        """Drop leading non-frame bytes up to the next MAGIC. Returns True if found."""
        buf = self._buf
        nxt = buf.find(MAGIC, 1)
        if self._throttle.should_log("resync"):
            _LOGGER.warning("XZYH stream desync; scanning for the next frame boundary")
        if nxt == -1:
            # No magic anywhere; keep only a possible split-magic tail.
            if len(buf) > 3:
                del buf[: len(buf) - 3]
            return False
        del buf[:nxt]
        return True
