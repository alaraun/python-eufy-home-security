"""The live open of a kind-6 call: command 1350 sub-id 1003 on the RTCP APP channel.

The client opens the stream with a GCM-sealed XZYH ``CMD_TRANSFER`` frame (1350) whose
JSON asks for sub-id 1003 on a channel (:func:`live_open_frame`). Subheader byte 2
is not the channel but a per-session stream id, 200 on the first open and counting
up modulo 50 (:func:`stream_id`); the station echoes it in a plaintext 1350 reply
whose body starts with an int32 status (:func:`parse_reply`), ``0`` or one of
:data:`~.p2p.messages.P2P_ERROR_CODES`.

Verified on a HomeBase 3: the reply echoes the stream id and carries a status
(observed: -106 ``NOT_FIND_DEV``). A successful open (status 0, then media) is
declared, not observed. See docs/protocol/rtc-signaling.md § Live open.
"""

from __future__ import annotations

import json
import struct
from dataclasses import dataclass
from typing import Final

from ..p2p.messages import CMD_START_REALTIME_MEDIA
from ..p2p.xzyh import HEADER_LEN, MAGIC, FrameType, encode_frame

#: The XZYH frame type of the live open and its reply (``CMD_TRANSFER``, 1350).
LIVE_OPEN_FRAME: Final = FrameType.CMD_TRANSFER
#: First stream id of a session and the span the id counts through (200..249).
STREAM_ID_BASE: Final = 200
STREAM_ID_SPAN: Final = 50
#: ``msg_id`` counts 1..255 per station, then wraps to 1.
MSG_ID_MAX: Final = 255
#: How long an open may take before it counts as unanswered (the app waits 10 s).
LIVE_OPEN_TIMEOUT: Final = 10.0
#: Subheader byte 0 of the plaintext open before sealing (sealing sets it to 10).
_OPEN_VERSION: Final = 1
#: Subheader offset (in the 16-byte header) of the stream id.
_STREAM_ID_OFFSET: Final = 12
#: Subheader offset of the version byte; 10 marks a GCM-sealed frame.
_VERSION_OFFSET: Final = 10
_VERSION_GCM: Final = 10


def stream_id(index: int) -> int:
    """The stream id of a session's ``index``-th open (0-based): 200..249, wrapping."""
    return STREAM_ID_BASE + index % STREAM_ID_SPAN


def msg_id(index: int) -> int:
    """The ``msg_id`` of a session's ``index``-th open (0-based): 1..255, wrapping."""
    return index % MSG_ID_MAX + 1


def live_open_body(channel: int, account_id: str, message_id: int) -> bytes:
    """The JSON of the live open of ``channel`` (no ``key``, ``streamtype`` 2,
    ``extValue`` 1000)."""
    params = {
        "cmd": CMD_START_REALTIME_MEDIA,
        "mChannel": channel,
        "account_id": account_id,
        "mValue3": CMD_START_REALTIME_MEDIA,
        "mValue5": 0,
        "msg_id": message_id,
        "payload": {
            "streamtype": 2,
            "camera_type": 0,
            "entrytype": 0,
            "accountId": account_id,
            "chn_list": [{"cameraType": 0, "chn": channel, "index": 0, "sensor": 0}],
            "ClientOS": "ANDROID",
            "station_video_type": 0,
            "audio_chn": 0,
            "pip_cord": "",
            "stitch_mode": 1,
            "extValue": 1000,
            "msg_id": message_id,
        },
    }
    return json.dumps(params, separators=(",", ":")).encode()


def live_open_frame(channel: int, account_id: str, *, stream: int, message_id: int) -> bytes:
    """The plaintext XZYH live-open frame (seal it with :class:`~.command.CommandCipher`).

    Subheader ``[1, 0, stream, 0, 0, 0]``: ``stream`` is :func:`stream_id`, the
    channel travels only in the JSON. Raises ``ValueError`` for a stream id outside
    0..255.
    """
    if not 0 <= stream <= 0xFF:
        raise ValueError(f"stream id must be 0..255, got {stream}")
    subheader = bytes([_OPEN_VERSION, 0, stream, 0, 0, 0])
    return encode_frame(LIVE_OPEN_FRAME, live_open_body(channel, account_id, message_id), subheader)


@dataclass(frozen=True, slots=True)
class CommandReply:
    """A station's plaintext reply on the command channel."""

    command: int
    """The XZYH frame type (1350 for the live open)."""
    stream: int
    """Subheader byte 2: the stream id of the open it answers."""
    status: int
    """The int32 at the head of the body: 0 or a ``P2P_ERROR_CODES`` code."""


def parse_reply(data: bytes) -> CommandReply | None:
    """The status reply in a device DATA body; None for anything else (a GCM-sealed
    notification, a frame without a 4-byte body, not an XZYH frame)."""
    if len(data) < HEADER_LEN + 4 or data[:4] != MAGIC:
        return None
    if data[_VERSION_OFFSET] == _VERSION_GCM:
        return None
    command, length = struct.unpack_from("<HI", data, 4)
    if length < 4 or len(data) < HEADER_LEN + length:
        return None
    (status,) = struct.unpack_from("<i", data, HEADER_LEN)
    return CommandReply(command, data[_STREAM_ID_OFFSET], status)
