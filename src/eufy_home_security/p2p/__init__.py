"""Local P2P to a eufy station: PPPP transport, XZYH framing, session crypto, codecs.

The codec modules (``pppp``, ``xzyh``, ``did``, ``crypto``, ``messages``,
``params``, ``notify``, ``alarm``, ``media``, ``mode_actions``, ``storage_info``,
``mpegts``, ``encoder``) are pure: no I/O. The modules that touch the
network — ``discovery`` (LAN search), ``transport`` and ``session`` — drive those
codecs over a UDP socket. ``clip`` and ``broadcast`` mux and share a session's media
streams and open no socket themselves.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from .._lazy import lazy_exports

if TYPE_CHECKING:
    from . import alarm, crypto, media, messages, mode_actions, notify, params
    from .did import Did, static_key
    from .pppp import (
        DISCOVERY_PORT,
        PPPP_MAGIC,
        DrwChunk,
        MsgType,
        decode_drw,
        decode_drw_ack,
        decode_packet,
        encode_drw,
        encode_drw_ack,
        encode_packet,
    )
    from .xzyh import Frame, FrameCipher, FrameType, StreamDecoder, encode_frame

__all__ = [
    "DISCOVERY_PORT",
    "PPPP_MAGIC",
    "Did",
    "DrwChunk",
    "Frame",
    "FrameCipher",
    "FrameType",
    "MsgType",
    "StreamDecoder",
    "alarm",
    "crypto",
    "decode_drw",
    "decode_drw_ack",
    "decode_packet",
    "encode_drw",
    "encode_drw_ack",
    "encode_frame",
    "encode_packet",
    "media",
    "messages",
    "mode_actions",
    "notify",
    "params",
    "static_key",
]

__getattr__, __dir__ = lazy_exports(
    __name__,
    globals(),
    {
        **{
            name: name
            for name in ("alarm", "crypto", "media", "messages", "mode_actions", "notify", "params")
        },
        **dict.fromkeys(("Did", "static_key"), "did"),
        **dict.fromkeys(
            (
                "DISCOVERY_PORT",
                "PPPP_MAGIC",
                "DrwChunk",
                "MsgType",
                "decode_drw",
                "decode_drw_ack",
                "decode_packet",
                "encode_drw",
                "encode_drw_ack",
                "encode_packet",
            ),
            "pppp",
        ),
        **dict.fromkeys(
            ("Frame", "FrameCipher", "FrameType", "StreamDecoder", "encode_frame"), "xzyh"
        ),
    },
)
