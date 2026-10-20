"""``rtc/live.py``: the live-open frame, the stream and message ids, the status reply."""

from __future__ import annotations

import json
import struct

import pytest

from eufy_home_security.p2p.xzyh import HEADER_LEN, FrameType, encode_frame
from eufy_home_security.rtc.live import (
    CommandReply,
    live_open_body,
    live_open_frame,
    msg_id,
    parse_reply,
    stream_id,
)
from eufy_home_security.testing import SYNTHETIC

ACCOUNT = SYNTHETIC.account_id
#: A HomeBase 3's answer to the first open on a channel it does not serve over WebRTC.
NOT_FIND_DEV_REPLY = (
    bytes.fromhex("585a59484605840000000100c8000100") + b"\x96\xff\xff\xff" + bytes(128)
)


def test_stream_ids_start_at_200_and_wrap_after_50_opens() -> None:
    assert [stream_id(i) for i in (0, 1, 49, 50, 51)] == [200, 201, 249, 200, 201]


def test_message_ids_count_1_to_255_then_wrap_to_1() -> None:
    assert [msg_id(i) for i in (0, 1, 254, 255)] == [1, 2, 255, 1]


def test_the_frame_carries_the_stream_id_and_the_channel_only_in_the_json() -> None:
    frame = live_open_frame(2, ACCOUNT, stream=201, message_id=7)
    command, length = struct.unpack_from("<HI", frame, 4)
    assert frame[:4] == b"XZYH"
    assert (command, length) == (FrameType.CMD_TRANSFER, len(frame) - HEADER_LEN)
    assert frame[10:16] == bytes([1, 0, 201, 0, 0, 0])
    assert frame[HEADER_LEN:] == live_open_body(2, ACCOUNT, 7)


def test_the_body_is_the_webrtc_player_open_without_a_key() -> None:
    body = json.loads(live_open_body(3, ACCOUNT, 9))
    assert {k: body[k] for k in ("cmd", "mChannel", "account_id", "mValue3", "msg_id")} == {
        "cmd": 1003,
        "mChannel": 3,
        "account_id": ACCOUNT,
        "mValue3": 1003,
        "msg_id": 9,
    }
    payload = body["payload"]
    assert "key" not in payload
    assert (payload["streamtype"], payload["extValue"], payload["msg_id"]) == (2, 1000, 9)
    assert payload["chn_list"] == [{"cameraType": 0, "chn": 3, "index": 0, "sensor": 0}]
    assert payload["accountId"] == ACCOUNT


def test_a_stream_id_must_fit_a_byte() -> None:
    with pytest.raises(ValueError, match=r"0\.\.255"):
        live_open_frame(0, ACCOUNT, stream=256, message_id=1)


def test_the_station_status_reply_is_parsed() -> None:
    assert parse_reply(NOT_FIND_DEV_REPLY) == CommandReply(FrameType.CMD_TRANSFER, 200, -106)
    ok = encode_frame(FrameType.CMD_TRANSFER, bytes(4), bytes([1, 0, 203, 0, 1, 0]))
    assert parse_reply(ok) == CommandReply(FrameType.CMD_TRANSFER, 203, 0)


@pytest.mark.parametrize(
    "data",
    [
        b"",
        b"ANKE" + NOT_FIND_DEV_REPLY[4:],  # not XZYH
        NOT_FIND_DEV_REPLY[:10] + b"\x0a" + NOT_FIND_DEV_REPLY[11:],  # GCM-sealed
        encode_frame(FrameType.CMD_TRANSFER, b"\x00\x00\x00", bytes(6)),  # body < 4 bytes
        NOT_FIND_DEV_REPLY[: HEADER_LEN + 4],  # truncated against its length
    ],
)
def test_anything_but_a_plaintext_status_reply_is_none(data: bytes) -> None:
    assert parse_reply(data) is None
