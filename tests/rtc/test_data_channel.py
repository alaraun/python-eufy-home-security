"""Tests for the WebRTC data channel's framing (:mod:`.rtc.data_channel`).

The golden header bytes are the ones a HomeBase 3 (T8030) sent/accepted on the kind-5
data channel, so they pin the field offsets against a real capture.
"""

from __future__ import annotations

import struct
import zlib

import pytest

from eufy_home_security.exceptions import ProtocolError
from eufy_home_security.rtc.data_channel import (
    FILE_HEAD_MAGIC,
    KCP_DOWNLOAD_CONV,
    WRTC_HEADER_NEW,
    WRTC_HEADER_OLD,
    DataMsgType,
    decode_wrtc_link,
    encode_kcp_prefix,
    encode_wrtc_link,
    strip_file_head,
    strip_kcp_prefix,
)


def test_new_header_round_trips() -> None:
    payload = bytes(range(80))
    frame = encode_wrtc_link(payload, msg_type=DataMsgType.COMMAND, seq=7, now=0x6AD77131)
    assert len(frame) == WRTC_HEADER_NEW + len(payload)
    msg = decode_wrtc_link(frame)
    assert (msg.msg_type, msg.seq, msg.payload) == (DataMsgType.COMMAND, 7, payload)


def test_old_header_round_trips() -> None:
    payload = b"\xaa" * 40
    frame = encode_wrtc_link(payload, msg_type=DataMsgType.NOTIFY, seq=3, old=True, now=0x6AD77131)
    assert len(frame) == WRTC_HEADER_OLD + len(payload)
    msg = decode_wrtc_link(frame)
    assert (msg.msg_type, msg.seq, msg.payload) == (DataMsgType.NOTIFY, 3, payload)


def test_new_header_bytes_are_as_the_app_builds_them() -> None:
    # version 9, header_len 24, payload_len, const 1 @8, time @12, type @16, seq @20.
    frame = encode_wrtc_link(b"\x00" * 148, msg_type=1, seq=0, now=0x6AD77131)
    head = frame[:WRTC_HEADER_NEW]
    assert struct.unpack_from("<H", head, 0) == (9,)
    assert struct.unpack_from("<H", head, 2) == (24,)
    assert struct.unpack_from("<I", head, 4) == (148,)
    assert head[8] == 1
    assert struct.unpack_from("<I", head, 12) == (0x6AD77131,)
    assert head[16] == 1
    assert struct.unpack_from("<I", head, 20) == (0,)


def test_decodes_the_hardware_new_header() -> None:
    # The WrtcLinkProtocol header a HomeBase 3 returned (file data msg_type 1, seq 0).
    head = bytes.fromhex("090018009400000001534d003171d76a01afff3d00000000")
    assert len(head) == WRTC_HEADER_NEW
    msg = decode_wrtc_link(head + b"\x11" * 148)
    assert msg.msg_type == 1
    assert msg.seq == 0
    assert len(msg.payload) == 148


@pytest.mark.parametrize(
    "buf",
    [
        b"\x00\x00",  # too short for the version
        struct.pack("<HH", 8, 24) + b"\x00" * 24,  # wrong version
        struct.pack("<HH", 9, 22) + b"\x00" * 24,  # unknown header length
        struct.pack("<HHI", 9, 24, 10) + b"\x00" * 10,  # header truncated (needs 24)
        struct.pack("<HHI", 9, 24, 50) + b"\x00" * 20,  # payload truncated
    ],
)
def test_decode_rejects_malformed(buf: bytes) -> None:
    with pytest.raises(ProtocolError):
        decode_wrtc_link(buf)


def test_strip_file_head_strips_a_wrapped_reply() -> None:
    body = encode_wrtc_link(b"XZYH-payload", msg_type=1, seq=1, now=0)
    head = struct.pack(
        "<IIIII", FILE_HEAD_MAGIC, 0x01000001, len(body), zlib.crc32(body) & 0xFFFFFFFF, 0
    )
    assert strip_file_head(head + body) == body
    assert strip_file_head(head + body, verify_crc=True) == body


def test_strip_file_head_passes_through_unwrapped() -> None:
    frame = encode_wrtc_link(b"direct", msg_type=1, seq=0, now=0)
    assert strip_file_head(frame) == frame  # client sends carry no file_head


def test_strip_file_head_hardware_prefix() -> None:
    # The 44-byte prefix (file_head + WrtcLink header) a HomeBase 3 sent: data_len 0xac.
    file_head = bytes.fromhex("48595a5801000001ac000000845800e400000000")
    wrtc_head = bytes.fromhex("090018009400000001534d003171d76a01afff3d00000000")
    body = wrtc_head + b"\x22" * (0xAC - WRTC_HEADER_NEW)
    stripped = strip_file_head(file_head + body)
    assert len(stripped) == 0xAC
    assert decode_wrtc_link(stripped).msg_type == 1


def test_strip_file_head_crc_mismatch_raises() -> None:
    body = b"abcdef"
    head = struct.pack("<IIIII", FILE_HEAD_MAGIC, 0, len(body), 0xDEADBEEF, 0)
    with pytest.raises(ProtocolError):
        strip_file_head(head + body, verify_crc=True)


def test_strip_file_head_truncated_body_raises() -> None:
    head = struct.pack("<IIII", FILE_HEAD_MAGIC, 0, 100, 0) + b"\x00\x00\x00\x00"
    with pytest.raises(ProtocolError):
        strip_file_head(head + b"short")


def test_kcp_prefix_round_trips() -> None:
    seg = b"kcp-segment-bytes"
    datagram = encode_kcp_prefix(seg, conv=1)
    assert len(datagram) == 32 + len(seg)
    conv, out = strip_kcp_prefix(datagram)
    assert conv == 1
    assert out == seg


def test_kcp_prefix_download_conv() -> None:
    conv, _ = strip_kcp_prefix(encode_kcp_prefix(b"x" * 40, conv=KCP_DOWNLOAD_CONV))
    assert conv == KCP_DOWNLOAD_CONV


def test_kcp_strip_short_datagram_is_bare() -> None:
    conv, out = strip_kcp_prefix(b"short-bare")
    assert conv == 0
    assert out == b"short-bare"
