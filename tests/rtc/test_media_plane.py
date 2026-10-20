"""``rtc/media_plane.py``: the SRTP context and the KCP data channel.

Needs the ``rtc`` extra; skipped where it is not installed.
"""

from __future__ import annotations

import asyncio
import base64
import struct

import pytest

pytest.importorskip("pylibsrtp")
pytest.importorskip("kcp")

from eufy_home_security.rtc.media_plane import (
    SDES_KEY_LEN,
    KcpDataChannel,
    SdesSrtp,
)
from eufy_home_security.rtc.sdp import SDES_INLINE_KEY


def _rtp(payload: bytes = b"frame") -> bytes:
    return struct.pack("!BBHII", 0x80, 97, 7, 9000, 0xDEADBEEF) + payload


def test_sdes_key_is_thirty_bytes() -> None:
    assert len(base64.b64decode(SDES_INLINE_KEY)) == SDES_KEY_LEN


def test_srtp_round_trips_rtp_under_the_sdes_key() -> None:
    sender, receiver = SdesSrtp.from_inline(), SdesSrtp.from_inline()
    packet = _rtp()
    protected = sender._outbound.protect(packet)  # the station encrypts; we decrypt
    assert protected != packet
    assert receiver.unprotect_rtp(protected) == packet


def test_srtcp_round_trips() -> None:
    srtp = SdesSrtp.from_inline()
    rtcp = struct.pack("!BBHI", 0x80, 201, 1, 0xDEADBEEF)  # a receiver report
    assert srtp.unprotect_rtcp(srtp.protect_rtcp(rtcp)) == rtcp


def test_a_wrong_length_master_key_is_refused() -> None:
    with pytest.raises(ValueError, match="30 bytes"):
        SdesSrtp(b"\x00" * 16)


class _Pipe:
    """One end of an in-memory packet link."""

    def __init__(self, outbound: asyncio.Queue[bytes], inbound: asyncio.Queue[bytes]) -> None:
        self._out = outbound
        self._in = inbound

    async def send(self, data: bytes) -> None:
        self._out.put_nowait(data)

    async def recv(self) -> bytes:
        return await self._in.get()

    async def close(self) -> None:
        return None


async def test_kcp_data_channel_round_trips_between_two_ends() -> None:
    a_to_b: asyncio.Queue[bytes] = asyncio.Queue()
    b_to_a: asyncio.Queue[bytes] = asyncio.Queue()
    left = KcpDataChannel(_Pipe(a_to_b, b_to_a), conv_id=1)
    right = KcpDataChannel(_Pipe(b_to_a, a_to_b), conv_id=1)
    try:
        await left.send(b'{"cmd":1350}')
        assert await asyncio.wait_for(right.recv(), 2) == b'{"cmd":1350}'
        await right.send(b"ack")
        assert await asyncio.wait_for(left.recv(), 2) == b"ack"
    finally:
        await left.close()
        await right.close()
