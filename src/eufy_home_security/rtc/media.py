"""The media plane of an RTC session: interfaces, RTP and RTCP framing,
H.264 and H.265 depacketizing.

A live view over RTC runs on one ICE connection (TURN relay from the CALL) carrying
SRTP keyed through the SDP, RTP video (payload type 97 H.265, 99 H.264), FlexFEC
(125) and audio (111, AAC in an Opus-labelled slot). The device additionally
encrypts parameter sets, IDR slices and audio inside the frames. Commands travel as
RTCP APP packets on the same connection, or over a KCP data channel on a second ICE
connection.

Implemented here (pure): RTP header parsing, RTCP APP build/parse, the H.264
(RFC 6184) and H.265 (RFC 7798) depacketizers, the CALL's TURN relay and ICE
candidate lines. The command and notification AES-128-GCM is in :mod:`.command`;
the in-frame AES-128-GCM (:class:`FrameDecryptor`, video) in :mod:`.frame_crypto`.
The interfaces :class:`IceTransport`, :class:`SrtpContext` and :class:`DataChannel`
are implemented on the ``rtc`` extra in :mod:`.media_plane`.
"""

from __future__ import annotations

import struct
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from enum import IntEnum
from typing import Any, Final, Protocol, runtime_checkable

from .._logging import redact
from ..exceptions import ProtocolError

RTP_VERSION: Final = 2
RTP_HEADER_LEN: Final = 12
RTCP_APP: Final = 204

START_CODE: Final = b"\x00\x00\x00\x01"


class PayloadType(IntEnum):
    """RTP payload types of an RTC live view."""

    AUDIO = 111
    """AAC (LC or ELD) in a slot the SDP labels Opus."""
    H265 = 97
    H264 = 99
    FLEXFEC = 125


class CommandRoute(IntEnum):
    """How a command reaches the device over RTC (a handler's ``rtcSendRoute``)."""

    DATA_CHANNEL = 0
    """The KCP data channel."""
    RTCP = 1
    """An RTCP APP packet on the media connection."""


@dataclass(frozen=True, slots=True)
class TurnServer:
    """The TURN relay the signaling server allocates for a call (CALL 100/200 ``turn``)."""

    host: str
    port: int
    username: str
    password: str

    @classmethod
    def from_json(cls, turn: Mapping[str, Any] | None) -> TurnServer | None:
        """The primary relay of a ``turn`` object (``turn_addr``, ``turn_port``,
        ``turn_user``, ``turn_password``), or ``None`` when one is missing. The app
        configures only this one; ``alt_turn_addr``/``alt_turn_port`` are unused."""
        if turn is None:
            return None
        host, port = turn.get("turn_addr"), turn.get("turn_port")
        user, password = turn.get("turn_user"), turn.get("turn_password")
        if not (isinstance(host, str) and host and isinstance(user, str) and user):
            return None
        if not isinstance(password, str) or not isinstance(port, int | str):
            return None
        try:
            return cls(host, int(port), user, password)
        except ValueError:
            return None

    def __repr__(self) -> str:
        return (
            f"TurnServer(host={self.host!r}, port={self.port}, username={redact(self.username)!r})"
        )


CANDIDATE_PREFIX: Final = "candidate:"


def candidate_body(line: str) -> str:
    """An ICE candidate line without its ``a=`` and ``candidate:`` prefixes (the
    device sends ``a=candidate:…``, the client ``candidate:…``)."""
    text = line.strip()
    text = text.removeprefix("a=")
    return text.removeprefix(CANDIDATE_PREFIX)


# ── interfaces ───────────────────────────────────────────────────────────────


@runtime_checkable
class IceTransport(Protocol):
    """One ICE connection (one component: BUNDLE and rtcp-mux) with local
    credentials the caller dictates; the client side is ICE-controlled."""

    async def gather(
        self, *, local_ufrag: str, local_pwd: str, turn: TurnServer | None
    ) -> list[str]:
        """Gather the local candidates; returns them as ``candidate:…`` lines."""
        ...

    def add_remote_candidate(self, candidate: str) -> None:
        """Add one remote candidate line, before or during :meth:`connect`."""
        ...

    async def connect(self, *, remote_ufrag: str, remote_pwd: str) -> None:
        """Run the connectivity checks until the remote side nominates a pair."""
        ...

    async def recv(self) -> bytes: ...

    async def send(self, data: bytes) -> None: ...

    async def close(self) -> None: ...


@runtime_checkable
class SrtpContext(Protocol):
    """SRTP/SRTCP protection keyed through the SDP."""

    def unprotect_rtp(self, packet: bytes) -> bytes: ...

    def unprotect_rtcp(self, packet: bytes) -> bytes: ...

    def protect_rtcp(self, packet: bytes) -> bytes: ...


@runtime_checkable
class FrameDecryptor(Protocol):
    """The device's encryption inside frames (parameter sets, IDR slices, audio)."""

    def video(self, frame: bytes, *, keyframe: bool) -> bytes: ...

    def audio(self, frame: bytes) -> bytes: ...


@runtime_checkable
class DataChannel(Protocol):
    """The KCP data channel for commands, notifications and files."""

    async def send(self, data: bytes) -> None: ...

    async def recv(self) -> bytes: ...

    async def close(self) -> None: ...


# ── RTP ──────────────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class RtpPacket:
    """One RTP packet (header extension and padding removed)."""

    payload_type: int
    marker: bool
    sequence: int
    timestamp: int
    ssrc: int
    payload: bytes

    @classmethod
    def parse(cls, data: bytes) -> RtpPacket:
        if len(data) < RTP_HEADER_LEN:
            raise ProtocolError("RTP packet shorter than its header")
        b0, b1, seq, ts, ssrc = struct.unpack_from("!BBHII", data, 0)
        if b0 >> 6 != RTP_VERSION:
            raise ProtocolError(f"RTP version {b0 >> 6}")
        offset = RTP_HEADER_LEN + 4 * (b0 & 0x0F)
        if b0 & 0x10:
            if len(data) < offset + 4:
                raise ProtocolError("RTP header extension truncated")
            words = struct.unpack_from("!H", data, offset + 2)[0]
            offset += 4 + 4 * words
        end = len(data)
        if b0 & 0x20:
            end -= data[-1]
        if offset > end:
            raise ProtocolError("RTP packet shorter than its header")
        return cls(b1 & 0x7F, bool(b1 & 0x80), seq, ts, ssrc, data[offset:end])


def is_rtcp(data: bytes) -> bool:
    """Whether a muxed packet is RTCP (payload type byte 192..223, RFC 5761)."""
    return len(data) >= 2 and 192 <= data[1] <= 223


# ── RTCP APP (commands over the media connection) ────────────────────────────


@dataclass(frozen=True, slots=True)
class RtcpApp:
    """An RTCP APP packet (RFC 3550 § 6.7)."""

    subtype: int
    ssrc: int
    name: bytes
    data: bytes

    def encode(self) -> bytes:
        if len(self.name) != 4:
            raise ValueError("an RTCP APP name is four bytes")
        if not 0 <= self.subtype < 32:
            raise ValueError("an RTCP APP subtype is five bits")
        data = self.data + b"\0" * (-len(self.data) % 4)
        words = (8 + len(self.name) + len(data)) // 4 - 1
        return (
            struct.pack("!BBHI", 0x80 | self.subtype, RTCP_APP, words, self.ssrc) + self.name + data
        )

    @classmethod
    def parse(cls, packet: bytes) -> RtcpApp:
        if len(packet) < 12 or packet[1] != RTCP_APP:
            raise ProtocolError("not an RTCP APP packet")
        b0, _, words, ssrc = struct.unpack_from("!BBHI", packet, 0)
        end = 4 * (words + 1)
        if end > len(packet):
            raise ProtocolError("RTCP APP packet truncated")
        return cls(b0 & 0x1F, ssrc, packet[8:12], packet[12:end])


# ── depacketizers ────────────────────────────────────────────────────────────


@dataclass(frozen=True, slots=True)
class AccessUnit:
    """One video frame in Annex B form (start code before every NAL unit)."""

    data: bytes
    timestamp: int
    keyframe: bool


class _Depacketizer:
    """Collects NAL units per RTP timestamp; a marker bit or a new timestamp ends
    the frame. A lost fragment drops the NAL unit it belonged to."""

    def __init__(self) -> None:
        self._nals: list[bytes] = []
        self._timestamp: int | None = None
        self._fragment: bytearray | None = None
        self._next_seq: int | None = None

    def push(self, packet: RtpPacket) -> list[AccessUnit]:
        out: list[AccessUnit] = []
        if self._timestamp is not None and packet.timestamp != self._timestamp:
            out.extend(self._flush())
        if self._next_seq is not None and packet.sequence != self._next_seq:
            self._fragment = None
        self._next_seq = (packet.sequence + 1) & 0xFFFF
        self._timestamp = packet.timestamp
        self._nals.extend(self._unpack(packet.payload))
        if packet.marker:
            out.extend(self._flush())
        return out

    def _flush(self) -> list[AccessUnit]:
        nals, self._nals = self._nals, []
        ts, self._timestamp = self._timestamp, None
        self._fragment = None
        if not nals or ts is None:
            return []
        keyframe = any(self._is_key(n) for n in nals)
        return [AccessUnit(b"".join(START_CODE + n for n in nals), ts, keyframe)]

    def _fragment_part(self, start: bool, end: bool, header: bytes, data: bytes) -> list[bytes]:
        if start:
            self._fragment = bytearray(header + data)
        elif self._fragment is not None:
            self._fragment += data
        if end and self._fragment is not None:
            nal, self._fragment = bytes(self._fragment), None
            return [nal]
        return []

    @staticmethod
    def _aggregated(payload: bytes, offset: int) -> Iterable[bytes]:
        while offset + 2 <= len(payload):
            size = struct.unpack_from("!H", payload, offset)[0]
            offset += 2
            if size == 0 or offset + size > len(payload):
                return
            yield payload[offset : offset + size]
            offset += size

    def _unpack(self, payload: bytes) -> list[bytes]:
        raise NotImplementedError

    @staticmethod
    def _is_key(nal: bytes) -> bool:
        raise NotImplementedError


class H264Depacketizer(_Depacketizer):
    """RFC 6184, packetization mode 1: single NAL units, STAP-A, FU-A."""

    STAP_A: Final = 24
    FU_A: Final = 28

    def _unpack(self, payload: bytes) -> list[bytes]:
        if not payload:
            return []
        kind = payload[0] & 0x1F
        if kind == self.STAP_A:
            return list(self._aggregated(payload, 1))
        if kind == self.FU_A:
            if len(payload) < 2:
                return []
            fu = payload[1]
            header = bytes([(payload[0] & 0xE0) | (fu & 0x1F)])
            return self._fragment_part(bool(fu & 0x80), bool(fu & 0x40), header, payload[2:])
        return [payload]

    @staticmethod
    def _is_key(nal: bytes) -> bool:
        return bool(nal) and nal[0] & 0x1F == 5


class H265Depacketizer(_Depacketizer):
    """RFC 7798 without DONL: single NAL units, aggregation packets, fragmentation
    units."""

    AP: Final = 48
    FU: Final = 49

    def _unpack(self, payload: bytes) -> list[bytes]:
        if len(payload) < 2:
            return []
        kind = (payload[0] >> 1) & 0x3F
        if kind == self.AP:
            return list(self._aggregated(payload, 2))
        if kind == self.FU:
            if len(payload) < 3:
                return []
            fu = payload[2]
            header = bytes([(payload[0] & 0x81) | ((fu & 0x3F) << 1), payload[1]])
            return self._fragment_part(bool(fu & 0x80), bool(fu & 0x40), header, payload[3:])
        return [payload]

    @staticmethod
    def _is_key(nal: bytes) -> bool:
        return len(nal) >= 2 and 16 <= (nal[0] >> 1) & 0x3F <= 21
