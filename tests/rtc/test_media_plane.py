"""``rtc/media_plane.py``: ICE, the SRTP context, the KCP data channel and the
assembled media plane.

Needs the ``rtc`` extra; skipped where it is not installed.
"""

from __future__ import annotations

import asyncio
import base64
import struct
from collections.abc import AsyncIterator

import pytest

pytest.importorskip("aioice")
pytest.importorskip("pylibsrtp")
pytest.importorskip("kcp")

import aioice.ice
from aioice import Candidate, Connection
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from eufy_home_security.exceptions import (
    CommunicationError,
    DeviceTimeoutError,
    ProtocolError,
)
from eufy_home_security.rtc import media_plane
from eufy_home_security.rtc.data_channel import DataMsgType
from eufy_home_security.rtc.data_channel import KcpDataChannel as DataChannelKcp
from eufy_home_security.rtc.media import (
    START_CODE,
    AccessUnit,
    IceTransport,
    PayloadType,
    RtcpApp,
    TurnServer,
)
from eufy_home_security.rtc.media_plane import (
    SDES_KEY_LEN,
    AioiceTransport,
    RtcMediaPlane,
    SdesSrtp,
)
from eufy_home_security.rtc.rtcp_channel import (
    APP_NAME,
    APP_SUBTYPE,
    AnkeType,
    decode_anke,
    encode_anke,
)
from eufy_home_security.rtc.sdp import SDES_INLINE_KEY, SdpInfo


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


# ── ICE over aioice ──────────────────────────────────────────────────────────


@pytest.fixture(autouse=True)
def _loopback_only(monkeypatch: pytest.MonkeyPatch) -> None:
    """aioice gathers on the loopback only: tests reach no other address."""
    monkeypatch.setattr(aioice.ice, "get_host_addresses", lambda **_: ["127.0.0.1"])


async def test_aioice_transport_connects_controlled_with_dictated_credentials() -> None:
    ours = AioiceTransport()
    device = Connection(ice_controlling=True, components=1, use_ipv6=False)
    try:
        await device.gather_candidates()
        # A device candidate that arrives before gathering is kept; TCP ones are skipped.
        for c in device.local_candidates:
            ours.add_remote_candidate(f"a=candidate:{c.to_sdp()}")
        ours.add_remote_candidate("candidate:9 1 TCP 1 192.0.2.9 9 typ host tcptype active")
        lines = await ours.gather(local_ufrag="abcde", local_pwd="p" * 23, turn=None)
        assert lines
        assert all(line.startswith("candidate:") for line in lines)
        device.remote_username, device.remote_password = "abcde", "p" * 23
        for line in lines:
            await device.add_remote_candidate(Candidate.from_sdp(line[len("candidate:") :]))
        await device.add_remote_candidate(None)
        async with asyncio.timeout(10):
            await asyncio.gather(
                ours.connect(remote_ufrag=device.local_username, remote_pwd=device.local_password),
                device.connect(),
            )
        await device.send(b"rtp")
        assert await asyncio.wait_for(ours.recv(), 5) == b"rtp"
        await ours.send(b"rtcp")
        assert await asyncio.wait_for(device.recv(), 5) == b"rtcp"
    finally:
        await ours.close()
        await device.close()


async def test_data_channel_kcp_round_trips_over_real_aioice() -> None:
    """The command data channel (data_channel.KcpDataChannel = _ikcp + WrtcLinkProtocol
    framing + kcp_type-2 prefix) over a real aioice-connected UDP path, not an in-memory
    pipe: a controlled client against a controlling device, a command and a reply."""
    ours = AioiceTransport()
    device = Connection(ice_controlling=True, components=1, use_ipv6=False)
    client_kcp: DataChannelKcp | None = None
    device_kcp: DataChannelKcp | None = None
    try:
        await device.gather_candidates()
        for c in device.local_candidates:
            ours.add_remote_candidate(f"a=candidate:{c.to_sdp()}")
        lines = await ours.gather(local_ufrag="abcde", local_pwd="p" * 23, turn=None)
        device.remote_username, device.remote_password = "abcde", "p" * 23
        for line in lines:
            await device.add_remote_candidate(Candidate.from_sdp(line[len("candidate:") :]))
        await device.add_remote_candidate(None)
        async with asyncio.timeout(10):
            await asyncio.gather(
                ours.connect(remote_ufrag=device.local_username, remote_pwd=device.local_password),
                device.connect(),
            )
        client_kcp = DataChannelKcp(ours, conv=1)
        device_kcp = DataChannelKcp(device, conv=1)
        await client_kcp.send_message(b'{"cmd":1307}', msg_type=DataMsgType.COMMAND)
        got = await asyncio.wait_for(device_kcp.recv_message(), 5)
        assert (got.msg_type, got.payload) == (DataMsgType.COMMAND, b'{"cmd":1307}')
        await device_kcp.send_message(b"reply-body", msg_type=DataMsgType.COMMAND)
        back = await asyncio.wait_for(client_kcp.recv_message(), 5)
        assert back.payload == b"reply-body"
    finally:
        if client_kcp is not None:
            await client_kcp.close()  # closes `ours`
        else:
            await ours.close()
        if device_kcp is not None:
            await device_kcp.close()  # closes `device`
        else:
            await device.close()


async def test_aioice_transport_refuses_before_gathering_and_bad_candidates() -> None:
    ice = AioiceTransport()
    assert isinstance(ice, IceTransport)
    with pytest.raises(ProtocolError):
        ice.add_remote_candidate("a=candidate:1 1 UDP")
    with pytest.raises(CommunicationError):
        await ice.recv()
    with pytest.raises(CommunicationError):
        await ice.connect(remote_ufrag="u", remote_pwd="p")
    await ice.close()


async def test_aioice_transport_reports_a_failed_connection() -> None:
    ice = AioiceTransport()
    try:
        await ice.gather(local_ufrag="abcde", local_pwd="p" * 23, turn=None)
        conn = ice._require()
        await conn.add_remote_candidate(None)  # no remote candidate at all
        with pytest.raises(CommunicationError, match="did not connect"):
            await ice.connect(remote_ufrag="dev01", remote_pwd="q" * 23)
    finally:
        await ice.close()
    with pytest.raises(CommunicationError):
        await ice.recv()
    with pytest.raises(CommunicationError):
        await ice.send(b"x")


async def test_aioice_transport_hands_the_turn_relay_to_aioice(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: dict[str, object] = {}

    class Recorder(Connection):
        def __init__(self, **kwargs: object) -> None:
            seen.update(kwargs)
            super().__init__(**{**kwargs, "turn_server": None})  # type: ignore[arg-type]

    monkeypatch.setattr(media_plane, "Connection", Recorder)
    ice = AioiceTransport()
    try:
        await ice.gather(
            local_ufrag="abcde",
            local_pwd="p" * 23,
            turn=TurnServer("198.51.100.9", 3478, "u", "pw"),
        )
    finally:
        await ice.close()
    assert seen["ice_controlling"] is False
    assert seen["components"] == 1
    assert seen["turn_server"] == ("198.51.100.9", 3478)
    assert (seen["turn_username"], seen["turn_password"]) == ("u", "pw")
    assert (seen["local_username"], seen["local_password"]) == ("abcde", "p" * 23)


# ── the assembled media plane ────────────────────────────────────────────────

LOCAL = SdpInfo(
    audio_ssrc=1,
    video_ssrc=2,
    ice_ufrag="appuf",
    ice_pwd="a" * 23,
    content_key="A" * 16,
    content_iv="B" * 12,
)
REMOTE = SdpInfo(
    audio_ssrc=3,
    video_ssrc=4,
    ice_ufrag="devuf",
    ice_pwd="d" * 23,
    content_key="0123456789abcdef",
    content_iv="nonce-12char",
)


class FakeIce:
    """An IceTransport whose inbound packets the test feeds."""

    def __init__(self, *, hang: bool = False) -> None:
        self.inbound: asyncio.Queue[bytes | None] = asyncio.Queue()
        self.gathered: dict[str, object] = {}
        self.connected: dict[str, str] = {}
        self.remote: list[str] = []
        self.sent: list[bytes] = []
        self.closed = False
        self._hang = hang

    async def gather(
        self, *, local_ufrag: str, local_pwd: str, turn: TurnServer | None
    ) -> list[str]:
        self.gathered = {"ufrag": local_ufrag, "pwd": local_pwd, "turn": turn}
        return [
            "candidate:1 1 udp 1 192.0.2.1 1000 typ host",
            "candidate:2 1 udp 1 192.0.2.2 1000 typ relay",
        ]

    def add_remote_candidate(self, candidate: str) -> None:
        self.remote.append(candidate)

    async def connect(self, *, remote_ufrag: str, remote_pwd: str) -> None:
        self.connected = {"ufrag": remote_ufrag, "pwd": remote_pwd}
        if self._hang:
            await asyncio.Event().wait()

    async def recv(self) -> bytes:
        data = await self.inbound.get()
        if data is None:
            raise CommunicationError("closed")
        return data

    async def send(self, data: bytes) -> None:
        self.sent.append(data)

    async def close(self) -> None:
        self.closed = True


def _srtp_rtp(
    payload: bytes, *, seq: int, pt: int = PayloadType.H265, marker: bool = True
) -> bytes:
    header = struct.pack("!BBHII", 0x80, (0x80 if marker else 0) | pt, seq, 9000 + seq, 0xB8A23CFA)
    return SdesSrtp.from_inline()._outbound.protect(header + payload)


def _hevc(nal_type: int, body: bytes) -> bytes:
    return bytes([(nal_type << 1) & 0x7E, 0x01]) + body


def _encrypted(nal_type: int, body: bytes, key: str = REMOTE.content_key) -> bytes:
    sealed = AESGCM(key.encode()).encrypt(REMOTE.content_iv.encode(), body, None)
    return _hevc(nal_type, sealed)


async def _started(
    ice: FakeIce, connect_timeout: float = media_plane.ICE_TIMEOUT
) -> tuple[RtcMediaPlane, list[str]]:
    sent: list[str] = []
    plane = RtcMediaPlane(ice, connect_timeout=connect_timeout)
    await plane.start(LOCAL, REMOTE, TurnServer("198.51.100.9", 3478, "u", "p"), sent.append)
    return plane, sent


async def _take(frames: AsyncIterator[AccessUnit], count: int) -> list[AccessUnit]:
    out: list[AccessUnit] = []
    async with asyncio.timeout(2):
        async for frame in frames:
            out.append(frame)
            if len(out) == count:
                break
    return out


async def test_start_sends_local_candidates_and_connects_with_the_answer_credentials() -> None:
    ice = FakeIce()
    plane, sent = await _started(ice)
    try:
        assert ice.gathered == {
            "ufrag": "appuf",
            "pwd": "a" * 23,
            "turn": TurnServer("198.51.100.9", 3478, "u", "p"),
        }
        assert sent == [
            "candidate:1 1 udp 1 192.0.2.1 1000 typ host",
            "candidate:2 1 udp 1 192.0.2.2 1000 typ relay",
        ]
        assert ice.connected == {"ufrag": "devuf", "pwd": "d" * 23}
        plane.add_remote_candidate("a=candidate:9")
        assert ice.remote == ["a=candidate:9"]
    finally:
        await plane.close()
    assert ice.closed


async def test_an_ice_timeout_is_a_device_timeout() -> None:
    with pytest.raises(DeviceTimeoutError):
        await _started(FakeIce(hang=True), connect_timeout=0.05)


async def test_srtp_h265_is_depacketized_and_decrypted_others_are_dropped() -> None:
    ice = FakeIce()
    plane, _ = await _started(ice)
    try:
        idr = b"IDR-slice" * 8
        vps = _hevc(32, b"VPS-clear")
        ice.inbound.put_nowait(_srtp_rtp(b"audio", seq=1, pt=PayloadType.AUDIO))
        ice.inbound.put_nowait(struct.pack("!BBHI", 0x80, 201, 1, 1))  # RTCP RR
        ice.inbound.put_nowait(b"\x80\x61not-srtp-at-all")
        # An AP with the clear VPS and the encrypted IDR: one keyframe.
        ap = bytes([48 << 1, 1])
        for nal in (vps, _encrypted(19, idr)):
            ap += struct.pack("!H", len(nal)) + nal
        ice.inbound.put_nowait(_srtp_rtp(ap, seq=2))
        # A key frame under another key fails its tag and is dropped; the stream goes on.
        ice.inbound.put_nowait(_srtp_rtp(_encrypted(19, idr, key="f" * 16), seq=3))
        ice.inbound.put_nowait(_srtp_rtp(_hevc(1, b"P-slice"), seq=4))
        frames = await _take(plane.frames(), 2)
        assert frames[0].keyframe
        assert frames[0].data == START_CODE + vps + START_CODE + _hevc(19, idr)
        assert not frames[1].keyframe
        assert frames[1].data == START_CODE + _hevc(1, b"P-slice")
        assert plane.stats() == {
            "rtcp": 1,
            "srtp_failures": 1,
            "frames": 2,
            "keyframes": 1,
            "frame_failures": 1,
            "rtp_by_payload_type": {PayloadType.AUDIO: 1, PayloadType.H265: 3},
            "first_nal_types": [32, 1],
        }
    finally:
        await plane.close()


async def test_frames_end_when_the_connection_closes() -> None:
    ice = FakeIce()
    plane, _ = await _started(ice)
    ice.inbound.put_nowait(_srtp_rtp(_hevc(1, b"P"), seq=1))
    ice.inbound.put_nowait(None)
    async with asyncio.timeout(2):
        frames = [f async for f in plane.frames()]
    assert [f.data for f in frames] == [START_CODE + _hevc(1, b"P")]
    await plane.close()


async def test_a_full_frame_queue_drops_the_oldest(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(media_plane, "FRAME_QUEUE", 2)
    ice = FakeIce()
    plane, _ = await _started(ice)
    for seq in range(1, 4):
        ice.inbound.put_nowait(_srtp_rtp(_hevc(1, bytes([seq])), seq=seq))
    ice.inbound.put_nowait(None)
    async with asyncio.timeout(2):
        frames = [f async for f in plane.frames()]
    assert [f.data[-1] for f in frames] == [2, 3]
    await plane.close()


def _anke_app(frame: bytes) -> bytes:
    """Wrap an ANKE frame in an RTCP APP packet as the device sends it."""
    return RtcpApp(APP_SUBTYPE, 0xB8A23CFA, APP_NAME, frame).encode()


async def test_an_rtcp_app_with_a_different_name_is_dropped() -> None:
    # The command channel is name "AZWC" subtype 0; the "ANKE"/subtype-30
    # keepalive and any other RTCP APP name are not this channel and are dropped.
    ice = FakeIce()
    plane, _ = await _started(ice)
    try:
        other = RtcpApp(30, 0xB8A23CFA, b"ANKE", encode_anke(AnkeType.DATA, 0, b"x"))
        ice.inbound.put_nowait(other.encode())
        ice.inbound.put_nowait(_anke_app(encode_anke(AnkeType.DATA, 0, b"ok")))
        assert plane._channel is not None
        assert await asyncio.wait_for(plane._channel.recv_data(), 2) == b"ok"
    finally:
        await plane.close()


async def test_commands_before_start_are_refused() -> None:
    plane = RtcMediaPlane(FakeIce())
    with pytest.raises(CommunicationError):
        await plane.send_command(b"x")
    with pytest.raises(CommunicationError):
        await plane.recv_command()
    await plane.close()


async def test_wait_media_returns_on_the_first_frame() -> None:
    ice = FakeIce()
    plane, _ = await _started(ice)
    try:
        waiting = asyncio.ensure_future(plane.wait_media())
        await asyncio.sleep(0.01)
        assert not waiting.done()
        ice.inbound.put_nowait(_srtp_rtp(_hevc(1, b"P"), seq=1))
        await asyncio.wait_for(waiting, 2)
    finally:
        await plane.close()


async def test_send_command_sends_an_anke_data_packet_over_rtcp() -> None:
    ice = FakeIce()
    plane, _ = await _started(ice)
    try:
        await plane.send_command(b'{"cmd":1003}')
    finally:
        await plane.close()
    apps = [RtcpApp.parse(p) for p in ice.sent if p[1] == 204]
    anke = [a for a in apps if a.name == APP_NAME and a.subtype == APP_SUBTYPE]
    assert anke, "no ANKE packet went out"
    assert anke[0].ssrc == LOCAL.audio_ssrc
    frame = decode_anke(anke[0].data)
    assert frame.type == AnkeType.DATA
    assert frame.body == b'{"cmd":1003}'


async def test_an_inbound_anke_data_packet_is_acked_and_delivered() -> None:
    ice = FakeIce()
    plane, _ = await _started(ice)
    try:
        ice.inbound.put_nowait(_anke_app(encode_anke(AnkeType.DATA, 42, b"reply")))
        assert await asyncio.wait_for(plane.recv_command(), 2) == b"reply"
        await asyncio.sleep(0)  # let the ACK task run
        acks = [
            decode_anke(RtcpApp.parse(p).data)
            for p in ice.sent
            if p[1] == 204 and RtcpApp.parse(p).name == APP_NAME
        ]
        assert any(a.type == AnkeType.ACK and a.seq == 42 for a in acks)
    finally:
        await plane.close()


async def test_a_non_anke_rtcp_packet_is_dropped() -> None:
    ice = FakeIce()
    plane, _ = await _started(ice)
    try:
        ice.inbound.put_nowait(struct.pack("!BBHI", 0x80, 201, 1, 1))  # a receiver report
        ice.inbound.put_nowait(_anke_app(encode_anke(AnkeType.DATA, 1, b"ok")))
        assert plane._channel is not None
        assert await asyncio.wait_for(plane._channel.recv_data(), 2) == b"ok"
    finally:
        await plane.close()
