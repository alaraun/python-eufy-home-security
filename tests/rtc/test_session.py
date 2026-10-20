"""``rtc/session.py``: the live-call sequence over a fake server and media plane."""

from __future__ import annotations

import asyncio
import base64
import json
import struct
import sys
from collections.abc import AsyncIterator, Callable
from typing import Any, ClassVar

import pytest
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from eufy_home_security.exceptions import (
    CallRefusedError,
    CommandRejectedError,
    CommunicationError,
    DeviceTimeoutError,
    ProtocolError,
    SignalingError,
    UnsupportedError,
)
from eufy_home_security.p2p.crypto import GCM_AAD
from eufy_home_security.p2p.xzyh import FrameType, encode_frame
from eufy_home_security.rtc.codec import CallBody, MessageType
from eufy_home_security.rtc.config import QuickLogin
from eufy_home_security.rtc.media import AccessUnit, CommandRoute, TurnServer
from eufy_home_security.rtc.sdp import SdpInfo
from eufy_home_security.rtc.session import (
    RtcSession,
    UnavailableMediaPlane,
    answer_sdp_info,
    default_media_factory,
)
from eufy_home_security.rtc.signaling import SignalingClient

from .fakes import CONTACT, DEVICE_INFO, SESSION_KEY, FakeCrypto, config, start_server, unseal


def status_reply(stream: int, status: int) -> bytes:
    """The station's plaintext 1350 reply: the stream id echoed, an int32 status."""
    body = struct.pack("<i", status) + bytes(128)
    return encode_frame(FrameType.CMD_TRANSFER, body, bytes([1, 0, stream, 0, 1, 0]))


def open_command(packet: bytes) -> tuple[int, dict[str, Any]]:
    """The stream id and JSON of a sealed live open (key: DEVICE_INFO's content key)."""
    tag, iv, ciphertext = packet[16:32], packet[32:44], packet[48:]
    plain = AESGCM(DEVICE_INFO.content_key.encode()).decrypt(iv, ciphertext + tag, GCM_AAD)
    return packet[12], json.loads(plain)


class FakeMedia:
    """A media plane whose station answers each live open with ``status`` (None: no
    reply) and whose video starts when ``video`` is set."""

    instances: ClassVar[list[FakeMedia]] = []
    status: ClassVar[int | None] = 0
    video: ClassVar[bool] = False

    def __init__(self) -> None:
        self.ours: SdpInfo | None = None
        self.theirs: SdpInfo | None = None
        self.turn: TurnServer | None = None
        self.candidates: list[str] = []
        self.commands: list[bytes] = []
        self.inbound: asyncio.Queue[bytes] = asyncio.Queue()
        self.closed = False
        self.fail: BaseException | None = None
        FakeMedia.instances.append(self)

    async def start(
        self,
        local: SdpInfo,
        remote: SdpInfo,
        turn: TurnServer | None,
        send_candidate: Callable[[str], None],
    ) -> None:
        self.ours, self.theirs, self.turn = local, remote, turn
        send_candidate("candidate:1 1 udp 2130706431 192.0.2.7 50000 typ host")
        if self.fail is not None:
            raise self.fail

    def add_remote_candidate(self, candidate: str) -> None:
        if candidate == "bad":
            raise ProtocolError("unreadable")
        self.candidates.append(candidate)

    async def frames(self) -> AsyncIterator[AccessUnit]:
        yield AccessUnit(b"", 0, False)

    async def send_command(self, data: bytes) -> None:
        self.commands.append(data)
        if len(self.commands) == 1 and self.status is not None:
            self.inbound.put_nowait(b"noise")
            self.inbound.put_nowait(status_reply(data[12] + 1, -1))  # another stream's
            self.inbound.put_nowait(status_reply(data[12], self.status))

    async def recv_command(self) -> bytes:
        return await self.inbound.get()

    async def wait_media(self) -> None:
        if not self.video:
            await asyncio.Event().wait()

    async def close(self) -> None:
        self.closed = True


@pytest.fixture(autouse=True)
def _fake_media_defaults() -> None:
    FakeMedia.instances.clear()
    FakeMedia.status, FakeMedia.video = 0, False


class FakeDataChannel:
    def __init__(self) -> None:
        self.sent: list[bytes] = []
        self.closed = False

    async def send(self, data: bytes) -> None:
        self.sent.append(data)

    async def recv(self) -> bytes:
        return b""

    async def close(self) -> None:
        self.closed = True


async def _session(**kwargs: Any) -> tuple[Any, RtcSession]:
    server, port = await start_server(**kwargs.pop("server", {}))
    crypto = FakeCrypto()
    cfg = config(**kwargs.pop("cfg", {}))
    session = RtcSession(cfg, crypto, signaling=SignalingClient(cfg, crypto, port=port), **kwargs)
    return server, session


async def test_start_discovers_logs_in_and_pings() -> None:
    server, session = await _session()
    try:
        record = await session.start()
        assert record.contact_id == CONTACT
        async with asyncio.timeout(5):
            while MessageType.MESSAGE not in server.kinds():
                await asyncio.sleep(0.01)
        assert server.kinds()[:3] == [MessageType.DISCOVER, MessageType.LOGIN, MessageType.LOGIN]
    finally:
        await session.close()


async def test_a_quick_login_skips_discover() -> None:
    server, session = await _session(
        cfg={"quick_login": QuickLogin(SESSION_KEY, CONTACT, "127.0.0.1", 9e12)}
    )
    try:
        await session.start()
        assert MessageType.DISCOVER not in server.kinds()
    finally:
        await session.close()


async def _infos(server: Any, count: int) -> list[dict[str, Any]]:
    async with asyncio.timeout(2):
        while server.kinds().count(MessageType.INFO) < count:
            await asyncio.sleep(0.01)
    return [
        unseal(CallBody.decode(r.body).attachment)
        for r in server.received
        if r.header.message_type == MessageType.INFO and not r.header.is_response
    ]


async def test_open_live_starts_the_media_with_both_sdp_infos_and_relays_candidates() -> None:
    FakeMedia.instances.clear()
    server, session = await _session(media_factory=FakeMedia, server={"request_id": None})
    try:
        await session.start()
        live = await session.open_live(2, timeout=2)
        media = FakeMedia.instances[-1]
        assert media.ours == live.info
        assert media.theirs == live.remote == DEVICE_INFO
        assert media.turn == TurnServer("198.51.100.9", 3478, "u", "p")
        # No SDP answer: the app's only INFO is its candidate, without a request id.
        assert await _infos(server, 1) == [
            {"candidate": "candidate:1 1 udp 2130706431 192.0.2.7 50000 typ host"}
        ]
        caller = next(r for r in server.received if r.header.message_type == MessageType.INFO).addr
        for line in ("bad", "a=candidate:9 1 UDP 1 192.0.2.8 4000 typ host"):
            server.device_packet(
                MessageType.INFO, CallBody(2, live.call.uuid, CONTACT), {"candidate": line}, caller
            )
        async with asyncio.timeout(2):
            while not media.candidates:
                await asyncio.sleep(0.01)
        assert media.candidates == ["a=candidate:9 1 UDP 1 192.0.2.8 4000 typ host"]
        assert await session.open_live(2) is live
        await session.close_live(2)
        assert media.closed
        assert live.call.ended
    finally:
        await session.close()


async def test_a_failed_media_start_closes_it_and_hangs_up() -> None:
    FakeMedia.instances.clear()

    def failing() -> FakeMedia:
        media = FakeMedia()
        if len(FakeMedia.instances) == 1:
            media.fail = DeviceTimeoutError("ice")
        return media

    server, session = await _session(media_factory=failing)
    try:
        await session.start()
        with pytest.raises(DeviceTimeoutError):
            await session.open_live(2, timeout=2)
        assert FakeMedia.instances[-1].closed
        async with asyncio.timeout(2):
            while MessageType.HANGUP not in server.kinds():
                await asyncio.sleep(0.01)
        await session.open_live(2, timeout=2)  # a failed call is not kept
        assert len(FakeMedia.instances) == 2
    finally:
        await session.close()


async def test_a_refused_call_closes_the_media_plane_and_hangs_up() -> None:
    FakeMedia.instances.clear()
    _server, session = await _session(media_factory=FakeMedia, server={"call_reply": "busy"})
    try:
        await session.start()
        with pytest.raises(CallRefusedError):
            await session.open_live(1, timeout=2)
        assert FakeMedia.instances[-1].closed
    finally:
        await session.close()


async def test_the_unavailable_media_plane_refuses_and_hangs_up() -> None:
    server, session = await _session(media_factory=UnavailableMediaPlane)
    try:
        await session.start()
        with pytest.raises(UnsupportedError):
            await session.open_live(1, timeout=2)
        async with asyncio.timeout(2):
            while MessageType.HANGUP not in server.kinds():
                await asyncio.sleep(0.01)
    finally:
        await session.close()


async def test_commands_follow_their_route() -> None:
    FakeMedia.instances.clear()
    channel = FakeDataChannel()
    _, session = await _session(media_factory=FakeMedia, data_channel=channel)
    try:
        await session.start()
        with pytest.raises(SignalingError):
            await session.send_command(2, CommandRoute.RTCP, b"open")
        await session.open_live(2, timeout=2)
        await session.send_command(2, CommandRoute.RTCP, b"open")
        await session.send_command(2, CommandRoute.DATA_CHANNEL, b"guard")
        assert FakeMedia.instances[-1].commands[1:] == [b"open"]  # after the live open
        assert channel.sent == [b"guard"]
    finally:
        await session.close()
    assert channel.closed


async def test_open_live_sends_the_sealed_live_open_with_a_stream_id_per_open() -> None:
    _, session = await _session(media_factory=FakeMedia)
    try:
        await session.start()
        first = await session.open_live(2, timeout=2)
        await session.open_live(0, timeout=2, account_id="owner")
        (stream, body), (stream2, body2) = (
            open_command(m.commands[0]) for m in FakeMedia.instances
        )
        assert (stream, stream2) == (200, 201)
        assert (body["cmd"], body["mChannel"], body["msg_id"]) == (1003, 2, 1)
        assert (body2["mChannel"], body2["msg_id"], body2["account_id"]) == (0, 2, "owner")
        assert body["account_id"] == config().user_id
        assert first.cipher is not None
    finally:
        await session.close()


async def test_an_error_status_rejects_the_open_and_hangs_up() -> None:
    FakeMedia.status = -106
    server, session = await _session(media_factory=FakeMedia)
    try:
        await session.start()
        with pytest.raises(CommandRejectedError, match="NOT_FIND_DEV") as err:
            await session.open_live(2, timeout=2)
        assert (err.value.command, err.value.code) == (FrameType.CMD_TRANSFER, -106)
        assert FakeMedia.instances[-1].closed
        async with asyncio.timeout(2):
            while MessageType.HANGUP not in server.kinds():
                await asyncio.sleep(0.01)
    finally:
        await session.close()


async def test_video_without_a_reply_completes_the_open() -> None:
    FakeMedia.status, FakeMedia.video = None, True
    _, session = await _session(media_factory=FakeMedia)
    try:
        await session.start()
        live = await session.open_live(2, timeout=2, open_timeout=2)
        assert not FakeMedia.instances[-1].closed
        assert await session.open_live(2) is live
    finally:
        await session.close()


async def test_neither_a_reply_nor_video_times_the_open_out() -> None:
    FakeMedia.status = None
    _, session = await _session(media_factory=FakeMedia)
    try:
        await session.start()
        with pytest.raises(DeviceTimeoutError):
            await session.open_live(2, timeout=2, open_timeout=0.05)
        assert FakeMedia.instances[-1].closed
    finally:
        await session.close()


async def test_a_closed_command_channel_ends_the_reply_reader() -> None:
    class Ending(FakeMedia):
        async def recv_command(self) -> bytes:
            raise CommunicationError("closed")

    FakeMedia.video = True
    _, session = await _session(media_factory=Ending)
    try:
        await session.start()
        live = await session.open_live(2, timeout=2, open_timeout=2)
        assert live._replies is not None
        async with asyncio.timeout(2):
            await live._replies
    finally:
        await session.close()


async def test_without_a_data_channel_a_data_command_is_unsupported() -> None:
    _, session = await _session()
    try:
        with pytest.raises(UnsupportedError):
            await session.send_command(0, CommandRoute.DATA_CHANNEL, b"x")
    finally:
        await session.close()


def test_the_answer_must_carry_a_readable_sdp_info() -> None:
    raw = base64.b64encode(DEVICE_INFO.encode()).decode()
    assert answer_sdp_info({"sdp_info": raw}) == DEVICE_INFO
    for answer in ({}, {"sdp_info": ""}, {"sdp_info": "!!"}, {"sdp_info": "AAAA"}):
        with pytest.raises(ProtocolError):
            answer_sdp_info(answer)


async def test_the_unavailable_media_plane_closes_quietly() -> None:
    plane = UnavailableMediaPlane()
    await plane.close()
    with pytest.raises(UnsupportedError):
        await plane.start(DEVICE_INFO, DEVICE_INFO, None, print)
    with pytest.raises(UnsupportedError):
        plane.add_remote_candidate("c")
    with pytest.raises(UnsupportedError):
        plane.frames()
    with pytest.raises(UnsupportedError):
        await plane.send_command(b"x")
    with pytest.raises(UnsupportedError):
        await plane.recv_command()
    with pytest.raises(UnsupportedError):
        await plane.wait_media()


def test_the_default_media_plane_is_the_rtc_one_with_the_extra() -> None:
    pytest.importorskip("aioice")
    from eufy_home_security.rtc.media_plane import RtcMediaPlane  # noqa: PLC0415

    assert isinstance(default_media_factory(), RtcMediaPlane)


def test_without_the_extra_the_default_media_plane_refuses(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setitem(sys.modules, "eufy_home_security.rtc.media_plane", None)
    assert isinstance(default_media_factory(), UnavailableMediaPlane)


async def test_the_session_hands_every_login_record_on() -> None:
    _, port = await start_server()
    records: list[QuickLogin] = []
    session = RtcSession(config(), FakeCrypto(), on_login=records.append)
    session.signaling._port = port
    try:
        await session.start()
        assert [r.contact_id for r in records] == [CONTACT]
    finally:
        await session.close()
