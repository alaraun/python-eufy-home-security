"""``rtc/session.py``: the live-call sequence over a fake server and media plane."""

from __future__ import annotations

import asyncio
import base64
import sys
from collections.abc import AsyncIterator, Callable
from typing import Any, ClassVar

import pytest

from eufy_home_security.exceptions import (
    CallRefusedError,
    DeviceTimeoutError,
    ProtocolError,
    SignalingError,
    UnsupportedError,
)
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


class FakeMedia:
    instances: ClassVar[list[FakeMedia]] = []

    def __init__(self) -> None:
        self.ours: SdpInfo | None = None
        self.theirs: SdpInfo | None = None
        self.turn: TurnServer | None = None
        self.candidates: list[str] = []
        self.commands: list[bytes] = []
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

    async def close(self) -> None:
        self.closed = True


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
        assert FakeMedia.instances[-1].commands == [b"open"]
        assert channel.sent == [b"guard"]
    finally:
        await session.close()
    assert channel.closed


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
