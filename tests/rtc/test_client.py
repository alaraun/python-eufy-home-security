"""The WebRTC signaling client against the loopback fake server."""

from __future__ import annotations

import asyncio
import base64
import json
import socket
from collections.abc import AsyncIterator, Callable
from typing import Any

import pytest

from eufy_home_security.exceptions import (
    CallRefusedError,
    DeviceTimeoutError,
    ProtocolError,
    SignalingError,
)
from eufy_home_security.rtc import client as client_mod
from eufy_home_security.rtc import codec
from eufy_home_security.rtc.client import MAX_CALL_EVENTS, Call, CallEvent, SignalingClient
from eufy_home_security.rtc.codec import CallKind, Header, MessageBody, MessageType
from eufy_home_security.rtc.config import QuickLogin, ServerInfo
from eufy_home_security.rtc.sdp import SdpInfo
from eufy_home_security.rtc.signaling import CallEventKind
from eufy_home_security.testing.rtc import (
    CONTACT,
    DEVICE_CANDIDATE,
    TURN,
    FakeRtcServer,
    rtc_config,
)

INFO = SdpInfo.generate("m" * 16, "n" * 12, data_channel=True)


@pytest.fixture
async def fake() -> AsyncIterator[FakeRtcServer]:
    server = await FakeRtcServer().start()
    yield server
    await server.close()
    assert server.refused == []


@pytest.fixture
async def make_client(
    fake: FakeRtcServer,
) -> AsyncIterator[Callable[..., SignalingClient]]:
    made: list[SignalingClient] = []

    def make(**kwargs: Any) -> SignalingClient:
        config = kwargs.pop("config", rtc_config())
        client = SignalingClient(config, port=fake.port, tcp_ports=(fake.tcp_port,), **kwargs)
        made.append(client)
        return client

    yield make
    for client in made:
        await client.close()


async def until(check: Callable[[], object], timeout: float = 3.0) -> None:
    async with asyncio.timeout(timeout):
        while not check():
            await asyncio.sleep(0.01)


async def logged_in(make_client: Callable[..., SignalingClient], **kwargs: Any) -> SignalingClient:
    client = make_client(**kwargs)
    await client.open()
    await client.discover()
    await client.login()
    return client


# ── DISCOVER and LOGIN ───────────────────────────────────────────────────────


async def test_a_full_login_runs_the_key_exchange_and_reports_its_record(
    fake: FakeRtcServer, make_client: Callable[..., SignalingClient]
) -> None:
    records: list[QuickLogin] = []
    servers: list[ServerInfo] = []
    client = make_client(
        config=rtc_config(signaling_domain="signal.example.com"),
        on_login=records.append,
        on_server_info=servers.append,
    )
    await client.open()
    assert await client.discover() == "127.0.0.1"
    record = await client.login()
    assert client.logged_in
    assert client.contact_id == CONTACT
    assert records == [record]
    assert client.quick_login() == record
    assert record.session_key == fake.sessions[CONTACT]
    logins = fake.of_type(MessageType.LOGIN)
    assert [r.header.body_type for r in logins] == [
        codec.BodyType.NONE,
        codec.BodyType.KEY_EXCHANGE,
    ]
    [server] = servers
    assert (server.ip, server.port, server.domain) == ("127.0.0.1", fake.port, "signal.example.com")
    assert server.last_used_timestamp > 0
    assert server.last_fail_timestamp == 0


async def test_a_quick_login_takes_one_request(
    fake: FakeRtcServer, make_client: Callable[..., SignalingClient]
) -> None:
    first = await logged_in(make_client)
    record = first.quick_login()
    await first.close()
    fake.received.clear()
    second = make_client(config=rtc_config(quick_login=record))
    await second.open()
    assert (await second.login()).session_key == record.session_key  # type: ignore[union-attr]
    logins = fake.of_type(MessageType.LOGIN)
    assert [r.header.body_type for r in logins] == [codec.BodyType.CONTACT]


async def test_a_quick_login_seals_its_identity_with_the_packet_id(
    fake: FakeRtcServer, make_client: Callable[..., SignalingClient]
) -> None:
    """A clock that moves between the seal and the header must not split them."""
    first = await logged_in(make_client)
    record = first.quick_login()
    await first.close()
    fake.received.clear()
    ticks = iter(range(1_000_000, 2_000_000))
    second = make_client(config=rtc_config(quick_login=record), clock=lambda: float(next(ticks)))
    await second.open()
    await second.login()
    logins = fake.of_type(MessageType.LOGIN)
    assert [r.header.body_type for r in logins] == [codec.BodyType.CONTACT]


async def test_a_refused_quick_login_falls_back_to_the_key_exchange(
    fake: FakeRtcServer, make_client: Callable[..., SignalingClient]
) -> None:
    unknown = QuickLogin("q" * 16, "d" * 32, "127.0.0.1", 900.0)
    client = make_client(clock=lambda: 1000.0)
    await client.open()
    record = await client.login(unknown)
    assert record.session_key != unknown.session_key
    kinds = [r.header.body_type for r in fake.of_type(MessageType.LOGIN)]
    assert kinds == [codec.BodyType.CONTACT, codec.BodyType.KEY_EXCHANGE]


async def test_a_stale_record_is_not_used(
    fake: FakeRtcServer, make_client: Callable[..., SignalingClient]
) -> None:
    client = make_client(clock=lambda: 1_000_000.0)
    await client.open()
    await client.login(QuickLogin("q" * 16, "d" * 32, "127.0.0.1", 0.0))
    kinds = [r.header.body_type for r in fake.of_type(MessageType.LOGIN)]
    assert kinds == [codec.BodyType.NONE, codec.BodyType.KEY_EXCHANGE]


async def test_a_refused_login_raises_with_its_code_and_reports_the_failure(
    fake: FakeRtcServer, make_client: Callable[..., SignalingClient]
) -> None:
    fake.refuse_login = True
    servers: list[ServerInfo] = []
    client = make_client(on_server_info=servers.append)
    await client.open()
    with pytest.raises(SignalingError) as caught:
        await client.login()
    assert caught.value.code == 401
    assert not client.logged_in
    [server] = servers
    assert server.last_fail_timestamp > 0
    assert server.last_used_timestamp == 0


async def test_an_unanswered_login_is_sent_again(
    fake: FakeRtcServer,
    make_client: Callable[..., SignalingClient],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(client_mod, "login_retry_delays", lambda _rng: [0.2] * 4)
    fake.drop_logins = 1
    client = make_client()
    await client.open()
    await client.login()
    assert len(fake.of_type(MessageType.LOGIN)) == 3


async def test_a_login_never_answered_times_out(
    fake: FakeRtcServer,
    make_client: Callable[..., SignalingClient],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(client_mod, "login_retry_delays", lambda _rng: [0.05] * 4)
    fake.drop_logins = 99
    servers: list[ServerInfo] = []
    client = make_client(on_server_info=servers.append)
    await client.open()
    with pytest.raises(DeviceTimeoutError):
        await client.login()
    assert len(fake.of_type(MessageType.LOGIN)) == 4
    assert servers[0].last_fail_timestamp > 0


async def test_discover_refuses_a_server_named_by_host_name(
    fake: FakeRtcServer, make_client: Callable[..., SignalingClient]
) -> None:
    fake.server_addr = "signal.example.com"
    client = make_client()
    await client.open()
    with pytest.raises(ProtocolError):
        await client.discover()


async def test_discover_moves_to_the_named_server(
    fake: FakeRtcServer, make_client: Callable[..., SignalingClient]
) -> None:
    fake.server_addr = "127.0.0.2"
    client = make_client()
    await client.open()
    assert await client.discover() == "127.0.0.2"
    assert client.server == "127.0.0.2"


async def test_an_unanswered_discover_times_out_after_its_attempts(
    fake: FakeRtcServer,
    make_client: Callable[..., SignalingClient],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(client_mod, "DISCOVER_TIMEOUT", 0.05)
    fake.drop_discovers = 99
    client = make_client()
    await client.open()
    with pytest.raises(DeviceTimeoutError):
        await client.discover()
    assert len(fake.of_type(MessageType.DISCOVER)) == client_mod.DISCOVER_ATTEMPTS == 3


async def test_a_discover_answered_on_its_last_attempt_succeeds(
    fake: FakeRtcServer,
    make_client: Callable[..., SignalingClient],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(client_mod, "DISCOVER_TIMEOUT", 0.05)
    fake.drop_discovers = 2
    client = make_client()
    await client.open()
    assert await client.discover() == "127.0.0.1"


def test_a_host_name_as_signaling_host_is_refused() -> None:
    with pytest.raises(ProtocolError):
        SignalingClient(rtc_config(host="signal.example.com"))


# ── ping and messages ────────────────────────────────────────────────────────


async def test_the_ping_carries_the_contact_and_the_fixed_dynamic_id(
    fake: FakeRtcServer, make_client: Callable[..., SignalingClient]
) -> None:
    client = await logged_in(make_client)
    client.start_ping(0.05)
    await until(lambda: len(fake.of_type(MessageType.MESSAGE)) >= 2)
    payloads = [r.payload for r in fake.of_type(MessageType.MESSAGE)]
    assert {p["eufy_client_dynamic_id"] for p in payloads if p} == {client.dynamic_id}
    content = json.loads(base64.b64decode(payloads[0]["content"]))  # type: ignore[index]
    assert content["eufy_contact_id"] == CONTACT


def test_the_ping_interval_is_two_seconds() -> None:
    assert client_mod.PING_INTERVAL == 2.0


async def test_a_device_message_is_answered_with_the_clients_own_dynamic_id(
    fake: FakeRtcServer, make_client: Callable[..., SignalingClient]
) -> None:
    client = await logged_in(make_client)
    addr = fake.of_type(MessageType.LOGIN)[-1].addr
    fake.device_message(addr)
    fake.device_message(addr)
    await until(lambda: len(_responses(fake, MessageType.MESSAGE)) == 2)
    ids = [r.payload["eufy_client_dynamic_id"] for r in _responses(fake, MessageType.MESSAGE)]
    assert ids == [client.dynamic_id, client.dynamic_id]


async def test_a_device_message_on_a_call_socket_is_answered_there(
    fake: FakeRtcServer, make_client: Callable[..., SignalingClient]
) -> None:
    client = await logged_in(make_client)
    call = await client.call(CallKind.PRIV1, sdp_info=INFO, wake=False)
    await call.wait_answer(3)
    addr = fake.of_type(MessageType.CALL)[-1].addr
    assert addr != fake.of_type(MessageType.LOGIN)[-1].addr
    fake.device_message(addr)
    await until(lambda: _responses(fake, MessageType.MESSAGE) or fake.refused)
    assert fake.refused == []
    assert _responses(fake, MessageType.MESSAGE)[0].addr == addr


async def test_a_datagram_from_another_address_is_dropped(
    fake: FakeRtcServer, make_client: Callable[..., SignalingClient]
) -> None:
    client = await logged_in(make_client)
    addr = fake.of_type(MessageType.LOGIN)[-1].addr
    header = Header(
        message_type=MessageType.MESSAGE,
        packet_id=5,
        serial="T8030P2000012345",
        encrypted=False,
        body_type=codec.BodyType.MESSAGE,
    )
    packet = codec.obfuscate(codec.encode_packet(header, MessageBody(0, 2, 0x66, CONTACT).encode()))
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as other:
        other.bind(("127.0.0.2", 0))
        other.sendto(packet, addr)
        await asyncio.sleep(0.1)
    assert _responses(fake, MessageType.MESSAGE) == []
    fake.send(header, MessageBody(0, 2, 0x66, CONTACT).encode(), addr)  # the server's own
    await until(lambda: len(_responses(fake, MessageType.MESSAGE)) == 1)
    assert client.logged_in


async def test_the_rediscover_flag_runs_discover_and_a_quick_login(
    fake: FakeRtcServer, make_client: Callable[..., SignalingClient]
) -> None:
    await logged_in(make_client)
    addr = fake.of_type(MessageType.LOGIN)[-1].addr
    fake.received.clear()
    fake.device_message(addr, flags=codec.FLAG_REDISCOVER)
    await until(lambda: len(fake.of_type(MessageType.LOGIN)) == 1)
    assert MessageType.DISCOVER in fake.kinds()
    assert fake.of_type(MessageType.LOGIN)[0].header.body_type == codec.BodyType.CONTACT


def _responses(fake: FakeRtcServer, mtype: int) -> list[Any]:
    return [r for r in fake.of_type(mtype) if r.header.is_response]


# ── calls ────────────────────────────────────────────────────────────────────


async def test_a_private_call_gets_trying_then_the_answer_and_acks_every_200(
    fake: FakeRtcServer, make_client: Callable[..., SignalingClient]
) -> None:
    fake.answer_repeats = 3
    fake.request_id = "r1"
    client = await logged_in(make_client)
    call = await client.call(CallKind.PRIV1, sdp_info=INFO, wake=False)
    answer = await call.wait_answer(3)
    assert answer["eufy_p2p_type"] == "priv1"
    assert call.turn == TURN
    assert call.device_request_id == "r1"
    await until(lambda: len(fake.of_type(MessageType.ACK)) == 3)
    sent = fake.of_type(MessageType.CALL)[0]
    assert sent.payload["eufy_p2p_type"] == "priv1"  # type: ignore[index]
    assert fake.call_info == INFO
    assert len(call.uuid) == codec.UUID_LEN
    # the private call travels on its own socket
    assert sent.addr != fake.of_type(MessageType.LOGIN)[-1].addr
    client.send_info(call, {"file_candidate_ack": 0})
    await until(lambda: 0 in fake.device_acks)
    info = [r for r in fake.of_type(MessageType.INFO) if not r.header.is_response][-1]
    assert info.payload == {"request_id": "r1", "file_candidate_ack": 0}
    assert info.addr == sent.addr


async def test_a_private_info_is_answered_by_echoing_its_attachment(
    fake: FakeRtcServer, make_client: Callable[..., SignalingClient]
) -> None:
    client = await logged_in(make_client)
    call = await client.call(CallKind.PRIV1, sdp_info=INFO, wake=False)
    await call.wait_answer(3)
    await until(lambda: _responses(fake, MessageType.INFO))
    echo = _responses(fake, MessageType.INFO)[0]
    assert echo.payload == {"file_candidate": DEVICE_CANDIDATE, "file_candidate_num": 0}


@pytest.mark.parametrize(("script", "code"), [("busy", 486), ("hangup", None)])
async def test_a_refused_or_hung_up_call_raises(
    fake: FakeRtcServer, make_client: Callable[..., SignalingClient], script: str, code: int | None
) -> None:
    fake.call_reply = script
    client = await logged_in(make_client)
    call = await client.call(CallKind.PRIV1, sdp_info=INFO, wake=False)
    with pytest.raises(CallRefusedError) as caught:
        await call.wait_answer(3)
    assert caught.value.code == code
    assert call.ended


async def test_an_unanswered_call_times_out(
    fake: FakeRtcServer, make_client: Callable[..., SignalingClient]
) -> None:
    fake.call_reply = "silent"
    client = await logged_in(make_client)
    call = await client.call(CallKind.PRIV1, sdp_info=INFO, wake=False)
    with pytest.raises(DeviceTimeoutError):
        await call.wait_answer(0.1)


async def test_a_call_unanswered_over_udp_is_sent_again_over_tcp(
    fake: FakeRtcServer,
    make_client: Callable[..., SignalingClient],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(client_mod, "CALL_REPLY_TIMEOUT", 0.1)
    fake.udp_calls = False
    client = await logged_in(make_client)
    call = await client.call(CallKind.PRIV1, sdp_info=INFO)
    await call.wait_answer(3)
    assert [r.via for r in fake.of_type(MessageType.CALL)] == ["udp", "tcp"]


async def test_an_answered_call_is_not_sent_over_tcp(
    fake: FakeRtcServer,
    make_client: Callable[..., SignalingClient],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(client_mod, "CALL_REPLY_TIMEOUT", 0.1)
    client = await logged_in(make_client)
    call = await client.call(CallKind.PRIV1, sdp_info=INFO)
    await call.wait_answer(3)
    await asyncio.sleep(0.3)
    assert [r.via for r in fake.of_type(MessageType.CALL)] == ["udp"]


async def test_a_call_before_login_is_refused(make_client: Callable[..., SignalingClient]) -> None:
    client = make_client()
    await client.open()
    with pytest.raises(SignalingError):
        await client.call(CallKind.PRIV1, sdp_info=INFO)


async def test_a_second_calls_info_and_hangup_carry_their_sub_ids(
    fake: FakeRtcServer, make_client: Callable[..., SignalingClient]
) -> None:
    """An INFO always carries sub_id 1, a HANGUP its CALL's."""
    client = await logged_in(make_client)
    first = await client.call(CallKind.PRIV1, sdp_info=INFO, wake=False)
    second = await client.call(CallKind.PRIV1, sdp_info=INFO, wake=False)
    await second.wait_answer(3)
    assert (first.sub_id, second.sub_id) == (1, 2)
    client.send_info(second, {"file_candidate_ack": 7})
    client.hangup(second)
    await until(
        lambda: (fake.of_type(MessageType.HANGUP) and 7 in fake.device_acks) or fake.refused
    )
    assert fake.refused == []
    assert fake.of_type(MessageType.HANGUP)[0].header.sub_id == 2


async def test_hangup_is_sent_once(
    fake: FakeRtcServer, make_client: Callable[..., SignalingClient]
) -> None:
    client = await logged_in(make_client)
    call = await client.call(CallKind.PRIV1, sdp_info=INFO, wake=False)
    await call.wait_answer(3)
    client.hangup(call)
    client.hangup(call)
    await client.close()
    await until(lambda: len(fake.of_type(MessageType.HANGUP)) == 1)
    await asyncio.sleep(0.05)
    assert len(fake.of_type(MessageType.HANGUP)) == 1


def test_a_full_event_queue_drops_its_oldest_event() -> None:
    call = Call(CallKind.PRIV1, 0, "", 1, 1, True)
    header = Header(message_type=MessageType.INFO, packet_id=1, serial="")
    for n in range(MAX_CALL_EVENTS + 1):
        call.push(CallEvent(CallEventKind.INFO, header, {"n": n}))
    assert call.dropped == 1
    assert call.events.get_nowait().payload == {"n": 1}


# ── lifecycle ────────────────────────────────────────────────────────────────


async def test_a_socket_error_is_reported_once(make_client: Callable[..., SignalingClient]) -> None:
    lost: list[Exception] = []
    client = make_client(on_lost=lost.append)
    await client.open()
    endpoint = client._main
    assert endpoint is not None
    endpoint.error_received(ConnectionRefusedError())
    endpoint.error_received(ConnectionRefusedError())
    assert len(lost) == 1


async def test_close_fails_a_pending_request_and_is_final(
    fake: FakeRtcServer,
    make_client: Callable[..., SignalingClient],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    fake.drop_logins = 99
    lost: list[Exception] = []
    client = make_client(on_lost=lost.append)
    await client.open()
    login = asyncio.ensure_future(client.login())
    await until(lambda: fake.of_type(MessageType.LOGIN))
    await client.close()
    with pytest.raises(SignalingError):
        await login
    await client.close()
    assert lost == []
    with pytest.raises(SignalingError):
        await client.open()
