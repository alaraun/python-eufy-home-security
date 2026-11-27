"""The WebRTC session to ICE up, against the loopback fake station."""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import gc
import importlib.util
import logging
from collections.abc import AsyncIterator, Callable
from typing import Any

import pytest

from eufy_home_security.exceptions import (
    CallRefusedError,
    CommunicationError,
    DeviceTimeoutError,
    MissingDependencyError,
    ProtocolError,
    SignalingError,
    UnsupportedError,
)
from eufy_home_security.rtc import _ikcp
from eufy_home_security.rtc import session as session_mod
from eufy_home_security.rtc.codec import MessageType
from eufy_home_security.rtc.config import KCP_TYPE_MULTI, KCP_TYPE_SINGLE, QuickLogin, ServerInfo
from eufy_home_security.rtc.data_channel import DataMsgType
from eufy_home_security.rtc.ice import require_aioice
from eufy_home_security.rtc.session import (
    CallAnswer,
    DataTransport,
    RtcSession,
    candidate_resend_delay,
    client_flag,
    reconnect_delay,
    select_transport,
)
from eufy_home_security.testing.rtc import (
    DEVICE_CANDIDATE,
    DEVICE_INFO,
    FakeRtcServer,
    PipeIce,
    rtc_config,
)


@pytest.fixture
async def fake() -> AsyncIterator[FakeRtcServer]:
    server = await FakeRtcServer().start()
    yield server
    await server.close()


@pytest.fixture
async def handler_errors() -> list[dict[str, Any]]:
    """What reaches the loop's exception handler during the test."""
    seen: list[dict[str, Any]] = []
    asyncio.get_running_loop().set_exception_handler(lambda _loop, ctx: seen.append(ctx))
    return seen


@pytest.fixture
async def make_session(
    fake: FakeRtcServer, handler_errors: list[dict[str, Any]]
) -> AsyncIterator[Callable[..., RtcSession]]:
    made: list[RtcSession] = []

    def make(**kwargs: Any) -> RtcSession:
        config = kwargs.pop("config", rtc_config())
        kwargs.setdefault("ice_factory", fake.ice_factory)
        session = RtcSession(config, signaling_port=fake.port, tcp_ports=(fake.tcp_port,), **kwargs)
        made.append(session)
        return session

    yield make
    for session in made:
        await session.close()
    await asyncio.sleep(0)
    asyncio.get_running_loop().set_exception_handler(None)
    assert handler_errors == []


@pytest.fixture
def quick(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reconnect waits shortened."""
    monkeypatch.setattr(session_mod, "LOSS_DELAY", 0.01)
    monkeypatch.setattr(session_mod, "REINIT_DELAY", 0.01)


OWN = ("RtcSession.", "SignalingClient.", "KcpDataChannel.", "IceTransport.")


def own_tasks(fake: FakeRtcServer) -> set[asyncio.Task[Any]]:
    """Tasks of the session's code still running (the fake's and the test's excluded)."""
    tasks = set()
    for task in asyncio.all_tasks():
        coro: Any = task.get_coro()
        frame = getattr(coro, "cr_frame", None)
        owner = frame.f_locals.get("self") if frame is not None else None
        if any(owner is channel for channel in fake.device_channels):
            continue
        if not task.done() and getattr(coro, "__qualname__", "").startswith(OWN):
            tasks.add(task)
    return tasks


async def until(check: Callable[[], object], timeout: float = 3.0) -> None:
    async with asyncio.timeout(timeout):
        while not check():
            await asyncio.sleep(0.01)


needs_aioice = pytest.mark.skipif(
    importlib.util.find_spec("aioice") is None, reason="needs the rtc extra"
)


@pytest.fixture
def real_ice(monkeypatch: pytest.MonkeyPatch) -> None:
    """aioice on 127.0.0.1 only, its STUN retries every 20 ms; ICE up to 0.3 s."""
    aioice = require_aioice()
    monkeypatch.setattr(aioice.ice, "get_host_addresses", lambda **_kw: ["127.0.0.1"])
    monkeypatch.setattr(aioice.stun, "RETRY_RTO", 0.02)
    monkeypatch.setattr(session_mod, "ICE_TIMEOUT", 0.3)


def ice_checks() -> list[asyncio.Task[Any]]:
    return [
        t
        for t in asyncio.all_tasks()
        if not t.done() and getattr(t.get_coro(), "__qualname__", "").startswith("Connection.")
    ]


async def settled(errors: list[dict[str, Any]]) -> None:
    """Let the timers of anything left running fire, then collect garbage."""
    await asyncio.sleep(0.3)
    gc.collect()
    await asyncio.sleep(0)
    assert ice_checks() == []
    assert errors == []


# ── pure decisions ───────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("flag", "caps", "chosen"),
    [
        (3, 3, DataTransport.QUIC),
        (1, 3, DataTransport.KCP),
        (3, 1, DataTransport.KCP),
        (2, 2, DataTransport.QUIC),
        (3, None, DataTransport.KCP),
        (0, 3, DataTransport.KCP),
    ],
)
def test_quic_needs_bit_1_on_both_sides(flag: int, caps: int | None, chosen: DataTransport) -> None:
    assert select_transport(flag, caps) is chosen


def test_the_client_flag_carries_the_framing_bit_and_never_quic() -> None:
    assert client_flag(KCP_TYPE_MULTI) == 1
    assert client_flag(KCP_TYPE_SINGLE) == 0


def test_the_reconnect_wait_follows_the_app_then_backs_off() -> None:
    assert [reconnect_delay(n) for n in range(1, 10)] == [1.5, 1.5, 1.5, 3, 6, 12, 24, 48, 64]
    assert reconnect_delay(40) == 64


def test_the_reconnect_constants_are_the_apps() -> None:
    assert (session_mod.LOSS_DELAY, session_mod.REINIT_DELAY) == (1.0, 0.5)
    assert session_mod.ICE_TIMEOUT == 20.0


def test_candidates_are_resent_on_the_apps_schedule() -> None:
    assert [candidate_resend_delay(n) for n in (1, 5, 6, 7)] == [0.3, 0.7, 1.4, 1.6]


def test_the_answer_reads_sdp_info_and_transport_caps() -> None:
    raw = base64.b64encode(DEVICE_INFO.encode()).decode()
    answer = CallAnswer.parse({"sdp_info": raw, "transport_caps": 3, "pbsdp": "AA=="})
    assert (answer.sdp_info, answer.transport_caps, answer.pbsdp) == (DEVICE_INFO, 3, True)
    plain = CallAnswer.parse({"sdp_info": raw, "transport_caps": True})
    assert (plain.transport_caps, plain.pbsdp) == (None, False)


@pytest.mark.parametrize(
    "payload",
    [
        {},
        {"sdp_info": ""},
        {"sdp_info": 5},
        {"sdp_info": "!!"},
        {"sdp_info": "AAAA"},
        {"sdp_info": "\u00e9AAAA"},  # not ASCII: base64 refuses it with a ValueError
    ],
)
def test_an_answer_without_a_readable_sdp_info_is_refused(payload: dict[str, Any]) -> None:
    with pytest.raises(ProtocolError):
        CallAnswer.parse(payload)


# ── connect ──────────────────────────────────────────────────────────────────


async def test_start_brings_the_data_channel_up(
    fake: FakeRtcServer, make_session: Callable[..., RtcSession]
) -> None:
    records: list[QuickLogin] = []
    servers: list[ServerInfo] = []
    session = make_session(on_login=records.append, on_server_info=servers.append)
    await session.start()
    assert [s.ip for s in servers] == ["127.0.0.1"]
    assert session.connected
    assert session.link_generation == 1
    assert session.answer is not None
    assert session.answer.sdp_info == DEVICE_INFO
    assert session.quick_login == records[0]
    # the CALL's sdp_info: kcp_type 2 framing bit for this station, no QUIC bit
    assert fake.call_info is not None
    assert fake.call_info.data_channel
    # candidates both ways, each acknowledged
    assert fake.client_candidates[0]["file_candidate"].startswith("a=candidate:")
    assert fake.client_candidates[0]["file_candidate_num"] == 0
    await until(lambda: 0 in fake.device_acks)
    # the data channel runs over the connected ICE, framing as the device answered
    channel = session.data_channel
    assert channel is not None
    await channel.send_message(b"ping", msg_type=DataMsgType.HEARTBEAT)
    async with asyncio.timeout(3):
        echo = await channel.recv_message()
    assert (echo.payload, echo.msg_type) == (b"ping", DataMsgType.HEARTBEAT)


async def test_the_device_candidate_reaches_ice_once(
    fake: FakeRtcServer, make_session: Callable[..., RtcSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    pipes: list[PipeIce] = []

    def factory() -> PipeIce:
        pipes.append(fake.ice_factory())
        return pipes[-1]

    fake.ack_candidates = True
    session = make_session(ice_factory=factory)
    await session.start()
    await until(lambda: 0 in fake.device_acks)
    acks = len(fake.of_type(MessageType.INFO))
    fake.send_candidate(0)  # a re-send whose acknowledgement was lost
    await until(lambda: len(fake.of_type(MessageType.INFO)) >= acks + 2)  # 200 and the ack
    assert pipes[0].remote_candidates == [DEVICE_CANDIDATE]


async def test_unacknowledged_candidates_are_sent_again_until_acked(
    fake: FakeRtcServer, make_session: Callable[..., RtcSession]
) -> None:
    fake.ack_candidates = False
    session = make_session()
    await session.start()
    await until(lambda: len(fake.client_candidates) >= 3)
    fake.ack_candidates = True
    await until(lambda: len(fake.client_candidates) >= 4)
    count = len(fake.client_candidates)
    await asyncio.sleep(0.7)
    assert len(fake.client_candidates) == count


async def test_repeated_answers_still_connect(
    fake: FakeRtcServer, make_session: Callable[..., RtcSession]
) -> None:
    fake.answer_repeats = 3
    session = make_session()
    await session.start()
    assert session.connected
    await until(lambda: len(fake.of_type(MessageType.ACK)) == 3)


async def test_a_usable_quick_login_skips_discover(
    fake: FakeRtcServer, make_session: Callable[..., RtcSession]
) -> None:
    first = make_session()
    await first.start()
    record = first.quick_login
    await first.close()
    fake.received.clear()
    second = make_session(config=rtc_config(quick_login=record))
    await second.start()
    assert MessageType.DISCOVER not in fake.kinds()


@pytest.mark.parametrize(
    ("script", "error"), [("busy", CallRefusedError), ("hangup", CallRefusedError)]
)
async def test_a_refused_call_fails_start_with_nothing_left(
    fake: FakeRtcServer,
    make_session: Callable[..., RtcSession],
    script: str,
    error: type[Exception],
) -> None:
    fake.call_reply = script
    session = make_session()
    with pytest.raises(error):
        await session.start()
    assert not session.connected
    assert own_tasks(fake) == set()


async def test_a_refused_login_fails_start(
    fake: FakeRtcServer, make_session: Callable[..., RtcSession]
) -> None:
    fake.refuse_login = True
    session = make_session()
    with pytest.raises(SignalingError) as caught:
        await session.start()
    assert caught.value.code == 401


async def test_ice_that_never_connects_times_out_and_hangs_up(
    fake: FakeRtcServer, make_session: Callable[..., RtcSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(session_mod, "ICE_TIMEOUT", 0.2)
    fake.ice_connects = False
    session = make_session()
    with pytest.raises(DeviceTimeoutError):
        await session.start()
    await until(lambda: fake.of_type(MessageType.HANGUP))
    assert own_tasks(fake) == set()


async def test_ice_with_wrong_credentials_fails(
    fake: FakeRtcServer, make_session: Callable[..., RtcSession]
) -> None:
    fake.device_info = dataclasses.replace(DEVICE_INFO, ice_ufrag="other")

    class Lying(PipeIce):
        async def connect(self, *, remote_ufrag: str, remote_pwd: str) -> None:
            fake.device_info = DEVICE_INFO  # the answer said `other`; ICE runs with `dev01`
            await super().connect(remote_ufrag=remote_ufrag, remote_pwd=remote_pwd)

    def factory() -> PipeIce:
        pipe = Lying(fake)
        pipe.peer = PipeIce()
        pipe.peer.peer = pipe
        return pipe

    session = make_session(ice_factory=factory)
    with pytest.raises(CommunicationError):
        await session.start()
    assert own_tasks(fake) == set()


async def test_a_device_choosing_quic_is_refused_when_the_client_offered_it(
    fake: FakeRtcServer, make_session: Callable[..., RtcSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    fake.transport_caps = 3
    monkeypatch.setattr(session_mod, "client_flag", lambda _kcp_type: 3)
    session = make_session()
    with pytest.raises(UnsupportedError):
        await session.start()
    await until(lambda: fake.of_type(MessageType.HANGUP))


async def test_a_device_offering_quic_gets_kcp_from_this_client(
    fake: FakeRtcServer, make_session: Callable[..., RtcSession]
) -> None:
    fake.transport_caps = 3
    session = make_session()
    await session.start()
    assert session.answer is not None
    assert session.answer.transport_caps == 3
    assert session.data_channel is not None


async def test_a_single_kcp_station_sends_no_framing_bit(
    fake: FakeRtcServer, make_session: Callable[..., RtcSession]
) -> None:
    session = make_session(config=rtc_config(sdk_version="6.1.2"))
    await session.start()
    assert fake.call_info is not None
    assert not fake.call_info.data_channel


async def test_the_framing_follows_the_devices_answer(
    fake: FakeRtcServer, make_session: Callable[..., RtcSession]
) -> None:
    """The device answers byte 2 = 0: bare KCP segments both ways, whatever the client sent."""
    fake.device_info = dataclasses.replace(DEVICE_INFO, data_channel=False)
    session = make_session()
    await session.start()
    assert fake.call_info is not None
    assert fake.call_info.data_channel  # the client asked for the prefix
    channel = session.data_channel
    assert channel is not None
    await channel.send_message(b"bare")
    async with asyncio.timeout(3):
        assert (await channel.recv_message()).payload == b"bare"


async def test_candidate_resends_stop_at_their_bound(
    fake: FakeRtcServer, make_session: Callable[..., RtcSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(session_mod, "CANDIDATE_RESENDS", 2)
    monkeypatch.setattr(session_mod, "candidate_resend_delay", lambda _n: 0.02)
    fake.ack_candidates = False
    session = make_session()
    await session.start()
    await asyncio.sleep(0.3)
    assert len(fake.client_candidates) == 3  # the first send and two resends


async def test_an_acknowledged_candidate_is_not_sent_again(
    fake: FakeRtcServer, make_session: Callable[..., RtcSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(session_mod, "candidate_resend_delay", lambda _n: 0.05)
    fake.ack_only = {0}
    two = ["candidate:1 1 udp 1 127.0.0.1 7 typ host", "candidate:2 1 udp 1 127.0.0.1 8 typ host"]

    def factory() -> PipeIce:
        pipe = fake.ice_factory()
        pipe.lines = two
        return pipe

    session = make_session(ice_factory=factory)
    await session.start()
    await asyncio.sleep(0.4)
    numbers = [c["file_candidate_num"] for c in fake.client_candidates]
    assert numbers.count(0) == 1
    assert numbers.count(1) > 2


@needs_aioice
async def test_real_ice_that_times_out_leaves_nothing_running(
    real_ice: None, handler_errors: list[dict[str, Any]]
) -> None:
    """The device's candidate never answers the checks."""
    server = await FakeRtcServer(turn=None).start()
    session = RtcSession(rtc_config(), signaling_port=server.port, tcp_ports=(server.tcp_port,))
    try:
        with pytest.raises(DeviceTimeoutError):
            await session.start()
        assert ice_checks() == []
        await settled(handler_errors)
    finally:
        await session.close()
        await server.close()
        asyncio.get_running_loop().set_exception_handler(None)


@needs_aioice
async def test_close_during_real_ice_checks_leaves_nothing_running(
    real_ice: None, handler_errors: list[dict[str, Any]], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(session_mod, "ICE_TIMEOUT", 30.0)
    server = await FakeRtcServer(turn=None).start()
    session = RtcSession(rtc_config(), signaling_port=server.port, tcp_ports=(server.tcp_port,))
    before = set(ice_checks())
    start = asyncio.create_task(session.start())
    try:
        await until(lambda: set(ice_checks()) - before)  # this session's checks run
        await session.close()
        with pytest.raises(CommunicationError):
            await start
        await settled(handler_errors)
    finally:
        await session.close()
        await server.close()
        asyncio.get_running_loop().set_exception_handler(None)


async def test_start_without_the_extra_raises_before_any_socket(
    fake: FakeRtcServer, monkeypatch: pytest.MonkeyPatch
) -> None:
    def missing() -> None:
        raise MissingDependencyError("the WebRTC transport", extra="rtc")

    monkeypatch.setattr(session_mod, "require_aioice", missing)
    session = RtcSession(rtc_config(), signaling_port=fake.port)
    with pytest.raises(MissingDependencyError):
        await session.start()
    assert fake.received == []


async def test_a_second_start_returns_at_once(
    fake: FakeRtcServer, make_session: Callable[..., RtcSession]
) -> None:
    session = make_session()
    await session.start()
    await session.start()
    assert session.link_generation == 1
    assert len(fake.of_type(MessageType.CALL)) == 1


# ── loss and reconnect ───────────────────────────────────────────────────────


async def test_a_hang_up_reconnects_with_a_quick_login(
    fake: FakeRtcServer, make_session: Callable[..., RtcSession], quick: None
) -> None:
    session = make_session()
    await session.start()
    fake.received.clear()
    fake.hang_up()
    await until(lambda: session.link_generation == 2 and session.connected)
    assert isinstance(session.last_error, SignalingError)
    logins = fake.of_type(MessageType.LOGIN)
    assert len(logins) == 1
    assert MessageType.DISCOVER not in fake.kinds()


async def test_a_broken_data_channel_reconnects(
    fake: FakeRtcServer, make_session: Callable[..., RtcSession], quick: None
) -> None:
    session = make_session()
    await session.start()
    await fake.break_link()
    await until(lambda: session.link_generation == 2 and session.connected)
    assert isinstance(session.last_error, CommunicationError)


async def test_a_peer_that_stops_acknowledging_reconnects(
    fake: FakeRtcServer,
    make_session: Callable[..., RtcSession],
    quick: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(_ikcp, "IKCP_DEADLINK", 2)
    pipes: list[PipeIce] = []

    def factory() -> PipeIce:
        pipes.append(fake.ice_factory())
        return pipes[-1]

    session = make_session(ice_factory=factory)
    await session.start()
    channel = session.data_channel
    assert channel is not None
    pipes[0].drop_outbound = True
    await channel.send_message(b"lost")
    await until(lambda: session.link_generation == 2 and session.connected, timeout=10)
    assert isinstance(session.last_error, CommunicationError)


async def test_a_signaling_socket_error_reconnects(
    fake: FakeRtcServer, make_session: Callable[..., RtcSession], quick: None
) -> None:
    session = make_session()
    await session.start()
    endpoint = session._attempt.signaling._main  # type: ignore[union-attr]
    assert endpoint is not None
    endpoint.error_received(ConnectionRefusedError("gone"))
    await until(lambda: session.link_generation == 2 and session.connected)
    assert isinstance(session.last_error, ConnectionRefusedError)


async def test_failed_reconnects_retry_and_warn_once(
    fake: FakeRtcServer,
    make_session: Callable[..., RtcSession],
    quick: None,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    monkeypatch.setattr(session_mod, "reconnect_delay", lambda _n: 0.01)
    session = make_session()
    await session.start()
    fake.call_reply = "busy"
    fake.hang_up()
    await until(lambda: len(fake.of_type(MessageType.CALL)) >= 4)
    assert not session.connected
    fake.call_reply = "answer"
    await until(lambda: session.connected and session.link_generation == 2)
    warnings = [
        r for r in caplog.records if r.name == session_mod.__name__ and r.levelno == logging.WARNING
    ]
    assert len(warnings) == 1
    assert "RTC reconnect failed" in warnings[0].getMessage()


async def test_a_lost_session_waits_before_it_closes(
    fake: FakeRtcServer, make_session: Callable[..., RtcSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(session_mod, "LOSS_DELAY", 0.3)
    monkeypatch.setattr(session_mod, "REINIT_DELAY", 0.01)
    session = make_session()
    await session.start()
    await fake.break_link()
    await until(lambda: not session.connected)
    await asyncio.sleep(0.1)
    assert fake.of_type(MessageType.HANGUP) == []  # still within the wait
    await until(lambda: fake.of_type(MessageType.HANGUP))


# ── close and cancel ─────────────────────────────────────────────────────────


async def test_close_stops_everything(
    fake: FakeRtcServer, make_session: Callable[..., RtcSession]
) -> None:
    session = make_session()
    await session.start()
    await session.close()
    assert not session.connected
    assert session.data_channel is None
    assert own_tasks(fake) == set()
    await until(lambda: fake.of_type(MessageType.HANGUP))
    await session.close()


async def test_close_during_connect_fails_start(
    fake: FakeRtcServer, make_session: Callable[..., RtcSession]
) -> None:
    fake.call_reply = "silent"
    session = make_session()
    start = asyncio.ensure_future(session.start())
    await until(lambda: fake.of_type(MessageType.CALL))
    await session.close()
    with pytest.raises(CommunicationError):
        await start
    assert own_tasks(fake) == set()


async def test_a_start_queued_behind_a_close_does_not_run(
    fake: FakeRtcServer, make_session: Callable[..., RtcSession]
) -> None:
    fake.call_reply = "silent"
    session = make_session()
    first = asyncio.ensure_future(session.start())
    await until(lambda: fake.of_type(MessageType.CALL))
    second = asyncio.ensure_future(session.start())
    await asyncio.sleep(0)
    await session.close()
    for task in (first, second):
        with pytest.raises(CommunicationError):
            await task
    assert own_tasks(fake) == set()


STEPS = {
    "discover": MessageType.DISCOVER,
    "login": MessageType.LOGIN,
    "call": MessageType.CALL,
}


@pytest.mark.parametrize("step", [*STEPS, "ice"])
async def test_a_cancelled_start_leaves_nothing_running(
    fake: FakeRtcServer, make_session: Callable[..., RtcSession], step: str
) -> None:
    if step == "discover":
        fake.transport.close()  # type: ignore[union-attr]
    elif step == "login":
        fake.drop_logins = 99
    elif step == "call":
        fake.call_reply = "silent"
    else:
        fake.ice_connects = False
    session = make_session()
    start = asyncio.ensure_future(session.start())
    if step in ("login", "call"):
        await until(lambda: fake.of_type(STEPS[step]))
    elif step == "ice":
        await until(lambda: fake.client_candidates)
    else:
        await asyncio.sleep(0.05)
    start.cancel()
    with pytest.raises(asyncio.CancelledError):
        await start
    assert own_tasks(fake) == set()
    assert not session.connected
    if step in ("call", "ice"):
        await until(lambda: fake.of_type(MessageType.HANGUP))


async def test_a_cancelled_close_still_finishes(
    fake: FakeRtcServer, make_session: Callable[..., RtcSession]
) -> None:
    session = make_session()
    await session.start()
    with pytest.raises(TimeoutError):
        async with asyncio.timeout(0):
            await session.close()
    await until(lambda: not own_tasks(fake))
    await until(lambda: fake.of_type(MessageType.HANGUP))


async def test_a_failing_consumer_callback_is_logged_and_the_session_runs(
    fake: FakeRtcServer,
    make_session: Callable[..., RtcSession],
    caplog: pytest.LogCaptureFixture,
) -> None:
    def broken(_record: object) -> None:
        raise RuntimeError("cache full")

    session = make_session(on_login=broken, on_server_info=broken)
    await session.start()
    assert session.connected
    assert session.quick_login is not None
    failures = [
        r
        for r in caplog.records
        if r.name == session_mod.__name__ and "callback failed" in r.getMessage()
    ]
    assert [r.levelno for r in failures] == [logging.WARNING]


async def test_a_start_right_after_a_cancelled_close_runs_once(
    fake: FakeRtcServer, make_session: Callable[..., RtcSession]
) -> None:
    session = make_session()
    await session.start()
    with pytest.raises(TimeoutError):
        async with asyncio.timeout(0):
            await session.close()
    await session.start()
    assert session.connected
    runs = [t for t in asyncio.all_tasks() if "_run_loop" in repr(t.get_coro())]
    assert len(runs) == 1


async def test_a_closed_session_starts_again(
    fake: FakeRtcServer, make_session: Callable[..., RtcSession]
) -> None:
    session = make_session()
    await session.start()
    await session.close()
    await session.start()
    assert session.connected
    assert session.link_generation == 2


async def test_a_reconnect_waits_after_closing_the_lost_link(
    fake: FakeRtcServer, make_session: Callable[..., RtcSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(session_mod, "LOSS_DELAY", 0.01)
    monkeypatch.setattr(session_mod, "REINIT_DELAY", 0.4)
    session = make_session()
    await session.start()
    fake.received.clear()
    await fake.break_link()
    await until(lambda: fake.of_type(MessageType.HANGUP))
    await asyncio.sleep(0.2)
    assert fake.of_type(MessageType.LOGIN) == []  # still within the wait
    await until(lambda: session.link_generation == 2)


async def test_a_second_cancel_during_cleanup_still_closes_everything(
    fake: FakeRtcServer, make_session: Callable[..., RtcSession]
) -> None:
    """A loop shutdown cancels the run again while it closes the link."""
    session = make_session()
    await session.start()
    run = session._run
    assert run is not None
    run.cancel()
    await asyncio.sleep(0)
    run.cancel()
    await asyncio.wait({run})
    assert own_tasks(fake) == set()


async def test_close_during_a_reconnect_wait_stops_it(
    fake: FakeRtcServer, make_session: Callable[..., RtcSession], monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(session_mod, "LOSS_DELAY", 5.0)
    session = make_session()
    await session.start()
    fake.hang_up()
    await until(lambda: not session.connected)
    async with asyncio.timeout(1):
        await session.close()
    assert own_tasks(fake) == set()
    calls = len(fake.of_type(MessageType.CALL))
    await asyncio.sleep(0.1)
    assert len(fake.of_type(MessageType.CALL)) == calls
