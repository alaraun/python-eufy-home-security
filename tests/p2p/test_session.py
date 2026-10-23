from __future__ import annotations

import asyncio
import contextlib
import gc
import json
import logging
import os
import socket
import struct
import time
from collections.abc import AsyncIterator, Callable
from dataclasses import replace
from datetime import UTC, datetime
from typing import Any, cast

import pytest

import eufy_home_security.p2p.session as session_mod
import eufy_home_security.p2p.session as session_module
from eufy_home_security._logging import set_secret_logging
from eufy_home_security.devices.recipes import (
    goto_preset,
    query_preset_positions,
    set_default_preset,
)
from eufy_home_security.events import (
    AccountMismatch,
    AlarmChanged,
    AlarmStopSource,
    ConnectionChanged,
    DisconnectCause,
    Event,
    EventSource,
    GuardModeChanged,
    ParamChanged,
    SecurityEvent,
    StorageChanged,
)
from eufy_home_security.exceptions import (
    CameraWakeError,
    CipherUnavailableError,
    CipherUnusableError,
    CommandNotAppliedError,
    CommandRejectedError,
    CommandUnsupportedError,
    CommunicationError,
    DeviceTimeoutError,
    EufySecurityError,
    HandshakeError,
    KeyRejectedError,
    ProtocolError,
    RateLimitedError,
    StationUnreachableError,
    UnsupportedError,
)
from eufy_home_security.models import STATION_CHANNEL, GuardMode
from eufy_home_security.p2p import transport as transport_module
from eufy_home_security.p2p.crypto import (
    CONN_INIT_ECC_VERSION,
    FRAME_PLAIN,
    FRAME_SESSION_ECB,
    FRAME_STATIC_ECB,
    ecb_encrypt,
)
from eufy_home_security.p2p.did import Did, static_key
from eufy_home_security.p2p.media import (
    MediaDecoder,
    MediaFrame,
    MediaKind,
    Still,
    StillFormat,
    VideoCodec,
    generate_media_rsa_key,
)
from eufy_home_security.p2p.messages import (
    RECEIPT_NOT_HANDLED,
    STANDALONE_RECEIPT_LEN,
    history_cursor_time,
)
from eufy_home_security.p2p.session import (
    PARAM_SETTLE,
    CommandOutcome,
    CredentialProvider,
    EventSummary,
    Inbound,
    MediaStream,
    MemoryKeyRefreshLatch,
    P2PCredentials,
    ParamOrigin,
    StationSession,
    _scalar_result,
)
from eufy_home_security.p2p.transport import PPPPTransport
from eufy_home_security.p2p.xzyh import Frame, FrameCipher, FrameType
from eufy_home_security.testing import SYNTHETIC
from eufy_home_security.testing.station import (
    MEDIA_AUDIO,
    MEDIA_GOP,
    MEDIA_HEIGHT,
    MEDIA_KEYFRAME,
    MEDIA_PFRAME,
    MEDIA_RECORDING_PFRAME,
    MEDIA_WIDTH,
    RSA_SESSION_KEY,
    SESSION_KEY,
    FakeStation,
    audio_record,
    media_keyframe,
    media_keyframe_parts,
    synthetic_hub_storage,
    v1_still,
    v2_still,
    video_record,
)


class Provider:
    def __init__(
        self,
        station: FakeStation,
        *,
        account_id: str = SYNTHETIC.account_id,
        stale_key: str | None = None,
    ) -> None:
        self.station = station
        self.account_id = account_id
        self.stale_key = stale_key
        self.calls: list[bool] = []

    async def __call__(self, *, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        self.calls.append(refresh)
        key = (
            self.stale_key if (self.stale_key and not refresh) else self.station.ecc_private_key_hex
        )
        return P2PCredentials(self.account_id, "user", key)


@pytest.fixture
async def station() -> AsyncIterator[FakeStation]:
    fake = FakeStation()
    await fake.start()
    yield fake
    fake.stop()


@pytest.fixture
def short_settle(monkeypatch: pytest.MonkeyPatch) -> None:
    """A parameter read's settle wait shortened (the fake sends every block at once)."""
    monkeypatch.setattr(session_module, "PARAM_SETTLE", 0.05)


def make_session(station: FakeStation, provider: Provider) -> StationSession:
    return StationSession(
        SYNTHETIC.station_sn, provider, host="127.0.0.1", port=station.discovery_port
    )


async def wait_until(predicate: object, timeout: float = 3.0) -> None:
    assert callable(predicate)
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(0.02)


def reply_later(station: FakeStation, obj: dict[str, Any], delay: float = 0.3) -> None:
    """Have the station send a 0x0547 JSON frame while a request is in flight."""
    asyncio.get_running_loop().call_later(delay, station.send_json, FrameType.NOTIFY_PAYLOAD, obj)


async def test_closing_during_a_start_leaves_no_supervisor_behind(
    station: FakeStation,
) -> None:
    """A start/close race must not leak a task that supervises a dead session.

    ``async_close`` cancels the supervisor, but ``async_start`` creates one in its
    ``finally``. A close while the start is still connecting must stop that one too;
    otherwise nothing cancels it and it loops forever on a closed session: retrying the
    connect, re-entering the credential provider, and emitting ConnectionChanged to
    subscribers the consumer already dropped. One would leak per config-entry reload.
    """
    session = make_session(station, Provider(station))
    starting = asyncio.create_task(session.async_start())
    await asyncio.sleep(0)  # let the start reach its first await
    await session.async_close()
    with contextlib.suppress(EufySecurityError, asyncio.CancelledError):
        await starting

    assert session._supervisor is None or session._supervisor.done(), (
        "a closed session must supervise nothing"
    )


async def test_an_unexpected_supervisor_error_retries_instead_of_stopping(
    station: FakeStation, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bug in the supervisor must degrade to a retry, not end supervision.

    Catching only EufySecurityError would let any other exception kill the task for
    good: no more probes, no more reconnects, while ``connected`` keeps reporting the
    last value it saw — a station that looks healthy and is in fact dead until the
    process restarts. Driving ``_supervise`` directly keeps the test to that one contract.
    """
    session = make_session(station, Provider(station))
    calls = 0

    async def exploding() -> None:
        nonlocal calls
        calls += 1
        if calls == 1:
            msg = "a decoder bug"
            raise ValueError(msg)

    session.async_connect = exploding  # type: ignore[method-assign]
    monkeypatch.setattr(session_module, "RECONNECT_BACKOFF", (0.05,))
    supervisor = asyncio.create_task(session._supervise(0.01, 0.01))
    try:
        with caplog.at_level(logging.ERROR):
            await wait_until(lambda: calls >= 2, timeout=20.0)
        assert not supervisor.done(), "the supervisor survived the unexpected error"
        assert any("unexpected supervisor error" in r.message for r in caplog.records), (
            "and said so, rather than failing silently"
        )
    finally:
        supervisor.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await supervisor
        await session.async_close()


@pytest.mark.parametrize("secrets", [False, True])
async def test_handshake_logs_key_material_only_with_secret_logging(
    station: FakeStation, caplog: pytest.LogCaptureFixture, secrets: bool
) -> None:
    session = make_session(station, Provider(station))
    set_secret_logging(secrets)
    try:
        with caplog.at_level(logging.DEBUG, logger="eufy_home_security.p2p"):
            await session.async_get_params()
    finally:
        set_secret_logging(False)
        await session.async_close()
    text = caplog.text
    for step in ("LAN_SEARCH", "PUNCH_PKT", "sending CONN_INIT", "GCM session key", "answered in"):
        assert step in text
    for secret in (
        SESSION_KEY.hex(),
        station.static_key.hex(),
        station.ecc_private_key_hex,
        SYNTHETIC.account_id,
    ):
        assert (secret in text) is secrets


async def test_connect_reads_params_and_guard_mode(
    station: FakeStation, caplog: pytest.LogCaptureFixture
) -> None:
    station.params[255][1224] = "1"
    session = make_session(station, Provider(station))
    events: list[Event] = []
    session.subscribe(events.append)
    try:
        with caplog.at_level(logging.DEBUG, logger="eufy_home_security.p2p.session"):
            dump = await session.async_get_params()
    finally:
        await session.async_close()
    assert dump.guard_mode == GuardMode.HOME
    assert dump.devices[0][1101] == "87"  # the camera block, delivered before the station's
    assert session.did is not None
    assert station.conn_inits == 1
    assert any(isinstance(e, ConnectionChanged) and e.connected for e in events)
    assert (
        GuardModeChanged(
            station_sn=SYNTHETIC.station_sn,
            mode=GuardMode.HOME,
            active_mode=GuardMode.HOME,  # no 1151 in the dump: outside Schedule, the same
            source=EventSource.P2P,
        )
        in events
    )


async def test_params_return_as_soon_as_every_expected_channel_reported(
    station: FakeStation,
) -> None:
    session = StationSession(
        SYNTHETIC.station_sn,
        Provider(station),
        host="127.0.0.1",
        port=station.discovery_port,
        expect_channels={0},  # the default for every read that names none
    )
    try:
        started = time.monotonic()
        dump = await session.async_get_params()
        quick = time.monotonic() - started
        started = time.monotonic()
        await session.async_get_params(expect_channels={0, 7})  # channel 7 never reports
        bounded = time.monotonic() - started
    finally:
        await session.async_close()
    assert set(dump.devices) == {0, 255}
    assert quick < PARAM_SETTLE / 2
    assert PARAM_SETTLE <= bounded < PARAM_SETTLE * 2


async def test_first_search_after_close_is_ignored(station: FakeStation) -> None:
    station.ignore_searches = 1
    session = make_session(station, Provider(station))
    try:
        await session.async_connect()
    finally:
        await session.async_close()
    assert station.searches >= 2


async def test_arm_reports_the_applied_mode(station: FakeStation) -> None:
    session = make_session(station, Provider(station))
    try:
        applied = await session.async_set_guard_mode(GuardMode.HOME)
        again = await session.async_set_guard_mode(GuardMode.AWAY)
    finally:
        await session.async_close()
    assert applied == GuardMode.HOME
    assert again == GuardMode.AWAY
    assert station.guard_mode == GuardMode.AWAY
    assert station.conn_inits == 1  # one session serves every request
    assert station.received[0]["payload"] == {"mode_type": 1, "user_name": "user"}


def _modes(events: list[Event]) -> list[tuple[object, object]]:
    return [(e.mode, e.active_mode) for e in events if isinstance(e, GuardModeChanged)]


async def test_schedule_is_two_modes(station: FakeStation) -> None:
    station.params[255] |= {1224: "0", 1151: "0"}
    station.schedule_mode = GuardMode.HOME
    session = make_session(station, Provider(station))
    events: list[Event] = []
    session.subscribe(events.append)
    try:
        await session.async_get_params()
        # The report after selecting Schedule carries the slot's mode: confirmed by 1224.
        assert await session.async_set_guard_mode(GuardMode.SCHEDULE) is GuardMode.SCHEDULE
        assert (session.guard_mode, session.active_mode) == (GuardMode.SCHEDULE, GuardMode.HOME)
        station.send_alarm_mode(GuardMode.AWAY)  # a slot boundary
        await wait_until(lambda: session.active_mode == GuardMode.AWAY)
        station.send_alarm_mode(GuardMode.AWAY)  # the same report again
        await asyncio.sleep(0.3)
        assert await session.async_set_guard_mode(GuardMode.DISARMED) is GuardMode.DISARMED
    finally:
        await session.async_close()
    assert _modes(events) == [
        (GuardMode.AWAY, GuardMode.AWAY),
        (GuardMode.SCHEDULE, GuardMode.HOME),
        (GuardMode.SCHEDULE, GuardMode.AWAY),
        (GuardMode.DISARMED, GuardMode.DISARMED),  # the arm's own report leaves Schedule
    ]


async def test_a_report_under_schedule_moves_only_the_effective_mode(
    station: FakeStation,
) -> None:
    station.params[255] |= {1224: "2", 1151: "1"}
    session = make_session(station, Provider(station))
    events: list[Event] = []
    session.subscribe(events.append)
    try:
        await session.async_get_params()
        # cast: the plain None assignment narrows the attribute for the whole function,
        # which would make the "a read is due again" assert below look unreachable.
        session._reprobe_at = cast("float | None", None)
        station.send_alarm_mode(GuardMode.DISARMED)  # a boundary, or the app leaving Schedule
        await wait_until(lambda: session.active_mode == GuardMode.DISARMED)
    finally:
        await session.async_close()
    assert session.guard_mode is GuardMode.SCHEDULE
    assert session._reprobe_at is not None  # a read tells the two apart
    assert _modes(events) == [
        (GuardMode.SCHEDULE, GuardMode.HOME),
        (GuardMode.SCHEDULE, GuardMode.DISARMED),
    ]


async def test_an_unanswered_arm_to_the_current_mode_is_confirmed_by_read_back(
    station: FakeStation,
) -> None:
    station.params[255][1224] = "0"  # already Away
    station.unanswered_commands = {1224}  # no result, no report
    session = make_session(station, Provider(station))
    try:
        assert await session.async_set_guard_mode(GuardMode.AWAY, timeout=1.0) == GuardMode.AWAY
    finally:
        await session.async_close()
    assert station.received[-1]["cmd"] == 1224


async def test_report_only_off_is_refused_before_sending(station: FakeStation) -> None:
    session = make_session(station, Provider(station))
    try:
        with pytest.raises(UnsupportedError):
            await session.async_set_guard_mode(GuardMode.OFF)
    finally:
        await session.async_close()
    assert station.received == []
    assert station.conn_inits == 0


async def test_an_arm_only_acknowledged_is_not_applied(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A receipt 0 (the station took the arm off its queue) stops the resend; with no
    result and no report, it is no success."""
    monkeypatch.setattr(session_module, "COMMAND_RESEND_AFTER", 0.1)
    session = make_session(station, Provider(station, account_id="f" * 40))
    try:
        with pytest.raises(CommandNotAppliedError, match=r"took the arm \(receipt 0\)"):
            await session.async_set_guard_mode(GuardMode.HOME, timeout=1.0)
    finally:
        await session.async_close()
    assert [o["cmd"] for o in station.received] == [1224]  # never resent
    assert station.guard_mode == 0
    assert session.guard_mode != GuardMode.HOME


async def test_arm_takes_only_its_own_reply_as_the_result(station: FakeStation) -> None:
    # A foreign account: the station takes every arm off its queue (receipt 0) and
    # drops it, so only injected frames answer.
    session = make_session(station, Provider(station, account_id="f" * 40))
    events: list[Event] = []
    session.subscribe(events.append)
    loop = asyncio.get_running_loop()
    try:
        await session.async_connect()
        reply_later(station, {"cmd": 1004, "code": -104})  # another command's reply
        loop.call_later(0.2, station.push_camera_event)
        with pytest.raises(CommandNotAppliedError):
            await session.async_set_guard_mode(GuardMode.HOME, timeout=1.0)
        assert session.guard_mode != GuardMode.HOME
        reply_later(station, {"cmd": 1224, "code": -104})
        with pytest.raises(CommandRejectedError) as rejected:
            await session.async_set_guard_mode(GuardMode.HOME, timeout=3.0)
        assert session.guard_mode != GuardMode.HOME
        reply_later(station, {"cmd": "1224", "code": 0})  # the arm's own zero result
        armed = await session.async_set_guard_mode(GuardMode.HOME, timeout=3.0)
    finally:
        await session.async_close()
    assert rejected.value.code == -104
    assert armed is GuardMode.HOME
    assert session.guard_mode is GuardMode.HOME
    assert [e.mode for e in events if isinstance(e, GuardModeChanged)][-1] is GuardMode.HOME


async def test_a_receipt_then_a_rejecting_result_rejects_the_arm(station: FakeStation) -> None:
    """A GCM receipt 0 only takes the arm off the queue: the result that follows decides."""
    session = make_session(station, Provider(station, account_id="f" * 40))
    try:
        await session.async_connect()
        reply_later(station, {"cmd": 1224, "code": -104})
        with pytest.raises(CommandRejectedError) as rejected:
            await session.async_set_guard_mode(GuardMode.HOME, timeout=2.0)
        receipts = session.stats().receipts_by_code
    finally:
        await session.async_close()
    assert (rejected.value.command, rejected.value.code) == (1224, -104)
    assert receipts == {"0": 1}  # the arm's receipt came first
    assert session.guard_mode != GuardMode.HOME


@pytest.mark.parametrize("ticks", [0, 1, 2, 3, 5])
async def test_another_requests_receipt_is_not_the_arms_result(
    station: FakeStation, ticks: int
) -> None:
    """A still fetch's receipt 0, landing in any order around the arm's send, does not
    apply an arm the station never answers."""
    station.images["/zx/a.jpg"] = b"\xff\xd8image-A"
    station.unanswered_commands = {1224}
    session = make_session(station, Provider(station))
    try:
        await session.async_get_params()
        still = asyncio.ensure_future(session.async_fetch_still("/zx/a.jpg"))
        for _ in range(ticks):
            await asyncio.sleep(0)
        with pytest.raises(CommandNotAppliedError):
            await session.async_set_guard_mode(GuardMode.HOME, timeout=1.0)
        await still
    finally:
        await session.async_close()
    assert station.guard_mode != GuardMode.HOME
    assert session.guard_mode != GuardMode.HOME


async def test_a_dump_key_the_library_does_not_read_is_kept_and_logged_once(
    station: FakeStation, caplog: pytest.LogCaptureFixture
) -> None:
    station.dump_extra = {"future_list": [{"channel": 0}], "db_bypass_str": []}
    session = make_session(station, Provider(station))
    caplog.set_level(logging.INFO, logger="eufy_home_security.p2p.session")
    try:
        dump = await session.async_get_params(expect_channels={0})
        await session.async_get_params(expect_channels={0})
    finally:
        await session.async_close()
    assert dump.unread == {"future_list": [{"channel": 0}]}
    assert any("future_list" in obj for obj in dump.received)
    assert session.unread_dump_keys == {"future_list"}
    logged = [r for r in caplog.records if "future_list" in r.getMessage()]
    assert len(logged) == 1


async def test_a_gcm_session_takes_state_under_the_static_key(
    station: FakeStation, caplog: pytest.LogCaptureFixture
) -> None:
    """A parameter dump, a guard-mode report and an alarm frame under the static key
    (ECB) are taken, unauthenticated, and logged at INFO once per frame type."""
    caplog.set_level(logging.INFO, logger=session_module.__name__)
    station.params_cipher = FrameCipher.ECB
    station.params[255][1224] = "0"
    session = make_session(station, Provider(station))
    events: list[Event] = []
    session.subscribe(events.append)
    try:
        await session.async_get_params(expect_channels={0})
        station.params[255][1224] = "63"
        station.send_param_dump(cipher=FrameCipher.ECB)
        await wait_until(lambda: session.guard_mode == GuardMode.DISARMED)
        for _ in range(2):
            station.send_alarm_mode(GuardMode.HOME, cipher=FrameCipher.ECB)
            station.send_alarm_frame(
                FrameType.ALARM_TONE_NOTIFY, 3, 30, channel=1, cipher=FrameCipher.ECB
            )
        taken = 2 * len(station.params) + 4  # two dumps, two reports, two tone frames
        await wait_until(lambda: session.stats().state_frames_by_encryption.get("ecb") == taken)
        stats = session.stats()
    finally:
        await session.async_close()
    modes = [e.mode for e in events if isinstance(e, GuardModeChanged)]
    assert modes == [GuardMode.AWAY, GuardMode.DISARMED, GuardMode.HOME]
    assert [e.alarming for e in events if isinstance(e, AlarmChanged)] == [True]
    assert stats.state_frames_by_encryption == {"ecb": taken}
    assert (stats.state_authenticated, stats.ecb_state_refused) == (False, 0)
    logged = _messages(caplog, "(unauthenticated), taken as the eufy app does")
    assert sorted(logged) == sorted(
        f"{session._log_name}: station state 0x{t:04x} arrived under the fixed key "
        "(unauthenticated), taken as the eufy app does"
        for t in (0x044F, 0x047F, 0x04B1)
    )


@pytest.mark.parametrize("rsa", [False, True], ids=["gcm", "rsa"])
async def test_alarm_frames_become_param_and_alarm_changes(
    station: FakeStation, rsa: bool, short_settle: None
) -> None:
    """Alarm frames under the session's cipher (GCM, or an RSA session's key) count; one
    that does not decrypt is dropped."""
    session = make_rsa_session(station) if rsa else make_session(station, Provider(station))
    events: list[Event] = []
    started = datetime.now(UTC)
    try:
        await session.async_get_params()
        session.subscribe(events.append)
        tone, siren, light = (
            FrameType.ALARM_TONE_NOTIFY,
            FrameType.SIREN_NOTIFY,
            FrameType.LIGHT_NOTIFY,
        )
        station.send_alarm_frame(light, 0, channel=1)  # at the detection
        station.send_alarm_frame(tone, 3, 30, channel=1)  # the trigger
        station.send_alarm_frame(siren, 25, 30, channel=1)
        station.send_alarm_frame(light, 1, channel=1)
        undecodable = bytes([FrameCipher.GCM, 0, 1, 2, 0, 0])  # no GCM tag, not whole blocks
        station.send_frame(
            tone, bytes(40), cipher=FrameCipher.GCM, channel=2, subheader=undecodable, sealed=True
        )
        station.send_alarm_frame(tone, 16, 0, channel=255)  # stopped from the app
        station.send_alarm_frame(tone, 0, 0, channel=0)  # no alarm on: not a transition
        await wait_until(lambda: (0, 1201) in session.params)
    finally:
        await session.async_close()
    params = [(e.channel, e.param_id, e.old, e.new) for e in events if isinstance(e, ParamChanged)]
    assert params == [
        (1, 1400, None, "0"),
        (1, 1201, None, "3"),
        (1, 1202, None, "25"),
        (1, 1400, "0", "1"),
        (255, 1201, None, "16"),
        (0, 1201, None, "0"),
    ]
    alarms = [e for e in events if isinstance(e, AlarmChanged)]
    assert all(started <= e.at <= datetime.now(UTC) for e in alarms)  # when it arrived
    assert alarms == [
        AlarmChanged(
            station_sn=SYNTHETIC.station_sn,
            alarming=True,
            source=EventSource.P2P,
            channel=1,
            event_type=3,
            duration_s=30,
        ),
        AlarmChanged(
            station_sn=SYNTHETIC.station_sn,
            alarming=False,
            source=EventSource.P2P,
            channel=255,
            event_type=16,
            stop_source=AlarmStopSource.APP,
        ),
    ]
    assert session.stats().dropped_undecodable == 1


async def test_an_ecb_mode_report_is_an_arms_result(station: FakeStation) -> None:
    """A guard-mode report under the static key answers an arm, as the eufy app takes it;
    one that does not decode does not."""
    station.params[255][1224] = "0"
    station.unanswered_commands = {1224}  # only the injected report answers
    session = make_session(station, Provider(station))
    loop = asyncio.get_running_loop()
    try:
        await session.async_connect()
        undecodable = bytes([FrameCipher.ECB, 0, 0xFF, FRAME_STATIC_ECB, 0, 0])
        loop.call_later(
            0.1,
            lambda: station.send_frame(
                FrameType.ALARM_MODE_NOTIFY, bytes(8), cipher=0, channel=2, subheader=undecodable
            ),
        )
        loop.call_later(0.2, lambda: station.send_alarm_mode(1, cipher=FrameCipher.ECB))
        armed = await session.async_set_guard_mode(GuardMode.HOME, timeout=3.0)
    finally:
        await session.async_close()
    assert armed == session.guard_mode == GuardMode.HOME
    assert session.stats().state_frames_by_encryption.get("ecb") == 1


@pytest.mark.parametrize("late", [0.3, 1.3])  # inside the settle, and just after the read
async def test_late_sub_device_blocks_do_not_cue_a_reprobe(
    station: FakeStation, late: float, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(session_module, "UNSOLICITED_REPROBE_DELAY", 0.5)
    station.sub_blocks_after = late
    session = make_session(station, Provider(station))
    try:
        await session.async_start(probe_every=600.0)
        # A cued reprobe would run within the delay plus one 1 s supervisor tick.
        await asyncio.sleep(late + session_module.UNSOLICITED_REPROBE_DELAY + 1.5)
        assert (0, 1101) in session.params
    finally:
        await session.async_close()
    assert station.param_queries == 1


async def test_only_a_full_read_drops_vanished_blocks(
    station: FakeStation, caplog: pytest.LogCaptureFixture
) -> None:
    station.params[1] = {1101: "40"}
    session = make_session(station, Provider(station))
    session.expect_channels = {0, 1}
    signals: list[None] = []
    session.add_dump_listener(lambda: signals.append(None))

    def broken() -> None:
        raise RuntimeError("listener bug")

    session.add_dump_listener(broken)
    try:
        await session.async_get_params()
        del station.params[1]
        await session.async_get_params(expect_channels={0})  # a read-back: not full
        assert (1, 1101) in session.params
        await session.async_get_params()  # waits for every paired channel: full
    finally:
        await session.async_close()
    assert (1, 1101) not in session.params
    assert (0, 1101) in session.params
    assert len(signals) == 3
    assert "parameter dump listener failed" in caplog.text


async def test_unusable_did_is_not_a_handshake_failure(station: FakeStation) -> None:
    provider = Provider(station)
    session = StationSession("T8030", provider, host="127.0.0.1", port=station.discovery_port)
    try:
        with pytest.raises(ProtocolError, match="static key") as info:
            await session.async_connect()
        assert session._transport is None  # before close: the failed link was not kept
    finally:
        await session.async_close()
    assert not isinstance(info.value, HandshakeError)
    assert provider.calls == []  # no credentials before CONN_INIT, no re-fetch after
    assert station.conn_inits == 0


async def test_send_takes_only_its_own_zero_code_reply_as_applied(station: FakeStation) -> None:
    session = make_session(station, Provider(station))
    body = {"night_sion": 1, "channel": 0}
    try:
        await session.async_connect()
        reply_later(station, {"cmd": 1004, "code": 0})
        asyncio.get_running_loop().call_later(0.2, station.push_camera_event)
        foreign = await session.async_send_command(1277, channel=0, payload=body, timeout=1.0)
        reply_later(station, {"cmd": 1277, "code": -104})
        with pytest.raises(CommandRejectedError) as rejected:
            await session.async_send_command(1277, channel=0, payload=body, timeout=3.0)
        reply_later(station, {"cmd": "1277", "mIntRet": 0})
        applied = await session.async_send_command(1277, channel=0, payload=body, timeout=3.0)
    finally:
        await session.async_close()
    assert foreign is CommandOutcome.DELIVERED
    assert rejected.value.code == -104
    assert applied is CommandOutcome.APPLIED


async def test_session_loss_mid_request_raises_instead_of_a_partial_result(
    station: FakeStation, caplog: pytest.LogCaptureFixture
) -> None:
    station.unanswered_commands = {1224}
    session = make_session(station, Provider(station, account_id="f" * 40))
    loop = asyncio.get_running_loop()
    try:
        await session.async_connect()
        loop.call_later(0.3, station.send_close)  # while settling for channel 7
        with pytest.raises(StationUnreachableError):
            await session.async_get_params(expect_channels={0, 7})
        await session.async_connect()
        loop.call_later(0.3, station.send_close)  # while waiting for the (ignored) arm
        with pytest.raises(StationUnreachableError):
            await session.async_set_guard_mode(GuardMode.HOME, timeout=3.0)
        gc.collect()
        await asyncio.sleep(0.05)
    finally:
        await session.async_close()
    assert "never retrieved" not in caplog.text


async def test_a_closed_session_does_not_reconnect(station: FakeStation) -> None:
    session = make_session(station, Provider(station))
    await session.async_start()
    await session.async_close()
    with pytest.raises(StationUnreachableError, match="closed"):
        await session.async_get_params()
    with pytest.raises(StationUnreachableError, match="closed"):
        await session.async_start()
    with pytest.raises(StationUnreachableError, match="closed"):
        await session.async_open_live(0)
    assert session._supervisor is None
    assert station.conn_inits == 1


async def test_cancelled_connect_leaves_no_open_link(station: FakeStation) -> None:
    station.answer_conn_init = False
    session = make_session(station, Provider(station))
    task = asyncio.create_task(session.async_connect())
    await wait_until(lambda: station.conn_inits >= 1)
    task.cancel()
    with pytest.raises(asyncio.CancelledError):
        await task
    assert session._transport is None
    await session.async_close()


async def test_pinned_local_port_survives_an_immediate_reconnect(station: FakeStation) -> None:
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        port = probe.getsockname()[1]
    session = StationSession(
        SYNTHETIC.station_sn,
        Provider(station),
        host="127.0.0.1",
        port=station.discovery_port,
        local_port=port,
    )
    try:
        await session.async_connect()
        # as the supervisor does
        session._teardown("parameter probe unanswered", cause=DisconnectCause.PROBE_UNANSWERED)
        await session.async_connect()
        assert session.connected
    finally:
        await session.async_close()


async def test_stale_cipher_key_is_refreshed_once(station: FakeStation) -> None:
    other = FakeStation()
    provider = Provider(station, stale_key=other.ecc_private_key_hex)
    session = make_session(station, provider)
    try:
        await session.async_connect()
        assert session.connected
    finally:
        await session.async_close()
    assert provider.calls == [False, True]
    assert station.conn_inits == 2
    stats = session.stats()
    assert (stats.handshake_failures, stats.key_refreshes, stats.connects) == (1, 1, 1)
    assert (stats.conn_init_version, stats.cipher_id) == (CONN_INIT_ECC_VERSION, station.cipher_id)


async def test_a_rejected_refetched_key_latches_until_released(station: FakeStation) -> None:
    wrong = FakeStation().ecc_private_key_hex
    provider = Provider(station, stale_key=wrong)
    provider.station = FakeStation()  # every key it hands out is wrong, re-fetched or not
    latch = MemoryKeyRefreshLatch()
    session = StationSession(
        SYNTHETIC.station_sn,
        provider,
        host="127.0.0.1",
        port=station.discovery_port,
        key_refresh=latch,
    )
    try:
        with pytest.raises(KeyRejectedError):  # re-fetched once, rejected again
            await session.async_connect()
        assert provider.calls == [False, True]
        with pytest.raises(KeyRejectedError, match="already re-fetched"):
            await session.async_connect()
        assert provider.calls == [False, True, False]  # no second fetch while latched

        await latch.async_accepted()  # the release path
        provider.station = station  # and the re-fetch now brings the right key
        await session.async_connect()
        assert session.connected
        assert provider.calls == [False, True, False, False, True]
        assert latch.retry_blocked_for() == 0.0  # the handshake cleared the latch
    finally:
        await session.async_close()


async def test_a_failed_refetch_sets_no_latch(station: FakeStation) -> None:
    wrong = FakeStation().ecc_private_key_hex
    calls: list[bool] = []

    async def provider(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        calls.append(refresh)
        if refresh:
            raise RateLimitedError("throttled", code=26145)
        return P2PCredentials(SYNTHETIC.account_id, "user", wrong)

    latch = MemoryKeyRefreshLatch()
    session = StationSession(
        SYNTHETIC.station_sn,
        provider,
        host="127.0.0.1",
        port=station.discovery_port,
        key_refresh=latch,
    )
    try:
        for _ in range(2):
            with pytest.raises(RateLimitedError):
                await session.async_connect()
    finally:
        await session.async_close()
    assert calls == [False, True, False, True]  # each rejection may try a fetch again
    assert latch.retry_blocked_for() == 0.0


@pytest.mark.parametrize(
    ("failure", "error_type", "cause"),
    [
        (None, HandshakeError, DisconnectCause.KEY_REJECTED),  # a key that never unwraps
        (RateLimitedError(), RateLimitedError, DisconnectCause.CREDENTIALS_UNAVAILABLE),
        (ProtocolError("unexpected"), ProtocolError, DisconnectCause.PROTOCOL),
    ],
)
async def test_failed_first_start_raises_and_reports_its_cause(
    station: FakeStation,
    failure: EufySecurityError | None,
    error_type: type[EufySecurityError],
    cause: DisconnectCause,
) -> None:
    wrong = FakeStation().ecc_private_key_hex

    async def provider(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        if failure is not None:
            raise failure
        return P2PCredentials(SYNTHETIC.account_id, "user", wrong)

    session = StationSession(
        SYNTHETIC.station_sn, provider, host="127.0.0.1", port=station.discovery_port
    )
    events: list[Event] = []
    session.subscribe(events.append)
    try:
        with pytest.raises(error_type) as info:
            await session.async_start()
        await asyncio.sleep(0.3)  # the supervisor's first retry fails the same way
    finally:
        await session.async_close()
    changes = [e for e in events if isinstance(e, ConnectionChanged)]
    assert [(e.connected, e.cause) for e in changes] == [(False, cause)]
    assert changes[0].error is info.value
    assert session.last_error is not None


async def test_ecb_scalar_success_and_rejection(station: FakeStation) -> None:
    session = make_session(station, Provider(station))
    try:
        await session.async_send_ecb_scalar(1250, 30, channel=0)
        await session.async_send_ecb_scalar(1253, 1)
    finally:
        await session.async_close()
    assert station.ecb_received == [(1250, 0, 30), (1253, 255, 1)]

    rejected = make_session(station, Provider(station, account_id="f" * 40))
    try:
        with pytest.raises(CommandRejectedError) as info:
            await rejected.async_send_ecb_scalar(1253, 1)
    finally:
        await rejected.async_close()
    assert info.value.code == -104


@pytest.mark.parametrize("encryption", [None, FRAME_PLAIN, FRAME_STATIC_ECB, FRAME_SESSION_ECB])
async def test_an_rsa_session_sends_ecb_scalars_and_reads_results_under_any_encryption(
    station: FakeStation, encryption: int | None
) -> None:
    """The result code is read in clear under any encryption type (None: the station's
    default, its session key), counted as a result and never as undecodable."""
    station.answer_encryption = encryption
    session = make_rsa_session(station)
    try:
        await session.async_send_ecb_scalar(1250, 30, channel=0)
        station.account_id = "f" * 40  # the next command is not the owner's
        with pytest.raises(CommandRejectedError) as info:
            await session.async_send_ecb_scalar(1253, 1)
        stats = session.stats()
    finally:
        await session.async_close()
    assert station.ecb_received == [(1250, 0, 30), (1253, 255, 1)]
    assert info.value.code == -104  # read in clear
    assert (stats.receipts_by_code, stats.dropped_undecodable) == ({"0": 1, "-104": 1}, 0)


async def test_a_string_command_is_stored_on_its_channel_and_a_foreign_one_refused(
    station: FakeStation,
) -> None:
    session = make_session(station, Provider(station))
    try:
        await session.async_send_string_command(1215, "JST-9|1.1307", channel=0)
        with pytest.raises(ValueError, match="ASCII"):
            await session.async_send_string_command(1215, "Zürich", channel=0)
    finally:
        await session.async_close()
    assert station.string_commands_received == [(1215, 0, "JST-9|1.1307")]
    assert station.params[0][1215] == "JST-9|1.1307"

    rejected = make_session(station, Provider(station, account_id="f" * 40))
    try:
        with pytest.raises(CommandRejectedError) as info:
            await rejected.async_send_string_command(1215, "GMT0|1.1000", channel=0)
    finally:
        await rejected.async_close()
    assert info.value.code == -104
    assert station.params[0][1215] == "JST-9|1.1307"


async def test_setting_without_reply_is_delivered_not_applied(station: FakeStation) -> None:
    session = make_session(station, Provider(station))
    try:
        # Past the resend point: the receipt (code 0) says the station took it.
        outcome = await session.async_send_command(
            1277, channel=0, payload={"night_sion": 1, "channel": 0}, timeout=2.0
        )
        station.reply_to_settings = True
        applied = await session.async_send_command(
            1277, channel=0, payload={"night_sion": 3, "channel": 0}
        )
    finally:
        await session.async_close()
    assert outcome is CommandOutcome.DELIVERED
    assert applied is CommandOutcome.APPLIED
    assert [o["cmd"] for o in station.received] == [1277, 1277]  # never resent


@pytest.mark.parametrize(("channel", "header"), [(0, 0), (1, 1), (STATION_CHANNEL, 0)])
async def test_a_command_names_its_device_channel_in_the_subheader(
    station: FakeStation, channel: int, header: int
) -> None:
    """Byte 2 of a 1350 command carries the device's channel; a station-wide one keeps 0."""
    station.reply_to_settings = True
    session = make_session(station, Provider(station))
    try:
        await session.async_send_command(
            1277, channel=channel, payload={"night_sion": 1, "channel": channel}
        )
    finally:
        await session.async_close()
    assert station.received_header_channels == [header]


async def test_a_late_not_handled_receipt_is_awaited_and_raised(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(session_module, "COMMAND_RECEIPT_TIMEOUT", 3.0)
    station.unhandled_commands.add(1107)
    station.rejection_delay = 1.0  # after the command's own timeout, as on the real station
    session = make_session(station, Provider(station))
    try:
        await session.async_connect()
        with (
            caplog.at_level(logging.DEBUG, logger="eufy_home_security.p2p.session"),
            pytest.raises(CommandUnsupportedError) as rejected,
        ):
            await session.async_send_command(1107, timeout=0.5)
        await session.async_get_params()
        stats = session.stats()
    finally:
        await session.async_close()
    assert (rejected.value.command, rejected.value.code) == (1107, -108)
    assert isinstance(rejected.value, CommandRejectedError)
    assert isinstance(rejected.value, UnsupportedError)
    assert [o["cmd"] for o in station.received] == [1107]  # acknowledged: never resent
    assert stats.receipts_by_code == {"-108": 1, "0": 1}  # the command's, the query's
    assert stats.dropped_undecodable == 0
    assert "failed GCM" not in caplog.text


async def test_image_and_event_history(station: FakeStation) -> None:
    station.images["/zx/thumb.jpg"] = b"\xff\xd8jpeg-bytes\xff\xd9"
    station.images["/zx/crop.jpg"] = b"v2_eufysecurity" + b"\x00" * 16
    station.rows = [{"device_sn": SYNTHETIC.camera_sn, "thumb_path": "/zx/thumb.jpg"}]
    session = make_session(station, Provider(station))
    try:
        image = await session.async_fetch_image("/zx/thumb.jpg")
        still = await session.async_fetch_still("/zx/crop.jpg")
        rows = await session.async_query_events([SYNTHETIC.camera_sn], "20260101", "20260102")
    finally:
        await session.async_close()
    assert image == station.images["/zx/thumb.jpg"]
    assert still == Still("/zx/crop.jpg", station.images["/zx/crop.jpg"], StillFormat.V2)
    assert not still.is_image
    assert rows == station.rows
    assert session.stats().stills_by_format == {"jpeg": 1, "v2_eufysecurity": 1}


@pytest.mark.parametrize("echo_file", [True, False])
async def test_late_still_reply_never_answers_the_next_request(
    station: FakeStation, echo_file: bool
) -> None:
    station.images["/zx/a.jpg"] = b"\xff\xd8image-A"
    station.images["/zx/b.jpg"] = b"\xff\xd8image-B"
    station.image_reply_delay["/zx/a.jpg"] = 0.5  # after the client gave up on it
    if not echo_file:
        station.image_reply_file = {"/zx/a.jpg": None, "/zx/b.jpg": None}
    session = make_session(station, Provider(station))
    try:
        with pytest.raises(DeviceTimeoutError):
            await session.async_fetch_still("/zx/a.jpg", timeout=0.2)
        await asyncio.sleep(0.5)  # A's reply arrives with nothing outstanding
        late_before_b = session.still_late_replies
        station.image_reply_delay["/zx/b.jpg"] = 0.1
        b = await session.async_fetch_still("/zx/b.jpg")
    finally:
        await session.async_close()
    assert late_before_b == 1
    assert b.data == station.images["/zx/b.jpg"]


@pytest.mark.parametrize("echo_file", [True, False])  # bound by its path, or by timing alone
async def test_late_still_reply_arriving_during_the_next_request_is_discarded(
    station: FakeStation, echo_file: bool
) -> None:
    """A stale reply must never be served as the next request's image."""
    assert session_module.BIND_STILL_REPLY_TO_PATH
    station.images["/zx/a.jpg"] = b"\xff\xd8image-A"
    station.images["/zx/b.jpg"] = b"\xff\xd8image-B"
    if not echo_file:
        station.image_reply_file = {"/zx/a.jpg": None, "/zx/b.jpg": None}
    station.image_reply_delay = {"/zx/a.jpg": 0.4, "/zx/b.jpg": 0.5}
    session = make_session(station, Provider(station))
    try:
        with pytest.raises(DeviceTimeoutError):
            await session.async_fetch_still("/zx/a.jpg", timeout=0.2)
        b = await session.async_fetch_still("/zx/b.jpg")  # A's reply lands first
    finally:
        await session.async_close()
    assert b.data == station.images["/zx/b.jpg"]
    assert session.still_late_replies == 1


async def test_a_retry_of_a_timed_out_path_gets_its_own_reply(
    station: FakeStation,
) -> None:
    """One slow fetch must not become a run of failures.

    A timed-out fetch leaves the path owed. Without superseding that entry, the retry's
    own reply is taken for the late answer to its predecessor and discarded — and the
    retry then owes the path again, so every attempt fails in turn until the window
    expires.
    """
    station.images["/zx/a.jpg"] = b"\xff\xd8image-A"
    station.image_reply_delay["/zx/a.jpg"] = 0.5
    session = make_session(station, Provider(station))
    try:
        with pytest.raises(DeviceTimeoutError):
            await session.async_fetch_still("/zx/a.jpg", timeout=0.2)
        station.image_reply_delay["/zx/a.jpg"] = 0.05  # the station is responsive again
        again = await session.async_fetch_still("/zx/a.jpg", timeout=2.0)
    finally:
        await session.async_close()
    assert again.data == station.images["/zx/a.jpg"], "the retry got its own reply"


async def test_a_live_fetch_outranks_the_late_reply_bookkeeping(
    station: FakeStation,
) -> None:
    """A retry must not be starved by the entry its own timeout left behind.

    A station that echoes ``file`` — which real hardware does — binds every reply to its
    path, so the only way a request can lose its answer is through its own stale owed
    entry. Dropping that entry before sending is what keeps a retry working.
    """
    station.images["/zx/a.jpg"] = b"\xff\xd8image-A"
    station.images["/zx/b.jpg"] = b"\xff\xd8image-B"
    station.image_reply_delay["/zx/a.jpg"] = 0.5
    session = make_session(station, Provider(station))
    try:
        with pytest.raises(DeviceTimeoutError):
            await session.async_fetch_still("/zx/a.jpg", timeout=0.2)
        station.image_reply_delay["/zx/b.jpg"] = 0.1
        b = await session.async_fetch_still("/zx/b.jpg", timeout=2.0)
    finally:
        await session.async_close()
    assert b.data == station.images["/zx/b.jpg"], "B got B's image, not A's"


async def test_an_abandoned_media_stream_is_reclaimed(station: FakeStation) -> None:
    """A stream nobody reads must not hold the session's one media slot for good.

    Its deadlines are evaluated inside ``__anext__``, so ``async for ... : break``
    without closing must still free the slot; otherwise the camera sends until the
    process ends and every later open raises "already open".
    """
    session = make_session(station, Provider(station))
    try:
        stream = await session.async_open_live(0, first_frame_timeout=3.0, idle_timeout=0.3)
        async for _frame in stream:
            break  # abandoned: no aclose(), no __aexit__
        assert session._media is not None, "held while the stream is still fresh"

        # The station keeps sending, so the queue fills and every frame is dropped:
        # the deadlines never fire, and that is what marks the stream abandoned.
        async with asyncio.timeout(8):
            while not session._media._expired(time.monotonic()):
                await asyncio.sleep(0.05)

        again = await session.async_open_live(0, first_frame_timeout=3.0, idle_timeout=0.3)
        await again.aclose()  # the open reclaimed the slot rather than raising
    finally:
        await session.async_close()


async def test_the_supervisor_reclaims_an_abandoned_media_stream(
    station: FakeStation,
) -> None:
    """With no further open, a supervised session frees the slot on its own."""
    session = make_session(station, Provider(station))
    try:
        await session.async_start(probe_every=30.0, stale_after=5.0)
        stream = await session.async_open_live(0, first_frame_timeout=3.0, idle_timeout=0.3)
        async for _frame in stream:
            break
        assert session._media is not None
        async with asyncio.timeout(8):
            while session._media is not None:
                await asyncio.sleep(0.05)
    finally:
        await session.async_close()


async def test_concurrent_recipes_do_not_take_each_others_receipts(
    station: FakeStation,
) -> None:
    """A 1700 receipt must reach the recipe that earned it, and no other.

    A recipe's receipt is bound by frame type alone, and every standalone-device recipe
    is type 1700 — so two in flight could each complete or fail on the other's receipt.
    One "busy" rejection reaches its own caller only; raised into both, it would make
    ``_ptz_recipe`` retry a command the camera never rejected.
    """
    session = make_session(station, Provider(station))
    try:
        first = asyncio.create_task(session.async_run_recipe(query_preset_positions(), channel=0))
        second = asyncio.create_task(session.async_run_recipe(query_preset_positions(), channel=1))
        results = await asyncio.gather(first, second, return_exceptions=True)
        # Serialised, so the station handled them one after the other and each got its
        # own answer; sharing a waiter would give one of them the other's.
        sent = [body.get("commandType") for body in station.doorbell_payloads]
        assert sent.count(6034) == 2
        assert not [r for r in results if isinstance(r, CommandRejectedError)]
    finally:
        await session.async_close()


@pytest.mark.parametrize("bind", [False, True])
async def test_still_reply_file_mismatch_follows_the_binding_policy(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch, bind: bool
) -> None:
    monkeypatch.setattr(session_module, "BIND_STILL_REPLY_TO_PATH", bind)
    station.images["/zx/a.jpg"] = b"\xff\xd8image-A"
    station.image_reply_file["/zx/a.jpg"] = "zx/a.jpg"  # a normalised echo
    session = make_session(station, Provider(station))
    try:
        if bind:
            with pytest.raises(DeviceTimeoutError):
                await session.async_fetch_still("/zx/a.jpg", timeout=0.3)
        else:
            assert (await session.async_fetch_still("/zx/a.jpg")).data == b"\xff\xd8image-A"
    finally:
        await session.async_close()
    assert session.still_file_mismatches == 1


async def test_list_history_parses_records(station: FakeStation) -> None:
    station.rows = [
        {
            "record_id": 2026091400034,
            "device_sn": SYNTHETIC.camera_sn,
            "station_sn": SYNTHETIC.station_sn,
            "start_time": "2026-09-14 15:14:43",  # hygiene: ok
            "storage_type": 5,
            "thumb_path": "/zx/rec.jpg",
            "str_extra": '{"arm_mode":63,"msg_type":9,"user_name":"someone"}',
        }
    ]
    session = make_session(station, Provider(station))
    try:
        history = await session.async_list_history("20260914", "20260915")
    finally:
        await session.async_close()
    assert len(history) == 1
    rec = history[0]
    assert rec.record_id == 2026091400034
    assert rec.device_sn == SYNTHETIC.camera_sn
    assert (rec.arm_mode, rec.msg_type, rec.user_name) == (63, 9, "someone")


_HB2_SN = "T8010P2000000007"


def _history_row(day: str, counter: int) -> dict[str, Any]:
    return {
        "record_id": int(day) * 100_000 + counter,
        "device_sn": SYNTHETIC.camera_sn,
        "start_time": f"{day[:4]}-{day[4:6]}-{day[6:]} 12:{counter // 60:02d}:{counter % 60:02d}",
        "storage_path": f"/zx/{day}/{counter}.zxvideo",
    }


async def test_history_pages_every_day_of_the_window(station: FakeStation) -> None:
    """A window of two days lists the rows of both, newest first.

    The station answers each query with its start day only, a page at a time, and
    appends the whole person library to every page.
    """
    yesterday = [_history_row("20260915", n) for n in range(22, 36)]  # hygiene: ok
    today = [_history_row("20260916", n) for n in range(21, 131) if n % 7]  # gaps in ids
    station.rows = [*yesterday, *today]  # hygiene: ok
    station.history_side_tables = {
        "person_basic_info": [{"person_id": n, "name": f"stranger{n}"} for n in range(49)]
    }
    session = make_session(station, Provider(station))
    try:
        history = await session.async_list_history("20260915", "20260916", page_size=30)
        pages = len(station.history_queries)
        capped = await session.async_list_history("20260916", count=40)
        assert len(station.history_queries) == pages + 1  # stops paging at the cap
    finally:
        await session.async_close()
    newest_first = sorted(
        [*yesterday, *today],  # hygiene: ok
        key=lambda r: r["record_id"],
        reverse=True,
    )
    assert [r.record_id for r in history] == [r["record_id"] for r in newest_first]
    days = [
        (q["start_date"], q["end_date"], q["start_id"], q["count"]) for q in station.history_queries
    ]
    assert days[0] == ("20260916", "20260917", 0, 30)  # today first, the app's window
    assert days[1][:2] == ("20260916", "20260917")
    assert days[1][2] == history[29].record_id  # the next page starts at the last one seen
    assert ("20260915", "20260916", 0, 30) in days
    assert [r.record_id for r in capped] == [r["record_id"] for r in newest_first[:40]]


async def test_a_station_outside_the_homebase_3_family_is_paged_by_start_time() -> None:
    """A HomeBase 2 gets the app's 10017 query: the filters at their "all" values, no
    ids, a page of 20, and the next page from the oldest start_time of the last;
    ``before`` keeps the rows older than its record from the day's newest."""
    station = FakeStation(serial=_HB2_SN)
    await station.start()
    yesterday = [_history_row("20260915", n) for n in range(22, 36)]  # hygiene: ok
    today = [_history_row("20260916", n) for n in range(21, 71) if n % 7]  # gaps in ids
    station.rows = [*yesterday, *today]  # hygiene: ok
    session = StationSession(
        _HB2_SN, Provider(station), host="127.0.0.1", port=station.discovery_port
    )
    try:
        history = await session.async_list_history("20260915", "20260916")
        pages = len(station.history_queries)
        older = await session.async_list_history("20260916", before=today[10]["record_id"])
    finally:
        await session.async_close()
        station.stop()
    newest_first = sorted(
        [*yesterday, *today],  # hygiene: ok
        key=lambda r: r["record_id"],
        reverse=True,
    )
    assert [r.record_id for r in history] == [r["record_id"] for r in newest_first]
    first = station.history_queries[0]
    assert first == {
        "count": 20,
        "start_date": "20260916",
        "end_date": "20260917",
        "start_time": "0",
        "event_type": 0,
        "ai_type": 0,
        "storage_cloud": -1,
        "trigger_type": 0,
        "detection_type": 0,
        "flag": 0,
    }
    second = station.history_queries[1]
    assert second["start_date"] == "20260916"
    assert history[19].start_time is not None
    assert second["start_time"] == history_cursor_time(history[19].start_time)
    assert pages == 3 + 1  # 43 rows in 20, 20, 3; 14 rows in one page  # hygiene: ok
    assert [r.record_id for r in older] == [r["record_id"] for r in today[9::-1]]
    assert all(q["start_time"] == "0" for q in station.history_queries[pages : pages + 1])


def _timeless_row(counter: int) -> dict[str, Any]:
    return {**_history_row("20260916", counter), "start_time": ""}


def _repeating_rows() -> list[dict[str, Any]]:
    """Rows a start_time cursor cannot move past: one timed row among timeless ones,
    so the second page starts with the first page's first row."""
    rows = [_timeless_row(n) for n in range(1, 31)]
    rows[24] = _history_row("20260916", 25)  # in the first page of 20, not its first row
    return rows


@pytest.mark.parametrize(
    ("serial", "rows", "kwargs", "expected"),
    [
        pytest.param(
            _HB2_SN,
            [_history_row("20260916", n) for n in range(1, 26)],
            {"keep": lambda r: r.record_id % 2 == 0},
            [
                "page 1: 20 row(s), 20 new, 10 kept; asking the next",
                "page 2: 5 row(s), 5 new, 2 kept; last page (short page)",
            ],
            id="short-page",
        ),
        pytest.param(
            _HB2_SN,
            [_history_row("20260916", n) for n in range(1, 26)],
            {"count": 5},
            ["page 1: 20 row(s), 20 new, 20 kept; last page (enough rows)"],
            id="enough-rows",
        ),
        pytest.param(
            _HB2_SN,
            [_timeless_row(n) for n in range(1, 21)],
            {},
            ["page 1: 20 row(s), 20 new, 20 kept; last page (no start_time to page from)"],
            id="no-start-time",
        ),
        pytest.param(
            _HB2_SN,
            _repeating_rows(),
            {},
            [
                "page 1: 20 row(s), 20 new, 20 kept; asking the next",
                "page 2: 20 row(s), 1 new, 1 kept; last page (first row repeats)",
            ],
            id="first-row-repeats",
        ),
        pytest.param(
            SYNTHETIC.station_sn,
            [{"device_sn": SYNTHETIC.camera_sn} for _ in range(30)],
            {"page_size": 30},
            ["page 1: 30 row(s), 30 new, 30 kept; last page (no new cursor)"],
            id="no-new-cursor",
        ),
    ],
)
async def test_each_history_page_is_logged_with_its_counts_and_why_paging_stops(
    caplog: pytest.LogCaptureFixture,
    serial: str,
    rows: list[dict[str, Any]],
    kwargs: dict[str, Any],
    expected: list[str],
) -> None:
    """One DEBUG line per answered page: rows, new and kept counts, and whether the
    day goes on or why it ends; no record ids, times or paths."""
    station = FakeStation(serial=serial)
    await station.start()
    station.rows = rows
    session = StationSession(
        serial, Provider(station), host="127.0.0.1", port=station.discovery_port
    )
    try:
        with caplog.at_level(logging.DEBUG, logger="eufy_home_security.p2p.session"):
            await session.async_list_history("20260916", **kwargs)
    finally:
        await session.async_close()
        station.stop()
    marker = ": history of 2026-09-16, page"  # hygiene: ok
    lines = [r.getMessage() for r in caplog.records if marker in r.getMessage()]
    assert [line.split(", ", 1)[1] for line in lines] == expected
    assert len(station.history_queries) == len(expected)
    for needle in ("/zx/", "12:", "202609160"):  # a path, a time, a record id
        assert not [line for line in lines if needle in line]


@pytest.mark.parametrize(
    ("start", "end", "kwargs", "match"),
    [
        ("2026-09-15", "20260916", {}, "YYYYMMDD"),  # hygiene: ok
        ("20260916", "20260915", {}, "after end date"),
        ("20260915", "20261301", {}, "month must be"),
        ("20260915", None, {"page_size": 1}, "page_size"),
        ("20260915", None, {"count": 0}, "count"),
        ("20260915", None, {"before": 42}, "no day"),
    ],
)
async def test_history_arguments_are_checked_before_sending(
    station: FakeStation, start: str, end: str | None, kwargs: dict[str, Any], match: str
) -> None:
    session = make_session(station, Provider(station))
    try:
        with pytest.raises(ValueError, match=match):
            await session.async_list_history(start, end, **kwargs)
    finally:
        await session.async_close()
    assert station.history_queries == []


async def test_a_history_record_id_without_a_day_is_refused(station: FakeStation) -> None:
    session = make_session(station, Provider(station))
    try:
        with pytest.raises(ValueError, match="carries no day"):
            await session.async_history_record(42)
        assert station.history_queries == []
    finally:
        await session.async_close()


async def test_storage_is_read_kept_and_announced_on_change(station: FakeStation) -> None:
    session = make_session(station, Provider(station))
    changes: list[StorageChanged] = []
    session.subscribe(lambda e: changes.append(e) if isinstance(e, StorageChanged) else None)
    try:
        before = session.storage
        info = await session.async_get_storage()
        request = next(obj for obj in station.received if obj["cmd"] == 1307)
        assert request["payload"] == {"cmd": 11001, "version": 0, "mChannel": 255}
        disk = info.disk
        assert disk is not None
        assert disk.used_mib == 14500
        assert (before, session.storage) == (None, info)
        assert [c.storage for c in changes] == [info]
        assert changes[0].station_sn == SYNTHETIC.station_sn

        station.send_storage()  # another client's query: the same record
        await session.async_get_storage()  # the answer that proves the push was handled
        assert len(changes) == 1

        station.storage["hdd_info"]["parted_status"] = 2  # a format started elsewhere
        station.send_storage()
        await wait_until(lambda: len(changes) == 2)
        assert session.storage is not None
        assert session.storage.formatting

        station.storage["hdd_info"]["parted_status"] = 1
        station.send_json(
            FrameType.NOTIFY_PAYLOAD,
            {"cmd": 1307, "payload": {"cmd": 11001, "body": station.storage}},
            cipher=FrameCipher.ECB,  # forgeable: never station state
        )
        await session.async_get_params()
        assert session.storage.formatting
        assert len(changes) == 2
    finally:
        await session.async_close()


async def test_storage_answer_is_taken_under_either_cipher(station: FakeStation) -> None:
    session = make_session(station, Provider(station))
    try:
        for cipher in (FrameCipher.ECB, FrameCipher.GCM):
            station.storage_reply_cipher = cipher
            info = await session.async_get_storage()
            assert info.disk is not None
            assert session.storage == info
    finally:
        await session.async_close()


async def test_a_reply_queued_while_the_event_loop_was_blocked_is_still_taken(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A loop blocked past the deadline fires the timer late, ahead of the replies that
    arrived meanwhile; the request waits a grace period for them instead of failing."""
    timeout = 0.2
    sent = station.send_storage

    def answer_then_block(*, cipher: int = FrameCipher.GCM) -> None:
        for _ in range(4):  # frames ahead of the record, one datagram each
            station.send_receipt(FrameType.CMD_TRANSFER, 0)
        sent(cipher=cipher)
        time.sleep(timeout + 0.2)  # another component holds the loop past the deadline

    monkeypatch.setattr(station, "send_storage", answer_then_block)
    session = make_session(station, Provider(station))
    try:
        await session.async_connect()
        info = await session.async_get_storage(timeout=timeout)
    finally:
        await session.async_close()
    assert info.disk is not None


async def test_a_loop_held_twice_past_the_deadline_still_takes_the_reply(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Each stretch the loop is held moves the deadline out, not only the first."""
    timeout = 0.2
    sent = station.send_storage
    loop = asyncio.get_running_loop()

    def answer_then_block_twice(*, cipher: int = FrameCipher.GCM) -> None:
        for _ in range(4):
            station.send_receipt(FrameType.CMD_TRANSFER, 0)
        sent(cipher=cipher)
        time.sleep(timeout + 0.1)
        loop.call_soon(time.sleep, 0.3)  # held again before the queued reply is read

    monkeypatch.setattr(station, "send_storage", answer_then_block_twice)
    session = make_session(station, Provider(station))
    try:
        await session.async_connect()
        info = await session.async_get_storage(timeout=timeout)
    finally:
        await session.async_close()
    assert info.disk is not None


async def test_a_loop_held_before_a_resend_still_takes_the_parameter_dump(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch, short_settle: None
) -> None:
    """The held-loop credit covers a request's resend phase too: a dump queued while the
    loop was held there past the whole timeout is still taken, and not asked for twice."""
    monkeypatch.setattr(session_module, "PARAM_QUERY_RESEND_AFTER", 0.1)
    timeout = 0.2
    sent = station.send_param_dump

    def answer_then_block(*, cipher: int = FrameCipher.GCM) -> None:
        for _ in range(4):
            station.send_receipt(FrameType.CMD_TRANSFER, 0)
        sent(cipher=cipher)
        time.sleep(timeout + 0.2)

    session = make_session(station, Provider(station))
    try:
        await session.async_connect()
        monkeypatch.setattr(station, "send_param_dump", answer_then_block)
        dump = await session.async_get_params(timeout=timeout)
    finally:
        await session.async_close()
    assert dump.station == station.params[STATION_CHANNEL]
    assert station.param_queries == 1


async def test_a_loop_held_before_a_command_resend_still_takes_the_result(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A command's result queued while the loop was held in its first wait is taken as
    APPLIED, and the command is not resent."""
    station.reply_to_settings = True
    timeout = 0.2
    answer = station._on_command

    def answer_then_block(obj: dict[str, Any], subheader: bytes) -> None:
        for _ in range(4):
            station.send_receipt(FrameType.PARAM_NOTIFY, 0, dev_type=1)
        answer(obj, subheader)
        time.sleep(timeout + 0.2)

    monkeypatch.setattr(station, "_on_command", answer_then_block)
    session = make_session(station, Provider(station))
    try:
        await session.async_connect()
        outcome = await session.async_send_command(
            1277, channel=0, payload={"night_sion": 1, "channel": 0}, timeout=timeout
        )
    finally:
        await session.async_close()
    assert outcome is CommandOutcome.APPLIED
    assert [o["cmd"] for o in station.received] == [1277]


async def test_a_wait_entered_past_its_deadline_still_reads_what_is_queued(
    station: FakeStation,
) -> None:
    """A wait that starts after its deadline yields to the loop once before giving up."""
    session = make_session(station, Provider(station))
    future: asyncio.Future[object] = asyncio.get_running_loop().create_future()
    asyncio.get_running_loop().call_soon(future.set_result, True)
    assert await session._wait_until(future, time.monotonic() - 1.0, "test")


async def test_storage_rejection_and_silence_are_typed_errors(station: FakeStation) -> None:
    station.storage_reply_code = -104
    session = make_session(station, Provider(station))
    try:
        with pytest.raises(CommandRejectedError) as rejected:
            await session.async_get_storage()
        assert (rejected.value.command, rejected.value.code) == (1307, -104)
        station.storage_reply_code = 0
        station.send_json(
            FrameType.NOTIFY_PAYLOAD, {"cmd": 1307, "payload": {"cmd": 11001, "mIntRet": 0}}
        )
        await session.async_get_params()
        assert session.storage is None  # a record without a body is not state
        station.stop()
        with pytest.raises(DeviceTimeoutError):
            await session.async_get_storage(timeout=0.3)
    finally:
        await session.async_close()


@pytest.mark.parametrize("command", [1307, 55000])
async def test_a_refused_storage_query_fails_at_its_receipt(
    station: FakeStation, command: int
) -> None:
    """A station that refuses a storage query sends receipt -1 and no record: the
    query fails at once with that code instead of waiting out its timeout."""
    station.refused_commands = {command: -1}
    session = make_session(station, Provider(station))
    read = session.async_get_storage if command == 1307 else session.async_get_hub_storage
    try:
        await session.async_connect()
        started = time.monotonic()
        with pytest.raises(CommandRejectedError) as rejected:
            await read(timeout=5)
        assert time.monotonic() - started < 2
    finally:
        await session.async_close()
    assert (rejected.value.command, rejected.value.code) == (command, -1)


async def test_a_hub_storage_read_takes_only_its_own_reply(station: FakeStation) -> None:
    """A 1307 record arriving while 55000 is in flight is not its answer; the 55000
    reply is, and a non-zero ``mIntRet`` in it is a rejection."""
    session = make_session(station, Provider(station))
    try:
        await session.async_connect()
        station.send_storage()
        with pytest.raises(DeviceTimeoutError):
            await session.async_get_hub_storage(timeout=0.3)
        station.hub_storage = synthetic_hub_storage()
        info = await session.async_get_hub_storage(timeout=2)
        assert info.emmc is not None
        assert session.storage == info
        station.hub_storage = {**synthetic_hub_storage(), "mIntRet": -3}
        with pytest.raises(CommandRejectedError) as rejected:
            await session.async_get_hub_storage(timeout=2)
    finally:
        await session.async_close()
    assert (rejected.value.command, rejected.value.code) == (55000, -3)
    assert not isinstance(rejected.value, CommandUnsupportedError)


async def test_pushes_become_events(station: FakeStation) -> None:
    session = make_session(station, Provider(station))
    events: list[Event] = []
    session.subscribe(events.append)
    try:
        await session.async_get_params()
        station.push_camera_event()
        station.params[0][1101] = "86"
        station.send_param_dump()
        await wait_until(lambda: any(isinstance(e, ParamChanged) for e in events))
        await wait_until(lambda: any(isinstance(e, SecurityEvent) for e in events))
    finally:
        await session.async_close()
    push = next(e for e in events if isinstance(e, SecurityEvent))
    assert push.source is EventSource.P2P
    assert push.device_sn == SYNTHETIC.camera_sn
    assert push.thumb_path == "/zx/thumb.jpg"
    change = next(e for e in events if isinstance(e, ParamChanged))
    assert (change.channel, change.param_id, change.old, change.new) == (0, 1101, "87", "86")


@pytest.mark.parametrize(
    ("cipher", "authenticated"), [(FrameCipher.GCM, True), (FrameCipher.ECB, False)]
)
async def test_camera_push_carries_its_frame_cipher(
    station: FakeStation, cipher: FrameCipher, authenticated: bool
) -> None:
    session = make_session(station, Provider(station))
    events: list[Event] = []
    session.subscribe(events.append)
    inner = {"msg_type": 18, "event_type": 3102, "device_sn": SYNTHETIC.camera_sn}
    try:
        await session.async_get_params()  # a session key exists
        station.send_json(
            FrameType.NOTIFY_PAYLOAD, {"cmd": 2037, "payload": json.dumps(inner)}, cipher=cipher
        )
        await wait_until(lambda: any(isinstance(e, SecurityEvent) for e in events))
    finally:
        await session.async_close()
    push = next(e for e in events if isinstance(e, SecurityEvent))
    assert push.frame_cipher is cipher  # an ECB push is delivered, not refused
    assert push.authenticated is authenticated


async def test_stats_count_pushes_by_type_and_cipher(station: FakeStation) -> None:
    session = make_session(station, Provider(station))
    assert session.stats().seconds_since_last_event is None
    try:
        await session.async_get_params()
        station.push_camera_event(cipher=FrameCipher.GCM)
        station.push_camera_event(cipher=FrameCipher.ECB)
        await wait_until(lambda: session.stats().events_by_type.get("18:3102") == 2)
        stats = session.stats()
    finally:
        await session.async_close()
    assert stats.frames_by_cipher == {"gcm": 1, "ecb": 1}
    assert stats.seconds_since_last_event is not None
    assert stats.seconds_since_last_probe is not None
    assert (stats.dropped_undecodable, stats.ecb_state_refused) == (0, 0)
    assert stats.state_frames_by_encryption == {"gcm": 2}  # the dump, no push
    assert stats.state_authenticated is True


OTHER_ACCOUNT_ID = "fedcba9876543210fedcba9876543210fedcba98"


def push_stamped(
    station: FakeStation,
    accounts: list[str],
    *,
    event_type: int = 3102,
    cipher: FrameCipher = FrameCipher.GCM,
) -> None:
    """A camera push whose ``rec_content`` records carry ``accounts``."""
    inner = {
        "msg_type": 18,
        "event_type": event_type,
        "device_sn": SYNTHETIC.camera_sn,
        "trigger_time": 1_700_000_000_000,
        "rec_content": [{"device_sn": SYNTHETIC.camera_sn, "account": a} for a in accounts],
    }
    station.send_json(
        FrameType.NOTIFY_PAYLOAD, {"cmd": 2037, "payload": json.dumps(inner)}, cipher=cipher
    )


def _count(events: list[Event], kind: type, event_type: int | None = None) -> int:
    return sum(
        1
        for e in events
        if isinstance(e, kind)
        and (event_type is None or getattr(e, "event_type", None) == event_type)
    )


async def test_a_foreign_account_stamp_is_reported_once_per_connection(
    station: FakeStation, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger="eufy_home_security")
    session = make_session(station, Provider(station))
    events: list[Event] = []
    session.subscribe(events.append)
    try:
        await session.async_get_params()
        push_stamped(station, [OTHER_ACCOUNT_ID])
        push_stamped(station, [OTHER_ACCOUNT_ID])
        push_stamped(station, [SYNTHETIC.account_id], event_type=3107)  # sentinel
        await wait_until(lambda: _count(events, SecurityEvent, 3107) == 1)
        assert _count(events, AccountMismatch) == 1
        station.send_close()
        await wait_until(lambda: not session.connected)
        await session.async_get_params()
        push_stamped(station, [OTHER_ACCOUNT_ID])
        push_stamped(station, [SYNTHETIC.account_id], event_type=3107)
        await wait_until(lambda: _count(events, SecurityEvent, 3107) == 2)
    finally:
        await session.async_close()
    mismatches = [e for e in events if isinstance(e, AccountMismatch)]
    assert mismatches == [AccountMismatch(station_sn=SYNTHETIC.station_sn)] * 2
    assert OTHER_ACCOUNT_ID not in caplog.text
    assert SYNTHETIC.account_id not in caplog.text


@pytest.mark.parametrize(
    ("stamps", "cipher"),
    [
        ([SYNTHETIC.account_id.upper()], FrameCipher.GCM),  # ids compare case-insensitively
        ([OTHER_ACCOUNT_ID, SYNTHETIC.account_id], FrameCipher.GCM),  # one stamp is the session's
        ([], FrameCipher.GCM),  # nothing stamped
        ([OTHER_ACCOUNT_ID], FrameCipher.ECB),  # forgeable by anyone on the LAN
    ],
)
async def test_no_account_mismatch_without_an_authenticated_foreign_stamp(
    station: FakeStation, stamps: list[str], cipher: FrameCipher
) -> None:
    session = make_session(station, Provider(station))
    events: list[Event] = []
    session.subscribe(events.append)
    try:
        await session.async_get_params()
        push_stamped(station, stamps, cipher=cipher)
        push_stamped(station, [SYNTHETIC.account_id], event_type=3107)
        await wait_until(lambda: _count(events, SecurityEvent, 3107) == 1)
    finally:
        await session.async_close()
    assert _count(events, SecurityEvent, 3102) == 1
    assert _count(events, AccountMismatch) == 0


async def test_station_close_is_reported_and_next_request_reconnects(station: FakeStation) -> None:
    session = make_session(station, Provider(station))
    events: list[Event] = []
    session.subscribe(events.append)
    try:
        await session.async_get_params()  # announced: a parameter read answered
        station.send_close()
        await wait_until(lambda: not session.connected)
        await session.async_get_params()
        stats = session.stats()
    finally:
        await session.async_close()
    # The counters survive the reconnect; the error name outlives the recovery.
    assert (stats.connected, stats.connects, stats.reconnects) == (True, 2, 1)
    assert stats.last_error == "StationUnreachableError"
    assert session.last_error is None
    changes = [e for e in events if isinstance(e, ConnectionChanged)]
    assert [(e.connected, e.cause) for e in changes] == [
        (True, None),
        (False, DisconnectCause.STATION_CLOSED),
        (True, None),
        (False, DisconnectCause.CLOSED),
    ]
    assert changes[1].reason == "the station closed the session"
    assert station.conn_inits == 2


async def test_a_silent_link_is_reported_apart_from_a_station_close(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A held session whose station stops sending is LINK_SILENT, not STATION_CLOSED."""
    monkeypatch.setattr(transport_module, "SILENCE_TIMEOUT", 0.5)
    monkeypatch.setattr(transport_module, "KEEPALIVE_INTERVAL", 0.1)
    session = make_session(station, Provider(station))
    events: list[Event] = []
    session.subscribe(events.append)
    try:
        await session.async_get_params()
        station.stop()
        await wait_until(lambda: not session.connected)
    finally:
        await session.async_close()
    down = [e for e in events if isinstance(e, ConnectionChanged) and not e.connected]
    assert down[0].cause is DisconnectCause.LINK_SILENT
    assert down[0].reason.startswith("no datagram from the station for")
    assert isinstance(down[0].error, StationUnreachableError)


async def test_lost_drw_is_retransmitted(station: FakeStation) -> None:
    session = make_session(station, Provider(station))
    station.drop_first_drw = True
    try:
        await session.async_connect()  # the CONN_INIT itself is the dropped chunk
    finally:
        await session.async_close()
    assert station.conn_inits == 1


async def test_station_off_at_start_is_reported_once_per_outage_and_picked_up_later(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(session_module, "DISCOVERY_ATTEMPTS", 1)
    monkeypatch.setattr(session_module, "DISCOVERY_TIMEOUT", 0.3)
    monkeypatch.setattr(session_module, "RECONNECT_BACKOFF", (0.2,))

    fake = FakeStation()
    await fake.start()
    fake.ignore_searches = 10**6  # "off": never answers discovery
    provider = Provider(fake)
    session = make_session(fake, provider)
    events: list[Event] = []
    session.subscribe(events.append)
    attempts = 0
    establish = session._establish

    async def counted(creds: P2PCredentials | None) -> P2PCredentials:
        nonlocal attempts
        attempts += 1
        return await establish(creds)

    monkeypatch.setattr(session, "_establish", counted)

    def changes() -> list[tuple[bool, DisconnectCause | None]]:
        return [(e.connected, e.cause) for e in events if isinstance(e, ConnectionChanged)]

    try:
        with pytest.raises(StationUnreachableError):
            await session.async_start()
        assert session._supervisor is not None
        await wait_until(lambda: attempts >= 3, timeout=6.0)  # retried
        first = changes()
        assert first == [(False, DisconnectCause.UNREACHABLE)]
        # the property is read into a local: an isinstance() on it would narrow it for
        # the rest of the function and make the "cleared" assert below look unreachable.
        outage_error = session.last_error

        fake.ignore_searches = 0  # the station comes online
        await wait_until(lambda: session.announced, timeout=6.0)
        cleared = session.last_error

        fake.ignore_searches = 10**6  # and goes off again: a new outage
        fake.send_close()
        await wait_until(lambda: len(changes()) >= 4, timeout=6.0)
    finally:
        await session.async_close()
        fake.stop()
    outages = changes()
    assert isinstance(outage_error, StationUnreachableError)
    assert cleared is None  # the reconnect cleared the outage
    assert outages == [
        (False, DisconnectCause.UNREACHABLE),
        (True, None),
        (False, DisconnectCause.STATION_CLOSED),
        (False, DisconnectCause.UNREACHABLE),
    ]


async def test_probe_schedule_ignores_media_traffic(station: FakeStation) -> None:
    session = make_session(station, Provider(station))
    try:
        await session.async_start(probe_every=0.5, stale_after=5.0)
        async with await session.async_open_live(0) as stream:
            assert (await anext(stream)).is_keyframe
            before = station.param_queries
            await asyncio.sleep(3.5)
            during = station.param_queries - before
    finally:
        await session.async_close()
    assert during >= 2


async def test_unanswered_probes_back_off_without_flapping(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(session_module, "RECONNECT_BACKOFF", (0.5, 60.0))
    session = make_session(station, Provider(station))
    events: list[Event] = []
    session.subscribe(events.append)
    try:
        await session.async_start(probe_every=0.2, stale_after=0.3)
        station.answer_params = False  # the link punches and handshakes; nothing answers
        await asyncio.sleep(3.0)
    finally:
        await session.async_close()
    assert [(e.connected, e.cause) for e in events if isinstance(e, ConnectionChanged)] == [
        (True, None),
        (False, DisconnectCause.PROBE_UNANSWERED),
    ]
    assert station.conn_inits <= 3  # one reconnect, then a long backoff — not a loop


async def test_discovery_reply_from_another_station_is_ignored(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Every station answers a broadcast; a session only adopts the reply carrying its own DID."""
    monkeypatch.setattr(session_module, "DISCOVERY_ATTEMPTS", 1)
    monkeypatch.setattr(session_module, "DISCOVERY_TIMEOUT", 0.2)
    other = StationSession(
        SYNTHETIC.station_sn,
        Provider(station),
        host="127.0.0.1",
        port=station.discovery_port,
        did="EUPRAMA-654321-ZZZZZ",
    )
    with pytest.raises(StationUnreachableError):
        await other.async_connect()
    await other.async_close()

    mine = StationSession(
        SYNTHETIC.station_sn,
        Provider(station),
        host="127.0.0.1",
        port=station.discovery_port,
        did=SYNTHETIC.did,
    )
    try:
        await mine.async_connect()
        assert mine.connected
    finally:
        await mine.async_close()


# ── media ────────────────────────────────────────────────────────────────────


def _video(frames: list[MediaFrame]) -> list[MediaFrame]:
    return [f for f in frames if f.kind is MediaKind.VIDEO]


@pytest.mark.parametrize("channel", [0, 1])
async def test_live_stream_starts_at_a_keyframe_and_stops_on_close(
    station: FakeStation, channel: int
) -> None:
    session = make_session(station, Provider(station))
    try:
        frames: list[MediaFrame] = []
        async with await session.async_open_live(channel) as stream:
            async for frame in stream:
                frames.append(frame)
                if len(_video(frames)) > MEDIA_GOP:
                    break
            assert stream.other_camera_frames == 0
        video = _video(frames)
        # The P-frame sent before the first keyframe is not delivered: it cannot decode.
        assert (video[0].kind, video[0].data, video[0].is_keyframe) == (
            MediaKind.VIDEO,
            MEDIA_KEYFRAME,
            True,
        )
        assert [f.data for f in video[1:MEDIA_GOP]] == [MEDIA_PFRAME] * (MEDIA_GOP - 1)
        assert video[MEDIA_GOP].is_keyframe
        assert any(f.kind is MediaKind.AUDIO and f.data == MEDIA_AUDIO for f in frames)
        # The header fields a muxer needs ride along: codec, size and a rising clock.
        assert video[0].codec is VideoCodec.HEVC
        assert (video[0].width, video[0].height) == (MEDIA_WIDTH, MEDIA_HEIGHT)
        stamps = [f.timestamp_ms for f in video]
        assert stamps == sorted(stamps)
        assert stamps[0] > 0
        assert video[0].pts == video[0].timestamp_ms * 90

        opened = next(o for o in station.received if o["cmd"] == 1003)
        assert (opened["mChannel"], opened["mValue3"], opened["mValueStrSub"]) == (
            channel,
            1003,
            SYNTHETIC.account_id,
        )
        assert station.live_opens == [channel]

        await wait_until(lambda: station.received[-1]["cmd"] == 1004)
        assert station.received[-1]["payload"]["chn_list"] == [{"chn": channel}]
        # closing released the session for the next stream
        async with await session.async_open_live(1 - channel) as again:
            assert (await anext(again)).is_keyframe
    finally:
        await session.async_close()


# A playback ends on the station's end frame; without one, on the idle fallback.
@pytest.mark.parametrize(
    ("download", "command", "end_frame"), [(False, 1025, True), (True, 1024, False)]
)
async def test_recording_plays_to_its_end(
    station: FakeStation, download: bool, command: int, end_frame: bool
) -> None:
    if not end_frame:
        station.playback_end_delay = None
    session = make_session(station, Provider(station))
    try:
        stream = await session.async_open_recording(
            "/zx/clip.zxvideo", 1, download=download, idle_timeout=1.0
        )
        started = time.monotonic()
        frames = [frame async for frame in stream]
        assert (time.monotonic() - started < 1.0) is end_frame
        assert len(_video(frames)) == station.recording_frames
        assert stream.closed
        opened = next(o for o in station.received if o["cmd"] == command)
        assert opened["payload"]["filepath"] == "/zx/clip.zxvideo"
        assert opened["mChannel"] == 1
        await asyncio.sleep(0.1)
        assert [o["cmd"] for o in station.received] == [command]  # no stop: none works
    finally:
        await session.async_close()


async def test_an_rsa_recording_ends_on_its_clear_end_of_playback_frame(
    station: FakeStation,
) -> None:
    session = make_rsa_session(station)
    try:
        stream = await session.async_open_recording("/zx/clip.zxvideo", 1, idle_timeout=1.0)
        started = time.monotonic()
        frames = [frame async for frame in stream]
        assert time.monotonic() - started < 1.0  # ended by the frame, not the idle timeout
    finally:
        await session.async_close()
    assert len(_video(frames)) == station.recording_frames


async def test_unanswered_media_open_is_not_applied(station: FakeStation) -> None:
    session = make_session(station, Provider(station, account_id="f" * 40))
    try:
        stream = await session.async_open_live(0, first_frame_timeout=0.5)
        with pytest.raises(CommandNotAppliedError):
            await anext(stream)
        assert stream.closed
    finally:
        await session.async_close()


async def test_a_playback_end_before_the_first_keyframe_belongs_to_an_earlier_stream(
    station: FakeStation,
) -> None:
    _, rsa_key = generate_media_rsa_key()
    session = make_session(station, Provider(station))
    stream = MediaStream(
        session,
        command=1025,
        channel=0,
        decoder=MediaDecoder(rsa_key),
        stop_body=None,
        first_frame_timeout=1.0,
        idle_timeout=1.0,
    )
    session._set_media(stream)
    end = Frame(
        type=FrameType.RECORD_PLAY_CTRL,
        subheader=bytes([FrameCipher.GCM, 0, 0, 0, 0, 0]),
        payload=bytes.fromhex("0200000000"),
    )
    session._dispatch(Inbound(2, end, session))
    assert not stream.closed
    key = media_keyframe(rsa_key.public_key(), os.urandom(16))
    session._dispatch(
        Inbound(1, Frame(FrameType.VIDEO_FRAME, b"", video_record(key, keyframe=True)), session)
    )
    session._dispatch(Inbound(2, end, session))
    frames = [frame.data async for frame in stream]
    assert (stream.closed, session._media) == (True, None)
    assert frames == [MEDIA_KEYFRAME]  # queued frames first


async def test_rejected_media_open_raises_the_code(station: FakeStation) -> None:
    station.media_reply_code = -104
    session = make_session(station, Provider(station))
    try:
        stream = await session.async_open_recording("/zx/clip.zxvideo", 0)
        with pytest.raises(CommandRejectedError, match="-104"):
            await anext(stream)
    finally:
        await session.async_close()
    stats = session.stats()
    assert stats.media_opens == 1
    assert stats.media_failures_by_type == {"CommandRejectedError": 1}
    assert stats.media_failures_by_channel == {"0": {"CommandRejectedError": 1}}


async def test_a_wake_failure_receipt_fails_the_live_open_at_once(
    station: FakeStation, caplog: pytest.LogCaptureFixture
) -> None:
    """-204 on a HomeBase live open raises CameraWakeError, not the 20 s not-applied."""
    station.live_open_receipt_code = -204
    station.live_open_receipt_delay = 0.2
    session = make_session(station, Provider(station))
    caplog.set_level(logging.INFO, logger="eufy_home_security.p2p.session")
    try:
        stream = await session.async_open_live(0, first_frame_timeout=5.0)
        started = time.monotonic()
        with pytest.raises(CameraWakeError) as caught:
            await anext(stream)
        elapsed = time.monotonic() - started
        assert session._media is None  # the slot is free again
        await session.async_get_params()  # the session itself is fine
    finally:
        await session.async_close()
    assert elapsed < 2.0
    err = caught.value
    assert (err.command, err.code, err.retry_after) == (1003, -204, None)
    assert str(err).endswith("could not wake the camera (XM_WIFI_WAKEUP_FAIL)")
    assert isinstance(err, CommunicationError)
    assert not isinstance(err, StationUnreachableError)  # the station itself answered
    assert session.stats().media_failures_by_type == {"CameraWakeError": 1}
    assert any("refused for 60s" in r.message for r in caplog.records)


async def test_a_camera_that_did_not_wake_is_not_woken_again_during_the_backoff(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """Opens of that channel are refused locally, others go out; a stream clears it."""
    monkeypatch.setattr(session_module, "WAKE_BACKOFF", (0.5, 5.0))
    station.live_open_receipt_code = -204
    session = make_session(station, Provider(station))
    try:
        with pytest.raises(CameraWakeError):
            await anext(await session.async_open_live(0))
        with pytest.raises(CameraWakeError) as refused:
            await session.async_open_live(0)
        left_first = refused.value.retry_after
        assert station.live_opens == [0]  # refused without a wake

        station.live_open_receipt_code = 0
        async with await session.async_open_live(1) as other:  # another camera: sent
            assert (await anext(other)).is_keyframe

        await asyncio.sleep(0.6)  # the first backoff passed: one more attempt goes out
        station.live_open_receipt_code = -204
        with pytest.raises(CameraWakeError):
            await anext(await session.async_open_live(0, wait=True))
        left_second = session.wake_backoff_left(0)

        session.clear_wake_backoff(0)  # the owner knows better (camera back online)
        station.live_open_receipt_code = 0
        async with await session.async_open_live(0, wait=True) as stream:
            assert (await anext(stream)).is_keyframe
        cleared = session.wake_backoff_left(0)
    finally:
        await session.async_close()
    assert left_first is not None
    assert 0 < left_first <= 0.5
    assert 0.5 < left_second <= 5.0  # the second failure waits longer
    assert cleared == 0.0
    assert station.live_opens == [0, 1, 0, 0]


async def test_a_started_stream_clears_the_wake_backoff(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(session_module, "WAKE_BACKOFF", (0.3,))
    station.live_open_receipt_code = -204
    session = make_session(station, Provider(station))
    try:
        with pytest.raises(CameraWakeError):
            await anext(await session.async_open_live(0))
        await asyncio.sleep(0.35)
        station.live_open_receipt_code = 0
        async with await session.async_open_live(0, wait=True) as stream:
            assert (await anext(stream)).is_keyframe
        assert session._wake_failures == {}
    finally:
        await session.async_close()


@pytest.mark.parametrize(
    ("code", "kind", "text"),
    [
        (-108, CommandUnsupportedError, "NOT_HANDLED"),
        (-204, CameraWakeError, "could not wake the camera (XM_WIFI_WAKEUP_FAIL)"),
        (-205, CameraWakeError, "(XM_WIFI_TIMEOUT)"),
        (-114, CommandRejectedError, "command receipt DEV_BUSY"),
        (-999, CommandRejectedError, "command receipt"),
    ],
)
def test_a_command_receipt_error_names_its_code(
    code: int, kind: type[CommandRejectedError], text: str
) -> None:
    err = session_module._receipt_error(1234, code)
    assert type(err) is kind
    assert (err.command, err.code) == (1234, code)
    assert str(err).endswith(text)


async def test_one_media_stream_per_session(station: FakeStation) -> None:
    """A recording does not get an extra session: it waits for or refuses the busy slot."""
    session = make_session(station, Provider(station))
    try:
        async with await session.async_open_live(0):
            with pytest.raises(CommunicationError, match="already open"):
                await session.async_open_recording("/zx/clip.zxvideo", 1)
            with pytest.raises(CommunicationError, match=r"still open on this session after 0\.3s"):
                await session.async_open_recording(
                    "/zx/clip.zxvideo", 1, wait=True, first_frame_timeout=0.3
                )
    finally:
        await session.async_close()


async def test_waiting_open_takes_the_slot_without_blocking_commands(
    station: FakeStation,
) -> None:
    session = make_session(station, Provider(station))
    try:
        first = await session.async_open_live(0)
        assert (await anext(first)).is_keyframe
        waiting = asyncio.create_task(
            session.async_open_recording("/zx/clip.zxvideo", 1, wait=True)
        )
        await asyncio.sleep(0.1)
        started = time.monotonic()
        await session.async_get_params(expect_channels=(0,))
        elapsed = time.monotonic() - started
        assert not waiting.done()
        await first.aclose()
        async with await waiting as second:
            assert (await anext(second)).is_keyframe
    finally:
        await session.async_close()
    assert elapsed < 1.0
    assert station.opened_while_streaming == [False, False]


async def test_lost_session_ends_the_stream_with_an_error(station: FakeStation) -> None:
    session = make_session(station, Provider(station))
    try:
        stream = await session.async_open_live(0)
        assert (await anext(stream)).is_keyframe
        station.send_close()
        with pytest.raises(StationUnreachableError):
            async for _ in stream:
                pass
    finally:
        await session.async_close()


async def test_slow_reader_drops_video_until_the_next_keyframe(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(session_module, "MEDIA_QUEUE_FRAMES", 3)
    session = make_session(station, Provider(station))
    try:
        async with await session.async_open_live(0) as stream:
            await wait_until(lambda: station.media_frames_sent > 3 * MEDIA_GOP)
            buffered = [await anext(stream) for _ in range(3)]
            assert buffered[0].is_keyframe
            assert stream.dropped > 0
            later = await anext(stream)
            while later.kind is not MediaKind.VIDEO:
                later = await anext(stream)
            assert later.is_keyframe
    finally:
        await session.async_close()


async def test_stopped_recording_never_reaches_the_next_stream(station: FakeStation) -> None:
    station.recording_frames = 200  # still playing when closed: no command stops it
    session = make_session(station, Provider(station))
    try:
        recording = await session.async_open_recording("/zx/clip.zxvideo", 1)
        assert (await anext(recording)).is_keyframe
        await recording.aclose()
        assert station.streaming
        video: list[bytes] = []
        async with await session.async_open_live(0) as live:
            async for frame in live:
                if frame.kind is MediaKind.VIDEO:
                    video.append(frame.data)
                if len(video) >= 3 * MEDIA_GOP:
                    break
    finally:
        await session.async_close()
    assert station.opened_while_streaming == [False, False]  # the open waited for quiet
    assert MEDIA_RECORDING_PFRAME not in video
    assert video[0] == MEDIA_KEYFRAME


async def test_media_drain_does_not_hold_up_other_commands(station: FakeStation) -> None:
    station.recording_frames = 300  # still playing when closed: no command stops it
    station.reply_to_settings = True
    session = make_session(station, Provider(station))
    try:
        recording = await session.async_open_recording("/zx/clip.zxvideo", 1)
        assert (await anext(recording)).is_keyframe
        await recording.aclose()
        opening = asyncio.create_task(session.async_open_live(0))
        await asyncio.sleep(0.1)  # the open is draining the recording
        started = time.monotonic()
        outcome = await session.async_send_command(
            1277, channel=0, payload={"night_sion": 1, "channel": 0}
        )
        elapsed = time.monotonic() - started
        assert not opening.done()
        async with await opening as live:
            assert (await anext(live)).is_keyframe
    finally:
        await session.async_close()
    assert outcome is CommandOutcome.APPLIED
    assert elapsed < session_module.MEDIA_DRAIN_GAP
    assert station.opened_while_streaming == [False, False]


async def test_first_good_keyframe_pins_the_stream_key(
    station: FakeStation, caplog: pytest.LogCaptureFixture
) -> None:
    _, rsa_key = generate_media_rsa_key()
    _, other_key = generate_media_rsa_key()
    public = rsa_key.public_key()

    def keyframe(clear: bytes = MEDIA_KEYFRAME, to: Any = public) -> bytes:
        return video_record(media_keyframe(to, os.urandom(16), clear), keyframe=True)

    stream = MediaStream(
        make_session(station, Provider(station)),
        command=1003,
        channel=0,
        decoder=MediaDecoder(rsa_key),
        stop_body=lambda: (0, b""),
        first_frame_timeout=1.0,
        idle_timeout=1.0,
    )
    with caplog.at_level(logging.DEBUG, logger="eufy_home_security.p2p"):
        # Before the first keyframe, one not wrapped for this stream's key is another
        # stream's: wrapped to another RSA key, or decrypting to something not Annex-B.
        stream._feed(FrameType.VIDEO_FRAME, keyframe(to=other_key.public_key()))
        stream._feed(FrameType.VIDEO_FRAME, keyframe(bytes(range(256)) * 2))
        stream._feed(FrameType.VIDEO_FRAME, keyframe())  # decodes: pins its wrapped key
        stream._feed(FrameType.VIDEO_FRAME, keyframe())  # wrapped differently: another stream's
        stream._feed(FrameType.VIDEO_FRAME, video_record(MEDIA_PFRAME, keyframe=False))
    frames = [await anext(stream), await anext(stream)]
    assert [(f.kind, f.data, f.is_keyframe) for f in frames] == [
        (MediaKind.VIDEO, MEDIA_KEYFRAME, True),
        # the foreign keyframe did not re-arm the wait
        (MediaKind.VIDEO, MEDIA_PFRAME, False),
    ]
    assert not stream._frames
    assert stream.dropped == 0
    assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
    assert any("not wrapped for this stream's key" in r.getMessage() for r in caplog.records)


async def test_a_stream_whose_keyframes_never_decode_warns_at_the_first_frame_timeout(
    station: FakeStation, caplog: pytest.LogCaptureFixture
) -> None:
    _, rsa_key = generate_media_rsa_key()
    _, other_key = generate_media_rsa_key()
    stream = MediaStream(
        make_session(station, Provider(station)),
        command=1003,
        channel=0,
        decoder=MediaDecoder(rsa_key),
        stop_body=lambda: (0, b""),
        first_frame_timeout=0.2,
        idle_timeout=1.0,
    )
    foreign = media_keyframe(other_key.public_key(), os.urandom(16))
    with caplog.at_level(logging.DEBUG, logger="eufy_home_security.p2p"):
        for _ in range(3):
            stream._feed(FrameType.VIDEO_FRAME, video_record(foreign, keyframe=True))
        assert not [r for r in caplog.records if r.levelno >= logging.WARNING]
        with pytest.raises(ProtocolError, match="no keyframe decoded"):
            await anext(stream)
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert len(warnings) == 1
    assert "3 keyframe(s) not wrapped for this stream's key" in warnings[0]


async def test_a_corrupt_keyframe_with_the_pinned_key_still_warns(
    station: FakeStation, caplog: pytest.LogCaptureFixture
) -> None:
    _, rsa_key = generate_media_rsa_key()
    body = media_keyframe(rsa_key.public_key(), bytes(range(16)))
    corrupt = body[:129] + bytes(16) + body[145:]  # same wrapped key, garbled first block
    session = make_session(station, Provider(station))
    stream = MediaStream(
        session,
        command=1003,
        channel=0,
        decoder=MediaDecoder(rsa_key),
        stop_body=lambda: (0, b""),
        first_frame_timeout=1.0,
        idle_timeout=1.0,
    )
    stream._feed(FrameType.VIDEO_FRAME, video_record(body, keyframe=True, timestamp_ms=1000))
    stream._feed(FrameType.VIDEO_FRAME, video_record(MEDIA_PFRAME, keyframe=False))
    with caplog.at_level(logging.DEBUG, logger="eufy_home_security.p2p"):
        stream._feed(FrameType.VIDEO_FRAME, video_record(corrupt, keyframe=True, timestamp_ms=1960))
        stream._feed(FrameType.VIDEO_FRAME, video_record(MEDIA_PFRAME, keyframe=False))
    assert [(await anext(stream)).data for _ in range(2)] == [MEDIA_KEYFRAME, MEDIA_PFRAME]
    assert not stream._frames  # video waits for the next keyframe
    assert (stream.dropped, stream.skipped) == (0, 1)
    warnings = [r.getMessage() for r in caplog.records if r.levelno == logging.WARNING]
    assert warnings == ["undecodable media frame 0x0514: keyframe did not decrypt to Annex-B"]
    stats = session.stats()
    assert (stats.media_frames_dropped_for_reader, stats.media_frames_skipped_for_keyframe) == (
        0,
        1,
    )
    assert stats.media_pframes_without_start_code == 1  # the fake's P-frame body
    assert [(s.outcome, s.variant, s.key_flag, s.codec) for s in stats.media_first_records] == [
        ("keyframe", "none", 1, "hevc"),
        ("frame", "none", 0, "hevc"),
        ("not_annex_b", "none", 1, "hevc"),
        ("waiting_keyframe", "none", 0, "hevc"),
    ]
    rejected = stats.media_rejected_keyframe
    assert rejected is not None
    assert rejected.since_keyframe_ms == 960
    assert stats.media_first_records[0].head == MEDIA_KEYFRAME[:5].hex()
    assert stats.media_keyframes_rejected == 1
    assert rejected.gap_ms is not None
    assert rejected.gap_ms >= 0
    assert rejected == replace(
        stats.media_first_records[2],
        since_keyframe_ms=960,
        channel=0,
        gap_ms=rejected.gap_ms,
        previous_outcome="frame",
    )
    assert rejected.probe == "none"  # no layout yields a start code
    assert rejected.record_len == len(corrupt) + 22


async def test_a_keyframe_sent_in_parts_is_joined_into_one_picture(
    station: FakeStation,
) -> None:
    """A keyframe whose rest follows in keyframe-flagged records without a start code is
    delivered whole, as the app's player joins it (a HomeBase 2 camera)."""
    station.keyframe_parts = 2
    session = make_session(station, Provider(station))
    try:
        frames: list[MediaFrame] = []
        async with await session.async_open_live(0) as stream:
            async for frame in stream:
                frames.append(frame)
                if len(_video(frames)) > MEDIA_GOP:
                    break
        stats = session.stats()
    finally:
        await session.async_close()
    video = _video(frames)
    assert [f.data for f in video if f.is_keyframe] == [MEDIA_KEYFRAME] * 2
    assert [f.data for f in video[1:MEDIA_GOP]] == [MEDIA_PFRAME] * (MEDIA_GOP - 1)
    assert stats.media_keyframes_rejected == 0
    assert stats.media_keyframe_continuations >= 2
    outcomes = [s.outcome for s in stats.media_first_records]
    assert outcomes[outcomes.index("keyframe") + 1] == "continuation"


async def test_a_keyframe_no_video_record_follows_is_not_delivered(
    station: FakeStation,
) -> None:
    """The stream ends at its idle timeout without the held keyframe, as the app's
    player shows a frame only once the next one starts; a keyframe's delivery so never
    lags its arrival by more than one record."""
    _, stream, rsa_key = _rsa_stream(station, idle_timeout=0.3)
    body = media_keyframe(rsa_key.public_key(), bytes(range(16)))
    stream._feed(FrameType.VIDEO_FRAME, video_record(body, keyframe=True))
    stream._feed(FrameType.AUDIO_FRAME, audio_record(MEDIA_AUDIO))
    with pytest.raises(StopAsyncIteration):
        await anext(stream)


def _keyframe_in_two_parts(rsa_key: Any) -> tuple[bytes, bytes]:
    first, rest = media_keyframe_parts(rsa_key.public_key(), bytes(range(16)), 2)
    return (
        video_record(first, keyframe=True, timestamp_ms=1000),
        video_record(rest, keyframe=True, timestamp_ms=1000),
    )


async def test_a_keyframe_part_after_a_pause_is_still_joined(station: FakeStation) -> None:
    """The held keyframe waits for the next video record however long it takes, as the
    app's player does: a late part is joined, not rejected."""
    session, stream, rsa_key = _rsa_stream(station)
    first, rest = _keyframe_in_two_parts(rsa_key)
    stream._feed(FrameType.VIDEO_FRAME, first)
    reading = asyncio.ensure_future(anext(stream))
    await asyncio.sleep(0.3)
    assert not reading.done()
    stream._feed(FrameType.VIDEO_FRAME, rest)
    stream._feed(FrameType.VIDEO_FRAME, video_record(MEDIA_PFRAME, keyframe=False))
    frame = await reading
    assert (frame.data, frame.is_keyframe) == (MEDIA_KEYFRAME, True)
    assert (await anext(stream)).data == MEDIA_PFRAME
    assert session.stats().media_keyframes_rejected == 0


async def test_audio_between_keyframe_parts_goes_out_after_the_joined_keyframe(
    station: FakeStation,
) -> None:
    session, stream, rsa_key = _rsa_stream(station)
    first, rest = _keyframe_in_two_parts(rsa_key)
    stream._feed(FrameType.VIDEO_FRAME, first)
    stream._feed(FrameType.AUDIO_FRAME, audio_record(MEDIA_AUDIO, timestamp_ms=1000))
    stream._feed(FrameType.VIDEO_FRAME, rest)
    stream._feed(FrameType.VIDEO_FRAME, video_record(MEDIA_PFRAME, keyframe=False))
    frames = [await anext(stream) for _ in range(3)]
    assert [(f.kind, f.data if f.kind is MediaKind.VIDEO else b"") for f in frames] == [
        (MediaKind.VIDEO, MEDIA_KEYFRAME),
        (MediaKind.AUDIO, b""),
        (MediaKind.VIDEO, MEDIA_PFRAME),
    ]
    assert session.stats().media_keyframes_rejected == 0


async def test_another_cameras_record_between_keyframe_parts_does_not_split_them(
    station: FakeStation,
) -> None:
    """On a HomeBase a record tagged for another camera is dropped before the join."""
    session, stream, rsa_key = _rsa_stream(station)
    assert session.tags_live_camera
    first, rest = _keyframe_in_two_parts(rsa_key)
    stream._feed(FrameType.VIDEO_FRAME, first, camera=0)
    stream._feed(FrameType.VIDEO_FRAME, video_record(MEDIA_PFRAME, keyframe=False), camera=3)
    stream._feed(FrameType.VIDEO_FRAME, rest, camera=0)
    stream._feed(FrameType.VIDEO_FRAME, video_record(MEDIA_PFRAME, keyframe=False), camera=0)
    frame = await anext(stream)
    assert (frame.data, frame.is_keyframe) == (MEDIA_KEYFRAME, True)
    assert session.stats().media_keyframes_rejected == 0


async def test_video_dropped_after_a_reader_overflow_counts_as_reader_lag(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The P-frames dropped until the next keyframe after an overflow are the reader's
    lag (``dropped``), not frames skipped after one that did not decode."""
    monkeypatch.setattr(session_module, "MEDIA_QUEUE_FRAMES", 2)
    session, stream, rsa_key = _rsa_stream(station)
    body = media_keyframe(rsa_key.public_key(), bytes(range(16)))
    stream._feed(FrameType.VIDEO_FRAME, video_record(body, keyframe=True))
    for _ in range(2):  # the second overflows the queue
        stream._feed(FrameType.VIDEO_FRAME, video_record(MEDIA_PFRAME, keyframe=False))
    assert [(await anext(stream)).is_keyframe for _ in range(2)] == [True, False]
    stream._feed(FrameType.VIDEO_FRAME, video_record(MEDIA_PFRAME, keyframe=False))
    stats = session.stats()
    assert (stream.dropped, stream.skipped) == (2, 0)
    assert (stats.media_frames_dropped_for_reader, stats.media_frames_skipped_for_keyframe) == (
        2,
        0,
    )


#: An H.264 keyframe (SPS, PPS, IDR) and P-frame, as a HomeBase 2 camera sends them.
H264_KEYFRAME = (
    b"\x00\x00\x00\x01\x67\x4d\x00\x1f"
    + b"\x00\x00\x00\x01\x68\xee\x3c\x80"
    + b"\x00\x00\x00\x01\x65"
    + bytes((i * 5 + 1) & 0xFF for i in range(300))
)
H264_PFRAME = b"\x00\x00\x00\x01\x41\x9a" + bytes(range(1, 60))


def _rsa_stream(
    station: FakeStation, *, idle_timeout: float = 1.0
) -> tuple[StationSession, MediaStream, Any]:
    _, rsa_key = generate_media_rsa_key()
    session = make_session(station, Provider(station))
    stream = MediaStream(
        session,
        command=1003,
        channel=0,
        decoder=MediaDecoder(rsa_key),
        stop_body=lambda: (0, b""),
        first_frame_timeout=1.0,
        idle_timeout=idle_timeout,
    )
    return session, stream, rsa_key


async def test_a_stream_takes_its_codec_from_the_keyframe_picture(station: FakeStation) -> None:
    session, stream, rsa_key = _rsa_stream(station)
    body = media_keyframe(rsa_key.public_key(), bytes(range(16)), clear=H264_KEYFRAME)
    stream._feed(FrameType.VIDEO_FRAME, video_record(body, keyframe=True))  # header: HEVC
    stream._feed(FrameType.VIDEO_FRAME, video_record(H264_PFRAME, keyframe=False))
    key, pframe = await anext(stream), await anext(stream)
    assert (key.codec, pframe.codec) == (VideoCodec.H264, VideoCodec.H264)
    assert key.data == H264_KEYFRAME
    stats = session.stats()
    assert stats.media_codec_overrides == {"hevc->h264": 1}
    assert [s.codec for s in stats.media_first_records] == ["hevc", "hevc"]  # the headers
    assert stats.media_codecs_by_channel == {"0": "h264"}
    assert (session.video_codec(0), session.video_codec(1)) == (VideoCodec.H264, None)


async def test_a_keyframe_whose_picture_matches_its_header_keeps_the_header_codec(
    station: FakeStation,
) -> None:
    session, stream, rsa_key = _rsa_stream(station)
    body = media_keyframe(rsa_key.public_key(), bytes(range(16)))
    stream._feed(FrameType.VIDEO_FRAME, video_record(body, keyframe=True))
    stream._feed(FrameType.VIDEO_FRAME, video_record(MEDIA_PFRAME, keyframe=False))
    assert (await anext(stream)).codec is VideoCodec.HEVC
    assert session.stats().media_codec_overrides == {}


async def test_empty_nal_units_never_reach_the_reader(station: FakeStation) -> None:
    session, stream, rsa_key = _rsa_stream(station)
    body = media_keyframe(rsa_key.public_key(), bytes(range(16)), clear=H264_KEYFRAME)
    stream._feed(FrameType.VIDEO_FRAME, video_record(body, keyframe=True))
    with_empty = H264_PFRAME + b"\x00\x00\x00\x01"  # a trailing start code: an empty unit
    stream._feed(FrameType.VIDEO_FRAME, video_record(with_empty, keyframe=False))
    only_empty = b"\x00\x00\x00\x01\x00\x00\x00\x01"
    stream._feed(FrameType.VIDEO_FRAME, video_record(only_empty, keyframe=False))
    stream._feed(FrameType.VIDEO_FRAME, video_record(H264_PFRAME, keyframe=False))
    frames = [await anext(stream), await anext(stream)]
    assert [f.data for f in frames] == [H264_KEYFRAME, H264_PFRAME]
    assert not stream._frames, "after a frame with no NAL unit, video waits for a keyframe"
    stats = session.stats()
    assert (stats.media_empty_nals, stats.media_frames_without_nal) == (3, 1)
    assert [s.outcome for s in stats.media_first_records] == [
        "keyframe",
        "frame",
        "no_nal",
        "waiting_keyframe",
    ]


async def test_trigger_frame_plays_on_a_short_lived_session_and_closes_it(
    station: FakeStation,
) -> None:
    station.recording_frames = 200  # still playing when the frames are in
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as probe:
        probe.bind(("127.0.0.1", 0))
        pinned = probe.getsockname()[1]
    session = StationSession(
        SYNTHETIC.station_sn,
        Provider(station),
        host="127.0.0.1",
        port=station.discovery_port,
        local_port=pinned,  # held by this session: the short-lived one binds its own
    )
    try:
        await session.async_get_params()
        frame = await session.async_trigger_frame("/zx/clip.zxvideo", 1, trailing_frames=2)
        assert station.conn_inits == 2
        await wait_until(lambda: not station.streaming)  # its CLOSE stopped the playback
        assert (station.client_closes, station.sessions) == (1, 1)
        started = time.monotonic()
        await session.async_get_params(expect_channels=(0,))  # never flooded
        elapsed = time.monotonic() - started
        with pytest.raises(ValueError, match="trailing_frames"):
            await session.async_trigger_frame("/zx/clip.zxvideo", 1, trailing_frames=-1)
        stats = session.stats()
    finally:
        await session.async_close()
    assert frame == MEDIA_KEYFRAME + MEDIA_RECORDING_PFRAME * 2
    assert elapsed < session_module.MEDIA_DRAIN_GAP
    assert (stats.connects, stats.media_opens, stats.trigger_frame_sessions) == (1, 0, 1)
    assert next(o for o in station.received if o["cmd"] == 1025)["mChannel"] == 1


async def test_trigger_frames_take_one_short_lived_session_at_a_time_and_always_close_it(
    station: FakeStation,
) -> None:
    session = make_session(station, Provider(station))
    most = 0

    async def sample() -> None:
        nonlocal most
        while True:
            most = max(most, station.sessions)
            await asyncio.sleep(0.001)

    try:
        await session.async_get_params()
        sampler = asyncio.create_task(sample())
        both = await asyncio.gather(
            session.async_trigger_frame("/zx/a.zxvideo", 0),
            session.async_trigger_frame("/zx/b.zxvideo", 0),
        )
        station.media_reply_code = -104
        with pytest.raises(CommandRejectedError):
            await session.async_trigger_frame("/zx/c.zxvideo", 0)
        sampler.cancel()
    finally:
        await session.async_close()
    assert list(both) == [MEDIA_KEYFRAME, MEDIA_KEYFRAME]
    assert most == 2  # this session and one short-lived one
    await wait_until(lambda: station.client_closes == 4)  # three short-lived, then this one


async def test_fetch_still_out_of_lock_allows_concurrent_arm(station: FakeStation) -> None:
    station.reply_to_settings = True
    station.images["/zx/delayed.jpg"] = b"bytes"
    station.image_reply_delay["/zx/delayed.jpg"] = 3.0
    session = make_session(station, Provider(station))
    try:
        await session.async_get_params()
        fetch = asyncio.create_task(session.async_fetch_still("/zx/delayed.jpg", timeout=5.0))
        await asyncio.sleep(0.1)
        started = time.monotonic()
        await session.async_set_guard_mode(GuardMode.HOME)
        assert time.monotonic() - started < 1.5
        assert (await fetch).data == b"bytes"
    finally:
        await session.async_close()


async def test_history_query_out_of_lock_allows_concurrent_arm(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    station.reply_to_settings = True
    session = make_session(station, Provider(station))
    send = session._send_secure

    def drop_history(plaintext: bytes, **kwargs: Any) -> int:
        return 1 if b"start_id" in plaintext else send(plaintext, **kwargs)

    monkeypatch.setattr(session, "_send_secure", drop_history)
    try:
        await session.async_get_params()
        query = asyncio.create_task(session.async_history_record(2026091600042, timeout=3.0))
        await asyncio.sleep(0.1)
        started = time.monotonic()
        await session.async_set_guard_mode(GuardMode.HOME)
        assert time.monotonic() - started < 1.5
        with pytest.raises(DeviceTimeoutError):
            await query
    finally:
        await session.async_close()


def _history_sends(
    session: StationSession, monkeypatch: pytest.MonkeyPatch, fate: list[str]
) -> list[bytes]:
    """Route history queries by ``fate`` in order ("drop", "late", then "pass" for the
    rest); return every history query sent."""
    send = session._send_secure
    sent: list[bytes] = []

    def route(plaintext: bytes, **kwargs: Any) -> int:
        if b"start_id" not in plaintext:
            return send(plaintext, **kwargs)
        sent.append(plaintext)
        how = fate[len(sent) - 1] if len(sent) <= len(fate) else "pass"
        if how == "drop":
            return 1
        if how == "late":
            asyncio.get_running_loop().call_later(0.4, lambda: send(plaintext, **kwargs))
            return 1
        return send(plaintext, **kwargs)

    monkeypatch.setattr(session, "_send_secure", route)
    return sent


async def test_an_unanswered_history_page_is_asked_once_more(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    station.rows = [_history_row("20260916", n) for n in range(1, 4)]
    session = make_session(station, Provider(station))
    sent = _history_sends(session, monkeypatch, ["drop"])
    try:
        history = await session.async_list_history("20260916", timeout=0.3)
    finally:
        await session.async_close()
    assert [r.record_id % 100_000 for r in history] == [3, 2, 1]
    assert len(sent) == 2
    assert len(station.history_queries) == 1  # the second query's answer is the one used


async def test_a_late_answer_to_the_first_history_query_answers_the_second(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    station.rows = [_history_row("20260916", 7)]
    session = make_session(station, Provider(station))
    sent = _history_sends(session, monkeypatch, ["late", "drop"])
    try:
        history = await session.async_list_history("20260916", timeout=0.3)
    finally:
        await session.async_close()
    assert [r.record_id % 100_000 for r in history] == [7]
    assert len(sent) == 2


async def test_a_history_page_unanswered_twice_times_out_after_the_default(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The per-query default is read at call time; a single-row lookup is not resent."""
    monkeypatch.setattr(session_mod, "HISTORY_QUERY_TIMEOUT", 0.2)
    session = make_session(station, Provider(station))
    sent = _history_sends(session, monkeypatch, ["drop"] * 3)
    try:
        with pytest.raises(DeviceTimeoutError):
            await session.async_list_history("20260916")
        assert len(sent) == 2
        with pytest.raises(DeviceTimeoutError):
            await session.async_history_record(2026091600042)
        assert len(sent) == 3
    finally:
        await session.async_close()


async def test_request_rejects_resend_with_send_only_under_lock(station: FakeStation) -> None:
    session = make_session(station, Provider(station))
    with pytest.raises(ValueError, match="resent"):
        await session._request(
            lambda: None,
            lambda _: None,
            timeout=1.0,
            label="test",
            send_only_under_lock=True,
            resend_after=0.5,
        )


async def test_concurrent_still_fetches(station: FakeStation) -> None:
    station.images["/zx/1.jpg"] = b"bytes1"
    station.images["/zx/2.jpg"] = b"bytes2"
    station.image_reply_delay["/zx/1.jpg"] = 0.5
    session = make_session(station, Provider(station))
    try:
        results = await asyncio.gather(
            session.async_fetch_still("/zx/1.jpg"), session.async_fetch_still("/zx/2.jpg")
        )
        assert results[0].data == b"bytes1"
        assert results[1].data == b"bytes2"
    finally:
        await session.async_close()


async def test_fetch_still_of_unknown_path(station: FakeStation) -> None:
    station.images["/zx/known.jpg"] = b"\xff\xd8known\xff\xd9"
    session = make_session(station, Provider(station))
    try:
        with pytest.raises(DeviceTimeoutError):
            await session.async_fetch_still("/zx/unknown.jpg", timeout=0.1)

        assert "/zx/unknown.jpg" in station.image_requests

        known = await session.async_fetch_still("/zx/known.jpg")
        assert known.data == b"\xff\xd8known\xff\xd9"
    finally:
        await session.async_close()


async def test_media_commands_carry_channel_in_subheader(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    session = make_session(station, Provider(station))
    sent: list[bytes] = []
    send_drw = PPPPTransport.send_drw

    def record(self: PPPPTransport, channel: int, frame: bytes) -> int:
        sent.append(frame)
        return send_drw(self, channel, frame)

    monkeypatch.setattr(PPPPTransport, "send_drw", record)

    try:
        async with await session.async_open_live(1):
            pass
        async with await session.async_open_recording("/zx/clip.zxvideo", 2):
            pass
    finally:
        await session.async_close()

    cmds = [
        f
        for f in sent
        if len(f) >= 8 and struct.unpack_from("<H", f, 4)[0] == FrameType.CMD_TRANSFER
    ]

    # live open (channel byte, live flag), its stop (channel byte), recording open (neither)
    assert [(f[12], f[14]) for f in cmds] == [(1, 0x0A), (1, 0), (0, 0)]


async def test_live_stream_aborts_on_wrong_camera_frames(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    start_media = FakeStation._start_media

    def stream_channel_0(self: FakeStation, key_hex: str, *, live: bool, camera: int) -> None:
        start_media(self, key_hex, live=live, camera=0)

    monkeypatch.setattr(FakeStation, "_start_media", stream_channel_0)

    session = make_session(station, Provider(station))
    try:
        async with await session.async_open_live(1) as stream:
            with pytest.raises(ProtocolError, match="not the requested channel"):
                async for _ in stream:
                    pass
            assert stream.other_camera_frames >= 25

        monkeypatch.undo()
        async with await session.async_open_live(0) as again:
            assert (await anext(again)).is_keyframe

    finally:
        await session.async_close()


async def test_live_stream_ignores_a_few_wrong_camera_frames(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    stream_media = FakeStation._stream

    async def other_camera_first(
        self: FakeStation,
        public: Any,
        count: int | None,
        pframe: bytes,
        camera: int,
        **kwargs: Any,
    ) -> None:
        for _ in range(10):
            self.send_video(pframe, keyframe=False, camera=1 - camera)
        await stream_media(self, public, count, pframe, camera, **kwargs)

    monkeypatch.setattr(FakeStation, "_stream", other_camera_first)

    session = make_session(station, Provider(station))
    try:
        async with await session.async_open_live(1) as stream:
            assert (await anext(stream)).is_keyframe
            assert stream.other_camera_frames == 10
    finally:
        await session.async_close()


async def test_a_standalone_device_streams_whatever_channel_its_frames_name(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A standalone camera tags its live video with a channel other than its own (1 for
    channel 0): the app checks the tag only on a HomeBase, so the stream plays."""
    start_media = FakeStation._start_media

    def tagged_1(self: FakeStation, key_hex: str, *, live: bool, camera: int) -> None:
        start_media(self, key_hex, live=live, camera=1)

    monkeypatch.setattr(FakeStation, "_start_media", tagged_1)

    async def provider(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", station.ecc_private_key_hex)

    station.serial = "T8442P2000054321"
    station.static_key = static_key("T8442P2000054321", station.did)
    session = StationSession(
        "T8442P2000054321", provider, host="127.0.0.1", port=station.discovery_port
    )
    try:
        assert not session.tags_live_camera
        async with await session.async_open_live(0) as stream:
            assert (await anext(stream)).is_keyframe
            assert stream.other_camera_frames == 0
    finally:
        await session.async_close()


async def test_recording_open_ignores_wrong_camera_frames(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    start_media = FakeStation._start_media

    def stream_channel_0(self: FakeStation, key_hex: str, *, live: bool, camera: int) -> None:
        start_media(self, key_hex, live=live, camera=0)

    monkeypatch.setattr(FakeStation, "_start_media", stream_channel_0)
    session = make_session(station, Provider(station))
    try:
        async with await session.async_open_recording("/zx/clip.zxvideo", 1) as stream:
            assert (await anext(stream)).is_keyframe
            assert stream.other_camera_frames == 0
    finally:
        await session.async_close()


async def test_a_session_loads_the_key_of_the_cipher_the_station_names() -> None:
    station = FakeStation(cipher_id=98)
    await station.start()
    calls: list[tuple[bool, int | None]] = []
    step = 1
    bad_hex = FakeStation().ecc_private_key_hex

    async def provider(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        calls.append((refresh, cipher_id))
        if cipher_id == 98:
            if step >= 3:
                return P2PCredentials(SYNTHETIC.account_id, "user", bad_hex, cipher_id=98)
            return P2PCredentials(
                SYNTHETIC.account_id, "user", station.ecc_private_key_hex, cipher_id=98
            )
        return P2PCredentials(SYNTHETIC.account_id, "user", bad_hex, cipher_id=40)

    session = StationSession(
        SYNTHETIC.station_sn, provider, host="127.0.0.1", port=station.discovery_port
    )
    try:
        await session.async_get_params()
        assert calls == [(False, 98)]  # asked after CONN_INIT: never for a guessed id
        assert session._key_refresh.retry_blocked_for() == 0
        calls.clear()

        # a reconnect
        step = 2
        session._teardown("reconnect")
        await session.async_get_params()
        assert calls == [(False, 98)]
        calls.clear()

        # a wrong key for cipher 98 triggers one refresh call with cipher_id=98
        step = 3
        session._teardown("reconnect")
        with pytest.raises(KeyRejectedError):
            await session.async_get_params()
        assert calls == [(False, 98), (True, 98)]

    finally:
        await session.async_close()
        station.stop()


async def test_a_cloud_error_for_the_named_cipher_ends_the_attempt() -> None:
    station = FakeStation(cipher_id=98)
    await station.start()
    calls: list[int | None] = []
    error = CipherUnavailableError(
        "no key", cipher_id=98, owner_source="member.admin_user_id", retry_after=60.0
    )

    async def provider(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        calls.append(cipher_id)
        raise error

    session = StationSession(
        SYNTHETIC.station_sn, provider, host="127.0.0.1", port=station.discovery_port
    )
    try:
        with pytest.raises(CipherUnavailableError) as info:
            await session.async_connect()
        assert info.value is error
        assert (station.conn_inits, calls) == (1, [98])
        assert not session.connected
        assert session._transport is None
        assert session._key_refresh.retry_blocked_for() == 0  # not a rejected key
    finally:
        await session.async_close()
        station.stop()


async def test_a_standalone_block_is_filed_under_the_station_and_its_channel(
    caplog: pytest.LogCaptureFixture,
) -> None:
    caplog.set_level("DEBUG")
    station = FakeStation(receipt_len=STANDALONE_RECEIPT_LEN, params={48: {1224: "1", 1101: "51"}})
    await station.start()

    async def provider(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", station.ecc_private_key_hex)

    session = StationSession(
        SYNTHETIC.station_sn,
        provider,
        host="127.0.0.1",
        port=station.discovery_port,
        block_aliases={48: (255, 0)},
        expect_channels={0},
    )
    try:
        t0 = time.monotonic()
        dump = await session.async_get_params()
        assert time.monotonic() - t0 < 1.0  # well under PARAM_SETTLE + timeout
        assert dump.devices[255] == {1224: "1", 1101: "51"}
        assert dump.devices[0] == {1224: "1", 1101: "51"}
        assert dump.guard_mode == GuardMode.HOME
        assert not any("failed GCM authentication" in r.message for r in caplog.records)

        caplog.clear()
        # a pushed change of 1101 emits ParamChanged for 255 and 0, but ONE debug line
        events: list[ParamChanged] = []
        session.subscribe(lambda ev: events.append(ev) if isinstance(ev, ParamChanged) else None)
        station.params[48][1101] = "52"
        station.send_param_dump()
        await asyncio.sleep(0.1)
        assert len(events) == 2
        assert {e.channel for e in events} == {0, 255}
        debug_lines = [r.message for r in caplog.records if "param ch" in r.message]
        assert len(debug_lines) == 1

    finally:
        await session.async_close()
        station.stop()


async def test_a_standalone_block_under_an_unknown_label_is_the_devices_own() -> None:
    # A T8442 labels its one block 1000, not its cloud device type 46.
    station = FakeStation(receipt_len=STANDALONE_RECEIPT_LEN, params={1000: {1101: "64"}})
    await station.start()

    async def provider(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", station.ecc_private_key_hex)

    session = StationSession(
        SYNTHETIC.station_sn,
        provider,
        host="127.0.0.1",
        port=station.discovery_port,
        block_aliases={46: (255, 0)},
        expect_channels={0},
    )
    try:
        dump = await session.async_get_params(timeout=2.0)
        assert dump.devices[255] == dump.devices[0] == {1101: "64"}
        assert dump.relabelled == {1000}
    finally:
        await session.async_close()
        station.stop()


async def test_on_demand_session_closes_idle_and_reconnects(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(transport_module, "KEEPALIVE_INTERVAL", 0.05)
    monkeypatch.setattr(session_module, "_IDLE_CHECK_EVERY", 0.05)
    provider = Provider(station)
    session = StationSession(
        SYNTHETIC.station_sn,
        provider,
        host="127.0.0.1",
        port=station.discovery_port,
        on_demand=True,
        idle_close=0.1,
    )
    events: list[Any] = []
    session.subscribe(events.append)
    try:
        await session.async_start()  # on-demand: starts the idle watcher, connects nothing
        idle_at_start = session.connected
        await session.async_get_params()  # a read connects and announces
        after_read = session.connected
        await asyncio.sleep(0.3)
        after_idle = session.connected
        assert (idle_at_start, after_read, after_idle) == (False, True, False)
        down = [e for e in events if isinstance(e, ConnectionChanged) and not e.connected]
        assert down
        assert down[-1].cause is DisconnectCause.IDLE
        await session.async_get_params()  # reconnects on demand
        assert session.connected
    finally:
        await session.async_close()


async def test_note_guard_mode_on_demand(station: FakeStation) -> None:
    provider = Provider(station)
    session = StationSession(
        SYNTHETIC.station_sn,
        provider,
        host="127.0.0.1",
        port=station.discovery_port,
        on_demand=True,
        block_aliases={48: (255, 0)},
    )
    session._params[(255, 1224)] = "0"
    session._param_at[(255, 1224)] = 10.0
    session.note_guard_mode(GuardMode.HOME)
    assert session._params[(255, 1224)] == "1"
    assert session._param_at[(255, 1224)] > 10.0


async def test_ingest_cloud_params_block_aliases_and_events(station: FakeStation) -> None:
    provider = Provider(station)
    session = StationSession(
        SYNTHETIC.station_sn,
        provider,
        host="127.0.0.1",
        port=station.discovery_port,
        block_aliases={48: (255, 0)},
    )
    count = session.ingest_cloud_params(48, [(1101, "87", 10.0), (1224, "1", 10.0)])
    assert count == 2
    assert session.params[(255, 1224)] == "1"
    assert session.params[(0, 1101)] == "87"

    session._param_at[(255, 1224)] = 20.0
    count_old = session.ingest_cloud_params(48, [(1224, "0", 15.0)])
    assert count_old == 0
    assert session.params[(255, 1224)] == "1"

    count_new = session.ingest_cloud_params(48, [(1224, "2", 30.0)])
    assert count_new == 1


@pytest.mark.parametrize(
    ("aliases", "channel", "blocks"),
    [
        ({}, 1, (1,)),  # a paired device's block
        ({48: (255, 0)}, 0, (255, 0)),  # a standalone device: every alias of its block
    ],
)
async def test_apply_local_params_merges_written_values_as_a_dump(
    station: FakeStation, aliases: dict[int, tuple[int, ...]], channel: int, blocks: tuple[int, ...]
) -> None:
    session = StationSession(
        SYNTHETIC.station_sn,
        Provider(station),
        host="127.0.0.1",
        port=station.discovery_port,
        block_aliases=aliases,
    )
    for block in blocks:
        session._params[(block, 1246)] = "1"
    events: list[Event] = []
    session.subscribe(events.append)
    dumps: list[None] = []
    session.add_dump_listener(lambda: dumps.append(None))

    session.apply_local_params(channel, {1246: "2"})

    assert all(session.params[(block, 1246)] == "2" for block in blocks)
    changed = [e for e in events if isinstance(e, ParamChanged)]
    assert [(e.channel, e.param_id, e.old, e.new) for e in changed] == [
        (block, 1246, "1", "2") for block in blocks
    ]
    assert dumps == [None]


async def test_station_goes_silent_on_demand_is_idle_vs_closed(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(transport_module, "SILENCE_TIMEOUT", 0.5)
    monkeypatch.setattr(transport_module, "KEEPALIVE_INTERVAL", 0.1)
    provider = Provider(station)
    session = StationSession(
        SYNTHETIC.station_sn,
        provider,
        host="127.0.0.1",
        port=station.discovery_port,
        on_demand=True,
    )
    events: list[Any] = []
    session.subscribe(events.append)
    try:
        await session.async_start()
        await session.async_get_params()  # connects and announces
        after_read = session.connected
        station.stop()
        await asyncio.sleep(0.9)
        assert (after_read, session.connected) == (True, False)
        down = [e for e in events if isinstance(e, ConnectionChanged) and not e.connected]
        assert down
        assert down[-1].cause is DisconnectCause.IDLE
    finally:
        await session.async_close()


async def test_session_standalone_property(station: FakeStation) -> None:
    async def provider(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", station.ecc_private_key_hex)

    session = StationSession(
        SYNTHETIC.station_sn, provider, host="127.0.0.1", port=station.discovery_port
    )
    assert not session.standalone

    session2 = StationSession(
        "T8170P2000054321", provider, host="127.0.0.1", port=station.discovery_port
    )
    assert session2.standalone


async def test_session_run_recipe_query_preset(station: FakeStation) -> None:
    async def provider(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", station.ecc_private_key_hex)

    station.preset_points = [{"index": 1, "enable": 1, "zoom": 1, "isdefault": 0}]
    station.serial = "T8170P2000054321"
    station.static_key = static_key("T8170P2000054321", station.did)
    session = StationSession(
        "T8170P2000054321", provider, host="127.0.0.1", port=station.discovery_port
    )
    try:
        await session.async_start()
        reply = await session.async_run_recipe(query_preset_positions(), channel=0)
        assert reply.outcome == CommandOutcome.APPLIED
        assert reply.payload == {"points": station.preset_points}
    finally:
        await session.async_close()


async def test_session_run_recipe_goto_preset(station: FakeStation) -> None:
    async def provider(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", station.ecc_private_key_hex)

    station.serial = "T8170P2000054321"
    station.static_key = static_key("T8170P2000054321", station.did)
    session = StationSession(
        "T8170P2000054321", provider, host="127.0.0.1", port=station.discovery_port
    )
    try:
        await session.async_start()
        reply = await session.async_run_recipe(goto_preset(2), channel=0)
        assert reply.outcome == CommandOutcome.DELIVERED
        assert station.preset_gotos == [2]
    finally:
        await session.async_close()


async def test_session_run_recipe_unsupported(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def provider(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", station.ecc_private_key_hex)

    orig_send_receipt = station.send_receipt

    def drop_or_change_receipt(
        ftype: int, code: int, *, dev_type: int = 0, delay: float = 0.0
    ) -> None:
        if ftype == FrameType.DOORBELL_PAYLOAD and code == 0:
            code = -108
        orig_send_receipt(ftype, code, dev_type=dev_type, delay=delay)

    monkeypatch.setattr(station, "send_receipt", drop_or_change_receipt)

    station.serial = "T8170P2000054321"
    station.static_key = static_key("T8170P2000054321", station.did)
    session = StationSession(
        "T8170P2000054321", provider, host="127.0.0.1", port=station.discovery_port
    )
    try:
        await session.async_start()
        with pytest.raises(CommandUnsupportedError):
            await session.async_run_recipe(goto_preset(2), channel=0)
    finally:
        await session.async_close()


async def test_session_run_recipe_timeout(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    async def provider(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", station.ecc_private_key_hex)

    orig_send_json = station.send_json

    def drop_notify(msg_type: int, obj: dict[str, Any], cipher: int = 2, channel: int = 0) -> None:
        if msg_type == FrameType.NOTIFY_PAYLOAD and obj.get("cmd") == 6034:
            return
        orig_send_json(msg_type, obj, cipher=cipher, channel=channel)

    monkeypatch.setattr(station, "send_json", drop_notify)

    station.serial = "T8170P2000054321"
    station.static_key = static_key("T8170P2000054321", station.did)
    session = StationSession(
        "T8170P2000054321", provider, host="127.0.0.1", port=station.discovery_port
    )
    try:
        await session.async_start()
        with pytest.raises(DeviceTimeoutError):
            await session.async_run_recipe(query_preset_positions(), channel=0, timeout=0.1)
    finally:
        await session.async_close()


async def test_session_live_standalone_sends_doorbell_payload(station: FakeStation) -> None:
    async def provider(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", station.ecc_private_key_hex)

    station.serial = "T8170P2000054321"
    station.static_key = static_key("T8170P2000054321", station.did)
    session = StationSession(
        "T8170P2000054321", provider, host="127.0.0.1", port=station.discovery_port
    )
    try:
        await session.async_start()
        stream = await session.async_open_live(channel=0)
        await asyncio.sleep(0.05)
        assert len(station.doorbell_payloads) == 1
        assert station.doorbell_payloads[0].get("commandType") == 1000
        assert "encryptkey" in station.doorbell_payloads[0].get("data", {})

        await stream.aclose()
        await asyncio.sleep(0.05)
        assert station.bare_stops == 1
    finally:
        await session.async_close()


async def test_session_live_homebase_sends_1003(station: FakeStation) -> None:
    async def provider(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", station.ecc_private_key_hex)

    session = StationSession(
        SYNTHETIC.station_sn, provider, host="127.0.0.1", port=station.discovery_port
    )
    try:
        await session.async_start()
        stream = await session.async_open_live(channel=0)
        await asyncio.sleep(0.05)
        assert len(station.doorbell_payloads) == 0
        cmds = [obj.get("cmd") for obj in station.received]
        assert 1003 in cmds

        await stream.aclose()
        await asyncio.sleep(0.05)
        assert station.bare_stops == 0
    finally:
        await session.async_close()


async def test_session_live_standalone_pings(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(session_mod, "MEDIA_PING_INTERVAL", 0.05)

    async def provider(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", station.ecc_private_key_hex)

    station.serial = "T8170P2000054321"
    station.static_key = static_key("T8170P2000054321", station.did)
    session = StationSession(
        "T8170P2000054321", provider, host="127.0.0.1", port=station.discovery_port
    )
    try:
        await session.async_start()
        stream = await session.async_open_live(channel=0)
        await asyncio.sleep(0.15)
        assert station.pings >= 2

        pings_before_close = station.pings
        await stream.aclose()
        await asyncio.sleep(0.15)
        assert station.pings == pings_before_close
    finally:
        await session.async_close()


async def test_session_live_homebase_no_pings(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(session_mod, "MEDIA_PING_INTERVAL", 0.05)

    async def provider(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", station.ecc_private_key_hex)

    session = StationSession(
        SYNTHETIC.station_sn, provider, host="127.0.0.1", port=station.discovery_port
    )
    try:
        await session.async_start()
        stream = await session.async_open_live(channel=0)
        await asyncio.sleep(0.15)
        assert station.pings == 0
        await stream.aclose()
    finally:
        await session.async_close()


async def test_session_live_ends_early(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(session_mod, "MEDIA_PING_INTERVAL", 9999)
    station.live_ends_unpinged_after = 0.05
    monkeypatch.setattr(session_mod, "MEDIA_IDLE_TIMEOUT", 0.1)

    async def provider(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", station.ecc_private_key_hex)

    station.serial = "T8170P2000054321"
    station.static_key = static_key("T8170P2000054321", station.did)
    session = StationSession(
        "T8170P2000054321", provider, host="127.0.0.1", port=station.discovery_port
    )
    try:
        await session.async_start()
        stream = await session.async_open_live(channel=0)
        frames = [frame async for frame in stream]
        assert len(frames) < 30
    finally:
        await session.async_close()


async def test_session_live_keeps_delivering_with_pings(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(session_mod, "MEDIA_PING_INTERVAL", 0.02)
    station.live_ends_unpinged_after = 0.05
    monkeypatch.setattr(session_mod, "MEDIA_IDLE_TIMEOUT", 0.1)

    async def provider(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", station.ecc_private_key_hex)

    station.serial = "T8170P2000054321"
    station.static_key = static_key("T8170P2000054321", station.did)
    session = StationSession(
        "T8170P2000054321", provider, host="127.0.0.1", port=station.discovery_port
    )
    try:
        await session.async_start()
        stream = await session.async_open_live(channel=0)

        async def fetch_one() -> Any:
            async for frame in stream:
                return frame
            return None

        frame = await asyncio.wait_for(fetch_one(), timeout=0.3)
        assert frame is not None
        await stream.aclose()
    finally:
        await session.async_close()


async def test_async_event_summary_returns_counts_and_path(station: FakeStation) -> None:
    path = "/media/mmcblk0p1/Camera00/event/202609/20260917/20260917223859_snapshot.jpg"
    station.event_summaries = {
        SYNTHETIC.camera_sn: {
            "event_count": 11,
            "crop_hb3_path": path,
            "crop_cloud_path": "",
        }
    }
    session = make_session(station, Provider(station))
    try:
        await session.async_connect()
        summary = await session.async_event_summary(SYNTHETIC.camera_sn)
        assert summary == EventSummary(event_count=11, newest_still=path)

        summary_empty = await session.async_event_summary("T8160P2000000000")
        assert summary_empty == EventSummary(0, None)
    finally:
        await session.async_close()


async def test_async_event_summary_unnamed_single_item(station: FakeStation) -> None:
    path = "/media/mmcblk0p1/Camera00/event/202609/20260917/20260917223859_snapshot.jpg"
    station.event_summaries = {
        SYNTHETIC.camera_sn: {
            "event_count": 11,
            "crop_hb3_path": path,
            "crop_cloud_path": "",
        }
    }
    station.event_count_unnamed = True
    session = make_session(station, Provider(station))
    try:
        await session.async_connect()
        summary = await session.async_event_summary(SYNTHETIC.camera_sn)
        assert summary == EventSummary(event_count=11, newest_still=path)
    finally:
        await session.async_close()


async def test_async_event_summary_resends_and_timeouts(
    station: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    path = "/media/mmcblk0p1/Camera00/event/202609/20260917/20260917223859_snapshot.jpg"
    station.event_summaries = {
        SYNTHETIC.camera_sn: {
            "event_count": 11,
            "crop_hb3_path": path,
            "crop_cloud_path": "",
        }
    }
    monkeypatch.setattr(session_module, "EVENT_COUNT_RESEND", 0.2)
    station.event_count_ignored = 2
    session = make_session(station, Provider(station))
    try:
        await session.async_connect()
        summary = await session.async_event_summary(SYNTHETIC.camera_sn)
        assert summary == EventSummary(event_count=11, newest_still=path)
        assert station.event_count_queries == 3

        station.event_count_queries = 0
        station.event_count_ignored = 100
        with pytest.raises(DeviceTimeoutError):
            await session.async_event_summary(SYNTHETIC.camera_sn, timeout=0.5)
    finally:
        await session.async_close()


async def test_async_event_summary_and_fetch_still_accept_clear_replies(
    station: FakeStation,
) -> None:
    path = "/media/mmcblk0p1/Camera00/event/202609/20260917/20260917223859_snapshot.jpg"
    station.event_summaries = {
        SYNTHETIC.camera_sn: {
            "event_count": 11,
            "crop_hb3_path": path,
            "crop_cloud_path": "",
        }
    }
    image = b"\xff\xd8\xff\xe0" + bytes(400) + b"\xff\xd9"
    wrapped = v1_still(image, SYNTHETIC.camera_sn, did=SYNTHETIC.did)
    station.images[path] = wrapped
    station.clear_replies = True
    session = make_session(station, Provider(station))
    try:
        await session.async_connect()
        summary = await session.async_event_summary(SYNTHETIC.camera_sn)
        assert summary == EventSummary(event_count=11, newest_still=path)

        still = await session.async_fetch_still(path)
        assert still.path == path
        assert still.data == image
        assert still.format == StillFormat.V1
        assert still.is_image is True
    finally:
        await session.async_close()


@pytest.mark.parametrize(("build", "fmt"), [(v1_still, StillFormat.V1), (v2_still, StillFormat.V2)])
async def test_async_fetch_still_decodes_v1_and_v2(
    station: FakeStation, build: Callable[..., bytes], fmt: StillFormat
) -> None:
    path = "/media/mmcblk0p1/Camera00/event/202609/20260917/20260917223859_snapshot.jpg"
    image = b"\xff\xd8\xff\xe0" + bytes(400) + b"\xff\xd9"
    wrapped = build(image, SYNTHETIC.camera_sn, did=SYNTHETIC.did)
    station.images[path] = wrapped
    session = make_session(station, Provider(station))
    try:
        await session.async_connect()
        assert session.did == Did.parse(SYNTHETIC.did)
        still = await session.async_fetch_still(path)
        assert still.path == path
        assert still.data == image
        assert still.format == fmt
        assert still.is_image is True
        assert session.stats().stills_by_format[fmt.value] == 1
    finally:
        await session.async_close()


async def test_async_fetch_still_with_wrong_did_undecoded(station: FakeStation) -> None:
    path = "/media/mmcblk0p1/Camera00/event/202609/20260917/20260917223859_snapshot.jpg"
    image = b"\xff\xd8\xff\xe0" + bytes(400) + b"\xff\xd9"
    wrapped = v1_still(image, SYNTHETIC.camera_sn, did="EUPRAMA-654321-ZZZZZ")
    station.images[path] = wrapped
    session = make_session(station, Provider(station))
    try:
        await session.async_connect()
        still = await session.async_fetch_still(path)
        assert still.path == path
        assert still.data == wrapped
        assert still.format == StillFormat.V1
        assert still.is_image is False
    finally:
        await session.async_close()


async def test_async_run_recipe_set_default_preset_waits_for_receipt_only(
    station: FakeStation,
) -> None:
    provider = Provider(station)
    session = make_session(station, provider)
    await session.async_connect()

    reply = await session.async_run_recipe(set_default_preset(1), timeout=1.0)
    assert reply.outcome == session_module.CommandOutcome.DELIVERED
    assert station.default_preset_sets == [(1, 0)]
    await session.async_close()


async def test_async_run_recipe_serialises_set_default_preset_params_as_dict(
    station: FakeStation,
) -> None:
    provider = Provider(station)
    session = make_session(station, provider)
    await session.async_connect()

    await session.async_run_recipe(set_default_preset(2), timeout=1.0)
    assert station.default_preset_sets == [(2, 0)]
    await session.async_close()


async def test_on_demand_session_reconnects_when_probably_asleep(station: FakeStation) -> None:
    provider = Provider(station)
    session = session_module.StationSession(
        SYNTHETIC.station_sn,
        provider,
        host="127.0.0.1",
        port=station.discovery_port,
        on_demand=True,
    )
    await session.async_connect()
    searches = station.searches

    session._last_used = time.monotonic() - (session_module.ON_DEMAND_ASLEEP_AFTER + 1)

    await session.async_connect()
    assert station.searches == searches + 1
    assert session.connected
    await session.async_close()


async def test_fresh_on_demand_session_is_not_torn_down(station: FakeStation) -> None:
    provider = Provider(station)
    session = session_module.StationSession(
        SYNTHETIC.station_sn,
        provider,
        host="127.0.0.1",
        port=station.discovery_port,
        on_demand=True,
    )
    await session.async_connect()
    searches = station.searches

    await session.async_connect()
    assert station.searches == searches
    assert session.connected
    await session.async_close()


async def test_probably_asleep_is_false_while_media_stream_is_open(station: FakeStation) -> None:
    provider = Provider(station)
    session = session_module.StationSession(
        SYNTHETIC.station_sn,
        provider,
        host="127.0.0.1",
        port=station.discovery_port,
        on_demand=True,
    )
    await session.async_connect()

    session._last_used = time.monotonic() - (session_module.ON_DEMAND_ASLEEP_AFTER + 1)
    assert session._probably_asleep() is True

    session._media = cast("MediaStream", object())
    assert session._probably_asleep() is False

    session._media = None
    await session.async_close()


async def test_async_get_sd_info_returns_and_keeps_storage(station: FakeStation) -> None:
    session = make_session(station, Provider(station))
    station.sd_info = (0, 8000, 2000)
    try:
        info = await session.async_get_sd_info()
        assert info.disk is None
        assert info.external is None
        assert info.emmc is not None
        assert info.emmc.used_percent == 75.0
        assert session.storage == info
    finally:
        await session.async_close()


async def test_async_get_sd_info_emits_storage_changed(station: FakeStation) -> None:
    session = make_session(station, Provider(station))
    station.sd_info = (0, 8000, 2000)
    changes: list[StorageChanged] = []
    session.subscribe(lambda e: changes.append(e) if isinstance(e, StorageChanged) else None)
    try:
        info = await session.async_get_sd_info()
        assert changes == [StorageChanged(station_sn=SYNTHETIC.station_sn, storage=info)]
    finally:
        await session.async_close()


async def test_async_get_sd_info_raises_timeout_on_no_answer(station: FakeStation) -> None:
    session = make_session(station, Provider(station))
    station.sd_info = None
    try:
        with pytest.raises(DeviceTimeoutError):
            await session.async_get_sd_info(timeout=0.3)
    finally:
        await session.async_close()


async def test_a_session_key_that_is_not_printable_runs_the_gcm_session(
    station: FakeStation, short_settle: None
) -> None:
    """Version 8 with 32 session-key bytes outside printable ASCII: the handshake takes
    them as the GCM key, and commands and the parameter dump run under it."""
    station.session_key = bytes(range(0xE0, 0x100))
    station.reply_to_settings = True
    session = make_session(station, Provider(station))
    try:
        dump = await session.async_get_params()
        outcome = await session.async_send_command(
            1277, channel=0, payload={"night_sion": 1, "channel": 0}
        )
        stats = session.stats()
    finally:
        await session.async_close()
    assert not session.rsa_session
    assert dump.station == station.params[STATION_CHANNEL]
    assert outcome is CommandOutcome.APPLIED
    assert [o["cmd"] for o in station.received] == [1277]
    assert stats.handshake_failures == 0
    assert stats.conn_init_version == 8


class RsaProvider:
    """Credentials of a station answering the RSA CONN_INIT: its RSA key, or none.

    ``bad_key`` serves an unparsable ``private_key`` (the cloud lowercases the base64
    on some accounts); ``cached_rsa_key`` False serves none until a refresh (a cache
    that predates the RSA key); ``calls`` records each ``refresh`` flag asked.
    """

    def __init__(
        self,
        station: FakeStation,
        *,
        rsa_key: bool = True,
        bad_key: bool = False,
        cached_rsa_key: bool = True,
    ) -> None:
        self.station = station
        self.rsa_key = rsa_key
        self.bad_key = bad_key
        self.cached_rsa_key = cached_rsa_key
        self.calls: list[bool] = []

    async def __call__(self, *, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        self.calls.append(refresh)
        if not self.rsa_key or not (refresh or self.cached_rsa_key):
            rsa_key = None
        elif self.bad_key:
            rsa_key = self.station.rsa_private_key_pem.lower()  # lowercased = unparsable
        else:
            rsa_key = self.station.rsa_private_key_pem
        named = self.station.cipher_id if cipher_id is None else cipher_id
        return P2PCredentials(
            SYNTHETIC.account_id, "user", "", cipher_id=named, rsa_private_key=rsa_key
        )


def make_rsa_session(
    station: FakeStation, provider: CredentialProvider | None = None, **kwargs: Any
) -> StationSession:
    """A session to ``station`` answering the RSA CONN_INIT (version 1)."""
    station.conn_init_version = 1
    return StationSession(
        SYNTHETIC.station_sn,
        provider or RsaProvider(station),
        host="127.0.0.1",
        port=station.discovery_port,
        **kwargs,
    )


@pytest.mark.parametrize("encryption", [0, 1])
async def test_an_rsa_conn_init_runs_the_session_under_its_aes_key(
    station: FakeStation, encryption: int, short_settle: None
) -> None:
    """Version 1: the RSA-wrapped 16-character key, then every frame AES-128-ECB under it.

    The reply is read clear (encryption type 0) or ECB under the static key (1); the
    fake decodes a client frame under the session key only when it is tagged type 2.
    """
    station.conn_init_version = 1
    station.conn_init_encryption = encryption
    station.reply_to_settings = True
    session = StationSession(
        SYNTHETIC.station_sn, RsaProvider(station), host="127.0.0.1", port=station.discovery_port
    )
    try:
        await session.async_connect()
        assert session.rsa_session
        dump = await session.async_get_params()
        outcome = await session.async_send_command(
            1277, channel=0, payload={"night_sion": 1, "channel": 0}
        )
        stats = session.stats()
    finally:
        await session.async_close()
    assert dump.station == station.params[STATION_CHANNEL]
    assert outcome is CommandOutcome.APPLIED
    assert [o["cmd"] for o in station.received] == [1277]
    assert stats.receipts_by_code == {"0": 2}  # the query's and the command's, in clear
    assert (stats.dropped_undecodable, stats.ecb_state_refused) == (0, 0)
    assert (stats.conn_init_version, stats.cipher_id) == (1, station.cipher_id)


@pytest.mark.parametrize("tag", [FrameCipher.ECB, FrameCipher.GCM, 0x05])
async def test_an_rsa_session_takes_clear_state_but_authenticates_no_clear_push(
    station: FakeStation, tag: int, short_settle: None
) -> None:
    """On an RSA session a clear parameter dump under the ECB tag is taken; under another
    tag it names no key and is not decoded. A clear push is never authenticated."""
    session = make_rsa_session(station)
    events: list[Event] = []
    session.subscribe(events.append)
    clear = bytes([tag, 0, 0xFF, FRAME_PLAIN, 0, 0])
    dump = {"params": [{"dev_type": 255, "param_type": 1224, "param_value": "63"}]}
    inner = {"msg_type": 18, "event_type": 3104, "device_sn": SYNTHETIC.camera_sn, "channel": 0}
    push = {"cmd": 2037, "payload": json.dumps(inner)}
    try:
        await session.async_get_params()
        for ftype, body in ((FrameType.PARAM_NOTIFY, dump), (FrameType.NOTIFY_PAYLOAD, push)):
            station.send_frame(
                ftype, json.dumps(body).encode(), cipher=0, channel=1, subheader=clear
            )
        station.push_camera_event()  # under the session key, after the clear frames
        await wait_until(lambda: any(isinstance(e, SecurityEvent) for e in events))
    finally:
        await session.async_close()
    taken = tag == FrameCipher.ECB
    assert (session.params.get((STATION_CHANNEL, 1224)) == "63") is taken
    assert ("clear" in session.stats().state_frames_by_encryption) is taken
    assert session.ecb_state_refused == 0
    pushes = [e for e in events if isinstance(e, SecurityEvent)]
    assert not any(e.authenticated for e in pushes if e.event_type == 3104)
    assert all(e.frame_cipher is FrameCipher.ECB for e in pushes)


async def test_a_push_under_the_rsa_session_key_is_authenticated(station: FakeStation) -> None:
    session = make_rsa_session(station)
    events: list[Event] = []
    session.subscribe(events.append)
    try:
        await session.async_connect()
        station.push_camera_event()
        await wait_until(lambda: any(isinstance(e, SecurityEvent) for e in events))
    finally:
        await session.async_close()
    push = next(e for e in events if isinstance(e, SecurityEvent))
    assert (push.frame_cipher, push.session_ecb, push.authenticated) == (
        FrameCipher.ECB,
        True,
        True,
    )


def state_station(station: FakeStation, encryption: str) -> FakeStation:
    """``station`` as an RSA station that sends its state (parameter dump, guard-mode
    report, alarm frames) under ``encryption``: ``"clear"``, ``"type1"`` (the fixed
    static key) or ``"type2"`` (its session key)."""
    if encryption == "clear":
        station.station_encryption = FRAME_PLAIN
    elif encryption == "type1":
        station.params_cipher = station.state_cipher = FrameCipher.ECB
    return station


_RSA_TYPES = {"clear": FRAME_PLAIN, "type1": FRAME_STATIC_ECB, "type2": FRAME_SESSION_ECB}
"""The encryption type (subheader byte 3) of each :func:`state_station` encryption."""


def _messages(caplog: pytest.LogCaptureFixture, text: str) -> list[str]:
    return [r.getMessage() for r in caplog.records if text in r.getMessage()]


@pytest.mark.parametrize(
    ("encryption", "logged_as"),
    [("clear", "in clear"), ("type1", "under the fixed key"), ("type2", None)],
)
async def test_an_rsa_session_takes_state_under_any_encryption(
    station: FakeStation,
    encryption: str,
    logged_as: str | None,
    short_settle: None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """A parameter dump, a guard-mode report and an alarm frame are taken in clear and
    under either key; only the session key authenticates them. Unauthenticated state is
    logged at INFO once per frame type. A frame that does not decode is dropped."""
    caplog.set_level(logging.INFO, logger=session_module.__name__)
    state_station(station, encryption).params[255][1224] = "63"
    session = make_rsa_session(station)
    cipher = station.state_cipher
    undecodable = bytes([FrameCipher.ECB, 0, 0xFF, _RSA_TYPES[encryption], 0, 0])
    try:
        dump = await session.async_get_params()
        for _ in range(2):
            station.send_alarm_mode(GuardMode.HOME, cipher=cipher)
            station.send_alarm_frame(FrameType.LIGHT_NOTIFY, 1, channel=1, cipher=cipher)
        station.send_frame(FrameType.PARAM_NOTIFY, b"\x01" * 33, cipher=0, subheader=undecodable)
        light = bytes([FrameCipher.ECB, 0, 3, _RSA_TYPES[encryption], 0, 0])
        station.send_frame(FrameType.LIGHT_NOTIFY, b"\x01" * 3, cipher=0, subheader=light)
        await wait_until(lambda: session.stats().dropped_undecodable == 2)
        stats = session.stats()
    finally:
        await session.async_close()
    assert dump.station == station.params[STATION_CHANNEL]
    assert (session.guard_mode, session.params[(1, 1400)]) == (GuardMode.HOME, "1")
    assert (3, 1400) not in session.params
    assert stats.state_frames_by_encryption == {encryption: len(station.params) + 4}
    assert (stats.state_authenticated, stats.ecb_state_refused) == (logged_as is None, 0)
    logged = _messages(caplog, "(unauthenticated), taken as the eufy app does")
    expected = (
        []
        if logged_as is None
        else [
            f"{session._log_name}: station state 0x{t:04x} arrived {logged_as} "
            "(unauthenticated), taken as the eufy app does"
            for t in (0x044F, 0x047F, 0x0578)
        ]
    )
    assert sorted(logged) == sorted(expected)


async def test_an_rsa_session_reads_another_encryption_type_under_the_static_key(
    station: FakeStation, caplog: pytest.LogCaptureFixture
) -> None:
    """An ECB-tagged state frame of an unknown encryption type decodes under the static
    key, unauthenticated; a GCM-tagged one names no key an RSA session holds."""
    caplog.set_level(logging.INFO, logger=session_module.__name__)
    session = make_rsa_session(station)
    light = ecb_encrypt(station.static_key, struct.pack("<I", 1) + bytes(12))
    try:
        await session.async_get_params()
        for tag, channel in ((FrameCipher.GCM, 3), (FrameCipher.ECB, 2)):
            station.send_frame(
                FrameType.LIGHT_NOTIFY,
                light,
                cipher=0,
                channel=2,
                subheader=bytes([tag, 0, channel, 3, 0, 0]),
            )
        await wait_until(lambda: (2, 1400) in session.params)
        stats = session.stats()
    finally:
        await session.async_close()
    assert (3, 1400) not in session.params
    assert stats.state_frames_by_encryption["other"] == 1
    assert stats.state_authenticated is True  # the dump came under the session key
    assert _messages(caplog, "0x0578 arrived under an unknown encryption type")


@pytest.mark.parametrize("current", [False, True], ids=["change", "already-in-mode"])
@pytest.mark.parametrize("encryption", ["clear", "type1"])
async def test_unauthenticated_state_confirms_an_arm_and_a_disarm(
    station: FakeStation,
    encryption: str,
    current: bool,
    short_settle: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A mode report, or a read-back, in clear or under the fixed key confirms an arm
    and a disarm, as the eufy app takes it."""
    monkeypatch.setattr(session_module, "MODE_REPORT_GRACE", 0.2)
    state_station(station, encryption)
    if current:
        station.guard_mode = GuardMode.HOME  # silent: the read-back confirms it
        station.params[255][1224] = "1"
    session = make_rsa_session(station)
    try:
        armed = await session.async_set_guard_mode(GuardMode.HOME, timeout=1.0)
        disarmed = await session.async_set_guard_mode(GuardMode.DISARMED, timeout=1.0)
        stats = session.stats()
    finally:
        await session.async_close()
    assert (armed, disarmed) == (GuardMode.HOME, GuardMode.DISARMED)
    assert station.guard_mode == session.guard_mode == GuardMode.DISARMED
    assert set(stats.state_frames_by_encryption) == {encryption}
    assert stats.state_authenticated is False


@pytest.mark.parametrize("encryption", ["clear", "type1"])
async def test_an_unauthenticated_tone_frame_confirms_a_siren(
    station: FakeStation, encryption: str
) -> None:
    state_station(station, encryption).tone_frames = True
    session = make_rsa_session(station)
    events: list[Event] = []
    session.subscribe(events.append)
    try:
        outcome = await session.async_set_tone_file(30, timeout=0.5)
    finally:
        await session.async_close()
    assert outcome is CommandOutcome.APPLIED
    assert [e.alarming for e in events if isinstance(e, AlarmChanged)] == [True]


def _rsa_frame(
    station: FakeStation, encryption: int, body: bytes, *, ftype: int = FrameType.CMD_TRANSFER
) -> Frame:
    """A frame of an RSA session: ``body`` under ``encryption``, its block-aligned prefix
    only (0 clear, 1 the static key, 2 the session key)."""
    keys = {FRAME_STATIC_ECB: station.static_key, FRAME_SESSION_ECB: RSA_SESSION_KEY}
    key = keys.get(encryption)
    aligned = len(body) // 16 * 16
    wire = body if key is None else ecb_encrypt(key, body[:aligned]) + body[aligned:]
    return Frame(
        type=ftype, subheader=bytes([FrameCipher.ECB, 0, 0, encryption, 1, 0]), payload=wire
    )


def _result_frame(encryption: int, payload: bytes, *, ftype: int = FrameType.CMD_TRANSFER) -> Frame:
    """An RSA station's channel-0 reply as sent: ``payload`` as is, ``encryption`` in
    subheader byte 3."""
    return Frame(
        type=ftype, subheader=bytes([FrameCipher.ECB, 0, 0, encryption, 1, 0]), payload=payload
    )


def _sent(session: StationSession, ftype: int, *, ago: float = 0.0) -> None:
    """Mark a send of ``ftype`` awaiting its result, ``ago`` seconds back."""
    due = time.monotonic() - ago + session_module.RSA_RESULT_WINDOW
    session._result_slot += 1
    session._results_due.setdefault(ftype, []).append((due, session._result_slot))


_NOT_HANDLED = struct.pack("<i", RECEIPT_NOT_HANDLED)
_NOISE = bytes(range(1, 129))
"""128 bytes that are not zero: the data area a T8414 sends after the code."""


@pytest.mark.parametrize(
    ("encryption", "tail", "code"),
    [
        (FRAME_PLAIN, bytes(128), 0),
        (FRAME_PLAIN, _NOISE, 0),
        (FRAME_STATIC_ECB, b'{"cmd":1350}' + bytes(116), -1),
        (FRAME_STATIC_ECB, ecb_encrypt(bytes(range(16)), bytes(128)), 0),
        (FRAME_SESSION_ECB, ecb_encrypt(RSA_SESSION_KEY, bytes(128)), 5),
        (FRAME_PLAIN, bytes(32), RECEIPT_NOT_HANDLED),  # a T8170's 36 bytes
        (FRAME_STATIC_ECB, b"", -1),  # the code alone
        (3, _NOISE, 7),  # an encryption type that names no key
    ],
    ids=["zero", "noise", "json-tail", "fixed-key-tail", "session-key-tail", "36", "4", "type-3"],
)
async def test_an_rsa_session_reads_a_result_in_clear_as_the_app_does(
    station: FakeStation, encryption: int, tail: bytes, code: int
) -> None:
    """The reply to a send is its code in clear at payload[0:4], whatever the encryption
    type and the bytes after it; never JSON, never undecodable."""
    session = make_rsa_session(station)
    try:
        await session.async_connect()
        _sent(session, FrameType.CMD_TRANSFER)
        inbound = Inbound(0, _result_frame(encryption, struct.pack("<i", code) + tail), session)
        assert inbound.receipt() == code
        assert inbound.json() is None
        assert session.stats().dropped_undecodable == 0
    finally:
        await session.async_close()


@pytest.mark.parametrize(
    ("channel", "ftype", "length", "ago"),
    [
        (1, FrameType.CMD_TRANSFER, 132, 0.0),  # not the request channel
        (0, FrameType.DOORBELL_PAYLOAD, 132, 0.0),  # a type not sent
        (0, FrameType.CMD_TRANSFER, 133, 0.0),  # longer than any result
        (0, FrameType.CMD_TRANSFER, 3, 0.0),  # too short for a code
        (0, FrameType.CMD_TRANSFER, 132, session_module.RSA_RESULT_WINDOW + 1.0),  # too late
    ],
    ids=["channel-1", "other-type", "133", "3", "expired"],
)
async def test_an_rsa_session_reads_no_result_from_another_frame(
    station: FakeStation, channel: int, ftype: int, length: int, ago: float
) -> None:
    session = make_rsa_session(station)
    try:
        await session.async_connect()
        _sent(session, FrameType.CMD_TRANSFER, ago=ago)
        frame = _result_frame(FRAME_PLAIN, bytes(length), ftype=ftype)
        assert Inbound(channel, frame, session).receipt() is None
    finally:
        await session.async_close()


async def test_a_new_connection_forgets_the_sends_awaiting_results(
    station: FakeStation,
) -> None:
    session = make_rsa_session(station)
    try:
        _sent(session, FrameType.CMD_TRANSFER)  # left from an earlier connection
        await session.async_connect()
        frame = _result_frame(FRAME_PLAIN, bytes(132))
        assert Inbound(0, frame, session).receipt() is None
    finally:
        await session.async_close()


async def test_an_rsa_send_takes_one_result_and_leaves_notifies_alone(
    station: FakeStation,
) -> None:
    """Each send takes the first reply of its type; the next frame of that type, with no
    send waiting, is decoded as JSON like any other frame."""
    session = make_rsa_session(station)
    try:
        await session.async_connect()
        _sent(session, FrameType.CMD_TRANSFER)
        first = _result_frame(FRAME_STATIC_ECB, struct.pack("<i", 0) + _NOISE)
        assert Inbound(0, first, session).receipt() == 0
        notify = _rsa_frame(station, FRAME_STATIC_ECB, b'{"cmd":1350,"code":0}'.ljust(32))
        inbound = Inbound(0, notify, session)
        assert inbound.receipt() is None
        assert inbound.json() == {"cmd": 1350, "code": 0}
    finally:
        await session.async_close()


async def test_a_gcm_session_keeps_its_receipt_rule(station: FakeStation) -> None:
    """A GCM session takes only a GCM-tagged clear int32 + zero bytes as a receipt."""
    station.conn_init_version = CONN_INIT_ECC_VERSION
    gcm = make_session(station, Provider(station))
    try:
        await gcm.async_connect()
        for encryption in (FRAME_PLAIN, FRAME_STATIC_ECB):
            frame = _rsa_frame(station, encryption, bytes(132))
            assert Inbound(0, frame, gcm).receipt() is None
            assert gcm._decode_json(frame) is None
        assert gcm.stats().dropped_undecodable == 2  # decoded as ECB, not skipped as receipts
        receipt = Frame(
            type=FrameType.CMD_TRANSFER,
            subheader=bytes([FrameCipher.GCM, 0, 0, 0, 1, 0]),
            payload=bytes(132),
        )
        noisy = Frame(type=receipt.type, subheader=receipt.subheader, payload=bytes(4) + _NOISE)
        assert Inbound(0, receipt, gcm).receipt() == 0
        assert Inbound(0, noisy, gcm).receipt() is None
    finally:
        await gcm.async_close()


@pytest.mark.parametrize("encryption", [FRAME_PLAIN, FRAME_STATIC_ECB, FRAME_SESSION_ECB])
async def test_an_rsa_session_reads_playback_end_under_any_encryption(
    station: FakeStation, encryption: int
) -> None:
    session = make_rsa_session(station)
    try:
        await session.async_connect()
        frame = _rsa_frame(
            station, encryption, struct.pack("<I", 2) + bytes(12), ftype=FrameType.RECORD_PLAY_CTRL
        )
        assert session._rsa_play_ctrl(frame) == 2
    finally:
        await session.async_close()


@pytest.mark.parametrize("encryption", [FRAME_PLAIN, FRAME_STATIC_ECB, FRAME_SESSION_ECB])
@pytest.mark.parametrize("tail", [None, _NOISE], ids=["zero-area", "noise"])
async def test_an_rsa_session_takes_command_results_in_clear(
    station: FakeStation,
    encryption: int,
    tail: bytes | None,
    short_settle: None,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """Results with the code in clear confirm, refuse and count whatever the encryption
    type and tail; none is counted undecodable. One DEBUG line per result."""
    caplog.set_level(logging.DEBUG, logger=session_module.__name__)
    station.answer_encryption = encryption
    station.answer_tail = tail
    station.reply_to_settings = True
    station.refused_commands = {1276: -1}
    session = make_rsa_session(station)
    try:
        await session.async_get_params()
        outcome = await session.async_send_command(
            1277, channel=0, payload={"night_sion": 1, "channel": 0}
        )
        with pytest.raises(CommandRejectedError) as err:
            await session.async_send_command(1276, channel=0, payload={}, timeout=1.0)
        reply = await session.async_run_recipe(goto_preset(2), timeout=1.0)
        await session.async_send_string_command(1215, "JST-9|1.1307", channel=0, timeout=1.0)
        written = await session.async_send_json_frame(
            1256, lambda account: json.dumps({"account_id": account}).encode(), timeout=1.0
        )
        stats = session.stats()
    finally:
        await session.async_close()
    assert outcome is CommandOutcome.APPLIED
    assert err.value.code == -1
    assert reply.outcome is CommandOutcome.DELIVERED  # the 1700 recipe's result
    assert station.preset_gotos == [2]
    assert written
    assert station.params[0][1215] == "JST-9|1.1307"
    assert stats.receipts_by_code == {"0": 5, "-1": 1}
    assert stats.dropped_undecodable == 0
    label = "zero" if tail is None and encryption == FRAME_PLAIN else "nonzero"
    lines = _messages(caplog, "result 0x06a4")
    assert lines == [
        f"{session._log_name}: result 0x06a4 ch0 enc{encryption} len 132: code 0 TAKEN, tail {label}"
    ]
    assert _messages(caplog, f"rx frame 0x06a4 ch0 v1 enc{encryption} (132 bytes)")


@pytest.mark.parametrize("code", [-1, 5])
async def test_a_refused_recipe_raises_the_result_code(
    station: FakeStation, code: int, monkeypatch: pytest.MonkeyPatch
) -> None:
    station.answer_encryption = FRAME_STATIC_ECB
    station.answer_tail = _NOISE
    monkeypatch.setattr(station, "doorbell_receipt_code", lambda: code)
    session = make_rsa_session(station)
    try:
        with pytest.raises(CommandRejectedError) as err:
            await session.async_run_recipe(goto_preset(2), timeout=1.0)
    finally:
        await session.async_close()
    assert (err.value.code, station.preset_gotos) == (code, [])


@pytest.mark.parametrize("current", [False, True], ids=["change", "already-in-mode"])
async def test_a_result_and_report_confirm_an_arm(
    station: FakeStation, current: bool, short_settle: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A zero result (code in clear, a noise tail) answers the arm, whether the station
    changes its mode or is in it already: never resent, nothing read back."""
    monkeypatch.setattr(session_module, "COMMAND_RESEND_AFTER", 0.1)
    monkeypatch.setattr(session_module, "MODE_REPORT_GRACE", 0.2)
    state_station(station, "type1").answer_encryption = FRAME_STATIC_ECB
    station.answer_tail = _NOISE
    if current:
        station.guard_mode = GuardMode.HOME
        station.params[255][1224] = "1"
    session = make_rsa_session(station)
    try:
        armed = await session.async_set_guard_mode(GuardMode.HOME, timeout=1.0)
        stats = session.stats()
    finally:
        await session.async_close()
    assert armed == station.guard_mode == GuardMode.HOME
    assert [o["cmd"] for o in station.received] == [1224]  # answered: never resent
    assert stats.receipts_by_code == {"0": 1}  # the arm's
    assert stats.dropped_undecodable == 0


def standalone_camera(station: FakeStation) -> FakeStation:
    """``station`` as a standalone camera on an RSA session that reports its mode in no
    dump and sends no mode report: a 132-byte result with a noise tail answers an arm."""
    state_station(station, "type1").answer_encryption = FRAME_STATIC_ECB
    station.answer_tail = _NOISE
    station.mode_reports = False
    station.mode_in_dump = False
    return station


async def test_a_zero_result_applies_an_arm_without_a_mode_report(
    station: FakeStation, short_settle: None, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The arm's own result code 0 is final: the mode is filed as this library's write
    and returned at once, with no resend, no read-back and no report to wait for."""
    monkeypatch.setattr(session_module, "COMMAND_RESEND_AFTER", 0.1)
    standalone_camera(station)
    session = make_rsa_session(station)
    events: list[Event] = []
    session.subscribe(events.append)
    try:
        await session.async_get_params()
        queries = station.param_queries
        started = time.monotonic()
        armed = await session.async_set_guard_mode(GuardMode.HOME, timeout=3.0)
        took = time.monotonic() - started
    finally:
        await session.async_close()
    assert armed is GuardMode.HOME
    assert took < 1.0
    assert [o["cmd"] for o in station.received] == [1224]
    assert station.param_queries == queries
    assert (session.guard_mode, session.active_mode) == (GuardMode.HOME, GuardMode.HOME)
    key = (STATION_CHANNEL, 1224)
    assert session.params[key] == "1"
    assert session.param_origins[key] is ParamOrigin.LOCAL_WRITE
    assert _modes(events)[-1] == (GuardMode.HOME, GuardMode.HOME)


async def test_a_schedule_arm_waits_past_the_slots_report_for_its_result(
    station: FakeStation,
) -> None:
    """The slot's mode report answers no arm to Schedule: the result that follows it
    confirms the selection, without a read-back."""
    station.params[255] |= {1224: "0", 1151: "0"}
    station.schedule_mode = GuardMode.HOME
    station.arm_result_delay = 0.3
    session = make_session(station, Provider(station))
    try:
        await session.async_get_params()
        queries = station.param_queries
        armed = await session.async_set_guard_mode(GuardMode.SCHEDULE, timeout=3.0)
    finally:
        await session.async_close()
    assert armed is GuardMode.SCHEDULE
    assert station.param_queries == queries


async def test_a_zero_result_to_schedule_keeps_the_mode_in_force(
    station: FakeStation, short_settle: None
) -> None:
    standalone_camera(station)
    session = make_rsa_session(station)
    try:
        await session.async_get_params()
        await session.async_set_guard_mode(GuardMode.HOME, timeout=3.0)
        armed = await session.async_set_guard_mode(GuardMode.SCHEDULE, timeout=3.0)
    finally:
        await session.async_close()
    assert armed is GuardMode.SCHEDULE
    assert (session.guard_mode, session.active_mode) == (GuardMode.SCHEDULE, GuardMode.HOME)
    assert session.params[(STATION_CHANNEL, 1224)] == "2"


async def test_a_mode_report_after_an_applied_arm_still_moves_the_mode(
    station: FakeStation, short_settle: None
) -> None:
    """A report that follows (a change made elsewhere) wins over the filed arm, also in
    the parameters a station whose dump lacks the mode reads."""
    standalone_camera(station)
    session = make_rsa_session(station)
    try:
        await session.async_get_params()
        await session.async_set_guard_mode(GuardMode.HOME, timeout=3.0)
        station.send_alarm_mode(GuardMode.AWAY, cipher=FrameCipher.ECB)
        await wait_until(lambda: session.guard_mode == GuardMode.AWAY)
    finally:
        await session.async_close()
    assert session.active_mode is GuardMode.AWAY
    assert session.params[(STATION_CHANNEL, 1224)] == "0"
    assert session.params[(STATION_CHANNEL, 1151)] == "0"


async def test_a_mode_report_files_no_parameter_a_dump_carries(
    station: FakeStation, short_settle: None
) -> None:
    """A station whose dump carries the mode keeps the dump's values until the next dump."""
    station.params[255] |= {1224: "1", 1151: "1"}
    session = make_session(station, Provider(station))
    try:
        await session.async_get_params()
        station.send_alarm_mode(GuardMode.AWAY)
        await wait_until(lambda: session.guard_mode == GuardMode.AWAY)
    finally:
        await session.async_close()
    assert session.params[(STATION_CHANNEL, 1224)] == "1"
    assert (STATION_CHANNEL, 1224) not in session.param_origins


@pytest.mark.parametrize("rsa", [False, True], ids=["gcm", "rsa"])
async def test_an_arm_as_the_station_scalar(
    station: FakeStation, rsa: bool, short_settle: None
) -> None:
    """The scalar form: frame type 1224, ``[u32 mode][char[128] account]`` on channel 255,
    no payload object; the camera refuses the payload form with -103."""
    station.refused_commands = {1224: -103}
    station.mode_reports = False
    station.mode_in_dump = False
    session = make_rsa_session(station) if rsa else make_session(station, Provider(station))
    try:
        armed = await session.async_set_guard_mode(GuardMode.HOME, timeout=3.0, scalar=True)
        disarmed = await session.async_set_guard_mode(GuardMode.DISARMED, timeout=3.0, scalar=True)
        with pytest.raises(CommandUnsupportedError) as refused:
            await session.async_set_guard_mode(GuardMode.AWAY, timeout=3.0)
        # An RSA session sends every command under its own key, the scalar included.
        encryption = session._session_encryption if rsa else FRAME_STATIC_ECB
    finally:
        await session.async_close()
    assert (armed, disarmed) == (GuardMode.HOME, GuardMode.DISARMED)
    assert station.ecb_received == [(1224, 255, 1), (1224, 255, 63)]
    assert station.ecb_encryptions == [encryption, encryption]
    assert station.guard_mode == GuardMode.DISARMED
    assert [o["cmd"] for o in station.received] == [1224]  # only the refused payload form
    assert (refused.value.command, refused.value.code) == (1224, -103)
    assert session.guard_mode is GuardMode.DISARMED


def test_a_scalar_result_needs_its_type_and_four_bytes(station: FakeStation) -> None:
    session = make_session(station, Provider(station))
    replies = [
        Frame(1224, b"", b"\x00\x00\x00"),  # too short for a result code
        Frame(1224, b"", struct.pack("<i", -103)),
        Frame(1225, b"", struct.pack("<i", 0)),  # another command's
    ]
    codes = [_scalar_result(Inbound(0, frame, session), 1224) for frame in replies]
    assert codes == [None, -103, None]


async def test_a_scalar_arm_refused_raises_its_code(station: FakeStation) -> None:
    station.refused_scalars = {1224: -104}
    session = make_session(station, Provider(station))
    try:
        with pytest.raises(CommandRejectedError) as err:
            await session.async_set_guard_mode(GuardMode.HOME, timeout=3.0, scalar=True)
    finally:
        await session.async_close()
    assert type(err.value) is CommandRejectedError
    assert (err.value.command, err.value.code) == (1224, -104)
    assert session.guard_mode != GuardMode.HOME


async def test_a_scalar_setting_refused_as_invalid_is_unsupported(station: FakeStation) -> None:
    station.refused_scalars = {1214: -103}
    session = make_session(station, Provider(station))
    try:
        with pytest.raises(CommandUnsupportedError) as err:
            await session.async_send_ecb_scalar(1214, 1, channel=0, timeout=3.0)
    finally:
        await session.async_close()
    assert (err.value.command, err.value.code) == (1214, -103)


@pytest.mark.parametrize(
    ("code", "error"),
    [
        (RECEIPT_NOT_HANDLED, CommandUnsupportedError),
        (-103, CommandUnsupportedError),
        (-1, CommandRejectedError),
    ],
)
async def test_a_result_refusing_an_arm_raises_its_code(
    station: FakeStation, code: int, error: type[CommandRejectedError]
) -> None:
    station.answer_encryption = FRAME_STATIC_ECB
    station.answer_tail = _NOISE
    station.refused_commands = {1224: code}
    session = make_rsa_session(station)
    try:
        with pytest.raises(error) as err:
            await session.async_set_guard_mode(GuardMode.HOME, timeout=5.0)
    finally:
        await session.async_close()
    assert type(err.value) is error
    assert (err.value.command, err.value.code) == (1224, code)


async def test_an_rsa_arm_takes_only_the_result_after_those_owed_before_it(
    station: FakeStation, short_settle: None
) -> None:
    """A result owed to an earlier send, arriving after the arm's, is that send's: the
    arm takes the next one."""
    standalone_camera(station)
    station.arm_result_delay = 0.3
    session = make_rsa_session(station)
    try:
        await session.async_get_params()
        before = dict(session.stats().receipts_by_code)
        _sent(session, FrameType.CMD_TRANSFER)  # an earlier request, its result owed
        arm = asyncio.ensure_future(session.async_set_guard_mode(GuardMode.HOME, timeout=3.0))
        await wait_until(lambda: [o["cmd"] for o in station.received] == [1224])
        station.send_receipt(FrameType.CMD_TRANSFER, -1)  # the earlier request's result
        armed = await arm
        after = session.stats().receipts_by_code
    finally:
        await session.async_close()
    assert armed is GuardMode.HOME
    assert after == before | {"-1": 1, "0": before.get("0", 0) + 1}


DOORBELL_SN = "T8200P2000054321"
"""A synthetic serial of a model outside the app's static-key fallback list."""


@pytest.mark.parametrize(
    "case",
    [
        (SYNTHETIC.station_sn, 42, "intact", None, FRAME_SESSION_ECB),
        (SYNTHETIC.station_sn, 0, "absent", None, FRAME_STATIC_ECB),
        (DOORBELL_SN, 0, "absent", FRAME_PLAIN, FRAME_PLAIN),
        (SYNTHETIC.station_sn, 42, "unparsable", None, FRAME_STATIC_ECB),
        (DOORBELL_SN, 42, "unparsable", None, FRAME_PLAIN),
    ],
    ids=[
        "static-key-wrapped",
        "no-cipher-homebase",
        "no-cipher-clear",
        "unparsable-key-homebase",
        "unparsable-key-clear",
    ],
)
async def test_a_static_key_rsa_session_takes_the_station_state_unauthenticated(
    station: FakeStation,
    case: tuple[str, int, str, int | None, int],
    short_settle: None,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
) -> None:
    """An RSA session whose key is the static key takes the station's state under the
    static key or in clear and authenticates no push; only clear state is logged. It sends type 2 after a wrapped
    key; with no session key (no cipher named, or a cipher key that does not parse),
    type 1 to a HomeBase-family model, clear to any other."""
    monkeypatch.setattr(session_module, "MODE_REPORT_GRACE", 0.2)
    caplog.set_level(logging.INFO, logger=session_module.__name__)
    serial, cipher_id, rsa_key, station_encryption, sent = case
    station.serial = serial
    station.static_key = static_key(serial, station.did)
    station.static_key_session = True
    station.cipher_id = cipher_id
    station.station_encryption = station_encryption
    station.answer_encryption = FRAME_STATIC_ECB
    station.reply_to_settings = True
    own = dict(station.params[STATION_CHANNEL])  # before the arm changes it
    session = StationSession(
        serial,
        RsaProvider(station, rsa_key=rsa_key != "absent", bad_key=rsa_key == "unparsable"),
        host="127.0.0.1",
        port=station.discovery_port,
    )
    station.conn_init_version = 1
    events: list[Event] = []
    session.subscribe(events.append)
    try:
        await session.async_connect()
        dump = await session.async_get_params()
        outcome = await session.async_send_command(
            1277, channel=0, payload={"night_sion": 1, "channel": 0}
        )
        station.push_camera_event()
        await wait_until(lambda: any(isinstance(e, SecurityEvent) for e in events))
        armed = await session.async_set_guard_mode(GuardMode.HOME, timeout=1.0)
        stats = session.stats()
        assert session.rsa_session
    finally:
        await session.async_close()
    assert stats.static_key_session
    assert armed == GuardMode.HOME  # its state confirms an arm
    assert stats.state_authenticated is False
    logged = _messages(caplog, "(unauthenticated), taken as the eufy app does")
    assert bool(logged) == (station_encryption == FRAME_PLAIN)
    assert all("arrived in clear" in line for line in logged)
    assert dump.station == own
    assert outcome is CommandOutcome.APPLIED
    assert station.client_encryptions == {sent}
    assert (stats.ecb_state_refused, stats.cipher_id) == (0, cipher_id)
    push = next(e for e in events if isinstance(e, SecurityEvent))
    assert (push.session_ecb, push.authenticated) == (False, False)


async def test_an_rsa_conn_init_without_an_rsa_key_is_unusable_after_one_refresh(
    station: FakeStation,
) -> None:
    """Credentials without the RSA key are re-fetched once; still without it, the cipher
    is unusable (not a rejected key) and no stale-key latch is set."""
    provider = RsaProvider(station, rsa_key=False)
    latch = MemoryKeyRefreshLatch()
    session = make_rsa_session(station, provider, key_refresh=latch)
    try:
        with pytest.raises(CipherUnusableError, match="no RSA private key") as err:
            await session.async_connect()
    finally:
        await session.async_close()
    assert (err.value.reason, err.value.cipher_id) == ("no_rsa_key", station.cipher_id)
    assert provider.calls == [False, True]
    assert latch.retry_blocked_for() == 0.0


async def test_an_rsa_key_missing_from_the_cache_is_fetched_once(station: FakeStation) -> None:
    provider = RsaProvider(station, cached_rsa_key=False)
    session = make_rsa_session(station, provider)
    try:
        await session.async_connect()
        assert session.rsa_session
    finally:
        await session.async_close()
    assert provider.calls == [False, True]


async def test_a_refetched_rsa_key_that_does_not_parse_leaves_the_static_key(
    station: FakeStation,
) -> None:
    """A rejected key is re-fetched once; a re-fetched key that does not parse leaves
    the session under the static key, neither KeyRejectedError nor CipherUnusableError."""
    other = FakeStation().rsa_private_key_pem  # a valid key that unwraps noise
    calls: list[bool] = []

    async def provider(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        calls.append(refresh)
        key = station.rsa_private_key_pem.lower() if refresh else other
        return P2PCredentials(SYNTHETIC.account_id, "user", "", rsa_private_key=key)

    session = make_rsa_session(station, provider)
    try:
        await session.async_connect()
        assert session.static_key_session
    finally:
        await session.async_close()
    assert calls == [False, True]


async def test_a_cipher_still_mismatching_after_a_refresh_fails_without_the_latch(
    station: FakeStation,
) -> None:
    """Credentials of another cipher than CONN_INIT names, even after one refresh: a
    handshake error naming both ciphers, and no stale-key latch (no key was rejected)."""
    calls: list[tuple[bool, int | None]] = []

    async def provider(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        calls.append((refresh, cipher_id))
        key = station.ecc_private_key_hex
        return P2PCredentials(SYNTHETIC.account_id, "user", key, cipher_id=station.cipher_id + 1)

    latch = MemoryKeyRefreshLatch()
    session = StationSession(
        SYNTHETIC.station_sn,
        provider,
        host="127.0.0.1",
        port=station.discovery_port,
        key_refresh=latch,
    )
    try:
        with pytest.raises(
            HandshakeError, match=f"names cipher {station.cipher_id}, the key"
        ) as err:
            await session.async_connect()
    finally:
        await session.async_close()
    assert not isinstance(err.value, KeyRejectedError)
    assert latch.retry_blocked_for() == 0
    cipher = station.cipher_id
    assert calls == [(False, cipher), (True, cipher)]


async def test_an_ecies_conn_init_without_an_ecc_key_is_unusable(station: FakeStation) -> None:
    """Version 8 with no ``ecc_private_key`` held, even after one refresh: unusable."""
    calls: list[bool] = []

    async def provider(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        calls.append(refresh)
        return P2PCredentials(SYNTHETIC.account_id, "user", "")

    latch = MemoryKeyRefreshLatch()
    session = StationSession(
        SYNTHETIC.station_sn,
        provider,
        host="127.0.0.1",
        port=station.discovery_port,
        key_refresh=latch,
    )
    try:
        with pytest.raises(CipherUnusableError) as err:
            await session.async_connect()
    finally:
        await session.async_close()
    assert (err.value.reason, err.value.cipher_id) == ("no_ecc_key", station.cipher_id)
    assert calls == [False, True]
    assert latch.retry_blocked_for() == 0.0


async def test_an_rsa_key_that_does_not_parse_leaves_the_static_key_unfetched(
    station: FakeStation,
) -> None:
    """A key that cannot be parsed is not re-fetched (the cloud serves the same bytes)
    and sets no stale-key latch; like the app, the session runs under the static key,
    and a reconnect does the same."""
    station.conn_init_version = 1
    provider = RsaProvider(station, bad_key=True)
    latch = MemoryKeyRefreshLatch()
    session = StationSession(
        SYNTHETIC.station_sn,
        provider,
        host="127.0.0.1",
        port=station.discovery_port,
        key_refresh=latch,
    )
    try:
        await session.async_connect()
        assert session.static_key_session
        assert provider.calls == [False]  # read once after CONN_INIT, never re-fetched
        assert latch.retry_blocked_for() == 0.0  # and no latch was set

        session._teardown("test reconnect")
        await session.async_connect()
        assert session.static_key_session
        assert provider.calls[0] is False
        assert True not in provider.calls
        assert latch.retry_blocked_for() == 0.0
    finally:
        await session.async_close()
