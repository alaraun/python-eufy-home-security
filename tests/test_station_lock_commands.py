"""Lock and unlock over a station session (``Station.async_lock`` / ``async_unlock``,
``Station.lock_control``) against the fake station and its fake locks."""

from __future__ import annotations

import asyncio
import dataclasses
import gc
import time
from collections.abc import AsyncIterator, Callable
from types import MappingProxyType

import pytest

from eufy_home_security.client import EufySecurity
from eufy_home_security.cloud.models import CloudDevice
from eufy_home_security.devices._lock_routes_data import LOCK_ROUTES
from eufy_home_security.devices.lock_routes import LockForm
from eufy_home_security.devices.locks import LockState, LockStateSource
from eufy_home_security.events import Event, EventSource, LockStateChanged, SecurityEvent
from eufy_home_security.exceptions import (
    AccountRejectedError,
    CommandRejectedError,
    DeviceBusyError,
    DeviceTimeoutError,
    GuestAccessError,
    LockNotMovedError,
    UnsupportedError,
)
from eufy_home_security.lock_commands import control
from eufy_home_security.lock_commands.actions import LockAction, LockReply, LockResult
from eufy_home_security.lock_commands.control import LockPath
from eufy_home_security.mqtt.locks import MqttLocks
from eufy_home_security.p2p import session as session_module
from eufy_home_security.p2p.session import P2PCredentials, StationSession
from eufy_home_security.station import Station
from eufy_home_security.station import lock_control as lock_control_module
from eufy_home_security.testing import (
    SYNTHETIC,
    FakeCloud,
    FakeLock,
    FakeStation,
    build_eufy_security,
    warm_store,
)

STATION = CloudDevice(
    device_sn=SYNTHETIC.station_sn,
    device_type=0,
    name="Home Base",
    station_sn=SYNTHETIC.station_sn,
    p2p_did=SYNTHETIC.did,
)
NOW = 1_700_000_000.0


def _lock(serial: str, channel: int = 1, **changes: object) -> CloudDevice:
    device = CloudDevice(
        device_sn=serial,
        device_type=52,
        name="Front",
        station_sn=SYNTHETIC.station_sn,
        channel=channel,
        owner_user_id="0" * 40,
        member_type=2,
        member_user_id=SYNTHETIC.account_id,
        short_user_id="0001",
    )
    return dataclasses.replace(device, **changes)  # type: ignore[arg-type]


class _Cloud:
    """The account's user id and the locks' public keys, as the cloud client gives them."""

    def __init__(self, *locks: FakeLock) -> None:
        self.user_id: str | None = SYNTHETIC.account_id
        self.display_name = "Synthetic Nick"
        self.keys = {k: v for lock in locks for k, v in lock.public_keys().items()}
        self.asked: list[tuple[str, int]] = []

    async def async_get_lock_public_key(self, device_sn: str, key_type: int) -> bytes:
        self.asked.append((device_sn, key_type))
        return self.keys[(device_sn, key_type)]


@pytest.fixture
async def fake() -> AsyncIterator[FakeStation]:
    station = FakeStation()
    station.params[255][1224] = "63"
    await station.start()
    yield station
    station.stop()


@pytest.fixture(autouse=True)
def fixed_clock(monkeypatch: pytest.MonkeyPatch) -> None:
    """A fixed wall clock for the commands' time values and sequence numbers."""
    original = lock_control_module.StationLockControl.__init__

    def init(self: lock_control_module.StationLockControl, *args: object, **kw: object) -> None:
        kw.setdefault("clock", lambda: NOW)
        original(self, *args, **kw)  # type: ignore[arg-type]

    monkeypatch.setattr(lock_control_module.StationLockControl, "__init__", init)


def _session(fake: FakeStation) -> StationSession:
    async def credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "Nick", fake.ecc_private_key_hex)

    return StationSession(
        SYNTHETIC.station_sn, credentials, host="127.0.0.1", port=fake.discovery_port
    )


async def _hub(
    fake: FakeStation, device: CloudDevice, lock: FakeLock, cloud: _Cloud | None = None
) -> Station:
    fake.locks[lock.channel] = lock
    fake.params.setdefault(lock.channel, {})[1912] = str(lock.state_code)
    station = Station(
        STATION,
        _session(fake),
        sub_devices=[device],
        lock_cloud=cloud if cloud is not None else _Cloud(lock),
    )
    await station.async_update()
    return station


def _events(station: Station) -> list[Event]:
    seen: list[Event] = []
    station.subscribe(seen.append)
    return seen


# ── 1940 (cm2 through data) ──────────────────────────────────────────────────

LOCK_1940 = "T8502P2000000001"


@pytest.fixture
def lock_1940() -> FakeLock:
    return FakeLock(serial=LOCK_1940, channel=1, user_id=SYNTHETIC.account_id)


async def test_a_lock_is_confirmed_by_its_status_report(
    fake: FakeStation, lock_1940: FakeLock
) -> None:
    station = await _hub(fake, _lock(LOCK_1940), lock_1940)
    events = _events(station)
    try:
        assert station.lock_control(LOCK_1940).path is LockPath.STATION
        assert await station.async_lock(LOCK_1940) is LockState.LOCKED
    finally:
        await station.async_close()
    assert lock_1940.received == [(1940, LockAction.LOCK, int(NOW) + 1)]
    changes = [(e.state, e.source) for e in events if isinstance(e, LockStateChanged)]
    assert changes == [
        (LockState.LOCKING, LockStateSource.COMMAND),  # the lock took it
        (LockState.LOCKED, LockStateSource.LOCK),
    ]
    assert station.lock_state(LOCK_1940).state is LockState.LOCKED  # type: ignore[union-attr]


async def test_an_unlock_is_confirmed_by_the_unlocked_state(
    fake: FakeStation, lock_1940: FakeLock
) -> None:
    lock_1940.state_code = 4
    station = await _hub(fake, _lock(LOCK_1940), lock_1940)
    try:
        assert await station.async_unlock(LOCK_1940) is LockState.UNLOCKED
    finally:
        await station.async_close()
    assert lock_1940.received == [(1940, LockAction.UNLOCK, int(NOW) + 1)]


async def test_a_lock_already_in_the_asked_state_sends_nothing(
    fake: FakeStation, lock_1940: FakeLock
) -> None:
    lock_1940.state_code = 4
    station = await _hub(fake, _lock(LOCK_1940), lock_1940)
    try:
        assert await station.async_lock(LOCK_1940) is LockState.LOCKED
    finally:
        await station.async_close()
    assert lock_1940.received == []


@pytest.mark.parametrize("code", [1, 48, 49])
async def test_a_refusing_answer_raises_with_the_locks_code(
    fake: FakeStation, lock_1940: FakeLock, code: int
) -> None:
    lock_1940.answer_code = code
    station = await _hub(fake, _lock(LOCK_1940), lock_1940)
    try:
        with pytest.raises(CommandRejectedError) as raised:
            await station.async_lock(LOCK_1940)
    finally:
        await station.async_close()
    assert (raised.value.command, raised.value.code) == (1940, code)


async def test_a_station_refusal_raises_its_code(fake: FakeStation, lock_1940: FakeLock) -> None:
    lock_1940.result_code = -104
    station = await _hub(fake, _lock(LOCK_1940), lock_1940)
    try:
        with pytest.raises(AccountRejectedError):
            await station.async_lock(LOCK_1940)
    finally:
        await station.async_close()


async def test_a_sequence_refusal_keeps_waiting_for_the_locks_answer(
    fake: FakeStation, lock_1940: FakeLock
) -> None:
    lock_1940.result_code = -151
    station = await _hub(fake, _lock(LOCK_1940), lock_1940)
    try:
        assert await station.async_lock(LOCK_1940) is LockState.LOCKED
    finally:
        await station.async_close()


@pytest.mark.parametrize(
    ("result_code", "error"), [(-151, CommandRejectedError), (0, DeviceTimeoutError)]
)
async def test_a_sequence_refusal_without_an_answer_raises_its_code(
    fake: FakeStation, lock_1940: FakeLock, result_code: int, error: type[Exception]
) -> None:
    """A -151 with no answer and no sequence report ends as that refusal, bounded by the
    timeout; a silent lock after an accepted send is a timeout."""
    lock_1940.result_code, lock_1940.answer = result_code, False
    station = await _hub(fake, _lock(LOCK_1940), lock_1940)
    try:
        async with asyncio.timeout(5):
            with pytest.raises(error) as raised:
                await station.async_lock(LOCK_1940, timeout=0.5)
    finally:
        await station.async_close()
    if result_code:
        assert raised.value.code == -151  # type: ignore[attr-defined]
    else:
        assert "no answer" in str(raised.value)


async def test_a_resend_the_station_takes_ends_as_a_timeout_when_the_lock_is_silent(
    fake: FakeStation, lock_1940: FakeLock
) -> None:
    """After a refused send and an accepted resend, a silent lock is a timeout, not -151."""
    lock_1940.seq_report, lock_1940.answer = 500, False
    station = await _hub(fake, _lock(LOCK_1940), lock_1940)
    try:
        async with asyncio.timeout(5):
            with pytest.raises(DeviceTimeoutError, match="no answer"):
                await station.async_lock(LOCK_1940, timeout=0.5)
    finally:
        await station.async_close()
    assert [seq for _, _, seq in lock_1940.received] == [int(NOW) + 1, 502]


async def test_a_1961_lock_without_a_state_waits_the_answer_and_the_state_time(
    fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The station's result to a 1961 command is the lock's answer: the state wait follows."""
    monkeypatch.setattr(lock_control_module, "LOCK_ANSWER_TIMEOUT", 0.2)
    monkeypatch.setattr(lock_control_module, "LOCK_CONFIRM_TIMEOUT", 0.3)
    serial = "T8520P2000000001"
    lock = FakeLock(serial=serial, channel=1, report=False)
    station = await _hub(fake, _lock(serial), lock)
    try:
        async with asyncio.timeout(5):
            with pytest.raises(DeviceTimeoutError, match="locked state"):
                await station.async_lock(serial)
    finally:
        await station.async_close()


async def test_a_1961_command_the_station_only_acknowledges_has_no_answer(
    fake: FakeStation, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A station that takes a 1961 command without a result gave no lock answer: the
    command times out waiting for it, not for the state."""
    monkeypatch.setattr(session_module, "COMMAND_TIMEOUT", 0.2)
    monkeypatch.setattr(session_module, "COMMAND_RECEIPT_TIMEOUT", 0.3)
    serial = "T8530P2000000001"
    lock = FakeLock(serial=serial, channel=1, result=False)
    station = await _hub(fake, _lock(serial), lock)
    try:
        async with asyncio.timeout(5):
            with pytest.raises(DeviceTimeoutError, match="no answer"):
                await station.async_lock(serial, timeout=1.5)
    finally:
        await station.async_close()
    assert len(lock.received) == 1


async def test_the_state_wins_over_a_refusing_answer_taken_in_the_same_turn(
    fake: FakeStation, lock_1940: FakeLock
) -> None:
    """When the asked state and a refusing answer are both in when the wait ends, the
    state decides."""
    station = await _hub(fake, _lock(LOCK_1940), lock_1940)
    loop = asyncio.get_running_loop()
    pending = lock_control_module._Pending(
        LOCK_1940,
        LockForm.P2P_1940,
        LockAction.LOCK,
        lock_control_module._Sent(1940, {}),
        answer=loop.create_future(),
        state=loop.create_future(),
    )
    pending.answer.set_result(LockReply(1, LockResult.REFUSED))
    pending.state.set_result(LockState.LOCKED)
    try:
        done = await station._lock_control._first(pending, 1.0, LOCK_1940, "answer")
    finally:
        await station.async_close()
    assert done is pending.state


async def test_a_sequence_report_after_the_answer_sends_no_second_command(
    fake: FakeStation, lock_1940: FakeLock
) -> None:
    """A 1916 that names the command after the lock answered it resends nothing."""
    lock_1940.seq_after_answer, lock_1940.report = 900, False
    station = await _hub(fake, _lock(LOCK_1940), lock_1940)
    try:
        async with asyncio.timeout(5):
            with pytest.raises(DeviceTimeoutError, match="locked state"):
                await station.async_lock(LOCK_1940, timeout=0.5)
    finally:
        await station.async_close()
    assert len(lock_1940.received) == 1


async def test_a_sequence_report_of_another_form_leaves_the_1961_counter(
    fake: FakeStation,
) -> None:
    """A 1940 lock's sequence report does not move the counter of the 1961 locks."""
    cm2_lock = FakeLock(serial=LOCK_1940, channel=1, user_id=SYNTHETIC.account_id)
    cm2_lock.seq_report = 5000
    serial = "T8520P2000000001"
    anker_lock = FakeLock(serial=serial, channel=2)
    fake.locks[2] = anker_lock
    fake.params.setdefault(2, {})[1912] = str(anker_lock.state_code)
    devices = [_lock(LOCK_1940), _lock(serial, channel=2)]
    fake.locks[1] = cm2_lock
    fake.params.setdefault(1, {})[1912] = str(cm2_lock.state_code)
    station = Station(
        STATION, _session(fake), sub_devices=devices, lock_cloud=_Cloud(cm2_lock, anker_lock)
    )
    await station.async_update()
    try:
        assert await station.async_lock(LOCK_1940) is LockState.LOCKED
        assert await station.async_lock(serial) is LockState.LOCKED
    finally:
        await station.async_close()
    seq = anker_lock.received[-1][2]
    assert seq is not None
    assert seq < 1000


async def test_an_answer_to_another_request_is_skipped(
    fake: FakeStation, lock_1940: FakeLock
) -> None:
    lock_1940.mismatch_first = True
    lock_1940.answer_code = 1  # the real answer refuses; the stale one would accept
    station = await _hub(fake, _lock(LOCK_1940), lock_1940)
    try:
        with pytest.raises(CommandRejectedError) as raised:
            await station.async_lock(LOCK_1940)
    finally:
        await station.async_close()
    assert raised.value.code == 1


async def test_a_sequence_report_resends_with_the_next_number(
    fake: FakeStation, lock_1940: FakeLock
) -> None:
    lock_1940.seq_report = 500
    station = await _hub(fake, _lock(LOCK_1940), lock_1940)
    try:
        assert await station.async_lock(LOCK_1940) is LockState.LOCKED
    finally:
        await station.async_close()
    assert [seq for _, _, seq in lock_1940.received] == [int(NOW) + 1, 502]


async def test_no_state_report_times_out(fake: FakeStation, lock_1940: FakeLock) -> None:
    lock_1940.report = False
    station = await _hub(fake, _lock(LOCK_1940), lock_1940)
    try:
        with pytest.raises(DeviceTimeoutError, match="locked state"):
            await station.async_lock(LOCK_1940, timeout=0.5)
    finally:
        await station.async_close()


@pytest.mark.parametrize(
    ("what", "constant"),
    [("answer", "LOCK_ANSWER_TIMEOUT"), ("locked state", "LOCK_CONFIRM_TIMEOUT")],
)
async def test_a_bound_longer_than_a_wait_keeps_that_wait(
    fake: FakeStation,
    lock_1940: FakeLock,
    monkeypatch: pytest.MonkeyPatch,
    what: str,
    constant: str,
) -> None:
    """``timeout`` caps the whole call, each wait keeps its own default within it: a lock
    that never answers (or never reports) ends at the app's wait, not at the bound."""
    monkeypatch.setattr(lock_control_module, constant, 0.3)
    if what == "answer":
        lock_1940.answer = False
    else:
        lock_1940.report = False
    station = await _hub(fake, _lock(LOCK_1940), lock_1940)
    loop = asyncio.get_running_loop()
    try:
        started = loop.time()
        async with asyncio.timeout(5):
            with pytest.raises(DeviceTimeoutError, match=rf"no {what} within 0\.3 s"):
                await station.async_lock(LOCK_1940, timeout=75)
        assert loop.time() - started < 3
    finally:
        await station.async_close()


async def test_a_fault_state_raises_lock_not_moved(fake: FakeStation, lock_1940: FakeLock) -> None:
    lock_1940.move_to = 5
    station = await _hub(fake, _lock(LOCK_1940), lock_1940)
    try:
        with pytest.raises(LockNotMovedError) as raised:
            await station.async_lock(LOCK_1940)
    finally:
        await station.async_close()
    assert raised.value.state is LockState.INTERMEDIATE


async def test_a_second_command_while_one_waits_is_busy(
    fake: FakeStation, lock_1940: FakeLock
) -> None:
    lock_1940.report = False
    station = await _hub(fake, _lock(LOCK_1940), lock_1940)
    try:
        first = asyncio.create_task(station.async_lock(LOCK_1940, timeout=2))
        await asyncio.sleep(0.05)
        with pytest.raises(DeviceBusyError):
            await station.async_unlock(LOCK_1940)
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
    finally:
        await station.async_close()
    assert len(lock_1940.received) == 1


# ── a command the lock took, its call cancelled or failed ─────────────────────


async def _until(predicate: Callable[[], bool]) -> None:
    async with asyncio.timeout(5):
        while not predicate():
            await asyncio.sleep(0.01)


def _state(station: Station) -> LockState | None:
    reading = station.lock_state(LOCK_1940)
    return None if reading is None else reading.state


@pytest.fixture
def locked_1940(lock_1940: FakeLock) -> FakeLock:
    """The 1940 lock, reported locked, reporting no state after a command."""
    lock_1940.state_code = 4
    lock_1940.report = False
    return lock_1940


async def test_a_cancelled_command_the_lock_took_keeps_it_moving_and_the_next_is_sent(
    fake: FakeStation, locked_1940: FakeLock
) -> None:
    """An unlock the lock took whose call is cancelled keeps the lock unlocking; a lock
    command then is sent although the last report is locked, and its report ends the
    hold."""
    station = await _hub(fake, _lock(LOCK_1940), locked_1940)
    events = _events(station)
    try:
        assert _state(station) is LockState.LOCKED
        unlocking = asyncio.create_task(station.async_unlock(LOCK_1940))
        await _until(lambda: _state(station) is LockState.UNLOCKING)
        unlocking.cancel()
        with pytest.raises(asyncio.CancelledError):
            await unlocking
        held = station.lock_state(LOCK_1940)
        assert held is not None
        assert (held.state, held.source) == (LockState.UNLOCKING, LockStateSource.COMMAND)
        locked_1940.report = True
        assert await station.async_lock(LOCK_1940) is LockState.LOCKED
        assert station._locks._hold_expiry == {}
    finally:
        await station.async_close()
    assert [a for _, a, _ in locked_1940.received] == [LockAction.UNLOCK, LockAction.LOCK]
    changes = [(e.state, e.source) for e in events if isinstance(e, LockStateChanged)]
    assert changes == [
        (LockState.UNLOCKING, LockStateSource.COMMAND),
        (LockState.LOCKING, LockStateSource.COMMAND),
        (LockState.LOCKED, LockStateSource.LOCK),
    ]


async def test_a_timed_out_command_keeps_it_moving_until_the_locks_next_report(
    fake: FakeStation, locked_1940: FakeLock
) -> None:
    station = await _hub(fake, _lock(LOCK_1940), locked_1940)
    try:
        with pytest.raises(DeviceTimeoutError, match="unlocked state"):
            await station.async_unlock(LOCK_1940, timeout=0.3)
        assert _state(station) is LockState.UNLOCKING
        fake.params[locked_1940.channel][1912] = "3"
        fake.send_param_dump()
        await _until(lambda: _state(station) is LockState.UNLOCKED)
        assert station.lock_state(LOCK_1940).source is LockStateSource.P2P  # type: ignore[union-attr]
        assert station._locks._hold_expiry == {}
    finally:
        await station.async_close()


@pytest.mark.parametrize(
    ("event_type", "state"),
    [(262, LockState.LOCKED), (517, LockState.JAMMED)],
    ids=["opposite", "jammed"],
)
async def test_a_held_move_ends_at_any_report_not_only_the_asked_state(
    fake: FakeStation, locked_1940: FakeLock, event_type: int, state: LockState
) -> None:
    """A timed-out unlock's hold ends at the lock's next report whatever it says: the
    opposite state as well as a fault."""
    station = await _hub(fake, _lock(LOCK_1940), locked_1940)
    try:
        with pytest.raises(DeviceTimeoutError, match="unlocked state"):
            await station.async_unlock(LOCK_1940, timeout=0.3)
        assert _state(station) is LockState.UNLOCKING
        push = SecurityEvent(
            source=EventSource.CLOUD,
            device_sn=LOCK_1940,
            event_type=event_type,
            event_time_ms=int(time.time() * 1000),
        )
        assert station.note_lock_push(push) is True
        reading = station.lock_state(LOCK_1940)
        assert reading is not None
        assert (reading.state, reading.source) == (state, LockStateSource.PUSH)
        assert station._locks._hold_expiry == {}
    finally:
        await station.async_close()


async def test_a_command_cancelled_before_the_lock_took_it_holds_nothing(
    fake: FakeStation, locked_1940: FakeLock
) -> None:
    locked_1940.answer = False
    station = await _hub(fake, _lock(LOCK_1940), locked_1940)
    events = _events(station)
    try:
        unlocking = asyncio.create_task(station.async_unlock(LOCK_1940))
        await _until(lambda: bool(locked_1940.received))
        unlocking.cancel()
        with pytest.raises(asyncio.CancelledError):
            await unlocking
        assert station.lock_state(LOCK_1940).source is LockStateSource.P2P  # type: ignore[union-attr]
    finally:
        await station.async_close()
    assert not [e for e in events if isinstance(e, LockStateChanged)]


async def test_a_held_move_ends_at_the_confirm_wait_after_the_take(
    fake: FakeStation, locked_1940: FakeLock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A lost report cannot leave the lock moving for good: the hold ends
    ``LOCK_CONFIRM_TIMEOUT`` after the take, and the lock reads its last report again."""
    monkeypatch.setattr(control, "LOCK_CONFIRM_TIMEOUT", 0.4)
    station = await _hub(fake, _lock(LOCK_1940), locked_1940)
    events = _events(station)
    try:
        unlocking = asyncio.create_task(station.async_unlock(LOCK_1940))
        await _until(lambda: _state(station) is LockState.UNLOCKING)
        taken = asyncio.get_running_loop().time()
        unlocking.cancel()
        with pytest.raises(asyncio.CancelledError):
            await unlocking
        expiry = station._locks._hold_expiry[LOCK_1940]
        assert expiry.when() == pytest.approx(taken + 0.4, abs=0.1)
        await _until(lambda: _state(station) is LockState.LOCKED)
        assert station._locks._hold_expiry == {}
    finally:
        await station.async_close()
    last = [e for e in events if isinstance(e, LockStateChanged)][-1]
    assert (last.state, last.source, last.changed) == (LockState.LOCKED, LockStateSource.P2P, True)


async def test_closing_the_station_cancels_a_held_moves_expiry(
    fake: FakeStation, locked_1940: FakeLock
) -> None:
    station = await _hub(fake, _lock(LOCK_1940), locked_1940)
    try:
        unlocking = asyncio.create_task(station.async_unlock(LOCK_1940))
        await _until(lambda: _state(station) is LockState.UNLOCKING)
        unlocking.cancel()
        with pytest.raises(asyncio.CancelledError):
            await unlocking
        expiry = station._locks._hold_expiry[LOCK_1940]
    finally:
        await station.async_close()
    assert expiry.cancelled()
    assert station._locks._hold_expiry == {}


async def test_a_refusing_status_report_ends_the_move(
    fake: FakeStation, lock_1940: FakeLock
) -> None:
    """The lock took the command, then refused it in its status report: it does not move,
    and reads its last report again."""
    lock_1940.status_code = 2
    station = await _hub(fake, _lock(LOCK_1940), lock_1940)
    try:
        with pytest.raises(CommandRejectedError):
            await station.async_lock(LOCK_1940, timeout=5)
        reading = station.lock_state(LOCK_1940)
    finally:
        await station.async_close()
    assert reading is not None
    assert (reading.state, reading.source) == (LockState.UNLOCKED, LockStateSource.P2P)


async def test_a_reading_taken_while_connecting_does_not_end_the_command(
    fake: FakeStation, lock_1940: FakeLock, monkeypatch: pytest.MonkeyPatch
) -> None:
    """The connect's parameter dump repeats a fault code from before the command: only a
    reading after the send counts, as the app's wait starts at the send. The command
    connects before it is built."""
    lock_1940.state_code = 5
    fake.locks[lock_1940.channel] = lock_1940
    fake.params.setdefault(lock_1940.channel, {})[1912] = "5"
    station = Station(
        STATION, _session(fake), sub_devices=[_lock(LOCK_1940)], lock_cloud=_Cloud(lock_1940)
    )
    connect = station.session.async_connect
    dumped: list[bool] = []

    async def connect_with_dump() -> None:
        await connect()
        if not dumped:
            dumped.append(True)
            fake.send_param_dump()
            async with asyncio.timeout(5):
                while station.lock_state(LOCK_1940) is None:
                    await asyncio.sleep(0.01)

    monkeypatch.setattr(station.session, "async_connect", connect_with_dump)
    try:
        assert station.lock_state(LOCK_1940) is None
        assert await station.async_lock(LOCK_1940) is LockState.LOCKED
        assert dumped
    finally:
        await station.async_close()
    assert len(lock_1940.received) == 1


async def test_the_hkdf_variant_from_the_firmware_thresholds(
    fake: FakeStation, lock_1940: FakeLock
) -> None:
    device = _lock(LOCK_1940, main_sw_version="2.2.0.0", sec_sw_version="0.3.0.0")
    station = await _hub(fake, device, lock_1940)
    try:
        assert station.lock_control(LOCK_1940).form is LockForm.P2P_1940_HKDF
        assert await station.async_lock(LOCK_1940) is LockState.LOCKED
    finally:
        await station.async_close()
    assert len(lock_1940.received) == 1


async def test_a_status_report_with_an_error_code_fails_the_command(
    fake: FakeStation, lock_1940: FakeLock
) -> None:
    lock_1940.status_code = 2
    station = await _hub(fake, _lock(LOCK_1940), lock_1940)
    try:
        async with asyncio.timeout(5):  # at the report, not after the state wait
            with pytest.raises(CommandRejectedError) as raised:
                await station.async_lock(LOCK_1940)
        reading = station.lock_state(LOCK_1940)
    finally:
        await station.async_close()
    assert raised.value.code == 2
    assert reading is not None
    assert reading.source is not LockStateSource.LOCK  # the refusing report sets no state


class _SlowCloud(_Cloud):
    """A cloud whose public-key query takes longer than any test waits."""

    async def async_get_lock_public_key(self, device_sn: str, key_type: int) -> bytes:
        await asyncio.sleep(30)
        return await super().async_get_lock_public_key(device_sn, key_type)


@pytest.mark.parametrize("slow", ["public key", "connect", "send"])
async def test_an_explicit_timeout_bounds_the_steps_before_the_send(
    fake: FakeStation, monkeypatch: pytest.MonkeyPatch, slow: str
) -> None:
    serial = "T8520P2000000001"
    lock = FakeLock(serial=serial, channel=1)
    cloud = _SlowCloud(lock) if slow == "public key" else _Cloud(lock)
    station = await _hub(fake, _lock(serial), lock, cloud)
    if slow == "connect":

        async def connect() -> None:
            await asyncio.sleep(30)

        monkeypatch.setattr(station.session, "async_connect", connect)
    if slow == "send":

        async def send(*_: object, **__: object) -> None:
            await asyncio.sleep(30)

        monkeypatch.setattr(station.session, "async_send_command", send)
    try:
        async with asyncio.timeout(3):
            with pytest.raises(DeviceTimeoutError, match=r"not sent within 0\.3 s"):
                await station.async_lock(serial, timeout=0.3)
    finally:
        await station.async_close()
    assert lock.received == []


async def test_a_timeout_while_the_station_result_is_pending_names_the_result(
    fake: FakeStation,
) -> None:
    """The command went out and only the station's result was missing at the deadline."""
    serial = "T8530P2000000001"
    lock = FakeLock(serial=serial, channel=1, result=False)
    station = await _hub(fake, _lock(serial), lock)
    try:
        async with asyncio.timeout(3):
            with pytest.raises(DeviceTimeoutError, match=r"no station result within 0\.3 s"):
                await station.async_lock(serial, timeout=0.3)
    finally:
        await station.async_close()
    assert len(lock.received) == 1


async def test_a_failed_state_is_retrieved_when_the_send_raises_first(
    fake: FakeStation, lock_1940: FakeLock
) -> None:
    """A refusing status report fails the state wait before the station refuses the send:
    the command raises the station's refusal and leaves no unretrieved exception."""
    seen: list[dict[str, object]] = []
    loop = asyncio.get_running_loop()
    loop.set_exception_handler(lambda _loop, context: seen.append(context))
    try:
        station = await _hub(fake, _lock(LOCK_1940), lock_1940)

        async def send(command: int, **_: object) -> None:
            state = station._lock_control._pending[LOCK_1940].state
            state.set_exception(CommandRejectedError(command, 2, "status report"))
            raise CommandRejectedError(command, 1, "refused by the station")

        station.session.async_send_command = send  # type: ignore[method-assign,assignment]
        try:
            with pytest.raises(CommandRejectedError) as raised:
                await station.async_lock(LOCK_1940)
        finally:
            await station.async_close()
        code = raised.value.code
        del raised
        for _ in range(3):
            await asyncio.sleep(0)
        gc.collect()
    finally:
        loop.set_exception_handler(None)
    assert code == 1
    assert seen == []


def test_the_waits_are_the_apps() -> None:
    assert (control.LOCK_ANSWER_TIMEOUT, control.LOCK_CONFIRM_TIMEOUT) == (
        20.0,
        30.0,
    )


# ── refusals before sending ──────────────────────────────────────────────────


async def test_a_guest_is_refused_before_sending(fake: FakeStation, lock_1940: FakeLock) -> None:
    station = await _hub(fake, _lock(LOCK_1940, member_type=0), lock_1940)
    try:
        assert station.lock_control(LOCK_1940).guest
        with pytest.raises(GuestAccessError):
            await station.async_lock(LOCK_1940)
    finally:
        await station.async_close()
    assert lock_1940.received == []


_NO_MEMBER = {"owner_user_id": None, "member_type": None, "member_user_id": None}


async def test_a_lock_without_a_member_record_is_refused(
    fake: FakeStation, lock_1940: FakeLock
) -> None:
    device = _lock(LOCK_1940, 1, **_NO_MEMBER, short_user_id=None)
    station = await _hub(fake, device, lock_1940)
    try:
        with pytest.raises(UnsupportedError, match="member"):
            await station.async_lock(LOCK_1940)
    finally:
        await station.async_close()
    assert lock_1940.received == []


@pytest.mark.parametrize(
    "changes",
    [
        {"owner_user_id": None},
        {**_NO_MEMBER, "owner_user_id": "0" * 40, "short_user_id": None},
        {**_NO_MEMBER, "member_type": 1, "short_user_id": None},
        {**_NO_MEMBER, "member_user_id": SYNTHETIC.account_id, "short_user_id": None},
        dict(_NO_MEMBER),
    ],
    ids=["no-admin-id", "only-an-admin-id", "only-a-type", "only-a-member-id", "only-a-short-id"],
)
@pytest.mark.parametrize("serial", [LOCK_1940, "T8530P2000000001"])
async def test_a_partial_member_record_still_sends(
    fake: FakeStation, serial: str, changes: dict[str, object]
) -> None:
    """As the app: only a missing member record refuses, any of its fields makes one; a
    1940 command of a record without ``admin_user_id`` is keyed by the account's own user
    id, a 1961 one names no ``userId``."""
    lock = FakeLock(serial=serial, channel=1, user_id=SYNTHETIC.account_id)
    station = await _hub(fake, _lock(serial, 1, **changes), lock)
    try:
        assert await station.async_lock(serial) is LockState.LOCKED
    finally:
        await station.async_close()
    named = SYNTHETIC.account_id if serial == LOCK_1940 else changes["owner_user_id"]
    assert lock.user_ids == [named]


@pytest.mark.parametrize(
    ("serial", "form", "words"),
    [
        ("T8500P2000000001", LockForm.P2P_1911, "Bluetooth"),
        ("T85D0P2000000001", LockForm.MQTT, "mqtt"),
    ],
)
async def test_a_route_this_path_cannot_send_is_refused(
    fake: FakeStation, serial: str, form: LockForm, words: str
) -> None:
    lock = FakeLock(serial=serial, channel=1)
    station = await _hub(fake, _lock(serial), lock)
    try:
        assert station.lock_control(serial).form is form
        with pytest.raises(UnsupportedError, match=words):
            await station.async_lock(serial)
    finally:
        await station.async_close()
    assert lock.received == []


# ── 1961 and 1930 ────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("serial", "form", "keys"),
    [
        ("T8520P2000000001", LockForm.P2P_1961, [2]),
        ("T8530P2000000001", LockForm.P2P_1961_PLAIN, []),
        ("T8501P2000000001", LockForm.P2P_1930, [2]),
    ],
)
async def test_the_anker_forms_are_confirmed_by_the_state_parameter(
    fake: FakeStation, serial: str, form: LockForm, keys: list[int]
) -> None:
    lock = FakeLock(serial=serial, channel=1)
    cloud = _Cloud(lock)
    station = await _hub(fake, _lock(serial), lock, cloud)
    try:
        assert station.lock_control(serial).form is form
        assert await station.async_lock(serial) is LockState.LOCKED
    finally:
        await station.async_close()
    assert [(c, a) for c, a, _ in lock.received] == [(int(form.value[4:8]), LockAction.LOCK)]
    assert cloud.asked == [(serial, k) for k in keys]


async def test_the_1930_ecdh_form_when_the_lock_reports_it(fake: FakeStation) -> None:
    serial = "T8501P2000000001"
    lock = FakeLock(serial=serial, channel=1, state_code=4)
    cloud = _Cloud(lock)
    fake.params[1] = {6610: "1"}
    station = await _hub(fake, _lock(serial), lock, cloud)
    try:
        assert station.lock_control(serial).form is LockForm.P2P_1930_ECDH
        assert await station.async_unlock(serial) is LockState.UNLOCKED
    finally:
        await station.async_close()
    assert cloud.asked == [(serial, 3)]
    assert [(c, a) for c, a, _ in lock.received] == [(1930, LockAction.UNLOCK)]


async def test_a_1961_sequence_refusal_fails_as_the_app_does(fake: FakeStation) -> None:
    serial = "T8530P2000000001"
    lock = FakeLock(serial=serial, channel=1, result_code=-151)
    station = await _hub(fake, _lock(serial), lock)
    try:
        async with asyncio.timeout(5):  # at once, not after the answer wait
            with pytest.raises(CommandRejectedError) as raised:
                await station.async_lock(serial)
    finally:
        await station.async_close()
    assert raised.value.code == -151


async def test_a_1961_sequence_report_moves_the_shared_counter(fake: FakeStation) -> None:
    """The lock's 1916 report after a refusal sets the next 1961 number to report + 1."""
    serial = "T8520P2000000001"
    lock = FakeLock(serial=serial, channel=1, seq_report=700)
    station = await _hub(fake, _lock(serial), lock)
    try:
        with pytest.raises(CommandRejectedError):
            await station.async_lock(serial)
        assert await station.async_lock(serial) is LockState.LOCKED
    finally:
        await station.async_close()
    assert lock.received[-1][2] == 701


@pytest.mark.parametrize(
    "serial", ["T8502P2000000001", "T8520P2000000001", "T8530P2000000001", "T8501P2000000001"]
)
async def test_a_lock_command_names_the_accounts_nickname(fake: FakeStation, serial: str) -> None:
    """Every form names the cloud's display name, not the session's e-mail name ("Nick")."""
    lock = FakeLock(serial=serial, channel=1, user_id=SYNTHETIC.account_id)
    station = await _hub(fake, _lock(serial), lock)
    try:
        assert await station.async_lock(serial) is LockState.LOCKED
    finally:
        await station.async_close()
    assert lock.names == ["Synthetic Nick"]


async def test_without_a_cloud_client_a_lock_command_names_the_sessions_user(
    fake: FakeStation,
) -> None:
    serial = "T8530P2000000001"
    lock = FakeLock(serial=serial, channel=1)
    fake.locks[1] = lock
    fake.params.setdefault(1, {})[1912] = str(lock.state_code)
    station = Station(STATION, _session(fake), sub_devices=[_lock(serial)], lock_cloud=None)
    try:
        await station.async_update()
        assert await station.async_lock(serial) is LockState.LOCKED
    finally:
        await station.async_close()
    assert lock.names == ["Nick"]


# ── the client's entry point ─────────────────────────────────────────────────


async def test_the_client_routes_a_station_lock_to_its_station(
    fake: FakeStation, lock_1940: FakeLock
) -> None:
    station = await _hub(fake, _lock(LOCK_1940), lock_1940)
    cloud = FakeCloud()
    eufy = build_eufy_security(
        email=SYNTHETIC.email, store=warm_store(email=SYNTHETIC.email, cloud=cloud), cloud=cloud
    )
    eufy.stations[SYNTHETIC.station_sn] = station
    try:
        assert eufy.lock_control(LOCK_1940).path is LockPath.STATION
        assert await eufy.async_lock(LOCK_1940) is LockState.LOCKED
        assert await eufy.async_unlock(LOCK_1940) is LockState.UNLOCKED
    finally:
        await station.async_close()
        await eufy.async_close()
    assert [a for _, a, _ in lock_1940.received] == [LockAction.LOCK, LockAction.UNLOCK]


def _client() -> EufySecurity:
    cloud = FakeCloud()
    return build_eufy_security(
        email=SYNTHETIC.email, store=warm_store(email=SYNTHETIC.email, cloud=cloud), cloud=cloud
    )


@pytest.mark.parametrize(
    ("serial", "path"),
    [(LOCK_1940, LockPath.STATION), ("T85D0P2000000001", LockPath.MQTT)],
)
async def test_the_client_offers_a_listed_lock_only_on_a_path_it_serves(
    serial: str, path: LockPath
) -> None:
    """A lock no station of this client serves: its station route is not writable, with the
    reason its command raises; its MQTT route stays writable."""
    eufy = _client()
    eufy.listed_devices = MappingProxyType({serial: _lock(serial, station_sn=serial)})
    try:
        control = eufy.lock_control(serial)
        if path is LockPath.MQTT:
            assert (control.writable, control.path) == (True, LockPath.MQTT)
            return
        assert (control.writable, control.path, control.form) == (False, None, LockForm.P2P_1940)
        assert control.reason == "no station session of this client serves the lock"
        with pytest.raises(UnsupportedError, match=control.reason):
            await eufy.async_lock(serial)
    finally:
        await eufy.async_close()


def _lock_serials() -> list[str]:
    """One serial per lock product and serial-character variant of the route table."""
    return [
        f"{code}P{char.split(':')[1] if char else '2'}000000001"
        for code, rows in LOCK_ROUTES.items()
        for char, *_ in rows
    ]


@pytest.mark.parametrize("guest", [False, True])
@pytest.mark.parametrize("behind", [True, False])
@pytest.mark.parametrize("served", [True, False])
async def test_lock_control_and_the_command_agree_for_every_lock(
    monkeypatch: pytest.MonkeyPatch, served: bool, behind: bool, guest: bool
) -> None:
    """For every lock product in every context, a command reaches a sender exactly when
    ``lock_control`` says writable; otherwise it raises ``UnsupportedError`` first."""
    reached: list[str] = []

    async def run(self: object, device: object, *_: object, **__: object) -> LockState:
        reached.append(getattr(device, "device_sn", device))  # type: ignore[arg-type]
        return LockState.LOCKED

    monkeypatch.setattr(lock_control_module.StationLockControl, "_run", run)
    monkeypatch.setattr(MqttLocks, "_run", run)
    eufy = _client()
    eufy._mqtt_locks = MqttLocks(
        _NoBroker(),  # type: ignore[arg-type]
        user=_Cloud(),
        states=eufy._lock_states,
        devices=eufy._listed_device,
    )
    writable = 0
    try:
        for serial in _lock_serials():
            device = _lock(
                serial,
                station_sn=SYNTHETIC.station_sn if behind else serial,
                member_type=0 if guest else 2,
            )
            eufy.stations.clear()
            eufy.listed_devices = MappingProxyType({serial: device})
            if served:
                hub = STATION if behind else dataclasses.replace(device, p2p_did=SYNTHETIC.did)
                eufy.stations[hub.device_sn] = Station(
                    hub,
                    StationSession(hub.device_sn, _no_credentials, host="127.0.0.1", port=9),
                    sub_devices=[device] if behind else [],
                    lock_cloud=_Cloud(),
                )
            control = eufy.lock_control(serial)
            reached.clear()
            if control.writable:
                await eufy.async_lock(serial)
            else:
                with pytest.raises(UnsupportedError) as raised:
                    await eufy.async_lock(serial)
                assert isinstance(raised.value, GuestAccessError) is control.guest, serial
            assert reached == ([serial] if control.writable else []), serial
            writable += control.writable
    finally:
        await eufy.async_close()
    assert (writable > 0) is not guest  # each non-guest context offers some lock


class _NoBroker:
    """An MQTT account stand-in that is never asked to publish."""

    def add_listener(self, _callback: object) -> Callable[[], None]:
        return lambda: None


async def _no_credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
    raise AssertionError("no session is opened")
