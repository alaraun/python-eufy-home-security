"""Lock and unlock over a station session (``Station.async_lock`` / ``async_unlock``,
``Station.lock_control``) against the fake station and its fake locks."""

from __future__ import annotations

import asyncio
import dataclasses
from collections.abc import AsyncIterator

import pytest

from eufy_home_security.cloud.models import CloudDevice
from eufy_home_security.devices.lock_routes import LockForm
from eufy_home_security.devices.locks import LockState, LockStateSource
from eufy_home_security.events import Event, LockStateChanged
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
from eufy_home_security.lock_commands.actions import LockAction
from eufy_home_security.lock_commands.control import LockPath
from eufy_home_security.p2p.session import P2PCredentials, StationSession
from eufy_home_security.station import Station
from eufy_home_security.station import lock_control as lock_control_module
from eufy_home_security.testing import SYNTHETIC, FakeLock, FakeStation

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
    assert changes == [(LockState.LOCKED, LockStateSource.LOCK)]
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
        with pytest.raises(CommandRejectedError) as raised:
            await station.async_lock(LOCK_1940)
    finally:
        await station.async_close()
    assert raised.value.code == 2


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


async def test_a_lock_without_a_member_record_is_refused(
    fake: FakeStation, lock_1940: FakeLock
) -> None:
    station = await _hub(fake, _lock(LOCK_1940, owner_user_id=None), lock_1940)
    try:
        with pytest.raises(UnsupportedError, match="member"):
            await station.async_lock(LOCK_1940)
    finally:
        await station.async_close()
    assert lock_1940.received == []


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
        with pytest.raises(CommandRejectedError) as raised:
            await station.async_lock(serial)
    finally:
        await station.async_close()
    assert raised.value.code == -151
