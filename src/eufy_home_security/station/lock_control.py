"""Lock and unlock over a station session (:class:`StationLockControl`).

Each command goes as the lock's P2P form (:func:`~..devices.lock_routes.lock_route`) in the
station's 1350 wrapper on the lock's channel, and counts only once the lock's state says so
(declared, eufy app; docs/protocol/locks.md § Commands):

1. refusals before anything is sent (:mod:`~..lock_commands.control`), one command per lock;
2. the station's result: a non-zero code refuses the command, except the sequence refusal
   (-151) on the through-data forms, where the lock's answer is still awaited;
3. the lock's answer (1940/1930 through data; 1961 rides the station's result): an answer
   to another request is skipped, a refusal raises :class:`CommandRejectedError`;
4. the lock's state: the asked state returns it, a fault state raises
   :class:`LockNotMovedError`; none within the wait raises :class:`DeviceTimeoutError`.

A lock's sequence report (1916) stores its number (for a 1961 lock: the shared counter) and
resends a pending 1940 command with the next one, as the app does. A command the station
refused for its sequence number (-151) that gets neither answer nor resend within the wait
raises :class:`CommandRejectedError` with code -151.
"""

from __future__ import annotations

import asyncio
import json
import logging
import secrets
import time
from collections.abc import Awaitable, Callable, Iterator, Mapping
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Final, Protocol

from .._logging import redact_serial
from ..devices.lock_routes import LockForm, lock_route
from ..devices.locks import LockReading, LockState
from ..exceptions import (
    CommandRejectedError,
    DeviceBusyError,
    DeviceTimeoutError,
    LockNotMovedError,
    LockReplyMismatchError,
    UnsupportedError,
)
from ..lock_commands import anker, cm2
from ..lock_commands.actions import LockAction, LockReply, LockResult
from ..lock_commands.control import (
    FAULT_STATES,
    LOCK_ANSWER_TIMEOUT,
    LOCK_CONFIRM_TIMEOUT,
    SEQUENCE_REFUSED,
    TARGET_STATES,
    LockAccount,
    LockControl,
    LockPath,
    check_control,
    ends_wait,
    has_member_record,
    is_guest,
    lock_control,
)
from ..lock_commands.sequence import LockSequences, SharedSequence
from ..models import FrameCipher
from ..p2p._json import json_int
from ..p2p.session import CommandOutcome

if TYPE_CHECKING:
    from ..cloud.models import CloudDevice
    from . import Station
    from .locks import StationLocks

_LOGGER = logging.getLogger(__name__)

SEQ_REPORT_COMMAND: Final = 1916
"""The station's notify of a lock's sequence number."""
KEY_TYPE_ECC: Final = 2
"""``app/public_key/query`` type of the key a command's AES key is wrapped to."""
KEY_TYPE_ECDH: Final = 3
"""``app/public_key/query`` type of the lock's ECDH key."""
_THROUGH_DATA: Final = frozenset({cm2.P2P_COMMAND, anker.COMMAND_1930})


class LockCloud(LockAccount, Protocol):
    """What a lock command needs from the account's cloud client."""

    async def async_get_lock_public_key(self, device_sn: str, key_type: int) -> bytes: ...


class _Params(Mapping[int, object]):
    """A lock's parameter values as the station last reported them, read on demand."""

    def __init__(self, station: Station, device: CloudDevice) -> None:
        self._station, self._device = station, device

    def __getitem__(self, param_id: int) -> object:
        report = self._station._param_report(self._device, param_id)
        if report is None:
            raise KeyError(param_id)
        return report.value

    def __iter__(self) -> Iterator[int]:
        return iter(())

    def __len__(self) -> int:
        return 0

    def __bool__(self) -> bool:  # values are read on demand: never an empty mapping
        return True


@dataclass(slots=True)
class _Sent:
    """A command as built: what goes on the wire and how its answer reads."""

    command: int
    payload: Mapping[str, object] | str
    head: Mapping[str, object] | None = None
    read: Callable[[Mapping[str, Any]], LockReply] | None = None
    """The through-data answer's reader; None when the station's result is the answer."""


@dataclass(slots=True)
class _Pending:
    device_sn: str
    form: LockForm
    action: LockAction
    sent: _Sent
    answer: asyncio.Future[LockReply]
    state: asyncio.Future[LockState]
    resend: Callable[[], None] | None = None
    resends: list[asyncio.Task[Any]] = field(default_factory=list)
    refused: bool = False
    """The station refused the last send for its sequence number (-151)."""
    sent_out: bool = False
    """The command's frame went out; the station's result may still be pending."""


async def _within[T](
    deadline: float | None,
    timeout: float | None,
    serial: str,
    step: Awaitable[T],
    *,
    sent: Callable[[], bool] = lambda: False,
) -> T:
    """Await ``step`` until the loop time ``deadline``, the end of the command's ``timeout``
    (None: no bound); reaching it raises :class:`DeviceTimeoutError`, naming the station's
    result when ``sent`` says the command went out."""
    bound = asyncio.timeout_at(deadline)
    try:
        async with bound:
            return await step
    except TimeoutError:
        if not bound.expired():
            raise
        missing = "no station result" if sent() else "the command was not sent"
        raise DeviceTimeoutError(
            f"{redact_serial(serial)}: {missing} within {timeout:g} s", device_sn=serial
        ) from None


def _payload(obj: Mapping[str, Any]) -> Mapping[str, Any] | None:
    """A notify's ``payload`` object (sent as an object or as JSON text)."""
    payload = obj.get("payload")
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except ValueError:
            return None
    return payload if isinstance(payload, Mapping) else None


class StationLockControl:
    """Lock and unlock commands for the locks of one station."""

    def __init__(
        self,
        station: Station,
        locks: StationLocks,
        *,
        cloud: LockCloud | None,
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._station = station
        self._locks = locks
        self._cloud = cloud
        self._clock = clock
        self._sequences = LockSequences(clock=clock)
        self._shared = SharedSequence()
        self._busy: set[str] = set()
        self._pending: dict[str, _Pending] = {}

    # ── routing ─────────────────────────────────────────────────────────────

    def form(self, device: CloudDevice) -> LockForm | None:
        """The lock form of ``device`` (None: no route, or no graded lock)."""
        if self._locks.param_of(device) is None:
            return None
        station_sn = device.station_sn
        return lock_route(
            device.device_sn,
            behind_station=bool(station_sn) and station_sn != device.device_sn,
            main_sw_version=device.main_sw_version or "",
            sec_sw_version=device.sec_sw_version or "",
            params=_Params(self._station, device),
        )

    def control(self, device_sn: str) -> LockControl:
        device = self._station.sub_device(device_sn)
        return lock_control(self.form(device), guest=is_guest(device))

    # ── inbound ─────────────────────────────────────────────────────────────

    def on_notify(self, obj: Mapping[str, Any], _cipher: FrameCipher) -> None:
        """Take a lock's sequence report, answer or status report from a notify."""
        command = json_int(obj.get("cmd"))
        if command != SEQ_REPORT_COMMAND and command not in _THROUGH_DATA:
            return
        payload = _payload(obj)
        serial = None if payload is None else payload.get("dev_sn")
        if payload is None or not isinstance(serial, str):
            return
        if command == SEQ_REPORT_COMMAND:
            self._on_sequence(serial, payload)
            return
        pending = self._pending.get(serial)
        if pending is not None and pending.sent.command == command:
            self._on_answer(pending, payload)
        if command == cm2.P2P_COMMAND:
            self._on_status(serial, payload)

    def _on_sequence(self, serial: str, payload: Mapping[str, Any]) -> None:
        seq = json_int(payload.get("seq_num"))
        if seq is None:
            return
        self._sequences.report(serial, seq)
        device = next((d for d in self._station.devices if d.device_sn == serial), None)
        if device is not None and self.form(device) is LockForm.P2P_1961:
            self._shared.report(seq)
        pending = self._pending.get(serial)
        lock_cmd = json_int(payload.get("lock_cmd"))
        if (
            pending is not None
            and pending.resend is not None
            and lock_cmd == cm2.COMMAND_ON_OFF
            and not pending.answer.done()
        ):
            _LOGGER.debug("%s: sequence report; resending the command", redact_serial(serial))
            pending.resend()

    def _on_answer(self, pending: _Pending, payload: Mapping[str, Any]) -> None:
        read = pending.sent.read
        if read is None or pending.answer.done():
            return
        try:
            reply = read(payload)
        except LockReplyMismatchError as err:
            _LOGGER.debug(
                "%s: answer to another request: %s", redact_serial(pending.device_sn), err
            )
            return
        except Exception as err:
            pending.answer.set_exception(err)
            return
        pending.answer.set_result(reply)

    def _on_status(self, serial: str, payload: Mapping[str, Any]) -> None:
        device = next((d for d in self._station.devices if d.device_sn == serial), None)
        if device is None:
            return
        form = self.form(device)
        if form not in (LockForm.P2P_1940, LockForm.P2P_1940_HKDF):
            return
        try:
            report = cm2.parse_status_report(
                payload,
                serial=serial,
                user_id=self._key_user(device),
                hkdf=form is LockForm.P2P_1940_HKDF,
            )
        except Exception as err:
            _LOGGER.debug("%s: unreadable status report: %s", redact_serial(serial), err)
            return
        if report is None:
            return
        pending = self._pending.get(serial)
        if report.code != 0:
            if pending is not None and not pending.state.done():
                pending.state.set_exception(
                    CommandRejectedError(
                        cm2.P2P_COMMAND,
                        report.code,
                        f"{redact_serial(serial)}: status report",
                        device_sn=serial,
                    )
                )
            return
        self._locks.on_report(serial, report.state_code)

    # ── commands ────────────────────────────────────────────────────────────

    def _key_user(self, device: CloudDevice) -> str:
        account = (self._cloud.user_id if self._cloud is not None else None) or ""
        return cm2.key_user_id(
            account_user_id=account,
            admin_user_id=device.owner_user_id,
            member_type=device.member_type,
            member_user_id=device.member_user_id,
        )

    async def _build(self, device: CloudDevice, form: LockForm, action: LockAction) -> _Sent:
        serial = device.device_sn
        user_name = (
            self._station.session.user_name if self._cloud is None else self._cloud.display_name
        )
        now = self._clock()
        if form in (LockForm.P2P_1940, LockForm.P2P_1940_HKDF):
            if self._cloud is None or not self._cloud.user_id:
                raise UnsupportedError(
                    f"{redact_serial(serial)}: a lock command needs the account's cloud user id",
                    device_sn=serial,
                )
            request = cm2.build_on_off_request(
                serial,
                action,
                cm2.Cm2User(self._key_user(device), user_name, device.short_user_id),
                seq_num=self._sequences.next(serial),
                time_value=cm2.lock_time(now, secrets.randbelow(100)),
                timestamp=int(now),
                hkdf=form is LockForm.P2P_1940_HKDF,
            )
            return _Sent(
                request.command, request.payload, read=lambda a: cm2.parse_on_off_reply(a, request)
            )
        user = anker.AnkerUser(device.owner_user_id, user_name, device.short_user_id)
        if form is LockForm.P2P_1961_PLAIN:
            plain = anker.build_1961_plain_request(action, user)
            return _Sent(plain.command, plain.payload)
        cloud = self._require_cloud(serial)
        if form is LockForm.P2P_1961:
            ecc = anker.build_1961_request(
                serial,
                action,
                user,
                seq_num=self._shared.next(),
                lock_public_key=await cloud.async_get_lock_public_key(serial, KEY_TYPE_ECC),
            )
            return _Sent(ecc.command, ecc.payload, head={"key": ecc.key})
        ecdh = form is LockForm.P2P_1930_ECDH
        key = await cloud.async_get_lock_public_key(serial, KEY_TYPE_ECDH if ecdh else KEY_TYPE_ECC)
        cm = anker.build_1930_request(
            serial,
            action,
            user,
            seq_num=self._sequences.next(serial),
            timestamp=int(now),
            lock_public_key=None if ecdh else key,
            lock_ecdh_public_key=key if ecdh else None,
        )
        return _Sent(cm.command, cm.payload, read=lambda a: anker.parse_1930_reply(a, cm))

    def _require_cloud(self, serial: str) -> LockCloud:
        if self._cloud is None:
            raise UnsupportedError(
                f"{redact_serial(serial)}: a lock command on this route needs the cloud client",
                device_sn=serial,
            )
        return self._cloud

    async def async_command(
        self, device_sn: str, action: LockAction, *, timeout: float | None
    ) -> LockState:
        """Lock or unlock ``device_sn`` and return its confirmed state (module docstring)."""
        device = self._station.sub_device(device_sn)
        if self._locks.param_of(device) is None:
            raise UnsupportedError(f"{redact_serial(device_sn)} is no lock", device_sn=device_sn)
        form = check_control(self.control(device_sn), device_sn, LockPath.STATION)
        if device_sn in self._busy:
            raise DeviceBusyError(
                f"{redact_serial(device_sn)}: a lock command is still waiting for the lock",
                device_sn=device_sn,
            )
        target = TARGET_STATES[action]
        reading = self._locks.reading(device_sn)
        if reading is not None and reading.state is target:
            return target
        if not has_member_record(device):  # as the app: no member record, no command
            raise UnsupportedError(
                f"{redact_serial(device_sn)}: the cloud record names no member for the lock",
                device_sn=device_sn,
            )
        self._busy.add(device_sn)
        try:
            return await self._run(device, form, action, target, timeout)
        finally:
            self._busy.discard(device_sn)

    async def _run(
        self,
        device: CloudDevice,
        form: LockForm,
        action: LockAction,
        target: LockState,
        timeout: float | None,
    ) -> LockState:
        serial = device.device_sn
        loop = asyncio.get_running_loop()
        deadline = None if timeout is None else loop.time() + timeout
        await _within(deadline, timeout, serial, self._station.session.async_connect())
        sent = await _within(deadline, timeout, serial, self._build(device, form, action))
        channel = self._station.channel_for(serial)
        pending = _Pending(
            serial, form, action, sent, answer=loop.create_future(), state=loop.create_future()
        )

        def on_reading(reading: LockReading) -> None:
            if not pending.state.done() and ends_wait(reading.state, target):
                pending.state.set_result(reading.state)

        if form in (LockForm.P2P_1940, LockForm.P2P_1940_HKDF):

            def resend() -> None:
                async def again() -> None:
                    try:
                        rebuilt = await self._build(device, form, action)
                        pending.sent = rebuilt
                        await self._send(rebuilt, channel, pending)
                    except Exception as err:
                        if not pending.answer.done():
                            pending.answer.set_exception(err)

                pending.resends.append(loop.create_task(again()))

            pending.resend = resend
        # Armed at the send, as the app's wait starts there: a reading the connect brought
        # (a dump repeating an old fault) does not end the command.
        self._pending[serial] = pending
        unwatch = self._locks.watch(serial, on_reading)
        try:
            applied = await _within(
                deadline,
                timeout,
                serial,
                self._send(sent, channel, pending),
                sent=lambda: pending.sent_out,
            )
            if sent.read is None and applied:  # the station's result is the lock's answer
                pending.answer.set_result(LockReply(0, LockResult.ACCEPTED))
            budget = LOCK_ANSWER_TIMEOUT if deadline is None else deadline - loop.time()
            try:
                done = await self._first(pending, budget, serial, "answer")
            except DeviceTimeoutError:
                if not pending.refused:
                    raise
                raise CommandRejectedError(
                    pending.sent.command,
                    SEQUENCE_REFUSED,
                    f"{redact_serial(serial)}: sequence number refused, and no answer or "
                    f"sequence report within {budget:.0f} s",
                    device_sn=serial,
                ) from None
            if done is pending.answer:
                reply = pending.answer.result()
                if reply.result is not LockResult.ACCEPTED:
                    raise CommandRejectedError(
                        sent.command,
                        reply.code,
                        f"{redact_serial(serial)}: {reply.result.value}",
                        device_sn=serial,
                    )
                if not pending.state.done():
                    budget = LOCK_CONFIRM_TIMEOUT if deadline is None else deadline - loop.time()
                    await self._first(pending, budget, serial, f"{target.value} state", state=True)
            state = pending.state.result()
            if state in FAULT_STATES:
                raise LockNotMovedError(
                    sent.command,
                    f"{redact_serial(serial)} reported {state.value} after the "
                    f"{action.name.lower()} command",
                    state=state,
                    device_sn=serial,
                )
            return state
        finally:
            unwatch()
            self._pending.pop(serial, None)
            for task in pending.resends:
                task.cancel()
            for future in (pending.answer, pending.state):
                if future.done() and not future.cancelled():
                    future.exception()  # retrieved: another outcome decided the command

    async def _send(self, sent: _Sent, channel: int, pending: _Pending) -> bool:
        """Send ``sent``; whether the station gave a result. A non-zero result raises,
        except the sequence refusal of a through-data form (its answer is still awaited;
        ``pending.refused`` records it, ``pending.sent_out`` that the frame went out)."""

        def going_out() -> asyncio.Future[Any]:
            pending.sent_out = True
            return asyncio.get_running_loop().create_future()  # the station's result decides

        try:
            outcome = await self._station.session.async_send_command(
                sent.command,
                channel=channel,
                payload=sent.payload,
                head=sent.head,
                confirm=going_out,
            )
        except CommandRejectedError as err:
            if err.code == SEQUENCE_REFUSED and sent.read is not None:
                pending.refused = True
                return False
            raise
        pending.refused = False
        return outcome is CommandOutcome.APPLIED

    async def _first(
        self, pending: _Pending, budget: float, serial: str, what: str, *, state: bool = False
    ) -> asyncio.Future[Any]:
        """Wait up to ``budget`` s for the state (and, unless ``state``, the answer)."""
        waits: set[asyncio.Future[Any]] = (
            {pending.state} if state else {pending.state, pending.answer}
        )
        done, _ = await asyncio.wait(waits, timeout=max(0.0, budget), return_when="FIRST_COMPLETED")
        if not done:
            raise DeviceTimeoutError(
                f"{redact_serial(serial)}: no {what} within {budget:.0f} s", device_sn=serial
            )
        first = pending.state if pending.state in done else next(iter(done))
        if (error := first.exception()) is not None:
            raise error
        return first
