"""Lock and unlock over the eufy security MQTT broker (:class:`MqttLocks`; needs the ``mqtt``
extra), confirmed by the lock's state.

A Wi-Fi lock the route marks MQTT (:func:`~..devices.lock_routes.lock_route`) takes the
station path's 1940 payload object ``{apiCommand: 6018, lock_payload, seq_num, time}``,
keyed and named by the key user id (:func:`~..lock_commands.cm2.key_user_id`), as the
``trans`` of a command message whose payload carries only ``account_id`` (that user id),
``device_sn`` and ``trans``, as the eufy app's lock card sends it (declared, eufy app;
docs/protocol/mqtt.md § Lock commands). The publish has 15 s, the answer 20 s from the
broker's acknowledgement. The lock answers in a device message on its response topic with
the frame encrypted under the key its own ``time`` names, and reports its state in a status
report the same way; :class:`~..events.LockStateChanged` carries it.
The same refusals and waits as the station path apply (:mod:`~..lock_commands.control`).
"""

from __future__ import annotations

import asyncio
import logging
import secrets
import time
from collections.abc import Callable, Mapping
from typing import TYPE_CHECKING, Any

from .._logging import redact_serial
from ..devices.lock_routes import lock_route
from ..devices.locks import LockReading, LockState, LockStateSource, state_of_code
from ..events import Event, LockStateChanged
from ..exceptions import (
    CommandRejectedError,
    DeviceBusyError,
    DeviceTimeoutError,
    LockNotMovedError,
    LockReplyMismatchError,
    ProtocolError,
    UnsupportedError,
)
from ..lock_commands import cm2
from ..lock_commands.actions import LockAction, LockReply, LockResult
from ..lock_commands.control import (
    FAULT_STATES,
    LOCK_ANSWER_TIMEOUT,
    LOCK_CONFIRM_TIMEOUT,
    LOCK_PUBLISH_TIMEOUT,
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
from ..lock_commands.mqtt_trans import decode_trans, encode_trans
from ..lock_commands.sequence import LockSequences
from .envelope import CMD_UPLINK_TRANS

if TYPE_CHECKING:
    from ..cloud.models import CloudDevice
    from .account import EufyMqttAccount
    from .envelope import MqttMessage

_LOGGER = logging.getLogger(__name__)


def mqtt_lock_control(device: CloudDevice) -> LockControl:
    """The lock control of ``device`` when no station serves it: its route as a lock not
    behind a station (or behind the one its record names)."""
    station_sn = device.station_sn
    form = lock_route(
        device.device_sn,
        behind_station=bool(station_sn) and station_sn != device.device_sn,
        main_sw_version=device.main_sw_version or "",
        sec_sw_version=device.sec_sw_version or "",
        params={p.param_id: p.value for p in device.cloud_params},
    )
    return lock_control(form, guest=is_guest(device))


def _through_data(message: MqttMessage) -> Mapping[str, Any] | None:
    """The 1940 through-data object of a lock's device message (``cmd`` 8), as the eufy app
    reads it: the lock its ``dev_sn`` names, the topic's lock when it names none."""
    trans = message.trans
    if trans is None or message.head.cmd_code != CMD_UPLINK_TRANS:
        return None
    try:
        command, payload = decode_trans(trans)
    except ProtocolError:
        return None
    if command != cm2.P2P_COMMAND:
        return None
    return {"dev_sn": message.device_sn, **payload}


class MqttLocks:
    """Lock commands and lock state of the account's MQTT locks over ``account``.

    ``user`` gives the logged-in account's cloud user id and its display name (the sender
    a command names), read at each command; ``emit`` receives each
    :class:`~..events.LockStateChanged`. Call :meth:`close` to stop listening.
    """

    def __init__(
        self,
        account: EufyMqttAccount,
        *,
        user: LockAccount,
        emit: Callable[[Event], None],
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._account = account
        self._user = user
        self._emit = emit
        self._clock = clock
        self._sequences = LockSequences(clock=clock)
        self._readings: dict[str, LockReading] = {}
        self._owners: dict[str, str] = {}
        self._watchers: dict[str, Callable[[LockReading], None]] = {}
        self._states: dict[str, asyncio.Future[LockState]] = {}
        """Per lock, the state a command waits for (a refusing status report fails it)."""
        self._busy: set[str] = set()
        self._remove = account.add_listener(self._on_message)

    def close(self) -> None:
        self._remove()

    def reading(self, device_sn: str) -> LockReading | None:
        """The lock's state as its last status report over MQTT said."""
        return self._readings.get(device_sn)

    def _on_message(self, message: MqttMessage) -> None:
        payload = _through_data(message)
        if payload is None:
            return
        serial = payload["dev_sn"]
        owner = self._owners.get(serial) if isinstance(serial, str) else None
        if owner is None:
            return
        try:
            report = cm2.parse_status_report(payload, serial=serial, user_id=owner)
        except ProtocolError as err:
            _LOGGER.debug("%s: unreadable status report: %s", redact_serial(serial), err)
            return
        if report is None:
            return
        if report.code != 0:
            state = self._states.get(serial)
            if state is not None and not state.done():
                state.set_exception(
                    CommandRejectedError(
                        cm2.P2P_COMMAND,
                        report.code,
                        f"{redact_serial(serial)}: status report",
                        device_sn=serial,
                    )
                )
            return
        self._take(serial, report.state_code)

    def _take(self, device_sn: str, state_code: int) -> None:
        reading = LockReading(
            state=state_of_code(state_code), source=LockStateSource.LOCK, raw=str(state_code)
        )
        old = self._readings.get(device_sn)
        self._readings[device_sn] = reading
        if (watcher := self._watchers.get(device_sn)) is not None:
            watcher(reading)
        if old is None or old.state is not reading.state:
            self._emit(
                LockStateChanged(
                    device_sn=device_sn,
                    state=reading.state,
                    source=reading.source,
                    raw=reading.raw,
                )
            )

    async def async_command(
        self,
        device: CloudDevice,
        action: LockAction,
        *,
        control: LockControl,
        timeout: float | None,
    ) -> LockState:
        """Lock or unlock ``device`` over MQTT and return its confirmed state; raises as
        :meth:`~..station.Station.async_lock` does."""
        serial = device.device_sn
        check_control(control, serial, LockPath.MQTT)
        if not has_member_record(device):  # as the app: no member record, no command
            raise UnsupportedError(
                f"{redact_serial(serial)}: the cloud record names no member for the lock",
                device_sn=serial,
            )
        account_user_id = self._user.user_id
        if not account_user_id:
            raise UnsupportedError(
                f"{redact_serial(serial)}: a lock command needs the account's cloud user id",
                device_sn=serial,
            )
        if serial in self._busy:
            raise DeviceBusyError(
                f"{redact_serial(serial)}: a lock command is still waiting for the lock",
                device_sn=serial,
            )
        target = TARGET_STATES[action]
        reading = self._readings.get(serial)
        if reading is not None and reading.state is target:
            return target
        user_id = cm2.key_user_id(
            account_user_id=account_user_id,
            admin_user_id=device.owner_user_id,
            member_type=device.member_type,
            member_user_id=device.member_user_id,
        )
        self._owners[serial] = user_id
        self._busy.add(serial)
        try:
            return await self._run(device, user_id, action, target, timeout)
        finally:
            self._busy.discard(serial)
            self._watchers.pop(serial, None)
            self._states.pop(serial, None)

    async def _run(
        self,
        device: CloudDevice,
        user_id: str,
        action: LockAction,
        target: LockState,
        timeout: float | None,
    ) -> LockState:
        serial = device.device_sn
        loop = asyncio.get_running_loop()
        deadline = None if timeout is None else loop.time() + timeout
        now = self._clock()
        request = cm2.build_on_off_request(
            serial,
            action,
            cm2.Cm2User(user_id, self._user.display_name, device.short_user_id),
            seq_num=self._sequences.next(serial),
            time_value=cm2.lock_time(now, secrets.randbelow(100)),
            timestamp=int(now),
        )
        state: asyncio.Future[LockState] = loop.create_future()

        def on_reading(taken: LockReading) -> None:
            if not state.done() and ends_wait(taken.state, target):
                state.set_result(taken.state)

        self._watchers[serial] = on_reading
        self._states[serial] = state
        replies: list[LockReply] = []

        def match(message: MqttMessage) -> bool:
            answer = _through_data(message)
            if answer is None:
                return False
            try:
                replies.append(cm2.parse_on_off_reply(answer, request))
            except LockReplyMismatchError:
                return False
            except ProtocolError as err:
                _LOGGER.debug("%s: unreadable answer: %s", redact_serial(serial), err)
                return False
            return True

        if deadline is None:  # the app's waits: the publish, then the answer from its ack
            publish_wait: float | None = LOCK_PUBLISH_TIMEOUT
            budget = LOCK_ANSWER_TIMEOUT
        else:
            publish_wait, budget = None, deadline - loop.time()
        asking = loop.create_task(
            self._account.async_request(
                serial,
                encode_trans(cm2.P2P_COMMAND, request.payload),
                match=match,
                timeout=max(0.0, budget),
                publish_timeout=publish_wait,
                account_id=user_id,
                extra_fields=False,
            )
        )
        ends: set[asyncio.Future[Any]] = {asking, state}
        try:
            await asyncio.wait(ends, return_when=asyncio.FIRST_COMPLETED)
        finally:
            if not asking.done():  # the state came first: the answer no longer counts
                asking.cancel()
                await asyncio.wait({asking})
            if asking.done() and not asking.cancelled():
                asking.exception()  # retrieved: the state may decide instead
        if not state.done():  # the state decides when it is in
            if deadline is not None and isinstance(asking.exception(), DeviceTimeoutError):
                raise DeviceTimeoutError(
                    f"{redact_serial(serial)}: no answer within {budget:.0f} s", device_sn=serial
                )
            asking.result()
            if replies[-1].result is not LockResult.ACCEPTED:
                raise CommandRejectedError(
                    cm2.P2P_COMMAND,
                    replies[-1].code,
                    f"{redact_serial(serial)}: {replies[-1].result.value}",
                    device_sn=serial,
                )
            budget = LOCK_CONFIRM_TIMEOUT if deadline is None else deadline - loop.time()
            await asyncio.wait({state}, timeout=max(0.0, budget))
            if not state.done():
                raise DeviceTimeoutError(
                    f"{redact_serial(serial)}: no {target.value} state within {budget:.0f} s",
                    device_sn=serial,
                )
        result = state.result()
        if result in FAULT_STATES:
            raise LockNotMovedError(
                cm2.P2P_COMMAND,
                f"{redact_serial(serial)} reported {result.value} after the "
                f"{action.name.lower()} command",
                state=result,
                device_sn=serial,
            )
        return result
