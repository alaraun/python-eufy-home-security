"""Lock and unlock over the eufy security MQTT broker (:class:`MqttLocks`; needs the ``mqtt``
extra), confirmed by the lock's state.

A Wi-Fi lock the route marks MQTT (:func:`~..devices.lock_routes.lock_route`) takes the
1940 cm2 frame as the ``trans`` of a command message (declared, eufy app; docs/protocol/
mqtt.md § Lock commands): the payload object ``{lock_payload, seq_num, apiCommand, time}``
keyed by the member record's ``admin_user_id`` and a time value. The lock answers on its
response topic with the frame encrypted under the key its own ``time`` names, and reports
its state in a status report the same way; :class:`~..events.LockStateChanged` carries it.
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
    GUEST_MEMBER_TYPE,
    LOCK_ANSWER_TIMEOUT,
    LOCK_CONFIRM_TIMEOUT,
    TARGET_STATES,
    LockControl,
    LockPath,
    check_control,
    ends_wait,
    lock_control,
)
from ..lock_commands.mqtt_trans import decode_trans, encode_trans
from ..lock_commands.sequence import LockSequences

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
    return lock_control(form, guest=device.member_type == GUEST_MEMBER_TYPE)


def _through_data(message: MqttMessage) -> Mapping[str, Any] | None:
    """The 1940 through-data object of a lock's message (its serial from the topic)."""
    trans = message.trans
    if trans is None:
        return None
    try:
        command, payload = decode_trans(trans)
    except ProtocolError:
        return None
    if command != cm2.P2P_COMMAND:
        return None
    return {**payload, "dev_sn": message.device_sn}


class MqttLocks:
    """Lock commands and lock state of the account's MQTT locks over ``account``.

    ``user_name`` is what a command names as its sender; ``emit`` receives each
    :class:`~..events.LockStateChanged`. Call :meth:`close` to stop listening.
    """

    def __init__(
        self,
        account: EufyMqttAccount,
        *,
        user_name: str,
        emit: Callable[[Event], None],
        clock: Callable[[], float] = time.time,
    ) -> None:
        self._account = account
        self._user_name = user_name
        self._emit = emit
        self._clock = clock
        self._sequences = LockSequences(clock=clock)
        self._readings: dict[str, LockReading] = {}
        self._owners: dict[str, str] = {}
        self._watchers: dict[str, Callable[[LockReading], None]] = {}
        self._busy: set[str] = set()
        self._remove = account.add_listener(self._on_message)

    def close(self) -> None:
        self._remove()

    def reading(self, device_sn: str) -> LockReading | None:
        """The lock's state as its last status report over MQTT said."""
        return self._readings.get(device_sn)

    def _on_message(self, message: MqttMessage) -> None:
        payload = _through_data(message)
        owner = self._owners.get(message.device_sn)
        if payload is None or owner is None:
            return
        try:
            report = cm2.parse_status_report(payload, serial=message.device_sn, user_id=owner)
        except ProtocolError as err:
            _LOGGER.debug("%s: unreadable status report: %s", redact_serial(message.device_sn), err)
            return
        if report is None or report.code != 0 or report.state_code is None:
            return
        self._take(message.device_sn, report.state_code)

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
        owner = device.owner_user_id
        if not owner:  # as the app: no member record, no command
            raise UnsupportedError(
                f"{redact_serial(serial)}: the cloud record names no member for the lock",
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
        self._owners[serial] = owner
        self._busy.add(serial)
        try:
            return await self._run(serial, owner, action, target, timeout)
        finally:
            self._busy.discard(serial)
            self._watchers.pop(serial, None)

    async def _run(
        self, serial: str, owner: str, action: LockAction, target: LockState, timeout: float | None
    ) -> LockState:
        loop = asyncio.get_running_loop()
        deadline = None if timeout is None else loop.time() + timeout
        now = self._clock()
        request = cm2.build_on_off_request(
            serial,
            action,
            cm2.Cm2User(owner, self._user_name, None),
            seq_num=self._sequences.next(serial),
            time_value=cm2.lock_time(now, secrets.randbelow(100)),
            timestamp=int(now),
        )
        payload = {
            "lock_payload": request.payload["lock_payload"],
            "seq_num": request.payload["seq_num"],
            "apiCommand": cm2.P2P_COMMAND,
            "time": request.time_value,
        }
        state: asyncio.Future[LockState] = loop.create_future()

        def on_reading(taken: LockReading) -> None:
            if not state.done() and ends_wait(taken.state, target):
                state.set_result(taken.state)

        self._watchers[serial] = on_reading
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

        budget = LOCK_ANSWER_TIMEOUT if deadline is None else deadline - loop.time()
        try:
            await self._account.async_request(
                serial,
                encode_trans(cm2.P2P_COMMAND, payload),
                match=match,
                timeout=max(0.0, budget),
            )
        except DeviceTimeoutError:
            if not state.done():
                raise DeviceTimeoutError(
                    f"{redact_serial(serial)}: no answer within {budget:.0f} s", device_sn=serial
                ) from None
        if replies and replies[-1].result is not LockResult.ACCEPTED:
            raise CommandRejectedError(
                cm2.P2P_COMMAND,
                replies[-1].code,
                f"{redact_serial(serial)}: {replies[-1].result.value}",
                device_sn=serial,
            )
        if not state.done():
            budget = LOCK_CONFIRM_TIMEOUT if deadline is None else deadline - loop.time()
            try:
                async with asyncio.timeout(max(0.0, budget)):
                    await asyncio.shield(state)
            except TimeoutError:
                raise DeviceTimeoutError(
                    f"{redact_serial(serial)}: no {target.value} state within {budget:.0f} s",
                    device_sn=serial,
                ) from None
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
