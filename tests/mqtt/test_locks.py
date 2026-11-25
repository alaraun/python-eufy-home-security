"""Lock and unlock over the MQTT broker (``EufySecurity.use_mqtt`` / ``async_lock`` /
``async_unlock`` / ``lock_control``) against the loopback broker and a fake Wi-Fi lock."""

from __future__ import annotations

import asyncio
import base64
import dataclasses
import json
from types import MappingProxyType

import pytest

from eufy_home_security.cloud.models import CloudDevice
from eufy_home_security.devices.locks import LockState, LockStateSource
from eufy_home_security.events import Event, LockStateChanged
from eufy_home_security.exceptions import (
    CommandRejectedError,
    DeviceBusyError,
    DeviceTimeoutError,
    GuestAccessError,
    LockNotMovedError,
    MqttAccountRequiredError,
    UnsupportedError,
)
from eufy_home_security.lock_commands.actions import LockAction
from eufy_home_security.lock_commands.control import LockPath
from eufy_home_security.mqtt.account import EufyMqttAccount
from eufy_home_security.testing.mqtt import FakeMqttLock

from .conftest import LOCK_SN, OWNER, SHORT_USER, Rig, lock

pytestmark = pytest.mark.usefixtures("short_waits")


@pytest.fixture
def wifi_lock(rig: Rig) -> FakeMqttLock:
    fake = FakeMqttLock(
        broker=rig.broker, serial=LOCK_SN, product_code="T85D0", owner_user_id=OWNER
    )
    fake.attach()
    return fake


async def _served(rig: Rig, device: CloudDevice | None = None) -> EufyMqttAccount:
    device = device or lock()
    rig.eufy.listed_devices = MappingProxyType({device.device_sn: device})
    account = EufyMqttAccount(rig.eufy.cloud, port=rig.broker.port, server_ca_pem=rig.pki.ca_pem)
    await account.async_start([device])
    await account.async_wait_connected(5)
    await rig.broker.wait_for(
        lambda: any(t.endswith("/res") for _, t, _ in rig.broker.subscriptions)
    )
    rig.eufy.use_mqtt(account)
    return account


def _events(rig: Rig) -> list[Event]:
    seen: list[Event] = []
    rig.eufy.subscribe(seen.append)
    return seen


async def test_a_lock_over_mqtt_is_confirmed_by_its_status_report(
    rig: Rig, wifi_lock: FakeMqttLock
) -> None:
    account = await _served(rig)
    events = _events(rig)
    try:
        assert rig.eufy.lock_control(LOCK_SN).path is LockPath.MQTT
        assert await rig.eufy.async_lock(LOCK_SN) is LockState.LOCKED
    finally:
        await account.async_stop()
    assert [a for a, _ in wifi_lock.received] == [LockAction.LOCK]
    assert wifi_lock.users == [(OWNER, SHORT_USER)]  # the member record's ids, as the app sends
    changes = [(e.state, e.source, e.station_sn) for e in events if isinstance(e, LockStateChanged)]
    assert changes == [(LockState.LOCKED, LockStateSource.LOCK, None)]
    sent = json.loads(rig.broker.published[-1].payload)
    trans = json.loads(base64.b64decode(json.loads(sent["payload"])["trans"]))
    assert trans["cmd"] == 1940
    assert list(trans["payload"]) == ["lock_payload", "seq_num", "apiCommand", "time"]
    assert trans["payload"]["apiCommand"] == 1940
    assert sent["head"]["cmd"] == 9


async def test_an_unlock_over_mqtt_skips_an_answer_to_another_request(
    rig: Rig, wifi_lock: FakeMqttLock
) -> None:
    wifi_lock.mismatch_first = True
    wifi_lock.answer_code = 1  # the stale answer accepts, the lock's own refuses
    account = await _served(rig)
    try:
        with pytest.raises(CommandRejectedError) as raised:
            await rig.eufy.async_unlock(LOCK_SN, timeout=5)
    finally:
        await account.async_stop()
    assert raised.value.code == 1
    assert [a for a, _ in wifi_lock.received] == [LockAction.UNLOCK]


async def test_no_status_report_over_mqtt_times_out(rig: Rig, wifi_lock: FakeMqttLock) -> None:
    wifi_lock.report = False
    account = await _served(rig)
    try:
        with pytest.raises(DeviceTimeoutError, match="locked state"):
            await rig.eufy.async_lock(LOCK_SN, timeout=1)
    finally:
        await account.async_stop()


async def test_a_silent_mqtt_lock_times_out_within_the_given_timeout(
    rig: Rig, wifi_lock: FakeMqttLock
) -> None:
    wifi_lock.answer = False
    account = await _served(rig)
    try:
        async with asyncio.timeout(5):
            with pytest.raises(DeviceTimeoutError, match="no answer"):
                await rig.eufy.async_lock(LOCK_SN, timeout=0.5)
    finally:
        await account.async_stop()


async def test_an_mqtt_lock_already_locked_sends_nothing(rig: Rig, wifi_lock: FakeMqttLock) -> None:
    account = await _served(rig)
    try:
        assert await rig.eufy.async_lock(LOCK_SN, timeout=5) is LockState.LOCKED
        assert await rig.eufy.async_lock(LOCK_SN, timeout=5) is LockState.LOCKED
    finally:
        await account.async_stop()
    assert [a for a, _ in wifi_lock.received] == [LockAction.LOCK]


async def test_a_second_mqtt_command_while_one_waits_is_busy(
    rig: Rig, wifi_lock: FakeMqttLock
) -> None:
    wifi_lock.report = False
    account = await _served(rig)
    try:
        first = asyncio.create_task(rig.eufy.async_lock(LOCK_SN, timeout=5))
        async with asyncio.timeout(5):
            while not wifi_lock.received:
                await asyncio.sleep(0.01)
            with pytest.raises(DeviceBusyError):
                await rig.eufy.async_unlock(LOCK_SN)
        first.cancel()
        with pytest.raises(asyncio.CancelledError):
            await first
    finally:
        await account.async_stop()
    assert len(wifi_lock.received) == 1


async def test_an_mqtt_lock_without_a_member_record_is_refused(
    rig: Rig, wifi_lock: FakeMqttLock
) -> None:
    account = await _served(rig, dataclasses.replace(lock(), owner_user_id=None))
    try:
        with pytest.raises(UnsupportedError, match="member"):
            await rig.eufy.async_lock(LOCK_SN)
    finally:
        await account.async_stop()
    assert wifi_lock.received == []


async def test_a_fault_state_over_mqtt_raises_lock_not_moved(
    rig: Rig, wifi_lock: FakeMqttLock
) -> None:
    wifi_lock.move_to = 5
    account = await _served(rig)
    try:
        with pytest.raises(LockNotMovedError):
            await rig.eufy.async_lock(LOCK_SN, timeout=5)
    finally:
        await account.async_stop()


async def test_an_mqtt_lock_without_an_account_is_refused(rig: Rig) -> None:
    rig.eufy.listed_devices = MappingProxyType({LOCK_SN: lock()})
    with pytest.raises(MqttAccountRequiredError):
        await rig.eufy.async_lock(LOCK_SN)
    assert rig.broker.published == []


async def test_a_guest_of_an_mqtt_lock_is_refused(rig: Rig, wifi_lock: FakeMqttLock) -> None:
    guest = dataclasses.replace(lock(), member_type=0)
    account = await _served(rig, guest)
    try:
        assert rig.eufy.lock_control(LOCK_SN).guest
        with pytest.raises(GuestAccessError):
            await rig.eufy.async_lock(LOCK_SN)
    finally:
        await account.async_stop()
    assert wifi_lock.received == []


async def test_a_device_not_listed_is_refused(rig: Rig) -> None:
    with pytest.raises(UnsupportedError, match="device list"):
        rig.eufy.lock_control(LOCK_SN)
