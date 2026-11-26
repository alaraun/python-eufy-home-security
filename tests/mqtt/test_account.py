"""The account's MQTT connections: one client per login scope with MQTT devices."""

from __future__ import annotations

import asyncio
import gc
import json
import logging
from collections.abc import AsyncIterator, Callable, Coroutine
from typing import Any

import pytest

from eufy_home_security.cloud.models import CloudDevice
from eufy_home_security.events import CloudProblem, Event
from eufy_home_security.exceptions import (
    CloudError,
    CommunicationError,
    NoCachedSessionError,
    UnsupportedError,
)
from eufy_home_security.mqtt import account as account_module
from eufy_home_security.mqtt.account import EufyMqttAccount
from eufy_home_security.mqtt.envelope import MqttMessage, response_topic
from eufy_home_security.testing import FakeCloud

from .conftest import (
    CAMERA,
    LOCK2_SN,
    LOCK_SN,
    SCOPE,
    Rig,
    SlowProxy,
    answer,
    hold_selection,
    lock,
    mqtt_tasks,
    until,
)

EU_LOCK = lock(region="eu")
SCOPE_LOCK = lock(LOCK2_SN, "T85L0", region=SCOPE)


@pytest.fixture
async def account(rig: Rig) -> AsyncIterator[EufyMqttAccount]:
    mqtt = EufyMqttAccount(rig.eufy.cloud, port=rig.broker.port, server_ca_pem=rig.pki.ca_pem)
    try:
        yield mqtt
    finally:
        await mqtt.async_stop()


async def test_each_scope_with_mqtt_devices_gets_a_client_and_its_calls(
    rig: Rig, account: EufyMqttAccount
) -> None:
    seen: list[MqttMessage] = []
    account.add_listener(seen.append)
    await account.async_start([EU_LOCK, CAMERA, SCOPE_LOCK])
    await account.async_wait_connected(5)
    assert account.connected
    assert list(account.clients) == ["eu", SCOPE]
    assert [d.device_sn for d in account.clients[SCOPE].devices] == [LOCK2_SN]
    assert [d.device_sn for d in account.devices] == [LOCK_SN, LOCK2_SN]
    await until(lambda: len(account.topics) == 2)
    assert rig.cloud.calls.count("mqtt_register") == 1
    assert rig.cloud.calls.count(f"mqtt_register@{SCOPE}") == 1
    assert len(rig.broker.connects) == 2
    eu_id, scope_id = (c.client_id for c in rig.broker.connects)
    assert account.client_for(LOCK2_SN) is account.clients[SCOPE]

    await account.async_publish(LOCK2_SN, "to-scope")
    await account.async_publish(LOCK_SN, "to-eu")
    await until(lambda: len(rig.broker.published) == 2)
    sent = {json.loads(json.loads(p.payload)["payload"])["trans"]: p for p in rig.broker.published}
    assert {sent["to-scope"].client_id, sent["to-eu"].client_id} == {eu_id, scope_id}
    assert sent["to-scope"].client_id != sent["to-eu"].client_id

    task = asyncio.create_task(account.async_request(LOCK_SN, "ask", timeout=5))
    await until(lambda: len(rig.broker.published) == 3)
    seq = json.loads(rig.broker.published[2].payload)["head"]["msg_seq"]
    await rig.broker.send(response_topic("T85D0", LOCK_SN), answer({"msg_seq": seq}, "mine"))
    assert (await task).trans == "mine"
    await rig.broker.send(response_topic("T85L0", LOCK2_SN), answer({"msg_seq": 99}, "other"))
    await until(lambda: len(seen) == 2)
    assert {m.device_sn for m in seen} == {LOCK_SN, LOCK2_SN}


async def test_the_clients_follow_the_scopes_of_the_device_list(
    rig: Rig, account: EufyMqttAccount
) -> None:
    await account.async_start([EU_LOCK])
    await account.async_wait_connected(5)
    eu = account.clients["eu"]
    await account.async_update_devices([EU_LOCK, SCOPE_LOCK])
    await account.async_wait_connected(5)
    assert list(account.clients) == ["eu", SCOPE]
    assert account.clients["eu"] is eu
    assert len(rig.broker.connects) == 2  # the eu set is unchanged: its connection stays
    await account.async_update_devices([SCOPE_LOCK, CAMERA])
    assert list(account.clients) == [SCOPE]
    assert not eu.connected
    await until(lambda: len(rig.broker.connected_clients) == 1)
    await account.async_update_devices([CAMERA])
    assert account.clients == {}
    assert not account.connected
    await until(lambda: rig.broker.connected_clients == [])


@pytest.mark.parametrize("case", ["start", "update"])
async def test_a_stop_during_a_start_or_device_update_leaves_no_client(
    rig: Rig, account: EufyMqttAccount, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    call: Callable[[list[CloudDevice]], Coroutine[Any, Any, None]] = account.async_start
    if case == "update":
        await account.async_start([EU_LOCK])
        await account.async_wait_connected(5)
        call = account.async_update_devices
    held = hold_selection(monkeypatch, account_module)
    try:
        started = asyncio.create_task(call([EU_LOCK, SCOPE_LOCK]))
        await until(held.entered.is_set)
        stop = asyncio.create_task(account.async_stop())
        await asyncio.sleep(0.05)  # the stop arrives while the call reads the list
    finally:
        held.release.set()
    async with asyncio.timeout(5):
        await started
        await stop
    await asyncio.sleep(0.3)
    assert account.clients == {}
    assert rig.broker.connected_clients == []
    assert mqtt_tasks() == []


@pytest.mark.parametrize("queued", [True, False], ids=["queued-behind-the-stop", "after-the-stop"])
async def test_a_device_update_after_a_stop_starts_no_client(
    rig: Rig, account: EufyMqttAccount, queued: bool
) -> None:
    await account.async_start([EU_LOCK])
    await account.async_wait_connected(5)
    stop = asyncio.create_task(account.async_stop())
    await asyncio.sleep(0)
    assert account._stopped  # marked at once, before the stop awaits anything
    assert account.clients == {}
    if not queued:
        await stop
    update = asyncio.create_task(account.async_update_devices([EU_LOCK, SCOPE_LOCK]))
    async with asyncio.timeout(5):
        await stop
        await update
    await asyncio.sleep(0.3)
    assert account.clients == {}
    assert rig.broker.connected_clients == []
    assert len(rig.broker.connects) == 1
    assert mqtt_tasks() == []


async def test_a_start_queued_before_a_stop_starts_no_client(
    rig: Rig, account: EufyMqttAccount, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A start waiting behind a slow device update when a stop comes starts nothing: once
    the stop returns no client runs, and the account stays stopped."""
    await account.async_start([EU_LOCK])
    await account.async_wait_connected(5)
    held = hold_selection(monkeypatch, account_module)
    try:
        update = asyncio.create_task(account.async_update_devices([EU_LOCK]))
        await until(held.entered.is_set)
        start = asyncio.create_task(account.async_start([EU_LOCK, SCOPE_LOCK]))
        await asyncio.sleep(0.05)  # the start waits for the update
        stop = asyncio.create_task(account.async_stop())
        await asyncio.sleep(0.05)
    finally:
        held.release.set()
    async with asyncio.timeout(5):
        await update
        await start
        await stop
    assert account.clients == {}
    assert account._stopped
    await account.async_update_devices([EU_LOCK, SCOPE_LOCK])  # still stopped: ignored
    assert account.clients == {}
    await until(lambda: rig.broker.connected_clients == [])
    assert len(rig.broker.connects) == 1
    await until(lambda: mqtt_tasks() == [], 3.0)


async def test_a_start_after_a_stop_follows_device_updates_again(
    rig: Rig, account: EufyMqttAccount
) -> None:
    await account.async_start([CAMERA])
    await account.async_stop()
    await account.async_start([CAMERA])
    await account.async_update_devices([EU_LOCK])
    await account.async_wait_connected(5)
    assert list(account.clients) == ["eu"]


async def test_a_cancel_of_a_stop_still_stops_every_client(rig: Rig) -> None:
    async with SlowProxy(rig.broker.port, 1.0) as proxy:
        account = EufyMqttAccount(rig.eufy.cloud, port=proxy.port, server_ca_pem=rig.pki.ca_pem)
        await account.async_start([EU_LOCK, SCOPE_LOCK])
        clients = list(account.clients.values())
        try:
            await asyncio.sleep(0.2)  # both connect steps wait on the proxy
            with pytest.raises(TimeoutError):
                async with asyncio.timeout(0.2):
                    await account.async_stop()
            await until(lambda: mqtt_tasks() == [], 3.0)
            await asyncio.sleep(0.2)
            assert account.clients == {}
            assert rig.broker.connected_clients == []
        finally:
            for client in clients:
                await client.async_stop()


async def test_a_stop_cancelled_behind_a_slow_device_update_still_stops_every_client(
    rig: Rig, account: EufyMqttAccount, monkeypatch: pytest.MonkeyPatch
) -> None:
    """A bounded stop (an unload) cancelled while a device update still reads the list:
    the running client is stopped all the same, and the update starts no new one."""
    await account.async_start([EU_LOCK])
    await account.async_wait_connected(5)
    held = hold_selection(monkeypatch, account_module)
    try:
        update = asyncio.create_task(account.async_update_devices([EU_LOCK, SCOPE_LOCK]))
        await until(held.entered.is_set)
        with pytest.raises(TimeoutError):
            async with asyncio.timeout(0.2):
                await account.async_stop()
    finally:
        held.release.set()
    async with asyncio.timeout(5):
        await update
    await until(lambda: mqtt_tasks() == [], 3.0)
    assert account.clients == {}
    await until(lambda: rig.broker.connected_clients == [])
    assert len(rig.broker.connects) == 1  # no client for the update's new scope
    await account.async_update_devices([EU_LOCK, SCOPE_LOCK])  # stopped: ignored
    assert account.clients == {}


async def test_a_client_stop_failing_after_a_cancel_is_logged_once(
    account: EufyMqttAccount, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    await account.async_start([EU_LOCK])
    client = account.clients["eu"]
    real_stop = client.async_stop

    async def failing_stop() -> None:
        await real_stop()
        await asyncio.sleep(0.3)
        raise CommunicationError("client stop failed")

    monkeypatch.setattr(client, "async_stop", failing_stop)
    loop = asyncio.get_running_loop()
    loop_errors: list[dict[str, Any]] = []
    loop.set_exception_handler(lambda _loop, context: loop_errors.append(context))
    try:
        with pytest.raises(TimeoutError):
            async with asyncio.timeout(0.1):
                await account.async_stop()
        await until(lambda: not account._ending, 3.0)
        gc.collect()
        await asyncio.sleep(0)
    finally:
        loop.set_exception_handler(None)
    assert loop_errors == []  # no "Task exception was never retrieved"
    logged = [r for r in caplog.records if r.name == account_module.__name__]
    assert [(r.levelno, "client stop failed" in r.getMessage()) for r in logged] == [
        (logging.WARNING, True)
    ]


async def test_no_mqtt_device_starts_no_client_unless_a_check_asks(
    rig: Rig, account: EufyMqttAccount
) -> None:
    await account.async_start([CAMERA])
    assert account.clients == {}
    with pytest.raises(CommunicationError, match="no MQTT device"):
        await account.async_wait_connected(1)
    await account.async_stop()
    await account.async_start([CAMERA], connect_without_devices=True)
    await account.async_wait_connected(5)
    assert list(account.clients) == ["eu"]
    assert rig.broker.subscriptions == []


async def test_a_serial_of_no_scope_is_unsupported(account: EufyMqttAccount) -> None:
    await account.async_start([EU_LOCK])
    with pytest.raises(UnsupportedError) as caught:
        await account.async_publish(CAMERA.device_sn, "x")
    assert caught.value.device_sn == CAMERA.device_sn
    with pytest.raises(UnsupportedError):
        await account.async_request(CAMERA.device_sn, "x", timeout=1)
    with pytest.raises(RuntimeError, match="already started"):
        await account.async_start([EU_LOCK])


async def test_listeners_reach_later_clients_until_removed(
    rig: Rig, account: EufyMqttAccount
) -> None:
    removed: list[MqttMessage] = []
    kept: list[MqttMessage] = []
    remove = account.add_listener(removed.append)
    await account.async_start([EU_LOCK])
    account.add_listener(kept.append)
    remove()
    await account.async_update_devices([EU_LOCK, SCOPE_LOCK])
    await account.async_wait_connected(5)
    await until(lambda: len(account.topics) == 2)
    await rig.broker.send(response_topic("T85D0", LOCK_SN), answer({"msg_seq": 1}))
    await rig.broker.send(response_topic("T85L0", LOCK2_SN), answer({"msg_seq": 2}))
    await until(lambda: len(kept) == 2)
    await asyncio.sleep(0.05)
    assert removed == []
    remove()  # a second call is a no-op


async def test_a_certificate_fetchs_cloud_error_reaches_the_client_as_a_cloud_problem(
    rig: Rig, account: EufyMqttAccount
) -> None:
    """The account's certificate fetch never logs in; its cloud error reaches the
    account's listeners and, through ``use_mqtt``, the client's stream as one
    ``CloudProblem`` (no station), which a consumer routes like any other."""
    errors: list[CloudError] = []
    account.add_cloud_error_listener(errors.append)
    removed: list[CloudError] = []
    account.add_cloud_error_listener(removed.append)()  # removed at once: never called
    seen: list[Event] = []
    rig.eufy.subscribe(seen.append)
    rig.eufy.use_mqtt(account)
    rig.cloud.call_errors.extend([FakeCloud.refusal(401)] * 2)
    await account.async_start([EU_LOCK])
    await until(lambda: len(errors) == 2)
    await account.async_wait_connected(5)
    rig.eufy.use_mqtt(None)
    assert all(isinstance(e, NoCachedSessionError) for e in errors)
    problems = [e for e in seen if isinstance(e, CloudProblem)]
    assert [(type(p.error), p.station_sn) for p in problems] == [(NoCachedSessionError, None)]
    assert "login" not in rig.cloud.calls
    assert removed == []
