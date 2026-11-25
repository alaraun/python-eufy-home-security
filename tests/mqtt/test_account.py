"""The account's MQTT connections: one client per login scope with MQTT devices."""

from __future__ import annotations

import asyncio
import json
from collections.abc import AsyncIterator

import pytest

from eufy_home_security.exceptions import CommunicationError, UnsupportedError
from eufy_home_security.mqtt import account as account_module
from eufy_home_security.mqtt.account import EufyMqttAccount
from eufy_home_security.mqtt.envelope import MqttMessage, response_topic

from .conftest import (
    CAMERA,
    LOCK2_SN,
    LOCK_SN,
    SCOPE,
    Rig,
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


async def test_a_stop_during_a_device_update_leaves_no_client(
    rig: Rig, account: EufyMqttAccount, monkeypatch: pytest.MonkeyPatch
) -> None:
    await account.async_start([EU_LOCK])
    await account.async_wait_connected(5)
    held = hold_selection(monkeypatch, account_module)
    try:
        update = asyncio.create_task(account.async_update_devices([EU_LOCK, SCOPE_LOCK]))
        await until(held.entered.is_set)
        stop = asyncio.create_task(account.async_stop())
        await asyncio.sleep(0.05)  # the stop arrives while the update reads the list
    finally:
        held.release.set()
    async with asyncio.timeout(5):
        await update
        await stop
    await asyncio.sleep(0.3)
    assert account.clients == {}
    assert rig.broker.connected_clients == []
    assert mqtt_tasks() == []


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
