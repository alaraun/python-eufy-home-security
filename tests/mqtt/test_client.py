"""The MQTT client against a loopback broker: connect, subscribe, publish, answers, reconnects.

Nothing here reaches a real broker: the client connects to :class:`FakeMqttBroker` on
127.0.0.1 with the throwaway PKI the fake cloud issues.
"""

from __future__ import annotations

import asyncio
import contextlib
import functools
import gc
import json
import logging
import subprocess
import sys
from collections.abc import AsyncIterator, Callable, Coroutine
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from eufy_home_security._logging import LogThrottle
from eufy_home_security.cloud import const
from eufy_home_security.cloud.models import CloudDevice
from eufy_home_security.exceptions import (
    CommunicationError,
    DeviceTimeoutError,
    MissingDependencyError,
    UnsupportedError,
)
from eufy_home_security.mqtt import client as client_module
from eufy_home_security.mqtt.client import EufyMqttClient
from eufy_home_security.mqtt.envelope import (
    CMD_DOWNLINK_TRANS,
    CMD_STATUS_REQUEST_NO_ACK,
    MqttMessage,
    request_topic,
    response_topic,
)
from eufy_home_security.mqtt.selection import device_key
from eufy_home_security.testing import SYNTHETIC

from .conftest import (
    CAMERA,
    LOCK2_SN,
    LOCK_SN,
    OWNER,
    SCOPE,
    Rig,
    SlowProxy,
    answer,
    hold_selection,
    lock,
    mqtt_tasks,
    until,
)


@contextlib.asynccontextmanager
async def _scope_client(rig: Rig) -> AsyncIterator[EufyMqttClient]:
    client = EufyMqttClient(
        rig.eufy.cloud, region=SCOPE, port=rig.broker.port, server_ca_pem=rig.pki.ca_pem
    )
    try:
        yield client
    finally:
        await client.async_stop()


def _subscriptions_are(rig: Rig, count: int) -> bool:
    return len(rig.broker.subscriptions) == count


def _subscribed(rig: Rig) -> list[tuple[str, int]]:
    return [(topic, qos) for _client, topic, qos in rig.broker.subscriptions]


# ── connect and subscribe ────────────────────────────────────────────────────


async def test_it_connects_with_the_app_client_id_and_subscribes_each_mqtt_device(
    rig: Rig,
) -> None:
    await rig.client.async_start([lock(), CAMERA, lock(LOCK2_SN, "T85L0")])
    await rig.client.async_wait_connected(5)
    await until(lambda: len(rig.broker.subscriptions) == 2)
    openudid = rig.eufy.cloud._install_id("eu")
    (connect,) = rig.broker.connects
    assert connect.client_id == f"android-eufy_security-{SYNTHETIC.account_id}-{openudid}"
    assert connect.keepalive == 300
    assert connect.clean_session
    assert connect.protocol_level == 4  # MQTT 3.1.1
    assert connect.client_certificate
    assert connect.username == "?SDK=Android&Version=2.81.0"
    assert not connect.password
    assert sorted(_subscribed(rig)) == [
        (response_topic("T85D0", LOCK_SN), 1),
        (response_topic("T85L0", LOCK2_SN), 1),
    ]
    assert rig.client.topics == frozenset(topic for topic, _ in _subscribed(rig))
    assert [d.device_sn for d in rig.client.devices] == [LOCK_SN, LOCK2_SN]
    assert rig.registers() == 1
    assert rig.cloud.mqtt_requests == [(const.mega_host("eu"), True, {})]


async def test_a_client_serves_only_the_devices_of_its_login_scope(rig: Rig) -> None:
    async with _scope_client(rig) as client:
        await client.async_start([lock(region="eu"), lock(LOCK2_SN, "T85L0", region=SCOPE)])
        await client.async_wait_connected(5)
        assert client.scope == SCOPE
        assert [d.device_sn for d in client.devices] == [LOCK2_SN]
        await until(lambda: len(client.topics) == 1)
        assert _subscribed(rig) == [(response_topic("T85L0", LOCK2_SN), 1)]
        api = rig.eufy.cloud
        assert api._install_id(SCOPE) != api._install_id("eu")
        (connect,) = rig.broker.connects
        assert connect.client_id.endswith(f"-{api._install_id(SCOPE)}")
        assert rig.cloud.calls == [f"mqtt_register@{SCOPE}"]
        assert api._cache.mqtt_devices(SCOPE) == frozenset({device_key(lock(LOCK2_SN, "T85L0"))})
        assert api._cache.mqtt_certificate(SCOPE) is not None
        assert api._cache.mqtt_certificate("eu") is None
        with pytest.raises(UnsupportedError):
            await client.async_publish(LOCK_SN, "x")


async def test_the_default_scope_takes_the_devices_without_a_region(rig: Rig) -> None:
    await rig.client.async_start(
        [lock(region=SCOPE), lock(LOCK2_SN, "T85L0"), lock("T85D0P2000054323", region="eu")]
    )
    assert rig.client.scope == "eu"
    assert [d.device_sn for d in rig.client.devices] == [LOCK2_SN, "T85D0P2000054323"]


async def test_three_losses_drop_the_certificate_of_the_clients_scope(rig: Rig) -> None:
    async with _scope_client(rig) as client:
        await client.async_start([lock(region=SCOPE)])
        for count in (1, 2, 3):
            await until(functools.partial(_subscriptions_are, rig, count))
            rig.broker.drop_connections()
        await until(lambda: len(rig.broker.subscriptions) == 4)
        assert rig.cloud.calls == [f"mqtt_register@{SCOPE}"] * 2


async def test_no_mqtt_device_means_no_certificate_and_no_connection(rig: Rig) -> None:
    await rig.client.async_start([CAMERA])
    await asyncio.sleep(0.1)
    assert rig.broker.connects == []
    assert rig.registers() == 0
    assert not rig.client.connected


async def test_a_check_without_mqtt_devices_can_connect_subscribing_nothing(rig: Rig) -> None:
    await rig.client.async_start([CAMERA], connect_without_devices=True)
    await rig.client.async_wait_connected(5)
    await asyncio.sleep(0.1)
    assert len(rig.broker.connects) == 1
    assert rig.broker.subscriptions == []
    assert rig.registers() == 1


async def test_a_refused_subscription_is_retried_until_the_broker_takes_it(rig: Rig) -> None:
    topic = response_topic("T85D0", LOCK_SN)
    rig.broker.refused_topics.add(topic)
    await rig.client.async_start([lock()])
    await until(lambda: len(rig.broker.subscriptions) >= 2)
    assert topic not in rig.client.topics
    rig.broker.refused_topics.clear()
    await until(lambda: topic in rig.client.topics)
    assert all(t == topic for _c, t, _q in rig.broker.subscriptions)


# ── publish ──────────────────────────────────────────────────────────────────


async def test_a_publish_sends_the_envelope_to_the_request_topic_with_qos_1(rig: Rig) -> None:
    await rig.client.async_start([lock()])
    await rig.client.async_wait_connected(5)
    head = await rig.client.async_publish(LOCK_SN, "opaque-trans")
    await until(lambda: len(rig.broker.published) == 1)
    (sent,) = rig.broker.published
    assert sent.topic == request_topic("T85D0", LOCK_SN)
    assert (sent.qos, sent.retain) == (1, False)
    body = json.loads(sent.payload)
    assert body["head"]["client_id"] == rig.broker.connects[0].client_id
    assert body["head"]["cmd"] == CMD_DOWNLINK_TRANS
    assert body["head"]["cmd_status"] == CMD_STATUS_REQUEST_NO_ACK
    assert body["head"]["msg_seq"] == head.msg_seq == 1
    assert json.loads(body["payload"])["account_id"] == OWNER
    assert json.loads(body["payload"])["trans"] == "opaque-trans"
    second = await rig.client.async_publish(LOCK_SN, "again")
    assert second.msg_seq == 2


async def test_the_topics_name_the_entrys_product_not_the_serials(rig: Rig) -> None:
    # A unit whose serial names another product than its entry's.
    unit = lock("T85D0P2000054329", pn="T85D2")
    await rig.client.async_start([unit])
    await until(lambda: len(rig.client.topics) == 1)
    assert _subscribed(rig) == [(response_topic("T85D2", unit.device_sn), 1)]
    await rig.client.async_publish(unit.device_sn, "x")
    await until(lambda: len(rig.broker.published) == 1)
    assert rig.broker.published[0].topic == request_topic("T85D2", unit.device_sn)


async def test_a_publish_for_another_device_is_refused_before_sending(rig: Rig) -> None:
    await rig.client.async_start([lock()])
    await rig.client.async_wait_connected(5)
    with pytest.raises(UnsupportedError) as caught:
        await rig.client.async_publish(SYNTHETIC.camera_sn, "x")
    assert caught.value.device_sn == SYNTHETIC.camera_sn
    assert rig.broker.published == []


async def test_a_publish_before_start_is_a_communication_error(rig: Rig) -> None:
    with pytest.raises(CommunicationError):
        await rig.client.async_publish(LOCK_SN, "x")


async def test_a_publish_without_a_certificate_asks_for_one_at_once(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    # The first certificate request fails; the next try would wait out a long back-off.
    monkeypatch.setattr(client_module, "RECONNECT_MIN_SECONDS", 30.0)
    rig.cloud.call_errors.append(CommunicationError("cloud down"))
    await rig.client.async_start([lock()])
    await until(lambda: rig.registers() == 1)
    async with asyncio.timeout(5):
        await rig.client.async_publish(LOCK_SN, "x")
    assert rig.registers() == 2
    assert len(rig.broker.published) == 1


async def test_a_publish_after_an_unusable_cached_certificate_asks_for_a_new_one(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(client_module, "RECONNECT_MIN_SECONDS", 30.0)
    other_key = ec.generate_private_key(ec.SECP256R1()).private_bytes(
        serialization.Encoding.PEM,
        serialization.PrivateFormat.PKCS8,
        serialization.NoEncryption(),
    )
    cache = rig.eufy.cloud._cache
    cache.set_mqtt_certificate("eu", rig.pki.register_answer(private_key=other_key.decode()))
    cache.set_mqtt_devices("eu", [device_key(lock())])
    await rig.client.async_start([lock()])
    await asyncio.sleep(0.2)
    assert rig.registers() == 0  # the cached pair was tried and did not load
    assert rig.broker.connects == []
    async with asyncio.timeout(5):
        await rig.client.async_publish(LOCK_SN, "x")
    assert rig.registers() == 1
    assert len(rig.broker.published) == 1


# ── answers ──────────────────────────────────────────────────────────────────


async def test_a_request_gets_the_answer_with_its_sequence_from_its_device(rig: Rig) -> None:
    await rig.client.async_start([lock(), lock(LOCK2_SN, "T85L0")])
    await rig.client.async_wait_connected(5)
    await until(lambda: len(rig.client.topics) == 2)
    task = asyncio.create_task(rig.client.async_request(LOCK_SN, "ask", timeout=5))
    await until(lambda: len(rig.broker.published) == 1)
    seq = json.loads(rig.broker.published[0].payload)["head"]["msg_seq"]
    # Another device's answer and another sequence do not end the wait.
    await rig.broker.send(response_topic("T85L0", LOCK2_SN), answer({"msg_seq": seq}, "other"))
    await rig.broker.send(response_topic("T85D0", LOCK_SN), answer({"msg_seq": seq + 5}, "x"))
    await rig.broker.send(response_topic("T85D0", LOCK_SN), answer({"msg_seq": seq}, "mine"))
    message = await task
    assert (message.device_sn, message.trans) == (LOCK_SN, "mine")


async def test_a_request_takes_the_callers_match(rig: Rig) -> None:
    await rig.client.async_start([lock()])
    await rig.client.async_wait_connected(5)
    await until(lambda: len(rig.client.topics) == 1)
    task = asyncio.create_task(
        rig.client.async_request(LOCK_SN, "ask", match=lambda m: m.trans == "by-content", timeout=5)
    )
    await until(lambda: len(rig.broker.published) == 1)
    topic = response_topic("T85D0", LOCK_SN)
    await rig.broker.send(topic, answer({"msg_seq": 1}, "not this"))
    await rig.broker.send(topic, answer({"msg_seq": 99}, "by-content"))
    assert (await task).trans == "by-content"


async def test_a_request_without_an_answer_times_out_naming_the_device(rig: Rig) -> None:
    await rig.client.async_start([lock()])
    await rig.client.async_wait_connected(5)
    with pytest.raises(DeviceTimeoutError, match=r"0\.2 s") as caught:
        await rig.client.async_request(LOCK_SN, "ask", timeout=0.2)
    assert caught.value.device_sn == LOCK_SN
    with pytest.raises(UnsupportedError):
        await rig.client.async_request(SYNTHETIC.camera_sn, "ask", timeout=0.2)
    assert rig.client._waiters == {}  # nothing kept per serial once a request ended


async def test_one_answer_ends_only_the_first_request_it_matches(rig: Rig) -> None:
    await rig.client.async_start([lock()])
    await rig.client.async_wait_connected(5)
    await until(lambda: len(rig.client.topics) == 1)

    def any_report(message: MqttMessage) -> bool:
        return (message.trans or "").startswith("report")

    first = asyncio.create_task(rig.client.async_request(LOCK_SN, "a", match=any_report, timeout=5))
    await until(lambda: len(rig.broker.published) == 1)
    second = asyncio.create_task(
        rig.client.async_request(LOCK_SN, "b", match=any_report, timeout=5)
    )
    await until(lambda: len(rig.broker.published) == 2)
    topic = response_topic("T85D0", LOCK_SN)
    await rig.broker.send(topic, answer({"msg_seq": 50}, "report-1"))
    assert (await first).trans == "report-1"
    await asyncio.sleep(0.05)
    assert not second.done()
    await rig.broker.send(topic, answer({"msg_seq": 51}, "report-2"))
    assert (await second).trans == "report-2"


async def test_stop_ends_a_pending_request_with_a_communication_error(rig: Rig) -> None:
    await rig.client.async_start([lock()])
    await rig.client.async_wait_connected(5)
    task = asyncio.create_task(rig.client.async_request(LOCK_SN, "ask", timeout=10))
    await until(lambda: len(rig.broker.published) == 1)
    await rig.client.async_stop()
    async with asyncio.timeout(2):
        with pytest.raises(CommunicationError, match="stopped"):
            await task


async def test_a_lost_connection_ends_a_pending_request_at_once(rig: Rig) -> None:
    await rig.client.async_start([lock()])
    await rig.client.async_wait_connected(5)
    task = asyncio.create_task(rig.client.async_request(LOCK_SN, "ask", timeout=10))
    await until(lambda: len(rig.broker.published) == 1)
    rig.broker.drop_connections()
    async with asyncio.timeout(2):
        with pytest.raises(CommunicationError, match="connection lost") as caught:
            await task
    assert not isinstance(caught.value, DeviceTimeoutError)
    assert caught.value.device_sn == LOCK_SN


async def test_listeners_get_every_message_until_removed(rig: Rig) -> None:
    seen: list[MqttMessage] = []
    remove = rig.client.add_listener(seen.append)
    await rig.client.async_start([lock()])
    await rig.client.async_wait_connected(5)
    await until(lambda: len(rig.client.topics) == 1)
    topic = response_topic("T85D0", LOCK_SN)
    await rig.broker.send(topic, b"not json")  # dropped, the client stays up
    await rig.broker.send(topic, answer({"msg_seq": 3}, "report"))
    await until(lambda: len(seen) == 1)
    assert seen[0].trans == "report"
    remove()
    await rig.broker.send(topic, answer({"msg_seq": 4}, "later"))
    await asyncio.sleep(0.1)
    assert len(seen) == 1
    assert rig.client.connected


async def test_a_raising_listener_keeps_the_connection_and_the_other_listeners(
    rig: Rig, caplog: pytest.LogCaptureFixture
) -> None:
    def broken(_message: MqttMessage) -> None:
        raise RuntimeError("consumer bug")

    seen: list[MqttMessage] = []
    rig.client.add_listener(broken)
    rig.client.add_listener(seen.append)
    await rig.client.async_start([lock()])
    await rig.client.async_wait_connected(5)
    await until(lambda: len(rig.client.topics) == 1)
    topic = response_topic("T85D0", LOCK_SN)
    await rig.broker.send(topic, answer({"msg_seq": 3}, "one"))
    await rig.broker.send(topic, answer({"msg_seq": 4}, "two"))
    await until(lambda: len(seen) == 2)
    await asyncio.sleep(0.1)
    assert len(rig.broker.connects) == 1
    assert rig.client.connected
    failures = [r for r in caplog.records if "listener" in r.getMessage()]
    assert len(failures) == 1  # logged once, the repeat throttled
    assert failures[0].exc_info is not None


# ── losses, reconnects, certificate changes ─────────────────────────────────


async def test_a_lost_connection_reconnects_and_subscribes_again(rig: Rig) -> None:
    await rig.client.async_start([lock()])
    await until(lambda: len(rig.broker.subscriptions) == 1)
    rig.broker.drop_connections()
    await until(lambda: len(rig.broker.connects) == 2 and len(rig.broker.subscriptions) == 2)
    assert rig.registers() == 1  # the cached certificate serves the reconnect


async def test_three_lost_connections_drop_the_certificate_for_a_new_one(rig: Rig) -> None:
    await rig.client.async_start([lock()])
    for count in (1, 2, 3):
        await until(functools.partial(_subscriptions_are, rig, count))
        rig.broker.drop_connections()
    await until(lambda: len(rig.broker.subscriptions) == 4)
    assert rig.registers() == 2
    assert rig.eufy.cloud._cache.mqtt_certificate("eu") is not None
    rig.broker.drop_connections()  # the count started again: one loss keeps the certificate
    await until(lambda: len(rig.broker.subscriptions) == 5)
    assert rig.registers() == 2


async def test_a_certificate_drop_the_store_cannot_save_warns_and_keeps_reconnecting(
    rig: Rig, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    await rig.client.async_start([lock()])
    await until(functools.partial(_subscriptions_are, rig, 1))
    store = rig.eufy.cloud._cache._store
    real = store.async_save
    saves = 0

    async def failing_once(data: dict[str, Any]) -> None:
        nonlocal saves
        saves += 1
        if saves == 1:
            raise OSError("disk full")
        await real(data)

    monkeypatch.setattr(store, "async_save", failing_once)
    for count in (1, 2, 3):
        await until(functools.partial(_subscriptions_are, rig, count))
        rig.broker.drop_connections()
    await until(lambda: len(rig.broker.subscriptions) == 4)
    assert saves >= 1
    assert rig.registers() == 2  # the dropped certificate is replaced all the same
    (warning,) = _warnings(caplog, "certificate")
    assert "disk full" in warning.getMessage()
    assert [r for r in caplog.records if r.levelno >= logging.ERROR] == []


async def test_a_refused_connect_is_retried_and_is_no_loss(rig: Rig) -> None:
    rig.broker.connack_code = 5  # not authorised
    await rig.client.async_start([lock()])
    await until(lambda: len(rig.broker.connects) >= 4)
    rig.broker.connack_code = 0
    await rig.client.async_wait_connected(5)
    assert rig.registers() == 1


def _warnings(caplog: pytest.LogCaptureFixture, text: str) -> list[logging.LogRecord]:
    return [
        r
        for r in caplog.records
        if r.name == client_module.__name__ and r.levelno >= logging.WARNING and text in r.msg
    ]


async def test_repeated_connect_failures_warn_once(
    rig: Rig, caplog: pytest.LogCaptureFixture
) -> None:
    caplog.set_level(logging.DEBUG, logger=client_module.__name__)
    rig.broker.connack_code = 5
    await rig.client.async_start([lock()])
    await until(lambda: len(rig.broker.connects) >= 3)
    assert len(_warnings(caplog, "connection %s")) == 1
    retries = [r for r in caplog.records if "connection %s" in r.msg]
    assert len(retries) >= 2  # the repeats stay at DEBUG


async def test_repeated_certificate_failures_warn_once(
    rig: Rig, caplog: pytest.LogCaptureFixture
) -> None:
    rig.cloud.call_errors.extend([CommunicationError("cloud down")] * 3)
    await rig.client.async_start([lock()])
    await until(lambda: rig.registers() >= 3)
    assert len(_warnings(caplog, "certificate unavailable")) == 1


async def test_an_unexpected_error_is_logged_once_with_its_traceback_and_retried(
    rig: Rig, caplog: pytest.LogCaptureFixture, monkeypatch: pytest.MonkeyPatch
) -> None:
    attempts: list[object] = []

    async def broken_context(*args: object, **kwargs: object) -> None:
        attempts.append(args)
        raise RuntimeError("bug")

    monkeypatch.setattr(client_module, "async_tls_context", broken_context)
    await rig.client.async_start([lock()])
    await until(lambda: len(attempts) >= 3)
    (record,) = [r for r in caplog.records if r.levelno >= logging.ERROR]
    assert record.exc_info is not None


async def _gap_before_connect(rig: Rig, count: int) -> float:
    """Seconds from now until the broker has seen ``count`` CONNECTs."""
    loop = asyncio.get_running_loop()
    started = loop.time()
    await until(lambda: len(rig.broker.connects) >= count)
    return loop.time() - started


async def test_an_established_connection_resets_the_back_off(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(client_module, "RECONNECT_MIN_SECONDS", 0.1)
    monkeypatch.setattr(client_module, "RECONNECT_MAX_SECONDS", 1.6)
    rig.broker.connack_code = 5
    await rig.client.async_start([lock()])
    await until(lambda: len(rig.broker.connects) >= 3)  # waits 0.1, 0.2; next 0.4
    rig.broker.connack_code = 0
    await rig.client.async_wait_connected(5)  # the back-off stands at 0.8 s now
    await until(lambda: len(rig.client.topics) == 1)
    rig.broker.drop_connections()
    assert await _gap_before_connect(rig, 5) < 0.5


async def test_a_restart_reconnects_at_once_and_keeps_the_back_off(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(client_module, "RECONNECT_MIN_SECONDS", 0.6)
    monkeypatch.setattr(client_module, "RECONNECT_MAX_SECONDS", 4.8)
    await rig.client.async_start([lock()])
    await until(lambda: len(rig.client.topics) == 1)
    rig.broker.connack_code = 5
    await rig.client.async_update_devices([lock(), lock(LOCK2_SN, "T85L0")])
    assert await _gap_before_connect(rig, 2) < 0.4  # no back-off before it
    assert 0.4 < await _gap_before_connect(rig, 3) < 1.0  # the first wait, not doubled


def _held_disconnect(monkeypatch: pytest.MonkeyPatch, outcome: str, hold: float = 0.6) -> None:
    """Hold every DISCONNECT of an established connection ``hold`` seconds. After the first
    one closes, ``failing`` raises aiomqtt's error (an unanswered DISCONNECT), ``raising``
    another one."""
    aiomqtt = pytest.importorskip("aiomqtt")
    real = aiomqtt.Client.__aexit__
    disconnects = 0

    async def held(self: Any, *exc: Any) -> None:
        nonlocal disconnects
        disconnects += 1
        await asyncio.sleep(hold)
        await real(self, *exc)
        if disconnects == 1 and outcome == "failing":
            raise aiomqtt.MqttError("Operation timed out")
        if disconnects == 1 and outcome == "raising":
            raise RuntimeError("DISCONNECT failed")

    monkeypatch.setattr(aiomqtt.Client, "__aexit__", held)


@pytest.mark.parametrize("disconnect", ["slow", "failing", "raising"])
async def test_a_cancel_from_outside_ends_the_background_task(
    rig: Rig, monkeypatch: pytest.MonkeyPatch, disconnect: str
) -> None:
    _held_disconnect(monkeypatch, disconnect, hold=0.1)
    await rig.client.async_start([lock()])
    await rig.client.async_wait_connected(5)
    (task,) = [t for t in asyncio.all_tasks() if t.get_name() == "eufy-mqtt"]
    task.cancel()  # as an event loop shutting down does
    async with asyncio.timeout(2):
        await asyncio.wait({task})
    assert task.cancelled()


async def test_a_restart_whose_disconnect_fails_is_no_loss(
    rig: Rig, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    _held_disconnect(monkeypatch, "failing", hold=0.1)
    await rig.client.async_start([lock()])
    await rig.client.async_wait_connected(5)
    await rig.client.async_update_devices([lock(), lock(LOCK2_SN, "T85L0")])
    await until(lambda: len(rig.broker.connects) == 2)
    await rig.client.async_wait_connected(5)
    assert rig.client._losses == 0
    assert _warnings(caplog, "connection %s") == []


async def test_a_changed_device_set_reconnects_with_a_new_certificate(rig: Rig) -> None:
    await rig.client.async_start([lock()])
    await until(lambda: len(rig.broker.subscriptions) == 1)
    rig.cloud.mqtt_answer = rig.pki.register_answer(certificate_id="2" * 64)
    await rig.client.async_update_devices([lock(), lock(LOCK2_SN, "T85L0")])
    await until(lambda: len(rig.broker.connects) == 2 and len(rig.client.topics) == 2)
    assert rig.registers() == 2
    assert sorted(t for _c, t, _q in rig.broker.subscriptions[1:]) == sorted(
        [response_topic("T85D0", LOCK_SN), response_topic("T85L0", LOCK2_SN)]
    )


async def test_the_same_device_set_keeps_the_connection(rig: Rig) -> None:
    await rig.client.async_start([lock()])
    await until(lambda: len(rig.broker.subscriptions) == 1)
    await rig.client.async_update_devices([CAMERA, lock()])
    await asyncio.sleep(0.1)
    assert len(rig.broker.connects) == 1
    assert rig.registers() == 1


async def test_a_subscription_filter_keeps_every_device_in_the_certificate(rig: Rig) -> None:
    both = [lock(), lock(LOCK2_SN, "T85L0")]
    await rig.client.async_start(both, subscribe=[LOCK2_SN])
    await rig.client.async_wait_connected(5)
    await until(lambda: len(rig.client.topics) == 1)
    assert _subscribed(rig) == [(response_topic("T85L0", LOCK2_SN), 1)]
    cache = rig.eufy.cloud._cache
    assert cache.mqtt_devices("eu") == frozenset(device_key(d) for d in both)
    await rig.client.async_update_devices(both)  # the filter stays
    await asyncio.sleep(0.1)
    assert len(rig.broker.subscriptions) == 1
    assert [d.device_sn for d in rig.client.devices] == [LOCK_SN, LOCK2_SN]


async def test_a_device_set_back_after_none_connects_again(rig: Rig) -> None:
    await rig.client.async_start([lock()])
    await rig.client.async_wait_connected(5)
    await rig.client.async_update_devices([CAMERA])  # no MQTT device left: disconnects
    assert not rig.client.connected
    await asyncio.sleep(0.2)
    assert rig.broker.connected_clients == []
    assert len(rig.broker.connects) == 1
    await rig.client.async_update_devices([lock()])
    await rig.client.async_wait_connected(5)
    assert len(rig.broker.connects) == 2


async def test_a_start_after_a_stop_connects_again(rig: Rig) -> None:
    await rig.client.async_start([lock()])
    await rig.client.async_wait_connected(5)
    await rig.client.async_stop()
    await rig.client.async_start([lock()])
    await rig.client.async_wait_connected(5)
    assert len(rig.broker.connects) == 2


async def test_stop_disconnects_and_ends_its_task(rig: Rig) -> None:
    await rig.client.async_start([lock()])
    await rig.client.async_wait_connected(5)
    await rig.client.async_stop()
    await until(lambda: rig.broker.connected_clients == [])
    assert not rig.client.connected
    names = {t.get_name() for t in asyncio.all_tasks()}
    assert not any(name.startswith("eufy-mqtt") for name in names)


@pytest.mark.parametrize("case", ["start", "update-running", "update-stopped-to-empty"])
async def test_a_stop_during_a_start_or_device_update_leaves_nothing_running(
    rig: Rig, monkeypatch: pytest.MonkeyPatch, case: str
) -> None:
    call: Callable[[list[CloudDevice]], Coroutine[Any, Any, None]] = rig.client.async_start
    if case != "start":
        await rig.client.async_start([lock()])
        await rig.client.async_wait_connected(5)
        call = rig.client.async_update_devices
    if case == "update-stopped-to-empty":
        await rig.client.async_update_devices([CAMERA])
    held = hold_selection(monkeypatch, client_module)
    try:
        started = asyncio.create_task(call([lock(), lock(LOCK2_SN, "T85L0")]))
        await until(held.entered.is_set)
        stop = asyncio.create_task(rig.client.async_stop())
        await asyncio.sleep(0.05)  # the stop arrives while the call reads the list
    finally:
        held.release.set()
    async with asyncio.timeout(5):
        await started
        await stop
    await asyncio.sleep(0.3)
    assert not rig.client.connected
    assert rig.broker.connected_clients == []
    assert mqtt_tasks() == []


@pytest.mark.parametrize("queued", [True, False], ids=["queued-behind-the-stop", "after-the-stop"])
async def test_a_device_update_after_a_stop_starts_nothing(rig: Rig, queued: bool) -> None:
    await rig.client.async_start([lock()])
    await rig.client.async_wait_connected(5)
    stop = asyncio.create_task(rig.client.async_stop())
    await asyncio.sleep(0)
    assert rig.client._lifecycle.locked()  # the stop holds the lifecycle
    if not queued:
        await stop
    update = asyncio.create_task(rig.client.async_update_devices([lock(), lock(LOCK2_SN, "T85L0")]))
    async with asyncio.timeout(5):
        await stop
        await update
    await asyncio.sleep(0.3)
    assert not rig.client.connected
    assert rig.broker.connected_clients == []
    assert len(rig.broker.connects) == 1
    assert mqtt_tasks() == []


async def test_a_start_after_a_stop_follows_device_updates_again(rig: Rig) -> None:
    await rig.client.async_start([CAMERA])
    await rig.client.async_stop()
    await rig.client.async_start([CAMERA])
    await rig.client.async_update_devices([lock()])
    await rig.client.async_wait_connected(5)
    assert len(rig.broker.connects) == 1


async def test_a_stop_during_the_connect_step_leaves_no_connection(rig: Rig) -> None:
    async with SlowProxy(rig.broker.port, 0.5) as proxy:
        rig.client._port = proxy.port
        await rig.client.async_start([lock()])
        await asyncio.sleep(0.2)  # the connect step waits on the proxy
        await rig.client.async_stop()
        await until(lambda: rig.broker.connected_clients == [], 1.0)
        await asyncio.sleep(0.5)
        assert rig.broker.connected_clients == []
        assert not rig.client.connected
    names = {t.get_name() for t in asyncio.all_tasks()}
    assert not any(name.startswith("eufy-mqtt") for name in names)


async def test_a_restart_during_the_connect_step_keeps_one_connection(rig: Rig) -> None:
    async with SlowProxy(rig.broker.port, 0.5) as proxy:
        rig.client._port = proxy.port
        await rig.client.async_start([lock()])
        await asyncio.sleep(0.2)  # the connect step waits on the proxy
        await rig.client.async_update_devices([lock(), lock(LOCK2_SN, "T85L0")])
        await until(lambda: len(rig.client.topics) == 2)
        await asyncio.sleep(0.3)
        assert len(rig.broker.connected_clients) == 1
        await rig.client.async_stop()


async def test_a_stop_right_after_a_restart_during_the_connect_step_leaves_no_connection(
    rig: Rig,
) -> None:
    async with SlowProxy(rig.broker.port, 0.5) as proxy:
        rig.client._port = proxy.port
        await rig.client.async_start([lock()])
        await asyncio.sleep(0.2)  # the connect step waits on the proxy
        await rig.client.async_update_devices([lock(), lock(LOCK2_SN, "T85L0")])
        await asyncio.sleep(0.05)  # the restart waits for that step; the stop cancels again
        await rig.client.async_stop()
        await asyncio.sleep(0.6)
        assert rig.broker.connected_clients == []


async def test_a_cancel_of_a_stop_reaches_its_caller_and_the_stop_still_ends(rig: Rig) -> None:
    loop = asyncio.get_running_loop()
    async with SlowProxy(rig.broker.port, 1.0) as proxy:
        rig.client._port = proxy.port
        await rig.client.async_start([lock()])
        await asyncio.sleep(0.2)  # the connect step waits on the proxy
        started = loop.time()
        with pytest.raises(TimeoutError):
            async with asyncio.timeout(0.2):
                await rig.client.async_stop()
        assert loop.time() - started < 0.6
        await until(lambda: mqtt_tasks() == [], 3.0)
        await until(lambda: rig.broker.open_sockets == 0, 1.0)
        assert not rig.client.connected


async def test_a_start_after_a_cancelled_stop_keeps_its_connection(rig: Rig) -> None:
    async with SlowProxy(rig.broker.port, 1.0) as proxy:
        rig.client._port = proxy.port
        await rig.client.async_start([lock()])
        await asyncio.sleep(0.2)  # the connect step waits on the proxy
        (ending,) = [t for t in asyncio.all_tasks() if t.get_name() == "eufy-mqtt"]
        with pytest.raises(TimeoutError):
            async with asyncio.timeout(0.2):
                await rig.client.async_stop()
        rig.client._port = rig.broker.port
        await rig.client.async_start([lock()])
        await rig.client.async_wait_connected(5)
        async with asyncio.timeout(3):
            await asyncio.wait({ending})  # the stopped task ends after the new connect
        assert rig.client.connected
        await rig.client.async_publish(LOCK_SN, "x")
        await until(lambda: len(rig.broker.published) == 1)


@pytest.mark.parametrize("disconnect", ["slow", "failing", "raising"])
async def test_a_start_right_after_a_cancelled_stop_runs_only_its_own_connection(
    rig: Rig, monkeypatch: pytest.MonkeyPatch, disconnect: str
) -> None:
    _held_disconnect(monkeypatch, disconnect)
    await rig.client.async_start([lock()])
    await rig.client.async_wait_connected(5)
    await until(lambda: len(rig.client.topics) == 1)
    old_run = rig.client._run_task
    assert old_run is not None
    with pytest.raises(TimeoutError):
        async with asyncio.timeout(0.1):
            await rig.client.async_stop()  # the DISCONNECT is still held
    await rig.client.async_start([lock()])
    assert not rig.client.connected  # the closing connection is the stopped run's
    assert rig.client.topics == frozenset()
    await rig.client.async_wait_connected(5)
    assert len(rig.broker.connects) == 2  # the wait ended on the new connection
    await until(lambda: _subscriptions_are(rig, 2))  # the new connection subscribes
    async with asyncio.timeout(3):
        await asyncio.wait({old_run})
    assert old_run.cancelled()  # the stop's cancel is never swallowed
    await asyncio.sleep(0.3)  # a stopped run that went on would reconnect meanwhile
    assert mqtt_tasks().count("eufy-mqtt") == 1
    assert len(rig.broker.connects) == 2
    assert len(rig.broker.connected_clients) == 1
    await rig.client.async_stop()
    await until(lambda: mqtt_tasks() == [] and rig.broker.connected_clients == [], 3.0)
    assert rig.broker.open_sockets == 0


async def test_a_subscription_granted_after_a_stop_stays_with_its_connection(rig: Rig) -> None:
    granted = asyncio.Event()

    class HeldSuback:
        async def subscribe(self, topics: list[tuple[str, int]]) -> list[int]:
            await granted.wait()
            return [qos for _topic, qos in topics]

    rig.client._devices = {LOCK_SN: lock()}
    own = rig.client._subscribed  # the set of the connection the subscriber serves
    keep = rig.client._keep_subscribed(HeldSuback(), own)  # type: ignore[arg-type]
    subscriber = asyncio.create_task(keep)
    try:
        await asyncio.sleep(0.05)  # the SUBSCRIBE waits for its SUBACK
        await rig.client.async_stop()
        granted.set()
        await until(lambda: bool(own))
        assert rig.client.topics == frozenset()
    finally:
        subscriber.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await subscriber


def _left_tasks(before: set[asyncio.Task[Any]]) -> list[str]:
    """The names of the unfinished tasks started since ``before`` was taken."""
    return sorted(t.get_name() for t in asyncio.all_tasks() - before if not t.done())


@pytest.mark.parametrize("connack_delay", [None, 0.6], ids=["no-connack", "late-connack"])
async def test_a_connack_timeout_closes_the_socket(
    rig: Rig, monkeypatch: pytest.MonkeyPatch, connack_delay: float | None
) -> None:
    monkeypatch.setattr(client_module, "PUBLISH_TIMEOUT_SECONDS", 0.3)
    monkeypatch.setattr(client_module, "RECONNECT_MIN_SECONDS", 5.0)
    rig.broker.connack_delay = connack_delay
    before = asyncio.all_tasks()
    await rig.client.async_start([lock()])
    await until(lambda: len(rig.broker.connects) == 1)
    await asyncio.sleep(0.9)  # past the CONNACK wait and a late CONNACK
    assert rig.broker.open_sockets == 0
    assert rig.broker.connected_clients == []
    assert not rig.client.connected
    assert _left_tasks(before) == ["eufy-mqtt"]  # the back-off wait only


async def test_a_stop_during_a_connack_wait_that_times_out_leaves_nothing_open(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(client_module, "PUBLISH_TIMEOUT_SECONDS", 0.6)
    rig.broker.connack_delay = None
    loop = asyncio.get_running_loop()
    loop_errors: list[dict[str, Any]] = []
    loop.set_exception_handler(lambda _loop, context: loop_errors.append(context))
    try:
        before = asyncio.all_tasks()
        await rig.client.async_start([lock()])
        await until(lambda: len(rig.broker.connects) == 1)
        await rig.client.async_stop()  # waits for the CONNACK wait to end
        await asyncio.sleep(0.1)
        gc.collect()
        await asyncio.sleep(0)
    finally:
        loop.set_exception_handler(None)
    assert rig.broker.open_sockets == 0
    assert _left_tasks(before) == []
    assert loop_errors == []  # the connect's error is the client's, not the loop's


async def test_a_connect_step_left_past_the_bound_is_closed_when_it_connects(
    rig: Rig, monkeypatch: pytest.MonkeyPatch, caplog: pytest.LogCaptureFixture
) -> None:
    monkeypatch.setattr(client_module, "CONNECT_SETTLE_SECONDS", 0.3)
    async with SlowProxy(rig.broker.port, 1.0) as proxy:
        rig.client._port = proxy.port
        before = asyncio.all_tasks()
        await rig.client.async_start([lock()])
        await asyncio.sleep(0.2)  # the connect step waits on the proxy
        await rig.client.async_stop()  # returns after the bound, the step still running
        await until(lambda: len(rig.broker.connects) == 1, 3.0)
        await asyncio.sleep(0.5)
        assert rig.broker.connected_clients == []
        assert rig.broker.open_sockets == 0
        assert _left_tasks(before) == []
    assert len(_warnings(caplog, "when it ends")) == 1


async def test_a_connect_step_left_past_the_bound_is_closed_when_it_fails(
    rig: Rig, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(client_module, "CONNECT_SETTLE_SECONDS", 0.2)
    monkeypatch.setattr(client_module, "PUBLISH_TIMEOUT_SECONDS", 0.6)
    rig.broker.connack_delay = None
    loop = asyncio.get_running_loop()
    loop_errors: list[dict[str, Any]] = []
    loop.set_exception_handler(lambda _loop, context: loop_errors.append(context))
    try:
        before = asyncio.all_tasks()
        await rig.client.async_start([lock()])
        await until(lambda: len(rig.broker.connects) == 1)
        await rig.client.async_stop()  # returns after the bound, the CONNACK wait running
        assert rig.broker.open_sockets == 1
        await asyncio.sleep(0.8)  # past the CONNACK wait
        gc.collect()
        await asyncio.sleep(0)
    finally:
        loop.set_exception_handler(None)
    assert rig.broker.open_sockets == 0
    assert _left_tasks(before) == []
    assert loop_errors == []


async def test_the_paho_calls_the_close_relies_on_exist() -> None:
    aiomqtt = pytest.importorskip("aiomqtt")
    paho = pytest.importorskip("paho.mqtt.client")
    inner = aiomqtt.Client("127.0.0.1", 1)._client
    assert isinstance(inner, paho.Client)
    assert callable(inner.socket)
    assert callable(inner._sock_close)
    assert inner.socket() is None


@pytest.fixture
async def failing_close(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[list[Any]]:
    """paho's socket close raising on an open socket, as a renamed private API would.
    Yields the paho clients it left open; closes them and their keepalive tasks after."""
    paho = pytest.importorskip("paho.mqtt.client")
    monkeypatch.setattr(client_module, "_DROP_THROTTLE", LogThrottle())
    real_close = paho.Client._sock_close
    left: list[Any] = []

    def renamed(self: Any) -> None:
        if self.socket() is not None:
            left.append(self)
            raise AttributeError("_sock_close")
        real_close(self)

    monkeypatch.setattr(paho.Client, "_sock_close", renamed)
    yield left
    for inner in left:
        real_close(inner)
    for task in asyncio.all_tasks():
        if "_misc_loop" in getattr(task.get_coro(), "__qualname__", ""):
            task.cancel()


async def test_a_socket_close_that_fails_ends_the_stop_with_one_warning(
    rig: Rig,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    failing_close: list[Any],
) -> None:
    monkeypatch.setattr(client_module, "PUBLISH_TIMEOUT_SECONDS", 0.6)
    monkeypatch.setattr(client_module, "RECONNECT_MIN_SECONDS", 5.0)
    rig.broker.connack_delay = None
    await rig.client.async_start([lock()])
    await until(lambda: len(rig.broker.connects) == 1)
    loop = asyncio.get_running_loop()
    started = loop.time()
    async with asyncio.timeout(10):
        await rig.client.async_stop()  # waits for the CONNACK wait to end
    assert loop.time() - started < 3.0  # no reconnect back-off
    assert len(failing_close) == 1
    assert [r for r in caplog.records if r.levelno >= logging.ERROR] == []
    assert len(_warnings(caplog, "socket")) == 1


async def test_repeated_socket_close_failures_warn_once(
    rig: Rig,
    monkeypatch: pytest.MonkeyPatch,
    caplog: pytest.LogCaptureFixture,
    failing_close: list[Any],
) -> None:
    monkeypatch.setattr(client_module, "PUBLISH_TIMEOUT_SECONDS", 0.2)
    rig.broker.connack_delay = None
    await rig.client.async_start([lock()])
    await until(lambda: len(failing_close) >= 2)
    await rig.client.async_stop()
    assert [r for r in caplog.records if r.levelno >= logging.ERROR] == []
    assert len(_warnings(caplog, "socket")) == 1
    assert len(_warnings(caplog, "connection %s")) == 1  # the connect's own error kept


# ── the optional dependency ──────────────────────────────────────────────────


def test_the_client_without_aiomqtt_raises_naming_the_extra(
    monkeypatch: pytest.MonkeyPatch, rig: Rig
) -> None:
    monkeypatch.setitem(sys.modules, "aiomqtt", None)
    with pytest.raises(MissingDependencyError, match=r"eufy-home-security\[mqtt\]") as caught:
        EufyMqttClient(rig.eufy.cloud)
    assert caught.value.extra == "mqtt"


def test_the_package_imports_without_aiomqtt() -> None:
    code = (
        "import sys; sys.modules['aiomqtt'] = None; "
        "import eufy_home_security, eufy_home_security.mqtt, eufy_home_security.mqtt.client"
    )
    subprocess.run([sys.executable, "-c", code], check=True, timeout=60)
