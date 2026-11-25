"""The MQTT client against a loopback broker: connect, subscribe, publish, answers, reconnects.

Nothing here reaches a real broker: the client connects to :class:`FakeMqttBroker` on
127.0.0.1 with the throwaway PKI the fake cloud issues.
"""

from __future__ import annotations

import asyncio
import functools
import json
import subprocess
import sys
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from typing import Any

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from eufy_home_security.client import EufySecurity
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
    CMD_UPLINK_TRANS,
    MqttMessage,
    request_topic,
    response_topic,
)
from eufy_home_security.mqtt.selection import device_key
from eufy_home_security.testing import SYNTHETIC, FakeCloud, build_eufy_security, warm_store
from eufy_home_security.testing.mqtt import FakeMqttBroker, MqttTestPki, make_mqtt_pki

LOCK_SN = "T85D0P2000054321"
LOCK2_SN = "T85L0P2000054322"
OWNER = "fedcba9876543210fedcba9876543210fedcba98"


def _lock(serial: str = LOCK_SN, pn: str = "T85D0", bind_time: int = 1700000000) -> CloudDevice:
    return CloudDevice.from_api(
        {
            "device_sn": serial,
            "device_type": 0,
            "device_new_pn": pn,
            "bind_time": bind_time,
            "member": {"admin_user_id": OWNER, "member_type": 1},
        }
    )


CAMERA = CloudDevice.from_api({"device_sn": SYNTHETIC.camera_sn, "device_type": 0})


@dataclass
class Rig:
    pki: MqttTestPki
    cloud: FakeCloud
    eufy: EufySecurity
    broker: FakeMqttBroker
    client: EufyMqttClient

    def registers(self) -> int:
        return self.cloud.calls.count("mqtt_register")


@pytest.fixture(scope="module")
def pki() -> MqttTestPki:
    return make_mqtt_pki()


@pytest.fixture(autouse=True)
def short_waits(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(client_module, "RECONNECT_MIN_SECONDS", 0.05)
    monkeypatch.setattr(client_module, "RECONNECT_MAX_SECONDS", 0.2)
    monkeypatch.setattr(client_module, "SUBSCRIBE_RETRY_SECONDS", 0.05)


@pytest.fixture
async def rig(pki: MqttTestPki) -> AsyncIterator[Rig]:
    cloud = FakeCloud(mqtt_answer=pki.register_answer())
    eufy = build_eufy_security(
        email=SYNTHETIC.email, store=warm_store(email=SYNTHETIC.email, cloud=cloud), cloud=cloud
    )
    await eufy.async_login()
    cloud.calls.clear()
    broker = FakeMqttBroker(pki)
    await broker.async_start()
    client = EufyMqttClient(eufy.cloud, port=broker.port, server_ca_pem=pki.ca_pem)
    try:
        yield Rig(pki, cloud, eufy, broker, client)
    finally:
        await client.async_stop()
        await broker.async_stop()
        await eufy.async_close()


async def _until(predicate: Callable[[], bool], timeout: float = 5.0) -> None:
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(0.01)


def _subscriptions_are(rig: Rig, count: int) -> bool:
    return len(rig.broker.subscriptions) == count


def _subscribed(rig: Rig) -> list[tuple[str, int]]:
    return [(topic, qos) for _client, topic, qos in rig.broker.subscriptions]


# ── connect and subscribe ────────────────────────────────────────────────────


async def test_it_connects_with_the_app_client_id_and_subscribes_each_mqtt_device(
    rig: Rig,
) -> None:
    await rig.client.async_start([_lock(), CAMERA, _lock(LOCK2_SN, "T85L0")])
    await rig.client.async_wait_connected(5)
    await _until(lambda: len(rig.broker.subscriptions) == 2)
    openudid = rig.eufy.cloud._install_id("eu")
    (connect,) = rig.broker.connects
    assert connect.client_id == f"android-eufy_security-{SYNTHETIC.account_id}-{openudid}"
    assert connect.keepalive == 300
    assert connect.clean_session
    assert connect.protocol_level == 4  # MQTT 3.1.1
    assert connect.client_certificate
    assert connect.username is None
    assert sorted(_subscribed(rig)) == [
        (response_topic("T85D0", LOCK_SN), 1),
        (response_topic("T85L0", LOCK2_SN), 1),
    ]
    assert rig.client.topics == frozenset(topic for topic, _ in _subscribed(rig))
    assert [d.device_sn for d in rig.client.devices] == [LOCK_SN, LOCK2_SN]
    assert rig.registers() == 1
    assert rig.cloud.mqtt_requests == [(const.mega_host("eu"), True, {})]


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
    await rig.client.async_start([_lock()])
    await _until(lambda: len(rig.broker.subscriptions) >= 2)
    assert topic not in rig.client.topics
    rig.broker.refused_topics.clear()
    await _until(lambda: topic in rig.client.topics)
    assert all(t == topic for _c, t, _q in rig.broker.subscriptions)


# ── publish ──────────────────────────────────────────────────────────────────


async def test_a_publish_sends_the_envelope_to_the_request_topic_with_qos_1(rig: Rig) -> None:
    await rig.client.async_start([_lock()])
    await rig.client.async_wait_connected(5)
    head = await rig.client.async_publish(LOCK_SN, "opaque-trans")
    await _until(lambda: len(rig.broker.published) == 1)
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


async def test_a_publish_for_another_device_is_refused_before_sending(rig: Rig) -> None:
    await rig.client.async_start([_lock()])
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
    await rig.client.async_start([_lock()])
    await _until(lambda: rig.registers() == 1)
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
    cache.set_mqtt_devices("eu", [device_key(_lock())])
    await rig.client.async_start([_lock()])
    await asyncio.sleep(0.2)
    assert rig.registers() == 0  # the cached pair was tried and did not load
    assert rig.broker.connects == []
    async with asyncio.timeout(5):
        await rig.client.async_publish(LOCK_SN, "x")
    assert rig.registers() == 1
    assert len(rig.broker.published) == 1


# ── answers ──────────────────────────────────────────────────────────────────


def _answer(head: dict[str, Any], trans: str = "answer") -> bytes:
    payload = json.dumps({"account_id": OWNER, "device_sn": LOCK_SN, "trans": trans})
    return json.dumps({"head": {"cmd": CMD_UPLINK_TRANS, **head}, "payload": payload}).encode()


async def test_a_request_gets_the_answer_with_its_sequence_from_its_device(rig: Rig) -> None:
    await rig.client.async_start([_lock(), _lock(LOCK2_SN, "T85L0")])
    await rig.client.async_wait_connected(5)
    await _until(lambda: len(rig.client.topics) == 2)
    task = asyncio.create_task(rig.client.async_request(LOCK_SN, "ask", timeout=5))
    await _until(lambda: len(rig.broker.published) == 1)
    seq = json.loads(rig.broker.published[0].payload)["head"]["msg_seq"]
    # Another device's answer and another sequence do not end the wait.
    await rig.broker.send(response_topic("T85L0", LOCK2_SN), _answer({"msg_seq": seq}, "other"))
    await rig.broker.send(response_topic("T85D0", LOCK_SN), _answer({"msg_seq": seq + 5}, "x"))
    await rig.broker.send(response_topic("T85D0", LOCK_SN), _answer({"msg_seq": seq}, "mine"))
    message = await task
    assert (message.device_sn, message.trans) == (LOCK_SN, "mine")


async def test_a_request_takes_the_callers_match(rig: Rig) -> None:
    await rig.client.async_start([_lock()])
    await rig.client.async_wait_connected(5)
    await _until(lambda: len(rig.client.topics) == 1)
    task = asyncio.create_task(
        rig.client.async_request(LOCK_SN, "ask", match=lambda m: m.trans == "by-content", timeout=5)
    )
    await _until(lambda: len(rig.broker.published) == 1)
    topic = response_topic("T85D0", LOCK_SN)
    await rig.broker.send(topic, _answer({"msg_seq": 1}, "not this"))
    await rig.broker.send(topic, _answer({"msg_seq": 99}, "by-content"))
    assert (await task).trans == "by-content"


async def test_a_request_without_an_answer_times_out_naming_the_device(rig: Rig) -> None:
    await rig.client.async_start([_lock()])
    await rig.client.async_wait_connected(5)
    with pytest.raises(DeviceTimeoutError, match=r"0\.2 s") as caught:
        await rig.client.async_request(LOCK_SN, "ask", timeout=0.2)
    assert caught.value.device_sn == LOCK_SN


async def test_stop_ends_a_pending_request_with_a_communication_error(rig: Rig) -> None:
    await rig.client.async_start([_lock()])
    await rig.client.async_wait_connected(5)
    task = asyncio.create_task(rig.client.async_request(LOCK_SN, "ask", timeout=10))
    await _until(lambda: len(rig.broker.published) == 1)
    await rig.client.async_stop()
    async with asyncio.timeout(2):
        with pytest.raises(CommunicationError, match="stopped"):
            await task


async def test_listeners_get_every_message_until_removed(rig: Rig) -> None:
    seen: list[MqttMessage] = []
    remove = rig.client.add_listener(seen.append)
    await rig.client.async_start([_lock()])
    await rig.client.async_wait_connected(5)
    await _until(lambda: len(rig.client.topics) == 1)
    topic = response_topic("T85D0", LOCK_SN)
    await rig.broker.send(topic, b"not json")  # dropped, the client stays up
    await rig.broker.send(topic, _answer({"msg_seq": 3}, "report"))
    await _until(lambda: len(seen) == 1)
    assert seen[0].trans == "report"
    remove()
    await rig.broker.send(topic, _answer({"msg_seq": 4}, "later"))
    await asyncio.sleep(0.1)
    assert len(seen) == 1
    assert rig.client.connected


# ── losses, reconnects, certificate changes ─────────────────────────────────


async def test_a_lost_connection_reconnects_and_subscribes_again(rig: Rig) -> None:
    await rig.client.async_start([_lock()])
    await _until(lambda: len(rig.broker.subscriptions) == 1)
    rig.broker.drop_connections()
    await _until(lambda: len(rig.broker.connects) == 2 and len(rig.broker.subscriptions) == 2)
    assert rig.registers() == 1  # the cached certificate serves the reconnect


async def test_three_lost_connections_drop_the_certificate_for_a_new_one(rig: Rig) -> None:
    await rig.client.async_start([_lock()])
    for count in (1, 2, 3):
        await _until(functools.partial(_subscriptions_are, rig, count))
        rig.broker.drop_connections()
    await _until(lambda: len(rig.broker.subscriptions) == 4)
    assert rig.registers() == 2
    assert rig.eufy.cloud._cache.mqtt_certificate("eu") is not None
    rig.broker.drop_connections()  # the count started again: one loss keeps the certificate
    await _until(lambda: len(rig.broker.subscriptions) == 5)
    assert rig.registers() == 2


async def test_a_refused_connect_is_retried_and_is_no_loss(rig: Rig) -> None:
    rig.broker.connack_code = 5  # not authorised
    await rig.client.async_start([_lock()])
    await _until(lambda: len(rig.broker.connects) >= 4)
    rig.broker.connack_code = 0
    await rig.client.async_wait_connected(5)
    assert rig.registers() == 1


async def test_a_changed_device_set_reconnects_with_a_new_certificate(rig: Rig) -> None:
    await rig.client.async_start([_lock()])
    await _until(lambda: len(rig.broker.subscriptions) == 1)
    rig.cloud.mqtt_answer = rig.pki.register_answer(certificate_id="2" * 64)
    await rig.client.async_update_devices([_lock(), _lock(LOCK2_SN, "T85L0")])
    await _until(lambda: len(rig.broker.connects) == 2 and len(rig.client.topics) == 2)
    assert rig.registers() == 2
    assert sorted(t for _c, t, _q in rig.broker.subscriptions[1:]) == sorted(
        [response_topic("T85D0", LOCK_SN), response_topic("T85L0", LOCK2_SN)]
    )


async def test_the_same_device_set_keeps_the_connection(rig: Rig) -> None:
    await rig.client.async_start([_lock()])
    await _until(lambda: len(rig.broker.subscriptions) == 1)
    await rig.client.async_update_devices([CAMERA, _lock()])
    await asyncio.sleep(0.1)
    assert len(rig.broker.connects) == 1
    assert rig.registers() == 1


async def test_stop_disconnects_and_ends_its_task(rig: Rig) -> None:
    await rig.client.async_start([_lock()])
    await rig.client.async_wait_connected(5)
    await rig.client.async_stop()
    await _until(lambda: rig.broker.connected_clients == [])
    assert not rig.client.connected
    names = {t.get_name() for t in asyncio.all_tasks()}
    assert not any(name.startswith("eufy-mqtt") for name in names)


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
