"""Shared fixtures of the MQTT tests: a loopback broker, the fake cloud's certificate and
synthetic locks."""

from __future__ import annotations

import asyncio
import json
import threading
from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass, field
from types import ModuleType
from typing import Any

import pytest

from eufy_home_security.client import EufySecurity
from eufy_home_security.cloud import const
from eufy_home_security.cloud.models import REGION_KEY, CloudDevice
from eufy_home_security.mqtt import client as client_module
from eufy_home_security.mqtt.client import EufyMqttClient
from eufy_home_security.mqtt.envelope import CMD_UPLINK_TRANS
from eufy_home_security.testing import SYNTHETIC, FakeCloud, build_eufy_security, warm_store
from eufy_home_security.testing.mqtt import FakeMqttBroker, MqttTestPki, make_mqtt_pki

LOCK_SN = "T85D0P2000054321"
LOCK2_SN = "T85L0P2000054322"
OWNER = "fedcba9876543210fedcba9876543210fedcba98"


def lock(
    serial: str = LOCK_SN, pn: str = "T85D0", bind_time: int = 1700000000, region: str | None = None
) -> CloudDevice:
    return CloudDevice.from_api(
        {
            "device_sn": serial,
            "device_type": 0,
            "device_new_pn": pn,
            "bind_time": bind_time,
            "member": {"admin_user_id": OWNER, "member_type": 1},
            **({REGION_KEY: region} if region else {}),
        }
    )


def answer(head: dict[str, Any], trans: str = "answer") -> bytes:
    """A device message's body with ``head`` (``cmd`` 8 by default) and ``trans``."""
    payload = json.dumps({"account_id": OWNER, "device_sn": LOCK_SN, "trans": trans})
    return json.dumps({"head": {"cmd": CMD_UPLINK_TRANS, **head}, "payload": payload}).encode()


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


@pytest.fixture
def short_waits(monkeypatch: pytest.MonkeyPatch) -> None:
    """Reconnect and subscribe waits of a fraction of a second (see test_client_constants)."""
    monkeypatch.setattr(client_module, "RECONNECT_MIN_SECONDS", 0.05)
    monkeypatch.setattr(client_module, "RECONNECT_MAX_SECONDS", 0.2)
    monkeypatch.setattr(client_module, "SUBSCRIBE_RETRY_SECONDS", 0.05)


SCOPE = f"eu{const.SCOPE_SEPARATOR}FR"
"""An extra country's login scope: its own session, install id and certificate."""


@pytest.fixture
async def rig(pki: MqttTestPki, short_waits: None) -> AsyncIterator[Rig]:
    """The client of the default scope, ``eu``; the account also logs in to :data:`SCOPE`."""
    countries = ["EE", "FR"]
    cloud = FakeCloud(mqtt_answer=pki.register_answer(), country_regions={"EE": "eu", "FR": "eu"})
    store = warm_store(email=SYNTHETIC.email, cloud=cloud, country=countries)
    eufy = build_eufy_security(email=SYNTHETIC.email, store=store, cloud=cloud, country=countries)
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


async def until(predicate: Callable[[], bool], timeout: float = 5.0) -> None:
    async with asyncio.timeout(timeout):
        while not predicate():
            await asyncio.sleep(0.01)


def mqtt_tasks() -> list[str]:
    """The names of the MQTT client's unfinished background tasks."""
    return [
        t.get_name()
        for t in asyncio.all_tasks()
        if not t.done() and t.get_name().startswith("eufy-mqtt")
    ]


@dataclass
class HeldSelection:
    """A device selection that blocks in its worker thread until ``release`` is set."""

    entered: threading.Event = field(default_factory=threading.Event)
    release: threading.Event = field(default_factory=threading.Event)


def hold_selection(monkeypatch: pytest.MonkeyPatch, module: ModuleType) -> HeldSelection:
    """Make ``module``'s MQTT device selection wait for :attr:`HeldSelection.release`."""
    held = HeldSelection()
    real = module.mqtt_devices

    def slow(devices: list[CloudDevice]) -> list[CloudDevice]:
        held.entered.set()
        held.release.wait(10)
        return list(real(devices))

    monkeypatch.setattr(module, "mqtt_devices", slow)
    return held
