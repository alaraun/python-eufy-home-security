"""``eufy-security mqtt``: list the MQTT devices; ``--connect`` checks the broker, never publishes."""

from __future__ import annotations

from collections.abc import AsyncIterator, Callable
from dataclasses import dataclass
from typing import Any

import pytest

from eufy_home_security.cli import commands
from eufy_home_security.cli.commands import Context
from eufy_home_security.cli.config import EXIT_ERROR, UsageError, parse_args
from eufy_home_security.client import EufySecurity
from eufy_home_security.cloud.api import EufyCloudApi
from eufy_home_security.mqtt import client as client_module
from eufy_home_security.mqtt.client import EufyMqttClient
from eufy_home_security.mqtt.envelope import response_topic
from eufy_home_security.testing import (
    SYNTHETIC,
    FakeCloud,
    build_eufy_security,
    camera_device,
    station_device,
    warm_store,
)
from eufy_home_security.testing.mqtt import FakeMqttBroker, MqttTestPki, make_mqtt_pki

LOCK_SN = "T85D0P2000054321"
LOCK = {"device_sn": LOCK_SN, "device_type": 0, "device_name": "Door", "device_new_pn": "T85D0"}


@dataclass
class Setup:
    cloud: FakeCloud
    broker: FakeMqttBroker
    run: Callable[..., Any]


@pytest.fixture(scope="module")
def pki() -> MqttTestPki:
    return make_mqtt_pki()


@pytest.fixture
async def setup(
    pki: MqttTestPki, monkeypatch: pytest.MonkeyPatch, request: pytest.FixtureRequest
) -> AsyncIterator[Setup]:
    monkeypatch.setattr(client_module, "RECONNECT_MIN_SECONDS", 0.05)
    devices = getattr(request, "param", [station_device(), camera_device(), LOCK])
    cloud = FakeCloud(devices=list(devices), mqtt_answer=pki.register_answer())
    store = warm_store(email=SYNTHETIC.email, cloud=cloud)
    broker = FakeMqttBroker(pki)

    async def open_account(ctx: Context, *, station_sn: str | None = None) -> EufySecurity:
        return build_eufy_security(email=SYNTHETIC.email, store=store, cloud=cloud)

    def mqtt_client(cloud_api: EufyCloudApi, region: str | None) -> EufyMqttClient:
        return EufyMqttClient(cloud_api, region=region, port=broker.port, server_ca_pem=pki.ca_pem)

    monkeypatch.setattr(commands, "open_account", open_account)
    monkeypatch.setattr(commands, "mqtt_client", mqtt_client)

    async def run(*argv: str, options: tuple[str, ...] = ()) -> int:
        args = parse_args([*options, "mqtt", *argv])
        async with Context(args, env={}) as ctx:
            return await commands.COMMANDS["mqtt"](ctx)

    async with broker:
        yield Setup(cloud, broker, run)


async def test_the_default_is_a_dry_listing(
    setup: Setup, capsys: pytest.CaptureFixture[str]
) -> None:
    assert await setup.run() == 0
    out = capsys.readouterr().out
    assert LOCK_SN in out
    assert response_topic("T85D0", LOCK_SN) in out
    assert SYNTHETIC.camera_sn not in out
    assert "dry run" in out.lower()
    assert "mqtt_register" not in setup.cloud.calls
    assert setup.broker.connects == []


async def test_connect_subscribes_and_never_publishes(
    setup: Setup, capsys: pytest.CaptureFixture[str]
) -> None:
    assert await setup.run("check", "--connect", "--seconds", "0.2") == 0
    out = capsys.readouterr().out
    assert "connected" in out.lower()
    assert "1 of 1" in out
    assert [t for _c, t, _q in setup.broker.subscriptions] == [response_topic("T85D0", LOCK_SN)]
    assert setup.broker.published == []
    assert setup.broker.connected_clients == []  # disconnected at the end
    assert SYNTHETIC.account_id not in out  # the client id is not printed


async def test_a_refused_topic_fails_the_check(
    setup: Setup, capsys: pytest.CaptureFixture[str]
) -> None:
    setup.broker.refused_topics.add(response_topic("T85D0", LOCK_SN))
    assert await setup.run("--connect", "--seconds", "0.2") == EXIT_ERROR
    assert "0 of 1" in capsys.readouterr().out
    assert setup.broker.published == []


async def test_the_device_filter_names_only_mqtt_devices(setup: Setup) -> None:
    with pytest.raises(UsageError, match="no MQTT device"):
        await setup.run("--device", SYNTHETIC.camera_sn)
    assert await setup.run("--device", LOCK_SN.lower()) == 0


@pytest.mark.parametrize("setup", [[station_device(), camera_device()]], indirect=True)
async def test_an_account_without_mqtt_devices_connects_only_when_asked(
    setup: Setup, capsys: pytest.CaptureFixture[str]
) -> None:
    with pytest.raises(UsageError, match="--connect-empty"):
        await setup.run("--connect", "--seconds", "0.1")
    assert setup.broker.connects == []
    assert await setup.run("--connect", "--connect-empty", "--seconds", "0.1") == 0
    assert len(setup.broker.connects) == 1
    assert setup.broker.subscriptions == []
    assert setup.broker.published == []
    assert "0 of 0" in capsys.readouterr().out


async def test_redacted_serials_stay_redacted_in_the_topics(
    setup: Setup, capsys: pytest.CaptureFixture[str]
) -> None:
    assert await setup.run(options=("--redact-serials",)) == 0
    out = capsys.readouterr().out
    assert LOCK_SN not in out
    assert "cmd/eufy_security/T85D0/" in out
