"""The MQTT client's waits at their real values (the client tests shorten them)."""

from __future__ import annotations

from eufy_home_security.mqtt import client


def test_the_waits_are_the_apps() -> None:
    assert (client.RECONNECT_MIN_SECONDS, client.RECONNECT_MAX_SECONDS) == (4.0, 64.0)
    assert client.KEEPALIVE_SECONDS == 300
    assert client.MQTT_PORT == 8883
    assert client.LOSSES_BEFORE_NEW_CERTIFICATE == 3
    assert client.SUBSCRIBE_RETRY_SECONDS == 5.0
    assert client.CONNECT_WAIT_SECONDS == 10.0
    assert client.PUBLISH_TIMEOUT_SECONDS < client.REQUEST_TIMEOUT_SECONDS
