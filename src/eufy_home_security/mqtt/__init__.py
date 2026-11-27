"""The eufy security MQTT transport (the broker the eufy app uses for Wi-Fi locks).

Importable without the optional ``mqtt`` extra; only the client (:mod:`.client`) needs
``aiomqtt`` and raises :class:`~..exceptions.MissingDependencyError` without it. See
docs/protocol/mqtt.md.
"""

from __future__ import annotations

from .selection import (
    LOCK_CONNECTOR_DEVICE_TYPES,
    MQTT_CATEGORIES,
    SUPPORT_PROPERTY,
    device_key,
    is_mqtt_device,
    mqtt_devices,
    supports_mqtt,
    topic_code,
    topic_product_code,
)

__all__ = [
    "LOCK_CONNECTOR_DEVICE_TYPES",
    "MQTT_CATEGORIES",
    "SUPPORT_PROPERTY",
    "device_key",
    "is_mqtt_device",
    "mqtt_devices",
    "supports_mqtt",
    "topic_code",
    "topic_product_code",
]
