"""Which devices the MQTT transport serves, as the eufy app decides it.

A device is an MQTT device when its device-list entry belongs to one of the app families the
security SDK serves (:data:`MQTT_CATEGORIES`, an entry without a category is
``eufy_security``) and its model's thing description declares :data:`SUPPORT_PROPERTY` true
(declared, eufy app). The property is read from the bundled model data
(``devices/data/models``), never from a list of device types. See docs/protocol/mqtt.md.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Final

from .._logging import redact_serial
from ..cloud.models import CloudDevice
from ..devices import model_settings
from ..exceptions import ModelDataError

_LOGGER = logging.getLogger(__name__)

SUPPORT_PROPERTY: Final = "is_support_mqtt"
"""The thing-description property that makes a model an MQTT device."""

MQTT_CATEGORIES: Final = frozenset({"eufy_security", "eufy_care", "eufy_pet"})
"""The device-list categories whose devices the app's security SDK connects over MQTT;
``eufy_life`` devices (lights) have their own client."""


def supports_mqtt(product_code: str | None) -> bool:
    """Whether the model ``product_code`` declares :data:`SUPPORT_PROPERTY` true in its
    bundled settings; False without a code, a file or the property, and for a malformed
    file. Reads package data on the first call per model: call it off the event loop."""
    if not product_code:
        return False
    try:
        setting = model_settings.settings_of(product_code).get(SUPPORT_PROPERTY)
    except ModelDataError as err:
        _LOGGER.debug("%s: settings file malformed (%s): not an MQTT device", product_code, err)
        return False
    return setting is not None and setting.default is True


def topic_product_code(device: CloudDevice) -> str | None:
    """The product code of ``device`` as its MQTT topics name it: the entry's
    ``device_new_pn``, else the product its serial names."""
    return model_settings.product_code_of(device.raw.get("device_new_pn"), device.device_sn)


def is_mqtt_device(device: CloudDevice) -> bool:
    """Whether the eufy app connects ``device`` over MQTT (see the module docstring)."""
    if device.category not in MQTT_CATEGORIES:
        return False
    selected = supports_mqtt(topic_product_code(device))
    if selected:
        _LOGGER.debug("%s is an MQTT device", redact_serial(device.device_sn))
    return selected


def mqtt_devices(devices: Iterable[CloudDevice]) -> list[CloudDevice]:
    """The MQTT devices of ``devices``, in their order (:func:`is_mqtt_device`)."""
    return [device for device in devices if is_mqtt_device(device)]


def device_key(device: CloudDevice) -> str:
    """``<serial>-<bind time>``: the key of ``device`` in the MQTT device set whose change
    asks for a new certificate."""
    return f"{device.device_sn}-{device.bind_time}"
