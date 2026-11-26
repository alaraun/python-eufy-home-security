"""Which devices the MQTT transport serves, as the eufy app decides it.

The app runs two connectors on one MQTT connection, and a device is an MQTT device when
either selects it; its device-list entry must belong to one of the app families the security
SDK serves (:data:`MQTT_CATEGORIES`, an entry without a category is ``eufy_security``):

- the current one: its model's thing description declares :data:`SUPPORT_PROPERTY` true
  (declared, eufy app), read from the bundled model data (``devices/data/models``);
- the lock connector (legacy, still live for locks): its cloud ``device_type`` is one of
  :data:`LOCK_CONNECTOR_DEVICE_TYPES`, generated from the app's own list.

One rule serves the account's selection and the lock control
(:func:`~.locks.mqtt_lock_control`, :meth:`~..station.Station.lock_control`): a lock is
writable over MQTT only when it is selected here. See docs/protocol/mqtt.md.
"""

from __future__ import annotations

import logging
from collections.abc import Iterable
from typing import Final

from .._logging import redact_serial
from ..cloud.models import CloudDevice
from ..devices import model_settings
from ..devices._lock_routes_data import MQTT_DEVICE_TYPES
from ..exceptions import ModelDataError, UnsupportedError

_LOGGER = logging.getLogger(__name__)

SUPPORT_PROPERTY: Final = "is_support_mqtt"
"""The thing-description property that makes a model an MQTT device."""

MQTT_CATEGORIES: Final = frozenset({"eufy_security", "eufy_care", "eufy_pet"})
"""The device-list categories whose devices the app's security SDK connects over MQTT;
``eufy_life`` devices (lights) have their own client."""


LOCK_CONNECTOR_DEVICE_TYPES: Final[frozenset[int]] = MQTT_DEVICE_TYPES
"""The cloud device types the app's lock MQTT connector (legacy, still live) serves,
generated from the app's lock configuration (``scripts/gen_lock_routes.py``)."""


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


def topic_code(device: CloudDevice) -> str:
    """The product code an MQTT device's topics name (:func:`topic_product_code`), which
    every device :func:`is_mqtt_device` selects has; :class:`UnsupportedError` without one."""
    code = topic_product_code(device)
    if code is None:
        raise UnsupportedError(
            f"{redact_serial(device.device_sn)} names no product: no MQTT topic",
            device_sn=device.device_sn,
        )
    return code


def is_mqtt_device(device: CloudDevice) -> bool:
    """Whether the eufy app connects ``device`` over MQTT (see the module docstring). Reads
    the model's bundled data, which the client loads at discovery: called on the event loop
    only for a listed device."""
    if device.category not in MQTT_CATEGORIES:
        return False
    selected = device.device_type in LOCK_CONNECTOR_DEVICE_TYPES or supports_mqtt(
        topic_product_code(device)
    )
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
