"""Which devices the MQTT transport serves: the eufy app's rule, from the bundled model data."""

from __future__ import annotations

import json
from importlib import resources
from typing import Any

import pytest

from eufy_home_security.cloud.models import CloudDevice
from eufy_home_security.devices import model_settings
from eufy_home_security.devices.model_settings import bundled_codes, settings_of
from eufy_home_security.exceptions import ModelDataError, UnsupportedError
from eufy_home_security.mqtt import (
    SUPPORT_PROPERTY,
    device_key,
    is_mqtt_device,
    mqtt_devices,
    supports_mqtt,
    topic_code,
    topic_product_code,
)


def _declared_true() -> set[str]:
    """The bundled codes whose file declares the property's default true, read from the files."""
    root = resources.files("eufy_home_security.devices.data.models")
    out = set()
    for code in bundled_codes():
        settings = json.loads(root.joinpath(f"{code}.json").read_text())["settings"]
        entry = settings.get(SUPPORT_PROPERTY)
        if isinstance(entry, dict) and entry.get("default") is True:
            out.add(code)
    return out


def _device(serial: str, **entry: Any) -> CloudDevice:
    return CloudDevice.from_api({"device_sn": serial, "device_type": 0, **entry})


def test_the_selection_is_exactly_the_models_whose_data_declares_mqtt() -> None:
    declared = _declared_true()
    assert declared  # the bundled data carries the property
    assert {code for code in bundled_codes() if supports_mqtt(code)} == declared


@pytest.mark.parametrize(
    ("code", "selected"),
    [
        ("T85D0", True),  # a Wi-Fi lock: declared true
        ("T6010", True),  # not a lock, declared true: the data decides, not the kind
        ("T8L00", False),  # declared false
        ("T8030", False),  # no such property
        ("TXXXX", False),  # no model file
        (None, False),
    ],
)
def test_supports_mqtt_reads_the_declared_default(code: str | None, selected: bool) -> None:
    assert supports_mqtt(code) is selected


def test_the_property_needs_no_context() -> None:
    for code in _declared_true():
        assert settings_of(code)[SUPPORT_PROPERTY].default is True
        assert settings_of(code, standalone=True)[SUPPORT_PROPERTY].default is True


def test_a_malformed_model_file_selects_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    def broken(*_args: object, **_kwargs: object) -> object:
        raise ModelDataError("T85D0.json: broken")

    monkeypatch.setattr(model_settings, "settings_of", broken)
    assert supports_mqtt("T85D0") is False


@pytest.mark.parametrize(
    ("category", "selected"),
    [
        (None, True),  # no category: eufy_security
        ("eufy_security", True),
        ("eufy_care", True),
        ("eufy_pet", True),
        ("eufy_life", False),  # lights run their own client
        ("", False),
    ],
)
def test_only_the_security_sdk_categories_are_selected(
    category: str | None, selected: bool
) -> None:
    entry = {} if category is None else {"category": category}
    device = _device("T85D0P2000054321", device_new_pn="T85D0", **entry)
    assert is_mqtt_device(device) is selected


def test_the_product_code_comes_from_the_entry_before_the_serial() -> None:
    # A unit whose entry names its product decides by that product's data.
    by_entry = _device("T8030P2000054321", device_new_pn="T85D0")
    by_serial = _device("T85D0P2000054321")
    assert topic_product_code(by_entry) == "T85D0"
    assert is_mqtt_device(by_entry)
    assert is_mqtt_device(by_serial)
    assert not is_mqtt_device(_device("T8030P2000054321"))


def test_the_topic_code_of_a_device_without_a_product_is_unsupported() -> None:
    assert topic_code(_device("T8030P2000054321", device_new_pn="T85D0")) == "T85D0"
    nameless = _device("X0000P2000054321")
    assert topic_product_code(nameless) is None
    with pytest.raises(UnsupportedError) as caught:
        topic_code(nameless)
    assert caught.value.device_sn == "X0000P2000054321"


def test_mqtt_devices_keeps_the_order_of_the_list() -> None:
    devices = [
        _device("T85L0P2000054322"),
        _device("T8030P2000054321"),
        _device("T85D0P2000054321"),
    ]
    assert [d.device_sn for d in mqtt_devices(devices)] == ["T85L0P2000054322", "T85D0P2000054321"]


def test_the_device_key_is_the_serial_and_the_bind_time() -> None:
    assert device_key(_device("T85D0P2000054321", bind_time=1700000000)) == (
        "T85D0P2000054321-1700000000"
    )
    assert device_key(_device("T85D0P2000054321")) == "T85D0P2000054321-0"
