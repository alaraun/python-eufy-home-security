from __future__ import annotations

from typing import Final

import pytest

from eufy_home_security.devices import types
from eufy_home_security.devices._live_open_data import LIVE_OPEN
from eufy_home_security.devices._model_names_data import MODEL_NAMES
from eufy_home_security.devices.app_models import APP_MODELS, APP_VERSION
from eufy_home_security.devices.model_settings import bundled_codes
from eufy_home_security.devices.support import Support
from eufy_home_security.devices.types import (
    MODELS,
    ON_DEMAND_EVIDENCE,
    SERIAL_PRODUCT_CODES,
    DeviceKind,
    connects_on_demand,
    model_for_serial,
    product_name,
    serial_prefix,
)
from eufy_home_security.testing import SYNTHETIC


def test_registry_keys_match_models() -> None:
    assert all(key == model.model for key, model in MODELS.items())


def test_only_live_proven_models_are_verified() -> None:
    verified = {m.model for m in MODELS.values() if m.evidence.support is Support.VERIFIED}
    assert verified == {"T8030", "T8160"}


def test_evidence_has_a_source() -> None:
    assert all(m.evidence.source for m in MODELS.values())


@pytest.mark.parametrize(
    ("serial", "model", "kind"),
    [
        ("T8030P0000000000", "T8030", DeviceKind.STATION),
        ("T8160P0000000000", "T8160", DeviceKind.CAMERA),
        (" t8161p0000000000", "T8161", DeviceKind.CAMERA),
        ("T8410P0000000000", "T8410", DeviceKind.CAMERA),
    ],
)
def test_model_for_serial(serial: str, model: str, kind: DeviceKind) -> None:
    found = model_for_serial(serial)
    assert found is not None
    assert (found.model, found.kind) == (model, kind)


@pytest.mark.parametrize("serial", ["", "T80", "T9999P0000000000"])
def test_model_for_serial_unknown(serial: str) -> None:
    assert model_for_serial(serial) is None


@pytest.mark.parametrize(
    ("serial", "prefix"),
    [(" t8160p0000000000", "T8160"), ("T9999P0000000000", "T9999"), ("T80", None), ("", None)],
)
def test_serial_prefix(serial: str, prefix: str | None) -> None:
    assert serial_prefix(serial) == prefix


def test_model_for_serial_fixture(station_sn: str) -> None:
    found = model_for_serial(station_sn)
    assert found is not None
    assert found.model == "T8030"


def test_cloud_device_type_homebase3() -> None:
    assert MODELS["T8030"].cloud_device_type == 18


@pytest.mark.parametrize("model", ["T8001", "T8002", "T8010", "T8020"])
def test_the_first_homebases_share_device_type_0(model: str) -> None:
    assert MODELS[model].cloud_device_type == 0


def test_every_model_but_the_live_proven_is_declared_from_the_app() -> None:
    graded = {m.evidence.support for m in MODELS.values() if m.model not in {"T8030", "T8160"}}
    assert graded == {Support.DECLARED}
    declared = [m for m in MODELS.values() if m.evidence.support is Support.DECLARED]
    assert all("eufy app" in m.evidence.source for m in declared)


@pytest.mark.parametrize(
    ("model", "kind", "device_type", "name"),
    [
        ("T8113", DeviceKind.CAMERA, 8, "eufyCam 2C"),
        ("T8142", DeviceKind.CAMERA, 15, "eufyCam 2C Pro"),
        ("T8123", DeviceKind.CAMERA, 61, "SoloCam L40"),
        ("T8960", DeviceKind.KEYPAD, 11, "Keypad"),
        ("T8200", DeviceKind.DOORBELL, 5, "Video Doorbell 2K"),
        ("T8500", DeviceKind.LOCK, 52, "Smart Lock C100"),
        ("T90R0", DeviceKind.OTHER, None, "eufy Indoor Siren E20"),
        ("T90K0", DeviceKind.SENSOR, None, "eufy Key Fob E10"),
        ("T87B0", DeviceKind.OTHER, None, "Tracker 87B0"),
    ],
)
def test_the_apps_models_are_catalogued(
    model: str, kind: DeviceKind, device_type: int | None, name: str
) -> None:
    found = MODELS[model]
    assert (found.kind, found.cloud_device_type, found.name) == (kind, device_type, name)
    assert found.evidence.support is Support.DECLARED
    assert found.evidence.source.startswith(f"eufy app {APP_VERSION} model list: ")


def _serial(prefix: str) -> str:
    return prefix + SYNTHETIC.camera_sn[5:]


@pytest.mark.parametrize(
    ("prefix", "kind", "categories"),
    [
        ("T8162", DeviceKind.CAMERA, ("BatteryCamera", "Camera")),
        ("T8144", DeviceKind.CAMERA, ("BatteryCamera", "Camera")),
        ("T8215", DeviceKind.DOORBELL, ("VideoDoorbell", "Camera")),
        ("T8452", DeviceKind.CAMERA, ("GarageCamera", "Camera")),
        ("T8453", DeviceKind.CAMERA, ("GarageCamera", "Camera")),
        ("T8532", DeviceKind.LOCK, ("VideoSmartLock", "Camera")),
        ("T85M0", DeviceKind.LOCK, ("VideoSmartLock", "Camera")),
        ("T85M1", DeviceKind.LOCK, ("VideoSmartLock", "Camera")),
        ("T87A0", DeviceKind.OTHER, ()),
    ],
)
def test_a_model_takes_its_kind_from_the_apps_product_category(
    prefix: str, kind: DeviceKind, categories: tuple[str, ...]
) -> None:
    found = model_for_serial(_serial(prefix))
    assert found is not None
    assert (found.model, found.kind, found.categories) == (prefix, kind, categories)
    assert found.evidence.support is Support.DECLARED


def test_a_model_without_a_constant_is_sourced_by_its_device_type() -> None:
    assert MODELS["T8162"].cloud_device_type == 26
    assert (
        MODELS["T8162"].evidence.source
        == f"eufy app {APP_VERSION} model list: CAMERA3_PRO; device-type map (26)"
    )
    assert (
        MODELS["T8452"].evidence.source
        == f"eufy app {APP_VERSION} model list; device-type map (132)"
    )
    assert MODELS["T87A0"].evidence.note == "no app product category or constant"


def test_the_evidence_names_the_category_or_the_name_rule() -> None:
    assert MODELS["T8217"].evidence.note == "app product category: VideoDoorbell > Camera"
    assert MODELS["T8020"].evidence.note == (
        "no app product category; kind read from the constant's name"
    )


@pytest.mark.parametrize(
    ("model", "kind"),
    [
        ("T8217", DeviceKind.DOORBELL),  # the app's battery doorbell, a SoloCam by name
        ("T8352", DeviceKind.CAMERA),
        ("T8354", DeviceKind.CAMERA),
        ("T8790", DeviceKind.CAMERA),
        ("T8960", DeviceKind.KEYPAD),  # filed under the generic sensor category
        ("T8970", DeviceKind.OTHER),  # a siren sensor
        ("T8020", DeviceKind.STATION),  # under no category: kind by name
    ],
)
def test_the_apps_category_decides_where_it_differs_from_the_name(
    model: str, kind: DeviceKind
) -> None:
    assert MODELS[model].kind is kind


@pytest.mark.parametrize(
    ("model", "has_camera"),
    [
        ("T8160", True),
        ("T8532", True),  # a video lock: the camera category, lock kind
        ("T8101", True),  # under no category: camera kind
        ("T8212", True),  # under no category: doorbell kind
        ("T8910", False),
        ("T8960", False),  # a keypad under the generic sensor category
        ("T8520", False),  # a lock without a camera
        ("T8030", False),
    ],
)
def test_a_model_has_a_camera_by_the_apps_category_or_its_kind(
    model: str, has_camera: bool
) -> None:
    assert MODELS[model].has_camera is has_camera


def test_a_hand_written_entry_carries_the_apps_categories_and_kind() -> None:
    generated = {row[0]: row for row in APP_MODELS}
    app = f"eufy app {APP_VERSION}"
    hand = [m for m in MODELS.values() if not m.evidence.source.startswith(app)]
    assert {m.model for m in hand} >= {"T8030", "T8160", "T8410"}
    for model in hand:
        _prefix, _constant, kind, _type, categories = generated[model.model]
        assert (model.kind, model.categories) == (DeviceKind(kind), categories)


def test_every_bundled_or_live_open_product_is_catalogued() -> None:
    codes = set(bundled_codes()) | set(LIVE_OPEN)
    assert {code for code in codes if model_for_serial(_serial(code[:5])) is None} == set()


def test_a_hand_written_entry_wins_over_the_generated_one() -> None:
    assert MODELS["T8030"].evidence.support is Support.VERIFIED
    assert MODELS["T8910"].evidence.source.endswith("MOTION_SENSOR; eufy app device-type map (10)")


def test_connects_on_demand_on_demand_prefixes() -> None:
    assert connects_on_demand("T8170P0000000000") is True
    assert connects_on_demand(" t8170p0000000000") is True
    assert connects_on_demand("T8030P0000000000") is False
    assert connects_on_demand("T8160P0000000000") is False
    assert connects_on_demand("T817") is False


def test_t8170_in_models() -> None:
    assert "T8170" in MODELS
    model = MODELS["T8170"]
    assert model.kind == DeviceKind.CAMERA
    assert model.cloud_device_type == 48
    assert model.evidence.support is Support.DECLARED
    assert ON_DEMAND_EVIDENCE.support is Support.DECLARED


def test_the_t8410_is_the_apps_pan_tilt_indoor_cam_of_type_31() -> None:
    found = model_for_serial("T8410P0000000000")
    assert found is not None
    assert found.name == "Indoor Cam Pan&Tilt 2K"
    assert found.cloud_device_type == 31
    assert found.evidence.support is Support.DECLARED
    assert "INDOOR_CAMERA_PT" in found.evidence.source
    assert not connects_on_demand("T8410P0000000000")


NO_BUNDLED_SETTINGS: Final[dict[str, str]] = {}
"""Product codes a serial rule gives that ship no settings file, each with the reason."""


def test_every_product_code_a_serial_rule_gives_has_a_bundled_settings_file() -> None:
    codes = {code for _start, _sixth, code in SERIAL_PRODUCT_CODES}
    assert codes - set(bundled_codes()) - NO_BUNDLED_SETTINGS.keys() == set()


def test_no_exception_for_a_bundled_or_ruleless_product_code() -> None:
    codes = {code for _start, _sixth, code in SERIAL_PRODUCT_CODES}
    assert NO_BUNDLED_SETTINGS.keys() <= codes - set(bundled_codes())


def _unit(prefix: str, **chars: str) -> str:
    """A synthetic serial of ``prefix``: ``c6="5"`` puts ``5`` at index 6, ``Z`` elsewhere."""
    serial = list(prefix + "Z" * 11)
    for key, text in chars.items():
        pos = int(key[1:])
        serial[pos : pos + len(text)] = text
    return "".join(serial)


def test_a_model_is_named_as_the_app_names_its_product() -> None:
    """T817L and T814X are named by the generated names alone, not by library code."""
    assert MODELS["T817L"].name == "eufyCam C31"
    assert MODELS["T814X"].name == "eufyCam C37"


def test_a_hand_written_entry_takes_the_apps_product_name() -> None:
    assert MODELS["T8030"].name == "HomeBase 3"
    assert MODELS["T8160"].name == "eufyCam 3"


@pytest.mark.parametrize(
    ("model", "name"),
    [
        ("T7200", "Dogcam"),  # the app's constant DOGCAM
        ("T8170", "Battery Solo Cam 8170"),  # the names hold only serial rules for it
        ("T1206", "T1206"),  # no name and no constant
    ],
)
def test_a_model_the_apps_names_lack_is_named_by_its_constant_or_code(
    model: str, name: str
) -> None:
    assert MODELS[model].name == name


@pytest.mark.parametrize(
    ("serial", "code", "name"),
    [
        (_unit("T814X"), None, "eufyCam C37"),
        (_unit("T814X", c6="5"), None, "eufyCam C36"),
        (_unit("T814X", c6="9"), None, "eufyCam C37 4K Edition"),
        (" " + _unit("t814x", c6="6").lower(), None, "eufyCam C36 4K Edition"),
        (" " + _unit("T8134", c7="A").lower(), None, "eufy-C323WB-O"),
        (_unit("T8134", c7="A"), None, "eufy-C323WB-O"),
        (_unit("T8134", c7="A", c8="2609"), None, "SoloCam C10"),  # first rule wins
        (_unit("T8170", c6="3", c7="0"), None, "SoloCam S340"),
        (_unit("T8170", c6="3", c7="5"), None, "Battery Solo Cam 8170"),  # all must hold
        (_unit("T8124"), None, "SoloCam S40"),
        (_unit("T8191"), None, "SoloCam E60"),  # named by the app, not catalogued
        (_unit("T7200"), None, "Dogcam"),
        ("T814X", None, "eufyCam C37"),  # shorter than any rule's position
        (_unit("T9999"), None, None),
        ("T80", None, None),
        ("", None, None),
    ],
)
def test_product_name_is_the_name_the_app_shows_for_the_unit(
    serial: str, code: str | None, name: str | None
) -> None:
    assert product_name(serial, code) == name


@pytest.mark.parametrize(
    ("code", "name"),
    [
        ("T8124R", "Product R"),
        (" t8124r", "Product R"),
        ("T8410C", "Product"),  # another prefix's code
        ("T8124X", "Product"),  # a code without names
        (None, "Product"),
    ],
)
def test_product_name_takes_the_units_product_code_row(
    monkeypatch: pytest.MonkeyPatch, code: str | None, name: str
) -> None:
    """The unit's product code, where it shares the serial's prefix, picks its own row."""
    names = dict(MODEL_NAMES)
    names["T8124"] = ("Product", (), "T8124")
    names["T8124R"] = ("Product R", (), "T8124R")
    monkeypatch.setattr(types, "MODEL_NAMES", names)
    assert product_name(_unit("T8124"), code) == name
