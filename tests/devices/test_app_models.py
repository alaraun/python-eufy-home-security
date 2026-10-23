"""The app model generator: product categories, constants, the device-type map."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

from eufy_home_security.devices.app_models import APP_MODELS
from eufy_home_security.devices.types import MODELS

ROOT = Path(__file__).resolve().parents[2]

# Synthetic lines in the shape of the app's model tables.
_CONSTANTS = """
    public static final String CAMERA9X = "T9101";
    public static final String CAMERA9X_PRO = "T9102";
    public static final String STATION_9 = "T9001";
    public static final String DOORBELL_9 = "T9201";
    public static final String SOLO_CAM_9201 = "T9201";
    public static final String DOORBELL_START = "T92";
    public static final String NOT_A_SERIAL = "abc";
"""
_TYPE_MAP = """
        hashMap.put(7, new String[]{"T9101", "T9102"});
        hashMap.put(Integer.valueOf(DeviceTypes.TYPE_NINE), new String[]{"T9001"});
        hashMap.put(Integer.valueOf(DeviceTypes.TYPE_UNDEFINED), new String[]{"T9201"});
"""
_TYPE_INTS = """
    public static final int TYPE_NINE = 10009;
    public static final int TYPE_DEVICE_CAMERA9_MAX = 26;
    public static final int TYPE_DEVICE_TWICE_A = 27;
    public static final int TYPE_DEVICE_TWICE_B = 27;
"""
_DEVICE_CONFIG = json.dumps(
    {
        "Base": {"parent": None},
        "Camera": {"parent": "Base"},
        "BatteryCamera": {"parent": "Camera"},
        "VideoDoorbell": {"parent": "Camera"},
        "Sensor": {"parent": "Base"},
        "SirenSensor": {"parent": "Sensor"},
        "Scale": {"parent": "Base"},
        "Tools": {"parent": "Base"},  # a category label shaped like a serial prefix
        "T9201": {"parent": "VideoDoorbell"},
        "T9301": {"parent": "BatteryCamera"},
        "T9301E": {"parent": "T9301"},
        "T9401": {"parent": "T9402"},
        "T9402": {"parent": "BatteryCamera"},
        "t9501": {"parent": "base"},
        "TONVIF": {"parent": "Camera"},
    }
)


@pytest.fixture
def gen(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """``scripts/gen_app_models.py``, registered in ``sys.modules`` for this test only."""
    spec = importlib.util.spec_from_file_location(
        "gen_app_models", ROOT / "scripts" / "gen_app_models.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    return module


@pytest.mark.parametrize(
    ("constant", "kind"),
    [
        ("STATION_NVR", "station"),
        ("KEYPAD_85A3", "keypad"),
        ("WIFI_LOCK_NO_FINGER", "lock"),
        ("BATTERY_DOORBELL_8210", "doorbell"),
        ("INDOOR_SIREN_SENSOR", "other"),
        ("DOORBELL_CHIME_8028", "other"),
        ("PANIC_SENSOR_T90P0", "sensor"),
        ("CAMERA2C_PRO", "camera"),
        ("BATTERY_SOLO_CAM_8170", "camera"),
        ("FLOODLIGHT_E_2K", "camera"),
        ("WALLLIGHT_T84A1", "camera"),
        ("TRACKER_87B0", "other"),
        ("LIGHT_8L00", "other"),
    ],
)
def test_a_constant_name_reads_as_a_kind(gen: ModuleType, constant: str, kind: str) -> None:
    assert gen.kind_of(constant) == kind


@pytest.mark.parametrize(
    ("categories", "kind"),
    [
        (("HomeBase",), "station"),
        (("VideoDoorbell", "Camera"), "doorbell"),
        (("VideoSmartLock", "Camera"), "lock"),
        (("SmartLock",), "lock"),
        (("SirenSensor", "Sensor"), "other"),
        (("MotionSensor", "Sensor"), "sensor"),
        (("IndoorCamera", "WiredCamera", "Camera"), "camera"),
        (("SmartTracker",), "other"),
        ((), None),
    ],
)
def test_a_product_category_reads_as_a_kind(
    gen: ModuleType, categories: tuple[str, ...], kind: str | None
) -> None:
    assert gen.category_kind(categories) == kind


def test_the_device_configuration_gives_each_product_its_categories(gen: ModuleType) -> None:
    assert gen.categories(_DEVICE_CONFIG) == {
        "T9201": ("VideoDoorbell", "Camera"),
        "T9301": ("BatteryCamera", "Camera"),
        "T9401": ("BatteryCamera", "Camera"),  # filed under another product
        "T9402": ("BatteryCamera", "Camera"),
        "T9501": (),
    }


def test_a_parent_cycle_is_refused(gen: ModuleType) -> None:
    cycle = json.dumps({"T9001": {"parent": "T9002"}, "T9002": {"parent": "T9001"}})
    with pytest.raises(ValueError, match="cycle"):
        gen.categories(cycle)


def test_a_device_type_named_once_gives_its_name(gen: ModuleType) -> None:
    assert gen.type_names(_TYPE_INTS) == {10009: "NINE", 26: "CAMERA9_MAX"}


def _build(gen: ModuleType, **extra: object) -> tuple[list[tuple[object, ...]], list[str]]:
    named = gen.constants(_CONSTANTS)
    types = gen.device_types(_TYPE_MAP, _TYPE_INTS)
    args = {
        "named": named,
        "types": types,
        "categorised": gen.categories(_DEVICE_CONFIG),
        "typed_names": gen.type_names(_TYPE_INTS),
    }
    args.update(extra)
    rows, conflicts = gen.build(**args)
    return list(rows), conflicts


def test_the_tables_build_one_row_per_prefix_any_of_them_names(gen: ModuleType) -> None:
    assert gen.constants(_CONSTANTS) == {
        "T9101": ["CAMERA9X"],
        "T9102": ["CAMERA9X_PRO"],
        "T9001": ["STATION_9"],
        "T9201": ["DOORBELL_9", "SOLO_CAM_9201"],
    }
    assert gen.device_types(_TYPE_MAP, _TYPE_INTS) == {"T9101": 7, "T9102": 7, "T9001": 10009}
    rows, conflicts = _build(gen)
    assert rows == [
        ("T9001", "STATION_9", "station", 10009, ()),
        ("T9101", "CAMERA9X", "camera", 7, ()),
        ("T9102", "CAMERA9X_PRO", "camera", 7, ()),
        ("T9201", "DOORBELL_9", "doorbell", None, ("VideoDoorbell", "Camera")),
        ("T9301", None, "camera", None, ("BatteryCamera", "Camera")),
        ("T9401", None, "camera", None, ("BatteryCamera", "Camera")),
        ("T9402", None, "camera", None, ("BatteryCamera", "Camera")),
        ("T9501", None, "other", None, ()),
    ]
    assert conflicts == []


def test_without_a_category_mixed_constant_kinds_are_left_out(gen: ModuleType) -> None:
    rows, conflicts = _build(gen, categorised={})
    assert "T9201" not in {row[0] for row in rows}
    assert conflicts == ["T9201: DOORBELL_9 (doorbell), SOLO_CAM_9201 (camera)"]


def test_the_category_overrides_the_constants_name(gen: ModuleType) -> None:
    rows, _ = _build(gen, categorised={"T9101": ("VideoDoorbell", "Camera")})
    assert ("T9101", "CAMERA9X", "doorbell", 7, ("VideoDoorbell", "Camera")) in rows


def test_a_keypad_under_the_generic_sensor_category_stays_a_keypad(gen: ModuleType) -> None:
    named = {"T9601": ["KEYPAD_9"], "T9602": ["SENSOR_9"]}
    categorised = {"T9601": ("Sensor",), "T9602": ("Sensor",)}
    rows, _ = _build(gen, named=named, types={}, categorised=categorised)
    assert rows == [
        ("T9601", "KEYPAD_9", "keypad", None, ("Sensor",)),
        ("T9602", "SENSOR_9", "sensor", None, ("Sensor",)),
    ]


def test_a_mapped_prefix_without_a_constant_takes_its_device_types_name(gen: ModuleType) -> None:
    rows, _ = _build(gen, named={}, types={"T9701": 26, "T9702": 27}, categorised={})
    assert rows == [
        ("T9701", "CAMERA9_MAX", "camera", 26, ()),
        ("T9702", None, "other", 27, ()),  # type 27 has two names: none is taken
    ]


def test_the_constant_reading_as_the_kind_names_the_row(gen: ModuleType) -> None:
    named = {"T9801": ["SOLO_CAM_9801"], "T9802": ["CAM_9802", "DOORBELL_LONG_9802"]}
    categorised = {"T9801": ("VideoDoorbell",), "T9802": ("VideoDoorbell",)}
    typed = {26: "DOORBELL_9801"}
    rows, _ = _build(
        gen, named=named, types={"T9801": 26}, categorised=categorised, typed_names=typed
    )
    assert [row[1] for row in rows] == ["DOORBELL_9801", "DOORBELL_LONG_9802"]


def test_a_prefix_mapped_to_two_device_types_is_refused(gen: ModuleType) -> None:
    twice = _TYPE_MAP + '        hashMap.put(8, new String[]{"T9101"});\n'
    with pytest.raises(ValueError, match="T9101"):
        gen.device_types(twice, _TYPE_INTS)


def test_the_rendered_module_holds_the_rows(gen: ModuleType, tmp_path: Path) -> None:
    rows = [
        ("T9001", "STATION_9", "station", 10009, ()),
        ("T9101", None, "camera", None, ("Camera",)),
        ("T9201", "DOORBELL_9", "doorbell", 5, ("VideoDoorbell", "Camera")),
    ]
    namespace: dict[str, object] = {}
    exec(compile(gen.render(rows, "9.9.9"), "app_models", "exec"), namespace)  # noqa: S102
    assert (namespace["APP_VERSION"], namespace["APP_MODELS"]) == ("9.9.9", tuple(rows))


def test_the_committed_module_is_in_the_catalogue() -> None:
    assert len(APP_MODELS) > 150
    assert {prefix for prefix, *_ in APP_MODELS} <= set(MODELS)
    assert len({prefix for prefix, *_ in APP_MODELS}) == len(APP_MODELS)


def test_check_without_the_app_tables_exits_2(gen: ModuleType, tmp_path: Path) -> None:
    missing = str(tmp_path / "none.java")
    args = ["--device-config", missing, "--constants", missing]
    args += ["--type-map", missing, "--device-types", missing]
    assert gen.main([*args, "--app-version", "9.9.9", "--check"]) == 2


def _inputs(
    tmp_path: Path,
    constants: str = _CONSTANTS,
    config: str = _DEVICE_CONFIG,
    type_map: str = _TYPE_MAP,
) -> list[str]:
    files = {
        "device-config": config,
        "constants": constants,
        "type-map": type_map,
        "device-types": _TYPE_INTS,
    }
    args: list[str] = []
    for flag, text in files.items():
        path = tmp_path / f"{flag}.java"
        path.write_text(text, encoding="utf-8")
        args += [f"--{flag}", str(path)]
    return args


def test_the_app_version_is_required(gen: ModuleType, tmp_path: Path) -> None:
    with pytest.raises(SystemExit) as exc:
        gen.main([*_inputs(tmp_path), "--out", str(tmp_path / "out.py")])
    assert exc.value.code == 2
    assert not (tmp_path / "out.py").exists()


def test_no_rows_are_refused_and_nothing_is_written(gen: ModuleType, tmp_path: Path) -> None:
    out = tmp_path / "out.py"
    inputs = _inputs(tmp_path, constants="", config="{}", type_map="")
    args = [*inputs, "--out", str(out), "--app-version", "9.9.9"]
    assert gen.main(args) == 1
    assert not out.exists()


def test_a_shrinking_catalogue_needs_allow_shrink(gen: ModuleType, tmp_path: Path) -> None:
    out = tmp_path / "out.py"
    rows = [(f"T9{n:03d}", f"CAMERA_{n}", "camera", None, ()) for n in range(20)]
    before = gen.render(rows, "9.9.8")
    out.write_text(before, encoding="utf-8")
    args = [*_inputs(tmp_path), "--out", str(out), "--app-version", "9.9.9"]
    assert gen.main(args) == 1  # 8 rows against 20
    assert out.read_text(encoding="utf-8") == before
    assert gen.main([*args, "--allow-shrink"]) == 0
    assert out.read_text(encoding="utf-8").count('    ("T') == 8


def test_a_drop_within_the_margin_is_written(gen: ModuleType, tmp_path: Path) -> None:
    out = tmp_path / "out.py"
    gen.main([*_inputs(tmp_path), "--out", str(out), "--app-version", "9.9.8"])
    # the same rows again are within the margin
    assert gen.main([*_inputs(tmp_path), "--out", str(out), "--app-version", "9.9.9"]) == 0
    assert 'APP_VERSION: Final = "9.9.9"' in out.read_text(encoding="utf-8")
