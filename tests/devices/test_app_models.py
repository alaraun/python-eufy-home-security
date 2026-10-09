"""The app model generator: constants, the device-type map, kinds by name."""

from __future__ import annotations

import importlib.util
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
_TYPE_INTS = "    public static final int TYPE_NINE = 10009;\n"


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


def test_the_tables_build_one_row_per_prefix_and_leave_out_mixed_kinds(gen: ModuleType) -> None:
    named = gen.constants(_CONSTANTS)
    assert named == {
        "T9101": ["CAMERA9X"],
        "T9102": ["CAMERA9X_PRO"],
        "T9001": ["STATION_9"],
        "T9201": ["DOORBELL_9", "SOLO_CAM_9201"],
    }
    types = gen.device_types(_TYPE_MAP, _TYPE_INTS)
    assert types == {"T9101": 7, "T9102": 7, "T9001": 10009}
    rows, conflicts = gen.build(named, types)
    assert rows == [
        ("T9001", "STATION_9", "station", 10009),
        ("T9101", "CAMERA9X", "camera", 7),
        ("T9102", "CAMERA9X_PRO", "camera", 7),
    ]
    assert conflicts == ["T9201: DOORBELL_9 (doorbell), SOLO_CAM_9201 (camera)"]


def test_a_prefix_mapped_to_two_device_types_is_refused(gen: ModuleType) -> None:
    twice = _TYPE_MAP + '        hashMap.put(8, new String[]{"T9101"});\n'
    with pytest.raises(ValueError, match="T9101"):
        gen.device_types(twice, _TYPE_INTS)


def test_the_rendered_module_holds_the_rows(gen: ModuleType, tmp_path: Path) -> None:
    rows = [("T9001", "STATION_9", "station", 10009), ("T9101", "CAMERA9X", "camera", None)]
    namespace: dict[str, object] = {}
    exec(compile(gen.render(rows, "9.9.9"), "app_models", "exec"), namespace)  # noqa: S102
    assert (namespace["APP_VERSION"], namespace["APP_MODELS"]) == ("9.9.9", tuple(rows))


def test_the_committed_module_is_in_the_catalogue() -> None:
    assert len(APP_MODELS) > 150
    assert {prefix for prefix, *_ in APP_MODELS} <= set(MODELS)
    assert len({prefix for prefix, *_ in APP_MODELS}) == len(APP_MODELS)


def test_check_without_the_app_tables_exits_2(gen: ModuleType, tmp_path: Path) -> None:
    missing = str(tmp_path / "none.java")
    args = ["--constants", missing, "--type-map", missing, "--device-types", missing]
    assert gen.main([*args, "--app-version", "9.9.9", "--check"]) == 2


def _inputs(tmp_path: Path, constants: str = _CONSTANTS) -> list[str]:
    files = {"constants": constants, "type-map": _TYPE_MAP, "device-types": _TYPE_INTS}
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
    args = [*_inputs(tmp_path, constants=""), "--out", str(out), "--app-version", "9.9.9"]
    assert gen.main(args) == 1
    assert not out.exists()


def test_a_shrinking_catalogue_needs_allow_shrink(gen: ModuleType, tmp_path: Path) -> None:
    out = tmp_path / "out.py"
    rows = [(f"T9{n:03d}", f"CAMERA_{n}", "camera", None) for n in range(20)]
    before = gen.render(rows, "9.9.8")
    out.write_text(before, encoding="utf-8")
    args = [*_inputs(tmp_path), "--out", str(out), "--app-version", "9.9.9"]
    assert gen.main(args) == 1  # 3 rows against 20
    assert out.read_text(encoding="utf-8") == before
    assert gen.main([*args, "--allow-shrink"]) == 0
    assert out.read_text(encoding="utf-8").count('    ("T') == 3


def test_a_drop_within_the_margin_is_written(gen: ModuleType, tmp_path: Path) -> None:
    out = tmp_path / "out.py"
    gen.main([*_inputs(tmp_path), "--out", str(out), "--app-version", "9.9.8"])
    # one row of 3 left out is beyond the margin; the same 3 rows are within it
    assert gen.main([*_inputs(tmp_path), "--out", str(out), "--app-version", "9.9.9"]) == 0
    assert 'APP_VERSION: Final = "9.9.9"' in out.read_text(encoding="utf-8")
