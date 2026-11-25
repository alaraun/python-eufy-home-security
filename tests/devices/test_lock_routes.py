"""Which lock command form a lock takes (devices/lock_routes.py) and its generator."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType

import pytest

from eufy_home_security.devices import lock_routes
from eufy_home_security.devices.lock_routes import LockForm, lock_route

ROOT = Path(__file__).resolve().parents[2]
ROUTES_INPUT = ROOT / ".work" / "tools" / "data" / "lock_routes.json"
TAIL = "P2000012345"  # synthetic serial tail; index 6 is "0"

# Rows as the generator writes them (serial char, P2P form, MQTT rule, ECDH param, HKDF).
SYNTHETIC_TABLE = {
    "T0001": (("", "1940", "never", None, ("2.2.0.0", "0.3.0.0")),),
    "T0002": (("", "1961", "never", None, None), ("6:9", "1940", "never", None, None)),
    "T0003": (("", "1930", "never", 6610, None),),
    "T0004": (("", "1940", "standalone", None, None),),
    "T0005": (("", "1940", "always", None, None),),
    "T0006": (("", None, "always", None, None),),
    "T0007": (("", "1961-plain", "never", None, None),),
    "T0008": (("", "1911", "never", None, None),),
    "T0009": (("", "1940", "never", None, None), ("6:8", None, "never", None, None)),
}


@pytest.fixture
def table(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(lock_routes, "LOCK_ROUTES", SYNTHETIC_TABLE)


@pytest.mark.usefixtures("table")
@pytest.mark.parametrize(
    ("main", "wifi", "form"),
    [
        ("2.2.0.0", "0.3.0.0", LockForm.P2P_1940_HKDF),  # both at the threshold
        ("2.3", "1.0", LockForm.P2P_1940_HKDF),
        ("2.1.9.9", "0.3.0.0", LockForm.P2P_1940),  # main firmware below
        ("2.2.0.0", "0.2.9.9", LockForm.P2P_1940),  # Wi-Fi firmware below
        ("", "", LockForm.P2P_1940),  # unknown firmware reaches no threshold
    ],
)
def test_hkdf_needs_both_firmware_versions_at_their_thresholds(
    main: str, wifi: str, form: LockForm
) -> None:
    serial = "T0001" + TAIL
    assert (
        lock_route(serial, behind_station=True, main_sw_version=main, sec_sw_version=wifi) is form
    )


@pytest.mark.usefixtures("table")
def test_a_serial_character_row_wins_over_the_plain_row() -> None:
    assert lock_route("T0002" + TAIL, behind_station=True) is LockForm.P2P_1961
    assert lock_route("T00020" + "9" + TAIL[2:], behind_station=True) is LockForm.P2P_1940
    assert lock_route("T00020" + "8" + TAIL[2:], behind_station=True) is LockForm.P2P_1961
    assert lock_route("T00020", behind_station=True) is LockForm.P2P_1961  # too short to say


@pytest.mark.usefixtures("table")
@pytest.mark.parametrize(
    ("params", "form"),
    [
        ({6610: "1"}, LockForm.P2P_1930_ECDH),
        ({6610: 1}, LockForm.P2P_1930_ECDH),
        ({6610: "0"}, LockForm.P2P_1930),
        ({6610: ""}, LockForm.P2P_1930),
        ({6611: "1"}, LockForm.P2P_1930),
        ({}, LockForm.P2P_1930),
        (None, LockForm.P2P_1930),
    ],
)
def test_ecdh_follows_the_named_parameter(params: dict[int, object] | None, form: LockForm) -> None:
    assert lock_route("T0003" + TAIL, behind_station=True, params=params) is form


@pytest.mark.usefixtures("table")
def test_mqtt_rules() -> None:
    assert lock_route("T0004" + TAIL, behind_station=False) is LockForm.MQTT
    assert lock_route("T0004" + TAIL, behind_station=True) is LockForm.P2P_1940
    assert lock_route("T0005" + TAIL, behind_station=True) is LockForm.MQTT
    assert lock_route("T0006" + TAIL, behind_station=True) is LockForm.MQTT


@pytest.mark.usefixtures("table")
def test_other_forms_and_no_route() -> None:
    assert lock_route("T0007" + TAIL, behind_station=True) is LockForm.P2P_1961_PLAIN
    assert lock_route("T0008" + TAIL, behind_station=True) is LockForm.P2P_1911
    assert lock_route("T00090" + "8" + TAIL[2:], behind_station=True) is None
    assert lock_route("T9999" + TAIL, behind_station=True) is None
    assert lock_route("", behind_station=True) is None


@pytest.fixture
def gen(monkeypatch: pytest.MonkeyPatch) -> ModuleType:
    """``scripts/gen_lock_routes.py``, registered in ``sys.modules`` for this test only."""
    spec = importlib.util.spec_from_file_location(
        "gen_lock_routes", ROOT / "scripts" / "gen_lock_routes.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    monkeypatch.setitem(sys.modules, spec.name, module)
    spec.loader.exec_module(module)
    return module


def _entry(**kw: object) -> dict[str, object]:
    entry: dict[str, object] = {
        "prefix": "T0001",
        "serial_char": None,
        "p2p": "Anker_Company",
        "mqtt": "never",
        "plain_1961": False,
        "ecdh_param": None,
        "hkdf": None,
    }
    entry.update(kw)
    return entry


def test_the_generator_maps_services_to_forms(gen: ModuleType) -> None:
    assert gen.row("m", _entry(), {}) == ("", "1940", "never", None, None)
    assert gen.row("m", _entry(p2p="Anker"), {})[1] == "1961"
    assert gen.row("m", _entry(p2p="Anker", plain_1961=True), {})[1] == "1961-plain"
    assert gen.row("m", _entry(p2p="AnkerBleV12", ecdh_param=6610), {})[1:4] == (
        "1930",
        "never",
        6610,
    )
    assert gen.row("m", _entry(p2p="Station"), {})[1] == "1911"
    assert gen.row("m", _entry(p2p=None, mqtt="always"), {})[1:3] == (None, "always")
    assert gen.row("m", _entry(serial_char=[6, "9"]), {})[0] == "6:9"


def test_the_generator_takes_remote_config_over_the_defaults(gen: ModuleType) -> None:
    hkdf = {"main_key": "k_main", "wifi_key": "k_wifi", "main": "2.2.0.0", "wifi": "0.3.0.0"}
    assert gen.row("m", _entry(hkdf=hkdf), {})[4] == ("2.2.0.0", "0.3.0.0")
    assert gen.row("m", _entry(hkdf=hkdf), {"k_wifi": "0.4"})[4] == ("2.2.0.0", "0.4")


@pytest.mark.parametrize(("field", "value"), [("p2p", "Zhixin"), ("mqtt", "sometimes")])
def test_the_generator_stops_on_an_unknown_value(gen: ModuleType, field: str, value: str) -> None:
    with pytest.raises(SystemExit, match=value):
        gen.row("m", _entry(**{field: value}), {})


def test_the_generator_writes_a_loadable_table(gen: ModuleType, tmp_path: Path) -> None:
    routes = tmp_path / "routes.json"
    models = {
        "SL1": _entry(),
        "SL1P": _entry(serial_char=[6, "9"], p2p="Anker"),
        "SL2": _entry(prefix="T0002", p2p=None, mqtt="never"),  # no route: left out
        "SL3": _entry(prefix="T0003", p2p="AnkerBleV12", ecdh_param=6610),
    }
    routes.write_text(json.dumps({"models": models}))
    table = gen.generate(routes, tmp_path / "missing.json")
    assert table == {
        "T0001": [("", "1940", "never", None, None), ("6:9", "1961", "never", None, None)],
        "T0003": [("", "1930", "never", 6610, None)],
    }
    namespace: dict[str, object] = {}
    exec(gen.render(table), namespace)  # noqa: S102 - the generator's own output
    assert namespace["LOCK_ROUTES"] == {k: tuple(v) for k, v in table.items()}
    empty: dict[str, object] = {}
    exec(gen.render({}), empty)  # noqa: S102 - the generator's own output
    assert empty["LOCK_ROUTES"] == {}


def test_the_generator_needs_a_plain_row_per_product(gen: ModuleType, tmp_path: Path) -> None:
    routes = tmp_path / "routes.json"
    routes.write_text(json.dumps({"models": {"SL1P": _entry(serial_char=[6, "9"])}}))
    with pytest.raises(SystemExit, match="plain serial"):
        gen.generate(routes, tmp_path / "missing.json")
