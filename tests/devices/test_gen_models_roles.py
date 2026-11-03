"""``scripts/gen_models_roles.py``: each rule of a setting's role, and the role inputs
``gen_models`` builds from the shown-property file and a settings tree."""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


roles = _load("gen_models_roles")
gen_models = _load("gen_models")

STATE = (1101, 1131)  # parameters the library reads into device state

# A synthetic thing description: (identifier, access_mode).
TD = [("volume", "RW"), ("door", "R"), ("ability", "R"), ("battery", "R"), ("schedule", "RW")]
TD += [("password_set", "RW"), ("password_set__v1", "RW"), ("level__v1", "R"), ("wifi_name", "R")]
# A synthetic shown-property file and settings tree.
SHOWN_FILE = {"pages": {"wifi_name": ["WiFiScreen"]}, "cards": {"door": ["SensorCard"]}}
TREE = {"positions": {"player_model_config": {"Live": ["level#C#2", "light#F#4"]}}}


def _entry(access: str = "ro", param: int | None = None, **extra: Any) -> dict[str, Any]:
    read = None if param is None else {"param": param, "map": None}
    return {"kind": "string", "access": access, "read": read, "section": "other", **extra}


SETTINGS: dict[str, dict[str, Any]] = {
    "volume": _entry("rw", 1400),
    "door": _entry(param=1550),
    "ability": _entry(param=1103),
    "battery": _entry(param=1101),
    "schedule": _entry(),
    "password_set": _entry(param=1670),
    "password_set__v1": _entry(param=1671),
    "level__v1": _entry(param=1300),
    "wifi_name": _entry(param=1180),
}


def _assign(settings: dict[str, dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = roles.assign(
        settings,
        td_writable={i for i, access in TD if "W" in access},
        app_read_only={"password_set"},
        shown=gen_models.shown_identifiers(SHOWN_FILE) | gen_models.placed_identifiers(TREE),
        state_params=STATE,
    )
    return counts


def test_each_rule_gives_its_role() -> None:
    settings = {k: dict(v) for k, v in SETTINGS.items()}
    counts = _assign(settings)
    assert {k: e["role"] for k, e in settings.items()} == {
        "volume": "setting",  # the library writes it
        "door": "status",  # a device card reads it
        "ability": "diagnostic",  # nothing the app shows reads it
        "battery": "diagnostic",  # its parameter is a device state field
        "schedule": "setting",  # writable in the thing description, no library write
        "password_set": "status",  # writable in the thing description, the app only reads it
        "password_set__v1": "status",  # listed through its base
        "level__v1": "status",  # its base is placed in the app's layout
        "wifi_name": "status",  # a settings page reads it
    }
    assert counts == {
        "role:setting:written": 1,
        "role:setting:app control": 1,
        "role:status:shown": 5,
        "role:diagnostic:not shown": 1,
        "role:diagnostic:device state": 1,
    }


def test_a_setting_written_in_one_context_only_is_a_setting() -> None:
    entry = _entry(contexts=[{"names": ["standalone"], "entry": {"access": "rw"}}])
    assert _role("ability", entry) == ("setting", "written")


def test_a_setting_written_with_a_state_parameter_stays_a_setting() -> None:
    assert _role("battery", _entry("rw", 1101)) == ("setting", "written")


def test_a_state_parameter_read_in_another_context_is_a_device_state_field() -> None:
    entry = _entry(param=1103, contexts=[{"names": ["HB3"], "entry": {"read": {"param": 1131}}}])
    assert _role("door", entry) == ("diagnostic", "device state")


def test_a_device_state_field_wins_over_the_app_s_control() -> None:
    assert _role("schedule", _entry(param=1131)) == ("diagnostic", "device state")


def test_a_listed_status_is_a_status_without_being_shown() -> None:
    assert _role("password_set", _entry(), shown=set()) == ("status", "shown")


def _role(ident: str, entry: dict[str, Any], *, shown: set[str] | None = None) -> tuple[str, str]:
    found: tuple[str, str] = roles.role_of(
        ident,
        entry,
        td_writable={i for i, access in TD if "W" in access},
        app_read_only={"password_set"},
        shown={"door"} if shown is None else shown,
        state_params=STATE,
    )
    return found


def test_a_task_hands_its_shown_identifiers_to_generate(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fake(*args: Any, **kwargs: Any) -> tuple[dict[str, Any], dict[str, int]]:
        seen.update(kwargs)
        return {}, {}

    monkeypatch.setattr(gen_models, "generate", fake)
    task = gen_models._Task("T9ZZ9", ROOT, None, None, "1", None, {}, (), frozenset({"door"}))
    gen_models._build(task)
    assert seen["shown"] == frozenset({"door"})


def test_a_run_reads_the_shown_file_into_every_task(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    tasks: list[Any] = []

    def run(found: list[Any], _jobs: int) -> list[Any]:
        tasks.extend(found)
        return []

    monkeypatch.setattr(gen_models, "_run_tasks", run)
    data = tmp_path / "data"
    data.mkdir()
    for name in ("labels", "trees", "titles", "released"):
        (data / f"{name}.json").write_text("{}", encoding="utf-8")
    (data / "shown.json").write_text(json.dumps(SHOWN_FILE), encoding="utf-8")
    args = argparse.Namespace(
        product_codes=["T9ZZ8", "T9ZZ9"],
        jobs=1,
        app_version="1",
        **{name: data / f"{name}.json" for name in ("labels", "trees", "titles", "released")},
        shown=data / "shown.json",
    )
    gen_models._generate_all(args, tmp_path, tmp_path / "out", quiet=True)
    assert [t.shown for t in tasks] == [frozenset({"wifi_name", "door"})] * 2


def test_placed_identifiers_read_every_layout_of_the_tree() -> None:
    tree = {"positions": {"a": {"P": ["x#C#1"]}, "b": {"Q": ["y", "z#D#2"]}}}
    assert gen_models.placed_identifiers(tree) == {"x", "y", "z"}
    assert gen_models.placed_identifiers(None) == set()


@pytest.mark.parametrize("doc", [{"pages": {}}, {"cards": {}}, {"pages": [], "cards": {}}])
def test_shown_identifiers_need_both_objects(doc: dict[str, Any]) -> None:
    with pytest.raises(gen_models.GeneratorError, match="shown-property data"):
        gen_models.shown_identifiers(doc)
