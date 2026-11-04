"""``scripts/gen_models_roles.py``: each rule of a setting's role and where the app shows
it, and the inputs ``gen_models`` builds from the shown-property file and a settings tree."""

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

STATE = (1101, 1131, 2111)  # parameters whose value the library already reports

# A synthetic thing description: (identifier, access_mode).
TD = [("volume", "RW"), ("door", "R"), ("ability", "R"), ("battery", "R"), ("schedule", "RW")]
TD += [("password_set", "RW"), ("password_set__v1", "RW"), ("level__v1", "R"), ("wifi_name", "R")]
TD += [("charging", "R"), ("volume_card", "RW")]
# A synthetic shown-property file and settings tree: "wifi_name" is on a page and in the
# layout, "door" on a page and on the card, "volume_card" on the card and in the layout.
SHOWN_FILE = {
    "pages": {"wifi_name": ["WiFiScreen"], "door": ["SensorPage"]},
    "cards": {"door": ["SensorCard"], "volume_card": ["CameraCard"], "charging": ["CameraCard"]},
}
TREE = {"positions": {"player_model_config": {"Live": ["level#C#2", "wifi_name#F#4"]}}}
TREE["positions"]["setting_model_config"] = {"Main": ["volume_card#A#1"]}
# The parameter the handler fills each property from (read or not).
LOCATED = {"charging": 2111, "door": 1550, "schedule": 1400}


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
    "charging": _entry(),
    "volume_card": _entry("rw", 1401),
}


def _places() -> dict[str, str]:
    places: dict[str, str] = gen_models.model_shown(gen_models.shown_places(SHOWN_FILE), TREE)
    return places


def _assign(settings: dict[str, dict[str, Any]]) -> dict[str, int]:
    counts: dict[str, int] = roles.assign(
        settings,
        td_writable={i for i, access in TD if "W" in access},
        app_read_only={"password_set"},
        shown=_places(),
        state_params=STATE,
        located=LOCATED,
    )
    return counts


def test_each_rule_gives_its_role_and_place() -> None:
    settings = {k: dict(v) for k, v in SETTINGS.items()}
    counts = _assign(settings)
    assert {k: (e["role"], e.get("shown")) for k, e in settings.items()} == {
        "volume": ("setting", None),  # the library writes it; the app shows it nowhere
        "door": ("status", "card"),  # a device card reads it (a page too: the card wins)
        "ability": ("diagnostic", None),  # nothing the app shows reads it
        "battery": ("diagnostic", None),  # its parameter is a device state field
        "schedule": ("setting", None),  # writable in the thing description, no library write
        "password_set": ("status", "page"),  # TD-writable, the app lists it as read-only
        "password_set__v1": ("status", "page"),  # listed through its base
        "level__v1": ("status", "page"),  # its base is placed in the app's layout
        "wifi_name": ("status", "page"),  # a settings page reads it, the layout places it
        "charging": ("diagnostic", "card"),  # on the card, filled from a device state field
        "volume_card": ("setting", "card"),  # a written setting on the card (layout: a page)
    }
    assert counts == {
        "role:setting:written": 2,
        "role:setting:app control": 1,
        "role:status:shown": 5,
        "role:diagnostic:not shown": 1,
        "role:diagnostic:device state": 2,
        "shown:card": 3,
        "shown:page": 4,
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


def test_a_status_the_handler_fills_from_a_device_state_field_is_a_diagnostic() -> None:
    """No read (the handler converts the value), but its one parameter is device state."""
    assert _role("door", _entry(), located={"door": 2111}) == ("diagnostic", "device state")
    assert _role("door", _entry(), located={"door": 1550}) == ("status", "shown")
    assert _role("door", _entry(), located={"other": 2111}) == ("status", "shown")


def test_a_listed_status_is_a_status_without_being_shown() -> None:
    assert _role("password_set", _entry(), shown={}) == ("status", "shown")


@pytest.mark.parametrize(
    ("ident", "shown", "place"),
    [
        ("door", {"door": "card"}, "card"),
        ("door", {"door": "page"}, "page"),
        ("door", {}, None),
        ("door__v2", {"door": "card"}, "card"),  # a variant is shown where its base is
        ("door__v2", {"door__v2": "page", "door": "card"}, "card"),  # the card wins
        ("door__v2", {"door__v2": "card", "door": "page"}, "card"),
        ("password_set", {}, "page"),  # the app lists it as a status it only reads
        ("password_set__v1", {}, "page"),
        ("password_set", {"password_set": "card"}, "card"),
    ],
)
def test_shown_of_prefers_the_card(ident: str, shown: dict[str, str], place: str | None) -> None:
    assert roles.shown_of(ident, shown=shown, app_read_only={"password_set"}) == place


def _role(
    ident: str,
    entry: dict[str, Any],
    *,
    shown: dict[str, str] | None = None,
    located: dict[str, int] | None = None,
) -> tuple[str, str]:
    found: tuple[str, str] = roles.role_of(
        ident,
        entry,
        td_writable={i for i, access in TD if "W" in access},
        app_read_only={"password_set"},
        shown={"door": "card"} if shown is None else shown,
        state_params=STATE,
        located={} if located is None else located,
    )
    return found


def test_a_task_hands_its_shown_identifiers_to_generate(monkeypatch: pytest.MonkeyPatch) -> None:
    seen: dict[str, Any] = {}

    def fake(*args: Any, **kwargs: Any) -> tuple[dict[str, Any], dict[str, int]]:
        seen.update(kwargs)
        return {}, {}

    monkeypatch.setattr(gen_models, "generate", fake)
    task = gen_models._Task("T9ZZ9", ROOT, None, None, "1", None, {}, (), {"door": "card"})
    gen_models._build(task)
    assert seen["shown"] == {"door": "card"}


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
    expected = {"wifi_name": "page", "door": "card", "volume_card": "card", "charging": "card"}
    assert [t.shown for t in tasks] == [expected] * 2


def test_placed_identifiers_read_every_layout_of_the_tree() -> None:
    tree = {"positions": {"a": {"P": ["x#C#1"]}, "b": {"Q": ["y", "z#D#2"]}}}
    assert gen_models.placed_identifiers(tree) == {"x", "y", "z"}
    assert gen_models.placed_identifiers(None) == set()


def test_a_model_s_layout_adds_pages_but_never_hides_a_card() -> None:
    tree = {"positions": {"a": {"P": ["x#C#1", "y#C#2", "z#C#3"]}}}
    got = gen_models.model_shown({"x": "card", "y": "page", "w": "card"}, tree)
    assert got == {"x": "card", "y": "page", "z": "page", "w": "card"}
    assert gen_models.model_shown({"w": "page"}, None) == {"w": "page"}


@pytest.mark.parametrize("doc", [{"pages": {}}, {"cards": {}}, {"pages": [], "cards": {}}])
def test_shown_places_need_both_objects(doc: dict[str, Any]) -> None:
    with pytest.raises(gen_models.GeneratorError, match="shown-property data"):
        gen_models.shown_places(doc)


def test_a_card_identifier_is_a_card_even_when_a_page_reads_it() -> None:
    assert gen_models.shown_places(SHOWN_FILE)["door"] == "card"
    assert gen_models.shown_places(SHOWN_FILE)["wifi_name"] == "page"


def test_a_structured_status_is_a_diagnostic() -> None:
    assert _role("door", _entry(param=1550, structured=True)) == ("diagnostic", "structured")
    assert _role("ability", _entry(param=1103, structured=True)) == ("diagnostic", "structured")


def test_a_structured_value_keeps_its_control_role() -> None:
    """The flag says how to show a value; a control stays a control."""
    assert _role("volume", _entry("rw", 1400, structured=True)) == ("setting", "written")
    assert _role("schedule", _entry(structured=True)) == ("setting", "app control")
    assert _role("battery", _entry(param=1101, structured=True)) == ("diagnostic", "device state")


@pytest.mark.parametrize(
    ("extra", "shown", "role"),
    [
        ({"kind": "other"}, {"door": "card"}, ("diagnostic", "bare code")),
        ({"kind": "other"}, {"door": "page"}, ("status", "shown")),  # a page shows its value
        ({"kind": "other", "labels": {"1": "Wi-Fi"}}, {"door": "card"}, ("status", "shown")),
        ({"kind": "other", "unit": "s"}, {"door": "card"}, ("status", "shown")),
        ({"kind": "bool"}, {"door": "card"}, ("status", "shown")),
        ({"kind": "string"}, {"door": "card"}, ("status", "shown")),
    ],
)
def test_a_card_status_that_is_a_bare_code_is_a_diagnostic(
    extra: dict[str, Any], shown: dict[str, str], role: tuple[str, str]
) -> None:
    assert _role("door", _entry(param=1550, **extra), shown=shown) == role


def test_a_bare_code_variant_on_the_card_through_its_base_is_a_diagnostic() -> None:
    entry = _entry(param=1550, kind="other")
    assert _role("door__v1", entry, shown={"door": "card"}) == ("diagnostic", "bare code")


def test_a_structure_probe_holds_the_read_parameter_then_the_located_one() -> None:
    located = gen_models.Located(1257, as_command=False)
    probe = gen_models._probe_param
    in_context = _entry(contexts=[{"names": ["HB3"], "entry": {"read": {"param": 1300}}}])
    assert probe(_entry(param=1257), located) == located  # asked as it was located
    assert probe(_entry(param=1300), located) == gen_models.Located(1300, as_command=True)
    assert probe(in_context, None) == gen_models.Located(1300, as_command=True)
    assert probe(_entry(), located) == located
    assert probe(_entry(), None) is None
