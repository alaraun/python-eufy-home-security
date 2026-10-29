"""``scripts/gen_models_variants.py``: the ``variants`` field of a settings file."""

from __future__ import annotations

import importlib.util
import sys
from collections.abc import Sequence
from pathlib import Path
from types import ModuleType
from typing import Any

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gen = _load("gen_models_variants")

BEHIND_HB3 = {"type": "parent_sn", "qualifier": "RE", "value": "^T8030"}
EMPOWERED = {"type": "associated_field", "qualifier": "=", "value": "1", "prop_id": "ai_empower"}


def _prop(ident: str, *conditions: dict[str, str], default: str | None = None) -> dict[str, Any]:
    prop: dict[str, Any] = {"identifier": ident}
    if conditions:
        prop["read_conditions"] = {"condition_list": [{"conditions": list(conditions)}]}
    if default is not None:
        prop["data_type"] = {"specs": {"defaultValue": default}}
    return prop


def _run(
    settings: dict[str, dict[str, Any]],
    props: list[dict[str, Any]],
    dropped: Sequence[str] = (),
    found: int | None = 1299,
) -> list[tuple[str, list[str]]]:
    asked: list[tuple[str, list[str]]] = []

    def probe(ident: str, values: Sequence[str]) -> int | None:
        asked.append((ident, list(values)))
        return found

    gen.add_variants(settings, props, dropped, probe, {})
    return asked


def test_each_candidate_names_the_setting_that_stands_for_it() -> None:
    settings: dict[str, dict[str, Any]] = {
        "x": {},
        "x__v1": {"variant_of": "x"},
        "x__V2": {"variant_of": "x"},
        "x__v6": {},  # a setting of its own, not a member
    }
    props = [
        _prop("x"),
        _prop("x__v1", BEHIND_HB3),
        _prop("x__V2", BEHIND_HB3),
        _prop("x__v3", BEHIND_HB3),  # dropped as equal to the primary
        _prop("x__v4", BEHIND_HB3),  # not in the file
        _prop("x__v5"),  # no read conditions: never competes
        _prop("xy__v1", BEHIND_HB3),  # another identifier
        _prop("x__v6", BEHIND_HB3),
    ]
    _run(settings, props, dropped=["x__v3"])
    rules = settings["x"]["variants"]
    assert [(r["id"], r["key"]) for r in rules] == [
        ("x__v1", "x__v1"),
        ("x__V2", "x__V2"),
        ("x__v3", "x"),
        ("x__v4", None),
        ("x__v6", None),
    ]
    assert rules[0]["read_conditions"] == [[BEHIND_HB3]]
    assert "variants" not in settings["x__v1"]


def test_a_primary_without_candidates_gets_no_field() -> None:
    settings: dict[str, dict[str, Any]] = {"x": {}, "old_x": {"variant_of": "x"}}
    _run(settings, [_prop("x"), _prop("old_x", BEHIND_HB3)])
    assert "variants" not in settings["x"]


def test_an_associated_property_reads_the_probed_parameter_and_its_default() -> None:
    settings: dict[str, dict[str, Any]] = {"x": {}, "x__v1": {"variant_of": "x"}}
    props = [_prop("x"), _prop("x__v1", EMPOWERED), _prop("ai_empower", default="0")]
    asked = _run(settings, props)
    (condition,) = settings["x"]["variants"][0]["read_conditions"][0]
    assert condition == {
        "type": "associated_field",
        "qualifier": "=",
        "value": "1",
        "prop": "ai_empower",
        "param": 1299,
        "default": "0",
    }
    assert asked == [("ai_empower", ["0", "1"])]  # the compared values and the default


def test_a_property_the_probe_cannot_read_has_no_param() -> None:
    settings: dict[str, dict[str, Any]] = {"x": {}, "x__v1": {"variant_of": "x"}}
    props = [_prop("x"), _prop("x__v1", EMPOWERED), _prop("ai_empower", default="0")]
    _run(settings, props, found=None)
    (condition,) = settings["x"]["variants"][0]["read_conditions"][0]
    assert "param" not in condition
    assert condition["default"] == "0"


def test_a_readable_setting_gives_its_own_read() -> None:
    settings: dict[str, dict[str, Any]] = {
        "x": {},
        "x__v1": {"variant_of": "x"},
        "ai_empower": {"read": {"param": 6243, "map": {"0": 1, "12": True}}},
    }
    props = [_prop("x"), _prop("x__v1", EMPOWERED), _prop("ai_empower")]
    asked = _run(settings, props)
    (condition,) = settings["x"]["variants"][0]["read_conditions"][0]
    assert (condition["param"], condition["map"]) == (6243, {"0": "1", "12": "true"})
    assert asked == []


def test_an_identity_read_has_no_map() -> None:
    settings: dict[str, dict[str, Any]] = {
        "x": {},
        "x__v1": {"variant_of": "x"},
        "ai_empower": {"read": {"param": 1299, "map": None}},
    }
    _run(settings, [_prop("x"), _prop("x__v1", EMPOWERED), _prop("ai_empower")])
    (condition,) = settings["x"]["variants"][0]["read_conditions"][0]
    assert condition["param"] == 1299
    assert "map" not in condition


def test_a_property_the_thing_description_lacks_reads_empty() -> None:
    settings: dict[str, dict[str, Any]] = {"x": {}, "x__v1": {"variant_of": "x"}}
    _run(settings, [_prop("x"), _prop("x__v1", EMPOWERED)])
    (condition,) = settings["x"]["variants"][0]["read_conditions"][0]
    assert condition == {"type": "associated_field", "qualifier": "=", "value": "1"}


def test_each_property_is_probed_once() -> None:
    settings: dict[str, dict[str, Any]] = {
        "x": {},
        "x__v1": {"variant_of": "x"},
        "y": {},
        "y__v1": {"variant_of": "y"},
    }
    props = [
        _prop("x"),
        _prop("x__v1", EMPOWERED),
        _prop("y"),
        _prop("y__v1", {**EMPOWERED, "value": "2"}),
        _prop("ai_empower", default="0"),
    ]
    asked = _run(settings, props)
    assert asked == [("ai_empower", ["0", "1", "2"])]
    assert settings["y"]["variants"][0]["read_conditions"][0][0]["param"] == 1299


def test_text_forms() -> None:
    assert [gen.text(v) for v in (True, False, 1, "a")] == ["true", "false", "1", "a"]


def test_default_values() -> None:
    enum = {"data_type": {"specs": {"eunmList": [{"value": 1}, {"value": 2, "isDefault": 1}]}}}
    assert gen.default_value(enum) == "2"
    assert gen.default_value({"data_type": {"specs": {"eunmList": [{"value": 1}]}}}) == ""
    assert gen.default_value({"data_type": {"specs": {"defaultValue": 0}}}) == "0"
    assert gen.default_value({}) == ""
