"""``scripts/gen_models_join.py``: labels, applies_when, group/order/page and source."""

from __future__ import annotations

import copy
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


_load("gen_models_codec")
join = _load("gen_models_join")

PN = "T0001"


def _td(*props: dict[str, Any], plugin_path: str | None = None) -> dict[str, Any]:
    return {
        "large_version": 7,
        "profile": {
            "plugin_path": plugin_path
            or f"https://cdn.example/product/2024/05/06/abc/{PN}Handle.mix.js"
        },
        "properties": list(props),
    }


def _enum(ident: str, *rows: tuple[str, str]) -> dict[str, Any]:
    return {
        "identifier": ident,
        "data_type": {
            "type": "enum",
            "specs": {"eunmList": [{"value": v, "desc": d} for v, d in rows]},
        },
    }


MODE = _enum("mode", ("0", "LONG_LIFE"), ("1", "BEST_VIEW"), ("3", "CUSTOM"))
TREE_MODE = {"enum": [["0", "0", "LONG_LIFE"], ["1", "1", "BEST_VIEW"], ["3", "2", "CUSTOM"]]}


def _settings() -> dict[str, Any]:
    return {
        "mode": {"kind": "enum", "values": [0, 1, 3]},
        "clip": {"kind": "range"},
        "flag": {"kind": "bool"},
        "alerts": {"kind": "bool"},
    }


def _tree(**over: Any) -> dict[str, Any]:
    tree: dict[str, Any] = {
        "gates": [],
        "pages": {},
        "positions": {},
        "properties": {"mode": TREE_MODE},
    }
    tree.update(over)
    return tree


def test_labels_take_the_app_title_and_fall_back_to_the_td_desc() -> None:
    settings = _settings()
    app = {"mode": [{"ui": "3", "wire": "2", "td": "CUSTOM", "app": "Custom Recording"}]}
    join.join(PN, settings, _td(MODE), app, None)
    assert settings["mode"]["labels"] == {
        "0": "Long life",
        "1": "Best view",
        "3": "Custom Recording",
    }


def test_labels_ignore_app_rows_for_values_the_td_does_not_have() -> None:
    settings = _settings()
    app = {"mode": [{"ui": "9", "wire": "9", "td": "x", "app": "Ghost"}]}
    counts = join.join(PN, settings, _td(MODE), app, None)
    assert "9" not in settings["mode"]["labels"]
    assert counts["labels:app row without TD value"] == 1


def test_non_int_enum_value_without_a_clean_label_uses_the_raw_desc_or_value() -> None:
    prop = _enum("tone", ("a", "钟声"), ("b", ""))
    settings: dict[str, Any] = {"tone": {"kind": "enum", "values": ["a", "b"]}}
    join.join(PN, settings, _td(prop), None, None)
    assert settings["tone"]["labels"] == {"a": "钟声", "b": "b"}


def test_only_enum_settings_get_labels() -> None:
    settings = _settings()
    join.join(PN, settings, _td(MODE), None, None)
    assert [k for k, v in settings.items() if "labels" in v] == ["mode"]


def test_value_gate_sets_applies_when_on_shown_settings() -> None:
    gate = {"when": {"mode": "CUSTOM"}, "shows": ["clip", "flag", "gone"], "page": "Custom"}
    present = {"when": {"mode": "present"}, "shows": ["alerts"], "page": "Home"}
    settings = _settings()
    counts = join.join(PN, settings, _td(MODE), None, _tree(gates=[gate, present]))
    assert settings["clip"]["applies_when"] == ["mode", 3]
    assert settings["flag"]["applies_when"] == ["mode", 3]
    assert "applies_when" not in settings["alerts"]
    assert counts["applies_when:shown not a setting"] == 1


def test_gate_desc_that_does_not_map_raises() -> None:
    gate = {"when": {"mode": "UNKNOWN"}, "shows": ["clip"], "page": "Custom"}
    with pytest.raises(join.GeneratorError, match=f"{PN}.*mode"):
        join.join(PN, _settings(), _td(MODE), None, _tree(gates=[gate]))


def test_identifier_shown_by_two_gates_raises() -> None:
    gates = [
        {"when": {"mode": "CUSTOM"}, "shows": ["clip"], "page": "A"},
        {"when": {"mode": "BEST_VIEW"}, "shows": ["clip"], "page": "B"},
    ]
    with pytest.raises(join.GeneratorError, match=f"{PN}.*clip"):
        join.join(PN, _settings(), _td(MODE), None, _tree(gates=gates))


def test_setting_model_config_gives_group_order_and_page() -> None:
    positions = {
        "setting_model_config": {"SettingsNotification": ["alerts#B#1", "flag#A#2"]},
        "player_model_config": {"Live": ["clip#C#4"]},
    }
    settings = _settings()
    join.join(PN, settings, _td(MODE), None, _tree(positions=positions))
    assert {k: settings["alerts"][k] for k in ("group", "order", "page")} == {
        "group": "B",
        "order": 1,
        "page": "SettingsNotification",
    }
    assert settings["flag"]["group"] == "A"
    assert not {"group", "order", "page"} & set(settings["clip"])


def test_setting_model_config_entry_without_section_keeps_only_the_page() -> None:
    positions = {"setting_model_config": {"SettingsNotification": ["alerts##"]}}
    settings = _settings()
    join.join(PN, settings, _td(MODE), None, _tree(positions=positions))
    assert settings["alerts"]["page"] == "SettingsNotification"
    assert "group" not in settings["alerts"]
    assert "order" not in settings["alerts"]


def test_identifier_on_two_settings_pages_has_no_position() -> None:
    positions = {"setting_model_config": {"Home": ["alerts#A#1"], "General": ["alerts#B#1"]}}
    settings = _settings()
    join.join(PN, settings, _td(MODE), None, _tree(positions=positions))
    assert not {"group", "order", "page"} & set(settings["alerts"])


def test_page_precedence_gate_then_config_then_single_route() -> None:
    gate = {"when": {"mode": "CUSTOM"}, "shows": ["clip"], "page": "Custom"}
    positions = {"setting_model_config": {"Config": ["clip#A#1", "flag#A#2"]}}
    pages = {
        "g1": [{"route": "OnlyRoute", "props": ["alerts", "clip"]}],
        "g2": [
            {"route": "R1", "props": ["mode"]},
            {"route": "R2", "props": ["mode", "clip"]},
        ],
    }
    settings = _settings()
    tree = _tree(gates=[gate], positions=positions, pages=pages)
    join.join(PN, settings, _td(MODE), None, tree)
    assert settings["clip"]["page"] == "Custom"
    assert settings["flag"]["page"] == "Config"
    assert settings["alerts"]["page"] == "OnlyRoute"
    assert "page" not in settings["mode"]


def test_model_without_tree_gets_no_ui_placement() -> None:
    settings = _settings()
    join.join(PN, settings, _td(MODE), None, None)
    assert not any({"group", "order", "page", "applies_when"} & set(v) for v in settings.values())


def _titles(**over: Any) -> dict[str, Any]:
    titles: dict[str, Any] = {
        "titles": {
            "clip": {"title": "Clip length"},
            "flag": {"title": "Flag", "kind": "enum"},
            "mode": {"title": " Mode title "},
        },
        "models": {PN: {"mode": {"title": "Model mode"}}},
        "units": {"clip": {"unit": "s", "page": "Custom"}},
        "variants": {"alerts": {"primary": "flag", "kind": "bool"}},
    }
    titles.update(over)
    return titles


RN_TREE = {"settings_ui": "rn"}


def test_names_take_the_models_title_then_the_identifiers_matching_kind() -> None:
    settings = _settings()
    settings["clip__v1"] = {"kind": "range"}
    counts = join.join(PN, settings, _td(MODE), None, _tree(**RN_TREE), titles=_titles())
    names = {k: v.get("name") for k, v in settings.items()}
    assert names == {
        "mode": "Model mode",
        "clip": "Clip length",
        "flag": None,
        "alerts": None,
        "clip__v1": "Clip length",
    }
    assert counts["name:app"] == 3


def test_app_title_another_setting_is_named_is_not_applied() -> None:
    settings = _settings()
    settings["flag_v"] = {"kind": "bool"}
    titles = _titles(
        titles={"clip": {"title": "Flag"}, "alerts": {"title": "Same"}, "flag_v": {"title": "same"}}
    )
    counts = join.join(PN, settings, _td(MODE), None, _tree(**RN_TREE), titles=titles)
    assert not any("name" in settings[k] for k in ("clip", "alerts", "flag_v"))
    assert counts["name:app title shared with another setting"] == 3


def test_variants_of_one_primary_may_share_its_title() -> None:
    settings = _settings()
    settings["mode__v1"] = {"kind": "enum"}
    join.join(PN, settings, _td(MODE), None, _tree(**RN_TREE), titles=_titles())
    assert settings["mode"]["name"] == settings["mode__v1"]["name"] == "Model mode"


def test_app_unit_applies_on_its_page_and_never_overrides_the_td() -> None:
    gate = {"when": {"mode": "CUSTOM"}, "shows": ["clip"], "page": "Custom"}
    settings = _settings()
    settings["clip"].update(min=5, max=60)
    tree = _tree(gates=[gate], **RN_TREE)
    join.join(PN, settings, _td(MODE), None, tree, titles=_titles())
    assert settings["clip"]["unit"] == "s"
    elsewhere = _settings()
    join.join(PN, elsewhere, _td(MODE), None, _tree(**RN_TREE), titles=_titles())
    assert "unit" not in elsewhere["clip"]
    days = _settings()
    days["clip"]["unit"] = "d"
    counts = join.join(PN, days, _td(MODE), None, tree, titles=_titles())
    assert days["clip"]["unit"] == "d"
    assert counts["unit:app differs from TD"] == 1


def test_names_and_units_need_a_model_on_the_rn_settings_screens() -> None:
    settings = _settings()
    join.join(PN, settings, _td(MODE), None, _tree(settings_ui="native"), titles=_titles())
    join.join(PN, settings, _td(MODE), None, None, titles=_titles())
    assert not any({"name", "unit"} & set(v) for v in settings.values())


def test_variant_of_marks_versioned_and_listed_identifiers() -> None:
    settings = _settings()
    settings.update(
        {"mode__v1": {"kind": "enum"}, "mode__v2": {"kind": "enum"}, "orphan__v1": {"kind": "bool"}}
    )
    counts = join.join(PN, settings, _td(MODE), None, None, titles=_titles())
    marks = {k: v["variant_of"] for k, v in settings.items() if "variant_of" in v}
    assert marks == {"mode__v1": "mode", "mode__v2": "mode", "alerts": "flag"}
    assert counts["variant_of"] == 3


def test_listed_variant_needs_its_kind_and_a_present_primary() -> None:
    other_kind = _titles(variants={"alerts": {"primary": "flag", "kind": "enum"}})
    no_primary = _titles(variants={"alerts": {"primary": "gone"}})
    for titles in (other_kind, no_primary):
        settings = _settings()
        join.join(PN, settings, _td(MODE), None, None, titles=titles)
        assert "variant_of" not in settings["alerts"]


def test_variant_chain_resolves_to_the_primary_and_a_cycle_raises() -> None:
    chain = _titles(variants={"alerts": {"primary": "flag"}, "flag": {"primary": "clip"}})
    settings = _settings()
    join.join(PN, settings, _td(MODE), None, None, titles=chain)
    assert (settings["alerts"]["variant_of"], settings["flag"]["variant_of"]) == ("clip", "clip")
    cycle = _titles(variants={"alerts": {"primary": "flag"}, "flag": {"primary": "alerts"}})
    with pytest.raises(join.GeneratorError, match=f"{PN}: variant cycle"):
        join.join(PN, _settings(), _td(MODE), None, None, titles=cycle)


def test_empty_app_title_raises() -> None:
    titles = _titles(titles={"clip": {"title": " "}})
    with pytest.raises(join.GeneratorError, match=f"{PN}: clip"):
        join.join(PN, _settings(), _td(MODE), None, _tree(**RN_TREE), titles=titles)


def test_without_titles_no_name_unit_or_variant() -> None:
    settings = _settings()
    settings["mode__v1"] = {"kind": "enum"}
    join.join(PN, settings, _td(MODE), None, _tree(**RN_TREE))
    assert not any({"name", "variant_of"} & set(v) for v in settings.values())


def test_source_block_from_td_and_app_version() -> None:
    assert join.source_block(_td(), "6.1.10") == {
        "td_version": 7,
        "handler": f"{PN}Handle.mix.js",
        "handler_date": "2024-05-06",  # hygiene: ok (parsed from the synthetic path)
        "app_version": "6.1.10",
    }


def test_source_block_without_a_date_segment_raises() -> None:
    td = _td(plugin_path=f"https://cdn.example/product/abc/{PN}Handle.mix.js")
    with pytest.raises(join.GeneratorError, match="date"):
        join.source_block(td, "6.1.10")


def test_join_does_not_touch_its_inputs() -> None:
    app = {"mode": [{"ui": "3", "wire": "2", "td": "CUSTOM", "app": "Custom"}]}
    gate = {"when": {"mode": "CUSTOM"}, "shows": ["clip"], "page": "Custom"}
    tree = _tree(gates=[gate], **RN_TREE)
    titles = _titles()
    before = copy.deepcopy((app, tree, titles))
    join.join(PN, _settings(), _td(MODE), app, tree, titles=titles)
    assert (app, tree, titles) == before


def test_generated_t8160_custom_recording_settings_apply_when_mode_is_3() -> None:
    path = ROOT / "src" / "eufy_home_security" / "devices" / "data" / "models" / "T8160.json"
    doc = json.loads(path.read_text(encoding="utf-8"))
    settings = doc["settings"]
    assert set(doc["source"]) == {"td_version", "handler", "handler_date", "app_version"}
    assert 3 in settings["power_manager_mode"]["values"]
    for ident in ("video_clip_length", "trigger_interval_time", "motion_stop_end_early"):
        assert settings[ident]["applies_when"] == ["power_manager_mode", 3]
        assert settings[ident]["access"] == "rw"


@pytest.mark.parametrize(
    ("raw", "minimum", "maximum", "unit"),
    [
        ("s", 2, 60, "s"),
        ("秒", None, None, "s"),
        ("毫秒", None, None, "ms"),
        ("day", 10, 120, "d"),
        ("天", 10, 120, "d"),
        ("音量", 1, 100, "%"),
        ("音量", 0, 100, "%"),
        ("无", 0, 1, None),
        ("个", 1, 2, None),
    ],
)
def test_vendor_units_normalise_to_setting_units(
    raw: str, minimum: int | None, maximum: int | None, unit: str | None
) -> None:
    assert join.normalise_unit(PN, "x", raw, minimum, maximum) == unit


@pytest.mark.parametrize(
    ("raw", "minimum", "maximum"), [("音量", 0, 10), ("音量", None, None), ("lux", 0, 100)]
)
def test_unmapped_vendor_unit_raises_naming_model_and_identifier(
    raw: str, minimum: int | None, maximum: int | None
) -> None:
    with pytest.raises(join.GeneratorError, match=rf"{PN}: speaker_volume unit"):
        join.normalise_unit(PN, "speaker_volume", raw, minimum, maximum)


def test_an_unmapped_unit_is_a_generator_error_from_the_librarys_value_error() -> None:
    from eufy_home_security.devices.settings import SettingUnit  # noqa: PLC0415

    assert join.normalise_unit(PN, "x", "音量", 0, 100) == SettingUnit.PERCENT.value
    with pytest.raises(join.GeneratorError) as raised:
        join.normalise_unit(PN, "x", "lux", 0, 100)
    assert isinstance(raised.value.__cause__, ValueError)
