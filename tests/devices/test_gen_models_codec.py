"""``scripts/gen_models_codec.py``: domain sampling, slotting and write-codec inference."""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "gen_models_codec", ROOT / "scripts" / "gen_models_codec.py"
    )
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


codec = _load()
CHILD_SN = codec.CHILD.device_sn
STATION_SN = codec.CHILD.station_sn
ALT = codec.ALT_CHANNEL[codec.CHILD.name]


def _rec(param: Any, update: Any = None, channel: int = 3) -> dict[str, Any]:
    """A synthetic recipe in the handler's shape."""
    recipe: dict[str, Any] = {"cmd": 1000, "params": {"channel": channel, "x": param}}
    if update is not None:
        recipe["update"] = {"cmd": 1000, "paramValue": update}
    return recipe


def _pairs(values: list[Any], build: Any, channel: int = 3) -> list[tuple[Any, Any]]:
    return [(v, build(v, channel)) for v in values]


def test_domain_samples_long_ranges_on_the_step_grid() -> None:
    """A range over 41 points samples ends, neighbours, the middle and 5 grid points."""
    prop = {"data_type": {"type": "int", "specs": {"min": "0", "max": "1000", "step": "10"}}}
    kind, values = codec.domain(prop)
    assert kind == "range"
    assert values[:2] == [0, 10]
    assert values[-2:] == [990, 1000]
    assert 500 in values
    assert all(v % 10 == 0 for v in values)
    assert values == [0, 10, 170, 330, 500, 670, 830, 990, 1000]


def test_slot_replaces_serials_and_drops_volatile_keys() -> None:
    recipe = {"sn": CHILD_SN, "p": [{"st": STATION_SN, "transaction": "t"}], "buildTimestamp": 1}
    assert codec.slot(recipe, codec.CHILD) == {"sn": "$device_sn", "p": [{"st": "$station_sn"}]}


def test_value_forms_v_str_and_int() -> None:
    """Leaves equal to the value, its string, or its int become value slots."""
    result = codec.infer_write(
        "range",
        _pairs([1, 2, 3], lambda v, ch: _rec(v, str(v), ch)),
        _pairs([1, 2, 3], lambda v, ch: _rec(v, str(v), ch), ALT),
        3,
        ALT,
    )
    assert result.access == "rw"
    assert result.write["params"]["x"] == "$v"
    assert result.write["update"]["paramValue"] == "$v:str"
    flags = codec.infer_write(
        "bool",
        _pairs([False, True], lambda v, ch: _rec(int(v), str(int(v)), ch)),
        _pairs([False, True], lambda v, ch: _rec(int(v), str(int(v)), ch), ALT),
        3,
        ALT,
    )
    assert flags.write["params"]["x"] == "$v:int"
    assert flags.write["update"]["paramValue"] == "$v:str"


def test_enum_leaf_that_translates_becomes_a_complete_map() -> None:
    wire = {0: 5, 1: 6, 3: 2}
    result = codec.infer_write(
        "enum",
        _pairs([0, 1, 3], lambda v, ch: _rec(wire[v], str(wire[v]), ch)),
        _pairs([0, 1, 3], lambda v, ch: _rec(wire[v], str(wire[v]), ch), ALT),
        3,
        ALT,
    )
    assert result.access == "rw"
    assert result.form == "map"
    assert result.write["params"]["x"] == {"$map": {"0": 5, "1": 6, "3": 2}}
    assert result.write["update"]["paramValue"] == {"$map": {"0": "5", "1": "6", "3": "2"}}
    flags = codec.infer_write(
        "bool",
        _pairs([False, True], lambda v, ch: _rec("on" if v else "off", None, ch)),
        _pairs([False, True], lambda v, ch: _rec("on" if v else "off", None, ch), ALT),
        3,
        ALT,
    )
    assert flags.write["params"]["x"] == {"$map": {"false": "off", "true": "on"}}


def test_range_leaf_linear_in_the_value_becomes_affine() -> None:
    result = codec.infer_write(
        "range",
        _pairs([1, 2, 3], lambda v, ch: _rec(v * 10 + 5, None, ch)),
        _pairs([1, 2, 3], lambda v, ch: _rec(v * 10 + 5, None, ch), ALT),
        3,
        ALT,
    )
    assert result.access == "rw"
    assert result.form == "affine"
    assert result.write["params"]["x"] == {"$affine": [10, 5]}


def test_range_leaf_not_linear_is_read_only() -> None:
    result = codec.infer_write(
        "range",
        _pairs([1, 2, 3], lambda v, ch: _rec(v * v, None, ch)),
        _pairs([1, 2, 3], lambda v, ch: _rec(v * v, None, ch), ALT),
        3,
        ALT,
    )
    assert result.access == "ro"
    assert result.note == "non-linear range"
    assert result.write is None


def test_recipe_shape_that_varies_with_the_value_becomes_a_table() -> None:
    def build(v: int, ch: int) -> dict[str, Any]:
        return {"cmd": 1000 + v, "params": {"channel": ch, **({"extra": 1} if v else {})}}

    result = codec.infer_write("enum", _pairs([0, 1], build), _pairs([0, 1], build, ALT), 3, ALT)
    assert result.access == "rw"
    assert result.form == "table"
    assert result.write is None
    assert result.write_table == {
        "0": {"cmd": 1000, "params": {"channel": "$channel"}},
        "1": {"cmd": 1001, "params": {"channel": "$channel", "extra": 1}},
    }


def test_recipe_independent_of_the_value_is_read_only() -> None:
    result = codec.infer_write(
        "enum",
        _pairs([0, 1, 2], lambda v, ch: _rec(7, None, ch)),
        _pairs([0, 1, 2], lambda v, ch: _rec(7, None, ch), ALT),
        3,
        ALT,
    )
    assert (result.access, result.note, result.write) == ("ro", "handler ignores the value", None)


def test_single_probe_is_writable_only_when_a_leaf_carries_it() -> None:
    carried = codec.infer_write(
        "string",
        [("probe", _rec("probe", None))],
        [("probe", _rec("probe", None, ALT))],
        3,
        ALT,
    )
    assert carried.access == "rw"
    assert carried.write["params"]["x"] == "$v"
    ignored = codec.infer_write(
        "string",
        [("probe", _rec("fixed", None))],
        [("probe", _rec("fixed", None, ALT))],
        3,
        ALT,
    )
    assert (ignored.access, ignored.note) == ("ro", "handler ignores the value")


def test_string_property_with_numeric_bounds_is_a_range() -> None:
    prop = {"data_type": {"type": "string", "specs": {"min": "0", "max": "2", "step": "1"}}}
    assert codec.domain(prop) == ("range", [0, 1, 2])


def test_open_domain_recipe_whose_shape_follows_the_probe_is_read_only() -> None:
    def build(v: str, ch: int) -> dict[str, Any]:
        return {"cmd": 1, "params": dict(enumerate(v))}

    result = codec.infer_write(
        "string", _pairs(["ab", "abc"], build), _pairs(["ab", "abc"], build, ALT), 3, ALT
    )
    assert (result.access, result.note) == ("ro", "handler expects a structured value")


def test_open_domain_leaf_that_reencodes_the_probe_is_read_only() -> None:
    """Two probes: a leaf that varies but is no value form means the handler encodes it."""
    result = codec.infer_write(
        "string",
        _pairs(["a", "b"], lambda v, ch: _rec(v, f"enc({v})", ch)),
        _pairs(["a", "b"], lambda v, ch: _rec(v, f"enc({v})", ch), ALT),
        3,
        ALT,
    )
    assert (result.access, result.note) == ("ro", "handler transforms the value")


def test_single_value_enum_keeps_its_recipe_literal() -> None:
    """A one-value enum has nothing to slot; leaves equal to the value stay literal."""
    result = codec.infer_write("enum", [(0, _rec(0, "0"))], [(0, _rec(0, "0", ALT))], 3, ALT)
    assert result.access == "rw"
    assert result.form == "fixed"
    assert result.write == {
        "cmd": 1000,
        "params": {"channel": "$channel", "x": 0},
        "update": {"cmd": 1000, "paramValue": "0"},
    }


def test_no_recipe_at_all_is_read_only() -> None:
    result = codec.infer_write(
        "bool", [(False, None), (True, None)], [(False, None), (True, None)], 3, ALT
    )
    assert (result.access, result.note) == ("ro", "no handler write path")


def test_recipe_for_only_some_values_is_read_only() -> None:
    result = codec.infer_write(
        "bool",
        [(False, None), (True, _rec(1))],
        [(False, None), (True, _rec(1, None, ALT))],
        3,
        ALT,
    )
    assert (result.access, result.note) == ("ro", "handler rejects some values")


def test_channel_slot_needs_the_leaf_to_follow_the_channel() -> None:
    """A leaf is ``$channel`` only when it holds the channel on both sweeps."""
    follows = codec.infer_write(
        "range",
        _pairs([1, 2], lambda v, ch: _rec(v, None, ch)),
        _pairs([1, 2], lambda v, ch: _rec(v, None, ch), ALT),
        3,
        ALT,
    )
    assert follows.write["params"]["channel"] == "$channel"
    fixed = codec.infer_write(
        "range",
        _pairs([1, 2], lambda v, ch: _rec(v, None, 3)),
        _pairs([1, 2], lambda v, ch: _rec(v, None, 3), ALT),
        3,
        ALT,
    )
    assert fixed.write["params"]["channel"] == 3


def test_channel_slot_found_in_a_recipe_the_other_context_lacks() -> None:
    """The channel is found within one context, whatever another context sends."""

    def build(v: int, ch: int) -> dict[str, Any]:
        return {"cmd": 1350, "params": {"sensitivity": v, "channel": ch}}

    result = codec.infer_write("range", _pairs([1, 2], build), _pairs([1, 2], build, ALT), 3, ALT)
    assert result.write == {"cmd": 1350, "params": {"sensitivity": "$v", "channel": "$channel"}}


def test_serial_inside_a_longer_string_is_read_only() -> None:
    embedded = f"{CHILD_SN}_suffix"
    result = codec.infer_write(
        "bool",
        _pairs([False, True], lambda v, ch: {"cmd": 1, "params": {"id": embedded, "x": v}}),
        _pairs([False, True], lambda v, ch: {"cmd": 1, "params": {"id": embedded, "x": v}}, ALT),
        3,
        ALT,
    )
    assert (result.access, result.note) == ("ro", "serial embedded in a string")


def _reads(rows: list[tuple[Any, Any, Any, Any]]) -> list[Any]:
    """Read samples ``(written value, update.cmd, update.paramValue, decoded)``."""
    return [codec.ReadSample(*row) for row in rows]


ROUND_TRIP_NOTE = "round trip does not return the written value"


def test_read_identity_when_param_value_is_the_value() -> None:
    read, note = codec.infer_read(
        "range", _reads([(5, 1249, "5", "5"), (60, 1249, "60", 60), (120, 1249, "120", "120")])
    )
    assert (read, note) == ({"param": 1249, "map": None}, None)


def test_read_identity_for_bools_uses_the_int_form() -> None:
    read, _ = codec.infer_read("bool", _reads([(False, 7, "0", "false"), (True, 7, "1", 1)]))
    assert read == {"param": 7, "map": None}


def test_read_map_from_param_value_to_public_value() -> None:
    """An enum whose wire value differs from the public value (UI 3 = wire 2)."""
    read, note = codec.infer_read(
        "enum", _reads([(0, 1246, "0", 0), (1, 1246, "1", 1), (3, 1246, "2", 3)])
    )
    assert read == {"param": 1246, "map": {"0": 0, "1": 1, "2": 3}}
    assert note is None


def test_read_map_of_an_inverted_bool_inverts_too() -> None:
    read, _ = codec.infer_read("bool", _reads([(False, 1251, "1", False), (True, 1251, "0", True)]))
    assert read == {"param": 1251, "map": {"1": False, "0": True}}


def test_read_map_of_scaled_enum_values() -> None:
    read, _ = codec.infer_read(
        "enum", _reads([(0, 1230, "90", 0), (1, 1230, "95", 1), (2, 1230, "100", 2)])
    )
    assert read == {"param": 1230, "map": {"90": 0, "95": 1, "100": 2}}


def test_range_read_that_is_not_the_identity_is_null() -> None:
    read, note = codec.infer_read("range", _reads([(1, 9, "10", 1), (2, 9, "20", 2)]))
    assert read is None
    assert note == "range read is not the identity"


def test_read_missing_for_a_value_is_null() -> None:
    read, note = codec.infer_read("bool", _reads([(False, 7, "0", False), (True, 7, "1", None)]))
    assert (read, note) == (None, ROUND_TRIP_NOTE)
    read, note = codec.infer_read("bool", _reads([(False, 7, "0", codec.MISSING)]))
    assert (read, note) == (None, ROUND_TRIP_NOTE)


def test_read_decoding_to_another_value_is_null() -> None:
    read, note = codec.infer_read("enum", _reads([(0, 7, "0", 0), (1, 7, "1", 0)]))
    assert (read, note) == (None, ROUND_TRIP_NOTE)


def test_read_with_differing_update_cmd_is_null() -> None:
    read, note = codec.infer_read("enum", _reads([(0, 7, "0", 0), (1, 8, "1", 1)]))
    assert (read, note) == (None, ROUND_TRIP_NOTE)


def test_read_without_write_samples_is_null_without_note() -> None:
    assert codec.infer_read("enum", []) == (None, None)


MODELS = ROOT / "src" / "eufy_home_security" / "devices" / "data" / "models"


def test_generated_t8160_read_codecs_invert_the_write_maps() -> None:
    """Wire 2 reads as public 3, an inverted flag reads inverted, 90/95/100 read as 0/1/2;
    an empty value reads as the handler decodes it."""
    settings = json.loads((MODELS / "T8160.json").read_text(encoding="utf-8"))["settings"]
    assert settings["power_manager_mode"]["read"] == {
        "param": 1246,
        "map": {"": 0, "0": 0, "1": 1, "2": 3},
    }
    assert settings["motion_stop_end_early"]["read"] == {
        "param": 1251,
        "map": {"": False, "0": True, "1": False},
    }
    assert settings["speaker_volume"]["read"] == {
        "param": 1230,
        "map": {"": 1, "90": 0, "95": 1, "100": 2},
    }
    assert settings["video_clip_length"]["read"] == {"param": 1249, "map": None}
    assert settings["trigger_interval_time"]["read"] == {"param": 1250, "map": None}


def test_dump_sorts_keys_but_keeps_recipe_order() -> None:
    doc = {"b": 1, "a": {"write": {"z": 1, "a": {"y": 2, "b": 3}}, "kind": "bool"}}
    text = codec.dump(doc)
    assert text.endswith("\n")
    assert list(json.loads(text)) == ["a", "b"]
    assert list(json.loads(text)["a"]) == ["kind", "write"]
    assert list(json.loads(text)["a"]["write"]) == ["z", "a"]
    assert list(json.loads(text)["a"]["write"]["a"]) == ["y", "b"]


def _rw(write: Any, **extra: Any) -> dict[str, Any]:
    return {"kind": "enum", "access": "rw", "write": write, **extra}


def test_render_value_slots_and_their_type_tags() -> None:
    setting = _rw({"cmd": 1, "params": {"a": "$v", "b": "$v:str", "c": "$v:int"}})
    assert codec.render(setting, 7, channel=3) == {
        "cmd": 1,
        "params": {"a": 7, "b": "7", "c": 7},
    }
    assert codec.render(setting, "7", channel=3)["params"] == {
        "a": "7",
        "b": "7",
        "c": 7,
    }


def test_render_bool_value_tags_use_zero_and_one() -> None:
    setting = {"kind": "bool", "access": "rw", "write": {"p": ["$v", "$v:str", "$v:int"]}}
    assert codec.render(setting, True, channel=3) == {"p": [True, "1", 1]}


def test_render_map_and_unmapped_value() -> None:
    setting = _rw({"mode": {"$map": {"0": 0, "3": 2}}})
    assert codec.render(setting, 3, channel=3) == {"mode": 2}
    flag = {"kind": "bool", "access": "rw", "write": {"f": {"$map": {"false": 1, "true": 0}}}}
    assert codec.render(flag, False, channel=3) == {"f": 1}
    with pytest.raises(ValueError, match="not in \\$map"):
        codec.render(setting, 1, channel=3)


def test_render_affine_gives_an_int_when_integral() -> None:
    setting = {
        "kind": "range",
        "access": "rw",
        "write": {"x": {"$affine": [10, 5]}, "y": {"$affine": [0.5, 0]}},
    }
    out = codec.render(setting, 3, channel=3)
    assert out == {"x": 35, "y": 1.5}
    assert isinstance(out["x"], int)


def test_render_channel_and_serial_slots() -> None:
    setting = _rw({"ch": "$channel", "sn": "$device_sn", "st": "$station_sn", "v": "$v"})
    assert codec.render(setting, 1, channel=1) == {
        "ch": 1,
        "sn": "$device_sn",
        "st": "$station_sn",
        "v": 1,
    }
    assert codec.render(setting, 1, channel=0, device_sn="SN-A", station_sn="SN-B") == {
        "ch": 0,
        "sn": "SN-A",
        "st": "SN-B",
        "v": 1,
    }


def test_render_fixed_recipe_is_returned_as_is() -> None:
    setting = _rw({"cmd": 9, "params": {"mode": 4}})
    assert codec.render(setting, 4, channel=3) == {"cmd": 9, "params": {"mode": 4}}


def test_render_picks_the_write_table_before_the_write() -> None:
    table = {"1": {"cmd": 1}, "2": {"cmd": 2, "params": {"v": "$v"}}}
    setting = _rw({"cmd": 0}, write_table=table)
    assert codec.render(setting, 2, channel=0) == {"cmd": 2, "params": {"v": 2}}
    with pytest.raises(ValueError, match="not in the write table"):
        codec.render(setting, 3, channel=3)
    plain = _rw({"cmd": 0, "c": "$channel"})
    assert codec.render(plain, 1, channel=3) == {"cmd": 0, "c": 3}


@pytest.mark.parametrize(
    "write",
    [{"x": "$value"}, {"x": {"$scale": 2}}, {"x": {"$map": {}, "$affine": [1, 0]}}],
)
def test_render_rejects_unknown_placeholders(write: dict[str, Any]) -> None:
    with pytest.raises(ValueError, match="unknown placeholder"):
        codec.render(_rw(write), 1, channel=3)


def test_render_rejects_read_only_settings() -> None:
    with pytest.raises(ValueError, match="read-only"):
        codec.render({"kind": "bool", "access": "ro"}, True, channel=3)


def test_coerce_turns_int_payloads_of_bool_settings_into_bools() -> None:
    assert codec.coerce({"kind": "bool"}, 1) is True
    assert codec.coerce({"kind": "bool"}, 0) is False
    assert codec.coerce({"kind": "enum"}, 1) == 1
    with pytest.raises(ValueError, match="not a bool payload"):
        codec.coerce({"kind": "bool"}, 2)
