"""The settings generator reads a status the handler builds as an object of booleans, one
per bit of its parameter, as a read-only ``flags`` setting (scripts/gen_models.py,
``flag_members`` / ``flags_reads``).

The generate cases run a synthetic handler through the real driver, so they need Node.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from collections.abc import Callable, Iterator, Mapping
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


gen_models = _load("gen_models")
joiner = _load("gen_models_join")

PN = "T9ZZ8"  # a product code named nowhere in the library
MEMBERS = ["alarm", "test", "battery", "high"]  # bits 0, 1, 2, 7 in the handlers below
BITS = {"alarm": 1, "test": 2, "battery": 4, "high": 128}
PROBE_BITS: int = gen_models.FLAG_PROBE_BITS


def _struct(mask: int, members: dict[str, int] = BITS) -> dict[str, bool]:
    return {m: bool(mask & bit) for m, bit in members.items()}


class _Answers(Mapping[int, Any]):
    """getProperty's value at any held mask, as ``read`` gives it."""

    def __init__(self, read: Callable[[int], Any]) -> None:
        self._read = read

    def __getitem__(self, mask: int) -> Any:
        return self._read(mask)

    def __iter__(self) -> Iterator[int]:
        return iter([0, *(1 << k for k in range(PROBE_BITS))])

    def __len__(self) -> int:
        return PROBE_BITS + 1


def _answers(read: Callable[[int], Any] = _struct) -> Mapping[int, Any]:
    return _Answers(read)


def _repeated(mask: int) -> str:
    """The struct's JSON text with ``alarm`` named twice, both times with its value."""
    struct = _struct(mask)
    return json.dumps(struct)[:-1] + ', "alarm": ' + json.dumps(struct["alarm"]) + "}"


def test_a_struct_with_one_member_per_bit_gives_each_members_bit() -> None:
    assert gen_models.flag_members(_answers()) == BITS


def test_the_struct_may_come_as_its_json_text() -> None:
    answers = _answers(lambda m: json.dumps(_struct(m)))
    assert gen_models.flag_members(answers) == BITS


@pytest.mark.parametrize(
    "read",
    [
        lambda m: {**_struct(m), "never": False},  # a member no bit turns on
        lambda m: {**_struct(m), "level": m},  # a member that is no boolean
        lambda m: {**_struct(m), "level": m & 8},  # a number on for one bit
        lambda m: {**_struct(m), "alarm": bool(m & 1), "any": bool(m & 3)},  # on for two bits
        lambda m: {**_struct(m), "test": bool(m & 6)},  # a member on for two bits
        lambda m: {**_struct(m), "battery": bool(m & 4), "low": bool(m & 4)},  # two per bit
        lambda m: {**_struct(m), "idle": not m},  # on at 0
        lambda m: {**_struct(m), "test": bool(m & 2) or not m},  # on at 0 and for its bit
        lambda m: {**_struct(m), "low": bool(m & 12)},  # on with another member's bit too
        lambda m: {"alarm": bool(m & 1), "test": bool(m & 6), "high": bool(m & 128)},  # 2 bits
        lambda m: {k: v for k, v in _struct(m).items() if (m, k) != (4, "high")},  # one gone
        lambda m: (
            _struct(m)
            if m != sum(BITS.values())
            else dict.fromkeys(["alarm", "test", "battery"], True)
        ),  # a member gone at the OR of the bits
        lambda m: {m_: m == bit for m_, bit in BITS.items()},  # equal to a bit, no mask
        lambda m: _struct(m) if m else {"alarm": False},  # members change with the value
        lambda m: m,  # a number
        lambda m: {},  # an empty object
        _repeated,  # a member named twice
        lambda m: "[true]",  # a list text
        lambda m: "not json",
    ],
)
def test_any_other_answer_is_no_flags_read(read: Any) -> None:
    assert gen_models.flag_members(_answers(read)) is None


def test_a_missing_answer_is_no_flags_read() -> None:
    answers = {mask: _struct(mask) for mask in _answers()}  # the OR of the members not asked
    assert gen_models.flag_members(answers) is None
    assert gen_models.flag_members({**answers, 135: _struct(135)}) == BITS


# A handler shaped like the smoke sensors': getProperty parses a status from its command
# parameter into the JSON text of an object of booleans, one per bit. smoke (TD string,
# 1823) and listener (TD bool, 1824) are such masks; equal (1825) compares the value with
# each bit; partial (1826) has a member no bit sets; wide (1827) carries the number too.
HANDLER = """
function parse(s) { return JSON.parse(s.slice(0, s.lastIndexOf("EOF;"))); }
function bits(v) {
  const b = parseInt(v, 10) || 0;
  return { alarm: !!(b & 1), test: !!(b & 2), battery: !!(b & 4), high: !!(b & 128) };
}
module.exports.controlDevice = function (s) { return JSON.stringify({ data: {} }); };
module.exports.deviceStatus = function (s) {
  const m = parse(s);
  const cmds = m.input.commandId || [];
  const out = {};
  for (const p of m.device.params || []) {
    if (cmds.indexOf(p.param_type) < 0) continue;
    const v = p.param_value;
    const b = parseInt(v, 10) || 0;
    if (p.param_type === 1823) out.smoke = JSON.stringify(bits(v));
    if (p.param_type === 1824) out.listener = JSON.stringify(bits(v));
    if (p.param_type === 1825) out.equal = JSON.stringify({ alarm: b === 1, test: b === 2 });
    if (p.param_type === 1826) out.partial = JSON.stringify({ ...bits(v), never: false });
    if (p.param_type === 1827) out.wide = JSON.stringify({ ...bits(v), level: b });
  }
  return JSON.stringify({ data: { p2p: out } });
};
"""


def _prop(ident: str, data_type: dict[str, Any]) -> dict[str, Any]:
    return {"identifier": ident, "access_mode": "R", "data_type": data_type}


PROPS = [
    _prop("smoke", {"type": "text"}),
    _prop("listener", {"type": "bool", "specs": {"defaultValue": "false"}}),
    _prop("equal", {"type": "text"}),
    _prop("partial", {"type": "text"}),
    _prop("wide", {"type": "text"}),
]
TITLES: dict[str, Any] = {
    "flag_meanings": {
        "smoke": {
            "members": {"alarm": "smoke", "high": "smoke", "test": "testing", "gone": "muted"},
            "source": "card",
        },
        "equal": {"members": {"alarm": "smoke"}, "source": "card"},
    }
}

needs_node = pytest.mark.needs_node


@pytest.fixture(scope="module")
def generated(tmp_path_factory: pytest.TempPathFactory) -> dict[str, Any]:
    cache = tmp_path_factory.mktemp("cache")
    folder = cache / PN
    folder.mkdir()
    td = {
        "large_version": 3,
        "profile": {"plugin_path": f"https://cdn.example/p/2024/05/06/x/{PN}Handle.mix.js"},
        "properties": PROPS,
    }
    (folder / "td.json").write_text(json.dumps(td), encoding="utf-8")
    (folder / f"{PN}Handle.mix.js").write_text(HANDLER, encoding="utf-8")
    doc: dict[str, Any] = gen_models.generate(PN, cache, titles=TITLES)[0]
    return doc


@needs_node
@pytest.mark.timeout(120)
def test_a_status_built_from_the_bits_of_its_parameter_is_a_read_only_flags_setting(
    generated: dict[str, Any],
) -> None:
    entry = generated["settings"]["smoke"]
    assert (entry["kind"], entry["access"]) == ("flags", "ro")
    assert entry["flags"] == BITS
    assert entry["read"] == {"param": 1823, "map": None, "no_default": True}
    assert "contexts" not in entry


@needs_node
@pytest.mark.timeout(120)
def test_the_handlers_mask_wins_over_a_bool_the_description_declares(
    generated: dict[str, Any],
) -> None:
    entry = generated["settings"]["listener"]
    assert (entry["kind"], entry["flags"], entry["read"]["param"]) == ("flags", BITS, 1824)
    assert "default" not in entry  # the description's false is no mask


@needs_node
@pytest.mark.timeout(120)
@pytest.mark.parametrize("ident", ["equal", "partial", "wide"])
def test_a_struct_that_is_no_mask_of_its_parameter_stays_unreadable(
    generated: dict[str, Any], ident: str
) -> None:
    entry = generated["settings"][ident]
    assert (entry["kind"], entry["read"]) == ("string", None)
    assert "flags" not in entry
    assert "flag_meanings" not in entry


@needs_node
@pytest.mark.timeout(120)
def test_member_meanings_come_from_the_app_input_for_the_members_present(
    generated: dict[str, Any],
) -> None:
    assert generated["settings"]["smoke"]["flag_meanings"] == {
        "alarm": "smoke",
        "high": "smoke",
        "test": "testing",
    }
    assert "flag_meanings" not in generated["settings"]["listener"]  # no rule names it


def test_member_meanings_skip_a_setting_that_is_no_flags_mask() -> None:
    settings: dict[str, Any] = {"equal": {"kind": "string"}}
    counts: dict[str, int] = {}
    joiner._flag_meanings(PN, settings, TITLES, counts)
    assert settings == {"equal": {"kind": "string"}}
    assert counts == {"flag meaning:not a flags setting": 1}


@pytest.mark.parametrize(
    "members",
    [
        {"alarm": "duration"},  # not a binary meaning
        {"alarm": "no_such_meaning"},
        {},  # names no member
        ["alarm"],  # not an object
    ],
)
def test_a_bad_member_meaning_rule_fails_the_model(members: Any) -> None:
    settings: dict[str, Any] = {"smoke": {"kind": "flags", "flags": dict(BITS)}}
    titles = {"flag_meanings": {"smoke": {"members": members, "source": "card"}}}
    with pytest.raises(gen_models.GeneratorError, match="smoke"):
        joiner._flag_meanings(PN, settings, titles, {})
