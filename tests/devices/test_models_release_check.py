"""The bundled models' write codecs reproduce the frozen v1 wire recipes.

Each row of ``tests/fixtures/models_v1_reference.json`` is rendered with its model's codec
in the context and channel it was recorded in; cmd, subCmd and params must equal the
recorded recipe, unless ``gen_models.RELEASE_ACCEPTED`` names the (PN, identifier).
Needs only committed files: the renderer and the accepted list are loaded from
``scripts/`` by path, and nothing of the library is imported.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]
MODELS = ROOT / "src" / "eufy_home_security" / "devices" / "data" / "models"
REFERENCE = json.loads(
    (ROOT / "tests" / "fixtures" / "models_v1_reference.json").read_text(encoding="utf-8")
)
FIELDS = ("cmd", "subCmd", "params")


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


codec = _load("gen_models_codec")
gen_models = _load("gen_models")
ACCEPTED: dict[tuple[str, str], str] = gen_models.RELEASE_ACCEPTED


def _settings(product_code: str, context: str | None = None) -> dict[str, Any]:
    """The file's entries as ``context`` sees them (None: the base context)."""
    doc = json.loads((MODELS / f"{product_code}.json").read_text(encoding="utf-8"))
    settings: dict[str, Any] = {}
    for key, entry in doc["settings"].items():
        out = {k: v for k, v in entry.items() if k != "contexts"}
        for item in entry.get("contexts", []) if context is not None else ():
            if context in item["names"]:
                out.update(item["entry"])
                out = {k: v for k, v in out.items() if v is not None}
        settings[key] = out
    return settings


def _canon(x: Any) -> str:
    """JSON text that tells ``1``, ``1.0`` and ``true`` apart."""
    return json.dumps(x, sort_keys=True)


def _render(row: dict[str, Any]) -> dict[str, Any]:
    """The row's recipe as its bundled setting renders it, the payload restated in the
    shaped form the way the generator's check does."""
    settings = _settings(row["product_code"], _context(row))
    setting = settings[gen_models.reference_key(settings, row["identifier"])]
    value = gen_models.controls.reference_value(setting, row)
    if setting.get("kind") != "flags" and setting.get("bit") is None:
        value = codec.coerce(setting, value)
    recipe = codec.render(setting, value, channel=row["channel"])
    return {k: recipe[k] for k in FIELDS if k in recipe}


def _context(row: dict[str, Any]) -> str | None:
    """A row's context in the file: ``child`` rows are the base, ``standalone`` its own."""
    return "standalone" if row["context"] == "standalone" else None


def _standalone_rows(item: dict[str, Any]) -> dict[Any, dict[str, Any]]:
    """The standalone channel-0 reference rows of a hardware item, by payload."""
    key = (item["product_code"], item["identifier"])
    return {
        r["payload"]: r
        for r in REFERENCE["rows"]
        if (r["product_code"], r["identifier"]) == key
        and (r["context"], r["channel"]) == ("standalone", 0)
    }


def _mismatches() -> set[tuple[str, str]]:
    out = set()
    for row in REFERENCE["rows"]:
        want = {k: row["recipe"][k] for k in FIELDS if k in row["recipe"]}
        try:
            got: Any = _render(row)
        except (KeyError, ValueError) as err:
            got = repr(err)
        if _canon(got) != _canon(want):
            out.add((row["product_code"], row["identifier"]))
    return out


def test_every_v1_setting_exists_in_the_bundled_models() -> None:
    """Each v1 key is bundled, or absorbed by the key it duplicated."""
    pairs = {(r["product_code"], r["identifier"]) for r in REFERENCE["rows"]}
    pairs |= {(h["product_code"], h["identifier"]) for h in REFERENCE["hardware"]}
    assert len(pairs) == 34
    assert sorted(p for p in pairs if gen_models.reference_key(_settings(p[0]), p[1]) is None) == []
    assert {
        p: gen_models.reference_key(_settings(p[0]), p[1])
        for p in pairs
        if p[1] not in _settings(p[0])
    } == {}


def test_mismatching_rows_are_exactly_the_accepted_list() -> None:
    """All 136 rows render to their recorded cmd/subCmd/params; the accepted list is empty."""
    assert len(REFERENCE["rows"]) == 136
    assert _mismatches() == set(ACCEPTED)
    assert all(reason.strip() for reason in ACCEPTED.values())


def test_generator_and_test_share_one_comparison() -> None:
    """The generator's own reference check finds the same mismatches as this test."""
    by_model: dict[str, list[dict[str, Any]]] = {}
    for row in REFERENCE["rows"]:
        by_model.setdefault(row["product_code"], []).append(row)
    found = {
        (pn, ident)
        for pn, rows in by_model.items()
        for context in (None, "standalone")
        for ident, _ in gen_models.reference_mismatches(
            _settings(pn, context), [r for r in rows if _context(r) == context]
        )
    }
    assert found == _mismatches()


@pytest.mark.parametrize(
    "item", REFERENCE["hardware"], ids=lambda h: f"{h['product_code']}-{h['identifier']}"
)
def test_hardware_rows_render_their_command_id(item: dict[str, Any]) -> None:
    """A hardware-proven setting is rw, and each proven payload renders to its command id.

    ``payloads`` are handler (public) values; ``wire_values`` are the values on the wire, so for
    detection_sensitivity and live_streaming_resolution they differ from the payloads.
    """
    key = (item["product_code"], item["identifier"])
    setting = _settings(item["product_code"], "standalone")[item["identifier"]]
    assert setting["access"] == "rw"
    rows = _standalone_rows(item)
    for payload in item["payloads"]:
        recipe = _render(rows[payload])
        if key in ACCEPTED:
            continue
        assert recipe.get("subCmd", recipe["cmd"]) == item["command_id"]
        assert _canon(recipe["params"]) == _canon(rows[payload]["recipe"]["params"])


def test_hardware_wire_values_are_what_the_payloads_render_to() -> None:
    """The hardware-proven wire values are exactly the values the proven payloads put in params.

    The two lists pair as sets, not by position (live_streaming_resolution 1 sends 3).
    """
    for item in REFERENCE["hardware"]:
        wires = set(item["wire_values"])
        sent = set()
        rows = _standalone_rows(item)
        for payload in item["payloads"]:
            params = _render(rows[payload])["params"]
            hits = [v for v in params.values() if v in wires and not isinstance(v, bool)]
            assert hits, (item["identifier"], payload, params)
            sent.update(hits)
        assert sent == wires, item["identifier"]
