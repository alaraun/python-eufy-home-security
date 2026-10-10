"""The runtime encoder agrees with the generator's renderer.

For the four reference models, every rw setting and every value of its domain renders
through :meth:`Setting.encode` to what ``scripts/gen_models_codec.render`` gives, in
every context the file resolves (base, standalone, each station kind); a value the
renderer refuses, the runtime refuses too. The v1 reference rows encode to their recorded cmd/subCmd/params. The
scripts are loaded by path, so ``src/`` never imports them.
"""

from __future__ import annotations

import importlib.util
import json
import sys
from collections.abc import Mapping
from dataclasses import replace
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

from eufy_home_security.devices.model_settings import (
    Setting,
    SettingKind,
    Value,
    WireCommand,
    WriteContext,
    WritePath,
    settings_of,
)
from eufy_home_security.devices.recipes import ConnectType
from eufy_home_security.exceptions import UnsupportedError
from eufy_home_security.p2p.messages import is_ecb_scalar

ROOT = Path(__file__).resolve().parents[2]
MODELS_DIR = ROOT / "src" / "eufy_home_security" / "devices" / "data" / "models"
REFERENCE = json.loads(
    (ROOT / "tests" / "fixtures" / "models_v1_reference.json").read_text(encoding="utf-8")
)
MODELS = ("T8030", "T8160", "T8170", "T8910")
MAX_RANGE_POINTS = 41
PARAM_VALUE = "12"  # the value every ``$param`` leaf's parameter holds in these checks


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


def _entries(product_code: str, context: str | None = None) -> dict[str, Any]:
    """The file's entries as ``context`` sees them (None: the base)."""
    doc = json.loads((MODELS_DIR / f"{product_code}.json").read_text(encoding="utf-8"))
    entries: dict[str, Any] = {}
    for key, entry in doc["settings"].items():
        out = {k: v for k, v in entry.items() if k != "contexts"}
        for item in entry.get("contexts", []) if context is not None else ():
            if context in item["names"]:
                for k, v in item["entry"].items():
                    if v is None:
                        out.pop(k, None)
                    else:
                        out[k] = v
        entries[key] = out
    return entries


def _contexts(product_code: str) -> list[tuple[str | None, Any, Mapping[str, Setting]]]:
    """``(context name, generator context, runtime settings)`` for every context."""
    out: list[tuple[str | None, Any, Mapping[str, Setting]]] = [
        (None, codec.CHILD, settings_of(product_code)),
        (
            "standalone",
            codec.standalone_context(product_code),
            settings_of(product_code, standalone=True),
        ),
    ]
    out.extend(
        (c.value, codec.child_context(c.value), settings_of(product_code, c))
        for c in ConnectType
        if c is not ConnectType.SINGLE
    )
    return out


def _canon(x: Any) -> str:
    """JSON text that tells ``1``, ``1.0`` and ``true`` apart."""
    return json.dumps(x, sort_keys=True)


def _domain(setting: Setting) -> list[Value]:
    """The swept values: enum values, both bools, range points (both ends kept), a probe."""
    if setting.domain is not None:
        return [setting.values[0], "Europe/Tallinn", setting.values[-1]]
    match setting.kind:
        case SettingKind.ENUM:
            return list(setting.values)
        case SettingKind.BOOL if setting.bit is not None:
            # A shared bit renders the whole mask: off, the bit alone, the bit among others.
            return [0, setting.bit, setting.bit | 0x5A5]
        case SettingKind.BOOL:
            return [False, True]
        case SettingKind.FLAGS:
            bits = list(setting.flags.values())
            every = 0
            for b in bits:
                every |= b
            return [0, *bits, every]
        case SettingKind.RANGE:
            lo, hi, step = setting.minimum, setting.maximum, setting.step or 1
            assert lo is not None
            assert hi is not None
            n = round((hi - lo) / step) + 1
            stride = max(1, -(-n // MAX_RANGE_POINTS))
            points = {lo + i * step for i in range(0, n, stride)} | {hi}
            return [codec.intify(round(p, 9)) for p in sorted(points)]
        case SettingKind.STRING:
            return ["probe"]
        case _:
            return [0, 1]


def _params(setting: Setting) -> dict[int, str]:
    return dict.fromkeys(setting.write_params, PARAM_VALUE)


def _context(ctx: Any, setting: Setting) -> WriteContext:
    return WriteContext(
        standalone=ctx.name == codec.STANDALONE.name,
        channel=ctx.channel,
        device_sn=ctx.device_sn,
        station_sn=ctx.station_sn,
        params=_params(setting),
    )


def _wire_of(recipe: dict[str, Any]) -> tuple[int, Any]:
    """The id the session sends and the rendered body, from a renderer recipe."""
    sub = recipe.get("subCmd")
    return (
        sub if recipe["cmd"] in (1350, 1700) and sub is not None else recipe["cmd"]
    ), recipe.get("params")


def _updates(recipe: dict[str, Any]) -> list[tuple[int, str]]:
    out = []
    items = [recipe.get("update"), *(recipe.get("extUpdates") or [])]
    for i, item in enumerate(items):
        if not isinstance(item, dict) or item.get("paramValue") is None:
            continue
        if i == 0 and not item.get("needUpdate"):
            continue
        value = item["paramValue"]
        out.append((item["cmd"], str(int(value)) if isinstance(value, bool) else str(value)))
    return out


def _check(setting: Setting, entry: dict[str, Any], value: Value, ctx: Any) -> None:
    wctx = _context(ctx, setting)
    if setting.domain is not None:
        _check_domain(setting, entry, value, ctx)
        return
    try:
        want = codec.render(
            entry,
            value,
            channel=ctx.channel,
            device_sn=ctx.device_sn,
            station_sn=ctx.station_sn,
            params=_params(setting),
        )
    except ValueError:
        with pytest.raises((ValueError, UnsupportedError)):
            setting.encode(value, wctx)
        return
    if setting.write_params and setting.bit is None:
        with pytest.raises(ValueError, match="is not reported"):
            setting.encode(value, replace(wctx, params={}))
    if setting.bit is not None:
        with pytest.raises(ValueError, match="shares its parameter"):
            setting.encode(True, wctx)
        wire: WireCommand = setting.encode_mask(int(value), wctx)
    else:
        wire = setting.encode(value, wctx)
    cmd, params = _wire_of(want)
    assert wire.cmd == cmd
    body = params if isinstance(params, dict) else None
    assert _canon(wire.params) == _canon(body)
    if wire.path is WritePath.ECB:
        scalar: Any = params
        if body is not None:
            template = codec.write_template(entry, value)["params"]
            fields = [v for k, v in body.items() if template[k] != "$channel"]
            assert len({json.dumps(v) for v in fields}) == 1
            scalar = fields[0]
        assert wire.value == int(scalar)
    else:
        assert wire.value is None
        if wire.path is WritePath.DIRECT and is_ecb_scalar(cmd) and body is not None:
            # An ECB command id goes DIRECT only when its body is not one scalar.
            values = {json.dumps(v) for k, v in body.items() if k != "channel"}
            assert len(values) > 1
    assert [list(u) for u in wire.updates] == [list(u) for u in _updates(want)]
    public = value if setting.bit is not None else setting.validate(value)
    assert _canon(setting._render_recipe(public, wctx)) == _canon(want)


def _check_domain(setting: Setting, entry: dict[str, Any], value: Value, ctx: Any) -> None:
    """A domain setting sends the handler's command as a string frame carrying the
    device form of ``value``, and the handler's updates for that device form."""
    wire = setting.encode(value, _context(ctx, setting))
    want = codec.render(
        entry,
        wire.text,
        channel=ctx.channel,
        device_sn=ctx.device_sn,
        station_sn=ctx.station_sn,
    )
    assert wire.path is WritePath.STRING
    assert (wire.cmd, wire.params, wire.value) == (want["cmd"], None, None)
    assert [list(u) for u in wire.updates] == [list(u) for u in _updates(want)]
    assert setting.decode(wire.text) == value


@pytest.mark.parametrize("product_code", MODELS)
def test_runtime_encode_matches_the_renderer(product_code: str) -> None:
    checked = 0
    for name, ctx, settings in _contexts(product_code):
        entries = _entries(product_code, name)
        assert set(settings) == set(entries)
        for key, setting in settings.items():
            if not setting.writable:
                continue
            for value in _domain(setting):
                _check(setting, entries[key], value, ctx)
                checked += 1
    assert checked > 0


@pytest.mark.parametrize("product_code", MODELS)
def test_refused_settings_are_rw_in_the_file(product_code: str) -> None:
    """Every rw entry is writable unless the runtime names the transport it does not send."""
    for name, _, settings in _contexts(product_code):
        entries = _entries(product_code, name)
        for key, setting in settings.items():
            assert setting.writable <= (entries[key]["access"] == "rw")
            if entries[key]["access"] == "rw" and not setting.writable:
                assert setting.note, key


def test_v1_reference_rows_encode_identically() -> None:
    rows = [
        r
        for r in REFERENCE["rows"]
        if (r["product_code"], r["identifier"]) not in gen_models.RELEASE_ACCEPTED
    ]
    assert len(rows) == 136
    for row in rows:
        alone = row["context"] == codec.STANDALONE.name
        context = "standalone" if alone else None
        key = gen_models.reference_key(_entries(row["product_code"]), row["identifier"])
        entry = _entries(row["product_code"], context)[key]
        setting = settings_of(row["product_code"], standalone=alone)[key]
        ctx = WriteContext(
            standalone=alone,
            channel=row["channel"],
            device_sn="$device_sn",
            station_sn="$station_sn",
            params=_params(setting),
        )
        shaped = gen_models.controls.reference_value(entry, row)
        if setting.bit is not None:
            value = shaped
            wire = setting.encode_mask(value, ctx)
        else:
            value = setting.validate(
                codec.coerce(entry, shaped) if entry["kind"] != "flags" else shaped
            )
            wire = setting.encode(value, ctx)
        got = setting._render_recipe(value, ctx)
        fields = gen_models.RECIPE_FIELDS
        want = {k: row["recipe"][k] for k in fields if k in row["recipe"]}
        assert _canon({k: got[k] for k in fields if k in got}) == _canon(want), row
        cmd, params = _wire_of(row["recipe"])
        assert wire.cmd == cmd
        assert _canon(wire.params) == _canon(params if isinstance(params, dict) else None)
