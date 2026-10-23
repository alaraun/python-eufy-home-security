"""Generate ``devices/_device_alarm_data.py``: each product's own siren and light, as its handler sends them.

For every cached product whose thing description declares ``set_alarm_type`` (or a
``__v<n>`` form of it), the vendor handler runs offline (``scripts/gen_models_driver.js``,
Node) standalone and behind each station kind of ``PARENT_CONNECT_TYPES``, on two
channels. Per connect type the generator picks the identifier the app reads there (the
``__v`` form whose ``read_conditions`` pass with the most conditions, else the base;
``parent_sn``/``device_sn`` pattern conditions are evaluated on synthetic serials of the
product's and the station's prefix, any other condition does not pass), and records for
each choice of its enum except the HomeBase alarm (:data:`HOMEBASE_CHOICE`) the request
the handler builds to start (``open`` true) and to stop it (``open`` false): the command
(``subCmd`` of a 1350 wrapper, else ``cmd``) and ``params`` with the channel and the
nickname as slots. A choice is recorded only when both requests use a command of
:data:`ALARM_COMMANDS` with the same fields; a connect type without one is left out. The
default is the enum's default choice when recorded, else the first. Runs on a maintainer
host only; nothing at runtime executes vendor code.

    gen_device_alarm.py [--cache DIR] [--out FILE] [--check]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess
import sys
from collections.abc import Mapping, Sequence
from dataclasses import replace
from pathlib import Path
from types import ModuleType
from typing import Any

from eufy_home_security.devices.device_alarm import (
    ALARM_COMMANDS,
    ALARM_IDENTIFIER,
    CHANNEL_SLOT,
    HOMEBASE_CHOICE,
    USER_NAME_SLOT,
)
from eufy_home_security.devices.recipes import PARENT_CONNECT_TYPES, ConnectType

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CACHE = ROOT / ".work" / "cache" / "things_all"
DEFAULT_OUT = ROOT / "src" / "eufy_home_security" / "devices" / "_device_alarm_data.py"
NICKNAME = "nickname-probe"  # the app's ``nick_name``; becomes USER_NAME_SLOT
WRAPPER = 1350  # the handler's SET_PAYLOAD wrapper: the library sends its subCmd
_VARIANT = re.compile(r"__v\d+$")
_PATTERN_TYPES = frozenset({"parent_sn", "device_sn"})


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    if spec is None or spec.loader is None:
        raise ImportError(f"scripts/{name}.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gen_models = _load("gen_models")
codec = gen_models.codec


def contexts(code: str) -> dict[ConnectType, Any]:
    """Per connect type the driver context: standalone on a serial of the product's own
    prefix, else a child of a station of that kind."""
    own = f"{code[:5]}P0000000002"
    out = {ConnectType.SINGLE: replace(codec.STANDALONE, device_sn=own, station_sn=own)}
    for kind in sorted(set(PARENT_CONNECT_TYPES.values())):
        out[kind] = codec.child_context(kind.value)
    return out


def passes(prop: Mapping[str, Any], device_sn: str, parent_sn: str) -> bool:
    """Whether ``prop``'s ``read_conditions`` pass (none at all, or every condition of a
    group); only ``RE`` patterns on the serials are evaluated."""
    groups = (prop.get("read_conditions") or {}).get("condition_list") or []
    serials = {"device_sn": device_sn, "parent_sn": parent_sn}
    return not groups or any(
        all(
            c.get("type") in _PATTERN_TYPES
            and c.get("qualifier") == "RE"
            and re.search(str(c.get("value") or ""), serials[c["type"]]) is not None
            for c in group.get("conditions") or []
        )
        for group in groups
    )


def resolve(
    props: Sequence[Mapping[str, Any]], device_sn: str, parent_sn: str
) -> Mapping[str, Any] | None:
    """The alarm property the app reads for the device: the ``__v`` form whose read
    conditions pass with the most conditions (the first of equals), else the base."""
    base = next((p for p in props if p["identifier"] == ALARM_IDENTIFIER), None)
    chosen, most = base, -1
    for prop in props:
        groups = (prop.get("read_conditions") or {}).get("condition_list") or []
        if not _VARIANT.search(prop["identifier"]) or not groups:
            continue
        if not passes(prop, device_sn, parent_sn):
            continue
        count = sum(len(g.get("conditions") or []) for g in groups)
        if count > most:
            chosen, most = prop, count
    return chosen


def _choices(prop: Mapping[str, Any]) -> tuple[list[int], int | None]:
    rows = codec.specs_of(prop).get("eunmList") or []
    values = [int(r["value"]) for r in rows if str(r.get("value", "")).isdigit()]
    default = next((int(r["value"]) for r in rows if str(r.get("isDefault")) == "1"), None)
    return [v for v in values if v != HOMEBASE_CHOICE], default


def request(
    recipe: Mapping[str, Any] | None,
    alt: Mapping[str, Any] | None,
    channels: tuple[int, int],
) -> list[Any] | None:
    """``[command, params]`` of a handler recipe with the channel and nickname slotted,
    or None when it is no alarm command the station confirms. ``alt`` is the same
    request on the context's second channel; ``channels`` are the two channels."""
    if not recipe or not alt:
        return None
    command = recipe.get("subCmd") if recipe.get("cmd") == WRAPPER else recipe.get("cmd")
    params, other = recipe.get("params"), alt.get("params")
    if command not in ALARM_COMMANDS or not isinstance(params, dict) or not isinstance(other, dict):
        return None
    slotted: dict[str, Any] = {}
    for key, value in params.items():
        if value == NICKNAME:
            slotted[key] = USER_NAME_SLOT
        elif (value, other.get(key)) == channels:
            slotted[key] = CHANNEL_SLOT
        else:
            slotted[key] = value
    return [command, slotted]


def start_stop(start: list[Any] | None, stop: list[Any] | None) -> list[list[Any]] | None:
    """``[start, stop]`` when both are alarm requests with the same fields, else None."""
    if start is None or stop is None or set(start[1]) != set(stop[1]):
        return None
    return [start, stop]


def generate(cache: Path) -> dict[str, dict[str, dict[str, Any]]]:
    tm = gen_models
    products: dict[str, dict[str, dict[str, Any]]] = {}
    for folder in sorted(p for p in cache.iterdir() if (p / "td.json").is_file()):
        code = folder.name
        handler = folder / f"{code}Handle.mix.js"
        td = json.loads((folder / "td.json").read_text(encoding="utf-8"))
        props = [
            p
            for p in td.get("properties") or []
            if isinstance(p, dict)
            and (
                p.get("identifier") == ALARM_IDENTIFIER
                or _VARIANT.sub("", str(p.get("identifier", ""))) == ALARM_IDENTIFIER
            )
        ]
        if not props or not handler.is_file():
            continue
        keys: list[tuple[ConnectType, int, bool, bool]] = []
        requests: list[dict[str, Any]] = []
        picked: dict[ConnectType, tuple[Mapping[str, Any], Any]] = {}
        for kind, ctx in contexts(code).items():
            prop = resolve(props, ctx.device_sn, ctx.station_sn)
            if prop is None:
                continue
            picked[kind] = (prop, ctx)
            for second, c in ((False, ctx), (True, codec.alt_channel(ctx))):
                for choice in _choices(prop)[0]:
                    for start in (True, False):
                        payload = {"type": choice, "open": start, "nick_name": NICKNAME}
                        keys.append((kind, choice, start, second))
                        requests.append(
                            {
                                "kind": "set",
                                "identifier": prop["identifier"],
                                "payload": payload,
                                "device": c.device(code),
                            }
                        )
        replies = tm.run_driver(code, handler, requests) if requests else []
        got = {k: tm.p2p(r) for k, r in zip(keys, replies, strict=True)}
        kinds: dict[str, dict[str, Any]] = {}
        for kind, (prop, ctx) in picked.items():
            values, default = _choices(prop)
            recorded: dict[int, list[Any]] = {}
            for choice in values:
                pair = [
                    request(
                        _slot(got.get((kind, choice, start, False)), ctx),
                        _slot(got.get((kind, choice, start, True)), ctx),
                        (ctx.channel, codec.alt_channel(ctx).channel),
                    )
                    for start in (True, False)
                ]
                both = start_stop(*pair)
                if both is not None:
                    recorded[choice] = both
            if recorded:
                first = default if default in recorded else min(recorded)
                kinds[kind.value] = {"default": first, "choices": recorded}
        if kinds:
            products[code] = kinds
    return products


def _slot(recipe: Mapping[str, Any] | None, ctx: Any) -> Any:
    return None if recipe is None else codec.slot(recipe, ctx)


def render(products: Mapping[str, Mapping[str, Mapping[str, Any]]]) -> str:
    """The module text, formatted by ruff: per product, the connect types that share one
    entry grouped, in connect-type order."""
    lines = [
        '"""Generated by scripts/gen_device_alarm.py from the eufy app\'s product handlers and',
        "thing descriptions; do not edit. Per product code, groups of connect types with the",
        "alarm choice the app preselects there and, per choice, the ``(command, params)`` the",
        'handler sends to start it and to stop it."""',
        "",
        "from typing import Any, Final",
        "",
        "DEVICE_ALARMS: Final[dict[str, list[tuple[tuple[str, ...], dict[str, Any]]]]] = {",
    ]
    for code, kinds in products.items():
        groups: dict[str, list[str]] = {}
        for kind, entry in kinds.items():
            groups.setdefault(json.dumps(entry), []).append(kind)
        lines.append(f"    {json.dumps(code)}: [")
        for key, names in groups.items():
            entry = json.loads(key)
            choices = ", ".join(
                f"{c}: ({_literal(a)}, {_literal(b)})" for c, (a, b) in entry["choices"].items()
            )
            names_text = ", ".join(json.dumps(n) for n in names)
            lines.append(
                f'        (({names_text},), {{"default": {entry["default"]}, '
                f'"choices": {{{choices}}}}}),'
            )
        lines.append("    ],")
    lines.append("}")
    text = "\n".join(lines) + "\n"
    done = subprocess.run(
        [sys.executable, "-m", "ruff", "format", "--stdin-filename", str(DEFAULT_OUT), "-"],
        input=text,
        capture_output=True,
        text=True,
        check=False,
    )
    if done.returncode:
        raise SystemExit(f"ruff format failed: {done.stderr.strip()}")
    return done.stdout


def _literal(req: Sequence[Any]) -> str:
    command, params = req
    fields = ", ".join(f"{json.dumps(k)}: {json.dumps(v)}" for k, v in params.items())
    return f"({command}, {{{fields}}})"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate devices/_device_alarm_data.py.")
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--check", action="store_true", help="compare with --out, write nothing")
    args = parser.parse_args(argv)
    text = render(generate(args.cache))
    if args.check:
        same = args.out.exists() and args.out.read_text(encoding="utf-8") == text
        print("up to date" if same else f"{args.out} differs")
        return 0 if same else 1
    args.out.write_text(text, encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
