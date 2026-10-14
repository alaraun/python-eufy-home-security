"""Generate ``devices/_ptz_data.py``: which library pan/tilt/zoom recipe each product's handler asks for.

For every cached product whose thing description declares an action of
:data:`~eufy_home_security.devices.ptz.PTZ_IDENTIFIERS`, the vendor handler runs offline
(``scripts/thing_models.py`` harness, Node) standalone and behind each station kind of
``PARENT_CONNECT_TYPES``, with the inputs the app gives it, under two firmware versions.
Each recipe is compared with the library's builders in every
:class:`~eufy_home_security.devices.ptz.PtzForm`; the file records, per product, declared
action and connect type, the form whose recipe equals the handler's for every input, or
null when none does. Runs on a maintainer host only; nothing at runtime executes vendor
code.

Compared without the keys of ``HANDLER_UNUSED_KEYS``, without ``multipleRequest`` (the
handler's follow-up reads after a store or a default change: the library reads the slots
back itself) and without a ``notifySubCmd`` equal to ``subCmd`` (the answering notify
carries the sub-command either way). A recipe flagged ``webRtc`` is never a match.

    gen_ptz.py [--cache DIR] [--out FILE] [--check]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import subprocess
import sys
from collections.abc import Callable, Mapping, Sequence
from pathlib import Path
from types import ModuleType
from typing import Any

from eufy_home_security.devices import recipes
from eufy_home_security.devices.model_settings import product_code_of
from eufy_home_security.devices.ptz import PTZ_IDENTIFIERS, PtzForm
from eufy_home_security.devices.recipes import (
    HANDLER_UNUSED_KEYS,
    PARENT_CONNECT_TYPES,
    ConnectType,
    PanTilt,
    Recipe,
)

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CACHE = ROOT / ".work" / "cache" / "things_all"
DEFAULT_OUT = ROOT / "src" / "eufy_home_security" / "devices" / "_ptz_data.py"
APP_VERSION = "6.1.10"  # the app build whose handlers the cache holds
CHANNEL = 1
#: Firmware versions each request is run with; a form must hold under both.
VERSIONS = ("1.0.0.0", "9.9.9.9")
FOLLOW_UPS = "multipleRequest"

type Builder = Callable[[Any, PtzForm], Recipe | None]


def _pan_tilt(payload: Mapping[str, Any], form: PtzForm) -> Recipe:
    return recipes.pan_tilt(
        PanTilt(payload["rotateType"]), zoom=payload["zoom"], zoom_ivalue=form is PtzForm.STANDARD
    )


def _standard_only(build: Callable[[Any], Recipe]) -> Builder:
    """A builder with one form: :attr:`PtzForm.STANDARD`."""
    return lambda payload, form: build(payload) if form is PtzForm.STANDARD else None


#: Per action, the app's inputs (each a pan/tilt pad press, slot or zoom the library
#: sends) and the library builder for them in a given form (None: no such form).
ACTIONS: Mapping[str, tuple[Sequence[Any], Builder]] = {
    "ptz_action_control": (
        [{"cmdType": 1, "rotateType": int(d), "zoom": 1} for d in (PanTilt.LEFT, PanTilt.DOWN)],
        _pan_tilt,
    ),
    "query_preset_positions": (
        [0],
        lambda payload, form: recipes.query_preset_positions(value=form is PtzForm.STANDARD),
    ),
    "set_ptz_cruise_preview": ([1, 3], _standard_only(recipes.goto_preset)),
    "get_preset_position_pic": ([1, 3], _standard_only(recipes.preset_picture)),
    "set_preset_positions": ([1, 3], _standard_only(recipes.store_preset)),
    "delete_preset_positions": ([1, 3], _standard_only(recipes.delete_preset)),
    "default_preset_positions": (
        [{"index": 1, "settingState": 0}, {"index": 3, "settingState": 0}],
        _standard_only(lambda payload: recipes.set_default_preset(payload["index"])),
    ),
    "set_picture_zoom": (
        [{"dstZoom": 2.5, "orgZoom": 0}, {"dstZoom": 4, "orgZoom": 0}],
        _standard_only(lambda payload: recipes.set_picture_zoom(payload["dstZoom"])),
    ),
}
if set(ACTIONS) != set(PTZ_IDENTIFIERS):
    raise SystemExit("ACTIONS must cover PTZ_IDENTIFIERS")


def _harness() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "thing_models", ROOT / "scripts" / "thing_models.py"
    )
    if spec is None or spec.loader is None:
        raise ImportError("scripts/thing_models.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["thing_models"] = module
    spec.loader.exec_module(module)
    return module


def serial_for(code: str) -> str:
    """A synthetic serial whose product code is ``code`` (the serial rules can pick a
    variant by a later character, as a T8410C by index 6)."""
    for digit in "0123456789":
        serial = f"{code[:5]}P{digit}000054321"
        if product_code_of(None, serial) == code:
            return serial
    return f"{code[:5]}P2000054321"


def contexts() -> dict[ConnectType, str | None]:
    """Each connect type with a parent serial that yields it (None: standalone)."""
    out: dict[ConnectType, str | None] = {ConnectType.SINGLE: None}
    for prefix, kind in sorted(PARENT_CONNECT_TYPES.items()):
        out.setdefault(kind, f"{prefix}P0000000001")
    return out


def comparable(recipe: Mapping[str, Any]) -> dict[str, Any] | None:
    """``recipe`` reduced to what the library sends and waits for; None for a WebRTC one."""
    if recipe.get("webRtc"):
        return None
    out = {k: v for k, v in recipe.items() if k not in HANDLER_UNUSED_KEYS and k != FOLLOW_UPS}
    if out.get("notifySubCmd") is not None and out.get("notifySubCmd") == out.get("subCmd"):
        del out["notifySubCmd"]
    return out


def classify(identifier: str, handler_recipes: Sequence[Mapping[str, Any]]) -> PtzForm | None:
    """The form whose library recipe equals the handler's for every input, or None.
    ``handler_recipes`` holds one recipe per input of :data:`ACTIONS`, in order."""
    payloads, build = ACTIONS[identifier]
    wanted = [comparable(r) for r in handler_recipes]
    if any(w is None for w in wanted):
        return None
    for form in PtzForm:
        built = [build(p, form) for p in payloads]
        if all(
            b is not None and comparable(b.as_handler_dict()) == w
            for b, w in zip(built, wanted, strict=True)
        ):
            return form
    return None


def generate(cache: Path) -> dict[str, dict[str, dict[str, str | None]]]:
    tm = _harness()
    ctxs = contexts()
    products: dict[str, dict[str, dict[str, str | None]]] = {}
    for code in tm.cached_product_codes(cache):
        declared = [
            i for i in PTZ_IDENTIFIERS if i in tm.identifiers(tm.load_td(cache, code), "actions")
        ]
        if not declared:
            continue
        serial = serial_for(code)
        keys: list[tuple[str, ConnectType, str]] = []
        requests: list[dict[str, Any]] = []
        for identifier in declared:
            for kind, parent in ctxs.items():
                for version in VERSIONS:
                    device = {
                        "device_sn": serial,
                        "parent_sn": parent or serial,
                        "device_channel": 0 if parent is None else CHANNEL,
                        "main_sw_version": version,
                    }
                    for payload in ACTIONS[identifier][0]:
                        keys.append((identifier, kind, version))
                        requests.append(
                            {"identifier": identifier, "payload": payload, "device": device}
                        )
        replies = _run(tm, tm.handler_file(cache, code), requests)
        grouped: dict[tuple[str, ConnectType, str], list[dict[str, Any]]] = {}
        for key, reply in zip(keys, replies, strict=True):
            grouped.setdefault(key, []).append(reply)
        products[code] = {
            identifier: {
                kind.value: _same_form(
                    [classify(identifier, grouped[identifier, kind, v]) for v in VERSIONS]
                )
                for kind in ctxs
            }
            for identifier in declared
        }
    return products


def _run(tm: ModuleType, handler: Path, requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The handler's recipe per request, in one Node run; an empty recipe for a request
    the handler does not build."""
    job = json.dumps(
        {"handler": str(handler), "requests": [{"kind": "action", **r} for r in requests]}
    )
    proc = subprocess.run(
        [tm.node_executable(), str(tm.DRIVER)],
        input=job,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise tm.HarnessError(f"node failed on {handler.name}: {proc.stderr.strip()}")
    out: list[dict[str, Any]] = []
    for request, reply in zip(requests, json.loads(proc.stdout), strict=True):
        try:
            out.append(tm.recipe_from_reply(request["identifier"], reply))
        except tm.HarnessError:
            out.append({})
    return out


def _same_form(forms: Sequence[PtzForm | None]) -> str | None:
    """The form when every firmware version yields the same one, else None."""
    first = forms[0]
    return first.value if first is not None and all(f is first for f in forms) else None


def render(products: Mapping[str, Mapping[str, Mapping[str, str | None]]]) -> str:
    """The module text: one block per product, actions and connect types in table order."""
    lines = [
        '"""Generated by scripts/gen_ptz.py from the eufy app\'s product handlers; do not',
        "edit. Per product code, declared pan/tilt/zoom action and connect type, the library",
        '``PtzForm`` value whose recipe reproduces the handler\'s, or None."""',
        "",
        "from typing import Final",
        "",
        f"APP_VERSION: Final = {json.dumps(APP_VERSION)}",
        "",
        "PTZ: Final[dict[str, dict[str, dict[str, str | None]]]] = {",
    ]
    for code, actions in products.items():
        lines.append(f"    {json.dumps(code)}: {{")
        for identifier, forms in actions.items():
            lines.append(f"        {json.dumps(identifier)}: {{")
            lines.extend(
                f"            {json.dumps(kind)}: {'None' if form is None else json.dumps(form)},"
                for kind, form in forms.items()
            )
            lines.append("        },")
        lines.append("    },")
    lines.append("}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate devices/_ptz_data.py.")
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
