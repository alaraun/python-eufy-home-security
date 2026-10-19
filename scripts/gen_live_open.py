"""Generate ``devices/_live_open_data.py``: which library live open each product's handler asks for.

For every cached product whose thing description has ``open_live_stream``, the vendor
handler runs offline (``scripts/thing_models.py`` harness, Node) once standalone and once
behind each station kind of ``PARENT_CONNECT_TYPES``, with the input the app's live player
gives it. Each recipe is compared with the library's builders; the file records, per
product and connect type, the :class:`~eufy_home_security.devices.live_open.LiveOpen`
whose recipe equals the handler's (the keys of ``HANDLER_UNUSED_KEYS`` aside), or null
when none does. Where that open is a 1700 open behind a station, the handler's
``close_live_stream`` is recorded too, as the
:class:`~eufy_home_security.devices.live_open.LiveStop` it is, or null. Runs on a
maintainer host only; nothing at runtime executes vendor code.

The table is a Python module, so reading it is an import and never file I/O on the
event loop.

    gen_live_open.py [--cache DIR] [--out FILE] [--check]
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import sys
from collections.abc import Mapping
from pathlib import Path
from types import ModuleType
from typing import Any

from eufy_home_security.devices.live_open import LiveOpen, LiveStop
from eufy_home_security.devices.model_settings import product_code_of
from eufy_home_security.devices.recipes import (
    HANDLER_UNUSED_KEYS,
    PARENT_CONNECT_TYPES,
    ConnectType,
    RecipeCommand,
    close_live_stream,
    open_live_stream_single,
    open_live_stream_station,
)

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_CACHE = ROOT / ".work" / "cache" / "things_all"
DEFAULT_OUT = ROOT / "src" / "eufy_home_security" / "devices" / "_live_open_data.py"
APP_VERSION = "6.1.10"  # the app build whose handlers the cache holds
CHANNEL = 1
ACCOUNT = "0123456789abcdef0123456789abcdef01234567"
KEY = "0123456789ABCDEF" * 16
#: What the app's live player hands the handler (P2PLiveStreamPlayer.play()).
PLAYER_INPUT: Mapping[str, Any] = {
    "key": KEY,
    "userId": ACCOUNT,
    "ClientOS": "ANDROID",
    "streamType": 0,
    "cameraType": 0,
    "entryType": 0,
}


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


#: Firmware versions each request is run with; a product whose open depends on them is
#: recorded as null (the library would need the device's version to choose).
VERSIONS = ("1.0.0.0", "9.9.9.9")


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


def _library_recipes(channel: int) -> dict[LiveOpen, dict[str, Any]]:
    built = {
        LiveOpen.STATION: open_live_stream_station(
            channel=channel, account_id=ACCOUNT, key_hex=KEY
        ),
        LiveOpen.SINGLE: open_live_stream_single(channel=channel, account_id=ACCOUNT, key_hex=KEY),
        LiveOpen.SINGLE_NO_EXT: open_live_stream_single(
            channel=channel, account_id=ACCOUNT, key_hex=KEY, ext_value=False
        ),
    }
    return {mode: recipe.as_handler_dict() for mode, recipe in built.items()}


def classify(
    handler_p2p: Mapping[str, Any], library: Mapping[LiveOpen, dict[str, Any]]
) -> LiveOpen | None:
    """The library open equal to the handler's, or None; an open the handler flags
    ``webRtc`` (its ``isSupportWebRtc`` lists the parent) is never one."""
    if handler_p2p.get("webRtc"):
        return None
    wanted = {k: v for k, v in handler_p2p.items() if k not in HANDLER_UNUSED_KEYS}
    return next((mode for mode, recipe in library.items() if recipe == wanted), None)


def classify_stop(handler_p2p: Mapping[str, Any], channel: int) -> LiveStop | None:
    """The library stop the handler's ``close_live_stream`` is, or None: a bare 1004,
    or a 1350 ``DeviceMsgBean`` of cmd 1004 naming ``channel`` (the library sends its
    station stop for it, which names the channel too)."""
    if handler_p2p.get("webRtc"):
        return None
    wanted = {k: v for k, v in handler_p2p.items() if k not in HANDLER_UNUSED_KEYS}
    if wanted == close_live_stream().as_handler_dict():
        return LiveStop.BARE
    station = {
        "cmd": int(RecipeCommand.SET_PAYLOAD),
        "subCmd": int(RecipeCommand.STOP_LIVE_STREAM),  # 1004 as the 1350's sub-command
        "params": {"channel": channel},
    }
    return LiveStop.STATION if wanted == station else None


def _one(values: list[Any]) -> Any:
    """The value every firmware version gave, or None when they differ."""
    return values[0] if values[0] is not None and len(set(values)) == 1 else None


def generate(cache: Path) -> tuple[dict[str, Any], dict[str, Any]]:
    """Per product: the open per connect type, and the stop per connect type where the
    open is a 1700 open behind a station."""
    tm = _harness()
    libraries = {channel: _library_recipes(channel) for channel in (0, CHANNEL)}
    ctxs = contexts()
    channels = [0 if parent is None else CHANNEL for parent in ctxs.values()]
    products: dict[str, dict[str, str | None]] = {}
    stops: dict[str, dict[str, str | None]] = {}
    for code in tm.cached_product_codes(cache):
        if "open_live_stream" not in tm.identifiers(tm.load_td(cache, code), "actions"):
            continue
        serial = serial_for(code)
        requests = []
        for identifier, payload in (("open_live_stream", PLAYER_INPUT), ("close_live_stream", {})):
            for version in VERSIONS:
                for parent in ctxs.values():
                    device: dict[str, Any] = {
                        "device_sn": serial,
                        "parent_sn": parent or serial,
                        "device_channel": 0 if parent is None else CHANNEL,
                        "main_sw_version": version,
                    }
                    requests.append(
                        {"identifier": identifier, "payload": dict(payload), "device": device}
                    )
        p2ps = tm.run_handler(tm.handler_file(cache, code), requests)
        rows = [p2ps[i * len(ctxs) : (i + 1) * len(ctxs)] for i in range(2 * len(VERSIONS))]
        opens = [
            [classify(p2p, libraries[ch]) for p2p, ch in zip(row, channels, strict=True)]
            for row in rows[: len(VERSIONS)]
        ]
        closes = [
            [classify_stop(p2p, ch) for p2p, ch in zip(row, channels, strict=True)]
            for row in rows[len(VERSIONS) :]
        ]
        modes = {
            kind: _one(list(found))
            for kind, found in zip(ctxs, zip(*opens, strict=True), strict=True)
        }
        products[code] = {kind.value: None if m is None else m.value for kind, m in modes.items()}
        behind = {
            kind.value: (None if (stop := _one(list(found))) is None else stop.value)
            for kind, found in zip(ctxs, zip(*closes, strict=True), strict=True)
            if kind is not ConnectType.SINGLE
            and modes[kind] in (LiveOpen.SINGLE, LiveOpen.SINGLE_NO_EXT)
        }
        if behind:
            stops[code] = behind
    return products, stops


def _table(name: str, rows: Mapping[str, Mapping[str, str | None]]) -> list[str]:
    lines = [f"{name}: Final[dict[str, dict[str, str | None]]] = {{"]
    for code, values in rows.items():
        lines.append(f"    {json.dumps(code)}: {{")
        lines.extend(
            f"        {json.dumps(kind)}: {'None' if value is None else json.dumps(value)},"
            for kind, value in values.items()
        )
        lines.append("    },")
    lines.append("}")
    return lines


def render(
    products: Mapping[str, Mapping[str, str | None]],
    stops: Mapping[str, Mapping[str, str | None]],
) -> str:
    """The module text: one line per product and connect type, in table order."""
    lines = [
        '"""Generated by scripts/gen_live_open.py from the eufy app\'s product handlers; do not',
        "edit. Per product code and connect type, the library open (``LiveOpen`` value) that",
        "reproduces the handler's ``open_live_stream``, or None; and where that open is a",
        "1700 open behind a station, the library stop (``LiveStop`` value) its",
        '``close_live_stream`` is, or None."""',
        "",
        "from typing import Final",
        "",
        f"APP_VERSION: Final = {json.dumps(APP_VERSION)}",
        "",
        *_table("LIVE_OPEN", products),
        "",
        *_table("LIVE_STOP", stops),
    ]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate devices/_live_open_data.py.")
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--check", action="store_true", help="compare with --out, write nothing")
    args = parser.parse_args(argv)
    text = render(*generate(args.cache))
    if args.check:
        same = args.out.exists() and args.out.read_text(encoding="utf-8") == text
        print("up to date" if same else f"{args.out} differs")
        return 0 if same else 1
    args.out.write_text(text, encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
