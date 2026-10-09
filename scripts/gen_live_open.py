"""Generate ``devices/_live_open_data.py``: which library live open each product's handler asks for.

For every cached product whose thing description has ``open_live_stream``, the vendor
handler runs offline (``scripts/thing_models.py`` harness, Node) once standalone and once
behind each station kind of ``PARENT_CONNECT_TYPES``, with the input the app's live player
gives it. Each recipe is compared with the library's builders; the file records, per
product and connect type, the :class:`~eufy_home_security.devices.live_open.LiveOpen`
whose recipe equals the handler's (the keys of ``HANDLER_UNUSED_KEYS`` aside), or null
when none does. Runs on a maintainer host only; nothing at runtime executes vendor code.

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

from eufy_home_security.devices.live_open import LiveOpen
from eufy_home_security.devices.model_settings import product_code_of
from eufy_home_security.devices.recipes import (
    HANDLER_UNUSED_KEYS,
    PARENT_CONNECT_TYPES,
    ConnectType,
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


def generate(cache: Path) -> dict[str, Any]:
    tm = _harness()
    libraries = {channel: _library_recipes(channel) for channel in (0, CHANNEL)}
    ctxs = contexts()
    products: dict[str, dict[str, str | None]] = {}
    for code in tm.cached_product_codes(cache):
        if "open_live_stream" not in tm.identifiers(tm.load_td(cache, code), "actions"):
            continue
        serial = serial_for(code)
        requests = []
        for version in VERSIONS:
            for parent in ctxs.values():
                device: dict[str, Any] = {
                    "device_sn": serial,
                    "parent_sn": parent or serial,
                    "device_channel": 0 if parent is None else CHANNEL,
                    "main_sw_version": version,
                }
                requests.append(
                    {
                        "identifier": "open_live_stream",
                        "payload": dict(PLAYER_INPUT),
                        "device": device,
                    }
                )
        p2ps = tm.run_handler(tm.handler_file(cache, code), requests)
        channels = [0 if parent is None else CHANNEL for parent in ctxs.values()]
        by_version = [
            [
                classify(p2p, libraries[channel])
                for p2p, channel in zip(
                    p2ps[i * len(ctxs) : (i + 1) * len(ctxs)], channels, strict=True
                )
            ]
            for i in range(len(VERSIONS))
        ]
        products[code] = {
            kind.value: (modes[0].value if modes[0] is not None and len(set(modes)) == 1 else None)
            for kind, modes in zip(ctxs, zip(*by_version, strict=True), strict=True)
        }
    return products


def render(products: Mapping[str, Mapping[str, str | None]]) -> str:
    """The module text: one line per product, connect types in table order."""
    lines = [
        '"""Generated by scripts/gen_live_open.py from the eufy app\'s product handlers; do not',
        "edit. Per product code and connect type, the library open (``LiveOpen`` value) that",
        'reproduces the handler\'s ``open_live_stream``, or None."""',
        "",
        "from typing import Final",
        "",
        f"APP_VERSION: Final = {json.dumps(APP_VERSION)}",
        "",
        "LIVE_OPEN: Final[dict[str, dict[str, str | None]]] = {",
    ]
    for code, modes in products.items():
        lines.append(f"    {json.dumps(code)}: {{")
        lines.extend(
            f"        {json.dumps(kind)}: {'None' if mode is None else json.dumps(mode)},"
            for kind, mode in modes.items()
        )
        lines.append("    },")
    lines.append("}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate devices/_live_open_data.py.")
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
