"""Fetch the eufy app's thing models and turn their handlers into goldens and docs.

Per product code the app downloads a thing description (TD) and a handler script,
``<PN>Handle.mix.js``, that turns an action's input into a wire recipe (see
``docs/reference/thing-models.md``). This script keeps a private cache of both and
derives the committed artefacts from it:

``fetch``      TD + handler for the account's product codes, from the cached cloud
               session (never logs in with a password), into ``DIR/<PN>/``.
``recipe``     evaluate one action through a cached handler and print the recipe.
``goldens``    the handler's recipes for :data:`CASES`, one JSON file per product code
               (``tests/fixtures/thing_models/``); ``tests/devices/test_recipe_goldens.py``
               holds the library's builders to them.
``inventory``  the generated part of ``docs/reference/thing-models.md``.

Handlers run offline in Node (``scripts/gen_models_driver.js``); ``node`` must be
on PATH. The cache holds vendor code: keep it out of the repository (``.work/``).
"""

from __future__ import annotations

import argparse
import asyncio
import hashlib
import json
import re
import shutil
import subprocess
import sys
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Final

from eufy_home_security.devices import recipes
from eufy_home_security.testing import SYNTHETIC

ROOT: Final = Path(__file__).resolve().parent.parent
DRIVER: Final = Path(__file__).resolve().parent / "gen_models_driver.js"
GOLDENS_DIR: Final = ROOT / "tests" / "fixtures" / "thing_models"
DOC: Final = ROOT / "docs" / "reference" / "thing-models.md"

THINGS_PATH: Final = "/app/things/get_things_list"
TD_FILE: Final = "td.json"
BEGIN_MARKER: Final = "<!-- BEGIN GENERATED: scripts/thing_models.py inventory -->"
END_MARKER: Final = "<!-- END GENERATED: scripts/thing_models.py inventory -->"

# ── the golden cases ────────────────────────────────────────────────────────────

T8170_SN: Final = "T8170P2000054321"
"""A synthetic standalone T8170 serial (its own parent)."""
FAKE_STREAM_KEY: Final = "0123456789ABCDEF" * 16
"""A fixed fake stream key: 256 upper-case hex characters, like an RSA-1024 modulus."""

STANDALONE_T8170: Final[Mapping[str, Any]] = {
    "device_sn": T8170_SN,
    "parent_sn": T8170_SN,
    "device_channel": 0,
    "main_sw_version": "3.3.5.4",
}
T8410_SN: Final = "T8410P2000054321"
"""A synthetic standalone T8410 serial (index 6 is not '5', so not a T8410C)."""
STANDALONE_T8410: Final[Mapping[str, Any]] = {
    "device_sn": T8410_SN,
    "parent_sn": T8410_SN,
    "device_channel": 0,
    "main_sw_version": "2.3.2.6",
}
T8410C_SN: Final = "T8410P5000054321"
"""A synthetic standalone T8410C serial ('5' at index 6)."""
STANDALONE_T8410C: Final[Mapping[str, Any]] = {
    **STANDALONE_T8410,
    "device_sn": T8410C_SN,
    "parent_sn": T8410C_SN,
}
HOMEBASE_T8160: Final[Mapping[str, Any]] = {
    "device_sn": SYNTHETIC.camera_sn,
    "parent_sn": SYNTHETIC.station_sn,
    "device_channel": 1,
    "main_sw_version": "3.8.7.4",
}
HOMEBASE2_SN: Final = "T8010P2000054321"
"""A synthetic HomeBase 2 serial."""
HOMEBASE2_T8113: Final[Mapping[str, Any]] = {
    "device_sn": "T8113P2000067890",
    "parent_sn": HOMEBASE2_SN,
    "device_channel": 1,
    "main_sw_version": "1.7.4",
}
HOMEBASE2_T8142: Final[Mapping[str, Any]] = {
    **HOMEBASE2_T8113,
    "device_sn": "T8142P2000067890",
    "main_sw_version": "3.0.5.7",
}
LIVE_OPEN_PAYLOAD: Final[Mapping[str, Any]] = {
    "key": FAKE_STREAM_KEY,
    "userId": SYNTHETIC.account_id,
    "entryType": 0,
    "cameraType": 0,
    "streamType": 0,
}
HOMEBASE2_LIVE_OPEN_PAYLOAD: Final[Mapping[str, Any]] = {**LIVE_OPEN_PAYLOAD, "ClientOS": "ANDROID"}
"""The app's live-open input for a camera behind a station: it adds the client OS."""


@dataclass(frozen=True, slots=True, kw_only=True)
class Case:
    """One handler input whose recipe is kept as a golden."""

    product_code: str
    identifier: str
    device: Mapping[str, Any]
    payload: Any
    builder: str | None
    """The :mod:`eufy_home_security.devices.recipes` builder that reproduces the
    recipe, or None when the library deliberately sends something else."""
    verified: bool = False
    """Proven on hardware (a live send with the expected answer)."""
    note: str = ""


CASES: Final[tuple[Case, ...]] = (
    Case(
        product_code="T8170",
        identifier="open_live_stream",
        device=STANDALONE_T8170,
        payload=LIVE_OPEN_PAYLOAD,
        builder="open_live_stream_single",
        verified=True,
    ),
    Case(
        product_code="T8170",
        identifier="close_live_stream",
        device=STANDALONE_T8170,
        payload=0,
        builder="close_live_stream",
        verified=True,
    ),
    Case(
        product_code="T8170",
        identifier="query_preset_positions",
        device=STANDALONE_T8170,
        payload=0,
        builder="query_preset_positions",
        verified=True,
    ),
    Case(
        product_code="T8170",
        identifier="set_ptz_cruise_preview",
        device=STANDALONE_T8170,
        payload=1,
        builder="goto_preset",
        verified=True,
    ),
    Case(
        product_code="T8170",
        identifier="get_preset_position_pic",
        device=STANDALONE_T8170,
        payload=1,
        builder="preset_picture",
    ),
    Case(
        product_code="T8170",
        identifier="ptz_action_control",
        device=STANDALONE_T8170,
        payload={"cmdType": 1, "rotateType": 2, "zoom": 1},
        builder="ptz_rotate",
        verified=True,
    ),
    Case(
        product_code="T8170",
        identifier="set_picture_zoom",
        device=STANDALONE_T8170,
        payload={"dstZoom": 2.5, "orgZoom": 0},
        builder="set_picture_zoom",
        verified=True,
    ),
    Case(
        product_code="T8160",
        identifier="open_live_stream",
        device=HOMEBASE_T8160,
        payload=LIVE_OPEN_PAYLOAD,
        builder=None,
        note="The library sends its own HomeBase live open, not this recipe.",
    ),
    Case(
        product_code="T8160",
        identifier="close_live_stream",
        device=HOMEBASE_T8160,
        payload=0,
        builder="close_live_stream",
    ),
    Case(
        product_code="T8113",
        identifier="open_live_stream",
        device=HOMEBASE2_T8113,
        payload=HOMEBASE2_LIVE_OPEN_PAYLOAD,
        builder="open_live_stream_station",
    ),
    Case(
        product_code="T8113",
        identifier="close_live_stream",
        device=HOMEBASE2_T8113,
        payload=0,
        builder="close_live_stream",
    ),
    Case(
        product_code="T8142",
        identifier="open_live_stream",
        device=HOMEBASE2_T8142,
        payload=HOMEBASE2_LIVE_OPEN_PAYLOAD,
        builder="open_live_stream_station",
    ),
    Case(
        product_code="T8142",
        identifier="close_live_stream",
        device=HOMEBASE2_T8142,
        payload=0,
        builder="close_live_stream",
    ),
    Case(
        product_code="T8410",
        identifier="open_live_stream",
        device=STANDALONE_T8410,
        payload=LIVE_OPEN_PAYLOAD,
        builder="open_live_stream_single",
        note="The T8410 variant: no `extValue`.",
    ),
    Case(
        product_code="T8410",
        identifier="close_live_stream",
        device=STANDALONE_T8410,
        payload=0,
        builder="close_live_stream",
    ),
    Case(
        product_code="T8410",
        identifier="ptz_action_control",
        device=STANDALONE_T8410,
        payload={"cmdType": 1, "rotateType": 2, "zoom": 1},
        builder="ptz_rotate",
        note="The T8410 variant: no `zoom`, no `ivalue`.",
    ),
    Case(
        product_code="T8410C",
        identifier="open_live_stream",
        device=STANDALONE_T8410C,
        payload=LIVE_OPEN_PAYLOAD,
        builder="open_live_stream_single",
        note="The T8410C variant: no `extValue`.",
    ),
    Case(
        product_code="T8410C",
        identifier="close_live_stream",
        device=STANDALONE_T8410C,
        payload=0,
        builder="close_live_stream",
    ),
    Case(
        product_code="T8410C",
        identifier="ptz_action_control",
        device=STANDALONE_T8410C,
        payload={"cmdType": 1, "rotateType": 2, "zoom": 1},
        builder="ptz_rotate",
    ),
)


# ── Node harness ─────────────────────────────────────────────────────────────


class HarnessError(RuntimeError):
    """Node is missing, or a handler failed to produce a recipe."""


def node_executable() -> str:
    node = shutil.which("node")
    if node is None:
        raise HarnessError("node not found on PATH: install Node.js to evaluate handlers")
    return node


def run_handler(handler: Path, requests: Sequence[Mapping[str, Any]]) -> list[dict[str, Any]]:
    """The handler's ``p2p`` recipe for each request, ``buildTimestamp`` dropped.

    Each request is ``{"identifier", "payload", "device"}``.
    """
    job = json.dumps(
        {"handler": str(handler), "requests": [{"kind": "action", **r} for r in requests]}
    )
    proc = subprocess.run(
        [node_executable(), str(DRIVER)],
        input=job,
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise HarnessError(f"node failed on {handler.name}: {proc.stderr.strip()}")
    replies = json.loads(proc.stdout)
    return [
        recipe_from_reply(request["identifier"], reply)
        for request, reply in zip(requests, replies, strict=True)
    ]


def recipe_from_reply(identifier: str, reply: Mapping[str, Any]) -> dict[str, Any]:
    """The ``p2p`` recipe of one ``controlDevice`` reply; HarnessError for a failure."""
    if "error" in reply:
        raise HarnessError(f"{identifier}: the handler threw: {reply['error']}")
    data = reply.get("data")
    if reply.get("code") != 0 or not isinstance(data, Mapping) or "p2p" not in data:
        raise HarnessError(f"{identifier}: no recipe in the handler's reply: {reply!r}")
    p2p = data["p2p"]
    if not isinstance(p2p, dict):
        raise HarnessError(f"{identifier}: the recipe is not an object: {p2p!r}")
    return {k: v for k, v in p2p.items() if k != "buildTimestamp"}


# ── cache layout ─────────────────────────────────────────────────────────────


def handler_file(cache: Path, product_code: str) -> Path:
    return cache / product_code / f"{product_code}Handle.mix.js"


def load_td(cache: Path, product_code: str) -> dict[str, Any]:
    path = cache / product_code / TD_FILE
    try:
        td: dict[str, Any] = json.loads(path.read_text(encoding="utf-8"))
    except FileNotFoundError:
        raise SystemExit(f"{path} missing: run `fetch` first") from None
    return td


def cached_product_codes(cache: Path) -> list[str]:
    return sorted(p.parent.name for p in cache.glob(f"*/{TD_FILE}"))


_PLUGIN_DATE: Final = re.compile(r"/(\d{4}/\d{2}/\d{2})/")


def plugin_path_date(plugin_path: str) -> str | None:
    """The ``yyyy/mm/dd`` the CDN path of a handler carries (its publication date)."""
    match = _PLUGIN_DATE.search(plugin_path)
    return match.group(1) if match else None


def handler_info(td: Mapping[str, Any], handler_js: bytes) -> dict[str, Any]:
    """Which handler a golden came from: TD version, CDN date, and the script's hash."""
    return {
        "large_version": td.get("large_version"),
        "plugin_path_date": plugin_path_date(str(td.get("profile", {}).get("plugin_path", ""))),
        "sha256": hashlib.sha256(handler_js).hexdigest(),
    }


def identifiers(td: Mapping[str, Any], kind: str) -> list[str]:
    """The identifiers of one TD section (``actions``, ``properties``, ``events``)."""
    return [
        str(entry["identifier"])
        for entry in td.get(kind) or []
        if isinstance(entry, Mapping) and "identifier" in entry
    ]


def dumps(document: Any) -> str:
    """Stable JSON: two-space indent, trailing newline, nested key order kept."""
    return json.dumps(document, indent=2, ensure_ascii=False) + "\n"


# ── goldens ──────────────────────────────────────────────────────────────────


def case_request(case: Case) -> dict[str, Any]:
    return {"identifier": case.identifier, "payload": case.payload, "device": dict(case.device)}


def golden_document(
    product_code: str, info: Mapping[str, Any], cases: Sequence[Case], p2ps: Sequence[Any]
) -> dict[str, Any]:
    """One product code's golden file; top-level keys sorted, case order kept."""
    doc = {
        "product_code": product_code,
        "handler": dict(info),
        "cases": [
            {**case_request(case), "p2p": p2p} for case, p2p in zip(cases, p2ps, strict=True)
        ],
    }
    return dict(sorted(doc.items()))


def cases_by_product(cases: Iterable[Case] = CASES) -> dict[str, list[Case]]:
    grouped: dict[str, list[Case]] = {}
    for case in cases:
        grouped.setdefault(case.product_code, []).append(case)
    return grouped


def write_goldens(cache: Path, out: Path) -> list[Path]:
    written = []
    out.mkdir(parents=True, exist_ok=True)
    for product_code, cases in cases_by_product().items():
        handler = handler_file(cache, product_code)
        p2ps = run_handler(handler, [case_request(case) for case in cases])
        info = handler_info(load_td(cache, product_code), handler.read_bytes())
        path = out / f"{product_code}.json"
        path.write_text(dumps(golden_document(product_code, info, cases, p2ps)), "utf-8")
        written.append(path)
    return written


# ── inventory ────────────────────────────────────────────────────────────────


def render_inventory(tds: Mapping[str, Mapping[str, Any]], cases: Sequence[Case] = CASES) -> str:
    """The generated section of the reference doc (between the markers, exclusive)."""
    lines = [
        "### Thing models",
        "",
        "| Product code | Handler version | Handler date | Actions | Properties | Events |",
        "|---|---|---|---|---|---|",
    ]
    for product_code in sorted(tds):
        td = tds[product_code]
        date = plugin_path_date(str(td.get("profile", {}).get("plugin_path", ""))) or "?"
        lines.append(
            f"| {product_code} | {td.get('large_version', '?')} | {date} | "
            f"{len(identifiers(td, 'actions'))} | {len(identifiers(td, 'properties'))} | "
            f"{len(identifiers(td, 'events'))} |"
        )
    lines += [
        "",
        "### Recipes the library implements",
        "",
        "| Product code | Connect type | Action | Builder | Support | Note |",
        "|---|---|---|---|---|---|",
    ]
    for case in cases:
        kind = recipes.connect_type(case.device["parent_sn"], case.device["device_sn"])
        builder = f"`{case.builder}`" if case.builder else "—"
        td = tds.get(case.product_code)
        note = case.note
        if td is not None and case.identifier not in identifiers(td, "actions"):
            note = f"{note} Not an action of this TD.".strip()
        status = "verified" if case.verified else "declared"
        lines.append(
            f"| {case.product_code} | {kind.value} | `{case.identifier}` | {builder} | "
            f"{status} | {note} |"
        )
    return "\n".join(lines) + "\n"


def replace_generated(document: str, generated: str) -> str:
    """``document`` with the text between the markers replaced by ``generated``."""
    start = document.find(BEGIN_MARKER)
    end = document.find(END_MARKER)
    if start < 0 or end < start:
        raise SystemExit(f"the document has no {BEGIN_MARKER!r} … {END_MARKER!r} section")
    head = document[: start + len(BEGIN_MARKER)]
    return f"{head}\n\n{generated}\n{document[end:]}"


def write_inventory(cache: Path, out: Path) -> None:
    tds = {pn: load_td(cache, pn) for pn in cached_product_codes(cache)}
    current = out.read_text(encoding="utf-8")
    out.write_text(replace_generated(current, render_inventory(tds)), encoding="utf-8")


# ── fetch ────────────────────────────────────────────────────────────────────


def product_codes(devices: Iterable[Mapping[str, Any]]) -> list[str]:
    """The distinct product codes of a raw device list, sorted: each device's
    ``device_new_pn``, else its serial's catalogued model."""
    from eufy_home_security.devices import model_for_serial  # noqa: PLC0415

    codes: set[str] = set()
    for device in devices:
        pn = device.get("device_new_pn")
        if isinstance(pn, str) and pn.strip():
            codes.add(pn.strip())
            continue
        serial = device.get("device_sn")
        model = model_for_serial(serial) if isinstance(serial, str) else None
        if model is not None:
            codes.add(model.model)
    return sorted(codes)


def things_body(codes: Sequence[str]) -> dict[str, Any]:
    return {"product_codes": list(codes), "code_time_map": {}, "use_network_version": True}


def things_list(data: Any) -> list[dict[str, Any]]:
    """The ``things_list`` entries of a ``get_things_list`` reply."""
    entries = data.get("things_list") if isinstance(data, Mapping) else None
    if not isinstance(entries, list):
        raise SystemExit("the get_things_list reply has no things_list")
    return [entry for entry in entries if isinstance(entry, dict)]


async def fetch(store_path: Path, out: Path, codes: Sequence[str]) -> None:
    import aiohttp  # noqa: PLC0415 - only this command needs the network

    from eufy_home_security import EufySecurity, LoginNeed  # noqa: PLC0415
    from eufy_home_security.cloud import const  # noqa: PLC0415
    from eufy_home_security.storage import JsonFileStore, async_cached_account  # noqa: PLC0415

    store = JsonFileStore(store_path)
    email = await async_cached_account(store)
    if email is None:
        raise SystemExit(f"{store_path} holds no account: log in with eufy-security first")
    async with (
        aiohttp.ClientSession() as http,
        EufySecurity(http, email, None, store=store) as eufy,
    ):
        status = await eufy.async_cloud_status()
        if status.login_need is not LoginNeed.NONE:
            raise SystemExit(
                f"no usable cached session ({status.login_need.value}); this script never "
                "logs in: refresh the session with eufy-security first"
            )
        await eufy.async_login()
        api = eufy.cloud
        if not codes:
            devices = await api.async_get_devices()
            codes = product_codes(device.raw for device in devices)
            if not codes:
                raise SystemExit("no product code in the device list: pass --product-code")
        identity = api._identity
        if identity is None:
            raise SystemExit("no cloud session after login")
        host = const.cluster_host("things", api._region, api._mega_domain)
        _, _, data = await api._call(host, THINGS_PATH, things_body(codes), identity)
        for thing in things_list(data):
            profile = thing.get("profile") or {}
            product_code = str(profile.get("product_code") or "")
            if not product_code:
                continue
            folder = out / product_code
            folder.mkdir(parents=True, exist_ok=True)
            (folder / TD_FILE).write_text(
                json.dumps(thing, indent=2, sort_keys=True) + "\n", "utf-8"
            )
            plugin_path = profile.get("plugin_path")
            if not plugin_path:
                print(f"{product_code}: no handler (plugin_path empty)", file=sys.stderr)
                continue
            async with http.get(plugin_path) as response:
                response.raise_for_status()
                handler_file(out, product_code).write_bytes(await response.read())
            print(f"{product_code}: TD {thing.get('large_version')} and handler written")


# ── command line ─────────────────────────────────────────────────────────────


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    sub = parser.add_subparsers(dest="command", required=True)

    p_fetch = sub.add_parser("fetch", help="download TDs and handlers from the cached session")
    p_fetch.add_argument("--store", type=Path, required=True, help="the JsonFileStore cache")
    p_fetch.add_argument("--out", type=Path, required=True, help="the private cache directory")
    p_fetch.add_argument(
        "--product-code",
        action="append",
        default=[],
        dest="product_codes",
        help="product code to fetch (repeatable; default: the account's devices)",
    )

    p_recipe = sub.add_parser("recipe", help="evaluate one action through a cached handler")
    p_recipe.add_argument("--cache", type=Path, required=True)
    p_recipe.add_argument("product_code")
    p_recipe.add_argument("identifier")
    p_recipe.add_argument("payload", help="the action's payload value, as JSON")
    p_recipe.add_argument("--parent", help="the parent serial (default: standalone)")

    p_goldens = sub.add_parser("goldens", help="write the golden recipe files")
    p_goldens.add_argument("--cache", type=Path, required=True)
    p_goldens.add_argument("--out", type=Path, default=GOLDENS_DIR)

    p_inventory = sub.add_parser("inventory", help="regenerate the reference doc's tables")
    p_inventory.add_argument("--cache", type=Path, required=True)
    p_inventory.add_argument("--out", type=Path, default=DOC)

    args = parser.parse_args(argv)
    try:
        if args.command == "fetch":
            asyncio.run(fetch(args.store.expanduser(), args.out, args.product_codes))
        elif args.command == "recipe":
            serial = f"{args.product_code}P2000054321"
            device = {
                "device_sn": serial,
                "parent_sn": args.parent or serial,
                "device_channel": 0 if args.parent is None else 1,
                "main_sw_version": "",
            }
            request = {
                "identifier": args.identifier,
                "payload": json.loads(args.payload),
                "device": device,
            }
            handler = handler_file(args.cache, args.product_code)
            print(dumps(run_handler(handler, [request])[0]), end="")
        elif args.command == "goldens":
            for path in write_goldens(args.cache, args.out):
                print(f"wrote {path}")
        else:
            write_inventory(args.cache, args.out)
            print(f"wrote {args.out}")
    except HarnessError as err:
        print(f"error: {err}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
