"""Generate ``src/eufy_home_security/devices/app_models.py`` from the eufy app's product tables.

Four source files of the eufy Security app (build ``--app-version``) name the products:
the device configuration (``device_configuration.json``: per product code its parent in
a category tree, ``T8162`` → ``BatteryCamera`` → ``Camera`` → ``Base``), the model
constants (one ``String`` constant per serial prefix, e.g. ``CAMERA2C = "T8113"``), the
device-type map (``hashMap.put(<type>, new String[]{<prefixes>})``) and the device-type
ints (the ``TYPE_*`` ints that map refers to by name).

The output lists, per five-character prefix any of them names: a constant naming it
(the model constant, else the ``TYPE_*`` name of its device type), its device kind,
the cloud ``device_type`` when the map gives one, and its product categories, nearest
first. The kind is the app's product category (:data:`CATEGORY_KINDS`), as the app
decides whether a product shows a camera card and opens a live view. A product the
configuration files under no category takes the kind its constant's name reads as
(:data:`KIND_RULES`); such a prefix whose constants read as different kinds is left out
and reported. ``--check`` compares with the committed module.

Runs on a maintainer host (the app's code is not shipped):

    gen_app_models.py --device-config FILE --constants FILE --type-map FILE
                      --device-types FILE --app-version V [--out FILE] [--check]
                      [--allow-shrink]

It refuses (exit 1, nothing written) when the inputs give no rows, or fewer than
:data:`SHRINK_MARGIN` of the rows ``--out`` holds unless ``--allow-shrink``.
"""

from __future__ import annotations

import argparse
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_OUT = ROOT / "src" / "eufy_home_security" / "devices" / "app_models.py"
#: The share of ``--out``'s rows a run must keep without ``--allow-shrink``.
SHRINK_MARGIN = 0.9
PREFIX = re.compile(r"T[0-9A-Z]{4}")
#: A product code key of the device configuration (``T8110E``, ``T87B0-V``); every
#: other key is a category label.
PRODUCT_CODE = re.compile(r"T[0-9][0-9A-Z-]*")
#: The configuration's root, which every product and category descends from.
ROOT_CATEGORY = "Base"

_CONSTANT = re.compile(r'public static final String ([A-Z0-9_]+) = "([^"]*)";')
_ROW = re.compile(r'^    \("', re.MULTILINE)
_TYPE_INT = re.compile(r"public static final int (TYPE_[A-Za-z0-9_]+) = (\d+);")
_TYPE_PUT = re.compile(
    r"hashMap\.put\((?:Integer\.valueOf\()?(?:[A-Za-z]\w*\.)?([A-Za-z0-9_]+)\)?, "
    r"new String\[\]\{([^}]*)\}\);"
)
_TYPE_NAME_PREFIX = re.compile(r"^TYPE_(?:DEVICE_)?")

#: Kind by the words of the app's constant name, first match wins. A siren accessory
#: (``SIREN_SENSOR``) is no sensor and a chime (``DOORBELL_CHIME_8028``) no doorbell:
#: they sound, they do not trigger or ring.
KIND_RULES: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("other", ("SIREN", "CHIME")),
    ("station", ("STATION",)),
    ("keypad", ("KEYPAD",)),
    ("lock", ("LOCK",)),
    ("doorbell", ("DOORBELL",)),
    ("sensor", ("SENSOR",)),
    ("camera", ("CAM", "CAMERA", "DOGCAM", "FLOODLIGHT", "FLOODLIGHT2", "WALLLIGHT")),
)
OTHER = "other"

#: Kind by the app's product category; the nearest category of a product that is listed
#: here decides, any other category reads as ``other``. A video doorbell and a video lock
#: are cameras to the app too, a siren a sensor (see :data:`KIND_RULES`).
CATEGORY_KINDS: dict[str, str] = {
    "HomeBase": "station",
    "VideoDoorbell": "doorbell",
    "VideoSmartLock": "lock",
    "SmartLock": "lock",
    "SirenSensor": "other",
    "Sensor": "sensor",
    "Camera": "camera",
}

Row = tuple[str, str | None, str, int | None, tuple[str, ...]]


def kind_of(constant: str) -> str:
    """The device kind a constant's name reads as (:data:`KIND_RULES`), else ``other``."""
    words = set(constant.split("_"))
    words |= {w.rstrip("0123456789") for w in words}  # CAMERA2C → CAMERA, CAMERA3 → CAMERA
    words |= {re.sub(r"\d.*$", "", w) for w in words}
    for kind, markers in KIND_RULES:
        if words & set(markers):
            return kind
    return OTHER


def category_kind(categories: tuple[str, ...]) -> str | None:
    """The kind of a product with ``categories`` (nearest first, :data:`CATEGORY_KINDS`);
    None for a product under no category."""
    for category in categories:
        if category in CATEGORY_KINDS:
            return CATEGORY_KINDS[category]
    return OTHER if categories else None


def categories(text: str) -> dict[str, tuple[str, ...]]:
    """Each five-character product code of the device configuration with its categories,
    nearest first, the root left out. A product filed under another product (a variant
    code) inherits that product's categories. A parent cycle raises ``ValueError``."""
    entries = json.loads(text)
    label = {key.upper(): key for key in entries}
    parent = {key.upper(): (value.get("parent") or "").upper() for key, value in entries.items()}
    out: dict[str, tuple[str, ...]] = {}
    for key in label:
        if not PRODUCT_CODE.fullmatch(key) or not PREFIX.fullmatch(key):
            continue
        chain: list[str] = []
        seen = {key}
        node = parent[key]
        while node and node in label:
            if node in seen:
                raise ValueError(f"{key}: parent cycle at {label[node]}")
            seen.add(node)
            if not PRODUCT_CODE.fullmatch(node) and label[node] != ROOT_CATEGORY:
                chain.append(label[node])
            node = parent[node]
        out[key] = tuple(chain)
    return out


def constants(text: str) -> dict[str, list[str]]:
    """Each five-character prefix with the constant names that hold it, in file order."""
    found: dict[str, list[str]] = {}
    for name, value in _CONSTANT.findall(text):
        if PREFIX.fullmatch(value):
            found.setdefault(value, []).append(name)
    return found


def type_names(type_ints: str) -> dict[int, str]:
    """Each device type the ints name exactly once, with that name less its ``TYPE_``
    (``TYPE_DEVICE_CAMERA3_PRO = 26`` → ``CAMERA3_PRO``)."""
    names: dict[int, list[str]] = {}
    for name, value in _TYPE_INT.findall(type_ints):
        names.setdefault(int(value), []).append(_TYPE_NAME_PREFIX.sub("", name))
    return {number: listed[0] for number, listed in names.items() if len(listed) == 1}


def device_types(type_map: str, type_ints: str) -> dict[str, int]:
    """Each prefix the device-type map names, with its type; a name the ints do not define
    is skipped. A prefix named under two types raises ``ValueError``."""
    ints = {name: int(value) for name, value in _TYPE_INT.findall(type_ints)}
    out: dict[str, int] = {}
    for key, listed in _TYPE_PUT.findall(type_map):
        number = int(key) if key.isdigit() else ints.get(key)
        if number is None:
            continue
        for prefix in re.findall(r'"([^"]+)"', listed):
            if not PREFIX.fullmatch(prefix):
                continue
            if prefix in out and out[prefix] != number:
                raise ValueError(f"{prefix} is mapped to device types {out[prefix]} and {number}")
            out[prefix] = number
    return out


def build(
    named: dict[str, list[str]],
    types: dict[str, int],
    categorised: dict[str, tuple[str, ...]],
    typed_names: dict[int, str],
) -> tuple[list[Row], list[str]]:
    """The rows ``(prefix, constant, kind, device_type, categories)`` sorted by prefix, and
    the prefixes left out because they have no category and their constants read as
    different kinds.

    The constant is the shortest name reading as the row's kind, a model constant before
    the device type's name; else the shortest model constant, the device type's name or
    None. Under the generic ``Sensor``
    category, which also holds the keypad, a constant reading as a keypad keeps it one.
    """
    rows: list[Row] = []
    conflicts: list[str] = []
    for prefix in sorted(set(named) | set(types) | set(categorised)):
        device_type = types.get(prefix)
        type_name = typed_names.get(device_type) if device_type is not None else None
        names = named.get(prefix) or ([type_name] if type_name else [])
        cats = categorised.get(prefix, ())
        kind = category_kind(cats)
        name_kinds = {kind_of(n) for n in names}
        if kind is None:
            if len(name_kinds) > 1:
                listed = ", ".join(f"{n} ({kind_of(n)})" for n in names)
                conflicts.append(f"{prefix}: {listed}")
                continue
            kind = name_kinds.pop() if name_kinds else OTHER
        elif kind == "sensor" and "keypad" in name_kinds:
            kind = "keypad"
        typed = [type_name] if type_name else []
        choice = (
            [n for n in names if kind_of(n) == kind]
            or [n for n in typed if kind_of(n) == kind]
            or names
        )
        constant = min(choice, key=len) if choice else None
        rows.append((prefix, constant, kind, device_type, cats))
    return rows, conflicts


def _literal(row: Row) -> str:
    prefix, constant, kind, device_type, cats = row
    name = "None" if constant is None else f'"{constant}"'
    chain = "(" + ", ".join(f'"{c}"' for c in cats) + ("," if len(cats) == 1 else "") + ")"
    return f'    ("{prefix}", {name}, "{kind}", {device_type}, {chain}),'


def render(rows: list[Row], app_version: str) -> str:
    """The generated module's text."""
    lines = [
        f'"""Product models of the eufy Security app {app_version}: generated by',
        "``scripts/gen_app_models.py``, do not edit.",
        "",
        "Per serial prefix: the app's constant naming it (None where none does), its device",
        "kind, the cloud ``device_type`` from the app's device-type map (None where it gives",
        "none) and the app's product categories, nearest first (empty where the app files",
        'it under none)."""',
        "",
        "from __future__ import annotations",
        "",
        "from typing import Final",
        "",
        f'APP_VERSION: Final = "{app_version}"',
        "",
        "# fmt: off",
        "APP_MODELS: Final[tuple[tuple[str, str | None, str, int | None, tuple[str, ...]], ...]] = (",
    ]
    lines += [_literal(row) for row in rows]
    lines += [")", "# fmt: on", ""]
    return "\n".join(lines)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").split("\n\n")[0])
    parser.add_argument(
        "--device-config", type=Path, required=True, help="the app's device configuration JSON"
    )
    parser.add_argument(
        "--constants", type=Path, required=True, help="the app's model constants file"
    )
    parser.add_argument(
        "--type-map", type=Path, required=True, help="the app's device-type map file"
    )
    parser.add_argument(
        "--device-types", type=Path, required=True, help="the app's device-type ints file"
    )
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--app-version", required=True, help="the app build the inputs are from")
    parser.add_argument("--check", action="store_true", help="compare with --out, write nothing")
    parser.add_argument(
        "--allow-shrink", action="store_true", help="write even when rows drop beyond the margin"
    )
    args = parser.parse_args(argv)
    sources = (args.device_config, args.constants, args.type_map, args.device_types)
    missing = [str(p) for p in sources if not p.is_file()]
    if missing:
        print(f"missing input: {', '.join(missing)}", file=sys.stderr)
        return 2
    type_ints = args.device_types.read_text(encoding="utf-8")
    rows, conflicts = build(
        constants(args.constants.read_text(encoding="utf-8")),
        device_types(args.type_map.read_text(encoding="utf-8"), type_ints),
        categories(args.device_config.read_text(encoding="utf-8")),
        type_names(type_ints),
    )
    for line in conflicts:
        print(f"left out, kinds differ: {line}", file=sys.stderr)
    if not rows:
        print("no models in the inputs; nothing written", file=sys.stderr)
        return 1
    before = len(_ROW.findall(args.out.read_text(encoding="utf-8"))) if args.out.is_file() else 0
    if len(rows) < before * SHRINK_MARGIN and not args.allow_shrink:
        print(
            f"{len(rows)} models against {before} in {args.out}; nothing written "
            "(--allow-shrink to write)",
            file=sys.stderr,
        )
        return 1
    text = render(rows, args.app_version)
    if args.check:
        same = args.out.is_file() and args.out.read_text(encoding="utf-8") == text
        print("check: up to date" if same else f"check: {args.out} differs")
        return 0 if same else 1
    args.out.write_text(text, encoding="utf-8")
    print(f"{len(rows)} models written to {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
