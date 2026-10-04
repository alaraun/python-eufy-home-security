"""Generate ``src/eufy_home_security/devices/data/timezones.json`` from the eufy app's zone table.

The app ships one table of device time zones (``res/raw/time_zone_local.json``: rows of
``timeZoneName``, ``timeId``, ``timeSn``, ``timeZoneGMT``). A device stores its zone as
``<timeZoneGMT>|1.<timeSn>`` (param 1215). The output keeps ``id``, ``posix`` and ``sn``
per row, in the table's order. ``--check`` compares with the committed file.

Runs on a maintainer host (the table comes from the unpacked app, not shipped):

    gen_timezones.py [--table FILE] [--out FILE] [--app-version V] [--check]
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_TABLE = (
    ROOT / ".work" / "re" / "decompiled-6.1.10" / "apkres" / "base" / "resources" / "res" / "raw"
) / "time_zone_local.json"
DEFAULT_OUT = ROOT / "src" / "eufy_home_security" / "devices" / "data" / "timezones.json"
DEFAULT_APP_VERSION = "6.1.10"
SOURCE_FILE = "res/raw/time_zone_local.json"


def build(rows: list[dict[str, Any]], app_version: str) -> dict[str, Any]:
    """The data file's object from the app's rows; ValueError on a duplicate or bad row."""
    zones: list[dict[str, Any]] = []
    ids: set[str] = set()
    sns: set[int] = set()
    for row in rows:
        zone_id, posix, sn = row.get("timeId"), row.get("timeZoneGMT"), row.get("timeSn")
        if not (isinstance(zone_id, str) and isinstance(posix, str) and str(sn).isdigit()):
            raise ValueError(f"bad row: {row!r}")
        number = int(sn)
        if zone_id in ids or number in sns:
            raise ValueError(f"duplicate id or sn: {row!r}")
        if "|" in posix:
            raise ValueError(f"posix rule with a separator: {row!r}")
        ids.add(zone_id)
        sns.add(number)
        zones.append({"id": zone_id, "posix": posix, "sn": number})
    return {"source": {"app_version": app_version, "file": SOURCE_FILE}, "zones": zones}


def render(data: dict[str, Any]) -> str:
    """The file text: one zone per line, so a regeneration diff names the zones it moves."""
    lines = [
        "{",
        f'  "source": {json.dumps(data["source"], sort_keys=True)},',
        '  "zones": [',
    ]
    body = [f"    {json.dumps(z, ensure_ascii=False)}" for z in data["zones"]]
    lines.append(",\n".join(body))
    lines += ["  ]", "}"]
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--table", type=Path, default=DEFAULT_TABLE)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--app-version", default=DEFAULT_APP_VERSION)
    parser.add_argument("--check", action="store_true", help="compare, do not write")
    args = parser.parse_args(argv)
    rows = json.loads(args.table.read_text(encoding="utf-8"))
    text = render(build(rows, args.app_version))
    if args.check:
        current = args.out.read_text(encoding="utf-8") if args.out.exists() else ""
        if current != text:
            print(f"{args.out} differs from the table; run {Path(__file__).name}", file=sys.stderr)
            return 1
        return 0
    args.out.write_text(text, encoding="utf-8")
    print(f"wrote {len(json.loads(text)['zones'])} zones to {args.out}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
