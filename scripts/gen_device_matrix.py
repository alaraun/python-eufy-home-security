"""Write docs/reference/devices.md from the device catalog and the bundled settings files.

``--check`` writes nothing and exits 1 when the file is stale.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from eufy_home_security.devices.matrix import render_support_matrix

OUTPUT = Path(__file__).resolve().parent.parent / "docs" / "reference" / "devices.md"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="fail if the file is stale")
    parser.add_argument("--output", type=Path, default=OUTPUT)
    args = parser.parse_args(argv)
    content = render_support_matrix()
    current = args.output.read_text(encoding="utf-8") if args.output.is_file() else None
    if args.check:
        if current != content:
            print(f"{args.output} is stale; run scripts/gen_device_matrix.py", file=sys.stderr)
            return 1
        return 0
    if current != content:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(content, encoding="utf-8")
        print(f"wrote {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
