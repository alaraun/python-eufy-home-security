"""Fail if a tracked file contains a real identifier from the private denylist.

The denylist (real serials, P2P ids, account ids, LAN addresses) lives in
``.work/denylist.txt`` — outside this repository's history by design. Point
``EUFY_DENYLIST`` at another file to override.

A missing denylist fails the check, so a maintainer's lost list is never mistaken
for a clean tree. It only warns (exit 0) when ``CI`` is set (a CI runner has no
private data to protect) or when ``EUFY_DENYLIST_SKIP=1`` is set (a contributor who
does not have the private list; see CONTRIBUTING.md).
"""

from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SKIP_ENV = "EUFY_DENYLIST_SKIP"


def denylist_path() -> Path:
    return Path(os.environ.get("EUFY_DENYLIST", ROOT / ".work" / "denylist.txt"))


def load_denylist() -> list[str] | None:
    """The lower-cased needles, or None when the denylist file is missing."""
    path = denylist_path()
    if not path.is_file():
        return None
    stripped = (line.strip() for line in path.read_text(encoding="utf-8").splitlines())
    # Strip first: an indented "# ..." is still a comment, and a blank line is no needle.
    return [line.lower() for line in stripped if line and not line.startswith("#")]


def tracked_files(paths: list[str]) -> list[Path]:
    if paths:
        return [Path(p) for p in paths]
    out = subprocess.run(
        ["git", "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=True,
    ).stdout
    return [ROOT / line for line in out.splitlines() if line]


def main(argv: list[str]) -> int:
    needles = load_denylist()
    if needles is None:
        why = (
            "CI is set"
            if os.environ.get("CI")
            else f"{SKIP_ENV}=1"
            if os.environ.get(SKIP_ENV) == "1"
            else None
        )
        if why is None:
            print(
                f"denylist: {denylist_path()} not found; failing "
                f"(set {SKIP_ENV}=1 if you do not have the private list)"
            )
            return 1
        print(f"denylist: warning: {denylist_path()} not found; skipping ({why})")
        return 0
    hits = []
    for path in tracked_files(argv):
        try:
            text = path.read_bytes().decode("utf-8", "ignore").lower()
        except OSError:
            continue
        hits.extend(f"{path}: {needle}" for needle in needles if needle in text)
    for hit in hits:
        print(f"real identifier found: {hit}")
    return 1 if hits else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
