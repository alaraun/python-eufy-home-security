"""Read docs/reference/hardware-verification.md's area table for the catalog tests."""

from __future__ import annotations

import re
from pathlib import Path

LOG = Path(__file__).resolve().parents[2] / "docs" / "reference" / "hardware-verification.md"
VERIFIED_MARK = "✓"


def log_rows() -> dict[str, tuple[str, str]]:
    """``area -> (verified mark, notes)`` for every row of the log's tables."""
    rows: dict[str, tuple[str, str]] = {}
    for line in LOG.read_text(encoding="utf-8").splitlines():
        cells = [cell.strip() for cell in line.strip().strip("|").split("|")]
        if not line.startswith("|") or len(cells) < 3 or set(cells[0]) <= {"-"}:
            continue
        rows[cells[0]] = (cells[1], "|".join(cells[2:]))
    return rows


def backticked(text: str) -> set[str]:
    """The ``code`` spans in ``text``."""
    return set(re.findall(r"`([^`]+)`", text))
