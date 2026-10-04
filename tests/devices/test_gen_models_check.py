"""``scripts/gen_models.py --check`` regenerates two models byte-identically.

Runs only on a maintainer host with Node and the private thing-model cache; the full-corpus
``--check`` is the maintainer's command (docs/reference/models-schema.md).
"""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CACHE = ROOT / ".work" / "cache" / "things_all"

pytestmark = [
    pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed"),
    pytest.mark.skipif(
        not (CACHE / "T8160" / "td.json").is_file(), reason="no private thing-model cache"
    ),
]


@pytest.mark.timeout(180)
def test_check_regenerates_committed_files_byte_identically() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "gen_models.py"), "--check", "T8160", "T8910"],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=170,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "check: 0 files differ" in result.stdout
