"""Guard: no real identifier from the private denylist is in the tree."""

from __future__ import annotations

import importlib.util
import os
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_denylist.py"


def _run(env: dict[str, str]) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(SCRIPT)],
        cwd=ROOT,
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )


def test_denylist_ignores_indented_comments_and_blank_lines(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    denylist = tmp_path / "denylist.txt"
    denylist.write_text("# header\n   # indented note\n\n   \n  T0000P0000000001  \n", "utf-8")
    monkeypatch.setenv("EUFY_DENYLIST", str(denylist))
    spec = importlib.util.spec_from_file_location("check_denylist", SCRIPT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.load_denylist() == ["t0000p0000000001"]


@pytest.mark.parametrize(
    ("extra", "code"), [({}, 1), ({"CI": "1"}, 0), ({"EUFY_DENYLIST_SKIP": "1"}, 0)]
)
def test_a_missing_denylist_fails_unless_ci_or_opted_out(
    tmp_path: Path, extra: dict[str, str], code: int
) -> None:
    env = {k: v for k, v in os.environ.items() if k not in ("CI", "EUFY_DENYLIST_SKIP")}
    env |= {"EUFY_DENYLIST": str(tmp_path / "nonexistent"), **extra}
    result = _run(env)
    assert result.returncode == code, result.stdout
    assert "not found" in result.stdout


def test_no_real_identifiers_in_tree() -> None:
    result = _run(dict(os.environ))
    assert result.returncode == 0, result.stdout
