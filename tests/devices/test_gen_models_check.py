"""``scripts/gen_models.py --check`` regenerates three models byte-identically, and a run
into an empty directory writes the committed files: which same-codec variants stay comes
from the released-keys manifest alone (T8170 carries a released key that duplicates
another one, kept as its variant).

Runs only on a maintainer host with Node and the private thing-model cache; the full-corpus
``--check`` is the maintainer's command (docs/reference/models-schema.md).
"""

from __future__ import annotations

import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[2]
CACHE = ROOT / ".work" / "cache" / "things_all"
MODELS = ROOT / "src" / "eufy_home_security" / "devices" / "data" / "models"
RELEASED = ROOT / "scripts" / "data" / "released_keys.json"
PN = "T8170"
KEY = "detection_sensitivity_test_mode"  # released, duplicates detection_sensitivity

pytestmark = [
    pytest.mark.skipif(shutil.which("node") is None, reason="node is not installed"),
    pytest.mark.skipif(
        not (CACHE / "T8160" / "td.json").is_file(), reason="no private thing-model cache"
    ),
]


@pytest.mark.timeout(180)
def test_check_regenerates_committed_files_byte_identically() -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "gen_models.py"),
            "--check",
            "T8160",
            "T8170",
            "T8910",
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=170,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr
    assert "check: 0 files differ" in result.stdout


def _generate(out: Path, released: Path = RELEASED) -> None:
    result = subprocess.run(
        [
            sys.executable,
            str(ROOT / "scripts" / "gen_models.py"),
            "--out",
            str(out),
            "--released",
            str(released),
            PN,
        ],
        cwd=ROOT,
        capture_output=True,
        text=True,
        timeout=170,
        check=False,
    )
    assert result.returncode == 0, result.stdout + result.stderr


@pytest.mark.timeout(180)
def test_a_run_into_an_empty_directory_writes_the_committed_file(tmp_path: Path) -> None:
    """The released duplicate stays as variant_of its primary without any earlier file."""
    _generate(tmp_path)
    text = (tmp_path / f"{PN}.json").read_text(encoding="utf-8")
    assert text == (MODELS / f"{PN}.json").read_text(encoding="utf-8")
    assert json.loads(text)["settings"][KEY]["variant_of"] == "detection_sensitivity"


@pytest.mark.timeout(180)
def test_a_duplicate_key_the_manifest_does_not_list_is_dropped(tmp_path: Path) -> None:
    released = json.loads(RELEASED.read_text(encoding="utf-8"))
    released[PN].remove(KEY)
    manifest = tmp_path / "released.json"
    manifest.write_text(json.dumps(released), encoding="utf-8")
    out = tmp_path / "out"
    _generate(out, manifest)
    fresh = json.loads((out / f"{PN}.json").read_text(encoding="utf-8"))["settings"]
    committed = json.loads((MODELS / f"{PN}.json").read_text(encoding="utf-8"))["settings"]
    assert KEY not in fresh
    assert sorted(set(committed) - set(fresh)) == [KEY]
