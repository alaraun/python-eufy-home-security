"""The model snapshot ships inside a built wheel.

A source-tree check is not enough: ``scripts/dev_build.py`` copies only
``git ls-files --cached --others --exclude-standard`` output into the build tree, so a
snapshot file git does not know about passes a source-tree assertion and silently fails to
ship. This test builds a wheel the same way, offline and entirely under ``tmp_path``, and
inspects the archive itself.
"""

from __future__ import annotations

import shutil
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SNAPSHOT_MEMBERS = (
    "eufy_home_security/devices/data/models/T8160.json",
    "eufy_home_security/devices/data/models/T8170.json",
)


def test_the_model_snapshot_ships_in_a_built_wheel(tmp_path: Path) -> None:
    """A wheel built from the ``git ls-files`` tree contains the T8160 and T8170 snapshots."""
    git = shutil.which("git")
    uv = shutil.which("uv")
    assert git is not None
    assert uv is not None
    files = subprocess.run(
        [git, "ls-files", "--cached", "--others", "--exclude-standard"],
        cwd=ROOT,
        check=True,
        capture_output=True,
        text=True,
    ).stdout.splitlines()
    tree = tmp_path / "tree"
    dist = tmp_path / "dist"
    for name in files:
        source = ROOT / name
        if source.is_file():
            (tree / name).parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(source, tree / name)
    subprocess.run(
        [uv, "build", "--wheel", "--offline", "--out-dir", str(dist), str(tree)],
        check=True,
        capture_output=True,
    )
    (wheel,) = dist.glob("*.whl")
    with zipfile.ZipFile(wheel) as archive:
        members = set(archive.namelist())
    assert [m for m in SNAPSHOT_MEMBERS if m not in members] == []
