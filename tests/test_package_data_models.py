"""Every bundled model file is in a built wheel, and the removed v1 data is not.

``tests/test_package_data.py`` checks two members (T8160, T8170). This covers every
other model: one whose ``<PN>.json`` git does not track would pass every source-tree
test and silently fail to ship. The wheel is built the way
``scripts/dev_build.py`` builds it — from the ``git ls-files --cached --others
--exclude-standard`` tree, ``uv build --wheel --offline``, entirely under ``tmp_path``
— and the archive itself is inspected.
"""

from __future__ import annotations

import json
import shutil
import subprocess
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODELS = "eufy_home_security/devices/data/models/"
DATA = "eufy_home_security/devices/data/"


def _wheel_members(tmp_path: Path) -> set[str]:
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
        return set(archive.namelist())


def test_every_indexed_model_snapshot_ships_and_nothing_else(tmp_path: Path) -> None:
    """The wheel holds exactly one ``models/<PN>.json`` per ``INDEX.json`` code (107), the
    index and the resource packages, and none of the removed v1 data or modules."""
    codes = json.loads((ROOT / "src" / MODELS / "INDEX.json").read_text("utf-8"))["codes"]
    assert len(codes) == 107
    members = _wheel_members(tmp_path)
    shipped = {
        member.removeprefix(MODELS).removesuffix(".json")
        for member in members
        if member.startswith(MODELS) and member.endswith(".json")
    }
    assert sorted(shipped - {"INDEX"}) == sorted(codes)
    for required in (f"{DATA}__init__.py", f"{MODELS}__init__.py", f"{MODELS}INDEX.json"):
        assert required in members, required
    for removed in (
        f"{DATA}corpus_unanimous.json",
        "eufy_home_security/devices/registry.py",
        "eufy_home_security/devices/aliases.py",
        f"{DATA}app_choice_labels.json",
    ):
        assert removed not in members, removed
    assert [m for m in members if "td_corpus" in m] == []
    # models/ and the device time-zone table are the only data files.
    outside = {m for m in members if m.startswith(DATA) and not m.startswith(MODELS)}
    assert outside <= {DATA, f"{DATA}__init__.py", f"{DATA}timezones.json"}
    assert f"{DATA}timezones.json" in members
