"""Build a dev wheel whose version names the commit: ``<version>+g<sha>`` (``.dirty`` if edited).

Rebuilding with an unchanged version and reinstalling it is a silent no-op, so a
test host can keep running old code without anything showing it. This stamps a
PEP 440 local label on a copy of the tree (``pyproject.toml`` is never changed, so
release-please keeps the public version) and builds the wheel into ``dist/``.
Dev builds only: PyPI rejects local labels.

    VIRTUAL_ENV= uv run python scripts/dev_build.py
    uv pip install --reinstall-package eufy-home-security dist/eufy_home_security-*+g*.whl

Extra arguments are passed to ``uv build``.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys
import tempfile
import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_VERSION_LINE = re.compile(r'^version = "[^"]*"$', re.MULTILINE)


def _git(*args: str) -> str:
    return subprocess.run(
        ["git", *args], cwd=ROOT, capture_output=True, text=True, check=True
    ).stdout


def local_version(version: str, sha: str, *, dirty: bool) -> str:
    """``version`` with a PEP 440 local label naming the commit."""
    return f"{version}+g{sha}{'.dirty' if dirty else ''}"


def stamp_pyproject(text: str, version: str) -> str:
    """``pyproject.toml`` text with the ``[project]`` version replaced (exactly once)."""
    stamped, count = _VERSION_LINE.subn(f'version = "{version}"', text, count=1)
    if count != 1:
        raise ValueError("pyproject.toml has no top-level version line")
    return stamped


def main(argv: list[str]) -> int:
    pyproject = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    base = tomllib.loads(pyproject)["project"]["version"]
    sha = _git("rev-parse", "--short=7", "HEAD").strip()
    dirty = bool(_git("status", "--porcelain", "--untracked-files=no").strip())
    version = local_version(base, sha, dirty=dirty)
    files = _git("ls-files", "--cached", "--others", "--exclude-standard").splitlines()
    with tempfile.TemporaryDirectory(prefix="eufy-dev-build-") as tmp:
        tree = Path(tmp)
        for name in files:
            source = ROOT / name
            if source.is_file():
                (tree / name).parent.mkdir(parents=True, exist_ok=True)
                shutil.copy2(source, tree / name)
        (tree / "pyproject.toml").write_text(stamp_pyproject(pyproject, version), "utf-8")
        cmd = ["uv", "build", "--wheel", "--out-dir", str(ROOT / "dist"), *argv, str(tree)]
        result = subprocess.run(cmd, check=False)
    if result.returncode == 0:
        print(f"built eufy-home-security {version}")
    return result.returncode


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
