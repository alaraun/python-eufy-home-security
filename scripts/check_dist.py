"""Check the built sdist and wheel the way a user installs them.

    uv run --no-project python scripts/check_dist.py              # builds into a temp dir
    uv run --no-project python scripts/check_dist.py --dist dist  # checks an existing build

Checks, in order: exactly one sdist and one wheel of the project's name and version;
``twine check --strict`` and ``check-wheel-contents``; the sdist holds only what builds
the wheel; the wheel rebuilt from the sdist is byte-identical to the one given; the
wheel and the sdist each install into a clean venv, import, find their package data and
run ``eufy-security --help`` outside the source tree; ``uv tool install`` and
``uvx --from <wheel>`` run the CLI. Needs ``uv`` and network access (dependencies,
check tools). Exits non-zero on the first failure.
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zipfile
from collections.abc import Iterable
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
MODULE = "eufy_home_security"
SCRIPT = "eufy-security"
# Top-level sdist entries: the build inputs and the files a redistributor needs.
SDIST_TOP = frozenset({"PKG-INFO", "pyproject.toml", "README.md", "LICENSE", "CHANGELOG.md", "src"})
WHEEL_REQUIRED = (
    f"{MODULE}/py.typed",
    f"{MODULE}/devices/data/models/T8160.json",
)
JUNK = ("__pycache__/", ".pyc", ".pyo", ".DS_Store", ".orig", ".rej")
TWINE = "twine>=6.1"  # Metadata-Version 2.4 (PEP 639 license expressions)
CHECK_WHEEL_CONTENTS = "check-wheel-contents>=0.6"
# Run by the installed interpreter from an empty directory, so the source tree is not importable.
SMOKE = f"""
import importlib.metadata, importlib.resources, pathlib, sys
import {MODULE} as pkg
from {MODULE}.devices.model_settings import settings_of
root = pathlib.Path(pkg.__file__).resolve()
assert "site-packages" in root.parts, root
assert pkg.__version__ == importlib.metadata.version("eufy-home-security") == sys.argv[1], pkg.__version__
assert importlib.resources.files("{MODULE}").joinpath("py.typed").is_file()
assert settings_of("T8160"), "no T8160 settings"
print(pkg.__version__, root.parent)
"""


def _junk(name: str) -> bool:
    return name.endswith(JUNK) or "/__pycache__/" in name


def unexpected_sdist_members(names: Iterable[str], stem: str) -> list[str]:
    """Members of an sdist named ``stem`` outside its allowed top level, or build junk."""
    return [
        name
        for name in names
        if name.rstrip("/") != stem
        and (
            not name.startswith(f"{stem}/")
            or name.removeprefix(f"{stem}/").split("/")[0] not in SDIST_TOP
            or _junk(name)
        )
    ]


def unexpected_wheel_members(names: Iterable[str], dist_info: str) -> list[str]:
    """Wheel members outside the package and its ``.dist-info``, or build junk."""
    return [
        name
        for name in names
        if not name.startswith((f"{MODULE}/", f"{dist_info}/")) or _junk(name)
    ]


def _run(*cmd: str | Path, cwd: Path | None = None, env: dict[str, str] | None = None) -> str:
    print("+", " ".join("<script>" if "\n" in str(c) else str(c) for c in cmd), flush=True)
    result = subprocess.run(
        [str(c) for c in cmd], cwd=cwd, env=env, capture_output=True, text=True, check=False
    )
    if result.returncode != 0:
        sys.stderr.write(result.stdout + result.stderr)
        raise SystemExit(f"failed ({result.returncode}): {cmd[0]} {cmd[1] if len(cmd) > 1 else ''}")
    return result.stdout


def _fail(message: str) -> None:
    raise SystemExit(f"check_dist: {message}")


def _artifacts(dist: Path, name: str, version: str) -> tuple[Path, Path]:
    stem = f"{name.replace('-', '_')}-{version}"
    sdists = sorted(dist.glob("*.tar.gz"))
    wheels = sorted(dist.glob("*.whl"))
    if [p.name for p in sdists] != [f"{stem}.tar.gz"]:
        _fail(f"expected only {stem}.tar.gz in {dist}, found {[p.name for p in sdists]}")
    if [p.name for p in wheels] != [f"{stem}-py3-none-any.whl"]:
        _fail(f"expected only {stem}-py3-none-any.whl in {dist}, found {[p.name for p in wheels]}")
    return sdists[0], wheels[0]


def _check_contents(sdist: Path, wheel: Path, stem: str) -> None:
    with tarfile.open(sdist) as archive:
        sdist_names = archive.getnames()
    if bad := unexpected_sdist_members(sdist_names, stem):
        _fail(f"unexpected sdist members: {bad[:10]}")
    with zipfile.ZipFile(wheel) as archive:
        wheel_names = archive.namelist()
    if bad := unexpected_wheel_members(wheel_names, f"{stem}.dist-info"):
        _fail(f"unexpected wheel members: {bad[:10]}")
    if missing := [m for m in WHEEL_REQUIRED if m not in wheel_names]:
        _fail(f"wheel lacks {missing}")
    print(f"sdist: {len(sdist_names)} members, {sdist.stat().st_size} bytes")
    print(f"wheel: {len(wheel_names)} members, {wheel.stat().st_size} bytes")


def _check_rebuild(sdist: Path, wheel: Path, stem: str, work: Path) -> None:
    with tarfile.open(sdist) as archive:
        archive.extractall(work / "sdist", filter="data")
    out = work / "rebuilt"
    _run("uv", "build", "--wheel", "--no-sources", "--out-dir", out, work / "sdist" / stem)
    if (out / wheel.name).read_bytes() != wheel.read_bytes():
        _fail("the wheel rebuilt from the sdist differs from the one given")


def _check_install(artifact: Path, version: str, work: Path, python: str | None) -> None:
    venv = work / f"venv-{artifact.suffix.lstrip('.')}"
    _run("uv", "venv", "--quiet", venv, *(["--python", python] if python else []))
    interpreter = venv / "bin" / "python"
    _run("uv", "pip", "install", "--quiet", "--python", interpreter, artifact)
    empty = work / "empty"
    empty.mkdir(exist_ok=True)
    print(_run(interpreter, "-I", "-c", SMOKE, version, cwd=empty), end="")
    _run(venv / "bin" / SCRIPT, "--help", cwd=empty)


def _check_tool(wheel: Path, work: Path) -> None:
    env = {**os.environ, "UV_TOOL_DIR": str(work / "tools"), "UV_TOOL_BIN_DIR": str(work / "bin")}
    _run("uv", "tool", "install", "--quiet", wheel, env=env)
    _run(work / "bin" / SCRIPT, "--help", cwd=work)
    _run("uv", "tool", "run", "--isolated", "--from", wheel, SCRIPT, "--help", cwd=work)


def main(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(description=(__doc__ or "").splitlines()[0])
    parser.add_argument("--dist", type=Path, help="directory with the built sdist and wheel")
    parser.add_argument("--python", help="interpreter for the clean venvs (uv --python)")
    args = parser.parse_args(argv)
    project = tomllib.loads((ROOT / "pyproject.toml").read_text("utf-8"))["project"]
    stem = f"{project['name'].replace('-', '_')}-{project['version']}"
    with tempfile.TemporaryDirectory(prefix="eufy-check-dist-") as tmp:
        work = Path(tmp)
        dist = args.dist
        if dist is None:
            dist = work / "dist"
            _run("uv", "build", "--no-sources", "--out-dir", dist, ROOT)
        sdist, wheel = _artifacts(dist.resolve(), project["name"], project["version"])
        _run("uvx", "--from", TWINE, "twine", "check", "--strict", sdist, wheel)
        _run("uvx", CHECK_WHEEL_CONTENTS, wheel)
        _check_contents(sdist, wheel, stem)
        _check_rebuild(sdist, wheel, stem, work)
        _check_install(wheel, project["version"], work, args.python)
        _check_install(sdist, project["version"], work, args.python)
        _check_tool(wheel, work)
    print(f"check_dist: {sdist.name} and {wheel.name} OK")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
