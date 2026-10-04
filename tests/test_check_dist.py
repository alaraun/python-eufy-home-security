"""scripts/check_dist.py: which sdist and wheel members count as unexpected."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

ROOT = Path(__file__).resolve().parent.parent
STEM = "eufy_home_security-0.1.0"


def _script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("check_dist", ROOT / "scripts" / "check_dist.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_sdist_holds_only_the_build_inputs() -> None:
    script = _script()
    allowed = [
        f"{STEM}",
        f"{STEM}/",
        f"{STEM}/PKG-INFO",
        f"{STEM}/pyproject.toml",
        f"{STEM}/LICENSE",
        f"{STEM}/src/eufy_home_security/__init__.py",
    ]
    rejected = [
        f"{STEM}/tests/conftest.py",
        f"{STEM}/docs/README.md",
        f"{STEM}/.work/notes.md",
        f"{STEM}/src/eufy_home_security/__pycache__/x.cpython-313.pyc",
        "other-0.1.0/pyproject.toml",
    ]
    assert script.unexpected_sdist_members(allowed + rejected, STEM) == rejected


def test_the_wheel_holds_only_the_package_and_its_metadata() -> None:
    script = _script()
    dist_info = f"{STEM}.dist-info"
    allowed = ["eufy_home_security/py.typed", f"{dist_info}/METADATA"]
    rejected = ["tests/conftest.py", "eufy_home_security/__pycache__/x.pyc", "scripts/x.py"]
    assert script.unexpected_wheel_members(allowed + rejected, dist_info) == rejected
