"""scripts/dev_build.py: the PEP 440 local label stamped on a dev wheel."""

from __future__ import annotations

import importlib.util
from pathlib import Path
from types import ModuleType

import pytest

ROOT = Path(__file__).resolve().parent.parent


def _script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("dev_build", ROOT / "scripts" / "dev_build.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_local_label_names_the_commit_and_leaves_other_versions_alone() -> None:
    script = _script()
    assert script.local_version("0.1.0", "abc1234", dirty=False) == "0.1.0+gabc1234"
    assert script.local_version("0.1.0", "abc1234", dirty=True) == "0.1.0+gabc1234.dirty"
    text = '[project]\nname = "x"\nversion = "0.1.0"\n\n[tool.x]\ntarget-version = "py313"\n'
    stamped = script.stamp_pyproject(text, "0.1.0+gabc1234")
    assert 'version = "0.1.0+gabc1234"' in stamped
    assert 'target-version = "py313"' in stamped
    with pytest.raises(ValueError, match="no top-level version"):
        script.stamp_pyproject("[project]\n", "0.1.0+gabc1234")
