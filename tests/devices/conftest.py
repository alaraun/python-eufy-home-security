"""Device-test hooks: a test marked ``needs_node`` runs the generators' Node driver and is
skipped, with the reason, unless ``node`` of the major ``scripts/package.json`` pins is on
PATH."""

from __future__ import annotations

import functools
import importlib.util
from pathlib import Path

import pytest

NODE_SUPPORT = Path(__file__).resolve().parents[2] / "scripts" / "gen_models_node.py"


@functools.cache
def node_problem() -> str | None:
    """Why the driver cannot run here (``gen_models_node.node_problem``), or None."""
    spec = importlib.util.spec_from_file_location("_node_support", NODE_SUPPORT)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    problem: str | None = module.node_problem()
    return problem


def pytest_configure(config: pytest.Config) -> None:
    config.addinivalue_line(
        "markers", "needs_node: runs the Node driver; skipped without Node of the pinned major"
    )


def pytest_runtest_setup(item: pytest.Item) -> None:
    if item.get_closest_marker("needs_node") is not None and (problem := node_problem()):
        pytest.skip(f"needs Node of the pinned major: {problem}")
