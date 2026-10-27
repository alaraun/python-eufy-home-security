"""scripts/check_generated.py runs every generator's ``--check`` at once and fails when
any of them does, naming it and showing its output."""

from __future__ import annotations

import importlib.util
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


check = _load("check_generated")


def _py(code: str) -> list[str]:
    return [sys.executable, "-c", code]


def test_all_checks_passing_exits_0(capsys: pytest.CaptureFixture[str]) -> None:
    assert check.run_checks({"a": _py("print('up to date')"), "b": _py("")}) == 0
    lines = capsys.readouterr().out.splitlines()
    assert [line.split()[:2] for line in lines[:2]] == [["ok", "a"], ["ok", "b"]]
    assert lines[-1] == "2 passed, 0 failed"


def test_a_failing_check_is_named_with_its_output(capsys: pytest.CaptureFixture[str]) -> None:
    checks = {
        "a": _py("import sys; print('x.py differs'); sys.exit(1)"),
        "b": _py(""),
        "c": _py("import sys; sys.stderr.write('no cache'); sys.exit(2)"),
    }
    assert check.run_checks(checks) == 1
    out = capsys.readouterr().out
    assert out.index("FAILED  a (exit 1") < out.index("    x.py differs") < out.index("ok      b")
    assert "FAILED  c (exit 2" in out
    assert "    no cache" in out
    assert out.endswith("1 passed, 2 failed\n")


def test_the_checks_run_at_once() -> None:
    sleeper = _py("import time; time.sleep(1)")
    checks = dict.fromkeys("abcd", sleeper)
    start = time.monotonic()
    assert check.run_checks(checks) == 0
    assert time.monotonic() - start < 3


def test_names_skip_and_jobs_pick_the_commands() -> None:
    picked = check.commands(["gen_models", "gen_ptz"], jobs=3)
    assert picked["gen_models"][1:] == [
        str(ROOT / "scripts" / "gen_models.py"),
        "--check",
        "--jobs",
        "3",
    ]
    assert picked["gen_ptz"][1:] == [str(ROOT / "scripts" / "gen_ptz.py"), "--check"]
    assert "--jobs" not in check.commands(["gen_models"])["gen_models"]


def test_every_listed_generator_exists_and_has_a_check() -> None:
    for name in check.CHECKS:
        script = ROOT / "scripts" / f"{name}.py"
        assert "--check" in script.read_text(encoding="utf-8"), name


def test_an_unknown_name_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    ran: list[Any] = []
    monkeypatch.setattr(check, "run_checks", ran.append)
    with pytest.raises(SystemExit) as exc:
        check.main(["gen_nothing"])
    assert exc.value.code == 2
    check.main(["gen_ptz", "gen_timezones", "--skip", "gen_ptz"])
    assert list(ran[0]) == ["gen_timezones"]
