"""A settings-generator run (scripts/gen_models.py, ``_generate_all``) writes every model
that builds, reports each one that fails and what each printed, in model order whatever
order the models finish in, and exits 1 at the end; the same for one job in process and
for several in worker processes."""

from __future__ import annotations

import argparse
import importlib.util
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from types import ModuleType
from typing import Any

import pytest

ROOT = Path(__file__).resolve().parents[2]


def _load(name: str) -> ModuleType:
    spec = importlib.util.spec_from_file_location(name, ROOT / "scripts" / f"{name}.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gen_models = _load("gen_models")
PNS = ["T9ZZ1", "T9ZZ2", "T9ZZ3", "T9ZZ4", "T9ZZ5"]  # product codes named nowhere
ORDER_GATE: Path | None = None  # set: the first model finishes only after the last one

# Several jobs fork worker processes: that runs in a fresh interpreter without the test
# runner's threads, as on the command line.
SEVERAL_JOBS = """
import importlib.util, sys
from pathlib import Path
spec = importlib.util.spec_from_file_location("test_gen_models_run", sys.argv[1])
test = importlib.util.module_from_spec(spec)
spec.loader.exec_module(test)
test.gen_models.generate = test._fake_generate
test.gen_models.DRIVERS.close()  # as an earlier run leaves it
tmp = Path(sys.argv[2])
test.ORDER_GATE = tmp / "last-model-done"
sys.exit(test.gen_models._generate_all(test._args(tmp, 3), tmp, tmp / "out", quiet=False))
"""


def _fake_generate(pn: str, *_: Any, **__: Any) -> tuple[dict[str, Any], dict[str, int]]:
    if gen_models.DRIVERS._closed:
        raise gen_models.GeneratorError(f"{pn}: driver pool closed")
    if pn == PNS[0] and ORDER_GATE is not None:
        deadline = time.monotonic() + 30
        while not ORDER_GATE.exists() and time.monotonic() < deadline:
            time.sleep(0.01)
        assert ORDER_GATE.exists()
    if pn == PNS[-1]:
        print(f"{pn}: a driver notice", file=sys.stderr)
        if ORDER_GATE is not None:
            ORDER_GATE.touch()
    if pn == "T9ZZ2":
        raise gen_models.CheckError(f"{pn} (SINGLE): 1 codec mismatches")
    if pn == "T9ZZ4":
        raise KeyError("eunmList")
    return {"product_code": pn}, {"rw": 1, "pid": os.getpid()}


def _args(tmp_path: Path, jobs: int) -> argparse.Namespace:
    data = tmp_path / "data"
    data.mkdir()
    for name in ("labels", "trees", "titles", "released"):
        (data / f"{name}.json").write_text("{}", encoding="utf-8")
    return argparse.Namespace(
        product_codes=PNS,
        jobs=jobs,
        app_version="1",
        labels=data / "labels.json",
        trees=data / "trees.json",
        titles=data / "titles.json",
        released=data / "released.json",
    )


def _check_run(rc: int, out_dir: Path, out: str, err: str) -> set[int]:
    """Asserts the run's result; returns the ids of the processes that built the models."""
    assert rc == 1
    assert sorted(p.name for p in out_dir.iterdir()) == [
        "INDEX.json",
        "T9ZZ1.json",
        "T9ZZ3.json",
        "T9ZZ5.json",
    ]
    codes = json.loads((out_dir / "INDEX.json").read_text())["codes"]
    assert codes == ["T9ZZ1", "T9ZZ3", "T9ZZ5"]
    assert [line.split()[0] for line in out.splitlines()] == ["T9ZZ1", "T9ZZ3", "T9ZZ5", "total"]
    lines = err.splitlines()
    assert lines[0] == "T9ZZ2 (SINGLE): 1 codec mismatches"
    assert lines[1] == "T9ZZ4: KeyError: 'eunmList'"
    assert lines[2] == "Traceback (most recent call last):"
    assert err.count("Traceback") == 1
    assert lines[-2] == "T9ZZ5: a driver notice"
    assert err.count("notice") == 1
    assert lines[-1] == "check failed, not written: T9ZZ2 T9ZZ4"
    return {int(p) for p in re.findall(r'"pid": (\d+)', out.split("total", maxsplit=1)[0])}


def test_one_job_builds_in_process_and_reports_each_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    monkeypatch.setattr(gen_models, "generate", _fake_generate)
    gen_models.DRIVERS.close()  # as an earlier run leaves it
    rc = gen_models._generate_all(_args(tmp_path, 1), tmp_path, tmp_path / "out", quiet=False)
    captured = capsys.readouterr()
    assert _check_run(rc, tmp_path / "out", captured.out, captured.err) == {os.getpid()}
    assert gen_models.DRIVERS._closed  # no worker outlives the run


@pytest.mark.timeout(60)
def test_several_jobs_build_in_worker_processes_and_report_each_failure(tmp_path: Path) -> None:
    proc = subprocess.Popen(
        [sys.executable, "-c", SEVERAL_JOBS, __file__, str(tmp_path)],
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    out, err = proc.communicate(timeout=50)
    pids = _check_run(proc.returncode, tmp_path / "out", out, err)
    assert pids
    assert proc.pid not in pids


# Answers --version as Node of the given version; any other run fails at once.
FAKE_NODE = """#!/bin/sh
if [ "$1" = "--version" ]; then echo @VERSION@; exit 0; fi
echo "fake node: broken" >&2
exit 1
"""


def _cli(tmp_path: Path, node_version: str, jobs: int) -> subprocess.CompletedProcess[str]:
    """``gen_models.py`` on three synthetic models, with a fake ``node`` first on PATH."""
    bin_dir, cache = tmp_path / "bin", tmp_path / "cache"
    bin_dir.mkdir()
    (bin_dir / "node").write_text(FAKE_NODE.replace("@VERSION@", node_version), encoding="utf-8")
    (bin_dir / "node").chmod(0o755)
    td = {
        "properties": [{"identifier": "x_on", "access_mode": "RW", "data_type": {"type": "bool"}}]
    }
    for pn in PNS[:3]:
        (cache / pn).mkdir(parents=True)
        (cache / pn / "td.json").write_text(json.dumps(td), encoding="utf-8")
    args = _args(tmp_path, jobs)
    inputs = [
        f"--{name}={getattr(args, name)}" for name in ("labels", "trees", "titles", "released")
    ]
    paths = [f"--cache={cache}", f"--out={tmp_path / 'out'}", f"--jobs={jobs}"]
    return subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "gen_models.py"), *PNS[:3], *inputs, *paths],
        env={**os.environ, "PATH": f"{bin_dir}{os.pathsep}{os.environ['PATH']}"},
        capture_output=True,
        text=True,
        timeout=50,
        check=False,
    )


@pytest.mark.timeout(60)
@pytest.mark.parametrize("jobs", [1, 3])
def test_a_node_that_fails_every_job_stops_the_run_with_exit_2(tmp_path: Path, jobs: int) -> None:
    result = _cli(tmp_path, "v24.1.0", jobs)
    assert result.returncode == 2
    assert result.stderr.splitlines() == [
        "gen_models: T9ZZ1: driver exit 1: fake node: broken (after 2 reruns)"
    ]
    assert not (tmp_path / "out").exists() or not any((tmp_path / "out").glob("T9ZZ*.json"))


@pytest.mark.timeout(60)
def test_node_of_another_major_stops_the_run_before_it_starts(tmp_path: Path) -> None:
    result = _cli(tmp_path, "v22.11.0", 3)
    assert result.returncode == 2
    assert result.stderr == (
        "gen_models: node v22.11.0 found; the generators need Node 24.x"
        " (scripts/package.json engines.node)\n"
    )
    assert not (tmp_path / "out").exists()
