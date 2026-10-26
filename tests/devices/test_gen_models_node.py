"""The generators' Node workers (scripts/gen_models_node.py): one long-lived driver per
thread, a job rerun on a fresh worker when its worker dies, no worker left after
``close``, the pinned Node major, and the driver's fresh sandbox per job.

The pool tests run a fake driver (a Python script); the driver tests need Node.
"""

from __future__ import annotations

import importlib.util
import json
import os
import sys
import threading
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


node = _load("gen_models_node")

# Answers each job line by the behaviour its "handler" names; "marker" files make a
# behaviour happen only on a job's first sight.
FAKE_DRIVER = """
import json, os, signal, sys, time
n = 0
for line in sys.stdin:
    job = json.loads(line)
    how, n = job["handler"], n + 1
    marker = job.get("marker")
    if marker and os.path.exists(marker):
        how = "echo"
    elif marker:
        open(marker, "w").close()
    if how == "die":
        os.kill(os.getpid(), signal.SIGKILL)
    if how == "exit3":
        sys.stderr.write("handler blew up")
        sys.stderr.flush()
        sys.exit(3)
    if how == "sleep":
        time.sleep(30)
    if how == "partial":
        sys.stdout.write("[1, 2")
        sys.stdout.flush()
        sys.exit(0)
    reply = {
        "job-error": '{"error": "no such handler"}',
        "not-json": "nope",
        "not-list": '{"x": 1}',
    }.get(how, json.dumps([os.getpid(), n, job.get("requests")]))
    sys.stdout.write(reply + "\\n")
    sys.stdout.flush()
"""


@pytest.fixture
def fake(tmp_path: Path) -> list[str]:
    script = tmp_path / "fake_driver.py"
    script.write_text(FAKE_DRIVER, encoding="utf-8")
    return [sys.executable, str(script)]


@pytest.fixture
def pool(fake: list[str]) -> Any:
    drivers = node.DriverPool(fake, timeout=20)
    yield drivers
    drivers.close()


def test_a_thread_keeps_its_worker_across_jobs(pool: Any) -> None:
    first = pool.run({"handler": "echo", "requests": [1]})
    second = pool.run({"handler": "echo", "requests": [2]})
    assert first[0] == second[0]
    assert (first[1:], second[1:]) == ([1, [1]], [2, [2]])
    assert pool.started == 1


def test_each_thread_gets_its_own_worker(pool: Any) -> None:
    pids: list[int] = []
    gate = threading.Barrier(2)

    def work() -> None:
        gate.wait()
        pids.append(pool.run({"handler": "echo", "requests": []})[0])

    threads = [threading.Thread(target=work) for _ in range(2)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=20)
    assert len(set(pids)) == 2
    assert pool.started == 2


def test_a_job_whose_worker_dies_is_rerun_on_a_fresh_worker(
    pool: Any, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    before = pool.run({"handler": "echo", "requests": []})[0]
    job = {"handler": "die", "marker": str(tmp_path / "died"), "requests": [7]}
    pid, n, requests = pool.run(job)
    assert (pid != before, n, requests) == (True, 1, [7])
    assert pool.started == 2
    assert "killed by signal 9; rerun on a fresh worker" in capsys.readouterr().err


def test_a_worker_that_dies_between_jobs_is_replaced(
    pool: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    pid = pool.run({"handler": "echo", "requests": []})[0]
    (old,) = pool._workers
    os.kill(pid, 9)
    old.proc.wait(timeout=10)
    assert pool.run({"handler": "echo", "requests": []})[0] != pid
    assert pool.started == 2
    assert len(pool._workers) == 1
    assert old._stdout.closed
    assert "rerun" not in capsys.readouterr().err


def test_a_reply_cut_short_by_the_worker_ending_is_rerun(pool: Any, tmp_path: Path) -> None:
    job = {"handler": "partial", "marker": str(tmp_path / "cut"), "requests": [3]}
    assert pool.run(job)[1:] == [1, [3]]
    assert pool.started == 2


def test_a_job_that_always_kills_its_worker_fails_after_the_reruns(
    fake: list[str], capsys: pytest.CaptureFixture[str]
) -> None:
    drivers = node.DriverPool(fake, timeout=20, restarts=1)
    try:
        with pytest.raises(node.DriverError, match=r"signal 9 \(after 1 reruns\)"):
            drivers.run({"handler": "die", "requests": []})
        assert drivers.started == 2
    finally:
        drivers.close()
    assert capsys.readouterr().err.count("rerun on a fresh worker") == 1


def test_a_worker_exit_names_its_code_and_stderr(pool: Any) -> None:
    with pytest.raises(node.DriverError, match="driver exit 3: handler blew up"):
        pool.run({"handler": "exit3", "requests": []})


def test_a_slow_job_times_out_without_a_rerun(fake: list[str]) -> None:
    drivers = node.DriverPool(fake, timeout=0.5)
    try:
        start = time.monotonic()
        with pytest.raises(node.DriverError, match=r"no reply within 0.5 s"):
            drivers.run({"handler": "sleep", "requests": []})
        assert time.monotonic() - start < 10
        assert drivers.started == 1
    finally:
        drivers.close()


@pytest.mark.parametrize(
    ("how", "message"),
    [
        ("job-error", "driver: no such handler"),
        ("not-json", "not JSON"),
        ("not-list", "no list: dict"),
    ],
)
def test_a_reply_that_is_no_reply_list_is_an_error(pool: Any, how: str, message: str) -> None:
    with pytest.raises(node.DriverError, match=message):
        pool.run({"handler": how, "requests": []})
    assert pool.started == 1


def test_close_ends_the_workers_and_refuses_jobs_until_open(pool: Any) -> None:
    pool.run({"handler": "echo", "requests": []})
    (worker,) = pool._workers
    pool.close()
    assert worker.proc.poll() is not None
    with pytest.raises(node.DriverError, match="closed"):
        pool.run({"handler": "echo", "requests": []})
    pool.open()
    assert pool.run({"handler": "echo", "requests": []})[0] != worker.proc.pid
    assert pool.started == 2


def test_close_fails_the_job_in_flight_without_a_rerun(
    pool: Any, capsys: pytest.CaptureFixture[str]
) -> None:
    errors: list[BaseException] = []

    def work() -> None:
        try:
            pool.run({"handler": "sleep", "requests": []})
        except node.DriverError as err:
            errors.append(err)

    thread = threading.Thread(target=work)
    thread.start()
    deadline = time.monotonic() + 10
    while not pool._workers and time.monotonic() < deadline:
        time.sleep(0.01)
    time.sleep(0.2)
    start = time.monotonic()
    pool.close()
    assert time.monotonic() - start < 2  # killed, not waited for
    thread.join(timeout=10)
    assert not thread.is_alive()
    assert [str(e) for e in errors] == ["worker stopped"]
    assert pool.started == 1
    assert "rerun" not in capsys.readouterr().err


def _node_script(tmp_path: Path, version: str, *, then: str = "") -> str:
    script = tmp_path / "node"
    script.write_text(f"#!/bin/sh\n{then}echo {version}\n", encoding="utf-8")
    script.chmod(0o755)
    return str(script)


def _package(tmp_path: Path, pin: Any) -> Path:
    package = tmp_path / "package.json"
    package.write_text(json.dumps({"engines": {"node": pin}}), encoding="utf-8")
    return package


def test_the_pinned_major_comes_from_package_json(tmp_path: Path) -> None:
    assert node.node_major() == 24
    assert node.node_major(_package(tmp_path, "22.x")) == 22
    with pytest.raises(node.DriverError, match=r"'<major>\.x'"):
        node.node_major(_package(tmp_path, ">=22"))


@pytest.mark.parametrize("version", ["v24.1.0", "v24.0.0-nightly20250101a1b2c3d4e5"])
def test_node_of_the_pinned_major_passes(tmp_path: Path, version: str) -> None:
    package = _package(tmp_path, "24.x")
    assert node.node_problem(_node_script(tmp_path, version), package) is None


@pytest.mark.parametrize(
    "version", ["v22.11.0", "v240.0.0", "v25.0.0-nightly20250101a1b2c3d4e5", "garbage"]
)
def test_node_of_another_major_is_named(tmp_path: Path, version: str) -> None:
    problem = node.node_problem(_node_script(tmp_path, version), _package(tmp_path, "24.x"))
    assert problem is not None
    assert "need Node 24.x" in problem
    assert version in problem


def test_the_problem_names_the_pin_file_in_the_repository(tmp_path: Path) -> None:
    problem = node.node_problem(_node_script(tmp_path, "v22.11.0"))
    assert problem is not None
    assert problem.endswith("(scripts/package.json engines.node)")


def test_a_node_that_does_not_answer_is_named(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(node, "_VERSION_WAIT_S", 0.2)
    script = _node_script(tmp_path, "v24.1.0", then="exec sleep 30\n")
    assert node.node_problem(script, _package(tmp_path, "24.x")) == (
        f"{script} --version: no answer within 0.2 s"
    )


@pytest.mark.parametrize(
    ("text", "message"),
    [
        ("{", "Expecting property name"),
        ("[]", "not None"),
        ('{"engines": "24.x"}', "not None"),
        ('{"private": true}', "not None"),
    ],
)
def test_a_package_json_without_a_pin_is_named(tmp_path: Path, text: str, message: str) -> None:
    package = tmp_path / "package.json"
    package.write_text(text, encoding="utf-8")
    problem = node.node_problem(_node_script(tmp_path, "v24.1.0"), package)
    assert problem is not None
    assert problem.startswith(f"{package}: ")
    assert message in problem


def test_no_node_on_path_is_named(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(node.shutil, "which", lambda _: None)
    assert node.node_problem() == "node is not on PATH"


def test_the_default_worker_refuses_node_of_another_major(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    _node_script(tmp_path, "v22.11.0")
    monkeypatch.setenv("PATH", str(tmp_path))
    node.node_path.cache_clear()
    drivers = node.DriverPool()
    try:
        with pytest.raises(node.DriverError, match=r"node v22.11.0 found; .* Node 24.x"):
            drivers.run({"handler": "x", "requests": []})
        assert drivers.started == 0
    finally:
        drivers.close()
        node.node_path.cache_clear()


# ── the real driver ─────────────────────────────────────────────────────────

# Counts its calls in module state: a reused sandbox would carry the count over.
COUNTING_HANDLER = """
let calls = 0;
module.exports.controlDevice = function () {
  calls += 1;
  return JSON.stringify({ data: { p2p: { calls, r: Math.random(), t: Date.now() } } });
};
"""


def _set(n: int) -> dict[str, Any]:
    return {"kind": "set", "identifier": "x", "payload": n, "device": {}}


@pytest.mark.needs_node
def test_every_job_gets_a_fresh_handler_sandbox(tmp_path: Path) -> None:
    handler = tmp_path / "TestHandle.mix.js"
    handler.write_text(COUNTING_HANDLER, encoding="utf-8")
    drivers = node.DriverPool()
    try:
        job = {"handler": str(handler), "requests": [_set(1), _set(2)]}
        first, second = drivers.run(job), drivers.run(job)
    finally:
        drivers.close()
    assert drivers.started == 1
    assert first == second
    calls = [reply["data"]["p2p"]["calls"] for reply in first]
    assert calls == [1, 2]
    p2p = first[0]["data"]["p2p"]
    assert (p2p["t"], p2p["r"]) == (1700000000000, first[1]["data"]["p2p"]["r"])


@pytest.mark.needs_node
def test_an_unreadable_handler_fails_its_job_and_keeps_the_worker(tmp_path: Path) -> None:
    handler = tmp_path / "TestHandle.mix.js"
    handler.write_text(COUNTING_HANDLER, encoding="utf-8")
    drivers = node.DriverPool()
    try:
        with pytest.raises(node.DriverError, match="ENOENT"):
            drivers.run({"handler": str(tmp_path / "missing.js"), "requests": [_set(1)]})
        assert drivers.run({"handler": str(handler), "requests": []}) == []
    finally:
        drivers.close()
    assert drivers.started == 1


@pytest.mark.needs_node
def test_a_worker_ends_with_its_stdin_despite_pending_handler_timers(tmp_path: Path) -> None:
    handler = tmp_path / "TestHandle.mix.js"
    handler.write_text(COUNTING_HANDLER + "setTimeout(() => {}, 60000);\n", encoding="utf-8")
    drivers = node.DriverPool()
    drivers.run({"handler": str(handler), "requests": [_set(1)]})
    (worker,) = drivers._workers
    start = time.monotonic()
    drivers.close()
    assert time.monotonic() - start < 3
    assert worker.proc.returncode == 0
