"""Long-lived Node workers that run ``scripts/gen_models_driver.js`` jobs.

Each thread that runs a job starts its own ``--serve`` worker and keeps it: a job goes
out as one JSON line, its reply comes back as one. The driver runs every job in a fresh
handler sandbox, so a job's reply does not depend on the worker's earlier jobs. A worker
that dies mid-job (Node can abort under heavy parallel load) is replaced and the job
rerun as is. A worker exits when its stdin closes, so none outlives the generator;
``DriverPool.close`` ends them at once and fails the jobs in flight.

The Node major the generators run on is pinned in ``scripts/package.json``
(``engines.node``, ``"<major>.x"``); ``node_problem`` checks it.
"""

from __future__ import annotations

import atexit
import contextlib
import functools
import json
import re
import shutil
import subprocess
import sys
import tempfile
import threading
from collections.abc import Mapping, Sequence
from pathlib import Path
from typing import IO, Any

ROOT = Path(__file__).resolve().parent.parent
DRIVER = ROOT / "scripts" / "gen_models_driver.js"
PACKAGE = ROOT / "scripts" / "package.json"
TIMEOUT_S = 600  # one job
RESTARTS = 2  # reruns of a job whose worker died
_STOP_WAIT_S = 5
_VERSION_WAIT_S = 30


class DriverError(RuntimeError):
    """Node is missing or of another major, or a job failed in the driver."""


def node_major(package: Path = PACKAGE) -> int:
    """The Node major ``package`` pins (``engines.node`` = ``"<major>.x"``); DriverError
    when the file does not pin one."""
    try:
        data = json.loads(package.read_text(encoding="utf-8"))
    except (OSError, ValueError) as err:  # unreadable, or not JSON
        raise DriverError(f"{_shown(package)}: {err}") from err
    engines = data.get("engines") if isinstance(data, dict) else None
    pinned = engines.get("node") if isinstance(engines, dict) else None
    match = re.fullmatch(r"(\d+)\.x", pinned) if isinstance(pinned, str) else None
    if match is None:
        raise DriverError(f"{_shown(package)}: engines.node must be '<major>.x', not {pinned!r}")
    return int(match[1])


def node_problem(node: str | None = None, package: Path = PACKAGE) -> str | None:
    """Why the driver cannot run: no ``node`` on PATH, one that does not answer
    ``--version``, a major other than the pinned one, or no pin; None when it can."""
    node = node or shutil.which("node")
    if node is None:
        return "node is not on PATH"
    try:
        found = subprocess.run(
            [node, "--version"],
            capture_output=True,
            text=True,
            timeout=_VERSION_WAIT_S,
            check=False,
        ).stdout.strip()
    except subprocess.TimeoutExpired:
        return f"{node} --version: no answer within {_VERSION_WAIT_S} s"
    except OSError as err:
        return f"{node}: {err}"
    try:
        want = node_major(package)
    except DriverError as err:
        return str(err)
    match = re.fullmatch(r"v(\d+)\.\d+\.\d+\S*", found)
    if match is None or int(match[1]) != want:
        return (
            f"node {found or '(no version)'} found; the generators need Node {want}.x "
            f"({_shown(package)} engines.node)"
        )
    return None


def _shown(path: Path) -> str:
    """``path`` relative to the repository when inside it."""
    return str(path.relative_to(ROOT)) if path.is_relative_to(ROOT) else str(path)


class _WorkerDiedError(Exception):
    def __init__(self, detail: str, *, timed_out: bool = False) -> None:
        super().__init__(detail)
        self.timed_out = timed_out


class _Worker:
    """One ``--serve`` process; its stderr goes to a file, read only when it dies."""

    def __init__(self, argv: Sequence[str]) -> None:
        self._stderr: IO[bytes] = tempfile.TemporaryFile()  # noqa: SIM115 - closed in _release
        self.proc = subprocess.Popen(
            argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=self._stderr
        )
        stdin, stdout = self.proc.stdin, self.proc.stdout
        if stdin is None or stdout is None:  # pragma: no cover - PIPE always yields both
            raise DriverError("no pipes to the driver")
        self._stdin, self._stdout = stdin, stdout
        self._state = threading.Lock()  # guards _busy and _stopped
        self._busy = False
        self._stopped = False
        self._timed_out = False

    def call(self, line: bytes, timeout: float) -> bytes:
        """The reply line to the job ``line``; raises _WorkerDiedError when the worker
        ends (or is stopped) first."""
        with self._state:
            self._busy = True
        timer = threading.Timer(timeout, self._kill_slow)
        timer.start()
        try:
            self._stdin.write(line)
            self._stdin.flush()
            out = self._stdout.readline()
        except (BrokenPipeError, ValueError, OSError):
            out = b""
        finally:
            timer.cancel()
            with self._state:
                self._busy = False
                stopped = self._stopped
        if stopped:  # stop() killed it mid-job and left the clean-up to this thread
            self._release()
            raise _WorkerDiedError("worker stopped")
        if out.endswith(b"\n"):
            return out
        if self._timed_out:
            raise _WorkerDiedError(f"no reply within {timeout:g} s", timed_out=True)
        raise _WorkerDiedError(self._exit_detail())

    def _kill_slow(self) -> None:
        self._timed_out = True
        self.proc.kill()

    def _exit_detail(self) -> str:
        try:
            code = self.proc.wait(timeout=_STOP_WAIT_S)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            code = self.proc.wait()
        how = f"killed by signal {-code}" if code < 0 else f"exit {code}"
        self._stderr.seek(0)
        tail = self._stderr.read()[-400:].decode("utf-8", "replace").strip()
        return f"driver {how}" + (f": {tail}" if tail else "")

    def stop(self) -> None:
        """End the process: an idle one by closing its stdin, one mid-job by a kill (its
        calling thread then releases the pipes)."""
        with self._state:
            self._stopped = True
            busy = self._busy
        if busy:
            self.proc.kill()
            return
        with contextlib.suppress(OSError):
            self._stdin.close()
        self._release()

    def _release(self) -> None:
        try:
            self.proc.wait(timeout=_STOP_WAIT_S)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait()
        for stream in (self._stdin, self._stdout, self._stderr):
            with contextlib.suppress(OSError):  # unflushed input to a dead worker
                stream.close()


class DriverPool:
    """One driver worker per calling thread, started on the thread's first job.

    ``argv`` is the worker command (default: ``node gen_models_driver.js --serve``).
    ``close`` ends every worker and fails the jobs in flight; until ``open`` the pool
    refuses jobs. ``started`` counts the workers started.
    """

    def __init__(
        self,
        argv: Sequence[str] | None = None,
        *,
        timeout: float = TIMEOUT_S,
        restarts: int = RESTARTS,
    ) -> None:
        self._argv = list(argv) if argv is not None else None
        self._timeout = timeout
        self._restarts = restarts
        self._local = threading.local()
        self._lock = threading.Lock()
        self._workers: set[_Worker] = set()
        self._closed = False
        self.started = 0
        atexit.register(self.close)

    def run(self, job: Mapping[str, Any]) -> list[Any]:
        """The driver's replies to ``job`` (``{"handler", "requests"}``), one per request.

        Raises DriverError when the pool is closed, the job does not fit the driver
        (``{"error"}`` from it), times out, or its worker dies on every rerun.
        """
        line = (json.dumps(job) + "\n").encode()
        died: _WorkerDiedError | None = None
        for attempt in range(self._restarts + 1):
            worker = self._worker()
            try:
                out = worker.call(line, self._timeout)
            except _WorkerDiedError as err:
                self._discard(worker)
                if err.timed_out or self._closed:
                    raise DriverError(str(err)) from None
                died = err
                if attempt < self._restarts:
                    name = Path(str(job.get("handler"))).name
                    print(f"{name}: {err}; rerun on a fresh worker", file=sys.stderr)
                continue
            try:
                replies = json.loads(out)
            except json.JSONDecodeError as err:
                raise DriverError(f"driver output is not JSON: {err}") from err
            if isinstance(replies, dict) and "error" in replies:
                raise DriverError(f"driver: {replies['error']}")
            if not isinstance(replies, list):
                raise DriverError(f"driver reply is no list: {type(replies).__name__}")
            return replies
        raise DriverError(f"{died} (after {self._restarts} reruns)")

    def open(self) -> None:
        """Accept jobs again after ``close``."""
        with self._lock:
            self._closed = False

    def close(self) -> None:
        """End every worker; jobs in flight and later ones fail until ``open``."""
        with self._lock:
            self._closed = True
            workers, self._workers = self._workers, set()
        for worker in workers:
            worker.stop()

    def _worker(self) -> _Worker:
        mine: _Worker | None = getattr(self._local, "worker", None)
        with self._lock:
            if self._closed:
                raise DriverError("driver pool closed")
            if mine is not None and mine in self._workers:
                if mine.proc.poll() is None:
                    return mine
                self._workers.discard(mine)  # ended between jobs
            else:
                mine = None
            argv = self._argv or [node_path(), str(DRIVER), "--serve"]
            worker = _Worker(argv)
            self._workers.add(worker)
            self.started += 1
        if mine is not None:
            mine.stop()
        self._local.worker = worker
        return worker

    def _discard(self, worker: _Worker) -> None:
        with self._lock:
            self._workers.discard(worker)
        worker.stop()


@functools.cache
def node_path() -> str:
    """The ``node`` on PATH, checked once against the pinned major; DriverError (the
    ``node_problem``) when it does not run the driver."""
    node = shutil.which("node")
    problem = node_problem(node)
    if node is None or problem is not None:
        raise DriverError(problem or "node is not on PATH")
    return node
