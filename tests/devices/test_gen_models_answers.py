"""The generator's driver answer store (scripts/gen_models_answers.py): a job asked before
is replayed, a change of any key part (Node version, driver, handler, requests) asks
again, a damaged record is asked again, a product's file keeps what its run asked, and
without a store every job is asked.

No Node: the jobs go to a recording stand-in for the driver pool.
"""

from __future__ import annotations

import hashlib
import importlib.util
import json
import os
import random
import shutil
import string
import sys
import tempfile
import zlib
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


answers = _load("gen_models_answers")
PN = "T9ZZ1"  # a product code named nowhere


class Driver:
    """Answers each request with its payload and a running count; records the jobs."""

    def __init__(self) -> None:
        self.jobs: list[Any] = []

    def __call__(self, job: Any) -> list[Any]:
        self.jobs.append(job)
        return [{"echo": r["payload"], "n": len(self.jobs)} for r in job["requests"]]


class Setup:
    def __init__(self, tmp_path: Path) -> None:
        self.root = tmp_path / "answers"
        self.driver = tmp_path / "driver.js"
        self.driver.write_text("// driver", encoding="utf-8")
        self.handler = tmp_path / f"{PN}Handle.mix.js"
        self.handler.write_text("// handler", encoding="utf-8")
        self.runtime = "v24.0.0"
        self.ask = Driver()

    def store(self, root: Path | None = None) -> Any:
        return answers.AnswerStore(
            root if root is not None else self.root,
            driver=self.driver,
            runtime=lambda: self.runtime,
        )

    def job(self, *payloads: Any) -> dict[str, Any]:
        return {
            "handler": str(self.handler),
            "requests": [{"kind": "set", "payload": p} for p in payloads],
        }

    def product(self, *jobs: dict[str, Any], ok: bool = True) -> tuple[list[Any], Any]:
        """Run ``jobs`` as one product on a fresh store; the replies and the stats."""
        store = self.store()
        store.open(PN)
        replies = [store.run(job, self.ask) for job in jobs]
        assert store.close(ok=ok) is None
        return replies, store.stats

    @property
    def file(self) -> Path:
        return self.root / f"{PN}.answers"


@pytest.fixture
def setup(tmp_path: Path) -> Setup:
    return Setup(tmp_path)


def test_a_job_asked_before_is_replayed_without_the_driver(setup: Setup) -> None:
    first, stats = setup.product(setup.job(1, 2), setup.job(3))
    assert (stats.asked, stats.replayed) == (2, 0)
    assert len(setup.ask.jobs) == 2
    again, stats = setup.product(setup.job(1, 2), setup.job(3))
    assert again == first
    assert (stats.asked, stats.replayed, stats.damaged) == (0, 2, 0)
    assert len(setup.ask.jobs) == 2


def _change_runtime(setup: Setup) -> None:
    setup.runtime = "v24.0.1"


def _change_driver(setup: Setup) -> None:
    setup.driver.write_text("// driver 2", encoding="utf-8")


def _change_handler(setup: Setup) -> None:
    setup.handler.write_text("// handler 2", encoding="utf-8")


@pytest.mark.parametrize(
    "change", [_change_runtime, _change_driver, _change_handler], ids=lambda f: f.__name__
)
def test_a_changed_runtime_driver_or_handler_asks_again(setup: Setup, change: Any) -> None:
    setup.product(setup.job(1))
    change(setup)
    replies, stats = setup.product(setup.job(1))
    assert (stats.asked, stats.replayed) == (1, 0)
    assert replies == [[{"echo": 1, "n": 2}]]


def test_changed_requests_ask_again_and_the_same_requests_elsewhere_do_not(
    setup: Setup,
) -> None:
    """The key is the requests' JSON as sent: another value, another order or another
    handler path with the same bytes."""
    setup.product(setup.job(1, 2))
    moved = setup.handler.with_name("elsewhere.js")
    moved.write_bytes(setup.handler.read_bytes())
    same_bytes = {**setup.job(1, 2), "handler": str(moved)}
    _, stats = setup.product(setup.job(1, 3), setup.job(2, 1), setup.job(1, 2, 2), same_bytes)
    assert (stats.asked, stats.replayed) == (3, 1)


def test_the_handler_is_read_again_for_each_product(setup: Setup) -> None:
    """One store serves a process's products in turn: a handler file that changes
    between two products is not served from the first one's digest."""
    store = setup.store()
    for n in (1, 2):
        setup.handler.write_text(f"// handler {n}", encoding="utf-8")
        store.open(PN)
        store.run(setup.job(1), setup.ask)
        store.close(ok=True)
        assert store.stats.asked == 1


def _damage_blob(data: bytes) -> bytes:
    """The first record's last compressed byte flipped."""
    header_end = data.index(b"\n", len(answers.HEADER))
    size = int(data[len(answers.HEADER) : header_end].split()[2])
    at = header_end + size
    return data[:at] + bytes([data[at] ^ 0xFF]) + data[at + 1 :]


def _damage_digest(data: bytes) -> bytes:
    """The first record's digest replaced by another valid-looking one."""
    at = len(answers.HEADER) + 65
    return data[:at] + b"0" * 64 + data[at + 64 :]


@pytest.mark.parametrize("damage", [_damage_blob, _damage_digest], ids=lambda f: f.__name__)
def test_a_damaged_record_is_asked_again_and_the_others_replayed(setup: Setup, damage: Any) -> None:
    jobs = (setup.job(1), setup.job(2))
    first, _ = setup.product(*jobs)
    records, _ = answers.read_records(setup.file)
    damaged_key = min(records)  # the first record of the file
    setup.file.write_bytes(damage(setup.file.read_bytes()))
    replies, stats = setup.product(*jobs)
    assert (stats.asked, stats.replayed, stats.damaged) == (1, 1, 1)
    asked = setup.ask.jobs[-1]
    assert asked in jobs
    store = setup.store()
    assert store._key(setup.handler, asked["requests"]) == damaged_key
    other = 1 - jobs.index(asked)
    assert replies[other] == first[other]
    # the record asked again is stored again: the next run replays both
    _, stats = setup.product(*jobs)
    assert (stats.asked, stats.replayed, stats.damaged) == (0, 2, 0)


def test_a_truncated_file_keeps_the_records_before_the_cut(setup: Setup) -> None:
    jobs = (setup.job(1), setup.job(2), setup.job(3))
    setup.product(*jobs)
    data = setup.file.read_bytes()
    setup.file.write_bytes(data[: len(data) - 3])
    records, damaged = answers.read_records(setup.file)
    assert (len(records), damaged) == (2, 1)
    _, stats = setup.product(*jobs)
    assert (stats.asked, stats.replayed, stats.damaged) == (1, 2, 1)


def test_a_damaged_file_is_rewritten_even_when_nothing_is_asked(setup: Setup) -> None:
    """The run asks only the job before the damage: the file is written clean anyway."""
    jobs = {
        setup.store()._key(setup.handler, j["requests"]): j for j in (setup.job(1), setup.job(2))
    }
    kept = min(jobs)  # the file's first record
    setup.product(*jobs.values())
    records, _ = answers.read_records(setup.file)
    data = setup.file.read_bytes()
    setup.file.write_bytes(data[: len(data) - 3])
    _, stats = setup.product(jobs[kept])
    assert (stats.asked, stats.replayed, stats.damaged) == (0, 1, 1)
    assert answers.read_records(setup.file) == ({kept: records[kept]}, 0)


@pytest.mark.parametrize("content", [b"", b"not a store\n", b"gen_models answers 0\n"])
def test_a_file_of_another_format_is_asked_again_whole(setup: Setup, content: bytes) -> None:
    setup.product(setup.job(1), setup.job(2))
    setup.file.write_bytes(content)
    _, stats = setup.product(setup.job(1), setup.job(2))
    assert (stats.asked, stats.replayed, stats.damaged) == (2, 0, 1)
    assert setup.file.read_bytes().startswith(answers.HEADER)


def test_a_reply_that_does_not_fit_the_job_is_asked_again(setup: Setup) -> None:
    """A record whose reply list has another length than the job's requests."""
    store = setup.store()
    store.open(PN)
    key = store._key(setup.handler, setup.job(1, 2)["requests"])
    store.close(ok=True)
    text = b'[{"echo": 1}]'
    answers.write_records(
        setup.file, {key: (hashlib.sha256(text).hexdigest(), zlib.compress(text))}
    )
    replies, stats = setup.product(setup.job(1, 2))
    assert (stats.asked, stats.damaged) == (1, 1)
    assert len(replies[0]) == 2


def test_a_product_keeps_only_the_jobs_its_run_asked(setup: Setup) -> None:
    setup.product(setup.job(1), setup.job(2))
    setup.product(setup.job(2), setup.job(3))
    assert len(answers.read_records(setup.file)[0]) == 2
    _, stats = setup.product(setup.job(1))
    assert stats.asked == 1  # dropped by the second run


def test_a_run_that_replays_a_subset_drops_the_rest(setup: Setup) -> None:
    setup.product(setup.job(1), setup.job(2))
    _, stats = setup.product(setup.job(2))
    assert (stats.asked, stats.replayed) == (0, 1)
    assert len(answers.read_records(setup.file)[0]) == 1


def test_a_job_repeated_within_a_run_is_asked_once(setup: Setup) -> None:
    replies, stats = setup.product(setup.job(1), setup.job(1))
    assert (stats.asked, stats.replayed) == (1, 1)
    assert replies[0] == replies[1]


def test_a_failed_product_keeps_its_earlier_jobs_too(setup: Setup) -> None:
    setup.product(setup.job(1), setup.job(2))
    setup.product(setup.job(3), ok=False)
    _, stats = setup.product(setup.job(1), setup.job(2), setup.job(3))
    assert (stats.asked, stats.replayed) == (0, 3)


def test_a_run_that_replays_everything_writes_nothing(
    setup: Setup, monkeypatch: pytest.MonkeyPatch
) -> None:
    setup.product(setup.job(1), setup.job(2))

    def refuse(*_: Any) -> None:
        raise AssertionError("written")

    monkeypatch.setattr(answers, "write_records", refuse)
    _, stats = setup.product(setup.job(2), setup.job(1))
    assert stats.replayed == 2


def test_without_a_store_every_job_is_asked_and_nothing_is_written(setup: Setup) -> None:
    store = answers.AnswerStore(None, driver=setup.driver, runtime=lambda: "v24.0.0")
    for _ in range(2):
        store.open(PN)
        assert store.run(setup.job(1), setup.ask) == [{"echo": 1, "n": len(setup.ask.jobs)}]
        assert store.close(ok=True) is None
    assert len(setup.ask.jobs) == 2
    assert (store.stats.asked, store.stats.replayed) == (0, 0)
    assert not setup.root.exists()


def test_a_job_outside_a_product_goes_to_the_driver(setup: Setup) -> None:
    store = setup.store()
    store.run(setup.job(1), setup.ask)
    store.run(setup.job(1), setup.ask)
    assert len(setup.ask.jobs) == 2
    assert not setup.root.exists()


def test_a_missing_store_directory_is_created(setup: Setup) -> None:
    setup.root = setup.root / "deeper" / "still"
    setup.product(setup.job(1))
    assert setup.file.is_file()


def test_a_store_that_cannot_be_written_is_a_notice_not_a_failure(setup: Setup) -> None:
    setup.root.write_text("a file, not a directory", encoding="utf-8")
    store = setup.store()
    store.open(PN)
    assert store.run(setup.job(1), setup.ask) == [{"echo": 1, "n": 1}]
    notice = store.close(ok=True)
    assert notice is not None
    assert notice.startswith(f"{PN}: answers not stored: ")
    assert not list(setup.root.parent.glob(".*.tmp"))


def test_a_file_that_cannot_be_replaced_leaves_no_temporary_file(setup: Setup) -> None:
    setup.file.mkdir(parents=True)
    store = setup.store()
    store.open(PN)
    store.run(setup.job(1), setup.ask)
    notice = store.close(ok=True)
    assert notice is not None
    assert notice.startswith(f"{PN}: answers not stored: ")
    assert sorted(p.name for p in setup.root.iterdir()) == [setup.file.name]


def test_a_failed_driver_job_is_not_stored(setup: Setup) -> None:
    def fail(_: Any) -> list[Any]:
        raise RuntimeError("driver failed")

    store = setup.store()
    store.open(PN)
    with pytest.raises(RuntimeError):
        store.run(setup.job(1), fail)
    store.close(ok=False)
    _, stats = setup.product(setup.job(1))
    assert stats.asked == 1


def _no_handler(setup: Setup) -> None:
    setup.handler.unlink()


def _no_runtime(setup: Setup) -> None:
    def fail() -> str:
        raise answers.subprocess.CalledProcessError(1, ["node"])

    setup.store = lambda root=None: answers.AnswerStore(  # type: ignore[method-assign]
        root if root is not None else setup.root, driver=setup.driver, runtime=fail
    )


@pytest.mark.parametrize("cause", [_no_handler, _no_runtime], ids=lambda f: f.__name__)
def test_a_job_without_a_key_goes_to_the_driver_unstored(setup: Setup, cause: Any) -> None:
    """A missing handler or a Node that does not answer: the driver reports it itself; the
    store keys nothing on it."""
    cause(setup)
    for _ in range(2):
        replies, stats = setup.product(setup.job(1))
        assert replies == [[{"echo": 1, "n": len(setup.ask.jobs)}]]
        assert (stats.asked, stats.replayed, stats.unkeyed) == (0, 0, 1)
    assert len(setup.ask.jobs) == 2
    assert not setup.file.exists()


def test_the_runtime_is_asked_once_per_store_and_a_failure_once_too(
    setup: Setup, capsys: pytest.CaptureFixture[str]
) -> None:
    calls: list[int] = []

    def runtime() -> str:
        calls.append(1)
        if failing:
            raise answers.subprocess.CalledProcessError(1, ["node"])
        return "v24"

    for failing in (False, True):
        calls.clear()
        store = answers.AnswerStore(setup.root, driver=setup.driver, runtime=runtime)
        for pn in ("T9ZZ1", "T9ZZ2"):
            store.open(pn)
            for n in range(3):
                store.run(setup.job(n), setup.ask)
            store.close(ok=True)
        assert len(calls) == 1
        assert (store.stats.asked, store.stats.unkeyed) == ((0, 3) if failing else (3, 0))
    err = capsys.readouterr().err
    assert err.count("answers: cannot ask the Node runtime (") == 1


def _fake_node(path: Path, versions: str) -> str:
    """A ``node`` that prints ``versions`` for ``-p <the runtime probe>``."""
    path.write_text(
        f"""#!/bin/sh
[ "$1" = "-p" ] && [ "$2" = '{answers.RUNTIME_PROBE}' ] && echo '{versions}'
""",
        encoding="utf-8",
    )
    path.chmod(0o755)
    return str(path)


BASE_ENV = {"PATH": "/usr/bin:/bin", "HOME": "/home/a", "TZ": "UTC", "LC_ALL": "C.UTF-8"}


@pytest.mark.skipif(sys.platform == "win32", reason="a shell-script node")
@pytest.mark.parametrize(
    ("env", "changes"),
    [
        ({**BASE_ENV}, False),
        ({**BASE_ENV, "PATH": "/opt/bin", "HOME": "/home/b", "EDITOR": "vi"}, False),
        ({**BASE_ENV, "TZ": "Pacific/Kiritimati"}, True),
        ({**BASE_ENV, "LC_ALL": "de_DE.UTF-8"}, True),
        ({**BASE_ENV, "LC_TIME": "et_EE.UTF-8"}, True),
        ({**BASE_ENV, "LANG": "et_EE.UTF-8"}, True),
        ({**BASE_ENV, "LANGUAGE": "et"}, True),
        ({**BASE_ENV, "NODE_OPTIONS": "--require ./x.js"}, True),
        ({**BASE_ENV, "NODE_ICU_DATA": "/opt/icu"}, True),
    ],
)
def test_the_runtime_text_follows_the_environment_a_reply_can_depend_on(
    tmp_path: Path, env: dict[str, str], changes: bool
) -> None:
    node = _fake_node(tmp_path / "node", '{"node":"24.0.0","icu":"77.1","tz":"2026a"}')
    base = answers.runtime_version(node, BASE_ENV)
    assert (answers.runtime_version(node, env) != base) is changes


@pytest.mark.skipif(sys.platform == "win32", reason="a shell-script node")
def test_the_runtime_text_reads_this_process_s_environment_by_default(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    node = _fake_node(tmp_path / "node", '{"node":"24.0.0"}')
    monkeypatch.setenv("TZ", "UTC")
    utc = answers.runtime_version(node)
    monkeypatch.setenv("TZ", "Pacific/Kiritimati")
    assert answers.runtime_version(node) != utc
    assert answers.runtime_version(node, {**os.environ, "TZ": "UTC"}) == utc


@pytest.mark.skipif(sys.platform == "win32", reason="a shell-script node")
def test_the_runtime_text_does_not_depend_on_the_environment_s_order(tmp_path: Path) -> None:
    node = _fake_node(tmp_path / "node", '{"node":"24.0.0"}')
    backwards = dict(reversed({**BASE_ENV, "LANG": "et_EE.UTF-8"}.items()))
    assert answers.runtime_version(node, backwards) == answers.runtime_version(
        node, {**BASE_ENV, "LANG": "et_EE.UTF-8"}
    )


@pytest.mark.needs_node
def test_the_runtime_probe_names_the_build_and_the_zone_and_locale_node_resolves() -> None:
    """The zone and locale as Node resolves them, so a host zone (/etc/localtime) counts."""
    env = {"PATH": os.environ["PATH"], "TZ": "Pacific/Kiritimati", "LC_ALL": "de_DE.UTF-8"}
    probe, settings = json.loads(answers.runtime_version(shutil.which("node") or "node", env))
    versions, zone, locale, offsets, clock = json.loads(probe)
    assert {"node", "v8", "icu", "tz"} <= versions.keys()
    assert zone == "Pacific/Kiritimati"
    assert offsets == [-840] * 12
    assert clock.startswith("Wed Nov 15 2023 12:13:20 GMT+1400")
    assert isinstance(locale, str)
    assert locale
    assert settings == [["LC_ALL", "de_DE.UTF-8"], ["TZ", "Pacific/Kiritimati"]]


ZONEINFO = Path("/usr/share/zoneinfo")


@pytest.mark.needs_node
@pytest.mark.skipif(not (ZONEINFO / "Pacific" / "Kiritimati").is_file(), reason="no zoneinfo")
@pytest.mark.parametrize("form", [":{}", "{}"])
def test_a_zone_file_named_by_path_counts_by_its_content(form: str) -> None:
    """TZ as a path gives Node no zone name: the offsets still tell the zones apart. (Node
    reads a TZ path only when it holds no digit, so the file is not under ``tmp_path``.)"""
    base = Path(tempfile.gettempdir())
    if any(c.isdigit() for c in str(base)):
        pytest.skip("the temporary directory's path holds a digit")
    folder = base / ("eufy-zone-" + "".join(random.choices(string.ascii_lowercase, k=12)))
    folder.mkdir()
    try:
        zone = folder / "localtime"
        env = {"PATH": os.environ["PATH"], "TZ": form.format(zone)}
        texts = []
        for name in ("Pacific/Kiritimati", "Europe/Tallinn"):
            zone.write_bytes((ZONEINFO / name).read_bytes())
            texts.append(answers.runtime_version(shutil.which("node") or "node", env))
    finally:
        shutil.rmtree(folder)
    assert texts[0] != texts[1]


@pytest.mark.parametrize(
    ("err", "cause"),
    [
        (
            answers.subprocess.CalledProcessError(9, ["node"], "", "node: bad option\nmore\n"),
            "node exit 9: node: bad option",
        ),
        (answers.subprocess.CalledProcessError(1, ["node"], "", ""), "node exit 1"),
        (answers.subprocess.TimeoutExpired(["node"], 30), "node gave no answer within 30 s"),
        (FileNotFoundError(2, "No such file or directory"), "[Errno 2] No such file or directory"),
    ],
)
def test_a_failed_runtime_query_is_named_in_one_line(err: Exception, cause: str) -> None:
    assert answers._cause(err) == cause


@pytest.mark.skipif(sys.platform == "win32", reason="a shell-script node")
def test_the_runtime_text_follows_the_node_build(tmp_path: Path) -> None:
    """Two builds of one Node version with other ICU or time zone data differ."""
    texts = {
        answers.runtime_version(_fake_node(tmp_path / f"node{n}", versions), BASE_ENV)
        for n, versions in enumerate(
            (
                '{"node":"24.0.0","icu":"77.1","tz":"2026a"}',
                '{"node":"24.0.0","icu":"77.1","tz":"2026b"}',
                '{"node":"24.0.0","icu":"76.1","tz":"2026a"}',
            )
        )
    }
    assert len(texts) == 3
