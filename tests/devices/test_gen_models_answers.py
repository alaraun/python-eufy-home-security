"""The generator's driver answer store (scripts/gen_models_answers.py): a job asked before
is replayed, a change of any key part (Node version, driver, handler, requests) asks
again, a damaged record is asked again, a product's file keeps what its run asked, and
without a store every job is asked.

No Node: the jobs go to a recording stand-in for the driver pool.
"""

from __future__ import annotations

import hashlib
import importlib.util
import sys
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


def test_a_job_whose_handler_cannot_be_read_goes_to_the_driver_unstored(setup: Setup) -> None:
    """The driver reports a missing handler itself; the store keys nothing on it."""
    setup.handler.unlink()
    for _ in range(2):
        replies, stats = setup.product(setup.job(1))
        assert replies == [[{"echo": 1, "n": len(setup.ask.jobs)}]]
        assert (stats.asked, stats.replayed) == (0, 0)
    assert len(setup.ask.jobs) == 2
    assert not setup.file.exists()
