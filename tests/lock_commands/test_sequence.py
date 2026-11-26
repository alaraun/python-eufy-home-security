"""Lock sequence numbers, kept as the eufy app keeps them."""

from __future__ import annotations

from eufy_home_security.lock_commands.sequence import LockSequences, SharedSequence

LOCK = "T8502P2000000001"
OTHER = "T8502P2000000002"


def test_a_lock_without_a_report_sends_the_current_time_plus_one() -> None:
    seqs = LockSequences(clock=lambda: 1_700_000_000.7)
    assert seqs.next(LOCK) == 1_700_000_001
    assert seqs.next(LOCK) == 1_700_000_002
    assert seqs.next(OTHER) == 1_700_000_001


def test_a_report_is_stored_plus_one_and_the_next_send_adds_one() -> None:
    seqs = LockSequences(clock=lambda: 1_700_000_000.0)
    seqs.next(LOCK)
    seqs.report(LOCK, 41)
    assert seqs.next(LOCK) == 43
    assert seqs.next(LOCK) == 44
    assert seqs.next(OTHER) == 1_700_000_001


def test_the_shared_sequence_counts_up_from_its_start() -> None:
    shared = SharedSequence(start=5)
    assert [shared.next(), shared.next(), shared.next()] == [5, 6, 7]


def test_a_report_moves_the_shared_sequence_to_the_next_number() -> None:
    shared = SharedSequence(start=5)
    shared.next()
    shared.report(700)
    assert (shared.next(), shared.next()) == (701, 702)


def test_the_shared_sequence_starts_below_1000() -> None:
    assert all(0 <= SharedSequence().next() < 1000 for _ in range(20))
