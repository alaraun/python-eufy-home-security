"""Pages of a station's recordings, their opaque cursor, and a row's reference.

A cursor names a position in one listing (a station and its camera filter): after a
row, by the row's station day and ``record_id``, or at a day, by that day's rows and
older ones. A reference names one row of one camera (:attr:`~.events.HistoryRecord.ref`):
its station day, ``record_id`` and start time, enough to ask the station for that row
with one query. Days are the station's own (the day a history query names), never the
host's. Callers keep the text as it came and hand it back; its form is not API, and a
cursor is never accepted as a reference or the other way round.
See ``docs/how-to/home-assistant.md`` § The station's recordings.
"""

from __future__ import annotations

import hashlib
import re
from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date, datetime, time, timedelta
from typing import TYPE_CHECKING, Final

from .exceptions import RecordingCursorError, RecordingRefError
from .p2p.messages import history_cursor_time, record_id_day

if TYPE_CHECKING:
    from .events import HistoryRecord

__all__ = [
    "RecordingPosition",
    "RecordingRef",
    "RecordingsPage",
    "decode_cursor",
    "decode_ref",
    "encode_cursor",
    "encode_ref",
    "issue_ref",
]

CURSOR_VERSION: Final = "v1"
"""The version tag every cursor starts with; a cursor of another version is refused."""
_CHECK_LEN: Final = 8  # hex digits
_CURSOR_RE: Final = re.compile(
    r"(?P<version>v\d+)\.(?:r\.(?P<rday>\d{8})\.(?P<id>[1-9]\d{0,19})|d\.(?P<dday>\d{8}))"
    r"\.(?P<check>[0-9a-f]{8})",
    re.ASCII,
)
_REF_RE: Final = re.compile(
    r"(?P<version>v\d+)\.k\.(?P<day>\d{8})\.(?P<id>[1-9]\d{0,19})(?:\.(?P<started>\d{14}))?"
    r"\.(?P<check>[0-9a-f]{8})",
    re.ASCII,
)


@dataclass(frozen=True, slots=True)
class RecordingsPage:
    """One page of a camera's recordings, newest first.

    ``next_cursor`` asks the page after it (pass it back as ``cursor``); None when the
    window holds no more. A full page may be followed by an empty one.
    """

    rows: tuple[HistoryRecord, ...]
    next_cursor: str | None


@dataclass(frozen=True, slots=True)
class RecordingPosition:
    """Where a page starts: after the row ``record_id`` of ``day``, or (``record_id``
    None) at the newest row of ``day``."""

    day: date
    record_id: int | None = None

    @classmethod
    def after(cls, record_id: int, listed_day: date) -> RecordingPosition:
        """The position after a row: its id's day when the id carries one, else the day
        the row was listed under."""
        return cls(record_id_day(record_id) or listed_day, record_id)


def encode_cursor(position: RecordingPosition, *, station_sn: str, device_sn: str | None) -> str:
    """The cursor text of ``position`` in the listing of ``station_sn`` and ``device_sn``
    (None: every camera); the same position gives the same text."""
    day = _day_text(position.day)
    body = f"r.{day}.{position.record_id}" if position.record_id is not None else f"d.{day}"
    body = f"{CURSOR_VERSION}.{body}"
    return f"{body}.{_check(body, station_sn, device_sn)}"


def decode_cursor(text: object, *, station_sn: str, device_sn: str | None) -> RecordingPosition:
    """The position a cursor of :func:`encode_cursor` names; :class:`RecordingCursorError`
    for anything else, a cursor that does not check out for that station and camera
    included."""
    if not isinstance(text, str) or (match := _CURSOR_RE.fullmatch(text)) is None:
        raise RecordingCursorError("not a recordings cursor")
    if match["version"] != CURSOR_VERSION:
        raise RecordingCursorError(f"a recordings cursor of another version ({match['version']})")
    body = text[: match.start("check") - 1]
    if match["check"] != _check(body, station_sn, device_sn):
        raise RecordingCursorError(
            "the recordings cursor does not check out for this station and camera"
        )
    try:
        day = _parse_day(match["rday"] or match["dday"])
    except ValueError as err:
        raise RecordingCursorError("the recordings cursor names no valid day") from err
    if match["id"] is None:
        return RecordingPosition(day)
    record_id = int(match["id"])
    own = record_id_day(record_id)
    if own is not None and own != day:
        raise RecordingCursorError("the recordings cursor's day is not its record's")
    return RecordingPosition(day, record_id)


@dataclass(frozen=True, slots=True)
class RecordingRef:
    """One history row of a station, as a reference names it: the station ``day`` it is
    listed under, its ``record_id``, its camera ``device_sn`` and its start time
    ``started`` (``YYYYMMDDHHMMSS``, the station's wall clock; None when the row has
    none in that form)."""

    day: date
    record_id: int
    device_sn: str
    started: str | None = None

    def time_cursors(self) -> tuple[str, str] | None:
        """The ``start_time`` cursors (``YYYYMMDDHHMMSS``) a lookup asks from, in order:
        one second after ``started``, then ``started``; None without ``started``.

        A station that lists the rows before the cursor starts the first page with the
        rows of ``started``'s second; one that lists them up to the cursor starts it
        with the rows of the next second, then those of ``started``'s, and starts the
        second page with the rows of ``started``'s second. Neither reaches a row behind
        a full page of rows that started in its own second."""
        return None if self.started is None else (_second_after(self.started), self.started)


def row_started(row: HistoryRecord) -> str | None:
    """``row``'s ``start_time`` as ``YYYYMMDDHHMMSS`` (a valid wall-clock time), else None."""
    if row.start_time is None:
        return None
    text = history_cursor_time(row.start_time)
    if len(text) != 14 or not text.isascii() or not text.isdigit():
        return None
    try:
        _second_after(text)
    except ValueError:
        return None
    return text


def issue_ref(
    row: HistoryRecord, listed_day: date, *, station_sn: str, need_started: bool
) -> str | None:
    """The reference of ``row``, listed under the station day ``listed_day`` on
    ``station_sn``; None for a row without a ``record_id`` or a camera, and with
    ``need_started`` (a station whose lookup pages by start time) for one without a
    start time."""
    if row.record_id <= 0 or not row.device_sn:
        return None
    started = row_started(row)
    if need_started and started is None:
        return None
    day = record_id_day(row.record_id) or listed_day
    return encode_ref(
        RecordingRef(day, row.record_id, row.device_sn, started), station_sn=station_sn
    )


def encode_ref(ref: RecordingRef, *, station_sn: str) -> str:
    """The text of ``ref`` on ``station_sn``; the same row gives the same text."""
    body = f"{CURSOR_VERSION}.k.{_day_text(ref.day)}.{ref.record_id}"
    if ref.started is not None:
        body = f"{body}.{ref.started}"
    return f"{body}.{_check(body, station_sn, ref.device_sn)}"


def decode_ref(text: object, *, station_sn: str, device_sns: Iterable[str]) -> RecordingRef:
    """The row a reference of :func:`encode_ref` names, for a camera of ``device_sns``;
    :class:`RecordingRefError` for anything else, a reference that does not check out
    for that station and those cameras included."""
    if not isinstance(text, str) or (match := _REF_RE.fullmatch(text)) is None:
        raise RecordingRefError("not a recording reference")
    if match["version"] != CURSOR_VERSION:
        raise RecordingRefError(f"a recording reference of another version ({match['version']})")
    body = text[: match.start("check") - 1]
    device_sn = next(
        (sn for sn in device_sns if match["check"] == _check(body, station_sn, sn)), None
    )
    if device_sn is None:
        raise RecordingRefError(
            "the recording reference does not check out for this station and camera"
        )
    try:
        day = _parse_day(match["day"])
    except ValueError as err:
        raise RecordingRefError("the recording reference names no valid day") from err
    started = match["started"]
    if started is not None:
        try:
            _second_after(started)
        except ValueError as err:
            raise RecordingRefError("the recording reference names no valid start time") from err
    record_id = int(match["id"])
    own = record_id_day(record_id)
    if own is not None and own != day:
        raise RecordingRefError("the recording reference's day is not its record's")
    return RecordingRef(day, record_id, device_sn, started)


def _second_after(text: str) -> str:
    """The ``YYYYMMDDHHMMSS`` wall-clock time one second after ``text``; ValueError when
    ``text`` is no valid time or the last one."""
    clock = time(int(text[8:10]), int(text[10:12]), int(text[12:14]))
    try:
        after = datetime.combine(_parse_day(text[:8]), clock) + timedelta(seconds=1)
    except OverflowError as err:
        raise ValueError("no time follows it") from err
    return f"{_day_text(after.date())}{after.hour:02d}{after.minute:02d}{after.second:02d}"


def _day_text(day: date) -> str:
    return f"{day.year:04d}{day.month:02d}{day.day:02d}"


def _parse_day(text: str) -> date:
    return date(int(text[:4]), int(text[4:6]), int(text[6:]))


def _check(body: str, station_sn: str, device_sn: str | None) -> str:
    """8 hex digits binding ``body`` to its listing (integrity, not secrecy)."""
    data = "\0".join(("recordings", station_sn, device_sn or "", body)).encode()
    return hashlib.blake2s(data, digest_size=_CHECK_LEN // 2).hexdigest()
