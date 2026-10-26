"""Pages of a station's recordings and their opaque cursor.

A cursor names a position in one listing (a station and its camera filter): after a
row, by the row's station day and ``record_id``, or at a day, by that day's rows and
older ones. Days are the station's own (the day a history query names), never the
host's. Callers keep the text as it came and hand it back; its form is not API.
See ``docs/how-to/home-assistant.md`` § The station's recordings.
"""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass
from datetime import date
from typing import TYPE_CHECKING, Final

from .exceptions import RecordingCursorError
from .p2p.messages import record_id_day

if TYPE_CHECKING:
    from .events import HistoryRecord

__all__ = ["RecordingPosition", "RecordingsPage", "decode_cursor", "encode_cursor"]

CURSOR_VERSION: Final = "v1"
"""The version tag every cursor starts with; a cursor of another version is refused."""
_CHECK_LEN: Final = 8  # hex digits
_CURSOR_RE: Final = re.compile(
    r"(?P<version>v\d+)\.(?:r\.(?P<rday>\d{8})\.(?P<id>[1-9]\d{0,19})|d\.(?P<dday>\d{8}))"
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


def _day_text(day: date) -> str:
    return f"{day.year:04d}{day.month:02d}{day.day:02d}"


def _parse_day(text: str) -> date:
    return date(int(text[:4]), int(text[4:6]), int(text[6:]))


def _check(body: str, station_sn: str, device_sn: str | None) -> str:
    """8 hex digits binding ``body`` to its listing (integrity, not secrecy)."""
    data = "\0".join(("recordings", station_sn, device_sn or "", body)).encode()
    return hashlib.blake2s(data, digest_size=_CHECK_LEN // 2).hexdigest()
