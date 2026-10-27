"""``recordings.py``: the recordings page, its cursor text and a row's reference."""

from __future__ import annotations

import json
from datetime import date
from urllib.parse import quote

import pytest

from eufy_home_security import RecordingCursorError, RecordingRefError, RecordingsPage
from eufy_home_security.events import HistoryRecord
from eufy_home_security.p2p.messages import HISTORY_RECORD_COUNTER
from eufy_home_security.recordings import (
    RecordingPosition,
    RecordingRef,
    _check,
    decode_cursor,
    decode_ref,
    encode_cursor,
    encode_ref,
    issue_ref,
)
from eufy_home_security.testing import SYNTHETIC

STATION = SYNTHETIC.station_sn
CAMERA = SYNTHETIC.camera_sn
DAY = date(2026, 9, 16)
DAYED_ID = 20260916 * HISTORY_RECORD_COUNTER + 12
OTHER_CAMERA = "T8160P2000099999"
OTHER_STATION = "T8030P2000099999"
LISTING = {"station_sn": STATION, "device_sn": CAMERA}


def _signed(body: str, device_sn: str | None = CAMERA) -> str:
    return f"{body}.{_check(body, STATION, device_sn)}"


@pytest.mark.parametrize(
    "position",
    [
        RecordingPosition(DAY, DAYED_ID),
        RecordingPosition(DAY, 2818),  # an id without a day: the day rides beside it
        RecordingPosition(DAY),
    ],
)
@pytest.mark.parametrize("device_sn", [CAMERA, None])
def test_a_cursor_names_its_position_again(
    position: RecordingPosition, device_sn: str | None
) -> None:
    text = encode_cursor(position, station_sn=STATION, device_sn=device_sn)
    assert decode_cursor(text, station_sn=STATION, device_sn=device_sn) == position
    assert encode_cursor(position, station_sn=STATION, device_sn=device_sn) == text
    assert json.loads(json.dumps(text)) == text
    assert text.isascii()
    assert text.startswith("v1.")


def test_the_cursor_text_is_stable() -> None:
    """The text of a position never changes for the same listing: stored cursors keep
    working after a restart or an upgrade within the version."""
    assert encode_cursor(RecordingPosition(DAY, DAYED_ID), **LISTING) == _signed(
        f"v1.r.20260916.{DAYED_ID}"
    )
    assert encode_cursor(RecordingPosition(DAY), **LISTING) == _signed("v1.d.20260916")
    assert encode_cursor(RecordingPosition(date(999, 1, 2)), **LISTING) == _signed("v1.d.09990102")


def test_a_position_after_a_row_takes_its_ids_day() -> None:
    assert RecordingPosition.after(DAYED_ID, date(2026, 9, 1)) == RecordingPosition(DAY, DAYED_ID)
    assert RecordingPosition.after(2818, DAY) == RecordingPosition(DAY, 2818)


@pytest.mark.parametrize(
    ("text", "match"),
    [
        (42, "not a recordings cursor"),
        (None, "not a recordings cursor"),
        ("", "not a recordings cursor"),
        (f"{DAYED_ID}", "not a recordings cursor"),  # the bare id the old form took
        ("20260916", "not a recordings cursor"),
        (_signed(f"v1.r.20260916.{DAYED_ID}") + " ", "not a recordings cursor"),
        (_signed("v1.r.20260916.0"), "not a recordings cursor"),
        (_signed("v1.r.20260916.012"), "not a recordings cursor"),
        (_signed("v1.x.20260916"), "not a recordings cursor"),
        (_signed("v1.d.20260916").upper(), "not a recordings cursor"),
        (_signed("v2.d.20260916"), "another version"),
        (_signed("v1.d.20260916")[:-1] + "0", "does not check out"),
        (_signed("v1.d.20260917")[:-8] + _signed("v1.d.20260916")[-8:], "does not check out"),
        (_signed("v1.d.20260916", device_sn=None), "does not check out"),
        (_signed("v1.d.20260916", device_sn=OTHER_CAMERA), "does not check out"),
        (_signed("v1.d.20261332"), "no valid day"),
        (_signed("v1.d.00000101"), "no valid day"),
        (_signed(f"v1.r.20260915.{DAYED_ID}"), "not its record's"),
    ],
)
def test_a_cursor_that_does_not_parse_or_check_out_is_refused(text: object, match: str) -> None:
    with pytest.raises(RecordingCursorError, match=match) as caught:
        decode_cursor(text, **LISTING)
    assert isinstance(caught.value, ValueError)


def test_a_cursor_of_another_station_is_refused() -> None:
    text = encode_cursor(RecordingPosition(DAY), **LISTING)
    with pytest.raises(RecordingCursorError, match="does not check out"):
        decode_cursor(text, station_sn=OTHER_STATION, device_sn=CAMERA)


def test_a_page_is_a_hashable_value() -> None:
    row = HistoryRecord(record_id=DAYED_ID, device_sn=CAMERA)
    page = RecordingsPage((row,), "v1.d.20260916.00000000")
    assert hash(page) == hash(RecordingsPage((row,), "v1.d.20260916.00000000"))


STARTED = "20260916121314"
CAMERAS = (CAMERA, OTHER_CAMERA)


def _clip(record_id: int = DAYED_ID, **fields: object) -> HistoryRecord:
    values: dict[str, object] = {
        "device_sn": CAMERA,
        "start_time": "2026-09-16 12:13:14",  # hygiene: ok
        **fields,
    }
    return HistoryRecord(record_id=record_id, **values)  # type: ignore[arg-type]


@pytest.mark.parametrize(
    ("row", "listed", "need_started", "named"),
    [
        (_clip(), date(2026, 9, 1), True, RecordingRef(DAY, DAYED_ID, CAMERA, STARTED)),
        # an id without a day: the day it was listed under rides beside it
        (_clip(2818), DAY, True, RecordingRef(DAY, 2818, CAMERA, STARTED)),
        (
            _clip(2818, device_sn=OTHER_CAMERA),
            DAY,
            True,
            RecordingRef(DAY, 2818, OTHER_CAMERA, STARTED),
        ),
        # found by its id: named by day and id alone, whatever its start time
        (_clip(), DAY, False, RecordingRef(DAY, DAYED_ID, CAMERA)),
        (_clip(start_time="1758024794"), DAY, False, RecordingRef(DAY, DAYED_ID, CAMERA)),
        (_clip(start_time=None), DAY, False, RecordingRef(DAY, DAYED_ID, CAMERA)),
    ],
)
def test_a_row_reference_names_its_row_again(
    row: HistoryRecord, listed: date, need_started: bool, named: RecordingRef
) -> None:
    text = issue_ref(row, listed, station_sn=STATION, need_started=need_started)
    assert text is not None
    assert decode_ref(text, station_sn=STATION, device_sns=CAMERAS) == named
    assert encode_ref(named, station_sn=STATION) == text
    assert quote(text, safe="") == text  # one URL path segment as it is
    assert json.loads(json.dumps(text)) == text
    assert text.startswith("v1.k.")


def test_the_reference_text_is_stable() -> None:
    """Stored references keep finding their rows after a restart or an upgrade within the
    version."""
    ref = issue_ref(_clip(2818), DAY, station_sn=STATION, need_started=True)
    assert ref == _signed(f"v1.k.20260916.2818.{STARTED}")
    assert encode_ref(RecordingRef(DAY, DAYED_ID, CAMERA), station_sn=STATION) == _signed(
        f"v1.k.20260916.{DAYED_ID}"
    )


@pytest.mark.parametrize(
    ("row", "need_started"),
    [
        (_clip(0), False),  # no record_id
        (_clip(-3), False),
        (_clip(device_sn=None), False),
        (_clip(device_sn=""), False),
        (_clip(start_time=None), True),  # found by start time: needs one
        (_clip(start_time="1758024794"), True),
        (_clip(start_time="2026-09-16 25:00:00"), True),  # hygiene: ok
        (_clip(start_time="9999-12-31 23:59:59"), True),  # no second after it  # hygiene: ok
        (_clip(start_time="2026091612131400"), True),  # too many digits
        (_clip(start_time="20_6-09-16 12:13:14"), True),  # hygiene: ok
        (_clip(start_time="\uff12\uff10\uff12\uff16-09-16 12:13:14"), True),  # hygiene: ok
    ],
)
def test_a_row_that_cannot_be_found_again_gets_no_reference(
    row: HistoryRecord, need_started: bool
) -> None:
    assert issue_ref(row, DAY, station_sn=STATION, need_started=need_started) is None


@pytest.mark.parametrize(
    ("started", "cursor"),
    [
        (STARTED, "20260916121315"),
        ("20260916235959", "20260917000000"),
        ("20261231235959", "20270101000000"),
        ("09990102030405", "09990102030406"),
        (None, None),
    ],
)
def test_a_reference_asks_from_the_second_after_its_start_then_from_its_start(
    started: str | None, cursor: str | None
) -> None:
    cursors = RecordingRef(DAY, 2818, CAMERA, started).time_cursors()
    assert cursors == (None if cursor is None else (cursor, started))


@pytest.mark.parametrize(
    ("text", "match"),
    [
        (2818, "not a recording reference"),
        (None, "not a recording reference"),
        ("", "not a recording reference"),
        (f"{DAYED_ID}", "not a recording reference"),  # the bare id
        (_signed(f"v1.k.20260916.{DAYED_ID}") + "/", "not a recording reference"),
        (_signed("v1.k.20260916.0"), "not a recording reference"),
        (_signed("v1.k.20260916.02818"), "not a recording reference"),
        (_signed("v1.k.20260916.2818.2026091612131"), "not a recording reference"),
        (_signed(f"v1.k.20260916.2818.{STARTED}").upper(), "not a recording reference"),
        # a page cursor is no reference, whichever camera it is bound to
        (_signed(f"v1.r.20260916.{DAYED_ID}"), "not a recording reference"),
        (_signed("v1.d.20260916"), "not a recording reference"),
        (_signed("v2.k.20260916.2818"), "another version"),
        (_signed("v1.k.20260916.2818")[:-1] + "0", "does not check out"),
        (
            _signed("v1.k.20260916.2818")[:-8] + _signed("v1.k.20260916.2819")[-8:],
            "does not check out",
        ),
        (_signed("v1.k.20260916.2818", device_sn=None), "does not check out"),
        (_signed("v1.k.20260916.2818", device_sn="T8160P2000011111"), "does not check out"),
        (_signed("v1.k.20261332.2818"), "no valid day"),
        (_signed("v1.k.20260916.2818.20260916241314"), "no valid start time"),
        (_signed("v1.k.20260916.2818.99991231235959"), "no valid start time"),
        (_signed(f"v1.k.20260915.{DAYED_ID}"), "not its record's"),
    ],
)
def test_a_reference_that_does_not_parse_or_check_out_is_refused(text: object, match: str) -> None:
    with pytest.raises(RecordingRefError, match=match) as caught:
        decode_ref(text, station_sn=STATION, device_sns=CAMERAS)
    assert isinstance(caught.value, ValueError)


def test_a_reference_names_the_camera_it_checks_out_for() -> None:
    ref = RecordingRef(DAY, 2818, OTHER_CAMERA, STARTED)
    text = encode_ref(ref, station_sn=STATION)
    assert decode_ref(text, station_sn=STATION, device_sns=CAMERAS) == ref
    with pytest.raises(RecordingRefError, match="does not check out"):
        decode_ref(text, station_sn=STATION, device_sns=(CAMERA,))
    with pytest.raises(RecordingRefError, match="does not check out"):
        decode_ref(text, station_sn=OTHER_STATION, device_sns=CAMERAS)


def test_a_reference_is_no_page_cursor() -> None:
    text = encode_ref(RecordingRef(DAY, DAYED_ID, CAMERA), station_sn=STATION)
    with pytest.raises(RecordingCursorError, match="not a recordings cursor"):
        decode_cursor(text, **LISTING)
