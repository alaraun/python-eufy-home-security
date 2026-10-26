"""``recordings.py``: the recordings page and its cursor text."""

from __future__ import annotations

import json
from datetime import date

import pytest

from eufy_home_security import RecordingCursorError, RecordingsPage
from eufy_home_security.events import HistoryRecord
from eufy_home_security.p2p.messages import HISTORY_RECORD_COUNTER
from eufy_home_security.recordings import (
    RecordingPosition,
    _check,
    decode_cursor,
    encode_cursor,
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
