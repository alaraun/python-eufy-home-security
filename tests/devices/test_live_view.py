"""The app's live view of a camera with lenses (devices/live_view.py)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

import pytest

from eufy_home_security.devices.live_view import (
    PIP_CORD_DEFAULT,
    Lens,
    LensView,
    default_lens_view,
    live_view,
    parse_lenses,
    player_input,
)
from eufy_home_security.devices.recipes import StitchMode
from eufy_home_security.testing import SYNTHETIC

GOLDEN = Path(__file__).resolve().parent.parent / "fixtures" / "thing_models" / "T8172.json"
KEY = "0123456789ABCDEF" * 16
TWO = (Lens(1, 0), Lens(1, 1))


def _entry(chn: int, index: int, sensor: int) -> dict[str, int]:
    return {"cameraType": 0, "chn": chn, "index": index, "sensor": sensor}


@pytest.mark.parametrize(
    ("value", "lenses"),
    [
        ('[{"type":1,"id":0},{"type":1,"id":1}]', TWO),
        ('[{"type":"2","id":"1"}]', (Lens(2, 1),)),
        (None, ()),
        ("", ()),
        ("[]", ()),
        ("not json", ()),
        ('{"type":1,"id":0}', ()),
        ('[{"type":1}]', ()),
        ('[{"type":1,"id":0},3]', ()),
    ],
)
def test_the_lens_list_reads_as_the_app_reads_it(value: str | None, lenses: tuple[Lens]) -> None:
    assert parse_lenses(value) == lenses


def test_the_live_page_opens_stacked_with_lenses_and_on_the_fixed_lens_without() -> None:
    assert default_lens_view(TWO) is LensView.STACKED
    assert default_lens_view((Lens(1, 1),)) is LensView.STACKED
    assert default_lens_view(()) is LensView.MAIN


@pytest.mark.parametrize(
    ("view", "stitch", "entries", "video_type", "cord"),
    [
        (LensView.MAIN, StitchMode.SINGLE, [_entry(3, 0, 0)], 0, None),
        (LensView.SUB, StitchMode.SINGLE, [_entry(3, 0, 1)], 1, None),
        (LensView.STACKED, StitchMode.STACKED, [_entry(3, 0, 0), _entry(3, 1, 1)], 0, None),
        (LensView.PIP, StitchMode.PIP, [_entry(3, 0, 0), _entry(3, 1, 1)], 9, PIP_CORD_DEFAULT),
    ],
)
def test_each_layout_of_a_two_lens_camera(
    view: LensView,
    stitch: StitchMode,
    entries: list[dict[str, int]],
    video_type: int,
    cord: tuple[float, ...] | None,
) -> None:
    got = live_view(3, TWO, view)
    assert (got.view, got.stitch_mode, got.audio_chn) == (view, stitch, 3)
    assert [dict(e) for e in got.chn_list] == entries
    assert (got.station_video_type, got.pip_cord) == (video_type, cord)


def test_a_layout_of_several_lenses_keeps_the_list_order_and_places_the_fixed_lens_first() -> None:
    got = live_view(2, (Lens(1, 1), Lens(1, 0), Lens(1, 2)), LensView.STACKED)
    assert [dict(e) for e in got.chn_list] == [_entry(2, 1, 1), _entry(2, 0, 0), _entry(2, 1, 2)]


@pytest.mark.parametrize("view", [LensView.STACKED, LensView.PIP])
def test_a_layout_of_several_lenses_without_a_lens_list_names_the_fixed_lens(
    view: LensView,
) -> None:
    assert [dict(e) for e in live_view(4, (), view).chn_list] == [_entry(4, 0, 0)]


def test_one_lens_names_the_lens_asked_for_with_or_without_a_lens_list() -> None:
    assert [dict(e) for e in live_view(4, (), LensView.SUB).chn_list] == [_entry(4, 0, 1)]


def _golden_inputs() -> dict[str, dict[str, Any]]:
    """The HomeBase 3 player inputs of the golden cases, by layout."""
    cases = json.loads(GOLDEN.read_text(encoding="utf-8"))["cases"]
    by_mode = {
        StitchMode.SINGLE: {0: "main", 1: "sub"},
        StitchMode.STACKED: {0: "stacked"},
        StitchMode.PIP: {9: "pip"},
    }
    out = {}
    for case in cases:
        payload = case["payload"]
        if case["identifier"] == "open_live_stream" and "stitch_mode" in payload:
            name = by_mode[StitchMode(payload["stitch_mode"])][payload["station_video_type"]]
            out[name] = payload
    return out


@pytest.mark.parametrize("view", list(LensView))
def test_the_homebase3_player_input_is_the_golden_cases(view: LensView) -> None:
    got = player_input(
        account_id=SYNTHETIC.account_id,
        key_hex=KEY,
        view=live_view(3, TWO, view),
        station_fields=True,
    )
    assert got == _golden_inputs()[view.value]


def test_the_player_input_elsewhere_carries_no_view() -> None:
    got = player_input(
        account_id="a", key_hex="k", view=live_view(3, TWO, LensView.PIP), station_fields=False
    )
    assert got == {
        "key": "k",
        "userId": "a",
        "ClientOS": "ANDROID",
        "streamType": 0,
        "cameraType": 0,
        "entryType": 0,
    }
