"""The recipe builders against the app's own handlers (``tests/fixtures/thing_models``).

The golden files are written by ``scripts/thing_models.py goldens`` from the handler
scripts; each case's ``p2p`` is the handler's recipe for that device and payload.
"""

from __future__ import annotations

import json
from collections.abc import Callable, Iterator
from pathlib import Path
from typing import Any

import pytest

from eufy_home_security.devices import recipes
from eufy_home_security.devices.recipes import ConnectType, HandlerVariant, Recipe

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "thing_models"
GOLDEN_FILES = sorted(FIXTURES.glob("*.json"))

type Case = dict[str, Any]


def _open_live_stream(case: Case, variant: HandlerVariant) -> Recipe:
    payload = case["payload"]
    return recipes.open_live_stream_single(
        channel=case["device"]["device_channel"],
        account_id=payload["userId"],
        key_hex=payload["key"],
        entry_type=payload["entryType"],
        camera_type=payload["cameraType"],
        stream_type=payload["streamType"],
        ext_value=variant.live_open_ext_value,
    )


def _ptz_rotate(case: Case, variant: HandlerVariant) -> Recipe:
    payload = case["payload"]
    return recipes.ptz_rotate(
        cmd_type=payload["cmdType"],
        rotate_type=payload["rotateType"],
        zoom=payload["zoom"],
        zoom_ivalue=variant.ptz_zoom_ivalue,
    )


BUILDERS: dict[str, Callable[[Case, HandlerVariant], Recipe]] = {
    "open_live_stream": _open_live_stream,
    "close_live_stream": lambda case, variant: recipes.close_live_stream(),
    "query_preset_positions": lambda case, variant: recipes.query_preset_positions(),
    "set_ptz_cruise_preview": lambda case, variant: recipes.goto_preset(case["payload"]),
    "get_preset_position_pic": lambda case, variant: recipes.preset_picture(case["payload"]),
    "ptz_action_control": _ptz_rotate,
    "set_picture_zoom": lambda case, variant: recipes.set_picture_zoom(case["payload"]["dstZoom"]),
}
"""Each identifier the library implements, called with a golden case's input and the
product's :func:`~eufy_home_security.devices.recipes.handler_variant`."""


def _connect_type(case: Case) -> ConnectType:
    return recipes.connect_type(case["device"]["parent_sn"], case["device"]["device_sn"])


def _is_homebase_live_open(case: Case) -> bool:
    """The documented deviation: behind a station the library keeps its own live open."""
    return case["identifier"] == "open_live_stream" and _connect_type(case) is not (
        ConnectType.SINGLE
    )


def _golden_cases() -> Iterator[tuple[str, Case]]:
    for path in GOLDEN_FILES:
        golden = json.loads(path.read_text(encoding="utf-8"))
        for case in golden["cases"]:
            yield golden["product_code"], case


def _builder_params() -> Iterator[Any]:
    for product_code, case in _golden_cases():
        identifier = case["identifier"]
        if identifier not in BUILDERS or _is_homebase_live_open(case):
            continue
        yield pytest.param(product_code, case, id=f"{product_code}-{identifier}")


def test_the_golden_files_for_the_t8170_t8410_t8410c_and_the_homebase_t8160_are_present() -> None:
    names = [path.name for path in GOLDEN_FILES]
    assert names == ["T8160.json", "T8170.json", "T8410.json", "T8410C.json"]


def test_every_golden_identifier_is_mapped_to_a_builder() -> None:
    unmapped = {case["identifier"] for _, case in _golden_cases()} - BUILDERS.keys()
    assert unmapped == set()


@pytest.mark.parametrize(("product_code", "case"), list(_builder_params()))
def test_the_builder_reproduces_the_handlers_recipe(product_code: str, case: Case) -> None:
    expected = {k: v for k, v in case["p2p"].items() if k not in recipes.HANDLER_UNUSED_KEYS}
    variant = recipes.handler_variant(product_code)
    assert BUILDERS[case["identifier"]](case, variant).as_handler_dict() == expected


def test_the_handlers_homebase_live_open_is_the_1350_1003_frame_the_library_does_not_use() -> None:
    homebase_opens = [case for _, case in _golden_cases() if _is_homebase_live_open(case)]
    assert len(homebase_opens) == 1
    (case,) = homebase_opens
    assert _connect_type(case) is ConnectType.HB3
    p2p = case["p2p"]
    assert (p2p["cmd"], p2p["subCmd"], p2p["timeout"]) == (1350, 1003, 15000)
    assert p2p["params"]["cmd"] == 1003
    assert p2p["params"]["mChannel"] == case["device"]["device_channel"]
    assert p2p["params"]["payload"]["key"] == case["payload"]["key"]
