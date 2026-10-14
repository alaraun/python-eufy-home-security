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

from eufy_home_security.devices import live_open, ptz, recipes
from eufy_home_security.devices.model_settings import product_code_of
from eufy_home_security.devices.ptz import PtzForm
from eufy_home_security.devices.recipes import ConnectType, Recipe

FIXTURES = Path(__file__).resolve().parent.parent / "fixtures" / "thing_models"
GOLDEN_FILES = sorted(FIXTURES.glob("*.json"))

type Case = dict[str, Any]


def _open_live_stream(case: Case) -> Recipe:
    payload = case["payload"]
    if _connect_type(case) is not ConnectType.SINGLE:
        return recipes.open_live_stream_station(
            channel=case["device"]["device_channel"],
            account_id=payload["userId"],
            key_hex=payload["key"],
        )
    return recipes.open_live_stream_single(
        channel=case["device"]["device_channel"],
        account_id=payload["userId"],
        key_hex=payload["key"],
        entry_type=payload["entryType"],
        camera_type=payload["cameraType"],
        stream_type=payload["streamType"],
        ext_value=live_open.live_open(
            product_code_of(None, case["device"]["device_sn"]), ConnectType.SINGLE
        )
        is not live_open.LiveOpen.SINGLE_NO_EXT,
    )


def _ptz_form(case: Case) -> PtzForm | None:
    """The form the generated table (:mod:`eufy_home_security.devices.ptz`) names for the
    case's product, action and connect type."""
    code = product_code_of(None, case["device"]["device_sn"])
    return ptz.ptz_form(code, case["identifier"], _connect_type(case))


def _ptz_rotate(case: Case) -> Recipe:
    payload = case["payload"]
    return recipes.ptz_rotate(
        cmd_type=payload["cmdType"],
        rotate_type=payload["rotateType"],
        zoom=payload["zoom"],
        zoom_ivalue=_ptz_form(case) is PtzForm.STANDARD,
    )


BUILDERS: dict[str, Callable[[Case], Recipe]] = {
    "open_live_stream": _open_live_stream,
    "close_live_stream": lambda case: recipes.close_live_stream(),
    "query_preset_positions": lambda case: recipes.query_preset_positions(
        value=_ptz_form(case) is PtzForm.STANDARD
    ),
    "set_ptz_cruise_preview": lambda case: recipes.goto_preset(case["payload"]),
    "get_preset_position_pic": lambda case: recipes.preset_picture(case["payload"]),
    "ptz_action_control": _ptz_rotate,
    "set_picture_zoom": lambda case: recipes.set_picture_zoom(case["payload"]["dstZoom"]),
}
"""Each identifier the library implements, called with a golden case's input; a
pan/tilt/zoom action in the form :mod:`eufy_home_security.devices.ptz` names for it."""


def _connect_type(case: Case) -> ConnectType:
    return recipes.connect_type(case["device"]["parent_sn"], case["device"]["device_sn"])


def _is_homebase_live_open(case: Case) -> bool:
    """The documented deviation: behind a HomeBase 3 the library keeps the app's T8030 open."""
    return case["identifier"] == "open_live_stream" and _connect_type(case) is ConnectType.HB3


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


def test_the_golden_files_of_the_standalone_homebase3_and_homebase2_cameras_are_present() -> None:
    names = [path.name for path in GOLDEN_FILES]
    assert names == [
        "T8113.json",
        "T8142.json",
        "T8160.json",
        "T8170.json",
        "T8410.json",
        "T8410C.json",
        "T8425.json",
    ]


def test_every_golden_identifier_is_mapped_to_a_builder() -> None:
    unmapped = {case["identifier"] for _, case in _golden_cases()} - BUILDERS.keys()
    assert unmapped == set()


@pytest.mark.parametrize(("product_code", "case"), list(_builder_params()))
def test_the_builder_reproduces_the_handlers_recipe(product_code: str, case: Case) -> None:
    expected = {k: v for k, v in case["p2p"].items() if k not in recipes.HANDLER_UNUSED_KEYS}
    assert BUILDERS[case["identifier"]](case).as_handler_dict() == expected


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
