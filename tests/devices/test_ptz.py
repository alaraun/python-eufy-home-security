"""The generated pan/tilt/zoom table (devices/_ptz_data.py)."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from eufy_home_security.devices import ptz
from eufy_home_security.devices.ptz import (
    PTZ_IDENTIFIERS,
    PtzForm,
    has_ptz_recipes,
    ptz_actions,
    ptz_form,
)
from eufy_home_security.devices.recipes import PARENT_CONNECT_TYPES, ConnectType

ROOT = Path(__file__).resolve().parents[2]
CACHE = ROOT / ".work" / "cache" / "things_all"


def test_every_listed_action_names_every_connect_type() -> None:
    kinds = {ConnectType.SINGLE, *PARENT_CONNECT_TYPES.values()}
    assert ptz._TABLE
    for code, actions in ptz._TABLE.items():
        assert code == code.upper()
        assert actions, code
        assert set(actions) <= set(PTZ_IDENTIFIERS), code
        for forms in actions.values():
            assert set(forms) == kinds, code


@pytest.mark.parametrize(
    ("code", "action", "connect", "form"),
    [
        # the golden cases (tests/fixtures/thing_models)
        ("T8170", "ptz_action_control", ConnectType.SINGLE, PtzForm.STANDARD),
        ("T8170", "query_preset_positions", ConnectType.SINGLE, PtzForm.STANDARD),
        ("T8410", "ptz_action_control", ConnectType.SINGLE, PtzForm.PLAIN),
        ("T8410C", "ptz_action_control", ConnectType.SINGLE, PtzForm.STANDARD),
        ("T8425", "ptz_action_control", ConnectType.HB3, PtzForm.PLAIN),
        ("T8425", "query_preset_positions", ConnectType.HB3, PtzForm.PLAIN),
        ("T8425", "set_ptz_cruise_preview", ConnectType.HB3, PtzForm.STANDARD),
        ("T8425", "set_picture_zoom", ConnectType.HB3, PtzForm.STANDARD),
        # the app reaches a camera behind these stations over WebRTC only
        ("T8425", "ptz_action_control", ConnectType.NVR, None),
        # a pan/tilt step the handler sends as a 1350 DeviceMsgBean
        ("T8423", "ptz_action_control", ConnectType.SINGLE, None),
        # declared, but the handler builds no recipe for it
        ("T84A1", "query_preset_positions", ConnectType.SINGLE, None),
    ],
)
def test_the_handlers_form(
    code: str, action: str, connect: ConnectType, form: PtzForm | None
) -> None:
    assert ptz_form(code, action, connect) is form
    assert ptz_form(code.lower(), action, connect) is form


def test_an_action_the_thing_description_does_not_declare_has_no_form() -> None:
    assert "set_picture_zoom" not in ptz_actions("T8410")
    assert ptz_form("T8410", "set_picture_zoom", ConnectType.SINGLE) is None
    assert "set_preset_positions" not in ptz_actions("T8173")
    assert "set_preset_positions" in ptz_actions("t8425")


def test_an_unlisted_product_has_no_recorded_action() -> None:
    assert has_ptz_recipes("T8425")
    assert not has_ptz_recipes("T8160")
    assert not has_ptz_recipes(None)
    assert ptz_actions(None) == frozenset()
    assert ptz_form(None, "ptz_action_control", ConnectType.SINGLE) is None
    assert ptz.app_version()


@pytest.mark.skipif(
    not CACHE.is_dir() or shutil.which("node") is None,
    reason="needs the private thing-model cache and Node",
)
def test_the_table_is_what_the_generator_writes() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "gen_ptz.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert result.returncode == 0, result.stdout + result.stderr
