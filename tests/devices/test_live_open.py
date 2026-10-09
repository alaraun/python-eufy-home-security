"""The generated live-open table (devices/_live_open_data.py)."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from eufy_home_security.devices import live_open
from eufy_home_security.devices.live_open import LiveOpen, has_live_open, library_live_open
from eufy_home_security.devices.recipes import PARENT_CONNECT_TYPES, ConnectType

ROOT = Path(__file__).resolve().parents[2]
CACHE = ROOT / ".work" / "cache" / "things_all"


def test_every_product_lists_every_connect_type() -> None:
    kinds = {ConnectType.SINGLE, *PARENT_CONNECT_TYPES.values()}
    table = live_open._TABLE
    assert table
    for code, modes in table.items():
        assert code == code.upper()
        assert set(modes) == kinds, code


@pytest.mark.parametrize(
    ("code", "connect", "mode"),
    [
        # the golden cases (tests/fixtures/thing_models)
        ("T8170", ConnectType.SINGLE, LiveOpen.SINGLE),
        ("T8410", ConnectType.SINGLE, LiveOpen.SINGLE_NO_EXT),
        ("T8410C", ConnectType.SINGLE, LiveOpen.SINGLE_NO_EXT),
        ("T8113", ConnectType.HB2, LiveOpen.STATION),
        ("T8142", ConnectType.HB2, LiveOpen.STATION),
        ("T8160", ConnectType.HB3, LiveOpen.STATION),
        # a standalone product whose handler sends the station open
        ("T8213", ConnectType.SINGLE, LiveOpen.STATION),
        # a Wi-Fi camera whose handler keeps its 1700 open behind a station
        ("T8400", ConnectType.HB2, LiveOpen.SINGLE_NO_EXT),
        # dual-lens: an open the library does not implement
        ("T8172", ConnectType.HB3, None),
    ],
)
def test_the_handlers_open(code: str, connect: ConnectType, mode: LiveOpen | None) -> None:
    assert live_open.live_open(code, connect) is mode
    assert live_open.live_open(code.lower(), connect) is mode


def test_the_library_sends_a_1700_open_only_on_the_devices_own_session() -> None:
    assert library_live_open("T8400", ConnectType.SINGLE) is LiveOpen.SINGLE_NO_EXT
    assert library_live_open("T8400", ConnectType.HB3) is None
    assert library_live_open("T8113", ConnectType.HB2) is LiveOpen.STATION
    assert library_live_open("T8213", ConnectType.SINGLE) is LiveOpen.STATION


def test_an_unlisted_product_has_no_recorded_open() -> None:
    assert not has_live_open("T9999")
    assert not has_live_open(None)
    assert has_live_open("t8172")
    assert live_open.live_open("T9999", ConnectType.SINGLE) is None
    assert live_open.app_version()


@pytest.mark.skipif(
    not CACHE.is_dir() or shutil.which("node") is None,
    reason="needs the private thing-model cache and Node",
)
def test_the_table_is_what_the_generator_writes() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "gen_live_open.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
        timeout=300,
    )
    assert result.returncode == 0, result.stdout + result.stderr
