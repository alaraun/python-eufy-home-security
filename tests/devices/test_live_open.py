"""The generated live-open table (devices/_live_open_data.py)."""

from __future__ import annotations

import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from eufy_home_security.devices import live_open
from eufy_home_security.devices.live_open import (
    LiveOpen,
    LiveStop,
    has_live_open,
    library_live_open,
    live_stop,
)
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


def test_the_library_sends_a_1700_open_on_its_own_session_and_behind_a_homebase() -> None:
    assert (
        library_live_open("T8400", ConnectType.SINGLE, over_webrtc=False) is LiveOpen.SINGLE_NO_EXT
    )
    assert library_live_open("T8400", ConnectType.HB3, over_webrtc=False) is LiveOpen.SINGLE_NO_EXT
    assert library_live_open("T8400", ConnectType.HB2, over_webrtc=False) is LiveOpen.SINGLE_NO_EXT
    assert library_live_open("T8600", ConnectType.HB3, over_webrtc=False) is LiveOpen.SINGLE_NO_EXT
    assert library_live_open("T8113", ConnectType.HB2, over_webrtc=False) is LiveOpen.STATION
    assert library_live_open("T8213", ConnectType.SINGLE, over_webrtc=False) is LiveOpen.STATION


def test_no_1700_open_behind_a_station_without_the_handlers_stop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live_open, "_STOPS", {"T8600": {ConnectType.HB3: None}})
    assert library_live_open("T8600", ConnectType.HB3, over_webrtc=False) is None


def test_no_1700_open_behind_another_station_kind() -> None:
    assert live_open.live_open("T8400", ConnectType.M8025) is LiveOpen.SINGLE_NO_EXT
    assert library_live_open("T8400", ConnectType.M8025, over_webrtc=False) is None


@pytest.mark.parametrize(
    ("code", "connect"),
    [
        ("T8224", ConnectType.HB3),  # a 1700 open behind a station
        ("T8113", ConnectType.HB2),  # the station open
        ("T8400", ConnectType.SINGLE),  # on its own session
    ],
)
def test_no_open_where_the_app_streams_over_webrtc(code: str, connect: ConnectType) -> None:
    assert library_live_open(code, connect, over_webrtc=False) is not None
    assert library_live_open(code, connect, over_webrtc=True) is None


@pytest.mark.parametrize(
    ("code", "connect", "stop"),
    [
        ("T8600", ConnectType.HB3, LiveStop.STATION),
        ("T8400", ConnectType.HB3, LiveStop.STATION),
        ("T8200X", ConnectType.HB3, LiveStop.BARE),
        ("T8400", ConnectType.HB2, LiveStop.BARE),
        ("T8160", ConnectType.HB3, None),  # the station open: no 1700 stop recorded
        ("T8400", ConnectType.SINGLE, None),
        (None, ConnectType.HB3, None),
    ],
)
def test_the_handlers_stop_after_a_1700_open_behind_a_station(
    code: str | None, connect: ConnectType, stop: LiveStop | None
) -> None:
    assert live_stop(code, connect) is stop


def test_a_stop_is_recorded_only_for_a_1700_open_behind_a_station() -> None:
    assert live_open._STOPS
    for code, stops in live_open._STOPS.items():
        for connect in stops:
            assert connect is not ConnectType.SINGLE, code
            assert live_open.live_open(code, connect) in (LiveOpen.SINGLE, LiveOpen.SINGLE_NO_EXT)


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
