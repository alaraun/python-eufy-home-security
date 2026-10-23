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
    app_uses_webrtc,
    has_live_open,
    library_live_open,
    live_stop,
)
from eufy_home_security.devices.recipes import PARENT_CONNECT_TYPES, ConnectType

IN_WINDOW = "3.8.7.4"  # a HomeBase 3 firmware inside the app's WebRTC window
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
        library_live_open("T8400", ConnectType.SINGLE, station_firmware=IN_WINDOW)
        is LiveOpen.SINGLE_NO_EXT
    )
    assert (
        library_live_open("T8400", ConnectType.HB3, station_firmware=IN_WINDOW)
        is LiveOpen.SINGLE_NO_EXT
    )
    assert (
        library_live_open("T8400", ConnectType.HB2, station_firmware=IN_WINDOW)
        is LiveOpen.SINGLE_NO_EXT
    )
    assert (
        library_live_open("T8600", ConnectType.HB3, station_firmware=IN_WINDOW)
        is LiveOpen.SINGLE_NO_EXT
    )
    assert (
        library_live_open("T8113", ConnectType.HB2, station_firmware=IN_WINDOW) is LiveOpen.STATION
    )
    assert (
        library_live_open("T8213", ConnectType.SINGLE, station_firmware=IN_WINDOW)
        is LiveOpen.STATION
    )


def test_no_1700_open_behind_a_station_without_the_handlers_stop(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setattr(live_open, "_STOPS", {"T8600": {ConnectType.HB3: None}})
    assert library_live_open("T8600", ConnectType.HB3, station_firmware=IN_WINDOW) is None


def test_no_1700_open_behind_another_station_kind() -> None:
    assert live_open.live_open("T8400", ConnectType.M8025) is LiveOpen.SINGLE_NO_EXT
    assert library_live_open("T8400", ConnectType.M8025, station_firmware=IN_WINDOW) is None


@pytest.mark.parametrize("firmware", ["3.7.4.3", IN_WINDOW, "4.1.9.999"])
def test_no_open_where_the_app_streams_over_webrtc(firmware: str) -> None:
    assert live_open.live_open("T8224", ConnectType.HB3) is LiveOpen.SINGLE
    assert app_uses_webrtc("t8224", ConnectType.HB3, station_firmware=firmware)
    assert app_uses_webrtc("T8223", ConnectType.HB3, station_firmware=firmware)
    assert library_live_open("T8224", ConnectType.HB3, station_firmware=firmware) is None


@pytest.mark.parametrize("firmware", ["3.7.4.2", "4.1.9.1000", "4.2.0.0", "", None])
def test_the_handlers_open_outside_the_apps_webrtc_firmware_window(firmware: str | None) -> None:
    assert not app_uses_webrtc("T8224", ConnectType.HB3, station_firmware=firmware)
    assert library_live_open("T8224", ConnectType.HB3, station_firmware=firmware) is (
        LiveOpen.SINGLE
    )


def test_webrtc_only_for_the_listed_products_and_station_kind() -> None:
    assert not app_uses_webrtc("T8224", ConnectType.HB2, station_firmware=IN_WINDOW)
    assert library_live_open("T8224", ConnectType.HB2, station_firmware=IN_WINDOW) is (
        LiveOpen.STATION
    )
    assert not app_uses_webrtc("T8600", ConnectType.HB3, station_firmware=IN_WINDOW)
    assert not app_uses_webrtc(None, ConnectType.HB3, station_firmware=IN_WINDOW)


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
