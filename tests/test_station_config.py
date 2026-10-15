from __future__ import annotations

import base64
import dataclasses
import json
from collections.abc import AsyncIterator
from typing import Any

import pytest

from eufy_home_security.cloud.models import CloudDevice
from eufy_home_security.models import GUARD_MODE_LABELS, GuardMode, ValueSource
from eufy_home_security.p2p.params import ParamDump
from eufy_home_security.p2p.session import P2PCredentials, StationSession
from eufy_home_security.station import Station, StationState
from eufy_home_security.station_config import (
    MODE_ORDER,
    StationConfig,
    build_station_config,
    guard_mode_label,
)
from eufy_home_security.testing import SYNTHETIC
from eufy_home_security.testing.station import FakeStation

STATION = CloudDevice(
    device_sn=SYNTHETIC.station_sn,
    device_type=18,
    name="Home Base",
    p2p_did=SYNTHETIC.did,
    main_sw_version="3.8.7.4",
)
CAMERA = CloudDevice(
    device_sn=SYNTHETIC.camera_sn,
    device_type=19,
    name="Front",
    station_sn=SYNTHETIC.station_sn,
    channel=0,
)


def b64(obj: object) -> str:
    return base64.b64encode(json.dumps(obj, separators=(",", ":")).encode()).decode()


def mode_list(*entries: tuple[int, str, int]) -> str:
    """A 1256 value listing ``(mode, title, icon)`` entries."""
    modes = [{"iconType": icon, "mode": mode, "title": title} for mode, title, icon in entries]
    return b64({"account_id": SYNTHETIC.account_id, "mode_id": 3, "modes": modes})


def schedule(*slots: tuple[int, int, int, int]) -> str:
    """A 1254 value of ``(weekday, start hour, end hour, mode)`` slots."""
    return b64(
        {
            "account_id": SYNTHETIC.account_id,
            "schedules": [
                {"week": w, "start_h": s, "start_m": 0, "end_h": e, "end_m": 0, "mode_id": m}
                for w, s, e, m in slots
            ],
        }
    )


def _offline_station(sub_devices: tuple[CloudDevice, ...] = (CAMERA,)) -> Station:
    async def no_credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        raise AssertionError("not connecting")

    session = StationSession(SYNTHETIC.station_sn, no_credentials, host=None)
    return Station(STATION, session, sub_devices=sub_devices)


def _cloud_entry(params: dict[int, str]) -> CloudDevice:
    raw: dict[str, Any] = {
        "params": [
            {"param_type": pid, "param_value": value, "update_time": 1.7e9}
            for pid, value in params.items()
        ]
    }
    return dataclasses.replace(STATION, raw=raw)


def state_of(
    station: dict[int, str],
    *,
    cloud: dict[int, str] | None = None,
    blocks: dict[int, dict[int, str]] | None = None,
) -> StationState:
    """The state of the synthetic hub from its own block, a cloud copy and device blocks."""
    st = _offline_station()
    if cloud is not None:
        st.apply_cloud_device(_cloud_entry(cloud))
    dump = ParamDump()
    dump.ingest(
        {
            "params": [
                {"dev_type": dev, "param_type": pid, "param_value": value}
                for dev, params in {255: station, **(blocks or {})}.items()
                for pid, value in params.items()
            ]
        }
    )
    return st._state(dump)


def config_of(station: dict[int, str], **kwargs: Any) -> StationConfig:
    return build_station_config(state_of(station, **kwargs))


def names(config: StationConfig) -> list[tuple[GuardMode | int, str]]:
    return [(m.code, m.name) for m in config.modes]


# ── modes ────────────────────────────────────────────────────────────────────


def test_without_a_mode_list_the_station_has_the_built_in_modes() -> None:
    config = config_of({1224: "0"})
    assert names(config) == [
        (GuardMode.HOME, "Home"),
        (GuardMode.AWAY, "Away"),
        (GuardMode.DISARMED, "Disarmed"),
    ]
    assert config.settable_modes == (GuardMode.HOME, GuardMode.AWAY, GuardMode.DISARMED)
    assert config.sources["modes"] is ValueSource.APP_DEFAULT
    assert not config.is_defined(GuardMode.CUSTOM_2)


def test_a_custom_mode_is_defined_only_when_the_mode_list_names_it() -> None:
    """The cloud's 1256 lists Home, Away and Custom 1 with the user's title: Custom 2 and
    3 do not exist, and Custom 1 is set through 1224 like a built-in mode."""
    modes = mode_list((1, "Home", 1), (0, "Away", 0), (3, "Night watch", 6))
    config = config_of({1224: "1"}, cloud={1256: modes})

    assert names(config) == [
        (GuardMode.HOME, "Home"),
        (GuardMode.AWAY, "Away"),
        (GuardMode.CUSTOM_1, "Night watch"),
        (GuardMode.DISARMED, "Disarmed"),
    ]
    custom = config.mode(GuardMode.CUSTOM_1)
    assert custom is not None
    assert (custom.icon, custom.custom) == (6, True)
    home = config.mode(GuardMode.HOME)
    assert home is not None
    assert (home.icon, home.custom) == (1, False)
    assert config.mode(GuardMode.DISARMED) is not None
    assert config.mode(GuardMode.DISARMED).icon is None  # type: ignore[union-attr]
    assert GuardMode.CUSTOM_1 in config.settable_modes
    assert not config.is_defined(GuardMode.CUSTOM_2)
    assert not config.is_defined(GuardMode.CUSTOM_3)
    assert config.sources["modes"] is ValueSource.CLOUD
    assert config.mode_name(GuardMode.CUSTOM_1) == "Night watch"
    assert config.mode_name(GuardMode.CUSTOM_2) == "Custom 2"


def test_built_in_titles_are_fixed_and_an_untitled_custom_mode_gets_its_label() -> None:
    modes = mode_list((1, "Casa", 1), (4, "  ", 2))
    config = config_of({1224: "0", 1256: modes})
    assert names(config)[0] == (GuardMode.HOME, "Home")
    assert (GuardMode.CUSTOM_2, "Custom 2") in names(config)
    assert config.sources["modes"] is ValueSource.P2P


def test_a_custom_mode_the_station_is_in_is_defined_without_a_list() -> None:
    config = config_of({1224: "5"})
    assert config.mode_name(GuardMode.CUSTOM_3) == "Custom 3"
    assert GuardMode.CUSTOM_3 in config.settable_modes


@pytest.mark.parametrize(
    ("params", "defined"),
    [
        ({1224: "0"}, False),
        ({1224: "0", 1254: schedule()}, False),  # a schedule without a slot
        ({1224: "0", 1254: schedule((1, 8, 17, 0))}, True),
        ({1224: "2", 1151: "1"}, True),  # Schedule selected
    ],
)
def test_schedule_is_defined_by_a_slot_or_the_selection(
    params: dict[int, str], defined: bool
) -> None:
    config = config_of(params)
    assert config.is_defined(GuardMode.SCHEDULE) is defined
    assert (GuardMode.SCHEDULE in config.settable_modes) is defined


def test_geofencing_and_off_are_defined_only_while_reported_and_off_is_never_settable() -> None:
    assert not config_of({1224: "0"}).is_defined(GuardMode.GEOFENCE)
    assert not config_of({1224: "0"}).is_defined(GuardMode.OFF)

    geofence = config_of({1224: "47", 1151: "1"})
    assert geofence.mode_name(GuardMode.GEOFENCE) == "Geofencing"
    assert GuardMode.GEOFENCE in geofence.settable_modes

    off = config_of({1224: "6"})
    assert off.is_defined(GuardMode.OFF)
    assert GuardMode.OFF not in off.settable_modes


def test_modes_follow_the_app_order() -> None:
    modes = mode_list((5, "C", 1), (3, "A", 1), (4, "B", 1))
    config = config_of({1224: "47", 1151: "6", 1256: modes, 1254: schedule((0, 1, 2, 1))})
    assert [m.code for m in config.modes] == list(MODE_ORDER)


def test_an_unknown_reported_code_is_listed_by_number_and_not_settable() -> None:
    config = config_of({1224: "9"})
    assert (9, "Mode 9") in names(config)
    assert 9 not in config.settable_modes


def test_an_undecodable_mode_list_leaves_the_built_ins_and_says_why() -> None:
    config = config_of({1224: "0", 1256: "not base64!"})
    assert [m.code for m in config.modes] == [GuardMode.HOME, GuardMode.AWAY, GuardMode.DISARMED]
    assert "1256" in config.unreadable["modes"]


def test_every_guard_mode_has_a_sentence_case_label() -> None:
    assert set(GUARD_MODE_LABELS) == set(GuardMode)
    assert GuardMode.GEOFENCE.label == "Geofencing"
    assert GuardMode.CUSTOM_1.label == "Custom 1"
    assert guard_mode_label(63) == "Disarmed"
    assert guard_mode_label(9) == "Mode 9"


# ── guard-mode writes ────────────────────────────────────────────────────────


@pytest.fixture
async def fake() -> AsyncIterator[FakeStation]:
    station = FakeStation()
    station.params[255][1224] = "63"
    await station.start()
    yield station
    station.stop()


@pytest.fixture
async def station(fake: FakeStation) -> AsyncIterator[Station]:
    async def credentials(*, refresh: bool, cipher_id: int | None = None) -> P2PCredentials:
        return P2PCredentials(SYNTHETIC.account_id, "user", fake.ecc_private_key_hex)

    session = StationSession(
        SYNTHETIC.station_sn, credentials, host="127.0.0.1", port=fake.discovery_port
    )
    st = Station(STATION, session, sub_devices=[CAMERA])
    yield st
    await st.async_close()


@pytest.mark.parametrize("mode", [GuardMode.CUSTOM_1, GuardMode.CUSTOM_2, GuardMode.CUSTOM_3])
async def test_a_custom_mode_is_set_through_1224(
    station: Station, fake: FakeStation, mode: GuardMode
) -> None:
    assert await station.async_set_guard_mode(mode.name.lower()) == mode
    assert fake.guard_mode == mode
