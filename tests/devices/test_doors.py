"""Lock states and garage doors as the eufy app reads them (``devices.locks``,
``devices.garage``), and the capabilities the model files grade from them."""

from __future__ import annotations

import json
import logging
from collections.abc import Iterator
from pathlib import Path

import pytest

from eufy_home_security.devices import capabilities, model_settings
from eufy_home_security.devices.capabilities import Capability, profile_for_serial
from eufy_home_security.devices.garage import (
    COMMAND_TYPES,
    DOORS,
    GarageAction,
    GarageCommandType,
    GarageDoorState,
    bound,
    calibrated,
    command_body,
    door_state,
    garage_evidence,
    notify_doors,
    parse_bits,
    state_notify_bits,
)
from eufy_home_security.devices.locks import (
    CODE_STATES,
    LOCK_OFFLINE_EVENT,
    PUSH_STATES,
    LockState,
    lock_evidence,
    state_of_code,
)
from eufy_home_security.devices.model_settings import GarageParams
from eufy_home_security.devices.support import Support

ENTRY = {"access": "ro", "kind": "bool", "read": None, "section": "other", "role": "status"}
LOCK = {"param": 1912, "contexts": {"standalone": 6000}}
GARAGE = {"state": 7500, "motors": 7501, "sensors": 7502, "control": {"cmd": 1700, "subCmd": 7500}}
PARAMS = GarageParams(7500, 7501, 7502, 1700, 7500)

OPEN, CLOSED, UNKNOWN = GarageDoorState.OPEN, GarageDoorState.CLOSED, GarageDoorState.UNKNOWN


@pytest.mark.parametrize(
    ("bits", "door_1", "door_2"),
    [
        (0, UNKNOWN, UNKNOWN),
        (1, OPEN, UNKNOWN),
        (2, CLOSED, UNKNOWN),
        (4, UNKNOWN, OPEN),  # door 2 opens on bit 2, as the handler and the notify read it
        (8, UNKNOWN, CLOSED),
        (0x0A, CLOSED, CLOSED),
        (0x05, OPEN, OPEN),
        (0x11, UNKNOWN, UNKNOWN),  # the unknown bit wins over open
        (0x13, UNKNOWN, UNKNOWN),
        (0x2C, UNKNOWN, UNKNOWN),
        (0x03, OPEN, UNKNOWN),  # open before closed
        (0x0C, UNKNOWN, OPEN),
    ],
)
def test_the_state_bits_give_each_door_its_state(
    bits: int, door_1: GarageDoorState, door_2: GarageDoorState
) -> None:
    assert (door_state(bits, 1), door_state(bits, 2)) == (door_1, door_2)


@pytest.mark.parametrize(
    ("bits", "bound_1", "bound_2", "calibrated_1", "calibrated_2"),
    [
        (0, False, False, False, False),
        (1, True, False, False, False),
        (2, False, True, False, False),
        (3, True, True, False, False),
        (0x05, True, False, True, False),
        (0x0A, False, True, False, True),
        (0x0C, False, False, True, True),
    ],
)
def test_the_binding_bits_name_bound_and_calibrated_doors(
    bits: int, bound_1: bool, bound_2: bool, calibrated_1: bool, calibrated_2: bool
) -> None:
    assert (bound(bits, 1), bound(bits, 2)) == (bound_1, bound_2)
    assert (calibrated(bits, 1), calibrated(bits, 2)) == (calibrated_1, calibrated_2)


@pytest.mark.parametrize(
    ("raw", "bits"),
    [("5", 5), (" 5 ", 5), (5, 5), ("0", 0), ("-1", None), ("x", None), (None, None), (True, None)],
)
def test_reported_bits_are_non_negative_integers(raw: object, bits: int | None) -> None:
    assert parse_bits(raw) == bits


def test_each_door_and_action_has_the_apps_command_type() -> None:
    assert {(d, a): int(t) for (d, a), t in COMMAND_TYPES.items()} == {
        (1, GarageAction.CLOSE): 0,
        (1, GarageAction.OPEN): 1,
        (2, GarageAction.CLOSE): 2,
        (2, GarageAction.OPEN): 3,
        (1, GarageAction.OPERATE): 4,
        (2, GarageAction.OPERATE): 5,
    }
    assert set(COMMAND_TYPES.values()) == set(GarageCommandType)
    assert DOORS == (1, 2)


def test_the_command_body_is_the_apps() -> None:
    assert command_body(2, GarageAction.OPEN, "Nick") == {
        "type": 3,
        "user_name": "Nick",
        "source": 0,
        "disable_push": 0,
        "cmdType": 0,
    }
    assert type(command_body(1, GarageAction.CLOSE, "")["type"]) is int


@pytest.mark.parametrize(
    ("obj", "bits"),
    [
        ({"cmd": 7500, "payload": {"door_id": 1, "type": 9, "notify_tag": "x"}}, 9),
        ({"cmd": "7500", "payload": {"type": "6"}}, 6),
        ({"cmd": 7501, "payload": {"type": 9}}, None),
        ({"cmd": 7500, "payload": {"type": -1}}, None),
        ({"cmd": 7500, "payload": {}}, None),
        ({"cmd": 7500, "payload": "9"}, None),
        ({"cmd": 7500}, None),
    ],
)
def test_a_door_state_notify_carries_the_state_bits(
    obj: dict[str, object], bits: int | None
) -> None:
    assert state_notify_bits(obj, PARAMS) == bits


@pytest.mark.parametrize(
    ("payload", "doors"),
    [
        ({"door_id": 1, "type": 9}, (1,)),
        ({"door_id": "2", "type": 9}, (2,)),
        ({"door_id": 3, "type": 9}, (1, 2)),
        ({"door_id": "x", "type": 9}, (1, 2)),
        ({"type": 9}, (1, 2)),
        ("9", (1, 2)),
    ],
)
def test_a_door_state_notify_reports_on_its_door_or_both(
    payload: object, doors: tuple[int, ...]
) -> None:
    assert notify_doors({"cmd": 7500, "payload": payload}) == doors


@pytest.mark.parametrize(
    ("raw", "state"),
    [
        ("4", LockState.LOCKED),
        (4, LockState.LOCKED),
        ("3", LockState.UNLOCKED),
        ("7", LockState.LOCKING),
        ("6", LockState.UNLOCKING),
        ("0", LockState.INITIAL),
        ("1", LockState.UNCALIBRATED),
        ("2", LockState.CALIBRATING),
        ("5", LockState.INTERMEDIATE),
        ("8", LockState.PASSAGE_MODE),
        ("9", LockState.PRIVACY_MODE),
        ("10", LockState.UNKNOWN),  # a code the app names no state for
        ("-1", LockState.UNKNOWN),
        (" 4 ", LockState.LOCKED),
        (None, LockState.UNKNOWN),  # never reported
        ("", LockState.UNKNOWN),
        ("abc", LockState.UNKNOWN),
        (True, LockState.UNKNOWN),
    ],
)
def test_a_lock_state_code_reads_as_the_apps_card(raw: object, state: LockState) -> None:
    assert state_of_code(raw) is state


def test_the_code_table_names_codes_0_to_9_each_its_own_state() -> None:
    assert sorted(CODE_STATES) == list(range(10))
    assert len(set(CODE_STATES.values())) == 10
    assert LockState.JAMMED not in CODE_STATES.values()  # set by a push only


@pytest.mark.parametrize(
    ("event_type", "state"),
    [
        (257, LockState.UNLOCKED),
        (261, LockState.UNLOCKED),
        (269, LockState.UNLOCKED),
        (270, LockState.UNLOCKED),
        (530, LockState.UNLOCKED),
        (532, LockState.UNLOCKED),
        (538, LockState.UNLOCKED),
        (549, LockState.UNLOCKED),
        (550, LockState.UNLOCKED),
        (562, LockState.UNLOCKED),
        (262, LockState.LOCKED),
        (268, LockState.LOCKED),
        (271, LockState.LOCKED),
        (531, LockState.LOCKED),
        (533, LockState.LOCKED),
        (551, LockState.LOCKED),
        (552, LockState.LOCKED),
        (561, LockState.LOCKED),
        (517, LockState.JAMMED),
        (519, LockState.JAMMED),
        (LOCK_OFFLINE_EVENT, LockState.UNKNOWN),
    ],
)
def test_a_lock_push_sets_the_state_the_app_sets(event_type: int, state: LockState) -> None:
    assert PUSH_STATES[event_type] is state


@pytest.mark.parametrize("event_type", [513, 518, 520, 3103, 544])
def test_a_lock_push_of_another_kind_sets_no_state(event_type: int) -> None:
    assert event_type not in PUSH_STATES


def _clear() -> None:
    model_settings._load.cache_clear()
    model_settings._resolved.cache_clear()
    model_settings.bundled_codes.cache_clear()
    capabilities._GENERATED_PROFILES.clear()


@pytest.fixture
def data_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """Model files for a lock (T8502), a garage camera (T8453) and a camera (T8160)."""
    monkeypatch.setattr(model_settings, "_root", lambda: tmp_path)
    codes = ["T8160", "T8453", "T8502"]
    (tmp_path / "INDEX.json").write_text(
        json.dumps({"schema_version": 3, "codes": codes}), encoding="utf-8"
    )
    blocks: dict[str, dict[str, object]] = {"T8502": {"lock": LOCK}, "T8453": {"garage": GARAGE}}
    for code in codes:
        doc = {"schema_version": 3, "product_code": code, "settings": {"mode": ENTRY}}
        doc.update(blocks.get(code, {}))
        (tmp_path / f"{code}.json").write_text(json.dumps(doc), encoding="utf-8")
    _clear()
    yield tmp_path
    _clear()


@pytest.mark.usefixtures("data_root")
def test_a_models_file_grades_its_lock_and_garage_doors() -> None:
    lock = profile_for_serial("T8502P0000000001")
    garage = profile_for_serial("T8453P0000000001")
    camera = profile_for_serial("T8160P0000000001")
    assert lock is not None
    assert garage is not None
    assert camera is not None
    assert lock.support(Capability.LOCK) is Support.DECLARED
    assert lock.support(Capability.GARAGE_DOOR) is Support.UNKNOWN
    assert garage.support(Capability.GARAGE_DOOR) is Support.DECLARED
    assert garage.support(Capability.LOCK) is Support.UNKNOWN
    assert camera.support(Capability.LOCK) is Support.UNKNOWN
    assert camera.support(Capability.GARAGE_DOOR) is Support.UNKNOWN
    assert lock_evidence("T8502") is lock.capabilities[Capability.LOCK]
    assert garage_evidence("T8453") is garage.capabilities[Capability.GARAGE_DOOR]
    assert lock_evidence("T8160") is None
    assert garage_evidence(None) is None


def test_a_malformed_file_grades_neither(data_root: Path, caplog: pytest.LogCaptureFixture) -> None:
    (data_root / "T8502.json").write_text("{", encoding="utf-8")
    with caplog.at_level(logging.WARNING, logger=capabilities.__name__):
        profile = profile_for_serial("T8502P0000000001")
    assert profile is not None
    assert profile.support(Capability.LOCK) is Support.UNKNOWN
    assert [r.getMessage() for r in caplog.records if r.name == capabilities.__name__] == [
        "T8502: no lock or garage grade: T8502.json: Expecting property name enclosed in "
        "double quotes: line 1 column 2 (char 1)"
    ]
