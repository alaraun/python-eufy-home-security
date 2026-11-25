"""The generated lock route table (devices/_lock_routes_data.py) read through the rule."""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

import pytest

from eufy_home_security.devices._lock_routes_data import LOCK_ROUTES
from eufy_home_security.devices.lock_routes import MQTT_RULES, P2P_FORMS, LockForm, lock_route

ROOT = Path(__file__).resolve().parents[2]
ROUTES_INPUT = ROOT / ".work" / "tools" / "data" / "lock_routes.json"
TAIL = "P2000012345"  # synthetic serial tail; index 6 is "0"


@pytest.mark.parametrize(
    ("serial", "behind", "kwargs", "form"),
    [
        ("T8502" + TAIL, True, {}, LockForm.P2P_1940),
        (
            "T8502" + TAIL,
            True,
            {"main_sw_version": "2.2.0.0", "sec_sw_version": "0.3.0.0"},
            LockForm.P2P_1940_HKDF,
        ),
        ("T8520" + TAIL, True, {}, LockForm.P2P_1961),
        ("T85200" + "9" + TAIL[2:], True, {}, LockForm.P2P_1940),
        ("T85200" + "8" + TAIL[2:], True, {}, LockForm.P2P_1940),
        ("T8530" + TAIL, False, {}, LockForm.P2P_1961_PLAIN),
        ("T8501" + TAIL, True, {}, LockForm.P2P_1930),
        ("T8503" + TAIL, True, {"params": {6610: "1"}}, LockForm.P2P_1930_ECDH),
        ("T8531" + TAIL, True, {}, LockForm.P2P_1940),
        ("T8531" + TAIL, False, {}, LockForm.MQTT),
        ("T85D0" + TAIL, True, {}, LockForm.MQTT),
        ("T8500" + TAIL, True, {}, LockForm.P2P_1911),
        ("T85060" + "8" + TAIL[2:], True, {}, LockForm.MQTT),
        ("T8592" + TAIL, True, {}, None),
    ],
)
def test_generated_routes(
    serial: str, behind: bool, kwargs: dict[str, object], form: LockForm | None
) -> None:
    assert lock_route(serial, behind_station=behind, **kwargs) is form  # type: ignore[arg-type]


@pytest.mark.skipif(not ROUTES_INPUT.is_file(), reason="needs the private lock route input")
def test_the_table_is_what_the_generator_writes() -> None:
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "gen_lock_routes.py"), "--check"],
        capture_output=True,
        text=True,
        check=False,
        timeout=120,
    )
    assert result.returncode == 0, result.stdout + result.stderr


def test_the_rule_names_every_form_and_mqtt_rule_in_the_table() -> None:
    assert LOCK_ROUTES
    forms = {row[1] for rows in LOCK_ROUTES.values() for row in rows} - {None}
    assert forms <= P2P_FORMS
    assert {row[2] for rows in LOCK_ROUTES.values() for row in rows} <= MQTT_RULES
