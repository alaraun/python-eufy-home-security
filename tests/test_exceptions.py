"""``exceptions.py``: the serials an error names, on every error class."""

from __future__ import annotations

import ast
from pathlib import Path

import pytest

from eufy_home_security.exceptions import (
    CipherUnavailableError,
    CloudApiError,
    CommandNotAppliedError,
    DeviceBusyError,
    DeviceTimeoutError,
    EmptyResponseError,
    EufySecurityError,
    PtzActionUnsupportedError,
    RateLimitedError,
    RecordNotFoundError,
    RefreshCooldownError,
    UnsupportedError,
)
from eufy_home_security.testing import SYNTHETIC

SN = SYNTHETIC.camera_sn
SRC = Path(__file__).resolve().parent.parent / "src" / "eufy_home_security"
#: What a message names a device with: a redacted serial, or a station's log name.
NAMING = ("redact_serial(", "self._log_name")


class _InUseError(UnsupportedError):
    """A subclass with an initialiser of its own that names no device."""

    def __init__(self) -> None:
        super().__init__("in use")


def test_an_error_names_no_device_by_default() -> None:
    assert EufySecurityError("x").device_sn is None
    assert CloudApiError(1, "x").device_sn is None
    assert _InUseError().device_sn is None


@pytest.mark.parametrize(
    "err",
    [
        UnsupportedError("m", device_sn=SN),
        PtzActionUnsupportedError("m", action="set_preset_positions", device_sn=SN),
        RecordNotFoundError("m", device_sn=SN),
        DeviceBusyError("m", device_sn=SN),
        DeviceTimeoutError("m", device_sn=SN),
        CloudApiError(0, "m", device_sn=SN),
        EmptyResponseError(0, "m", device_sn=SN),
        CipherUnavailableError(
            "m", cipher_id=1, owner_source="own user id", retry_after=1.0, device_sn=SN
        ),
        RateLimitedError("m", device_sn=SN),
        RefreshCooldownError("m", retry_after=1.0, device_sn=SN),
        CommandNotAppliedError(1, "m", device_sn=SN),
    ],
    ids=lambda e: type(e).__name__,
)
def test_an_error_carries_the_serial_it_names(err: EufySecurityError) -> None:
    assert err.device_sn == SN


def test_an_error_lists_every_device_it_names() -> None:
    other = SYNTHETIC.station_sn
    assert EufySecurityError("x").device_sns == ()
    assert UnsupportedError("m", device_sn=SN).device_sns == (SN,)
    listed = CommandNotAppliedError(1, "m", device_sns=[SN, other, SN])
    assert (listed.device_sn, listed.device_sns) == (SN, (SN, other))
    first = UnsupportedError("m", device_sn=other, device_sns=(SN, other))
    assert (first.device_sn, first.device_sns) == (other, (other, SN))


def _unnamed_sites() -> list[str]:
    """Library errors built with a message naming a device but no ``device_sn``."""
    out = []
    for path in sorted(SRC.rglob("*.py")):
        text = path.read_text(encoding="utf-8")
        for node in ast.walk(ast.parse(text)):
            if not (isinstance(node, ast.Call) and isinstance(node.func, ast.Name)):
                continue
            if not node.func.id.endswith("Error") or node.func.id == "ValueError":
                continue
            source = ast.get_source_segment(text, node) or ""
            named = any(n in source for n in NAMING)
            if named and not any(k.arg == "device_sn" for k in node.keywords):
                out.append(f"{path.relative_to(SRC)}:{node.lineno}")
    return out


def test_every_error_naming_a_device_carries_its_serial() -> None:
    assert _unnamed_sites() == []
