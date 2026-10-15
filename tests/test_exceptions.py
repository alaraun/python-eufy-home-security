"""``exceptions.py``: the serial an error names, on every error class."""

from __future__ import annotations

import pytest

from eufy_home_security.exceptions import (
    CipherUnavailableError,
    CloudApiError,
    CommandNotAppliedError,
    DeviceBusyError,
    DeviceTimeoutError,
    EmptyResponseError,
    EufySecurityError,
    RateLimitedError,
    RecordNotFoundError,
    RefreshCooldownError,
    UnsupportedError,
)
from eufy_home_security.testing import SYNTHETIC

SN = SYNTHETIC.camera_sn


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
