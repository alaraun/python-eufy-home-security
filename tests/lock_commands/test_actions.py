"""Shared lock command parts: the serial IV, AES-CBC and hex text."""

from __future__ import annotations

import pytest

from eufy_home_security.exceptions import ProtocolError
from eufy_home_security.lock_commands import actions


def test_serial_iv_zero_pads_the_serial_to_16_bytes() -> None:
    assert actions.serial_iv("T8502") == b"T8502" + bytes(11)
    assert actions.serial_iv("T8502P2000012345") == b"T8502P2000012345"


@pytest.mark.parametrize("serial", ["", "T8502P20000123456"])
def test_serial_iv_needs_1_to_16_bytes(serial: str) -> None:
    with pytest.raises(ValueError, match=r"1\.\.16"):
        actions.serial_iv(serial)


def test_cbc_round_trip_and_errors() -> None:
    key, iv = bytes(range(16)), bytes(16)
    sealed = actions.cbc_encrypt(b"abc", key, iv)
    assert len(sealed) == 16
    assert actions.cbc_decrypt(sealed, key, iv) == b"abc"
    with pytest.raises(ProtocolError, match="whole AES blocks"):
        actions.cbc_decrypt(sealed[:15], key, iv)
    with pytest.raises(ProtocolError, match="whole AES blocks"):
        actions.cbc_decrypt(b"", key, iv)


def test_hex_bytes_left_pads_an_odd_length() -> None:
    assert actions.hex_bytes("abc", "x") == bytes.fromhex("0abc")
    with pytest.raises(ValueError, match="x is not hex"):
        actions.hex_bytes("zz", "x")
