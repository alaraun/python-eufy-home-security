"""The T8010's native 1024 request is separate from newer media commands."""

from typing import Any
from unittest.mock import patch

import pytest
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from eufy_home_security.exceptions import UnsupportedError
from eufy_home_security.p2p.session import (
    StationSession,
    _homebase2_private_key,
    _homebase2_recording_frame,
)
from eufy_home_security.p2p.xzyh import MAGIC

PATH = "/media/mmcblk0p1/Camera05/20261024084022.dat"
STATIC_KEY = b"0123456789abcdef"  # synthetic, not a station key
ACCOUNT = "synthetic_owner_account"


def test_native_homebase2_recording_wire_format() -> None:
    frame = _homebase2_recording_frame(PATH, ACCOUNT, 5, STATIC_KEY)
    assert frame.startswith(MAGIC)
    offset = len(MAGIC)
    assert frame[offset : offset + 2] == (1024).to_bytes(2, "little")
    assert frame[offset + 2 : offset + 6] == (272).to_bytes(4, "little")
    assert frame[offset + 6 : offset + 12] == bytes([1, 0, 5, 1, 0, 0])
    ciphertext = frame[offset + 12 :]
    assert len(ciphertext) == 272
    # HomeBase 2 mandates ECB for this native P2P command.
    cipher = Cipher(
        algorithms.AES(STATIC_KEY),
        modes.ECB(),  # noqa: S305 - required by the device protocol
    )
    plaintext = cipher.decryptor().update(ciphertext)
    assert plaintext[:5] == bytes(5)
    assert plaintext[5:133].rstrip(b"\0") == PATH.encode()
    assert plaintext[133:261].rstrip(b"\0") == ACCOUNT.encode()
    assert plaintext[261:] == bytes(11)


@pytest.mark.parametrize("path", ["/zx/test.zxvideo", "/media/mmcblk0p1/Camera05/../x.dat"])
def test_native_refuses_non_homebase2_paths(path: str) -> None:
    with pytest.raises(ValueError, match="not a validated HomeBase 2 recording path"):
        _homebase2_recording_frame(path, ACCOUNT, 5, STATIC_KEY)


@pytest.mark.parametrize("channel", [-1, 256])
def test_native_refuses_bad_channels(channel: int) -> None:
    with pytest.raises(ValueError, match="invalid recording camera channel"):
        _homebase2_recording_frame(PATH, ACCOUNT, channel, STATIC_KEY)


def test_existing_ecc_owner_key_is_usable() -> None:
    key = _homebase2_private_key("1" * 64)
    assert isinstance(key, ec.EllipticCurvePrivateKey)


@pytest.mark.asyncio
async def test_t8010_dat_uses_native_route() -> None:
    session = object.__new__(StationSession)
    session.serial = "T8010SYNTHETIC"
    sentinel = object()

    async def fake_open(self: StationSession, *args: Any, **kwargs: Any) -> object:
        assert args[0] == 1024
        assert kwargs["native_recording_path"] == PATH
        return sentinel

    with patch.object(StationSession, "_open_media", fake_open):
        assert await session.async_open_recording(PATH, 5) is sentinel


@pytest.mark.asyncio
async def test_newer_station_keeps_existing_recording_route() -> None:
    session = object.__new__(StationSession)
    session.serial = "T8030SYNTHETIC"
    sentinel = object()

    async def fake_open(self: StationSession, *args: Any, **kwargs: Any) -> object:
        assert args[0] == 1025
        assert "native_recording_path" not in kwargs
        return sentinel

    with patch.object(StationSession, "_open_media", fake_open):
        assert await session.async_open_recording("/zx/test.zxvideo", 5) is sentinel


@pytest.mark.asyncio
async def test_newer_station_rejects_homebase2_dat() -> None:
    session = object.__new__(StationSession)
    session.serial = "T8030SYNTHETIC"
    with pytest.raises(UnsupportedError):
        await session.async_open_recording(PATH, 5)


def test_native_command_accepts_doorbell_recording_path() -> None:
    doorbell_path = "/media/mmcblk0p1/Camera05/A123_20261024084022.dat"
    frame = _homebase2_recording_frame(doorbell_path, ACCOUNT, 5, STATIC_KEY)
    assert frame.startswith(MAGIC)
    assert frame[len(MAGIC) : len(MAGIC) + 2] == (1024).to_bytes(2, "little")
