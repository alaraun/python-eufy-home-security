"""Lock frame layers: the TLV body, the cm2 frame (1940 route) and the Anker cm frame (1930)."""

from __future__ import annotations

import pytest

from eufy_home_security.exceptions import ProtocolError
from eufy_home_security.lock_commands import frames


def test_tlv_numbers_tags_from_a1_with_a_length_byte() -> None:
    assert frames.tlv([b"\x01\x02", b"", b"xyz"]) == bytes.fromhex("a1020102a200a30378797a")


def test_tlv_refuses_a_value_longer_than_its_length_byte() -> None:
    with pytest.raises(ValueError, match="255"):
        frames.tlv([bytes(256)])
    assert frames.tlv([bytes(255)])[:2] == b"\xa1\xff"


def test_xor8_folds_every_byte() -> None:
    assert frames.xor8(b"") == 0
    assert frames.xor8(bytes([0xFF, 0x09, 0x0F])) == 0xF9


def test_cm2_frame_layout() -> None:
    body = bytes(range(16))
    frame = frames.cm2_frame(body, command=0x23, function_type=2, version=3, encrypted=True)
    head = bytes.fromhex("ff09") + (10 + 16).to_bytes(2, "little") + bytes([3, 0, 2, 0x40, 0x23])
    assert frame[:9] == head
    assert frame[9:-1] == body
    assert frame[-1] == frames.xor8(frame[:-1])
    plain = frames.cm2_frame(b"", command=0x7FF, function_type=1, version=4, encrypted=False)
    assert plain == bytes.fromhex("ff090a00040001 07ff".replace(" ", "")) + bytes(
        [frames.xor8(bytes.fromhex("ff090a0004000107ff"))]
    )


def test_cm2_frame_refuses_a_command_code_over_11_bits() -> None:
    with pytest.raises(ValueError, match="command"):
        frames.cm2_frame(b"", command=0x800, function_type=2, version=3, encrypted=True)
    frames.cm2_frame(b"", command=0x7FF, function_type=2, version=3, encrypted=True)


def test_frames_refuse_a_total_length_over_16_bits() -> None:
    fits = bytes(0xFFFF - 10)  # head 9 + body + check byte == 0xFFFF
    assert (
        len(frames.cm2_frame(fits, command=1, function_type=2, version=3, encrypted=False))
        == 0xFFFF
    )
    with pytest.raises(ValueError, match="65535"):
        frames.cm2_frame(fits + b"\0", command=1, function_type=2, version=3, encrypted=False)


def test_parse_cm2_frame_reads_an_11_bit_command() -> None:
    frame = frames.cm2_frame(b"\1", command=0x523, function_type=2, version=3, encrypted=False)
    assert frames.parse_cm2_frame(frame).command == 0x523


def test_cm2_frame_round_trip() -> None:
    frame = frames.cm2_frame(b"abc", command=35, function_type=2, version=3, encrypted=True)
    parsed = frames.parse_cm2_frame(frame)
    assert parsed == frames.Cm2Frame(
        version=3, slave_id=0, function_type=2, command=35, encrypted=True, body=b"abc"
    )
    plain = frames.parse_cm2_frame(
        frames.cm2_frame(b"", command=74, function_type=2, version=3, encrypted=False, slave_id=7)
    )
    assert (plain.encrypted, plain.slave_id, plain.command, plain.body) == (False, 7, 74, b"")


@pytest.mark.parametrize(
    ("mutate", "reason"),
    [
        (lambda f: b"\xff\x08" + f[2:], "start"),
        (lambda f: f[:-1] + bytes([f[-1] ^ 1]), "check"),
        (lambda f: f[:4], "short"),
        (lambda f: f[:2] + (len(f) + 1).to_bytes(2, "little") + f[4:], "length"),
        (lambda f: f[:7] + bytes([f[7] | 0x80]) + f[8:], "multi"),
    ],
)
def test_parse_cm2_frame_refuses_malformed_input(mutate: object, reason: str) -> None:
    frame = frames.cm2_frame(b"abcd", command=35, function_type=2, version=3, encrypted=True)
    bad = mutate(frame)  # type: ignore[operator]
    if reason != "check":  # keep the check byte right so the named defect is the one hit
        bad = bad[:-1] + bytes([frames.xor8(bad[:-1])])
    with pytest.raises(ProtocolError, match=reason):
        frames.parse_cm2_frame(bad)


def test_anker_frame_layout() -> None:
    key = bytes(range(5))
    data = bytes(range(32))
    frame = frames.anker_frame(data, command=8, version=18, key_field=key)
    total = 11 + len(key) + len(data)
    assert frame[:10] == bytes.fromhex("ff09") + total.to_bytes(2, "little") + bytes(
        [18, 0xFF, 8, 0xC0, 0xA0, len(key)]
    )
    assert frame[10:15] == key
    assert frame[15:-1] == data
    assert frame[-1] == frames.xor8(frame[:-1])
    assert len(frame) == total


def test_anker_frame_refuses_a_key_field_over_255_bytes() -> None:
    with pytest.raises(ValueError, match="255"):
        frames.anker_frame(b"", command=8, version=18, key_field=bytes(256))


def test_parse_anker_frame_reads_a_single_packet_answer() -> None:
    # an answer carries no index or key field: the body starts after the package flag
    raw = bytes.fromhex("ff09") + (9 + 3).to_bytes(2, "little") + bytes([18, 0xFF, 8, 0xC0])
    raw += b"\x10\x20\x30"
    raw += bytes([frames.xor8(raw)])
    assert frames.parse_anker_frame(raw) == frames.AnkerFrame(
        version=18, device_type=0xFF, command=8, body=b"\x10\x20\x30"
    )


@pytest.mark.parametrize(
    ("raw", "reason"),
    [
        (bytes.fromhex("ff080c0012ff08c0aa"), "start"),
        (bytes.fromhex("ff09"), "short"),
        (bytes.fromhex("ff090c0012ff08c1aabbcc"), "multi"),
        (bytes.fromhex("ff090c0012ff08c3aabbcc"), "multi"),
    ],
)
def test_parse_anker_frame_refuses_malformed_input(raw: bytes, reason: str) -> None:
    raw += bytes([frames.xor8(raw)])
    with pytest.raises(ProtocolError, match=reason):
        frames.parse_anker_frame(raw)


def test_parse_anker_frame_ignores_the_length_field_as_the_app_does() -> None:
    raw = bytes.fromhex("ff09ffff12ff08c0aabbcc")
    assert frames.parse_anker_frame(raw + bytes([frames.xor8(raw)])).body == b"\xaa\xbb\xcc"


def test_parse_anker_frame_refuses_a_bad_check_byte() -> None:
    raw = bytes.fromhex("ff090c0012ff08c0aabbcc")
    with pytest.raises(ProtocolError, match="check"):
        frames.parse_anker_frame(raw + bytes([frames.xor8(raw) ^ 1]))
