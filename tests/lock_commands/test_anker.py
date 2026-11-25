"""The 1961 lock command (ECIES-wrapped key or plain JSON) and the 1930 cm frame."""

from __future__ import annotations

import base64
import json

import pytest
from cryptography.hazmat.primitives import padding, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from eufy_home_security.exceptions import LockReplyMismatchError, ProtocolError
from eufy_home_security.lock_commands import LockAction, LockReply, LockResult, anker, frames
from eufy_home_security.p2p import crypto
from eufy_home_security.testing import SYNTHETIC

SERIAL_1961 = "T8520" + SYNTHETIC.station_sn[5:]
SERIAL_1930 = "T8501" + SYNTHETIC.station_sn[5:]
ADMIN = SYNTHETIC.account_id
NOW = 1_700_000_000
AES_KEY = bytes(range(0x10, 0x20))
LOCK_PRIV = ec.derive_private_key(0x5EED_0000_0000_0042, ec.SECP256R1())
_NUMBERS = LOCK_PRIV.public_key().public_numbers()
LOCK_PUB64 = _NUMBERS.x.to_bytes(32, "big") + _NUMBERS.y.to_bytes(32, "big")
EPHEMERAL = ec.derive_private_key(0xE9E9_0000_0000_0007, ec.SECP256R1())
ECIES_IV = bytes(range(16))
USER = anker.AnkerUser(admin_user_id=ADMIN, user_name="Synth User", short_user_id="0a1b")


def _iv(serial: str) -> bytes:
    return serial.encode().ljust(16, b"\0")


def _open(key: bytes, iv: bytes, blob: bytes) -> bytes:
    dec = Cipher(algorithms.AES(key), modes.CBC(iv)).decryptor()
    unpadder = padding.PKCS7(128).unpadder()
    return unpadder.update(dec.update(blob) + dec.finalize()) + unpadder.finalize()


def _seal(key: bytes, iv: bytes, data: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    enc = Cipher(algorithms.AES(key), modes.CBC(iv)).encryptor()
    return enc.update(padder.update(data) + padder.finalize()) + enc.finalize()


# ── lock public key ──────────────────────────────────────────────────────────


def test_lock_public_key_reads_64_bytes_x_then_y() -> None:
    key = anker.parse_lock_public_key(LOCK_PUB64)
    assert key.public_numbers() == LOCK_PRIV.public_key().public_numbers()


@pytest.mark.parametrize(
    ("raw", "match"),
    [
        (LOCK_PUB64[:63], "64 bytes"),
        (b"\x04" + LOCK_PUB64, "64 bytes"),
        (bytes(64), "not a P-256 point"),
    ],
)
def test_lock_public_key_refuses_anything_else(raw: bytes, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        anker.parse_lock_public_key(raw)


# ── Gson-shaped JSON ─────────────────────────────────────────────────────────


def test_gson_json_is_compact_keeps_unicode_and_escapes_html_characters() -> None:
    text = anker.gson_json({"a": "Jüri <&>='", "b": 1, "c": "\u2028"})
    assert text == '{"a":"Jüri \\u003c\\u0026\\u003e\\u003d\\u0027","b":1,"c":"\\u2028"}'
    assert json.loads(text) == {"a": "Jüri <&>='", "b": 1, "c": "\u2028"}


# ── 1961 ─────────────────────────────────────────────────────────────────────


def _request_1961(action: LockAction = LockAction.LOCK) -> anker.Anker1961Request:
    return anker.build_1961_request(
        SERIAL_1961,
        action,
        USER,
        seq_num=7,
        lock_public_key=LOCK_PUB64,
        aes_key=AES_KEY,
        ephemeral=EPHEMERAL,
        ecies_iv=ECIES_IV,
    )


def test_1961_payload_is_the_json_body_encrypted_under_the_random_key() -> None:
    request = _request_1961()
    assert request.command == 1961
    assert request.aes_key == AES_KEY
    assert isinstance(request.payload, str)
    plain = _open(AES_KEY, _iv(SERIAL_1961), base64.b64decode(request.payload))
    assert plain == (
        b'{"shortUserId":"0a1b","slOperation":1,"userId":"'
        + ADMIN.encode()
        + b'","userName":"Synth User","seq_num":7}'
    )


def test_1961_unlock_sends_operation_0() -> None:
    request = _request_1961(LockAction.UNLOCK)
    assert isinstance(request.payload, str)
    plain = _open(AES_KEY, _iv(SERIAL_1961), base64.b64decode(request.payload))
    assert json.loads(plain)["slOperation"] == 0


def test_1961_key_is_the_ecies_of_the_aes_keys_upper_case_hex_text() -> None:
    request = _request_1961()
    expected = crypto.ecies_encrypt(
        AES_KEY.hex().upper().encode(),
        LOCK_PRIV.public_key(),
        iv=ECIES_IV,
        ephemeral=EPHEMERAL,
    )
    assert request.key == expected.hex()
    assert len(expected) == 129
    assert crypto.ecies_decrypt(
        bytes.fromhex(str(request.key)), format(0x5EED_0000_0000_0042, "x")
    ) == (AES_KEY.hex().upper().encode())


def test_1961_payload_info_has_the_apps_field_order() -> None:
    request = _request_1961()
    info = request.payload_info(account_id="owner-id", channel=3)
    assert list(info) == ["key", "account_id", "cmd", "mChannel", "mValue3", "payload"]
    assert (info["account_id"], info["cmd"], info["mChannel"], info["mValue3"]) == (
        "owner-id",
        1961,
        3,
        0,
    )


def test_1961_random_parts_default_to_fresh_values() -> None:
    one = anker.build_1961_request(
        SERIAL_1961, LockAction.LOCK, USER, seq_num=1, lock_public_key=LOCK_PUB64
    )
    two = anker.build_1961_request(
        SERIAL_1961, LockAction.LOCK, USER, seq_num=1, lock_public_key=LOCK_PUB64
    )
    assert len(one.aes_key) == 16
    assert one.aes_key != two.aes_key
    assert one.key != two.key


def test_1961_refuses_a_wrong_sized_aes_key() -> None:
    with pytest.raises(ValueError, match="16"):
        anker.build_1961_request(
            SERIAL_1961, LockAction.LOCK, USER, seq_num=1, lock_public_key=LOCK_PUB64, aes_key=b"x"
        )


def test_1961_plain_form_sends_the_json_object_without_seq_or_key() -> None:
    request = anker.build_1961_plain_request(LockAction.UNLOCK, USER)
    assert request.key is None
    assert request.payload == {
        "shortUserId": "0a1b",
        "slOperation": 0,
        "userId": ADMIN,
        "userName": "Synth User",
    }
    info = request.payload_info(account_id="owner-id", channel=0)
    assert list(info) == ["account_id", "cmd", "mChannel", "mValue3", "payload"]


def test_1961_leaves_out_an_absent_short_user_id() -> None:
    user = anker.AnkerUser(admin_user_id=ADMIN, user_name="Synth User")
    assert user.short_user_id is None
    request = anker.build_1961_request(
        SERIAL_1961, LockAction.LOCK, user, seq_num=7, lock_public_key=LOCK_PUB64, aes_key=AES_KEY
    )
    assert isinstance(request.payload, str)
    plain = _open(AES_KEY, _iv(SERIAL_1961), base64.b64decode(request.payload))
    assert plain == (
        b'{"slOperation":1,"userId":"' + ADMIN.encode() + b'","userName":"Synth User","seq_num":7}'
    )
    assert anker.build_1961_plain_request(LockAction.LOCK, user).payload == {
        "slOperation": 1,
        "userId": ADMIN,
        "userName": "Synth User",
    }


def test_1961_keeps_an_empty_short_user_id() -> None:
    user = anker.AnkerUser(admin_user_id=ADMIN, user_name="x", short_user_id="")
    payload = anker.build_1961_plain_request(LockAction.LOCK, user).payload
    assert isinstance(payload, dict)
    assert payload["shortUserId"] == ""


@pytest.mark.parametrize(
    ("code", "result"),
    [(0, LockResult.ACCEPTED), (1, LockResult.REFUSED), (-1, LockResult.REFUSED)],
)
def test_1961_result_code(code: int, result: LockResult) -> None:
    assert anker.parse_1961_result(code) == LockReply(code, result)


# ── 1930 ─────────────────────────────────────────────────────────────────────


def test_1930_cm_body_layout() -> None:
    body = anker.cm_on_off_body(LockAction.LOCK, USER, timestamp=NOW)
    assert (
        body == bytes.fromhex("A1020a1b A20101 A30400F15365 A40A".replace(" ", "")) + b"Synth User"
    )
    unlock = anker.cm_on_off_body(LockAction.UNLOCK, USER, timestamp=NOW)
    assert unlock[4:7] == bytes.fromhex("A20100")


def test_1930_cm_body_needs_a_two_byte_short_user_id() -> None:
    for short in ("0a", "0a1b2c", "", None):
        user = anker.AnkerUser(admin_user_id=ADMIN, user_name="x", short_user_id=short)
        with pytest.raises(ValueError, match="2 bytes"):
            anker.cm_on_off_body(LockAction.LOCK, user, timestamp=NOW)


def _request_1930(**kw: object) -> anker.Anker1930Request:
    args: dict[str, object] = {
        "seq_num": 9,
        "timestamp": NOW,
        "lock_public_key": LOCK_PUB64,
        "aes_key": AES_KEY,
        "ephemeral": EPHEMERAL,
        "ecies_iv": ECIES_IV,
    }
    args.update(kw)
    return anker.build_1930_request(SERIAL_1930, LockAction.LOCK, USER, **args)  # type: ignore[arg-type]


def test_1930_ecc_frame_carries_the_ecies_key_and_the_encrypted_body() -> None:
    request = _request_1930()
    assert request.command == 1930
    assert list(request.payload) == ["apiCommand", "lock_payload", "seq_num"]
    assert (request.payload["apiCommand"], request.payload["seq_num"]) == (6018, 9)
    raw = bytes.fromhex(str(request.payload["lock_payload"]))
    wrapped = crypto.ecies_encrypt(
        AES_KEY, LOCK_PRIV.public_key(), iv=ECIES_IV, ephemeral=EPHEMERAL
    )
    assert len(wrapped) == 113
    body = anker.cm_on_off_body(LockAction.LOCK, USER, timestamp=NOW)
    sealed = _seal(AES_KEY, _iv(SERIAL_1930), body)
    assert raw == frames.anker_frame(sealed, command=8, version=18, key_field=wrapped)
    assert request.key == AES_KEY


def test_1930_ecdh_frame_keys_with_the_shared_secret() -> None:
    lock_ecdh = ec.derive_private_key(0xECD4_0000_0000_0003, ec.SECP256R1())
    sec1 = lock_ecdh.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.CompressedPoint
    )
    request = _request_1930(lock_public_key=None, lock_ecdh_public_key=sec1)
    shared = lock_ecdh.exchange(ec.ECDH(), EPHEMERAL.public_key())
    assert request.key == shared[:16]
    app_pub = EPHEMERAL.public_key().public_bytes(
        serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
    )
    body = anker.cm_on_off_body(LockAction.LOCK, USER, timestamp=NOW)
    sealed = _seal(shared[:16], _iv(SERIAL_1930), body)
    raw = bytes.fromhex(str(request.payload["lock_payload"]))
    assert raw == frames.anker_frame(sealed, command=8, version=20, key_field=app_pub)


def test_1930_needs_exactly_one_lock_key() -> None:
    with pytest.raises(ValueError, match="one of"):
        _request_1930(lock_public_key=None)
    with pytest.raises(ValueError, match="one of"):
        _request_1930(lock_ecdh_public_key=b"\x02" + bytes(32))
    with pytest.raises(ValueError, match="ECDH public key"):
        _request_1930(lock_public_key=None, lock_ecdh_public_key=b"\x04" + bytes(64))


def _answer_1930(
    code: int,
    *,
    version: int = 18,
    command: int = 8,
    key: bytes = AES_KEY,
    serial: str = SERIAL_1930,
) -> dict[str, object]:
    body = bytes([code, 1, 2])
    if version != 33:
        body = _seal(key, _iv(SERIAL_1930), body)
    raw = (
        frames.START + (9 + len(body)).to_bytes(2, "little") + bytes([version, 0xFF, command, 0xC0])
    )
    raw += body
    raw += bytes([frames.xor8(raw)])
    return {"dev_sn": serial, "lock_payload": raw.hex()}


@pytest.mark.parametrize(("code", "result"), [(0, LockResult.ACCEPTED), (1, LockResult.REFUSED)])
def test_1930_answer_code(code: int, result: LockResult) -> None:
    assert anker.parse_1930_reply(_answer_1930(code), _request_1930()) == LockReply(code, result)


def test_1930_answer_with_version_33_is_plain() -> None:
    reply = anker.parse_1930_reply(_answer_1930(0, version=33), _request_1930())
    assert reply.result is LockResult.ACCEPTED


def test_1930_answer_for_another_command_or_lock_is_not_ours() -> None:
    with pytest.raises(LockReplyMismatchError, match="command"):
        anker.parse_1930_reply(_answer_1930(0, command=9), _request_1930())
    with pytest.raises(LockReplyMismatchError, match="serial"):
        anker.parse_1930_reply(_answer_1930(0, serial="T8501P2000099999"), _request_1930())


def test_1930_answer_with_an_empty_payload_names_it() -> None:
    with pytest.raises(ProtocolError, match="no lock_payload"):
        anker.parse_1930_reply({"dev_sn": SERIAL_1930, "lock_payload": ""}, _request_1930())


@pytest.mark.parametrize(
    "answer",
    [
        {},
        {"dev_sn": SERIAL_1930},
        {"dev_sn": SERIAL_1930, "lock_payload": "nothex"},
        {"dev_sn": SERIAL_1930, "lock_payload": "ff09"},
        {"dev_sn": 5, "lock_payload": "ff09"},
        _answer_1930(0, key=b"y" * 16),
        {"dev_sn": SERIAL_1930, "lock_payload": "ff090900" + "21ff08c0" + "e9"},
    ],
)
def test_1930_malformed_answer_raises_protocol_error(answer: dict[str, object]) -> None:
    with pytest.raises(ProtocolError):
        anker.parse_1930_reply(answer, _request_1930())
