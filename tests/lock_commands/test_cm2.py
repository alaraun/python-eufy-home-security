"""The 1940 lock command: cm2 body, time key, HKDF variant, request payload and answer."""

from __future__ import annotations

import hashlib
import hmac
import json

import pytest
from cryptography.hazmat.primitives import padding
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes

from eufy_home_security.exceptions import LockReplyMismatchError, ProtocolError
from eufy_home_security.lock_commands import LockAction, LockReply, LockResult, cm2, frames
from eufy_home_security.lock_commands.actions import cbc_encrypt
from eufy_home_security.testing import SYNTHETIC

SERIAL = "T8502" + SYNTHETIC.station_sn[5:]
USER_ID = SYNTHETIC.account_id  # 40 characters, like the cloud's user ids
NOW = 1_700_000_000
TIME = NOW | 37
USER = cm2.Cm2User(user_id=USER_ID, user_name="Synth User", short_user_id="0000")

# The body the eufy app's handler builds for these inputs (its own clock fixed at NOW): the
# account's user id, the operation byte, the name, the short user id, each a TLV entry.
HANDLER_BODY_OP0 = bytes.fromhex(
    "A10400F15365A228303132333435363738396162636465663031323334353637383961626364656630313233"
    "34353637A30100A40A53796E74682055736572A5020000"
)


def _aes(key: bytes, iv: bytes, data: bytes, *, decrypt: bool = False) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv))
    if decrypt:
        dec = cipher.decryptor()
        raw = dec.update(data) + dec.finalize()
        unpadder = padding.PKCS7(128).unpadder()
        return unpadder.update(raw) + unpadder.finalize()
    padder = padding.PKCS7(128).padder()
    enc = cipher.encryptor()
    return enc.update(padder.update(data) + padder.finalize()) + enc.finalize()


def _iv() -> bytes:
    return SERIAL.encode().ljust(16, b"\0")


def _hkdf(ikm: bytes, salt: bytes, info: bytes, length: int) -> bytes:
    prk = hmac.new(salt, ikm, hashlib.sha256).digest()
    out, block, i = b"", b"", 1
    while len(out) < length:
        block = hmac.new(prk, block + info + bytes([i]), hashlib.sha256).digest()
        out += block
        i += 1
    return out[:length]


# ── who the frame names and keys with ────────────────────────────────────────


@pytest.mark.parametrize(
    ("member_type", "member_user_id", "admin", "expected"),
    [
        (1, "me", "owner-admin-id", "owner-admin-id"),  # a shared member: the owner's admin id
        (2, "me", "owner-admin-id", "me"),  # member type 2 keys with the account's own id
        (1, "someone-else", "owner-admin-id", "me"),  # a record for another account
        (1, "me", "", "me"),  # no admin id recorded
        (None, None, None, "me"),  # no member record
        (None, "me", "owner-admin-id", "owner-admin-id"),  # no type recorded: not type 2
    ],
)
def test_key_user_id_follows_the_apps_member_rule(
    member_type: int | None, member_user_id: str | None, admin: str | None, expected: str
) -> None:
    assert (
        cm2.key_user_id(
            account_user_id="me",
            admin_user_id=admin,
            member_type=member_type,
            member_user_id=member_user_id,
        )
        == expected
    )


# ── body ─────────────────────────────────────────────────────────────────────


def test_lock_body_equals_the_handlers_body_with_operation_byte_0() -> None:
    assert cm2.on_off_body(LockAction.LOCK, USER, timestamp=NOW) == HANDLER_BODY_OP0


def test_unlock_body_carries_operation_byte_1() -> None:
    body = cm2.on_off_body(LockAction.UNLOCK, USER, timestamp=NOW)
    assert body == HANDLER_BODY_OP0.replace(bytes.fromhex("A30100"), bytes.fromhex("A30101"))


def test_body_takes_the_short_user_id_as_hex_and_the_name_as_utf8() -> None:
    user = cm2.Cm2User(user_id=USER_ID, user_name="Jüri", short_user_id="0a1b")
    body = cm2.on_off_body(LockAction.LOCK, user, timestamp=0)
    assert body.endswith(bytes.fromhex("A405") + "Jüri".encode() + bytes.fromhex("A5020a1b"))
    odd = cm2.Cm2User(user_id=USER_ID, user_name="x", short_user_id="abc")
    assert cm2.on_off_body(LockAction.LOCK, odd, timestamp=0).endswith(bytes.fromhex("A5020abc"))
    with pytest.raises(ValueError, match="short user id"):
        cm2.on_off_body(LockAction.LOCK, cm2.Cm2User(USER_ID, "x", short_user_id="zz"), timestamp=0)


# ── time and keys ────────────────────────────────────────────────────────────


def test_lock_time_ors_the_noise_into_the_seconds() -> None:
    assert cm2.lock_time(NOW + 0.9, 37) == NOW | 37
    assert cm2.lock_time(NOW, 0) == NOW
    with pytest.raises(ValueError, match="noise"):
        cm2.lock_time(NOW, 100)
    with pytest.raises(ValueError, match="noise"):
        cm2.lock_time(NOW, -1)
    assert cm2.lock_time(NOW, 99) == NOW | 99
    assert cm2.lock_time(NOW + 37, 5) == (NOW + 37) | 5  # OR, not a sum


def test_time_key_is_the_user_ids_last_12_chars_and_the_time() -> None:
    assert cm2.time_key(USER_ID, TIME) == USER_ID[-12:].encode() + TIME.to_bytes(4, "big")


@pytest.mark.parametrize("value", [0x0FFF_FFFF, 0x1_0000_0000, -1])
def test_time_key_needs_exactly_8_hex_digits(value: int) -> None:
    with pytest.raises(ValueError, match="8 hex"):
        cm2.time_key(USER_ID, value)
    cm2.time_key(USER_ID, 0x1000_0000)
    cm2.time_key(USER_ID, 0xFFFF_FFFF)


def test_time_key_needs_a_user_id_of_12_or_more_chars() -> None:
    with pytest.raises(ValueError, match="12"):
        cm2.time_key("a" * 11, TIME)
    assert cm2.time_key("a" * 12, TIME)[:12] == b"a" * 12
    with pytest.raises(ValueError, match="16"):
        cm2.time_key("ä" * 12, TIME)


def test_hkdf_key_is_rfc5869_sha256_over_the_user_id_and_salt() -> None:
    info = bytes(range(0xF0, 0xFA))
    expected = _hkdf(USER_ID.encode(), TIME.to_bytes(4, "big"), info, 16)
    assert cm2.hkdf_key(USER_ID, TIME) == expected
    assert cm2.hkdf_key(USER_ID, -2) == _hkdf(USER_ID.encode(), b"\xff\xff\xff\xfe", info, 16)


def test_hkdf_time_field_seals_the_user_id_and_salt() -> None:
    sealed = cm2.hkdf_time_field(USER_ID, TIME)
    plain = USER_ID.encode() + TIME.to_bytes(4, "big")
    assert sealed == _aes(b"ANKER_SMARTLOCK_", b"OCK_WORLD'S_NO.1", plain).hex()
    assert cm2.open_hkdf_time_field(sealed) == (USER_ID, TIME)


# ── request ──────────────────────────────────────────────────────────────────


def _request(action: LockAction = LockAction.LOCK, *, hkdf: bool = False) -> cm2.Cm2Request:
    return cm2.build_on_off_request(
        SERIAL, action, USER, seq_num=42, time_value=TIME, timestamp=NOW, hkdf=hkdf
    )


def test_request_payload_is_the_apps_v12_payload() -> None:
    request = _request()
    assert list(request.payload) == ["apiCommand", "lock_payload", "seq_num", "time"]
    assert request.payload["apiCommand"] == 6018
    assert request.payload["seq_num"] == 42
    assert request.payload["time"] == TIME
    assert request.command == 1940
    assert request.key == USER_ID[-12:].encode() + TIME.to_bytes(4, "big")
    lock_payload = request.payload["lock_payload"]
    assert isinstance(lock_payload, str)
    assert lock_payload == lock_payload.lower()


def test_request_frame_carries_the_zero_padded_encrypted_body() -> None:
    request = _request()
    frame = frames.parse_cm2_frame(bytes.fromhex(str(request.payload["lock_payload"])))
    assert (frame.version, frame.slave_id, frame.function_type) == (3, 0, 2)
    assert (frame.command, frame.encrypted) == (0x23, True)
    body = HANDLER_BODY_OP0
    padded = body + b"\0" * (-len(body) % 16)
    assert _aes(request.key, _iv(), frame.body, decrypt=True) == padded


def test_an_aligned_body_gains_a_whole_padding_block() -> None:
    assert len(cm2.seal_body(bytes(16), b"k" * 16, _iv())) == 32
    assert len(cm2.seal_body(bytes(17), b"k" * 16, _iv())) == 48
    assert cm2.seal_body(b"", b"k" * 16, _iv()) == _aes(b"k" * 16, _iv(), b"")


def test_hkdf_request_keys_with_hkdf_and_sends_the_sealed_time() -> None:
    request = _request(hkdf=True)
    assert list(request.payload) == ["apiCommand", "lock_payload", "seq_num", "time", "version"]
    assert request.payload["version"] == "1"
    assert request.payload["time"] == cm2.hkdf_time_field(USER_ID, TIME)
    assert request.key == cm2.hkdf_key(USER_ID, TIME)
    frame = frames.parse_cm2_frame(bytes.fromhex(str(request.payload["lock_payload"])))
    padded = HANDLER_BODY_OP0 + b"\0" * (-len(HANDLER_BODY_OP0) % 16)
    assert _aes(request.key, _iv(), frame.body, decrypt=True) == padded


def test_request_json_is_compact() -> None:
    assert json.loads(json.dumps(_request().payload))["seq_num"] == 42


# ── answer ───────────────────────────────────────────────────────────────────


def _answer(
    code: int,
    *,
    key: bytes | None = None,
    time_field: str | None = None,
    command: int = 0x23,
    encrypted: bool = True,
    serial: str = SERIAL,
) -> dict[str, object]:
    key = key if key is not None else cm2.time_key(USER_ID, TIME)
    body = bytes([code, 0x11, 0x22])
    if encrypted:
        body = cm2.seal_body(body, key, _iv())
    frame = frames.cm2_frame(body, command=command, function_type=2, version=3, encrypted=encrypted)
    return {
        "dev_sn": serial,
        "lock_payload": frame.hex(),
        "time": time_field if time_field is not None else f"{TIME:08x}",
    }


@pytest.mark.parametrize(
    ("code", "result"),
    [
        (0, LockResult.ACCEPTED),
        (48, LockResult.ALREADY_UNLOCKED),
        (49, LockResult.ALREADY_LOCKED),
        (1, LockResult.REFUSED),
        (0xFF, LockResult.REFUSED),
    ],
)
def test_answer_code_maps_to_a_result(code: int, result: LockResult) -> None:
    assert cm2.parse_on_off_reply(_answer(code), _request()) == LockReply(code, result)


def test_answer_is_decrypted_with_the_key_of_its_own_time() -> None:
    other = TIME ^ 0x40
    answer = _answer(0, key=cm2.time_key(USER_ID, other), time_field=f"{other:08x}")
    with pytest.raises(LockReplyMismatchError, match="time"):
        cm2.parse_on_off_reply(answer, _request())


def test_answer_with_the_requests_time_in_upper_case_hex_is_ours() -> None:
    answer = _answer(0, time_field=f"{TIME:08X}")
    assert cm2.parse_on_off_reply(answer, _request()).result is LockResult.ACCEPTED


def test_plain_answer_is_read_without_a_key() -> None:
    reply = cm2.parse_on_off_reply(_answer(49, encrypted=False), _request())
    assert reply == LockReply(49, LockResult.ALREADY_LOCKED)


@pytest.mark.parametrize("time_field", [f"{TIME ^ 0x40:08x}", "1234"])
def test_plain_answer_with_another_time_is_not_ours(time_field: str) -> None:
    answer = _answer(0, encrypted=False, time_field=time_field)
    with pytest.raises(LockReplyMismatchError, match="time"):
        cm2.parse_on_off_reply(answer, _request())


@pytest.mark.parametrize("time_field", [None, "", "xyz", "00000000", f"00{TIME:08X}"])
def test_plain_answer_without_another_usable_time_is_read(time_field: str | None) -> None:
    answer = _answer(0, encrypted=False)
    answer["time"] = time_field
    assert cm2.parse_on_off_reply(answer, _request()) == LockReply(0, LockResult.ACCEPTED)
    del answer["time"]
    assert cm2.parse_on_off_reply(answer, _request()) == LockReply(0, LockResult.ACCEPTED)


def test_encrypted_answer_with_time_zero_is_not_ours() -> None:
    answer = _answer(0, time_field="00000000")
    with pytest.raises(LockReplyMismatchError, match="time"):
        cm2.parse_on_off_reply(answer, _request())


def test_plain_answer_to_an_hkdf_request_has_no_stale_check() -> None:
    answer = _answer(0, encrypted=False, time_field=f"{TIME ^ 0x40:08x}")
    assert cm2.parse_on_off_reply(answer, _request(hkdf=True)).result is LockResult.ACCEPTED


def test_answer_for_another_command_is_not_ours() -> None:
    with pytest.raises(LockReplyMismatchError, match="command"):
        cm2.parse_on_off_reply(_answer(0, command=0x4A), _request())


def test_answer_of_another_function_type_is_not_ours() -> None:
    body = cm2.seal_body(bytes([0]), cm2.time_key(USER_ID, TIME), _iv())
    frame = frames.cm2_frame(body, command=0x23, function_type=3, version=3, encrypted=True)
    answer = {"dev_sn": SERIAL, "lock_payload": frame.hex(), "time": f"{TIME:08x}"}
    with pytest.raises(LockReplyMismatchError, match="command"):
        cm2.parse_on_off_reply(answer, _request())


@pytest.mark.parametrize(
    ("answer", "match"),
    [
        ({"dev_sn": "", "lock_payload": "ff", "time": "0"}, "no dev_sn"),
        ({"dev_sn": SERIAL, "lock_payload": "", "time": "0"}, "no lock_payload"),
        (
            {"dev_sn": SERIAL, "lock_payload": _answer(0)["lock_payload"], "time": f"00{TIME:08x}"},
            "8 hex",
        ),
    ],
)
def test_answer_field_errors_name_the_field(answer: dict[str, object], match: str) -> None:
    with pytest.raises(ProtocolError, match=match) as exc:
        cm2.parse_on_off_reply(answer, _request())
    assert type(exc.value) is ProtocolError


def test_answer_from_another_lock_is_not_ours() -> None:
    with pytest.raises(LockReplyMismatchError, match="serial"):
        cm2.parse_on_off_reply(_answer(0, serial="T8502P2000099999"), _request())


def test_hkdf_answer_opens_with_the_key_its_time_names() -> None:
    salt = TIME ^ 0x55  # an answer under its own salt: the HKDF form has no stale check
    answer = _answer(
        0, key=cm2.hkdf_key(USER_ID, salt), time_field=cm2.hkdf_time_field(USER_ID, salt)
    )
    assert cm2.parse_on_off_reply(answer, _request(hkdf=True)).result is LockResult.ACCEPTED


@pytest.mark.parametrize(
    "answer",
    [
        {},
        {"dev_sn": SERIAL, "lock_payload": "", "time": f"{TIME:08x}"},
        {"dev_sn": SERIAL, "lock_payload": "zz", "time": f"{TIME:08x}"},
        {"dev_sn": SERIAL, "lock_payload": 12, "time": f"{TIME:08x}"},
        {"dev_sn": SERIAL, "lock_payload": "ff09", "time": f"{TIME:08x}"},
        {"dev_sn": SERIAL, "lock_payload": _answer(0)["lock_payload"], "time": "xyz"},
        {"dev_sn": SERIAL, "lock_payload": _answer(0)["lock_payload"], "time": None},
        {"dev_sn": SERIAL, "lock_payload": _answer(0)["lock_payload"], "time": "1234"},
        {"dev_sn": None, "lock_payload": _answer(0)["lock_payload"], "time": f"{TIME:08x}"},
    ],
)
def test_malformed_answer_raises_protocol_error(answer: dict[str, object]) -> None:
    with pytest.raises(ProtocolError):
        cm2.parse_on_off_reply(answer, _request())


def test_answer_under_a_wrong_key_raises_protocol_error() -> None:
    answer = _answer(0, key=b"x" * 16)
    with pytest.raises(ProtocolError, match="decrypt"):
        cm2.parse_on_off_reply(answer, _request())


def test_answer_with_an_empty_body_raises_protocol_error() -> None:
    frame = frames.cm2_frame(b"", command=0x23, function_type=2, version=3, encrypted=False)
    answer = {"dev_sn": SERIAL, "lock_payload": frame.hex(), "time": f"{TIME:08x}"}
    with pytest.raises(ProtocolError, match="empty"):
        cm2.parse_on_off_reply(answer, _request())


def test_hkdf_answer_time_must_hold_a_user_id_and_salt() -> None:
    short = cbc_encrypt(b"x" * 43, b"ANKER_SMARTLOCK_", b"OCK_WORLD'S_NO.1").hex()
    with pytest.raises(ProtocolError, match="not a user id and salt"):
        cm2.parse_on_off_reply(_answer(0, time_field=short), _request(hkdf=True))


@pytest.mark.parametrize(
    "time_field",
    ["", "zz", "00" * 20, cm2.hkdf_time_field("x", 1)[:-2], cm2.hkdf_time_field("x", 1)],
)
def test_hkdf_answer_with_an_unusable_time_raises_protocol_error(time_field: str) -> None:
    answer = _answer(0, time_field=time_field)
    with pytest.raises(ProtocolError):
        cm2.parse_on_off_reply(answer, _request(hkdf=True))
