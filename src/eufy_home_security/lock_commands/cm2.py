"""The 1940 lock command: an encrypted cm2 frame in through-data, and its answer.

The form of locks that reach the app's newer lock protocol through a station (declared,
eufy app; not tested on hardware; docs/protocol/locks.md § 1940):

- body: TLV ``[timestamp u32 LE][user id UTF-8][operation u8][name UTF-8][short user id]``,
  operation 0 = lock, 1 = unlock (the inverse of :class:`LockAction`'s value);
- key: the user id's last 12 characters (UTF-8) and the 4 bytes of an 8-hex-digit time
  value, or, in the HKDF variant, HKDF-SHA256 over the user id with the time value as salt;
- AES-128-CBC under the serial IV, the body zero-padded to whole blocks and then PKCS#7
  padded (an aligned body gains a whole padding block);
- the cm2 frame (:mod:`.frames`), hex, in the payload
  ``{"apiCommand", "lock_payload", "seq_num", "time"[, "version"]}`` of P2P command 1940.

The answer comes back as 1940 through-data ``{"dev_sn", "lock_payload", "time"}``; its
own time value names the key, and for a time-key request a positive time other than the
request's marks an answer to another request, encrypted or not. Builders raise
:class:`ValueError` on an argument outside its domain; :func:`parse_on_off_reply` raises
:class:`~eufy_home_security.exceptions.ProtocolError` (or its subclass
:class:`~eufy_home_security.exceptions.LockReplyMismatchError`) and nothing else.
"""

from __future__ import annotations

import math
import re
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from ..exceptions import LockReplyMismatchError, ProtocolError
from . import frames
from .actions import (
    API_ON_OFF,
    LockAction,
    LockReply,
    LockResult,
    cbc_decrypt,
    cbc_encrypt,
    hex_bytes,
    serial_iv,
)

P2P_COMMAND: Final = 1940
COMMAND_ON_OFF: Final = 0x23
FUNCTION_TYPE: Final = 2
FRAME_VERSION: Final = 3
HKDF_VERSION: Final = "1"
"""``version`` of a payload keyed by HKDF."""

_KEY_USER_CHARS: Final = 12
_TIME_HEX_DIGITS: Final = 8
_HKDF_INFO: Final = bytes(range(0xF0, 0xFA))
_HKDF_KEY_LEN: Final = 16
# The fixed key and IV that seal the HKDF form's time field.
_TIME_FIELD_KEY: Final = b"ANKER_SMARTLOCK_"
_TIME_FIELD_IV: Final = b"OCK_WORLD'S_NO.1"
_TIME_FIELD_USER_LEN: Final = 40
_MEMBER_TYPE_OWN_KEY: Final = 2
_MAX_NOISE: Final = 99
_SIGNED_HEX: Final = re.compile(r"[+-]?[0-9a-fA-F]+")
_INT32: Final = range(-(2**31), 2**31)

_RESULTS: Final = {
    0: LockResult.ACCEPTED,
    48: LockResult.ALREADY_UNLOCKED,
    49: LockResult.ALREADY_LOCKED,
}


def key_user_id(
    *,
    account_user_id: str,
    admin_user_id: str | None,
    member_type: int | None,
    member_user_id: str | None,
) -> str:
    """The user id a 1940 frame names and keys with, by the app's rule.

    The lock's member record's ``admin_user_id`` when the record names this account
    (``member_user_id``), holds an admin id and its ``member_type`` is not 2; the
    account's own user id otherwise.
    """
    if admin_user_id and member_type != _MEMBER_TYPE_OWN_KEY and member_user_id == account_user_id:
        return admin_user_id
    return account_user_id


@dataclass(frozen=True, slots=True)
class Cm2User:
    """Who a 1940 command names: the key user id (:func:`key_user_id`), the account's
    nickname and the member's ``short_user_id`` (hex text; absent or empty sends an empty
    entry)."""

    user_id: str
    user_name: str
    short_user_id: str | None = None


def on_off_body(action: LockAction, user: Cm2User, *, timestamp: int) -> bytes:
    """The cm2 lock/unlock body; ``timestamp`` is the current Unix time in seconds."""
    operation = 0 if action is LockAction.LOCK else 1
    return frames.tlv(
        [
            (timestamp & 0xFFFF_FFFF).to_bytes(4, "little"),
            user.user_id.encode(),
            bytes([operation]),
            user.user_name.encode(),
            hex_bytes(user.short_user_id or "", "short user id"),
        ]
    )


def lock_time(now: float, noise: int) -> int:
    """The app's time value: whole seconds of ``now`` OR ``noise`` (0..99, random)."""
    if not 0 <= noise <= _MAX_NOISE:
        raise ValueError(f"time noise must be 0..99, got {noise}")
    return math.floor(now) | noise


def time_key(user_id: str, time_value: int) -> bytes:
    """The 1940 AES key: the user id's last 12 characters and the time value's 4 bytes."""
    if len(user_id) < _KEY_USER_CHARS:
        raise ValueError("a 1940 key needs a user id of 12 or more characters")
    if not 0x1000_0000 <= time_value <= 0xFFFF_FFFF:
        raise ValueError(f"a 1940 time value must be 8 hex digits, got {time_value:#x}")
    key = user_id[-_KEY_USER_CHARS:].encode() + time_value.to_bytes(4, "big")
    if len(key) != 16:
        raise ValueError(f"a 1940 key must be 16 bytes, the user id gives {len(key)}")
    return key


def _salt(value: int) -> bytes:
    return (value & 0xFFFF_FFFF).to_bytes(4, "big")


def hkdf_key(user_id: str, salt: int) -> bytes:
    """The HKDF variant's key: HKDF-SHA256(user id, 4-byte salt, info F0..F9), 16 bytes."""
    kdf = HKDF(algorithm=hashes.SHA256(), length=_HKDF_KEY_LEN, salt=_salt(salt), info=_HKDF_INFO)
    return kdf.derive(user_id.encode())


def hkdf_time_field(user_id: str, salt: int) -> str:
    """The HKDF variant's ``time``: the user id and salt sealed under a fixed key, as hex."""
    return cbc_encrypt(user_id.encode() + _salt(salt), _TIME_FIELD_KEY, _TIME_FIELD_IV).hex()


def open_hkdf_time_field(text: str) -> tuple[str, int]:
    """``(user id, salt)`` from an HKDF ``time`` field; ProtocolError when it does not open."""
    try:
        blob = bytes.fromhex(text)
    except ValueError as exc:
        raise ProtocolError("lock answer time is not hex") from exc
    plain = cbc_decrypt(blob, _TIME_FIELD_KEY, _TIME_FIELD_IV)
    if len(plain) < _TIME_FIELD_USER_LEN + 4:
        raise ProtocolError(f"lock answer time holds {len(plain)} bytes, not a user id and salt")
    user = plain[:_TIME_FIELD_USER_LEN].decode(errors="replace")
    salt = int.from_bytes(plain[_TIME_FIELD_USER_LEN : _TIME_FIELD_USER_LEN + 4], "big")
    return user, salt


def seal_body(body: bytes, key: bytes, iv: bytes) -> bytes:
    """Zero-pad ``body`` to whole AES blocks, then AES-128-CBC with PKCS#7 padding."""
    return cbc_encrypt(body + b"\0" * (-len(body) % 16), key, iv)


@dataclass(frozen=True, slots=True, kw_only=True)
class Cm2Request:
    """A built 1940 request: the payload to send and what its answer is read with."""

    serial: str
    payload: dict[str, object]
    """The P2P 1940 payload object."""
    key: bytes
    """The AES key of the request."""
    time_value: int
    hkdf: bool
    user_id: str
    command: int = P2P_COMMAND


def build_on_off_request(
    serial: str,
    action: LockAction,
    user: Cm2User,
    *,
    seq_num: int,
    time_value: int,
    timestamp: int,
    hkdf: bool = False,
) -> Cm2Request:
    """The 1940 lock/unlock request for the lock ``serial``.

    ``seq_num`` is the value to send: as the eufy app keeps it, a reported sequence
    number ``R`` is stored as ``R + 1`` and each send uses the stored value plus one
    (so the first send after a report carries ``R + 2``), the current Unix time plus one
    when nothing is stored.
    ``time_value`` a :func:`lock_time`, ``timestamp`` the current Unix time; ``hkdf``
    picks the HKDF variant (:func:`eufy_home_security.devices.lock_routes.lock_route`).
    """
    key = hkdf_key(user.user_id, time_value) if hkdf else time_key(user.user_id, time_value)
    body = seal_body(on_off_body(action, user, timestamp=timestamp), key, serial_iv(serial))
    frame = frames.cm2_frame(
        body,
        command=COMMAND_ON_OFF,
        function_type=FUNCTION_TYPE,
        version=FRAME_VERSION,
        encrypted=True,
    )
    payload: dict[str, object] = {
        "apiCommand": API_ON_OFF,
        "lock_payload": frame.hex(),
        "seq_num": seq_num,
        "time": hkdf_time_field(user.user_id, time_value) if hkdf else time_value,
    }
    if hkdf:
        payload["version"] = HKDF_VERSION
    return Cm2Request(
        serial=serial,
        payload=payload,
        key=key,
        time_value=time_value,
        hkdf=hkdf,
        user_id=user.user_id,
    )


def _text(answer: Mapping[str, object], name: str) -> str:
    value = answer.get(name)
    if not isinstance(value, str) or not value:
        raise ProtocolError(f"lock answer has no {name}")
    return value


def _answer_time(value: object) -> int:
    """The answer's ``time`` read as the eufy app reads it: a signed 32-bit hex number,
    -1 when it is absent, not hex or out of that range."""
    if isinstance(value, str) and _SIGNED_HEX.fullmatch(value):
        number = int(value, 16)
        if number in _INT32:
            return number
    return -1


def _answer_key(request: Cm2Request, time_text: str) -> bytes:
    """The key an encrypted answer opens with, from the answer's own ``time``."""
    if request.hkdf:
        user, salt = open_hkdf_time_field(time_text)
        return hkdf_key(user, salt)
    try:
        time_bytes = bytes.fromhex(time_text)
    except ValueError as exc:
        raise ProtocolError(f"lock answer time {time_text!r} is not hex") from exc
    if len(time_text) != _TIME_HEX_DIGITS:
        raise ProtocolError(f"lock answer time {time_text!r} is not 8 hex digits")
    return request.user_id[-_KEY_USER_CHARS:].encode() + time_bytes


def parse_on_off_reply(answer: Mapping[str, object], request: Cm2Request) -> LockReply:
    """The lock's answer to ``request`` from its 1940 through-data object."""
    if _text(answer, "dev_sn") != request.serial:
        raise LockReplyMismatchError("lock answer names another serial")
    try:
        raw = bytes.fromhex(_text(answer, "lock_payload"))
    except ValueError as exc:
        raise ProtocolError("lock answer payload is not hex") from exc
    frame = frames.parse_cm2_frame(raw)
    if (frame.function_type, frame.command) != (FUNCTION_TYPE, COMMAND_ON_OFF):
        raise LockReplyMismatchError(f"lock answer is for command {frame.command:#x}")
    if not request.hkdf:
        # As the eufy app: an answer whose time and the request's are both positive and
        # differ answers another request, whether or not it is encrypted.
        answer_time = _answer_time(answer.get("time"))
        if answer_time > 0 and request.time_value > 0 and answer_time != request.time_value:
            raise LockReplyMismatchError("lock answer carries another time value than the request")
    body = frame.body
    if frame.encrypted:
        key = _answer_key(request, _text(answer, "time"))
        body = cbc_decrypt(body, key, serial_iv(request.serial))
    if not body:
        raise ProtocolError("lock answer body is empty")
    code = body[0]
    return LockReply(code, _RESULTS.get(code, LockResult.REFUSED))
