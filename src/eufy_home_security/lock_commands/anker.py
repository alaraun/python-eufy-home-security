"""The Anker lock forms: P2P command 1961 (JSON) and 1930 (a cm frame in through-data).

Declared, eufy app; not tested on hardware (docs/protocol/locks.md § 1961, § 1930).

**1961** ``{"shortUserId", "slOperation", "userId", "userName"}`` (``slOperation`` 1 =
lock, 0 = unlock; ``userId`` the member's ``admin_user_id``; an absent ``shortUserId`` is
left out). In the encrypted form the object gains ``seq_num``, is AES-128-CBC encrypted
under a random 16-byte key and the serial IV, and travels base64 as ``payload``; ``key``
is the hex of the ECIES (P-256, the lock's public key) of that AES key's upper-case hex
text. The plain form sends the object itself.

**1930** a cm on/off body ``A1 02 <short user id> A2 01 <slOperation> A3 04 <u32 LE
time> A4 <len> <name>``, AES-128-CBC under the serial IV, in an Anker cm frame
(:mod:`.frames`) whose key field wraps the AES key: ECIES of the 16 key bytes under the
lock's public key (frame version 18), or the app's own P-256 public key when the key is
an ECDH secret with the lock's ECDH key (version 20, the first 16 bytes of the shared
x-coordinate). The frame travels hex in ``{"apiCommand", "lock_payload", "seq_num"}``.

Builders raise :class:`ValueError` on an argument outside its domain; the answer readers
raise :class:`~eufy_home_security.exceptions.ProtocolError` (or its subclass
:class:`~eufy_home_security.exceptions.LockReplyMismatchError`) and nothing else.
"""

from __future__ import annotations

import base64
import json
import os
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Final

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ec

from ..exceptions import LockReplyMismatchError, ProtocolError
from ..p2p.crypto import ecies_encrypt
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

COMMAND_1961: Final = 1961
COMMAND_1930: Final = 1930
CM_ON_OFF: Final = 8
VERSION_ECC: Final = 18
VERSION_ECDH: Final = 20
VERSION_PLAIN_ANSWER: Final = 33
"""An answer frame of this version carries its body unencrypted."""

_AES_KEY_LEN: Final = 16
_PUBLIC_KEY_LEN: Final = 64
_SHORT_USER_ID_LEN: Final = 2
# Gson's default escaping: HTML-sensitive characters and the two JS line separators.
_GSON_ESCAPES: Final = {c: f"\\u{ord(c):04x}" for c in "<>&='\u2028\u2029"}


@dataclass(frozen=True, slots=True)
class AnkerUser:
    """Who an Anker lock command names: the lock member's ``admin_user_id``, the account's
    nickname and the member's ``short_user_id`` (hex text; 1961 leaves an absent one out,
    1930 needs 2 bytes)."""

    admin_user_id: str
    user_name: str
    short_user_id: str | None = None


def parse_lock_public_key(raw: bytes) -> ec.EllipticCurvePublicKey:
    """The lock's P-256 public key from its 64 bytes ``X || Y`` (the cloud's hex, decoded)."""
    if len(raw) != _PUBLIC_KEY_LEN:
        raise ValueError(f"lock public key must be 64 bytes, got {len(raw)}")
    try:
        return ec.EllipticCurvePublicKey.from_encoded_point(ec.SECP256R1(), b"\x04" + raw)
    except ValueError as exc:
        raise ValueError("lock public key is not a P-256 point") from exc


def gson_json(obj: Mapping[str, object]) -> str:
    """``obj`` as the app's JSON writer renders it: compact, Unicode kept, HTML escaped."""
    text = json.dumps(obj, ensure_ascii=False, separators=(",", ":"))
    return "".join(_GSON_ESCAPES.get(c, c) for c in text)


def _on_off_object(action: LockAction, user: AnkerUser) -> dict[str, object]:
    obj: dict[str, object] = (
        {} if user.short_user_id is None else {"shortUserId": user.short_user_id}
    )
    return obj | {
        "slOperation": int(action),
        "userId": user.admin_user_id,
        "userName": user.user_name,
    }


def _aes_key(aes_key: bytes | None) -> bytes:
    key = aes_key if aes_key is not None else os.urandom(_AES_KEY_LEN)
    if len(key) != _AES_KEY_LEN:
        raise ValueError(f"lock AES key must be 16 bytes, got {len(key)}")
    return key


@dataclass(frozen=True, slots=True, kw_only=True)
class Anker1961Request:
    """A built 1961 request. ``key`` is None in the plain form."""

    payload: str | dict[str, object]
    key: str | None
    aes_key: bytes = b""
    command: int = COMMAND_1961

    def payload_info(self, *, account_id: str, channel: int) -> dict[str, object]:
        """The P2P payload object in the app's field order (sent as the 1350 wrapper's text)."""
        info: dict[str, object] = {} if self.key is None else {"key": self.key}
        info |= {
            "account_id": account_id,
            "cmd": self.command,
            "mChannel": channel,
            "mValue3": 0,
            "payload": self.payload,
        }
        return info


def build_1961_request(
    serial: str,
    action: LockAction,
    user: AnkerUser,
    *,
    seq_num: int,
    lock_public_key: bytes,
    aes_key: bytes | None = None,
    ephemeral: ec.EllipticCurvePrivateKey | None = None,
    ecies_iv: bytes | None = None,
) -> Anker1961Request:
    """The encrypted 1961 lock/unlock request. ``seq_num`` is the value to send; the AES
    key, the ECIES ephemeral key and IV are random unless given."""
    public = parse_lock_public_key(lock_public_key)
    key = _aes_key(aes_key)
    body = _on_off_object(action, user) | {"seq_num": seq_num}
    sealed = cbc_encrypt(gson_json(body).encode(), key, serial_iv(serial))
    wrapped = ecies_encrypt(key.hex().upper().encode(), public, iv=ecies_iv, ephemeral=ephemeral)
    return Anker1961Request(
        payload=base64.b64encode(sealed).decode(), key=wrapped.hex(), aes_key=key
    )


def build_1961_plain_request(action: LockAction, user: AnkerUser) -> Anker1961Request:
    """The plain 1961 lock/unlock request (no key, no sequence number)."""
    return Anker1961Request(payload=_on_off_object(action, user), key=None)


def parse_1961_result(code: int) -> LockReply:
    """The 1961 command's result code: 0 accepted, anything else refused."""
    return LockReply(code, LockResult.ACCEPTED if code == 0 else LockResult.REFUSED)


def cm_on_off_body(action: LockAction, user: AnkerUser, *, timestamp: int) -> bytes:
    """The cm on/off body of the 1930 form; ``timestamp`` is the Unix time in seconds."""
    short = hex_bytes(user.short_user_id or "", "short user id")
    if len(short) != _SHORT_USER_ID_LEN:
        raise ValueError(f"a cm short user id must be 2 bytes, got {len(short)}")
    return frames.tlv(
        [
            short,
            bytes([int(action)]),
            (timestamp & 0xFFFF_FFFF).to_bytes(4, "little"),
            user.user_name.encode(),
        ]
    )


@dataclass(frozen=True, slots=True, kw_only=True)
class Anker1930Request:
    """A built 1930 request: the payload object and the AES key its answer opens with."""

    serial: str
    payload: dict[str, object]
    key: bytes
    command: int = COMMAND_1930


def build_1930_request(
    serial: str,
    action: LockAction,
    user: AnkerUser,
    *,
    seq_num: int,
    timestamp: int,
    lock_public_key: bytes | None = None,
    lock_ecdh_public_key: bytes | None = None,
    aes_key: bytes | None = None,
    ephemeral: ec.EllipticCurvePrivateKey | None = None,
    ecies_iv: bytes | None = None,
) -> Anker1930Request:
    """The 1930 lock/unlock request.

    Exactly one of ``lock_public_key`` (64 bytes ``X || Y``: the ECIES form) and
    ``lock_ecdh_public_key`` (a SEC1 point: the ECDH form) is given;
    :func:`eufy_home_security.devices.lock_routes.lock_route` says which. The AES key
    (ECIES form), the ephemeral key and the ECIES IV are random unless given.
    """
    if lock_public_key is not None and lock_ecdh_public_key is not None:
        raise ValueError("give one of lock_public_key and lock_ecdh_public_key, not both")
    body = cm_on_off_body(action, user, timestamp=timestamp)
    if lock_ecdh_public_key is not None:
        try:
            peer = ec.EllipticCurvePublicKey.from_encoded_point(
                ec.SECP256R1(), lock_ecdh_public_key
            )
        except ValueError as exc:
            raise ValueError("lock ECDH public key is not a P-256 point") from exc
        own = ephemeral if ephemeral is not None else ec.generate_private_key(ec.SECP256R1())
        key = own.exchange(ec.ECDH(), peer)[:_AES_KEY_LEN]
        key_field = own.public_key().public_bytes(
            serialization.Encoding.X962, serialization.PublicFormat.UncompressedPoint
        )
        version = VERSION_ECDH
    elif lock_public_key is not None:
        public = parse_lock_public_key(lock_public_key)
        key = _aes_key(aes_key)
        key_field = ecies_encrypt(key, public, iv=ecies_iv, ephemeral=ephemeral)
        version = VERSION_ECC
    else:
        raise ValueError("give one of lock_public_key and lock_ecdh_public_key")
    frame = frames.anker_frame(
        cbc_encrypt(body, key, serial_iv(serial)),
        command=CM_ON_OFF,
        version=version,
        key_field=key_field,
    )
    payload: dict[str, object] = {
        "apiCommand": API_ON_OFF,
        "lock_payload": frame.hex(),
        "seq_num": seq_num,
    }
    return Anker1930Request(serial=serial, payload=payload, key=key)


def parse_1930_reply(answer: Mapping[str, object], request: Anker1930Request) -> LockReply:
    """The lock's answer to ``request`` from its 1930 through-data object."""
    serial = answer.get("dev_sn")
    if not isinstance(serial, str) or not serial:
        raise ProtocolError("lock answer has no dev_sn")
    if serial != request.serial:
        raise LockReplyMismatchError("lock answer names another serial")
    text = answer.get("lock_payload")
    if not isinstance(text, str) or not text:
        raise ProtocolError("lock answer has no lock_payload")
    try:
        raw = bytes.fromhex(text)
    except ValueError as exc:
        raise ProtocolError("lock answer payload is not hex") from exc
    frame = frames.parse_anker_frame(raw)
    if frame.command != CM_ON_OFF:
        raise LockReplyMismatchError(f"lock answer is for command {frame.command}")
    body = frame.body
    if frame.version != VERSION_PLAIN_ANSWER:
        body = cbc_decrypt(body, request.key, serial_iv(request.serial))
    if not body:
        raise ProtocolError("lock answer body is empty")
    code = body[0]
    return LockReply(code, LockResult.ACCEPTED if code == 0 else LockResult.REFUSED)
