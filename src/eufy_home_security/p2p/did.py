"""P2P device id (DID) and the static AES key derived from it.

A eufy P2P id is ``PREFIX-NUMBER-SUFFIX`` (e.g. ``EUPRAMA-123456-ABCDE``). On
the wire it is a 20-byte struct; a station announces it in the body of a
PUNCH_PKT during discovery.

The static key wraps the CONN_INIT handshake frame (AES-128-ECB) and every
base->app parameter/notify frame the station sends under ECB. It is derived as::

    key = serial[-7:] + "-" + NUMBER + "-" + suffix[0]

where ``NUMBER`` is the six-digit, zero-padded number exactly as it appears in the
text form, and it must come out to exactly 16 ASCII bytes.

Every malformed DID — text, struct or serial — raises :class:`ProtocolError`:
DIDs and serials come from the cloud device list or the wire, not from a user.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass

from .._logging import redact
from ..exceptions import ProtocolError

#: On-disk / on-wire size of a DID struct: prefix(8) + number(4) + suffix(5) = 17,
#: zero-padded to 20.
_DID_STRUCT_LEN = 20
_DID_STRUCT_MIN = 17
_PREFIX_LEN = 8
_NUMBER_DIGITS = 6
_SUFFIX_LEN = 5

#: ``PREFIX-NUMBER-SUFFIX``: 1..8 ASCII capitals, exactly 6 ASCII digits, 5 capitals.
_DID_RE = re.compile(r"([A-Z]{1,8})-([0-9]{6})-([A-Z]{5})")
_PREFIX_RE = re.compile(r"[A-Z]{1,8}")
_SUFFIX_RE = re.compile(r"[A-Z]{5}")


@dataclass(frozen=True, slots=True)
class Did:
    """A parsed P2P device id."""

    prefix: str
    number: int
    suffix: str

    def __str__(self) -> str:
        return f"{self.prefix}-{self.number:06d}-{self.suffix}"

    @classmethod
    def parse(cls, text: str) -> Did:
        """Parse ``PREFIX-NUMBER-SUFFIX`` strictly (raises :class:`ProtocolError`).

        The prefix is 1..8 ASCII capitals, the number exactly six ASCII digits
        (leading zeros kept by :meth:`__str__`), the suffix five ASCII capitals. No
        whitespace, underscores or non-ASCII digits are accepted.
        """
        match = _DID_RE.fullmatch(text)
        if match is None:
            raise ProtocolError(f"invalid DID {text!r} (expected PREFIX-NNNNNN-SUFFIX)")
        prefix, number, suffix = match.groups()
        return cls(prefix=prefix, number=int(number), suffix=suffix)

    @classmethod
    def from_struct(cls, body: bytes) -> Did:
        """Parse a DID struct: prefix 8B NUL-padded ascii, number u32 BE, suffix 5B."""
        if len(body) < _DID_STRUCT_MIN:
            raise ProtocolError(
                f"DID struct too short: {len(body)} bytes (need >= {_DID_STRUCT_MIN})"
            )
        try:
            prefix = body[:8].rstrip(b"\x00").decode("ascii")
            suffix = body[12:17].rstrip(b"\x00").decode("ascii")
        except UnicodeDecodeError as exc:
            raise ProtocolError("DID struct holds non-ASCII text") from exc
        number = struct.unpack_from(">I", body, 8)[0]
        did = cls(prefix=prefix, number=number, suffix=suffix)
        did._validate()
        return did

    def to_struct(self) -> bytes:
        """Serialize to the 20-byte, zero-padded DID struct (raises :class:`ProtocolError`)."""
        self._validate()
        prefix = self.prefix.encode("ascii").ljust(_PREFIX_LEN, b"\x00")
        suffix = self.suffix.encode("ascii")
        body = prefix + struct.pack(">I", self.number) + suffix
        return body.ljust(_DID_STRUCT_LEN, b"\x00")

    def _validate(self) -> None:
        """Raise :class:`ProtocolError` unless every field has the text form's shape."""
        if (
            _PREFIX_RE.fullmatch(self.prefix) is None
            or _SUFFIX_RE.fullmatch(self.suffix) is None
            or not 0 <= self.number < 10**_NUMBER_DIGITS
        ):
            raise ProtocolError(
                f"invalid DID fields: prefix={self.prefix!r} number={self.number} "
                f"suffix={self.suffix!r}"
            )


def static_key(serial: str, did: Did | str) -> bytes:
    """Derive the 16-byte AES-128-ECB static key from serial and DID.

    ``key = serial[-7:] + "-" + NNNNNN + "-" + suffix[0]`` (the zero-padded
    number), which must be exactly 16 ASCII bytes; anything else raises
    :class:`ProtocolError`.
    """
    parsed = Did.parse(did) if isinstance(did, str) else did
    clean = serial.strip()
    if len(clean) < 7:
        raise ProtocolError(f"serial too short to derive a static key: {redact(serial)!r}")
    if not parsed.suffix:
        raise ProtocolError(f"DID {redact(str(parsed))} has no suffix to derive a static key")
    try:
        key = f"{clean[-7:]}-{parsed.number:06d}-{parsed.suffix[0]}".encode("ascii")
    except UnicodeEncodeError as exc:
        raise ProtocolError(
            f"serial or DID is not ASCII: {redact(serial)!r}, {redact(str(parsed))!r}"
        ) from exc
    if len(key) != 16:
        raise ProtocolError(
            f"derived static key is {len(key)} bytes, not 16 (serial={redact(serial)!r}, did={redact(str(parsed))})"
        )
    return key
