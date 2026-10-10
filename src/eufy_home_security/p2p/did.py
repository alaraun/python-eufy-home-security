"""P2P device id (DID) and the static AES key derived from it.

A eufy P2P id is ``PREFIX-NUMBER-SUFFIX`` (e.g. ``EUPRAMA-123456-ABCDE``): a prefix
of 1..7 capitals, a number below 2**31, a suffix of 1..7 capitals, as the eufy app's
P2P stack accepts it. On the wire it is a 20-byte struct; a station announces it in
the body of a PUNCH_PKT during discovery.

The static key wraps the CONN_INIT handshake frame (AES-128-ECB) and every
base->app parameter/notify frame the station sends under ECB. It is the id's text
with its first seven characters replaced by the serial's last seven::

    key = serial[-7:] + did_text[7:16]

and must come out to exactly 16 ASCII bytes (for ``EUPRAMA-123456-ABCDE``:
``serial[-7:] + "-123456-A"``).

Every malformed DID — text, struct or serial — raises :class:`ProtocolError`:
DIDs and serials come from the cloud device list or the wire, not from a user.
"""

from __future__ import annotations

import re
import struct
from dataclasses import dataclass

from .._logging import redact
from ..exceptions import ProtocolError

#: On-wire DID struct: prefix field 8 bytes, number u32 BE at 8, suffix field 8 bytes
#: at 12 (each text NUL-terminated inside its field), 20 bytes in all. A body of 17
#: bytes still holds a five-letter suffix.
_DID_STRUCT_LEN = 20
_DID_STRUCT_MIN = 17
_PREFIX_LEN = 8
_SUFFIX_OFFSET = 12
_NUMBER_MAX = 2**31 - 1
_KEY_LEN = 16
_SERIAL_TAIL = 7

#: ``PREFIX-NUMBER-SUFFIX``: 1..7 ASCII capitals, ASCII digits, 1..7 ASCII capitals.
_DID_RE = re.compile(r"([A-Z]{1,7})-([0-9]+)-([A-Z]{1,7})")
_PREFIX_RE = re.compile(r"[A-Z]{1,7}")
_SUFFIX_RE = re.compile(r"[A-Z]{1,7}")


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

        The prefix and the suffix are 1..7 ASCII capitals, the number ASCII digits
        below 2**31 (:meth:`__str__` renders at least six, zero-padded). No
        whitespace, underscores or non-ASCII digits are accepted.
        """
        match = _DID_RE.fullmatch(text)
        if match is None:
            raise ProtocolError(f"invalid DID {text!r} (expected PREFIX-NUMBER-SUFFIX)")
        prefix, number, suffix = match.groups()
        did = cls(prefix=prefix, number=int(number), suffix=suffix)
        did._validate()
        return did

    @classmethod
    def from_struct(cls, body: bytes) -> Did:
        """Parse a DID struct: prefix 8B, number u32 BE, suffix up to 8B, NUL-padded ASCII."""
        if len(body) < _DID_STRUCT_MIN:
            raise ProtocolError(
                f"DID struct too short: {len(body)} bytes (need >= {_DID_STRUCT_MIN})"
            )
        try:
            prefix = body[:8].rstrip(b"\x00").decode("ascii")
            suffix = body[_SUFFIX_OFFSET:_DID_STRUCT_LEN].rstrip(b"\x00").decode("ascii")
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
            or not 0 <= self.number <= _NUMBER_MAX
        ):
            raise ProtocolError(
                f"invalid DID fields: prefix={self.prefix!r} number={self.number} "
                f"suffix={self.suffix!r}"
            )


def static_key(serial: str, did: Did | str) -> bytes:
    """Derive the 16-byte AES-128-ECB static key from serial and DID.

    ``key = serial[-7:] + did_text[7:16]``, where ``did_text`` is ``did`` as given
    (a :class:`Did` renders through :meth:`Did.__str__`); it must be exactly 16 ASCII
    bytes, anything else raises :class:`ProtocolError`.
    """
    if isinstance(did, str):
        Did.parse(did)  # validates; the key slices the text as written
        text = did
    else:
        text = str(did)
    clean = serial.strip()
    if len(clean) < _SERIAL_TAIL:
        raise ProtocolError(f"serial too short to derive a static key: {redact(serial)!r}")
    try:
        key = (clean[-_SERIAL_TAIL:] + text[_SERIAL_TAIL:_KEY_LEN]).encode("ascii")
    except UnicodeEncodeError as exc:
        raise ProtocolError(
            f"serial or DID is not ASCII: {redact(serial)!r}, {redact(text)!r}"
        ) from exc
    if len(key) != _KEY_LEN:
        raise ProtocolError(
            f"derived static key is {len(key)} bytes, not {_KEY_LEN} "
            f"(serial={redact(serial)!r}, did={redact(text)})"
        )
    return key
