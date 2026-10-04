"""Logging helpers shared by every subsystem.

Loggers follow the module tree (``eufy_home_security.p2p.session`` and so on), so a
consumer can raise one subsystem to DEBUG without the rest. Home Assistant does
exactly that when the integration lists ``eufy_home_security`` under ``loggers``.

Wire-level dumps go to a separate branch, ``eufy_home_security.wire.<subsystem>``,
which is held at WARNING at import time — unless the application has already
configured it (Home Assistant applies ``logger:`` before importing integrations).
Turning on DEBUG for the package does not turn them on — they are far too noisy for
a normal debug log — so enable them explicitly with :func:`set_wire_logging`.

Secrets (passwords, tokens, cipher and session keys) and identifiers (account and
user ids, user and device names, serials, DIDs, MAC and public IP addresses, media
paths, push device ids) are logged through :class:`Secret`, :class:`Identifier`,
:class:`Address` and :class:`Payload`, which render them redacted unless the
``eufy_home_security.secrets`` logger is at DEBUG (:func:`set_secret_logging`). That
switch is separate from the package level for the same reason as the wire dumps:
a debug log attached to an issue must not carry the account or the house.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import time
from collections.abc import Mapping
from typing import Final

from .models import IDENTIFYING_PARAMS

PACKAGE_LOGGER: Final = logging.getLogger("eufy_home_security")
PACKAGE_LOGGER.addHandler(logging.NullHandler())

WIRE_LOGGER: Final = logging.getLogger("eufy_home_security.wire")
if WIRE_LOGGER.level == logging.NOTSET:
    WIRE_LOGGER.setLevel(logging.WARNING)


def wire_logger(subsystem: str) -> logging.Logger:
    """Return the wire-dump logger for ``subsystem`` (``p2p``, ``cloud``, ``push``)."""
    return WIRE_LOGGER.getChild(subsystem)


def set_wire_logging(enabled: bool) -> None:
    """Enable or disable wire-level (hexdump) logging for every subsystem."""
    WIRE_LOGGER.setLevel(logging.DEBUG if enabled else logging.WARNING)


SECRET_LOGGER: Final = logging.getLogger("eufy_home_security.secrets")
if SECRET_LOGGER.level == logging.NOTSET:
    SECRET_LOGGER.setLevel(logging.WARNING)


def set_secret_logging(enabled: bool) -> None:
    """Log passwords, tokens and keys in clear (see :class:`Secret`), or stop doing so."""
    SECRET_LOGGER.setLevel(logging.DEBUG if enabled else logging.WARNING)


def secrets_enabled() -> bool:
    return SECRET_LOGGER.isEnabledFor(logging.DEBUG)


class Secret:
    """A secret as a logging argument: in full when secret logging is on, else redacted.

    Bytes render as hex. Rendering is lazy, so ``log.debug("key %s", Secret(key))``
    costs nothing when the record is not emitted.
    """

    __slots__ = ("_value",)

    def __init__(self, value: object) -> None:
        self._value = value

    def __str__(self) -> str:
        value = self._value
        if isinstance(value, bytes | bytearray | memoryview):
            value = bytes(value).hex()
        if value is None or not secrets_enabled():
            return redact(value)
        return str(value)


#: What a :class:`Credential` renders as while secret logging is off: no tail, no length.
CREDENTIAL_MASK: Final = "***"


class Credential:
    """A credential (a password, a one-time code, a captcha answer) as a logging
    argument: in full when secret logging is on, else :data:`CREDENTIAL_MASK`.

    Unlike :class:`Secret` it keeps no tail and no length: a tail tells two keys apart,
    but every character of a password is a real loss. An absent value renders as
    ``None`` and an empty one as ``""``, so a log still shows whether one was given.
    """

    __slots__ = ("_value",)

    def __init__(self, value: object) -> None:
        self._value = value

    def __str__(self) -> str:
        value = self._value
        if value is None:
            return "None"
        text = str(value)
        if not text or secrets_enabled():
            return text
        return CREDENTIAL_MASK


#: Key fragments whose values :class:`Payload` treats as credentials: masked with
#: :class:`Credential`, no tail (case-insensitive).
CREDENTIAL_KEY_PARTS: Final = ("password", "passwd", "captcha", "verify_code", "answer")

#: Key fragments whose values :class:`Payload` treats as secrets (case-insensitive).
SENSITIVE_KEY_PARTS: Final = (
    "password",
    "passwd",
    "token",
    "secret",
    "key",
    "cipher",
    "sign",
    "cookie",
    "authorization",
    "email",
    "phone",
    "captcha",
    "verify_code",
)


#: Keys whose values identify the account, a person, a device or the house, compared
#: with case, ``_`` and ``-`` ignored (``device_sn``, ``mValueStrSub``, ``app-conn``).
IDENTIFYING_KEYS: Final = frozenset(
    {
        # account and people
        "account", "accountid", "userid", "uid", "shortuserid", "adminuserid",
        "memberuserid", "actionuserid", "ownerid", "owneruserid", "mvaluestrsub",
        "username", "nickname", "actionusername", "personname", "mobile", "openudid",
        # devices and the house
        "sn", "s", "serial", "serialnumber", "devicesn", "stationsn", "parentsn", "did",
        "p2pdid", "hddlabel", "curstoragelabel", "oldstoragelabel",
        "name", "devicename", "stationname", "devicealiasname", "homename", "roomname",
        "houseid", "homeid", "roomid", "mac", "btmac", "wifimac", "ssid", "wifissid",
        "appconn", "p2pconn", "ip", "ipaddr", "localip", "androidid", "fid",
        # media on the station's disk
        "file", "filepath", "path", "thumbpath", "storagepath", "croppath", "videopath",
        "coverpath", "cloudpath", "crophb3path", "cropcloudpath", "snapshotcloud", "mp4cloud",
    }
)  # fmt: skip

_IDENTIFYING_PARAM_TEXT: Final = frozenset(str(param) for param in IDENTIFYING_PARAMS)
_SERIAL = re.compile(r"(?<![A-Z0-9])T[0-9A-Z]{15}(?![A-Z0-9])")
_ACCOUNT_ID = re.compile(r"(?<![0-9a-fA-F])[0-9a-f]{40}(?![0-9a-fA-F])")
_EMAIL = re.compile(r"[\w.+-]+@[\w-]+(?:\.[\w-]+)+")
_MEDIA_PATH = re.compile(r"/zx/[^\s\"',;]*")


def _hidden_text(text: str) -> str:
    """``text`` with serials, 40-hex account ids, e-mail addresses and station media
    paths (``/zx/…``) redacted."""
    text = _MEDIA_PATH.sub(lambda m: redact(m.group()), text)
    text = _SERIAL.sub(lambda m: redact_serial(m.group()), text)
    text = _ACCOUNT_ID.sub(lambda m: redact(m.group()), text)
    return _EMAIL.sub(lambda m: redact(m.group()), text)


def scrub(value: object) -> str:
    """Free text for a log line with any serial, account id, e-mail address or media
    path in it redacted (in full when secret logging is on)."""
    text = str(value)
    return text if secrets_enabled() else _hidden_text(text)


class Identifier:
    """An identifier as a logging argument: in full when secret logging is on, else
    redacted (a serial keeps its model prefix, see :func:`redact_serial`)."""

    __slots__ = ("_value",)

    def __init__(self, value: object) -> None:
        self._value = value

    def __str__(self) -> str:
        value = self._value
        if value is None or not secrets_enabled():
            return _hidden_identifier(value)
        return str(value)


def _hidden_identifier(value: object) -> str:
    if isinstance(value, str) and _SERIAL.fullmatch(value):
        return redact_serial(value)
    return redact(value)


class Address:
    """A host as a logging argument: private, loopback and link-local IP addresses and
    host names in full (they say which network path was taken, not who you are);
    public IP addresses redacted unless secret logging is on."""

    __slots__ = ("_host",)

    def __init__(self, host: object) -> None:
        self._host = host

    def __str__(self) -> str:
        text = str(self._host)
        try:
            ip = ipaddress.ip_address(text)
        except ValueError:
            return text
        if ip.is_private or ip.is_loopback or ip.is_link_local or secrets_enabled():
            return text
        return redact(text)


def _masked(data: object, clear: bool) -> object:
    if isinstance(data, Mapping):
        out: dict[str, object] = {}
        # A parameter entry ({"param_type": 1217, "param_value": "Front"}) is identified
        # by its id, not its key.
        named_param = str(data.get("param_type")) in _IDENTIFYING_PARAM_TEXT
        for k, v in data.items():
            key = str(k)
            if isinstance(v, str | bytes | int) and not isinstance(v, bool) and _credential(key):
                out[key] = str(Credential(v))
            elif isinstance(v, str | bytes | int) and not isinstance(v, bool) and _sensitive(key):
                out[key] = str(Secret(v))
            elif (
                isinstance(v, str | int)
                and not isinstance(v, bool)
                and (_identifying(key) or (named_param and key == "param_value"))
            ):
                out[key] = str(v) if clear else _hidden_identifier(v)
            else:
                out[key] = _masked(v, clear)
        return out
    if isinstance(data, list | tuple):
        return [_masked(v, clear) for v in data]
    if isinstance(data, bytes | bytearray):
        return bytes(data).hex()
    if isinstance(data, str):
        stripped = data.strip()
        if stripped[:1] in ("{", "[") and stripped[-1:] in ("}", "]"):
            try:
                decoded = json.loads(stripped)
            except ValueError:
                decoded = None
            if isinstance(decoded, dict | list):
                return _masked(decoded, clear)  # a JSON body inside a string
        return data if clear else _hidden_text(data)
    return data


def _sensitive(key: str) -> bool:
    lowered = key.lower()
    return any(part in lowered for part in SENSITIVE_KEY_PARTS)


def _credential(key: str) -> bool:
    lowered = key.lower()
    return any(part in lowered for part in CREDENTIAL_KEY_PARTS)


def _identifying(key: str) -> bool:
    return key.lower().replace("_", "").replace("-", "") in IDENTIFYING_KEYS


class Payload:
    """A request/response body or header map as a logging argument, rendered as JSON.

    Values under a sensitive key (:data:`SENSITIVE_KEY_PARTS`) go through
    :class:`Secret`; values under an identifying key (:data:`IDENTIFYING_KEYS`) and
    serials, account ids, e-mail addresses and media paths anywhere in a string are redacted
    unless secret logging is on. A string holding a JSON object is decoded so its
    fields are masked too. Long renderings are cut at ``limit`` characters.
    """

    __slots__ = ("_data", "_limit")

    def __init__(self, data: object, limit: int = 4000) -> None:
        self._data = data
        self._limit = limit

    def __str__(self) -> str:
        clear = secrets_enabled()
        text = json.dumps(_masked(self._data, clear), ensure_ascii=False, default=str)
        if len(text) > self._limit:
            return f"{text[: self._limit]}… {len(text) - self._limit} more chars"
        return text


_SERIAL_BYTES = re.compile(rb"T[0-9A-Z]{4}([0-9A-Z]{7})[0-9A-Z]{4}")
_DID_STRUCT_BYTES = re.compile(rb"[A-Z]{3,8}\x00{0,5}((?s:.{4})[A-Z]{5})")
_DID_TEXT_BYTES = re.compile(rb"[A-Z]{3,8}-([0-9]{6}-[A-Z]{5})")
_ACCOUNT_ID_BYTES = re.compile(rb"([0-9a-f]{36})[0-9a-f]{4}")

#: Extra literal byte strings to star out of hexdumps: secrets with no fixed shape,
#: such as a device session key (DSK). Registered at runtime, deduplicated, and never
#: persisted; empty by default.
_SECRET_BYTES: set[bytes] = set()


def register_secret_bytes(*values: bytes | str) -> None:
    """Star ``values`` out of every wire hexdump (unless the secrets switch is on).

    For secrets that carry no recognisable shape (a DSK, say), so the pattern-based
    masking cannot catch them. A short or empty value is ignored, so a blank key never
    blanks a whole dump."""
    for value in values:
        raw = value.encode() if isinstance(value, str) else value
        if len(raw) >= 4:
            _SECRET_BYTES.add(raw)


def _hidden_bytes(data: bytes) -> bytes:
    """``data`` with serials, DIDs (struct and text form), 40-hex account ids and any
    registered secret bytes starred out in place, so a hexdump keeps its offsets."""
    out = bytearray(data)
    for pattern in (_SERIAL_BYTES, _DID_STRUCT_BYTES, _DID_TEXT_BYTES, _ACCOUNT_ID_BYTES):
        for match in pattern.finditer(data):
            if pattern is _DID_STRUCT_BYTES and match.start(1) - match.start() != 8:
                continue  # a DID prefix is NUL-padded to exactly 8 bytes
            out[match.start(1) : match.end(1)] = b"*" * (match.end(1) - match.start(1))
    for secret in _SECRET_BYTES:
        start = data.find(secret)
        while start != -1:
            out[start : start + len(secret)] = b"*" * len(secret)
            start = data.find(secret, start + 1)
    return bytes(out)


class HexDump:
    """Lazily formatted hexdump: the bytes are only rendered if the record is emitted.

    Use as a logging argument: ``log.debug("rx %s", HexDump(data))``.
    """

    __slots__ = ("_data", "_limit")

    def __init__(self, data: bytes | bytearray | memoryview, limit: int = 256) -> None:
        self._data = bytes(data)
        self._limit = limit

    def __str__(self) -> str:
        data = self._data if secrets_enabled() else _hidden_bytes(self._data)
        shown = data[: self._limit]
        lines = []
        for off in range(0, len(shown), 16):
            chunk = shown[off : off + 16]
            hexpart = " ".join(f"{b:02x}" for b in chunk)
            text = "".join(chr(b) if 32 <= b < 127 else "." for b in chunk)
            lines.append(f"{off:04x}  {hexpart:<47}  {text}")
        if len(self._data) > self._limit:
            lines.append(f"… {len(self._data) - self._limit} more bytes")
        return f"({len(self._data)} bytes)\n" + "\n".join(lines)


def redact(value: object, visible: int = 4) -> str:
    """Hide a secret, keeping only its last ``visible`` characters and its length."""
    if value is None:
        return "None"
    text = str(value)
    if not text:
        return ""
    if len(text) <= visible * 2:
        return "*" * len(text)
    return f"***{text[-visible:]}"


def redact_serial(serial: str | None) -> str:
    """Hide a device serial, keeping the model prefix (``T8030``) and the last 4."""
    if not serial:
        return str(serial)
    if len(serial) <= 9:
        return redact(serial)
    return f"{serial[:5]}***{serial[-4:]}"


class LogThrottle:
    """Decide whether a repeated log line should be emitted again.

    UDP retransmits, unknown frame types and reconnect loops repeat; logging each
    occurrence buries the first one. ``should_log(key)`` is True the first time a
    key is seen and then at most once per ``interval`` seconds.

    Keys are often taken from the wire — a peer address, a frame type — so the table is
    bounded and expired entries are dropped. Without that, anything on the LAN could
    grow it without limit for the life of the process.
    """

    def __init__(self, interval: float = 300.0, *, max_keys: int = 512) -> None:
        self._interval = interval
        self._max_keys = max_keys
        self._last: dict[object, float] = {}

    def should_log(self, key: object) -> bool:
        now = time.monotonic()
        last = self._last.get(key)
        if last is not None and now - last < self._interval:
            return False
        if key not in self._last and len(self._last) >= self._max_keys:
            self._evict(now)
        self._last[key] = now
        return True

    def _evict(self, now: float) -> None:
        """Drop every entry past its interval; failing that, the oldest half.

        An expired entry would allow its line again anyway, so dropping it changes
        nothing. When none has expired the keys are arriving faster than the interval,
        which is the flood this table exists to survive.
        """
        self._last = {key: at for key, at in self._last.items() if now - at < self._interval}
        if len(self._last) < self._max_keys:
            return
        keep = sorted(self._last.items(), key=lambda item: item[1])[len(self._last) // 2 :]
        self._last = dict(keep)
