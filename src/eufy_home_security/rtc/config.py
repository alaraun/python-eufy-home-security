"""What an RTC signaling client needs to know about one station.

The inputs come from the station's cloud device-list entry (``signaling_servers``,
``p2p_did``, ``p2p_license``, ``main_sw_version``, ``webrtc_sdk_version``) and the
account (user id, an app install id). The signaling host is the first bare IPv4
entry of ``signaling_servers``; a domain entry is only a cache key and is never
resolved. Also the per-station protocol choices the eufy app makes from the station's
prefix and versions: the data channel's KCP framing and whether commands are sealed.
Declared (eufy app): per-prefix rules with no data source.
"""

from __future__ import annotations

import ipaddress
import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final, cast

from .._logging import redact, redact_serial
from .codec import CONTACT_LEN, ascii_decimal
from .crypto import SESSION_KEY_LEN

#: How long a quick-login record stays usable after its login, in seconds.
QUICK_LOGIN_LIFETIME: Final = 82800

_DOMAIN: Final = re.compile(r"^[A-Za-z0-9-]+(\.[A-Za-z0-9-]+)+(:\d+)?$")


def _host(entry: str) -> str:
    host = entry.strip()
    for prefix in ("https://", "http://"):
        host = host.removeprefix(prefix)
    return host.split("/", 1)[0]


def signaling_ipv4(servers: Sequence[object]) -> str | None:
    """The first entry of ``signaling_servers`` that is a bare IPv4 address."""
    for entry in servers:
        if not isinstance(entry, str):
            continue
        host = _host(entry)
        try:
            ipaddress.IPv4Address(host)
        except ValueError:
            continue
        return host
    return None


def signaling_domain(servers: Sequence[object]) -> str | None:
    """The first entry of ``signaling_servers`` that is a domain name."""
    for entry in servers:
        if not isinstance(entry, str):
            continue
        host = _host(entry)
        if signaling_ipv4([host]) is None and _DOMAIN.match(host):
            return host
    return None


#: The most digits a firmware number is read with.
_FIRMWARE_DIGITS: Final = 16


def firmware_number(version: str | None) -> int | None:
    """``main_sw_version`` with the dots removed, as an int (``"3.8.7.4"`` -> 3874);
    None when that is not 1 to 16 ASCII digits."""
    if not version:
        return None
    return ascii_decimal(version.replace(".", ""), _FIRMWARE_DIGITS)


#: Data-channel framing: kcp_type 2 puts a 32-byte prefix before every KCP datagram,
#: kcp_type 1 sends bare KCP segments.
KCP_TYPE_SINGLE: Final = 1
KCP_TYPE_MULTI: Final = 2
#: The ``webrtc_sdk_version`` (second and third component; the first is ignored) from
#: which a station prefix uses kcp_type 2; any other prefix always does. Declared (eufy
#: app).
_KCP_MULTI_SINCE: Final[Mapping[str, tuple[int, int]]] = {
    "T8223": (1, 3),
    "T8224": (1, 3),
    "T8030": (1, 3),
    "T8025": (1, 3),
    "T8N00": (1, 2),
    "T9000": (1, 2),
}
#: Prefixes whose unreadable ``webrtc_sdk_version`` means kcp_type 1 (else 2).
_KCP_SINGLE_ON_BAD_VERSION: Final = frozenset({"T8030", "T8025"})


def data_channel_kcp_type(model: str, sdk_version: str | None) -> int:
    """The data channel's kcp_type for station prefix ``model`` at ``sdk_version``
    (:data:`KCP_TYPE_MULTI` when the version is absent). Declared (eufy app)."""
    since = _KCP_MULTI_SINCE.get(model)
    if since is None or not sdk_version:
        return KCP_TYPE_MULTI
    parts = sdk_version.split(".")
    try:
        found = tuple(int(parts[i]) if len(parts) > i else 0 for i in (1, 2))
    except ValueError:
        return KCP_TYPE_SINGLE if model in _KCP_SINGLE_ON_BAD_VERSION else KCP_TYPE_MULTI
    return KCP_TYPE_MULTI if found >= since else KCP_TYPE_SINGLE


#: Per station prefix, the :func:`firmware_number` ranges (inclusive; None = open) in
#: which commands are AES-GCM sealed; a prefix not listed always seals them. Declared
#: (eufy app).
_COMMAND_GCM_FIRMWARE: Final[Mapping[str, tuple[tuple[int, int | None], ...]]] = {
    "T9000": ((4100, None),),
    "T8N00": ((1089, 1199), (1209, None)),
    "T8030": ((3743, None),),
    "T8223": ((3376, None),),
    "T8224": ((3476, None),),
    "T8172": ((1021, None),),
    "T8025": (),
}


def commands_encrypted(model: str, firmware: int | None) -> bool:
    """Whether station prefix ``model`` at ``firmware`` (:func:`firmware_number`) takes
    AES-GCM commands; otherwise they go in the clear. An unknown firmware (None) reads as
    0, as the app's integer version defaults to 0: a gated prefix then sends in the clear.
    Declared (eufy app)."""
    ranges = _COMMAND_GCM_FIRMWARE.get(model)
    if ranges is None:
        return True
    fw = firmware or 0
    return any(low <= fw and (high is None or fw <= high) for low, high in ranges)


def missing_inputs(raw: Mapping[str, Any]) -> tuple[str, ...]:
    """The fields of a station's device-list entry ``raw`` an RTC config needs and the
    entry lacks: ``device_sn``, ``p2p_did``, ``p2p_license`` (non-empty strings) and
    ``signaling_servers`` (a list with a bare IPv4 entry)."""
    missing = [
        key
        for key in ("device_sn", "p2p_did", "p2p_license")
        if not (isinstance(raw.get(key), str) and raw[key])
    ]
    servers = raw.get("signaling_servers")
    if not isinstance(servers, list) or signaling_ipv4(servers) is None:
        missing.append("signaling_servers")
    return tuple(missing)


@dataclass(frozen=True, slots=True)
class QuickLogin:
    """What a LOGIN 200 leaves for the next start: the session key, the contact id,
    the server that accepted it and when."""

    session_key: str
    contact_id: str
    server: str
    logged_in_at: float

    def usable(self, now: float | None = None) -> bool:
        """Whether the record is complete and younger than :data:`QUICK_LOGIN_LIFETIME`."""
        current = time.time() if now is None else now
        return (
            len(self.session_key) == SESSION_KEY_LEN
            and len(self.contact_id) == CONTACT_LEN
            and self.logged_in_at + QUICK_LOGIN_LIFETIME >= current
        )

    def __repr__(self) -> str:
        return (
            f"QuickLogin(session_key={redact(self.session_key)!r}, "
            f"contact_id={redact(self.contact_id)!r}, server={self.server!r})"
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class RtcConfig:
    """The inputs of one station's RTC signaling client."""

    station_sn: str
    p2p_did: str
    p2p_license: str
    signaling_host: str
    user_id: str
    app_id: str
    """An install-wide app id (the app sends the phone's Android id)."""
    signaling_domain: str | None = None
    firmware: int | None = None
    sdk_version: str | None = None
    quick_login: QuickLogin | None = None

    @property
    def identity(self) -> bytes:
        """The station identity a LOGIN proves: ``"<p2p_did>:<p2p_license>"``."""
        return f"{self.p2p_did}:{self.p2p_license}".encode()

    @classmethod
    def from_device(
        cls,
        raw: Mapping[str, Any],
        *,
        user_id: str,
        app_id: str,
        quick_login: QuickLogin | None = None,
    ) -> RtcConfig | None:
        """The config of the station whose device-list entry is ``raw``; None when the
        entry lacks one of :func:`missing_inputs`."""
        if missing_inputs(raw):
            return None
        servers = raw["signaling_servers"]
        host = cast("str", signaling_ipv4(servers))  # missing_inputs found one
        sdk = raw.get("webrtc_sdk_version")
        version = raw.get("main_sw_version")
        return cls(
            station_sn=raw["device_sn"],
            p2p_did=raw["p2p_did"],
            p2p_license=raw["p2p_license"],
            signaling_host=host,
            user_id=user_id,
            app_id=app_id,
            signaling_domain=signaling_domain(servers),
            firmware=firmware_number(version if isinstance(version, str) else None),
            sdk_version=sdk if isinstance(sdk, str) and sdk else None,
            quick_login=quick_login,
        )

    def __repr__(self) -> str:
        return (
            f"RtcConfig(station_sn={redact_serial(self.station_sn)!r}, "
            f"p2p_did={redact(self.p2p_did)!r}, p2p_license={redact(self.p2p_license)!r}, "
            f"signaling_host={self.signaling_host!r}, firmware={self.firmware!r})"
        )
