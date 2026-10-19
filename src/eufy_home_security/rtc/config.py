"""What an RTC signaling client needs to know about one station.

The inputs come from the station's cloud device-list entry (``signaling_servers``,
``p2p_did``, ``p2p_license``, ``main_sw_version``, ``webrtc_sdk_version``) and the
account (user id, an app install id). The signaling host is the first bare IPv4
entry of ``signaling_servers``; a domain entry is only a cache key and is never
resolved.
"""

from __future__ import annotations

import ipaddress
import re
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Final

from .._logging import redact, redact_serial

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


def firmware_number(version: str | None) -> int | None:
    """``main_sw_version`` with the dots removed, as an int (``"3.8.7.4"`` -> 3874)."""
    if not version:
        return None
    digits = version.replace(".", "")
    return int(digits) if digits.isdigit() else None


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
            len(self.session_key) == 16
            and len(self.contact_id) == 32
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
        entry lacks a serial, a DID, a license or an IPv4 signaling server."""
        servers = raw.get("signaling_servers")
        servers = servers if isinstance(servers, list) else []
        sn, did, lic = raw.get("device_sn"), raw.get("p2p_did"), raw.get("p2p_license")
        host = signaling_ipv4(servers)
        if not (isinstance(sn, str) and sn and isinstance(did, str) and did):
            return None
        if not (isinstance(lic, str) and lic and host):
            return None
        sdk = raw.get("webrtc_sdk_version")
        version = raw.get("main_sw_version")
        return cls(
            station_sn=sn,
            p2p_did=did,
            p2p_license=lic,
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
