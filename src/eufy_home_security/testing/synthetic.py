"""The synthetic identities every fake and test uses: the one canonical definition.

None of these is real. Real serials, P2P ids, account ids and LAN addresses must
never appear in a repository (the library checks its own tree against a private
denylist). The fake serial and DID are shaped like real ones so key derivation still
yields the 16-byte static key: ``serial[-7:] + did_text[7:16]``.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Final


@dataclass(frozen=True, slots=True, kw_only=True)
class Synthetic:
    """A set of synthetic identities for one account with one station and one camera."""

    station_sn: str
    camera_sn: str
    did: str
    static_key: bytes
    """The ECB static key derived from ``station_sn`` and ``did``."""
    session_key: bytes
    """The 32-byte GCM session key the fake station hands out."""
    account_id: str
    """The station owner's cloud user id (``member.admin_user_id``)."""
    email: str
    password: str
    station_ip: str
    """A documentation-range (RFC 5737) address: never a real LAN."""
    disk_serial: str
    """The drive serial in the fake station's storage record."""
    disk_label: str
    """The file-system label in the fake station's storage record."""


SYNTHETIC: Final = Synthetic(
    station_sn="T8030P2000012345",
    camera_sn="T8160P2000067890",
    did="EUPRAMA-123456-ABCDE",
    static_key=b"0012345-123456-A",
    session_key=b"0123456789abcdef0123456789abcdef",
    account_id="0123456789abcdef0123456789abcdef01234567",
    email="user@example.com",
    password="synthetic-password",  # noqa: S106 - a synthetic credential
    station_ip="192.0.2.10",
    disk_serial="SYNTHDISK0000001",
    disk_label="hdd_00000000000000000000000000000001",
)
