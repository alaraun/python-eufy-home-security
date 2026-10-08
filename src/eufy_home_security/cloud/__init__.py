"""The eufy cloud (eufy_mega backend): login, device list, cipher keys, push registration."""

from __future__ import annotations

from typing import TYPE_CHECKING

from .._lazy import lazy_exports

if TYPE_CHECKING:
    from .api import EufyCloudApi
    from .const import CIPHER_ID_P2P, CloudCode, cluster_host
    from .models import CipherRecord, CloudDevice, CloudHouse, CloudInvite, LoginCountry

__all__ = [
    "CIPHER_ID_P2P",
    "CipherRecord",
    "CloudCode",
    "CloudDevice",
    "CloudHouse",
    "CloudInvite",
    "EufyCloudApi",
    "LoginCountry",
    "cluster_host",
]

__getattr__, __dir__ = lazy_exports(
    __name__,
    globals(),
    {
        "EufyCloudApi": "api",
        **dict.fromkeys(("CIPHER_ID_P2P", "CloudCode", "cluster_host"), "const"),
        **dict.fromkeys(
            ("CipherRecord", "CloudDevice", "CloudHouse", "CloudInvite", "LoginCountry"), "models"
        ),
    },
)
