"""Supported test doubles for code built on this library (a Home Assistant integration).

Never imported by the package itself: import it from a test suite only.

- :data:`SYNTHETIC`: the synthetic identities (serials, DID, keys, account) the fakes
  use; never a real identifier.
- :class:`FakeStation`: a HomeBase speaking PPPP/XZYH on loopback, handshake to media.
- :class:`FakeCloud`: the eufy cloud answered below the HTTP envelope.
- :func:`v1_still`: a JPEG as a standalone camera's obfuscated V1 still.
- :func:`warm_store`: a cache document as after one login.
- :func:`build_eufy_security`: a real :class:`~eufy_home_security.EufySecurity` wired
  to the fakes.
- :func:`short_timeouts`: the library's hardware waits shortened for a test.
"""

from __future__ import annotations

from .cloud import (
    FakeCloud,
    build_eufy_security,
    camera_device,
    security_device,
    security_station,
    station_device,
    warm_store,
)
from .station import FakeStation, v1_still
from .synthetic import SYNTHETIC, Synthetic
from .timeouts import short_timeouts

__all__ = [
    "SYNTHETIC",
    "FakeCloud",
    "FakeStation",
    "Synthetic",
    "build_eufy_security",
    "camera_device",
    "security_device",
    "security_station",
    "short_timeouts",
    "station_device",
    "v1_still",
    "warm_store",
]
