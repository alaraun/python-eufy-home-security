"""Verification status: how much is known about a device model, a capability or an event.

:class:`Support` / :class:`Evidence` grade a model, a profile's capability or an event
field. Settings carry no grade: they come from the generated per-model files.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import StrEnum


class Support(StrEnum):
    """How a model, capability or event is known to work.

    Only ``VERIFIED`` entries should be exposed to end users by default.
    """

    VERIFIED = "verified"
    """Proven on real hardware: a live capture, or a live write plus read-back."""
    DECLARED = "declared"
    """Present in the app's own code or enums, not yet proven on hardware."""
    UNKNOWN = "unknown"
    """Seen but not understood, or known not to work."""


@dataclass(frozen=True, slots=True)
class Evidence:
    """A support status with its provenance.

    ``source`` says how the status was established (never a real identifier);
    ``note`` carries caveats a consumer should know about.
    """

    support: Support
    source: str
    note: str = ""
