"""The UI sections every setting belongs to: one fixed, ordered catalogue.

Each bundled setting carries the id of one section (:attr:`.model_settings.Setting.section`),
assigned by the settings-file generator from the eufy app's page for the setting, else
from its identifier. A UI builds its tabs or headings from these ids and places them by
:attr:`SettingSection.order`; see docs/how-to/home-assistant.md § Grouping settings in a UI.
Ids are stable across releases; a new section may be added at any ``order``.
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Final

from ..exceptions import UnsupportedError

__all__ = [
    "MODES_SECTION",
    "OTHER_SECTION",
    "SETTING_SECTIONS",
    "SettingSection",
    "setting_section",
]


@dataclass(frozen=True, slots=True)
class SettingSection:
    """One UI section: a stable lower-case ``id``, an English ``heading`` in sentence
    case and the display ``order`` (ascending; gaps leave room for new sections).

    ``alarm_affecting`` marks a section whose settings change how or whether the
    alarm sounds (:attr:`.model_settings.Setting.alarm_affecting`).
    """

    id: str
    heading: str
    order: int
    alarm_affecting: bool = False


SETTING_SECTIONS: Final[tuple[SettingSection, ...]] = (
    # Night vision, image, lights and indicator LEDs, watermark, orientation.
    SettingSection("picture", "Picture", 10),
    # Motion, sound, radar and AI detection, zones, package guard, cross-camera tracking.
    SettingSection("detection", "Detection", 20),
    # Recording and streaming quality, clip length, continuous recording, audio recording.
    SettingSection("recording", "Recording", 30),
    # Microphone, speaker and their volumes, two-way talk.
    SettingSection("audio", "Audio", 40),
    # Working mode, power source, battery and solar.
    SettingSection("power", "Power", 50),
    # Pan/tilt speed, tracking, cruise, presets and calibration.
    SettingSection("ptz", "Pan & tilt", 60),
    # Push notifications, their types, intervals and snooze.
    SettingSection("notifications", "Notifications", 70),
    # Chimes, ringtones, quick and automatic responses.
    SettingSection("doorbell", "Doorbell & chime", 80),
    # Siren, alarm tone and volume, prompts, anti-theft, SOS and panic.
    SettingSection("alarm", "Alarm", 90, alarm_affecting=True),
    # Guard modes, schedule, keypad, and the per-mode delays and device actions.
    SettingSection("modes", "Modes", 100, alarm_affecting=True),
    # Local, HomeBase, NAS, SD-card and cloud storage.
    SettingSection("storage", "Storage", 110),
    # Wi-Fi, bridges, the HomeBase link, addresses, HomeKit and streaming protocols.
    SettingSection("network", "Network", 120),
    # Name, time zone and format, firmware updates, device information and status.
    SettingSection("system", "System", 130),
    # A setting no other section fits.
    SettingSection("other", "Other", 140),
)
"""Every section in display order."""

OTHER_SECTION: Final = "other"
"""The fallback section."""
MODES_SECTION: Final = "modes"
"""The section of the per-mode delays and device actions a paired device carries."""

_BY_ID: Final = MappingProxyType({s.id: s for s in SETTING_SECTIONS})


def setting_section(section_id: str) -> SettingSection:
    """The catalogue entry of ``section_id``; ``UnsupportedError`` for an unknown id."""
    try:
        return _BY_ID[section_id]
    except KeyError:
        raise UnsupportedError(
            f"unknown setting section {section_id!r}; known: {', '.join(_BY_ID)}"
        ) from None
