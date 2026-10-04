"""Display text for settings: a short name and a label per choice.

The vendor's value maps carry a label per wire code, but not one a UI can show as it is:
typos (``"Hight"``, ``"4K UItra"``), Chinese (``"低"``), code names
(``"OPTIMAL_BATTERY_LIFE"``), stray spaces (``" logo"``), lost units (``"30"`` for 1800 s)
and terse words (``"close"`` for off, ``"hb"``). :func:`choice_label` turns them into
English: a curated table for the labels whose meaning is clear from the vendor data
itself, then mechanical clean-up (spacing, units, case). A label that still is not
English is shown as ``"Value <code>"``, never guessed.

:func:`setting_name` gives a vendor identifier a short title; curated where the
identifier is misleading (``disable_ptz_turn_switch`` is bound to
``APP_CMD_PRIVACY_ZONES_STATUS`` and sends ``PrivacyZoneSwitch``, so it is named after
its binding), mechanical otherwise.

Pure data and string functions.
"""

from __future__ import annotations

import re
from collections.abc import Mapping
from types import MappingProxyType
from typing import Final

#: Short titles for vendor identifiers. Only what the mechanical rule would get wrong
#: or leave unclear; everything else goes through :func:`_mechanical_name`.
SETTING_NAMES: Final[Mapping[str, str]] = MappingProxyType(
    {
        "ai_tracking_status": "AI tracking",
        "audio_recording_on_off": "Record audio",
        "detection_type_set": "Detection types",
        "device_cross_cam_assistance_switch": "Cross-camera assistance",
        "device_cross_cam_interval": "Cross-camera interval",
        "device_cross_cam_tracking_swtich": "Cross-camera tracking",
        "device_multiple_bridge_mode": "Bridge mode",
        "device_silent_ota_switch": "Silent firmware updates",
        "device_snooze_time": "Snooze",
        # The handler binds it to APP_CMD_PRIVACY_ZONES_STATUS (6248) and sends
        # {"PrivacyZoneSwitch": 0|1}: the identifier's name does not match what it does.
        "disable_ptz_turn_switch": "Privacy zones",
        "hb_connect_nas_storage_type": "NAS storage type",
        "hb_connect_nas_switch": "NAS storage",
        "hb_connect_storage_type": "Recording type",
        "hb_keypad_is_password_set": "Keypad password set",
        "led_on_off": "Status LED",
        "live_streaming_resolution": "Streaming quality",
        "motion_detection_status": "Motion detection",
        "nas_select_video_type": "NAS video type",
        "nas_stream_switch": "NAS streaming",
        "nightvision_type": "Night vision",
        "playback_play_speed": "Playback speed",
        "record_resolution": "Recording quality",
        "sensor_motion_pet_setting": "Pet setting",
        "spotlight_switch": "Spotlight",
        "time_format_set": "Clock format",
        "watermark_set": "Watermark",
    }
)

_VERSION_SUFFIX: Final = re.compile(r"__v\d+$")
_NAME_TAILS: Final = ("_on_off", "_switch", "_swtich", "_status", "_set")


def setting_name(identifier: str) -> str:
    """A short display title for a vendor identifier (never empty)."""
    base = _VERSION_SUFFIX.sub("", identifier)
    return SETTING_NAMES.get(base) or SETTING_NAMES.get(identifier) or _mechanical_name(base)


def _mechanical_name(identifier: str) -> str:
    for tail in _NAME_TAILS:
        if identifier.endswith(tail) and len(identifier) > len(tail):
            identifier = identifier[: -len(tail)]
            break
    words = identifier.replace("_", " ").split()
    text = " ".join(_ACRONYMS.get(w, w) for w in words)
    return _capitalise(text) or identifier


# ── choice labels ──────────────────────────────────────────────────────────────

#: Vendor labels (compared lower-case, whitespace collapsed) → display text. Typos,
#: Chinese, code names and terse words whose meaning the vendor data states itself.
_FIXES: Final[Mapping[str, str]] = MappingProxyType(
    {
        # typos
        "hight": "High",
        "4k uitra": "4K Ultra",
        "media": "Medium",
        "mid": "Medium",
        "controll": "Control",
        "cricuit": "Circuit",
        "week": "Weak",
        "continous": "Continuous",
        "log": "Logo",
        "camera sound & sotlight": "Camera sound & spotlight",
        # terse
        "close": "Off",
        "hb": "HomeBase",
        "route": "Router",
        "exist": "Present",
        "no exist": "Not present",
        "off(infrared)": "Off (infrared)",
        # code names
        "optimal_battery_life": "Optimal battery life",
        "optimal_surveillance": "Optimal surveillance",
        "balance_surveillance": "Balanced surveillance",
        "customize_recording": "Custom recording",
        "time_system_12": "12-hour",
        "time_system_24": "24-hour",
        "split_mode": "Split view",
        "upper_left": "Upper left",
        "main_lower_right": "Main camera, lower right",
        "second_lower_right": "Second camera, lower right",
        "homebasealarm": "HomeBase alarm",
        "camalarm": "Camera alarm",
        "lightalarm": "Light alarm",
        "monitoralarm": "Monitoring alarm",
        # Chinese
        "低": "Low",
        "中": "Medium",
        "高": "High",
        "不充电": "Not charging",
        "usb充电": "USB charging",
        "内置太阳能充电": "Built-in solar charging",
        "外置太阳能": "External solar panel",
        "外置+内置太阳能充电": "External and built-in solar charging",
        "usb+内置太阳能充电": "USB and built-in solar charging",
        "交流充电(doorbell)": "AC charging (doorbell)",
        "华氏度": "Fahrenheit",
        "摄氏度": "Celsius",
        "第一格": "Level 1",
        "第二格": "Level 2",
        "第三格": "Level 3",
        "第四格": "Level 4",
        "第五格": "Level 5",
        "180度": "Rotated 180°",
        "上下翻转": "Flipped vertically",
        "picture-in-picture(右上)": "Picture-in-picture, top right",
        "picture-in-picture(右下)": "Picture-in-picture, bottom right",
        "picture-in-picture(左上)": "Picture-in-picture, top left",
        "picture-in-picture(左下)": "Picture-in-picture, bottom left",
    }
)

#: Labels that are a bare number of a unit the vendor dropped, per identifier.
_UNIT_OF_BARE_NUMBER: Final[Mapping[str, str]] = MappingProxyType(
    {
        "device_cross_cam_interval": "min",  # "30" beside "15min" (code 1800 s)
        "device_alarm_duration": "s",  # codes 30, 60, 300, 600 are seconds
    }
)

#: Per-identifier labels where a word means something else than elsewhere.
_BY_IDENTIFIER: Final[Mapping[tuple[str, str], str]] = MappingProxyType(
    {
        ("device_snooze_time", "0min"): "Off",
    }
)

_ACRONYMS: Final[Mapping[str, str]] = MappingProxyType(
    {
        "ai": "AI",
        "led": "LED",
        "nas": "NAS",
        "ota": "OTA",
        "ptz": "PTZ",
        "hb": "HomeBase",
        "hdr": "HDR",
        "pir": "PIR",
        "rtsp": "RTSP",
        "wifi": "Wi-Fi",
        "usb": "USB",
    }
)

_UNIT: Final = re.compile(r"^(\d+(?:\.\d+)?)\s*(min|mins|s|hour|hours|hz|x|ft)$", re.IGNORECASE)
_WITHIN_FEET: Final = re.compile(r"^within (\d+)\s*ft$", re.IGNORECASE)
_MINUTES_ZH: Final = re.compile(r"^(\d+)分钟$")
_BC_PREFIX: Final = re.compile(r"^BC(?:TabBarFunction|LiveVideoNavigationBarRightBtnsType)")
_CAMEL: Final = re.compile(r"(?<=[a-z])(?=[A-Z])|(?<=[A-Z])(?=[A-Z][a-z])")
_SPACES: Final = re.compile(r"\s+")
_SHOUTED: Final = re.compile(r"^[A-Z]{2,}$")
_KEEP_UPPER: Final = frozenset(
    {"HD", "UHD", "AAC", "ACC", "PCM", "EU", "US", "AI", "HDR", "LED", "PTZ", "NAS", "USB"}
)
#: Words spelt one way in display text, whatever the vendor wrote.
_WORD_FIXES: Final[Mapping[str, str]] = MappingProxyType(
    {"homebase": "HomeBase", "nas": "NAS", "controll": "Control", "ptz": "PTZ"}
)
_DISPLAY_EXTRA: Final = frozenset("°")


def choice_label(identifier: str, code: int, vendor: str) -> str:
    """The display text for one vendor label (never empty; ``"Value <code>"`` when the
    label is empty or not English after curation)."""
    text = _SPACES.sub(" ", vendor).strip()
    key = text.lower()
    base = _VERSION_SUFFIX.sub("", identifier)
    if (base, key) in _BY_IDENTIFIER:
        return _BY_IDENTIFIER[(base, key)]
    if key in _FIXES:
        return _FIXES[key]
    if (m := _MINUTES_ZH.match(text)) is not None:
        return f"{m.group(1)} min"
    if text.isdigit() and base in _UNIT_OF_BARE_NUMBER:
        return _with_unit(text, _UNIT_OF_BARE_NUMBER[base])
    if (m := _UNIT.match(text)) is not None:
        return _with_unit(m.group(1), m.group(2).lower())
    if (m := _WITHIN_FEET.match(text)) is not None:
        return f"Within {m.group(1)} ft"
    text = _words(text)
    if (
        not text
        or not text.isprintable()
        or any(not ch.isascii() and ch not in _DISPLAY_EXTRA for ch in text)
    ):
        return f"Value {code}"
    return _capitalise(text)


def _with_unit(number: str, unit: str) -> str:
    if unit in ("hour", "hours"):
        return f"{number} hour" + ("" if number == "1" else "s")
    if unit in ("min", "mins"):
        return f"{number} min"
    if unit == "hz":
        return f"{number} Hz"
    if unit == "x":
        return f"{number}x"
    return f"{number} {unit}"


def _words(text: str) -> str:
    """Code-name clean-up: a ``BCTabBarFunction`` prefix, ``snake_case`` and CamelCase
    become words; shouted words lose their caps (acronyms keep them)."""
    text = _BC_PREFIX.sub("", text)
    if "_" in text and " " not in text:
        text = text.replace("_", " ")
    elif " " not in text and _CAMEL.search(text):
        text = _CAMEL.sub(" ", text)
    words = []
    for raw in text.split(" "):
        word = raw.lower() if _SHOUTED.match(raw) and raw not in _KEEP_UPPER else raw
        words.append(_WORD_FIXES.get(word.lower(), word))
    return " ".join(words)


def _capitalise(text: str) -> str:
    return text[:1].upper() + text[1:] if text else text
