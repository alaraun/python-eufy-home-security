"""What each device model can do, and how well that is proven.

A :class:`DeviceProfile` is the per-model answer to "may the library offer this?".
Hardware without a profile gets the generic profile for its kind, where every
capability is ``UNKNOWN`` — it degrades to "not offered", never to a guess.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final

from ..models import (
    PARAM_BATTERY,
    PARAM_DEVICE_NAME,
    PARAM_EMMC_USED_PERCENT,
    PARAM_FIRMWARE,
    PARAM_HUB_NAME,
    PARAM_LAN_IP,
    PARAM_PIR_EVENT_MS,
    PARAM_SUB1G_RSSI,
    PARAM_WIFI_RSSI,
    GuardMode,
)
from ..p2p.params import GUARD_MODE_PARAM
from .support import Evidence, Support
from .types import MODELS, DeviceKind, model_for_serial


class Capability(StrEnum):
    """A feature a device may offer."""

    GUARD_MODE_READ = "guard_mode_read"
    GUARD_MODE_WRITE = "guard_mode_write"
    PARAM_DUMP = "param_dump"
    LOCAL_EVENTS = "local_events"
    """Events pushed by the station over the P2P session."""
    CLOUD_EVENTS = "cloud_events"
    """Events relayed by the eufy cloud over FCM."""
    EVENT_HISTORY = "event_history"
    """The station's own event database, queried over P2P."""
    SNAPSHOT_FETCH = "snapshot_fetch"
    """An event's still image, fetched from the station's disk by path."""
    LIVE_KEYFRAME = "live_keyframe"
    LIVE_STREAM = "live_stream"
    RECORDING_DOWNLOAD = "recording_download"
    SETTINGS_WRITE = "settings_write"
    BATTERY = "battery"
    RSSI = "rssi"
    PIR_EVENT_TIME = "pir_event_time"
    """The time of a motion sensor's last PIR event (param 1605)."""
    PTZ_PRESETS = "ptz_presets"
    """Pan/tilt preset slots: read them, turn the camera to one, take its live image."""
    PTZ_CONTROL = "ptz_control"
    """Pan/tilt the camera by one step, and store or delete a preset slot (6030/6032/6033)."""
    PTZ_ZOOM = "ptz_zoom"
    """Zoom the picture (6203) and follow the zoom the camera reports."""


@dataclass(frozen=True, slots=True, kw_only=True)
class DeviceProfile:
    """The capabilities and readable parameters of one model.

    A model's settings come from its bundled settings file
    (:func:`~.model_settings.settings_of`), not from the profile.

    ``params`` names parameters of the device's block in the station's parameter
    dump (``dev_type`` 255 for the station, the channel for a sub-device).
    ``kind_markers`` are parameter ids whose presence on a block marks a device of
    this model's kind when its serial is unknown (see :func:`kind_from_params`).
    """

    model: str
    capabilities: Mapping[Capability, Evidence]
    params: Mapping[str, int]
    kind_markers: frozenset[int] = frozenset()

    def support(self, capability: Capability) -> Support:
        """The support status of ``capability``; ``UNKNOWN`` when not listed."""
        evidence = self.capabilities.get(capability)
        return Support.UNKNOWN if evidence is None else evidence.support


_HB3 = "T8030 HomeBase 3"
_CAM3 = "T8160 eufyCam 3"

# Every VERIFIED entry is traced in docs/reference/hardware-verification.md
# (tests/devices/test_capabilities.py keeps the two in step).
_T8030 = DeviceProfile(
    model="T8030",
    capabilities=MappingProxyType(
        {
            Capability.PARAM_DUMP: Evidence(
                Support.VERIFIED, f"live P2P parameter dump, {_HB3} fw 3.8.6.0 and 3.8.7.4"
            ),
            Capability.GUARD_MODE_READ: Evidence(
                Support.VERIFIED,
                f"live: param 1224 in the parameter dump across app and P2P arms, {_HB3} fw 3.8.7.4",
                "a change is also reported over P2P (0x047f alarm-mode report); arming to the "
                "mode already in force is silent, so settle it by reading the dump",
            ),
            Capability.GUARD_MODE_WRITE: Evidence(
                Support.VERIFIED,
                f"live arm Away -> Home -> Away with dump read-back, {_HB3} fw 3.8.7.4",
                "commands must carry the station owner's account id",
            ),
            Capability.LOCAL_EVENTS: Evidence(
                Support.VERIFIED,
                f"live P2P push (cmd 2037) of camera detections, standalone probe client, {_HB3} fw 3.8.6.0 + {_CAM3}",
                "library delivery verified on fw 3.8.7.4 (verification log); guard-mode "
                "changes arrive as the separate 0x047f report",
            ),
            Capability.CLOUD_EVENTS: Evidence(
                Support.VERIFIED,
                f"live FCM delivery of arm/disarm: a standalone probe client, and through the library on {_HB3} "
                "fw 3.8.7.4 (about 1 s after the P2P report)",
                "the eufy app re-registering its push token can orphan ours: never the only "
                "source of state",
            ),
            Capability.EVENT_HISTORY: Evidence(
                Support.VERIFIED,
                f"live CMD_DATABASE 1306 query 10000 on history_record_info, {_HB3} fw 3.8.7.4",
                "a firmware update clears the history; query 10017 answers ERROR_NO_SUPPORT",
            ),
            Capability.SETTINGS_WRITE: Evidence(
                Support.VERIFIED,
                f"live write+read-back of time_system, {_HB3} fw 3.8.7.4",
                "the write+read-back proves the value persists; its meaning is confirmed by "
                "the eufy app showing the 24-hour clock while the station reported 1253 = 1 "
                "(seen in the eufy app)",
            ),
        }
    ),
    params=MappingProxyType(
        {
            "guard_mode": GUARD_MODE_PARAM,
            "name": PARAM_HUB_NAME,
            "lan_ip": PARAM_LAN_IP,
            "emmc_used_percent": PARAM_EMMC_USED_PERCENT,
            "sub_device_serials": 1072,
            "country_code": 14000,
        }
    ),
)

_T8160 = DeviceProfile(
    model="T8160",
    capabilities=MappingProxyType(
        {
            Capability.LOCAL_EVENTS: Evidence(
                Support.VERIFIED,
                f"live P2P push (cmd 2037) of person and vehicle detections, standalone probe client, {_CAM3} on {_HB3}",
            ),
            Capability.CLOUD_EVENTS: Evidence(
                Support.DECLARED,
                "app code relays detections over FCM",
                "not observed live: no detection happened during the FCM test window",
            ),
            Capability.SNAPSHOT_FETCH: Evidence(
                Support.VERIFIED,
                f"live IMAGE_NOTIFY 1308 fetch of a plain 640x360 JPEG, standalone probe client, {_CAM3} on "
                f"{_HB3} fw 3.8.6.0",
                "library fetch of thumb_path and crop_path verified on fw 3.8.7.4 (verification log)",
            ),
            Capability.LIVE_KEYFRAME: Evidence(
                Support.VERIFIED,
                f"live START_REALTIME_MEDIA 1003, 3840x2160 keyframe decoded, {_CAM3} on {_HB3}",
                "wakes a battery camera",
            ),
            Capability.LIVE_STREAM: Evidence(
                Support.VERIFIED,
                f"live HEVC 3840x2160 video + AAC audio decoded, {_CAM3} on {_HB3}",
                "few concurrent P2P sessions: idle extra sessions starve media opens",
            ),
            Capability.RECORDING_DOWNLOAD: Evidence(
                Support.VERIFIED,
                f"live DOWNLOAD_VIDEO 1024 of an event recording, {_CAM3} on {_HB3}",
            ),
            Capability.SETTINGS_WRITE: Evidence(
                Support.VERIFIED,
                f"live write+read-back, {_CAM3} on {_HB3} fw 3.8.7.4",
                "rests on pir_sensitivity, motion_sensitivity, retrigger_interval, clip_length, "
                "speaker_volume, streaming_quality and night_vision codes 0/1 (standalone probe "
                "client) and 2 and 3 (library), and power_mode codes 0-3 (library and a private "
                "probe, with the app label of each observed), written with read-back (keys as "
                "the verification log names them); the settings proven only by a write round "
                "trip are not part of the claim",
            ),
            Capability.BATTERY: Evidence(
                Support.VERIFIED, f"live parameter dump (param 1101), {_CAM3} fw 3.4.3.0"
            ),
            Capability.RSSI: Evidence(
                Support.VERIFIED, f"live parameter dump (param 1142), {_CAM3} fw 3.4.3.0"
            ),
        }
    ),
    params=MappingProxyType(
        {
            "battery": PARAM_BATTERY,
            "wifi_rssi": PARAM_WIFI_RSSI,
            "name": PARAM_DEVICE_NAME,
            "firmware": PARAM_FIRMWARE,
        }
    ),
    # SET_FLOODLIGHT_MANUAL_SWITCH / _BRIGHT_VALUE: present on a camera's block,
    # never on a sensor's. A camera without a light lacks them.
    kind_markers=frozenset({1400, 1401}),
)

_T8910_DUMPS = (
    "three live parameter dumps of a T8910 on a T8030 HomeBase 3 fw 3.8.7.4, from a "
    "sensor offline for months: the value never changed, so it is not proven to track"
)

_T8910 = DeviceProfile(
    model="T8910",
    capabilities=MappingProxyType(
        {
            Capability.BATTERY: Evidence(
                Support.DECLARED, "eufy app GET_BATTERY (param 1101)", _T8910_DUMPS
            ),
            Capability.RSSI: Evidence(
                Support.DECLARED,
                "eufy app GET_SUB1G_RSSI (param 1141), the sensor's only signal parameter",
                _T8910_DUMPS,
            ),
            Capability.PIR_EVENT_TIME: Evidence(
                Support.DECLARED,
                "eufy app MOTION_SENSOR_PIR_EVT (param 1605)",
                "epoch ms on the sensor's block only in the same dumps; whether it moves on "
                "motion past a working sensor is untested, so it is no last-seen time",
            ),
        }
    ),
    params=MappingProxyType(
        {
            "battery": PARAM_BATTERY,
            "sub1g_rssi": PARAM_SUB1G_RSSI,
            "pir_event_ms": PARAM_PIR_EVENT_MS,
        }
    ),
    # MOTION_SENSOR_BAT_STATE, _PIR_EVT, _SET_PIR_SENSITIVITY: on a sensor's block only.
    kind_markers=frozenset({1601, PARAM_PIR_EVENT_MS, 1609}),
)


_T8170_SOLO = "T8170 Battery SoloCam, standalone, fw 3.3.5.4"

_T8170 = DeviceProfile(
    model="T8170",
    capabilities=MappingProxyType(
        {
            Capability.PARAM_DUMP: Evidence(
                Support.VERIFIED,
                f"live P2P parameter dump through the library, {_T8170_SOLO}",
                "the camera sleeps: it answers only once woken through its rendezvous servers",
            ),
            Capability.GUARD_MODE_READ: Evidence(
                Support.VERIFIED, f"live: param 1224 in the parameter dump, {_T8170_SOLO}"
            ),
            Capability.GUARD_MODE_WRITE: Evidence(
                Support.VERIFIED,
                f"live Disarmed -> Home -> Disarmed with dump read-back, {_T8170_SOLO}",
            ),
            Capability.LIVE_KEYFRAME: Evidence(
                Support.VERIFIED,
                f"live keyframe through the handler's 1700/1000 open, {_T8170_SOLO}",
                "the station's 1350/1003 open is taken but never streams on this camera",
            ),
            Capability.LIVE_STREAM: Evidence(
                Support.VERIFIED,
                f"live video through the handler's 1700/1000 open and bare 1004 stop, {_T8170_SOLO}",
            ),
            Capability.PTZ_PRESETS: Evidence(
                Support.VERIFIED,
                f"live preset query (6034) and go-to (6035) with a live image per preset, {_T8170_SOLO}",
                "the camera is left at the preset; read the slots while it is awake",
            ),
            Capability.PTZ_CONTROL: Evidence(
                Support.VERIFIED,
                f"live one-step pan/tilt (6030) and store/delete a slot (6032/6033), {_T8170_SOLO}",
                "at most 5 slots are stored; a store while full is receipted but does nothing",
            ),
            Capability.PTZ_ZOOM: Evidence(
                Support.VERIFIED,
                f"live picture zoom 1-12 (6203) with its echo, measured in the stream, {_T8170_SOLO}; "
                "4x and 8x also paired to a HomeBase 3 fw 3.8.7.4",
                "the library accepts 1-12; the camera caps near 14x; single view only; a go-to, "
                "the idle return or a reopened view resets it to 1x",
            ),
            Capability.SETTINGS_WRITE: Evidence(
                Support.VERIFIED,
                f"live write + independent dump read-back + restore through the library, "
                f"with the eufy app display checked, {_T8170_SOLO}",
                "rests on detection_sensitivity (6070), "
                "motion_detection_status (6040), led_on_off (6014), nightvision_type (1277), "
                "audio_recording_on_off (6012), ai_tracking_status (6016) and "
                "live_streaming_resolution (2730), app labels observed; disable_ptz_turn_switch "
                "(6248) and spotlight_switch (1400) round-tripped with the app label unobserved; "
                "the model's other settings are not part of "
                "the claim",
            ),
        }
    ),
    params=MappingProxyType({}),
)


def _register(registry: dict[str, DeviceProfile], *profiles: DeviceProfile) -> None:
    for entry in profiles:
        if entry.model in registry:
            raise ValueError(f"duplicate device profile {entry.model}")
        registry[entry.model] = entry


_profiles: dict[str, DeviceProfile] = {}
_register(_profiles, _T8030, _T8160, _T8910, _T8170)

PROFILES: Final[Mapping[str, DeviceProfile]] = MappingProxyType(_profiles)

_GUARD_WRITE_LIVE = Evidence(
    Support.VERIFIED,
    "live guard-mode transitions through the library, T8030 HomeBase 3 fw 3.8.7.4",
    "each reported over P2P (0x047f) and read back from the parameter dump",
)

GUARD_MODE_EVIDENCE: Final[Mapping[GuardMode, Evidence]] = MappingProxyType(
    {
        GuardMode.AWAY: _GUARD_WRITE_LIVE,
        GuardMode.HOME: _GUARD_WRITE_LIVE,
        GuardMode.CUSTOM_1: _GUARD_WRITE_LIVE,
        GuardMode.OFF: Evidence(
            Support.DECLARED,
            "eufy app guard-mode enum (GUARD_TYPE_OFF = 6)",
            "no use found in the app and never reported by a station; report-only: "
            "the library refuses to write it and disarms with 63",
        ),
        GuardMode.DISARMED: _GUARD_WRITE_LIVE,
    }
)
"""Guard modes with recorded evidence; a mode not listed has none recorded."""

_NO_PROFILE = Evidence(Support.UNKNOWN, "no profile for this model")

KIND_MARKERS: Final[Mapping[DeviceKind, frozenset[int]]] = MappingProxyType(
    {
        kind: frozenset().union(
            *(p.kind_markers for p in PROFILES.values() if MODELS[p.model].kind is kind)
        )
        for kind in DeviceKind
    }
)
"""Every profile's kind markers, merged per kind (measured on one camera and one
sensor model only)."""

FALLBACK_PROFILES: Final[Mapping[DeviceKind, DeviceProfile]] = MappingProxyType(
    {
        kind: DeviceProfile(
            model=f"generic {kind}",
            capabilities=MappingProxyType(dict.fromkeys(Capability, _NO_PROFILE)),
            params=MappingProxyType({}),
            kind_markers=KIND_MARKERS[kind],
        )
        for kind in DeviceKind
    }
)


def kind_from_params(params: Mapping[int, object]) -> DeviceKind | None:
    """The device kind a sub-device block's parameters mark, for a block without a
    catalogued serial; ``None`` when no kind or more than one kind is marked.

    Prefer :func:`~.types.model_for_serial` whenever the serial is known.
    """
    kinds = [kind for kind, markers in KIND_MARKERS.items() if not markers.isdisjoint(params)]
    return kinds[0] if len(kinds) == 1 else None


def profile_for_serial(serial: str) -> DeviceProfile | None:
    """The profile for a serial's model.

    A model in the catalog without its own profile gets the generic profile for
    its kind; a serial whose model is not catalogued at all returns ``None``
    (use ``FALLBACK_PROFILES`` for the kind the caller believes it has).
    """
    model = model_for_serial(serial)
    if model is None:
        return None
    return PROFILES.get(model.model, FALLBACK_PROFILES[model.kind])
