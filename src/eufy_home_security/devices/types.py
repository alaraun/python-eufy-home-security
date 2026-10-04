"""Device models, keyed by serial-number prefix."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import StrEnum
from types import MappingProxyType
from typing import Final

from .support import Evidence, Support

SERIAL_PREFIX_LEN: Final = 5


class DeviceKind(StrEnum):
    """What role a device plays in a eufy Security system."""

    STATION = "station"
    CAMERA = "camera"
    SENSOR = "sensor"
    KEYPAD = "keypad"
    DOORBELL = "doorbell"
    LOCK = "lock"
    OTHER = "other"


@dataclass(frozen=True, slots=True, kw_only=True)
class DeviceModel:
    """One hardware model.

    ``model`` is the serial-number prefix (``"T8030"``). ``cloud_device_type`` is
    the ``device_type`` the cloud device list reports, recorded only where a source
    states it.
    """

    model: str
    name: str
    kind: DeviceKind
    cloud_device_type: int | None
    evidence: Evidence


def _register(registry: dict[str, DeviceModel], *models: DeviceModel) -> None:
    for entry in models:
        if len(entry.model) != SERIAL_PREFIX_LEN:
            raise ValueError(f"model {entry.model!r} is not a {SERIAL_PREFIX_LEN}-char prefix")
        if entry.model in registry:
            raise ValueError(f"duplicate device model {entry.model}")
        registry[entry.model] = entry


_APP_SN_CONSTANTS = "eufy app SnConstants"

_models: dict[str, DeviceModel] = {}
_register(
    _models,
    DeviceModel(
        model="T8030",
        name="HomeBase 3 (S380)",
        kind=DeviceKind.STATION,
        cloud_device_type=18,
        evidence=Evidence(
            Support.VERIFIED,
            "live P2P sessions, HomeBase 3 fw 3.8.6.0 and 3.8.7.4",
            "device_type 18 is from the cloud device list; event-push and event-database "
            "records for the same station carry device_type 43",
        ),
    ),
    DeviceModel(
        model="T8160",
        name="eufyCam 3 (S330)",
        kind=DeviceKind.CAMERA,
        cloud_device_type=19,
        evidence=Evidence(
            Support.VERIFIED,
            "live settings write+read-back and media on T8030 HomeBase 3, camera fw 3.4.3.0",
            "device_type 19 is carried by live event pushes and matches the eufy app SnUtils type map",
        ),
    ),
    DeviceModel(
        model="T8161",
        name="eufyCam 3C",
        kind=DeviceKind.CAMERA,
        cloud_device_type=23,
        evidence=Evidence(
            Support.DECLARED,
            f"{_APP_SN_CONSTANTS} CAMERA3C; eufy app SnUtils type map (23)",
        ),
    ),
    DeviceModel(
        model="T8910",
        name="Outdoor motion sensor",
        kind=DeviceKind.SENSOR,
        cloud_device_type=10,
        evidence=Evidence(
            Support.UNKNOWN,
            "cloud device list: a T8910 paired to a HomeBase 3 reports device_type 10; "
            "its battery is in the station's parameter dump",
            "no eufy app source ties the prefix to a model; the name is inferred from the type",
        ),
    ),
    DeviceModel(
        model="T8170",
        name="Battery SoloCam (T8170)",
        kind=DeviceKind.CAMERA,
        cloud_device_type=48,
        evidence=Evidence(
            Support.DECLARED,
            f"{_APP_SN_CONSTANTS} BATTERY_SOLO_CAM_8170; eufy app SnUtils type map (48)",
            "a standalone camera, its own station; the cloud device list reports "
            "device_type 48 and the parameter dump labels its block 48",
        ),
    ),
    DeviceModel(
        model="T8010",
        name="HomeBase 2",
        kind=DeviceKind.STATION,
        cloud_device_type=None,
        evidence=Evidence(
            Support.DECLARED,
            f"{_APP_SN_CONSTANTS} STATION_2",
            "eufy app SnUtils files T8001/T8002/T8010/T8020 under one shared type 0",
        ),
    ),
    DeviceModel(
        model="T8002",
        name="HomeBase 1",
        kind=DeviceKind.STATION,
        cloud_device_type=None,
        evidence=Evidence(
            Support.DECLARED,
            f"{_APP_SN_CONSTANTS} STATION_AI",
            "the eufy app constant calls this prefix STATION_AI",
        ),
    ),
)

MODELS: Final[Mapping[str, DeviceModel]] = MappingProxyType(_models)

#: Serial prefixes the eufy app never keeps a P2P session to: it connects them only
#: while the user has one open, and its watchdog does not reconnect them (battery
#: SoloCams, battery doorbells, trackers, locks). A prefix, not a catalog model:
#: most of them are not catalogued.
ON_DEMAND_PREFIXES: Final = frozenset(
    {
        "T7400", "T7401", "T8110", "T8115", "T8122", "T8123", "T8124", "T8130", "T8131",
        "T8134", "T814X", "T8150", "T8151", "T8152", "T8153", "T8170", "T8171", "T8173",
        "T8214", "T8500", "T8501", "T8502", "T8503", "T8506", "T8510", "T8520", "T8531",
        "T85V0", "T86P2", "T8790", "T87B0", "T87B1", "T87B2", "T87B3", "T87B4", "T87B5",
        "T8B00",
    }
)  # fmt: skip
ON_DEMAND_EVIDENCE: Final = Evidence(
    Support.DECLARED,
    "eufy app PlatformP2PClientKt.getConnectBlackList (= P2PConfigManager.getFilter), used by "
    "P2PWatchDog and needAutoReconnectP2P",
    "the app reconnects every other station's session every 60 s while it is in the "
    "foreground, and closes every session 120 s after it leaves",
)


def serial_prefix(serial: str) -> str | None:
    """The 5-character model prefix of ``serial`` (``"T8160"``), catalogued or not;
    ``None`` for a serial shorter than a prefix."""
    prefix = serial.strip().upper()[:SERIAL_PREFIX_LEN]
    return prefix if len(prefix) == SERIAL_PREFIX_LEN else None


def model_for_serial(serial: str) -> DeviceModel | None:
    """The model a serial number belongs to, by its 5-character prefix."""
    prefix = serial_prefix(serial)
    return None if prefix is None else MODELS.get(prefix)


def connects_on_demand(serial: str) -> bool:
    """Whether a station is reached only on demand, never over a held session
    (:data:`ON_DEMAND_PREFIXES`): a battery device a held session would keep awake."""
    return serial_prefix(serial) in ON_DEMAND_PREFIXES
