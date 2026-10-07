"""Asyncio client for eufy Security: local P2P to the HomeBase, the eufy cloud, and push events."""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from . import _logging as _logging  # installs the NullHandler and wire-logger defaults
from ._lazy import lazy_exports

if TYPE_CHECKING:
    from ._logging import redact, redact_serial, set_secret_logging, set_wire_logging
    from .client import EufySecurity, ModelStatus, SkippedDevice
    from .cloud.models import CloudDevice, FirmwareUpdate
    from .cloud.status import CloudStatus, LoginNeed, RegionStatus, StationRefreshStatus
    from .devices.model_settings import Setting, SettingControl, SettingKind
    from .devices.recipes import MAX_PRESET_SLOTS, MAX_ZOOM, MIN_ZOOM, PanTilt, PresetPosition
    from .devices.settings import SettingUnit
    from .events import (
        AccountMismatch,
        AlarmChanged,
        AlarmPhase,
        AlarmStopSource,
        ArmingSource,
        CameraBusyChanged,
        CloudProblem,
        ConnectionChanged,
        CredentialsRefreshed,
        DetectionType,
        DevicesChanged,
        DisconnectCause,
        Event,
        EventDeduplicator,
        EventScope,
        EventSource,
        GuardModeChanged,
        HistoryRecord,
        ParamChanged,
        PresetsChanged,
        PushChanged,
        PushMessageType,
        SecurityEvent,
        StationStateChanged,
        StorageChanged,
        ZoomChanged,
    )
    from .exceptions import (
        AuthenticationError,
        CameraWakeError,
        CipherUnavailableError,
        CloudApiError,
        CloudError,
        CommandError,
        CommandNotAppliedError,
        CommandRejectedError,
        CommandUnsupportedError,
        CommunicationError,
        DeviceBusyError,
        DeviceTimeoutError,
        EmptyResponseError,
        EufySecurityError,
        HandshakeError,
        KeyExchangeRefusedError,
        KeyRejectedError,
        LiveStreamLimitError,
        LoginChallengeError,
        LoginLimitedError,
        ModelDataError,
        NoCachedSessionError,
        PresetSlotsFullError,
        ProtocolError,
        RateLimitedError,
        RecordNotFoundError,
        RefreshCooldownError,
        SessionRejectedError,
        SessionReplacedError,
        StationUnreachableError,
        StillNotWrittenError,
        UnsupportedError,
    )
    from .identity import StationClaims, entity_unique_id
    from .images import IMAGE_SOURCES, CameraImage, ImageSource, ImageSourceInfo
    from .inclusion import Reach, StationChoice
    from .install import InstallState
    from .models import FrameCipher, GuardMode
    from .network import HostSource, LanPath, PathWarning, suggest_local_ports
    from .p2p.broadcast import DEFAULT_QUEUE_CHUNKS, FrameStream, ResizePolicy, StreamBroadcast
    from .p2p.clip import CLIP_CONTENT_TYPE, ClipWriter, MediaClip
    from .p2p.encoder import SETTLE_STANDALONE, SETTLE_STATION
    from .p2p.media import Still, StillFormat
    from .p2p.pppp import LAN_DISCOVERY_TIMEOUT
    from .p2p.session import (
        DEFAULT_STATION_SESSIONS,
        MIN_STATION_SESSIONS,
        STATION_SESSION_LIMIT,
        CommandOutcome,
        SessionStats,
    )
    from .p2p.storage_info import DiskInfo, EmmcInfo, StorageInfo, StorageMedium
    from .station import RemoteStation, SettingsCoverage, Station, StationState, SubDeviceState
    from .storage import (
        CACHE_LAYOUT_VERSION,
        JsonFileStore,
        MemoryStore,
        SessionCache,
        Store,
        async_forget_account,
    )

    __version__: str

# Resolved on first use (see _lazy): importing the package, or one submodule, does
# not load aiohttp, the cloud client or the push stack until something needs them.
_EXPORTS: dict[str, str] = {
    **dict.fromkeys(
        ("redact", "redact_serial", "set_secret_logging", "set_wire_logging"), "_logging"
    ),
    **dict.fromkeys(("EufySecurity", "ModelStatus", "SkippedDevice"), "client"),
    **dict.fromkeys(("CloudDevice", "FirmwareUpdate"), "cloud.models"),
    **dict.fromkeys(
        ("CloudStatus", "LoginNeed", "RegionStatus", "StationRefreshStatus"), "cloud.status"
    ),
    **dict.fromkeys(("Setting", "SettingControl", "SettingKind"), "devices.model_settings"),
    "SettingUnit": "devices.settings",
    **dict.fromkeys(
        ("MAX_PRESET_SLOTS", "MAX_ZOOM", "MIN_ZOOM", "PanTilt", "PresetPosition"), "devices.recipes"
    ),
    **dict.fromkeys(
        ("DEFAULT_QUEUE_CHUNKS", "FrameStream", "ResizePolicy", "StreamBroadcast"), "p2p.broadcast"
    ),
    **dict.fromkeys(("CLIP_CONTENT_TYPE", "ClipWriter", "MediaClip"), "p2p.clip"),
    **dict.fromkeys(("SETTLE_STANDALONE", "SETTLE_STATION"), "p2p.encoder"),
    **dict.fromkeys(
        (
            "AccountMismatch",
            "AlarmChanged",
            "AlarmPhase",
            "AlarmStopSource",
            "ArmingSource",
            "CameraBusyChanged",
            "CloudProblem",
            "ConnectionChanged",
            "CredentialsRefreshed",
            "DetectionType",
            "DevicesChanged",
            "DisconnectCause",
            "Event",
            "EventDeduplicator",
            "EventScope",
            "EventSource",
            "GuardModeChanged",
            "HistoryRecord",
            "ParamChanged",
            "PresetsChanged",
            "PushChanged",
            "PushMessageType",
            "SecurityEvent",
            "StationStateChanged",
            "StorageChanged",
            "ZoomChanged",
        ),
        "events",
    ),
    **dict.fromkeys(
        (
            "AuthenticationError",
            "CameraWakeError",
            "CipherUnavailableError",
            "CloudApiError",
            "CloudError",
            "CommandError",
            "CommandNotAppliedError",
            "CommandRejectedError",
            "CommandUnsupportedError",
            "CommunicationError",
            "DeviceBusyError",
            "DeviceTimeoutError",
            "EmptyResponseError",
            "EufySecurityError",
            "HandshakeError",
            "KeyExchangeRefusedError",
            "KeyRejectedError",
            "LiveStreamLimitError",
            "LoginChallengeError",
            "LoginLimitedError",
            "ModelDataError",
            "NoCachedSessionError",
            "PresetSlotsFullError",
            "ProtocolError",
            "RateLimitedError",
            "RecordNotFoundError",
            "RefreshCooldownError",
            "SessionRejectedError",
            "SessionReplacedError",
            "StationUnreachableError",
            "StillNotWrittenError",
            "UnsupportedError",
        ),
        "exceptions",
    ),
    **dict.fromkeys(("StationClaims", "entity_unique_id"), "identity"),
    **dict.fromkeys(("IMAGE_SOURCES", "CameraImage", "ImageSource", "ImageSourceInfo"), "images"),
    "InstallState": "install",
    **dict.fromkeys(("Reach", "StationChoice"), "inclusion"),
    **dict.fromkeys(("FrameCipher", "GuardMode"), "models"),
    **dict.fromkeys(("HostSource", "LanPath", "PathWarning", "suggest_local_ports"), "network"),
    **dict.fromkeys(("Still", "StillFormat"), "p2p.media"),
    "LAN_DISCOVERY_TIMEOUT": "p2p.pppp",
    **dict.fromkeys(
        (
            "DEFAULT_STATION_SESSIONS",
            "MIN_STATION_SESSIONS",
            "STATION_SESSION_LIMIT",
            "CommandOutcome",
            "SessionStats",
        ),
        "p2p.session",
    ),
    **dict.fromkeys(("DiskInfo", "EmmcInfo", "StorageInfo", "StorageMedium"), "p2p.storage_info"),
    **dict.fromkeys(
        ("RemoteStation", "SettingsCoverage", "Station", "StationState", "SubDeviceState"),
        "station",
    ),
    **dict.fromkeys(
        (
            "CACHE_LAYOUT_VERSION",
            "JsonFileStore",
            "MemoryStore",
            "SessionCache",
            "Store",
            "async_forget_account",
        ),
        "storage",
    ),
}

__all__ = [
    "CACHE_LAYOUT_VERSION",
    "CLIP_CONTENT_TYPE",
    "DEFAULT_QUEUE_CHUNKS",
    "DEFAULT_STATION_SESSIONS",
    "IMAGE_SOURCES",
    "LAN_DISCOVERY_TIMEOUT",
    "MAX_PRESET_SLOTS",
    "MAX_ZOOM",
    "MIN_STATION_SESSIONS",
    "MIN_ZOOM",
    "SETTLE_STANDALONE",
    "SETTLE_STATION",
    "STATION_SESSION_LIMIT",
    "AccountMismatch",
    "AlarmChanged",
    "AlarmPhase",
    "AlarmStopSource",
    "ArmingSource",
    "AuthenticationError",
    "CameraBusyChanged",
    "CameraImage",
    "CameraWakeError",
    "CipherUnavailableError",
    "ClipWriter",
    "CloudApiError",
    "CloudDevice",
    "CloudError",
    "CloudProblem",
    "CloudStatus",
    "CommandError",
    "CommandNotAppliedError",
    "CommandOutcome",
    "CommandRejectedError",
    "CommandUnsupportedError",
    "CommunicationError",
    "ConnectionChanged",
    "CredentialsRefreshed",
    "DetectionType",
    "DeviceBusyError",
    "DeviceTimeoutError",
    "DevicesChanged",
    "DisconnectCause",
    "DiskInfo",
    "EmmcInfo",
    "EmptyResponseError",
    "EufySecurity",
    "EufySecurityError",
    "Event",
    "EventDeduplicator",
    "EventScope",
    "EventSource",
    "FirmwareUpdate",
    "FrameCipher",
    "FrameStream",
    "GuardMode",
    "GuardModeChanged",
    "HandshakeError",
    "HistoryRecord",
    "HostSource",
    "ImageSource",
    "ImageSourceInfo",
    "InstallState",
    "JsonFileStore",
    "KeyExchangeRefusedError",
    "KeyRejectedError",
    "LanPath",
    "LiveStreamLimitError",
    "LoginChallengeError",
    "LoginLimitedError",
    "LoginNeed",
    "MediaClip",
    "MemoryStore",
    "ModelDataError",
    "ModelStatus",
    "NoCachedSessionError",
    "PanTilt",
    "ParamChanged",
    "PathWarning",
    "PresetPosition",
    "PresetSlotsFullError",
    "PresetsChanged",
    "ProtocolError",
    "PushChanged",
    "PushMessageType",
    "RateLimitedError",
    "Reach",
    "RecordNotFoundError",
    "RefreshCooldownError",
    "RegionStatus",
    "RemoteStation",
    "ResizePolicy",
    "SecurityEvent",
    "SessionCache",
    "SessionRejectedError",
    "SessionReplacedError",
    "SessionStats",
    "Setting",
    "SettingControl",
    "SettingKind",
    "SettingUnit",
    "SettingsCoverage",
    "SkippedDevice",
    "Station",
    "StationChoice",
    "StationClaims",
    "StationRefreshStatus",
    "StationState",
    "StationStateChanged",
    "StationUnreachableError",
    "Still",
    "StillFormat",
    "StillNotWrittenError",
    "StorageChanged",
    "StorageInfo",
    "StorageMedium",
    "Store",
    "StreamBroadcast",
    "SubDeviceState",
    "UnsupportedError",
    "ZoomChanged",
    "__version__",
    "async_forget_account",
    "entity_unique_id",
    "redact",
    "redact_serial",
    "set_secret_logging",
    "set_wire_logging",
    "suggest_local_ports",
]

_getattr, __dir__ = lazy_exports(__name__, globals(), _EXPORTS)


def __getattr__(name: str) -> Any:
    if name != "__version__":
        return _getattr(name)
    from importlib.metadata import PackageNotFoundError, version  # noqa: PLC0415

    try:
        value = version("eufy-home-security")
    except PackageNotFoundError:  # pragma: no cover - running from a source tree
        value = "0.0.0"
    globals()[name] = value
    return value
