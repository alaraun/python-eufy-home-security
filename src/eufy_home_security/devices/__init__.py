"""Device catalog: types and capabilities with their verification status, and per-model settings."""

from .capabilities import (
    FALLBACK_PROFILES,
    PROFILES,
    Capability,
    DeviceProfile,
    profile_for_serial,
)
from .command_types import COMMAND_NAMES, command_name
from .model_settings import Setting, SettingControl, SettingKind, WireCommand, WritePath
from .settings import (
    MODE_ACTION_FLAGS,
    MOTION_SENSOR_DEVICE_TYPES,
    SCOPE_DEFAULT_CHANNEL,
    Scope,
    SettingUnit,
    mode_action_flags,
    mode_action_key,
    mode_delay_key,
    scope_for_kind,
)
from .support import Evidence, Support
from .types import (
    MODELS,
    ON_DEMAND_EVIDENCE,
    ON_DEMAND_PREFIXES,
    SERIAL_PRODUCT_CODES,
    SERIAL_PRODUCT_CODES_EVIDENCE,
    DeviceKind,
    DeviceModel,
    connects_on_demand,
    model_for_serial,
    serial_prefix,
    serial_product_code,
)

__all__ = [
    "COMMAND_NAMES",
    "FALLBACK_PROFILES",
    "MODELS",
    "MODE_ACTION_FLAGS",
    "MOTION_SENSOR_DEVICE_TYPES",
    "ON_DEMAND_EVIDENCE",
    "ON_DEMAND_PREFIXES",
    "PROFILES",
    "SCOPE_DEFAULT_CHANNEL",
    "SERIAL_PRODUCT_CODES",
    "SERIAL_PRODUCT_CODES_EVIDENCE",
    "Capability",
    "DeviceKind",
    "DeviceModel",
    "DeviceProfile",
    "Evidence",
    "Scope",
    "Setting",
    "SettingControl",
    "SettingKind",
    "SettingUnit",
    "Support",
    "WireCommand",
    "WritePath",
    "command_name",
    "connects_on_demand",
    "mode_action_flags",
    "mode_action_key",
    "mode_delay_key",
    "model_for_serial",
    "profile_for_serial",
    "scope_for_kind",
    "serial_prefix",
    "serial_product_code",
]
