"""Which station configuration features a station model offers, and how well that is proven.

``_station_config_data.py`` is written by ``scripts/gen_station_config.py`` from the eufy
app's thing descriptions and product handlers, its HomeBase capability table and a
Remote Config snapshot. Per station model and :class:`StationFeature` it holds a grade
(*declared* when the app offers the feature on the model and its handler builds the
request the library sends, else *unknown* with the reason) and the data a consumer
needs: where the model keeps its per-mode tables (:class:`ModeTableStorage`), the
cross-camera tracking times, the app's firmware gates and the restart command.
*Verified* entries are hardware facts, kept here and traced in
``docs/reference/hardware-verification.md``. Pure lookups: no I/O.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType
from typing import Final

from ..models import GuardMode
from ..p2p.station_config_codecs import CUSTOM_MODES
from ._station_config_data import (
    APP_VERSION,
    CROSS_CAMERA_INTERVALS,
    FEATURES,
    MIN_FIRMWARE,
    MODE_TABLE_PARAMS,
    MODE_TABLE_STORAGE,
    REMOTE_CONFIG_TEMPLATE,
    RESTART_COMMAND,
)
from .capabilities import PROFILES, Capability
from .support import Evidence, Support


class StationFeature(StrEnum):
    """A station configuration feature, one per section a station settings UI shows."""

    GUARD_MODE = "guard_mode"
    """Switch the guard mode (1224)."""
    CUSTOM_MODES = "custom_modes"
    """Add, rename and delete Custom 1-3 (1256)."""
    SCHEDULE = "schedule"
    """The weekly mode schedule (1254) and the mode outside every slot (1257)."""
    MODE_TABLES = "mode_tables"
    """Per mode, what each paired device does on a trigger (1255 action flags)."""
    MODE_DELAYS = "mode_delays"
    """Per mode, the entry (alarm) and exit (leaving) delays (1255 count-downs)."""
    CROSS_CAMERA = "cross_camera"
    """Cross-camera tracking: on/off (1065), assistance (1069), continuous tracking time
    (1070), the chosen cameras (1072)."""
    CROSS_CAMERA_GROUPS = "cross_camera_groups"
    """Cross-camera tracking groups (1073)."""
    ARMING_GROUPS = "arming_groups"
    """The app's Group Control: house-level groups that set several stations' modes."""
    RESTART = "restart"
    """Restart the station."""
    SOUND_ALARM = "sound_alarm"
    """Sound and stop the station's alarm (1201)."""
    WORKING_MODE = "working_mode"
    """The Wi-Fi radio profile, Standard or Performance (1296)."""

    @property
    def alarm_affecting(self) -> bool:
        """Whether a write changes how or whether the station alarms: a consumer
        confirms it with the user first (the library does not prompt)."""
        return self in ALARM_AFFECTING


ALARM_AFFECTING: Final[frozenset[StationFeature]] = frozenset(
    {
        StationFeature.GUARD_MODE,
        StationFeature.SCHEDULE,
        StationFeature.MODE_TABLES,
        StationFeature.MODE_DELAYS,
        StationFeature.ARMING_GROUPS,
        StationFeature.RESTART,
        StationFeature.SOUND_ALARM,
    }
)
"""Features whose writes change the alarm: the guard mode now or by schedule or group,
what sounds or records per mode, the delays, the alarm itself, and a restart (the
station does not alarm while it boots)."""


class ModeTableStorage(StrEnum):
    """Where a station keeps each mode's table after a 1255 write (the param the app
    updates); :func:`mode_table_params` gives the param per mode."""

    ACTION_PARAMS = "action_params"
    """One action param per mode: 1239 Away, 1225 Home, 1148-1150 Custom 1-3, 1177
    Disarmed; the delays live in each device's own params."""
    HB3_TABLES = "hb3_tables"
    """The whole table per mode as base64 JSON: 1158 Away, 1157 Home, 1159-1161 Custom
    1-3, 1177 Disarmed (see :data:`~..p2p.station_config_codecs.STORED_MODE_TABLE_PARAMS`)."""
    PRO_ALARM = "pro_alarm"
    """The professional-alarm params: 61301 Away, 61300 Home, 61307-61309 Custom 1-3,
    61306 Disarmed."""


#: Hardware facts: (model, feature) -> evidence, each traced in the verification log.
_VERIFIED: Final[Mapping[tuple[str, StationFeature], Evidence]] = MappingProxyType(
    {
        ("T8030", StationFeature.GUARD_MODE): PROFILES["T8030"].capabilities[
            Capability.GUARD_MODE_WRITE
        ],
        ("T8030", StationFeature.CUSTOM_MODES): Evidence(
            Support.VERIFIED,
            "live 1256 create, rename and delete, each confirmed and checked in the eufy "
            "app, T8030 HomeBase 3 fw 3.8.7.4",
            "the station seeds an added mode's tables (cameras record and notification, "
            "sensors notification)",
        ),
        ("T8030", StationFeature.SCHEDULE): Evidence(
            Support.VERIFIED,
            "live 1254 write of the weekly slots, confirmed, checked in the eufy app and "
            "restored, T8030 HomeBase 3 fw 3.8.7.4",
            "the mode outside every slot (1257) declared",
        ),
        ("T8030", StationFeature.CROSS_CAMERA): Evidence(
            Support.VERIFIED,
            "live 1072 write of the chosen cameras + read-back, checked in the eufy app and "
            "restored, T8030 HomeBase 3 fw 3.8.7.4",
            "the tracking switches (1065, 1069, 1070) are settings, not written here",
        ),
        ("T8030", StationFeature.CROSS_CAMERA_GROUPS): Evidence(
            Support.VERIFIED,
            "live 1073 write of the groups + read-back, checked in the eufy app and "
            "restored, T8030 HomeBase 3 fw 3.8.7.4",
        ),
        ("T8030", StationFeature.MODE_TABLES): Evidence(
            Support.VERIFIED,
            "live 1255 write + read-back of one device's action mask per mode, "
            "T8030 HomeBase 3 fw 3.8.7.4",
            "one mask per write; the flag names are declared; Custom 2 and 3 not written",
        ),
        ("T8030", StationFeature.MODE_DELAYS): Evidence(
            Support.VERIFIED,
            "live 1255 write + read-back of the Home, Away and Custom 1 entry and exit "
            "delays, T8030 HomeBase 3 fw 3.8.7.4",
            "Custom 2 and 3 declared",
        ),
        ("T8030", StationFeature.RESTART): Evidence(
            Support.VERIFIED,
            "live library restart (1034): the station answered, rebooted and its session "
            "came back, T8030 HomeBase 3 fw 3.8.7.4",
        ),
        ("T8030", StationFeature.SOUND_ALARM): Evidence(
            Support.VERIFIED,
            "live library 1201 sound (30 s) and stop, each confirmed by the station's "
            "alarm-tone frame, the siren heard and then silent, T8030 HomeBase 3 fw 3.8.7.4",
            "the station acknowledges 1201 without a result",
        ),
    }
)

#: Read-only hardware observations: the feature's data was read, nothing written.
_READ_SEEN: Final[Mapping[tuple[str, StationFeature], str]] = MappingProxyType(
    {
        ("T8030", StationFeature.ARMING_GROUPS): "the group list read for a house with a "
        "T8030; not written or activated",
    }
)

_STORAGE: Final[Mapping[str, ModeTableStorage]] = MappingProxyType(
    {code: ModeTableStorage(value) for code, value in MODE_TABLE_STORAGE.items()}
)
_MODE_PARAMS: Final[Mapping[str, Mapping[GuardMode, int]]] = MappingProxyType(
    {
        code: MappingProxyType({GuardMode(mode): param for mode, param in params.items()})
        for code, params in MODE_TABLE_PARAMS.items()
    }
)


def app_version() -> str:
    """The eufy app build whose thing descriptions and handlers the table comes from."""
    return APP_VERSION


def remote_config_template() -> int:
    """The template version of the Remote Config snapshot the firmware gates come from."""
    return REMOTE_CONFIG_TEMPLATE


def station_config_models() -> tuple[str, ...]:
    """Every station product code the table lists, sorted; a model without a thing
    description on record is listed with every feature *unknown*."""
    return tuple(FEATURES)


def _key(product_code: str | None) -> str | None:
    return None if product_code is None else product_code.upper()


def _version(text: str) -> tuple[int, ...] | None:
    parts = text.strip().split(".")
    return tuple(int(p) for p in parts) if all(p.isdigit() for p in parts) else None


def min_firmware(product_code: str | None, feature: StationFeature) -> str | None:
    """The lowest station firmware the eufy app offers ``feature`` on, or None (no gate
    on record)."""
    code = _key(product_code)
    return None if code is None else MIN_FIRMWARE.get(code, {}).get(feature.value)


def config_support(
    product_code: str | None, feature: StationFeature, *, firmware: str | None = None
) -> Evidence:
    """How well ``feature`` is supported on a station of ``product_code``.

    *Verified* from a hardware check on that model; else the generated grade:
    *declared* when the eufy app offers the feature on the model and its handler builds
    the request the library sends, *unknown* with the reason otherwise. With
    ``firmware``, a station below the app's gate (:func:`min_firmware`) is *unknown*, a
    verified feature too; a firmware string that is not dotted numbers is not compared.
    """
    code = _key(product_code)
    if code is None or code not in FEATURES:
        return Evidence(Support.UNKNOWN, f"{code or 'this model'} is not a station model on record")
    verified = _VERIFIED.get((code, feature))
    grade, source = FEATURES[code][feature.value]
    support = Support(grade)
    gate = min_firmware(code, feature)
    if verified is not None and gate is None:
        return verified
    if support is Support.DECLARED and gate is not None and firmware is not None:
        have, need = _version(firmware), _version(gate)
        if have is not None and need is not None and have < need:
            return Evidence(
                Support.UNKNOWN,
                f"the eufy app offers {feature.value} on a {code} from firmware {gate}; "
                f"this station runs {firmware}",
            )
    if verified is not None:
        support, source = verified.support, verified.source
    notes = [n for n in (verified.note if verified else _READ_SEEN.get((code, feature)),) if n]
    if gate is not None:
        notes.append(f"the eufy app offers it from firmware {gate}")
    return Evidence(support, source, "; ".join(notes))


def mode_table_storage(product_code: str | None) -> ModeTableStorage | None:
    """Where the model keeps its per-mode tables; None when not on record."""
    code = _key(product_code)
    return None if code is None else _STORAGE.get(code)


def mode_table_params(product_code: str | None) -> Mapping[GuardMode, int]:
    """The param holding each mode's table (Away, Home, Custom 1-3, Disarmed) on the
    model, as its handler updates it after a 1255 write; empty when not on record."""
    code = _key(product_code)
    return MappingProxyType({}) if code is None else _MODE_PARAMS.get(code, MappingProxyType({}))


def max_custom_modes(product_code: str | None) -> int:
    """How many custom modes the model offers: 3 where :attr:`StationFeature.CUSTOM_MODES`
    is not *unknown*, else 0."""
    evidence = config_support(product_code, StationFeature.CUSTOM_MODES)
    return 0 if evidence.support is Support.UNKNOWN else len(CUSTOM_MODES)


def cross_camera_intervals(product_code: str | None) -> tuple[int, ...]:
    """The continuous tracking times (seconds) the model's thing description offers for
    1070, in the app's order; empty without cross-camera tracking."""
    code = _key(product_code)
    return () if code is None else CROSS_CAMERA_INTERVALS.get(code, ())


def restart_command(product_code: str | None) -> tuple[int, int | None] | None:
    """The model handler's restart request: ``(cmd, sub-command or None)``; None when
    the model offers no restart."""
    code = _key(product_code)
    return None if code is None else RESTART_COMMAND.get(code)
