"""A device's lamps: which settings make each lamp, grouped as the eufy app groups them.

A lamp is one of the app's lamp switches of its live view (``spotlight_switch``,
``zoom_spotlight_switch``) present on the model as a readable or writable bool. Each lamp
takes the brightness and colour temperature the app pairs with that switch, the master
enable whose off state disables the app's lamp control, and the settings that configure
when it lights (declared, eufy app). See ``docs/how-to/home-assistant.md`` § Lights.
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from types import MappingProxyType
from typing import Final

from ..p2p.xzyh import FrameType
from .model_settings import (
    STANDALONE_CONTEXT,
    Setting,
    SettingKind,
    Value,
    _context_name,
    settings_of,
)
from .recipes import ConnectType
from .support import Evidence, Support

_MAIN_CONFIG: Final = (
    "spotlight_status",
    "enable_floodlights_status",
    "auto_spotlight_switch",
    "spotlight_schedule_switch",
    "spotlight_schedule_config",
    "motion_activated_light_setting",
    "motion_activated_light_switch",
    "motion_activated_light_brightness",
    "motion_activated_light_color_temperature",
    "manual_light_brightness",
    "manual_light_color_temperature",
    "light_activation_mode",
    "light_daily_lighting",
    "light_schecule_daily_lighting",
)


@dataclass(frozen=True, slots=True)
class LampSpec:
    """One of the app's lamps, by the identifiers that make it."""

    id: str
    switch: str
    brightness: str | None
    color_temp: str | None
    enabled_by: str | None
    config: tuple[str, ...]


LAMP_SPECS: Final[tuple[LampSpec, ...]] = (
    LampSpec(
        "spotlight",
        "spotlight_switch",
        "spotlight_brightness_level",
        "light_color_temperature",
        "spotlight_status",
        _MAIN_CONFIG,
    ),
    LampSpec(
        "zoom_spotlight", "zoom_spotlight_switch", "zoom_spotlight_brightness_level", None, None, ()
    ),
)
"""The lamps of the eufy app's live view (declared, eufy app): the main lamp of the live
view and device card, and the zoom lamp of a two-lamp track light. The main lamp's colour
temperature and settings are those of its light settings page."""

#: Lamp settings written and read back on hardware (docs/reference/hardware-verification.md),
#: keyed by product code, settings context and setting key.
_VERIFIED_WRITES: Final[Mapping[tuple[str, str, str], str]] = MappingProxyType(
    {
        ("T8160", ConnectType.HB3.value, "spotlight_switch"): (
            "spotlight_switch (1400) written on and off and read back through the library, "
            "eufyCam 3 behind a HomeBase 3"
        ),
        ("T8160", ConnectType.HB3.value, "spotlight_brightness_level"): (
            "spotlight_brightness_level (1401) written and read back through the library with "
            "the lamp off, eufyCam 3 behind a HomeBase 3; the lamp itself was not observed"
        ),
        ("T8170", STANDALONE_CONTEXT, "spotlight_switch"): (
            "spotlight_switch (1400) written and read back through the library, standalone "
            "Battery SoloCam"
        ),
    }
)

_DECLARED: Final = Evidence(
    Support.DECLARED,
    "declared (eufy app): the model's lamp settings, grouped as the app groups them",
)

#: The lowest brightness percent the app writes; at 1 or less it turns the lamp off instead.
LOWEST_WRITTEN_BRIGHTNESS: Final = 2


def _evidence(code: str, context: str, key: str) -> Evidence:
    source = _VERIFIED_WRITES.get((code, context, key))
    return _DECLARED if source is None else Evidence(Support.VERIFIED, source)


@dataclass(frozen=True, slots=True, kw_only=True)
class LightBrightness:
    """A lamp's brightness setting and its percent scale.

    A range setting's value is the percent (``minimum``..``maximum`` by ``step``); an enum
    setting's ``levels`` map each value to its percent (Low/Medium/High = 40/70/100 on a
    eufyCam 3), as the device stores it. The app never writes a brightness of 1 or less: it
    turns the lamp off instead, so :meth:`value_for` gives no range value below
    :data:`LOWEST_WRITTEN_BRIGHTNESS` and a consumer turns the lamp off for such a percent.
    ``evidence`` grades the brightness write: verified only where it was written and read
    back on hardware for this model and context.
    """

    key: str
    writable: bool
    readable: bool
    evidence: Evidence = _DECLARED
    minimum: int
    """The lowest percent the setting takes."""
    maximum: int
    """The highest percent the setting takes."""
    step: int | None
    """A range's step; None for an enum (``levels``)."""
    levels: Mapping[Value, int] = field(default_factory=lambda: MappingProxyType({}))
    """An enum's value -> percent; empty for a range, whose value is the percent."""

    def percent(self, value: Value | None) -> int | None:
        """The percent of a setting value; None for None or a value outside the scale."""
        if value is None or isinstance(value, bool):
            return None
        if self.levels:
            for level, pct in self.levels.items():
                if level == value:
                    return pct
            return None
        if not isinstance(value, int | float) or not self.minimum <= value <= self.maximum:
            return None
        return round(value)

    def value_for(self, percent: float) -> Value:
        """The setting value closest to ``percent``: the nearest enum level (the lower on a
        tie), or the percent clamped into the range from ``minimum`` but at least
        :data:`LOWEST_WRITTEN_BRIGHTNESS`, snapped to its step (up to the next step when the
        nearest lies below that floor)."""
        if self.levels:
            return min(
                self.levels,
                key=lambda level: (abs(self.levels[level] - percent), self.levels[level]),
            )
        floor = max(self.minimum, LOWEST_WRITTEN_BRIGHTNESS)
        clamped = min(max(percent, floor), self.maximum)
        step = self.step or 1
        snapped = self.minimum + round((clamped - self.minimum) / step) * step
        if snapped < floor:
            snapped += step
        return int(min(snapped, self.maximum))


@dataclass(frozen=True, slots=True, kw_only=True)
class LightColorTemperature:
    """A lamp's colour temperature setting: a range on the app's own scale.

    ``kelvin`` is None: no model states its scale in Kelvin, so a consumer offers no
    colour temperature in Kelvin and keeps the setting as a number.
    """

    key: str
    writable: bool
    readable: bool
    minimum: int | float
    maximum: int | float
    step: int | float | None
    kelvin: tuple[int, int] | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class Light:
    """One lamp of a device in a context (standalone, or behind a station kind).

    ``id`` is stable (``spotlight``, ``zoom_spotlight``); ``name`` is the app's title of the
    lamp's switch. ``on_off`` is the switch setting's key, writable and readable as
    :attr:`on_off_writable` / :attr:`on_off_readable` say for this context. ``enabled_by`` is
    the master setting (``spotlight_status``) while whose off state the app disables the
    lamp's control, or None. ``keys`` are the settings a light entity replaces: ``on_off``
    and the brightness, with their variants. The colour temperature and ``config`` (master,
    automatic, schedule: the settings that configure the lamp) stay settings of their own.

    ``state_reported`` is True where the switch is read from param 1400, the param the
    station's light frame (``0x0578``) updates, as the eufy app shows the lamp: the read then
    follows a lamp that changes by itself. Observed on a eufyCam 3 behind a HomeBase 3: a
    lamp switched on went dark around a detection, and the light frame and the station's
    dump both read off; after a write, the frame's 0 is replaced by the written value once
    the write's result arrives. Declared (eufy app) elsewhere. False for a switch read from
    another param or not readable: a consumer then shows an assumed state. ``evidence``
    grades the on/off write: verified only where it was written and read back on hardware
    for this model and context.
    """

    id: str
    name: str
    product_code: str
    on_off: str
    on_off_writable: bool
    on_off_readable: bool
    brightness: LightBrightness | None
    color_temp: LightColorTemperature | None
    enabled_by: str | None
    config: tuple[str, ...]
    keys: tuple[str, ...]
    state_reported: bool
    evidence: Evidence


def lights_of(
    product_code: str, connect: ConnectType | None = None, *, standalone: bool = False
) -> tuple[Light, ...]:
    """The lamps of a model in a context, as :func:`~.model_settings.settings_of` resolves
    it (``standalone``, else behind a station of kind ``connect``); ``()`` for a code
    without a file or a model without a lamp. Raises ModelDataError as ``settings_of``."""
    settings = settings_of(product_code, connect, standalone=standalone)
    return lights_from(settings, product_code, connect, standalone=standalone)


def lights_from(
    settings: Mapping[str, Setting],
    product_code: str,
    connect: ConnectType | None = None,
    *,
    standalone: bool = False,
) -> tuple[Light, ...]:
    """The lamps that ``settings`` (keyed by key: a model's settings in the context
    ``connect`` / ``standalone`` names, as :func:`lights_of` takes it) make."""
    context = STANDALONE_CONTEXT if standalone else _context_name(connect)
    code = product_code.upper()
    lights: list[Light] = []
    for spec in LAMP_SPECS:
        switch = settings.get(spec.switch)
        if switch is None or switch.kind is not SettingKind.BOOL:
            continue
        if not (switch.readable or switch.writable):
            continue
        brightness = _brightness(settings.get(spec.brightness or ""), code, context or "")
        color_temp = _color_temp(settings.get(spec.color_temp or ""))
        enabled_by = spec.enabled_by if spec.enabled_by in settings else None
        config = tuple(key for key in spec.config if key in settings)
        replaced = [spec.switch, *([brightness.key] if brightness is not None else [])]
        variants = [s.key for s in settings.values() if s.variant_of in replaced]
        lights.append(
            Light(
                id=spec.id,
                name=switch.name,
                product_code=code,
                on_off=spec.switch,
                on_off_writable=switch.writable,
                on_off_readable=switch.readable,
                brightness=brightness,
                color_temp=color_temp,
                enabled_by=enabled_by,
                config=config,
                keys=tuple(dict.fromkeys([*replaced, *variants])),
                state_reported=switch.readable and switch.read_param == FrameType.LIGHT_NOTIFY,
                evidence=_evidence(code, context or "", spec.switch),
            )
        )
    return tuple(lights)


def _usable(setting: Setting | None) -> bool:
    return setting is not None and (setting.readable or setting.writable)


def _brightness(setting: Setting | None, code: str, context: str) -> LightBrightness | None:
    """A brightness setting with a percent scale; None when it has none."""
    if setting is None or not _usable(setting):
        return None
    if setting.kind is SettingKind.RANGE:
        low, high = setting.minimum, setting.maximum
        if not isinstance(low, int) or not isinstance(high, int):
            return None
        step = setting.step if isinstance(setting.step, int) else None
        return LightBrightness(
            key=setting.key,
            writable=setting.writable,
            readable=setting.readable,
            evidence=_evidence(code, context, setting.key),
            minimum=low,
            maximum=high,
            step=step,
        )
    if setting.kind is SettingKind.ENUM:
        levels = _enum_percents(setting)
        if levels is None:
            return None
        return LightBrightness(
            key=setting.key,
            writable=setting.writable,
            readable=setting.readable,
            evidence=_evidence(code, context, setting.key),
            minimum=min(levels.values()),
            maximum=max(levels.values()),
            step=None,
            levels=MappingProxyType(levels),
        )
    return None


def _enum_percents(setting: Setting) -> dict[Value, int] | None:
    """Each enum value's percent: the device value its read maps from (the thing
    description's associated value); None when a value has no numeric device value."""
    read_map = setting._read_map or {}
    found: dict[Value, int] = {}
    for raw, value in read_map.items():
        if raw.isdigit() and value in setting.values and value not in found:
            found[value] = int(raw)
    if not setting.values or any(value not in found for value in setting.values):
        return None
    return {value: found[value] for value in setting.values}


def _color_temp(setting: Setting | None) -> LightColorTemperature | None:
    """A colour temperature range; None without a range's bounds (no scale to offer)."""
    if setting is None or not _usable(setting):
        return None
    if setting.minimum is None or setting.maximum is None:
        return None
    return LightColorTemperature(
        key=setting.key,
        writable=setting.writable,
        readable=setting.readable,
        minimum=setting.minimum,
        maximum=setting.maximum,
        step=setting.step,
    )
