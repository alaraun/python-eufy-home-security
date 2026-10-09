"""Per-model device settings from the bundled model files (``data/models/<PN>.json``).

A :class:`Setting` is one thing-description property of a model, keyed by the vendor
identifier, with its domain, labels and the write and read codecs of the vendor handler.
:meth:`Setting.encode` renders the write codec for a value into a :class:`WireCommand`;
:meth:`Setting.decode` turns a station parameter value back into the public value. The
file format and the placeholder forms are in docs/reference/models-schema.md.

:func:`settings_of` reads package data on the first call for a product code and memoises
the result: call it off the event loop (``asyncio.to_thread``) the first time.
"""

from __future__ import annotations

import functools
import importlib.resources
import json
import math
import operator
import re
from collections.abc import Mapping
from dataclasses import dataclass, field
from enum import StrEnum
from importlib.resources.abc import Traversable
from types import MappingProxyType
from typing import Any, Final, cast

from ..exceptions import ModelDataError, UnsupportedError
from ..p2p.mode_actions import ACTION_FLAGS
from .labels import setting_name
from .settings import MODE_TABLE_SETTINGS, Scope, SettingDef, SettingUnit
from .timezones import TIMEZONE_DOMAIN, decode_zone, encode_zone, zone_ids
from .types import model_for_serial, serial_product_code

__all__ = [
    "IDENTIFIER",
    "Setting",
    "SettingControl",
    "SettingKind",
    "Value",
    "WireCommand",
    "WriteContext",
    "WritePath",
    "bundled_codes",
    "bundled_td_version",
    "canonical_code",
    "mode_table_settings",
    "product_code_of",
    "settings_of",
]

type Value = bool | int | float | str
type Recipe = Mapping[str, Any]

SCHEMA_VERSION: Final = 2
_DATA_PACKAGE: Final = "eufy_home_security.devices.data.models"
_INDEX: Final = "INDEX.json"  # the generator's list of the bundled codes
IDENTIFIER: Final = re.compile(r"[a-z0-9_]+")
"""A setting key: a vendor identifier this library lists."""
_PRODUCT_CODE: Final = re.compile(r"[A-Za-z0-9]{1,32}")
_SN_SLOTS: Final = frozenset({"$device_sn", "$station_sn"})
_SUB_1350: Final = 1350
_RECIPE_1700: Final = 1700


class SettingKind(StrEnum):
    """The value domain of a setting."""

    BOOL = "bool"
    ENUM = "enum"
    RANGE = "range"
    STRING = "string"
    OTHER = "other"
    FLAGS = "flags"
    """An int bitmask with named members (:attr:`Setting.flags`); several may be on."""


class SettingControl(StrEnum):
    """The control a UI offers for a writable setting, decided by the generator."""

    SWITCH = "switch"
    """On/off (a ``BOOL``)."""
    SELECT = "select"
    """One of a few named choices (an ``ENUM``)."""
    SLIDER = "slider"
    """A ``RANGE`` of at most :data:`SLIDER_MAX_STEPS` steps."""
    BOX = "box"
    """A ``RANGE`` entered as a number: a duration, or too many steps for a slider."""
    TOGGLES = "toggles"
    """One on/off per member of a ``FLAGS`` mask."""
    TEXT = "text"
    """Free text (a ``STRING``)."""


#: The controls each kind may carry (a ``STRING`` with a :attr:`Setting.domain` is a select).
CONTROLS_BY_KIND: Final[Mapping[SettingKind, frozenset[SettingControl]]] = MappingProxyType(
    {
        SettingKind.BOOL: frozenset({SettingControl.SWITCH}),
        SettingKind.ENUM: frozenset({SettingControl.SELECT}),
        SettingKind.RANGE: frozenset({SettingControl.SLIDER, SettingControl.BOX}),
        SettingKind.FLAGS: frozenset({SettingControl.TOGGLES}),
        SettingKind.STRING: frozenset({SettingControl.TEXT, SettingControl.SELECT}),
        SettingKind.OTHER: frozenset(),
    }
)
SLIDER_MAX_STEPS: Final = 200


class WritePath(StrEnum):
    """How a rendered write reaches the device."""

    ECB = "ecb"  # legacy AES-ECB scalar frame (frame type = cmd, body = value)
    DIRECT = "direct"  # GCM DeviceMsgBean with the command's own id
    SUB_1350 = "1350"  # GCM command 1350 carrying ``subCmd``
    RECIPE_1700 = "1700"  # handler recipe 1700 carrying ``subCmd``
    STRING = "string"  # GCM string frame (frame type = cmd, body = channel, value, account)


@dataclass(frozen=True, slots=True)
class WriteContext:
    """The device a write is rendered for: standalone or station child, its channel, serials."""

    standalone: bool
    channel: int
    device_sn: str
    station_sn: str


@dataclass(frozen=True, slots=True, kw_only=True)
class WireCommand:
    """A rendered write.

    ``cmd`` is the id the session sends (``subCmd`` for 1350/1700). ``params`` is the
    rendered body object (None when the body is not an object). ``value`` is the ECB
    scalar. ``text`` is a ``STRING`` write's value. ``updates`` are the
    ``(param id, value)`` pairs the app writes to its parameter cache after a
    successful send.
    """

    path: WritePath
    cmd: int
    params: Mapping[str, Any] | None
    value: int | None
    updates: tuple[tuple[int, str], ...]
    text: str | None = None


@dataclass(frozen=True, slots=True, kw_only=True)
class Setting:
    """One setting of a model: domain, labels, layout and the handler's codecs.

    Values are thing-description values: int for enum and range, bool for bool, str for
    string (a few enums have str values). ``writable`` is False for read-only settings
    and for writes the library does not send; ``note`` then names why.

    ``control`` is the control a UI offers (None when not writable). A ``FLAGS``
    setting's value is the whole mask; ``flags`` maps each member to its bit (one or
    more bits) and ``labels`` titles the members. A ``BOOL`` with ``bit`` is one bit of a
    parameter other settings share: it reads ``raw & bit`` and is written by
    :meth:`mask_with` on the current mask, never blind (:meth:`encode` refuses).

    ``name`` is the eufy app's title for the setting where the app has one, else a title
    made from the key. ``variant_of`` is the key of the setting the app uses in this
    one's place on the same model (``record_resolution`` for ``record_resolution__v1``),
    or None: a variant reads the same parameter in another form or applies only under
    conditions the library does not evaluate. Offer a variant disabled by default.

    ``domain`` names a library table a ``STRING`` setting's values come from
    (:data:`~.timezones.TIMEZONE_DOMAIN`: the app's device time zones). Such a setting is
    a ``SELECT``: ``values`` are the table's ids, a write takes an id and sends the
    device form, and a read gives the id back (None when the device holds a value the
    table does not place).
    """

    key: str
    product_code: str
    name: str
    kind: SettingKind
    values: tuple[Value, ...] = ()
    minimum: int | float | None = None
    maximum: int | float | None = None
    step: int | float | None = None
    unit: SettingUnit | None = None
    default: Value | None = None
    labels: Mapping[Value, str] = field(default_factory=lambda: MappingProxyType({}))
    writable: bool = False
    readable: bool = False
    group: str | None = None
    order: int | None = None
    page: str | None = None
    applies_when: tuple[str, Value] | None = None
    note: str | None = None
    variant_of: str | None = None
    control: SettingControl | None = None
    flags: Mapping[str, int] = field(default_factory=lambda: MappingProxyType({}))
    bit: int | None = None
    domain: str | None = None
    _write: Recipe | None = field(default=None, repr=False)
    _write_standalone: Recipe | None = field(default=None, repr=False)
    _write_table: Mapping[str, Recipe] | None = field(default=None, repr=False)
    _write_table_standalone: Mapping[str, Recipe] | None = field(default=None, repr=False)
    _read_param: int | None = field(default=None, repr=False)
    _read_map: Mapping[str, Value] | None = field(default=None, repr=False)
    _standalone_refused: bool = field(default=False, repr=False)
    _mode_table: SettingDef | None = field(default=None, repr=False)
    """The hand-written mode-table entry a mode-table setting is written through."""

    @property
    def read_param(self) -> int | None:
        """The parameter id that reports this setting's value; None when not readable."""
        return self._read_param

    def validate(self, value: object) -> Value:
        """``value`` as the setting's public value; raises ValueError outside the domain."""
        match self.kind:
            case SettingKind.BOOL:
                return _as_bool(value)
            case SettingKind.ENUM:
                return self._enum_value(value)
            case SettingKind.RANGE:
                return self._range_value(value)
            case SettingKind.FLAGS:
                mask = _mask(value) if not isinstance(value, bool) else None
                if mask is None:
                    raise ValueError(f"{self.key}: expected a non-negative int mask, got {value!r}")
                return mask
            case SettingKind.STRING:
                if not isinstance(value, str):
                    raise ValueError(f"{self.key}: expected a string, got {value!r}")
                if self.domain is not None and value not in self.values:
                    raise ValueError(f"{self.key}: {value!r} is not one of its {self.domain} ids")
                return value
            case _:
                if not isinstance(value, bool | int | float | str):
                    raise ValueError(f"{self.key}: expected a scalar, got {value!r}")
                return value

    def label(self, value: Value) -> str | None:
        """The display title of an enum value, or None."""
        for known, title in self.labels.items():
            if _same(known, value):
                return title
        return None

    def decode(self, raw: str | None) -> Value | None:
        """The public value of parameter value ``raw``; None when unreadable or unknown."""
        if raw is None or self._read_param is None:
            return None
        if self.domain is not None:
            return _domain_decode(self.domain, raw)
        if self.bit is not None or self.kind is SettingKind.FLAGS:
            mask = _mask(raw)
            if mask is None:
                return None
            return bool(mask & self.bit) if self.bit is not None else mask
        if self._read_map is not None:
            mapped = self._read_map.get(raw)
            if mapped is None or (self.kind is SettingKind.ENUM and not self._in_values(mapped)):
                return None
            return mapped
        match self.kind:
            case SettingKind.BOOL:
                try:
                    return _as_bool(raw)
                except ValueError:
                    return None
            case SettingKind.ENUM:
                for candidate in (_number(raw), raw):
                    if candidate is not None and self._in_values(candidate):
                        return self._known(candidate)
                return None
            case SettingKind.RANGE:
                return _number(raw)
            case _:
                return raw

    def encode(self, value: object, ctx: WriteContext) -> WireCommand:
        """The wire command that writes ``value`` to the device ``ctx`` describes.

        Raises UnsupportedError when the setting is not writable (in a standalone
        context: when its standalone write is refused) and ValueError for a value outside
        the domain or one the codec has no rendering for.
        """
        if not self.writable:
            raise UnsupportedError(f"{self.key} is not writable: {self.note or 'read-only'}")
        if self.bit is not None:
            raise ValueError(f"{self.key} shares its parameter: write the current mask (mask_with)")
        public = self.validate(value)
        return self._encode_value(public, ctx)

    def encode_mask(self, mask: int, ctx: WriteContext) -> WireCommand:
        """The wire command that writes the whole shared ``mask`` of a ``bit`` setting
        (the result of :meth:`mask_with` on a fresh read)."""
        if not self.writable:
            raise UnsupportedError(f"{self.key} is not writable: {self.note or 'read-only'}")
        if self.bit is None or _mask(mask) is None:
            raise ValueError(f"{self.key}: not a bit setting, or {mask!r} is not a mask")
        return self._encode_value(int(mask), ctx)

    def mask_with(self, current: int, on: bool) -> int:
        """``current`` with this setting's bit set or cleared; every other bit kept."""
        if self.bit is None or _mask(current) is None:
            raise ValueError(f"{self.key}: not a bit setting, or {current!r} is not a mask")
        return (current | self.bit) if on else (current & ~self.bit)

    def decode_flags(self, raw: object) -> tuple[frozenset[str], int]:
        """The members of a ``FLAGS`` mask that are on (all of a member's bits set) and
        the bits no member names; ValueError for a value that is not a mask."""
        mask = _mask(raw)
        if self.kind is not SettingKind.FLAGS or mask is None:
            raise ValueError(f"{self.key}: {raw!r} is not a flags mask")
        on = frozenset(k for k, bits in self.flags.items() if mask & bits == bits)
        named = 0
        for bits in self.flags.values():
            named |= bits
        return on, mask & ~named

    def with_flag(self, current: int, flag: str, *, on: bool) -> int:
        """``current`` with member ``flag``'s bits set or cleared; every other bit kept."""
        if self.kind is not SettingKind.FLAGS or flag not in self.flags:
            raise ValueError(f"{self.key}: unknown flag {flag!r}; known: {sorted(self.flags)}")
        mask = _mask(current)
        if mask is None:
            raise ValueError(f"{self.key}: {current!r} is not a mask")
        bits = self.flags[flag]
        return (mask | bits) if on else (mask & ~bits)

    def flag_label(self, flag: str) -> str:
        """The app's title of a ``FLAGS`` member, else the member key."""
        for known, title in self.labels.items():
            if str(known) == flag:
                return title
        return flag

    def _encode_value(self, public: Value, ctx: WriteContext) -> WireCommand:
        if self.domain is not None:
            return self._encode_domain(str(public), ctx)
        template = self._template(public, standalone=ctx.standalone)
        recipe = _render(
            template,
            public,
            channel=ctx.channel,
            device_sn=ctx.device_sn,
            station_sn=ctx.station_sn,
        )
        return _classify(template, recipe)

    def _encode_domain(self, public: str, ctx: WriteContext) -> WireCommand:
        """A domain setting's write: the device form of ``public`` as a string frame of
        the handler's command, with the handler's parameter-cache updates."""
        device = _domain_encode(cast(str, self.domain), public)
        template = self._template(device, standalone=ctx.standalone)
        recipe = _render(
            template,
            device,
            channel=ctx.channel,
            device_sn=ctx.device_sn,
            station_sn=ctx.station_sn,
        )
        return WireCommand(
            path=WritePath.STRING,
            cmd=int(recipe["cmd"]),
            params=None,
            value=None,
            updates=_updates(recipe),
            text=device,
        )

    def _render_recipe(self, value: Value, ctx: WriteContext) -> dict[str, Any]:
        """The full rendered recipe (every key of the template), for comparisons."""
        template = self._template(value, standalone=ctx.standalone)
        return _render(
            template, value, channel=ctx.channel, device_sn=ctx.device_sn, station_sn=ctx.station_sn
        )

    def _template(self, value: Value, *, standalone: bool) -> Recipe:
        if standalone and self._standalone_refused:
            raise UnsupportedError(f"{self.key} is not writable standalone: {self.note}")
        key = _value_key(value)
        tables = [self._write_table_standalone] if standalone else []
        tables.append(self._write_table)
        for table in tables:
            if table is not None:
                if key not in table:
                    raise ValueError(f"value {key} not in the write table")
                return table[key]
        if standalone and self._write_standalone is not None:
            return self._write_standalone
        if self._write is not None:
            return self._write
        raise ValueError("setting has no write codec")

    def _in_values(self, value: Value) -> bool:
        return any(_same(v, value) for v in self.values)

    def _known(self, value: Value) -> Value:
        return next(v for v in self.values if _same(v, value))

    def _enum_value(self, value: object) -> Value:
        if isinstance(value, int | float | str) and not isinstance(value, bool):
            candidates: list[Value] = [value]
            if isinstance(value, str) and (number := _number(value)) is not None:
                candidates.append(number)
            for candidate in candidates:
                if self._in_values(candidate):
                    return self._known(candidate)
            if isinstance(value, str):
                for fold in (False, True):
                    for known, title in self.labels.items():
                        if title == value or (fold and title.casefold() == value.casefold()):
                            return known
        raise ValueError(f"{self.key}: {value!r} is not one of {list(self.values)}")

    def _range_value(self, value: object) -> int | float:
        number = _number(value) if isinstance(value, str) else value
        if isinstance(number, bool) or not isinstance(number, int | float):
            raise ValueError(f"{self.key}: expected a number, got {value!r}")
        lo, hi = self.minimum, self.maximum
        if lo is None or hi is None or not lo <= number <= hi:
            raise ValueError(f"{self.key}: {number} is outside {lo}..{hi}")
        steps = (number - lo) / (self.step or 1)
        if not math.isclose(steps, round(steps), abs_tol=1e-9):
            raise ValueError(f"{self.key}: {number} is not on the {self.step} step from {lo}")
        return _intify(number)


# ── values ──────────────────────────────────────────────────────────────────


def _mask(raw: object) -> int | None:
    """``raw`` as a non-negative int bitmask, or None."""
    if isinstance(raw, bool):
        return None
    if isinstance(raw, int):
        return raw if raw >= 0 else None
    if isinstance(raw, str) and raw.strip().isdigit():
        return int(raw.strip())
    return None


def _same(a: object, b: object) -> bool:
    """Equality that keeps bools apart from numbers."""
    if isinstance(a, bool) or isinstance(b, bool):
        return type(a) is type(b) and a == b
    if isinstance(a, int | float) and isinstance(b, int | float):
        return a == b
    return type(a) is type(b) and a == b


def _intify(x: int | float) -> int | float:
    return int(x) if float(x).is_integer() else x


def _number(raw: object) -> int | float | None:
    """``raw`` as a number (int when integral), or None."""
    if isinstance(raw, bool):
        return None
    try:
        x = float(str(raw).strip())
    except ValueError:
        return None
    return _intify(x) if math.isfinite(x) else None


_TRUE: Final = frozenset({"1", "true", "on"})
_FALSE: Final = frozenset({"0", "false", "off"})


def _as_bool(value: object) -> bool:
    if isinstance(value, bool):
        return value
    if isinstance(value, int) and value in (0, 1):
        return bool(value)
    if isinstance(value, str):
        text = value.strip().lower()
        if text in _TRUE:
            return True
        if text in _FALSE:
            return False
    raise ValueError(f"not a bool: {value!r}")


def _value_key(value: Value) -> str:
    """The JSON-object key form of a public value (``"3"``, ``"true"``)."""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _str_form(value: Value) -> str:
    """The string the handler writes for a value (bools as ``"0"``/``"1"``)."""
    if isinstance(value, bool):
        return str(int(value))
    return str(value)


# ── rendering ───────────────────────────────────────────────────────────────


def _render(
    template: Recipe, value: Value, *, channel: int, device_sn: str, station_sn: str
) -> dict[str, Any]:
    """Fill a write template's placeholders for ``value`` (docs/reference/models-schema.md).

    Raises ValueError for an unknown placeholder or a value the template does not map.
    """
    serials = {"$device_sn": device_sn, "$station_sn": station_sn}

    def fill(x: Any) -> Any:
        if isinstance(x, Mapping):
            if any(isinstance(k, str) and k.startswith("$") for k in x):
                return form(x)
            return {k: fill(v) for k, v in x.items()}
        if isinstance(x, list):
            return [fill(v) for v in x]
        if isinstance(x, str) and x.startswith("$"):
            return scalar(x)
        return x

    def scalar(slot: str) -> Any:
        if slot == "$v":
            return value
        if slot == "$v:str":
            return _str_form(value)
        if slot == "$v:int":
            if isinstance(value, float) and not value.is_integer():
                raise ValueError(f"$v:int of a fraction: {value!r}")
            return int(value)
        if slot == "$channel":
            return channel
        if slot in _SN_SLOTS:
            return serials[slot]
        raise ValueError(f"unknown placeholder {slot!r}")

    def form(x: Mapping[str, Any]) -> Any:
        if len(x) != 1:
            raise ValueError(f"unknown placeholder object {sorted(x)}")
        ((name, arg),) = x.items()
        if name == "$map" and isinstance(arg, Mapping):
            key = _value_key(value)
            if key not in arg:
                raise ValueError(f"value {key} not in $map")
            return arg[key]
        if name == "$affine" and isinstance(arg, list) and len(arg) == 2:
            if isinstance(value, bool) or not isinstance(value, int | float):
                raise ValueError(f"$affine of a non-number: {value!r}")
            a, b = arg
            return _intify(round(a * value + b, 9))
        raise ValueError(f"unknown placeholder object {name!r}")

    rendered: dict[str, Any] = fill(template)
    return rendered


def _channel_fields(template: Recipe) -> frozenset[str]:
    params = template.get("params")
    if not isinstance(params, Mapping):
        return frozenset()
    return frozenset(k for k, v in params.items() if v == "$channel")


def _updates(recipe: Mapping[str, Any]) -> tuple[tuple[int, str], ...]:
    out: list[tuple[int, str]] = []
    update = recipe.get("update")
    if isinstance(update, Mapping) and update.get("needUpdate"):
        cmd, param_value = update.get("cmd"), update.get("paramValue")
        if isinstance(cmd, int) and param_value is not None:
            out.append((cmd, _str_form(param_value)))
    ext = recipe.get("extUpdates")
    for item in ext if isinstance(ext, list) else ():
        if isinstance(item, Mapping):
            cmd, param_value = item.get("cmd"), item.get("paramValue")
            if isinstance(cmd, int) and param_value is not None:
                out.append((cmd, _str_form(param_value)))
    return tuple(out)


def _classify(template: Recipe, recipe: Mapping[str, Any]) -> WireCommand:
    """The send path of a rendered P2P recipe."""
    cmd, sub, params = recipe["cmd"], recipe.get("subCmd"), recipe.get("params")
    updates = _updates(recipe)
    body = params if isinstance(params, Mapping) else None
    if cmd == _SUB_1350 and isinstance(sub, int):
        return WireCommand(
            path=WritePath.SUB_1350, cmd=sub, params=body, value=None, updates=updates
        )
    if cmd == _RECIPE_1700 and isinstance(sub, int):
        return WireCommand(
            path=WritePath.RECIPE_1700, cmd=sub, params=body, value=None, updates=updates
        )
    if _is_ecb_scalar(cmd):
        scalar: object = params
        if body is not None:
            channel = _channel_fields(template)
            fields = [v for k, v in body.items() if k not in channel]
            # Some handlers repeat the value under two names ({"duration": v, "value": v}).
            distinct = {json.dumps(v) for v in fields}
            scalar = fields[0] if len(distinct) == 1 else None
        # An ECB body is an int: handlers write some values as digit strings.
        if isinstance(scalar, str):
            if not scalar.lstrip("-").isdigit():
                raise ValueError(f"ECB command {cmd} needs an integer value, got {scalar!r}")
            scalar = int(scalar)
        if isinstance(scalar, bool | int):
            return WireCommand(
                path=WritePath.ECB, cmd=cmd, params=body, value=int(scalar), updates=updates
            )
    return WireCommand(path=WritePath.DIRECT, cmd=cmd, params=body, value=None, updates=updates)


# ── refusals ───────────────────────────────────────────────────────────────

# Recipe keys of transports the library does not send, with the note a refused setting gets.
_TRANSPORTS: Final = (
    ("sendRequestUrl", "cloud request"),
    ("http", "cloud request"),
    ("multipleRequest", "multi-command write"),
    ("localParams", "app-local"),
    ("storeToLocal", "app-local"),
    ("ble", "Bluetooth"),
    ("mqttCmdCode", "MQTT"),
)
# Alarm state changes only through the dedicated guard-mode API.
_GUARD_MODE_KEY: Final = "arming_selected_mode"
_GUARD_MODE_NOTE: Final = "guard mode: use Station.async_set_guard_mode"


def _refusal(template: Recipe) -> str | None:
    """Why the library does not send a write template, or None when it does."""
    for key, reason in _TRANSPORTS:
        if key in template:
            return reason
    cmd, sub, params = template.get("cmd"), template.get("subCmd"), template.get("params")
    if isinstance(cmd, bool) or not isinstance(cmd, int):
        return "no P2P command"
    if cmd == _RECIPE_1700 and "param_data" in template:
        return "1700 data body not supported"
    if sub is not None and (isinstance(sub, bool) or not isinstance(sub, int)):
        return "no P2P command"
    if params is None or isinstance(params, Mapping):
        return None
    if sub is None and _is_ecb_scalar(cmd):
        return None
    return "scalar body on a non-ECB command"


def _first_refusal(templates: list[Recipe | None]) -> str | None:
    return next((r for t in templates if t is not None and (r := _refusal(t)) is not None), None)


# ── domains ────────────────────────────────────────────────────────────────


def _domain_values(domain: str) -> tuple[str, ...]:
    if domain == TIMEZONE_DOMAIN:
        return zone_ids()
    raise ValueError(f"unknown domain {domain!r}")


def _domain_encode(domain: str, value: str) -> str:
    if domain == TIMEZONE_DOMAIN:
        return encode_zone(value)
    raise ValueError(f"unknown domain {domain!r}")


def _domain_decode(domain: str, raw: str) -> str | None:
    if domain == TIMEZONE_DOMAIN:
        return decode_zone(raw)
    return None


def _is_ecb_scalar(cmd: int) -> bool:
    # Deferred: p2p.messages loads cryptography, which the light CLI modules must not.
    from ..p2p.messages import is_ecb_scalar  # noqa: PLC0415 - the table's one definition

    return is_ecb_scalar(cmd)


# ── mode tables ─────────────────────────────────────────────────────────────

# An action mask holds the app's action bits (p2p.mode_actions.ACTION_FLAGS).
_ACTION_MASK_MAX: Final = functools.reduce(operator.or_, ACTION_FLAGS.values())


def _mode_table_setting(spec: SettingDef) -> Setting:
    delay = spec.flags is None
    return Setting(
        key=spec.key,
        product_code="",
        name=spec.name,
        kind=SettingKind.RANGE,
        minimum=spec.value_range[0] if delay and spec.value_range else 0,
        maximum=spec.value_range[1] if delay and spec.value_range else _ACTION_MASK_MAX,
        step=1,
        unit=SettingUnit.SECONDS if delay else None,
        writable=True,
        readable=True,
        _read_param=spec.read_param,
        _mode_table=spec,
    )


_MODE_TABLE_SETTINGS: Final = tuple(_mode_table_setting(spec) for spec in MODE_TABLE_SETTINGS)


def mode_table_settings(scope: Scope) -> tuple[Setting, ...]:
    """The per-mode delays and action masks a device of ``scope`` carries: the
    hand-written mode-table entries of :mod:`.settings`, as settings."""
    return tuple(
        s
        for s in _MODE_TABLE_SETTINGS
        if s._mode_table is not None and s._mode_table.applies_to(scope)
    )


# ── loading ─────────────────────────────────────────────────────────────────


def _root() -> Traversable:
    """The directory of the bundled model files."""
    return importlib.resources.files(_DATA_PACKAGE)


def canonical_code(product_code: object) -> str | None:
    """``product_code`` in the one form models are keyed and files named by, or ``None``.

    Product codes match case-insensitively and canonicalise to upper case on every
    platform. The ASCII check runs before upper-casing, so a character whose upper case is
    ASCII (``"ß"`` → ``"SS"``) is refused. ``None`` for anything that is not a ``str`` of 1
    to 32 ASCII letters and digits. Never raises.
    """
    if not isinstance(product_code, str) or not _PRODUCT_CODE.fullmatch(product_code):
        return None
    return product_code.upper()


def product_code_of(device_new_pn: object, serial: str) -> str | None:
    """A device's product code: the cloud's ``device_new_pn`` (canonical), else the
    product a serial rule names (:func:`~.types.serial_product_code`), else the serial's
    catalogued model; ``None`` when none names one."""
    code = canonical_code(device_new_pn) or serial_product_code(serial)
    if code is not None:
        return code
    model = model_for_serial(serial)
    return model.model if model is not None else None


@functools.cache
def bundled_codes() -> tuple[str, ...]:
    """The product codes with a bundled settings file, sorted, as the generator's
    ``INDEX.json`` lists them. Reads package data on the first call (memoised): call it
    off the event loop. Raises ModelDataError when the index is malformed."""
    try:
        data = json.loads(_root().joinpath(_INDEX).read_text(encoding="utf-8"))
        codes = data["codes"]
        if data.get("schema_version") != SCHEMA_VERSION or not isinstance(codes, list):
            raise ValueError("not a schema-2 index")
        if not all(isinstance(c, str) and canonical_code(c) == c for c in codes):
            raise ValueError("a code is not canonical")
    except (OSError, UnicodeDecodeError, ValueError, KeyError, TypeError) as err:
        raise ModelDataError(f"{_INDEX}: {err}") from err
    return tuple(sorted(codes))


def settings_of(product_code: str) -> Mapping[str, Setting]:
    """The settings of a model keyed by identifier; empty for a code without a file.

    Product codes match case-insensitively. Reads package data on the first call per
    code (memoised). Raises ModelDataError when the bundled file is malformed.
    """
    if not _PRODUCT_CODE.fullmatch(product_code):
        return MappingProxyType({})
    return _load(product_code.upper()).settings


def bundled_td_version(product_code: str) -> int | None:
    """The thing-description version a model's bundled file was generated from
    (``source.td_version``); None without a file or a version. Reads like
    :func:`settings_of` (same memo) and raises like it."""
    if not _PRODUCT_CODE.fullmatch(product_code):
        return None
    return _load(product_code.upper()).td_version


@dataclass(frozen=True, slots=True)
class _Model:
    settings: Mapping[str, Setting]
    td_version: int | None


_NO_MODEL: Final = _Model(MappingProxyType({}), None)


@functools.cache
def _load(code: str) -> _Model:
    if code not in bundled_codes():
        return _NO_MODEL
    name = f"{code}.json"
    resource = _root().joinpath(name)
    if not resource.is_file():
        raise ModelDataError(f"{name}: listed in {_INDEX} but missing")
    try:
        data = json.loads(resource.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as err:
        raise ModelDataError(f"{name}: {err}") from err
    try:
        return _Model(MappingProxyType(_parse(code, data)), _source_version(data))
    except (KeyError, TypeError, ValueError) as err:
        raise ModelDataError(f"{name}: {err}") from err


def _source_version(data: Mapping[str, Any]) -> int | None:
    source = data.get("source")
    version = source.get("td_version") if isinstance(source, dict) else None
    return version if isinstance(version, int) and not isinstance(version, bool) else None


def _parse(code: str, data: Any) -> dict[str, Setting]:
    if not isinstance(data, dict):
        raise TypeError("not a JSON object")
    if data.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"schema_version {data.get('schema_version')!r} is not {SCHEMA_VERSION}")
    if data.get("product_code") != code:
        raise ValueError(f"product_code {data.get('product_code')!r} is not {code}")
    entries = data["settings"]
    if not isinstance(entries, dict):
        raise TypeError("settings is not an object")
    settings = {
        key: _setting(code, key, entry)
        for key, entry in entries.items()
        if IDENTIFIER.fullmatch(key)
    }
    for key, setting in settings.items():
        if setting.variant_of is not None and setting.variant_of not in settings:
            raise ValueError(f"{key}: variant_of {setting.variant_of!r} is not a setting")
    return settings


def _recipe(entry: Mapping[str, Any], key: str) -> Recipe | None:
    raw = entry.get(key)
    if raw is None:
        return None
    if not isinstance(raw, dict):
        raise TypeError(f"{key} is not an object")
    return MappingProxyType(raw)


def _table(entry: Mapping[str, Any], key: str) -> Mapping[str, Recipe] | None:
    raw = entry.get(key)
    if raw is None:
        return None
    if not isinstance(raw, dict) or not all(isinstance(r, dict) for r in raw.values()):
        raise TypeError(f"{key} is not an object of recipes")
    return MappingProxyType({k: MappingProxyType(r) for k, r in raw.items()})


def _scalar(raw: Any, what: str) -> Value:
    if not isinstance(raw, bool | int | float | str):
        raise TypeError(f"{what} is not a scalar: {raw!r}")
    return raw


def _optional_number(entry: Mapping[str, Any], key: str) -> int | float | None:
    raw = entry.get(key)
    if raw is None:
        return None
    if isinstance(raw, bool) or not isinstance(raw, int | float):
        raise TypeError(f"{key} is not a number")
    return raw


def _optional_str(entry: Mapping[str, Any], key: str) -> str | None:
    raw = entry.get(key)
    if raw is not None and not isinstance(raw, str):
        raise TypeError(f"{key} is not a string")
    return raw


def _unit(raw: Any) -> SettingUnit | None:
    if raw is None:
        return None
    try:
        return SettingUnit(raw)
    except ValueError:
        return None


def _join_note(note: str | None, extra: str) -> str:
    return extra if not note else f"{note}; {extra}"


def _control_fields(
    kind: SettingKind, entry: Mapping[str, Any], rw: bool
) -> tuple[SettingControl | None, Mapping[str, int], int | None]:
    """``control``, ``flags`` and ``bit`` of an entry, checked against its kind.

    An ``rw`` entry carries a control its kind allows (``OTHER`` none); ``flags`` names
    at least one member, each with a positive bit; ``bit`` is a single positive bit on
    a ``BOOL`` only.
    """
    raw = entry.get("control")
    control = None if raw is None else SettingControl(raw)
    allowed = CONTROLS_BY_KIND[kind]
    if rw and allowed and control not in allowed:
        raise ValueError(f"control {raw!r} for kind {kind.value}")
    if control is not None and control not in allowed:
        raise ValueError(f"control {raw!r} for kind {kind.value}")
    flags: dict[str, int] = {}
    if kind is SettingKind.FLAGS:
        members = entry.get("flags")
        if not isinstance(members, dict) or not members:
            raise ValueError("flags setting names no members")
        for name, bits in members.items():
            if isinstance(bits, bool) or not isinstance(bits, int) or bits <= 0:
                raise ValueError(f"flag {name!r} has no bit")
            flags[str(name)] = bits
    bit = entry.get("bit")
    if bit is not None and (
        kind is not SettingKind.BOOL
        or isinstance(bit, bool)
        or not isinstance(bit, int)
        or bit <= 0
        or bit & (bit - 1)
    ):
        raise ValueError(f"bit {bit!r} on a {kind.value} setting")
    return control, MappingProxyType(flags), bit


def _setting(code: str, key: str, entry: Any) -> Setting:
    if not isinstance(entry, dict):
        raise TypeError(f"{key}: not an object")
    try:
        return _build(code, key, entry)
    except (KeyError, TypeError, ValueError) as err:
        raise type(err)(f"{key}: {err}") from err


def _build(code: str, key: str, entry: dict[str, Any]) -> Setting:
    kind = SettingKind(entry["kind"])
    access = entry["access"]
    if access not in ("rw", "ro"):
        raise ValueError(f"access {access!r}")
    values = tuple(_scalar(v, "value") for v in entry.get("values") or ())
    by_key = {_value_key(v): v for v in values}
    labels_raw = entry.get("labels") or {}
    if not isinstance(labels_raw, dict):
        raise TypeError("labels is not an object")
    labels: dict[Value, str] = {}
    for k, title in labels_raw.items():
        number = _number(k)
        labels[by_key.get(k, k if number is None else number)] = str(title)
    read = entry.get("read")
    read_param: int | None = None
    read_map: dict[str, Value] | None = None
    if read is not None:
        if not isinstance(read, dict) or not isinstance(read.get("param"), int):
            raise TypeError("read is not {param, map}")
        read_param = read["param"]
        if read.get("map") is not None:
            read_map = {str(k): _scalar(v, "read value") for k, v in read["map"].items()}
    when = entry.get("applies_when")
    applies_when = None
    if when is not None:
        if not (isinstance(when, list) and len(when) == 2 and isinstance(when[0], str)):
            raise TypeError("applies_when is not [identifier, value]")
        applies_when = (when[0], _scalar(when[1], "applies_when value"))
    order = entry.get("order")
    if order is not None and (isinstance(order, bool) or not isinstance(order, int)):
        raise TypeError("order is not an int")
    default = entry.get("default")
    name = _optional_str(entry, "name")
    variant_of = _optional_str(entry, "variant_of")
    if variant_of is not None and (variant_of == key or not IDENTIFIER.fullmatch(variant_of)):
        raise ValueError(f"variant_of {variant_of!r}")
    write = _recipe(entry, "write")
    write_standalone = _recipe(entry, "write_standalone")
    table = _table(entry, "write_table")
    table_standalone = _table(entry, "write_table_standalone")
    writable = access == "rw"
    note = _optional_str(entry, "note")
    refusal = None
    standalone_refused = False
    if writable:
        if key == _GUARD_MODE_KEY:
            refusal = _GUARD_MODE_NOTE
        else:
            refusal = _first_refusal([write, *(table or {}).values()])
        if refusal is None:
            alone = _first_refusal([write_standalone, *(table_standalone or {}).values()])
            if alone is not None:
                note = _join_note(note, f"standalone: {alone}")
                standalone_refused = True
    if refusal is not None:
        writable, note = False, _join_note(note, refusal)
    control, flags, bit = _control_fields(kind, entry, access == "rw")
    domain = _optional_str(entry, "domain")
    if domain is not None:
        if kind is not SettingKind.STRING or values:
            raise ValueError(f"domain {domain!r} on a {kind.value} setting with values")
        values = _domain_values(domain)
        if writable and control is not SettingControl.SELECT:
            raise ValueError(f"domain {domain!r} needs control select")
    elif kind is SettingKind.STRING and control is SettingControl.SELECT:
        raise ValueError("control select on a string setting needs a domain")
    return Setting(
        key=key,
        product_code=code,
        name=name or setting_name(key),
        kind=kind,
        values=values,
        minimum=_optional_number(entry, "min"),
        maximum=_optional_number(entry, "max"),
        step=_optional_number(entry, "step"),
        unit=_unit(entry.get("unit")),
        default=None if default is None else _scalar(default, "default"),
        labels=MappingProxyType(labels),
        writable=writable,
        readable=read_param is not None,
        group=_optional_str(entry, "group"),
        order=order,
        page=_optional_str(entry, "page"),
        applies_when=applies_when,
        note=note,
        variant_of=variant_of,
        control=control if writable else None,
        flags=flags,
        bit=bit,
        domain=domain,
        _write=write,
        _write_standalone=write_standalone,
        _write_table=table,
        _write_table_standalone=table_standalone,
        _read_param=read_param,
        _read_map=None if read_map is None else MappingProxyType(read_map),
        _standalone_refused=standalone_refused,
    )
