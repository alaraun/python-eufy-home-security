"""Whether the eufy app reaches a device over WebRTC or P2P, decided as the app decides it.

The inputs per product are the ``is_connect_webrtc*`` properties of its thing
description, generated into ``_webrtc_routing_data.py`` by
``scripts/gen_webrtc_routing.py``; the inputs per device are its serial, product code,
station serial and firmware, and the other devices paired to the same station. One rule
reads them for every device **[declared: eufy app]** (see docs/protocol/media.md,
*WebRTC or P2P*):

- A device paired to a station on the list first reads the station's value: no such
  property or 0 means P2P, 2 means WebRTC; 1 means P2P unless the station itself is
  routed over WebRTC, and then the device's own value decides.
- A device's (or a station's) own value: no such property means P2P; above 0 means
  WebRTC, except that a 1 with a sub-device list means WebRTC only when a product code
  in that list is paired to it.

A property is present when any property whose name starts with it has passing
``available_conditions``; its value is the default of the ``__v`` variant whose
``read_conditions`` pass with the most conditions (the base property when none does),
and reads as empty, so 0, when the chosen property's ``read_conditions`` fail. Pure
functions: no I/O.
"""

from __future__ import annotations

import json
import re
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from types import MappingProxyType
from typing import TYPE_CHECKING, Final

from ._webrtc_routing_data import ROUTE_PROPERTIES, THING_SDK_VERSION
from .model_settings import product_code_of
from .versions import version_bigger_than, version_equals

if TYPE_CHECKING:
    from ..cloud.models import CloudDevice

ROUTE_PROPERTY: Final = "is_connect_webrtc"
SUB_DEVICE_LIST: Final = "is_connect_webrtc_sub_device_list"
CONDITION_TYPES: Final = frozenset(
    {"device_version", "parent_version", "sdk_version", "device_sn", "parent_sn"}
)
"""The condition types the rule evaluates (the generator refuses any other)."""

_VARIANT: Final = "__v"
_MAX_PATTERN: Final = 512
_MAX_VALUE: Final = 2048
_JAVA_INT: Final = re.compile(r"[+-]?[0-9]+")

type _Conditions = tuple[tuple[tuple[str, str, str], ...], ...]


@dataclass(frozen=True, slots=True)
class _Property:
    identifier: str
    default: str
    available: _Conditions
    read: _Conditions


def _conditions(groups: list[list[list[str]]]) -> _Conditions:
    return tuple(tuple((c[0], c[1], c[2]) for c in group) for group in groups)


_PROPERTIES: Final[Mapping[str, tuple[_Property, ...]]] = MappingProxyType(
    {
        code: tuple(
            _Property(identifier, default, _conditions(available), _conditions(read))
            for identifier, default, available, read in props
        )
        for code, props in ROUTE_PROPERTIES.items()
    }
)


@dataclass(frozen=True, slots=True, kw_only=True)
class RouteDevice:
    """One device as the routing rule reads it."""

    serial: str
    product_code: str | None
    station_serial: str | None = None
    """The serial of the station it is paired to; None or its own serial when it stands
    alone or is a station."""
    firmware: str | None = None
    """Its main firmware version (the cloud's ``main_sw_version``); None when unknown,
    which compares as below every version."""

    @property
    def parent(self) -> str:
        """The serial the rule reads as its parent: its station's, else its own."""
        return self.station_serial or self.serial


def route_device(device: CloudDevice) -> RouteDevice:
    """``device`` (a cloud device-list entry) as the routing rule reads it."""
    return RouteDevice(
        serial=device.device_sn,
        product_code=product_code_of(device.raw.get("device_new_pn"), device.device_sn),
        station_serial=device.station_sn,
        firmware=device.main_sw_version,
    )


def _regex(pattern: str, value: str) -> bool:
    """A pattern condition: an empty pattern or value passes; a match anywhere passes."""
    if not pattern or not value:
        return True
    if len(pattern) > _MAX_PATTERN or len(value) > _MAX_VALUE:
        return False
    return re.search(pattern, value) is not None


def _version(version: str, qualifier: str, bound: str) -> bool:
    """A version condition: ``version`` against ``bound`` (:mod:`.versions`)."""
    match qualifier:
        case ">":
            return version_bigger_than(version, bound)
        case "<":
            return version_bigger_than(bound, version)
        case "=":
            return version_equals(version, bound)
        case "!=":
            return not version_equals(version, bound)
        case ">=":
            return version_bigger_than(version, bound) or version_equals(version, bound)
        case "<=":
            return version_bigger_than(bound, version) or version_equals(version, bound)
        case "RE":
            return _regex(bound, version)
    return False


class _Graph:
    """The device list the rule reads: devices by serial and paired product codes."""

    def __init__(self, devices: Iterable[RouteDevice]) -> None:
        self.devices = {d.serial: d for d in devices}

    def parent_of(self, device: RouteDevice) -> RouteDevice | None:
        return self.devices.get(device.parent)

    def paired_codes(self, device: RouteDevice) -> set[str]:
        """The product codes of the devices whose parent is ``device`` (itself included
        when it is its own parent)."""
        return {
            d.product_code.upper()
            for d in self.devices.values()
            if d.parent == device.serial and d.product_code is not None
        }

    def condition(self, device: RouteDevice, kind: str, qualifier: str, value: str) -> bool:
        match kind:
            case "device_version":
                return _version(device.firmware or "", qualifier, value)
            case "parent_version":
                if not value or not qualifier:
                    return True
                parent = self.parent_of(device)
                return _version((parent and parent.firmware) or "", qualifier, value)
            case "sdk_version":
                return _version(THING_SDK_VERSION, qualifier, value)
            case "device_sn":
                return _regex(value, device.serial)
            case "parent_sn":
                return _regex(value, device.parent)
        return False

    def passes(self, device: RouteDevice, groups: _Conditions) -> bool:
        """Whether ``groups`` pass: none at all, or every condition of some group."""
        return not groups or any(
            all(self.condition(device, *cond) for cond in group) for group in groups
        )

    def has(self, device: RouteDevice, identifier: str) -> bool:
        props = _properties(device)
        return any(p.identifier == identifier for p in props) and any(
            p.identifier.startswith(identifier) and self.passes(device, p.available) for p in props
        )

    def resolve(self, device: RouteDevice, identifier: str) -> _Property | None:
        """The property ``identifier`` reads: its ``__v`` variant whose read conditions
        pass with the most conditions (the first of equals), else itself."""
        chosen, most = identifier, -1
        for prop in _properties(device):
            rest = prop.identifier[len(identifier) :]
            if (
                not prop.identifier.startswith(identifier)
                or not rest.lower().startswith(_VARIANT)
                or not prop.read
                or not self.passes(device, prop.read)
            ):
                continue
            count = sum(len(group) for group in prop.read)
            if count > most:
                chosen, most = prop.identifier, count
        return next((p for p in _properties(device) if p.identifier == chosen), None)

    def value(self, device: RouteDevice, identifier: str) -> str:
        """The property's value: its default when readable, else empty."""
        prop = self.resolve(device, identifier)
        if prop is None or not self.passes(device, prop.read):
            return ""
        return prop.default

    def own_value(self, device: RouteDevice) -> int:
        return _as_int(self.value(device, ROUTE_PROPERTY))

    def is_webrtc(self, device: RouteDevice, seen: frozenset[str] = frozenset()) -> bool:
        if device.serial in seen:
            return False
        parent = self.parent_of(device) if device.parent != device.serial else None
        if parent is not None:
            if not self.has(parent, ROUTE_PROPERTY):
                return False
            value = self.own_value(parent)
            if value == 2:
                return True
            if value == 0 or (value == 1 and not self.is_webrtc(parent, seen | {device.serial})):
                return False
        if not self.has(device, ROUTE_PROPERTY):
            return False
        value = self.own_value(device)
        if value == 1 and self.has(device, SUB_DEVICE_LIST):
            paired = self.paired_codes(device)
            return any(code in paired for code in _code_list(self.value(device, SUB_DEVICE_LIST)))
        return value > 0


def _properties(device: RouteDevice) -> tuple[_Property, ...]:
    code = device.product_code
    return () if code is None else _PROPERTIES.get(code.upper(), ())


def _as_int(text: str) -> int:
    """A property value as a number: ``true``/``false`` as 1/0, a 32-bit integer as
    written, anything else 0."""
    lowered = text.lower()
    if lowered in ("true", "false"):
        return int(lowered == "true")
    if not _JAVA_INT.fullmatch(text):
        return 0
    number = int(text)
    return number if -(2**31) <= number < 2**31 else 0


def _code_list(text: str) -> list[str]:
    """A sub-device list: a JSON list of product codes; anything else is empty."""
    try:
        codes = json.loads(text)
    except ValueError:
        return []
    if not isinstance(codes, list) or not all(isinstance(c, str) for c in codes):
        return []
    return codes


def app_uses_webrtc(serial: str, devices: Iterable[RouteDevice]) -> bool:
    """Whether the eufy app reaches the device ``serial`` over WebRTC (live view,
    talkback and commands), given the account's ``devices`` (it among them, with its
    station and every device paired to that station). False for a serial not in
    ``devices``."""
    graph = _Graph(devices)
    device = graph.devices.get(serial)
    return device is not None and graph.is_webrtc(device)


def app_webrtc_only(station: RouteDevice) -> bool:
    """Whether the eufy app reaches ``station`` and every device paired to it over
    WebRTC whatever is paired: the station's own ``is_connect_webrtc`` reads 2."""
    graph = _Graph((station,))
    return graph.has(station, ROUTE_PROPERTY) and graph.own_value(station) == 2
