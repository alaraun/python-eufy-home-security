"""Arming groups (the eufy app's "Group Control"): models, request bodies and parsing.

A group is a house-level list of members, each a station or standalone device with the
guard mode it takes when the group is activated. The cloud stores the groups and logs
each activation; the guard-mode changes themselves are P2P writes to each member (see
:meth:`~..client.EufySecurity.async_activate_arming_group`). Pure: no I/O here. Wire
format: docs/protocol/cloud.md § Arming groups.
"""

from __future__ import annotations

import unicodedata
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import IntEnum, StrEnum
from types import MappingProxyType
from typing import Any, Final

from .._logging import redact, redact_serial
from ..devices.types import serial_prefix
from ..exceptions import EufySecurityError, ProtocolError, UnsupportedError
from ..models import GUARD_MODE_LABELS, GuardMode

MAX_NAME_LENGTH: Final = 31
"""The longest group name the app accepts, counted as the app counts: a character above
U+00FF counts two."""
MAX_GROUPS_PER_HOUSE: Final = 20
"""The app refuses to create a group past this many in one house."""
SHARED_DEVICES_HOUSE_ID: Final = "shared.devices"
"""The app's id for devices shared to the account outside a house: no groups there."""
PROFESSIONAL_ARMING_MODELS: Final = frozenset({"T9000"})
"""Models whose house the app arms with its professional-arming flow, never groups."""
NAME_FORBIDDEN_CHARACTERS: Final = frozenset(
    "`~!$%=|{}:;[]<>/?\\'\""
    # full-width forms of ! ¥ ; : , ? and an ellipsis, CJK brackets, quotes and stops
    "\uff01\uffe5\u2026\u3010\u3011\u2018\uff1b\uff1a\u201d\u201c\u3002\uff0c\u3001\uff1f"
)
"""Characters the app refuses in a group name (with emoji)."""
_EMOJI_JOINERS: Final = frozenset("\u200d\ufe0f\u20e3")

MODE_TITLES: Final[Mapping[GuardMode, str]] = MappingProxyType(
    {mode: label for mode, label in GUARD_MODE_LABELS.items() if mode is not GuardMode.OFF}
)
"""The ``mode`` title sent with each member: the app's English mode names, which are
the display labels (:data:`~..models.GUARD_MODE_LABELS`). For a custom mode the app
sends the mode's own name; ``Custom N`` stands in when it is not known. Every writable
guard mode is a key (:attr:`GuardMode.OFF` is report-only)."""


class ArmingGroupPreset(IntEnum):
    """A group's ``default`` field: the app draws a preset group with its own icon."""

    USER = 0
    LEAVING = 1
    """The app's "I'm Leaving" preset (every member to Away)."""
    STAYING = 2
    """The app's "I'm Staying" preset (every member to Home)."""


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class ArmingGroupMember:
    """One member of a group: a station or standalone device and its target mode."""

    device_sn: str
    mode: GuardMode | int
    """The guard mode the member takes on activation (``mode_id``); a plain int for a
    code :class:`GuardMode` does not name."""
    title: str = ""
    """The mode's display name stored with the member (``mode``)."""
    bypass: bool = False
    """``isBypass`` as the cloud reports it; the app only dims such a member."""

    def __repr__(self) -> str:
        return (
            f"ArmingGroupMember(device_sn={redact_serial(self.device_sn)!r}, "
            f"mode={self.mode!r}, bypass={self.bypass})"
        )


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class ArmingGroup:
    """One arming group of a house (``guard_list`` ``data.groups[]``)."""

    group_id: str
    name: str
    status: str = "0"
    """The cloud's ``status`` as sent: ``"1"`` marks the group the app shows highlighted,
    the last one activated (inferred, not verified)."""
    preset: ArmingGroupPreset | int = ArmingGroupPreset.USER
    members: tuple[ArmingGroupMember, ...] = ()

    @property
    def active(self) -> bool:
        """Whether :attr:`status` is ``"1"``."""
        return self.status == "1"

    def __repr__(self) -> str:
        """The name redacted: a repr lands in logs."""
        return (
            f"ArmingGroup(group_id={self.group_id!r}, name={redact(self.name)!r}, "
            f"status={self.status!r}, preset={self.preset!r}, members={self.members!r})"
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class ArmingGroupList:
    """A house's arming groups as ``guard_list`` answers them, in the cloud's order."""

    house_id: str
    groups: tuple[ArmingGroup, ...] = ()
    guided: int | None = None
    """``data.guided``: 2 once the app's group introduction was completed; any other value
    shows the app's "Create Your Group Now" card instead of the groups. None if absent."""


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class ArmingGroupLog:
    """One activation record of a group (``get_guard_logs`` ``data.logs[]``)."""

    group_id: str
    group_name: str = ""
    user_id: str = ""
    user_name: str = ""
    create_time: int
    """The activation time as the cloud sends it: epoch seconds (:attr:`created_at`)."""

    @property
    def created_at(self) -> datetime:
        """:attr:`create_time` as an aware UTC datetime."""
        return datetime.fromtimestamp(self.create_time, UTC)

    def __repr__(self) -> str:
        return (
            f"ArmingGroupLog(group_id={self.group_id!r}, group_name={redact(self.group_name)!r}, "
            f"user_id={redact(self.user_id)!r}, user_name={redact(self.user_name)!r}, "
            f"create_time={self.create_time})"
        )


class ArmingOutcome(StrEnum):
    """What activating a group did to one member."""

    CHANGED = "changed"
    """The guard-mode write was sent and the station confirmed the target mode."""
    ALREADY = "already"
    """The station reported the target mode already; nothing was sent."""
    SKIPPED_OFFLINE = "skipped_offline"
    """The station's session is down; nothing was sent and nothing is retried."""
    FAILED = "failed"
    """The member could not be set: :attr:`ArmingMemberResult.error` says why."""


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class ArmingMemberResult:
    """One member's outcome of an activation."""

    device_sn: str
    mode: GuardMode | int
    """The group's target mode for this member."""
    outcome: ArmingOutcome
    applied: GuardMode | int | None = None
    """The mode the station reported it applied (:attr:`ArmingOutcome.CHANGED` only)."""
    error: EufySecurityError | None = None
    """Why the member failed (:attr:`ArmingOutcome.FAILED` only)."""

    def __repr__(self) -> str:
        return (
            f"ArmingMemberResult(device_sn={redact_serial(self.device_sn)!r}, "
            f"mode={self.mode!r}, outcome={self.outcome!r}, applied={self.applied!r}, "
            f"error={self.error!r})"
        )


@dataclass(frozen=True, slots=True, kw_only=True)
class ArmingActivation:
    """The result of activating a group: the cloud recorded it, then each member's write."""

    group: ArmingGroup
    results: tuple[ArmingMemberResult, ...]

    @property
    def complete(self) -> bool:
        """Whether every member is now in its target mode (changed or already)."""
        done = (ArmingOutcome.CHANGED, ArmingOutcome.ALREADY)
        return all(result.outcome in done for result in self.results)


# ── houses, members, names and modes ────────────────────────────────────────


@dataclass(frozen=True, slots=True, kw_only=True, repr=False)
class ArmingHouse:
    """The house an arming-group call works on: its id, the login scope that lists it,
    and the serials that may be members (its stations and standalone devices)."""

    house_id: str
    region: str
    stations: frozenset[str]

    def __repr__(self) -> str:
        return (
            f"ArmingHouse(house_id={redact(self.house_id)!r}, region={self.region!r}, "
            f"stations={sorted(redact_serial(s) for s in self.stations)!r})"
        )


def uses_professional_arming(serials: Iterable[str]) -> bool:
    """Whether a house holding ``serials`` is armed with the app's professional-arming
    flow (:data:`PROFESSIONAL_ARMING_MODELS`), which replaces groups."""
    return any(serial_prefix(serial) in PROFESSIONAL_ARMING_MODELS for serial in serials)


def find_group(listing: ArmingGroupList, group_id: str) -> ArmingGroup:
    """The group ``group_id`` of ``listing``; :class:`UnsupportedError` when the house
    has none."""
    for group in listing.groups:
        if group.group_id == group_id:
            return group
    raise UnsupportedError(f"the house has no arming group {group_id!r}")


def check_unique_name(listing: ArmingGroupList, name: str, *, group_id: str | None = None) -> None:
    """:class:`ValueError` when another group of the house (not ``group_id``) is
    already named ``name``."""
    if any(g.name.strip() == name and g.group_id != group_id for g in listing.groups):
        raise ValueError("the house already has an arming group of that name")


def build_members(
    house: ArmingHouse,
    targets: Mapping[str, GuardMode],
    previous: ArmingGroup | None = None,
    *,
    titles: Mapping[str, str] | None = None,
) -> tuple[ArmingGroupMember, ...]:
    """The members to send for ``targets`` (serial → mode), in their order.

    :class:`UnsupportedError` for a serial that is not a station or standalone device of
    ``house``. A member's title is its station's name for the mode where ``titles``
    (serial → name) gives one, else, for a member of ``previous`` keeping its mode, its
    stored title (a custom mode's name), else :func:`mode_title`.
    """
    stored = {} if previous is None else {m.device_sn: m for m in previous.members}
    named = titles or {}
    members = []
    for serial, mode in targets.items():
        if serial not in house.stations:
            raise UnsupportedError(
                f"{redact_serial(serial)} is not a station or standalone device of the house"
            )
        old = stored.get(serial)
        title = named.get(serial, "")
        if not title and old is not None and old.mode == mode:
            title = old.title
        members.append(
            ArmingGroupMember(device_sn=serial, mode=mode, title=title or mode_title(mode))
        )
    return tuple(members)


def target_modes(members: Mapping[str, GuardMode | int | str]) -> dict[str, GuardMode]:
    """``members`` (serial → mode) with each mode checked by :func:`target_mode`;
    :class:`ValueError` for an empty mapping or a mode that cannot be a target."""
    if not members:
        raise ValueError("an arming group needs at least one member")
    return {serial: target_mode(mode) for serial, mode in members.items()}


def name_length(name: str) -> int:
    """``name``'s length as the app counts it: two for a character above U+00FF."""
    return sum(2 if ord(char) > 0xFF else 1 for char in name)


def check_group_name(name: str) -> str:
    """``name`` trimmed, as the app sends it; :class:`ValueError` when the app would
    refuse it: blank, longer than :data:`MAX_NAME_LENGTH`, or holding a character of
    :data:`NAME_FORBIDDEN_CHARACTERS` or an emoji."""
    trimmed = name.strip()
    if not trimmed:
        raise ValueError("an arming group name must not be blank")
    if name_length(trimmed) > MAX_NAME_LENGTH:
        raise ValueError(
            f"an arming group name is at most {MAX_NAME_LENGTH} characters "
            "(two for each character above U+00FF)"
        )
    bad = sorted({char for char in trimmed if char in NAME_FORBIDDEN_CHARACTERS or _emoji(char)})
    if bad:
        raise ValueError(
            f"an arming group name must not contain {''.join(bad)!r}: "
            "special characters and emoji are not supported"
        )
    return trimmed


def _emoji(char: str) -> bool:
    """Whether ``char`` is an emoji, an emoji joiner, or another pictographic symbol."""
    return (
        char in _EMOJI_JOINERS or ord(char) >= 0x1F000 or unicodedata.category(char) in {"So", "Cs"}
    )


def target_mode(mode: GuardMode | int | str) -> GuardMode:
    """``mode`` as a writable :class:`GuardMode` (a name or a code, see
    :meth:`GuardMode.parse`); :class:`ValueError` for anything else, including the
    report-only :attr:`GuardMode.OFF`."""
    parsed = GuardMode.parse(mode)
    if parsed not in MODE_TITLES:
        raise ValueError(f"guard mode {parsed.name.lower()} cannot be a group target")
    return parsed


def mode_title(mode: GuardMode | int) -> str:
    """The ``mode`` title the app stores with ``mode`` (:data:`MODE_TITLES`); the code as
    text for one it does not name."""
    return MODE_TITLES.get(mode, str(int(mode))) if isinstance(mode, GuardMode) else str(mode)


# ── request bodies ───────────────────────────────────────────────────────────


def member_body(member: ArmingGroupMember) -> dict[str, Any]:
    """One member as the app sends it: serial, mode title and mode code."""
    return {
        "device_sn": member.device_sn,
        "mode": member.title or mode_title(member.mode),
        "mode_id": int(member.mode),
    }


def list_body(house_id: str) -> dict[str, Any]:
    """``guard_list``: the house's groups."""
    return {"house_id": house_id}


def add_body(house_id: str, name: str, members: Sequence[ArmingGroupMember]) -> dict[str, Any]:
    """``add_guard``: a user group (``default`` 0) with ``members``."""
    return {
        "house_id": house_id,
        "group_name": name,
        "devices": [member_body(m) for m in members],
        "default": int(ArmingGroupPreset.USER),
    }


def update_body(
    house_id: str, group_id: str, *, name: str, members: Sequence[ArmingGroupMember]
) -> dict[str, Any]:
    """``update_guard``: the group's name and its whole member list (never a delta).
    Both are always sent: the cloud refuses an update that lacks either, so a rename
    carries the current members and a member change the current name."""
    return {
        "house_id": house_id,
        "group_id": group_id,
        "group_name": name,
        "devices": [member_body(m) for m in members],
    }


def delete_body(house_id: str, group_id: str) -> dict[str, Any]:
    """``delete_guard``."""
    return {"house_id": house_id, "group_id": group_id}


def activate_body(house_id: str, group_id: str, user_name: str) -> dict[str, Any]:
    """``setup_guard``: records the activation by ``user_name`` (``enable`` is always true
    in the app)."""
    return {"house_id": house_id, "group_id": group_id, "user_name": user_name, "enable": True}


def logs_body(house_id: str, group_id: str) -> dict[str, Any]:
    """``get_guard_logs``."""
    return {"house_id": house_id, "group_id": group_id}


# ── parsing ──────────────────────────────────────────────────────────────────


def parse_group_list(data: object, house_id: str, path: str) -> ArmingGroupList:
    """A ``guard_list`` answer's ``data``; unknown keys are ignored.

    No data, or ``groups`` null, is an empty list. :class:`ProtocolError` for data that
    is not an object, one without a ``groups`` key, or a malformed group.
    """
    if data is None:
        return ArmingGroupList(house_id=house_id)
    entry = _object(data, path, "data")
    if "groups" not in entry:
        raise ProtocolError(f"cloud response to {path} has no groups")
    groups = entry["groups"]
    if groups is None:
        groups = []
    if not isinstance(groups, list):
        raise ProtocolError(f"cloud response to {path} has no group list")
    guided = entry.get("guided")
    return ArmingGroupList(
        house_id=house_id,
        groups=tuple(parse_group(g, path) for g in groups),
        guided=_optional_int(guided),
    )


def parse_group(data: object, path: str) -> ArmingGroup:
    """One ``groups[]`` entry: ``group_id`` and ``group_name`` required, the rest
    defaulted when absent (``status`` ``"0"``, a user group, no members)."""
    entry = _object(data, path, "group")
    preset = _optional_int(entry.get("default"))
    devices = entry.get("devices")
    if devices is None:
        devices = []
    if not isinstance(devices, list):
        raise ProtocolError(f"cloud response to {path} has a group whose devices are no list")
    status = entry.get("status")
    return ArmingGroup(
        group_id=_required_text(entry, "group_id", path),
        name=_required_text(entry, "group_name", path, allow_empty=True),
        status="0" if status is None else str(status),
        preset=ArmingGroupPreset.USER if preset is None else _preset(preset),
        members=tuple(parse_member(d, path) for d in devices),
    )


def parse_member(data: object, path: str) -> ArmingGroupMember:
    """One ``devices[]`` entry of a group: ``device_sn`` and ``mode_id`` required."""
    entry = _object(data, path, "group member")
    mode_id = _optional_int(entry.get("mode_id"))
    if mode_id is None:
        raise ProtocolError(f"cloud response to {path} has a group member without mode_id")
    title = entry.get("mode")
    return ArmingGroupMember(
        device_sn=_required_text(entry, "device_sn", path),
        mode=_guard_mode(mode_id),
        title=title if isinstance(title, str) else "",
        bypass=entry.get("isBypass") is True,
    )


def parse_logs(data: object, path: str) -> tuple[ArmingGroupLog, ...]:
    """A ``get_guard_logs`` answer's ``data.logs``, in the cloud's order; no data or no
    logs is an empty tuple. Each log needs ``group_id`` and ``create_time``."""
    if data is None:
        return ()
    logs = _object(data, path, "data").get("logs")
    if logs is None:
        return ()
    if not isinstance(logs, list):
        raise ProtocolError(f"cloud response to {path} has no log list")
    return tuple(_parse_log(entry, path) for entry in logs)


def _parse_log(data: object, path: str) -> ArmingGroupLog:
    entry = _object(data, path, "log")
    created = _optional_int(entry.get("create_time"))
    if created is None:
        raise ProtocolError(f"cloud response to {path} has a log without create_time")
    return ArmingGroupLog(
        group_id=_required_text(entry, "group_id", path),
        group_name=_text(entry.get("group_name")),
        user_id=_text(entry.get("user_id")),
        user_name=_text(entry.get("user_name")),
        create_time=created,
    )


def _object(data: object, path: str, what: str) -> Mapping[str, Any]:
    if not isinstance(data, Mapping):
        raise ProtocolError(f"cloud response to {path}: the {what} is not an object")
    return data


def _required_text(
    entry: Mapping[str, Any], key: str, path: str, *, allow_empty: bool = False
) -> str:
    value = entry.get(key)
    if isinstance(value, int) and not isinstance(value, bool):
        value = str(value)
    if not isinstance(value, str) or not (value or allow_empty):
        raise ProtocolError(f"cloud response to {path} lacks {key}")
    return value


def _text(value: object) -> str:
    if isinstance(value, int) and not isinstance(value, bool):
        return str(value)
    return value if isinstance(value, str) else ""


def _optional_int(value: object) -> int | None:
    """An int, or a string of digits, as an int; None for anything else."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    if isinstance(value, str) and value.strip().lstrip("-").isdigit():
        return int(value)
    return None


def _guard_mode(code: int) -> GuardMode | int:
    try:
        return GuardMode(code)
    except ValueError:
        return code


def _preset(code: int) -> ArmingGroupPreset | int:
    try:
        return ArmingGroupPreset(code)
    except ValueError:
        return code
