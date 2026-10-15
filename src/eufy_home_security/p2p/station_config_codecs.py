"""Station configuration a station keeps as base64 JSON parameters (pure).

Each value is the base64 of a compact JSON document; a param that is absent (``None``)
or blank decodes to ``None`` (or an empty tuple for the tracking groups). Undecodable
input raises :class:`~..exceptions.ProtocolError`; a value the station could not take
raises :class:`ValueError` before anything is built.

- 1256 the guard-mode list (:class:`CustomModes`), with the add / modify / delete
  bodies of a 1256 write (:func:`add_custom_mode`, :func:`modify_custom_mode`,
  :func:`delete_custom_mode`);
- 1254 the weekly schedule (:class:`Schedule`) and 1257 the mode outside every slot;
- 1157-1161, 1177 the whole action table of each mode as a HomeBase 3 stores it
  (:class:`StoredModeTable`, same keys as the 1255 body of :mod:`.mode_actions`);
- 1072 the cameras chosen for cross-camera tracking, 1073 the tracking groups.

**JSON style.** Every encoder emits compact JSON (``","`` and ``":"``, no spaces),
non-ASCII as UTF-8, and escapes ``<``, ``>``, ``&``, ``=``, ``'``, U+2028 and U+2029
as ``\\uXXXX``: the style of the values the station stores. 1256 and 1254 objects
list their keys sorted; a stored mode table keeps the 1255 body's order. Standard
base64 with padding. ``encode(decode(value))`` gives back ``value`` (without
surrounding whitespace) for any document in that style whose numbers are JSON
integers. See ``docs/protocol/commands.md`` § Station configuration.
"""

from __future__ import annotations

import base64
import binascii
import json
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from datetime import time
from enum import IntEnum
from types import MappingProxyType
from typing import Any, Final

from ..exceptions import ProtocolError
from ..models import PARAM_SUB_DEVICE_ASSOCIATION, PARAM_SUB_DEVICE_SERIALS, GuardMode
from ._json import json_int, loads_json
from .mode_actions import CountDown, ModeTable

CMD_CUSTOM_MODES: Final = 1256
"""``SET_CUSTOM_MODE``: the mode-list param and the frame type of its write."""
CMD_SCHEDULE: Final = 1254
"""``SET_JSON_SCHEDULE``: the schedule param and the frame type of its write."""
CMD_SCHEDULE_DEFAULT: Final = 1257
"""``SET_SCHEDULE_DEFAULT``: the mode outside every schedule slot (an integer)."""
PARAM_TRACKING_CAMERAS: Final = PARAM_SUB_DEVICE_SERIALS
"""1072: the cameras chosen for cross-camera tracking."""
PARAM_TRACKING_GROUPS: Final = PARAM_SUB_DEVICE_ASSOCIATION
"""1073: the cross-camera tracking groups."""

STORED_MODE_TABLE_PARAMS: Final[Mapping[GuardMode, int]] = MappingProxyType(
    {
        GuardMode.HOME: 1157,
        GuardMode.AWAY: 1158,
        GuardMode.CUSTOM_1: 1159,
        GuardMode.CUSTOM_2: 1160,
        GuardMode.CUSTOM_3: 1161,
        GuardMode.DISARMED: 1177,
    }
)
"""The param that holds each mode's whole table on a HomeBase 3 (absent = never set)."""

CUSTOM_MODES: Final[tuple[GuardMode, ...]] = (
    GuardMode.CUSTOM_1,
    GuardMode.CUSTOM_2,
    GuardMode.CUSTOM_3,
)
"""The modes a user can add, rename and delete, in the order an add fills them."""

BUILT_IN_MODE_TITLES: Final[Mapping[GuardMode, str]] = MappingProxyType(
    {GuardMode.HOME: "Home", GuardMode.AWAY: "Away", GuardMode.DISARMED: "Disarmed"}
)
"""The modes every station offers, with the titles the app shows whatever 1256 says."""

SCHEDULE_MODES: Final[tuple[GuardMode, ...]] = (
    GuardMode.AWAY,
    GuardMode.HOME,
    *CUSTOM_MODES,
    GuardMode.DISARMED,
)
"""The modes a schedule slot or the schedule default can name."""

MAX_TITLE_LENGTH: Final = 30
"""Longest mode title the app accepts (after trimming)."""
MAX_DETAIL_LENGTH: Final = 60
"""Longest mode description the app accepts."""

_ADDED_MODE_ACTION_FLAGS: Final = 1 | 8  # record | notification
_GSON_ESCAPES: Final = str.maketrans(
    {c: f"\\u{ord(c):04x}" for c in ("<", ">", "&", "=", "'", "\u2028", "\u2029")}
)


class ModeOperation(IntEnum):
    """``operate_type`` of a 1256 write."""

    ADD = 100
    DELETE = 101
    MODIFY = 102


class Weekday(IntEnum):
    """A schedule slot's ``week``: 0 is Sunday."""

    SUNDAY = 0
    MONDAY = 1
    TUESDAY = 2
    WEDNESDAY = 3
    THURSDAY = 4
    FRIDAY = 5
    SATURDAY = 6


# --- shared helpers ---------------------------------------------------------


def _dumps(obj: object, *, sort_keys: bool) -> str:
    text = json.dumps(obj, separators=(",", ":"), ensure_ascii=False, sort_keys=sort_keys)
    # The escaped characters only occur inside JSON strings, so a plain translate is safe.
    return text.translate(_GSON_ESCAPES)


def _b64(text: str) -> str:
    return base64.b64encode(text.encode()).decode("ascii")


def _blank(raw: object) -> bool:
    return raw is None or (isinstance(raw, str) and not raw.strip())


def _b64_json(raw: object, what: str) -> Any:
    if not isinstance(raw, str):
        raise ProtocolError(f"{what}: expected a base64 string, got {type(raw).__name__}")
    try:
        data = base64.b64decode(raw.strip(), validate=True)
    except (binascii.Error, ValueError) as exc:
        raise ProtocolError(f"{what}: not base64 ({exc})") from None
    try:
        return loads_json(data)
    except ProtocolError as exc:
        raise ProtocolError(f"{what}: {exc}") from None


def _obj(value: object, what: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        raise ProtocolError(f"{what}: expected a JSON object, got {value!r}")
    return value


def _list(value: object, what: str) -> list[Any]:
    if not isinstance(value, list):
        raise ProtocolError(f"{what}: expected a JSON list, got {value!r}")
    return value


def _int(obj: Mapping[str, Any], key: str, what: str) -> int:
    value = json_int(obj.get(key))
    if value is None:
        raise ProtocolError(f"{what}: {key!r} is not an integer: {obj.get(key)!r}")
    return value


def _str(obj: Mapping[str, Any], key: str, what: str) -> str:
    value = obj.get(key)
    if not isinstance(value, str):
        raise ProtocolError(f"{what}: {key!r} is not a string: {value!r}")
    return value


def _opt_str(obj: Mapping[str, Any], key: str, what: str) -> str | None:
    return None if key not in obj else _str(obj, key, what)


def _opt_int(obj: Mapping[str, Any], key: str, what: str) -> int | None:
    return None if key not in obj else _int(obj, key, what)


def _guard_mode(code: int, what: str, allowed: Iterable[GuardMode] | None = None) -> GuardMode:
    try:
        mode = GuardMode(code)
    except ValueError:
        raise ProtocolError(f"{what}: unknown guard mode {code}") from None
    if allowed is not None and mode not in allowed:
        raise ProtocolError(f"{what}: guard mode {mode.name.lower()} is not allowed here")
    return mode


def _to_mode(value: GuardMode | int, what: str) -> GuardMode:
    if isinstance(value, bool) or not isinstance(value, int):
        raise ValueError(f"{what} must be a guard mode, got {value!r}")
    try:
        return GuardMode(value)
    except ValueError:
        raise ValueError(f"{what}: unknown guard mode {value}") from None


def _non_negative(what: str, value: object) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
        raise ValueError(f"{what} must be a non-negative integer, got {value!r}")
    return value


def _put(obj: dict[str, Any], key: str, value: object) -> None:
    if value is not None:
        obj[key] = value


# --- 1256: the guard-mode list ----------------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class ModeDefinition:
    """One entry of the 1256 mode list.

    ``detail`` and ``mode_action`` are ``None`` when the entry leaves them out;
    ``extra`` keeps any other key verbatim so a write carries it back.
    """

    mode: GuardMode
    title: str
    icon_type: int
    detail: str | None = None
    mode_action: int | None = None
    extra: Mapping[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        """The entry as its JSON object."""
        obj: dict[str, Any] = {**self.extra, "mode": int(self.mode), "title": self.title}
        obj["iconType"] = self.icon_type
        _put(obj, "detail", self.detail)
        _put(obj, "mode_action", self.mode_action)
        return obj


_MODE_KEYS: Final = frozenset({"mode", "title", "iconType", "detail", "mode_action"})


@dataclass(frozen=True, slots=True, kw_only=True)
class CustomModes:
    """The 1256 document: the mode list and the operation that last wrote it.

    The same shape is both the stored param and the body of a write. A key the
    document leaves out is ``None`` and is left out again on encode.
    """

    account_id: str | None
    mode_id: GuardMode | None
    """The mode the last operation named."""
    operate_type: int | None
    """The last operation (:class:`ModeOperation`)."""
    modes: tuple[ModeDefinition, ...]

    def get(self, mode: GuardMode) -> ModeDefinition | None:
        """The listed entry for ``mode``, if any."""
        return next((m for m in self.modes if m.mode == mode), None)

    def custom_modes(self) -> tuple[GuardMode, ...]:
        """The custom modes that exist (listed), in code order."""
        return tuple(m for m in CUSTOM_MODES if self.get(m) is not None)

    def titles(self) -> dict[GuardMode, str]:
        """The modes the app offers with their titles: Home, Away, each listed custom
        mode with its title, Disarmed. Built-in titles are fixed."""
        out = {GuardMode.HOME: BUILT_IN_MODE_TITLES[GuardMode.HOME]}
        out[GuardMode.AWAY] = BUILT_IN_MODE_TITLES[GuardMode.AWAY]
        for entry in sorted(self.modes, key=lambda m: m.mode):
            if entry.mode in CUSTOM_MODES:
                out[entry.mode] = entry.title
        out[GuardMode.DISARMED] = BUILT_IN_MODE_TITLES[GuardMode.DISARMED]
        return out

    def defined_modes(self) -> frozenset[GuardMode]:
        """Every mode :meth:`titles` lists."""
        return frozenset(self.titles())

    def request(self) -> dict[str, Any]:
        """The document as a JSON object (``account_id``, ``mode_id``, ``modes``,
        ``operate_type``)."""
        obj: dict[str, Any] = {}
        _put(obj, "account_id", self.account_id)
        _put(obj, "mode_id", None if self.mode_id is None else int(self.mode_id))
        obj["modes"] = [m.to_json() for m in self.modes]
        _put(obj, "operate_type", self.operate_type)
        return obj

    def body(self) -> bytes:
        """The JSON bytes sent as the body of a 1256 frame."""
        return _dumps(self.request(), sort_keys=True).encode()

    def param_value(self) -> str:
        """The base64 value the station stores in param 1256."""
        return base64.b64encode(self.body()).decode("ascii")


def decode_custom_modes(raw: str | None) -> CustomModes | None:
    """Param 1256 → :class:`CustomModes`; ``None`` when absent or blank.

    Raises ``ProtocolError`` for input that is not that document (bad base64 or
    JSON, a missing or mistyped field, an unknown or repeated mode).
    """
    if _blank(raw):
        return None
    what = "custom modes (1256)"
    body = _obj(_b64_json(raw, what), what)
    modes: list[ModeDefinition] = []
    for entry in _list(body.get("modes"), f"{what} modes"):
        item = _obj(entry, f"{what} mode entry")
        mode = _guard_mode(_int(item, "mode", what), what)
        if any(m.mode == mode for m in modes):
            raise ProtocolError(f"{what}: mode {mode.name.lower()} listed twice")
        modes.append(
            ModeDefinition(
                mode=mode,
                title=_str(item, "title", what),
                icon_type=_int(item, "iconType", what),
                detail=_opt_str(item, "detail", what),
                mode_action=_opt_int(item, "mode_action", what),
                extra={k: v for k, v in item.items() if k not in _MODE_KEYS},
            )
        )
    mode_id = _opt_int(body, "mode_id", what)
    return CustomModes(
        account_id=_opt_str(body, "account_id", what),
        mode_id=None if mode_id is None else _guard_mode(mode_id, what),
        operate_type=_opt_int(body, "operate_type", what),
        modes=tuple(modes),
    )


def _require_custom(mode: GuardMode | int, action: str) -> GuardMode:
    guard_mode = _to_mode(mode, f"the mode to {action}")
    if guard_mode not in CUSTOM_MODES:
        raise ValueError(
            f"cannot {action} {guard_mode.name.lower()}: only custom modes 1-3 can be changed"
        )
    return guard_mode


def _clean_title(current: CustomModes | None, title: object, mode: GuardMode) -> str:
    if not isinstance(title, str) or not title.strip():
        raise ValueError("a mode title must not be empty")
    text = title.strip()
    if len(text) > MAX_TITLE_LENGTH:
        raise ValueError(f"a mode title has at most {MAX_TITLE_LENGTH} characters, got {len(text)}")
    titles = current.titles() if current is not None else dict(BUILT_IN_MODE_TITLES)
    for other, other_title in titles.items():
        if other != mode and other_title == text:
            raise ValueError(f"mode title {text!r} is already used by {other.name.lower()}")
    return text


def _clean_detail(detail: object) -> str:
    if not isinstance(detail, str):
        raise ValueError(f"a mode detail must be a string, got {detail!r}")
    if len(detail) > MAX_DETAIL_LENGTH:
        raise ValueError(
            f"a mode detail has at most {MAX_DETAIL_LENGTH} characters, got {len(detail)}"
        )
    return detail


def _written(modes: Iterable[ModeDefinition]) -> tuple[ModeDefinition, ...]:
    # The app adds Disarmed itself and never writes it into the list.
    return tuple(m for m in modes if m.mode != GuardMode.DISARMED)


def add_custom_mode(
    current: CustomModes | None,
    *,
    account_id: str,
    title: str,
    icon_type: int,
    detail: str = "",
    mode: GuardMode | int | None = None,
) -> CustomModes:
    """The 1256 add body (100): the current list plus a new custom mode.

    ``current`` ``None`` is an empty list. ``mode`` defaults to the first free of
    Custom 1-3. The new entry's ``mode_action`` is ``mode << 24 | 9`` (record and
    notification), as the app sets it. Raises ``ValueError`` when no custom slot is
    free, ``mode`` is not a free custom mode, or the title is empty, longer than
    :data:`MAX_TITLE_LENGTH` after trimming or already used, or ``detail`` is longer
    than :data:`MAX_DETAIL_LENGTH`.
    """
    existing = current.custom_modes() if current is not None else ()
    if mode is None:
        free = [m for m in CUSTOM_MODES if m not in existing]
        if not free:
            raise ValueError("all three custom modes exist; delete one first")
        new_mode = free[0]
    else:
        new_mode = _require_custom(mode, "add")
        if new_mode in existing:
            raise ValueError(f"{new_mode.name.lower()} already exists")
    entry = ModeDefinition(
        mode=new_mode,
        title=_clean_title(current, title, new_mode),
        icon_type=_non_negative("icon_type", icon_type),
        detail=_clean_detail(detail),
        mode_action=int(new_mode) << 24 | _ADDED_MODE_ACTION_FLAGS,
    )
    return CustomModes(
        account_id=account_id,
        mode_id=new_mode,
        operate_type=ModeOperation.ADD,
        modes=(*_written(current.modes if current is not None else ()), entry),
    )


def modify_custom_mode(
    current: CustomModes,
    mode: GuardMode | int,
    *,
    account_id: str,
    title: str | None = None,
    icon_type: int | None = None,
    detail: str | None = None,
) -> CustomModes:
    """The 1256 modify body (102): ``mode``'s entry with the given fields replaced.

    Raises ``ValueError`` when ``mode`` is not an existing custom mode, or for a
    title or detail :func:`add_custom_mode` would refuse.
    """
    target = _require_custom(mode, "modify")
    entry = current.get(target)
    if entry is None:
        raise ValueError(f"{target.name.lower()} does not exist")
    changed = replace(
        entry,
        title=entry.title if title is None else _clean_title(current, title, target),
        icon_type=entry.icon_type if icon_type is None else _non_negative("icon_type", icon_type),
        detail=entry.detail if detail is None else _clean_detail(detail),
    )
    return CustomModes(
        account_id=account_id,
        mode_id=target,
        operate_type=ModeOperation.MODIFY,
        modes=_written(changed if m.mode == target else m for m in current.modes),
    )


def delete_custom_mode(
    current: CustomModes,
    mode: GuardMode | int,
    *,
    account_id: str,
    schedule: Schedule | None = None,
) -> CustomModes:
    """The 1256 delete body (101): the current list without ``mode``.

    Raises ``ValueError`` when ``mode`` is a built-in mode or not listed, or when
    ``schedule`` has a slot in it (the app asks to change the schedule first).
    """
    target = _require_custom(mode, "delete")
    if current.get(target) is None:
        raise ValueError(f"{target.name.lower()} does not exist")
    if schedule is not None and target in schedule.modes():
        raise ValueError(
            f"{target.name.lower()} is used by the schedule; change the schedule first"
        )
    return CustomModes(
        account_id=account_id,
        mode_id=target,
        operate_type=ModeOperation.DELETE,
        modes=_written(m for m in current.modes if m.mode != target),
    )


# --- 1254 / 1257: the schedule ----------------------------------------------


def _check_time(what: str, value: object) -> time:
    if not isinstance(value, time):
        raise ValueError(f"{what} must be a datetime.time, got {value!r}")
    if value.tzinfo is not None or value.second or value.microsecond:
        raise ValueError(f"{what} must be a whole minute without a time zone, got {value!r}")
    return value


@dataclass(frozen=True, slots=True)
class ScheduleSlot:
    """One schedule slot: ``mode`` from ``start`` up to ``end`` on ``weekday``.

    An integer ``weekday`` or ``mode`` is converted to its enum. Raises ``ValueError`` unless
    ``start < end`` (whole minutes, no time zone) and ``mode`` is in
    :data:`SCHEDULE_MODES`.
    """

    weekday: Weekday
    start: time
    end: time
    mode: GuardMode

    def __post_init__(self) -> None:
        weekday: object = self.weekday
        if isinstance(weekday, bool) or not isinstance(weekday, int) or not 0 <= weekday <= 6:
            raise ValueError(f"weekday must be 0 (Sunday) to 6, got {weekday!r}")
        object.__setattr__(self, "weekday", Weekday(weekday))
        mode = _to_mode(self.mode, "a slot's mode")
        if mode not in SCHEDULE_MODES:
            raise ValueError(f"a schedule slot cannot use {mode.name.lower()}")
        object.__setattr__(self, "mode", mode)
        if _check_time("start", self.start) >= _check_time("end", self.end):
            raise ValueError(f"a slot must start before it ends: {self.start} - {self.end}")

    def overlaps(self, other: ScheduleSlot) -> bool:
        """Whether both slots share a minute of the same weekday (an end is exclusive)."""
        return self.weekday == other.weekday and self.start < other.end and other.start < self.end

    def to_json(self) -> dict[str, int]:
        """The slot as its JSON object."""
        return {
            "week": int(self.weekday),
            "start_h": self.start.hour,
            "start_m": self.start.minute,
            "end_h": self.end.hour,
            "end_m": self.end.minute,
            "mode_id": int(self.mode),
        }


@dataclass(frozen=True, slots=True, kw_only=True)
class Schedule:
    """The 1254 document: the whole weekly table, slots in their stored order.

    Raises ``ValueError`` when two slots of a weekday overlap.
    """

    account_id: str | None
    slots: tuple[ScheduleSlot, ...] = ()

    def __post_init__(self) -> None:
        slots = tuple(self.slots)
        object.__setattr__(self, "slots", slots)
        for i, slot in enumerate(slots):
            if not isinstance(slot, ScheduleSlot):
                raise ValueError(f"a schedule holds ScheduleSlot entries, got {slot!r}")
            for other in slots[:i]:
                if slot.overlaps(other):
                    raise ValueError(
                        f"slots overlap on {slot.weekday.name.lower()}: "
                        f"{other.start}-{other.end} and {slot.start}-{slot.end}"
                    )

    def modes(self) -> frozenset[GuardMode]:
        """Every mode a slot uses."""
        return frozenset(slot.mode for slot in self.slots)

    def require_defined(self, defined: Iterable[GuardMode]) -> None:
        """Raise ``ValueError`` when a slot uses a mode outside ``defined``
        (e.g. :meth:`CustomModes.defined_modes`)."""
        missing = self.modes() - frozenset(defined)
        if missing:
            names = ", ".join(sorted(m.name.lower() for m in missing))
            raise ValueError(f"the schedule uses modes that do not exist: {names}")

    def request(self) -> dict[str, Any]:
        """The document as a JSON object (``account_id``, ``schedules``)."""
        obj: dict[str, Any] = {}
        _put(obj, "account_id", self.account_id)
        obj["schedules"] = [slot.to_json() for slot in self.slots]
        return obj

    def body(self) -> bytes:
        """The JSON bytes sent as the body of a 1254 frame (the whole table)."""
        return _dumps(self.request(), sort_keys=True).encode()

    def param_value(self) -> str:
        """The base64 value the station stores in param 1254."""
        return base64.b64encode(self.body()).decode("ascii")


def _slot_time(item: Mapping[str, Any], prefix: str, what: str) -> time:
    hour, minute = _int(item, f"{prefix}_h", what), _int(item, f"{prefix}_m", what)
    try:
        return time(hour, minute)
    except ValueError:
        raise ProtocolError(f"{what}: {prefix} time {hour}:{minute} is not a time of day") from None


def _weekday(code: int, what: str) -> Weekday:
    try:
        return Weekday(code)
    except ValueError:
        raise ProtocolError(f"{what}: week {code} is not 0 (Sunday) to 6") from None


def decode_schedule(raw: str | None) -> Schedule | None:
    """Param 1254 → :class:`Schedule`; ``None`` when absent or blank.

    Raises ``ProtocolError`` for input that is not that document or holds a slot
    :class:`ScheduleSlot` or :class:`Schedule` would refuse.
    """
    if _blank(raw):
        return None
    what = "schedule (1254)"
    body = _obj(_b64_json(raw, what), what)
    slots: list[ScheduleSlot] = []
    for entry in _list(body.get("schedules"), f"{what} schedules"):
        item = _obj(entry, f"{what} slot")
        try:
            slots.append(
                ScheduleSlot(
                    _weekday(_int(item, "week", what), what),
                    _slot_time(item, "start", what),
                    _slot_time(item, "end", what),
                    _guard_mode(_int(item, "mode_id", what), what),
                )
            )
        except ValueError as exc:
            raise ProtocolError(f"{what}: {exc}") from None
    try:
        return Schedule(account_id=_opt_str(body, "account_id", what), slots=tuple(slots))
    except ValueError as exc:
        raise ProtocolError(f"{what}: {exc}") from None


def decode_schedule_default(raw: str | int | None) -> GuardMode | None:
    """Param 1257 → the mode outside every slot; ``None`` when absent or blank.

    Raises ``ProtocolError`` for anything but the code of a :data:`SCHEDULE_MODES` mode.
    """
    if _blank(raw):
        return None
    what = "schedule default (1257)"
    code = json_int(raw.strip() if isinstance(raw, str) else raw)
    if code is None:
        raise ProtocolError(f"{what}: not an integer: {raw!r}")
    return _guard_mode(code, what, SCHEDULE_MODES)


def encode_schedule_default(mode: GuardMode | int) -> int:
    """The 1257 value for ``mode``; ``ValueError`` unless it is in :data:`SCHEDULE_MODES`."""
    guard_mode = _to_mode(mode, "the schedule default")
    if guard_mode not in SCHEDULE_MODES:
        raise ValueError(f"the schedule default cannot be {guard_mode.name.lower()}")
    return int(guard_mode)


# --- 1157-1161, 1177: stored mode tables -------------------------------------


@dataclass(frozen=True, slots=True, kw_only=True)
class StoredModeTable:
    """One mode's table as a HomeBase 3 stores it (the keys of the 1255 body).

    ``actions`` and ``siren_actions`` map channel → value in their stored order;
    ``alarm`` / ``arm`` are ``count_down_alarm`` / ``count_down_arm``. A read view:
    :meth:`to_mode_table` gives the :class:`~.mode_actions.ModeTable` to edit and write.
    """

    account_id: str | None
    mode: GuardMode
    actions: Mapping[int, int]
    alarm: CountDown
    arm: CountDown
    siren_actions: Mapping[int, int]

    @property
    def param(self) -> int:
        """The param that holds this mode's table."""
        return STORED_MODE_TABLE_PARAMS[self.mode]

    def _delays(self, count_down: CountDown) -> dict[int, int]:
        listed = set(count_down.channels)
        return {ch: count_down.delay if ch in listed else 0 for ch in self.actions}

    def alarm_delays(self) -> dict[int, int]:
        """channel → alarm delay in seconds: the count-down's value on each listed
        device of the table, 0 on the others."""
        return self._delays(self.alarm)

    def leaving_delays(self) -> dict[int, int]:
        """channel → leaving delay in seconds, by the rule of :meth:`alarm_delays`."""
        return self._delays(self.arm)

    def to_mode_table(self) -> ModeTable:
        """The :class:`~.mode_actions.ModeTable` with these actions and delays.

        Raises ``UnsupportedError`` for a mode without a 1255 table (Disarmed).
        """
        return ModeTable(
            mode=self.mode,
            actions=dict(self.actions),
            alarm_delays=self.alarm_delays(),
            leaving_delays=self.leaving_delays(),
        )

    def request(self) -> dict[str, Any]:
        """The table as a JSON object, keys in the 1255 body's order."""
        obj: dict[str, Any] = {}
        _put(obj, "account_id", self.account_id)
        obj["mode_id"] = int(self.mode)
        obj["devices"] = [{"device_channel": c, "action": a} for c, a in self.actions.items()]
        for key, count_down in (("count_down_alarm", self.alarm), ("count_down_arm", self.arm)):
            obj[key] = {"channel_list": list(count_down.channels), "delay_time": count_down.delay}
        obj["siren_sensor_action"] = [
            {"device_channel": c, "action": a} for c, a in self.siren_actions.items()
        ]
        return obj

    def param_value(self) -> str:
        """The base64 value the station stores for this mode."""
        return _b64(_dumps(self.request(), sort_keys=False))


def _channel_actions(value: object, what: str) -> dict[int, int]:
    out: dict[int, int] = {}
    for entry in _list(value, what):
        item = _obj(entry, what)
        channel, action = _int(item, "device_channel", what), _int(item, "action", what)
        if channel < 0 or action < 0:
            raise ProtocolError(f"{what}: negative channel or action in {item!r}")
        if channel in out:
            raise ProtocolError(f"{what}: channel {channel} listed twice")
        out[channel] = action
    return out


def _count_down(value: object, what: str) -> CountDown:
    item = _obj(value, what)
    channels = []
    for raw in _list(item.get("channel_list"), f"{what} channel_list"):
        channel = json_int(raw)
        if channel is None or channel < 0:
            raise ProtocolError(f"{what}: channel {raw!r} is not a channel number")
        channels.append(channel)
    delay = _int(item, "delay_time", what)
    if delay < 0:
        raise ProtocolError(f"{what}: negative delay_time {delay}")
    return CountDown(tuple(channels), delay)


def decode_stored_mode_table(
    raw: str | None, mode: GuardMode | int | None = None
) -> StoredModeTable | None:
    """A mode-table param (:data:`STORED_MODE_TABLE_PARAMS`) → :class:`StoredModeTable`;
    ``None`` when absent or blank.

    With ``mode`` given, the table's ``mode_id`` must be that mode. Raises
    ``ProtocolError`` for input that is not a table, a ``mode_id`` without a stored
    table, or a ``mode_id`` other than ``mode``.
    """
    if _blank(raw):
        return None
    what = "mode table"
    body = _obj(_b64_json(raw, what), what)
    table_mode = _guard_mode(_int(body, "mode_id", what), what, STORED_MODE_TABLE_PARAMS)
    if mode is not None and table_mode != _to_mode(mode, "mode"):
        raise ProtocolError(
            f"{what}: holds {table_mode.name.lower()}, expected {GuardMode(mode).name.lower()}"
        )
    return StoredModeTable(
        account_id=_opt_str(body, "account_id", what),
        mode=table_mode,
        actions=_channel_actions(body.get("devices"), f"{what} devices"),
        alarm=_count_down(body.get("count_down_alarm"), f"{what} count_down_alarm"),
        arm=_count_down(body.get("count_down_arm"), f"{what} count_down_arm"),
        siren_actions=_channel_actions(
            body.get("siren_sensor_action", []), f"{what} siren_sensor_action"
        ),
    )


# --- 1072 / 1073: cross-camera tracking --------------------------------------


def _serial_list(value: object, what: str) -> tuple[str, ...]:
    serials = _list(value, what)
    if not all(isinstance(s, str) and s for s in serials):
        raise ProtocolError(f"{what}: expected a list of serial strings")
    return tuple(serials)


def _check_serials(serials: Iterable[str], what: str) -> list[str]:
    if isinstance(serials, str):
        raise ValueError(f"{what} must be a list of serials, not one string")
    out = list(serials)
    for serial in out:
        item: object = serial
        if not isinstance(item, str) or not item.strip():
            raise ValueError(f"{what}: a serial must be a non-empty string, got {serial!r}")
    if len(set(out)) != len(out):
        raise ValueError(f"{what}: a serial is listed twice")
    return out


def decode_tracking_cameras(raw: str | None) -> tuple[str, ...] | None:
    """Param 1072 → the chosen camera serials in stored order.

    ``None`` when absent or blank, which means every camera of the station. Raises
    ``ProtocolError`` unless the value is a base64 JSON list of serial strings.
    """
    if _blank(raw):
        return None
    what = "tracking cameras (1072)"
    return _serial_list(_b64_json(raw, what), what)


def encode_tracking_cameras(serials: Iterable[str]) -> str:
    """The 1072 value for ``serials``; ``ValueError`` for an empty or repeated serial."""
    return _b64(_dumps(_check_serials(serials, "tracking cameras"), sort_keys=False))


def decode_tracking_groups(raw: str | None) -> tuple[tuple[str, ...], ...]:
    """Param 1073 → the tracking groups, each a tuple of serials; ``()`` when absent.

    Raises ``ProtocolError`` unless the value is a base64 JSON list of
    ``{"value": [serial, ...]}`` objects.
    """
    if _blank(raw):
        return ()
    what = "tracking groups (1073)"
    return tuple(
        _serial_list(_obj(group, what).get("value"), what)
        for group in _list(_b64_json(raw, what), what)
    )


def encode_tracking_groups(groups: Iterable[Iterable[str]]) -> str:
    """The 1073 value for ``groups``; ``ValueError`` for an empty or repeated serial
    within a group."""
    body = [{"value": _check_serials(group, "a tracking group")} for group in groups]
    return _b64(_dumps(body, sort_keys=False))
