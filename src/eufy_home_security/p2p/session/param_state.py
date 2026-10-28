"""Parameter state of a station session: held values, their origin and time, guard modes."""

from __future__ import annotations

import asyncio
import contextlib
import logging
import time
from collections.abc import Callable, Collection, Iterable, Mapping, Sequence
from enum import StrEnum
from types import MappingProxyType
from typing import Any

from ..._logging import LogThrottle
from ...devices.param_info import ParamInfo
from ...events import EventBus, EventSource, GuardModeChanged, ParamChanged, Unsubscribe
from ...models import STATION_CHANNEL, GuardMode
from ..params import ACTIVE_MODE_PARAM, GUARD_MODE_PARAM, ParamDump

_LOGGER = logging.getLogger(__name__)


class ParamOrigin(StrEnum):
    """Where a held parameter value came from when no dump delivered it."""

    CLOUD = "cloud"
    """A cloud snapshot (:meth:`StationSession.ingest_cloud_params`)."""
    LOCAL_WRITE = "local_write"
    """This library's own write (:meth:`StationSession.apply_local_params`, an applied
    arm), or a guard mode the station reported outside a dump."""


class ParamState:
    """The parameters a station session holds and the guard modes they carry.

    Merges dumps, cloud snapshots and local writes into one table keyed by
    ``(dev_type, param_id)``, dates and attributes each value, emits
    :class:`~...events.ParamChanged` and :class:`~...events.GuardModeChanged` on the
    session's bus, and signals completed dumps to their listeners. No I/O.
    """

    def __init__(
        self,
        serial: str,
        *,
        bus: EventBus,
        log_name: str,
        throttle: LogThrottle,
        param: Callable[[int, int], ParamInfo],
        block_aliases: Mapping[int, Sequence[int]] | None,
        expect_channels: Iterable[int],
    ) -> None:
        # param: the parameter's description by (param_id, channel), for log lines.
        self.serial = serial
        self._bus = bus
        self._log_name = log_name
        self._throttle = throttle
        self._param = param
        self._expect_channels = frozenset(expect_channels)
        self._block_aliases = dict(block_aliases or {})
        # Values filed under a second alias are the same parameter: log their change once.
        self._alias_copies = frozenset(
            ch for targets in self._block_aliases.values() for ch in targets[1:]
        )
        self._station_blocks = next(
            (tuple(t) for t in self._block_aliases.values() if STATION_CHANNEL in t),
            (STATION_CHANNEL,),
        )
        self._params: dict[tuple[int, int], str | None] = {}
        self._param_at: dict[tuple[int, int], float] = {}
        """Epoch seconds each parameter's value dates from: its arrival over P2P, or the
        cloud snapshot's ``update_time`` (an older snapshot never overwrites it)."""
        self._param_origin: dict[tuple[int, int], ParamOrigin] = {}
        """Where each parameter's value came from when not a dump (:attr:`param_origins`)."""
        self._meta: dict[str, Any] = {}
        """The dump's frame-level fields (firmware versions), latest value of each."""
        self._unread_dump_keys: set[str] = set()
        """Top-level dump keys the parser does not read, each logged once."""
        self._dump_listeners: list[Callable[[], None]] = []
        self._push_channels: set[int] = set()
        """Blocks of the unsolicited dump in progress (see :meth:`note_pushed_blocks`)."""
        self._push_timer: asyncio.TimerHandle | None = None
        self._guard_mode: GuardMode | int | None = None
        """The selected guard mode (param 1224)."""
        self._active_mode: GuardMode | int | None = None
        """The effective guard mode (param 1151, the 0x047F report)."""

    @property
    def guard_mode(self) -> GuardMode | int | None:
        return self._guard_mode

    @property
    def active_mode(self) -> GuardMode | int | None:
        return self._active_mode

    @property
    def params(self) -> Mapping[tuple[int, int], str | None]:
        return self._params

    @property
    def param_origins(self) -> Mapping[tuple[int, int], ParamOrigin]:
        return MappingProxyType(self._param_origin)

    def param_time(self, key: tuple[int, int]) -> float | None:
        return self._param_at.get(key)

    @property
    def unread_dump_keys(self) -> frozenset[str]:
        return frozenset(self._unread_dump_keys)

    @property
    def expect_channels(self) -> frozenset[int]:
        return self._expect_channels

    @expect_channels.setter
    def expect_channels(self, channels: Iterable[int]) -> None:
        self._expect_channels = frozenset(channels)

    def merged_params(self) -> ParamDump:
        dump = ParamDump()
        for (dev, pid), value in self._params.items():
            if value is not None:
                dump.devices.setdefault(dev, {})[pid] = value
        dump.meta.update(self._meta)
        return dump

    def add_dump_listener(self, callback: Callable[[], None]) -> Unsubscribe:
        """Call ``callback`` per completed dump (see :meth:`StationSession.add_dump_listener`)."""
        self._dump_listeners.append(callback)

        def unsubscribe() -> None:
            with contextlib.suppress(ValueError):
                self._dump_listeners.remove(callback)

        return unsubscribe

    def ingest_cloud_params(
        self, dev_type: int, params: Iterable[tuple[int, str, float | None]]
    ) -> int:
        """Merge a cloud snapshot of one device (see :meth:`StationSession.ingest_cloud_params`)."""
        targets = tuple(self._block_aliases.get(dev_type, (dev_type,)))
        fresh: list[dict[str, Any]] = []
        stamps: dict[int, float] = {}
        for param_id, value, updated_at in params:
            keys = [(block, param_id) for block in targets]
            if updated_at is None:
                if any(key in self._params for key in keys):
                    continue
            elif updated_at <= max((self._param_at.get(key, 0.0) for key in keys), default=0.0):
                continue
            fresh.append({"dev_type": dev_type, "param_type": param_id, "param_value": value})
            if updated_at is not None:
                stamps[param_id] = updated_at
        if not fresh:
            return 0
        dump = ParamDump()
        dump.ingest({"params": fresh}, aliases=self._block_aliases)
        self.merge_dump(
            dump,
            "cloud snapshot",
            time.time(),
            stamps,
            source=EventSource.CLOUD,
            origin_kind=ParamOrigin.CLOUD,
        )
        self.complete_dump(None)
        return len(fresh)

    def apply_local_params(self, channel: int, values: Mapping[int, str]) -> None:
        """Merge the values a write set (see :meth:`StationSession.apply_local_params`)."""
        if not values:
            return
        block = next(
            (dev for dev, targets in self._block_aliases.items() if channel in targets), channel
        )
        dump = ParamDump()
        dump.ingest(
            {
                "params": [
                    {"dev_type": block, "param_type": pid, "param_value": value}
                    for pid, value in values.items()
                ]
            },
            aliases=self._block_aliases,
        )
        self.merge_dump(dump, "local write", time.time(), origin_kind=ParamOrigin.LOCAL_WRITE)
        self.notify_dump_listeners()

    def ingest_dump(self, dump: ParamDump, obj: Mapping[str, Any]) -> None:
        """Merge a station's 0x044F object; a standalone device's lone block under an
        unknown label is filed as its own (:meth:`~..params.ParamDump.ingest` ``other``)."""
        other = self._station_blocks if self._block_aliases else None
        dump.ingest(obj, aliases=self._block_aliases, other=other)
        for label in dump.relabelled:
            if self._throttle.should_log(("relabelled-block", label)):
                _LOGGER.debug(
                    "%s: parameter block labelled %d filed as the device's own",
                    self._log_name,
                    label,
                )

    def merge_dump(
        self,
        dump: ParamDump,
        origin: str,
        now: float,
        stamps: Mapping[int, float] | None = None,
        *,
        source: EventSource = EventSource.P2P,
        origin_kind: ParamOrigin | None = None,
    ) -> None:
        """Merge ``dump`` into the held parameters: emit each change, then the guard modes.

        ``stamps`` date values by parameter id (a cloud snapshot); others date from ``now``.
        ``origin_kind`` marks the values as not a dump's (:attr:`param_origins`).
        """
        self._meta.update(dump.meta)
        for unread in sorted(dump.unread.keys() - self._unread_dump_keys):
            self._unread_dump_keys.add(unread)
            _LOGGER.info(
                "%s: parameter dump carries key %r (%s), which the library does not read",
                self._log_name,
                unread,
                type(dump.unread[unread]).__name__,
            )
        flat = dump.flatten()
        changed = sum(
            1 for key, new in flat.items() if key in self._params and self._params[key] != new
        )
        _LOGGER.debug(
            "%s: parameter dump (%s): channels %s, %d value(s), %d changed",
            self._log_name,
            origin,
            sorted(dump.devices),
            len(flat),
            changed,
        )
        for key, new in flat.items():
            known = key in self._params
            old = self._params.get(key)
            self._params[key] = new
            self._param_at[key] = stamps.get(key[1], now) if stamps else now
            if origin_kind is None:
                self._param_origin.pop(key, None)
            else:
                self._param_origin[key] = origin_kind
            if known and old != new:
                if key[0] not in self._alias_copies and _LOGGER.isEnabledFor(logging.DEBUG):
                    info = self._param(key[1], key[0])
                    _LOGGER.debug(
                        "%s: param ch%d/%d: %s → %s / %s",
                        self._log_name,
                        key[0],
                        key[1],
                        info.raw(old),
                        info.raw(new),
                        info.change(old, new),
                    )
                self._bus.emit(
                    ParamChanged(
                        station_sn=self.serial, channel=key[0], param_id=key[1], old=old, new=new
                    )
                )
        mode, active = dump.guard_mode, dump.active_mode
        if mode is not None or active is not None:
            self.set_modes(mode, active, source=source)

    def take_alarm_value(self, channel: int, param_id: int, new: str | None) -> None:
        """File an alarm frame's value as the station's own; emit ParamChanged when it moved."""
        key = (channel, param_id)
        old = self._params.get(key)
        self._param_origin.pop(key, None)
        if old != new:
            self._params[key] = new
            self._bus.emit(
                ParamChanged(
                    station_sn=self.serial,
                    channel=channel,
                    param_id=param_id,
                    old=old,
                    new=new,
                )
            )

    def note_pushed_blocks(self, channels: Iterable[int], settle: float) -> None:
        """Track a frame of an unsolicited dump; signal its completion (see
        :meth:`add_dump_listener`) at once when the station block and every expected
        channel are in, else ``settle`` seconds after its last frame."""
        self._push_channels.update(channels)
        self.cancel_push_timer()
        expected = {STATION_CHANNEL, *self._expect_channels}
        if len(expected) > 1 and expected <= self._push_channels:
            self.complete_dump(None)
        else:
            self._push_timer = asyncio.get_running_loop().call_later(
                settle, self.complete_dump, None
            )

    def cancel_push_timer(self) -> None:
        if self._push_timer is not None:
            self._push_timer.cancel()
            self._push_timer = None

    def complete_dump(self, carried: Collection[int] | None) -> None:
        """A dump completed; ``carried``: the blocks of a full read (others are dropped).

        Only pass ``carried`` for a read that waited for every expected channel — then a
        block that is absent really has departed. A read that gave up waiting must pass
        ``None``: dropping a block that was merely late erases the device's whole
        parameter set, and a camera would vanish from the caller's state, battery and
        signal entities with it, until the next complete dump.
        """
        self.cancel_push_timer()
        self._push_channels.clear()
        if carried is not None:
            for key in [key for key in self._params if key[0] not in carried]:
                del self._params[key]
                self._param_origin.pop(key, None)
                # The freshness stamp is only meaningful with the value it describes.
                # Leaving it behind leaks a key per departed device, and a re-paired
                # device's fresh cloud value would be rejected as older than a stamp
                # that outlived the value.
                self._param_at.pop(key, None)
        self.notify_dump_listeners()

    def notify_dump_listeners(self) -> None:
        for listener in list(self._dump_listeners):
            try:
                listener()
            except Exception:
                _LOGGER.exception("%s: parameter dump listener failed", self._log_name)

    def file_modes(self, origin: str, *, origin_kind: ParamOrigin | None = None) -> None:
        """File the known modes as the station's own parameters (1224, 1151), dated now.

        The station's state is built from the held parameters, so a mode learned without
        a dump (a push, an arm's result or report) is filed there; a cloud snapshot dated
        before it then no longer overwrites it (:meth:`ingest_cloud_params`).
        ``origin_kind`` marks the values as no dump's (:attr:`param_origins`).
        """
        values = {GUARD_MODE_PARAM: self._guard_mode, ACTIVE_MODE_PARAM: self._active_mode}
        dump = ParamDump()
        for param_id, value in values.items():
            if value is None:
                continue
            for block in self._station_blocks:
                dump.devices.setdefault(block, {})[param_id] = str(int(value))
        if not dump.devices:
            return
        self.merge_dump(dump, origin, time.time(), origin_kind=origin_kind)
        self.complete_dump(None)

    def dump_carries_mode(self) -> bool:
        """Whether a dump delivered the station's selected mode (1224) that is held."""
        key = (self._station_blocks[0], GUARD_MODE_PARAM)
        return key in self._params and key not in self._param_origin

    def apply_modes(self, mode: GuardMode | int | None, active: GuardMode | int | None) -> bool:
        """Update the selected and effective mode; whether either changed.

        None leaves a value as it is, except that a selected mode other than Schedule
        without an effective one is its own effective mode.
        """
        before = (self._guard_mode, self._active_mode)
        if mode is not None:
            self._guard_mode = mode
        if active is not None:
            self._active_mode = active
        elif mode is not None and mode != GuardMode.SCHEDULE:
            self._active_mode = mode
        return (self._guard_mode, self._active_mode) != before

    def set_modes(
        self,
        mode: GuardMode | int | None,
        active: GuardMode | int | None,
        *,
        source: EventSource = EventSource.P2P,
    ) -> None:
        """Apply the modes the station reported; emit :class:`GuardModeChanged` on a change."""
        before = (self._guard_mode, self._active_mode)
        if not self.apply_modes(mode, active) or self._guard_mode is None:
            return
        _LOGGER.debug(
            "%s: guard mode %r → %r", self._log_name, before, (self._guard_mode, self._active_mode)
        )
        self._bus.emit(
            GuardModeChanged(
                station_sn=self.serial,
                mode=self._guard_mode,
                active_mode=self._active_mode,
                source=source,
            )
        )
