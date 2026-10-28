"""A station's configuration and its writes: modes, mode tables, schedule and
cross-camera tracking (:class:`StationConfiguration`)."""

from __future__ import annotations

import asyncio
import contextlib
import logging
from collections.abc import Awaitable, Callable, Iterable, Mapping
from dataclasses import dataclass, replace
from typing import TYPE_CHECKING, Any, Final, Protocol, cast

from .._logging import redact_serial
from ..cloud.models import CloudDevice
from ..devices.settings import (
    MODE_ACTION_FLAGS,
    SettingDef,
    mode_action_flags,
    mode_action_key,
    mode_table_setting,
    scope_for_kind,
)
from ..devices.station_config_support import (
    ModeTableStorage,
    StationFeature,
    cross_camera_eligible,
    mode_table_storage,
)
from ..devices.support import Evidence, Support
from ..devices.types import DeviceKind, model_for_serial
from ..events import EventBus, StationConfigChanged
from ..exceptions import CommandNotAppliedError, ModeInUseError, ProtocolError, UnsupportedError
from ..models import STATION_CHANNEL, GuardMode, ValueSource
from ..p2p._json import json_int
from ..p2p.mode_actions import (
    CMD_SET_ALL_ACTION,
    FIELD_PARAMS,
    MODE_TABLE_MODES,
    MODE_TABLE_PARAMS,
    ModeTable,
    ModeTableField,
    mode_action_on,
    mode_table_from_params,
    require_mode_delay,
)
from ..p2p.params import ParamDump
from ..p2p.session import CommandOutcome, StationSession
from ..p2p.station_config_codecs import (
    CMD_CUSTOM_MODES,
    CMD_SCHEDULE,
    CMD_SCHEDULE_DEFAULT,
    CUSTOM_MODES,
    DEFAULT_MODE_ICON,
    PARAM_TRACKING_CAMERAS,
    PARAM_TRACKING_GROUPS,
    CustomModes,
    Schedule,
    add_custom_mode,
    decode_custom_modes,
    decode_schedule,
    decode_schedule_default,
    decode_tracking_cameras,
    decode_tracking_groups,
    delete_custom_mode,
    encode_schedule_default,
    encode_stored_mode_table,
    encode_tracking_cameras,
    encode_tracking_groups,
    modify_custom_mode,
    require_custom_mode,
)
from ..station_config import (
    ModeInfo,
    StationConfig,
    build_station_config,
    changed_fields,
    check_revision,
    stored_mode_table,
)

if TYPE_CHECKING:
    from . import StationState

_LOGGER = logging.getLogger(__name__)


MODE_TABLES_LOCK: Final = "mode_tables"
"""The shared parameter group of the per-mode action tables
(:meth:`StationConfiguration._shared_lock`)."""
CROSS_CAMERA_LOCK: Final = "cross_camera"
"""The shared parameter group of the cross-camera tracking cameras (1072) and groups (1073)."""
MODE_LIST_LOCK: Final = "mode_list"
"""The shared parameter group of the mode list (1256) and the schedule (1254, 1257), which
names its modes."""


@dataclass(frozen=True, slots=True)
class ConfigRules:
    """The read-back waits and the cross-camera minimum a :class:`StationConfiguration`
    reads, as ``station`` holds them when asked (``READBACK_ATTEMPTS``,
    ``READBACK_DELAY``, ``MIN_TRACKING_CAMERAS``)."""

    readback_attempts: int
    readback_delay: float
    min_tracking_cameras: int


class ConfigurationOwner(Protocol):
    """The station members a :class:`StationConfiguration` uses."""

    sub_devices: tuple[CloudDevice, ...]
    session: StationSession
    _bus: EventBus
    _log_name: str
    _cloud_refresh: Callable[[], Awaitable[object]] | None

    @property
    def serial(self) -> str: ...

    @property
    def state(self) -> StationState | None: ...

    @property
    def channels(self) -> frozenset[int]: ...

    @property
    def has_cloud_copy(self) -> bool: ...

    def channel_for(self, device_sn: str) -> int: ...

    def config_support(self, feature: StationFeature) -> Evidence: ...

    def _product_code(self, serial: str) -> str | None: ...

    def _cloud_by_channel(self) -> dict[int, CloudDevice | None]: ...

    def _state(self, dump: ParamDump) -> StationState: ...

    async def async_update(self, *, wake: bool = False) -> StationState: ...

    def _config_rules(self) -> ConfigRules: ...

    @property
    def config(self) -> StationConfig | None: ...

    def cross_camera_eligible(self) -> tuple[str, ...]: ...

    async def async_set_mode_actions(
        self,
        mode: GuardMode | str | int,
        changes: Mapping[str, Mapping[str, bool]],
        *,
        entry_s: int | None = None,
        exit_s: int | None = None,
        entry_devices: Mapping[str, bool] | None = None,
        exit_devices: Mapping[str, bool] | None = None,
        expect_revision: int | None = None,
    ) -> ModeTable: ...


class StationConfiguration:
    """A station's configuration (:class:`~..station_config.StationConfig`) and the
    writes that change it: mode actions and delays, custom modes, the schedule and
    cross-camera tracking.

    It serialises the read-modify-writes of each shared parameter group, checks an
    expected revision before a write, confirms each write by read-back and announces
    :class:`~..events.StationConfigChanged` when the revision moves.
    """

    def __init__(self, station: ConfigurationOwner) -> None:
        self._station = station
        self.emitted_config: StationConfig | None = None
        self.shared_locks: dict[str, asyncio.Lock] = {}
        """:meth:`_shared_lock` per shared parameter group."""

    def _shared_lock(self, group: str) -> asyncio.Lock:
        """The lock that serialises read-modify-writes of the shared parameter ``group``
        on this station (:data:`MODE_TABLES_LOCK`), so concurrent writes keep each
        other's changes."""
        return self.shared_locks.setdefault(group, asyncio.Lock())

    async def async_set_mode_actions(
        self,
        mode: GuardMode | str | int,
        changes: Mapping[str, Mapping[str, bool]],
        *,
        entry_s: int | None = None,
        exit_s: int | None = None,
        entry_devices: Mapping[str, bool] | None = None,
        exit_devices: Mapping[str, bool] | None = None,
        expect_revision: int | None = None,
    ) -> ModeTable:
        """See :meth:`Station.async_set_mode_actions`."""
        if changes:
            self._require_feature(StationFeature.MODE_TABLES)
        if any(v is not None for v in (entry_s, exit_s)) or entry_devices or exit_devices:
            self._require_feature(StationFeature.MODE_DELAYS)
        for what, seconds in (("entry_s", entry_s), ("exit_s", exit_s)):
            if seconds is not None:
                require_mode_delay(what, seconds)
        guard = GuardMode.parse(mode)
        if guard not in MODE_TABLE_MODES:
            raise UnsupportedError(f"guard mode {guard!r} has no per-device actions")
        edits: dict[int, tuple[SettingDef, dict[str, bool]]] = {}
        for device_sn, flags in changes.items():
            channel = self._station.channel_for(device_sn)
            spec = self._mode_action_spec(guard, channel)
            for flag, on in flags.items():
                if not isinstance(on, bool):
                    raise ValueError(f"{flag}: on must be a bool, got {on!r}")
            spec.with_flags(0, flags)  # refuses an unknown or clashing flag before any traffic
            edits.setdefault(channel, (spec, {}))[1].update(flags)
        count_downs = {
            ModeTableField.ALARM_DELAY: (entry_s, self._delay_channels(entry_devices)),
            ModeTableField.LEAVING_DELAY: (exit_s, self._delay_channels(exit_devices)),
        }
        targets = set(edits).union(*(chs for _, chs in count_downs.values()))

        def edit(table: ModeTable) -> ModeTable:
            table = self._with_flags(table, edits)
            for table_field, (seconds, channels) in count_downs.items():
                if seconds is not None or channels:
                    table = table.with_count_down(table_field, seconds=seconds, channels=channels)
            return table

        _, new = await self._async_edit_mode_table(
            guard,
            edit,
            targets={ch: edits[ch][0] if ch in edits else None for ch in targets},
            command=FIELD_PARAMS[ModeTableField.ACTION][guard],
            expect_revision=expect_revision,
        )
        return new

    async def async_set_mode_delays(
        self,
        mode: GuardMode | str | int,
        *,
        entry_s: int | None = None,
        exit_s: int | None = None,
        entry_devices: Mapping[str, bool] | None = None,
        exit_devices: Mapping[str, bool] | None = None,
        expect_revision: int | None = None,
    ) -> ModeTable:
        """See :meth:`Station.async_set_mode_delays`."""
        return await self._station.async_set_mode_actions(
            mode,
            {},
            entry_s=entry_s,
            exit_s=exit_s,
            entry_devices=entry_devices,
            exit_devices=exit_devices,
            expect_revision=expect_revision,
        )

    async def async_create_custom_mode(
        self,
        name: str,
        *,
        icon: int | None = None,
        detail: str | None = None,
        expect_revision: int | None = None,
    ) -> ModeInfo:
        """See :meth:`Station.async_create_custom_mode`."""
        self._require_feature(StationFeature.CUSTOM_MODES)
        icon_type = DEFAULT_MODE_ICON if icon is None else icon
        text = "" if detail is None else detail
        add_custom_mode(None, account_id="", title=name, icon_type=icon_type, detail=text)
        async with self._shared_lock(MODE_LIST_LOCK):
            state, config = await self._config_for_write(expect_revision)
            current = self._custom_modes(state, config)
            doc = add_custom_mode(
                current, account_id="", title=name, icon_type=icon_type, detail=text
            )
            await self._async_write_mode_list(doc)
        return self._defined_mode(cast(GuardMode, doc.mode_id))

    async def async_rename_custom_mode(
        self,
        mode: GuardMode | str | int,
        name: str,
        *,
        icon: int | None = None,
        expect_revision: int | None = None,
    ) -> ModeInfo:
        """See :meth:`Station.async_rename_custom_mode`."""
        self._require_feature(StationFeature.CUSTOM_MODES)
        target = require_custom_mode(GuardMode.parse(mode), "rename")
        add_custom_mode(
            None, account_id="", title=name, icon_type=icon or 0, mode=target
        )  # refuses a name or icon before any traffic
        async with self._shared_lock(MODE_LIST_LOCK):
            state, config = await self._config_for_write(expect_revision)
            current = self._custom_modes(state, config)
            if current is None:
                raise ValueError(f"{target.label} does not exist")
            doc = modify_custom_mode(current, target, account_id="", title=name, icon_type=icon)
            await self._async_write_mode_list(doc)
        return self._defined_mode(target)

    async def async_delete_custom_mode(
        self, mode: GuardMode | str | int, *, expect_revision: int | None = None
    ) -> None:
        """See :meth:`Station.async_delete_custom_mode`."""
        self._require_feature(StationFeature.CUSTOM_MODES)
        target = require_custom_mode(GuardMode.parse(mode), "delete")
        async with self._shared_lock(MODE_LIST_LOCK):
            state, config = await self._config_for_write(expect_revision)
            current = self._custom_modes(state, config)
            if current is None:
                raise ValueError(f"{target.label} does not exist")
            doc = delete_custom_mode(current, target, account_id="")
            self._check_mode_unused(config, target)
            await self._async_write_mode_list(doc)

    @staticmethod
    def _check_mode_unused(config: StationConfig, mode: GuardMode) -> None:
        """:class:`~..exceptions.ModeInUseError` when ``config`` is in ``mode`` or its
        schedule uses it."""
        name = config.mode_name(mode)
        if mode in (config.guard_mode, config.effective_mode):
            raise ModeInUseError(
                f"{name} is the station's current mode; switch to another mode before deleting it"
            )
        if config.schedule is not None and mode in config.schedule.modes():
            raise ModeInUseError(
                f"{name} is used by the schedule; remove it from the schedule first"
            )
        if config.schedule_default == mode:
            raise ModeInUseError(
                f"{name} is the schedule's mode outside its time slots; choose another one first"
            )

    async def async_set_schedule(
        self,
        schedule: Schedule,
        *,
        default_mode: GuardMode | str | int | None = None,
        expect_revision: int | None = None,
    ) -> tuple[Schedule | None, GuardMode | None]:
        """See :meth:`Station.async_set_schedule`."""
        self._require_feature(StationFeature.SCHEDULE)
        if not isinstance(schedule, Schedule):
            raise ValueError(f"a schedule must be a Schedule, got {schedule!r}")
        default = None if default_mode is None else GuardMode.parse(default_mode)
        if default is not None:
            encode_schedule_default(default)
        async with self._shared_lock(MODE_LIST_LOCK):
            _, config = await self._config_for_write(expect_revision)
            defined = [m.code for m in config.modes if isinstance(m.code, GuardMode)]
            schedule.require_defined(defined)
            if default is not None and default not in defined:
                raise ValueError(
                    f"the schedule default {default.label} is a mode the station does not have"
                )
            current = config.schedule
            if current is None or current.slots != schedule.slots:

                def holds(raw: str) -> bool:
                    stored = decode_schedule(raw)
                    return stored is not None and stored.slots == schedule.slots

                await self._async_write_document(CMD_SCHEDULE, schedule, holds)
            if default is not None and default != config.schedule_default:
                await self._station.session.async_send_ecb_scalar(
                    CMD_SCHEDULE_DEFAULT, int(default)
                )
                await self._async_confirm_param(
                    CMD_SCHEDULE_DEFAULT,
                    str(int(default)),
                    lambda raw: decode_schedule_default(raw) == default,
                    answered=True,
                )
        after = self._station.config
        if after is None:  # pragma: no cover - a write leaves a state
            return schedule, default
        return after.schedule, after.schedule_default

    async def async_set_cross_camera_cameras(
        self, serials: Iterable[str] | None, *, expect_revision: int | None = None
    ) -> tuple[str, ...]:
        """See :meth:`Station.async_set_cross_camera_cameras`."""
        self._require_feature(StationFeature.CROSS_CAMERA)
        if serials is None:
            chosen = self._station.cross_camera_eligible()
            if len(chosen) < self._station._config_rules().min_tracking_cameras:
                raise UnsupportedError(
                    f"{self._station._log_name} has fewer than "
                    f"{self._station._config_rules().min_tracking_cameras} cameras "
                    "cross-camera tracking can follow",
                    device_sn=self._station.serial,
                )
        else:
            chosen = self._own_cameras(serials, "tracking cameras")
            if len(chosen) < self._station._config_rules().min_tracking_cameras:
                raise ValueError(
                    f"choose at least {self._station._config_rules().min_tracking_cameras} "
                    "cameras, as the eufy app requires; None chooses every camera"
                )
        value = encode_tracking_cameras(chosen)
        async with self._shared_lock(CROSS_CAMERA_LOCK):
            _, config = await self._config_for_write(expect_revision)
            if config.cross_camera is None or config.cross_camera.cameras != chosen:
                await self._async_write_list(
                    PARAM_TRACKING_CAMERAS,
                    list(chosen),
                    value,
                    lambda raw: decode_tracking_cameras(raw) == chosen,
                )
        after = self._station.config
        cross = after.cross_camera if after is not None else None
        return cross.cameras if cross is not None and cross.cameras is not None else chosen

    async def async_set_cross_camera_groups(
        self, groups: Iterable[Iterable[str]], *, expect_revision: int | None = None
    ) -> tuple[tuple[str, ...], ...]:
        """See :meth:`Station.async_set_cross_camera_groups`."""
        self._require_feature(StationFeature.CROSS_CAMERA_GROUPS)
        if isinstance(groups, str):
            raise ValueError("tracking groups must be a list of serial lists")
        chosen = tuple(self._own_cameras(group, "a tracking group") for group in groups)
        members = [serial for group in chosen for serial in group]
        if any(not group for group in chosen):
            raise ValueError("a tracking group needs at least one camera")
        if len(set(members)) != len(members):
            raise ValueError("a camera can be in one tracking group only")
        value = encode_tracking_groups(chosen)
        async with self._shared_lock(CROSS_CAMERA_LOCK):
            _, config = await self._config_for_write(expect_revision)
            if config.cross_camera is None or config.cross_camera.groups != chosen:
                await self._async_write_list(
                    PARAM_TRACKING_GROUPS,
                    [{"value": list(group)} for group in chosen],
                    value,
                    lambda raw: decode_tracking_groups(raw) == chosen,
                )
        after = self._station.config
        cross = after.cross_camera if after is not None else None
        return cross.groups if cross is not None else chosen

    def _own_cameras(self, serials: Iterable[str], what: str) -> tuple[str, ...]:
        """``serials`` checked as distinct cameras paired to this station."""
        if isinstance(serials, str):
            raise ValueError(f"{what} must be a list of serials, not one string")
        out = tuple(serials)
        encode_tracking_cameras(out)  # refuses an empty or repeated serial
        eligible = self._station.cross_camera_eligible()
        for serial in out:
            if serial not in eligible:
                raise UnsupportedError(
                    f"{redact_serial(serial)} is not a device paired to "
                    f"{self._station._log_name} that cross-camera tracking can follow",
                    device_sn=serial,
                )
        return out

    def cross_camera_eligible(self) -> tuple[str, ...]:
        """See :meth:`Station.cross_camera_eligible`."""
        paired = sorted(
            self._station.sub_devices, key=lambda d: (d.channel is None, d.channel or 0)
        )
        return cross_camera_eligible(d.device_sn for d in paired)

    async def _async_write_list(
        self, param: int, payload: list[Any], stored: str, holds: Callable[[str], bool]
    ) -> None:
        """Send ``payload`` as the 1350 sub-command ``param`` (the handler's ``param_list``)
        and confirm it (:meth:`_async_confirm_param`; ``stored`` is its param value)."""
        outcome = await self._station.session.async_send_command(param, payload=payload)
        await self._async_confirm_param(
            param, stored, holds, answered=outcome is CommandOutcome.APPLIED
        )

    def target_mode_name(self, mode: GuardMode) -> str | None:
        """See :meth:`Station.target_mode_name`."""
        config = self._station.config
        if config is None or config.sources.get("modes") in (None, ValueSource.APP_DEFAULT):
            return None
        if mode in CUSTOM_MODES and not config.is_defined(mode):
            have = ", ".join(m.name for m in config.modes if m.custom) or "none"
            raise UnsupportedError(
                f"{self._station._log_name} has no {mode.label} (its custom modes: {have})",
                device_sn=self._station.serial,
            )
        return config.mode_name(mode)

    def _require_feature(self, feature: StationFeature) -> None:
        """``UnsupportedError`` when ``feature`` is *unknown* on this station."""
        evidence = self._station.config_support(feature)
        if evidence.support is Support.UNKNOWN:
            raise UnsupportedError(f"{feature.value} is not supported here: {evidence.source}")

    async def _config_for_write(
        self, expect_revision: int | None
    ) -> tuple[StationState, StationConfig]:
        """A fresh read and its configuration, checked against ``expect_revision``
        (:class:`~..exceptions.ConfigChangedError`, nothing sent, when it differs)."""
        state = await self._station.async_update(wake=True)
        config = build_station_config(state)
        check_revision(config, expect_revision)
        return state, config

    def _custom_modes(self, state: StationState, config: StationConfig) -> CustomModes | None:
        """The mode list (1256) a write starts from; None when the station has none.

        ``UnsupportedError`` when the list does not decode, or when no source carries
        it and the station has no cloud copy: the list may exist where the library cannot
        see it, and a write would replace it.
        """
        if (problem := config.unreadable.get("modes")) is not None:
            raise UnsupportedError(f"the station's mode list cannot be read: {problem}")
        raw = state.setting_params.get(CMD_CUSTOM_MODES)
        if raw is None and not self._station.has_cloud_copy:
            raise UnsupportedError(
                "the station's mode list is not known yet (its parameter dump does not "
                "carry it); read the configuration with refresh first"
            )
        return decode_custom_modes(raw)

    async def _async_write_mode_list(self, doc: CustomModes) -> None:
        """Send mode list ``doc`` (frame 1256) and confirm it (:meth:`_async_confirm_param`)."""

        def holds(raw: str) -> bool:
            stored = decode_custom_modes(raw)
            return stored is not None and stored.modes == doc.modes

        await self._async_write_document(CMD_CUSTOM_MODES, doc, holds)

    async def _async_write_document(
        self, command: int, doc: CustomModes | Schedule, holds: Callable[[str], bool]
    ) -> None:
        """Send ``doc`` with the owner's account id as a JSON frame of type ``command``
        (the param it sets) and confirm it (:meth:`_async_confirm_param`)."""
        sent: list[CustomModes | Schedule] = []

        def body(account: str) -> bytes:
            sent.append(replace(doc, account_id=account))
            return sent[-1].body()

        receipted = await self._station.session.async_send_json_frame(command, body)
        await self._async_confirm_param(command, sent[-1].param_value(), holds, receipted)

    async def _async_confirm_param(
        self, param: int, stored: str, holds: Callable[[str], bool], answered: bool
    ) -> None:
        """Confirm a write of the station's own ``param`` and show it in :attr:`Station.state`.

        Where a fresh parameter dump carries ``param``, it must hold the write
        (``holds``) within :data:`~.READBACK_ATTEMPTS` reads. Where the dump does not carry
        it (a HomeBase 3's mode list and schedule live in the cloud's copy), the station's
        own answer to the write (``answered``: a zero receipt or result) is all that
        confirms it, and ``stored`` is filed as this library's own write, which
        :attr:`Station.state` shows until the cloud copy changes after it. Raises
        :class:`CommandNotAppliedError` when neither confirms the write.
        """
        for attempt in range(self._station._config_rules().readback_attempts):
            raw = (await self._station.session.async_get_params()).station.get(param)
            if raw is None:
                break
            with contextlib.suppress(ProtocolError):
                if holds(raw):
                    return
            if attempt + 1 < self._station._config_rules().readback_attempts:
                await asyncio.sleep(self._station._config_rules().readback_delay)
        else:
            raise CommandNotAppliedError(
                param, f"param {param} not confirmed: the station reports another value"
            )
        if not answered:
            raise CommandNotAppliedError(
                param,
                f"the station acknowledged command {param} without answering it, and its "
                "parameter dump does not carry it: nothing confirms the write",
            )
        self._station.session.apply_local_params(STATION_CHANNEL, {param: stored})

    def _defined_mode(self, mode: GuardMode) -> ModeInfo:
        """``mode`` as :attr:`config` lists it after a write."""
        config = self._station.config
        info = config.mode(mode) if config is not None else None
        if info is None:
            raise CommandNotAppliedError(
                CMD_CUSTOM_MODES, f"{mode.label} is not listed after the write"
            )
        return info

    @staticmethod
    def _with_flags(
        table: ModeTable, edits: Mapping[int, tuple[SettingDef, Mapping[str, bool]]]
    ) -> ModeTable:
        """``table`` with each channel's flags turned on or off (:meth:`SettingDef.with_flags`:
        with the flags a flag turned off clears), every other bit kept;
        :class:`CommandNotAppliedError` when a channel's current mask is not in it."""
        for channel, (spec, flags) in sorted(edits.items()):
            mask = table.actions.get(channel)
            if mask is None:
                raise CommandNotAppliedError(
                    spec.command_id,
                    f"{spec.key}: the station does not report the current mask on channel "
                    f"{channel}; refusing to write a whole mask blind",
                )
            table = table.with_action(channel, spec.with_flags(mask, flags))
        return table

    def _delay_channels(self, devices: Mapping[str, bool] | None) -> dict[int, bool]:
        """``{serial: on}`` as ``{channel: on}``; refuses an unpaired serial or a non-bool."""
        out: dict[int, bool] = {}
        for device_sn, on in (devices or {}).items():
            if not isinstance(on, bool):
                raise ValueError(f"a delay's on must be a bool, got {on!r}")
            out[self._station.channel_for(device_sn)] = on
        return out

    def _mode_action_spec(self, mode: GuardMode, channel: int) -> SettingDef:
        """The action-mask setting of the device on ``channel`` for ``mode``, with the
        flags of its kind and cloud type; ``UnsupportedError`` for a mode without
        actions or a device of no catalogued kind."""
        key = mode_action_key(mode, scope_for_kind(self._kind_on(channel)))
        cloud = self._station._cloud_by_channel().get(channel)
        return mode_table_setting(key).for_device_type(cloud.device_type if cloud else None)

    async def _async_edit_mode_table(
        self,
        mode: GuardMode,
        edit: Callable[[ModeTable], ModeTable],
        *,
        targets: Mapping[int, SettingDef | None],
        command: int,
        expect_revision: int | None = None,
    ) -> tuple[ModeTable, ModeTable]:
        """Read ``mode``'s whole table fresh, ``edit`` it, send it once and confirm it by
        read-back, all under the mode-table lock; returns (table read, table in effect).

        ``targets`` are the channels the edit changes, each with the setting it changes
        (checked against the device's kind) or None. Refuses (nothing sent) as
        :meth:`async_set_mode_actions` lists; ``command`` is the id its errors carry.
        """
        async with self._shared_lock(MODE_TABLES_LOCK):
            wanted = self._station.channels | targets.keys()
            dump = await self._station.session.async_get_params(expect_channels=wanted)
            missing = sorted(wanted - dump.devices.keys())
            if missing:
                raise CommandNotAppliedError(
                    command,
                    f"{mode.name.lower()} mode table: channels {missing} are missing from the "
                    "parameter dump; refusing to write a mode table without them",
                    device_sns=self._serials_on(missing),
                )
            state = self._station._state(dump)
            for target, spec in sorted(targets.items()):
                device = state.devices.get(target)
                if device is None:
                    # `state.devices` holds sub-devices only, so a station channel (or one
                    # that went away since the dump) lands here.
                    raise UnsupportedError(f"channel {target} is no paired device")
                if spec is not None and not spec.applies_to(scope_for_kind(device.kind)):
                    raise UnsupportedError(
                        f"setting {spec.key!r} is a {spec.scope} setting, not one of "
                        f"channel {target}"
                    )
            if expect_revision is not None:
                # The merged state after this dump, as `config` shows it: the dump alone
                # lacks the receipt-confirmed writes the revision covers.
                check_revision(build_station_config(self._station.state or state), expect_revision)
            table = mode_table_from_params(dump.devices, mode)
            stored_param: int | None = None
            if not table.actions:
                # The merged state: the fresh dump, else a write of this library's own
                # that the cloud has not replaced, else the cloud's copy.
                merged = self._station.state or state
                stored_param, table = self._stored_table_for_write(merged, mode, table)
            new = edit(table)
            if new.same_values(table):
                return table, table
            # A channel with no known device (the station's own block can carry a
            # per-mode action) is refused like one of a kind without catalogued actions.
            unknown = sorted(
                ch
                for ch in new.actions
                if ch not in state.devices
                or scope_for_kind(state.devices[ch].kind) not in MODE_ACTION_FLAGS
            )
            if unknown:
                raise UnsupportedError(
                    f"{mode.name.lower()} mode table: channels {unknown} are of a kind "
                    "without catalogued actions; a mode table always clears siren-accessory "
                    "triggers, so it is not written",
                    device_sns=self._serials_on(unknown),
                )
            new.request("")  # refuses a delay the table cannot carry, before any traffic
            if stored_param is not None:
                await self._async_write_stored_mode_table(new, stored_param)
                return table, new
            try:
                await self._station.session.async_set_mode_table(new)
            except CommandNotAppliedError as err:
                detail, serials = self._mode_table_mismatch(new)
                raise CommandNotAppliedError(
                    err.command, f"{detail}: {err}", device_sns=serials
                ) from err
            return table, new

    def _serials_on(self, channels: Iterable[int]) -> tuple[str, ...]:
        """The cloud serials of the devices on ``channels``, in their order; a channel the
        cloud lists no device on (or several) is left out."""
        cloud = self._station._cloud_by_channel()
        return tuple(d.device_sn for ch in channels if (d := cloud.get(ch)) is not None)

    @staticmethod
    def _stored_table_for_write(
        state: StationState, mode: GuardMode, table: ModeTable
    ) -> tuple[int, ModeTable]:
        """The table a write starts from when no device reports ``mode``'s action
        param (``table`` is empty): a pro-alarm station's stored copy (61300-61309, dump
        before cloud) with its param. ``UnsupportedError`` when there is none (a 1255
        replaces the whole table, so it is never sent blind), when it does not decode,
        or when it names a siren-accessory trigger (a library table clears those).
        """
        action_param = FIELD_PARAMS[ModeTableField.ACTION][mode]
        name = mode.name.lower()
        if mode_table_storage(state.product_code) is not ModeTableStorage.PRO_ALARM:
            raise UnsupportedError(
                f"the station stores no {name} mode table (no device reports param {action_param})"
            )
        try:
            stored = stored_mode_table(state.setting_params, state.product_code, mode)
            built = stored.to_mode_table() if stored is not None else table
        except (ProtocolError, ValueError) as err:
            raise UnsupportedError(
                f"the station's stored {name} mode table cannot be read: {err}"
            ) from err
        if stored is None or not built.actions:
            raise UnsupportedError(
                f"the station stores no {name} mode table (no device reports param "
                f"{action_param}, and no source carries its stored copy)"
            )
        if any(stored.siren_actions.values()):
            raise UnsupportedError(
                f"the stored {name} mode table sounds a siren accessory on a trigger; a "
                "library mode table clears those triggers, so it is not written"
            )
        return stored.param, built

    async def _async_write_stored_mode_table(self, table: ModeTable, param: int) -> None:
        """Send ``table`` (frame 1255) to a station that keeps it in its own ``param``
        and confirm it (:meth:`_async_confirm_param`): a fresh dump carrying ``param``
        must hold the table, else the station's zero receipt confirms it and the sent
        body is filed as this library's write of ``param``."""
        sent: list[bytes] = []

        def body(account: str) -> bytes:
            sent.append(table.encode(account))
            return sent[-1]

        def holds(raw: str) -> bool:
            try:
                stored = stored_mode_table({param: raw}, product_code, table.mode)
                return stored is not None and stored.to_mode_table().same_values(table)
            except (UnsupportedError, ValueError):
                return False

        product_code = self._station._product_code(self._station.serial)
        _LOGGER.info(
            "%s: writing the %s mode table (%d devices, stored in param %d)",
            self._station._log_name,
            table.mode.name,
            len(table.actions),
            param,
        )
        receipted = await self._station.session.async_send_json_frame(CMD_SET_ALL_ACTION, body)
        await self._async_confirm_param(param, encode_stored_mode_table(sent[-1]), holds, receipted)

    def _mode_table_mismatch(self, table: ModeTable) -> tuple[str, tuple[str, ...]]:
        """Which device's flag or delay the last read does not show as ``table`` set it,
        and the serials of those devices, in the order the text names them."""
        reported = self._station.session.merged_params().devices
        cloud = self._station._cloud_by_channel()
        action_param = FIELD_PARAMS[ModeTableField.ACTION][table.mode]
        problems: list[str] = []
        serials: list[str] = []
        for channel, values in sorted(table.params().items()):
            entry = cloud.get(channel)
            name = redact_serial(entry.device_sn) if entry else f"channel {channel}"
            block = reported.get(channel, {})
            before = len(problems)
            for param, want in sorted(values.items()):
                raw = block.get(param)
                got = json_int(raw) if raw is not None else None
                if got == want:
                    continue
                if param != action_param or got is None:
                    what = "action" if param == action_param else MODE_TABLE_PARAMS[param][1]
                    problems.append(f"{name} {what}: wrote {want}, station reports {got}")
                    continue
                flags = mode_action_flags(
                    scope_for_kind(self._kind_on(channel)), entry.device_type if entry else None
                )
                for flag, bit in flags.items():
                    if (want ^ got) & bit:
                        wrote, reads = (
                            ("on", "off") if mode_action_on(flag, want) else ("off", "on")
                        )
                        problems.append(f"{name} {flag}: wrote {wrote}, station reports {reads}")
                named = 0
                for bit in flags.values():
                    named |= bit
                if (want ^ got) & ~named:
                    problems.append(f"{name} action: wrote {want}, station reports {got}")
            if entry is not None and len(problems) > before:
                serials.append(entry.device_sn)
        detail = "; ".join(problems) or "the read-back differs"
        return f"{table.mode.name.lower()} mode table not confirmed ({detail})", tuple(serials)

    async def async_set_mode_action(
        self,
        mode: GuardMode | str | int,
        flag: str,
        on: bool,
        *,
        device_sn: str | None = None,
        channel: int | None = None,
    ) -> int:
        """See :meth:`Station.async_set_mode_action`."""
        if (device_sn is None) == (channel is None):
            raise ValueError("pass exactly one of device_sn or channel")
        self._require_feature(StationFeature.MODE_TABLES)
        target = (
            self._station.channel_for(device_sn) if device_sn is not None else cast(int, channel)
        )
        guard = GuardMode.parse(mode)
        spec = self._mode_action_spec(guard, target)
        spec.with_flag(0, flag, on)  # refuses an unknown flag before any traffic
        _, new = await self._async_edit_mode_table(
            guard,
            lambda table: self._with_flags(table, {target: (spec, {flag: on})}),
            targets={target: spec},
            command=spec.command_id,
        )
        return new.actions[target]

    @property
    def config(self) -> StationConfig | None:
        """See :attr:`Station.config`."""
        state = self._station.state
        return None if state is None else build_station_config(state)

    async def async_get_config(self, *, refresh: bool = False) -> StationConfig:
        """See :meth:`Station.async_get_config`."""
        if refresh:
            await self._station.async_update(wake=True)
            if self._station._cloud_refresh is not None:
                await self._station._cloud_refresh()
        state = self._station.state or await self._station.async_update()
        return build_station_config(state)

    def emit_config_change(self, state: StationState) -> None:
        """Emit :class:`~..events.StationConfigChanged` when ``state``'s configuration has
        another revision than the last one emitted."""
        config = build_station_config(state)
        old = self.emitted_config
        if old is not None and old.revision == config.revision:
            return
        self.emitted_config = config
        self._station._bus.emit(
            StationConfigChanged(
                station_sn=self._station.serial,
                revision=config.revision,
                fields=changed_fields(old, config),
            )
        )

    async def _check_revision(self, expect_revision: int | None) -> StationConfig | None:
        """For a write taking ``expect_revision``: None when it is None; else the
        configuration of a fresh parameter read, raising
        :class:`~..exceptions.ConfigChangedError` (nothing sent) when its revision differs."""
        if expect_revision is None:
            return None
        config = build_station_config(await self._station.async_update(wake=True))
        check_revision(config, expect_revision)
        return config

    def _kind_on(self, channel: int) -> DeviceKind | None:
        """The kind of the device on ``channel``: its cloud serial's model, else the last
        snapshot's reading of its block; None when neither says."""
        cloud = self._station._cloud_by_channel().get(channel)
        model = model_for_serial(cloud.device_sn) if cloud is not None else None
        if model is not None:
            return model.kind
        state = self._station.state
        device = state.devices.get(channel) if state is not None else None
        return device.kind if device is not None else None

    async def async_set_mode_table_value(self, spec: SettingDef, value: int, target: int) -> int:
        """Write one mode-table value: read the whole mode fresh, change ``target``'s
        entry, send the table (``SET_ALL_ACTION``) and confirm every value by read-back.

        Refuses (``UnsupportedError``, nothing sent) where :meth:`Station.config_support` grades
        mode tables (an action) or mode delays (a delay) *unknown*, when the setting does not apply to
        the device on ``target``, when a device of the table is of a kind without catalogued
        actions (it may be a siren accessory, whose triggers a library table would clear),
        or when a delay the table must carry unchanged differs between devices; and
        (``CommandNotAppliedError``) when a paired device or the target is missing from
        the fresh read, since a table without it would drop it. A non-zero delay also
        moves the delay of every device that has it on (one value per mode). Returns
        ``value`` without writing when the table already holds it.
        """
        mode, table_field = MODE_TABLE_PARAMS[spec.command_id]
        self._require_feature(
            StationFeature.MODE_TABLES
            if table_field is ModeTableField.ACTION
            else StationFeature.MODE_DELAYS
        )

        def edit(table: ModeTable) -> ModeTable:
            if table_field is ModeTableField.ACTION:
                return table.with_action(target, value)
            return table.with_delay(table_field, target, value)

        await self._async_edit_mode_table(
            mode, edit, targets={target: spec}, command=spec.command_id
        )
        return value
