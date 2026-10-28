"""Pan/tilt, presets, picture zoom and the captures holding a camera (:class:`StationPtz`)."""

from __future__ import annotations

import asyncio
import logging
import time
from collections.abc import Callable, Coroutine, Mapping, Sequence
from dataclasses import dataclass
from typing import TYPE_CHECKING, Any, Final, Protocol

from .._logging import redact_serial
from ..cloud.models import CloudDevice
from ..devices.capabilities import (
    PTZ_ACTION_NEEDS,
    PTZ_ACTIONS,
    Capability,
    own_profile,
    profile_for_serial,
)
from ..devices.live_view import LensView
from ..devices.ptz import PtzForm, has_ptz_recipes, ptz_actions, ptz_form
from ..devices.ptz import app_version as ptz_app_version
from ..devices.recipes import (
    MAX_PRESET_SLOTS,
    MAX_ZOOM,
    MIN_ZOOM,
    ConnectType,
    PanTilt,
    PresetPosition,
    PtzAction,
    Recipe,
    SubCommand,
    delete_preset,
    free_preset_slot,
    goto_preset,
    pan_tilt,
    parse_preset_positions,
    preset_picture,
    query_preset_positions,
    reported_zoom,
    set_default_preset,
    set_picture_zoom,
    store_preset,
)
from ..devices.settings import DUAL_VIEW, VIEW_MODE_PARAM
from ..devices.support import Evidence, Support
from ..events import CameraBusyChanged, EventBus, PresetsChanged, ZoomChanged
from ..exceptions import (
    CommandNotAppliedError,
    DeviceBusyError,
    DeviceTimeoutError,
    EufySecurityError,
    PresetSlotsFullError,
    PtzActionUnsupportedError,
    UnsupportedError,
)
from ..images import CameraImage, ImageSource
from ..models import FrameCipher
from ..p2p._json import json_int
from ..p2p.messages import decode_preset_picture
from ..p2p.session import RecipeReply, StationSession
from ..p2p.session.media_stream import MediaStream
from .base import _NOT_PAIRED, own_channel

if TYPE_CHECKING:
    from ..storage import SessionCache

_LOGGER = logging.getLogger(__name__)


_PTZ_NAMES: Final[Mapping[Capability, str]] = {
    Capability.PTZ_CONTROL: "pan/tilt control",
    Capability.PTZ_PRESETS: "pan/tilt presets",
    Capability.PTZ_ZOOM: "picture zoom",
}
"""How a refusal names each pan/tilt/zoom capability the device lacks."""


async def _settle(seconds: float) -> None:
    """Wait ``seconds`` when positive."""
    if seconds > 0:
        await asyncio.sleep(seconds)


@dataclass(frozen=True, slots=True)
class _Capture:
    """The capture holding a camera: a live image (``preset`` None) or a preset image."""

    preset: int | None
    task: asyncio.Task[CameraImage]


@dataclass(frozen=True, slots=True)
class PtzWaits:
    """The waits a :class:`StationPtz` reads, as ``station`` holds them when asked
    (``DEFAULT_PRESET_RESULT_WAIT``, ``PRESET_STREAM_IDLE_SECONDS``)."""

    default_preset_result: float
    preset_stream_idle: float


class PtzOwner(Protocol):
    """The station members a :class:`StationPtz` uses."""

    device: CloudDevice
    sub_devices: tuple[CloudDevice, ...]
    session: StationSession
    _bus: EventBus
    _cache: SessionCache | None
    _log_name: str

    @property
    def serial(self) -> str: ...

    @property
    def is_standalone(self) -> bool: ...

    def channel_for(self, device_sn: str) -> int: ...

    def _is_paired(self, device_sn: str) -> bool: ...

    def _product_code(self, serial: str) -> str | None: ...

    def _connect_type_of(self, device_sn: str) -> ConnectType: ...

    async def _ptz_recipe(self, recipe: Recipe, channel: int) -> RecipeReply: ...

    async def _session_live(
        self, channel: int, *, lens_view: LensView | None = None, **kwargs: Any
    ) -> MediaStream: ...

    def _ptz_waits(self) -> PtzWaits: ...

    def presets(self, device_sn: str) -> tuple[PresetPosition, ...] | None: ...

    def ptz_support(self, device_sn: str, capability: Capability) -> Evidence: ...

    async def async_refresh_presets(self, device_sn: str) -> tuple[PresetPosition, ...]: ...

    async def async_store_preset(
        self, device_sn: str, preset: int, *, confirm: bool = False
    ) -> tuple[PresetPosition, ...]: ...

    async def async_set_default_preset(
        self, device_sn: str, preset: int, *, confirm: bool = False
    ) -> tuple[PresetPosition, ...]: ...


class StationPtz:
    """Pan/tilt, presets and picture zoom of a station's cameras, and the one capture
    (a live or preset image) holding each camera.

    It keeps each camera's preset slots (with the session cache), its reported zoom and
    its running capture, grades and checks pan/tilt/zoom support, and sends the preset,
    pan/tilt and zoom recipes. Every ``settle`` is a number: :class:`Station` resolves
    the defaults before calling.
    """

    def __init__(self, station: PtzOwner) -> None:
        self._station = station
        self.preset_slots: dict[str, tuple[PresetPosition, ...]] = {}
        self.captures: dict[str, _Capture] = {}
        """The capture holding each camera (a live or preset image), by serial."""
        self.zooms: dict[str, float] = {}

    def on_notify(self, obj: Mapping[str, Any], cipher: FrameCipher) -> None:
        zoom = reported_zoom(obj)
        if zoom is None:
            return
        device_sn = self._zoom_device(obj)
        if device_sn is not None:
            self.keep_zoom(device_sn, zoom)

    def _zoom_device(self, obj: Mapping[str, Any]) -> str | None:
        """The camera a 6203 report is about: the one on its ``mChannel``; a standalone
        station's own serial when it names none. None when that is not a zoom camera."""
        channel = json_int(obj.get("mChannel"))
        if self._station.is_standalone and channel in (None, own_channel(self._station.device)):
            device_sn: str | None = self._station.serial
        else:
            device_sn = next(
                (
                    d.device_sn
                    for d in self._station.sub_devices
                    if channel is not None and d.channel == channel
                ),
                None,
            )
        if device_sn is None:
            return None
        profile = profile_for_serial(device_sn)
        if profile is None or profile.support(Capability.PTZ_ZOOM) is Support.UNKNOWN:
            return None
        return device_sn

    def keep_zoom(self, device_sn: str, zoom: float) -> None:
        if self.zooms.get(device_sn) == zoom:
            return
        self.zooms[device_sn] = zoom
        self._station._bus.emit(
            ZoomChanged(station_sn=self._station.serial, device_sn=device_sn, zoom=zoom)
        )

    def ptz_support(self, device_sn: str, capability: Capability) -> Evidence:
        """See :meth:`Station.ptz_support`."""
        actions = PTZ_ACTIONS.get(capability)
        if actions is None:
            raise ValueError(f"{capability} is not a pan/tilt/zoom capability")
        if not self._station._is_paired(device_sn):
            return Evidence(Support.UNKNOWN, _NOT_PAIRED)
        code = self._station._product_code(device_sn)
        connect = self._station._connect_type_of(device_sn)
        if has_ptz_recipes(code):
            missing = [a for a in actions if ptz_form(code, a, connect) is None]
            if missing:
                return Evidence(Support.UNKNOWN, self._ptz_unsupported_reason(device_sn, missing))
        profile = own_profile(device_sn)
        listed = None if profile is None else profile.capabilities.get(capability)
        if listed is not None and listed.support is Support.VERIFIED:
            return listed
        if not has_ptz_recipes(code):
            return listed or Evidence(
                Support.UNKNOWN, f"no pan/tilt/zoom action recorded for {code or 'this model'}"
            )
        return Evidence(
            Support.DECLARED,
            f"the {code} handler's {' and '.join(actions)} under {connect.value} "
            f"{'is' if len(actions) == 1 else 'are'} the library's recipe "
            f"(eufy app {ptz_app_version()})",
        )

    def ptz_action_support(self, device_sn: str, action: PtzAction) -> Evidence:
        """See :meth:`Station.ptz_action_support`."""
        grades = tuple(Support)
        weakest = max(
            (self._station.ptz_support(device_sn, c) for c in PTZ_ACTION_NEEDS[action]),
            key=lambda evidence: grades.index(evidence.support),
        )
        if weakest.support is Support.UNKNOWN:
            return weakest
        code = self._station._product_code(device_sn)
        connect = self._station._connect_type_of(device_sn)
        if has_ptz_recipes(code) and ptz_form(code, action, connect) is None:
            return Evidence(Support.UNKNOWN, self._ptz_unsupported_reason(device_sn, [action]))
        profile = own_profile(device_sn)
        listed = None if profile is None else profile.ptz_actions.get(action)
        if listed is not None and listed.support is Support.VERIFIED:
            return listed
        if not has_ptz_recipes(code):
            return weakest
        return Evidence(
            Support.DECLARED,
            f"the {code} handler's {action.value} under {connect.value} is the library's recipe",
        )

    def _ptz_unsupported_reason(self, device_sn: str, actions: Sequence[str]) -> str:
        code = self._station._product_code(device_sn)
        connect = self._station._connect_type_of(device_sn)
        where = (
            "on its own" if connect is ConnectType.SINGLE else f"behind a {connect.value} station"
        )
        undeclared = [a for a in actions if a not in ptz_actions(code)]
        if undeclared:
            return f"the {code} thing description declares no {', '.join(undeclared)}"
        return (
            f"the eufy app sends {', '.join(actions)} to a {code} {where} in a way this "
            "library does not implement"
        )

    def _ptz_form(self, device_sn: str, action: str) -> PtzForm:
        """The form the library sends ``action`` to ``device_sn`` in (:mod:`..devices.ptz`):
        :attr:`~..devices.ptz.PtzForm.STANDARD` for a model without recorded handler
        actions. Raises :class:`~..exceptions.PtzActionUnsupportedError` when the device's
        handler sends it in no form the library has, or its thing description does not
        declare it; nothing is sent."""
        code = self._station._product_code(device_sn)
        if not has_ptz_recipes(code):
            return PtzForm.STANDARD
        form = ptz_form(code, action, self._station._connect_type_of(device_sn))
        if form is None:
            raise PtzActionUnsupportedError(
                f"{redact_serial(device_sn)}: {self._ptz_unsupported_reason(device_sn, [action])}",
                action=action,
                device_sn=device_sn,
            )
        return form

    def _require_ptz(self, device_sn: str, capability: Capability) -> int:
        """``device_sn``'s channel, after checking :meth:`ptz_support` for ``capability``;
        ``UnsupportedError`` naming it and the reason otherwise."""
        channel = self._station.channel_for(device_sn)
        evidence = self._station.ptz_support(device_sn, capability)
        if evidence.support is Support.UNKNOWN:
            raise UnsupportedError(
                f"{redact_serial(device_sn)} has no {_PTZ_NAMES[capability]}: {evidence.source}",
                device_sn=device_sn,
            )
        return channel

    def _require_ptz_action(self, device_sn: str, action: PtzAction) -> int:
        """``device_sn``'s channel, after the checks :meth:`ptz_action_support` grades:
        each capability ``action`` needs, then the action itself; nothing is sent."""
        channel = self._station.channel_for(device_sn)
        for capability in PTZ_ACTION_NEEDS[action]:
            self._require_ptz(device_sn, capability)
        self._ptz_form(device_sn, action)
        return channel

    def presets(self, device_sn: str) -> tuple[PresetPosition, ...] | None:
        """See :meth:`Station.presets`."""
        cached = self.preset_slots.get(device_sn)
        if cached is not None or self._station._cache is None:
            return cached
        stored = self._station._cache.presets(self._station.serial, device_sn)
        if stored is None:
            return None
        try:
            slots = parse_preset_positions({"points": stored})
        except (EufySecurityError, TypeError, ValueError):
            return None
        self.preset_slots[device_sn] = slots
        return slots

    def default_preset(self, device_sn: str) -> int | None:
        """See :meth:`Station.default_preset`."""
        slots = self._station.presets(device_sn)
        if slots is None:
            return None
        return next((s.index for s in slots if s.is_default), None)

    async def async_set_default_preset(
        self, device_sn: str, preset: int, *, confirm: bool = False
    ) -> tuple[PresetPosition, ...]:
        """See :meth:`Station.async_set_default_preset`."""
        self._require_ptz_action(device_sn, PtzAction.SET_DEFAULT)
        channel = self.stored_slot(device_sn, preset)
        self.refuse_while_capturing(device_sn)
        await self._station.session.async_run_recipe(
            set_default_preset(preset, confirm=confirm),
            channel=channel,
            timeout=self._station._ptz_waits().default_preset_result,
        )
        await self._station.session.async_run_recipe(goto_preset(preset), channel=channel)
        slots = await self._station.async_refresh_presets(device_sn)
        if not any(s.index == preset and s.is_default for s in slots):
            raise CommandNotAppliedError(
                SubCommand.COMMAND_APP_SET_DEFAULT_POSITION,
                f"{redact_serial(device_sn)} did not make preset {preset} its default",
                device_sn=device_sn,
            )
        return slots

    def zoom(self, device_sn: str) -> float | None:
        """See :meth:`Station.zoom`."""
        return self.zooms.get(device_sn)

    async def async_set_zoom(self, device_sn: str, zoom: float) -> None:
        """See :meth:`Station.async_set_zoom`."""
        if not (MIN_ZOOM <= zoom <= MAX_ZOOM):
            raise ValueError(f"zoom {zoom!r} is outside {MIN_ZOOM:g}..{MAX_ZOOM:g}")
        channel = self._require_ptz(device_sn, Capability.PTZ_ZOOM)
        self._ptz_form(device_sn, "set_picture_zoom")
        view_mode = (
            self._station.session.merged_params().devices.get(channel, {}).get(VIEW_MODE_PARAM)
        )
        if json_int(view_mode) == DUAL_VIEW:
            raise UnsupportedError(
                f"{redact_serial(device_sn)} is in dual view; zoom needs single",
                device_sn=device_sn,
            )
        self.refuse_while_capturing(device_sn)
        await self._station._ptz_recipe(set_picture_zoom(zoom), channel)

    def is_capturing(self, device_sn: str) -> bool:
        """See :meth:`Station.is_capturing`."""
        return device_sn in self.captures

    async def async_refresh_presets(self, device_sn: str) -> tuple[PresetPosition, ...]:
        """See :meth:`Station.async_refresh_presets`."""
        channel = self._preset_channel(device_sn)
        form = self._ptz_form(device_sn, "query_preset_positions")
        reply = await self._station._ptz_recipe(
            query_preset_positions(value=form is PtzForm.STANDARD), channel
        )
        slots = parse_preset_positions(reply.payload or {})
        self._store_presets(device_sn, slots)
        return slots

    async def async_pan_tilt(self, device_sn: str, direction: PanTilt, *, settle: float) -> None:
        """See :meth:`Station.async_pan_tilt`."""
        channel = self._ptz_channel(device_sn)
        form = self._ptz_form(device_sn, "ptz_action_control")
        self.refuse_while_capturing(device_sn)
        await self._station._ptz_recipe(
            pan_tilt(direction, zoom_ivalue=form is PtzForm.STANDARD), channel
        )
        await _settle(settle)

    async def async_goto_preset(self, device_sn: str, preset: int, *, settle: float) -> None:
        """See :meth:`Station.async_goto_preset`."""
        channel = self.stored_slot(device_sn, preset)
        self.refuse_while_capturing(device_sn)
        await self._station._ptz_recipe(goto_preset(preset), channel)
        await _settle(settle)

    async def async_store_preset(
        self, device_sn: str, preset: int, *, confirm: bool = False
    ) -> tuple[PresetPosition, ...]:
        """See :meth:`Station.async_store_preset`."""
        channel = self._require_ptz_action(device_sn, PtzAction.STORE)
        self._check_slot(device_sn, preset)
        self.refuse_while_capturing(device_sn)
        await self._station._ptz_recipe(store_preset(preset, confirm=confirm), channel)
        slots = await self._station.async_refresh_presets(device_sn)
        if not any(s.index == preset and s.enabled for s in slots):
            raise self._not_stored(device_sn, preset, slots)
        return slots

    async def async_save_preset(
        self,
        device_sn: str,
        *,
        preset: int | None = None,
        make_default: bool = False,
        confirm: bool = False,
    ) -> PresetPosition:
        """See :meth:`Station.async_save_preset`."""
        self._require_ptz_action(device_sn, PtzAction.STORE)
        if make_default:
            self._require_ptz_action(device_sn, PtzAction.SET_DEFAULT)
        if preset is not None:
            self._check_slot(device_sn, preset)
        self.refuse_while_capturing(device_sn)
        known = self._station.presets(device_sn)
        if known is not None and self._is_full(known, preset):
            raise self._not_stored(device_sn, preset, known)
        if preset is None:
            known = await self._station.async_refresh_presets(device_sn)
            preset = free_preset_slot(known)
            if preset is None:
                raise self._not_stored(device_sn, None, known)
        slots = await self._station.async_store_preset(device_sn, preset, confirm=confirm)
        if make_default:
            slots = await self._station.async_set_default_preset(device_sn, preset, confirm=confirm)
        return next(s for s in slots if s.index == preset)

    def free_preset(self, device_sn: str) -> int | None:
        """See :meth:`Station.free_preset`."""
        slots = self._station.presets(device_sn)
        return None if slots is None else free_preset_slot(slots)

    @staticmethod
    def _is_full(slots: Sequence[PresetPosition], preset: int | None) -> bool:
        """Whether a store into ``preset`` (None: a free slot) cannot take: the camera
        holds the most it stores and ``preset`` is not one of them."""
        stored = {s.index for s in slots if s.enabled}
        return len(stored) >= MAX_PRESET_SLOTS and preset not in stored

    def _not_stored(
        self, device_sn: str, preset: int | None, slots: Sequence[PresetPosition]
    ) -> CommandNotAppliedError:
        """The error for a store that did not take (or cannot), naming a full camera.

        A camera at :data:`~..devices.recipes.MAX_PRESET_SLOTS` yields
        :class:`~..exceptions.PresetSlotsFullError` so a consumer can tell a full
        camera from a genuine not-applied store without re-deriving the rule.
        """
        stored = [s.index for s in slots if s.enabled]
        full = len(stored) >= MAX_PRESET_SLOTS
        hint = (
            f" (the camera already holds {MAX_PRESET_SLOTS} slots; delete one first)"
            if full
            else ""
        )
        target = "a preset" if preset is None else f"preset {preset}"
        message = (
            f"{redact_serial(device_sn)} did not store {target}{hint} (slots in use: {stored})"
        )
        if full:
            return PresetSlotsFullError(
                SubCommand.COMMAND_INDOOR_SPAN_SET_POINT,
                message,
                slots=MAX_PRESET_SLOTS,
                in_use=tuple(stored),
            )
        return CommandNotAppliedError(SubCommand.COMMAND_INDOOR_SPAN_SET_POINT, message)

    async def async_delete_preset(self, device_sn: str, preset: int) -> tuple[PresetPosition, ...]:
        """See :meth:`Station.async_delete_preset`."""
        channel = self._require_ptz_action(device_sn, PtzAction.DELETE)
        self._check_slot(device_sn, preset)
        await self._station._ptz_recipe(delete_preset(preset), channel)
        slots = await self._station.async_refresh_presets(device_sn)
        if any(s.index == preset and s.enabled for s in slots):
            raise CommandNotAppliedError(
                SubCommand.COMMAND_INDOOR_SPAN_DEL_POINT,
                f"{redact_serial(device_sn)} still holds preset {preset}",
                device_sn=device_sn,
            )
        return slots

    async def async_preset_picture(self, device_sn: str, preset: int) -> bytes | None:
        """See :meth:`Station.async_preset_picture`."""
        channel = self._require_ptz_action(device_sn, PtzAction.SLOT_PICTURE)
        self._check_slot(device_sn, preset)
        reply = await self._station._ptz_recipe(preset_picture(preset), channel)
        data = decode_preset_picture(reply.payload or {})
        return data or None

    def _check_slot(self, device_sn: str, preset: int) -> None:
        """Refuse a slot the camera does not have, before anything is sent.

        The slot range and the store limit are different numbers: a T8170 offers ten
        slot indices (0-9) but stores at most :data:`~..devices.recipes.MAX_PRESET_SLOTS`
        of them at a time. Only the range can be checked up front; a store beyond the
        limit is caught by the read-back.
        """
        known = self._station.presets(device_sn)
        if known and not any(s.index == preset for s in known):
            raise UnsupportedError(
                f"{redact_serial(device_sn)} has no preset slot {preset} "
                f"(slots 0-{max(s.index for s in known)})",
                device_sn=device_sn,
            )
        if preset < 0:
            raise UnsupportedError(f"preset {preset} is not a slot number")

    def _ptz_channel(self, device_sn: str) -> int:
        """``device_sn``'s channel, after checking it has pan/tilt control here."""
        return self._require_ptz(device_sn, Capability.PTZ_CONTROL)

    async def async_preset_image(
        self, device_sn: str, preset: int, *, settle: float, wait: bool = False
    ) -> CameraImage:
        """See :meth:`Station.async_preset_image`."""
        channel = self.stored_slot(device_sn, preset)

        async def capture() -> CameraImage:
            await self._station.session.async_run_recipe(goto_preset(preset), channel=channel)
            data = await self._settled_keyframe(channel, settle, wait=wait)
            await self.refresh_presets_while_awake(device_sn)
            return CameraImage.keyframe(
                source=ImageSource.LIVE, device_sn=device_sn, data=data, preset=preset
            )

        return await self.run_capture(device_sn, preset, capture)

    async def _settled_keyframe(self, channel: int, settle: float, *, wait: bool) -> bytes:
        """The first keyframe of live video that arrives ``settle`` seconds from now.

        A keyframe from before then may show the camera still turning, so none is
        returned instead: a stream that ends first raises ``DeviceTimeoutError``.
        """
        deadline = time.monotonic() + settle
        stream = await self._station._session_live(
            channel,
            idle_timeout=max(self._station._ptz_waits().preset_stream_idle, settle),
            wait=wait,
        )
        async with stream:
            async for frame in stream:
                if frame.is_keyframe and time.monotonic() >= deadline:
                    return frame.data
        raise DeviceTimeoutError(f"the stream ended before the camera settled ({settle:g}s)")

    async def run_capture(
        self,
        device_sn: str,
        preset: int | None,
        capture: Callable[[], Coroutine[Any, Any, CameraImage]],
    ) -> CameraImage:
        """Run ``capture`` as the one capture holding ``device_sn``: join the running one
        when it is the same (live, or the same preset), else raise ``DeviceBusyError``."""
        running = self.captures.get(device_sn)
        if running is not None and running.preset == preset:
            return await asyncio.shield(running.task)
        self.refuse_while_capturing(device_sn)
        task = asyncio.get_running_loop().create_task(
            capture(), name=f"eufy-security-capture-{self._station._log_name}"
        )
        self.captures[device_sn] = _Capture(preset=preset, task=task)
        self._station._bus.emit(
            CameraBusyChanged(station_sn=self._station.serial, device_sn=device_sn, busy=True)
        )

        def release(_task: asyncio.Task[CameraImage]) -> None:
            if self.captures.get(device_sn) is not None and self.captures[device_sn].task is task:
                del self.captures[device_sn]
                self._station._bus.emit(
                    CameraBusyChanged(
                        station_sn=self._station.serial, device_sn=device_sn, busy=False
                    )
                )

        task.add_done_callback(release)
        return await asyncio.shield(task)

    def refuse_while_capturing(self, device_sn: str) -> None:
        """Raise ``DeviceBusyError`` when a capture holds ``device_sn``: a command that
        turns the camera would spoil the image being taken."""
        running = self.captures.get(device_sn)
        if running is not None:
            raise DeviceBusyError(
                f"{redact_serial(device_sn)} is busy with "
                + ("a live image" if running.preset is None else f"preset {running.preset}"),
                device_sn=device_sn,
            )

    def stored_slot(self, device_sn: str, preset: int) -> int:
        """``device_sn``'s channel, after checking its model has presets and ``preset``
        is not a slot the last read showed empty; nothing is sent."""
        channel = self._preset_channel(device_sn)
        known = self._station.presets(device_sn)
        if known is not None and not any(s.index == preset and s.enabled for s in known):
            raise UnsupportedError(
                f"preset {preset} is not set on {redact_serial(device_sn)}", device_sn=device_sn
            )
        return channel

    def _preset_channel(self, device_sn: str) -> int:
        """``device_sn``'s channel, after checking it has pan/tilt presets here."""
        return self._require_ptz(device_sn, Capability.PTZ_PRESETS)

    async def refresh_presets_while_awake(self, device_sn: str) -> None:
        """Re-read the presets of a pan/tilt camera that is awake anyway (best effort)."""
        if self._station.ptz_support(device_sn, Capability.PTZ_PRESETS).support is Support.UNKNOWN:
            return
        try:
            await self._station.async_refresh_presets(device_sn)
        except EufySecurityError as err:
            _LOGGER.debug("%s: preset read while awake failed: %s", self._station._log_name, err)

    def _store_presets(self, device_sn: str, slots: tuple[PresetPosition, ...]) -> None:
        if self._station.presets(device_sn) == slots:
            return
        self.preset_slots[device_sn] = slots
        if self._station._cache is not None:
            self._station._cache.set_presets(
                self._station.serial,
                device_sn,
                [
                    {
                        "index": s.index,
                        "enable": int(s.enabled),
                        "zoom": s.zoom,
                        "isdefault": int(s.is_default),
                    }
                    for s in slots
                ],
            )
            self._station._cache.schedule_save()
        _LOGGER.debug(
            "%s: presets of %s: %s enabled",
            self._station._log_name,
            redact_serial(device_sn),
            [s.index for s in slots if s.enabled],
        )
        self._station._bus.emit(
            PresetsChanged(station_sn=self._station.serial, device_sn=device_sn, presets=slots)
        )
