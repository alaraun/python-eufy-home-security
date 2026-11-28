"""Bounded repeated activation of a momentary dedicated siren."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from typing import Final

from ..exceptions import (
    DeviceBusyError,
    DeviceTimeoutError,
    StationUnreachableError,
)
from ..p2p.session import CommandOutcome

_LOGGER = logging.getLogger(__name__)

SIREN_REPEAT_INTERVAL: Final = 1.5
SIREN_REPEAT_DURATION: Final = 30.0

type PulseResult = tuple[CommandOutcome, float] | None
type Pulse = Callable[
    [Callable[[], bool]],
    Awaitable[PulseResult],
]


class SirenLoop:
    """Maintain a momentary siren with bounded repeated activation.

    The pulse callback must check its supplied predicate under the
    session command lock, immediately before transmission.

    It returns the command outcome and monotonic transmission time,
    or None when the predicate prevents transmission.

    Both command callbacks must use the original connection generation
    without automatically reconnecting.

    Running describes a library operation, not confirmed ringing.
    """

    def __init__(
        self,
        pulse: Pulse,
        interrupt: Callable[[], Awaitable[CommandOutcome]],
        is_current: Callable[[], bool],
        *,
        log_name: str,
        on_active_changed: Callable[[bool], None],
    ) -> None:
        self._pulse = pulse
        self._interrupt = interrupt
        self._is_current = is_current
        self._log_name = log_name
        self._on_active_changed = on_active_changed
        self._active = False
        self._lock = asyncio.Lock()
        self._stop_requested = asyncio.Event()
        self._task: asyncio.Task[CommandOutcome | None] | None = None
        self._first: asyncio.Future[CommandOutcome] | None = None

    @property
    def running(self) -> bool:
        """Whether the operation, including cleanup, remains active."""
        return self._task is not None and not self._task.done()

    @property
    def active(self) -> bool:
        """Whether an accepted sustained alarm operation is active."""
        return self._active

    def _set_active(self, active: bool) -> None:
        if self._active == active:
            return

        self._active = active
        self._on_active_changed(active)

    def _require_current(self) -> None:
        if not self._is_current():
            raise StationUnreachableError("siren connection is no longer current")

    def _can_send(self, deadline: float) -> bool:
        return (
            not self._stop_requested.is_set()
            and self._is_current()
            and asyncio.get_running_loop().time() < deadline
        )

    @staticmethod
    def _observe_first(
        future: asyncio.Future[CommandOutcome],
    ) -> None:
        if not future.cancelled():
            future.exception()

    def _observe_task(
        self,
        task: asyncio.Task[CommandOutcome | None],
    ) -> None:
        if not task.cancelled():
            error = task.exception()
            if error is not None:
                _LOGGER.error(
                    "%s: dedicated siren cleanup failed",
                    self._log_name,
                    exc_info=error,
                )

    async def test(self) -> CommandOutcome:
        """Submit one sound-test pulse without starting repetition."""
        async with self._lock:
            self._require_current()

            if self.running:
                raise DeviceBusyError("dedicated siren alarm is already active")

            deadline = asyncio.get_running_loop().time() + SIREN_REPEAT_INTERVAL

            result = await self._pulse(lambda: self._can_send(deadline))

            if result is None:
                raise DeviceTimeoutError("siren test was not submitted")

            outcome, _ = result
            return outcome

    async def start(self) -> CommandOutcome:
        """Start one bounded operation without extending duplicate starts."""
        async with self._lock:
            self._require_current()

            if self.running:
                if self._stop_requested.is_set():
                    raise DeviceBusyError("dedicated siren is stopping")
                if self._first is None:
                    raise RuntimeError("active siren operation has no initial outcome")

                first = self._first
            else:
                loop = asyncio.get_running_loop()

                self._stop_requested = asyncio.Event()

                first = loop.create_future()
                first.add_done_callback(self._observe_first)
                self._first = first

                self._task = loop.create_task(
                    self._run_operation(first),
                    name="dedicated-siren-loop",
                )

                self._task.add_done_callback(self._observe_task)

        # Cancellation of the API caller must not abandon
        # the command's outstanding receipt.
        return await asyncio.shield(first)

    async def _wait_for_slot(self, when: float) -> bool:
        """Wait for a refresh slot, or return early on stop."""
        if self._stop_requested.is_set() or not self._is_current():
            return False

        delay = when - asyncio.get_running_loop().time()

        if delay > 0:
            try:
                async with asyncio.timeout(delay):
                    await self._stop_requested.wait()
            except TimeoutError:
                pass

        return not self._stop_requested.is_set() and self._is_current()

    async def _run_operation(
        self,
        first: asyncio.Future[CommandOutcome],
    ) -> CommandOutcome | None:
        try:
            return await self._run(first)
        finally:
            self._set_active(False)

    async def _run(
        self,
        first: asyncio.Future[CommandOutcome],
    ) -> CommandOutcome | None:
        loop = asyncio.get_running_loop()
        may_have_sent = False

        try:
            self._require_current()

            deadline = loop.time() + SIREN_REPEAT_INTERVAL

            may_have_sent = True

            result = await self._pulse(lambda: self._can_send(deadline))

            if result is None:
                may_have_sent = False
                raise DeviceTimeoutError("initial siren activation was not submitted")

            outcome, sent_at = result

            self._set_active(True)
            first.set_result(outcome)

            expires_at = sent_at + SIREN_REPEAT_DURATION

            scheduled_at = sent_at + SIREN_REPEAT_INTERVAL

            while scheduled_at < expires_at:
                # Never replay missed refresh slots.
                if scheduled_at <= loop.time():
                    scheduled_at += SIREN_REPEAT_INTERVAL
                    continue

                if not await self._wait_for_slot(scheduled_at):
                    break

                deadline = min(
                    scheduled_at + SIREN_REPEAT_INTERVAL,
                    expires_at,
                )

                if not self._can_send(deadline):
                    break

                # No timeout around this command:
                # the transport owns the receipt wait.
                def can_send(deadline: float = deadline) -> bool:
                    return self._can_send(deadline)

                result = await self._pulse(can_send)

                if result is None:
                    scheduled_at += SIREN_REPEAT_INTERVAL
                else:
                    _, sent_at = result

                    # Maintain minimum spacing between
                    # actual activation transmissions.
                    scheduled_at = sent_at + SIREN_REPEAT_INTERVAL

            if not self._stop_requested.is_set() and self._is_current():
                await self._wait_for_slot(expires_at)

        except asyncio.CancelledError:
            if not first.done():
                first.cancel()
            raise

        except Exception as error:
            if not first.done():
                first.set_exception(error)

            _LOGGER.exception(
                "%s: dedicated siren activation ended early",
                self._log_name,
            )

        # A lost connection must not be reopened to finish
        # an earlier siren operation.
        if not self._is_current():
            return None

        if may_have_sent or self._stop_requested.is_set():
            return await self._interrupt()

        return None

    async def stop(self) -> CommandOutcome:
        """Prevent further activations and send the native stop."""
        async with self._lock:
            self._stop_requested.set()

            task = self._task

            if task is not None and not task.done():
                # Preserve any outstanding receipt wait.
                outcome = await asyncio.shield(task)

                if outcome is None:
                    raise StationUnreachableError("siren interruption could not be submitted")

                return outcome

            # Explicit OFF also works when no loop is active.
            self._require_current()
            return await self._interrupt()

    def request_stop(self) -> None:
        """Prevent further pulses without cancelling a pending receipt."""
        self._stop_requested.set()
