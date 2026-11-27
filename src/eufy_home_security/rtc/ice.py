"""ICE for the WebRTC data channel, over :mod:`aioice` (the ``rtc`` extra).

:class:`IceTransport` runs one ICE connection with the local credentials the client put
in its CALL's ``sdp_info`` and the remote credentials of the device's answer. The device
is the controlling side, so the client is the controlled one; one component, UDP only,
IPv4 only (the signaling path is IPv4), the TURN relay of the CALL when there is one.
Remote candidates may arrive before :meth:`IceTransport.gather`; they are kept and handed
over then. A device sends a handful of candidates; at most :data:`MAX_REMOTE_CANDIDATES`
are taken per connection.

:meth:`IceTransport.close` closes the aioice connection, which stops its connectivity
checks; a cancelled or timed-out connect leaves them to that close (the session always
closes an attempt). aioice fails ICE only after the end of the remote candidates, which
the device does not signal, so a failed ICE ends at the session's ``ICE_TIMEOUT`` as a
:class:`~.exceptions.DeviceTimeoutError`. With a TURN server, a cancel or a close while
candidates are gathered leaves aioice's TURN allocation running until its request times
out, or its socket open when the server answers after it (an aioice limit).

:mod:`aioice` is imported on first use; without the extra the constructor raises
:class:`~.exceptions.MissingDependencyError`. See ``docs/protocol/rtc-signaling.md``
§ Session.
"""

from __future__ import annotations

import asyncio
import logging
from typing import TYPE_CHECKING, Any, Final, Protocol, runtime_checkable

from .._logging import LogThrottle
from ..exceptions import CommunicationError, MissingDependencyError, ProtocolError
from .media import CANDIDATE_PREFIX, TurnServer, candidate_body

if TYPE_CHECKING:
    from aioice import Candidate, Connection

_LOGGER = logging.getLogger(__name__)

#: Remote candidates taken per connection; more are dropped.
MAX_REMOTE_CANDIDATES: Final = 16

#: aioice's own bound on gathering STUN and TURN candidates, in seconds.
AIOICE_GATHER_TIMEOUT: Final = 5.0


def require_aioice() -> Any:
    """The ``aioice`` module; :class:`~.exceptions.MissingDependencyError` without the
    ``rtc`` extra."""
    try:
        import aioice  # noqa: PLC0415 - optional dependency
    except ImportError as err:
        raise MissingDependencyError("the WebRTC transport", extra="rtc") from err
    return aioice


@runtime_checkable
class IceAgent(Protocol):
    """What the session needs of an ICE connection (:class:`IceTransport`, or a fake)."""

    async def gather(
        self, *, local_ufrag: str, local_pwd: str, turn: TurnServer | None
    ) -> list[str]:
        """Gather local candidates; returns their ``candidate:`` lines."""
        ...

    def add_remote_candidate(self, candidate: str) -> None: ...

    async def connect(self, *, remote_ufrag: str, remote_pwd: str) -> None: ...

    async def recv(self) -> bytes: ...

    async def send(self, data: bytes) -> None: ...

    async def close(self) -> None: ...


class IceTransport:
    """An :class:`IceAgent` over one :class:`aioice.Connection`."""

    def __init__(self) -> None:
        self._aioice = require_aioice()
        self._connection: Connection | None = None
        self._pending: list[Candidate] = []
        self._remote = 0
        self._tasks: set[asyncio.Task[None]] = set()
        self._checks: asyncio.Task[None] | None = None
        self._closed = False
        self._throttle = LogThrottle()

    async def gather(
        self, *, local_ufrag: str, local_pwd: str, turn: TurnServer | None
    ) -> list[str]:
        connection = self._aioice.Connection(
            ice_controlling=False,
            components=1,
            turn_server=(turn.host, turn.port) if turn else None,
            turn_username=turn.username if turn else None,
            turn_password=turn.password if turn else None,
            use_ipv6=False,
            local_username=local_ufrag,
            local_password=local_pwd,
        )
        self._connection = connection
        pending, self._pending = self._pending, []
        for candidate in pending:
            await connection.add_remote_candidate(candidate)
        await connection.gather_candidates()
        return [f"{CANDIDATE_PREFIX}{c.to_sdp()}" for c in connection.local_candidates]

    def add_remote_candidate(self, candidate: str) -> None:
        """Take one remote candidate line (``a=candidate:...`` or ``candidate:...``);
        a TCP one is ignored. Raises :class:`~.exceptions.ProtocolError` for a line that
        does not parse."""
        try:
            parsed = self._aioice.Candidate.from_sdp(candidate_body(candidate))
        except (ValueError, IndexError) as exc:
            raise ProtocolError(f"unreadable ICE candidate: {exc}") from exc
        if parsed.transport.lower() != "udp":
            return
        if self._remote >= MAX_REMOTE_CANDIDATES:
            if self._throttle.should_log("candidates"):
                _LOGGER.debug("RTC remote candidate dropped: %d taken", self._remote)
            return
        self._remote += 1
        if self._connection is None:
            self._pending.append(parsed)
            return
        task = asyncio.get_running_loop().create_task(self._connection.add_remote_candidate(parsed))
        self._tasks.add(task)
        task.add_done_callback(self._added)

    def _added(self, task: asyncio.Task[None]) -> None:
        self._tasks.discard(task)
        if not task.cancelled() and (exc := task.exception()) is not None:
            _LOGGER.debug("RTC remote candidate not added: %s", exc)

    async def connect(self, *, remote_ufrag: str, remote_pwd: str) -> None:
        """Run the ICE checks; raises :class:`~.exceptions.CommunicationError` when they
        fail."""
        connection = self._require()
        connection.remote_username = remote_ufrag
        connection.remote_password = remote_pwd
        checks = asyncio.get_running_loop().create_task(connection.connect())
        self._checks = checks
        try:
            await asyncio.wait({checks})
        except asyncio.CancelledError:
            checks.cancel()
            await asyncio.wait({checks})
            raise
        finally:
            if self._checks is checks:
                self._checks = None
        if checks.cancelled() or self._closed:
            raise CommunicationError("RTC ICE closed while it connected")
        exc = checks.exception()
        if exc is not None:  # aioice cancelled its checks itself
            if isinstance(exc, ConnectionError):
                raise CommunicationError(f"RTC ICE did not connect: {exc}") from exc
            raise exc

    def selected_pair(self) -> tuple[str, str] | None:
        """The candidate types (``host``, ``srflx``, ``relay``, ...) of the selected pair,
        local first; None before ICE connects or when aioice does not say."""
        if self._connection is None:
            return None
        for stats in self._connection.get_statistics():
            if stats.selected:
                return stats.local_candidate.type, stats.remote_candidate.type
        return None

    async def recv(self) -> bytes:
        try:
            return await self._require().recv()
        except ConnectionError as exc:
            raise CommunicationError("RTC ICE connection closed") from exc

    async def send(self, data: bytes) -> None:
        try:
            await self._require().send(data)
        except ConnectionError as exc:
            raise CommunicationError("RTC ICE connection closed") from exc

    async def close(self) -> None:
        """Close the connection, which stops its checks, and every socket; a running
        :meth:`connect` raises :class:`~.exceptions.CommunicationError`."""
        self._closed = True
        checks = self._checks
        tasks = list(self._tasks)
        if checks is not None:
            tasks.append(checks)
        for task in tasks:
            task.cancel()
        if tasks:
            await asyncio.wait(tasks)
        if self._connection is not None:
            await self._connection.close()

    def _require(self) -> Connection:
        if self._connection is None:
            raise CommunicationError("RTC ICE has not gathered candidates yet")
        return self._connection
