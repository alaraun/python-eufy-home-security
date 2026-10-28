"""The contract between a station session and its parts: inbound frames and requests."""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from typing import TYPE_CHECKING, Any, Protocol

from ...exceptions import (
    AccountRejectedError,
    CameraWakeError,
    CommandRejectedError,
    CommandUnsupportedError,
)
from ..messages import (
    CAMERA_WAKE_CODES,
    CMD_DOWNLOAD_VIDEO,
    CMD_RECORD_VIEW,
    RECEIPT_CODES,
    RECEIPT_NOT_HANDLED,
    RESULT_INVALID_ACCOUNT,
    RESULT_INVALID_COMMAND,
)
from ..xzyh import Frame, FrameType

if TYPE_CHECKING:
    from . import P2PCredentials

_RECORDING_COMMANDS = frozenset({CMD_DOWNLOAD_VIDEO, CMD_RECORD_VIEW})


class FrameDecoder(Protocol):
    """The session's decoders an :class:`Inbound` uses."""

    def _decode_json(self, frame: Frame) -> dict[str, Any] | None: ...

    def _decode_receipt(self, channel: int, frame: Frame) -> tuple[int, int | None] | None: ...

    def _decode_alarm_mode(self, frame: Frame) -> int | None: ...


@dataclass(slots=True)
class Inbound:
    """One reassembled frame, with its JSON body decrypted at most once."""

    channel: int
    frame: Frame
    _session: FrameDecoder = field(repr=False)
    _json: dict[str, Any] | None = field(default=None, repr=False)
    _json_done: bool = field(default=False, repr=False)
    _mode: int | None = field(default=None, repr=False)
    _mode_done: bool = field(default=False, repr=False)
    _receipt: int | None = field(default=None, repr=False)
    _receipt_done: bool = field(default=False, repr=False)
    _result_slot: int | None = field(default=None, repr=False)

    @property
    def type(self) -> int:
        return self.frame.type

    def json(self) -> dict[str, Any] | None:
        """The frame's JSON body, decoded at most once; None for a command receipt."""
        if not self._json_done:
            receipt = self.receipt() is not None
            self._json = None if receipt else self._session._decode_json(self.frame)
            self._json_done = True
        return self._json

    def receipt(self) -> int | None:
        """The code of a command receipt on the request channel (0), decoded at most once;
        None for any other frame.

        On an RSA session it is the reply to a send of the frame's type, its code read
        in clear as the eufy app reads it (:meth:`StationSession._decode_receipt`).
        """
        if not self._receipt_done:
            decoded = self._session._decode_receipt(self.channel, self.frame)
            if decoded is not None:
                self._receipt, self._result_slot = decoded
            self._receipt_done = True
        return self._receipt

    def result_slot(self) -> int | None:
        """On an RSA session, the slot of the send whose result this frame is
        (:meth:`StationSession._send_request`); None on a GCM session or for no result."""
        self.receipt()
        return self._result_slot

    def alarm_mode(self) -> int | None:
        """The guard mode of a 0x047F report, decoded at most once."""
        if not self._mode_done:
            self._mode = self._session._decode_alarm_mode(self.frame)
            self._mode_done = True
        return self._mode


type Matcher = Callable[[Inbound], object | None]


class RequestCore(Protocol):
    """The session members a request-only part (history, stills, queries) uses."""

    serial: str
    _log_name: str

    async def async_connect(self) -> None: ...

    def _require_creds(self) -> P2PCredentials: ...

    def _send_secure(
        self,
        plaintext: bytes,
        *,
        frame_type: int = FrameType.CMD_TRANSFER,
        dev_type: int = 0,
        flag: int = 0,
    ) -> int: ...

    async def _request(
        self,
        send: Callable[[], object],
        match: Matcher,
        *,
        timeout: float,
        resend_after: float | None = None,
        label: str = "request",
        send_only_under_lock: bool = False,
    ) -> object: ...


def _rejection(command: int, code: int, message: str = "") -> CommandRejectedError:
    """The error a non-zero result or receipt code raises on every command path: -104
    :class:`AccountRejectedError`, -103 :class:`CommandUnsupportedError`, any other
    :class:`CommandRejectedError`."""
    if code == RESULT_INVALID_ACCOUNT:
        return AccountRejectedError(command, code, message)
    if code == RESULT_INVALID_COMMAND:
        return CommandUnsupportedError(command, code, message)
    return CommandRejectedError(command, code, message)


def _receipt_error(command: int, code: int) -> CommandRejectedError:
    """The error a non-zero command receipt or result raises: -108
    :class:`CommandUnsupportedError`, a camera wake failure :class:`CameraWakeError`,
    any other code as :func:`_rejection` maps it."""
    name = RECEIPT_CODES.get(code, "")
    if code == RECEIPT_NOT_HANDLED:
        return CommandUnsupportedError(command, code, name)
    if code in CAMERA_WAKE_CODES:
        return CameraWakeError(command, code, f"the station could not wake the camera ({name})")
    return _rejection(command, code, f"command receipt {name}".rstrip())
