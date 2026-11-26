"""What the RTC signaling client sends and how it reads a call's packets (pure).

The JSON a CALL, an INFO, the MESSAGE ping and a MESSAGE answer carry, the uuid of a
private call, the LOGIN retry waits, and which event a packet on a call is. The
client that sends them over UDP is not part of this module. See
``docs/protocol/rtc-signaling.md`` § Sequence.
"""

from __future__ import annotations

import base64
import hashlib
import random
from collections.abc import Mapping
from enum import StrEnum
from typing import Any, Final

from . import codec
from .codec import CallKind, Header, MessageType, ResponseCode
from .config import RtcConfig
from .sdp import SdpInfo

LOGIN_ATTEMPTS: Final = 4
LOGIN_RETRY_BASE: Final = 10.0
LOGIN_RETRY_FACTOR: Final = 3
LOGIN_RETRY_MAX: Final = 270.0
#: The ``ftv`` field of a CALL attachment.
CALL_FTV: Final = 20
#: ``eufy_network_type`` of a client on UDP.
NETWORK_UDP: Final = 1
#: The ``to`` field of every attachment the client sends.
TO_DEVICE: Final = "device"


def login_retry_delays(rng: random.Random) -> list[float]:
    """How long each LOGIN attempt waits for its answer: 10 s plus 1-10 s, then three
    times the previous wait, at most 270 s; :data:`LOGIN_ATTEMPTS` waits."""
    delay = LOGIN_RETRY_BASE + rng.randint(1, 10)
    delays = []
    for _ in range(LOGIN_ATTEMPTS):
        delays.append(min(delay, LOGIN_RETRY_MAX))
        delay *= LOGIN_RETRY_FACTOR
    return delays


def md5_hex(text: str) -> str:
    """Lower-case hex MD5 of ``text``: the attachments' ``account`` field and the
    private calls' uuid (an identifier, not a secret)."""
    return hashlib.md5(text.encode(), usedforsecurity=False).hexdigest()


def private_call_uuid(config: RtcConfig, kind: CallKind, micros: int) -> str:
    """The 36-character uuid of a private call: ``"FF00<kind>"`` and 31 hex digits of
    an MD5 over the station's identity, the app id, the time in microseconds and the
    kind."""
    digest = md5_hex(
        f"{config.station_sn}{config.app_id}{config.p2p_did}{config.p2p_license}{micros}{int(kind)}"
    )
    return f"FF00{int(kind)}{digest[:31]}"


def call_attachment(
    config: RtcConfig,
    kind: CallKind,
    *,
    channel: int,
    contact_id: str,
    now: int,
    video_format: int = 0,
    token: bytes | None = None,
    sdp_info: SdpInfo | None = None,
    boot_action: int | None = None,
) -> dict[str, Any]:
    """The JSON of a CALL of ``kind`` on ``channel`` at ``now`` (the packet id).

    A private kind (:data:`~.codec.PRIVATE_CALL_KINDS`) also carries ``token`` (the
    station identity sealed with the session key) and ``sdp_info``, both base64, and
    ``boot_action`` when given. Raises :class:`ValueError` for a private kind without
    ``token`` and ``sdp_info``.
    """
    call_type, p2p_type = codec.CALL_TYPES[kind]
    value: dict[str, Any] = {
        "account": md5_hex(f"{channel}{config.user_id}{now}"),
        "ftv": CALL_FTV,
        "call_type": call_type,
    }
    if p2p_type is not None:
        value["eufy_p2p_type"] = p2p_type
    value |= {
        "to": TO_DEVICE,
        "eufy_from_contact": contact_id,
        "eufy_video_format": video_format,
        "eufy_network_type": NETWORK_UDP,
        "eufy_app_id": config.app_id,
    }
    if kind in codec.PRIVATE_CALL_KINDS:
        if token is None or sdp_info is None:
            raise ValueError(f"a {kind.name} call needs a token and sdp_info")
        value["token"] = base64.b64encode(token).decode()
        value["sdp_info"] = base64.b64encode(sdp_info.encode()).decode()
        if boot_action is not None:
            value["boot_action"] = boot_action
    return value


def ping_message(
    config: RtcConfig, *, contact_id: str, dynamic_id: int, now: int
) -> dict[str, Any]:
    """The JSON of a MESSAGE ping at ``now``; ``dynamic_id`` is the client's random id,
    fixed for its lifetime."""
    content = {
        "eufy_contact_id": contact_id,
        "eufy_network_type": NETWORK_UDP,
        "eufy_app_id": config.app_id,
    }
    return {
        "to": TO_DEVICE,
        "account": md5_hex(f"0{config.user_id}{now}"),
        "eufy_client_dynamic_id": dynamic_id,
        "content": base64.b64encode(codec.json_bytes(content)).decode(),
    }


def message_answer(dynamic_id: int) -> dict[str, Any]:
    """The JSON of the 200 that answers a MESSAGE request from the server or device."""
    return {
        "to": TO_DEVICE,
        "eufy_client_dynamic_id": dynamic_id,
        "account": "",
        "content": "",
        "eufy_network_type": NETWORK_UDP,
    }


def info_payload(device_request_id: object, payload: Mapping[str, Any]) -> dict[str, Any]:
    """The JSON of an INFO on a call: ``payload`` (a candidate or an SDP), led by the
    device's ``request_id`` when its CALL 200 carried a non-empty one."""
    if device_request_id in (None, ""):
        return dict(payload)
    return {"request_id": device_request_id, **payload}


class CallEventKind(StrEnum):
    """What a packet on a call means."""

    TRYING = "trying"
    """CALL 100 from the server; the attachment may carry ``turn``."""
    OFFER = "offer"
    """CALL 200 from the device: its ``sdp_info`` (base64) plus ``turn``, ``srflx``,
    ``port`` and ``addr``; the client acknowledges it with ACK."""
    INFO = "info"
    """INFO from the device (a candidate, an SDP or ``content``), answered 200 when it
    is a request."""
    HANGUP = "hangup"
    REFUSED = "refused"
    """CALL answered with an error code (480, 486): the call ends."""


def call_event(header: Header) -> CallEventKind:
    """The event a CALL, INFO or HANGUP packet on a call stands for."""
    if header.message_type == MessageType.HANGUP:
        return CallEventKind.HANGUP
    if header.message_type == MessageType.INFO:
        return CallEventKind.INFO
    if header.code == ResponseCode.TRYING:
        return CallEventKind.TRYING
    if header.code == ResponseCode.OK:
        return CallEventKind.OFFER
    if header.is_response:
        return CallEventKind.REFUSED
    return CallEventKind.INFO
