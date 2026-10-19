"""SDP pieces of an RTC media call that the signaling carries.

A private media CALL (:attr:`~.codec.CallKind.PRIV_MEDIA`) carries an ``sdp_info``
the app generates: both its SSRCs, the ICE username and password the app side will
use, a content key and IV, and whether a data channel is wanted. The device
answers with a compact offer (``ice-u``, ``ice-p``, ``asc``, ``vsc``, ``sg``,
``sgc``) that the app expands into a full SRTP offer from a template; the app's
answer keeps only its ICE credentials and SSRC lines.

The byte layout of ``sdp_info`` and the offer template are not known yet:
:meth:`SdpInfo.encode` and :func:`expand_offer` raise
:class:`~.exceptions.UnsupportedError`.
"""

from __future__ import annotations

import random
import string
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from .._logging import redact
from ..exceptions import UnsupportedError

SDP_INFO_LEN: Final = 86
"""Length of the packed ``sdp_info`` structure."""

_ICE_ALPHABET: Final = string.ascii_letters + string.digits
_ICE_FIELD_LEN: Final = 64
#: Answer lines the app keeps: its ICE credentials and its SSRC attributes.
ANSWER_PREFIXES: Final = ("a=ice-ufrag:", "a=ice-pwd:", "a=ssrc:")


@dataclass(frozen=True, slots=True, kw_only=True)
class SdpInfo:
    """What a private media CALL tells the device about the app side."""

    audio_ssrc: int
    video_ssrc: int
    ice_ufrag: str
    ice_pwd: str
    content_key: str
    content_iv: str
    data_channel: bool = False

    @classmethod
    def generate(
        cls,
        content_key: str,
        content_iv: str,
        *,
        data_channel: bool = False,
        rng: random.Random | None = None,
    ) -> SdpInfo:
        """Fresh SSRCs and ICE credentials; the content key and IV come from the
        signaling crypto (:meth:`~.crypto.RtcCrypto.new_media_secret`)."""
        rand = rng or random.SystemRandom()
        return cls(
            audio_ssrc=rand.getrandbits(32),
            video_ssrc=rand.getrandbits(32),
            ice_ufrag="".join(rand.choice(_ICE_ALPHABET) for _ in range(_ICE_FIELD_LEN)),
            ice_pwd="".join(rand.choice(_ICE_ALPHABET) for _ in range(_ICE_FIELD_LEN)),
            content_key=content_key,
            content_iv=content_iv,
            data_channel=data_channel,
        )

    def encode(self) -> bytes:
        """The packed structure (:data:`SDP_INFO_LEN` bytes). Not known yet."""
        raise UnsupportedError("the layout of a private call's sdp_info is not known")

    def __repr__(self) -> str:
        return (
            f"SdpInfo(audio_ssrc={self.audio_ssrc}, video_ssrc={self.video_ssrc}, "
            f"ice_ufrag={redact(self.ice_ufrag)!r}, content_key={redact(self.content_key)!r}, "
            f"data_channel={self.data_channel})"
        )


@dataclass(frozen=True, slots=True)
class CompactOffer:
    """The device's compact offer of a private media call."""

    ice_ufrag: str | None
    ice_pwd: str | None
    audio_ssrc: int | None
    video_ssrc: int | None
    fields: Mapping[str, Any]
    """Every field as received (``sg``, ``sgc`` are not interpreted)."""

    @classmethod
    def from_json(cls, data: Mapping[str, Any]) -> CompactOffer:
        def num(key: str) -> int | None:
            value = data.get(key)
            if isinstance(value, int):
                return value
            if isinstance(value, str) and value.isdigit():
                return int(value)
            return None

        def text(key: str) -> str | None:
            value = data.get(key)
            return value if isinstance(value, str) and value else None

        return cls(text("ice-u"), text("ice-p"), num("asc"), num("vsc"), dict(data))


def expand_offer(offer: CompactOffer) -> str:
    """The full SDP offer the app builds from a compact offer. Not known yet."""
    raise UnsupportedError("the SDP template of a private media call is not known")


def answer_attributes(sdp: str) -> str:
    """The lines of an SDP answer the app sends back: its ICE credentials and its
    SSRC attributes, CRLF-separated."""
    lines = [line for line in sdp.splitlines() if line.startswith(ANSWER_PREFIXES)]
    return "".join(f"{line}\r\n" for line in lines)
