"""SDP pieces of an RTC media call that the signaling carries.

A private media CALL (:attr:`~.codec.CallKind.PRIV_MEDIA`) carries an ``sdp_info``
the client generates: both its SSRCs, its ICE username and password, a content key
and IV, and whether a data channel is wanted. Verified on a
HomeBase 3 (T8030P): the device answers the CALL 200 with its own ``sdp_info`` of
the same 86-byte shape (its ICE credentials, content key, content IV and SSRCs) —
not an SDP text offer — alongside the TURN relay, its ``srflx`` and ``port``, and
then trickles its ICE candidates as INFO frames. Use :meth:`SdpInfo.decode` on the
answer.

:class:`CompactOffer` / :func:`expand_offer` are the *event* device-SDP path
(compact JSON ``ice-u``/``asc``/… expanded from a template); they are not the live
CALL answer and are not verified.

The ``sdp_info`` layout is verified on hardware; the SDP template is declared (eufy
app), not verified.
"""

from __future__ import annotations

import random
import string
import struct
from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, Final

from .._logging import redact
from ..exceptions import SignalingError

SDP_INFO_LEN: Final = 86
"""Length of the packed ``sdp_info`` structure."""

#: ICE credential alphabet (RFC 5245 ice-char).
_ICE_ALPHABET: Final = string.ascii_uppercase + string.ascii_lowercase + string.digits + "+/"
#: ICE username length, in characters.
ICE_UFRAG_LEN: Final = 5
#: ICE password length, in characters.
ICE_PWD_LEN: Final = 23
#: Content key length, in characters.
CONTENT_KEY_LEN: Final = 16
#: Content IV length, in characters.
CONTENT_IV_LEN: Final = 12
#: Answer lines kept: the ICE credentials and the SSRC attributes.
ANSWER_PREFIXES: Final = ("a=ice-ufrag:", "a=ice-pwd:", "a=ssrc:")

#: The constant SDES master key of the SDP template, base64 of a 30-byte
#: AES_CM_128_HMAC_SHA1_80 key+salt; the same key both directions, DTLS off.
SDES_INLINE_KEY: Final = "FvLcvU2P3ZWmQxgPAgcDu7Zl9vftYElFOjEzhWs5"

_CRYPTO_LINE: Final = f"a=crypto:1 AES_CM_128_HMAC_SHA1_80 inline:{SDES_INLINE_KEY}"
# The media SDP template rendered from a device's compact offer (the `v=extmap:3`
# line is kept verbatim). `{...}` fields are filled from the offer; everything else,
# including the cnames, is constant.
_SDP_TEMPLATE: Final = (
    "v=0",
    "o=- 1751872 1751872 IN IP4 127.0.0.1",
    "s=Anker Webrtc Stream",
    "t=0 0",
    "a=group:BUNDLE 0 1",
    "a=msid-semantic: WMS b350J",
    "m=audio 1 RTP/SAVPF 111",
    "c=IN IP4 127.0.0.1",
    "a=mid:0",
    "a=extmap:9 anker-qos-feedback:transport-sequence",
    "a=sendrecv",
    "a=rtcp-mux",
    "a=ice-ufrag:{ufrag}",
    "a=ice-pwd:{pwd}",
    _CRYPTO_LINE,
    "a=setup:actpass",
    "a=rtpmap:111 opus/48000/2",
    "a=fmtp:111 maxplaybackrate=48000;stereo=1;minptime=10;maxptime=80;useinbandfec=1",
    "a=ssrc:{audio_ssrc} cname:uIGCl7ux",
    "m=video 1 RTP/SAVPF 97 99 125",
    "c=IN IP4 0.0.0.0",
    "a=mid:1",
    "a=extmap:2 http://www.webrtc.org/experiments/rtp-hdrext/abs-send-time",
    "v=extmap:3 http://www.ietf.org/id/draft-holmer-rmcat-transport-wide-cc-extensions-01",
    "a=extmap:5 http://www.webrtc.org/experiments/rtp-hdrext/playout-delay",
    "a=extmap:6 http://www.webrtc.org/experiments/rtp-hdrext/abs-capture-time",
    "a=extmap:9 anker-qos-feedback:transport-sequence",
    "a=sendonly",
    "a=rtcp-mux",
    "a=ice-ufrag:{ufrag}",
    "a=ice-pwd:{pwd}",
    _CRYPTO_LINE,
    "a=setup:actpass",
    "a=rtpmap:97 H265/90000",
    "a=rtcp-fb:97 rrtr",
    "a=rtcp-fb:97 goog-remb",
    "a=rtcp-fb:97 transport-cc",
    "a=rtcp-fb:97 nack",
    "a=rtcp-fb:97 nack pli",
    "a=fmtp:97 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f",
    "a=rtcp-fb:97 ccm fir",
    "a=rtpmap:99 H264/90000",
    "a=rtcp-fb:99 rrtr",
    "a=rtcp-fb:99 goog-remb",
    "a=rtcp-fb:99 transport-cc",
    "a=rtcp-fb:99 nack",
    "a=rtcp-fb:99 nack pli",
    "a=fmtp:99 level-asymmetry-allowed=1;packetization-mode=1;profile-level-id=42e01f",
    "a=rtcp-fb:99 ccm fir",
    "a=ssrc:{video_ssrc} cname:u21w8kF2",
    "a=rtpmap:125 flexfec-03/90000",
    "a=fmtp:125 repair-window=10000000",
    "a=ssrc-group:FEC-FR {video_ssrc} {fec_ssrc}",
    "a=ssrc:{fec_ssrc} cname:u21w8kF2",
)


def _slot(value: str, size: int) -> bytes:
    """``value`` as a NUL-terminated field of ``size`` bytes (it must leave room)."""
    raw = value.encode("ascii")
    if len(raw) >= size:
        raise SignalingError(f"RTC sdp_info field {value!r} does not fit {size} bytes")
    return raw.ljust(size, b"\0")


@dataclass(frozen=True, slots=True, kw_only=True)
class SdpInfo:
    """What a private media CALL tells the device about the client side."""

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
            ice_ufrag="".join(rand.choice(_ICE_ALPHABET) for _ in range(ICE_UFRAG_LEN)),
            ice_pwd="".join(rand.choice(_ICE_ALPHABET) for _ in range(ICE_PWD_LEN)),
            content_key=content_key,
            content_iv=content_iv,
            data_channel=data_channel,
        )

    def encode(self) -> bytes:
        """The packed 86-byte structure a private CALL carries (base64).

        Layout: 2 reserved, a data-channel flag, two bytes set to 1, a device-config
        byte (left 0), ICE ufrag[8], ICE pwd[24], content key[20], content IV[20],
        then the audio and video SSRCs as little-endian u32.

        The layout is verified on hardware: a HomeBase 3 (T8030P) answers a kind-6
        CALL with its own ``sdp_info`` of this exact shape (content key 16 bytes,
        content IV 12 bytes).
        """
        buf = bytearray(SDP_INFO_LEN)
        buf[0x02] = 1 if self.data_channel else 0
        buf[0x03] = 1
        buf[0x04] = 1
        buf[0x06:0x0E] = _slot(self.ice_ufrag, 8)
        buf[0x0E:0x26] = _slot(self.ice_pwd, 24)
        buf[0x26:0x3A] = _slot(self.content_key, 20)
        buf[0x3A:0x4E] = _slot(self.content_iv, 20)
        struct.pack_into(
            "<II", buf, 0x4E, self.audio_ssrc & 0xFFFFFFFF, self.video_ssrc & 0xFFFFFFFF
        )
        return bytes(buf)

    @classmethod
    def decode(cls, raw: bytes) -> SdpInfo:
        """Parse the device's answer ``sdp_info`` (the live CALL 200 carries this
        same 86-byte structure, not an SDP text offer; verified on a HomeBase 3).

        The device's ICE credentials, content key and IV, and both SSRCs come back;
        the data-channel flag is read from byte 2. Raises
        :class:`~.exceptions.SignalingError` on a buffer that is too short.
        """
        if len(raw) < SDP_INFO_LEN:
            raise SignalingError(f"RTC sdp_info is {len(raw)} bytes, need {SDP_INFO_LEN}")

        def field(start: int, size: int) -> str:
            return raw[start : start + size].split(b"\0", 1)[0].decode("ascii", "replace")

        audio_ssrc, video_ssrc = struct.unpack_from("<II", raw, 0x4E)
        return cls(
            audio_ssrc=audio_ssrc,
            video_ssrc=video_ssrc,
            ice_ufrag=field(0x06, 8),
            ice_pwd=field(0x0E, 24),
            content_key=field(0x26, 20),
            content_iv=field(0x3A, 20),
            data_channel=bool(raw[0x02]),
        )

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
    """The full SDP built from a device's compact offer: the device's ICE
    credentials and SSRCs fill :data:`_SDP_TEMPLATE`, everything else (the SDES key,
    codecs, FEC) is constant. CRLF-terminated.

    Raises :class:`~.exceptions.SignalingError` when the offer carries no ICE
    credentials (such a remote SDP is refused).
    """
    if offer.ice_ufrag is None or offer.ice_pwd is None:
        raise SignalingError("RTC compact offer has no ICE credentials")
    fec = offer.fields.get("sgc")
    fec_ssrc = (
        fec if isinstance(fec, int) else (int(fec) if isinstance(fec, str) and fec.isdigit() else 0)
    )
    fields = {
        "ufrag": offer.ice_ufrag,
        "pwd": offer.ice_pwd,
        "audio_ssrc": offer.audio_ssrc or 0,
        "video_ssrc": offer.video_ssrc or 0,
        "fec_ssrc": fec_ssrc,
    }
    return "".join(f"{line.format(**fields)}\r\n" for line in _SDP_TEMPLATE)


def answer_attributes(sdp: str) -> str:
    """The lines of an SDP answer sent back: the ICE credentials and the SSRC
    attributes, CRLF-separated."""
    lines = [line for line in sdp.splitlines() if line.startswith(ANSWER_PREFIXES)]
    return "".join(f"{line}\r\n" for line in lines)
