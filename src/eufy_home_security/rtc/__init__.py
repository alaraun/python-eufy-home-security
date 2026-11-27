"""eufy's WebRTC path: the protocol layers, the signaling client and the session for devices
the eufy app reaches over WebRTC instead of P2P.

Pure codecs and small state machines: the signaling wire format (:mod:`.codec`), its
cryptography (:mod:`.crypto`), the station inputs (:mod:`.config`), the private call's
``sdp_info`` (:mod:`.sdp`), the signaling message builders (:mod:`.signaling`), the
command encryption (:mod:`.command`), the RTCP APP command channel (:mod:`.rtcp_channel`),
the data channel's framing over KCP (:mod:`.data_channel`) and the RTP depacketizers
(:mod:`.media`). On the event loop: the signaling client (:mod:`.client`), ICE
(:mod:`.ice`, the ``rtc`` extra), the session that brings a station's data channel up
(:mod:`.session`) and the read-only report of one station's link (:mod:`.diagnostics`).

Internal: nothing here is part of the public API yet, and no station uses it. See
``docs/protocol/rtc-signaling.md``.
"""
