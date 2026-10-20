"""eufy's RTC path: the signaling and media sessions for stations reached over
WebRTC instead of P2P.

The signaling client and its cryptography (:mod:`.signaling`,
:class:`.crypto.RtcSignalingCrypto`), the private-call ``sdp_info`` structure and the
SDP offer template (:mod:`.sdp`), and the media plane (:mod:`.media`, on the ``rtc``
extra :mod:`.media_plane`). Not wired into :class:`~.station.Station`, so stations
reached only over RTC stay skipped.
"""
