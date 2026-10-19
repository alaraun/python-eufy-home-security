"""eufy's RTC path: the signaling and media sessions the eufy app uses for stations
it reaches over WebRTC instead of P2P.

The signaling layer is complete, including its cryptography
(:class:`.crypto.RtcSignalingCrypto`), the private-call ``sdp_info`` structure and
the SDP offer template (:mod:`.sdp`). Not wired into :class:`~.station.Station`: the
media plane (:mod:`.media`, :class:`.session.MediaPlane`) — ICE, SRTP, the in-frame
decryption and the KCP data channel — is an interface without an implementation, so
stations the app reaches only over RTC stay skipped.
"""
