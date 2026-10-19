"""eufy's RTC path: the signaling and media sessions the eufy app uses for stations
it reaches over WebRTC instead of P2P.

The signaling layer is complete, including its cryptography
(:class:`.crypto.RtcSignalingCrypto`). Not wired into
:class:`~.station.Station`: the media plane (:mod:`.media`,
:class:`.session.MediaPlane`) is an interface without an implementation, and the
private-call ``sdp_info`` layout and SDP offer template are not known, so stations
the app reaches only over RTC stay skipped.
"""
