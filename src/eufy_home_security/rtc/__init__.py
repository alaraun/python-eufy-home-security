"""eufy's RTC path: the signaling and media sessions the eufy app uses for stations
it reaches over WebRTC instead of P2P.

Not wired into :class:`~.station.Station`: the cryptography (:mod:`.crypto`) and the
media plane (:mod:`.media`, :class:`.session.MediaPlane`) are interfaces without an
implementation, so stations the app reaches only over RTC stay skipped.
"""
