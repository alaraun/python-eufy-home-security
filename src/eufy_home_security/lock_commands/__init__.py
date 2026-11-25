"""Lock command codecs: the frames, keys and payloads of lock and unlock, pure functions.

Three P2P forms carry a lock command to a lock through its station (declared, eufy app;
not tested on hardware):

- :mod:`.cm2`: the 1940 through-data form (an encrypted cm2 frame, key from the account's
  user id and a time value, or an HKDF variant), for locks behind a station;
- :mod:`.anker`: the 1961 JSON form (ECIES-wrapped AES key or plain) and the 1930 cm
  frame (ECIES or ECDH key);
- :mod:`.frames`: the frame layers both use.

Which form a lock takes is :func:`eufy_home_security.devices.lock_routes.lock_route`.
Nothing here sends anything. See docs/protocol/locks.md.
"""

from __future__ import annotations

from .actions import LockAction, LockReply, LockResult

__all__ = ["LockAction", "LockReply", "LockResult"]
