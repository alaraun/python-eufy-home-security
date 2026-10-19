"""The cryptographic operations eufy's RTC signaling needs, as an interface.

The signaling client (:mod:`.signaling`) calls these at fixed points of the flow;
the library ships no implementation yet. :class:`UnavailableCrypto` refuses every
operation with :class:`~.exceptions.UnsupportedError`, so a client built without a
real implementation fails at its first login rather than sending a wrong packet.

Where each operation runs:

- LOGIN challenge (401): :meth:`RtcCrypto.open_challenge` turns the body into the
  server's public key.
- LOGIN key exchange: :meth:`RtcCrypto.new_session_key` makes the session key,
  :meth:`RtcCrypto.seal_session_key` seals it with the server's public key, and
  :meth:`RtcCrypto.seal` seals the station identity ``"<p2p_did>:<p2p_license>"``.
- Every encrypted attachment and message (header flag set): :meth:`RtcCrypto.seal`
  and :meth:`RtcCrypto.open` with the session key, salted with the header's
  packet id.
- A private CALL's ``sdp_info``: :meth:`RtcCrypto.new_media_secret` for the content
  key and IV.
"""

from __future__ import annotations

from typing import Protocol, runtime_checkable

from ..exceptions import UnsupportedError


@runtime_checkable
class RtcCrypto(Protocol):
    """The signaling's cryptographic operations."""

    def open_challenge(self, body: bytes, salt: int) -> str:
        """The server's public key (text) from a LOGIN 401 body."""
        ...

    def new_session_key(self) -> str:
        """A fresh session key for one login."""
        ...

    def seal_session_key(self, public_key: str, session_key: str) -> bytes:
        """``session_key`` sealed for the server (the key exchange's first blob)."""
        ...

    def seal(self, session_key: str, salt: int, data: bytes) -> bytes:
        """``data`` encrypted with ``session_key``, salted with a packet id."""
        ...

    def open(self, session_key: str, salt: int, data: bytes) -> bytes:
        """The inverse of :meth:`seal`."""
        ...

    def new_media_secret(self) -> str:
        """A random secret for a private call's content key or IV."""
        ...


class UnavailableCrypto:
    """An :class:`RtcCrypto` that refuses every operation."""

    REASON = "RTC signaling cryptography is not implemented in this library version"

    def _refuse(self) -> UnsupportedError:
        return UnsupportedError(self.REASON)

    def open_challenge(self, body: bytes, salt: int) -> str:
        raise self._refuse()

    def new_session_key(self) -> str:
        raise self._refuse()

    def seal_session_key(self, public_key: str, session_key: str) -> bytes:
        raise self._refuse()

    def seal(self, session_key: str, salt: int, data: bytes) -> bytes:
        raise self._refuse()

    def open(self, session_key: str, salt: int, data: bytes) -> bytes:
        raise self._refuse()

    def new_media_secret(self) -> str:
        raise self._refuse()
