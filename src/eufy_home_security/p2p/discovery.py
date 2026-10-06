"""LAN discovery: list every station that answers a ``LAN_SEARCH``.

A station answers a ``LAN_SEARCH`` sent to UDP 32108 with a ``PUNCH_PKT`` that
carries its DID, from a random high port (see :mod:`.transport`). Discovery here
only listens: it never punches back, so it opens no session and leaves a
session another client holds untouched.

The station ignores the first search after a session closed, so the search is
repeated until the timeout, and replies are de-duplicated by address and DID.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from .._logging import Address, HexDump, wire_logger
from ..exceptions import CommunicationError, ProtocolError
from . import pppp
from .did import Did
from .pppp import (
    BROADCAST,
    DISCOVERY_PORT,
    MsgType,
    decode_packet,
    encode_packet,
)
from .transport import DISCOVERY_RETRY_INTERVAL

_LOGGER = logging.getLogger(__name__)
_WIRE = wire_logger("p2p")


@dataclass(frozen=True, slots=True)
class DiscoveredStation:
    """A station that answered LAN discovery."""

    ip: str
    port: int
    """The port the answer came from (the station's session port, not 32108)."""
    did: Did


class _DiscoveryProtocol(asyncio.DatagramProtocol):
    def __init__(self) -> None:
        self.found: dict[tuple[str, str], DiscoveredStation] = {}
        self.send_error: OSError | None = None

    def error_received(self, exc: Exception) -> None:
        # An asyncio datagram transport reports a failed sendto here instead of
        # raising it; keep the latest so an empty result can say why.
        if isinstance(exc, OSError):
            self.send_error = exc
        _LOGGER.debug("discovery: socket error: %s", exc)

    def datagram_received(self, data: bytes, addr: tuple[str | int, int]) -> None:
        host, port = str(addr[0]), int(addr[1])
        if _WIRE.isEnabledFor(logging.DEBUG):
            _WIRE.debug("discovery rx %s:%d %s", Address(host), port, HexDump(data))
        try:
            msg, payload = decode_packet(data)
            if msg != MsgType.PUNCH_PKT:
                return
            did = Did.from_struct(payload)
        except ProtocolError:
            _LOGGER.debug("discovery: undecodable reply from %s:%d", Address(host), port)
            return
        key = (host, str(did))
        if key not in self.found:
            _LOGGER.debug("discovery: %s answered from %s:%d", did.prefix, Address(host), port)
            self.found[key] = DiscoveredStation(ip=host, port=port, did=did)


async def discover_stations(
    *,
    timeout: float | None = None,
    port: int = DISCOVERY_PORT,
    target: str = BROADCAST,
    local_port: int = 0,
) -> list[DiscoveredStation]:
    """Search the LAN for ``timeout`` seconds (None: :data:`~.pppp.LAN_DISCOVERY_TIMEOUT`,
    read at call time) and return every station that answered.

    ``target`` is the broadcast address, or one station's address to probe it
    alone. ``local_port`` pins the local UDP port for a firewall (0 = ephemeral).
    Raises :class:`CommunicationError` when the socket cannot be opened, or when
    no station answered and sending the search failed (e.g. no route to
    ``target``).
    """
    if timeout is None:
        timeout = pppp.LAN_DISCOVERY_TIMEOUT
    loop = asyncio.get_running_loop()
    protocol = _DiscoveryProtocol()
    try:
        transport, _ = await loop.create_datagram_endpoint(
            lambda: protocol,
            local_addr=("0.0.0.0", local_port),  # noqa: S104 - replies arrive on any interface
            allow_broadcast=True,
        )
    except OSError as err:
        raise CommunicationError(f"cannot open a UDP socket for discovery: {err}") from err
    search = encode_packet(MsgType.LAN_SEARCH)
    deadline = loop.time() + timeout
    attempt = 0
    try:
        while (remaining := deadline - loop.time()) > 0:
            attempt += 1
            _LOGGER.debug("discovery: LAN_SEARCH #%d to %s:%d", attempt, Address(target), port)
            if _WIRE.isEnabledFor(logging.DEBUG):
                _WIRE.debug("discovery tx %s:%d %s", Address(target), port, HexDump(search))
            transport.sendto(search, (target, port))
            await asyncio.sleep(min(DISCOVERY_RETRY_INTERVAL, remaining))
    finally:
        transport.close()
    _LOGGER.debug(
        "discovery: %d station(s) answered %s within %.1fs",
        len(protocol.found),
        Address(target),
        timeout,
    )
    if not protocol.found and protocol.send_error is not None:
        send_error = protocol.send_error
        raise CommunicationError(f"cannot send discovery to {target}: {send_error}") from send_error
    return list(protocol.found.values())
