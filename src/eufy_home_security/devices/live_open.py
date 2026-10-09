"""Which live open the app's handler sends for a product, per connect type (generated data).

``_live_open_data.py`` is written by ``scripts/gen_live_open.py`` from the product
handlers the eufy app runs: for each product and connect type, the library's open whose
recipe equals the handler's, or none. A product the table does not list (no cached
handler, or no ``open_live_stream`` action) has no recorded open. Pure lookups: no I/O.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType
from typing import Final

from ._live_open_data import APP_VERSION, LIVE_OPEN
from .recipes import ConnectType


class LiveOpen(StrEnum):
    """A live open the library sends exactly as a product's handler describes it."""

    STATION = "station"
    """1350/1003 ``DeviceMsgBean`` with the plain payload
    (:func:`~.recipes.open_live_stream_station`); to a HomeBase 3 the library sends the
    app's T8030 fields as well, as the app's live player adds them."""
    SINGLE = "single"
    """1700 with sub-command 1000 and ``extValue`` (:func:`~.recipes.open_live_stream_single`)."""
    SINGLE_NO_EXT = "single_no_ext"
    """1700 with sub-command 1000, without ``extValue``."""


_TABLE: Final[Mapping[str, Mapping[ConnectType, LiveOpen | None]]] = MappingProxyType(
    {
        code: MappingProxyType(
            {
                ConnectType(kind): None if mode is None else LiveOpen(mode)
                for kind, mode in modes.items()
            }
        )
        for code, modes in LIVE_OPEN.items()
    }
)


def app_version() -> str:
    """The eufy app build whose handlers the table was generated from."""
    return APP_VERSION


def has_live_open(product_code: str | None) -> bool:
    """Whether the table lists ``product_code`` (its handler has a live open)."""
    return product_code is not None and product_code.upper() in _TABLE


def live_open(product_code: str | None, connect: ConnectType) -> LiveOpen | None:
    """The open the handler of ``product_code`` sends under ``connect``; None when the
    product is not listed or its handler sends an open the library does not implement
    (see :func:`has_live_open` to tell the two apart)."""
    if product_code is None:
        return None
    return _TABLE.get(product_code.upper(), {}).get(connect)


def library_live_open(product_code: str | None, connect: ConnectType) -> LiveOpen | None:
    """The open the library sends for ``product_code`` under ``connect``: the handler's
    (:func:`live_open`) where the library can send it there. On its own session
    (``SINGLE``) every :class:`LiveOpen`; behind a station only :attr:`LiveOpen.STATION`
    (a 1700 open behind a station needs the route the app takes to the device, which the
    library does not implement). None otherwise."""
    mode = live_open(product_code, connect)
    if connect is ConnectType.SINGLE or mode is LiveOpen.STATION:
        return mode
    return None
