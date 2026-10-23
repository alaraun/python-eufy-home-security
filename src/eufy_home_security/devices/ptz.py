"""Which pan/tilt/zoom recipe the app's handler sends for a product, per connect type (generated data).

``_ptz_data.py`` is written by ``scripts/gen_ptz.py`` from the product handlers the eufy
app runs. A product is listed when its thing description declares at least one action of
:data:`PTZ_IDENTIFIERS`; per declared action and connect type the table names the
:class:`PtzForm` whose library recipe equals the handler's, or none (the handler sends
something the library does not, a WebRTC route among them). The app sends an action only
when the device's thing description declares it, so an action the product does not
declare is never sent. Pure lookups: no I/O.
"""

from __future__ import annotations

from collections.abc import Mapping
from enum import StrEnum
from types import MappingProxyType
from typing import Final

from ._ptz_data import APP_VERSION, PTZ
from .recipes import ConnectType, PtzAction


class PtzForm(StrEnum):
    """A pan/tilt/zoom recipe the library sends exactly as a product's handler does."""

    STANDARD = "standard"
    """The T8170 handler's recipe: the :mod:`.recipes` builders' defaults."""
    PLAIN = "plain"
    """Without the T8170's extra fields: a pan/tilt step (6030) of ``cmd_type`` and
    ``rotate_type`` only, a preset query (6034) without ``value``."""


PTZ_IDENTIFIERS: Final = (
    "ptz_action_control",
    "query_preset_positions",
    "set_ptz_cruise_preview",
    PtzAction.SLOT_PICTURE.value,
    PtzAction.STORE.value,
    PtzAction.DELETE.value,
    PtzAction.SET_DEFAULT.value,
    "set_picture_zoom",
)
"""The thing-model actions behind the library's pan/tilt, preset and zoom calls."""

_TABLE: Final[Mapping[str, Mapping[str, Mapping[ConnectType, PtzForm | None]]]] = MappingProxyType(
    {
        code: MappingProxyType(
            {
                identifier: MappingProxyType(
                    {
                        ConnectType(kind): None if form is None else PtzForm(form)
                        for kind, form in forms.items()
                    }
                )
                for identifier, forms in actions.items()
            }
        )
        for code, actions in PTZ.items()
    }
)


def app_version() -> str:
    """The eufy app build whose handlers the table was generated from."""
    return APP_VERSION


def has_ptz_recipes(product_code: str | None) -> bool:
    """Whether the table lists ``product_code`` (its thing description declares a
    pan/tilt/zoom action)."""
    return product_code is not None and product_code.upper() in _TABLE


def ptz_actions(product_code: str | None) -> frozenset[str]:
    """The actions of :data:`PTZ_IDENTIFIERS` the product's thing description declares."""
    if product_code is None:
        return frozenset()
    return frozenset(_TABLE.get(product_code.upper(), {}))


def ptz_form(product_code: str | None, identifier: str, connect: ConnectType) -> PtzForm | None:
    """The form the library sends ``identifier`` in to ``product_code`` under ``connect``:
    the one whose recipe equals the handler's. None when the product is not listed, does
    not declare the action, or its handler sends a recipe the library does not."""
    if product_code is None:
        return None
    return _TABLE.get(product_code.upper(), {}).get(identifier, {}).get(connect)
