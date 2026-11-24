"""A synthetic routing input for the settings generator's tests: built from the library's
own frame-form tables and value fields, so it carries no app data and agrees with the
library (scripts/gen_models_routing.py ``drift``)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from eufy_home_security.p2p import messages

FORMS = {
    "ecb_channel_value": messages.ECB_CHANNEL_VALUE_CMDS,
    "ecb_station": messages.ECB_STATION_CMDS,
    "ecb_value": messages.ECB_VALUE_CMDS,
    "channel_value": messages.CHANNEL_VALUE_CMDS,
    "json_text": messages.JSON_TEXT_CMDS,
    "string_int": messages.STRING_CMDS,
}


def library_routing() -> dict[str, Any]:
    """A routing input with the library's forms, a request case per value field, the
    1350/1700 wrappers and no native screens."""
    forms: dict[str, dict[str, Any]] = {n: {"cmds": sorted(c)} for n, c in FORMS.items()}
    forms["json_text"]["caller_channel_cmds"] = sorted(messages.JSON_TEXT_CALLER_CHANNEL_CMDS)
    forms["wrap_1700"] = {"cmds": [1700]}
    cases: dict[str, dict[str, Any]] = {
        str(cmd): {"msgType": 10, "reader": "flag" if f.flag else "int", "field": f.name}
        for cmd, f in messages.ECB_VALUE_FIELDS.items()
    }
    cases |= {
        "1350": {"msgType": 6, "reader": "payload"},
        "1700": {"msgType": 10, "reader": "model"},
    }
    return {
        "native": {"forms": forms},
        "executor": {"cases": cases},
        "screens": {"senders": {}, "forms": {}},
    }


def write_routing(path: Path) -> Path:
    """:func:`library_routing` written to ``path``."""
    path.write_text(json.dumps(library_routing()), encoding="utf-8")
    return path
