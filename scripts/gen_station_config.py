"""Generate ``devices/_station_config_data.py``: which station configuration features each station model offers.

For every station model of :data:`STATIONS` whose thing description is cached, the
vendor handler runs offline (``scripts/thing_models.py`` harness, Node) for the
properties and actions behind each
:class:`~eufy_home_security.devices.station_config_support.StationFeature`; the
thing description's capability gates (``arming_support_*``), the app's HomeBase
capability table (``hb_capability_config.json``) and a Remote Config snapshot add the
app's own conditions. Per model and feature the file records a grade (``declared`` or
``unknown``) with its source, the mode-table storage and param per mode (the param the
handler updates after an ``arming_config`` write for each mode), the cross-camera
tracking times, firmware gates and the restart request. Hardware grades are not
generated (``station_config_support._VERIFIED``). Runs on a maintainer host only;
nothing at runtime executes vendor code.

    gen_station_config.py [--data DIR] [--cache DIR] [--remote-config FILE] [--out FILE] [--check]

``--data`` holds ``hb_capability_config.json`` (the app's asset); ``--cache`` the thing
descriptions and handlers (``<PN>/td.json``, ``<PN>/<PN>Handle.mix.js``);
``--remote-config`` a Remote Config fetch (``{"template_version", "entries"}``).
"""

from __future__ import annotations

import argparse
import importlib.util
import json
import re
import subprocess
import sys
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from pathlib import Path
from types import ModuleType
from typing import Any

from eufy_home_security.devices.station_config_support import ModeTableStorage, StationFeature
from eufy_home_security.models import GuardMode
from eufy_home_security.p2p.station_config_codecs import STORED_MODE_TABLE_PARAMS

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATA = ROOT / ".work" / "notes" / "hb-config" / "data"
DEFAULT_CACHE = ROOT / ".work" / "cache" / "things_all"
DEFAULT_REMOTE_CONFIG = ROOT / ".work" / "tools" / "data" / "firebase_rc_EE.json"
DEFAULT_OUT = ROOT / "src" / "eufy_home_security" / "devices" / "_station_config_data.py"
CAPABILITY_FILE = "hb_capability_config.json"
APP_VERSION = "6.1.10"  # the app build whose handlers the cache holds

#: The station models the eufy app names (T6010, a station of another product line,
#: is not one).
STATIONS = (
    "T7000",
    "T8001",
    "T8002",
    "T8010",
    "T8020",
    "T8021",
    "T8023",
    "T8024",
    "T8025",
    "T8026",
    "T8028",
    "T8030",
    "T8040",
    "T8N00",
    "T9000",
)

#: The modes a 1255 table exists for, in the order the file lists them.
TABLE_MODES = (
    GuardMode.AWAY,
    GuardMode.HOME,
    GuardMode.CUSTOM_1,
    GuardMode.CUSTOM_2,
    GuardMode.CUSTOM_3,
    GuardMode.DISARMED,
)
PRO_ALARM_PARAMS = range(61300, 61310)


@dataclass(frozen=True, slots=True)
class Request:
    """One handler call: a ``setProperty`` (``set``) or an action, and the wire id the
    library sends for it (``cmd``, or the sub-command of a 1350 envelope)."""

    kind: str
    identifier: str
    payload: Any
    wire: int


#: Per feature, the handler calls behind it; the feature is declared when the thing
#: description declares every one and the handler builds each as ``wire``.
REQUESTS: Mapping[StationFeature, tuple[Request, ...]] = {
    StationFeature.GUARD_MODE: (Request("set", "arming_selected_mode", {"mode_type": 1}, 1224),),
    StationFeature.CUSTOM_MODES: (
        Request("set", "arming_cust_mode_config", {"operate_type": 102, "modes": []}, 1256),
    ),
    StationFeature.SCHEDULE: (Request("set", "arming_schedule_config", {"schedules": []}, 1254),),
    StationFeature.MODE_TABLES: (
        Request("action", "arming_config", {"mode_id": 1, "devices": []}, 1255),
    ),
    StationFeature.MODE_DELAYS: (
        Request("action", "arming_config", {"mode_id": 1, "devices": []}, 1255),
    ),
    StationFeature.CROSS_CAMERA: (
        Request("set", "device_cross_cam_tracking_swtich", True, 1065),
        Request("set", "device_cross_cam_assistance_switch", True, 1069),
        Request("set", "device_cross_cam_interval", 1, 1070),
        Request("set", "device_cross_cam_list", ["T8160P0000000001"], 1072),
    ),
    StationFeature.CROSS_CAMERA_GROUPS: (),
    StationFeature.ARMING_GROUPS: (),
    StationFeature.RESTART: (Request("action", "restart_device", {}, 1034),),
    StationFeature.SOUND_ALARM: (Request("set", "set_alarm_type", 1, 1201),),
    StationFeature.WORKING_MODE: (Request("set", "working_mode_value", 1, 1296),),
}
if set(REQUESTS) != set(StationFeature):
    raise SystemExit("REQUESTS must cover StationFeature")

#: A feature's thing-description gate: the app hides the feature when it is false.
GATES: Mapping[StationFeature, str] = {
    StationFeature.CUSTOM_MODES: "arming_support_custom_mode",
    StationFeature.MODE_DELAYS: "arming_support_arm_delay",
}
#: Group Control shows for a house with a station whose TD sets this (unset = false) ...
ARMING_GATE = "arming_support_arming"
#: ... unless the house has a station the capability table gives professional guard.
PROFESSIONAL_SCENARIO = "guard_professional"
#: The tracking-group property: declared by the thing description; the app's own
#: cross-camera screen writes 1073, the handler builds nothing for it.
GROUP_PROPERTY = "device_cross_cam_group"
INTERVAL_PROPERTY = "device_cross_cam_interval"
#: Remote Config keys that gate a feature on one model by station firmware.
REMOTE_CONFIG_GATES: Mapping[tuple[str, StationFeature], str] = {
    ("T8030", StationFeature.CROSS_CAMERA): "hb3_support_cross_tracking",
    ("T8030", StationFeature.CROSS_CAMERA_GROUPS): "hb3_support_cross_tracking",
}


def _harness() -> ModuleType:
    spec = importlib.util.spec_from_file_location(
        "thing_models", ROOT / "scripts" / "thing_models.py"
    )
    if spec is None or spec.loader is None:
        raise ImportError("scripts/thing_models.py")
    module = importlib.util.module_from_spec(spec)
    sys.modules["thing_models"] = module
    spec.loader.exec_module(module)
    return module


def _device(code: str) -> dict[str, Any]:
    """The station itself as the handler's device (synthetic serial)."""
    serial = f"{code}P0000000001"
    return {
        "device_sn": serial,
        "parent_sn": serial,
        "station_sn": serial,
        "device_pn": code,
        "device_channel": 0,
        "channel": 0,
        "main_sw_version": "9.9.9.9",
        "params": [],
    }


def _run(tm: ModuleType, handler: Path, requests: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """The handler's recipe per request, in one Node run; an empty recipe for a request
    the handler does not build."""
    proc = subprocess.run(
        [tm.node_executable(), str(tm.DRIVER)],
        input=json.dumps({"handler": str(handler), "requests": requests}),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise tm.HarnessError(f"node failed on {handler.name}: {proc.stderr.strip()}")
    out: list[dict[str, Any]] = []
    for request, reply in zip(requests, json.loads(proc.stdout), strict=True):
        try:
            out.append(tm.recipe_from_reply(request["identifier"], reply))
        except tm.HarnessError:
            out.append({})
    return out


def wire_of(recipe: Mapping[str, Any]) -> int | None:
    """The id the recipe sends: the sub-command of a 1350 envelope, else ``cmd``."""
    cmd = recipe.get("cmd")
    return recipe.get("subCmd") if cmd == 1350 else cmd


#: A capability flag the model's handler reports (``name:!0`` true, ``name:!1`` false).
_HANDLER_FLAG = re.compile(r"\b(arming_support_[a-z_]+):(!0|!1|true|false)\b")


def _handler_flags(handler: Path) -> dict[str, bool]:
    """The capability flags the model's handler reports to the app; a flag set to
    both values is left out."""
    seen: dict[str, set[bool]] = {}
    for name, value in _HANDLER_FLAG.findall(handler.read_text(encoding="utf-8")):
        seen.setdefault(name, set()).add(value in ("!0", "true"))
    return {name: values.pop() for name, values in seen.items() if len(values) == 1}


def _gate(
    td_properties: Mapping[str, Any], identifier: str, handler_flags: Mapping[str, bool]
) -> bool | None:
    """A capability flag as the app sees it: the handler's value, else the thing
    description's default; None when neither sets it."""
    if identifier in handler_flags:
        return handler_flags[identifier]
    prop = td_properties.get(identifier)
    if prop is None:
        return None
    value = (prop.get("data_type") or {}).get("specs", {}).get("defaultValue")
    if value is None:
        return None
    return str(value).strip().lower() == "true"


def _scenario_stations(capabilities: Mapping[str, Any], scenario: str) -> frozenset[str]:
    for module in capabilities["modules"].values():
        found = module["scenarios"].get(scenario)
        if found is not None:
            return frozenset(found.get("supportedStations", ())) - {"*"}
    raise SystemExit(f"{CAPABILITY_FILE}: no scenario {scenario}")


@dataclass(frozen=True, slots=True)
class Model:
    """What the generator found for one station model."""

    features: dict[str, tuple[str, str]]
    storage: str | None
    mode_params: dict[int, int]
    intervals: tuple[int, ...]
    restart: tuple[int, int | None] | None


def _unknown_model(code: str) -> Model:
    reason = f"no thing description or handler of the {code} is on record"
    return Model({f.value: ("unknown", reason) for f in StationFeature}, None, {}, (), None)


def _storage(params: Mapping[int, int]) -> str | None:
    if len(set(params.values())) != len(TABLE_MODES):
        return None
    by_mode = {GuardMode(m): p for m, p in params.items()}
    if by_mode == dict(STORED_MODE_TABLE_PARAMS):
        return ModeTableStorage.HB3_TABLES.value
    if all(p in PRO_ALARM_PARAMS for p in params.values()):
        return ModeTableStorage.PRO_ALARM.value
    return ModeTableStorage.ACTION_PARAMS.value


def _model(
    tm: ModuleType,
    cache: Path,
    code: str,
    professional: frozenset[str],
) -> Model:
    td = tm.load_td(cache, code)
    td = td["things_list"][0] if "things_list" in td else td
    properties = {p["identifier"]: p for p in td.get("properties", [])}
    actions = {a["identifier"] for a in td.get("actions", [])}
    device = _device(code)

    def declared(request: Request) -> bool:
        if request.kind == "set":
            return "W" in properties.get(request.identifier, {}).get("access_mode", "")
        return request.identifier in actions

    calls: list[tuple[str, Request | GuardMode]] = []
    jobs: list[dict[str, Any]] = []
    for feature, requests in REQUESTS.items():
        for request in requests:
            if declared(request):
                calls.append((feature.value, request))
                jobs.append(
                    {
                        "kind": request.kind,
                        "identifier": request.identifier,
                        "payload": request.payload,
                        "device": device,
                    }
                )
    if "arming_config" in actions:
        for mode in TABLE_MODES:
            calls.append(("mode", mode))
            jobs.append(
                {
                    "kind": "action",
                    "identifier": "arming_config",
                    "payload": {"mode_id": int(mode), "devices": []},
                    "device": device,
                }
            )
    recipes = _run(tm, tm.handler_file(cache, code), jobs) if jobs else []
    flags = _handler_flags(tm.handler_file(cache, code))

    built: dict[tuple[str, str], Mapping[str, Any]] = {}
    mode_params: dict[int, int] = {}
    for (feature_name, what), recipe in zip(calls, recipes, strict=True):
        if isinstance(what, GuardMode):
            update = (recipe.get("update") or {}).get("cmd")
            if wire_of(recipe) == 1255 and isinstance(update, int):
                mode_params[int(what)] = update
        else:
            built[feature_name, what.identifier] = recipe

    features: dict[str, tuple[str, str]] = {}
    restart: tuple[int, int | None] | None = None
    for feature in REQUESTS:
        features[feature.value] = _grade(
            code,
            feature,
            declared=declared,
            built=built,
            properties=properties,
            flags=flags,
            professional=professional,
        )
        if feature is StationFeature.RESTART and features[feature.value][0] == "declared":
            recipe = built[feature.value, "restart_device"]
            restart = (recipe["cmd"], recipe.get("subCmd"))
    intervals: tuple[int, ...] = ()
    if features[StationFeature.CROSS_CAMERA.value][0] == "declared":
        specs = properties[INTERVAL_PROPERTY]["data_type"]["specs"]
        intervals = tuple(int(e["associatedValue"]) for e in specs["eunmList"])
    return Model(features, _storage(mode_params), mode_params, intervals, restart)


def _grade(
    code: str,
    feature: StationFeature,
    *,
    declared: Callable[[Request], bool],
    built: Mapping[tuple[str, str], Mapping[str, Any]],
    properties: Mapping[str, Any],
    flags: Mapping[str, bool],
    professional: frozenset[str],
) -> tuple[str, str]:
    """``(grade, source)`` of one feature on one model."""
    app = f"eufy app {APP_VERSION}"
    if feature is StationFeature.ARMING_GROUPS:
        if code in professional:
            return (
                "unknown",
                f"a house with a {code} gets the app's professional arming, not groups",
            )
        if _gate(properties, ARMING_GATE, flags) is not True:
            return (
                "unknown",
                f"the eufy app does not set {ARMING_GATE} for a {code}: it offers "
                "groups only for a house with a station that does",
            )
        return (
            "declared",
            f"the eufy app sets {ARMING_GATE} for a {code} ({app}); a house-level "
            "cloud feature that sets each member's guard mode",
        )
    if feature is StationFeature.CROSS_CAMERA_GROUPS:
        if "W" not in properties.get(GROUP_PROPERTY, {}).get("access_mode", ""):
            return ("unknown", f"the {code} thing description declares no {GROUP_PROPERTY}")
        cross = _grade(
            code,
            StationFeature.CROSS_CAMERA,
            declared=declared,
            built=built,
            properties=properties,
            flags=flags,
            professional=professional,
        )
        if cross[0] != "declared":
            return cross
        return (
            "declared",
            f"the {code} thing description declares {GROUP_PROPERTY} ({app}); the app "
            "writes the groups as 1073",
        )
    requests = REQUESTS[feature]
    missing = [r.identifier for r in requests if not declared(r)]
    if missing:
        return ("unknown", f"the {code} thing description declares no {', '.join(missing)}")
    for request in requests:
        recipe = built[feature.value, request.identifier]
        if recipe.get("webRtc"):
            return (
                "unknown",
                f"the eufy app sends {request.identifier} to a {code} over WebRTC, "
                "which this library does not implement",
            )
        wire = wire_of(recipe)
        if wire != request.wire:
            return (
                "unknown",
                f"the {code} handler builds {request.identifier} as {wire}, not {request.wire}",
            )
    gate = GATES.get(feature)
    if gate is not None and _gate(properties, gate, flags) is False:
        return ("unknown", f"the eufy app sets {gate} false for a {code}")
    names = ", ".join(dict.fromkeys(r.identifier for r in requests))
    wires = ", ".join(str(w) for w in dict.fromkeys(r.wire for r in requests))
    return ("declared", f"the {code} handler builds {names} as {wires} ({app})")


def generate(data: Path, cache: Path, remote_config: Path) -> dict[str, Any]:
    tm = _harness()
    capabilities = json.loads((data / CAPABILITY_FILE).read_text(encoding="utf-8"))
    professional = _scenario_stations(capabilities, PROFESSIONAL_SCENARIO)
    remote = json.loads(remote_config.read_text(encoding="utf-8"))
    entries: Mapping[str, Any] = remote["entries"]
    cached = set(tm.cached_product_codes(cache))
    models = {
        code: _model(tm, cache, code, professional) if code in cached else _unknown_model(code)
        for code in sorted(STATIONS)
    }
    min_firmware: dict[str, dict[str, str]] = {}
    for (code, feature), key in sorted(REMOTE_CONFIG_GATES.items()):
        value = entries.get(key)
        if value is not None and models[code].features[feature.value][0] == "declared":
            min_firmware.setdefault(code, {})[feature.value] = str(value)
    return {
        "template": int(remote["template_version"]),
        "models": models,
        "min_firmware": min_firmware,
    }


def render(result: Mapping[str, Any]) -> str:
    """The module text: per model in sorted order, features in enum order."""
    models: Mapping[str, Model] = result["models"]
    lines = [
        '"""Generated by scripts/gen_station_config.py from the eufy app\'s thing',
        "descriptions, product handlers, HomeBase capability table and a Remote Config",
        "snapshot; do not edit. Per station product code: each feature's grade and source,",
        "the mode-table storage and param per mode, the cross-camera tracking times",
        '(seconds), firmware gates and the restart request ``(cmd, sub-command)``."""',
        "",
        "from typing import Final",
        "",
        f"APP_VERSION: Final = {json.dumps(APP_VERSION)}",
        f"REMOTE_CONFIG_TEMPLATE: Final = {result['template']}",
        "",
        "FEATURES: Final[dict[str, dict[str, tuple[str, str]]]] = {",
    ]
    for code, model in models.items():
        lines.append(f"    {json.dumps(code)}: {{")
        for feature in StationFeature:
            grade, source = model.features[feature.value]
            lines.append(f"        {json.dumps(feature.value)}: (")
            lines.append(f"            {json.dumps(grade)},")
            lines.append(f"            {json.dumps(source)},")
            lines.append("        ),")
        lines.append("    },")
    lines += ["}", "", "MODE_TABLE_STORAGE: Final[dict[str, str]] = {"]
    lines += [
        f"    {json.dumps(code)}: {json.dumps(m.storage)},"
        for code, m in models.items()
        if m.storage is not None
    ]
    lines += ["}", "", "MODE_TABLE_PARAMS: Final[dict[str, dict[int, int]]] = {"]
    for code, m in models.items():
        if m.mode_params:
            pairs = ", ".join(f"{mode}: {param}" for mode, param in m.mode_params.items())
            lines.append(f"    {json.dumps(code)}: {{{pairs}}},")
    lines += ["}", "", "CROSS_CAMERA_INTERVALS: Final[dict[str, tuple[int, ...]]] = {"]
    for code, m in models.items():
        if m.intervals:
            items = ", ".join(map(str, m.intervals))
            lines.append(
                f"    {json.dumps(code)}: ({items}{',' if len(m.intervals) == 1 else ''}),"
            )
    lines += ["}", "", "MIN_FIRMWARE: Final[dict[str, dict[str, str]]] = {"]
    for code, gates in result["min_firmware"].items():
        pairs = ", ".join(f"{json.dumps(f)}: {json.dumps(v)}" for f, v in gates.items())
        lines.append(f"    {json.dumps(code)}: {{{pairs}}},")
    lines += ["}", "", "RESTART_COMMAND: Final[dict[str, tuple[int, int | None]]] = {"]
    for code, m in models.items():
        if m.restart is not None:
            cmd, sub = m.restart
            lines.append(f"    {json.dumps(code)}: ({cmd}, {'None' if sub is None else sub}),")
    lines.append("}")
    return "\n".join(lines) + "\n"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Generate devices/_station_config_data.py.")
    parser.add_argument("--data", type=Path, default=DEFAULT_DATA)
    parser.add_argument("--cache", type=Path, default=DEFAULT_CACHE)
    parser.add_argument("--remote-config", type=Path, default=DEFAULT_REMOTE_CONFIG)
    parser.add_argument("--out", type=Path, default=DEFAULT_OUT)
    parser.add_argument("--check", action="store_true", help="compare with --out, write nothing")
    args = parser.parse_args(argv)
    text = render(generate(args.data, args.cache, args.remote_config))
    if args.check:
        same = args.out.exists() and args.out.read_text(encoding="utf-8") == text
        print("up to date" if same else f"{args.out} differs")
        return 0 if same else 1
    args.out.write_text(text, encoding="utf-8")
    print(f"wrote {args.out}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
