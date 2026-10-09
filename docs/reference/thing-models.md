# Thing models and wire recipes

The eufy app has no per-device command table. What it sends for a device comes
from three layers, and the library mirrors the first two as data
(`eufy_home_security.devices.recipes`).

| Layer | What it is | Where it comes from |
|---|---|---|
| Thing description (TD) | Per product code (`T8170`, `T8160`, …): the model's *actions*, *properties* and *events*, each with an `identifier` (`open_live_stream`, `set_ptz_cruise_preview`, …) and its input/output types | `POST app-things-{region}-pr.eufy.com/app/things/get_things_list`, body `{"product_codes": [...], "code_time_map": {}, "use_network_version": true}` (an authenticated, encrypted cloud call); reply `data.things_list[]` = `{profile, version, large_version, properties[], actions[], events[]}` |
| Handler | `<PN>Handle.mix.js`, a JavaScript bundle at the TD's `profile.plugin_path` (public CDN). Its `controlDevice(request)` turns an action and its input into a *recipe*: the outer command, the sub-command, the parameters, a timeout, and where the answer arrives | downloaded by the app per product code; `large_version` in the TD names the version |
| Native executor | The app's code that sends a recipe over P2P and waits for its answer | the app itself; in this library, the P2P session |

A recipe in the handler's shape:

| Key | Meaning |
|---|---|
| `cmd` | Outer command: `1700` (a standalone device: `{"commandType": subCmd, "data": params}`), `1350` (a station: a device message whose `cmd` is `subCmd`), `1004` (stop live video, sent bare) |
| `subCmd` | The command inside the outer one |
| `params` | Sent as given, in the handler's key order |
| `timeout` | Milliseconds the app waits for the answer |
| `resultFrom` | `0` the command's own reply, `1` a notify (`notifyCmd`, normally `1351`) carrying the same sub-command, `2` a notify only |
| `notifyCmd` | The frame type the answer arrives in when `resultFrom` is not `0` |
| `parsePayloadAction`, `payloadFrom`, `rtcSendRoute`, `dropSameRequest`, `condition` | Result shaping in the handler, the WebRTC route and request de-duplication; the library does not use them (`HANDLER_UNUSED_KEYS`) |

## Connect type

The handler picks a recipe by how the device is reached, from the serial prefix of
its parent (station):

| Parent serial prefix | Connect type |
|---|---|
| `T8030` | HB3 (HomeBase 3) |
| `T8010` | HB2 |
| `T8001` | HB1 |
| `T8020` … `T8025` | M8020 … M8025 |
| `T9000` | T9000 |
| `T8N00` | NVR |
| `T7000` | T7000 |
| `T8040` | HB4 |
| anything else, or no parent | standalone (`SINGLE`) |

`recipes.connect_type()` implements the rule. The handlers also treat a device reporting
parameter `6271` (outdoor mode) as true as standalone whatever its parent; no T8030,
T8160, T8170 or T8910 dump carries 6271, so the library does not apply it.

## Goldens

`scripts/thing_models.py goldens` evaluates the handlers offline (Node, with
`scripts/gen_models_driver.js`) for a fixed set of cases with synthetic
serials and keys, and writes their recipes to `tests/fixtures/thing_models/<PN>.json`
together with the handler's version, CDN date and SHA-256.
`tests/devices/test_recipe_goldens.py` holds every library builder to the handler's
output, so a new handler version shows up as a failing test, not as a surprise on
hardware. The handler scripts themselves are never committed.

One deviation is deliberate: for a camera behind a HomeBase the handler's live open
is `1350`/`1003`; the library keeps its own hardware-verified HomeBase live frame.
The golden still records the handler's shape, so a change to it is noticed.

## Adding a device or an action

1. **Fetch** the TD and handler into the private cache (from a cached session; the
   script never logs in with a password):
   `uv run python scripts/thing_models.py fetch --store ~/.eufy.json --out .work/things`.
   Explore an action with
   `uv run python scripts/thing_models.py recipe --cache .work/things T8170 set_ptz_cruise_preview 1`.
2. **Goldens**: add the case to `CASES` in `scripts/thing_models.py` (synthetic
   device, fixed payload, the builder's name) and run
   `uv run python scripts/thing_models.py goldens --cache .work/things`.
3. **Implement** the builder in `src/eufy_home_security/devices/recipes.py` so that
   its `as_handler_dict()` equals the golden minus the unused keys.
4. **Test**: the golden test picks up the new case; map it to the builder there.
5. **Verify on hardware**, record it in [hardware-verification.md](hardware-verification.md),
   mark the case `verified=True`, and regenerate this page:
   `uv run python scripts/thing_models.py inventory --cache .work/things`.

Support is *declared* for a recipe taken from a handler and *verified* only once
it has been sent to real hardware with the expected answer.

## Inventory

Generated from the cached TDs and `CASES`; do not edit by hand.

<!-- BEGIN GENERATED: scripts/thing_models.py inventory -->

### Thing models

| Product code | Handler version | Handler date | Actions | Properties | Events |
|---|---|---|---|---|---|
| T8030 | 174 | 2026/09/04 | 54 | 75 | 6 |
| T8113 | 115 | 2026/07/24 | 35 | 98 | 4 |
| T8142 | 123 | 2026/08/19 | 35 | 98 | 4 |
| T8160 | 119 | 2026/07/15 | 34 | 98 | 4 |
| T8170 | 283 | 2026/08/31 | 70 | 148 | 7 |
| T8410 | 159 | 2026/09/07 | 62 | 130 | 3 |
| T8410C | 146 | 2026/09/29 | 65 | 133 | 3 |
| T8910 | 48 | 2025/08/27 | 7 | 11 | 1 |

### Recipes the library implements

| Product code | Connect type | Action | Builder | Support | Note |
|---|---|---|---|---|---|
| T8170 | SINGLE | `open_live_stream` | `open_live_stream_single` | verified |  |
| T8170 | SINGLE | `close_live_stream` | `close_live_stream` | verified |  |
| T8170 | SINGLE | `query_preset_positions` | `query_preset_positions` | verified |  |
| T8170 | SINGLE | `set_ptz_cruise_preview` | `goto_preset` | verified |  |
| T8170 | SINGLE | `get_preset_position_pic` | `preset_picture` | declared |  |
| T8170 | SINGLE | `ptz_action_control` | `ptz_rotate` | verified |  |
| T8170 | SINGLE | `set_picture_zoom` | `set_picture_zoom` | verified |  |
| T8160 | HB3 | `open_live_stream` | — | declared | The library sends its own HomeBase live open, not this recipe. |
| T8160 | HB3 | `close_live_stream` | `close_live_stream` | declared |  |
| T8113 | HB2 | `open_live_stream` | `open_live_stream_station` | declared |  |
| T8113 | HB2 | `close_live_stream` | `close_live_stream` | declared |  |
| T8142 | HB2 | `open_live_stream` | `open_live_stream_station` | declared |  |
| T8142 | HB2 | `close_live_stream` | `close_live_stream` | declared |  |
| T8410 | SINGLE | `open_live_stream` | `open_live_stream_single` | declared | The T8410 variant: no `extValue`. |
| T8410 | SINGLE | `close_live_stream` | `close_live_stream` | declared |  |
| T8410 | SINGLE | `ptz_action_control` | `ptz_rotate` | declared | The T8410 variant: no `zoom`, no `ivalue`. |
| T8410C | SINGLE | `open_live_stream` | `open_live_stream_single` | declared | The T8410C variant: no `extValue`. |
| T8410C | SINGLE | `close_live_stream` | `close_live_stream` | declared |  |
| T8410C | SINGLE | `ptz_action_control` | `ptz_rotate` | declared |  |

<!-- END GENERATED: scripts/thing_models.py inventory -->
