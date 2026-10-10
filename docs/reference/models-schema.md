# Settings files (schema v3)

`src/eufy_home_security/devices/data/models/<PN>.json` holds one file per product
code (107). Each file lists the model's settings, as the vendor's thing description (TD)
declares them, with the write and read codecs the vendor's handler
(`<PN>Handle.mix.js`) gives. `scripts/gen_models.py` generates the files and
`INDEX.json` beside them, `{"schema_version": 3, "codes": [...]}`: the sorted product
codes of every file in the directory. The library reads a model's file only when the
index lists its code; the tests and the wheel check pin the file set to the index. They
ship in the wheel.

## Top level

| Key | Meaning |
|---|---|
| `schema_version` | `3` |
| `product_code` | The file stem, e.g. `T8160` |
| `source` | `td_version` (int), `handler` (file name), `handler_date` (`YYYY-MM-DD`, from the handler's plugin path), `app_version` (the app build the labels and layout come from) |
| `settings` | Object keyed by the TD identifier (`[a-z0-9_]+`, verbatim) |

Keys are sorted, except inside recipe objects, where the handler's key order is kept. Files
are 1-space-indented JSON with a trailing newline, and a re-run gives the same bytes.

## Per setting

| Key | Meaning |
|---|---|
| `kind` | `enum`, `bool`, `range`, `string`, `other` or `flags` (an int bitmask of named members, several may be on) |
| `values` | The enum's values (TD values, the public values the handler takes) |
| `min`, `max`, `step`, `default` | From the TD where it gives them |
| `unit` | The TD unit normalised to `s`, `ms`, `d` or `%`, else the unit the app's control shows on the page the setting is on (the custom-recording sliders: `s`); absent otherwise |
| `access` | `rw`: the handler has a value-dependent write. `ro`: it has none |
| `write` | Recipe template (base context, below) |
| `write_table` | `{"<value>": recipe}` when the recipe's shape depends on the value. It replaces `write` |
| `read` | `{"param": <id>, "map": null}`: the parameter's value is the public value's string form. `{"param": <id>, "map": {"<param value>": <public value>}}`: decode through the map. Either may carry `view` (below). `null`: not readable |
| `contexts` | What other contexts change (below); absent when every context sees the base entry |
| `labels` | `{"<value>": "<title>"}` from the app's titles, else the cleaned TD description |
| `group`, `order` | Section and position on the app's settings page. Always present together |
| `page` | The app page the setting lives on |
| `applies_when` | `[<enum setting>, <value>]`: the app shows the setting only while that setting has that value |
| `note` | Why a setting is `ro`, or what is limited on an `rw` one |
| `name` | The app's title for the setting (the model's own branch title where the app has one); only for models whose settings the app shows on its React Native screens |
| `control` | On every `rw` setting except `other`: the control a UI offers. `switch` (bool), `select` (enum, or a string with a `domain`), `slider` (range of at most 200 steps), `box` (larger range), `toggles` (flags, one on/off per member), `text` (string) |
| `domain` | `string` only: the library table its values come from. `timezone`: the app's device time zones (`devices/data/timezones.json`, from `scripts/gen_timezones.py`); the value is an IANA id, written as `<POSIX rule>\|1.<row>` in the app's string frame, read back to the id. Set on an `rw` string whose write is command 1215 |
| `flags` | `flags` only: `{"<member>": <bits>}`, one or more bits per member; `labels` titles the members |
| `bit` | A `bool` that is one bit of a parameter other settings share: the value is `raw & bit`, and a write sends the whole current mask with this bit set or cleared (`$v:int` is the mask) |
| `variant_of` | The identifier of the setting the app uses in this one's place on the same model, absent on the primary. Set for `<base>__v<n>` when `<base>` exists (the app resolves a versioned identifier to its base and picks one by the TD's read conditions) and for listed legacy pairs (`nightvision_type` → `nightvision_type_new`, enum form only) |

An `rw` setting has exactly one of `write` and `write_table`. An `ro` setting has no
write key and `read: null`. A `flags` setting and a `bit` setting read the raw mask
(`read.map` null).

### Contexts

The handler's codecs depend on how the app reaches the device. The entry itself is the
**base** context: a device whose parent is no station kind (the handler's `SINGLE`).
`contexts` lists the others that differ, as
`[{"names": [<context>, ...], "entry": {<field>: <value or null>}}]`: one item per
distinct change, its `entry` holding the fields that context replaces (`null`: the field
is absent there, so `"read": null` is not readable). The names are `standalone` (a
device that is its own station, `parent_sn` = `device_sn`) and the station kinds of
`ConnectType` (`HB1`, `HB2`, `HB3`, `HB4`, `M8020`–`M8025`, `NVR`, `T7000`, `T9000`) for a
device paired to such a station. Every context lists the same settings. The generator
sweeps the handler in each context on two channels; a T8170 behind a HomeBase 3, for
example, reads `detection_sensitivity` from 1276 and `notification_type` from 1289
instead of the standalone 6070 and 6020.

### Per-view reads

A multi-view camera reports a quality parameter (2730, 2731) as base64 JSON with one
quality per view, `{"mode_0": {"quality": q}, "mode_1": {…}, "cur_mode": m}`.
`read.view` is `{"by": <rule>, "map": {"<quality>": <public value>}}`: the value is the
current view's `quality` through `map`. `by` names the current view: a parameter id
(6243, the view mode: `12` selects `mode_1`, any other value or none `mode_0`),
`"cur_mode"` (the report's `cur_mode`: 0, 1 or none select `mode_0`, any other
`mode_1`) or null (always `mode_0`). The library tries `read.map` (or the identity) first
and the view read when that gives no value. The generator adds `view` to an enum whose
write sends a `quality` per value when the handler's getProperty picks the quality of
the view that rule names in each of three probes (the value's quality in one view,
another value's in the other, with view mode 0 or 12 and `cur_mode` 0 or 2); the map
keys that are such reports are dropped.

### Shaping

After the codecs are inferred, the generator reshapes a setting only when the handler's
own recipes prove the new form sends the same bytes:

- **bit**: a bool whose write is `0` / one power of two to a parameter, and which the
  handler read-modifies-writes (probed with other bits set in the parameter).
- **flags**: an enum whose comma-joined payload (the app's multi-choice form) renders the
  OR of its members' values; a member that sets no bit is dropped. Never an enum other
  settings' `applies_when` names.
- **scale**: an enum whose labels are `1..N` (or `0..N`) in value order becomes a `range`
  of the shown numbers, its codecs restated as a slot or `$affine`.
- **variant**: a setting whose write equals that of a shorter key it extends
  (`detection_sensitivity_test_mode`) is `variant_of` that key; when only the longer one
  reads the parameter the shared write updates, the shorter one takes that read.
- **update of an absent value**: an `update` or `extUpdates` item whose value is an
  empty JSON object (`"{}"` or its base64 `"e30="`) is left out. It is the handler's
  read-modify-write of a parameter the sweep's device does not hold, and written to the
  parameter cache it would replace the device's real value; the next dump has the new
  value.
- **dropped variant**: an `rw` variant whose key extends its primary's and whose entry
  equals the primary's in everything but `variant_of` and a placement (`page`, `group`,
  `order`) it lacks is left out of the file: it would be a second entity for the same
  write and read. A variant that differs in any codec, domain, label or control stays,
  and so does one an `applies_when` names. A v1 reference row of a dropped key is
  checked through the longest remaining key it extends.

The v1 reference rows are checked again after shaping, with their payloads restated in
the shaped form. `variant_of` names another setting of the file, which has no
`variant_of` itself.

## Placeholders

Recipe templates are the handler's recipe with the value positions replaced:

| Form | Rendered as |
|---|---|
| `"$v"` | The public value as is |
| `"$v:str"` | Its string form (bools as `"0"`/`"1"`) |
| `"$v:int"` | Its int form (bools as `0`/`1`) |
| `{"$map": {"<value>": x}}` | `x` for the value's key (`"3"`, `"true"`). Covers every enum value, or `false`/`true` |
| `{"$affine": [a, b]}` | `a * value + b`, an int when integral |
| `"$channel"` | The device's channel (3 as a station child, 0 standalone in the samples) |
| `"$device_sn"`, `"$station_sn"` | The device's and its station's serial |
| `"$param:<id>:int"`, `"$param:<id>:str"` | The device's current value of parameter `<id>`, as an int or as the string. A leaf the handler fills from the device's parameters: null in every sweep (the parameter absent) and that value with the parameter set to two values the model's writes give it. A T8170's 2731 write sends `"mode": "$param:6243:int"` |

`write_table` uses the same forms. Volatile keys (`transaction`,
`buildTimestamp`) are dropped. All other keys of the handler's recipe are kept: `cmd`,
`subCmd`, `params`, `update`, `extUpdates`, and transport keys such as `http`, `ble` and
`mqttCmdCode`.

## Notes

| Note | Meaning |
|---|---|
| `no handler write path` | The TD marks the property writable, but setProperty gives no recipe |
| `handler ignores the value` | Every value gives the same recipe |
| `handler rejects the probed values` | The handler threw or returned an error for every probe |
| `handler rejects some values` | Some domain values give no recipe |
| `handler transforms the value` | A string/other value is encoded (e.g. base64 JSON), not placed |
| `handler expects a structured value` | The recipe shape depends on a free-form value |
| `non-linear range` | A range whose leaf is not `a * value + b` |
| `serial embedded in a string` | A serial appears inside a longer string and cannot be slotted |
| `round trip does not return the written value` | `rw` with `read: null`: getProperty does not decode the written value back |

A TD property that is not writable is `ro` without a note.

## Example

T8160 `video_clip_length`:

```json
{
 "access": "rw",
 "applies_when": ["power_manager_mode", 3],
 "control": "slider",
 "default": 60,
 "kind": "range",
 "max": 120,
 "min": 5,
 "name": "Clip length",
 "page": "CustomizeRecording",
 "read": {"map": null, "param": 1249},
 "step": 1,
 "unit": "s",
 "write": {
  "cmd": 1249,
  "params": {"duration": "$v"},
  "update": {"needUpdate": true, "cmd": 1249, "paramValue": "$v:str"}
 }
}
```

Writing 30 sends `cmd` 1249 with `{"duration": 30}`. Parameter 1249 reads back `"30"`.

## At runtime

`eufy_home_security.devices.model_settings` loads a file on the first request for its
product code and turns each entry into a `Setting`:

| `Setting` field | From |
|---|---|
| `key` | the settings key (the TD identifier) |
| `name` | `name`, else a short English title for the key (`devices/labels.py`) |
| `kind` (`SettingKind`) | `kind` |
| `values`, `minimum`, `maximum`, `step`, `default` | `values`, `min`, `max`, `step`, `default` |
| `unit` (`SettingUnit` or None) | `unit` |
| `labels` | `labels`, keyed by the public value; `label(value)` looks one up |
| `writable` | `access` is `rw` and the library sends the write (below) |
| `readable` | `read` is not null |
| `group`, `order`, `page`, `applies_when` | the same keys; `applies_when` as a `(key, value)` tuple |
| `note` | `note`, plus the reason when the library refuses the write |
| `variant_of` | `variant_of` |
| `control` (`SettingControl` or None) | `control`; None when the library does not write the setting |
| `flags`, `bit` | `flags` (member → bits), `bit` |

A `bit` setting's `encode` refuses: write it through `Station.async_set_setting`, which
reads the current mask fresh, moves the one bit (`Setting.mask_with`) and sends the
whole mask (`Setting.encode_mask`), and refuses when the mask cannot be read. A `flags`
setting's value is the whole mask; `Station.async_set_flag(key, member, on)` moves one
member the same way, and `Setting.decode_flags(raw)` gives the members that are on plus
the bits no member names.

`settings_of(code, connect, standalone=)` resolves a file for one context: `standalone`
for a device that is its own station, else the station kind `connect` the device is
paired to (None or `SINGLE`: the base). `Station.settings_for` passes the device's own.

`Setting.validate(value)` checks a value against the domain (an enum also takes its
label), `Setting.encode(value, ctx)` renders the write recipe for the device `ctx`
describes into a `WireCommand`, and `Setting.decode(raw, block)` turns a dumped
parameter value into the public value (`block`: the device's other parameters, for a
per-view read). `Setting.write_params` names the parameters a write's `$param` leaves
take; `encode` takes their values from `WriteContext.params` and raises `ValueError`
when one is missing. `Station.async_set_setting` fills them from the session's
parameters, else from a fresh dump, and raises `CommandNotAppliedError` when the device
does not report one (the handler would send null; a HomeBase 3 refuses a 2731 write with
`"mode": null`). The library does not send a write, and the
setting is not `writable`, when its recipe goes over another transport: the note then
names it (`cloud request`, `multi-command write`, `app-local`, `Bluetooth`, `MQTT`,
`no P2P command`, `1700 data body not supported`, `scalar body on a non-ECB command`).
`arming_selected_mode` is never written as a setting (`guard mode: use
Station.async_set_guard_mode`).

The per-mode delays and action masks (`alarm_delay_<mode>`, `leaving_delay_<mode>`,
`camera_action_<mode>`, `sensor_action_<mode>`) are not in these files. They are the
station's mode tables, defined in `devices/settings.py` and appended by
`Station.settings_for` to every paired camera's or sensor's settings.

A product code with no file has no bundled settings. When the client's model scan
finds the code's thing description in the cloud, `Station.settings_for` lists its
properties read-only (`writable` and `readable` False, `note` `not in bundled data`):
domain, labels, unit and default from the TD, no codec.

## Regenerating and checking

```
uv run python scripts/gen_models.py              # all models in the cache
uv run python scripts/gen_models.py T8160 T8170  # some models
uv run python scripts/gen_models.py --check      # regenerate to a temp dir, compare bytes
```

The generator needs Node and the private thing-model cache (`<PN>/td.json` and the
handler). Both stay on the maintainer's host and are never committed: vendor code runs
only at generate time, in a `vm` sandbox (`scripts/gen_models_driver.js`). Before a model
is written, every codec must render back each swept recipe, and every row of
`tests/fixtures/models_v1_reference.json` must render to its recorded `cmd`/`subCmd`/`params`.
A model that fails is not written, and the run exits 1. `--check` exits 1 on any byte
difference and 2 when Node, the cache, the labels, the layout or the title data are missing.
Run it on the full corpus after changing the generator.

Tests that need only committed files check the schema of all 107 files and the v1
reference. The `--check` test runs on two models and skips without Node or the cache.
When and how to regenerate: [how-to/regenerate-models.md](../how-to/regenerate-models.md).
