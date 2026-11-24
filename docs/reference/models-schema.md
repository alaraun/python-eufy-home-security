# Settings files (schema v3)

`src/eufy_home_security/devices/data/models/<PN>.json` holds one file per product
code (166). Each file lists the model's settings, as the vendor's thing description (TD)
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
| `battery` | Present when the model's TD has `battery_value` and its handler fills it from a parameter: the parameters a device's battery level is read from (`SubDeviceState.battery`), first one first, each `{"param": <id>}` plus `levels`, `{"<raw value>": <level or null>}`, for the raw values 0-255 the handler reads as another level than their number (null: below 0, no level). The generator lists each parameter the handler fills the property from alone (named as a command id, in the base context), and reads each at 0-255; a parameter that wins over another whichever the device lists first comes first, and where the device's list order decides (the handler takes the one listed last) the lower id comes first. A model without it reads 1101 as reported; a device that reports none of the parameters, or a negative raw value, has no level |
| `sd_status_groups` | Present when the model's handler groups an `SDINFO_EX` (1144) status ([commands.md](../protocol/commands.md#a-devices-sd-card-or-emmc-1144-get_sd_info_ext-verified)): `default`, the group of a status it does not list, and `codes`, `{"<status>": <group>}` for each status whose group is another (`StorageMedium.status_group`, `devices.model_settings.sd_status_groups`), `from`, what the table is read from (`answer`: the handler's parse of the answer; `status_property`: the status property, below; `SdStatusSource`), plus `param` (only with `from` `answer`) where the handler groups that device parameter in place of the answer's status whenever the device lists it with a value. The generator runs the handler's parse of the answer for every status from -1 to 255 and every number literal of the handler (with its negative); where that parse reads no status (one group for every status), it runs the property the handler fills from the device's status parameter instead (`get_storage_status`, at the parameter it is read from, located in the base context whether or not the TD declares it), the library's choice (`from` `status_property`). Both sweeps and the check of `param` run in every context (the base, `standalone` and each station kind, one driver job each), and the contexts must agree, or the model is not written; `param` is searched for in the base context, and in every other context the handler's other parameter ids, listed together, must leave the group as it is. `param` is the one parameter that, listed with a value, changes the parse's group; the generator checks the parse groups every swept value of it by the same table, keeps the answer's status for an empty value and gives the default group to a value that is no decimal code (`+4`, `4.0`, `0x4`, text, blanks; surrounding blanks are stripped). A model without it is grouped by the library's table (`SD_STATUS_GROUPS`) |

Keys are sorted, except inside recipe objects, where the handler's key order is kept. Files
are 1-space-indented JSON with a trailing newline, and a re-run gives the same bytes.

## Per setting

| Key | Meaning |
|---|---|
| `kind` | `enum`, `bool`, `range`, `string`, `other`, `flags` (an int bitmask of named members, several may be on) or `object` (a JSON object, as the device stores it, written whole; see *Object writes*). A property the thing description leaves without a domain (`other`) that an app screen writes from an on/off switch is the `bool` the switch shows, its handler driven with the two values the switch writes (the HomeBase alarm delay `notification_alarm_delay_value`: 1 on, 0 off; the generator's `switch_writes` input, extracted from the app's screens) |
| `values` | The enum's values (TD values, the public values the handler takes) |
| `min`, `max`, `step`, `default` | From the TD where it gives them; `default` is the eufy app's own where the app shows another value while the device reports none (`device_cross_cam_assistance_switch` on a T8030: on); an enum's `default` is always one of its `values` |
| `unit` | The unit the app's screen shows: a settings-page control's on the page the setting is on, on a model whose settings the app's RN screens render, or a screen that reads the property wherever it sits (the clip length and retrigger interval: `s` on every model; the power-manager counters show a bare number: no unit); it wins over the TD unit. Else the TD unit normalised to `s`, `ms` or `%` (the TD's `day` is dropped: no app screen shows those values in days; its volume unit is `%` on a 0..100 or 1..100 scale and dropped on any other, a bare level); absent otherwise |
| `meaning` | What the app reads the value as, where its own code names the property: a security sensor's card status (`opening`, `tamper`, `low_battery`, `moisture`, `cold`, `siren_ringing`; bool settings only), `timestamp` (epoch milliseconds), `time_of_day` (`HH:MM`); or `temperature` from the TD unit `degree`. Absent otherwise: the loader then derives it from `unit` (a time unit: `duration`, `%`: `percent`) |
| `access` | `rw`: the handler has a value-dependent write. `ro`: it has none, or the setting is a status the eufy app only reads (`hb_keypad_is_password_set`, `device_back_screen_connect_status`). The handler's write is probed for every property, whatever the TD's `access_mode` declares (the app does not check it before writing); a property the TD does not declare writable (no `W`) is `rw` only in a context where its write also gives a `read`: getProperty returns the written value (the motion light switch `motion_actived_light_switch` of a T8420), or the setting is an enum read by the inverse of its write (`read` below), or an `object` setting the handler reads from the value its write stores (*Object writes*). A handler write the eufy app does not send is `ro` (*Write routing*) |
| `write` | Recipe template (base context, below) |
| `write_table` | `{"<value>": recipe}` when the recipe's shape depends on the value. It replaces `write` |
| `read` | `{"param": <id>, "map": null}`: the parameter's value is the public value's string form. An `object` read may carry `members` instead (*Object writes*). `{"param": <id>, "map": {"<param value>": <public value>}}`: decode through the map. Either may carry `view` or `span` (below). `fallback` (an enum's value): any reported value outside the values reads as it, as the eufy app's screen shows it (the recording type `device_recording_type` reads `3`, Continuous); writing a value outside the values is still refused. `null`: not readable. The generator takes it from the handler's getProperty of each written value; for a setting without a write, from the one parameter the handler fills it from (located once, in the base context: the parameter ids the handler's code names are held at two values, in ascending and in descending order, and the property is read back by name, else by command id), held at each value's string form. Such a read carries `"no_default": true`: unreported, the setting reads None, never its `default`. It stays `null` when several parameters decide the value (in either order, or together), when a bool does not read as a boolean for every value held (`"2"` too), or when an open kind (`string`, `other`) does not read a multi-digit number and a JSON object back unchanged; an `other` is also read as a number when each integer text reads back as that integer, the JSON object does not read as another structure, no other property reads its parameter and its own write, if any, stores the number as is (a property that reads one field of a JSON value stays `null`; reading such fields is not described). An enum whose getProperty does not return the written value, but whose write stores every value as its own parameter value (no failed conversion such as `NaN`), is read by the inverse of the write unless a per-view read decodes it: the value read is the one the client wrote. The eufy app's own display of the watermark setting (T8414, T8440, T8442) differs from it |
| `contexts` | What other contexts change (below); absent when every context sees the base entry |
| `labels` | `{"<value>": "<title>"}` from the app's titles, else the cleaned TD description. The app's option titles of `working_mode_value`: `Standard` (EU), `Performance (beta)` (US) |
| `section` | Always present: the UI section id, one of `devices/sections.py`'s `SETTING_SECTIONS`. Assigned by `scripts/gen_models_sections.py` from the app page the setting lives on, else the station rules (station models), else the identifier rules, else `other`; a variant has its primary's. Every context has the same section |
| `role` | Always present: what the setting is to the user, from where the eufy app shows it; assigned by `scripts/gen_models_roles.py`, the first rule that applies deciding. `setting`: the handler has a write (`rw` in some context); or the thing description declares the property writable and the app does not list it as a status it only reads (the app's control, which the library cannot write: `access` `ro`). `diagnostic`: read from, or filled by the handler from, a parameter whose value the library already reports (`devices/param_info.py` `STATE_PARAM_INFO`: battery, online status, a station's own status, power source, signal, storage, counters, active mode, a firmware update being installed, a camera's media ability; the parameter is the one the read uses or, for a setting without a read, the one parameter the handler fills it from), so a consumer has the value as a device field (a camera's `charging_status` is `diagnostic`: it is filled from the power source). `diagnostic`: read-only and `structured`. `diagnostic`: read-only, on the device card, and a bare code: an `other` without `labels` or `unit` (the card turns such a code into an icon or a gate and never shows the number: a station's connection type and Wi-Fi level, a paired device's connect type). `status`: read-only and shown by the app (`shown` present). `diagnostic`: read-only and shown nowhere (capability data such as `device_ability_data`, schedules and other configuration values). Every context has the same role |
| `shown` | Where the eufy app shows the setting, whatever its `role`; assigned by `scripts/gen_models_roles.py`. `card`: the app's device card or home page reads it (an entry sensor's door state, tamper and low-battery flag, a camera's battery and charging state), even when a settings page reads it too. `page`: a settings page reads it, the model's layout places it on a page, or the app lists it as a status it only reads. Absent: the app shows it nowhere. A `<base>__v<n>` variant also takes its base's place. Every context has the same value |
| `structured` | `true` when the value is a JSON structure (an object or array, or its JSON text): a `string` or `other` whose handler reads its parameter as JSON (held at a JSON object, it reads back as that object parsed; held at the object's base64, as the object or its JSON text), or, unreadable, whose `default` is the JSON text of an object or array; an `object` setting; or a value the app's screen builds and parses as JSON itself (the generator's `structured` input: the light schedule `spotlight_schedule_config`, writable on some models, keeping its control). Absent otherwise. Decided in the base context |
| `group`, `order` | Block and position on the app's settings page, where the app's layout names them. Always present together; they order settings within a section |
| `page` | The app page the setting lives on; it decides `section` where the page holds one kind of setting |
| `applies_when` | `[<enum setting>, <value>]`: the app shows the setting only while that setting has that value |
| `note` | Why a setting is `ro`, or what is limited on an `rw` one; on an `advanced` setting it ends with the app's warning |
| `name` | The app's title for the setting (the model's own branch title where the app has one), in sentence case: a capitalised word after the first is lower-cased unless it is a proper noun (`Wi-Fi`, `Alexa`, weekdays); acronyms and mixed case (`LED`, `HomeBase`, `2K`) stay. Models whose settings the app shows on its React Native screens take the RN titles; models on the native settings screens only the titles read from that model's own native screens |
| `control` | On every `rw` setting except `other`: the control a UI offers. `switch` (bool), `select` (enum, or a string with a `domain`), `slider` (range of at most 200 steps), `box` (larger range), `toggles` (flags, one on/off per member), `text` (string), `object` (object: the whole object, read, changed and written back) |
| `domain` | `string` only: the library table its values come from. `timezone`: the app's device time zones (`devices/data/timezones.json`, from `scripts/gen_timezones.py`); the value is an IANA id, written as `<POSIX rule>\|1.<row>` in the app's string frame, read back to the id. Set on an `rw` string whose write is command 1215 |
| `flags` | `flags` only: `{"<member>": <bits>}`, one or more bits per member; `labels` titles the members |
| `bit` | A `bool` that is one bit of a parameter other settings share: the value is `raw & bit`, and a write sends the whole current mask with this bit set or cleared (`$v:int` is the mask) |
| `advanced` | `true` on a setting the eufy app puts behind a warning (`working_mode_value`: switching to Standard reduces the HomeBase's Wi-Fi range). A UI offers it hidden by default; absent otherwise |
| `variant_of` | The identifier of the setting the app uses in this one's place on the same model, absent on the primary. Set for `<base>__v<n>` when `<base>` exists (the app resolves a versioned identifier to its base and picks one by the TD's read conditions) and for listed legacy pairs (`nightvision_type` → `nightvision_type_new`, enum form only) |
| `variants` | On a primary only: the `__v` properties the app may read in its place, with their read conditions (see *Variants*); absent when it has none with read conditions |

An `rw` setting has exactly one of `write` and `write_table`. An `ro` setting has no
write key; it is readable (`read` not null, with `no_default`) when one parameter fills it as above. A `flags` setting and a `bit` setting read the raw mask
(`read.map` null). An `object` setting's read (`read.map` null) decodes the parameter's
value to the object, as the eufy app's handler reads it: base64 of the object's JSON text
when the value is base64 in whole groups of four characters (padding included, no
blanks), else the JSON text itself; anything that is not a JSON object reads
as None.

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

### Variants

The app reads a setting through its versioned forms: of the TD properties named
`<identifier>__v<n>` (any case) that have read conditions, those whose conditions pass for
the unit compete, the one with the most conditions (summed over its groups) wins, the
first in TD order among equals, and none passing leaves the primary itself. The primary's
`variants` lists those candidates in TD order:

```json
"variants": [
  {"id": "detection_type_set__v1", "key": "detection_type_set__v1",
   "read_conditions": [[
     {"type": "parent_sn", "qualifier": "RE", "value": "^(?!(T8410|T8040)).*$"},
     {"type": "associated_field", "qualifier": "=", "value": "1",
      "prop": "ai_empower", "param": 1299, "default": "0"}]]}
]
```

`id` is the TD property, `key` the setting that stands for it (itself; the primary when it
was dropped as equal to the primary; `null` when the file has no setting for it). A
condition list passes when any group passes, a group when all its conditions pass:

| `type` | Input | Comparison |
|---|---|---|
| `device_version`, `parent_version` | the device's / its parent's main firmware (the device's own when it is its own parent); a missing firmware is `""`, below every version | `>`, `<`, `=`, `!=`, `>=`, `<=` as versions (`devices/versions.py`), `RE` as a pattern; `parent_version` without a value or qualifier passes |
| `sdk_version` | the app's thing-SDK version | as above |
| `device_sn`, `parent_sn` | the device's / its parent's serial | the value is a pattern, whatever the qualifier |
| `user_country` | the country the account logs in with | pattern |
| `associated_field` | the property `prop`: device parameter `param` read through `map` (absent: as reported), `default` when the device reports no such parameter; no `param` when the generator found no parameter the handler reports it from as is (read by name, else by command id; the property's own `read` when it has one) and its own write, if any, stores as is; no `prop`: `""` | `=`, `!=`, text order for `<`, `<=`, `>`, `>=`; `RE` as a pattern |
| `parent_associated_field` | the parent's property `prop`; passes when the parent is not listed | not evaluated otherwise (unknown) |

A pattern passes on an empty pattern or value and on a match anywhere (an inline flag
such as `(?i)` applies to the whole pattern); any other type fails.
`Station.setting_in_use(key, device_sn)` evaluates it per unit (see *At runtime*).

Where the inputs differ from the app's:

- `device_version`, `parent_version` read the device list's `main_sw_version`; the app
  prefers the device's own `firmware_main_version` property where it has one, so right
  after a firmware update the answer can lag until the next device list.
- For a HomeBase 2 and other stations of its generation, the app removes every character
  other than digits and dots from the station's firmware before comparing
  `parent_version`; the library compares the firmware as listed.
- `user_country` is the country of the login scope that lists the device: an extra
  country scope's own country, else the country the library logs in with
  (`EufyCloudApi.login_country`: the `country` option, else the host's IP country), which
  can differ from the country the account was registered in.
- An associated condition whose value the handler's read never produces never passes,
  as in the app: on a T8180, `live_streaming_resolution__v1` and `record_resolution__v1`
  need view mode `12`, which the view-mode read reports only as `0` or `1`, so the
  primaries stay in use.

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

### Span reads

A device can store a timed value as its end and start, base64 JSON
`{"snooze_time": <end>, "startTime": <start>}` in Unix seconds (a HomeBase 3 stores the
snooze `device_snooze_time`, 1271, so). `read.span` is `{"member": <end member>, "start":
<start member>, "map": {"<seconds>": <public value>}}`: the value is the choice whose
duration is end − start, both members integers. The library tries `read.map` first (the
empty text reads as off there) and the span when that gives no value; any other stored
value reads as unknown. The generator adds `span` to an enum whose write stores at least
two values as base64 JSON with the same one integer member (`{"snooze_time": 1800}`; a
value stored otherwise has no span), when the handler's getProperty reads `{<member>:
start + n, "startTime": start}` as the value whose stored member is `n`, for each of
them and two starts. Whether a device clears the
record when the time runs out is not known; until it does, the read gives the duration
chosen, not the time left.

### Object writes

A property whose app screens write a JSON object (the combined light settings
`motion_activated_light_setting` and `light_ambient_lighting_setting`, a floodlight's
light schedule `ambient_light_schedule_config` and dusk-to-dawn switch
`ambient_light_schedule_sunset_to_sunrise`) is driven, besides
the domain sweep, with the objects the app's screens write for it, whatever the thing
description's `access_mode` (the generator's `object_writes` input: the screen's starting
object with the switch on and off, a schedule written, dusk-to-dawn written, a
read-modify-write of a read object), in every context on both channels. The value each
object stands for is the object the recipe stores (the first `update` or `extUpdates`
value that decodes to a JSON object as above; a plain JSON text only when it holds every
member of the app's object), else the app's object itself. The setting becomes `object`
when one template, built from the first recipe with the [object forms](#placeholders) at
the positions that equal that value, a member of it or its base64, renders every swept
value back to its recipe byte for byte (member order included), with at least two
distinct values. A leaf that varies across the recipes and equals a scalar member of each
value (as is, as a switch, as text, or as the text of its switch) takes that member's
slot, and a JSON object's text whose members do so becomes `$jsontext`; such a template
must slot every member of the value, since a write of some members only would drop the
others. It is readable from the parameter the write stores the value's base64 in when the
handler fills the property from that parameter (held at each written value's stored form,
the property reads back, with as many distinct answers as values). A write that stores the
value's members in several parameters instead is readable member by member when the
handler's answer, held at each value's stored parameters, is an object whose every member
is one parameter read as a switch or one member of a parameter's JSON object (a member no
write stores, such as the sun times the device fills, is found by holding a probe text
there): `read.members` is `{"<member>": {"param": <id>, "as": "flag"}}` or
`{"<member>": {"param": <id>, "member": "<name>"}}`, decoded from the device's parameters
(an unreported switch 0, a missing member `""`). A property the thing description does not declare
writable (no `W`) becomes `object` only in a context where its object write is also
readable that way, as for its `access` above. Otherwise the setting keeps its entry and,
when the description declares it writable, its note names why (below); an undeclared one
keeps it without a note. So a handler that reshapes the app's object (days to a bitmask,
renamed members, defaults) and stores the result as base64 gets the stored object as
its value; one that stores JSON text is left read-only.

### Write routing

The generator emits a write only in a frame form the eufy app sends
([commands.md § Frame forms](../protocol/commands.md#frame-forms)). Its private routing
input, generated from the eufy app by an offline extractor
([regenerate-models.md](../how-to/regenerate-models.md#the-routing-input)), holds the
frame form the app's send handler gives each command, the request type and value field
the app's request builder takes per bare command, and the own write forms of the settings
screens the app draws natively. For each `rw` template, in each context:

- A 1350 or 1700 template with a `subCmd` is sent as its wrapper.
- A bare command is sent when it gets a request type (its `params`' `msgType`, else the
  builder's) and has a frame form the library sends. A JSON-text command whose request
  case adds the owner's id to the text gets an `account_id` member `"$account_id"`
  (replacing one of that name in place, else appended).
- Otherwise, on a model whose settings the app draws natively (the settings tree's
  `settings_ui` is not the React Native one), the native screen's form: its own `params`
  where the input gives one, else the same template when a screen sends the command as
  the same scalar frame. A screen form that reads members of an object needs an `object`
  setting: any other setting is `ro` with the note `the eufy app's screen sends this write
  as an object, which this setting is not`.
- Otherwise the setting is `ro` with the note `the eufy app sends nothing for this
  write`, its read kept.

A bare JSON-text write's body is the handler's params as JSON text. The handler fills
some members from the account the app's message names (the snooze's `account_id`); the
generator drives such a write once more naming an account, and each member that takes
it becomes `"$account_id"`, in the handler's member order. A native screen's own form
is sent as the screen builds it, and the other frame forms carry the owner's id outside
the body (or none), so their templates are left as they are.

The run fails when the library's frame-form tables (`p2p.messages`) or its per-command
value fields (`ECB_VALUE_FIELDS`) differ from the input's.

### Shaping

After the codecs are inferred, the generator reshapes a setting only when the handler's
own recipes prove the new form sends the same bytes:

- **bit**: a bool whose write is `0` / one power of two to a parameter, and which the
  handler read-modifies-writes (probed with other bits set in the parameter).
- **flags**: an enum whose comma-joined payload (the app's multi-choice form) renders the
  OR of its members' values; a member that sets no bit is dropped. Never an enum other
  settings' `applies_when` names. A member whose bit the eufy app and the handler
  disagree on is left out (`switching_notification` keyfob), and so is one that belongs
  to another parameter (`switching_notification` "Start Alarm Delay", 1282); its bit
  stays in the mask, unnamed.
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
  and so does one an `applies_when` names. A key a release bundled is never dropped: a
  key the model lists in `scripts/data/released_keys.json` (product code → the setting
  keys a release shipped; a generator input, not package data) stays as `variant_of` its
  primary, and a released product code stays in `INDEX.json`. A released key the
  model's thing description no longer declares is listed in
  `scripts/data/retired_keys.json` instead (see the regeneration how-to). The
  generator reads only that manifest, never the files in `--out`. A v1 reference row of a
  dropped key is checked through the longest remaining key it extends.

The v1 reference rows are checked again after shaping, with their payloads restated in
the shaped form. `variant_of` names another setting of the file, which has no
`variant_of` itself.

## Placeholders

Recipe templates are the handler's recipe with the value positions replaced:

| Form | Rendered as |
|---|---|
| `"$v"` | The public value as is |
| `"$v:str"` | Its string form (bools as `"0"`/`"1"`) |
| `"$v:int"` | Its int form (bools as `0`/`1`, a digit string as its number). An `other` setting's value is also written as the text of each of its probes (`"0"`, `"1"`): a leaf the handler fills with that text's number is `$v:int`, one it fills with the text stays `$v` |
| `{"$map": {"<value>": x}}` | `x` for the value's key (`"3"`, `"true"`). Covers every enum value, or `false`/`true` |
| `{"$affine": [a, b]}` | `a * value + b`, an int when integral |
| `"$channel"` | The device's channel (3 as a station child, 0 standalone in the samples) |
| `"$device_sn"`, `"$station_sn"` | The device's and its station's serial |
| `"$v:json"` | An `object` value as a JSON object (a copy); the only object form that can be the whole `params` (any other is refused: `scalar body on a non-ECB command`) |
| `"$v.<member>:json"` | The value's member `<member>` (members chain with `.`) as JSON data, inside a body |
| `"$v.<member>:str"` | A scalar member as text: a string as is, a number or bool as its JSON text |
| `"$v.<member>:flag"` | A member as a switch: 1 for `true`, the number 1 or the text `"1"`, `"true"`, `"TRUE"`, else 0 |
| `"$v.<member>:int"` | A member as an integer: a whole number or its digit text; anything else (a bool, a fraction, other text) is refused |
| `{"$format": [text, part, ...]}` | `text` with each `%s` replaced by the next part's text |
| `{"$jsontext": template}` | The compact JSON text of the rendered template |
| `{"$each": [list slot, item template]}` | The item template rendered once per object of the list, its `$v` slots reading that object |
| `{"$or": [slot, constant]}` | The slot's rendering, or the constant when the value lacks the slot's member |
| `"$account_id"` | The owner's account id, filled when the frame is sent (a JSON-text frame's body) |
| `"$v:b64json"`, `"$v.<member>:b64json"` | Base64 of the value's (or member's) compact JSON text: no blanks, members in order, non-ASCII kept, an integral number without a fraction. That is `JSON.stringify`'s text when no key is an integer (JavaScript lists such keys first), every integer lies within ±2^53 and every fraction between 1e-4 and 1e16 in magnitude; other values give the same JSON value spelled differently. In the bundled files this form is only a parameter-cache `update`, so such a difference changes the local copy until the next dump, never what is sent |
| `"$param:<id>:int"`, `"$param:<id>:str"` | The device's current value of parameter `<id>`, as an int or as the string. A leaf the handler fills from the device's parameters: null in every sweep (the parameter absent) and that value with the parameter set to two values the file's writes give it. A T8170's 2731 write sends `"mode": "$param:6243:int"` |

`write_table` uses the same forms. Volatile keys (`transaction`,
`buildTimestamp`) are dropped. All other keys of the handler's recipe are kept: `cmd`,
`subCmd`, `params`, `update`, `extUpdates`, and transport keys such as `http`, `ble` and
`mqttCmdCode`.

## Notes

| Note | Meaning |
|---|---|
| `no handler write path` | The TD declares the property writable, but setProperty gives no recipe |
| `handler ignores the value` | Every value gives the same recipe |
| `handler rejects the probed values` | The handler threw or returned an error for every probe |
| `handler rejects some values` | Some domain values give no recipe |
| `handler transforms the value` | A string/other value is encoded (e.g. base64 JSON), not placed |
| `handler expects a structured value` | The recipe shape depends on a free-form value |
| `non-linear range` | A range whose leaf is not `a * value + b` |
| `serial embedded in a string` | A serial appears inside a longer string and cannot be slotted |
| `round trip does not return the written value` | `rw` with `read: null`: getProperty does not decode the written value back, and the write is no inverse-readable enum (two values share a parameter value, or it is no enum) |
| `status the eufy app only reads` | `ro` with its read: the app shows the value and offers no control for it |
| `no object form reproduces the app's object write` | Appended: the handler writes the app's objects, but no template of the object forms renders its recipes (it stores the object as JSON text, the body is no copy of the stored value, or it sends some members of the value only) |
| `the eufy app sends nothing for this write` | `ro`: the handler has a write, but the eufy app sends no frame for it (*Write routing*) |
| `the eufy app's screen sends this write as an object, which this setting is not` | `ro`: only a settings screen the eufy app draws natively sends the write, in a form that reads members of an object; the setting is no `object` (*Write routing*) |
| `handler rejects some of the app's objects` | Appended: the handler threw for some of the objects the app writes |

A property the TD does not declare writable and that the library does not write is `ro`
without a note, read as its handler fills it. `set_alarm_type` (and its
`__v<n>` forms) is not in the files: it is the device siren, an action rather than a
setting, served by `Station.async_trigger_device_alarm` from its own generated table
([commands.md § Device siren](../protocol/commands.md#device-siren-declared-app)).

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
| `name` | `name`, else a short sentence-case title for the key (`devices/labels.py`) |
| `kind` (`SettingKind`) | `kind` |
| `values`, `minimum`, `maximum`, `step`, `default` | `values`, `min`, `max`, `step`, `default` |
| `unit` (`SettingUnit` or None) | `unit` |
| `meaning` (`SettingMeaning` or None) | `meaning`, else `unit_meaning(unit)`; a setting listed from a thing description alone takes its unit's (`degree`: `TEMPERATURE`), a mode-table delay `DURATION` |
| `labels` | `labels`, keyed by the public value; `label(value)` looks one up |
| `writable` | `access` is `rw` and the library sends the write (below) |
| `readable` | `read` is not null |
| `role` (`SettingRole`) | `role`: `SETTING`, `STATUS` or `DIAGNOSTIC`; a setting listed from a thing description alone, without a file, is `DIAGNOSTIC`, a mode-table setting a `SETTING` |
| `shown` (`SettingShown` or None) | `shown`: `CARD`, `PAGE`, or None when absent; None for a setting listed from a thing description alone and for a mode-table setting |
| `structured` | `structured` (False when absent, and for a setting listed from a thing description alone); an `OBJECT` whose file does not set it is a malformed file (`ModelDataError`), so it is always True there |
| `group`, `order`, `page`, `applies_when` | the same keys; `applies_when` as a `(key, value)` tuple |
| `note` | `note`, plus the reason when the library refuses the write |
| `advanced` | `advanced` (False when absent) |
| `variant_of` | `variant_of` |
| (not public) | `variants`: `devices/variants.py` `setting_in_use` and `Station.setting_in_use` |
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
label; an `OBJECT` takes a non-empty JSON object or its JSON text, at most 32 levels deep,
and gives a plain copy, an integral float as an int), `Setting.encode(value, ctx)` renders the write recipe for the device `ctx`
describes into a `WireCommand`, and `Setting.decode(raw, block)` turns a dumped
parameter value into the public value (`block`: the device's other parameters, for a
per-view or a member read). `Setting.write_params` names the parameters a write's `$param` leaves
take; `encode` takes their values from `WriteContext.params` and raises `ValueError`
when one is missing. `Station.async_set_setting` fills them from the session's
parameters, else from a fresh dump, and raises `CommandNotAppliedError` when the device
does not report one (the handler would send null; a HomeBase 3 refuses a 2731 write with
`"mode": null`). The library does not send a write, and the
setting is not `writable`, when its recipe goes over another transport: the note then
names it (`cloud request`, `multi-command write`, `app-local`, `Bluetooth`, `MQTT`,
`no P2P command`, `1700 data body not supported`, `scalar body on a non-ECB command`),
when its command has no frame form (`no frame the eufy app sends for command <id>`), or
when its body cannot fill that form (a string frame without `mValueStr`, a JSON-text frame
without a body, an ECB body with no value member). These body checks are the ones `encode`
applies, so a `writable` setting never fails them at send time.
`arming_selected_mode` is never written as a setting (`guard mode: use
Station.async_set_guard_mode`).

The per-mode delays and action masks (`alarm_delay_<mode>`, `leaving_delay_<mode>`,
`camera_action_<mode>`, `doorbell_action_<mode>`, `sensor_action_<mode>`) are not in
these files. They are the station's mode tables, defined in `devices/settings.py` and
appended by `Station.settings_for` to every paired camera's, doorbell's or sensor's
settings.

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

The generator needs Node, the private thing-model cache (`<PN>/td.json` and the
handler) and the private routing input (*Write routing*). Both stay on the maintainer's host and are never committed: vendor code runs
only at generate time, in a `vm` sandbox (`scripts/gen_models_driver.js`). Before a model
is written, every codec must render back each swept recipe, and every row of
`tests/fixtures/models_v1_reference.json` must render to its recorded `cmd`/`subCmd`/`params`.
A model that fails is not written, and the run exits 1; Node failing a job stops the run
with exit 2. `--check` exits 1 on any byte difference and 2 when Node, the cache, the
labels, the layout, the title, the shown-property or the routing data are missing, or
the routing data and the library differ.
Run it on the full corpus after changing the generator. The handler's replies are kept in
a private answer store, so a run whose driver jobs were asked before replays them
without running the handler ([regenerate-models.md § The answer store](../how-to/regenerate-models.md#the-answer-store)).

Tests that need only committed files check the schema of all 166 files and the v1
reference. The `--check` test runs on three models and skips without Node of the pinned
major or the cache.
When and how to regenerate: [how-to/regenerate-models.md](../how-to/regenerate-models.md).
