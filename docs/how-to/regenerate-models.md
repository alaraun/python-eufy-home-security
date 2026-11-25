# Regenerate the settings files

The per-model settings (`src/eufy_home_security/devices/data/models/<PN>.json` and
`INDEX.json`) are generated offline from the eufy app's thing models and ship with each
release. Besides the settings, a model's file carries its battery reads (`battery`) and
how its handler groups an `SDINFO_EX` storage status (`sd_status_groups`). Nothing at
runtime fetches or runs vendor code: a newer handler reaches users only through a
regenerated file in a library release. The format is in
[reference/models-schema.md](../reference/models-schema.md).

## When

- The eufy app ships a new release, or a model's handler changes. `eufy-security
  status` and `EufySecurity.model_status()` report a model whose cloud thing description
  is newer than the bundled one (`vendor data newer than bundled (td N > M)`).
- A product code has no bundled file: `model_status()` says `cloud-listed` or
  `unknown`, and `Station.settings_for` lists its settings read-only at most.

## Inputs

All inputs are private and stay out of the repository:

| input | default | how to get it |
|---|---|---|
| thing-model cache: `<cache>/<PN>/td.json` and `<PN>Handle.mix.js` | `.work/cache/things_all` | `scripts/thing_models.py fetch` (below) |
| app labels | `.work/tools/data/app_choice_labels.json` (`--labels`) | the app's choice titles, extracted from the app build named by `--app-version` |
| app settings layout | `.work/tools/data/settings_trees.json` (`--trees`) | the app's settings pages, groups and order, from the same build |
| app shown properties | `.work/tools/data/app_shown.json` (`--shown`) | the properties the app's settings pages read (`pages`) and the ones its device cards and home page read (`cards`), each `{identifier: [where, ...]}`, from the same build; they give each setting its `shown` (`card` wins over `page`) and decide the `role` (status or diagnostic) of a read-only setting and of a write the thing description does not declare and no control offers |
| app setting titles | `.work/tools/data/app_setting_titles.json` (`--titles`) | the app's setting titles (per identifier, per model where the app branches), the units its screens show (`units`: `{identifier: {unit, page, source}}`, the screen's unit winning over the TD's; `unit` null for a bare number, `page` null for a screen that reads the property wherever it sits), what it reads a property as (`meanings`: `{identifier: {meaning, source}}`, `meaning` a `SettingMeaning` value), the binary meaning of each member of a bit status (`flag_meanings`: `{identifier: {members: {member: meaning}, source}}`, binary meanings only, set on a `flags` setting for the members it has; a smoke sensor's status: the state the app's device card shows for each member it shows, by its priority, and for the test members, which no card shows, the library's reading of their names) and legacy identifier pairs, plus app behaviour read by hand: defaults the app shows, read-only statuses, option titles, settings behind a warning, held flags members, excluded actions, the string properties the app shows as an on/off switch with the text it writes for each state (`switches`: such a property is generated as a bool, swept with those texts, its write and read polarity taken from the handler; `bool_switches` (`{identifier: {"source": text}}`) lists those whose switch writes the JSON bool itself, swept with `true`/`false`, a description default `"true"`/`"false"` kept as that state: the manual light `spotlight_switch` and the microphone `microphone_on_off` on a model whose description types them as a string), the properties an app screen writes from an on/off switch (`switch_writes`: `{identifier: {type, on, off, sources}}`, extracted from the app's RN screens that write one of two values by the switch's state, the native HomeBase settings screen's switch checked against the app's code by hand; `type` is the write type, `Int`, `Bool` or `String`, and `on`/`off` the values the handler gets for each state: a property the description leaves without a domain (kind `other`) is generated as a bool swept with them, the HomeBase alarm delay; other kinds keep their own domain, a `domains` rule for the property applies first and wins, and a bare property also listed in `object_writes` fails the model: two rules for one value), the JSON objects the app's screens write for a property (`object_writes`: `{identifier: {source, payloads: [object, ...]}}`, at least two distinct objects; the handler is driven with each, whatever the property's `access_mode`, and the property becomes an `object` setting where an object form reproduces its recipes (and, for a property the thing description does not declare writable, the handler reads the stored value back), see [models-schema.md § Object writes](../reference/models-schema.md#object-writes)) and the enum choices whose app screen writes another value than the thing description lists (`screen_values`: continuous recording time writes 0 for `default:00`, the motion light's on-time `timer_for_lights` the seconds 30, 60, 180, 300 and 900 for its choices 0-4; the handler is swept with the screen's value, the public value stays the description's), the domain the app's screen offers for a property (`domains`: `{identifier: {kind, labels | min/max/step, td, fallback, source}}`, `kind` `enum` with integer-keyed labels or `range`; applied to the property before the handler sweep, `td` `replace` on every model (the screen never reads the description's domain: the storage type's two choices, the response delay's 0s/5s/10s/15s) or `fill` only where the description declares no values or range, whatever its type (the chime ring volume 1-26, the library's reading of two app screens; the 12/24-hour time format); an enum's labels are the screen's texts as written; `fallback`, an enum value, is what the screen shows for any other value: it becomes the read's `fallback` and replaces a description default outside the labels (the recording type: Continuous), and without it such a default is dropped; the domains come with the bundled model files only) and the values the app's screen builds and parses as JSON itself (`structured`: `{identifier: {source}}`, marked `structured` on every model: the light schedule); from the same build |
| app write routing | `app_routing.json` beside the app setting titles (`--routing`) | which frame form the eufy app sends each command in, the request type and value field it builds per command, and its native settings screens' own write forms, from the same build ([below](#the-routing-input)) |

Node is needed for generating and for `--check`, and nowhere else: the handler runs in
a `vm` sandbox (`scripts/gen_models_driver.js`), a fresh one per batch of requests. The
generators need the Node major that `scripts/package.json` pins (`engines.node`) and
refuse any other major with an error that names the version in use. `gen_models.py`
keeps the handler's replies in an [answer store](#the-answer-store) and asks Node only
for batches it has not seen.

## Fetch

`fetch` uses a cached cloud session (log in with `eufy-security login` first; the
script never logs in) and writes one directory per product code:

```
uv run python scripts/thing_models.py fetch --store <cache.json> --out .work/cache/things_all
uv run python scripts/thing_models.py fetch --store <cache.json> --out .work/cache/things_all \
    --product-code T8160 --product-code T8170
```

Without `--product-code` it fetches the account's own models. To refresh every bundled
model, pass each code of `INDEX.json`.

## Generate

```
uv run python scripts/gen_models.py              # every model in the cache
uv run python scripts/gen_models.py T8160 T8170  # some models
```

`--jobs N` (default: the CPU count) generates N models at a time, each in its own
process with one long-lived Node worker; the output does not depend on it. On Ctrl-C or
SIGTERM no queued model starts: a SIGTERM to the run's process alone lets the models in
flight finish, one to the process group (or Ctrl-C) ends them too. When the run's own
process is killed, its generating processes and Node workers end with it.

A model is written only when every codec renders back each swept recipe and every row
of `tests/fixtures/models_v1_reference.json` for that model renders to its recorded
`cmd`/`subCmd`/`params`. A model that fails (a check, or an input the generator does not
handle, such as a unit without a mapping) is reported and not written; the run goes on
with the other models and exits 1 at the end. A job that Node or its handler does not
run (a worker that cannot start, dies on every rerun of the job or does not reply within
the job timeout) stops the run with exit 2: the model's driver notices, then the cause on
one line. A
reference row that is meant to change (the vendor changed the recipe) goes into
`RELEASE_ACCEPTED` in `scripts/gen_models.py`, keyed `(PN, identifier)`, with the reason.
`INDEX.json` lists every `<PN>.json` in the output directory, so a new product code is
bundled by generating its file.

Which keys a release shipped is an input too: `scripts/data/released_keys.json` (a
generator input, not shipped in the package) lists per product code every setting key a
release bundled. A variant that duplicates its primary is left out of a file unless that
list names its key, so a key never disappears after it shipped; the output directory's
earlier contents play no part. A released product code must stay in `INDEX.json`:
`tests/devices/test_models_release_check.py` fails when a listed code or key is no longer
bundled. After each release, union its keys into the list and commit it (a ref without
bundled models exits 2):

```
uv run python scripts/gen_models.py --update-released <tag>   # the release just tagged
```

A released key the model's current thing description no longer declares cannot be
generated. It goes into `scripts/data/retired_keys.json` (same form: product code ->
sorted keys), which the release checks subtract; `released_keys.json` keeps it. A
retired key must be in the manifest and absent from the model's file: one that comes
back leaves the list. A retired key is a breaking change for a consumer whose entity
ids use it: name each in the release notes.

The live-open table (`devices/_live_open_data.py`: which library open reproduces each
product handler's `open_live_stream`, per connect type) is generated from the same cache:

```
uv run python scripts/gen_live_open.py           # rewrite the table
uv run python scripts/gen_live_open.py --check   # compare, write nothing
```

The product names (`devices/_model_names_data.py`, read by `DeviceModel.name` and
`product_name`) come from the name table each product handler carries: per product code
a base name and the serial rules that name single units, in three steps. The product's
own table where it names the prefix, as the eufy app shows it; else, as the library's
choice, the newest table that names the prefix; else no row, and the library derives the
name from the app's model constant. A product whose thing description declares no
`device_model` is named the same way, though the app shows no such name for it. The
generator parses the tables, then checks the parse against every handler that declares
`device_model` (Node; a handler may answer the cloud record's product code where its
table names nothing), and writes nothing when one disagrees:

```
uv run python scripts/gen_model_names.py           # rewrite the table
uv run python scripts/gen_model_names.py --check   # compare, write nothing
```

The WebRTC route inputs (`devices/_webrtc_routing_data.py`: every product's
`is_connect_webrtc*` properties with their default and conditions, read by
`devices.webrtc`) come from the thing descriptions alone (no Node):

```
uv run python scripts/gen_webrtc_routing.py           # rewrite the table
uv run python scripts/gen_webrtc_routing.py --check   # compare, write nothing
```

The lock command routes (`devices/_lock_routes_data.py`: per lock product, the command
form each serial takes, its MQTT rule, the parameter that switches a 1930 frame to ECDH
and the firmware thresholds of the HKDF key, read by `devices.lock_routes`) come from the
per-model lock configuration extracted from the app build (private input
`.work/tools/data/lock_routes.json`) and a Remote Config fetch (`--remote-config`, default
`.work/tools/data/firebase_rc_EE.json`) whose values replace the app's defaults when present:

```
uv run python scripts/gen_lock_routes.py           # rewrite the table
uv run python scripts/gen_lock_routes.py --check   # compare, write nothing
```

The pan/tilt/zoom table (`devices/_ptz_data.py`: per product whose thing description
declares a pan/tilt, preset or zoom action, the library recipe form that reproduces the
handler's, per connect type) is generated the same way:

```
uv run python scripts/gen_ptz.py                 # rewrite the table
uv run python scripts/gen_ptz.py --check         # compare, write nothing
```

The device-alarm table (`devices/_device_alarm_data.py`: per product whose thing
description declares `set_alarm_type`, per connect type, the alarm choices the app offers
and the request its handler sends to start and stop each, read by
`devices.device_alarm`) is generated the same way:

```
uv run python scripts/gen_device_alarm.py           # rewrite the table
uv run python scripts/gen_device_alarm.py --check   # compare, write nothing
```

The station configuration table (`devices/_station_config_data.py`: per station model,
which configuration features the app offers and the library sends as its handler does,
where the model keeps its per-mode tables, the cross-camera tracking times, firmware
gates and the restart request) comes from the same cache plus two app inputs: the
app's HomeBase capability table (`hb_capability_config.json`, in the directory
`--data` names) and a Remote Config fetch (`--remote-config`). The defaults point
into `.work/`, since the inputs are private:

```
uv run python scripts/gen_station_config.py      # rewrite the table
uv run python scripts/gen_station_config.py --check
uv run python scripts/gen_station_config.py --data DIR --cache DIR --remote-config FILE
```

Hardware grades (*verified*) are not generated: they live in
`devices/station_config_support.py`, each traced to a row of
[hardware-verification.md](../reference/hardware-verification.md). Regenerate the
support matrix afterwards (`scripts/gen_device_matrix.py`).

## Check

```
uv run python scripts/gen_models.py --check      # regenerate to a temp dir, compare bytes
```

`--check` exits 0 when every file is byte-identical, 1 on any difference (it names the
files) and 2 when Node (of the pinned major), the cache, the labels, the layout or the
title data are missing. Run it on the whole corpus after changing the generator;
`tests/devices/test_gen_models_check.py` runs it on three models and skips without Node
of the pinned major or the cache, as every test that runs the driver does.

Every generator's `--check` at once, in parallel (one line per generator, the output of
each that fails; exit 1 when any fails):

```
uv run python scripts/check_generated.py                   # all of them
uv run python scripts/check_generated.py --skip gen_models # all but the settings files
uv run python scripts/check_generated.py gen_ptz gen_live_open
```

The model list (`gen_app_models.py`) takes the app's input files as arguments and is
checked on its own.

## The routing input

The generator emits a write only in the frame form the eufy app sends
([models-schema.md § Write routing](../reference/models-schema.md#write-routing)). Its
input is generated from the app build by a private offline extractor: the frame form per
command from the app's own send handler (its command switch, each form named by a probe
command and checked to cover the library's frame-form sets), the request type and the
value field per command from the app's request builder (checked against known cases), and
the native settings screens that send a command themselves. The write forms the generator
uses for those screens are written from the screens' code and checked against it on every
extraction (the calls they make, the fields and integer types of the objects they
serialise). Re-extract it for each app release with the other
app inputs; the extractor's check mode fails when a fresh extraction differs from the
file. `gen_models.py` refuses to run (exit 2) when the file's frame-form sets or value
fields differ from the library's (`p2p.messages`), so a release that moves a command
fails loudly: move the library's table to match (with its tests) and regenerate.

## The answer store

Nearly all of a run's time is the handler answering the generator's requests. A driver
job's reply depends only on the Node runtime, the driver, the handler file and the job's
requests (each job runs in a fresh sandbox with a seeded `Math.random` and a fixed
clock), so `gen_models.py` keeps every reply in a store keyed by the SHA-256 of exactly
those: Node's `process.versions` (Node, V8, ICU, time zone data), the time zone and
locale Node resolves (from `TZ` or the host's `/etc/localtime`, from the locale
variables) with the zone's UTC offsets over a year and its rendering of the driver's
fixed clock, the environment variables a reply can depend on (`TZ`, `LANG`, `LANGUAGE`,
every `LC_*`, `NODE_OPTIONS`, `NODE_ICU_DATA`), the bytes of
`scripts/gen_models_driver.js` and of `<PN>Handle.mix.js`, and the requests as the driver
receives them. A run replays every job it finds and asks Node for the rest:

- a change to the Python side that leaves the requests as they were (how replies are
  read, joined or written) replays every job: a fix round costs the Python work only;
- a change that alters some requests (a new probe, another sweep value) asks Node for
  the jobs it alters, for every model;
- a new handler, a driver change, another Node build or another time zone or locale
  asks Node again for the models they touch.

The store is private, since the replies come from vendor code: `--answers DIR`, default
`.work/cache/gen_models_answers`, one file per model (`<PN>.answers`; worktrees that link
`.work` share it). Each record carries a SHA-256 of its reply: a record that does not
decompress, fails that check or does not fit its job is asked again, as are the records
after a damaged or truncated spot. After a model is generated, its file holds the jobs
that run asked, so replies no request names any more are dropped; a model that fails
keeps its earlier records too. A job whose key cannot be made (Node does not answer the
runtime query, or the driver or handler cannot be read) goes to Node and is not stored,
and its model drops nothing; a failed runtime query is reported once per run. A file
is written to a temporary name and renamed into place, and a store that cannot be written
is reported and the run goes on without it. A run killed while it writes a file can leave
a hidden `.<PN>.answers.<pid>.tmp` beside it, which no run reads; delete it. Do not fetch
the handler cache while a run is going: the worker compiles a handler again when its file
changes, but a reply asked between the store's read and the worker's could be stored
under the other file's key.

Every run that uses the store and finishes prints `answers: <n> jobs replayed, <m> asked
of Node` to stderr, with `, <j> asked without the store` for jobs that had no key and
`, <k> damaged in the store` when it found damaged records or files. To ask Node for
everything, clear the store or bypass it:

```
rm -r .work/cache/gen_models_answers                 # all models
rm .work/cache/gen_models_answers/T8170.answers      # one model
uv run python scripts/gen_models.py --check --no-answers  # read and write no store
```

The other generators run few handler jobs and keep no store.

## The model list

The model list (`devices/app_models.py`: every serial prefix the app names, with its
kind, product categories and cloud device type) comes from the same app build, through
`scripts/gen_app_models.py`; see
[add-a-device.md § The model](add-a-device.md#1-the-model). Regenerate it with the
settings files, then the support matrix. The app build's thing-SDK version, which
`sdk_version` conditions compare, is `THING_SDK_VERSION` in `devices/conditions.py`:
set it to that build's version when the cache moves to a new build.

## Before a release

1. Generate, then `--check` on the whole corpus: `check: 0 files differ`. Regenerate
   the model list (`gen_app_models.py`, `--check` to compare).
2. Regenerate the support matrix, which lists every model's settings:
   `uv run python scripts/gen_device_matrix.py`. Then `scripts/check_generated.py`:
   every generated table up to date.
3. Update the settings counts in [home-assistant.md](home-assistant.md#settings-per-model)
   if a listed model changed; `tests/devices/test_docs_home_assistant.py` recomputes them.
4. Run `uv run pytest tests/devices tests/test_package_data_models.py`: the schema of
   every file, the index against the files, and the wheel's file set.
5. Review the diff of the model files: a key that disappears is a breaking change for a
   consumer whose entity ids use it.
6. Once the release is tagged, run `gen_models.py --update-released <tag>` and commit
   `scripts/data/released_keys.json`; until then
   `test_the_manifest_holds_every_key_of_the_latest_release` fails (it is skipped in a
   checkout without git tags).
