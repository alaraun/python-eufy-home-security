# Regenerate the settings files

The per-model settings (`src/eufy_home_security/devices/data/models/<PN>.json` and
`INDEX.json`) are generated offline from the eufy app's thing models and ship with each
release. Nothing at runtime fetches or runs vendor code: a newer handler reaches users
only through a regenerated file in a library release. The format is in
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
| app setting titles | `.work/tools/data/app_setting_titles.json` (`--titles`) | the app's setting titles (per identifier, per model where the app branches), control units and legacy identifier pairs, from the same build |

Node is needed for generating and for `--check`, and nowhere else: the handler runs in
a `vm` sandbox (`scripts/gen_models_driver.js`).

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

A model is written only when every codec renders back each swept recipe and every row
of `tests/fixtures/models_v1_reference.json` for that model renders to its recorded
`cmd`/`subCmd`/`params`. A model that fails is not written, and the run exits 1. A
reference row that is meant to change (the vendor changed the recipe) goes into
`RELEASE_ACCEPTED` in `scripts/gen_models.py`, keyed `(PN, identifier)`, with the reason.
`INDEX.json` lists every `<PN>.json` in the output directory, so a new product code is
bundled by generating its file.

The live-open table (`devices/_live_open_data.py`: which library open reproduces each
product handler's `open_live_stream`, per connect type) is generated from the same cache:

```
uv run python scripts/gen_live_open.py           # rewrite the table
uv run python scripts/gen_live_open.py --check   # compare, write nothing
```

## Check

```
uv run python scripts/gen_models.py --check      # regenerate to a temp dir, compare bytes
```

`--check` exits 0 when every file is byte-identical, 1 on any difference (it names the
files) and 2 when Node, the cache, the labels, the layout or the title data are missing.
Run it on the whole corpus after changing the generator;
`tests/devices/test_gen_models_check.py` runs it on two models and skips without Node or
the cache.

## The model list

The model list (`devices/app_models.py`: every serial prefix the app names, with its
kind and cloud device type) comes from the same app build, through
`scripts/gen_app_models.py`; see
[add-a-device.md § The model](add-a-device.md#1-the-model). Regenerate it with the
settings files, then the support matrix.

## Before a release

1. Generate, then `--check` on the whole corpus: `check: 0 files differ`. Regenerate
   the model list (`gen_app_models.py`, `--check` to compare).
2. Regenerate the support matrix, which lists every model's settings:
   `uv run python scripts/gen_device_matrix.py`.
3. Update the settings counts in [home-assistant.md](home-assistant.md#settings-per-model)
   if a listed model changed; `tests/devices/test_docs_home_assistant.py` recomputes them.
4. Run `uv run pytest tests/devices tests/test_package_data_models.py`: the schema of
   every file, the index against the files, and the wheel's file set.
5. Review the diff of the model files: a key that disappears is a breaking change for a
   consumer whose entity ids use it.
