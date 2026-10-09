# eufy-home-security

[![PyPI](https://img.shields.io/pypi/v/eufy-home-security)](https://pypi.org/project/eufy-home-security/)
[![Python](https://img.shields.io/pypi/pyversions/eufy-home-security)](https://pypi.org/project/eufy-home-security/)
[![CI](https://github.com/alaraun/python-eufy-home-security/actions/workflows/ci.yml/badge.svg)](https://github.com/alaraun/python-eufy-home-security/actions/workflows/ci.yml)
[![Ko-fi](https://img.shields.io/badge/Ko--fi-support-FF5E5B?logo=ko-fi&logoColor=white)](https://ko-fi.com/alaraun)

Asyncio Python library and command-line tool for **eufy Security** systems. It talks
to the HomeBase and its cameras directly over the local network, and uses eufy's cloud
only for login, keys and push events. It is written for a Home Assistant integration,
but it has no Home Assistant dependency and works on its own.

> **Status: beta, incomplete.** This is a 0.x release. It works day to day on the
> hardware it was developed against, but device coverage is narrow, much of the
> device support is unproven, and the API may change in any release. Do not make it
> the only thing between you and an intruder: keep the eufy app installed.
> Not affiliated with Anker or eufy.

## What it does

- **Local P2P to the station**: guard mode, status (battery, signal, storage,
  firmware), device settings, live video and audio, stored recordings and stills, the
  station's event history, and pan/tilt presets. Once connected, commands and state
  stay on your LAN.
- **eufy cloud** (the `eufy_mega` backend): login with the e-mailed code or captcha,
  the device list, the per-station keys a local session needs, and firmware-update
  notices.
- **Push events over FCM**: guard-mode changes made elsewhere (app, keypad, schedule),
  and events when the host is not on the station's LAN.
- **A session cache**, so a restart needs no cloud call.
- **Per-model settings from eufy's own code**: each product's settings (values, labels,
  units, how to write and read them) are generated from the thing description and
  handler the eufy app downloads, and ship with the library for 107 products.
- **Every product the eufy app names**: the model list (161 serial prefixes, with kind
  and cloud device type) is generated from the app's own tables, so a camera is
  recognised as a camera even when nobody has tested it.
- **Support graded as data**: every model and capability carries *verified* (proven on
  hardware), *declared* (from the eufy app, not proven) or *unknown*, with its source,
  so a consumer can tell what is proven.

Pure `asyncio` on `aiohttp`, `cryptography`, `firebase-messaging` and `protobuf`: no
Node.js bridge, no add-on, no threads.

## Status

| area | state |
|---|---|
| HomeBase 3 (T8030) with eufyCam 3 (T8160) | the primary target. Login, local session, status, guard mode, camera settings, live stream, recordings, stills, local and push events are verified on hardware |
| Battery SoloCam (T8170), standalone | guard mode, status, live stream, pan/tilt presets and control, zoom, and settings (write + read-back) verified. The camera sleeps, so each call first wakes it (seconds) |
| Motion sensor (T8910) | battery and signal read through the station; of its settings, only the per-mode delays and actions were written |
| HomeBase 2 (T8010) | local session reported working by users (version-8 handshake); its cameras (eufyCam 2 / 2C / 2 Pro / 2C Pro) are *declared*, live view through it not yet confirmed |
| other HomeBases and cameras | *declared* only: known from the app, never tested. Every product the app names is in the model list; settings files for 107 products ship with the library, generated from eufy's own code; a product without one is listed read-only from the cloud |
| per-mode actions and delays | readable and writable; the Home, Away and Custom 1 delays are verified by write + read-back, the action flags' names are not checked against the app |
| firmware updates | reported, never installed |
| API | not stable: names and signatures may change in any 0.x release |
| packaging | a pure-Python wheel with typing (`py.typed`) on PyPI |

The full picture is in the generated [support matrix](https://github.com/alaraun/python-eufy-home-security/blob/main/docs/reference/devices.md) and
the [hardware verification page](https://github.com/alaraun/python-eufy-home-security/blob/main/docs/reference/hardware-verification.md). A setting comes from
eufy's code, not from a test on hardware: it may be rejected by a device, and the
page names the ones written and read back.

## Requirements

- Python 3.13 or newer.
- A eufy Security account that can see the station: the owner's, or a member it is
  shared with (commands are sent on the owner's behalf).
- For local access, a host on the **same L2 network** as the station: discovery is a
  broadcast, and a routed host cannot reach it. Login and push work from anywhere.
- If inbound UDP is filtered: a fixed IP and a pinned local port per station.
  `eufy-security network` prints what each station needs.

## Install

```
uv add eufy-home-security                       # the library, in a uv project (or: pip install eufy-home-security)
uv tool install eufy-home-security              # the eufy-security CLI on PATH
uvx --from eufy-home-security eufy-security --help   # run once
```

The development version: `uv add "eufy-home-security @ git+https://github.com/alaraun/python-eufy-home-security"`,
or from a checkout `uv sync && uv run eufy-security --help`.

## Usage

### Command line

```
eufy-security login                 # asks for the password and the e-mailed code once
eufy-security status                # guard mode, firmware, storage, every paired device
eufy-security guard set home
eufy-security settings --model T8160 # a model's settings, keyed by eufy's identifiers
eufy-security set detection_sensitivity 4 --channel 0
eufy-security live --channel 0 --seconds 10 --out clip
eufy-security monitor               # print events as they arrive
```

The password is never a flag: it comes from `$EUFY_PASSWORD`, the session cache or a
prompt. Every command is in [the CLI reference](https://github.com/alaraun/python-eufy-home-security/blob/main/docs/reference/cli.md).

### Library

```python
import asyncio

import aiohttp

from eufy_home_security import EufySecurity, JsonFileStore, LoginChallengeError


async def main() -> None:
    async with aiohttp.ClientSession() as http:
        eufy = EufySecurity(
            http, "you@example.com", "password", store=JsonFileStore("~/.eufy-cache.json")
        )
        try:
            await eufy.async_login()
        except LoginChallengeError as challenge:
            if challenge.kind != "verify_code":
                raise
            await eufy.async_login(verify_code=input("code from the e-mail: "))

        station = (await eufy.async_discover())[0]
        state = await station.async_update()
        print(station.name, state.guard_mode, state.firmware)

        await station.async_set_guard_mode("home")  # returns once the station confirms
        await eufy.async_close()


asyncio.run(main())
```

Events from the local session and from push arrive on one stream:

```python
eufy.subscribe(print)
await eufy.async_start()  # local sessions and cloud push, until async_close()
```

Arming returns only after the station confirms it; a setting write returns how far it
got (`CommandOutcome`). A failure raises a typed error from
`eufy_home_security.exceptions`.
The cache file holds the cloud session, the station keys and the account password:
keep it private.

More in [getting started](https://github.com/alaraun/python-eufy-home-security/blob/main/docs/getting-started.md) and, for an integration, the
[Home Assistant guide](https://github.com/alaraun/python-eufy-home-security/blob/main/docs/how-to/home-assistant.md).

## Documentation

| | |
|---|---|
| [Getting started](https://github.com/alaraun/python-eufy-home-security/blob/main/docs/getting-started.md) | install, login, arm, settings, events |
| [Home Assistant integration](https://github.com/alaraun/python-eufy-home-security/blob/main/docs/how-to/home-assistant.md) | how an integration uses the library: cache, reauth, ids, network, coordinators, events, entities, stills, streaming, errors |
| [Command line](https://github.com/alaraun/python-eufy-home-security/blob/main/docs/reference/cli.md) | every `eufy-security` command |
| [Support matrix](https://github.com/alaraun/python-eufy-home-security/blob/main/docs/reference/devices.md) · [Hardware verification](https://github.com/alaraun/python-eufy-home-security/blob/main/docs/reference/hardware-verification.md) | what is supported, and what is proven on hardware |
| [Add or verify a device](https://github.com/alaraun/python-eufy-home-security/blob/main/docs/how-to/add-a-device.md) | how support is declared and proven |
| [Regenerate the settings files](https://github.com/alaraun/python-eufy-home-security/blob/main/docs/how-to/regenerate-models.md) · [Settings file schema](https://github.com/alaraun/python-eufy-home-security/blob/main/docs/reference/models-schema.md) | how the per-model settings are generated, and their format |
| [Debug logging](https://github.com/alaraun/python-eufy-home-security/blob/main/docs/how-to/debug-logging.md) | loggers, wire dumps, redaction |
| [Testing](https://github.com/alaraun/python-eufy-home-security/blob/main/docs/how-to/testing.md) | end-to-end tests with `eufy_home_security.testing` |
| [Thing models](https://github.com/alaraun/python-eufy-home-security/blob/main/docs/reference/thing-models.md) | the app's per-model descriptions and handler recipes |
| [Protocol reference](https://github.com/alaraun/python-eufy-home-security/blob/main/docs/protocol/README.md) | cloud, P2P transport, session crypto, commands, events, media |

## Contributing

Reports from other hardware help most: `eufy-security status --raw` and
`eufy-security coverage` show what a station reports, and
[add a device](https://github.com/alaraun/python-eufy-home-security/blob/main/docs/how-to/add-a-device.md) explains how an entry becomes *verified*.
Never post serials, credentials or captures from your home; see
[CONTRIBUTING.md](https://github.com/alaraun/python-eufy-home-security/blob/main/CONTRIBUTING.md) and [SECURITY.md](https://github.com/alaraun/python-eufy-home-security/blob/main/SECURITY.md).

```
uv sync
uv run pytest -n auto
uv run ruff check && uv run ruff format --check
uv run mypy
```

## Support

This project is built in spare time and is free to use. If it is useful to you,
donations are welcome. They are voluntary, buy no support or priority, and are not
tax-deductible.

- [Ko-fi](https://ko-fi.com/alaraun)

Donated eufy hardware helps develop future features; please get in touch first.

## License

MIT. eufy and Anker are trademarks of Anker Innovations; this project is not
affiliated with or endorsed by them.
