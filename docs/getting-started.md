# Getting started

## Requirements

- Python 3.13+
- A eufy Security account that can see the station (the owner's, or a shared
  member's — commands are sent on the owner's behalf automatically).
- For local P2P: a host on the **same L2 network** as the HomeBase. LAN discovery is
  a broadcast; a routed host cannot reach the station. Cloud login and push work
  from anywhere.
- If the host or the network filters inbound UDP: a fixed IP for each station (a DHCP
  reservation), and either all UDP from the station allowed, or one pinned local port
  per station (`local_ports=`) allowed. `eufy-security network` prints what each of
  your stations needs.
- **Current station/camera firmware.** The library speaks the current P2P session
  handshake (ECIES, CONN_INIT version 8). A device still on outdated firmware that
  negotiates the legacy RSA handshake (CONN_INIT version 1) is **not supported**: eufy's
  cloud serves that path's key corrupted (lowercased), so neither this library nor the
  eufy app can establish the session — the station reports `key_unusable` and stays
  unavailable. Update the device's firmware in the eufy app; there is no library-side
  workaround. See [protocol/session-crypto.md](protocol/session-crypto.md#rsa-conn_init-declared-app-legacy).

## Install

```
uv add eufy-home-security                            # or: pip install eufy-home-security
```

## Log in and read a station

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
        for device in state.devices.values():
            print(" ", device.name, device.battery, device.rssi)
        await eufy.async_close()


asyncio.run(main())
```

The store caches the cloud session, the station owner's id, the station's cipher
key **and the device list**, so a warm start needs no cloud call at all — it reads
the cached list and talks to the station over the LAN. Force a fresh device list
with `await eufy.async_discover(refresh=True)`. Keep the file private: after a
successful login it also holds the account password, so later runs may pass `None`
and still log in again by themselves when the session expires. `password` may also
be an async callable: it is awaited only when a login really happens and no password
is cached, so an interactive program can prompt just in time.

## Arm, change a setting

```python
await station.async_set_guard_mode("away")  # returns the mode the station applied
await station.async_set_setting("detection_sensitivity", 4, device_sn=camera_sn)
```

Setting keys are eufy's own identifiers for the model (`station.settings_for(camera_sn)`
lists them, `eufy-security settings --model T8160` prints them). Arming returns once
the station has confirmed the mode. A setting write returns a `CommandOutcome`:
`APPLIED` when the station answered, `DELIVERED` when it only acknowledged the
datagram; the next parameter dump shows the value. Otherwise it raises:

| Exception | Meaning |
|---|---|
| `CommandNotAppliedError` | The station received it and did nothing — usually not the owner's account id |
| `CommandRejectedError` | The station answered with an error code (`.code`) |
| `DeviceTimeoutError` | No answer at all |
| `UnsupportedError` | Unknown setting, not writable (its `note` says why), or the device is not paired to this station |

What each model supports, how well it is proven, and every model's settings are in
[reference/devices.md](reference/devices.md).

## Events

```python
from eufy_home_security import GuardModeChanged, SecurityEvent


def on_event(event) -> None:
    if isinstance(event, SecurityEvent):
        print(event.source, event.device_name, event.detection)
    elif isinstance(event, GuardModeChanged):
        print("guard mode", event.mode, "via", event.source)


eufy.subscribe(on_event)
await eufy.async_start()  # local sessions + cloud push; runs until async_close()
```

Two channels feed the same stream, tagged by `event.source`:

- **P2P** (`EventSource.P2P`) — camera detections straight from the station, about
  a second before the cloud, without internet. Guard-mode reports arrive as
  `GuardModeChanged`, parameter changes as `ParamChanged`.
- **Cloud** (`EventSource.CLOUD`) — FCM push. It carries guard-mode changes made
  elsewhere (app, keypad, schedule) also while no local session is up, and it is the
  only channel that works off the LAN.

Run both. Sessions reconnect on their own; `ConnectionChanged` reports it.

## In Home Assistant

- Pass HA's shared session (`async_get_clientsession(hass)`) and a
  `homeassistant.helpers.storage.Store` — it already has the `async_load` /
  `async_save` shape the library expects.
- List `"loggers": ["eufy_home_security"]` in `manifest.json`.
- Map `AuthenticationError` → reauth, `CommunicationError` → retry/unavailable,
  `LoginChallengeError` → a config-flow step asking for the code.

## Command line

The same API as a tool, for trying things out and verifying devices:

```
eufy-security login
eufy-security status
eufy-security guard set home
eufy-security settings
eufy-security monitor
```

`eufy-security --help` lists everything.
