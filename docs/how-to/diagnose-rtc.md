# Help test WebRTC stations: `eufy-security diagnose rtc`

The eufy app reaches some stations only over WebRTC: by its routing data the
T8N00, T9000, T7000 and T8040 stations, and on some firmware it streams cameras behind
other stations the same way (a T8215, T8223 or T8224 behind a HomeBase 3, for example). The
library does not serve these stations yet. `eufy-security diagnose rtc` checks, on your
own station, how far the library's WebRTC client gets and what the station answers, so
that support can be built on facts rather than guesses. It changes nothing.

## Run it

You need Python 3.13 or newer and [uv](https://docs.astral.sh/uv/). The WebRTC code
comes with the `rtc` extra:

```
uvx --from 'eufy-home-security[rtc]' eufy-security login
uvx --from 'eufy-home-security[rtc]' eufy-security diagnose rtc
```

`login` asks for your eufy account's e-mail and password (and a code eufy e-mails you)
and keeps the session in `~/.config/eufy-security/cache.json` on your machine. Logging
in with an account that another client of this library (a Home Assistant integration, a
script) already uses ends that client's cloud session; an account the owner shared the
station with avoids that.

`diagnose rtc` takes about a minute per station: it picks every station on the account
the eufy app reaches over WebRTC, prints a summary, and writes
`eufy-rtc-diagnose-<number>.json` in the current directory. Options:

| option | |
|---|---|
| `SERIAL` | only this station, whatever its route (for example a HomeBase 3 whose camera the app streams over WebRTC) |
| `--seconds N` | how long to record what the station sends on its own (default 60, at most 600) |
| `--probe-kinds` | also ask once for each of three older channel kinds; only the answer codes are kept |
| `--out FILE` | where to write the report |

Without the extra it stops before logging in and prints the install command.

## What it does and does not send

It talks to eufy's cloud (log in, read the device list) and to eufy's WebRTC signaling
servers, through which it reaches the station:

1. reads the station's WebRTC settings from the device list and how the app routes each
   device paired to it (nothing is sent);
2. logs in to the signaling server, as the eufy app does;
3. asks the station for its command channel (one call), as the app does when it opens;
4. connects that channel (ICE);
5. listens on it for `--seconds`, recording what the station sends unasked;
6. with `--probe-kinds`, places one call of each older kind and hangs up.

It sends **no command** to the station: no setting, no guard mode, no live view, no
download, nothing on the command channel. It registers no push notifications, opens
no local (P2P) session and writes nothing to your account. The station sees what it sees
when the eufy app connects and stays idle.

## What the file contains

For each station, per step: whether it worked, how long it took, and the error's type
and code when it did not. Then the facts the support needs:

- which WebRTC settings the station's record has, its firmware and WebRTC SDK version,
  its devices' models and channels;
- the station's answer to the call: the names of its fields, its `transport_caps` (the
  data-channel transports it offers), the shape of its session description (lengths and
  flag bytes, not the values);
- the kinds of ICE candidates on each side (host, server-reflexive, relay) and the pair
  that connected;
- for every message the station sent unasked: its type, length, header bytes and
  channel; never its content;
- with `--probe-kinds`, the answer codes of the older channel kinds.

It does **not** contain your e-mail, password, account or user id, serial numbers (only
the model and the last four characters, as `T8N00***1234`), the station's P2P id or
license, keys, IP addresses (only their kind: private, public, loopback), candidates or
any message content. Read it before you share it: it is plain JSON.

`--secrets` (a maintainer may ask for it privately, never in public) writes the raw
values (serial, P2P id and license, contact id, addresses, the station's full answer,
the first bytes of each message) to a second file, `<name>.secrets.json`, readable by
you only, and prints a warning. The report itself stays the same.

## Send it

Attach the `.json` report (not a `.secrets.json`) to the GitHub issue that asked for
it, or open one at <https://github.com/alaraun/python-eufy-home-security/issues> with
your station's model and what the summary printed. The command reference is in
[cli.md](../reference/cli.md#commands); the protocol is described in
[rtc-signaling.md](../protocol/rtc-signaling.md).
