# MQTT: the eufy security broker

The eufy app reaches some devices, its Wi-Fi smart locks first, through an MQTT broker
of eufy's instead of a P2P session. `eufy_home_security.mqtt` holds the client side of
that transport: the certificate, which devices use it, the topics and the message
envelope, and an asyncio client. The command a device runs (the `trans` text) is the
caller's: this layer carries it as given.

Everything here is **[app]**: taken from the eufy app, not yet tested against the eufy
cloud or broker.

## Which devices

A device is an MQTT device when both hold:

- its device-list entry's `category` is one of `eufy_security`, `eufy_care`,
  `eufy_pet` (an entry without a category counts as `eufy_security`); the app's lights
  (`eufy_life`) have a client of their own;
- its model's thing description declares the property `is_support_mqtt` with default
  `true`. The model is the entry's `device_new_pn`, else the product its serial names.

The property is read from the bundled settings files (`devices/data/models/<PN>.json`),
never from a list of device types, so a regenerated data set moves products in or out by
itself. In the bundled data these models declare it: T8501, T8531, T8532, T85D0, T85D2,
T85F0, T85F1, T85L0, T85L1, T85M0, T85M1, T85P0, T85P1, T85V0, T8028 and T6010. T8L04, a
light, declares it too and is picked only when its entry's category is one of the three. `eufy_home_security.mqtt.mqtt_devices()`
applies the rule to a device list.

With no MQTT device on the account the app asks for no certificate and opens no
connection; the library does the same.

## The certificate

The client authenticates with a TLS client certificate the cloud issues per account and
login scope:

```
POST https://<mega domain>/app/mqtt/register/iot
app-tab: eufy_security
(empty body, signed and encrypted like every eufy_mega request; see cloud.md)
```

The host is the `mega-` domain of the session (`const.mega_host(cluster)` without
one). The answer's `data` carries:

| field | use |
|---|---|
| `user_id` | part of the client id |
| `app_name` | part of the client id (`eufy_security`) |
| `endpoint_addr` | the broker's host name |
| `certificate_pem` | the client certificate |
| `private_key` | its private key (PEM) |
| `thing_name`, `certificate_id` | kept; the connection needs neither |

The first five are required; an answer without them is a `ProtocolError`.
`EufyCloudApi.async_register_iot()` makes the request; `async_mqtt_certificate()`
applies the app's rules for reusing it:

- The certificate is kept per login scope in the session cache, with the set of MQTT
  devices it was asked for, each as `<serial>-<bind_time>` (the entry's `bind_time`).
- While that set is unchanged the cached certificate is used and nothing is requested,
  across restarts too.
- A changed set (a lock added, removed or bound again) asks for a new certificate; when
  that request fails, the cached one is used.
- After three lost connections the client drops the cached certificate
  (`async_drop_mqtt_certificate()`), so its next connect asks for a new one. A store
  that cannot save the drop logs a WARNING (once per 5 minutes) and the client
  reconnects all the same.
- A publish while no certificate was obtained asks for one at once, without waiting out
  the reconnect back-off.

The certificate, its key and the thing name are masked in every log line and never shown
in a repr.

## Connecting

| | |
|---|---|
| broker | `endpoint_addr`, port 8883, TLS 1.2 or newer, the server verified with the system's trust store |
| client certificate | `certificate_pem` + `private_key` |
| client id | `android-<app_name>-<user_id>-<openudid>`, the `openudid` being this install's own (the one the library sends the cloud) |
| protocol | MQTT 3.1.1, clean session, keepalive 300 s |
| user name | `?SDK=Android&Version=2.81.0`, as the eufy app's MQTT SDK sends it; no password |
| subscriptions | the answer topic of every MQTT device, QoS 1 |

The PEM pair is written to a private temporary directory (mode 0700, files 0600) only for
as long as the TLS context takes to load it, in a worker thread; nothing stays on disk.

A lost connection is retried after 4 s, the wait doubling per failed attempt up to
64 s, and then every 64 s for as long as the client runs: the library's choice, where the
eufy app gives up after ten attempts. A refused connect counts as no loss. A topic the
broker refuses is asked for again every 5 s. A connection that ends fails every pending
`async_request` at once with a `CommunicationError` ("MQTT connection lost"); a stop
does the same ("the MQTT client stopped") before its DISCONNECT completes, also for a
request still waiting for its connection. Repeated
connect and certificate failures log a WARNING once per 5 minutes and DEBUG in between.

## Topics

```
cmd/eufy_security/<product code>/<serial>/req    the client publishes commands
cmd/eufy_security/<product code>/<serial>/res    the device publishes; the client subscribes
```

The product code is the one the selection used. Commands are published with QoS 1, not
retained.

## The envelope

Every message body is a JSON object:

```json
{
  "head": {
    "version": "1.0.0.1",
    "client_id": "android-eufy_security-<user_id>-<openudid>",
    "sess_id": "3fa1",
    "msg_seq": 7,
    "seed": "<32 hex digits>",
    "timestamp": 1700000000,
    "cmd_status": 2,
    "cmd": 9,
    "sign_code": 0
  },
  "payload": "{\"account_id\":\"<owner id>\",\"device_sn\":\"<serial>\",\"trans\":\"<command>\",\"data\":\"\",\"update_data\":\"\",\"method\":\"\"}"
}
```

| field | |
|---|---|
| `cmd` | `(business type << 16) \| command code`; 9 for a command to a device, 8 for a device's message |
| `cmd_status` | 2 for a request that wants no acknowledgement (every command the app sends a lock), 1 for one that wants one |
| `msg_seq` | the client's counter, from 1 |
| `sess_id` | 4 random hex digits per request |
| `seed` | 32 random hex digits |
| `timestamp` | epoch seconds |
| `payload` | JSON **text**, not an object: `account_id` is the device owner's id (`member.admin_user_id`), `trans` the command |

A received message is parsed leniently: unknown head fields are ignored, quoted numbers
accepted, missing fields take their defaults, and a `payload` that is no JSON object is
kept as text. A topic that names no serial, a body that is no JSON object, one without a
`head`, or a head field of another type is dropped (and logged at DEBUG).

## The client

A login scope (the login country's region, each extra country) has its own session, install
id and certificate, so each scope holding MQTT devices gets a connection of its own.
`EufyMqttClient` is the connection of one scope: of the devices it is given it serves the
MQTT devices whose `region` is its scope (a device without one counts as the cloud's
`region`'s). `EufyMqttAccount` runs one client per scope of the account's device list and
sends each call to the client of its device's scope:

```python
from eufy_home_security.mqtt.account import EufyMqttAccount

mqtt = EufyMqttAccount(eufy.cloud)  # needs the `mqtt` extra
await mqtt.async_start(devices)  # the cloud device list; a client per scope with MQTT devices
await mqtt.async_wait_connected(30)
answer = await mqtt.async_request(serial, trans, timeout=20)
remove = mqtt.add_listener(on_message)  # every message any device publishes
await mqtt.async_update_devices(devices)  # after a device-list refresh
await mqtt.async_stop()
```

| call | |
|---|---|
| `async_start(devices, subscribe=None)` | serves the MQTT devices among `devices`; `subscribe` (serials) narrows the answer topics, the certificate still covering every MQTT device |
| `async_publish(sn, trans)` | publishes the command; returns its `MqttHead` once the broker acknowledged it, which is no answer of the device |
| `async_request(sn, trans, match=None, timeout=20)` | publishes and waits for the device's message: the first that `match` accepts, or without `match` the one with the request's `msg_seq` or `sess_id`. One message ends only the first waiting request it matches. `DeviceTimeoutError` when none comes |
| `add_listener(fn)` | `fn(MqttMessage)` for every message; returns its remover. An exception from `fn` is logged (once per 5 minutes per listener) and touches neither the connection nor the other listeners |
| `async_update_devices(devices)` | a changed MQTT device set reconnects with a new certificate; an unchanged one changes nothing. On the account: a scope left without MQTT devices has its client stopped, a new one gets a client. After `async_stop()` it does nothing until the next `async_start()` |
| `clients`, `client_for(sn)` | the account's client per scope, and the one serving a device |

The calls are the same on both classes. A serial that is not one of the client's (the
account's) MQTT devices is an `UnsupportedError`; no
connection within 10 s, or a publish the broker does not take, a
`CommunicationError`. The library imports without `aiomqtt`; constructing the client
without it raises `MissingDependencyError` naming the `mqtt` extra.

The `mqtt` extra needs `aiomqtt>=2.2,<3`. The client closes a failed connect's socket
through `aiomqtt`'s paho client, so the range stops below the next major; 2.2 is the
first `aiomqtt` that runs on paho-mqtt 2.1 (the version Home Assistant pins) without a
deprecation warning per connect.

`aiomqtt`'s connect step (the broker's name lookup, the socket connect and the TLS
handshake) runs in the event loop's default executor; every read and write after that runs
on the event loop. A stop or a device-set restart during that step waits for it (30 s at
most, which the step normally stays within; the name lookup has no timeout of its own) and
closes the connection it opened, a DISCONNECT that takes up to `aiomqtt`'s 15 s timeout.
A stop therefore takes 45 s at most, plus a device update in progress; the account stops
its clients together and logs a client stop that fails as a warning (the first one is
also raised to a caller still waiting). A cancel of the stop's caller (an `asyncio.timeout`
around it) propagates at once, and the stop still completes in the background. A start
right after that cancel serves only its own connection: the stopped one, still closing,
counts neither as connected nor for the subscribed topics, and its task ends even when
its DISCONNECT fails.

A step still running after the wait is closed when it ends; a restart past that bound
can briefly run two connects with the same client id, the left one closed when it ends.
So can a start right after a stop cancelled during the connect step: the stopped step's
CONNECT can reach the broker after the new one, and a broker that then drops the newer
session costs one lost connection, after which the client reconnects by itself (4 s).
A connect that fails (a CONNACK timeout too) has its socket closed. A TLS handshake that
fails can leave paho's own socket, which it never stores, to the garbage collector (an
`aiomqtt`/paho limitation). If paho's close call itself fails, the socket is left open
and a warning logged (once per 5 minutes); the connect's own outcome stands.

Start, device update and stop run one at a time: a stop during a device update waits for
it, then stops what it started, and a device update after a stop (one queued behind it
too) does nothing until the next start.

`eufy-security mqtt` lists the account's MQTT devices and their topics; with `--connect`
it fetches the certificate, connects, subscribes and counts what arrives, and never
publishes ([cli.md](../reference/cli.md)).

## Lock commands

`EufySecurity.use_mqtt(account)` serves the locks whose route is MQTT
([locks.md](locks.md#routes)) through an `EufyMqttAccount` the consumer started for the
account (`None` stops). `async_lock`/`async_unlock` then publish the 1940 cm2 frame
([locks.md](locks.md#1940-cm2-frame-in-through-data)) as the `trans` of a command message,
`{"cmd": 1940, "payload": {"lock_payload", "seq_num", "apiCommand": 1940, "time"}}`, naming
the member record's `admin_user_id` and `short_user_id` as the station path does, keyed by the
`admin_user_id` and a time value. The lock answers on its response topic
under the key its own `time` names; an answer to another request is skipped. The refusals,
waits and sequence numbers of [locks.md](locks.md#commands) apply.

The lock's status reports on its response topic set its state: each change emits
`LockStateChanged` with `source` `lock` and `station_sn` None. They are read for a lock that
took a command from this client (the member record's key opens them). A status report with
a non-zero code ends no command on this path: the state wait runs out. Declared from the
eufy app, not tested against the broker.
