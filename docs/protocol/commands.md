# Commands, parameters and the event database

All commands in this file travel on DRW channel 0 inside an established session
([session-crypto.md](session-crypto.md)). Legacy scalar settings use the ECB frame
described there. Everything else is a **DeviceMsgBean** in a GCM `0x0546` frame.

Code: `src/eufy_home_security/p2p/messages.py` (builders, decoders, result codes),
`p2p/params.py` (dump model), `p2p/session.py` (send and confirm),
`src/eufy_home_security/devices/` (command names, per-model settings).

## DeviceMsgBean

```json
{"account_id": "<owner user id>",
 "cmd": 1224,
 "mChannel": 0,
 "mValue3": 0,
 "payload": {"mode_type": 1, "user_name": "home-assistant"},
 "transaction": "1700000000000"}
```

| field | meaning |
|---|---|
| `account_id` | **the station owner's** user id, verbatim ([cloud.md](cloud.md)). Any other id is silently dropped. |
| `cmd` | the CommandType |
| `mChannel` | sub-device channel, 255 = station. The verified arm frame uses 0. |
| `mValue3` | scalar slot. No verified payload-object command reads it. The media commands set it to the command id. |
| `payload` | an object for nearly every command. **A list for `1308`.** |
| `transaction` | optional string, usually epoch milliseconds, echoed in replies |
| `mValueStrSub`, `mValue5` | sent by the app on media commands only ([media.md](media.md)) |

Serialize compactly (no spaces). This is the app's `SecurityMqttPayloadInfo` shape
**[app]**, byte-for-byte what the app sends for arming **[verified]**.

## What counts as success

| evidence | proves |
|---|---|
| DRW_ACK of the command chunk | the datagram arrived. **Nothing else.** |
| receipt code 0 ([below](#command-receipt-verified)) | the station took the command off its queue. Not that it applied. |
| receipt code −108 | rejected: the station does not handle this command |
| `0x0547` frame whose JSON `cmd` names the command sent (never 2037), `code` 0 | the station processed the command (a command result) |
| the same with a non-zero `code` (or `mIntRet`) | rejected; the code says why (−104: not the owner id) |
| `0x047F` guard notify decoding to a mode (GCM u64le, or ECB first u32le) | applied, as reported by the station |
| the value in a fresh parameter dump | applied, as observed |

- **A wrong `account_id` is ACKed and then ignored:** no result, no error, no state
  change **[verified]**. An ACK with no application-level answer should be reported
  as "not applied", and the owner id is the first thing to check.
- `0x0547` also carries camera pushes and replies to other commands (a media open,
  a stream stop). **Match the reply's `cmd` to the command sent** and exclude
  `cmd == 2037`, or a stray reply or a person walking past a camera mid-command
  reads as success. Frames that do not decode (and `0x04B1`/`0x04B2`) are not
  counted as results: they cannot be attributed to a command.
- GCM settings commands send **no** command result. Only read-back confirms them.

### Command receipt **[verified]**

Every GCM frame the station takes from channel 0 — a `0x0546` command or the `0x044F`
parameter query — is answered on channel 0 with one frame **of the request's own
type**, 132 bytes, GCM-tagged (subheader `08 00 00 00 01 00` for a command,
`08 00 FF 00 01 00` for the query). It is **not ciphertext**: an `int32le` code
followed by 128 zero bytes. A T8170 standalone camera (fw 3.3.5.4) answers the query
with the same code in **36 bytes** (32 zero bytes, subheader `08 02 FF 08 01 00`); the
library takes both lengths (`RECEIPT_LENS`).

| code | seen for |
|---|---|
| 0 | the parameter query; the eufy app's 1306, 1308 and 1310 (from an app capture) |
| −108 (`94 ff ff ff`) | every `APP_CMD_GET_*` command sent ([below](#get-commands-not-served-verified)) |
| −204 | a live open (1003) of a HomeBase camera the station could not wake, about 12 s after the open, instead of the code-0 receipt ([media.md](media.md#open-1003-verified)) |

`RECEIPT_CODES` names the other codes of the app's error table as well (−100 to −135,
−203 to −205, spelled as in the app's `P2PErrorCode`) **[declared]**; the app calls 0
`SUCCESSFUL` and −108 `WAIT_TIMEOUT`; the library raises `CameraWakeError` for −203, −204 and
−205 and `CommandRejectedError` with the name for the rest.

The receipt carries no command id or transaction, so it can be attributed only
while a single command is in flight.

**The station works through channel-0 GCM frames one at a time, per session.** A
rejected command holds the queue until its −108 receipt, **12–17 s** after it was
sent. Everything sent behind it on the same session waits, the parameter query
included, so three rejected commands in a row delay a query by about 50 s. Other
sessions are not held up: a second client's full parameter read took 2.6 s while
one was pending. Never send a command the firmware may not handle on a session
that serves reads, and do not resend into a stall — each resend queues again.

**In the library** (`decode_command_receipt` in `p2p/messages.py`, `p2p/session.py`):

- A frame on channel 0 that is GCM-tagged, 132 (or 36) bytes long and zero after its
  first four bytes is taken as a receipt before any decrypt attempt. Receipts are
  counted by code in `SessionStats.receipts_by_code` and never in
  `dropped_undecodable`.
- `async_send_command` takes a `0x0546` receipt that arrives while it is in flight as
  its own. Code −108 raises `CommandUnsupportedError` (a `CommandRejectedError` with
  `code` −108 and an `UnsupportedError`); any other non-zero code raises
  `CommandRejectedError`. Code 0 only means taken: the outcome is still `APPLIED` on
  a `0x0547` result, else `DELIVERED`.
- The command is resent once, after 1.5 s, only when neither a receipt nor a DRW ACK
  came back. A command that was acknowledged but has no receipt when its timeout
  runs out keeps the session's request lock until the receipt arrives, at most 20 s
  after sending (`COMMAND_RECEIPT_TIMEOUT`). That way a late −108 is attributed to its
  own command, and the next request does not queue behind the stall.
- **Stills and history pages wait outside the lock.** A still fetch (1308) and a
  history query (10011) take the request lock only to send; their replies are bound
  by path and by transaction, and they wait for them after releasing the lock. Each
  kind is still serialised against itself. So a guard-mode write or a command issued
  while a still reply is late or lost goes out at once instead of after the fetch's
  timeout. The station may still work through the frames in order, but it answers a
  still in well under a second.
- **Limit.** Requests on one session are serialised, but a media open (sent under the
  lock), a still fetch and a history query (both wait outside it) and a live-stream
  stop (sent on close) can have their receipts arrive while a later command is in
  flight. Such a receipt (code 0) can be taken as that command's, which at most skips
  its resend.

## Arming (1224) **[verified]**

```json
{"account_id": "<owner user id>", "cmd": 1224, "mChannel": 0, "mValue3": 0,
 "payload": {"mode_type": <mode>, "user_name": "<free text>"}}
```

| `mode_type` | mode | status |
|---|---|---|
| 0 | Away | **[verified]** |
| 1 | Home | **[verified]** |
| 2 | Schedule | **[verified]** as the *selected* mode (see below) |
| 3, 4, 5 | Custom 1, 2, 3 | **[app]** |
| 47 | Geofence | **[app]** |
| 63 | Disarmed | **[verified]** |

- `user_name` is free text. The station records it in its event history as "by
  <user_name>" without authenticating it. The station also writes an `ARMING_EVT`
  row within about 2 s of the command.
- **Confirmation.** After an arm the station sends `0x047F` (1151) on DRW channel 2,
  under the cipher named by its subheader byte 0 — read it per frame:
  - `0x08`, AES-256-GCM under the session key, base->app layout
    `tag(16) ‖ nonce(12) ‖ ct`: the plaintext is 8 bytes, a u64le whose value is the
    applied mode (same value space as the command and the FCM `arming` field).
  - `0x01`, AES-128-ECB under the static key: a 16-byte block holding four u32le
    values `mode, 0, <constant marker>, 0`. The first is the applied mode.
- Take the applied mode from a decoded `0x047F` and fail if it differs from the
  request. A `0x0547` naming 1224 with code 0 but no mode report only proves the
  command was processed: confirm the mode by reading it back. A non-zero code is a
  rejection.
- The `0x047F` follows every change, whoever made it: a P2P client, the eufy app, or a
  schedule slot starting or ending, and every open session on the station receives it
  (fw 3.8.7.4; see [events.md](events.md#guard-mode-announcements)). Keypad changes are
  untested. The library trusts the report only under GCM once a session key exists
  ([session-crypto.md](session-crypto.md)).
- **Selected and effective mode are two parameters [verified].** Param **1224** is the
  mode the user *selected*; param **1151** is the mode *in force*. They differ only
  while Schedule is selected: 1224 reads 2 and 1151 follows the schedule's slots (1
  Home, 0 Away, 63 Disarmed …). The `0x047F` report carries the **effective** mode —
  it never says 2 — and a schedule change reports the slot's mode. The cloud arming
  push carries both (`arming` = selected, `mode` = effective;
  [events.md](events.md#station-pushes-arming-and-alarm)).
- Resend once if nothing at all (not even an ACK) comes back. The library resends
  after 1.5 s within a 6 s deadline.
- GET commands do **not** read guard mode on this firmware: `1107`, `1108` and
  `1151` are rejected with receipt −108
  ([GET commands](#get-commands-not-served-verified)).
- **`0x0473` (1139).** The eufy app sends an empty `0x0473` about every 20 s and the
  station answers each with a GCM body of 8 zero bytes **[verified]** — a keepalive,
  not a status read. The library sends it only to a standalone device while it streams
  ([media.md](media.md#standalone-device-open-17001000-stop-bare-1004-ping-1139-verified)).

## Settings

Two write schemes, chosen by command id ([session-crypto.md](session-crypto.md)).

**GCM payload objects.** The value **and the channel** go inside `payload`.
`mValue3` is ignored, and a payload without `channel` is not applied **[verified]**.

| setting | cmd | payload | status |
|---|---|---|---|
| detection types | 1298 | `{"ai_detect_type": <bitmask>, "channel": <ch>}` (face 1, body 2, vehicle 4, pet 8) | **[wire verified]** (written with read-back), meaning **[declared]** (not proven), bit names **[app]** |
| motion sensitivity | 1276 | `{"sensitivity": <1–7>, "channel": <ch>}` | **[verified]** |
| night vision | 1277 | `{"night_sion": <0\|1\|2\|3>, "channel": <ch>}` (the key is spelled `night_sion` on the wire) | **[verified]** for 0, 1, 2 and 3 (written with read-back; 2 and 3 by the library, and the app sends 2 too). Meanings from the vendor description: 0 off, 1 black & white, 2 color. 3's meaning is unknown: no vendor description of this model names it, and what the camera does in mode 3 was not observed. |

**ECB scalars** (frame type = cmd, [session-crypto.md](session-crypto.md)):

| setting | cmd | handler | scope | values | status |
|---|---|---|---|---|---|
| PIR sensitivity | 1210 | channel + value | camera | 1–7 | **[verified]** |
| mirror | 1207 | channel + value | camera | 0/1 | **[wire verified]** (written with read-back), meaning **[declared]** (not proven) |
| status LED | 1045 | channel + value | camera | 0/1 | **[wire verified]** (written with read-back), meaning **[declared]** (not proven) |
| speaker volume | 1230 | channel + value | camera | 0–100 | **[verified]** |
| power mode | 1246 | channel + value | camera | `<0\|1\|2\|3>`: 0 optimal battery life, 1 optimal surveillance, 2 custom (the T8160 handler and description, and the eufy app's labels); 3 undocumented (the station keeps it and the app shows "Optimal Battery Life", but no vendor description names it) | **[verified]** (0, 1, 2 and 3 written with read-back on a T8160, and the app label of each observed). A write of 1 or 3 can be reported as not acted on although it applied; re-read before trusting that error |
| mic volume | 1229 | channel + value | camera | 0–100 | **[app]** (not in the dump, so not written) |
| clip length | 1249 | value | camera | 10–120 s; applies only when power mode is custom (2) | **[verified]** |
| retrigger interval | 1250 | value | camera | 0–60 s; applies only when power mode is custom (2) | **[verified]** |
| record auto-stop | 1251 | value | camera | **0 = on**, 1 = off; applies only when power mode is custom (2) | **[wire verified]** (written with read-back), meaning **[declared]** (not proven) |
| clock format | 1253 | station | station | 0 = 12 h, 1 = 24 h | **[verified]** (wire); meaning from the vendor corpus |
| hub speaker volume | 1235 | station | station | 0–100 | **[app]** (not in the dump, so not written) |

**Couplings** **[verified]**: on a T8160, writing 1276 also sets 1210 and param
6041, but writing 1210 moves only 1210. Writing 1045 also moves 1056, 1716 and 6014.
Always re-read after a write.

**Not writable by their own id.** The arm, alarm and leaving delays (1157–1161,
1166–1170, 1171–1175, one id per mode) sit on the default ECB handler (−103), and a
GCM write of the id changes nothing. The alarm and leaving delays are written through
the mode table (`SET_ALL_ACTION` 1255,
[below](#mode-actions-delays-and-schedule-app-writes-verified)); 1157–1161 are the
app's copy of each mode's table, not a number. `1203` (`SET_RECORDTIME`, a hub-wide
record time) is not reported by the station.

**Read-back.** The authoritative confirmation is a fresh parameter dump. The
parameter id equals the command id, filed under `dev_type` = the sub-device channel
(255 for the station). A camera block can arrive after the station block, so allow
a few seconds.

**Library write path.** `Station.async_set_setting(key, value, device_sn=…,
channel=…)` writes one setting of the addressed device's model file
(`devices/data/models/<PN>.json`, [models-schema.md](../reference/models-schema.md)),
keyed by the vendor identifier. The value is validated against the setting's domain,
the handler's write codec is rendered for the device (station, station child on its
channel, or a standalone camera on its own channel) and sent on the path the codec
names: an ECB scalar frame for an ECB command with one value field, a `0x0546`
(1350) DeviceMsgBean whose `cmd` is the codec's `subCmd`, the 1700 wrapper with its
`subCmd` ([below](#the-1700-wrapper-a-standalone-devices-commands-verified)), or a
DeviceMsgBean of the codec's own command (not observed on hardware). A codec that goes
to the cloud, stays in the app or uses another transport is not sent: such a setting
is not writable and says why. A rejection raises the typed error; nothing is read
back. After a send, the parameter values the codec's `update` names are merged into
the cached dump, as the app does, until the next real dump replaces them. The
mode-table settings are the exception: they go through the 1255 table write
([below](#mode-actions-delays-and-schedule-app-writes-verified)).

## Parameter dump **[verified]**

**Request.** A GCM frame of type `0x044F` on DRW channel 0, subheader
`08 <ctr> FF 08 00 00` (dev_type `0xFF` = station). The plaintext is the fixed 8 bytes:

```
ff 00 00 00 87 03 00 00        # u32le 0xFF, u32le 0x387 (903)
```

It is a pure read. The station answers the first query of a session. If nothing
arrives within about 2 s, send it again.

**Receipt.** The station first answers on the request channel (0) with one `0x044F`
frame, subheader `08 00 FF 00 01 00`, whose body is 132 zero bytes. It carries the
GCM tag but is not ciphertext — do not try to authenticate it: it is the
[command receipt](#command-receipt-verified) with code 0. **[verified]**

**Response.** One or more `0x044F` frames on DRW channel 2, under either cipher tag.
About 300 params for a station with three sub-devices, about 19 KB in about 23
chunks:

```json
{"params": [{"dev_type": 255, "param_type": 1224, "param_value": "1"},
            {"dev_type": 0,   "param_type": 1101, "param_value": "92"}, ...],
 "main_sw_version": "3.8.7.4", "sec_sw_version": "1.4.0.8", "hb_bind_type": ..., "app_cloud_encrypt": ...}
```

- `param_value` is a **string** (ints as decimal text, some values base64).
- **Group by `dev_type`.** The same `param_type` appears once per device (three
  batteries, for example), so flattening loses data.
- **A standalone device has no 255 block [verified].** A T8170 (fw 3.3.5.4) answers
  the same query with one frame whose every entry carries `dev_type` 48, its cloud
  `device_type`, guard mode 1224 included. Under a HomeBase `dev_type` is the channel,
  so a hub's block cannot be told apart by that number; the library applies the rule
  only to a station whose cloud `parent_sn` is its own serial, and files that block
  under 255 and under the device's channel (`params.standalone_aliases`).
- The dump is complete for the station once `dev_type 255` includes 1224. Keep
  listening about 1 s longer for sub-device blocks — unless every paired channel has
  already reported: on a HomeBase 3 the sub-device blocks ride in the same frame as
  the station's, so a client that knows the paired channels can return at once.
- Diff successive dumps to derive changes. A dump that arrives without a request is
  a parameter-change push ([events.md](events.md)).
- **Completion (library).** A read completes when it returns. A dump nobody asked
  for completes as soon as the station block and every paired channel have arrived,
  else `PARAM_SETTLE` (1 s) after its last frame. Each completion rebuilds
  `Station.state`, and `StationStateChanged` is emitted when it differs from the
  last one emitted.
- **Vanished blocks (library).** Parameters merge across dumps, and a block that
  arrives without some parameter keeps its earlier value (a push may be partial). A
  device block is dropped only when a read that waited for at least every paired
  channel completes without it; a read-back of one channel drops nothing.
- **Sub-device serials (library).** A channel's serial comes from the cloud device
  list. For a channel the list lacks (a device paired since it was fetched), the
  library takes the 1072 entry at that channel's rank among the dump's camera
  channels, only when the camera blocks number exactly the list's length, at least
  one cloud-known serial is listed, and every listed cloud-known serial sits at its
  own channel's rank. An entry that is not `T` + 15 uppercase alphanumerics, repeats
  an earlier one, or is the station's own serial is an empty position. A channel two
  cloud devices claim has no serial.

| param | dev_type | meaning |
|---|---|---|
| 1224 `ALARM_MODE` (app enum `SET_ARMING`) | 255 | **selected guard mode**, 2 = Schedule (see Arming). 1148 is **not** guard mode: it is a sub-device's Custom 1 action mask (eufy app `GET_CUSTOM1_ACTION`). |
| 1151 `GET_ALARM_MODE` | 255 | **effective** mode: equals 1224 except while Schedule is selected |
| 1239 `GET_AWAY_ACTION`, 1225 home, 1148–1150 custom 1–3, 1177 off | sub-device | per-mode action mask of the device; written by `SET_ALL_ACTION` (below) |
| 1166–1170 / 1171–1175 | sub-device | alarm / leaving delay per mode; written by `SET_ALL_ACTION` (below) |
| 1072 | 255 | base64 JSON list of paired sub-device serials. Two dumps of one base listed the cameras in channel order and left the motion sensor out **[unknown]** (see below) |
| 1102 `SDINFO`, 1190 eMMC % | 255 | storage. 1189 (app enum `GET_HB_HD_PERSENT`) stays 0 with an internal SSD attached and 6 % used — it does not track that disk; use the storage record ([Storage](#storage-1307-verified)). 1102 is one integer no handler decodes (`StationState.sd_info`) |
| 1135 `GET_TFCARD_STATUS` | 255 | storage status code; the handlers show 0, 25 and 30 as normal (`StationState.storage_ok`) |
| 5006–5012 | 255 | subsystem version strings; no vendor code names the subsystems |
| 14000 | 255 | ISO country code |
| 1101 `BATTERY_VALUE` (app enum `GET_BATTERY`), 1138 battery temp | sub-device | battery; 1138 in °C by its range |
| 1142 `GET_WIFI_RSSI`, 1141 sub-GHz RSSI | sub-device | signal |
| 1113 `GET_IRMODE` | camera | night vision currently on |
| 1191 working days, 1192 PIR count, 1193 record count | camera | the app's power-manager figures since the last USB charge |
| 2111 `BATTERY_STATUS` | camera | charging source: 0/2 not charging, 1 USB, 3 AC, 4 built-in solar, 5 USB + built-in solar, 6 or 8 external panel, 7 or 12 external + built-in (per-model thing descriptions), 20 a connected panel (handler `is_connected_solar_panel`). The app's command table names the id `SUB1G_REP_UNPLUG_POWER_LINE`. Parameter ids and XZYH frame types are separate namespaces: frame type `0x083F` (2111, seen when a session ends, [p2p-transport.md](p2p-transport.md#frame-types)) only shares the number |
| 1309 `SOLAR_INTENSITY` | camera | raw solar input; 0 without light or panel |
| 1509–1513 | sub-device | per-mode siren action (Away, Home, Custom 1–3; app `getSirenAction`) |
| 1601 `MOTION_SENSOR_BAT_STATE` | motion sensor | low-battery flag (handler `sensor_is_low_power`) |
| 1605 | motion sensor | epoch ms of the last PIR trigger |
| 1609 | motion sensor | raw PIR sensitivity; the handler maps only 0–2 |
| 3100 | camera | 30-day battery history |

Names for every id: `src/eufy_home_security/devices/command_types.py`.

## Event database (1306) **[verified]**

```json
{"account_id": "<owner user id>", "cmd": 1306, "mChannel": 0, "mValue3": 0,
 "payload": {"cmd": 10000, "table": "history_record_info", "transaction": "<ms>",
   "payload": {"count": 100, "device_info": [{"device_sn": "T8160XXXXXXXXXXX"}],
     "start_date": "20260101", "end_date": "20260107", "start_time": "20260101000000",
     "start_id": 0, "end_id": 1, "need_ai": 1, "update_time": 0, "alarm_id": 0,
     "event_type": 0, "detection_type": 0, "ai_type": 0, "flag": 0,
     "res_unzip": 1, "storage_cloud": -1}}}
```

- **`start_id`, `end_id`, `need_ai`, `update_time` and `alarm_id` are mandatory.**
  Without them the station never answers at all, which looks exactly like a rejected
  `account_id`.
- **Query verb.** `10000` returns rows. `10017` (the app's QUERY_LOCAL) answers
  `-6006 ERROR_NO_SUPPORT`. `10006`, `10009` and `10011` answer `SUCCESSFUL` with no
  rows. `10013` returns only the newest crop per device.
- `device_info` may list the station serial as well as cameras. Station param 1072
  gives the paired serials.
- **Reply:** `0x051A` with `{"cmd": 10000, "count": n, "data": [...], "mIntRet": 0, "msg": "SUCCESSFUL"}`.
  `data` is the string `"[]"` when empty.
- Row fields include `device_sn`, `start_time`/`end_time` (local-time strings),
  `video_type`, `storage_path` (`.zxvideo`), `thumb_path`, `crop_path`. Rows with
  empty paths are **station** events (arming, alarms). Their details are a JSON
  string in `str_extra` carrying the push `msg_type` ([events.md](events.md)).
- **History list (verb `10011`), as the app sends it:** no `device_info`,
  `mChannel` 255, `start_date` = the day, `end_date` = the next day, `count` 30 for the
  first page and 50 for the next, `start_id` 0 and then the previous reply's `end_id`,
  `end_id` 1. The reply (`0x051A`, ECB) names `cmd` 10011, echoes `transaction`, and
  carries `start_id` / `end_id` = the newest and oldest `record_id` of the page. Rows
  come newest first; a page asked from `start_id` repeats that row first. A page
  shorter than `count` is the last. `record_id` is the day (`YYYYMMDD`) followed by a
  five-digit counter.
- **One day per query.** Asked for day D to day D+1, the station returned only D's
  rows; asked for D+1 to D+2, or D+1 to D+1, D+1's. Whether it reads only
  `start_date`, or treats `end_date` as exclusive unless it equals `start_date`, is
  open — the app's one-day window satisfies both. The library therefore asks one day at
  a time, newest day first, and pages each day: `async_list_history(start, end,
  count=None, page_size=50)` includes both dates and returns records newest first,
  up to `count`.
- **Every page carries other tables** in `data` next to the `history_record_info`
  wrapper: the AI crops, relations and head positions of that page's records, and the
  whole `person_basic_info`, `face_feature_info` and `reid_feature_info` libraries
  (hundreds of rows on every page). Only the `history_record_info` wrapper holds
  history rows.
- **A firmware update clears the event database.** An empty result after an update
  is expected, not a query failure.

## Image fetch (1308) **[verified]**

```json
{"account_id": "<owner user id>", "cmd": 1308, "mChannel": 0, "mValue3": 0,
 "payload": [{"file": "/zx/hdd_data0/Camera00/<...>/snapshort.jpg"}], "transaction": "<any>"}
```

Reply: `0x051C`, ECB-tagged, `{"file": "<path>", "content": "<base64>"}`. The base64
is **URL-safe** and may be unpadded. Content and formats: [media.md](media.md).

## Storage (1307) **[verified]**

The app's HDD screen, reproduced by the library (read-only):

```json
{"account_id": "<owner user id>", "cmd": 1307, "mChannel": 0, "mValue3": 0,
 "payload": {"version": 1, "cmd": 11001}}
```

Receipt 0, then a `0x0547` in about 0.2 s: `{"cmd": 1307, "payload": {"cmd": 11001,
"mIntRet": 0, "old_storage_label": "", "cur_storage_label": "", "body": {...}}}`.

| `body` field | meaning (all sizes **MiB**) |
|---|---|
| `storage_days`, `storage_events` | days and event records kept |
| `format_transaction`, `format_errcode` | the id of the last format request and its error (0) |
| `hdd_info.device_module`, `serial_number`, `disk_path`, `hdd_type` | the attached disk (`/dev/sda`, a SATA SSD: `hdd_type` 1) |
| `hdd_info.disk_size_1024` | disk size — the app's total (476940 MiB = 465.76 GiB) |
| `hdd_info.disk_size` | nominal size (512000) |
| `hdd_info.system_size`, `system_size_data` | reserved system areas |
| `hdd_info.video_used`, `video_size` | recordings used / recording capacity |
| `hdd_info.disk_used` | file-system use: `video_used` + about 633 MiB |
| `hdd_info.cur_temperate` | disk temperature, °C |
| `hdd_info.health`, `work_status` | 0 = healthy / idle |
| `hdd_info.parted_status` | 1 ready, **2 formatting** |
| `hdd_info.hdd_label` | file-system label; changes on every format |
| `move_disk_info` | an external disk (empty when none) |
| `emmc_info` | the built-in eMMC: `disk_nominal`, `disk_size`, `system_size`, `disk_used`, `data_used_percent`, `swap_size`, `video_size`, `video_used`, `data_partition_size`, `eol_percent` (wear), `work_status`, `health` |

**The app's "used" figure** is `system_size + system_size_data + video_used`, divided
by 1024 and labelled GB: 8065 + 18819 + 2237 = 29121 MiB → "28.44 GB", and after a
format 26884 MiB → "26.25 GB". Its total is `disk_size_1024 / 1024`.

**Library API.** `await station.async_get_storage()` (or the session's) sends the read
under the command lock and returns a `StorageInfo`; a non-zero `mIntRet` raises
`CommandRejectedError`, a reply without `body` `ProtocolError`, silence
`DeviceTimeoutError`. The reply is matched by `cmd` 1307 with inner `cmd` 11001 under
either cipher (a fresh session gets it under ECB). `station.storage` holds the last
record (None until one arrives), and the answer and every unsolicited GCM record —
another client's query, the push after a format — whose parsed value differs from the
last one emit `StorageChanged(station_sn, storage)`.

| `StorageInfo` | from |
|---|---|
| `storage_days`, `storage_events`, `continuous_video_hours` | `storage_days`, `storage_events`, `con_video_hours` |
| `format_transaction`, `format_error` | `format_transaction` (`""` → None), `format_errcode` |
| `disk: DiskInfo \| None` | `hdd_info` |
| `external: DiskInfo \| None` | `move_disk_info` (`disk_path`, `disk_size`, `disk_used` only) |
| `emmc: EmmcInfo \| None` | `emmc_info` |
| `formatting` | any disk formatting |

`DiskInfo` and `EmmcInfo` are both a **`StorageMedium`**: the same fields and derived
figures, so a consumer reads a disk and the eMMC alike. A figure a record does not
carry is None (a disk record has no wear, an eMMC record no temperature, path or
serial). The keys `hdd_info` and `emmc_info` name alike are read by one parser, so a
field one record gains later is not lost.

| `StorageMedium` (MiB unless noted) | `hdd_info` (`DiskInfo`) | `emmc_info` (`EmmcInfo`) |
|---|---|---|
| `size_mib` / `size_gib` | `disk_size_1024` — the app's total | `disk_size` |
| `nominal_size_mib` | `disk_size` | `disk_nominal` |
| `used_mib` / `used_gib` | `system_size + system_size_data + video_used` — the app's "used" | `disk_used` |
| `system_mib` | `system_size + system_size_data` | `system_size` |
| `free_mib` / `free_gib` | `size_mib - used_mib` | same |
| `used_percent` (float) | `used_mib` of `size_mib`, one decimal | `data_used_percent` (the app's and param 1190's figure; 20 against a computed 19.2 on the one station seen), else computed |
| `station_used_percent` | `data_used_percent` if present | `data_used_percent` |
| `recordings_used_mib` / `_gib`, `recordings_capacity_mib` / `_gib` | `video_used`, `video_size` | same |
| `filesystem_used_mib` | `disk_used` | `disk_used` |
| `data_partition_mib`, `swap_mib` | `data_partition_size`, `swap_size` if present | same |
| `wear_percent` | `eol_percent` if present | `eol_percent` (life used, 0-100) |
| `temperature_c` | `cur_temperate` (°C) | `cur_temperate` if present |
| `health` / `healthy`, `work_status` | `health` (0 = healthy), `work_status` (0 idle) | same |
| `parted_status`, `ready`, `formatting` | `parted_status` (1 ready, 2 formatting) | same, if present |
| `model`, `disk_type`, `path` | `device_module`, `hdd_type`, `disk_path` | same, if present |
| `serial`, `label` | `serial_number`, `hdd_label` — left out of `repr`; redact them in logs | same, if present |

An external disk (`move_disk_info`) is a `DiskInfo` with `size_mib` = `disk_size` and
`used_mib` = `disk_used`. GiB figures are rounded to two decimals, like the app.

Every field is validated on its own: a missing, non-integer or out-of-range value
(negative sizes, percentages above 100, temperatures outside −40…150 °C) becomes None
and the rest still parses; `used_mib` is None when one of its terms is. **No disk:**
`disk` is None when `hdd_info` is missing or has neither a size nor a device path, and
`external` is None unless `move_disk_info` names a path or a size. That rule follows
the record's shape; a station without an internal disk, and any external disk, have
not been seen.

### A standalone camera's eMMC (1144 `GET_SD_INFO_EXT`) **[verified]**

A standalone camera (a T8170) does not answer the HomeBase storage record (1307 /
11001). Its handler's `get_storage_info` recipe resolves, for a non-station device, to
a bare **`GET_SD_INFO_EXT`** command (app enum `SDINFO_EX`) — an XZYH frame of type **1144 (`0x0478`)** with an empty
body (the app's `getSdInfoEx`, `msgType 10`, no JSON). The camera answers with a frame
of the **same type on channel 0**, GCM-tagged but **clear** (like a command receipt),
whose 12-byte body is three little-endian `int32`:

| offset | `int32` | meaning |
|---|---|---|
| 0 | status | 0 normal (`AndroidP2PReceiver` maps it to a UI status: 2 = no card, 3 = low memory, 4 = corrupted) |
| 4 | total | total size |
| 8 | free | free size |

The app formats the sizes as **MB** (base 1000, `< 1000` → "MB", else ÷1000 → "GB") and
takes used as `total − free` (this query carries no system-reserve figure). So for the
eMMC, used% = `(total − free) / total`. **Verified** on a T8170: the
reply body was `00000000 e41b0000 c41b0000` = `[0, 7140, 7108]` (a ~7.14 GB eMMC, 32 MB
= 0.4 % used); sent as a plain `1307` `DeviceMsgBean` instead the camera answered receipt
code −1. The field order is by observation (free never exceeds total, so with status 0
`[status, total, free]` is the only consistent reading of `[0, 7140, 7108]`).

**Library API.** On a standalone camera `station.async_get_storage()` sends this query
instead (`session.async_get_sd_info()`): a bare `1144` frame, its answer bound by frame
type on channel 0 and parsed from the 12-byte body. It returns a `StorageInfo` with only
`emmc` set: an `EmmcInfo` (`size_mib` = total, `used_mib` = `total − free`,
`work_status` = status), whose `used_percent` is the figure the eMMC diagnostic shows. It
is kept as `station.storage` and emits `StorageChanged` like the HomeBase record. The
passive `emmc_used_percent` state field is HomeBase param 1190 (`GET_HB_EMMC_PERSENT`)
only; a standalone camera has no such param, so read its eMMC use from `storage.emmc`.

**Format** (a destructive write, verified once from the app):

```json
{"cmd": 1307, "payload": {"cmd": 11003, "version": 0,
 "body": {"media_type": "hdd", "transaction": "<id>"}}}
```

The station answers after about 4 s with `{"cmd": 1307, "payload": {"cmd": 11003,
"old_storage_label": "<label>", "cur_storage_label": "", "body": {"media_type": "hdd"}}}`.
The storage record then shows `format_transaction` = the request's id and
`parted_status` 2; about 60 s later `parted_status` 1, a new `hdd_label`,
`video_used` 0, and fewer `storage_events`. The station **pushes** that final record to
every open session unasked.

`1082` (`NOTIFY_MIGRATION_STATUS`, payload `{}`) is sent by the same screen and
answers `{"devices": [], "code": 0, "HB3SN": "<station>", "DID": "", "SN": "", "type": 0}`.

Replies to one client's storage and 1082 requests reach **every** session on the
station, so a passive session sees another client's queries.

## Mode actions, delays and schedule (app writes) **[verified]**

Captured from the eufy app. These travel as GCM frames whose **frame type
is the command id** with a JSON body — not as a `DeviceMsgBean` — and each is answered
by a receipt (code 0) and no `0x0547`.

**`SET_ALL_ACTION` (1255, frame `0x04E7`)** replaces one mode's whole action table:

```json
{"account_id": "<owner>", "mode_id": 1,
 "devices": [{"device_channel": 16, "action": 0}, {"device_channel": 1, "action": 1}, {"device_channel": 0, "action": 1}],
 "count_down_alarm": {"channel_list": [1, 0], "delay_time": 30},
 "count_down_arm": {"channel_list": [1], "delay_time": 30},
 "siren_sensor_action": [{"device_channel": 16, "action": 0}, ...]}
```

- `mode_id` is the guard-mode code: 0 Away, 1 Home, 3/4/5 Custom 1–3 **[app]**
  (`ArmingManager`). `devices[].action` lands in the device's per-mode action param
  (1239 for Away). `delay_time` lands in the alarm delay
  (1166–1170) of every channel in `count_down_alarm.channel_list` and the leaving
  delay (1171–1175) of every channel in `count_down_arm.channel_list`; other channels
  keep theirs.
- **`action` is a bitmask** (the app's `DeviceParam` constants), stored per device per
  mode in 1239 (Away), 1225 (Home), 1148–1150 (Custom 1–3):

  | bit | app name | meaning |
  |---|---|---|
  | 1 | `BIT_RECORD` | record video |
  | 2 | `BIT_ALARM` | the camera's own siren ("sound alarm") |
  | 4 | `BIT_STATION_ALARM` | the HomeBase alarm |
  | 8 | `BIT_NOTIFICATION` | push notification |
  | 16, 256 | `BIT_PRAVACY_ON`, `BIT_PRIVACY_ON_NEW` | privacy (camera off in this mode) |
  | 32 | `BIT_MOTION_SENSOR_RESPOND` | respond to the motion sensor |
  | 64 | `BIT_REPORT_MONITOR_CENTER` | report to professional monitoring |
  | 128 | `BIT_LIGHT_ALARM` | light alarm |

  **[verified]** against the station: a camera at 143 (record, notify, camera siren,
  HomeBase alarm, light) raised the camera siren (`0x04B2`), the HomeBase tone
  (`0x04B1`) and its light (`0x0578`) when it triggered in Away, while a camera at 9
  (record, notify) raised nothing. Its bit names are **[app]**.
- The table carries every device of the mode, so a client must write back the other
  devices' current actions and the delays unchanged.
- Which bits a device has depends on its type **[app]** (`ArmingManager.g`): a camera
  (eufyCam 3 is type 19) gets record, notification, camera siren, HomeBase alarm and
  light; a motion sensor (type 10) notification, HomeBase alarm and respond (32); every
  device the monitoring-centre report (64). The privacy bits belong to indoor cameras.
- The delay ids run Home first: alarm 1166 Home, 1167 Away, 1168–1170 Custom 1–3;
  leaving 1171 Home, 1172 Away, 1173–1175 Custom 1–3 **[app]** (`ArmingManager.c/d`).
  The app reads a count-down back from the dump as "the channels whose delay for this
  mode is non-zero, at that value", so a delay is **one value per mode**, switched on
  per device.
- `siren_sensor_action` **[app]**: per device, 1 when its trigger sounds a paired eufy
  siren accessory (`GuardSirenAlarmAdapter`), else 0. All 0 on a station without one.
- 1157–1161 (`ARM_DELAY_*`, not in the parameter dump) are, to the app, a base64 JSON
  copy of each mode's table (`ArmingManager.b`), not a number.
- 1177 (`GET_OFF_ACTION`) is the Off mode's action param; the Off mode has no delay ids
  and the library writes no table for it.

**Library write path [verified].** A mode-table setting (the
`camera_action_<mode>`, `sensor_action_<mode>`, `alarm_delay_<mode>` and
`leaving_delay_<mode>` settings) is written by `Station.async_set_setting` /
`async_set_mode_action`, never as a frame of its own:

1. Read a fresh parameter dump that includes every paired channel; a paired channel
   missing from it refuses the write (a table without it would drop it).
2. Build the mode's table from it (`p2p.mode_actions.mode_table_from_params`): every
   sub-device block that reports the mode's action param is a device of the table;
   an unreported delay counts as 0.
3. Apply the one change. An action replaces that device's mask (named flags only
   change their bit). A delay follows the one-value-per-mode rule: **non-zero** sets the
   value on the target **and on every device whose delay for that mode is already on**
   (the count-down lists them all); **zero** turns the target off and leaves the others.
   When no device keeps it on, the target is listed with `delay_time` 0 so the station
   writes the 0; otherwise the target is left out of the list, and the station writes 0
   into every device of the table that the list leaves out [verified].
4. Refuse before sending (`UnsupportedError`) when the setting does not apply to the
   target's device kind, when a device of the table is of no known kind (it may be a
   siren accessory: the library always sends `siren_sensor_action` 0 and would clear
   its triggers), or when the count-down the table must carry unchanged has devices
   at different non-zero values (one table cannot carry two).
5. Send it (`StationSession.async_set_mode_table`, frame type 1255, no resend). A
   non-zero receipt raises `CommandRejectedError`; a zero receipt is not success: every
   action and every listed or turned-off delay is read back, and a value that does not
   hold after three reads raises `CommandNotAppliedError`.

The library's 1255 write is proven on a HomeBase 3 with two eufyCam 3 and a motion
sensor: every delay of Home, Away and Custom 1 on a camera and the Home delays on the
sensor were written, read back from an independent dump and restored, each moving only
its own parameter; the one-value-per-mode rule held with two devices; action masks were
written and restored on a camera and the sensor. The delays are proven for those
modes; Custom 2 and 3 (no table on this station) are not, and the action flag names
come from the app and are unproven. See the verification log's mode-table row.

**`SET_JSON_SCHEDULE` (1254, frame `0x04E6`)** replaces the whole weekly schedule:

```json
{"account_id": "<owner>",
 "schedules": [{"week": 1, "start_h": 7, "start_m": 50, "end_h": 17, "end_m": 10, "mode_id": 3}, ...]}
```

`week` 0–6, one row per slot, slots covering each day. Every edit in the app resends
the full table (27 rows for a Monday–Friday three-slot plan), so a delete that picks
the wrong row silently drops it. Selecting the schedule sets param 1224 to 2.

**Hub speaker volume (1235, frame `0x04D3`)**: 132-byte body `u32le value ‖
char[128] owner account id`. The app's slider maximum sent 26.

**Hub alarm tone (1281)**: `DeviceMsgBean` `{"type": <n>}`.

**Stop the alarm (1202, frame `0x04B2`)**: an 8-byte body `u32le 1, u32le 0`. The
app sends it from the live view it opens on an alarm; the station stops the siren and
light and reports `0x04B1` = `[16, 0]` on channel 255 ([events.md](events.md#alarm-over-p2p)).

## Recording triggers

HomeBase 3 fw 3.8.7.4, eufyCam 3 (T8160). The station starts a camera recording only on
its own events. No client command records directly. A clip comes from one of these
paths:

| path | what starts the clip | status |
|---|---|---|
| detection | the camera's detection, when the record bit (value 1, `BIT_RECORD`) of its action mask for the mode in force is set ([Mode actions](#mode-actions-delays-and-schedule-app-writes-verified)) | **[verified]** that detections record with masks 1 and 9. The effect of the record bit on its own is **[open]** |
| automation rule | a station-held rule (1278) whose trigger fires, with a RECORD action on the camera | **[verified]** with a hub-alarm trigger |
| continuous (24/7) | 6010 enable, 6011 time type, 6013 schedule, sent in the 1700 wrapper | **[app]**: only the T8170 handler registers these ids; the T8160 and T8030 handlers do not |

**No direct record command [verified negative].** Each of these was sent to a T8160 on
channel 1 in Away and no recording row appeared in the event database within 150 s:
- 1202 camera siren `{channel, type 10, time_out 10}`, stopped after 5 s. The siren
  sounded.
- 1201 hub alarm `{channel, type 0, time_out 5}`. The hub siren sounded.
- Bare 1009 held for 20 s, then bare 1010. These are `START/STOP_FIXED_RESOLUTION`
  (`live_record_set`), a live-picture setting despite the app enum's `START_RECORD` name.

The app's handlers have no "record now" identifier for the HomeBase, the T8160
or the T8170 **[app]**.

**Automation list (1278, `device_linkage_mode`) [verified].** A `DeviceMsgBean` with
cmd 1278 on `mChannel` 255 whose payload is the whole rule list as a JSON array. The
handler frames it as 1350 / sub 1278. A write replaces the whole list, so it must carry
the existing rules. The station answers with a receipt of 0 and no `0x0547`, and applies
the list at once. The cloud copy of 1278 (base64, in the device list) changes only when
the app uploads it, so it is not a read-back. Verify a restore by behaviour: fire the
trigger and confirm that the removed rule no longer records.

```json
[{"automation_id": <int>, "automation_name": "<text>", "automation_enable": 1,
  "automation_trigger": [{"device_sn": "<sn>", "device_type": <type>, "trigger_mode": <BCTriggerMode>}],
  "automation_action": [{"device_sn": "<sn>", "device_type": <type>, "action_mode": <BCActionMode>}]}]
```

- `trigger_mode` (BCTriggerMode) **[app]**: 0 close, 1 open, 2 motion (camera detection
  and motion sensor), 3 HomeBase alarm, 4 delayed HomeBase alarm, 5 doorbell press,
  6 water, 7 smoke, 8 temperature, 16 sound, 32 recognition, 64 lock, 65 lock error,
  66 unlock, 144/145 cloud motion, 149 glass break, 150 tamper. Only 3 is
  **[verified]**.
- `action_mode` (BCActionMode) **[app]**: 1 RECORD, 2 device alarm, 4 HomeBase alarm,
  8 push, 64 call 911, 256 privacy, 512 quick response, 1024 camera on/off, 2048
  doorbell lock, 4096 light lock, 8192 PTZ record, 65536 light effect. Only 1 is
  **[verified]**.
- The app's extended rule shape **[app]** adds `trigger_config` (camera detection:
  `{detectValue, other}` with bits human 3, vehicle 4, pet 8, take-package 512,
  package 1536, motion 32768), `action_config`, and `automation_time`
  `{repeat, from, to}` (the window in which the rule is active). The rule the station
  holds on fw 3.8.7.4 has the shape shown above.
- **Which triggers and actions a device offers [app].** A device takes these from its
  thing-model property `automation_config` (`{"trigger": [...], "action": [...]}`, in
  the app's own codes, not BC codes): T8030 triggers 3/4 (HomeBase alarm, delayed alarm)
  and has no actions; T8160 on a HomeBase 3 has trigger 12 (its own detection) and
  actions 0/3/6 (camera on/off, RECORD, alarm); T8170 has trigger 12 and actions 0/4/6,
  where 4 is PTZ record. A motion sensor (T8910) only triggers. A sensor has no record
  bit in its mode action mask, so a rule is the only way for it to cause a clip.
- **Where a rule runs [app].** If the trigger device is on a HomeBase, the rule is
  written to that station's 1278 and the station runs it (no cloud, no app). If the
  trigger device is standalone, the app stores the rule in the cloud
  (`app/automation/insert_automation_link_setting`).
- **Clip length [verified].** The RECORD action carries no duration: its
  `action_config` is always `{}`, and PTZ record's config chooses a preset position. A
  hub-alarm-triggered RECORD clip was a fixed 10–12 s in five runs, whatever the
  settings: `clip_length` (1249) 60 or 20, `power_mode` (1246) 1 or 2, alarm
  `time_out` 5 or 15 s. The clip started 1–2 s after the alarm, and its
  event-database row appeared 20–35 s after the alarm, carrying the rule's
  `automation_id` and `trigger_type` 1. `clip_length` sets the camera's own detection
  clip, not this one.

**On-demand recording [verified].** Install a rule with HomeBase-alarm trigger (3) and
RECORD action (1), then send 1201 `{channel, type 0, time_out n}`. This records every
time, but it costs:
- the hub siren (the minimum volume, 1 of 26, is still audible),
- the station's alarm state (`triggered` over FCM),
- a fixed 10–12 s clip.

The siren-free triggers this hardware offers (camera detection, sensor motion) need
something to move in view. A client cannot fire them.

**[open]**
- Clip length when one camera's detection triggers RECORD on another camera, and whether
  the target camera's `clip_length` applies.
- Whether clearing the record bit (1) of the Away mask stops the clip while the push still fires.
- A second 1201 during a clip: in one session, 1201s sent after a stop (`time_out` 0)
  were acknowledged and ignored, while a fresh session worked.
- Whether a command id unused by the app would start a recording. None has been
  probed.

## GET commands: not served **[verified]**

The app's `APP_CMD_GET_*` ids sent as a `DeviceMsgBean` with an empty payload, on
`mChannel` 255 and 0, all return receipt −108 and nothing else — no `0x0547`
result and no parameter push (HomeBase 3, fw 3.8.7.4): 1101
`GET_BATTERY` (handler `BATTERY_VALUE`), 1107 `GET_ARMING_INFO`, 1108 `GET_ARMING_STATUS`, 1126
`GET_HUB_TONE_INFO`, 1128 `GET_HUB_NAME`, 1131 `GET_DEV_STATUS` (handler `DEVICE_STATUS`), 1137
`GET_HUB_POWWER_SUPPLY`, 1140 `GET_HUB_LOGIG` (handler `GET_HUB_LOGIN`), 1151 `GET_ALARM_MODE`, 1152
`GET_DEVICE_PING`, 1164 `GET_DELAY_ALARM`, 1176 `GET_HUB_LAN_IP` (handler `GET_IP_ADDRESS`), 1177
`GET_OFF_ACTION`, 1239 `GET_AWAY_ACTION`, 1265 `GET_WAN_MODE`, 1268
`GET_WAN_LINK_STATUS`, 1274 `GET_DEVS_RSSI_LIST`, 61025 `GET_DELAY_PRO_ALARM`.

The parameter query with its second `u32le` changed from 903 to a single id (1158,
1140, 1235, 1254) or 0 got no parameter reply either, and the subheader dev_type (255, 0, 1 or 16)
is ignored: each returns the same full dump, with no parameter added. **So the
parameter dump is the only local read.** The app agrees: its P2P send table
(`AndroidP2PClient.p2pSendRequestByCommand`) has only the 1103 query as a read and
only SET shapes for the parameters the dump lacks (1235 as a value, 1254 and 1256 as
JSON). Those values reach the app through the cloud device list.

Their ids (1157–1159, 1235, 1254, 1256, 1278) are SET commands. Never send one as
an empty "read": the station may take it as a write.

## The 1700 wrapper: a standalone device's commands **[verified]**

A standalone device takes many commands inside XZYH type `0x06A4` (1700
`DOOR_BELL_PAYLOAD`, app enum `DOORBELL_SET_PAYLOAD`), GCM, on channel 0: `{"commandType": <sub-command>, "data":
{…}}`. It answers with a receipt of type `0x06A4` and, for a query, a 1351 notify whose
`cmd` is the sub-command. Which command a device takes this way comes from the app's
handler for its model ([thing-models.md](../reference/thing-models.md)). Verified on a
T8170:

| sub-command | body `data` | answer |
|---|---|---|
| 1000 start live stream | see [media.md](media.md#standalone-device-open-17001000-stop-bare-1004-ping-1139-verified) | the stream |
| 6034 preset query | `{"value": 0}` | notify `{"cmd": 6034, "payload": {"points": [{"index", "enable", "zoom", "isdefault"} × 10]}}` |
| 6035 go to preset | `{"value": <slot>}` | receipt; 6203 `{"dstZoom": …}` about 2 s later; the camera stands still within 7 s |
| 6030 pan/tilt one step | `{"cmd_type": 1, "rotate_type": 1-4, "zoom": 1, "ivalue": -1}` | receipt only; the camera moves one fixed step and holds |
| 6032 store preset | `{"value": <slot>, "settingstate": 0}` | receipt only; confirm with a 6034 read |
| 6033 delete preset | `{"value": <slot>}` | receipt only; confirm with a 6034 read |
| 6097 preset picture | `{"value": <slot>}` | notify `{"cmd": 6097, "payload": {"index", "data"}}`; `data` is the slot's stored JPEG in URL-safe base64, empty for an empty slot |

**Pan/tilt (6030)** is a **step, not a drag**: each send moves the camera one fixed
amount and it then stands still, so there is no stop command — the app's pad sends one
6030 per press. `rotate_type` is **1 left, 2 right, 3 up, 4 down**, named as the
camera turns (the view follows) **[verified, T8170]**, measured by correlating keyframes
*within one held live stream*: the camera returns to its default preset about 7 s after its last traffic,
so a turn compared against a freshly opened stream reads back as no movement at all.

**Storing a preset (6032)** is receipt-only and **silently does nothing when the camera
is full**: a T8170 keeps **at most 5 slots** of the ten indices the 6034 read reports,
and a store beyond that is receipted exactly like one that worked. Only a 6034 read-back
distinguishes them; 6033 frees a slot and the next store then takes
**[verified, T8170]**.

**A preset command sent while the camera is still moving is rejected with receipt
code 1** — a 6034 read right after a 6032 store got code 1 and the same read succeeded
seconds later. Code 1 here means "busy", not "bad command", so it is worth re-sending
**[verified, T8170]**.

**6249 `device_thumbnail_path` is a HomeBase (T8030) command, not a camera one**: it is
`cmd 1350 / subCmd 6249` (notify `1351/6249`) in the T8030 handler and absent from the
T8170 and T8160 handlers. A standalone camera's `device_thumbnail_path` is the 10013
event-count query instead.

**Set the default preset** — the slot the camera returns to on its own when idle — is
**not** a 1700 command but a **1350** `DeviceMsgBean` (`CMD_TRANSFER`, cmd 6242
`COMMAND_APP_SET_DEFAULT_POSITION`, on channel 0): `payload {"index": <slot>,
"settingstate": 0}`. The camera answers a receipt only (no result frame); the new
default shows up as `isdefault` in a following 6034 read. `settingstate` is 1 to confirm
a slot the camera first refuses with code −502 (the app's "set anyway?" dialog). The
app follows the write with a 6035 turn to the slot and a 6097 picture; the library sends
the turn and re-reads 6034 **[verified, T8170]**. The camera then returns to
that slot by itself after any manual turn, preset capture or tracking, once it goes idle
(verified: turned to another preset, it was back at the default after a 90 s sleep).

**Picture zoom** is a **1350** `DeviceMsgBean` too (`CMD_TRANSFER`, cmd 6203
`COMMAND_DUAL_CAMERA_ZOOM`, the handler's `set_picture_zoom`, on the camera's channel, which
subheader byte 2 names as well): `payload
{"x": 0, "y": 0, "w": 0, "h": 0, "offset": false, "orgZoom": 0, "dstZoom": <zoom>}`, the
centre zoom (`offset` true zooms into the x/y/w/h window instead; not used). `dstZoom` is
the factor, a float. The camera receipts it and echoes the payload in a 1351 notify
`{"cmd": 6203, …}` within 0.1 s; the picture follows within 3 s, in a running stream too.
It also reports its zoom unasked, as notify `{"cmd": 6203, "payload": {"dstZoom": z}}`
(ECB, channel 2), after each live open and about 2 s after each go-to; `z` 0 and 1 both
mean 1x **[verified, T8170]**:

- `dstZoom` below 1 gives 1x, 1–12 give the zoom asked for within 10 %, and beyond that
  the camera stops at about 14x.
- From 2.5x up the picture is streamed at 2304×1296 instead of 2880×1616; 2x and less
  keep 2880×1616.
- The zoom does not last: a go-to sets the slot's own stored zoom, and a reopened view
  and the idle return are at 1x.
- The handler's thing description offers it only in single view (6243 = 0).
- Behind a HomeBase 3 the same command reaches a paired T8170 when subheader byte 2
  names the camera's channel ([p2p-transport.md](p2p-transport.md#subheader)); the camera
  echoes it on that channel and zooms as standalone (`dstZoom` 4 → 3.95x, 8 → about
  7.7x). With byte 2 at 0 the HomeBase answers receipt −108 **[verified, T8170 behind a
  HomeBase 3]**.
- A 6030 step with `zoom` 1 turns the camera the same angle at any picture zoom, so the
  view moves as many times further as the picture is zoomed; the app's pad sends the
  picture's zoom there for a finer step.

## Result codes

| where | code | meaning |
|---|---|---|
| ECB scalar reply | 0, −103, −104, −106, −110 | see [session-crypto.md](session-crypto.md) |
| JSON reply | `mIntRet` 0 / `msg` `"SUCCESSFUL"` | success |
| JSON reply | `-6006` | ERROR_NO_SUPPORT (unsupported query verb) |
| 132-byte receipt | 0 / −108 | taken off the queue / command not handled ([receipt](#command-receipt-verified)). `1051` (`STOP_DOWNLOAD_VIDEO`, app enum `DOWNLOAD_CANCEL`) is −108 **[verified]**. |
| 132-byte receipt | −204 | the station could not wake the camera (live open) **[verified]** |
| 1700 receipt, preset commands | 1 | the camera is still moving; the same command succeeds once it stops **[verified, T8170]** |
| media / download | −104 | INVALID_ACCOUNT: the owner-id gate |
| (none) | — | silence after an ACK: wrong `account_id`, or a database query missing its paging fields |
