# Events

A station reports what happens at the house on two independent channels:

| | local P2P push | cloud push (FCM) |
|---|---|---|
| transport | the PPPP session already held | Firebase Cloud Messaging from the eufy backend |
| needs internet | no | yes |
| latency | about 1 s **ahead** of the cloud, about 3 s behind the trigger **[verified]** | about 1 s behind local **[verified]** |
| camera detections | yes, with on-disk video, thumbnail and crop paths | yes (same inner JSON), with `pic_url` |
| guard-mode changes | changes over P2P, from the app and from a schedule announced by `0x047F` **[verified, fw 3.8.7.4]**; keypad changes **[open]** (poll the parameter dump); no arming push (msg_type 9) over P2P | **pushed**, decoded within about 1 s **[verified]** |
| parameter changes (battery, settings) | pushed as dumps, plus polling | no |
| stills | 640×360 thumbnail, crop, 4K from the recording ([media.md](media.md)) | encrypted `pic_url` thumbnail **[app]** |
| off-LAN | no | yes |

Code: `src/eufy_home_security/p2p/notify.py` (P2P push decode), `p2p/alarm.py`
(alarm frames), `p2p/params.py` (dumps), `p2p/session.py` (probe and supervision),
`src/eufy_home_security/push/fcm.py`, `push/decode.py` and `push/const.py` (FCM),
`events.py` (ordering, alarm tracking, de-duplication).

## Local P2P push **[verified]**

### No subscription

Any established session receives pushes. A client that sent nothing after
CONN_INIT, and a second client connected at the same time, both received the same
event in the same second. The app sends `START_REC_BROADCASE` (900) **[app]** and the
1139 ping ([p2p-transport.md](p2p-transport.md#frame-types)), but a HomeBase 3 requires
neither. Keep the session alive with ALIVE ([p2p-transport.md](p2p-transport.md)).

### Frame

```
XZYH 0x0547 (NOTIFY_PAYLOAD), cipher tag 0x08 or 0x01, decrypted:
{"cmd": 2037, "payload": "<JSON object serialized as a STRING>"}
```

- `cmd` 2037 (`CAMERA_PUSH_NOTIFY`) is the **only** thing that separates an event
  from a command result on this frame type.
- `payload` is double-encoded: parse the outer JSON, then parse the string.
- The same event arrives under GCM or ECB depending on the client (see
  [session-crypto.md](session-crypto.md)).
- The decoded `SecurityEvent` carries the frame's cipher as `frame_cipher`.
  `authenticated` is True under GCM (the tag proves the station sent it) and False
  under ECB (the static key is derivable on the LAN). An ECB push is still
  delivered. Neither proves freshness: station → client frames carry no seq, so a
  GCM frame can be replayed within one session.
- A cloud push has `frame_cipher` None and counts as authenticated (TLS from
  eufy's servers).

### Payload

The inner object is the same object the backend relays over FCM (long-key form):

```json
{"msg_type": 18, "event_type": 3102,
 "device_sn": "T8160XXXXXXXXXXX", "name": "<camera name>", "channel": 1,
 "create_time": 1700000000000, "trigger_time": 1700000000000,
 "file_path": "/zx/hdd_data0/Camera01/<YYYYMM>/<YYYYMMDDhhmmss>/<...>.zxvideo",
 "pic_url": "", "pic_filepath": "", "push_count": 1, "notification_style": 1,
 "storage_type": 1, "session_id": "...", "unique_id": "...", "record_id": 0,
 "rec_content": [{"account": "<owner user id>", "device_sn": "T8160XXXXXXXXXXX",
                  "station_sn": "T8030XXXXXXXXXXX", "device_type": 19,
                  "start_time": "YYYY-MM-DD hh:mm:ss", "end_time": "...",
                  "storage_path": ".../<...>.zxvideo", "thumb_path": ".../snapshort.jpg",
                  "trigger_type": 4, "video_type": 2, "frame_num": 351}],
 "pic_content": [{"crop_path": ".../<...>.jpg", "detection_type": 1, "person_id": 0,
                  "bbox_ul_x": 0, "bbox_ul_y": 0, "bbox_bd_x": 0, "bbox_bd_y": 0}]}
```

| field | use |
|---|---|
| `trigger_time` / `create_time` | **epoch milliseconds**. Use `trigger_time` as the event time, not arrival time. Both decoders take `SecurityEvent.event_time_ms` from them (`trigger_time`, else `create_time`). |
| `unique_id` | a per-occurrence id, identical on the P2P and the FCM copy: `SecurityEvent.unique_id` (printable ASCII, at most 64 characters) and the de-duplication key |
| `record_id` | the occurrence's event-database row (`SecurityEvent.record_id`; `0` = none): binds the attached records |
| `device_sn`, `name`, `channel` | the camera. Trust these top-level fields for the event itself. |
| `file_path` | the event's recording, for the 4K trigger frame ([media.md](media.md)) |
| `rec_content[].thumb_path` | the fetchable 640×360 thumbnail (`pic_url` and `pic_filepath` are empty locally) |
| `pic_content[].crop_path` | the detection crop |
| `rec_content[].account` | **the owner account_id**, the id the station accepts commands from. On an authenticated (GCM) push whose stamps all differ from the id the session sends (case-insensitively), the session emits `AccountMismatch(station_sn)` once per connection. It never logs either id in clear and never adopts the stamped id. ECB pushes are not checked, and neither are cloud pushes: a remote station gets no commands. |

- `rec_content` and `pic_content` are attached database records and **may describe an
  earlier event**, even on another camera **[verified]**: a Camera01 event
  arrived with a `rec_content` record and a `pic_content` crop of Camera00 hours
  earlier, and in all seven detections captured on fw 3.8.7.4 the attached records'
  `record_id` was an earlier event's while the push's own `record_id` named the new
  clip. The library never takes the event's device, station or time from them.

### Binding the attached records

A record is **bound** to the push when its `record_id` equals the push's `record_id`.
A push without a `record_id` (older firmware) falls back to the rules marked *no
`record_id`*.

| field | taken from | rule |
|---|---|---|
| `station_sn` | the session | always the session's station; `rec_content[].station_sn` is ignored |
| `thumb_path` | the bound `rec_content` entry | None when none is bound. *No `record_id`:* the first entry whose `device_sn` equals the top-level `device_sn` |
| `video_path` | top-level `file_path`, else the bound record's `storage_path` | |
| `crop_path` | the bound `pic_content` entry | None when none is bound. *No `record_id`:* `pic_content[0]`, kept only when its `CameraNN` directory equals the one in `video_path`, or, when neither path has one, when the `rec_content` binding matched **[inferred]** |

When nothing is bound (the usual case on fw 3.8.7.4), take the thumbnail from the history
row (1306/10011) of the push's `record_id`, whose `thumb_path` is in the new clip's folder. The library does this in
`Station.async_event_thumbnail` ([media.md](media.md#stills-1308-verified)).

### Validating untrusted fields

A push is the station's, and under ECB anyone's on the LAN. Its paths become command
payloads (a still fetch's `file`, a playback's `filepath`), so both decoders check them
before lifting. A value that fails is dropped (None) and its field name is listed in
`SecurityEvent.rejected_fields`; the rest of the event is still delivered.

| check | rule |
|---|---|
| media path | starts with `/zx/`; ends in `.jpg` (thumbnail, crop) or `.zxvideo` (recording); at most 256 characters; printable ASCII; no `..` |
| event time | in epoch **ms**, within 2020-01-01 .. 2100-01-01, and at most 600 s ahead of the host clock. A time ahead of the clock is logged once (a wrong host or station clock). |
| names | `device_name`, `person_name` and `user_name` are cut to 64 characters |

An attached record that is merely unbound is not a rejection: its fields are None and
`rejected_fields` does not name them.
- **The same event can be announced again** (`push_count` > 1), and with cloud push
  on, every detection also arrives over FCM. See
  [De-duplication across channels](#de-duplication-across-channels).
- **There is no "cleared" edge.** The station announces a detection, never its end.
  Hold a binary state on and drop it on a timer (10 s matches the observed pattern).

**`msg_type`** (subsystem), the app's push enum **[app]**, values marked with `*` seen live:

| | | | |
|---|---|---|---|
| 1 SECURITY_EVT | 2 TFCARD | 3 DOOR_SENSOR | 4 CAM_STATE |
| 5 GSENSOR | 6 BATTERY_LOW | 7 BATTERY_HOT | 8 LIGHT_STATE |
| 9 ARMING `*` | 10 ALARM | 11 BATTERY_FULL | 12 REPEATER_RSSI_WEAK |
| 13 UPGRADE | 14 MOTION_SENSOR | 15 BAT_DOORBELL | 16 ALARM_DELAY |
| 17 HUB_BATT_POWERED | 18 INDOOR `*` (cameras paired to a HomeBase 3) | 19 SMARTLOCK | 20 LOCK |
| 21 BBM_SOCK | 22 DOOR_STATUS | 23 HHD | |

**`event_type`** (detection): 3101 motion, **3102 person** `*`, 3103 doorbell press,
3104 crying, 3105 sound, 3106 pet, **3107 vehicle** `*`, 3108–3110 dog / lick / poop,
**3111 identified person** `*`, 3112 stranger.

**`notification_style`**: 1 text, 2 thumbnail, 3 both.

### Station pushes: arming and alarm

`msg_type` 9 (ARMING), 10 (ALARM) and 16 (ALARM_DELAY) describe the station, not a
device: `SecurityEvent.scope` is `station` for them and `device` for everything else.
Both decoders lift the same fields from the inner payload:

| payload field | `SecurityEvent` field | meaning |
|---|---|---|
| `arming` | `guard_mode` | the **selected** guard mode (2 while Schedule is selected); over P2P only from an authenticated frame (see below) |
| `mode` | `mode` | the mode **in force** (a schedule slot's mode while Schedule is selected) |
| `type` | `alarm_type` | the alarm cause, on msg_type 10 and 16 only. On FCM the **outer** `type` is the device type and is never used here. |
| `alarm_delay` | `alarm_delay` | seconds |
| `user` | `arming_user` | who armed, as a code |
| `user_name` | `user_name` | whatever the arming client sent; **not authenticated** |
| `nick_name` / `person_name` | `person_name` | the identified person (event 3111) |
| `push_count` | `push_count` | |

Derived properties, which apply the authentication rule of the frame:

| property | rule | evidence |
|---|---|---|
| `alarm_phase` (one push; the alarm's state is [`AlarmChanged`](#alarm-lifecycle)) | msg_type 10 → `triggered`, or `stopped` when `alarm_type` is 15 keypad / 16 app / 17 HomeBase **and** the event is authenticated (an unauthenticated stop is None, `alarm_type` still set); msg_type 16 → `delay` | msg_type 10 **[verified]** over FCM: `alarm_type` 3 and 25 at a trigger, **16 when stopped from the app** (device = the station, channel 255). msg_type 16 not captured (no delay was configured). Over P2P no msg_type 10 push exists: see [Alarm over P2P](#alarm-over-p2p). |
| `arming_source` | msg_type 9 and authenticated only: `user` 1 → `keypad`, 5 → `key_fob`, any other code → `app`; None without a `user` | **[app]** `CusPushMode`. Captured FCM arming pushes: `user` 2 from the app and a P2P client; **`user` 0 with `user_name` "Eufy Security" from a schedule slot** — which the rule above maps to `app` |

The enum members carry this grading in code (`PushMessageType.evidence`,
`DetectionType.evidence`, `AlarmStopSource.evidence`, `ArmingSource.evidence`).

- **Over P2P these pushes are not sent [verified fw 3.8.7.4].** Across alarms,
  app stops, app arms and schedule changes, no msg_type 9, 10 or 16
  arrived on any P2P session: the station reports the same facts with `0x047F` and
  the alarm frames below. The P2P decoder's lifting of these fields is a **dormant
  path**, kept so a firmware that sends them passes the same rules: it takes
  `guard_mode` only from an authenticated (GCM) frame (under ECB it is None and listed
  in `rejected_fields`), and guard modes from both channels pass one ordering rule
  ([Guard-mode ordering](#guard-mode-ordering)).
- An alarm stop can be replayed (neither channel proves freshness). Order stops and
  triggers by `event_time_ms`, compared at **second** granularity, because FCM times
  are seconds.

### Alarm over P2P

**[verified, fw 3.8.7.4]** Every open session receives these GCM frames. The
subheader's byte 2 is the channel (255 = the station). Bodies are u32le values.

| frame (cmd) | body | meaning |
|---|---|---|
| `0x04B1` (1201 `SET_TONE_FILE`) | `[event_type, seconds]` | the station's alarm tone: `[3, 30]` on the triggering camera's channel starts a 30 s alarm; `[0, 0]` ends it; **`[16, 0]` on channel 255 = stopped from the app** |
| `0x04B2` (1202 `SET_DEVS_TONE_FILE`) | `[event_type, seconds]` | the camera's siren: `[25, 30]` on, `[0, 0]` off |
| `0x0578` (1400 `FLOODLIGHT_MANUAL_SWITCH`, app enum `SET_FLOODLIGHT_MANUAL_SWITCH`) | `[0 \| 1]` | the camera's light: 1 on during the alarm; also 0 at each detection and periodically |
| `0x047F` (1151) | u64le mode | the effective guard mode |

The station's history records the same alarm as `msg_type 10` rows with
`event_type` 3 and 25 (`str_extra`), matching the tone values. Timeline of one alarm:

| t | frames |
|---|---|
| detection | `0x0578` ch1 = 0, then the `2037` push about 2 s later |
| trigger (+1.3 s) | `0x04B1` ch1 `[3, 30]`, `0x04B2` ch1 `[25, 30]`, `0x0578` ch1 = 1 |
| 30 s later, if not stopped | `0x04B1` ch0 `[0, 0]`, `0x04B2` ch1 `[0, 0]` |
| app stop | `0x04B2` ch1 `[0, 0]`, `0x04B1` ch255 `[16, 0]`, `0x04B2` ch1 `[0, 0]`, `0x0578` ch1 = 0 |
| disarm during the alarm | `0x04B1`/`0x04B2` `[0, 0]` on each channel, `0x047F` = 63; the siren stops |

Arming and disarming also send `0x04B1`/`0x04B2` `[0, 0]` on each channel next to the
`0x047F`.

**What the library does with them.** The session decodes the three frames (GCM only: an
ECB copy is refused once a session key exists and counted in `ecb_state_refused`, like
the other state frames), caches the first value per `(channel, param)` — the tone's or
siren's event type, the light state — and emits `ParamChanged` when it moves. The tone
frame (1201) also drives `AlarmChanged`, on transitions only: a non-zero event type that
is not a stop code starts the alarm (`duration_s` from the seconds), `[0, 0]` ends it,
and `[16, 0]` ends it with `stop_source` `APP`.

### Alarm lifecycle

`AlarmChanged(station_sn, alarming, channel, event_type, duration_s, stop_source,
source)` is the alarm's state, from both channels. `EufySecurity` passes both through
one account-wide `AlarmTracker` (`events.py`), so each alarm is one start and one end:

| input | effect |
|---|---|
| P2P tone frame (above) | applied at once, stamped with the host clock |
| FCM msg_type 10, `alarm_type` 3 or 25 | starts the alarm (`event_type` = `alarm_type`) |
| FCM msg_type 10, `alarm_type` 15 / 16 / 17, authenticated | ends it, with `stop_source` |
| a guard-mode change whose mode in force is disarmed | ends it (`stop_source` None) |

- A push that repeats the state already known emits nothing: the cloud copies of a P2P
  trigger (3 and 25) and of an app stop (on the camera's channel and on 255).
- A push more than 300 s old, or older than the station's last transition (a late
  trigger arriving after the alarm ended), is ignored; so is an unauthenticated push.
- The `SecurityEvent` of each alarm push is still delivered, with `alarm_phase`.
- **Cloud only:** an alarm that times out sends no push, so without a P2P session it
  stays on until a stop push or a disarm.

### Other station-initiated frames

| frame | meaning |
|---|---|
| `0x044F` without a request | parameter-change push: a full or partial dump, to diff against state **[verified]**. The library emits `ParamChanged` per frame and one `StationStateChanged` once the dump completes, if the state changed ([commands.md](commands.md)) |
| `0x051A` | "new rows in the event database". Pull with a 1306 query. |
| `0x047F` | guard mode in force after any change (see below) |
| `0x04B1`, `0x04B2`, `0x0578` | alarm tone, siren and light ([Alarm over P2P](#alarm-over-p2p)) |
| `0x0408` (1032) | Wi-Fi RSSI (`[-61, 0]`) of a camera while it streams |
| `0x0547` cmd 6246 | live viewers of a camera: `{"num": 1}` when a stream opens, 0 when it closes — every session sees another client's live view |
| `0x0547` cmd 1307 / 1082 | storage records and 1082 answers, including those requested by another client ([commands.md](commands.md#storage-1307-verified)). The library keeps each GCM 11001 record and emits `StorageChanged` when it differs from the last |
| `0x0402` (1026) | `02` when a recording playback ends ([media.md](media.md)) |

## Guard mode announcements

- **Changes made over P2P are announced [verified, fw 3.8.7.4].** Each real change
  (Custom 1, Disarmed, Away) made through a P2P session emitted a `0x047F` report under
  GCM about 1 s before the matching cloud push, and a separate, passive session on the
  same station received it too. The library emits it as `GuardModeChanged` with source
  P2P. Setting the mode already in force sends no report.
- **Changes from the app and from a schedule are announced too [verified, fw
  3.8.7.4, app 6.1.00].** Three app arms/disarms each produced one `0x047F` on the
  library's sessions within a second, and each schedule slot boundary produced one
  with the **slot's** mode (the effective mode — never 2). On fw 3.8.6.0 app arms
  produce no report. Keypad changes are untested.
- **A schedule is two values.** Selecting Schedule changes param 1224 to 2 and sends
  no `0x047F`; the slot's mode then arrives as `0x047F` and in param 1151. The cloud
  push for each boundary carries `arming` 2 and `mode` = the slot's mode. The library
  keeps both (next section).
- **Poll.** The parameter dump always carries station param 1224, whoever changed
  the mode and by whatever path. It stays the safety net for any path that sends no
  report. End-to-end latency is one probe interval (observed 5–7 min at a 300 s
  interval).
- **Treat unsolicited traffic as a cue.** The station does push other parameter
  changes unsolicited; on fw 3.8.7.4 a P2P-made change sends the `0x047F` report
  above. Re-probing shortly after any unsolicited dump, or after a data frame that
  yields nothing, is cheap and can shorten the latency for changes that send no
  report. Unsolicited dumps are not emitted on a fixed schedule, so do not design
  the latency around them.
- The station's own event database gets an `ARMING_EVT` row within about 2 s of a
  change ([commands.md](commands.md)). That row is the fastest local confirmation,
  but it too must be queried.
- For sub-poll latency on changes that send no `0x047F`, take guard mode from **cloud
  push** and everything else from the probe.

## Selected and effective mode

| value | P2P | cloud push | library |
|---|---|---|---|
| **selected** (what the user chose; 2 = Schedule) | param 1224 | `arming` | `GuardModeChanged.mode`, `StationState.guard_mode`, `StationSession.guard_mode` |
| **effective** (in force; a slot's mode under Schedule) | param 1151, `0x047F` | `mode` | `GuardModeChanged.active_mode`, `StationState.active_mode` (1151, else `guard_mode`), `StationSession.active_mode` |

- `GuardModeChanged` is emitted once when **either** value changes, so a schedule
  boundary is one event: `mode` stays `SCHEDULE`, `active_mode` moves.
- A `0x047F` report moves only the effective mode while Schedule is selected, and the
  session cues a parameter read, because leaving Schedule for the slot's own mode (from
  the app) sends the same report. Outside Schedule, or before the selection is known,
  the selected mode follows the report. A report of the mode the session's own arm asks
  for is that arm's.
- A cloud arming push is `GuardModeChanged(mode=arming, active_mode=mode)`; a push
  without `mode` takes `arming` as the effective mode outside Schedule, else the last one
  known.
- `async_set_guard_mode(GuardMode.SCHEDULE)` is confirmed by reading param 1224 back:
  the report that follows the arm carries the slot's mode, never 2.

## Guard-mode ordering

Guard mode reaches `EufySecurity` three ways: a cloud arming push, a P2P arming push,
and the station's own state over P2P (a `0x047F` report, a parameter dump, the
read-back of an arm). One account-wide rule (`GuardModeTracker` in `events.py`) orders
them per station:

- **A push** is dropped, event and all, when its event time is more than 300 s old or
  falls in an earlier second than the station's stamp. An admitted push moves the stamp
  to its event time. A push without an event time is delivered.
- **A report** is never dropped. It moves the stamp to 30 s before it was received:
  the push for the same change (about 1 s later, in whole seconds, from another clock)
  still passes, while a push about an earlier change cannot move the mode back.
- **`GuardModeChanged`** is emitted only when the pair (`mode`, `active_mode`) differs
  from the last one emitted for that station. A change seen on both channels is emitted once, with the
  source of the channel that delivered it first; the `SecurityEvent` of each arming
  push that passes is still delivered.
- Stamps only move forward and persist in the session cache (`push.guard_event_ms`),
  so a push redelivered after a restart is still ordered. The last mode is not
  persisted: the first mode after a start is always emitted.

The P2P arming push is a **dormant path**: the station sends none over P2P (verified,
fw 3.8.7.4), so in practice a push is always the cloud's.

## Liveness and supervision **[verified]**

- An idle house sends nothing, and the station answers ALIVE even when the session
  is dead. A monitor watching packets reports "alive" forever on a deaf session.
- **Probe at the application level**: send the parameter dump request when no dump
  has been read for `probe_every` (library default 300 s). If no dump arrives within
  `stale_after` (30 s), tear down and back off before reconnecting (with discovery
  retries). A fresh connection is probed at once, and the failure count resets only
  after a probe succeeds, so a station that completes the handshake but never answers
  backs off instead of cycling at the minimum delay.
- **`ConnectionChanged(connected=True)` means the session answered**, not just that
  the handshake completed: it is emitted once per connection, after the first
  successful parameter read. `connected=False` follows only a `True` that was
  announced. A bare `async_connect()` emits nothing.
- **Background cloud failures are account events.** When a credential refresh or
  the push-token upload hits a cloud error, `EufySecurity` emits one `CloudProblem`
  per error type until the next successful cloud call or login. Such an error is
  delivered only there: the station's `ConnectionChanged` carries
  `cause=CREDENTIALS_UNAVAILABLE` with `error=None`. The library's own cipher-refresh
  cooldown (`RefreshCooldownError`) is not a cloud problem and stays on
  `ConnectionChanged.error`. A re-fetched cipher key emits `CredentialsRefreshed`; a
  key rejected again is `KeyRejectedError` (`cause=KEY_REJECTED`) until the
  key-refresh latch lifts ([cloud.md](cloud.md)).
- **Diff the first dump after a reconnect against state kept from before.**
  Re-seeding from it would swallow exactly the change that happened while the
  session was down.
- Schedule the probe from the last successful parameter read, never from "last data
  received". Media, fetches and pushes are data too: a camera streaming for hours
  would otherwise postpone the guard-mode poll for hours.
- One long-lived monitor session per station, plus short-lived sessions for fetches,
  at most one at a time (the session budget, [p2p-transport.md](p2p-transport.md)).

## Cloud push (FCM)

### Registration **[verified]**

The app uses FCM as its only push transport **[app]**. A headless client registers
**as the Android app**, not as a web-push client:

| step | what | detail |
|---|---|---|
| 1 | Android checkin | Google checkin with a synthetic, persisted `androidId` and security token. Profile fields (IMEI, MAC) are derived from the install's own `openudid` so that each install is a distinct, stable device. |
| 2 | Firebase Installations | project `batterycam-3250a`. The API key is restricted to the app, so the request must send `X-Android-Package: com.oceanwing.battery.cam` and `X-Android-Cert: <app signing cert SHA-1>`. Constants: `push/const.py`. |
| 3 | `c2dm/register3` | as the app package, sender `348804314802`, with the installation auth. The result is the FCM token. |
| 4 | eufy registration | `POST app-push-{region}-pr.eufy.com/app/push/register_push_token`, body `{"token": T, "is_notification_enable": true, "voip_token": T}`. MegaCrypto-encrypted and signed with the ordinary eufy.com identity, not the security realm ([cloud.md](cloud.md)). There is no platform field: `os-type: android` selects FCM. |
| 5 | MCS | hold the socket to `mtalk.google.com:5228`. Messages arrive as plain `app_data` key/value pairs. |

- A web-push registration fails twice over: the Installations call is rejected
  without the Android headers, and web-push payloads arrive ECE-encrypted instead of
  as plain `app_data`.
- **Re-register the token with eufy on every start.** There is no unregister
  endpoint, and a token the backend dropped simply stops receiving. The call costs
  one signed POST on a cached session.
- `androidId` (Google's) and `openudid` (eufy's) are separate identities. Mint both
  per install and never reuse another install's. Several registrations on one
  account (the phone plus headless clients) all receive pushes.
- The MCS socket is long-lived, with heartbeats of 60 s from the
  server and 120 s from the client.
- The upstream FCM client gives up after repeated connect failures and does not
  retry on its own. The listener therefore supervises it: when the client stops
  listening it is rebuilt from the stored credentials, with a back-off that starts
  at 5 s and doubles to a cap.
- A checkin that fails for a network reason or a 5xx keeps the stored device and
  raises. Only an explicit rejection registers a new `androidId`, because every new
  device orphans the tokens registered for the old one.
- Registration errors are typed: network failures, timeouts and 5xx/429 are
  `CommunicationError`, rejections and malformed replies `CloudApiError`. The whole
  start is bounded by a 60 s deadline.

### Message **[verified]** (fields) / **[app]** (full list)

| outer key | meaning |
|---|---|
| `payload` | base64 (URL-safe or standard, padding optional) of NUL-terminated JSON, **not encrypted** |
| `span_id` | **redelivery key**, lifted as `SecurityEvent.push_id`. The backend redelivers on reconnect and re-registration. The app keeps a 1000-entry ring; the listener keeps its own. It never matches the P2P copy of the same event: see [De-duplication across channels](#de-duplication-across-channels). |
| `app_tab` | `eufy_security` (`eufy_home` = robot vacuums on the same channel). The listener drops any other value; a message without `app_tab` is kept. |
| `type` | **device** type, not event type. ≥ 10100 = account-level server push (device removed, invitation, alarm notify). These decode raw-only: no fields are lifted. |
| `event_type` | detection, same 31xx enum as local |
| `station_sn`, `device_sn` | |
| `event_time`, `push_time`, `server_receive_time` | epoch, **seconds or milliseconds**: multiply by 1000 when < 10¹⁰. Every captured `event_time` was seconds (10 digits). The time checks above run after this conversion. |
| `message_id`, `trace_id`, `push_type`, `event_level`, `title`, `content`, `doorbell`, `origin`, `push_control` | metadata and pre-rendered text |

**Inner payload.** Newer firmware uses the long names of the local payload. Older
firmware uses single letters, and **one payload has been seen mixing both**, so map
short keys onto long ones instead of choosing a dialect:

| short | long | short | long |
|---|---|---|---|
| `a` | msg_type | `t` | event time, **seconds** |
| `s` | device/station serial | `m` | online "0"/"1" |
| `c` | channel | `e` | sensor open "1" |
| `n` | name | `k` | cipher id (thumbnail key) |
| `p` | clip file | `f` | person name |
| `i` | fetch/face id (hex) | `j` | sense id (hex) |

**Redelivery.** Because the token is re-registered on every start, old messages
come back after a restart. The listener persists its dedupe ring (span ids with
first-seen times, expiring after 7 days) in the session cache. A redelivered or
out-of-order arming push is dropped by the [guard-mode ordering](#guard-mode-ordering),
so it never overrides a newer mode.

**Guard mode.** An arming push has `msg_type` 9 (`a: 9`) with `arming` (the guard
mode) and `mode` (the mode in force), plus `alarm`, `alarm_delay`, `user_name`, and
a `rec_content[]` record whose `account` is the owner id **[verified]**. The
top-level `user_name` is whatever the arming client sent. The `user_name` inside
`rec_content[].str_extra` is station bookkeeping (it can read `admin` for the same
event). Neither is authenticated. An arming push whose event time is rejected
(implausible or far ahead of the clock) does not lift `guard_mode` either, since it
cannot be ordered; both names are then in `rejected_fields`. The fields and the
properties derived from them are described under
[Station pushes](#station-pushes-arming-and-alarm).

## De-duplication across channels

With cloud push on, a detection arrives twice, once per channel, and the station can
announce it again (`push_count` > 1). The cloud's `span_id` exists only on FCM, but the
inner payload of both copies carries the same `unique_id`. `EufySecurity` passes every `SecurityEvent` from both
channels through one `EventDeduplicator` per account before emitting it
(`EufySecurity(deduplicate=False)` turns this off). The ring outlives session
reconnects. It holds at most 256 keys, each for one hour.

**Key.** `SecurityEvent.dedupe_key` = `unique:<unique_id>` when the payload carries a
`unique_id`, else `device_sn:event second:event_type`. The fallback compares the event
time in **seconds**, because a cloud time without an inner time is whole seconds while
P2P `trigger_time` is milliseconds; `event_type` stays in it, so at worst two detections
of one second are both delivered.

**Which time [verified].** For a detection the FCM *outer* `event_time` runs about 3 s
later than the inner payload's `create_time`, so a key built from the outer time lands
in a later second than the P2P copy's and misses it. The inner payload of both copies is
byte-identical and carries
`create_time`/`trigger_time` in ms plus a per-event `unique_id`, `record_id` and
`session_id`. The cloud decoder therefore takes `event_time_ms` from the inner
`trigger_time`/`create_time` when present, and the outer `event_time` only otherwise
(arming and alarm pushes carry no inner time).

**Attached records.** A copy's `thumb_path`/`crop_path` come only from records bound by
`record_id` ([Binding the attached records](#binding-the-attached-records)).

| copy | outcome |
|---|---|
| station scope (msg_type 9, 10, 16) | always delivered: an alarm stop can reuse its alarm's time |
| no device or no event time | always delivered |
| key not seen, or forgotten | delivered, a `push_count` > 1 repeat too (its first copy may have been lost while a channel was down) |
| key seen, and the copy carries a media path (`thumb_path`, `crop_path`, `video_path`) no earlier copy had | delivered as an **enrichment**: `SecurityEvent.enriches` is True. Typically the P2P copy, with the thumbnail and crop, after the cloud copy. Update the occurrence already shown; do not count a new detection. |
| key seen, nothing new | dropped; counted in `dropped_repeats` when `push_count` > 1, else `dropped_duplicates` |

The push listener also drops FCM redeliveries by `span_id` (`SecurityEvent.push_id`)
before anything reaches the deduplicator.

## Choosing a channel

| need | use |
|---|---|
| camera detections on the LAN | local push: sooner, richer paths, no internet |
| guard mode, within seconds | cloud push (`arming`) |
| guard mode, authoritative | parameter dump (station 1224) |
| batteries, RSSI, storage, settings | parameter dump + local change pushes |
| anything while the station is unreachable | cloud push |
| history and backfill | event database query (1306), or the cloud `app/events/list` API **[app]** |

The AWS IoT MQTT topics (`cmd/eufy_security/<PN>/<SN>/{req,res}`) carry the same
envelope, but carry no camera event traffic, and no arming path exists
over MQTT or REST **[app]**. Arming is P2P only.
