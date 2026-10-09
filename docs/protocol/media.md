# Media

Three ways to get pixels from a camera behind a HomeBase 3, cheapest first:

| source | command | result | wakes a battery camera |
|---|---|---|---|
| event thumbnail or crop | 1308 image fetch | 640×360 JPEG (about 34 KB), crop JPEG | no |
| event recording | 1025 playback or 1024 download | the recorded HEVC + AAC stream. Its first keyframe is the 3840×2160 trigger frame. | no |
| live stream | 1003 start / 1004 stop | live HEVC 3840×2160 at 25 fps + AAC | yes |

Code: `src/eufy_home_security/p2p/media.py` (payload builders, frame parsing,
keyframe decrypt, `MediaDecoder`), `p2p/session.py` (`MediaStream`: open, receive,
stop), `p2p/messages.py` (image request and decode).

## Library API

```python
async with await station.async_open_live(channel=0) as stream:  # or device_sn=
    async for frame in stream:  # MediaFrame(kind="video"|"audio", data, is_keyframe, timestamp_ms)
        ...

stream = await station.async_open_recording(storage_path, channel=1)  # ends by itself
frame = await station.async_trigger_frame(storage_path, channel=1)  # first keyframe
frame = await station.async_event_trigger_frame(event, trailing_frames=8)  # + P-frames
image = await station.async_preset_image(device_sn, preset=1)  # pan/tilt: turn, settle, keyframe
```

- **Trigger frames use a short-lived session.** `async_trigger_frame` (and
  `async_event_trigger_frame`, and `async_snapshot(recording=...)`) opens a second
  `StationSession` to the same station with the same credential provider, plays the
  recording (1025) there, takes the first keyframe plus up to `trailing_frames`
  P-frames (never past the next keyframe), and closes that session in all cases: its
  CLOSE stops the station within about 5 ms (below). The station's long-lived session
  is never flooded by the rest of the recording and never waits for it to drain.
  - The short-lived session binds an **ephemeral local port**, also when the station's
    session pins one: the pinned port is already bound. A firewall that admits only
    the pinned port makes its discovery fail (`StationUnreachableError`).
  - One short-lived session per station at a time; concurrent calls queue. It is
    counted in the station's session budget below, so live streams never take its
    place.
  - `SessionStats.trigger_frame_sessions` counts them.
  - `async_event_trigger_frame` takes the camera from the event's `device_sn` when it
    is paired to the station, else from its `channel`, and raises `UnsupportedError`
    for an event without `video_path`, of another station, or naming no camera.

- A session carries **one media stream at a time**; a station serves several at
  once, one per session **[verified]**: a HomeBase 3 streamed six cameras' live views
  on six sessions at full rate, and a T8170 four views on four sessions.
- **Live on a HomeBase: an extra session per concurrent stream.** The first live open
  takes the station session's slot. While that slot holds any stream (another camera,
  the same camera, a recording), `async_open_live` connects an extra session to the
  station (same credentials, learned address, an ephemeral local port, one handshake of
  about 0.5 s), opens live there, and the stream's end (close, failure, first-frame or
  idle timeout, an unread stream reclaimed) closes that session with a PPPP `CLOSE`.
  - **The session budget** (`StationSession.max_sessions`, default
    `DEFAULT_STATION_SESSIONS` = 6, from `MIN_STATION_SESSIONS` = 2 to
    `STATION_SESSION_LIMIT` = 9): the station session, one trigger-frame session and
    `max_sessions - 2` extra live sessions, so `max_sessions - 1` live streams (5 by
    default). The default leaves 3 of a HomeBase 3's 9 sessions to the app and other
    clients; at 9 nothing is left, and the station CLOSEs someone's session when another
    client connects. Past the budget, `LiveStreamLimitError` (a `CommunicationError`,
    `limit` = `max_sessions - 1`) at once, nothing sent; with `wait=True` the open waits
    for the slot or an extra session to free, for at most `first_frame_timeout`, then
    raises it. The budget can change at any time: lowering it ends no stream, raising it
    serves waiting opens at once.
  - A live still (`async_snapshot` without a recording) and a preset capture are live
    opens and take the same route: beside a live view they run on an extra session
    **[verified, HB3: stills of the viewed camera and of another camera]**.
  - The wake backoff (`CameraWakeError`, `wake_backoff_left`) is shared: a wake
    failure on an extra session refuses the next open of that camera on any session.
  - `SessionStats.extra_live_sessions` counts them, `extra_live_sessions_open` is the
    number open now; their own media counters are not included.
  - Closing the station session closes its extra sessions.
  - A standalone camera (one camera, 4 sessions in all) and recordings, trigger frames
    aside, keep the one slot: a second open raises `CommunicationError`, or waits.
- With `wait=True` (on `async_open_live`, `async_open_recording`, `async_snapshot` and
  `async_preset_image`; `async_camera_image(…, LIVE)` waits unless given `wait=False`)
  an open that needs the busy slot instead waits for it, for at most
  `first_frame_timeout`, then drains as below. The
  wait holds no lock: commands and parameter reads issued meanwhile go out at once.
  Closing a live stream sends its stop (1004). Closing a recording sends nothing:
  no command stops a playback, and `STOP_DOWNLOAD_VIDEO` (1051, app enum `DOWNLOAD_CANCEL`) would stall the session's
  command queue (below).
- **A closed recording keeps flowing.** Channel-1 frames carry no stream id, and
  nothing but closing the session stops a playback. A recording opened with
  `async_open_recording` and closed early on the station's session therefore still
  arrives to its end (a live stream's in-flight frames too), so before sending the
  next open the session waits until channel 1 has been quiet for 0.5 s (at most 5 s).
  Trigger frames never need this wait: their session is closed instead. The wait
  does not block other requests on the session: commands issued meanwhile go out
  at once, and the open re-checks for quiet before it sends. As a
  backstop, a stream pins the wrapped key of its first keyframe that decrypts to
  Annex-B HEVC and drops keyframes wrapped under any other key. Before that first
  keyframe, a keyframe that does not decode under the stream's RSA key (see
  [keyframe decryption](#keyframe-decryption-verified)) is dropped the same way,
  logged at DEBUG; it is a WARNING only when no keyframe decodes by
  `first_frame_timeout`. A keyframe with the pinned wrapped key that still does not
  decrypt to Annex-B is corrupt and logged as a WARNING.
- Video and audio are delivered from the first keyframe on, video already
  decrypted: Annex-B HEVC that a decoder accepts as is. Audio is ADTS AAC.
- A slow reader does not stall the session: past 250 buffered frames (video and
  audio together), new frames are dropped, video until the next keyframe, and
  counted in `stream.dropped`. A keyframe that does not decode also drops video
  until the next one.
- A recording ends on the station's **end-of-playback frame** (`0x0402` = 2, below):
  the frames already queued are delivered, then iteration stops. Only a recording
  that has delivered its first keyframe takes it, because the frame carries no stream
  id and an earlier playback's end can arrive just after the next open. Without one
  (a download, a lost frame) the stream ends after 3 s without a frame
  (`idle_timeout`).
- No frame within `first_frame_timeout` (20 s live, 10 s recording) raises
  `CommandNotAppliedError` when the station acknowledged the open, the owner-id
  case, and `DeviceTimeoutError` when it did not. Frames that arrive without a
  keyframe that decodes raise `ProtocolError`. A reply with a non-zero code raises
  `CommandRejectedError`.
- A HomeBase live open answered with a wake-failure receipt (−204, below) raises
  `CameraWakeError` at once, and the session refuses further live opens of that
  channel for `WAKE_BACKOFF` (60 s, 300 s, 900 s), raising `CameraWakeError` with
  `retry_after` and sending nothing.

## Stills (1308) **[verified]**

Request and reply shapes: [commands.md](commands.md). Paths come from an event push
(`rec_content[].thumb_path`, `pic_content[].crop_path`) or from event-database rows.

- Reply `0x051C`, ECB-tagged: `{"file": "<path>", "content": "<URL-safe base64>"}`.
- On HomeBase 3 the content is a **plain baseline JPEG**, 640×360 for thumbnails.
- A T8170 standalone camera (fw 3.3.5.4) answers in clear JSON under the ECB tag, and
  its stills are **V1** (below), 640×360 once decoded **[verified]**.
- Check the magic before decoding anyway. The app's image loader recognises
  header-encrypted variants, and cloud `pic_url` thumbnails use them **[app]**:

| first bytes | variant | encryption | key |
|---|---|---|---|
| `ff d8` | plain JPEG | none | — |
| `eufysecurity` | V1 | AES-128-ECB over the first 256 bytes | first 16 chars of the check code `p2p.media.pic_check_code(sn, p2p_did, code)` |
| `v2_eufysecurity` | V2 | AES-256-GCM over the first 256 bytes | the full 32-char check code |
| `v8_eufysecurity` | V8 | AES-256-GCM over the whole body | ECIES-wrapped per-image key under a cloud cipher (`k` in the push) |

**The V1 header** is `eufysecurity:<serial, 16>:<code, 10 digits>:<body>`: serial at
bytes 13–28, code at 30–39, body from 41. The first 256 body bytes are AES-128-ECB
(no padding); the rest is clear JPEG.

**The check code** (`p2p.media.pic_check_code`) **[verified]**: its output decoded a T8170 still to the camera's picture.
With the DID `PREFIX-NNNNNN-SUFFIX`:

1. `s` = a sum over the DID's number `n` (hex digits): `n0 + n1 + n3 + (n3 if n3 < 5
   else 0) + n5` for a 6-digit number; `n0 + n5 + n6 + (n6 if n6 < 5 else 0) + n8` for
   a 9-digit one; `100` otherwise.
2. `base` = the serial from index `(last serial char as hex) mod 10`, then `str(s)`.
3. `seed` = upper-case hex MD5 of `str(1000 − s) + str(int(code[2:10]))`.
4. `d` = SHA-256 of `"01" + base + seed`. For `i` in 0..31, with `next` = `d[i+1]`
   (for `i` = 31: `d[10]`, already rewritten): at even `i`, `d[i] = (d[i] + next) mod
   256` unless `d[i] ≥ 0x7D` and `next > 0x7C`; at odd `i`, `d[i] = |d[i] − next|` when
   `d[i] > 0x7E` or `next ≥ 0x7F`.
5. The code is `d[16:32]` as upper-case hex (32 characters); V1's key is its first 16
   characters as ASCII.

V2 uses the full 32 characters under AES-256-GCM; the library does not decode V2:
no station has been seen sending a V2 still **[open]**.

In the library, `async_fetch_still(path)` returns a `Still(path, data, format)`.
`format` is a `StillFormat` (`JPEG`, `V1`, `V2`, `V8`, `UNKNOWN`) read from the magic,
with the `v8_`/`v2_` prefixes checked before the bare `eufysecurity`. A V1 still is
decoded with the session's DID (`media.decode_v1_still`): `data` is then the JPEG
and `format` stays `V1`. `is_image` is true when `data` is a JPEG; any other still is
returned, not raised, and is not a picture. `async_fetch_image(path)` returns the same
bytes without the label.

**An event's thumbnail.** `await station.async_event_thumbnail(event)` returns the
`Still` of the push's `thumb_path` when the push carried one bound to the event.
Otherwise it reads the event's history row by `record_id` in **one query**: the day is
the id's first eight digits, and a page asked with `start_id` = the id and `count` 2
starts with that row. It then fetches the row's `thumb_path`. On fw 3.8.7.4 the push's
attached records describe an earlier event ([events.md](events.md#binding-the-attached-records)),
so the history row is the usual source. Raised before anything is sent:
`UnsupportedError` for an event of another station, or one with neither a
`thumb_path` nor a `record_id` whose first eight digits are a real calendar day
(`messages.record_id_day`; an id such as `2026139900001` counts as none). After the query: `StillNotWrittenError`
(a `RecordNotFoundError`) when there is no such row or its `thumb_path` is missing;
`RecordNotFoundError` when the row names another camera or its `thumb_path` fails the
media-path rules. **The row itself comes late
[verified]:** 3.8 s after a detection's trigger there was no row; 42 s after there was,
already with its `thumb_path`, while the clip was still recording. An early miss
succeeds on a later retry.

## Choosing an image source

`eufy_home_security.images` names the three sources of the table at the top as
`ImageSource` (`THUMBNAIL`, `TRIGGER_FRAME`, `LIVE`) and describes each in
`IMAGE_SOURCES` (`ImageSourceInfo`: resolution class, content type, whether it wakes the
camera, whether it needs a recording, typical time, verification status).

- `Station.async_event_image(event, source)` → `CameraImage`: the thumbnail
  (`async_event_thumbnail`, JPEG only: an obfuscated still raises `UnsupportedError`),
  the trigger frame (`async_event_trigger_frame`, HEVC), or a live keyframe of the
  event's camera (HEVC). The camera is the event's paired `device_sn`, else its paired
  `channel`.
- `Station.async_camera_image(device_sn, source, days=7)` → `CameraImage`: without an
  event. For `THUMBNAIL` / `TRIGGER_FRAME` it lists the history one day at a time, today
  first (the host's local date), takes the newest row of that camera whose `thumb_path`
  (`.jpg`) or `storage_path` (`.zxvideo`) passes the media-path rules, and fetches or
  plays it; `record_id` and `recorded_at` (the row's `start_time`) identify the event.
  No such row in `days` days raises `RecordNotFoundError`. `LIVE` takes a live
  keyframe.

- The content must be strict URL-safe base64 (padding optional, ASCII whitespace
  ignored), non-empty and at most 1 MiB decoded, or the fetch raises `ProtocolError`.
- Requests carry no correlation id, but the reply is exactly `{"file", "content"}`
  and `file` echoes the requested path **byte for byte**, for thumbnails and crops
  alike **[verified]**. The library binds a reply to its request by
  `file`: a reply naming another path is counted (`still_file_mismatches`), logged at
  debug level with the paths redacted, and ignored. The switch is
  `BIND_STILL_REPLY_TO_PATH` in `p2p/session.py` (on).
- Late replies are discarded. Fetches are serialised, so when a fetch times out its
  reply is owed for 30 s: a 1308 reply naming an owed path, or the next one naming
  no path at all, is taken as that late answer and discarded (`still_late_replies`),
  whether it arrives with no fetch outstanding or during the next one. A reconnect
  forgets owed replies.

The legacy `SNAPSHOT` command (1028) exists in the enum but is untested **[open]**.

## Live stream

### Open (1003) **[verified]**

Sent as a GCM DeviceMsgBean on DRW channel 0, with the XZYH subheader
`08 <ctr> <camera channel> 08 0a 00`:

```json
{"cmd": 1003, "mChannel": <camera channel>, "account_id": "<owner user id>",
 "mValue3": 1003, "mValueStrSub": "<owner user id>", "mValue5": 0,
 "payload": {"streamtype": 0, "camera_type": 0, "entrytype": 0,
   "accountId": "<owner user id>",
   "chn_list": [{"cameraType": 0, "chn": <camera channel>, "index": 0, "sensor": 0}],
   "ClientOS": "ANDROID", "station_video_type": 0, "audio_chn": 0,
   "pip_cord": "", "stitch_mode": 1,
   "key": "<RSA-1024 modulus, 256 hex chars, UPPERCASE>", "extValue": 1000},
 "transaction": "<epoch ms>"}
```

- **The station picks the camera from the subheader, not the JSON
  [verified].** Byte 2 names the camera's channel, as on every command the app sends
  (it copies `mChannel` there; byte 4 is `0x0a` on the live open only). With byte 2 = 0,
  a HomeBase 3 streamed its channel-0 camera for `mChannel` and `chn` 1. With byte 2 = 1,
  it streamed the channel-1 camera.
- The station tags each media frame (`0x0514`, `0x0515`) with the streaming camera's
  channel in subheader byte 2, and the `0x0408` RSSI and 6246 viewer frames too. A live
  `MediaStream` drops frames tagged with another channel (`other_camera_frames`) and
  fails with `ProtocolError` when 25 of them arrive before a frame of its own camera.
  So a consumer never receives another camera's view.
- `key` is the **public modulus of an RSA-1024 key pair the client mints for this
  stream** (exponent 65537 implied). The station wraps the stream's AES key to it.
- `extValue`, `chn_list`, `stitch_mode` and `pip_cord` belong to the app's T8030
  (multi-camera station) branch. The app sends them even for a single camera.
- The owner `account_id` is required. A shared member's session streams when it
  sends the owner id.
- **Stop** with 1004, same envelope with `mValue3: 1004`, payload
  `{"accountId": "<owner user id>", "chn_list": [{"chn": <camera channel>}]}`, subheader
  byte 2 = the channel. The app stops its live view differently: a bare GCM frame of XZYH
  type `0x03EC` (1004) whose body is the channel as `u32le`, with the channel in byte 2
  **[captured, not used]**.
- Camera wake to first frame took about 1.9–2.5 s on a T8160 (battery camera).
  Opening a live stream costs camera battery.
- **A camera the station cannot wake: receipt −204 [verified].** The open is not
  receipted with 0. About 12.3 s after it the station sends one channel-0 `0x0546`
  receipt with code −204 (`XM_WIFI_WAKEUP_FAIL` in the app's error table), and no
  frame follows. The station itself stays up and answers parameter reads meanwhile, and
  its dump still reports the camera online with its battery and RSSI; the other camera
  of the same station streams. A T8160 answered every open from two clients this way
  for 5 h while its dump showed nothing different from when it streamed; the cause is
  not known **[open]**. −203 (`XM_WIFI_DISCONNECT`) and
  −205 (`XM_WIFI_TIMEOUT`) are taken as the same failure **[declared, from the app's error
  table]**.
- The live resolution is not fixed: 3840×2160 at 25 fps (daylight),
  2304×1296 at about 15 fps (night) and **3840×2160 at about 17 fps (dusk, both
  T8160)** with the same open. Resolution and frame rate change
  independently; what selects them has not been isolated **[open]**.
- While a camera streams, every session receives `0x0547` cmd 6246 `{"num": <viewers>}`
  and `0x0408` (1032) frames carrying the camera's Wi-Fi RSSI.

### Standalone device: open 1700/1000, stop bare 1004, ping 1139 **[verified]**

A standalone camera (its own station, e.g. the T8170 Battery SoloCam) takes the 1003
open (receipt code 0) but never streams. The app, and the library, open it with the
standalone recipe (see [thing-models.md](../reference/thing-models.md)): a GCM frame of
XZYH type **`0x06A4` (1700)**, subheader `08 <ctr> <channel> 08 0a 00`, body

```json
{"commandType": 1000,
 "data": {"cmd": 1000, "mChannel": 0, "account_id": "<owner>", "mValueStrSub": "<owner>",
          "mValue3": 0, "mValue5": 0, "restore": 0, "video_type": 12,
          "encryptkey": "<RSA-1024 modulus, 256 hex>", "entrytype": 0, "accountId": "<owner>",
          "camera_type": 0, "ivalue": 1, "extValue": 1000, "streamtype": 0}}
```

- Stop: a bare GCM frame of type `0x03EC` (1004), body four zero bytes. Both get a
  receipt of their own frame type on channel 0.
- Before the first frame the camera sends 1351 notifies 6203 `{"dstZoom": …}`, 6445
  `{"result": 5}` and 6258 `{"module": "live_stream", …}`.
- **Ping.** The app sends an empty XZYH `0x0473` (1139 `PING`) frame, subheader
  `01 <ctr> FF 00 00 00`, every 3 s for its whole session; the camera answers each on
  channel 2. Unpinged, a T8170 ends a live stream about 10 s after the open and then
  answers nothing, so the link times out; pinged, it streamed for the whole 45 s tried.
  The library pings a standalone device while one of its streams is open
  (`MEDIA_PING_INTERVAL`), and not otherwise, so the camera still sleeps after use.
- **Stale first keyframe.** Woken again, a T8170 may start a stream with the last
  keyframe of its previous one (minutes old), followed about 0.2 s later by a fresh
  one; without a replay the first keyframes are about 2 s apart. A live snapshot
  therefore prefers a keyframe that follows the first within 0.5 s.

### Frames

- Media arrives on **DRW channel 1**. Each record's XZYH type is the media command id.
  **ACK every chunk immediately** or the station stops streaming.
- A 132-byte `0x0546` frame arrives on channel 0 during the open: the command
  receipt, code 0 ([commands.md](commands.md#command-receipt-verified)). It is not
  ciphertext and not needed: the key rides inside each keyframe.

| XZYH type | cmd | content |
|---|---|---|
| `0x0514` | 1300 VIDEO_FRAME | H.265 / HEVC Annex-B, up to 3840×2160, ~15 fps (T8160) |
| `0x0515` | 1301 AUDIO_FRAME | AAC-LC ADTS, 16 kHz, mono, about 24 kb/s |

**Video frame payload:**

```
off  0..3    datalen u32le
off  4       keyframe flag: 0x01 = keyframe (VPS/SPS/PPS + IDR), 0x00 = P-frame
off  5       codec: 0x01 = H.265/HEVC, 0x00 = H.264                                            [verified]
off  6..9    frame counter u32le; the high 16 bits are a stream tag on a HomeBase 3
             (0x000f0000 seen), so compare `counter & 0xFFFF`                                  [verified]
off 10..11   width u16le                                                                       [verified]
off 12..13   height u16le                                                                      [verified]
off 14..17   stream clock in ms u32le                                                           [verified]
off 18..21   constant tail (a0 01 00 00 on a HomeBase 3, zero on a T8170)                      [open]
off 22..     body: datalen bytes on a P-frame; on a keyframe the rest of the record,
             datalen + 129 (the wrapped-key prefix, below)                                     [verified]
```

The codec byte matches the read-only `support_video_codec` property of the thing
description (`0:H264, 1:H265`). Every camera observed streams HEVC.

**Audio frame payload:**

```
off  0..3    datalen u32le
off  4..5    zero in every capture                                                             [open]
off  6..7    counter u16le — NOT a frame index on every station (see below)                    [verified]
off  8..11   stream clock in ms u32le, the SAME clock as the video header                      [verified]
off 12..15   the same constant tail as the video header                                        [open]
off 16..     one clear ADTS AAC frame, datalen bytes (the ADTS frame-length field equals datalen)
```

Audio is not encrypted. Concatenating bodies gives a playable `.aac`.

#### Timestamps **[verified]**

Both headers carry **one millisecond clock**, so the two tracks need no separate
anchoring: a muxer can use the header stamp directly (×90 for 90 kHz MPEG ticks, an
exact integer ratio). The clock is free-running from an arbitrary origin — station
uptime, not wall clock — and does **not** restart per stream, so only differences are
meaningful. Over a 20 s HomeBase 3 capture the audio stamps advanced 16 844 ms across
264 frames: **64.0 ms per frame**, exactly one AAC-LC frame (1024 samples at 16 kHz).

The audio `counter` is not portable. On a T8170 it steps +1 per frame alongside a
+64 ms stamp; on a HomeBase 3 it ticks about every 40 ms, so it advances by 1 or 2 per
64 ms frame. **Use the timestamp, never the counter, for timing.**

#### Resolution changes mid-stream **[verified]**

A live stream does not stay at one size. It always begins at the sensor's full
resolution and steps down to the configured streaming quality, each step arriving on a
keyframe with fresh parameter sets. Measured on a T8160 (30 s holds):

| streaming quality | timeline |
|---|---|
| medium | 3840×2160 → **1920×1080 at t+0.62 s** (13 frames at 4K, then 416) |
| low | 3840×2160 → 640×360 at t+0.29 s → 960×540 at t+4.13 s → **1280×720 at t+7.55 s** |

Consumers must therefore follow the per-frame `width`/`height` rather than trusting the
first frame, and anything that muxes the stream must re-emit parameter sets at every
keyframe. See [streaming quality](#streaming-quality-verified) for the setting itself.

A T8170 also changes size **after** the ramp, when the picture zoom (6203) crosses 2x:
measured on held streams, 2880×1616 → **2304×1296** about 1.5 s after a zoom to 3x, and
back on the return to 1x. The first frame at the new size can be a P-frame (one frame,
67 ms, before the keyframe); the return arrived on a keyframe. The same at
`live_streaming_resolution` 1080p: 1920×1080 → 2304×1296 → 1920×1080, the change on a
keyframe. Neither of the candidate "fixed size" controls prevents it:

| control, sent during the stream before the zoom | receipt | size under zoom 3x |
|---|---|---|
| `live_streaming_resolution` (2730) = 1080p | read-back 2 | changes (1920×1080 → 2304×1296) |
| bare 1009 `START_FIXED_RESOLUTION` (app enum `START_RECORD`; handler `live_record_set`) | code 0 | changes (2880×1616 → 2304×1296) |
| `fixed_resolution` 1700/1018 `{"open": 1}` | code 0 | changes (2880×1616 → 2304×1296) |

### Keyframe decryption **[verified]**

P-frames are clear HEVC. A keyframe encrypts only a short header prefix:

```
body[0:128]     RSA-1024 PKCS#1 v1.5 ciphertext of the 16-byte AES-128 key
                (to the modulus sent in 1003; the same for every keyframe of the stream)
body[128]       1-byte marker (0x00)
body[129:257]   AES-128-ECB ciphertext of the first 128 bytes of the frame (8 blocks,
                no IV, no chaining): VPS, SPS, PPS and the slice header
body[257:]      clear HEVC (the rest of the IDR slice)
```

```
aes_key = RSA_PKCS1v15_decrypt(client_priv, body[0:128])
frame   = AES128_ECB_decrypt(aes_key, body[129:257]) ‖ body[257:]      # Annex-B HEVC
```

- Concatenate decrypted keyframes and clear P-frames in order to get a playable
  `.hevc` elementary stream. Mux with the AAC track, or decode one keyframe to a JPEG.
- A body shorter than 257 bytes cannot carry the prefix. Pass it through unchanged.
- **A keyframe wrapped for another key rarely fails the unwrap.** OpenSSL 3.2 and
  later use implicit rejection for PKCS#1 v1.5: decrypting with the wrong private
  key returns a pseudo-random plaintext of random length instead of an error
  (measured: 18 of 20 wrong-key unwraps returned 6-117 bytes on OpenSSL 4.0.1). The
  real guards are that the unwrapped key is exactly 16 bytes and that the decrypted
  prefix starts with an Annex-B start code; the second catches the wrong key that
  unwraps to 16 bytes by chance (about 1 in 100). A key that fails either check is
  never kept as the stream key.
- This is the app's own `aes_decrypt` (whole-block AES-ECB) applied to a fixed
  128-byte prefix. With a longer prefix the clear tail decodes as garbage.
- **ECC / AES-256-GCM media variant** **[app]**: when the app negotiates the newer
  ECC exchange instead of an RSA `key`, frames carry a 129-byte ECC-wrapped key and
  are decrypted with AES-256-GCM (12-byte IV, 16-byte tag, constant 13-byte AAD).
  Driving the open with an RSA modulus always selected the RSA path on HomeBase 3,
  so this variant is not implemented.

## Streaming quality **[verified]**

What the eufy app calls **Streaming Quality** (the thing description's
`live_streaming_resolution`, access mode RW) picks the resolution a live stream settles
at. It does **not** change the codec: every value streams HEVC.

The value is read back from **param 1705** (`STREAMING_QUALITY_OTHER`, app enum `BAT_DOORBELL_VIDEO_QUALITY`). Param 1020 is a
decoy — it reads `0` on a HomeBase 3 while the real setting is 10. The app's parser
selects its value table by `param_value >= 5`; on a HomeBase 3 that is:

| app label | wire value | steady-state size | bitrate |
|---|---|---|---|
| Auto | 5 | 2304×1296 | ~1290 kb/s |
| Low | 6 | 1280×720 | ~425 kb/s |
| Medium | 7 | 1920×1080 | ~523 kb/s |
| High | 8 | 2304×1296 | ~659 kb/s |
| Ultra 4K | 10 | 3840×2160 | ~2280 kb/s |

The write is a **legacy ECB scalar on command 1705 at the camera's own channel**, not a
payload-object command: every `DeviceMsgBean` shape — 1705, 1205, 1020 and 2730, with and
without `channel`, either `value3` convention — is refused with receipt code `-108`
(`NOT_HANDLED`). Channel 255 gives `-106` (`NOT_FIND_DEV`), so it is per-camera and not a
station setting.

A T8170 exposes the same setting with its own labels (`0:Auto, 1:3K HD, 2:Full HD(1080P),
6:HD(720P)`). Recording quality is a separate parameter (**1286**,
`APP_CMD_SET_RECORD_QUALITY`).

Whatever the setting, a stream still starts at full sensor resolution and steps down; see
[resolution changes mid-stream](#resolution-changes-mid-stream-verified).

## Recording playback (1025) and download (1024) **[verified]**

```json
{"account_id": "<owner user id>", "cmd": 1024, "mChannel": <event channel>,
 "mValue3": 1024,
 "payload": {"filepath": "<file_path from the event, .zxvideo>",
             "key": "<RSA-1024 modulus, UPPERCASE hex>"}}
```

- `RECORD_VIEW` (1025) is what the app sends to play a recording. Same payload,
  `cmd` and `mValue3` 1025. On HomeBase 3 fw 3.8.7.4 both commands returned
  **byte-identical** video and audio for the same recording.
- Frames come back on DRW channel 1 as `0x0514`/`0x0515`, identical in format and
  keyframe crypto to live video.
- The whole recording arrives faster than real time: a 20 s recording (324 frames
  of 3840×2160 at about 16 fps, 6.0 MB, plus 20.2 s of AAC) took about 7 s, and a 36 s
  one (1068 frames, 10.6 MB) 6.1 s, with no frame lost and no decode error.
- **End of playback [verified].** About 0.5 s after the last frame of a 1025
  playback the station sends `0x0402` (1026 `RECORD_PLAY_CTRL`) under GCM with the 5-byte
  body `02 00 00 00 00` on channel 2 (0.51 s after the last frame): playback ended. It is the end signal a client can use instead of
  waiting for silence. The value is the body's first `u32le`, 2 being the app's
  `ControlEvent` STOP. Whether the 5 bytes are the body as sent or a GCM plaintext
  is not settled, so `decode_record_play_ctrl` (`p2p/media.py`) takes a body of at
  most 8 bytes as is and decrypts a longer one under the session key.
- **Download frames.** A 1024 download on a short-lived session was followed by
  `0x0517` (1303 `CONVERT_MP4_OK`, a 16-byte ECB block whose first u32 varies and
  whose third is constant) and `0x0518` (1304 `DOWNLOAD_FINISH`, app enum `DOENLOAD_FINISH`, empty) **[observed,
  not decoded]**.
- The **first keyframe is the trigger moment** at full resolution: it arrived 0.4 s
  after the request and decoded to a 3840×2160 JPEG of about 1.7 MB.
- It does not wake the camera: the recording is on the station's storage.
- A −104 (INVALID_ACCOUNT) reply means the `account_id` is not the owner's.
- **No stop command ends a playback [verified].** On HomeBase 3 fw 3.8.7.4:
  - `STOP_DOWNLOAD_VIDEO` (1051) is **rejected**: receipt −108 about 11–12 s after it was
    sent, and like any rejected command it holds the session's command queue until
    then ([commands.md](commands.md#command-receipt-verified)). Do not send it.
  - `PLAY_BACK_EVENT_STOP` (1055, payload `{"filepath"}`) changed nothing: the rest of
    a 6 MB recording kept arriving for about 3.6 s, as with no stop at all.
  - `RECORD_PLAY_CTRL` (1026) with the app's stop payload `{"type": 2, "frame": 0}`
    (`ControlEvent`: 1 PAUSE, 2 STOP, 3 DRAG with `frame` = the seek position), sent 1 s
    into a 36 s playback, changed nothing: all 1068 frames arrived.
- **Closing the session stops it [verified].** The station stops sending to a session
  within about 5 ms of its CLOSE (in-flight datagrams only), and closing a short-lived
  second session mid-playback left the main session's parameter reads at 0.05 s. To
  take one frame of a recording without waiting for the rest, open it on a short-lived
  session and close that session. The library does this for trigger frames
  ([Library API](#library-api)).
- Media opens are more sensitive to the session budget than commands: a clip
  download still worked with idle extra sessions open, where a live open starved.
- What makes the station record a clip in the first place (detection mask, automation
  rules, and no direct record command) is in
  [commands.md](commands.md#recording-triggers).

## Proven and not proven

| item | status |
|---|---|
| thumbnail/crop fetch, plain JPEG on HomeBase 3 | **[verified]** |
| live open, reassembly, keyframe decrypt, playable HEVC + AAC | **[verified]** (T8160 on HomeBase 3) |
| recording download (1024), 4K trigger frame | **[verified]** |
| recording playback (1025), identical output to 1024 | **[verified]** |
| whole-recording receive through the library, ends on the end-of-playback frame, else on silence | **[verified]** |
| stream stop (1004) | **[verified]** (sent; the stream ends) |
| download cancel (1051), playback stop (1055), play control stop (1026) | **[verified]** not to stop a 1025 playback; 1051 is rejected (−108) |
| stopping a playback by closing its session | **[verified]** (station silent within about 5 ms) |
| end-of-playback frame (`0x0402` = 2) | **[verified]** |
| V1 encrypted stills (key from `gen_pic_code_v1`) | **[verified]** (T8170) |
| V2/V8 encrypted stills | **[app]**, not decoded |
| ECC / AES-256-GCM media path | **[app]**, not exercised |
| legacy snapshot (1028) | **[open]** |
| talkback (outbound audio, AUDIO_FRAME from client) | **[app]**, not attempted |
| cameras on other stations, H.264 variants | **[open]** |
| standalone live open (1700/1000), bare 1004 stop, 1139 ping keeping it streaming | **[verified]** (T8170) |
| video header width, height, stream-relative ms time | **[verified]** (T8170); no wall clock |
| video header bytes 18..21, audio header bytes 4..5 and 12..15 | **[open]** |
