# Lock commands

How a lock or unlock command is encoded for a eufy smart lock, per lock family, and how the
lock's answer is read. The library holds these as pure codecs
(`eufy_home_security.lock_commands`) and the choice of form as generated data
(`devices.lock_routes`), and sends them over a station session or the MQTT broker
(§ Commands).

**Grade: declared (eufy app); not tested on hardware.** Every byte below follows the eufy
app's behaviour; no lock has answered any of it. The ECIES scheme is pinned against the
app's own output for synthetic keys. Unlock is a physical security action: a command is a
codec output until a lock owner has tested the path.

All P2P forms travel to the lock's **station** (for a Wi-Fi lock without a HomeBase, the
lock is its own station) as the payload of a P2P command inside the station's command
wrapper, on the lock's channel ([commands.md](commands.md)). A command is applied only when
the lock's state follows: the app confirms by the new state, never by the transport answer.

## Routes

Which form a lock takes is the app's rule over per-product data generated from the app's
lock configuration (`devices/_lock_routes_data.py`, `scripts/gen_lock_routes.py`):

1. The product's rows: a row for a serial character (the serial's 7th character) wins over
   the product's plain row.
2. **MQTT** when the row says so always, or for a lock that is not behind a station when
   it says so for standalone locks only.
3. Else the row's P2P form, with two per-unit switches: the **HKDF** key for the 1940 form
   when the row carries firmware thresholds and both the lock's main and Wi-Fi firmware
   reach them, and **ECDH** for the 1930 form when the lock reports the row's parameter as
   `"1"`.

| products | form | path grade |
|---|---|---|
| T8502; T8506; T8520 with 7th serial character `8` or `9`; T8531, T8532, T85M0, T85M1, T85V0 behind a station | 1940 (time key) | current |
| T8502 with main firmware ≥ 2.2.0.0 and Wi-Fi firmware ≥ 0.3.0.0 | 1940 (HKDF key) | current |
| T8520 (other serials) | 1961 (ECIES-wrapped key) | current |
| T8530 | 1961 (plain JSON) | current |
| T8501, T8503 | 1930 (ECIES-wrapped key) | current |
| T8501, T8503 reporting parameter 6610 = `"1"` | 1930 (ECDH key) | current |
| T8500, T8510 | 1911 (a BLE frame through the station) | current; no codec here |
| T85D0, T85D2, T85F0, T85F1, T85F2, T85F3, T85L0, T85L1, T85P0, T85P1, T8506 with 7th serial character `8`; T8531, T8532, T85M0, T85M1, T85V0 not behind a station | MQTT (the 1940 frame over the eufy cloud's broker) | current; sent over the broker ([mqtt.md](mqtt.md#lock-commands)) |

The HKDF thresholds are the app's defaults for two Remote Config values; the generator takes
a fetched Remote Config over them when it names the keys. Versions compare as the app
compares a firmware with a Remote Config value: every character but digits and dots dropped,
fields as integers, missing fields 0, an empty or unparsable version reaching nothing.
Keypads (T8592, T85A3) have no lock command route. No legacy path is ported: where the app
holds two forms for one lock family (time key and HKDF, ECIES and ECDH), the lock's firmware
or parameter picks between them, and the library ports both.

## Shared parts

- **Serial IV**: the lock serial's UTF-8 bytes zero-padded to 16.
- **AES**: AES-128-CBC with PKCS#7 padding, under the serial IV.
- **Sequence number**: the codec takes the `seq_num` to send. For 1940 and 1930 a reported
  sequence number `R` is stored as `R + 1` and each send uses the stored value plus one
  (the first send after a report carries `R + 2`; the current Unix time plus one when
  nothing is stored); for 1961 it comes from one
  counter shared by every lock, set to the last reported sequence number plus one and
  incremented after each command.
- **User fields**: the lock member record's `admin_user_id` and `short_user_id` (hex text)
  and the account's nickname. An absent `short_user_id` is sent as each form sends it: 1940
  as an empty `A5` entry, 1961 by leaving the field out; 1930 needs its 2 bytes.
- **Result**: an answer code 0 is accepted (the state change follows), anything else is
  refused; the 1940 answer also names "already unlocked" (48) and "already locked" (49).
  A well-formed answer for another lock, another command or another time value (both
  times positive as signed 32-bit hex, as the app reads them, and different) raises
  `LockReplyMismatchError` (the caller keeps waiting); anything that does not decode raises
  `ProtocolError`.

## 1940: cm2 frame in through-data

Body, a TLV of `[tag, length u8, value]` entries, tags from `A1`:

| tag | value |
|---|---|
| A1 | the current Unix time, u32 little-endian |
| A2 | the key user id, UTF-8 |
| A3 | operation u8: **0 lock, 1 unlock** |
| A4 | the account's nickname, UTF-8 |
| A5 | `short_user_id` as bytes (empty when absent) |

The **key user id** is the member record's `admin_user_id` when the record names this
account (`member_user_id`), holds an admin id and its `member_type` is not 2; otherwise the
account's own user id.

**Time key.** A time value `t` = the Unix time in whole seconds OR a random 0..99. The key
is the key user id's last 12 characters (UTF-8) followed by the 4 bytes of `t` as 8 hex
digits (big-endian). The body is zero-padded to whole AES blocks and then encrypted (so an
aligned body gains a whole padding block).

**HKDF key.** The key is HKDF-SHA256 (RFC 5869) with the key user id (UTF-8) as input key
material, `t` as a 4-byte big-endian salt, info `F0 F1 … F9`, 16 bytes. The `time` field is
then not `t` but the hex of AES-128-CBC/PKCS#7 under the fixed key `ANKER_SMARTLOCK_` and
IV `OCK_WORLD'S_NO.1` of the user id followed by the salt, and the payload adds
`"version": "1"`.

Frame: `FF 09 | total length u16 LE | version 03 | slave id 00 | function type 02 |
u16 BE (encrypted 0x4000 | command 0x23) | encrypted body | XOR of all previous bytes`.
Payload of P2P command 1940:

```json
{"apiCommand": 6018, "lock_payload": "<frame hex>", "seq_num": 42, "time": 1700000037}
```

**Answer**: 1940 through-data `{"dev_sn", "lock_payload", "time"}`. The frame must be
function type 2, command 0x23. For a time-key request, an answer whose `time` reads as a
positive hex number other than the request's `t` is a late answer to another request,
encrypted or not; an unencrypted answer without a readable `time` is read. An encrypted body
opens with the key its own `time` names: for the time key `time` is 8 hex digits equal to the
request's `t`; for the HKDF key `time` opens under the fixed key to a 40-byte user id and a
4-byte salt (further bytes are ignored), and the answer has no time check. The first byte of
the body is the result code.

## 1961: JSON

`{"shortUserId", "slOperation", "userId", "userName"}` with `slOperation` **1 lock, 0
unlock** and `userId` the member's `admin_user_id` (`shortUserId` left out when absent),
written compact with the app's JSON escaping (`<`, `>`, `&`, `=`, `'` as `\u` escapes).

- **ECIES form**: the object gains `seq_num`, is encrypted under a random 16-byte AES key
  and sent base64 as `payload`; `key` is the lower-case hex of the ECIES (below) of that
  AES key written as 32 upper-case hex characters (129 bytes). The P2P payload object is
  `{"key", "account_id", "cmd": 1961, "mChannel", "mValue3": 0, "payload"}`.
- **Plain form**: the object itself is `payload`, without `seq_num` or `key`.

The lock's public key is 64 bytes, `X || Y` of a P-256 point, from the cloud's
`app/public_key/query` (type 2) per lock. The **answer** is the command's result code.

## 1930: Anker cm frame in through-data

Body: `A1 02 <short user id, 2 bytes> | A2 01 <slOperation: 1 lock, 0 unlock> |
A3 04 <Unix time u32 LE> | A4 <length> <nickname UTF-8>`, encrypted under a 16-byte key.

Frame: `FF 09 | total length u16 LE | version | device type FF | command 08 | package flag C0
| index A0 | key length | key field | encrypted body | XOR of all previous bytes`.

- **ECIES form** (version 18): a random key; the key field is the ECIES of its 16 bytes
  under the lock's public key (113 bytes).
- **ECDH form** (version 20): the client's ephemeral P-256 key agrees with the lock's ECDH
  public key (the cloud's `app/public_key/query` type 3, a SEC1 point); the key is the first
  16 bytes of the shared x-coordinate and the key field is the client's public key,
  uncompressed (65 bytes).

Payload of P2P command 1930: `{"apiCommand": 6018, "lock_payload": "<frame hex>",
"seq_num"}`. **Answer**: 1930 through-data `{"dev_sn", "lock_payload"}`; a single-packet
answer frame is `FF 09 | length | version | device type | command | C0 | body | XOR` (its
length field is not read). A version other than 33 means the body is encrypted under the
request's key. The first byte of the body is the result code.

## ECIES

P-256 ECIES as the station's session handshake uses it ([session-crypto.md](session-crypto.md)):
an ephemeral key `r`, `S` = x-coordinate of `r · LockKey`, `K` = TLS-1.2 P_SHA256(`S`,
`"ECIES"`) to 48 bytes, AES-128-CBC/PKCS#7 under `K[0:16]` with a random IV, HMAC-SHA256
under `K[16:48]` over IV and ciphertext. Output: the compressed ephemeral point (33 bytes),
the IV (16), the ciphertext and the tag (32).

## Commands

`EufySecurity.async_lock(device_sn, timeout=None)` and `async_unlock` send the lock's form
over the path its route takes (`Station.async_lock`/`async_unlock` for the station path
alone) and return the `LockState` once the lock reports the asked state. A station or lock
acknowledgement alone never counts. In order:

1. **Before sending** (nothing goes out on a refusal). `lock_control(device_sn)` decides
   from the route, the firmware and the cloud record, without a session: no route, the
   1911 form, or a station route whose station this client does not run raise
   `UnsupportedError`; an account whose member record for the lock names a
   guest (`member_type` 0) raises `GuestAccessError`, as the app refuses guests. A record
   without the owner's `admin_user_id` raises `UnsupportedError`; an MQTT route with no
   account given to `use_mqtt()` raises `MqttAccountRequiredError`; a command still waiting
   for the same lock raises `DeviceBusyError`. A lock whose last reading already is the
   asked state returns it at once and sends nothing (the app's lock card offers lock only
   for a lock it shows open, unlock otherwise). An unknown or offline reading refuses
   nothing.
2. **The station's result** (P2P): a non-zero code raises `CommandRejectedError(code)`,
   except -151 (sequence number refused) on the 1940 and 1930 forms, where the wait for the
   lock's answer goes on, as in the app. On the 1961 form the station's result is the
   lock's answer: any non-zero code refuses, -151 included.
3. **The lock's answer** (1940 and 1930: a through-data notify `{"cmd": 1940|1930,
   "payload": {"dev_sn": ..., ...}}`; over MQTT the response topic): an answer to another
   request (another time value) is skipped; a non-zero answer code (48/49: already
   unlocked/locked, or another) raises `CommandRejectedError(code)`. A -151 followed by
   neither an answer nor a resend within the wait raises `CommandRejectedError(-151)`.
4. **The state**: the asked state from any source (the lock's status report, `0x4A` in the
   1940 through data: a code byte, then `A1` the battery level and `A2` the lock-state code,
   a missing entry read as 0 as the app reads it; a parameter dump or notify; a push)
   returns it, also when it comes
   before the lock's answer; `jammed` or
   `intermediate` raises `LockNotMovedError` (`err.state`); a status report with a non-zero
   code raises `CommandRejectedError`; another state keeps the wait, so a
   stale dump does not end it. This last rule is the library's: the app ends on the first
   status report with code 0, whatever state it names.

The waits are the app's: 20 s for the lock's answer, then 30 s for its state; a `timeout`
bounds the whole command, the public-key query, the connect and the send included. Nothing
within it raises `DeviceTimeoutError`.

**Sequence numbers.** The 1940 and 1930 forms (and MQTT) count per lock: a report `R` (the
station's notify 1916 `{"dev_sn", "seq_num", "bus_type", "lock_cmd"}`) is stored as `R + 1`,
each send takes the stored value plus one and stores it, so a report `R` puts `R + 2` on the
wire; with nothing stored the current Unix time stands in. A 1916 naming the waiting 1940
command (`lock_cmd` the on/off command) resends it with the next number, each time one
arrives within the wait. The 1961 form counts on one number per station client from a random
start below 1000; a 1916 of a 1961 lock moves it to `R + 1`. All are kept in memory, as the
app keeps them: a restart starts again from these fallbacks.

**Public keys.** The 1961 (ECIES) and 1930 forms need the lock's key:
`EufyCloudApi.async_get_lock_public_key(device_sn, key_type)`, a signed GET of
`v3/app/public_key/query` (type 2 the ECC key, 3 the ECDH key), cached in memory per lock and
type.

## Not covered

- The 1911 form (T8500, T8510): the BLE frame through the station is not built;
  `lock_control()` says so.
- Multi-packet frames: a lock command and its answer fit one packet; a multi-packet answer
  raises `ProtocolError`.
