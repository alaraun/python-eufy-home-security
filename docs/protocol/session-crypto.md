# Session crypto

Three schemes, verified against a live HomeBase 3, and a fourth, the RSA session of
a station whose CONN_INIT is not version 8 (a T8410), declared from the eufy app:

| scheme | key | protects |
|---|---|---|
| AES-128-ECB | **static key** (serial + DID) | CONN_INIT, legacy scalar commands and results, ECB-tagged station frames |
| ECIES (P-256 + HMAC-SHA256 KDF) | the `ecc_private_key` of the cipher CONN_INIT names (40 on a HomeBase 3, 98 on a T8170) | the session key inside CONN_INIT |
| AES-256-GCM | **session key** (32 bytes) | JSON commands and GCM-tagged station frames, in both directions |
| RSA-1024 PKCS#1 v1.5, then AES-128-ECB | the cipher's RSA `private_key`; then the 16-character key it carries | the RSA CONN_INIT; then every frame of that session |

Media keyframes use a separate RSA/AES-128 scheme ([media.md](media.md)).

Code: `src/eufy_home_security/p2p/did.py` (static key), `p2p/crypto.py` (ECB, GCM,
ECIES, CONN_INIT), `p2p/messages.py` (ECB scalar frames).

## Static key **[verified]**

```
key = serial[-7:] + "-" + did_number + "-" + did_suffix[0]        # exactly 16 ASCII bytes
```

| input | value | part |
|---|---|---|
| serial | `T8030XXXXXXXXXXX` | `XXXXXXX` |
| DID | `EUPRAMA-123456-ABCDE` | `123456`, `A` |
| key | `XXXXXXX-123456-A` | hex `585858585858582d3132333435362d41` |

The number is the decimal DID number as text. The key is derivable offline, with no
cloud call.

**ECB details.** AES-128-ECB, no IV. The client zero-pads to a 16-byte boundary.
Station JSON payloads carry trailing NUL padding, so decode the leading JSON object
and ignore the rest. Identical plaintext encrypts identically: a given guard-mode
notify is always the same 16 bytes.

## CONN_INIT: establishing the session key **[verified]**

```
client → station  ch0 idx0   XZYH 0x044C  subheader 01 00 FF 00 00 00   payload: none
station → client             XZYH 0x044C  payload: 144 bytes
```

```
ECB-decrypt(static_key, payload[144]) =
  cipher_id u32le ‖ ECIES blob (129 bytes) ‖ padding tail

ECIES blob =
  eph_pub    33   compressed P-256 point
  iv         16
  ct         48   AES-128-CBC, PKCS7 (a 32-byte key padded to 48)
  tag        32   HMAC-SHA256
```

Unwrap (from `DecryptECC` / `kdf_func` in the app's ECC library):

```
S          = ECDH(ecc_private_key, eph_pub).x                     # 32 bytes
fb         = HMAC-SHA256(S, "ECIES")
km         = HMAC-SHA256(S, fb ‖ "ECIES")                         # block 1
while len(km) < 48:
    fb     = HMAC-SHA256(S, fb)
    km    += HMAC-SHA256(S, fb ‖ "ECIES")
aes_key    = km[0:16]
hmac_key   = km[16:48]
check        HMAC-SHA256(hmac_key, iv ‖ ct) == tag
session    = PKCS7-unpad(AES-128-CBC-decrypt(aes_key, iv, ct))   # exactly 32 bytes
```

- The blob is the first 129 bytes after the cipher id; the ECB layer adds a padding
  tail after it, which the tag does not cover.
- The session key is used as-is: any 32 bytes. A HomeBase 3 sends 32 printable ASCII
  bytes [verified]; nothing requires it [declared], and a key of another length fails
  the handshake.
- **The station chooses the cipher [verified].** `cipher_id` is 40 on a HomeBase 3
  (fw 3.8.7.4) and 98 on a T8170 standalone camera (fw 3.3.5.4), on the same account.
  The id is readable before any cloud key is needed (only the static key), so it tells
  which cipher to fetch ([cloud.md](cloud.md)). The library loads no credentials before
  the reply: it reads the id (`crypto.parse_conn_init`), stores it per station
  (`stations.<serial>.cipher_id`), then loads that cipher's key from the cache, else the
  cloud. A cipher other than the one of the credentials held is not a stale key (no
  re-fetch latch). The eufy app does the same **[declared: app]**: it fetches a key only
  when the station's `APP_CMD_GATEWAYINFO` (1100) callback names the id, caches it per
  owner id and cipher id, and preloads nothing.
- An HMAC mismatch, or a key that is not 32 printable bytes, means the cached key of
  that cipher no longer matches the station. Re-fetch it **once**. No other signal
  tells a stale key apart from a dead link.

### Reply version and encryption type **[declared: app]**

Two subheader bytes of the CONN_INIT reply select its handshake and its encryption:

| byte | meaning | values |
|---|---|---|
| 0 | version | `08`: the ECIES handshake above and a GCM session; any other: the RSA handshake |
| 3 | encryption type | `00`: clear; otherwise AES-128-ECB under the static key over whole blocks |

A HomeBase 3 and a T8170 answer `08 xx FF 01` (144 bytes) **[verified]**. A T8410
(fw 2.3.2.6) answers version `01` with 133 bytes (seen in a user debug log; byte 3 not logged).

### RSA CONN_INIT **[declared: app, legacy]**

This is a **legacy** path. The current eufy app/SDK derives every station's session key
from the cipher's `ecc_private_key` (ECIES, below) and no longer implements an RSA session
path at all; only an old-firmware station whose CONN_INIT reply is not version 8 (e.g. a
T8410 on fw 2.3.2.6) still needs it, decrypted with the cipher's cloud RSA `private_key`.

```
payload (after the encryption type is undone) =
  cipher_id u32le ‖ RSA-1024 ciphertext (128 bytes) ‖ tail (a T8410: 1 byte)
key = RSA-PKCS#1-v1.5-decrypt(private_key, ciphertext) up to its first NUL, first 16 bytes
```

- `private_key` is the same cipher's RSA key from `get_ciphers` (base64 PKCS#8, PEM armour
  optional; [cloud.md](cloud.md)). The library keeps it beside `ecc_private_key`
  (`stations.<serial>.rsa_ciphers`).
- The 16 bytes are an AES-128 key. From then on **every** frame in both directions is
  AES-128-ECB under it, zero-padded, subheader byte 3 = `02`; there is no GCM. A
  client frame is `01 <seq> <dev_type> 02 <flag> 00`. Byte 3 = `01` is still the static
  key, `00` a clear frame (a receipt).
- A wrong RSA key decrypts to noise rather than failing (PKCS#1 implicit rejection);
  the library takes a key that is not 16 printable bytes as a handshake failure.
- A `private_key` whose bytes do not parse as a key at all is distinct from a wrong
  key: the cloud serves the same bytes on every fetch, so re-fetching cannot help. The
  library raises `CipherUnusableError` (cause `key_unusable`) without re-fetching and
  without the stale-key latch, and retries only after a code change or the cached key
  being dropped. On some accounts the cloud lowercases the base64 of `private_key`
  ([cloud.md](cloud.md)), which lands here.
- Library code: `crypto.parse_conn_init`, `crypto.aes_key_from_conn_init`,
  `crypto.load_rsa_private_key`, `StationSession.rsa_session`. Not observed on hardware:
  whether the T8410's reply is clear (the 133 bytes only fit as clear: ECB needs whole
  blocks), the shape of its receipts, and whether any account serves its `private_key`
  with the case intact.

### One session per connection **[verified]**

- Send **exactly one** CONN_INIT per PPPP connection, and derive the key from its reply.
- **A second CONN_INIT on the same connection is not honoured.** Two operations on
  one client need a close, re-discovery (expect the ignored first LAN_SEARCH) and a
  new CONN_INIT. A repeated CONN_INIT makes the station mint a fresh challenge,
  invalidating the key already derived: never resend it.
- Every reconnect starts fresh: DRW indices at 0, the GCM seq at `0x01020304`, the
  message counter at 0, the ECB seq at 0, and new per-channel reassembly buffers.
- **Two readers cannot share one UDP socket**, and the station mints one session per
  connection. Concurrent work (a long-lived monitor plus a media fetch) needs
  separate connections, which count against the session budget
  ([p2p-transport.md](p2p-transport.md)).

## AES-256-GCM frames **[verified]**

| | client → station | station → client |
|---|---|---|
| key | session key (32 bytes, used as-is) | same key. **There is no separate receive key.** |
| AAD | `"eufy security"` (13 bytes, a constant in the app) | same |
| nonce | 12 random bytes per frame | chosen by the station |
| layout | `tag(16) ‖ nonce(12) ‖ seq u32le(4) ‖ ciphertext` | `tag(16) ‖ nonce(12) ‖ ciphertext` |
| plaintext | DeviceMsgBean JSON, or the 8-byte parameter query | JSON (NUL-padded) |

- The **tag comes first**, and the ciphertext has no trailing tag. To use a standard
  AEAD API: `decrypt(nonce, ct ‖ tag, aad)`.
- `seq` is a plaintext counter that starts at `0x01020304` and grows by 1 per GCM
  frame the client sends. It is not in the AAD.
- The station → client layout has **no seq**. Reading 4 bytes of seq there
  misaligns the ciphertext and every tag fails; there is no second key.
- The subheader of a client GCM frame is `08 <ctr> <dev_type> 08 <flag> 00`
  ([p2p-transport.md](p2p-transport.md)).

## Per-frame cipher selection **[verified]**

Station frames are **not** all encrypted the same way. Subheader byte 0 names the
cipher of that frame alone:

| byte 0 | cipher | key | payload |
|---|---|---|---|
| `0x08` | AES-256-GCM, no-seq layout | session key | JSON, or an 8-byte u64le guard mode (`0x047F`) |
| `0x01` | AES-128-ECB | static key | JSON, a 16-byte binary block (`0x047F`), or an int32 result |

Observed behaviour:

- Two clients connected at once received **the same camera event**: as `0x08` on
  the client that had sent a GCM frame, and as `0x01` on the client that had sent
  nothing after CONN_INIT.
- Image replies (`0x051C`) come back `0x01` even on a session that has sent GCM commands.
- The parameter dump (`0x044F`) can arrive under either tag.
- The guard-mode notify (`0x047F`) arrives under either tag: GCM carries the mode as
  an 8-byte u64le plaintext, ECB as the first u32le of a 16-byte block.
- Legacy scalar results are ECB.

**Why.** The app's command dispatcher switches on
the command id. Only `0x0546` (1350) takes JSON with GCM, and every other command id
uses the legacy AES-128-ECB path under the static key. The station keeps both
schemes and evidently answers in the one it associates with the client's traffic and
the frame type. A client must therefore keep both keys and pick per frame. Assuming
one cipher per session silently loses part of the traffic.

### Trust policy for ECB state

Once a session key exists, the library **refuses** station state that arrives under
ECB: parameter dumps (`0x044F`) and guard-mode reports (`0x047F`). They are not
decoded for parameter reads, the arm read-back, change events or the arm result.
Only their GCM copies count.

**Evidence.** The static key is derived from the serial and DID alone (above), both
of which are visible to anyone on the LAN. An ECB frame therefore proves nothing
about its origin, and a forged one could fake a guard mode or an arm confirmation.
GCM frames are sealed under the per-connection session key. They authenticate the
origin but not freshness: station → client frames carry no seq, so a frame can be
replayed within the same session.

- ECB frames that are not state still decode: image replies (`0x051C`), legacy
  scalar results and camera pushes (cmd 2037).
- A camera push records the cipher of its frame in `SecurityEvent.frame_cipher`.
  `SecurityEvent.authenticated` is False for an ECB push and True for a GCM push or
  a cloud push (`frame_cipher` None, TLS). It proves origin, not freshness.
- Each refusal is logged at DEBUG (throttled) and counted in
  `StationSession.ecb_state_refused`.
- A parameter read that times out while ECB dumps were refused says so in its
  `DeviceTimeoutError`. A firmware that answers the query under ECB only then does
  not look like an outage.

## Legacy ECB scalar frames **[verified]**

Plain scalar settings do not ride `0x0546`. They use an XZYH frame whose **type is
the command id**, with a cleartext header and an AES-128-ECB body under the static key:

```
"XZYH" | type = cmd u16le | length = padded body u32le | 01 | seq u8 | channel u8 | 01 | 00 00
ECB(static_key, body, zero-padded)
```

The body layout depends on which of the app's three scalar handlers the
command id maps to:

| handler | body | header channel | catalogued commands (full sets in `p2p/messages.py`) |
|---|---|---|---|
| channel + value | `u32le channel ‖ u32le value ‖ char[128] account_id` (136 B → 144 padded) | the sub-device channel | 1045, 1207, 1210, 1229, 1230, 1246 (51 ids in all) |
| value | `u32le value ‖ char[128] account_id` (132 B → 144 padded) | the sub-device channel | 1249, 1250, 1251, 1252 |
| station | `u32le value ‖ char[128] account_id` | **forced to 255** | 1235, 1253 (23 ids in all) |
| default | none. The app rejects the command with −103. | — | everything else, including 1157–1175, 1276, 1277, 1296, 1298 |

- `account_id` is the **owner's** user id, ASCII, NUL-terminated inside the 128-byte field.
- A command on the default handler is not a scalar: send it as a GCM payload object
  ([commands.md](commands.md)) or not at all.
- Id 1224 (arming) is in the station scalar set, but the app and the library arm
  with the GCM payload object, which is the verified path.

**String commands [verified: 1215 on a T8170].** The app's set-with-string handler
(`msgType 6`) sends a GCM frame whose **type is the command id**, subheader channel 255,
and a fixed body: `u32le 0 ‖ u8 channel ‖ char[128] value ‖ char[128] account_id`. The
reply is a receipt of the same type (code 0, or −104 for a foreign account). The device
time zone (1215) takes only this form; the handler's `DeviceMsgBean` JSON for 1215 is
refused (−1). The app routes 1132, 1216 and 1217 the same way; the library sends
only 1215 this way (`p2p/messages.py` `STRING_CMDS`).

**Reply.** A frame of the **same type**. Its payload starts with an int32le result code.

| code | name | usual cause |
|---|---|---|
| 0 | SUCCESSFUL | applied (still confirm by read-back, [commands.md](commands.md)) |
| −103 | INVALID_COMMAND | the command is not a scalar on this path |
| −104 | INVALID_ACCOUNT | missing or wrong owner id, **or a wrong body layout** (for example, a channel-prefixed command sent without its prefix, which puts the value where the account belongs) |
| −106 | NOT_FIND_DEV | a camera command sent on a channel with no device |
| −110 | INVALID_PARAM | header channel outside 0..50 and 255 |

**Firmware drift.** ECB is the legacy scheme. The multi-field commands (arming,
detection type, night vision, motion sensitivity) are GCM payload objects. A scalar
reply tagged `0x08` means the firmware handles that command under GCM: the library
logs a warning, and read-back verification catches a silent change. These layouts
hold on main fw 3.8.7.4 / security fw 1.4.0.8.
