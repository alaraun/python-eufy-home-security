# Testing an integration against the real library

`eufy_home_security.testing` ships supported test doubles, so code built on the library
(a Home Assistant integration) can test end to end against the real client instead of
mocking it. The library itself never imports this package; import it from a test suite
only.

What it proves that a boundary mock cannot: a warm restart makes no cloud call, one
session serves a poll, a snapshot and an arm, and a push reaches an entity.

## What it provides

| Name | What it is |
|---|---|
| `SYNTHETIC` | The synthetic identities the doubles use: station and camera serial, P2P id, keys, owner id, e-mail, password, a documentation-range address. Never a real identifier. |
| `FakeStation` | A HomeBase speaking PPPP/XZYH on loopback: discovery, handshake, parameter dumps, arming, settings, camera pushes, images, media. `await start()` binds it, `stop()` silences it. |
| `FakeCloud` | The eufy cloud answered below the HTTP envelope. The real client's session cache, hold-offs, login budget and owner-id rules still run. |
| `warm_store(email=, cloud=)` | A `MemoryStore` holding the cache document as after one login, written by the library's own cache writers. |
| `build_eufy_security(email=, store=, cloud=, stations=)` | A real `EufySecurity` wired to the fakes at the cloud-HTTP and discovery-port seams. |

## A test

```python
from eufy_home_security.testing import (
    SYNTHETIC,
    FakeCloud,
    FakeStation,
    build_eufy_security,
    warm_store,
)


async def test_warm_start_needs_no_cloud() -> None:
    station = FakeStation()
    await station.start()
    cloud = FakeCloud.for_stations(station)  # lists it, with its owner id and key
    eufy = build_eufy_security(
        email=SYNTHETIC.email,
        store=warm_store(email=SYNTHETIC.email, cloud=cloud),
        cloud=cloud,
        stations={station.serial: station},
    )
    try:
        await eufy.async_login()
        await eufy.async_discover()
        assert await eufy.async_start(push=False) == {}
        station.push_camera_event()  # arrives through eufy.subscribe
    finally:
        await eufy.async_close()
        station.stop()
    assert cloud.calls == []
```

## Controlling the fakes

- **Cloud answers.** `FakeCloud` fields are live: change `devices`, `owner_ids` or
  `cipher_keys` between steps. `cipher_ids_held` limits the cipher ids the cloud holds
  a key for (None: any); a request for another id gets the empty answer, which the
  library raises as `CipherUnavailableError`. Set `login_error` to the error a password login meets,
  and `call_errors` to the errors the next other requests meet, in order.
- **Cloud refusals.** `FakeCloud.refusal(status, code, message, retry_after=)` is an HTTP
  answer: served from `call_errors` or `login_error`, it runs through the library's own
  answer handling, so a 401 with the takeover code latches the session, another 401 costs
  one login and a retry, a 463 one key exchange and a retry, and a 429 starts the request
  hold-off (the longer of one hour and its `Retry-After`). A `RateLimitedError` (or
  `LoginLimitedError`) whose `code` is a throttle body code (`26145`, `100028`, …) or 429
  is that answer too: the library's hold-off for the code starts and the library's error is
  raised. One without such a code holds off for its own `retry_after`. Either way
  `async_cloud_status()` reports the hold-off and later calls are refused locally.
- **Cloud requests.** `calls` lists each request that reached the cloud, in order:
  `"login"`, `"devices"`, `"owner:<serial>"`, `"cipher:<serial>"`, `"dsk:<serial>"`,
  `"push_token"`, `"things"`, with serials redacted. A cached answer adds nothing.
  `cipher_ids_requested` lists the cipher ids those `get_ciphers` requests named.
- **Cold or warm.** A `MemoryStore()` is a cold start (one login, one device list, one
  key per station); `warm_store(...)` is a restart. Reuse one store across two clients
  to test a restart with whatever the first client cached.
- **Stations.** Pass started fakes keyed by serial. They are reached on loopback and
  must share one discovery port, so use one `FakeStation` per client. A stopped fake is
  an unreachable station: `async_start()` returns its error.
- **Station behaviour.** `FakeStation` fields shape it: `params` (the parameter dump),
  `guard_mode`, `schedule_mode` (the slot mode a selected Schedule puts in force),
  `images` (stills by path; a path not in it gets no reply, so the fetch times out, and
  `image_requests` lists every path asked), `answer_params`, `answer_conn_init`, `params_cipher`, `recording_frames`,
  `unhandled_commands` (answered with receipt −108), `playback_end_delay`.
  A standalone fake (a T8170 serial, `cipher_id=98`, `receipt_len=STANDALONE_RECEIPT_LEN`)
  answers the 1700 recipes: `preset_points` (the 6034 answer), `preset_gotos`,
  `doorbell_payloads`, `bare_stops` and `pings` record what arrived, and
  `live_ends_unpinged_after` ends a live stream that gets no ping, as the camera does.
  `push_camera_event(cipher=...)` sends a camera event under either frame cipher, and
  `send_alarm_frame(FrameType.ALARM_TONE_NOTIFY, 3, 30, channel=1)` an alarm frame.
- **Sessions.** Like the real station, the fake holds several client sessions at once
  (a trigger frame opens a short-lived second one): replies go to the session that
  asked, and what a test sends directly (`push_camera_event`, `send_close`) goes to
  every open session. `sessions` counts the open ones, `client_closes` the CLOSEs
  received, and a CLOSE stops that session's streams.
- **Push.** Cloud push (FCM) is not faked: start with `async_start(push=False)`.
- **Other client options.** Extra keyword arguments go to `EufySecurity` as they are.
  The inclusion map is `include=` (the fakes use `stations=`), and `password=` defaults
  to the synthetic one.

## Timing

The library's waits are sized for real hardware: a command the station does not
answer takes `COMMAND_TIMEOUT` (6 s), an unreachable station three 6 s discovery
attempts. A test that meets such a wait on purpose shortens it.

- **All at once:** `testing.short_timeouts()` is a context manager that sets every wait
  in `testing.timeouts.SHORT_TIMEOUTS` to a loopback value and restores them on exit;
  keyword arguments override single values by name. The library's own suite passes with
  it applied to every test. As a fixture:

  ```python
  @pytest.fixture
  def short():
      with short_timeouts():
          yield
  ```

- **One at a time:** `monkeypatch.setattr` on the module that defines the constant
  (`eufy_home_security.p2p.session.COMMAND_TIMEOUT`, `…p2p.pppp.LAN_DISCOVERY_TIMEOUT`,
  `…p2p.broadcast.CAPTURE_START_TIMEOUT`, `…station.READBACK_DELAY`), never on a name
  imported elsewhere. Every call with a `timeout=None` default reads its constant there
  at call time, also when a caller such as `Station.async_set_guard_mode` passes no
  timeout.

| wait | constant | shortened by `short_timeouts` |
|---|---|---|
| discovery attempts, each | `p2p.session.DISCOVERY_ATTEMPTS`, `DISCOVERY_TIMEOUT` | 1 × 2.5 s (a station ignores the first search after a close) |
| CONN_INIT reply | `p2p.session.HANDSHAKE_TIMEOUT` | 2.5 s (outlasts one DRW retransmit, 1.5 s) |
| command result; its late receipt | `p2p.session.COMMAND_TIMEOUT`, `COMMAND_RECEIPT_TIMEOUT` | 0.5 s, 1 s (shorter than a retransmit: a test that drops a command frame sets it itself) |
| parameter dump | `p2p.session.PARAM_QUERY_TIMEOUT` | 2.5 s |
| station database query (history page, event count, event list) | `p2p.session.HISTORY_QUERY_TIMEOUT` | 2.5 s (a history page is asked once more after a timeout, so it fails after twice that) |
| guard-mode report, mode-table read-back | `p2p.session.MODE_REPORT_GRACE`, `MODE_TABLE_READBACK_DELAY` | 0.3 s, 0.05 s |
| setting read-back retry | `station.READBACK_DELAY` | 0.05 s |
| reconnect back-off | `p2p.session.RECONNECT_BACKOFF` | 0.1 s |
| still download, SD info | `p2p.session.STILL_FETCH_TIMEOUT`, `SD_INFO_TIMEOUT` | 1 s |
| first live / recording frame | `p2p.session.MEDIA_LIVE_FIRST_FRAME_TIMEOUT`, `MEDIA_RECORDING_FIRST_FRAME_TIMEOUT` | 2 s |
| preset image stream idle, capture start | `station.PRESET_STREAM_IDLE_SECONDS`, `p2p.broadcast.CAPTURE_START_TIMEOUT` | 1 s, 2 s |
| LAN search (`async_probe_lan`, `async_station_choices`) | `p2p.pppp.LAN_DISCOVERY_TIMEOUT` | 0.5 s |

Not shortened, because a test observes their length: `PARAM_SETTLE` (sub-device blocks
following a dump), `MEDIA_IDLE_TIMEOUT`, `MEDIA_DRAIN_MAX` (a stopped stream's leftover
frames), the probe schedule, and the reprobe and idle-close delays. Set them per test.
