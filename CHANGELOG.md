# Changelog

All notable changes to this project. The project follows
[Semantic Versioning](https://semver.org/); before 1.0, a minor release may change the
API. From 0.1.0 on, release-please writes the entries from the conventional commits.

## [0.3.6](https://github.com/alaraun/python-eufy-home-security/compare/v0.3.5...v0.3.6) (2026-10-10)


### Bug Fixes

* read and write a device's settings in the context the app sees it ([#53](https://github.com/alaraun/python-eufy-home-security/issues/53)) ([b457637](https://github.com/alaraun/python-eufy-home-security/commit/b4576370323db7f5897773618183e5f2066e70c0))

## [0.3.5](https://github.com/alaraun/python-eufy-home-security/compare/v0.3.4...v0.3.5) (2026-10-10)


### Features

* keep parameter-dump keys the library does not read; status --received ([#51](https://github.com/alaraun/python-eufy-home-security/issues/51)) ([c2ac52e](https://github.com/alaraun/python-eufy-home-security/commit/c2ac52eb138d4c26cbbf3ef3d328fd504bb131a3))


### Bug Fixes

* leave out a paired device's settings the app offers only without a parent ([#52](https://github.com/alaraun/python-eufy-home-security/issues/52)) ([f0ff19d](https://github.com/alaraun/python-eufy-home-security/commit/f0ff19d6e956e4eb23ed5a9061d9fefc0d89cce3))
* read a paired camera's own parameters from the dump's db_bypass_str ([#49](https://github.com/alaraun/python-eufy-home-security/issues/49)) ([5eda9b4](https://github.com/alaraun/python-eufy-home-security/commit/5eda9b423c3d06bd355ca62e343aefca20928b97))

## [0.3.4](https://github.com/alaraun/python-eufy-home-security/compare/v0.3.3...v0.3.4) (2026-10-09)


### Features

* live video declared for every camera whose handler's open the library sends ([#46](https://github.com/alaraun/python-eufy-home-security/issues/46)) ([52041cc](https://github.com/alaraun/python-eufy-home-security/commit/52041ccbdbbc81d59636a0df252fbd17ea8bfaff))


### Documentation

* the app routes live opens to WebRTC by the parent's is_connect_webrtc ([#48](https://github.com/alaraun/python-eufy-home-security/issues/48)) ([f822c0b](https://github.com/alaraun/python-eufy-home-security/commit/f822c0bb1b980ee03f0446d7d5cd1973166b91fb))

## [0.3.3](https://github.com/alaraun/python-eufy-home-security/compare/v0.3.2...v0.3.3) (2026-10-09)


### Features

* ECC media key for live streams ([#44](https://github.com/alaraun/python-eufy-home-security/issues/44)) ([df76f0e](https://github.com/alaraun/python-eufy-home-security/commit/df76f0e4224a9f91f6727bfc96f79499b93b13fd))

## [0.3.2](https://github.com/alaraun/python-eufy-home-security/compare/v0.3.1...v0.3.2) (2026-10-09)


### Features

* live video from HomeBase 2 and other non-T8030 stations ([#42](https://github.com/alaraun/python-eufy-home-security/issues/42)) ([cef8f94](https://github.com/alaraun/python-eufy-home-security/commit/cef8f9436530b067a32261bea1f8fc2c59d409c4))

## [0.3.1](https://github.com/alaraun/python-eufy-home-security/compare/v0.3.0...v0.3.1) (2026-10-09)


### Features

* a rate-limit error names who refused it (origin) and the login scope it was for; RegionStatus.next_login_allowed_in per scope ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* EufySecurity.device_list_source and listed_devices say how the last device list was obtained and what it named; StationsChanged reports stations a discovery built or no longer finds ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* mode_action_flags gives a sensor's per-mode actions by device type; only motion sensors get the respond action, and sirens are kind other ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* RegionStatus reports each scope's session state, login refusal and logins in the budget window ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* the cloud package exports CipherKeys and RsaKeyCheck ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* warm_store takes the client's country and region; FakeCloud plays refusals and throttles through the library's own handling; short_timeouts covers the preset, pan/tilt, live-open and discovery-retry waits ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* without a product code from the cloud, the serial names the product variant (T8410C, T8420X, T8210C, T8510P, T8520P, T8W11C) ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))


### Bug Fixes

* a cached device list that misses a login scope is fetched again, and the cached-list fallback leaves out the devices of scopes no longer in use ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* a failed verification-code request still raises the login challenge, and the one-time country re-login never asks for an e-mailed code ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* a firmware check that gets no verdict raises instead of reading as up to date ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* a login challenge raised for an extra country is answered there, also on a new client instance ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* a login-free call whose session the cloud answers as expired raises NoCachedSessionError, not an authentication error; pending invitations survive one failing region ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* a reply queued while the event loop was held is read in every wait phase of a request ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* an extra country whose login eufy refuses is skipped until a rescan instead of failing every login, and a refused login country is not sent again on later logins ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* async_event_thumbnail gives each of its queries its own default timeout ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* cloud_status counts logins per cluster and covers the first region when every scope is suspended ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* credentials without the key the station's handshake needs raise CipherUnusableError (no_rsa_key, no_ecc_key) after one refresh, and credentials for another cipher set no stale-key latch ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* house names, nicknames and locations are masked in debug logs, and error texts in the account report are scrubbed ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* on an RSA session only frames under the session key count as station state, and pushes under that key are authenticated ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* the CLI reports a bad country, e-mail or port as a usage error and gives specific advice for SessionRejectedError and CipherUnusableError ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* the empty-cipher back-off ends when the station's owner id changes ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* the extra countries' install ids are kept wherever openudid is ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))
* the login country is looked up before a login picks its region; a lookup that gets no answer spends no login and is asked again ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))


### Documentation

* the RSA handshake is declared and works with an intact key; cloud docs use neutral example countries ([7290f42](https://github.com/alaraun/python-eufy-home-security/commit/7290f42e0d3b0012f35ecc903f3a46d4343e8eaa))

## [0.3.0](https://github.com/alaraun/python-eufy-home-security/compare/v0.2.8...v0.3.0) (2026-10-09)


### Features

* every product the eufy app names is in the model list ([#36](https://github.com/alaraun/python-eufy-home-security/issues/36)) ([36df33a](https://github.com/alaraun/python-eufy-home-security/commit/36df33ae9dff25f20d0b05592df6173ff5be79af))


### Bug Fixes

* an extra country logs in under its own install id ([#35](https://github.com/alaraun/python-eufy-home-security/issues/35)) ([2e79411](https://github.com/alaraun/python-eufy-home-security/commit/2e79411aa5d3d286e94da19700259e095b877d8a))


### Miscellaneous Chores

* release 0.3.0 ([#38](https://github.com/alaraun/python-eufy-home-security/issues/38)) ([acd4167](https://github.com/alaraun/python-eufy-home-security/commit/acd4167ed84d25c390bae5e0de02fb13f19b9e85))

## [0.2.8](https://github.com/alaraun/python-eufy-home-security/compare/v0.2.7...v0.2.8) (2026-10-08)


### Features

* log in once per user-set country, on its home region only ([#33](https://github.com/alaraun/python-eufy-home-security/issues/33)) ([f5714a3](https://github.com/alaraun/python-eufy-home-security/commit/f5714a3db42fb60c4243d52609ca7ce90145ebb9))

## [0.2.7](https://github.com/alaraun/python-eufy-home-security/compare/v0.2.6...v0.2.7) (2026-10-08)


### Features

* log in with the account's country, as the eufy app does ([#31](https://github.com/alaraun/python-eufy-home-security/issues/31)) ([d289991](https://github.com/alaraun/python-eufy-home-security/commit/d289991a90deac38086ed0bee9508fd61551ec29))
* pending home and device invitations ([#29](https://github.com/alaraun/python-eufy-home-security/issues/29)) ([cb5eb27](https://github.com/alaraun/python-eufy-home-security/commit/cb5eb27582653d24c381af77b5002508ef5ac14b))


### Bug Fixes

* a reply that arrived while the event loop was held is not a timeout ([#32](https://github.com/alaraun/python-eufy-home-security/issues/32)) ([afc3eb4](https://github.com/alaraun/python-eufy-home-security/commit/afc3eb402f17ebb009f05f5b078504b6c961887f))

## [0.2.6](https://github.com/alaraun/python-eufy-home-security/compare/v0.2.5...v0.2.6) (2026-10-08)


### Bug Fixes

* a version-8 session key need not be printable ([#27](https://github.com/alaraun/python-eufy-home-security/issues/27)) ([0fad068](https://github.com/alaraun/python-eufy-home-security/commit/0fad068fb7bb6058163c35248db923e707bbdeeb))

## [0.2.5](https://github.com/alaraun/python-eufy-home-security/compare/v0.2.4...v0.2.5) (2026-10-08)


### Features

* account report of every eufy device list, firmware and cipher state ([#25](https://github.com/alaraun/python-eufy-home-security/issues/25)) ([9f9809e](https://github.com/alaraun/python-eufy-home-security/commit/9f9809eaeda31599e73e51a6fc29b17f772a1c2b))

## [0.2.4](https://github.com/alaraun/python-eufy-home-security/compare/v0.2.3...v0.2.4) (2026-10-07)


### Features

* a cipher key that does not parse is unusable, not rejected ([#23](https://github.com/alaraun/python-eufy-home-security/issues/23)) ([2a811eb](https://github.com/alaraun/python-eufy-home-security/commit/2a811eb426a4cac5ad2d8d5f6c2b2961b9526a7d))

## [0.2.3](https://github.com/alaraun/python-eufy-home-security/compare/v0.2.2...v0.2.3) (2026-10-07)


### Bug Fixes

* a login pending two-step verification is a challenge, not a session ([#21](https://github.com/alaraun/python-eufy-home-security/issues/21)) ([6e0140e](https://github.com/alaraun/python-eufy-home-security/commit/6e0140ef3b9f7ebd73ecf5bb9852419b6c1f07ae))

## [0.2.2](https://github.com/alaraun/python-eufy-home-security/compare/v0.2.1...v0.2.2) (2026-10-07)


### Features

* the RSA session variant and T8410/T8161 device profiles ([#19](https://github.com/alaraun/python-eufy-home-security/issues/19)) ([c8921d1](https://github.com/alaraun/python-eufy-home-security/commit/c8921d194e8cd54213bb6a385353fa4bd94b7189))

## [0.2.1](https://github.com/alaraun/python-eufy-home-security/compare/v0.2.0...v0.2.1) (2026-10-07)


### Features

* find the account's devices in every cloud region ([#17](https://github.com/alaraun/python-eufy-home-security/issues/17)) ([f1bb721](https://github.com/alaraun/python-eufy-home-security/commit/f1bb721902cbe684ce4c70c67df74b60e46062c3))

## [0.2.0](https://github.com/alaraun/python-eufy-home-security/compare/v0.1.2...v0.2.0) (2026-10-06)


### Features

* list recordings from a chosen day, and ask an unanswered history page once more ([#15](https://github.com/alaraun/python-eufy-home-security/issues/15)) ([ef22ed1](https://github.com/alaraun/python-eufy-home-security/commit/ef22ed1274fc73f3d644dc478b8921dc5dd78d25))
* read every hardware wait at call time; testing.short_timeouts ([#12](https://github.com/alaraun/python-eufy-home-security/issues/12)) ([054887a](https://github.com/alaraun/python-eufy-home-security/commit/054887a079d2c4f98a9748f29cc2362a21e78290))
* StillNotWrittenError for an event still that is not written yet ([#13](https://github.com/alaraun/python-eufy-home-security/issues/13)) ([7dde1e4](https://github.com/alaraun/python-eufy-home-security/commit/7dde1e4b98c391cda0054cf51dacf4b6042a584d))

## [0.1.2](https://github.com/alaraun/python-eufy-home-security/compare/v0.1.1...v0.1.2) (2026-10-06)


### Bug Fixes

* fetch the cipher key the station names, after CONN_INIT ([#9](https://github.com/alaraun/python-eufy-home-security/issues/9)) ([a2af4fb](https://github.com/alaraun/python-eufy-home-security/commit/a2af4fb55fd5a5dbc4ff1299d83ca1d7f0e10c5f))

## [0.1.1](https://github.com/alaraun/python-eufy-home-security/compare/v0.1.0...v0.1.1) (2026-10-05)


### Bug Fixes

* name the device channel in the subheader of 1350 commands ([#7](https://github.com/alaraun/python-eufy-home-security/issues/7)) ([9925351](https://github.com/alaraun/python-eufy-home-security/commit/9925351036e43fe324b6654a21338397d7a7c121))

## 0.1.0

The first public release: an asyncio client for eufy Security that works on the local
network and uses the eufy cloud only for login, keys and push.

### Local network

- Discovery and the encrypted P2P session to a HomeBase 3 (T8030) and to a standalone
  battery camera (T8170), including waking a sleeping camera.
- Guard mode: read, set and follow, confirmed by the station's own report.
- State from the station: battery, signal, firmware, storage, charging and online
  state, with change events.
- Live video and audio (HEVC + AAC) shared by several viewers, still images at full
  resolution, stored recordings (played back or downloaded as a clip) and event stills.
- Pan/tilt, presets and picture zoom on the T8170; per-mode alarm actions and delays.

### Settings

- Settings for 107 eufy products, generated from the eufy app's own thing descriptions
  and handlers: values, labels, units, the control to show, and how each is written
  and read back.

### Cloud and push

- `eufy_mega` login with the e-mailed code or a captcha, a session cache that survives
  restarts, the device list and the per-station keys.
- Push events over FCM, merged with the local session's events.
- Firmware-update notices.
- Protection against the cloud's limits: a login budget, hold-offs after throttling,
  and no automatic re-login after another client takes over the session.

### Tools

- The `eufy-security` command line: status, guard mode, settings, live video,
  recordings, events and more.
- `eufy_home_security.testing`: a fake station and a fake cloud for end-to-end tests of
  a consumer such as a Home Assistant integration.
- Support graded as data: each model and capability is *verified* on hardware,
  *declared* from the eufy app, or *unknown*, with its source.
