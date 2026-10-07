# Changelog

All notable changes to this project. The project follows
[Semantic Versioning](https://semver.org/); before 1.0, a minor release may change the
API. From 0.1.0 on, release-please writes the entries from the conventional commits.

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
