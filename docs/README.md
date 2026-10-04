# Documentation

| | |
|---|---|
| [getting-started.md](getting-started.md) | Install, log in, discover stations, arm, listen for events |
| **How-to** | |
| [how-to/home-assistant.md](how-to/home-assistant.md) | Build a Home Assistant integration on the library: where logic belongs, the cache, password, reauth and removal, several accounts and shared stations, device and entity ids, which stations to include, network and firewall, coordinators and pushed state, availability, which events to trust and de-duplication, alarm phases, entities from the per-model settings, unknown models, camera stills, live streaming, diagnostics and statistics, errors and repairs |
| [how-to/testing.md](how-to/testing.md) | End-to-end tests against the real library with `eufy_home_security.testing` (fake station, fake cloud, warm cache) |
| [how-to/add-a-device.md](how-to/add-a-device.md) | Add a model or a capability, and verify a device on hardware |
| [how-to/regenerate-models.md](how-to/regenerate-models.md) | Regenerate the per-model settings files from the vendor's thing models, check them, and when to do it |
| [how-to/debug-logging.md](how-to/debug-logging.md) | Loggers, wire dumps, redaction, Home Assistant |
| **Reference** | |
| [reference/devices.md](reference/devices.md) | Support matrix and per-model settings (generated) |
| [reference/cli.md](reference/cli.md) | The `eufy-security` command line |
| [reference/thing-models.md](reference/thing-models.md) | The app's thing models: thing descriptions, handler recipes, connect types, the golden recipes and how to add an action |
| [reference/models-schema.md](reference/models-schema.md) | The generated per-model settings files (schema v2): fields, write and read codecs, placeholders, notes, how to regenerate and check |
| [reference/source-of-truth.md](reference/source-of-truth.md) | Which source answers which question: cloud vs the live dump, why entities come from the model's settings and not from reported parameters, grades and freshness |
| [reference/hardware-verification.md](reference/hardware-verification.md) | What has been proven on real hardware |
| **Protocol** | |
| [protocol/README.md](protocol/README.md) | The wire formats: cloud, P2P transport, session crypto, commands, events, media |

Scope: the eufy HomeBase 3 (T8030) and the cameras paired to it, over local P2P,
with the eufy cloud used only for login, keys and push. Models and capabilities are
marked *verified* (proven on hardware), *declared* (from the app, unproven) or
*unknown*; settings come from per-model files generated from eufy's own code.
