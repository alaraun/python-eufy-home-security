# Security policy

## Reporting a vulnerability

Please report security problems privately through GitHub Security Advisories
("Report a vulnerability" on the repository's Security tab), not in public issues.
Include the library version and, if relevant, device model and firmware — but
**never** credentials, tokens, serial numbers or captures from your home.

## What this library handles

- It logs in to the eufy cloud with your e-mail and password and caches the
  password, the resulting session, per-station keys and push credentials in the
  `Store` you provide. Treat that store like a password file: `JsonFileStore` writes it with
  mode `0600`.
- It never logs passwords, tokens, keys or full serial numbers unless the secrets
  switch is on (`set_secret_logging`, the CLI's `--secrets`). Wire-level dumps
  are off by default and must be enabled explicitly.
- Protocol constants embedded in the eufy app are part of the code; no
  per-account or per-device secret is bundled.

This project is not affiliated with Anker or eufy.
