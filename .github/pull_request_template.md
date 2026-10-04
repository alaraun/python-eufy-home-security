## What and why

<!-- One change per pull request. Adding or verifying a device? Use the device
template instead: add `?template=new_device.md` to this page's URL. -->

## Checklist

- [ ] Conventional commit title (`feat:`, `fix:`, `docs:` …): it becomes the changelog entry
- [ ] Tests for the change; `uv run pytest` passes
- [ ] `uv run ruff check && uv run ruff format --check && uv run mypy` clean
- [ ] No serials, account ids, e-mails, addresses, device names or captures in the diff
