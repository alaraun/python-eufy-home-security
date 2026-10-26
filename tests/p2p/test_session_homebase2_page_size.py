from types import SimpleNamespace

import pytest

from eufy_home_security.p2p import session as session_module
from eufy_home_security.p2p.session import StationSession


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("serial", "verb", "requested", "expected"),
    [
        ("T8010TEST", "local", None, 50),
        ("T8410TEST", "local", None, 20),
        ("T8030TEST", "history", None, 50),
        ("T8010TEST", "local", 12, 12),
    ],
)
async def test_history_page_size_by_station_model(
    monkeypatch: pytest.MonkeyPatch,
    serial: str,
    verb: str,
    requested: int | None,
    expected: int,
) -> None:
    observed: list[int] = []

    async def capture_day(*args: object, **kwargs: object) -> None:
        size = kwargs["page_size"]
        assert isinstance(size, int)
        observed.append(size)

    query_verb = (
        session_module.DB_QUERY_HISTORY
        if verb == "history"
        else session_module.DB_QUERY_LOCAL_EVENTS
    )
    monkeypatch.setattr(session_module, "history_query_verb", lambda _serial: query_verb)
    fake = SimpleNamespace(serial=serial, _history_day=capture_day)

    rows = await StationSession.async_list_history(fake, "20261025", page_size=requested)

    assert rows == []
    assert observed == [expected]
