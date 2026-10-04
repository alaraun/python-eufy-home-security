"""Stable ids and one serving account per station."""

from __future__ import annotations

import logging

import pytest

from eufy_home_security.cloud.models import CloudDevice
from eufy_home_security.identity import StationClaims, entity_unique_id
from eufy_home_security.testing import SYNTHETIC

OTHER_STATION_SN = "T8030P2000054321"
OWNER = "owner@example.com"
MEMBER = "member@example.com"
GUEST = "guest@example.com"


def _station(serial: str = SYNTHETIC.station_sn, *, member_type: int | None = None) -> CloudDevice:
    member = (
        {} if member_type is None else {"admin_user_id": "owner-id", "member_type": member_type}
    )
    return CloudDevice(
        device_sn=serial,
        device_type=18,
        name="HomeBase",
        p2p_did=SYNTHETIC.did,
        member_type=member_type,
        raw={"member": member} if member else {},
    )


class Changes(list[str]):
    def __call__(self, account: str) -> None:
        self.append(account)


def test_entity_unique_id_is_the_serial_and_the_key() -> None:
    assert (
        entity_unique_id(SYNTHETIC.station_sn, "guard_mode") == f"{SYNTHETIC.station_sn}_guard_mode"
    )


@pytest.mark.parametrize(
    ("serial", "key"),
    [
        ("", "battery"),
        ("T8030_P2", "battery"),
        (SYNTHETIC.station_sn, ""),
        (SYNTHETIC.station_sn, "Guard"),
    ],
)
def test_entity_unique_id_rejects_ambiguous_parts(serial: str, key: str) -> None:
    # A serial with "_" could collide: ("A_b", "c") and ("A", "b_c") would both be "A_b_c".
    with pytest.raises(ValueError, match=r"serial|key"):
        entity_unique_id(serial, key)


def test_a_free_station_goes_to_the_first_account_and_stays_with_it() -> None:
    claims = StationClaims()
    assert claims.claim(MEMBER, [_station(member_type=1)]) == {SYNTHETIC.station_sn}
    assert claims.claim(MEMBER, [_station(member_type=1)]) == {
        SYNTHETIC.station_sn
    }  # a rediscovery
    assert claims.holder(SYNTHETIC.station_sn) == MEMBER
    assert claims.holder(OTHER_STATION_SN) is None


def test_the_owner_takes_a_station_from_a_shared_account() -> None:
    changes = Changes()
    claims = StationClaims(changes)
    claims.claim(MEMBER, [_station(member_type=1), _station(OTHER_STATION_SN, member_type=1)])

    assert claims.claim(OWNER, [_station()]) == {SYNTHETIC.station_sn}
    assert changes == [MEMBER]  # told once to rebuild, however many stations moved
    assert claims.holder(SYNTHETIC.station_sn) == OWNER
    assert claims.holder(OTHER_STATION_SN) == MEMBER  # the owner does not see this one

    # The shared account rebuilds: it keeps only the station the owner does not serve.
    claims.release(MEMBER)
    assert changes == [MEMBER]  # releasing its own claims wakes nobody
    assert claims.claim(
        MEMBER, [_station(member_type=1), _station(OTHER_STATION_SN, member_type=1)]
    ) == {OTHER_STATION_SN}

    # When the owner's account goes, the waiting shared account is told to rebuild.
    claims.release(OWNER)
    assert changes == [MEMBER, MEMBER]
    assert claims.holder(SYNTHETIC.station_sn) is None


def test_owner_member_type_counts_as_owner() -> None:
    changes = Changes()
    claims = StationClaims(changes)
    claims.claim(GUEST, [_station(member_type=0)])
    assert claims.claim(OWNER, [_station(member_type=2)]) == {SYNTHETIC.station_sn}
    assert changes == [GUEST]


def test_between_shared_accounts_the_first_keeps_it() -> None:
    changes = Changes()
    claims = StationClaims(changes)
    claims.claim(MEMBER, [_station(member_type=1)])
    assert claims.claim(GUEST, [_station(member_type=0)]) == frozenset()
    assert changes == []

    claims.release(MEMBER)
    assert changes == [GUEST]
    assert claims.claim(GUEST, [_station(member_type=0)]) == {SYNTHETIC.station_sn}


def test_an_account_that_left_is_not_woken() -> None:
    changes = Changes()
    claims = StationClaims(changes)
    claims.claim(MEMBER, [_station(member_type=1)])
    claims.claim(GUEST, [_station(member_type=0)])
    claims.release(GUEST)  # stopped while waiting
    claims.release(MEMBER)
    assert changes == []


def test_a_failing_callback_is_logged_not_raised(caplog: pytest.LogCaptureFixture) -> None:
    def boom(_account: str) -> None:
        raise RuntimeError("boom")

    claims = StationClaims(boom)
    claims.claim(MEMBER, [_station(member_type=1)])
    with caplog.at_level(logging.ERROR):
        assert claims.claim(OWNER, [_station()]) == {SYNTHETIC.station_sn}
    assert "callback raised" in caplog.text
