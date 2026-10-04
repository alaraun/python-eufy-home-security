"""P2P device id and static-key derivation."""

from __future__ import annotations

import contextlib
import string

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st

from eufy_home_security.exceptions import ProtocolError
from eufy_home_security.p2p.did import Did, static_key
from eufy_home_security.testing import SYNTHETIC


def test_parse_and_str_round_trip() -> None:
    did = Did.parse(SYNTHETIC.did)
    assert (did.prefix, did.number, did.suffix) == ("EUPRAMA", 123456, "ABCDE")
    assert str(did) == SYNTHETIC.did


def test_struct_round_trip() -> None:
    did = Did.parse(SYNTHETIC.did)
    body = did.to_struct()
    assert len(body) == 20
    assert Did.from_struct(body) == did


def test_from_struct_rejects_short_body() -> None:
    with pytest.raises(ProtocolError):
        Did.from_struct(b"too short")


def test_parse_rejects_malformed() -> None:
    with pytest.raises(ProtocolError):
        Did.parse("INVALID-STRING")
    with pytest.raises(ProtocolError):
        Did.parse("PREFIX-notanumber-SUFFIX")


def test_static_key_matches_the_synthetic_identity() -> None:
    key = static_key(SYNTHETIC.station_sn, SYNTHETIC.did)
    assert key == SYNTHETIC.static_key
    assert len(key) == 16
    # a Did instance is accepted as well as a string
    assert static_key(SYNTHETIC.station_sn, Did.parse(SYNTHETIC.did)) == SYNTHETIC.static_key


def test_static_key_rejects_a_non_16_byte_result() -> None:
    with pytest.raises(ProtocolError):
        static_key("T8030", SYNTHETIC.did)  # serial too short
    with pytest.raises(ProtocolError):
        static_key(SYNTHETIC.station_sn, Did(prefix="EUPRAMA", number=9999999, suffix="ABCDE"))


def test_a_small_number_keeps_its_leading_zeros() -> None:
    did = Did.parse("EUPRAMA-000123-ABCDE")
    assert did.number == 123
    assert str(did) == "EUPRAMA-000123-ABCDE"
    assert Did.from_struct(did.to_struct()) == did
    key = static_key(SYNTHETIC.station_sn, did)
    assert key == b"0012345-000123-A"
    assert len(key) == 16


@pytest.mark.parametrize(
    "text",
    [
        "EUPRAMA-12_3456-ABCDE",  # underscore: int() would accept it
        " EUPRAMA-123456-ABCDE",
        "EUPRAMA-123456-ABCDE\n",
        "EUPRAMA- 123456-ABCDE",
        "EUPRAMA-١٢٣٤٥٦-ABCDE",  # non-ASCII digits
        "EUPRAMA-12345-ABCDE",  # five digits
        "EUPRAMA-1234567-ABCDE",
        "EUPRAMA-123456-ABCD",  # four-letter suffix
        "eupRAMA-123456-ABCDE",
        "EUPRAMAXX-123456-ABCDE",  # nine-letter prefix
        "ÉUPRAMA-123456-ABCDE",
    ],
)
def test_parse_rejects_non_canonical_text(text: str) -> None:
    with pytest.raises(ProtocolError):
        Did.parse(text)


def test_non_ascii_or_malformed_fields_raise_protocol_error() -> None:
    with pytest.raises(ProtocolError):
        static_key("T8030P20000123é5", SYNTHETIC.did)  # non-ASCII serial
    body = bytearray(Did.parse(SYNTHETIC.did).to_struct())
    body[12] = 0xC3  # non-ASCII suffix byte
    with pytest.raises(ProtocolError):
        Did.from_struct(bytes(body))
    with pytest.raises(ProtocolError):
        Did(prefix="ÉUPRAMA", number=1, suffix="ABCDE").to_struct()
    with pytest.raises(ProtocolError):
        Did(prefix="EUPRAMA", number=1, suffix="ABCDEFG").to_struct()  # would truncate


_PREFIX = st.text(alphabet=string.ascii_uppercase, min_size=1, max_size=8)
_SUFFIX = st.text(alphabet=string.ascii_uppercase, min_size=5, max_size=5)


@given(prefix=_PREFIX, number=st.integers(0, 999_999), suffix=_SUFFIX)
@settings(max_examples=100)
def test_struct_and_text_round_trip_for_any_valid_did(
    prefix: str, number: int, suffix: str
) -> None:
    did = Did(prefix=prefix, number=number, suffix=suffix)
    assert Did.from_struct(did.to_struct()) == did
    assert Did.parse(str(did)) == did


@given(data=st.binary(max_size=40))
@settings(max_examples=200)
def test_from_struct_only_raises_protocol_error(data: bytes) -> None:
    with contextlib.suppress(ProtocolError):
        Did.from_struct(data)


@given(text=st.text(max_size=24))
@settings(max_examples=200)
def test_parse_only_raises_protocol_error(text: str) -> None:
    with contextlib.suppress(ProtocolError):
        Did.parse(text)
