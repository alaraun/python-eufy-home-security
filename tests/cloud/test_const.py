"""The cloud hosts and login scopes of ``cloud.const``."""

from __future__ import annotations

import pytest

from eufy_home_security.cloud import const


def test_each_region_has_its_own_security_host() -> None:
    assert const.security_host("eu") == "security-app-eu.eufylife.com"
    assert const.security_host("us") == "security-app.eufylife.com"
    with pytest.raises(ValueError, match="unknown region"):
        const.security_host("ap")


@pytest.mark.parametrize(
    ("region", "country", "scope"), [("eu", None, "eu"), ("us", None, "us"), ("eu", "CH", "eu:CH")]
)
def test_a_login_scope_names_its_region_and_country(
    region: str, country: str | None, scope: str
) -> None:
    assert const.scope(region, country) == scope
    assert (const.scope_region(scope), const.scope_country(scope)) == (region, country)
