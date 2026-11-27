"""How a model groups an ``SDINFO_EX`` status, from its file
(``devices.model_settings.sd_status_groups``)."""

from __future__ import annotations

import copy
import dataclasses
import json
import pickle
from collections.abc import Iterator
from pathlib import Path

import pytest

from eufy_home_security.devices import model_settings
from eufy_home_security.devices.model_settings import (
    SdStatusGroups,
    SdStatusSource,
    sd_status_groups,
)
from eufy_home_security.exceptions import ModelDataError

GOOD_ENTRY = {"access": "ro", "kind": "bool", "read": None, "section": "other", "role": "status"}
GROUPS = {"codes": {"0": 0, "4": 2, "-5": 3}, "default": 1, "from": "answer"}


def _clear() -> None:
    model_settings._load.cache_clear()
    model_settings._resolved.cache_clear()
    model_settings.bundled_codes.cache_clear()


@pytest.fixture
def data_root(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[Path]:
    """A temporary models directory the loader reads from, indexing ``T0001``."""
    monkeypatch.setattr(model_settings, "_root", lambda: tmp_path)
    index = {"schema_version": 3, "codes": ["T0001"]}
    (tmp_path / "INDEX.json").write_text(json.dumps(index), encoding="utf-8")
    _clear()
    yield tmp_path
    _clear()


def _write(root: Path, groups: object) -> None:
    doc = {"schema_version": 3, "product_code": "T0001", "settings": {"mode": GOOD_ENTRY}}
    if groups is not None:
        doc["sd_status_groups"] = groups
    (root / "T0001.json").write_text(json.dumps(doc), encoding="utf-8")


def test_the_file_names_each_status_group_and_the_default(data_root: Path) -> None:
    _write(data_root, {**GROUPS, "param": 1135})
    assert sd_status_groups("t0001") == SdStatusGroups({0: 0, 4: 2, -5: 3}, 1, 1135)


def test_the_file_names_what_the_table_is_read_from(data_root: Path) -> None:
    _write(data_root, {**GROUPS, "from": "status_property"})
    groups = sd_status_groups("T0001")
    assert groups == SdStatusGroups({0: 0, 4: 2, -5: 3}, 1, None, SdStatusSource.STATUS_PROPERTY)


def test_a_loaded_grouping_copies_pickles_and_converts(data_root: Path) -> None:
    _write(data_root, {**GROUPS, "param": 1135})
    groups = sd_status_groups("T0001")
    assert groups is not None
    for copied in (copy.deepcopy(groups), pickle.loads(pickle.dumps(groups))):  # noqa: S301
        assert copied == groups
        assert copied.group(4) == 2
    assert dataclasses.asdict(groups)["codes"] == {0: 0, 4: 2, -5: 3}
    assert hash(groups) == hash(SdStatusGroups({-5: 3, 4: 2, 0: 0}, 1, 1135))


def test_a_grouping_keeps_its_codes_when_the_caller_s_dict_changes() -> None:
    codes = {0: 0, 4: 2}
    groups = SdStatusGroups(codes, 1)
    codes[4] = 7
    assert (groups.group(4), dict(groups.codes)) == (2, {0: 0, 4: 2})


@pytest.mark.parametrize(("status", "group"), [(0, 0), (4, 2), (-5, 3), (30, 1), (5, 1)])
def test_a_status_the_file_does_not_list_has_the_default_group(
    data_root: Path, status: int, group: int
) -> None:
    _write(data_root, GROUPS)
    groups = sd_status_groups("T0001")
    assert groups is not None
    assert groups.group(status) == group


@pytest.mark.parametrize(
    ("status", "params", "group"),
    [
        (0, {1135: "4"}, 2),  # the parameter's status wins over the answer's
        (4, {1135: "0"}, 0),  # "0" is set
        (0, {1135: " 4 "}, 2),
        (0, {1135: "-5"}, 3),
        (0, {1135: "abc"}, 1),  # set, but no status: the default group
        (0, {1135: "4.0"}, 1),
        (0, {1135: "+4"}, 1),
        (4, {1135: ""}, 2),  # empty: the answer's status
        (4, {1135: None}, 2),
        (4, {1136: "0"}, 2),
        (4, {}, 2),
        (4, None, 2),
    ],
)
def test_a_set_status_parameter_is_grouped_in_place_of_the_answer(
    data_root: Path, status: int, params: dict[int, str | None] | None, group: int
) -> None:
    _write(data_root, {**GROUPS, "param": 1135})
    groups = sd_status_groups("T0001")
    assert groups is not None
    assert groups.group(status, params) == group


def test_without_a_parameter_the_device_params_do_not_matter(data_root: Path) -> None:
    _write(data_root, GROUPS)
    groups = sd_status_groups("T0001")
    assert groups is not None
    assert groups.group(0, {1135: "4"}) == 0


@pytest.mark.parametrize("code", [None, "T9ZZ9", "not a code!"])
def test_a_model_without_a_file_has_no_grouping(code: str | None) -> None:
    assert sd_status_groups(code) is None


def test_a_file_without_a_grouping_has_none(data_root: Path) -> None:
    _write(data_root, None)
    assert sd_status_groups("T0001") is None


@pytest.mark.parametrize(
    ("groups", "match"),
    [
        ([], "not an object"),
        ({"codes": {}, "default": 1}, r"\{codes, default, from, param\}"),
        ({**GROUPS, "map": {}}, r"\{codes, default, from, param\}"),
        ({**GROUPS, "from": "param"}, "not a valid SdStatusSource"),
        ({**GROUPS, "from": None}, "not a valid SdStatusSource"),
        ({**GROUPS, "from": []}, ""),
        ({**GROUPS, "from": "status_property", "param": 1135}, "not read from the answer"),
        ({**GROUPS, "default": "1"}, "default group"),
        ({**GROUPS, "default": True}, "default group"),
        ({**GROUPS, "codes": []}, "status -> group"),
        ({**GROUPS, "codes": {"x": 1}}, "status -> group"),
        ({**GROUPS, "codes": {"04": 1}}, "status -> group"),
        ({**GROUPS, "codes": {"0": "0"}}, "status -> group"),
        ({**GROUPS, "codes": {"0": False}}, "status -> group"),
        ({**GROUPS, "param": "1135"}, "no parameter id"),
        ({**GROUPS, "param": 0}, "no parameter id"),
        ({**GROUPS, "param": 65536}, "no parameter id"),
    ],
)
def test_a_malformed_grouping_names_the_file(data_root: Path, groups: object, match: str) -> None:
    _write(data_root, groups)
    with pytest.raises(ModelDataError, match=rf"T0001\.json.*{match}"):
        sd_status_groups("T0001")


@pytest.mark.parametrize(
    ("code", "status", "params", "group"),
    [
        ("T8210", 30, None, 0),  # the table that groups 30 as normal
        ("T8210", 33, None, 1),  # and leaves out 33
        ("T8162", 33, None, 22),  # the table that groups 33
        ("T8160", 4, None, 2),  # read from its status property: its parse reads no status
        ("T8160", 30, None, 0),
        ("T8115", 30, None, 1),  # its table leaves out 29, 30 and 31
        ("T8115", 29, None, 1),
        ("T8115", 31, None, 1),
        ("T8115", 33, None, 1),
        ("T8600", 0, {1135: "4"}, 2),  # it groups a set status parameter
        ("T8600", 0, {1135: ""}, 0),
    ],
)
def test_bundled_models_group_as_their_file_says(
    code: str, status: int, params: dict[int, str | None] | None, group: int
) -> None:
    groups = sd_status_groups(code)
    assert groups is not None
    assert groups.group(status, params) == group


@pytest.mark.parametrize(
    ("code", "source", "param"),
    [
        ("T8170", SdStatusSource.ANSWER, None),
        ("T8160", SdStatusSource.STATUS_PROPERTY, None),
        ("T8600", SdStatusSource.ANSWER, 1135),
    ],
)
def test_bundled_models_name_what_their_table_is_read_from(
    code: str, source: SdStatusSource, param: int | None
) -> None:
    groups = sd_status_groups(code)
    assert groups is not None
    assert (groups.source, groups.param) == (source, param)


def test_a_bundled_model_whose_handler_reads_no_status_has_no_grouping() -> None:
    assert sd_status_groups("T8500") is None
