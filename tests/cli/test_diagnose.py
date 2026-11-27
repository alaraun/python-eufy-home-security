"""``eufy-security diagnose rtc``: the read-only WebRTC report, end to end.

A real client over the fake cloud (``testing.cloud``) and the loopback fake WebRTC
station (``testing.rtc``).
"""

from __future__ import annotations

import dataclasses
import functools
import json
import stat
from collections.abc import AsyncIterator
from pathlib import Path
from typing import Any

import pytest

from eufy_home_security.cli import app, commands
from eufy_home_security.cli.config import EXIT_ERROR, EXIT_USAGE, parse_args
from eufy_home_security.cli.render import render_rtc_diagnose
from eufy_home_security.exceptions import MissingDependencyError
from eufy_home_security.p2p.xzyh import encode_frame
from eufy_home_security.push import fcm as fcm_module
from eufy_home_security.rtc import diagnostics as diag
from eufy_home_security.rtc import ice as ice_module
from eufy_home_security.rtc.data_channel import DataMsgType
from eufy_home_security.testing import SYNTHETIC
from eufy_home_security.testing.cloud import FakeCloud, build_eufy_security, warm_store
from eufy_home_security.testing.rtc import CONTACT, LICENSE, FakeRtcServer

NVR_SN = "T8N00" + SYNTHETIC.station_sn[5:]
PLAIN_SN = "T8025" + SYNTHETIC.station_sn[5:]
#: Every cloud request a read-only run may make.
READ_ONLY_CALLS = {"login", "profile", "client_country", "last_login_code", "devices", "houses"}


def nvr_entry(serial: str = NVR_SN) -> dict[str, Any]:
    return {
        "device_sn": serial,
        "device_type": 0,
        "device_name": "Synthetic NVR",
        "device_new_pn": serial[:5],
        "p2p_did": SYNTHETIC.did,
        "p2p_license": LICENSE,
        "signaling_servers": ["https://127.0.0.1"],
        "main_sw_version": "1.3.0.0",
        "webrtc_sdk_version": "1.1.0",
    }


@pytest.fixture
async def station(monkeypatch: pytest.MonkeyPatch) -> AsyncIterator[FakeRtcServer]:
    server = await FakeRtcServer().start()
    server.unasked = [(DataMsgType.NOTIFY, encode_frame(0x0514, b"x" * 8, bytes(6)))]
    monkeypatch.setattr(
        diag,
        "async_diagnose_station",
        functools.partial(
            diag.async_diagnose_station,
            ice_factory=server.ice_factory,
            signaling_port=server.port,
            tcp_ports=(server.tcp_port,),
        ),
    )
    yield server
    await server.close()
    assert server.refused == []


@pytest.fixture
def cloud(monkeypatch: pytest.MonkeyPatch) -> FakeCloud:
    fake = FakeCloud(devices=[nvr_entry(), nvr_entry(PLAIN_SN)])
    store = warm_store(email=SYNTHETIC.email, cloud=fake)

    async def open_account(_ctx: commands.Context, **_kwargs: Any) -> Any:
        return build_eufy_security(email=SYNTHETIC.email, store=store, cloud=fake)

    monkeypatch.setattr(commands, "open_account", open_account)
    return fake


@pytest.fixture
def no_push(monkeypatch: pytest.MonkeyPatch) -> None:
    class Refused:
        def __init__(self, *_args: Any, **_kwargs: Any) -> None:
            raise AssertionError("diagnose must not start the push listener")

    monkeypatch.setattr(fcm_module, "PushListener", Refused)


async def run(*argv: str) -> int:
    return await app.run(parse_args(list(argv)), env={})


def synthetic_values() -> list[str]:
    values = [NVR_SN, PLAIN_SN, LICENSE, CONTACT, "127.0.0.1"]
    for f in dataclasses.fields(SYNTHETIC):
        value = getattr(SYNTHETIC, f.name)
        if isinstance(value, bytes):
            value = value.decode()
        if isinstance(value, str):
            values.append(value)
    return values


async def test_the_report_is_redacted_and_the_summary_names_each_step(
    station: FakeRtcServer,
    cloud: FakeCloud,
    no_push: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    out = tmp_path / "report.json"
    assert await run("diagnose", "rtc", "--seconds", "0.3", "--probe-kinds", "--out", str(out)) == 0
    text = out.read_text()
    data = json.loads(text)
    assert [s["station"] for s in data["stations"]] == ["T8N00***2345"]  # the routed one only
    entry = data["stations"][0]
    assert entry["reason"] == "station"
    assert entry["call"]["outcome"]["status"] == "ok"
    assert entry["data_channel"]["frames"][0]["xzyh_type"] == 0x0514
    assert data["options"] == {"seconds": 0.3, "probe_kinds": True, "serial": None}
    assert [v for v in synthetic_values() if v in text] == []
    assert not (tmp_path / "report.secrets.json").exists()
    printed = capsys.readouterr()
    assert "T8N00***2345" in printed.out
    assert "login ok" in printed.out
    assert "kcp" in printed.out
    assert str(out) in printed.out
    assert [v for v in synthetic_values() if v in printed.out + printed.err] == []


async def test_the_run_writes_nothing_to_the_account(
    station: FakeRtcServer, cloud: FakeCloud, no_push: None, tmp_path: Path
) -> None:
    out = tmp_path / "report.json"
    assert await run("diagnose", "rtc", "--seconds", "0.2", "--out", str(out)) == 0
    assert cloud.calls  # the device list was fetched
    assert {c.split("@")[0].split(":")[0] for c in cloud.calls} <= READ_ONLY_CALLS
    assert cloud.invite_accepts == []


async def test_secrets_go_to_a_separate_private_file_with_a_warning(
    station: FakeRtcServer,
    cloud: FakeCloud,
    no_push: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    out = tmp_path / "report.json"
    assert await run("diagnose", "rtc", "--seconds", "0.2", "--secrets", "--out", str(out)) == 0
    secret = tmp_path / "report.secrets.json"
    assert stat.S_IMODE(secret.stat().st_mode) == 0o600
    raw = json.loads(secret.read_text())
    assert raw["stations"][0]["p2p_did"] == SYNTHETIC.did
    assert SYNTHETIC.did not in out.read_text()
    assert "WARNING" in capsys.readouterr().err


async def test_a_refused_secrets_file_comes_after_the_report_and_summary(
    station: FakeRtcServer,
    cloud: FakeCloud,
    no_push: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    out = tmp_path / "report.json"
    target = tmp_path / "elsewhere.json"
    secret = tmp_path / "report.secrets.json"
    secret.symlink_to(target)
    code = await run("diagnose", "rtc", "--seconds", "0.2", "--secrets", "--out", str(out))
    assert code == EXIT_ERROR
    assert json.loads(out.read_text())["stations"][0]["station"] == "T8N00***2345"
    assert not target.exists()
    printed = capsys.readouterr()
    assert "Report written to" in printed.out
    assert "1 inputs" in printed.out
    assert f"secrets file {secret} not written" in printed.err
    assert "WARNING" not in printed.err


async def test_a_named_station_runs_whatever_its_route(
    station: FakeRtcServer, cloud: FakeCloud, no_push: None, tmp_path: Path
) -> None:
    out = tmp_path / "report.json"
    assert await run("diagnose", "rtc", PLAIN_SN, "--seconds", "0.2", "--out", str(out)) == 0
    text = out.read_text()
    data = json.loads(text)
    assert [(s["station"], s["reason"]) for s in data["stations"]] == [("T8025***2345", "asked")]
    assert data["options"]["serial"] == "T8025***2345"
    assert [v for v in synthetic_values() if v in text] == []


async def test_a_serial_no_station_has_is_a_usage_error(
    station: FakeRtcServer,
    cloud: FakeCloud,
    no_push: None,
    tmp_path: Path,
    capsys: pytest.CaptureFixture[str],
) -> None:
    out = tmp_path / "report.json"
    code = await run("diagnose", "rtc", "T8030P0000000000", "--out", str(out))
    assert code == EXIT_USAGE
    assert not out.exists()
    err = capsys.readouterr().err
    assert "T8030***0000" in err
    assert "T8030P0000000000" not in err


async def test_without_the_extra_it_says_how_to_install_before_logging_in(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    def missing() -> None:
        raise MissingDependencyError("the WebRTC transport", extra="rtc")

    async def no_login(*_args: Any, **_kwargs: Any) -> Any:
        raise AssertionError("no login without the extra")

    monkeypatch.setattr(ice_module, "require_aioice", missing)
    monkeypatch.setattr(commands, "open_account", no_login)
    code = await run("diagnose", "rtc", "--out", str(tmp_path / "r.json"))
    assert code == EXIT_USAGE
    assert "pip install 'eufy-home-security[rtc]'" in capsys.readouterr().err


class ReachedLoginError(Exception):
    """Raised by a stand-in login: the command got past its argument checks."""


async def test_a_watch_longer_than_the_bound_is_refused_before_login(
    monkeypatch: pytest.MonkeyPatch, tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    async def reached(*_args: Any, **_kwargs: Any) -> Any:
        raise ReachedLoginError

    monkeypatch.setattr(commands, "open_account", reached)
    argv = ("diagnose", "rtc", "--store", str(tmp_path / "cache.json"), "--out")
    code = await run(*argv, str(tmp_path / "r.json"), "--seconds", "601")
    assert code == EXIT_USAGE
    assert "--seconds must be at most 600" in capsys.readouterr().err
    with pytest.raises(ReachedLoginError):
        await run(*argv, str(tmp_path / "r.json"), "--seconds", "600")


@pytest.mark.parametrize(
    "argv",
    [
        ["diagnose", "rtc", "--seconds", "0"],
        ["diagnose", "media"],
        ["diagnose"],
    ],
)
def test_bad_arguments_are_refused(argv: list[str]) -> None:
    with pytest.raises(SystemExit) as caught:
        parse_args(argv)
    assert caught.value.code == EXIT_USAGE


def test_the_defaults() -> None:
    args = parse_args(["diagnose", "rtc"])
    assert (args.kind, args.serial, args.seconds, args.probe_kinds, args.out) == (
        "rtc",
        None,
        None,
        False,
        None,
    )


def summary_entry(**changes: Any) -> dict[str, Any]:
    ok = {"status": "ok", "seconds": 0.1, "error": None, "code": None, "reason": None}
    entry: dict[str, Any] = {
        "station": "T8N00***2345",
        "reason": "station",
        "inputs": {"outcome": ok, "missing": [], "webrtc_sdk_version": "1.1.0", "kcp_type": 1},
        "login": {"discover": ok, "login": ok},
        "call": {
            "outcome": ok,
            "transport": "kcp",
            "transport_caps": 0,
            "transport_caps_source": "pbsdp",
            "pbsdp_len": 12,
        },
        "ice": {"outcome": ok, "selected": ["host", "srflx"]},
        "data_channel": {
            "outcome": ok,
            "messages": 3,
            "heartbeats": 1,
            "frames": [{}, {}],
            "watched": 60.0,
            "guard_mode_at": 1.25,
            "sealed_opened": 0,
            "sealed_unread": 0,
        },
        "close": ok,
        "probes": {"login": ok, "kinds": []},
    }
    entry.update(changes)
    return entry


def test_the_summary_names_the_caps_source_and_the_guard_mode_time() -> None:
    text = render_rtc_diagnose([summary_entry()])
    assert "transport_caps 0 (pbsdp)" in text
    assert "guard mode after 1.25 s" in text


def test_the_summary_gives_a_probes_status_and_code_when_it_is_not_ok() -> None:
    failed = {"status": "failed", "seconds": None, "error": "RtcCallError", "code": 486}
    kinds = [
        {"kind": 1, "codes": [200], "outcome": {"status": "ok", "seconds": 0.2}},
        {"kind": 3, "codes": [100], "outcome": {"status": "timeout", "seconds": 8.0}},
        {"kind": 4, "codes": [], "outcome": failed},
    ]
    probes = {"login": {"status": "ok", "seconds": 0.1}, "kinds": kinds}
    text = render_rtc_diagnose([summary_entry(probes=probes)])
    assert "kind 1: 200, kind 3: 100 timeout, kind 4: failed: RtcCallError 486" in text


def test_the_summary_gives_the_probe_logins_timeout() -> None:
    skipped = {"status": "skipped", "seconds": None, "reason": "run timed out"}
    kinds: list[dict[str, Any]] = [{"kind": k, "codes": [], "outcome": skipped} for k in (1, 3, 4)]
    login = {"status": "timeout", "seconds": 2.49, "error": None, "code": None}
    text = render_rtc_diagnose([summary_entry(probes={"login": login, "kinds": kinds})])
    assert "6 probes        login timeout, kind 1: skipped: run timed out" in text


@pytest.mark.parametrize(
    ("opened", "unread", "at", "expected"),
    [
        (0, 0, None, ", no guard mode frame"),
        (1, 0, 1.25, ", sealed 1 opened / 0 unread, guard mode after 1.25 s"),
        (0, 2, None, ", sealed 0 opened / 2 unread, guard mode unknown"),
        (1, 2, None, ", sealed 1 opened / 2 unread, guard mode unknown"),
        (1, 0, None, ", sealed 1 opened / 0 unread, no guard mode frame"),
        (0, 2, 0.5, ", sealed 0 opened / 2 unread, guard mode after 0.5 s"),
    ],
)
def test_the_summary_tells_an_unknown_guard_mode_from_an_absent_one(
    opened: int, unread: int, at: float | None, expected: str
) -> None:
    channel = {
        **summary_entry()["data_channel"],
        "sealed_opened": opened,
        "sealed_unread": unread,
        "guard_mode_at": at,
    }
    line = render_rtc_diagnose([summary_entry(data_channel=channel)]).splitlines()[5]
    assert line.endswith(" s" + expected)


def test_the_summary_names_a_close_that_timed_out() -> None:
    close = {"status": "timeout", "seconds": 1.0, "reason": "run timed out while closing"}
    text = render_rtc_diagnose([summary_entry(close=close)])
    assert "    close         timeout: run timed out while closing" in text
    assert "close" not in render_rtc_diagnose([summary_entry()])


def test_a_private_file_is_not_written_through_a_symlink(tmp_path: Path) -> None:
    target = tmp_path / "elsewhere.json"
    target.write_text("{}")
    link = tmp_path / "report.secrets.json"
    link.symlink_to(target)
    with pytest.raises(OSError, match="symbolic link"):
        commands._write_json(link, {"secret": 1}, private=True)
    assert target.read_text() == "{}"


DOCS = Path(__file__).resolve().parents[2] / "docs" / "how-to" / "diagnose-rtc.md"


def test_the_how_tos_commands_parse_and_pin_a_version() -> None:
    lines = [ln for ln in DOCS.read_text().splitlines() if ln.startswith("uvx ")]
    assert len(lines) == 2
    for line in lines:
        assert "--from 'eufy-home-security[rtc]>=<version>' eufy-security " in line
        parse_args(line.split(" eufy-security ", 1)[1].split())
    assert "--redact-serials" in lines[0]  # login lists the stations' serials
