import json
import os
import threading
import time
from types import SimpleNamespace

import pytest

from pwn_broker import checks
from pwn_broker.checks import (
    CheckResult,
    latest_version,
    launch_checks,
    newer,
    newer_release_within,
    report,
    run_checks,
    version_check,
)
from pwn_broker.config import Settings
from pwn_broker.console import FakeConsole
from pwn_broker.vpn import Tunnel


def _no_tunnel():
    return None


def _env(paths, **extra):
    env = {"DISPLAY": ":0", "PATH": f"{paths.bin}{os.pathsep}/usr/bin"}
    env.update(extra)
    return env


def _found(name):
    return "/usr/bin/" + name


def _venv_ok(argv, **kwargs):
    return SimpleNamespace(returncode=0, stdout=b"", stderr=b"")


def _ready(paths):
    paths.active.mkdir(parents=True)
    paths.wrapped.mkdir(parents=True)


def _by_name(results):
    return {r.name: r for r in results}


def _missing(wanted):
    return lambda name: None if name == wanted else _found(name)


def test_all_checks_pass(paths):
    _ready(paths)
    results = run_checks(
        paths, Settings(), _env(paths), which=_found, run=_venv_ok, tunnel=lambda: Tunnel("tun0", "10.10.14.7")
    )
    assert all(r.status == "ok" for r in results)
    assert [r.name for r in results] == [
        "vim", "terminal", "tar", "venv", "display", "path", "folders", "vpn"
    ]  # fmt: skip


def test_vpn_check_names_the_address_and_interface(paths):
    results = run_checks(paths, Settings(), _env(paths), which=_found, tunnel=lambda: Tunnel("tun1", "10.10.14.7"))
    found = _by_name(results)["vpn"]
    assert (found.status, found.message) == ("ok", "10.10.14.7 on tun1")


def test_vpn_check_warns_without_a_tunnel_and_never_fails(paths):
    results = run_checks(paths, Settings(), _env(paths), which=_found, tunnel=lambda: None)
    found = _by_name(results)["vpn"]
    assert (found.status, found.message, found.hint) == (
        "warn", "no VPN tunnel is up", "start one with: vpn start"
    )  # fmt: skip
    assert found.repair is None


def test_launch_checks_pass_the_tunnel_reader_through(paths, tmp_path):
    results = launch_checks(
        paths, Settings(), {"PATH": ""}, tmp_path, include_version=False,
        tunnel=lambda: Tunnel("tun0", "10.10.14.7"),
    )  # fmt: skip
    assert _by_name(results)["vpn"].message == "10.10.14.7 on tun0"


def test_missing_vim_fails_with_install_hint(paths):
    _ready(paths)
    results = run_checks(paths, Settings(), _env(paths), which=_missing("vim"), tunnel=_no_tunnel)
    vim = _by_name(results)["vim"]
    assert vim.status == "fail"
    assert "apt install vim" in vim.hint


def test_missing_tar_fails_with_install_hint(paths):
    _ready(paths)
    results = run_checks(paths, Settings(), _env(paths), which=_missing("tar"), tunnel=_no_tunnel)
    tar = _by_name(results)["tar"]
    assert tar.status == "fail"
    assert "apt install tar" in tar.hint


def test_missing_terminal_names_setting_and_config_file(paths):
    _ready(paths)
    results = run_checks(
        paths, Settings(terminal="kitty"), _env(paths), which=_missing("kitty"), tunnel=_no_tunnel
    )
    term = _by_name(results)["terminal"]
    assert term.status == "fail"
    assert "kitty" in term.hint
    assert str(paths.config_file) in term.hint


def test_no_display_warns_with_manual_command(paths):
    _ready(paths)
    env = {"PATH": str(paths.bin), "DISPLAY": ""}
    display = _by_name(run_checks(paths, Settings(), env, which=_found, tunnel=_no_tunnel))["display"]
    assert display.status == "warn"
    assert f"vim -u {paths.vim_dir / 'vimrc'} notes.md" in display.hint


def test_wayland_counts_as_display(paths):
    _ready(paths)
    env = {"PATH": str(paths.bin), "WAYLAND_DISPLAY": "wayland-0"}
    assert _by_name(run_checks(paths, Settings(), env, which=_found, tunnel=_no_tunnel))["display"].status == "ok"


def test_path_missing_warns_and_can_repair(paths):
    _ready(paths)
    called = []
    results = run_checks(
        paths, Settings(), {"DISPLAY": ":0", "PATH": "/usr/bin"}, which=_found,
        repair_path=lambda: called.append(1), tunnel=_no_tunnel,
    )  # fmt: skip
    path = _by_name(results)["path"]
    assert path.status == "warn"
    assert path.repair is not None
    path.repair()
    assert called == [1]


def test_path_must_match_an_entry_exactly(paths):
    _ready(paths)
    env = {"DISPLAY": ":0", "PATH": f"{paths.bin}-old{os.pathsep}/usr/bin"}
    assert _by_name(run_checks(paths, Settings(), env, which=_found, tunnel=_no_tunnel))["path"].status == "warn"


def test_folders_missing_are_repairable(paths):
    results = run_checks(paths, Settings(), _env(paths), which=_found, run=_venv_ok, tunnel=_no_tunnel)
    folders = _by_name(results)["folders"]
    assert folders.status == "warn"
    folders.repair()
    assert paths.active.is_dir() and paths.wrapped.is_dir()


def test_report_one_line_when_all_ok():
    c = FakeConsole()
    report(c, [CheckResult("vim", "ok", "")] * 5)
    assert c.lines == [("ok", "5 checks passed")]


def test_report_lists_each_problem_and_offers_repair():
    fixed = []
    c = FakeConsole(["y"])
    results = [
        CheckResult("vim", "ok", ""),
        CheckResult("path", "warn", "not on PATH", "open a new terminal", lambda: fixed.append(1)),
        CheckResult("tar", "fail", "not found", "apt install tar"),
    ]
    report(c, results)
    assert fixed == [1]
    assert c.asked == ["fix it now?"]
    assert c.lines == [
        ("ok", "1 check passed"),
        ("warn", "path   not on PATH"),
        ("info", "open a new terminal"),
        ("ok", "path fixed"),
        ("fail", "tar   not found"),
        ("info", "apt install tar"),
    ]


def test_report_omits_count_when_nothing_passed():
    c = FakeConsole()
    report(c, [CheckResult("tar", "fail", "not found")])
    assert c.lines == [("fail", "tar   not found")]


def test_report_declined_repair_is_not_run():
    fixed = []
    c = FakeConsole(["n"])
    report(c, [CheckResult("path", "warn", "m", repair=lambda: fixed.append(1))])
    assert fixed == []
    assert ("ok", "path fixed") not in c.lines


def test_report_cancelled_confirm_counts_as_no():
    fixed = []
    c = FakeConsole([])
    report(c, [CheckResult("path", "warn", "m", repair=lambda: fixed.append(1))])
    assert fixed == []


def test_report_repair_oserror_prints_fail():
    def boom():
        raise OSError("disk full")

    c = FakeConsole(["y"])
    report(c, [CheckResult("folders", "warn", "m", repair=boom)])
    assert c.lines[-1] == ("fail", "disk full")


def test_report_repair_valueerror_prints_one_fail():
    def boom():
        raise ValueError("bad text")

    c = FakeConsole(["y"])
    report(c, [CheckResult("path", "warn", "m", repair=boom)])
    assert c.lines == [("warn", "path   m"), ("fail", "bad text")]


@pytest.mark.parametrize("count,line", [(1, "1 check passed"), (2, "2 checks passed"), (7, "7 checks passed")])
def test_report_count_is_singular_for_one(count, line):
    c = FakeConsole()
    report(c, [CheckResult("vim", "ok", "")] * count)
    assert c.lines == [("ok", line)]


def test_newer_release_within_returns_the_result(monkeypatch):
    found = CheckResult("version", "warn", "9.9 is available")
    monkeypatch.setattr(checks, "version_check", lambda settings: found)
    assert newer_release_within(Settings()) is found


def test_newer_release_within_gives_up_after_the_timeout(monkeypatch):
    release = threading.Event()
    monkeypatch.setattr(checks, "version_check", lambda settings: release.wait(10))
    started = time.monotonic()
    try:
        assert newer_release_within(Settings(), timeout=0.05) is None
        assert time.monotonic() - started < 2
    finally:
        release.set()


def test_newer_release_within_swallows_errors(monkeypatch):
    def boom(settings):
        raise RuntimeError("no network")

    monkeypatch.setattr(checks, "version_check", boom)
    assert newer_release_within(Settings()) is None


def test_path_repair_also_writes_bashrc_when_it_exists(paths, tmp_path):
    home = tmp_path / "user"
    home.mkdir()
    (home / ".bashrc").write_text("# mine\n", encoding="utf-8")
    [path] = [r for r in launch_checks(paths, Settings(), {"PATH": ""}, home, include_version=False, tunnel=_no_tunnel) if r.name == "path"]
    path.repair()
    for rc in (".zshrc", ".bashrc"):
        assert paths.bin.as_posix() in (home / rc).read_text(encoding="utf-8")
    assert (home / ".bashrc").read_text(encoding="utf-8").startswith("# mine\n")


def test_path_repair_leaves_a_missing_bashrc_alone(paths, tmp_path):
    home = tmp_path / "user"
    home.mkdir()
    [path] = [r for r in launch_checks(paths, Settings(), {"PATH": ""}, home, include_version=False, tunnel=_no_tunnel) if r.name == "path"]
    path.repair()
    assert (home / ".zshrc").exists() and not (home / ".bashrc").exists()


def test_newer():
    assert newer("0.1.0", "0.2.0") and newer("0.9.0", "0.10.0")
    assert not newer("0.2.0", "0.2.0")
    assert not newer("0.2.0", "garbage")
    assert not newer("garbage", "0.2.0")
    assert newer("0.2", "0.2.1")
    assert not newer("0.2", "0.2.0") and not newer("0.2.0", "0.2")


def test_latest_version_strips_v():
    body = json.dumps({"tag_name": "v1.2.3"}).encode()
    assert latest_version(fetch=lambda url, timeout: body) == "1.2.3"


def test_latest_version_passes_url_and_timeout():
    seen = []

    def fetch(url, timeout):
        seen.append((url, timeout))
        return b'{"tag_name": "1.0.0"}'

    latest_version(fetch=fetch, timeout=1.5)
    assert seen == [
        ("https://api.github.com/repos/Real-Fruit-Snacks/pwn-broker/releases/latest", 1.5)
    ]


@pytest.mark.parametrize("body", [b"not json", b"{}", b'{"tag_name": 3}', b"[1]", b"\xff"])
def test_latest_version_junk_is_none(body):
    assert latest_version(fetch=lambda url, timeout: body) is None


def test_latest_version_swallows_errors():
    def fetch(url, timeout):
        raise OSError("offline")

    assert latest_version(fetch=fetch) is None


def test_version_check_off():
    def fetch(url, timeout):
        raise AssertionError("must not be called")

    assert version_check(Settings(check_updates=False), fetch=fetch) is None


def test_version_check_reports_newer():
    result = version_check(Settings(), "0.1.0", fetch=lambda u, t: b'{"tag_name": "v0.2.0"}')
    assert result == CheckResult("version", "warn", "0.2.0 is available, this is 0.1.0")


def test_version_check_quiet_when_current():
    assert version_check(Settings(), "0.2.0", fetch=lambda u, t: b'{"tag_name": "v0.2.0"}') is None


def test_version_check_quiet_when_fetch_fails():
    def fetch(url, timeout):
        raise OSError("offline")

    assert version_check(Settings(), "0.1.0", fetch=fetch) is None


def test_venv_check_passes_when_python_can_make_environments(paths):
    seen = []

    def run(argv, **kwargs):
        seen.append(argv)
        return SimpleNamespace(returncode=0)

    _ready(paths)
    venv = _by_name(run_checks(paths, Settings(), _env(paths), which=_found, run=run, tunnel=_no_tunnel))["venv"]
    # venv --help works without python3-venv; ensurepip is the part that package adds
    assert venv.status == "ok" and seen == [["python3", "-c", "import ensurepip"]]


@pytest.mark.parametrize("failure", ["exit", "missing", "hang"])
def test_venv_check_warns_with_the_package_hint(paths, failure):
    import subprocess

    def run(argv, **kwargs):
        if failure == "missing":
            raise FileNotFoundError("python3")
        if failure == "hang":
            raise subprocess.TimeoutExpired(argv, 20)
        return SimpleNamespace(returncode=1)

    _ready(paths)
    venv = _by_name(run_checks(paths, Settings(), _env(paths), which=_found, run=run, tunnel=_no_tunnel))["venv"]
    assert venv.status == "warn" and venv.hint == "apt install python3-venv"


def test_a_missing_venv_does_not_stop_the_app(paths):
    def run(argv, **kwargs):
        return SimpleNamespace(returncode=1)

    _ready(paths)
    results = run_checks(paths, Settings(), _env(paths), which=_found, run=run, tunnel=_no_tunnel)
    assert not any(r.status == "fail" for r in results)
    console = FakeConsole()
    checks.report(console, results)
    assert ("warn", "venv   python3 cannot make virtual environments") in console.lines
