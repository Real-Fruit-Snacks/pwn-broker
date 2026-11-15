import hashlib
import subprocess
from pathlib import Path

import pytest

from helpers import NOW
from pwn_broker import shell  # noqa: F401  (fills the command registry)
from pwn_broker.config import State, load_state, save_state
from pwn_broker.console import FakeConsole
from pwn_broker.model import VpnRecord
from pwn_broker.shell.commands import dispatch
from pwn_broker.store import load_box, write_toml
from pwn_broker.vpn import Tunnel

PID = 4321
START = "123456"
TUN = Tunnel("tun0", "10.10.14.7")
CONTENT = b"client\nremote 10.10.10.1 1194\n"
SHA = hashlib.sha256(CONTENT).hexdigest()


class OpenVpn:
    """What sudo and openvpn would do, against the conftest process table."""

    def __init__(self, system, *, status=0, comes_up=True):
        self.system = system
        self.status = status
        self.comes_up = comes_up
        self.calls: list[list[str]] = []
        self.dies_on_kill = True

    def __call__(self, argv):
        self.calls.append(list(argv))
        if argv[0] == "openvpn":
            Path(argv[argv.index("--log") + 1]).write_text("one\ntwo\n", encoding="utf-8")
            if self.status == 0:
                Path(argv[argv.index("--writepid") + 1]).write_text(f"{PID}\n")
                self.system.processes[PID] = (START, "openvpn")
                if self.comes_up:
                    self.system.tunnel_found = TUN
            return subprocess.CompletedProcess(argv, self.status)
        if argv[:2] == ["kill", "-TERM"] and self.dies_on_kill:
            self.system.processes.pop(int(argv[2]), None)
            self.system.tunnel_found = None
        return subprocess.CompletedProcess(argv, 0)


@pytest.fixture
def openvpn(session, system):
    system.programs["openvpn"] = "/usr/sbin/openvpn"
    fake = OpenVpn(system)
    session.run_privileged = fake
    return fake


@pytest.fixture
def source(tmp_path):
    folder = tmp_path / "Downloads"
    folder.mkdir()
    path = folder / "lab_user.ovpn"
    path.write_bytes(CONTENT)
    return path


def lines(session):
    return session.console.lines


def running(paths, system, box_name="cascade", box_id="id-other"):
    system.processes[PID] = (START, "openvpn")
    system.tunnel_found = TUN
    write_toml(
        paths.run_vpn / "marker.toml",
        {
            "pid": PID, "start": START, "box_id": box_id, "box_name": box_name,
            "file": "lab_user.ovpn", "sha256": SHA, "started": NOW,
        },
    )  # fmt: skip


# ---- vpn start


def test_start_uses_the_last_file_by_default(session, paths, openvpn, source):
    save_state(paths.state_file, State(last_platform="htb", last_vpn_file=str(source)))
    session.console = FakeConsole([""])
    dispatch(session, "vpn start")
    assert session.console.asked == ["vpn file"]
    assert lines(session) == [
        ("ok", "copied to vpn/lab_user.ovpn"),
        ("ok", "vpn up, 10.10.14.7 on tun0"),
    ]
    assert openvpn.calls[0][:3] == ["openvpn", "--cd", str(source.parent)]
    assert (session.box.path / "vpn" / "lab_user.ovpn").read_bytes() == CONTENT
    assert load_state(paths.state_file) == State(last_platform="htb", last_vpn_file=str(source))
    assert [r.file for r in load_box(session.box.path).vpn] == ["lab_user.ovpn"]


def test_start_expands_home_and_saves_the_original_path(
    session, paths, openvpn, source, monkeypatch
):
    monkeypatch.setenv("HOME", str(source.parent.parent))
    monkeypatch.setenv("USERPROFILE", str(source.parent.parent))
    session.console = FakeConsole(["~/Downloads/lab_user.ovpn"])
    dispatch(session, "vpn start")
    assert ("ok", "vpn up, 10.10.14.7 on tun0") in lines(session)
    assert load_state(paths.state_file).last_vpn_file == str(source)


def test_start_with_no_answer_and_no_default_fails(session, openvpn):
    session.console = FakeConsole([""])
    dispatch(session, "vpn start")
    assert lines(session) == [("fail", "no vpn file given")]
    assert openvpn.calls == []


def test_start_with_a_missing_file_fails_and_copies_nothing(session, openvpn, tmp_path):
    session.console = FakeConsole(["~/nope.ovpn"])
    dispatch(session, "vpn start")
    assert lines(session) == [("fail", "no such file: ~/nope.ovpn")]
    assert openvpn.calls == [] and not (session.box.path / "vpn").exists()


def test_start_without_openvpn_says_how_to_install_it_and_asks_nothing(session, system):
    dispatch(session, "vpn start")
    assert session.console.asked == []
    install = "openvpn is not installed. install it with: apt install openvpn"
    assert lines(session) == [("fail", install)]
    assert system.privileged == []


def test_start_when_ours_is_already_up_uses_it(session, paths, system, openvpn):
    running(paths, system)
    dispatch(session, "vpn start")
    assert session.console.asked == []
    assert lines(session) == [("ok", "vpn already up, 10.10.14.7 on tun0, started for cascade")]
    assert openvpn.calls == []
    assert load_box(session.box.path).vpn == [VpnRecord("lab_user.ovpn", SHA, NOW.replace(hour=13))]
    dispatch(session, "vpn start")
    assert len(load_box(session.box.path).vpn) == 1


def test_start_when_a_tunnel_not_ours_is_up_keeps_it_on_enter(session, system, openvpn):
    system.tunnel_found = TUN
    session.console = FakeConsole([""])
    dispatch(session, "vpn start")
    assert session.console.asked == ["start another?"]
    assert lines(session) == [
        ("warn", "a tunnel is up that pwn-broker did not start: 10.10.14.7 on tun0")
    ]
    assert openvpn.calls == []


def test_start_when_a_tunnel_not_ours_is_up_starts_another_on_yes(session, system, openvpn, source):
    system.tunnel_found = TUN
    openvpn.comes_up = False
    session.console = FakeConsole(["y", str(source)])
    dispatch(session, "vpn start")
    assert session.console.asked == ["start another?", "vpn file"]
    assert openvpn.calls[0][0] == "openvpn"
    # the tunnel that was up before is not the new one
    assert lines(session)[-1] == ("warn", "not up after 15 s; see: vpn log")


def test_start_copies_the_file_once(session, openvpn, source, monkeypatch):
    from pwn_broker import vpnctl

    copies = []
    real = vpnctl.copy_into_box

    def counted(box, path):
        copies.append(path)
        return real(box, path)

    monkeypatch.setattr(vpnctl, "copy_into_box", counted)
    session.console = FakeConsole([str(source)])
    dispatch(session, "vpn start")
    assert copies == [source]
    assert ("ok", "vpn up, 10.10.14.7 on tun0") in lines(session)


def test_start_says_when_the_tunnel_is_not_up_after_15_s(session, system, openvpn, source):
    openvpn.comes_up = False
    session.console = FakeConsole([str(source)])
    dispatch(session, "vpn start")
    assert lines(session)[-1] == ("warn", "not up after 15 s; see: vpn log")
    assert system.sleeps == [0.5] * 30


def test_start_prints_the_log_when_openvpn_fails(session, paths, openvpn, source):
    openvpn.status = 1
    session.console = FakeConsole([str(source)])
    dispatch(session, "vpn start")
    assert lines(session) == [
        ("ok", "copied to vpn/lab_user.ovpn"),
        ("fail", "openvpn exited with status 1"),
        ("raw", "one"),
        ("raw", "two"),
    ]
    assert load_state(paths.state_file).last_vpn_file is None


# ---- vpn stop


def test_stop_stops_ours(session, paths, system, openvpn):
    running(paths, system)
    dispatch(session, "vpn stop")
    assert openvpn.calls == [["kill", "-TERM", str(PID)]]
    assert lines(session) == [("ok", "vpn stopped")]


def test_stop_says_when_it_is_still_running(session, paths, system, openvpn):
    running(paths, system)
    openvpn.dies_on_kill = False
    dispatch(session, "vpn stop")
    assert lines(session) == [("warn", f"openvpn is still running (pid {PID})")]
    assert system.sleeps == [0.5] * 10


def test_stop_never_touches_a_tunnel_it_did_not_start(session, system, openvpn):
    system.tunnel_found = TUN
    dispatch(session, "vpn stop")
    assert lines(session) == [
        ("fail", "this tunnel was not started by pwn-broker; stop it yourself")
    ]
    assert openvpn.calls == []


def test_stop_with_nothing_running(session, openvpn):
    dispatch(session, "vpn stop")
    assert lines(session) == [("fail", "no VPN started by pwn-broker is running")]


def test_stop_never_signals_a_reused_pid(session, paths, system, openvpn):
    running(paths, system)
    system.processes[PID] = ("999", "openvpn")
    dispatch(session, "vpn stop")
    assert lines(session) == [
        ("fail", "this tunnel was not started by pwn-broker; stop it yourself")
    ]
    assert openvpn.calls == []


# ---- vpn status and vpn log


def test_status_of_ours(session, paths, system):
    running(paths, system)
    dispatch(session, "vpn status")
    assert lines(session) == [
        ("info", "state        up"),
        ("info", "address      10.10.14.7 on tun0"),
        ("info", "since        2026-11-14 12:00"),
        ("info", "file         lab_user.ovpn"),
        ("info", "started for  cascade"),
    ]


def test_status_of_ours_before_the_tunnel_comes(session, paths, system):
    running(paths, system)
    system.tunnel_found = None
    dispatch(session, "vpn status")
    assert lines(session)[:2] == [("info", "state        starting"), ("info", "address      -")]


def test_status_of_a_tunnel_not_ours_and_of_none(session, system):
    system.tunnel_found = TUN
    dispatch(session, "vpn status")
    system.tunnel_found = None
    dispatch(session, "vpn status")
    assert lines(session) == [
        ("info", "a tunnel is up that pwn-broker did not start"),
        ("info", "not up"),
    ]


def test_log_prints_the_tail_raw(session, paths):
    dispatch(session, "vpn log")
    paths.run_vpn.mkdir(parents=True)
    (paths.run_vpn / "openvpn.log").write_text("a\tb\nInitialization Sequence Completed\n")
    dispatch(session, "vpn log")
    assert lines(session) == [
        ("info", "no log yet"),
        ("raw", "a\tb"),
        ("raw", "Initialization Sequence Completed"),
    ]


def test_session_seams_cannot_start_signal_or_sleep(session, paths, box):
    from dataclasses import fields

    from pwn_broker.session import load_session

    defaults = {f.name: f.default for f in fields(type(session))}
    built = load_session(paths, session.settings, FakeConsole(), box, lambda: NOW)
    for name in ("run_privileged", "which", "sleep", "pid_alive", "pid_started", "vpn_comm", "play"):
        assert getattr(built, name) is not defaults[name], name
    assert built.which("openvpn") is None and built.pid_alive(1) is False
