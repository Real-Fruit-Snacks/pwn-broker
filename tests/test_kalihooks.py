import subprocess

import pytest

from pwn_broker import hostflow, kalihooks, lifecycle
from pwn_broker.console import FakeConsole
from pwn_broker.lifecycle import finish_box

SAVED = dict(fix=lambda path: 0, unsaved=lambda box: False)
HOOK_LISTS = ("BLOCK_HOOKS", "SUMMARY_HOOKS", "PRE_PACK_HOOKS", "UNDO_HOOKS", "RESTORE_HOOKS")
MARKED = "10.10.10.161 forest.htb.local  # pwn-broker "


@pytest.fixture
def registered(monkeypatch):
    for name in HOOK_LISTS:
        monkeypatch.setattr(lifecycle, name, [])
    kalihooks.register()


def test_register_adds_each_hook_once(monkeypatch):
    for name in HOOK_LISTS:
        monkeypatch.setattr(lifecycle, name, [])
    kalihooks.register()
    kalihooks.register()
    assert lifecycle.SUMMARY_HOOKS == [hostflow.summary]
    assert lifecycle.UNDO_HOOKS == [hostflow.undo, kalihooks.vpn_question]
    assert lifecycle.RESTORE_HOOKS == []


def test_finish_removes_the_boxes_lines_and_keeps_every_other_line(session, registered):
    box_id = session.box.id
    session.box.hosts = ["dc01"]
    other = "10.10.10.5 cascade.htb  # pwn-broker some-other-box\n"
    session.hosts_path.write_bytes(
        b"127.0.0.1 localhost\r\n"
        + other.encode()
        + (MARKED + box_id + "\n").encode()
        + b"# a comment\n10.0.0.9 plain.example"
    )
    session.console = FakeConsole(["y", "n"])
    assert finish_box(session, **SAVED) is not None
    assert session.hosts_path.read_bytes() == (
        b"127.0.0.1 localhost\r\n" + other.encode() + b"# a comment\n10.0.0.9 plain.example"
    )
    assert ("info", "hosts     1 line to remove from /etc/hosts") in session.console.lines
    assert ("ok", "removed 1 line from /etc/hosts") in session.console.lines
    assert session.box.path.is_dir()


def test_finish_still_finishes_when_the_hosts_file_cannot_be_written(session, registered):
    box_id = session.box.id
    session.box.hosts = ["dc01"]
    text = "127.0.0.1 localhost\n" + MARKED + box_id + "\n"
    session.hosts_path.write_text(text, encoding="utf-8", newline="")
    session.is_root = lambda: False
    session.run_privileged = lambda argv: subprocess.CompletedProcess(argv, 1)
    session.console = FakeConsole(["y", "n"])
    assert finish_box(session, **SAVED) is not None
    assert session.hosts_path.read_text(encoding="utf-8") == text
    assert session.console.asked[-1] == "remove working folder?"
    assert not any("kept" in t for _, t in session.console.lines)
    assert session.box.status == "finished"


# ---- the VPN at finish

PID = 4321
QUESTION = "the VPN is still up (10.10.14.7). stop it?"


def _vpn_running(session, system):
    from pwn_broker.store import write_toml
    from pwn_broker.vpn import Tunnel

    system.processes[PID] = ("123456", "openvpn")
    system.tunnel_found = Tunnel("tun0", "10.10.14.7")
    write_toml(
        session.paths.run_vpn / "marker.toml",
        {
            "pid": PID, "start": "123456", "box_id": session.box.id, "box_name": "forest",
            "file": "lab_user.ovpn", "sha256": "ab" * 32, "started": session.clock(),
        },
    )  # fmt: skip


def _kills(system):
    return [argv for argv in system.privileged if argv[:2] == ["kill", "-TERM"]]


def _kill_works(system):
    def run(argv):
        system.privileged.append(list(argv))
        system.processes.pop(int(argv[2]), None)
        return subprocess.CompletedProcess(argv, 0)

    return run


def test_finish_asks_nothing_about_a_vpn_when_none_of_ours_is_up(session, system, registered):
    from pwn_broker.vpn import Tunnel

    system.tunnel_found = Tunnel("tun0", "10.10.14.7")
    session.console = FakeConsole(["y", "n"])
    assert finish_box(session, **SAVED) is not None
    assert session.console.asked == ["finish this box?", "remove working folder?"]


def test_finish_keeps_the_vpn_on_enter(session, system, registered):
    _vpn_running(session, system)
    session.console = FakeConsole(["y", "", "n"])
    assert finish_box(session, **SAVED) is not None
    assert session.console.asked == ["finish this box?", QUESTION, "remove working folder?"]
    assert _kills(system) == [] and PID in system.processes


def test_finish_stops_the_vpn_on_yes(session, system, registered):
    _vpn_running(session, system)
    session.run_privileged = _kill_works(system)
    session.console = FakeConsole(["y", "y", "n"])
    assert finish_box(session, **SAVED) is not None
    assert _kills(system) == [["kill", "-TERM", str(PID)]]
    assert ("ok", "vpn stopped") in session.console.lines
    assert not any("kept" in text for _, text in session.console.lines)


def test_finish_asks_without_an_address_when_no_tunnel_is_up(session, system, registered):
    _vpn_running(session, system)
    system.tunnel_found = None
    session.console = FakeConsole(["y", "", "n"])
    finish_box(session, **SAVED)
    assert "the VPN is still running. stop it?" in session.console.asked


def test_the_vpn_question_never_raises(session, system, registered):
    _vpn_running(session, system)
    session.console = FakeConsole([])
    kalihooks.vpn_question(session)
    assert session.console.lines == [("warn", "the VPN was left running")]

    def gone_before_the_signal(pid):
        # alive for the question, gone by the time stop checks again
        session.vpn_alive = lambda pid: False
        return True

    session.vpn_alive = gone_before_the_signal
    session.console = FakeConsole(["y"])
    kalihooks.vpn_question(session)
    assert session.console.lines == [("warn", "no VPN started by pwn-broker is running")]

    _vpn_running(session, system)
    session.vpn_alive = system.vpn_alive

    def broken(argv):
        raise RuntimeError("sudo is gone")

    session.run_privileged = broken
    session.console = FakeConsole(["y"])
    kalihooks.vpn_question(session)
    assert session.console.lines == [("warn", "could not stop the VPN: sudo is gone")]
