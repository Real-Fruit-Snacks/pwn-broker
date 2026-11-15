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
    assert lifecycle.BLOCK_HOOKS == [kalihooks.recording_block]
    assert lifecycle.PRE_PACK_HOOKS == [kalihooks.recordings_pre_pack]
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


def test_ctrl_c_at_sudo_during_the_hosts_undo_still_asks_the_vpn_and_folder_questions(
    session, system, registered
):
    _vpn_running(session, system)
    box_id = session.box.id
    session.box.hosts = ["dc01"]
    text = "127.0.0.1 localhost\n" + MARKED + box_id + "\n"
    session.hosts_path.write_text(text, encoding="utf-8", newline="")
    session.is_root = lambda: False

    def interrupted(argv):
        raise KeyboardInterrupt

    session.run_privileged = interrupted
    session.console = FakeConsole(["y", "", "n"])
    assert finish_box(session, **SAVED) is not None
    assert session.console.asked == ["finish this box?", QUESTION, "remove working folder?"]
    assert ("warn", "/etc/hosts was not changed: sudo was cancelled") in session.console.lines
    assert session.hosts_path.read_text(encoding="utf-8") == text
    assert session.box.status == "finished"


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
        session.pid_alive = lambda pid: False
        return True

    session.pid_alive = gone_before_the_signal
    session.console = FakeConsole(["y"])
    kalihooks.vpn_question(session)
    assert session.console.lines == [("warn", "no VPN started by pwn-broker is running")]

    _vpn_running(session, system)
    session.pid_alive = system.pid_alive

    def broken(argv):
        raise RuntimeError("sudo is gone")

    session.run_privileged = broken
    session.console = FakeConsole(["y"])
    kalihooks.vpn_question(session)
    assert session.console.lines == [("warn", "could not stop the VPN: sudo is gone")]


# ---- recordings at finish and export


def test_finish_refuses_while_windows_record_and_asks_nothing(session, system, registered):
    from casts import recording_now

    recording_now(session, system, "dc01", pid=5150)
    recording_now(session, system, "web01", "2026-11-14_1510", pid=5151)
    recording_now(session, system, "dc01", "2026-11-14_1600", pid=5152)
    session.console = FakeConsole(["y", "n"])
    assert finish_box(session, **SAVED) is None
    assert session.console.lines == [
        ("fail", "3 windows are still recording (dc01, web01). exit them, then finish again")
    ]
    assert session.console.asked == []
    assert session.box.status == "active"


def test_finish_names_one_window(session, system, registered):
    from casts import recording_now

    recording_now(session, system, "dc01")
    session.console = FakeConsole(["y", "n"])
    assert finish_box(session, **SAVED) is None
    assert session.console.lines == [
        ("fail", "1 window is still recording (dc01). exit it, then finish again")
    ]


def test_a_stale_recording_marker_does_not_block_finish(session, system, registered):
    from casts import recording_now

    cast = recording_now(session, system, "dc01")
    del system.processes[5150]  # the window was killed
    session.console = FakeConsole(["y", "n"])
    assert finish_box(session, **SAVED) is not None
    assert not (session.paths.run_recordings / "5150").exists()
    # the killed window's text copy is written before the archive is made
    assert cast.with_suffix(".txt").exists()


def test_export_warns_about_windows_still_recording_and_writes_their_text(session, system, registered):
    from casts import recording_now

    cast = recording_now(session, system, "dc01")
    assert lifecycle.export_box(session, fix=lambda path: 0) is not None
    assert session.console.lines[0] == (
        "warn", "1 window is still recording; the export holds it up to now"
    )
    assert "14:32:07  hello" in cast.with_suffix(".txt").read_text(encoding="utf-8")
    recording_now(session, system, "dc01", "2026-11-14_1600", pid=5151)
    session.console = FakeConsole()
    lifecycle.export_box(session, fix=lambda path: 0)
    assert session.console.lines[0] == (
        "warn", "2 windows are still recording; the export holds them up to now"
    )


def test_export_without_recordings_says_nothing_about_them(session, registered):
    lifecycle.export_box(session, fix=lambda path: 0)
    assert [k for k, _ in session.console.lines] == ["ok"]


def test_one_bad_cast_does_not_stop_an_export(session, registered):
    folder = session.box.path / "targets/dc01/recordings"
    folder.mkdir(parents=True, exist_ok=True)
    (folder / "2026-11-14_1432.cast").write_bytes(b"broken\n")
    assert lifecycle.export_box(session, fix=lambda path: 0) is not None
    assert [k for k, _ in session.console.lines] == ["warn", "ok"]
