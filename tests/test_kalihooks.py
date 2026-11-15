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
    assert lifecycle.UNDO_HOOKS == [hostflow.undo]
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
