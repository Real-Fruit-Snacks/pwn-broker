from dataclasses import replace

from pwn_broker import targetflow
from pwn_broker.console import FakeConsole
from pwn_broker.ping import Result
from pwn_broker.questions import TargetAnswers
from pwn_broker.store import load_box, load_targets

WEB = TargetAnswers(["10.10.10.50"], ["web.htb"], "external", "web01")


def test_add_makes_the_target_current_then_offers_and_pings(session, system):
    session.console = FakeConsole([""])
    target = targetflow.add(session, WEB, make_current=True)
    assert target.name == "web01" and session.current is target
    assert load_box(session.box.path).last_target == "web01"
    assert [t.name for t in load_targets(session.box)] == ["dc01", "web01"]
    assert "web01" in (session.box.path / "notes.md").read_text(encoding="utf-8")
    assert "10.10.10.50 web.htb" in (session.box.path / "lists" / "hosts.txt").read_text(encoding="utf-8")
    assert session.console.asked == ["add web01's hostnames to /etc/hosts?"]
    assert session.console.lines == [
        ("ok", "target web01 created"),
        ("ok", "/etc/hosts updated"),
        ("info", "    10.10.10.50 web.htb"),
        ("ok", "10.10.10.50 answered in 1 ms"),
    ]
    assert system.pings == ["10.10.10.50"]
    assert load_box(session.box.path).hosts == ["web01"]


def test_add_can_leave_the_current_target_alone(session):
    dc01 = session.current
    session.console = FakeConsole(["n"])
    target = targetflow.add(session, WEB, make_current=False)
    assert session.current is dc01
    assert load_box(session.box.path).last_target is None
    assert target in session.targets


def test_a_target_that_does_not_answer_is_a_warning_and_is_kept(session, system):
    system.answer = Result(False, None, True)
    session.console = FakeConsole(["n"])
    targetflow.add(session, WEB, make_current=True)
    assert session.console.lines[-1] == (
        "warn", "10.10.10.50 did not answer a ping; Windows targets often do not"
    )
    assert [t.name for t in load_targets(session.box)] == ["dc01", "web01"]


def test_a_missing_ping_is_said_once_per_session(session, system):
    system.answer = Result(False, None, False)
    session.console = FakeConsole()
    bare = replace(session.targets[0], hostnames=[])
    targetflow.after_add(session, bare)
    targetflow.after_add(session, bare)
    assert session.console.lines == [("warn", "ping is not installed; the target was not checked")]
    assert system.pings == ["10.10.10.161", "10.10.10.161"]


def test_ctrl_c_during_the_ping_cancels_only_the_ping(session, system):
    system.answer = KeyboardInterrupt()
    session.console = FakeConsole(["n"])
    target = targetflow.add(session, WEB, make_current=True)
    assert session.console.lines[-1] == ("info", "cancelled")
    assert session.current is target


def test_a_target_without_an_ip_is_not_pinged(session, system):
    session.console = FakeConsole(["n"])
    targetflow.add(session, TargetAnswers([], ["web.htb"], "external", "web01"), make_current=True)
    assert system.pings == []
    assert session.console.lines == [("ok", "target web01 created")]


def test_cancelling_the_question_still_pings(session, system):
    session.console = FakeConsole([])
    targetflow.add(session, WEB, make_current=True)
    assert session.box.hosts == []
    assert session.console.lines[1:] == [("info", "cancelled"), ("ok", "10.10.10.50 answered in 1 ms")]


def test_ctrl_c_at_sudo_skips_the_line_and_still_pings(session, system):
    def interrupted(argv):
        raise KeyboardInterrupt

    session.is_root = lambda: False
    session.run_privileged = interrupted
    session.console = FakeConsole(["y"])
    targetflow.add(session, WEB, make_current=True)
    assert session.box.hosts == [] and load_box(session.box.path).hosts == []
    assert ("info", "add this line yourself:") in session.console.lines
    assert session.console.lines[-1] == ("ok", "10.10.10.50 answered in 1 ms")
    assert system.pings == ["10.10.10.50"]


def test_a_record_that_cannot_be_saved_is_a_warning_and_the_ping_still_runs(
    session, system, monkeypatch
):
    from pwn_broker import hostflow
    from pwn_broker.store import StoreError

    def broken(box):
        raise StoreError("box.toml: disk full")

    monkeypatch.setattr(hostflow, "save_box", broken)
    session.console = FakeConsole(["y"])
    targetflow.after_add(session, session.targets[0])
    assert session.box.hosts == []
    # the file is written before the record is saved; a line the box does not record is
    # taken out by its next rewrite, or at finish
    assert session.console.lines == [
        ("ok", "/etc/hosts updated"),
        ("info", "    10.10.10.161 forest.htb.local"),
        ("warn", "the /etc/hosts line could not be recorded: box.toml: disk full"),
        ("ok", "10.10.10.161 answered in 1 ms"),
    ]
