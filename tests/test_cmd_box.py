import pytest

from pwn_broker import lifecycle
from pwn_broker import shell  # noqa: F401  (fills the command registry)
from pwn_broker.console import FakeConsole
from pwn_broker.shell.commands import Quit, dispatch


def _archive(session, kind):
    return session.paths.wrapped / f"2026-11-14_htb_forest.{kind}.tar.gz"


def test_export_command_calls_export(session, monkeypatch):
    calls = []
    monkeypatch.setattr(lifecycle, "export_box", lambda s: calls.append(s))
    dispatch(session, "export")
    assert calls == [session]


def test_export_command_writes_archive(session):
    dispatch(session, "export")
    assert _archive(session, "exported").exists()


def test_quit_offers_export_default_yes(session):
    session.console = FakeConsole([""])
    with pytest.raises(Quit):
        dispatch(session, "quit")
    assert session.console.asked == ["export forest before you go?"]
    assert _archive(session, "exported").exists()


def test_quit_declined_exports_nothing(session):
    session.console = FakeConsole(["n"])
    with pytest.raises(Quit):
        dispatch(session, "quit")
    assert not _archive(session, "exported").exists()


def test_quit_quits_even_when_export_fails(session, monkeypatch):
    monkeypatch.setattr(lifecycle, "export_box", lambda s: None)
    session.console = FakeConsole(["y"])
    with pytest.raises(Quit):
        dispatch(session, "quit")


def test_quit_cancelled_at_the_question_stays_open(session, monkeypatch):
    monkeypatch.setattr(lifecycle, "export_box", lambda s: pytest.fail("exported"))
    session.console = FakeConsole([])
    dispatch(session, "quit")
    assert session.console.lines == [("info", "cancelled")]


def test_quit_on_finished_box_does_not_ask(session):
    session.box.status = "finished"
    with pytest.raises(Quit):
        dispatch(session, "quit")
    assert session.console.asked == []


def test_finish_command_quits_after_success(session):
    session.console = FakeConsole(["y", "n"])
    with pytest.raises(Quit):
        dispatch(session, "finish")
    assert _archive(session, "finished").exists()


def test_finish_command_stays_open_when_declined(session):
    session.console = FakeConsole(["n"])
    dispatch(session, "finish")
    assert not _archive(session, "finished").exists()
    assert session.box.status == "active"
