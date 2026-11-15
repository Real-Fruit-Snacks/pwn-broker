import pytest

from pwn_broker import lifecycle
from pwn_broker.archive import ArchiveError
from pwn_broker import shell  # noqa: F401  (fills the command registry)
from pwn_broker.config import Settings
from pwn_broker.console import FakeConsole
from pwn_broker.shell.commands import Quit, dispatch


def _archive(session, kind):
    return session.paths.wrapped / f"2026-11-14_htb_forest.{kind}.tar.gz"


def test_export_command_calls_export(session, monkeypatch):
    calls = []
    monkeypatch.setattr(lifecycle, "export_box", lambda s, **kwargs: calls.append(s))
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


def _failing_pack(monkeypatch):
    def pack(box, dest, cut=None):
        raise ArchiveError("disk full")

    monkeypatch.setattr(lifecycle, "pack", pack)


def test_quit_after_failed_export_asks_and_stays_open_by_default(session, monkeypatch):
    _failing_pack(monkeypatch)
    session.console = FakeConsole(["y", ""])
    dispatch(session, "quit")
    assert session.console.asked == ["export forest before you go?", "the export failed. quit anyway?"]
    assert [k for k, _ in session.console.lines] == ["fail"]


def test_quit_after_failed_export_quits_when_confirmed(session, monkeypatch):
    _failing_pack(monkeypatch)
    session.console = FakeConsole(["y", "y"])
    with pytest.raises(Quit):
        dispatch(session, "quit")


def _failing_copy(session, monkeypatch, tmp_path):
    out = tmp_path / "usb"
    out.mkdir()
    session.settings = Settings(copy_to=out)

    def copy_out(archive, copy_to):
        raise ArchiveError(f"cannot copy to {copy_to}: device gone")

    monkeypatch.setattr(lifecycle, "copy_out", copy_out)
    return out


def test_quit_after_failed_copy_asks_and_stays_open_by_default(session, monkeypatch, tmp_path):
    out = _failing_copy(session, monkeypatch, tmp_path)
    session.console = FakeConsole(["y", ""])
    dispatch(session, "quit")
    assert session.console.asked == ["export forest before you go?", "the export failed. quit anyway?"]
    [line] = [t for k, t in session.console.lines if k == "fail"]
    archive = _archive(session, "exported")
    assert archive.exists() and str(archive) in line and str(out) in line and "device gone" in line


def test_quit_after_failed_copy_quits_when_confirmed(session, monkeypatch, tmp_path):
    _failing_copy(session, monkeypatch, tmp_path)
    session.console = FakeConsole(["y", "y"])
    with pytest.raises(Quit):
        dispatch(session, "quit")


def test_export_command_after_failed_copy_is_still_a_warning(session, monkeypatch, tmp_path):
    _failing_copy(session, monkeypatch, tmp_path)
    dispatch(session, "export")
    kinds = [k for k, _ in session.console.lines]
    assert "fail" not in kinds and "warn" in kinds


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


def test_quit_warns_about_windows_still_recording_before_the_question(session, system):
    from casts import recording_now

    recording_now(session, system, "dc01")
    session.console = FakeConsole(["n"])
    with pytest.raises(Quit):
        dispatch(session, "quit")
    assert session.console.lines == [("warn", "1 window is still recording for this box")]
    assert session.console.asked == ["export forest before you go?"]
    recording_now(session, system, "dc01", "2026-11-14_1600", pid=5151)
    session.console = FakeConsole(["n"])
    with pytest.raises(Quit):
        dispatch(session, "quit")
    assert session.console.lines == [("warn", "2 windows are still recording for this box")]


def test_quit_says_nothing_about_recordings_when_none_are_live(session, system):
    from casts import recording_now

    recording_now(session, system, "dc01")
    del system.processes[5150]
    session.console = FakeConsole(["n"])
    with pytest.raises(Quit):
        dispatch(session, "quit")
    assert session.console.lines == []
