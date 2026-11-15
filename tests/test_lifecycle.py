import shutil
import tarfile
import tomllib
from dataclasses import replace

import pytest

from helpers import NOW
from pwn_broker import lifecycle
from pwn_broker.archive import ArchiveError, archive_path, verify
from pwn_broker.config import Settings
from pwn_broker.console import Cancelled, FakeConsole
from pwn_broker.creds import add_cred
from pwn_broker.lifecycle import export_box, finish_box, import_box, reopen_box
from pwn_broker.model import Flag
from pwn_broker.note import read_note
from pwn_broker.paths import AppPaths
from pwn_broker.store import load_box, load_creds, load_targets, read_toml, save_box

NOFIX = dict(fix=lambda path: 0)
SAVED = dict(fix=lambda path: 0, unsaved=lambda box: False)


def answers(session, *values):
    session.console = FakeConsole(list(values))
    return session


def kinds(session, kind):
    return [t for k, t in session.console.lines if k == kind]


def test_export_leaves_box_active(session):
    path = export_box(session, **NOFIX)
    assert path == session.paths.wrapped / "2026-11-14_htb_forest.exported.tar.gz" and path.exists()
    assert load_box(session.box.path).status == "active"
    assert read_toml(session.box.path / "manifest.toml")["kind"] == "exported"
    verify(path)
    assert str(path) in kinds(session, "ok")[0]


def test_export_fixes_ownership_first(session):
    order = []
    export_box(session, fix=lambda p: order.append(p) or 0)
    assert order == [session.box.path]


def test_export_replaces_previous_export_without_asking(session):
    first = export_box(session, **NOFIX)
    second = export_box(session, **NOFIX)
    assert first == second
    assert len(list(session.paths.wrapped.iterdir())) == 1
    assert session.console.asked == []


def test_export_copies_to_copy_to(session, tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    session.settings = Settings(copy_to=out)
    path = export_box(session, **NOFIX)
    assert (out / path.name).read_bytes() == path.read_bytes()
    assert len(kinds(session, "ok")) == 2


def test_export_failure_reports_and_returns_none(session, monkeypatch):
    def boom(*args):
        raise ArchiveError("disk full")

    monkeypatch.setattr(lifecycle, "pack", boom)
    assert export_box(session, **NOFIX) is None
    assert len(kinds(session, "fail")) == 1 and kinds(session, "ok") == []


def test_finish_declined_changes_nothing(session):
    answers(session, "n")
    assert finish_box(session, **SAVED) is None
    assert not archive_path(session.paths, session.box, "finished").exists()
    assert load_box(session.box.path).status == "active"


def test_finish_shows_summary_before_asking(session):
    console = answers(session, "n").console
    shown = []
    original = console.confirm
    console.confirm = lambda q, default=False: shown.extend(console.lines) or original(q, default)
    finish_box(session, **SAVED)
    text = "\n".join(t for k, t in shown if k == "info")
    assert "forest (htb), started 2026-11-14" in text
    assert "targets   1" in text
    assert "files     " in text
    assert str(archive_path(session.paths, session.box, "finished")) in text


def test_finish_happy_path(session):
    answers(session, "y", "n")
    path = finish_box(session, **SAVED)
    assert path == archive_path(session.paths, session.box, "finished") and path.exists()
    verify(path)
    box = load_box(session.box.path)
    assert box.status == "finished" and box.finished == session.clock()
    assert session.box.path.exists()


def test_finished_archive_holds_the_finished_box_toml(session):
    answers(session, "y", "n")
    path = finish_box(session, **SAVED)
    verify(path)
    with tarfile.open(path, "r:gz") as tar:
        data = tomllib.loads(tar.extractfile(f"{session.box.path.name}/box.toml").read().decode())
    assert data["status"] == "finished"


def test_finish_removes_folder_only_on_yes(session):
    answers(session, "y", "y")
    path = finish_box(session, **SAVED)
    assert path.exists() and not session.box.path.exists()


def test_finish_cancel_at_remove_question_counts_as_no(session):
    answers(session, "y")
    path = finish_box(session, **SAVED)
    assert path.exists() and session.box.path.exists()


def test_finish_cancel_before_work_propagates(session):
    answers(session)
    with pytest.raises(Cancelled):
        finish_box(session, **SAVED)
    assert load_box(session.box.path).status == "active"


def test_finish_stops_on_unsaved_note(session):
    answers(session)
    assert finish_box(session, fix=lambda p: 0, unsaved=lambda b: True) is None
    assert not archive_path(session.paths, session.box, "finished").exists()
    assert load_box(session.box.path).status == "active"
    assert session.console.asked == []
    assert len(kinds(session, "fail")) == 1 and ":w" in kinds(session, "fail")[0]


def test_finish_asks_before_replacing_an_archive(session):
    existing = archive_path(session.paths, session.box, "finished")
    existing.parent.mkdir(parents=True)
    existing.write_bytes(b"old")
    answers(session, "y", "n")
    assert finish_box(session, **SAVED) is None
    assert session.console.asked[-1] == "replace the existing archive?"
    assert existing.read_bytes() == b"old"
    assert load_box(session.box.path).status == "active"


def test_finish_replaces_an_archive_when_told_to(session):
    existing = archive_path(session.paths, session.box, "finished")
    existing.parent.mkdir(parents=True)
    existing.write_bytes(b"old")
    answers(session, "y", "y", "n")
    assert finish_box(session, **SAVED) == existing
    verify(existing)


def test_finish_failure_rolls_back(session, monkeypatch, tmp_path):
    out = tmp_path / "out"
    out.mkdir()
    session.settings = Settings(copy_to=out)
    ran = []
    monkeypatch.setattr(lifecycle, "UNDO_HOOKS", [ran.append])

    def boom(*args):
        raise ArchiveError("copy failed")

    monkeypatch.setattr(lifecycle, "copy_out", boom)
    answers(session, "y")
    assert finish_box(session, **SAVED) is None
    box = load_box(session.box.path)
    assert box.status == "active" and box.finished is None
    assert session.box.status == "active" and session.box.finished is None
    assert ran == [] and session.box.path.exists()
    assert len(kinds(session, "fail")) == 1
    assert session.console.asked == ["finish this box?"]


def test_finish_failure_still_reports_when_rollback_save_fails(session, monkeypatch):
    def boom(*args):
        raise ArchiveError("cannot pack")

    monkeypatch.setattr(lifecycle, "pack", boom)
    calls = []

    def flaky_save(box):
        calls.append(box.status)
        if box.status == "active":
            raise OSError("read-only")
        save_box(box)

    monkeypatch.setattr(lifecycle, "save_box", flaky_save)
    answers(session, "y")
    assert finish_box(session, **SAVED) is None
    assert calls == ["finished", "active"]
    assert "cannot pack" in kinds(session, "fail")[0]


def test_finish_runs_undo_hooks_after_archive(session, monkeypatch):
    seen = []
    path = archive_path(session.paths, session.box, "finished")
    monkeypatch.setattr(
        lifecycle,
        "UNDO_HOOKS",
        [lambda s: seen.append(("a", path.exists())), lambda s: seen.append(("b", s))],
    )
    answers(session, "y", "n")
    finish_box(session, **SAVED)
    assert seen == [("a", True), ("b", session)]


def test_finish_refuses_to_delete_outside_active(session, tmp_path):
    outside = tmp_path / "elsewhere" / session.box.path.name
    outside.parent.mkdir()
    shutil.move(session.box.path, outside)
    session.box.path = outside
    answers(session, "y", "y")
    path = finish_box(session, **SAVED)
    assert path.exists() and outside.exists()
    assert len(kinds(session, "warn")) == 1


def test_finish_refuses_to_delete_active_itself(session):
    session.box.path = session.paths.active
    lifecycle._remove_folder(session)
    assert session.paths.active.exists() and len(kinds(session, "warn")) == 1


def populate(session):
    add_cred(
        session.creds, username="svc", domain="HTB", secret="pw", kind="password",
        found_on="forest", note="n", now=NOW,
    )  # fmt: skip
    session.box.flags["user"] = Flag("abc", NOW)
    session.box.last_target = "dc01"
    save_box(session.box)
    (session.box.path / "targets" / "dc01" / "loot" / "x.txt").write_text("loot")


def fresh_home(tmp_path):
    return AppPaths(opt=tmp_path / "opt2", home=tmp_path / "home2")


def test_import_round_trip(session, tmp_path):
    populate(session)
    archive = export_box(session, **NOFIX)
    paths = fresh_home(tmp_path)
    console = FakeConsole()
    box = import_box(paths, Settings(), console, archive, lambda: NOW)
    assert box.path == paths.active / session.box.path.name
    original = load_box(session.box.path)
    assert replace(box, path=original.path) == original
    assert box.flags == {"user": Flag("abc", NOW)} and box.last_target == "dc01"
    assert load_targets(box) == session.targets
    assert load_creds(box) == session.creds
    assert read_note(box) == read_note(session.box)
    assert (box.path / "targets" / "dc01" / "loot" / "x.txt").read_text() == "loot"
    assert [t for k, t in console.lines if k == "ok"] == [f"unpacked to {box.path}", "1 targets"]


def test_import_of_finished_archive_reopens(session, tmp_path):
    answers(session, "y", "n")
    archive = finish_box(session, **SAVED)
    box = import_box(fresh_home(tmp_path), Settings(), FakeConsole(), archive, lambda: NOW)
    assert box.status == "active" and box.finished is None
    assert load_box(box.path).status == "active"


def test_import_runs_restore_hooks(session, tmp_path, monkeypatch):
    seen = []
    monkeypatch.setattr(lifecycle, "RESTORE_HOOKS", [lambda s: seen.append(s.box.path)])
    archive = export_box(session, **NOFIX)
    box = import_box(fresh_home(tmp_path), Settings(), FakeConsole(), archive, lambda: NOW)
    assert seen == [box.path]


def test_import_asks_when_folder_exists(session):
    archive = export_box(session, **NOFIX)
    marker = session.box.path / "marker.txt"
    marker.write_text("keep")
    console = FakeConsole(["n"])
    assert import_box(session.paths, Settings(), console, archive, lambda: NOW) is None
    assert marker.read_text() == "keep"
    assert console.asked == ["a box named 2026-11-14_htb_forest is already here. replace it?"]


def test_import_replaces_when_told_to(session):
    archive = export_box(session, **NOFIX)
    marker = session.box.path / "marker.txt"
    marker.write_text("gone")
    box = import_box(session.paths, Settings(), FakeConsole(["y"]), archive, lambda: NOW)
    assert box is not None and not marker.exists()


def test_import_bad_archive_reports_and_returns_none(paths, tmp_path):
    bad = tmp_path / "bad.tar.gz"
    bad.write_bytes(b"not an archive")
    console = FakeConsole()
    assert import_box(paths, Settings(), console, bad, lambda: NOW) is None
    assert [k for k, _ in console.lines] == ["fail"]
    assert not paths.active.exists() or list(paths.active.iterdir()) == []


def test_reopen_box(box):
    box.status = "finished"
    box.finished = NOW
    reopen_box(box)
    loaded = load_box(box.path)
    assert loaded.status == "active" and loaded.finished is None
