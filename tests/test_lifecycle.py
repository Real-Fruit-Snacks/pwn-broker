import io
import os
import shutil
import sys
import tarfile
import tomllib
from dataclasses import replace

import pytest
import tomli_w

from helpers import NOW, odd_name
from pwn_broker import lifecycle
from pwn_broker.archive import ArchiveError, archive_path, verify
from pwn_broker.config import Settings
from pwn_broker.console import Cancelled, FakeConsole
from pwn_broker.creds import add_cred
from pwn_broker.lifecycle import export_box, finish_box, import_box, reopen_box
from pwn_broker.model import Flag
from pwn_broker.note import read_note
from pwn_broker.paths import AppPaths
from pwn_broker.session import write_new_note
from pwn_broker.store import StoreError, load_box, load_creds, load_files, load_targets, read_toml, save_box

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
    def boom(*args, **kwargs):
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
    archive = archive_path(session.paths, session.box, "finished")
    assert shown == [
        ("field", "box  forest (htb), started 2026-11-14"),
        ("field", "targets  1"),
        ("field", f"files  {len(load_files(session.box))}"),
        ("field", f"archive  {archive}"),
    ]


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

    def boom(*args, **kwargs):
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
    def boom(*args, **kwargs):
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


def test_loot_with_common_names_survives_export_and_import(session, tmp_path):
    loot = session.box.path / "targets" / "dc01" / "loot"
    names = (".index.php.swp", "config.php~", "backup.tmp", "x.part", "files.toml")
    for name in names:
        (loot / name).write_bytes(f"loot {name}\x00".encode())
    archive = export_box(session, **NOFIX)
    box = import_box(fresh_home(tmp_path), Settings(), FakeConsole(), archive, lambda: NOW)
    for name in names:
        assert (box.path / "targets" / "dc01" / "loot" / name).read_bytes() == (loot / name).read_bytes()


def test_import_of_an_archive_whose_targets_share_a_hostname(session, tmp_path):
    # made before a hostname belonged to one target of a box
    from pwn_broker.store import save_target

    twin = replace(session.targets[0], name="twin", ips=["10.10.10.162"])
    (session.box.path / "targets" / "twin").mkdir()
    save_target(session.box, twin)
    archive = export_box(session, **NOFIX)
    console = FakeConsole()
    box = import_box(fresh_home(tmp_path), Settings(), console, archive, lambda: NOW)
    assert box is not None
    assert [t.hostnames for t in load_targets(box)] == [["forest.htb.local"], ["forest.htb.local"]]
    assert ("ok", "2 targets") in console.lines


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


def record_calls(monkeypatch):
    calls = []

    def wrap(name):
        real = getattr(lifecycle, name)

        def inner(*args, **kwargs):
            if name == "rescan":
                tag = "rescan-hash" if kwargs.get("hash_all") else "rescan"
            elif name == "save_box":
                tag = f"save-{args[0].status}"
            else:
                tag = name
            calls.append(tag)
            return real(*args, **kwargs)

        monkeypatch.setattr(lifecycle, name, inner)

    for name in ("refresh", "rescan", "write_manifest", "pack", "save_box"):
        wrap(name)
    return calls


def fix_recorder(calls):
    return lambda path: calls.append("fix") or 0


def test_export_order(session, monkeypatch):
    calls = record_calls(monkeypatch)
    export_box(session, fix=fix_recorder(calls))
    assert calls == ["fix", "refresh", "rescan-hash", "write_manifest", "pack"]


def test_finish_order(session, monkeypatch):
    calls = record_calls(monkeypatch)
    answers(session, "y", "n")
    finish_box(session, fix=fix_recorder(calls), unsaved=lambda b: False)
    assert calls == [
        "rescan", "fix", "save-finished", "refresh", "rescan-hash", "write_manifest", "pack",
    ]  # fmt: skip


def assert_rolled_back(session):
    box = load_box(session.box.path)
    assert box.status == "active" and box.finished is None
    assert session.box.status == "active" and session.box.finished is None
    assert not archive_path(session.paths, session.box, "finished").exists()
    assert session.box.path.exists()


@pytest.mark.parametrize("exc", [KeyboardInterrupt(), ValueError("bad")])
def test_finish_rolls_back_on_any_exception_and_reraises(session, monkeypatch, exc):
    ran = []
    monkeypatch.setattr(lifecycle, "UNDO_HOOKS", [ran.append])

    def boom(*args, **kwargs):
        raise exc

    monkeypatch.setattr(lifecycle, "pack", boom)
    answers(session, "y")
    with pytest.raises(type(exc)):
        finish_box(session, **SAVED)
    assert_rolled_back(session)
    assert ran == []


def test_finish_rolls_back_when_fix_fails(session):
    def bad_fix(path):
        raise OSError("sudo failed")

    answers(session, "y")
    assert finish_box(session, fix=bad_fix, unsaved=lambda b: False) is None
    assert_rolled_back(session)
    assert len(kinds(session, "fail")) == 1


def test_finish_rolls_back_when_refresh_fails_after_status_save(session, monkeypatch):
    def boom(s):
        raise StoreError("cannot write creds")

    monkeypatch.setattr(lifecycle, "refresh", boom)
    answers(session, "y")
    assert finish_box(session, **SAVED) is None
    assert_rolled_back(session)


def test_finish_rolls_back_when_hashing_rescan_fails(session, monkeypatch):
    real = lifecycle.rescan

    def flaky(s, *, hash_all=False, live=None):
        if hash_all:
            raise OSError("io error")
        return real(s, hash_all=hash_all, live=live)

    monkeypatch.setattr(lifecycle, "rescan", flaky)
    answers(session, "y")
    assert finish_box(session, **SAVED) is None
    assert_rolled_back(session)


def test_finish_copy_failure_names_the_archive(session, tmp_path):
    out = tmp_path / "missing"
    session.settings = Settings(copy_to=out)
    answers(session, "y")
    assert finish_box(session, **SAVED) is None
    line = kinds(session, "fail")[0]
    archive = archive_path(session.paths, session.box, "finished")
    assert str(archive) in line and str(out) in line and "still active" in line
    assert load_box(session.box.path).status == "active"


def test_export_copy_failure_is_a_warning_and_keeps_the_export(session, tmp_path):
    out = tmp_path / "missing"
    session.settings = Settings(copy_to=out)
    path = export_box(session, **NOFIX)
    assert path is not None and path.exists()
    assert kinds(session, "fail") == []
    assert str(path) in kinds(session, "warn")[0] and str(out) in kinds(session, "warn")[0]


def test_strict_export_copy_failure_is_a_fail_and_returns_none(session, tmp_path):
    out = tmp_path / "missing"
    session.settings = Settings(copy_to=out)
    assert export_box(session, strict_copy=True, **NOFIX) is None
    archive = archive_path(session.paths, session.box, "exported")
    [line] = kinds(session, "fail")
    assert archive.exists() and str(archive) in line and str(out) in line
    assert kinds(session, "warn") == []


def pack_leaving_out(monkeypatch, count):
    real = lifecycle.pack
    names = [f"loot/link{i:02}" for i in range(count)]

    def fake(box, dest, cut=None):
        real(box, dest, cut=cut)
        return list(names)

    monkeypatch.setattr(lifecycle, "pack", fake)
    return names


def left_out_lines(session):
    return [t for t in kinds(session, "warn") if "not archived" in t or t.startswith("and ")]


def test_export_reports_what_was_not_archived(session, monkeypatch):
    names = pack_leaving_out(monkeypatch, 3)
    assert export_box(session, **NOFIX) is not None
    assert left_out_lines(session) == [f"{n}   not archived: a link or special file" for n in names]


def test_export_reports_at_most_ten_and_a_count(session, monkeypatch):
    names = pack_leaving_out(monkeypatch, 13)
    export_box(session, **NOFIX)
    lines = left_out_lines(session)
    assert lines[:10] == [f"{n}   not archived: a link or special file" for n in names[:10]]
    assert lines[10:] == ["and 3 more"]


def test_export_with_nothing_left_out_reports_nothing(session):
    export_box(session, **NOFIX)
    assert kinds(session, "warn") == []


def test_finish_warns_before_the_remove_question_when_items_are_not_archived(session, monkeypatch):
    pack_leaving_out(monkeypatch, 12)
    console = answers(session, "y", "n").console
    before_question = []
    original = console.confirm

    def confirm(question, default=False):
        if question == "remove working folder?":
            before_question.extend(console.lines)
        return original(question, default)

    console.confirm = confirm
    assert finish_box(session, **SAVED) is not None
    warns = [t for k, t in before_question if k == "warn"]
    assert len(warns) == 12
    assert warns[10] == "and 2 more"
    assert before_question[-1] == ("warn", "12 items are not in the archive and will be deleted with the folder")


def test_finish_one_item_not_archived_is_singular(session, monkeypatch):
    pack_leaving_out(monkeypatch, 1)
    answers(session, "y", "n")
    finish_box(session, **SAVED)
    assert kinds(session, "warn")[-1] == "1 item is not in the archive and will be deleted with the folder"


def test_finish_with_nothing_left_out_does_not_warn(session):
    answers(session, "y", "n")
    finish_box(session, **SAVED)
    assert kinds(session, "warn") == []


@pytest.mark.skipif(sys.platform == "win32", reason="needs symlinks")
def test_finish_reports_a_real_symlink(session, tmp_path):
    (session.box.path / "targets" / "dc01" / "loot" / "shadow").symlink_to(tmp_path)
    answers(session, "y", "n")
    finish_box(session, **SAVED)
    assert "targets/dc01/loot/shadow   not archived: a link or special file" in kinds(session, "warn")


def test_failing_undo_hook_does_not_stop_the_rest(session, monkeypatch):
    seen = []

    def broken(s):
        raise RuntimeError("nope")

    monkeypatch.setattr(lifecycle, "UNDO_HOOKS", [broken, lambda s: seen.append("second")])
    answers(session, "y", "y")
    path = finish_box(session, **SAVED)
    assert path == archive_path(session.paths, session.box, "finished") and path.exists()
    assert seen == ["second"]
    assert kinds(session, "fail") == ["broken failed: nope"]
    assert "remove working folder?" not in session.console.asked
    [warn] = kinds(session, "warn")
    assert "kept" in warn and "undo step failed" in warn
    assert session.box.path.exists()


def test_interrupt_in_undo_hook_propagates(session, monkeypatch):
    def stop(s):
        raise KeyboardInterrupt

    monkeypatch.setattr(lifecycle, "UNDO_HOOKS", [stop])
    answers(session, "y", "n")
    with pytest.raises(KeyboardInterrupt):
        finish_box(session, **SAVED)


@pytest.mark.skipif(sys.platform == "win32", reason="needs symlinks")
def test_remove_guard_resolves_symlinks(session, tmp_path):
    target = tmp_path / "real"
    target.mkdir()
    link = session.paths.active / "link"
    link.symlink_to(target, target_is_directory=True)
    session.box.path = link
    lifecycle._remove_folder(session)
    assert target.exists() and len(kinds(session, "warn")) == 1


@pytest.mark.skipif(sys.platform == "win32", reason="needs symlinks")
def test_import_asks_when_folder_is_a_dangling_symlink(session, tmp_path):
    archive = export_box(session, **NOFIX)
    paths = fresh_home(tmp_path)
    paths.active.mkdir(parents=True)
    (paths.active / session.box.path.name).symlink_to(tmp_path / "nowhere")
    console = FakeConsole(["n"])
    assert import_box(paths, Settings(), console, archive, lambda: NOW) is None
    assert len(console.asked) == 1


def test_block_hook_reasons_stop_finish_before_anything_else(session, monkeypatch):
    monkeypatch.setattr(lifecycle, "BLOCK_HOOKS", [lambda s: "kerbrute is running", lambda s: None])
    console = answers(session).console
    assert finish_box(session, **SAVED) is None
    assert [t for k, t in console.lines if k == "fail"] == ["kerbrute is running"]
    assert console.asked == [] and not archive_path(session.paths, session.box, "finished").exists()
    assert load_box(session.box.path).status == "active"


def test_block_reasons_and_an_unsaved_note_are_both_reported(session, monkeypatch):
    monkeypatch.setattr(lifecycle, "BLOCK_HOOKS", [lambda s: "a tool is running"])
    answers(session)
    assert finish_box(session, fix=lambda p: 0, unsaved=lambda b: True) is None
    assert len(kinds(session, "fail")) == 2


def test_summary_hook_lines_follow_the_existing_ones_before_the_question(session, monkeypatch):
    monkeypatch.setattr(lifecycle, "SUMMARY_HOOKS", [lambda s: [("extra", "one"), ("", "two")]])
    console = answers(session, "n").console
    shown = []
    original = console.confirm
    console.confirm = lambda q, default=False: shown.extend(console.events) or original(q, default)
    finish_box(session, **SAVED)
    # one list, so the hooks' labels line up with the summary's own
    assert [k for k, _ in shown] == ["field"] * 6
    assert [t for _, t in shown][-2:] == ["extra  one", "  two"]
    assert shown[-3][1].startswith("archive  ")


def test_pre_pack_hooks_run_after_ownership_and_before_refresh(session, monkeypatch):
    calls = record_calls(monkeypatch)
    monkeypatch.setattr(lifecycle, "PRE_PACK_HOOKS", [lambda s: calls.append("hook")])
    export_box(session, fix=fix_recorder(calls))
    assert calls == ["fix", "hook", "refresh", "rescan-hash", "write_manifest", "pack"]
    del calls[:]
    answers(session, "y", "n")
    finish_box(session, fix=fix_recorder(calls), unsaved=lambda b: False)
    assert calls[:3] == ["rescan", "fix", "hook"]
    assert calls.index("hook") < calls.index("refresh")


def test_a_failing_pre_pack_hook_rolls_finish_back_and_stops_export(session, monkeypatch):
    from pwn_broker.toolpkg import ToolError

    def boom(s):
        raise ToolError("the disk is full")

    monkeypatch.setattr(lifecycle, "PRE_PACK_HOOKS", [boom])
    answers(session, "y")
    assert finish_box(session, **SAVED) is None
    assert_rolled_back(session)
    assert export_box(session, **NOFIX) is None
    assert [t for t in kinds(session, "fail")] == [
        "finish failed, the box is still active: the disk is full",
        "export failed: the disk is full",
    ]


# ---- a recording still being written at export


def test_export_packs_a_live_cast_up_to_its_last_whole_line(session, system, monkeypatch):
    from casts import recording_now

    cast = recording_now(session, system, "dc01", events=[(0, "o", "one\r\n"), (1, "o", "two\r\n")])
    cast.write_bytes(cast.read_bytes() + b'[2, "o", "thr')  # a line still being written
    whole = cast.read_bytes()[: cast.read_bytes().rindex(b"\n") + 1]
    rel = "targets/dc01/recordings/2026-11-14_1432.cast"
    real = lifecycle.rescan

    def rescan_then_grow(session, **kwargs):
        records = real(session, **kwargs)
        cast.write_bytes(cast.read_bytes() + b'ee"]\n[3, "o", "four"]\n')
        return records

    monkeypatch.setattr(lifecycle, "rescan", rescan_then_grow)
    path = export_box(session, **NOFIX)
    assert path is not None
    verify(path)
    [row] = [r for r in read_toml(session.box.path / "manifest.toml")["file"] if r["path"] == rel]
    assert row["size"] == len(whole)
    [saved] = [r for r in read_toml(session.box.path / "files.toml")["file"] if r["path"] == rel]
    assert saved["size"] == len(whole) and saved["sha256"] == row["sha256"]
    with tarfile.open(path) as tar:
        assert tar.extractfile(f"2026-11-14_htb_forest/{rel}").read() == whole
    assert cast.stat().st_size > len(whole)


def window(open_now=True, signalled=None):
    """Stand-in for closing the note window: it notes the box and says whether a window is left."""
    signalled = [] if signalled is None else signalled

    def close(paths, box):
        signalled.append(box.path)
        return open_now

    return dict(close=close), signalled


def test_finish_closes_the_note_window_before_removing_the_folder(session):
    stand_in, signalled = window(open_now=False)
    answers(session, "y", "y")
    folder = session.box.path
    seen = []

    def close(paths, box):
        seen.append(folder.exists())
        return False

    assert finish_box(session, **SAVED, close=close) is not None
    assert seen == [True] and not folder.exists()
    assert "the note window did not close" not in kinds(session, "warn")


def test_finish_keeps_the_folder_when_the_window_stays(session):
    stand_in, signalled = window(open_now=True)
    answers(session, "y", "y")
    assert finish_box(session, **SAVED, **stand_in) is not None
    assert signalled == [session.box.path] and session.box.path.exists()
    assert kinds(session, "warn") == ["the note window did not close; the folder was kept"]
    assert not any(text.startswith("removed ") for text in kinds(session, "ok"))


def test_finish_keeps_the_folder_when_the_note_became_unsaved(session):
    stand_in, signalled = window()
    answers(session, "y", "y")
    states = iter([False, True])
    assert finish_box(session, fix=lambda p: 0, unsaved=lambda b: next(states), **stand_in) is not None
    assert session.box.path.exists() and signalled == []
    assert kinds(session, "warn") == ["the note has unsaved changes; the folder was kept"]


def test_finish_leaves_the_window_when_the_folder_is_kept(session):
    stand_in, signalled = window()
    answers(session, "y", "n")
    finish_box(session, **SAVED, **stand_in)
    assert session.box.path.exists() and signalled == []


def test_import_closes_the_window_of_the_box_it_replaces(session):
    archive = export_box(session, **NOFIX)
    stand_in, signalled = window(open_now=False)
    box = import_box(
        session.paths, Settings(), FakeConsole(["y"]), archive, lambda: NOW,
        unsaved=lambda b: False, **stand_in,
    )  # fmt: skip
    assert box is not None and signalled == [session.box.path]


def test_import_with_an_unsaved_note_stops_and_replaces_nothing(session):
    archive = export_box(session, **NOFIX)
    marker = session.box.path / "marker.txt"
    marker.write_text("keep")
    stand_in, signalled = window()
    console = FakeConsole(["y"])
    result = import_box(
        session.paths, Settings(), console, archive, lambda: NOW, unsaved=lambda b: True, **stand_in
    )  # fmt: skip
    assert result is None and marker.read_text() == "keep" and signalled == []
    assert console.lines == [
        ("fail", f"import failed: the note of {session.box.path.name} has unsaved changes; save it and import again")
    ]


def test_import_does_not_close_anything_when_nothing_is_replaced(session, tmp_path):
    archive = export_box(session, **NOFIX)
    stand_in, signalled = window()
    box = import_box(fresh_home(tmp_path), Settings(), FakeConsole(), archive, lambda: NOW, **stand_in)
    assert box is not None and signalled == []


def test_import_declined_closes_nothing(session):
    archive = export_box(session, **NOFIX)
    stand_in, signalled = window()
    assert import_box(session.paths, Settings(), FakeConsole(["n"]), archive, lambda: NOW, **stand_in) is None
    assert signalled == []


def test_finish_keeps_the_folder_and_window_when_the_note_changed_after_the_archive(session):
    stand_in, signalled = window()
    answers(session, "y", "y")
    note = session.box.path / "notes.md"
    write_new_note(session.paths, session.box, session.targets)
    archived = note.read_text()
    console = session.console
    ask = console.confirm

    def confirm(question, default=False):
        if question == "remove working folder?":
            note.write_text(archived + "saved when the window lost focus\n")
        return ask(question, default)

    console.confirm = confirm
    assert finish_box(session, **SAVED, **stand_in) is not None
    assert session.box.path.exists() and note.read_text() == archived + "saved when the window lost focus\n"
    assert signalled == []
    assert kinds(session, "warn") == ["the note changed after the archive was made; the folder was kept"]


def test_finish_keeps_the_folder_when_the_note_cannot_be_read_after_the_archive(session):
    stand_in, signalled = window()
    answers(session, "y", "y")
    note = session.box.path / "notes.md"
    write_new_note(session.paths, session.box, session.targets)
    archived = note.read_text()
    console = session.console
    ask = console.confirm

    def confirm(question, default=False):
        if question == "remove working folder?":
            note.unlink()
        return ask(question, default)

    console.confirm = confirm
    finish_box(session, **SAVED, **stand_in)
    assert session.box.path.exists() and signalled == []
    assert kinds(session, "warn") == ["the note changed after the archive was made; the folder was kept"]


def test_finish_says_so_when_the_signal_could_not_be_sent(session):
    answers(session, "y", "y")
    finish_box(session, **SAVED, close=lambda paths, box: True)
    assert kinds(session, "warn") == ["the note window did not close; the folder was kept"]
    assert session.box.path.exists()


# --- what was written after the archive ---


def at_the_remove_question(session, act):
    ask = session.console.confirm

    def confirm(question, default=False):
        if question == "remove working folder?":
            act()
        return ask(question, default)

    session.console.confirm = confirm


def test_finish_keeps_the_folder_when_a_file_was_made_after_the_archive(session):
    stand_in, signalled = window()
    answers(session, "y", "y")
    new = session.box.path / "targets" / "scan-output.txt"
    at_the_remove_question(session, lambda: new.write_text("found late"))
    path = finish_box(session, **SAVED, **stand_in)
    assert path is not None and new.read_text() == "found late" and signalled == []
    assert kinds(session, "warn") == [
        "targets/scan-output.txt changed after the archive was made; the folder was kept"
    ]
    with tarfile.open(path) as tar:
        assert not any(name.endswith("scan-output.txt") for name in tar.getnames())


def test_finish_keeps_the_folder_when_files_grew_after_the_archive(session):
    stand_in, signalled = window()
    first = session.box.path / "a.txt"
    second = session.box.path / "b.txt"
    first.write_text("one")
    second.write_text("two")
    answers(session, "y", "y")

    def grow():
        first.write_text("one and more")
        second.write_text("two and more")

    at_the_remove_question(session, grow)
    assert finish_box(session, **SAVED, **stand_in) is not None
    assert session.box.path.exists() and signalled == []
    assert kinds(session, "warn") == ["a.txt and 1 more changed after the archive was made; the folder was kept"]


def test_finish_removes_the_folder_though_the_undo_steps_wrote_box_toml(session, monkeypatch):
    def undo(s):
        s.box.extra["undone"] = True
        save_box(s.box)

    monkeypatch.setattr(lifecycle, "UNDO_HOOKS", [undo])
    (session.box.path / "loot.txt").write_text("kept in the archive")
    answers(session, "y", "y")
    assert finish_box(session, **SAVED, close=lambda paths, box: False) is not None
    assert not session.box.path.exists() and kinds(session, "warn") == []


def test_finish_removes_the_folder_when_a_file_only_went_away(session):
    gone = session.box.path / "scratch.txt"
    gone.write_text("x")
    answers(session, "y", "y")
    at_the_remove_question(session, gone.unlink)
    assert finish_box(session, **SAVED, close=lambda paths, box: False) is not None
    assert not session.box.path.exists()


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs named pipes")
def test_a_special_file_made_before_the_archive_does_not_keep_the_folder(session):
    os.mkfifo(session.box.path / "pipe")
    answers(session, "y", "y")
    assert finish_box(session, **SAVED, close=lambda paths, box: False) is not None
    assert not session.box.path.exists()


def test_finish_keeps_the_folder_when_the_box_cannot_be_read_again(session, monkeypatch):
    answers(session, "y", "y")
    real = lifecycle.scan

    looks = []

    def scan(box, records, **options):
        if options.get("limit") == -1:
            looks.append(1)
            # the look before the archive goes through; the one before the removal does not
            if len(looks) == 2:
                raise PermissionError("no")
        return real(box, records, **options)

    monkeypatch.setattr(lifecycle, "scan", scan)
    assert finish_box(session, **SAVED, close=lambda paths, box: False) is not None
    assert session.box.path.exists()
    assert kinds(session, "warn") == [
        "the box could not be read again after the archive was made; the folder was kept"
    ]


# --- import: the box that is there stays until the new one opens ---


def boxless_archive(dest, top, files):
    def add(tar, name, data):
        info = tarfile.TarInfo(name)
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))

    with tarfile.open(dest, "w:gz") as tar:
        folder = tarfile.TarInfo(top)
        folder.type = tarfile.DIRTYPE
        folder.mode = 0o755
        tar.addfile(folder)
        add(tar, f"{top}/manifest.toml", tomli_w.dumps({"schema": 1, "kind": "exported", "file": []}).encode())
        for name, data in files.items():
            add(tar, f"{top}/{name}", data)
    return dest


def test_import_keeps_the_box_it_would_replace_when_the_archive_holds_no_box(session, tmp_path):
    work = session.box.path / "work.txt"
    work.write_text("mine")
    archive = boxless_archive(tmp_path / "x.tar.gz", session.box.path.name, {"readme": b"hello"})
    console = FakeConsole(["y"])
    assert import_box(session.paths, Settings(), console, archive, lambda: NOW) is None
    assert work.read_text() == "mine" and load_box(session.box.path).id == session.box.id
    assert [t for k, t in console.lines if k == "fail"] == [
        "import failed: the box in the archive cannot be opened: cannot read box.toml: "
        + [t for k, t in console.lines if k == "fail"][0].split("cannot read box.toml: ", 1)[1]
    ]
    assert sorted(p.name for p in session.paths.active.iterdir()) == [session.box.path.name]


def test_import_keeps_the_box_it_would_replace_when_a_target_cannot_be_read(session, tmp_path):
    work = session.box.path / "work.txt"
    work.write_text("mine")
    box_toml = (session.box.path / "box.toml").read_bytes()
    archive = boxless_archive(
        tmp_path / "x.tar.gz",
        session.box.path.name,
        {"box.toml": box_toml, "targets/dc01/target.toml": b'schema = 1\nnot_a_field = "x"\n'},
    )
    console = FakeConsole(["y"])
    assert import_box(session.paths, Settings(), console, archive, lambda: NOW) is None
    assert work.read_text() == "mine"
    [line] = [t for k, t in console.lines if k == "fail"]
    assert line.startswith("import failed: the box in the archive cannot be opened: ")
    assert "target.toml" in line and str(session.paths.active) not in line
    assert sorted(p.name for p in session.paths.active.iterdir()) == [session.box.path.name]


def test_import_of_a_new_box_that_cannot_be_opened_leaves_nothing(paths, tmp_path):
    archive = boxless_archive(tmp_path / "x.tar.gz", "2026-11-14_htb_other", {"readme": b"hello"})
    console = FakeConsole()
    assert import_box(paths, Settings(), console, archive, lambda: NOW) is None
    assert [k for k, _ in console.lines] == ["fail"]
    assert not paths.active.exists() or list(paths.active.iterdir()) == []


def test_export_and_finish_go_through_with_a_file_whose_name_is_not_utf8(session):
    if odd_name(session.box.path) is None:
        pytest.skip("no file here can have a name that is not UTF-8")
    assert export_box(session, **NOFIX) is not None
    assert any("its name is not UTF-8, so it is not listed" in line for line in kinds(session, "warn"))
    answers(session, "y", "n")
    archive = finish_box(session, **SAVED)
    assert archive is not None
    with tarfile.open(archive) as tar:
        names = [os.fsencode(name) for name in tar.getnames()]
    assert os.fsencode(session.box.path.name) + b"/caf\xe9 \xff.txt" in names


def renamed_copy(archive, dest, top):
    """The same archive under another top folder: the same box, id and all, by another name."""
    with tarfile.open(archive) as old, tarfile.open(dest, "w:gz") as new:
        for member in old.getmembers():
            first, _, rest = member.name.partition("/")
            member.name = f"{top}/{rest}" if rest else top
            new.addfile(member, old.extractfile(member) if member.isreg() else None)
    return dest


def test_import_refuses_a_box_that_is_already_here_under_another_name(session, tmp_path):
    archive = renamed_copy(export_box(session, **NOFIX), tmp_path / "copy.tar.gz", "2026-11-14_htb_twin")
    console = FakeConsole()
    assert import_box(session.paths, Settings(), console, archive, lambda: NOW) is None
    assert [t for k, t in console.lines if k == "fail"] == [
        f"import failed: this box is already here as {session.box.path.name}, under another folder name"
    ]
    assert sorted(p.name for p in session.paths.active.iterdir()) == [session.box.path.name]


def test_import_over_the_same_box_is_not_taken_for_another(session):
    archive = export_box(session, **NOFIX)
    box = import_box(session.paths, Settings(), FakeConsole(["y"]), archive, lambda: NOW)
    assert box is not None and box.id == session.box.id


def test_import_goes_on_when_another_folder_here_cannot_be_read(session, tmp_path):
    archive = renamed_copy(export_box(session, **NOFIX), tmp_path / "copy.tar.gz", "2026-11-14_htb_twin")
    (session.box.path / "box.toml").write_text("not toml [", encoding="utf-8")
    box = import_box(session.paths, Settings(), FakeConsole(), archive, lambda: NOW)
    assert box is not None and box.path.name == "2026-11-14_htb_twin"


def test_finish_keeps_the_folder_when_a_file_was_rewritten_at_the_same_size(session):
    stand_in, signalled = window()
    loot = session.box.path / "loot.txt"
    loot.write_text("first")
    answers(session, "y", "y")

    def rewrite():
        before = loot.stat()
        loot.write_text("other")
        os.utime(loot, ns=(before.st_atime_ns, before.st_mtime_ns + 2_000_000_000))

    at_the_remove_question(session, rewrite)
    assert finish_box(session, **SAVED, **stand_in) is not None
    assert loot.read_text() == "other" and signalled == []
    assert kinds(session, "warn") == ["loot.txt changed after the archive was made; the folder was kept"]


def test_finish_keeps_the_folder_when_a_new_folder_cannot_be_looked_into(session, monkeypatch):
    stand_in, signalled = window()
    answers(session, "y", "y")
    real = lifecycle.scan
    looks = []

    def scan(box, records, **options):
        found = real(box, records, **options)
        if options.get("limit") == -1:
            looks.append(1)
            if len(looks) == 2:
                options["on_skip"]("targets/locked", "cannot read")
        return found

    monkeypatch.setattr(lifecycle, "scan", scan)
    assert finish_box(session, **SAVED, **stand_in) is not None
    assert session.box.path.exists() and signalled == []
    assert kinds(session, "warn") == ["targets/locked changed after the archive was made; the folder was kept"]


def test_finish_keeps_the_folder_when_a_file_whose_name_is_not_utf8_was_made_after_the_archive(session):
    stand_in, signalled = window()
    answers(session, "y", "y")
    made = []
    at_the_remove_question(session, lambda: made.append(odd_name(session.box.path)))
    assert finish_box(session, **SAVED, **stand_in) is not None
    if made == [None]:
        pytest.skip("no file here can have a name that is not UTF-8")
    assert os.path.exists(made[0]) and signalled == []
    [line] = kinds(session, "warn")
    assert line.endswith(" changed after the archive was made; the folder was kept")


def test_finish_keeps_the_folder_when_a_file_whose_name_is_not_utf8_grew_after_the_archive(session):
    path = odd_name(session.box.path)
    if path is None:
        pytest.skip("no file here can have a name that is not UTF-8")
    stand_in, signalled = window()
    answers(session, "y", "y")

    def grow():
        with open(path, "ab") as fh:
            fh.write(b" and more")

    at_the_remove_question(session, grow)
    assert finish_box(session, **SAVED, **stand_in) is not None
    assert os.path.exists(path) and signalled == []
    assert any(line.endswith("the folder was kept") for line in kinds(session, "warn"))


def test_finish_removes_the_folder_when_a_file_whose_name_is_not_utf8_did_not_change(session):
    if odd_name(session.box.path) is None:
        pytest.skip("no file here can have a name that is not UTF-8")
    answers(session, "y", "y")
    assert finish_box(session, **SAVED, close=lambda paths, box: False) is not None
    assert not session.box.path.exists()
