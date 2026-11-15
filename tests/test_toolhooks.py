import os
import shutil
import sys
import tarfile
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

import toolkit
from helpers import NOW
from pwn_broker import lifecycle, toolhooks, toolindex, toolinstall, toolstate
from pwn_broker.archive import archive_path
from pwn_broker.console import FakeConsole
from pwn_broker.lifecycle import export_box, finish_box, import_box
from pwn_broker.model import ToolRecord, current_tools
from pwn_broker.paths import AppPaths
from pwn_broker.store import load_box, save_box
from pwn_broker.toolpkg import ToolError, machine_arch
from pwn_broker.toolstate import load_installed

SAVED = dict(fix=lambda path: 0, unsaved=lambda box: False)
HOOK_LISTS = ("BLOCK_HOOKS", "SUMMARY_HOOKS", "PRE_PACK_HOOKS", "UNDO_HOOKS", "RESTORE_HOOKS")


@pytest.fixture
def registered(monkeypatch):
    for name in HOOK_LISTS:
        monkeypatch.setattr(lifecycle, name, [])
    toolhooks.register()


@pytest.fixture
def user(tmp_path, monkeypatch):
    home = tmp_path / "user"
    home.mkdir()
    monkeypatch.setattr(toolhooks, "user_home", lambda: home)
    monkeypatch.setattr(toolhooks.tooldata, "homes", lambda h, **k: [h])
    monkeypatch.setattr(toolhooks.tooldata, "root_unchecked", lambda h, **k: False)
    return home


@pytest.fixture
def shop(tmp_path):
    zip_path, entry = toolkit.make_entry(tmp_path / "pkg", {"data": {"home": [".kerb", ".old"]}})
    toolkit.write_index(tmp_path / "index", [entry])
    (tmp_path / "index" / entry.file).write_bytes(zip_path.read_bytes())
    return SimpleNamespace(zip=zip_path, entry=entry, folder=tmp_path / "index")


@pytest.fixture
def tooled(session, shop, user, registered):
    # kerbrute installed for the box; ~/.old existed before the install, ~/.kerb did not
    (user / ".old").write_text("before")
    session.settings = replace(session.settings, tools_index=str(shop.folder))
    toolinstall.install(
        session.paths, session.box, shop.entry, shop.zip,
        installed={}, unfinished={session.box.id: session.box.name},
        home=user, console=FakeConsole(), now=NOW, on_path=lambda n: None,
    )  # fmt: skip
    (user / ".kerb").mkdir()
    (user / ".kerb" / "found.txt").write_text("result")
    return session


def say(session, *answers):
    session.console = FakeConsole(list(answers))
    return session


def lines(session, kind):
    return [t for k, t in session.console.lines if k == kind]


def mark(session, pid=4321, text="55"):
    path = toolstate.mark_path(session.paths, "kerbrute", pid)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text + "\n")
    return path


def record(sha="ab" * 32, version="1.0.3", build=1):
    return ToolRecord("kerbrute", version, build, sha, NOW)


def wipe(session):
    item = load_installed(session.paths)["kerbrute"]
    toolinstall.remove_files(session.paths, item)
    toolstate.save_installed(session.paths, {})


def archive_names(path):
    with tarfile.open(path) as tar:
        return tar.getnames()


def fresh_paths(tooled, tmp_path):
    return AppPaths(opt=tooled.paths.opt, home=tmp_path / "fresh-home")


# ---- register


def test_register_appends_once_after_existing_hooks(monkeypatch):
    other = lambda s: None  # noqa: E731
    for name in HOOK_LISTS:
        monkeypatch.setattr(lifecycle, name, [other])
    toolhooks.register()
    toolhooks.register()
    assert lifecycle.BLOCK_HOOKS == [other, toolhooks.block]
    assert lifecycle.SUMMARY_HOOKS == [other, toolhooks.summary]
    assert lifecycle.PRE_PACK_HOOKS == [other, toolhooks.pre_pack]
    assert lifecycle.UNDO_HOOKS == [other, toolhooks.undo]
    assert lifecycle.RESTORE_HOOKS == [other, toolhooks.restore]


# ---- block


def test_block_names_a_running_tool(tooled):
    mark(tooled)
    reason = toolhooks.block(tooled, alive=lambda pid: True, started=lambda pid: None)
    assert "kerbrute" in reason and "4321" in reason
    assert str(toolstate.mark_path(tooled.paths, "kerbrute", 4321)) in reason


def test_block_is_none_without_a_running_tool(tooled):
    assert toolhooks.block(tooled) is None


def test_block_ignores_tools_the_box_does_not_use(session):
    path = toolstate.mark_path(session.paths, "nmap", 4321)
    path.parent.mkdir(parents=True)
    path.write_text("55\n")
    assert toolhooks.block(session, alive=lambda pid: True) is None


def test_stale_markers_do_not_block_and_are_removed(tooled):
    dead = mark(tooled, 4321)
    reused = mark(tooled, 4322, text="55")
    assert toolhooks.block(tooled, alive=lambda pid: pid == 4322, started=lambda pid: "99") is None
    assert not dead.exists() and not reused.exists()


def test_stale_run_box_file_and_dead_marker_do_not_block_finish(tooled):
    toolstate.write_open_box(tooled.paths, tooled.box.path, 4321)
    marker = mark(tooled)
    say(tooled, "y", "n")
    stale = mark(tooled, 4322, text="99")
    assert toolhooks.block(tooled) is None
    assert finish_box(tooled, **SAVED) is not None
    assert not lines(tooled, "fail")
    assert not marker.exists() and not stale.exists()


# ---- summary


def test_summary_is_empty_for_a_box_without_tools(session, registered):
    assert toolhooks.summary(session) == []


def test_summary_lists_tools_and_home_paths(tooled, user):
    assert toolhooks.summary(tooled) == [
        "tools     kerbrute 1.0.3   (will be removed)",
        f"home      {user / '.kerb'}   (will be deleted)",
    ]


def test_summary_lists_no_home_path_another_box_still_uses(tooled, other):
    item = load_installed(tooled.paths)["kerbrute"]
    item.users.append(other.id)
    toolstate.save_installed(tooled.paths, {"kerbrute": item})
    assert toolhooks.summary(tooled) == ["tools     kerbrute 1.0.3   (will be removed)"]


# ---- pre_pack


def test_pre_pack_copies_tool_data_into_the_box(tooled):
    toolhooks.pre_pack(tooled)
    data = tooled.box.path / "tooldata" / "kerbrute" / "home"
    assert (data / ".kerb" / "found.txt").read_text() == "result"
    assert not (data / ".old").exists()


def test_pre_pack_lets_a_tool_error_out_unchanged(tooled, monkeypatch):
    def boom(*a):
        raise ToolError("the disk is full")

    monkeypatch.setattr(toolhooks.tooldata, "collect", boom)
    with pytest.raises(ToolError, match="^the disk is full$"):
        toolhooks.pre_pack(tooled)


def test_pre_pack_names_the_tool_for_any_other_os_error(tooled, monkeypatch):
    def boom(*a):
        raise PermissionError("denied")

    monkeypatch.setattr(toolhooks.tooldata, "collect", boom)
    with pytest.raises(ToolError, match="kerbrute.*denied"):
        toolhooks.pre_pack(tooled)


def test_pre_pack_skips_a_tool_that_is_not_installed(session, registered, user):
    session.box.tools = [record()]
    toolhooks.pre_pack(session)
    assert not (session.box.path / "tooldata").exists()


# ---- undo


def test_undo_releases_the_tool_and_deletes_new_home_paths(tooled, user):
    toolhooks.pre_pack(tooled)
    toolhooks.undo(tooled)
    assert load_installed(tooled.paths) == {}
    assert not (user / ".kerb").exists()
    assert (user / ".old").read_text() == "before"
    assert [t.name for t in load_box(tooled.box.path).tools] == ["kerbrute"]
    assert any(".old" in t for t in lines(tooled, "warn"))


def test_undo_frees_the_tool_even_when_the_box_still_reads_active(tooled):
    assert tooled.box.status == "active"
    toolhooks.undo(tooled)
    assert load_installed(tooled.paths) == {}


def test_undo_leaves_a_tool_and_its_data_to_another_unfinished_box(tooled, other, user):
    item = load_installed(tooled.paths)["kerbrute"]
    item.users.append(other.id)
    toolstate.save_installed(tooled.paths, {"kerbrute": item})
    toolhooks.undo(tooled)
    assert load_installed(tooled.paths)["kerbrute"].users == [other.id]
    assert (user / ".kerb").exists()


def test_undo_tries_every_tool_then_raises(tooled, shop, user, monkeypatch):
    other_command = [{"name": "other-tool", "type": "binary", "path": "files/kerbrute"}]
    zip2, entry2 = toolkit.make_entry(
        shop.folder.parent / "pkg2", {"name": "other-tool", "command": other_command}
    )
    toolinstall.install(
        tooled.paths, tooled.box, entry2, zip2,
        installed=load_installed(tooled.paths), unfinished={tooled.box.id: "forest"},
        home=user, console=FakeConsole(), now=NOW, on_path=lambda n: None,
    )  # fmt: skip
    real = toolinstall.release
    tried = []

    def release(paths, box, name, **kw):
        tried.append(name)
        if name == "kerbrute":
            raise ToolError("cannot remove it")
        return real(paths, box, name, **kw)

    monkeypatch.setattr(toolhooks.toolinstall, "release", release)
    with pytest.raises(ToolError, match="kerbrute.*cannot remove it"):
        toolhooks.undo(tooled)
    assert sorted(tried) == ["kerbrute", "other-tool"]
    assert "other-tool" not in load_installed(tooled.paths)


# ---- restore


def test_restore_installs_the_recorded_build_on_yes(tooled):
    wipe(tooled)
    say(tooled, "y")
    toolhooks.restore(tooled)
    assert tooled.console.asked == ["install these tools again?"]
    assert tooled.box.id in load_installed(tooled.paths)["kerbrute"].users
    assert any("kerbrute 1.0.3" in t for t in lines(tooled, "info"))


def test_restore_does_nothing_on_no(tooled):
    wipe(tooled)
    say(tooled, "n")
    toolhooks.restore(tooled)
    assert load_installed(tooled.paths) == {}


def test_restore_is_silent_when_the_tools_are_installed(tooled):
    say(tooled)
    toolhooks.restore(tooled)
    assert tooled.console.asked == [] and tooled.console.lines == []


def test_restore_offers_a_tool_installed_for_other_boxes_only(tooled, other):
    item = load_installed(tooled.paths)["kerbrute"]
    item.users = [other.id]
    toolstate.save_installed(tooled.paths, {"kerbrute": item})
    say(tooled, "y")
    toolhooks.restore(tooled)
    assert sorted(load_installed(tooled.paths)["kerbrute"].users) == sorted([other.id, tooled.box.id])


def test_restore_warns_for_a_build_the_index_does_not_list(tooled):
    wipe(tooled)
    tooled.box.tools = [record(version="9.9")]
    say(tooled, "y")
    toolhooks.restore(tooled)
    assert any("kerbrute 9.9" in t and "index" in t for t in lines(tooled, "warn"))
    assert load_installed(tooled.paths) == {}


def test_restore_skips_a_build_whose_sha256_changed(tooled):
    wipe(tooled)
    tooled.box.tools = [record(sha="cd" * 32)]
    say(tooled, "y")
    toolhooks.restore(tooled)
    assert any("SHA-256" in t for t in lines(tooled, "warn"))
    assert load_installed(tooled.paths) == {}


def test_restore_carries_on_after_a_tool_error(tooled, monkeypatch):
    def boom(*a, **k):
        raise ToolError("no network")

    wipe(tooled)
    monkeypatch.setattr(toolhooks.toolindex, "fetch_zip", boom)
    say(tooled, "y")
    toolhooks.restore(tooled)
    assert any("no network" in t for t in lines(tooled, "warn"))


def test_restore_warns_once_when_the_index_cannot_be_loaded(tooled, tmp_path):
    wipe(tooled)
    tooled.settings = replace(tooled.settings, tools_index=str(tmp_path / "nowhere"))
    say(tooled, "y")
    toolhooks.restore(tooled)
    assert len(lines(tooled, "warn")) == 1 and not lines(tooled, "fail")


def test_restore_never_raises(tooled, monkeypatch):
    def boom(paths):
        raise RuntimeError("odd")

    wipe(tooled)
    monkeypatch.setattr(toolhooks, "load_installed", boom)
    toolhooks.restore(tooled)
    assert lines(tooled, "warn")


def test_restore_treats_a_cancelled_question_as_no(tooled):
    wipe(tooled)
    say(tooled)
    toolhooks.restore(tooled)
    assert load_installed(tooled.paths) == {}


# ---- leftovers


def finish_without_undo(tooled):
    tooled.box.status = "finished"
    tooled.box.finished = NOW
    save_box(tooled.box)


def test_leftovers_are_offered_and_removed_on_yes(tooled):
    finish_without_undo(tooled)
    console = FakeConsole(["y"])
    toolhooks.leftovers(tooled.paths, console)
    assert console.asked == ["remove tools left by finished boxes?"]
    assert load_installed(tooled.paths) == {}
    assert not (tooled.paths.tools / "kerbrute").exists()


def test_leftovers_stay_on_no(tooled):
    finish_without_undo(tooled)
    toolhooks.leftovers(tooled.paths, FakeConsole(["n"]))
    assert "kerbrute" in load_installed(tooled.paths)


def test_leftovers_are_not_offered_while_an_unfinished_box_uses_the_tool(tooled):
    console = FakeConsole()
    toolhooks.leftovers(tooled.paths, console)
    assert console.asked == [] and console.lines == []


def test_leftovers_count_a_missing_box_as_finished(tooled):
    item = load_installed(tooled.paths)["kerbrute"]
    item.users = ["no-such-box"]
    toolstate.save_installed(tooled.paths, {"kerbrute": item})
    toolhooks.leftovers(tooled.paths, FakeConsole(["y"]))
    assert load_installed(tooled.paths) == {}


def test_leftovers_do_nothing_without_installed_tools(paths):
    console = FakeConsole()
    toolhooks.leftovers(paths, console)
    assert console.asked == [] and console.lines == []


def test_leftovers_never_take_a_runtime_for_an_unused_tool_or_a_stray(paths, tmp_path):
    zip_path, entry = toolkit.make_runtime(tmp_path / "rtzips")
    installed = {}
    toolinstall.install_runtime(paths, entry, zip_path, installed=installed, console=FakeConsole())
    console = FakeConsole(["n", "y"])
    toolhooks.leftovers(paths, console)
    # offered once, as a runtime
    assert console.asked == [RUNTIME_QUESTION]
    assert console.lines == [("info", "runtimes  python-3.13 3.13.18")]
    assert list(load_installed(paths)) == ["python-3.13"]
    assert (paths.tools / "python-3.13" / "3.13.18-1").is_dir()


def test_leftovers_survive_a_cancelled_question_and_a_bad_state_file(tooled):
    finish_without_undo(tooled)
    toolhooks.leftovers(tooled.paths, FakeConsole())
    assert "kerbrute" in load_installed(tooled.paths)
    tooled.paths.tools_state.write_text("not toml [", encoding="utf-8")
    console = FakeConsole()
    toolhooks.leftovers(tooled.paths, console)
    assert [k for k, _ in console.lines] == ["warn"]


def test_leftovers_warn_and_keep_the_entry_when_removal_fails(tooled, monkeypatch):
    def boom(paths, item):
        raise ToolError("stuck")

    finish_without_undo(tooled)
    monkeypatch.setattr(toolhooks.toolinstall, "remove_files", boom)
    console = FakeConsole(["y"])
    toolhooks.leftovers(tooled.paths, console)
    assert ("warn", "kerbrute   stuck") in console.lines
    assert "kerbrute" in load_installed(tooled.paths)


# ---- finish and export end to end


def test_finish_end_to_end(tooled, user):
    shown = []
    say(tooled, "y", "n")
    original = tooled.console.confirm
    tooled.console.confirm = lambda q, default=False: (
        shown.extend(tooled.console.lines) or original(q, default)
    )
    path = finish_box(tooled, **SAVED)
    assert path is not None and path.exists()
    before_question = [t for k, t in shown if k == "info"]
    assert "tools     kerbrute 1.0.3   (will be removed)" in before_question
    assert f"home      {user / '.kerb'}   (will be deleted)" in before_question
    assert any(n.endswith("tooldata/kerbrute/home/.kerb/found.txt") for n in archive_names(path))
    assert load_installed(tooled.paths) == {}
    assert not (user / ".kerb").exists() and (user / ".old").exists()
    assert any(".old" in t for t in lines(tooled, "warn"))
    assert load_box(tooled.box.path).status == "finished"


def test_finish_is_stopped_by_a_running_tool(tooled, monkeypatch):
    mark(tooled)
    monkeypatch.setattr(toolstate, "_resolve_alive", lambda alive: lambda pid: True)
    monkeypatch.setattr(toolstate, "process_start", lambda pid: None)
    say(tooled)
    assert finish_box(tooled, **SAVED) is None
    assert any("kerbrute" in t for t in lines(tooled, "fail"))
    assert tooled.console.asked == []
    assert "kerbrute" in load_installed(tooled.paths)
    assert load_box(tooled.box.path).status == "active"


def test_a_failing_undo_keeps_the_folder_and_the_box_stays_finished(tooled, monkeypatch):
    def boom(*a, **k):
        raise ToolError("cannot remove it")

    monkeypatch.setattr(toolhooks.toolinstall, "release", boom)
    say(tooled, "y")
    path = finish_box(tooled, **SAVED)
    assert path is not None and path.exists()
    assert tooled.box.path.exists()
    assert load_box(tooled.box.path).status == "finished"
    assert any("cannot remove it" in t for t in lines(tooled, "fail"))
    assert any("kept" in t for t in lines(tooled, "warn"))
    assert tooled.console.asked == ["finish this box?"]


@pytest.mark.parametrize("error", [ToolError("the disk is full"), PermissionError("denied")])
def test_finish_rolls_back_when_collecting_fails(tooled, user, monkeypatch, error):
    def boom(*a):
        raise error

    monkeypatch.setattr(toolhooks.tooldata, "collect", boom)
    say(tooled, "y")
    assert finish_box(tooled, **SAVED) is None
    failed = lines(tooled, "fail")
    assert len(failed) == 1 and str(error) in failed[0]
    assert load_box(tooled.box.path).status == "active"
    assert "kerbrute" in load_installed(tooled.paths)
    assert (user / ".kerb" / "found.txt").exists()


def test_export_collects_and_removes_nothing(tooled, user):
    path = export_box(tooled, fix=lambda p: 0)
    assert path is not None
    assert any(n.endswith("tooldata/kerbrute/home/.kerb/found.txt") for n in archive_names(path))
    assert "kerbrute" in load_installed(tooled.paths)
    assert load_box(tooled.box.path).tools
    assert (user / ".kerb" / "found.txt").exists()
    assert load_box(tooled.box.path).status == "active"


def test_export_stops_when_collecting_fails(tooled, user, monkeypatch):
    def boom(*a):
        raise ToolError("the disk is full")

    monkeypatch.setattr(toolhooks.tooldata, "collect", boom)
    assert export_box(tooled, fix=lambda p: 0) is None
    failed = lines(tooled, "fail")
    assert len(failed) == 1 and "the disk is full" in failed[0]
    assert "kerbrute" in load_installed(tooled.paths) and (user / ".kerb").exists()


@pytest.mark.skipif(sys.platform == "win32", reason="needs symlinks")
def test_export_and_finish_stop_on_a_tooldata_symlink(tooled, tmp_path):
    (tooled.box.path / "tooldata").symlink_to(tmp_path)
    assert export_box(tooled, fix=lambda p: 0) is None
    assert len(lines(tooled, "fail")) == 1
    say(tooled, "y")
    assert finish_box(tooled, **SAVED) is None
    assert load_box(tooled.box.path).status == "active"


# ---- import


def test_import_offers_to_install_the_tools_again(tooled, tmp_path):
    archive = export_box(tooled, fix=lambda p: 0)
    wipe(tooled)
    paths = fresh_paths(tooled, tmp_path)
    console = FakeConsole(["y"])
    box = import_box(paths, tooled.settings, console, archive, lambda: NOW)
    assert box is not None
    assert console.asked == ["install these tools again?"]
    assert box.id in load_installed(paths)["kerbrute"].users


def test_import_carries_on_when_the_build_is_gone(tooled, tmp_path):
    archive = export_box(tooled, fix=lambda p: 0)
    wipe(tooled)
    (tmp_path / "index" / "index.toml").write_text("schema = 1\n", encoding="utf-8")
    paths = fresh_paths(tooled, tmp_path)
    console = FakeConsole(["y"])
    box = import_box(paths, tooled.settings, console, archive, lambda: NOW)
    assert box is not None
    assert any(k == "warn" and "kerbrute 1.0.3" in t for k, t in console.lines)
    assert load_installed(paths) == {}


def test_import_with_no_declines_the_reinstall(tooled, tmp_path):
    archive = export_box(tooled, fix=lambda p: 0)
    wipe(tooled)
    paths = fresh_paths(tooled, tmp_path)
    box = import_box(paths, tooled.settings, FakeConsole(["n"]), archive, lambda: NOW)
    assert box is not None and load_installed(paths) == {}


def test_import_with_a_changed_sha256_warns_and_skips(tooled, tmp_path):
    archive = export_box(tooled, fix=lambda p: 0)
    wipe(tooled)
    index = tmp_path / "index" / "index.toml"
    index.write_text(
        index.read_text(encoding="utf-8").replace(tooled_sha(tooled), "ef" * 32), encoding="utf-8"
    )
    paths = fresh_paths(tooled, tmp_path)
    console = FakeConsole(["y"])
    assert import_box(paths, tooled.settings, console, archive, lambda: NOW) is not None
    assert any(k == "warn" and "SHA-256" in t for k, t in console.lines)
    assert load_installed(paths) == {}


def tooled_sha(session):
    return session.box.tools[0].sha256


# ---- unreadable boxes and lists


def break_box(box_dir):
    (box_dir / "box.toml").write_text("nope [", encoding="utf-8")


def test_undo_keeps_the_box_recording_its_tools(tooled, user):
    toolhooks.undo(tooled)
    saved = load_box(tooled.box.path)
    assert [t.name for t in saved.tools] == ["kerbrute"]
    assert load_installed(tooled.paths) == {}


def test_reopen_after_a_failed_removal_offers_the_tools_again(tooled, env, monkeypatch):
    def stuck(paths, item):
        raise ToolError("cannot remove it")

    real = toolinstall.remove_files
    monkeypatch.setattr(toolinstall, "remove_files", stuck)
    say(tooled, "y")
    assert finish_box(tooled, **SAVED) is not None
    monkeypatch.setattr(toolinstall, "remove_files", real)
    assert [t.name for t in load_box(tooled.box.path).tools] == ["kerbrute"]
    from pwn_broker import cli

    env.settings = tooled.settings
    env.console = FakeConsole(["3", "y"])
    reopened = cli.choose(env)
    assert reopened.box.status == "active"
    assert env.console.asked[-1] == "install these tools again?"
    assert any("kerbrute 1.0.3" in t for k, t in env.console.lines if k == "info")
    assert reopened.box.id in load_installed(tooled.paths)["kerbrute"].users


def test_finishing_one_box_keeps_the_tool_for_a_box_that_cannot_be_read(tooled, other, user):
    item = load_installed(tooled.paths)["kerbrute"]
    item.users.append(other.id)
    toolstate.save_installed(tooled.paths, {"kerbrute": item})
    break_box(other.path)
    toolhooks.undo(tooled)
    assert load_installed(tooled.paths)["kerbrute"].users == [other.id]
    assert (user / ".kerb" / "found.txt").exists()
    assert any(".old" in t for t in lines(tooled, "warn"))


def test_a_loaded_finished_box_still_does_not_count_while_another_is_unreadable(tooled, user):
    from pwn_broker.boxes import create_box

    done = create_box(
        tooled.paths, name="Done", platform="htb", day=NOW.date(), os_name="linux",
        difficulty="easy", now=NOW, new_id=lambda: "id-done",
    )  # fmt: skip
    done.status = "finished"
    save_box(done)
    broken = create_box(
        tooled.paths, name="Broken", platform="htb", day=NOW.date(), os_name="linux",
        difficulty="easy", now=NOW, new_id=lambda: "id-broken",
    )  # fmt: skip
    break_box(broken.path)
    item = load_installed(tooled.paths)["kerbrute"]
    item.users += [done.id]
    toolstate.save_installed(tooled.paths, {"kerbrute": item})
    toolhooks.pre_pack(tooled)
    toolhooks.undo(tooled)
    assert load_installed(tooled.paths) == {}
    assert not (user / ".kerb").exists()


def test_leftovers_make_no_offer_while_a_box_cannot_be_read(tooled, other):
    finish_without_undo(tooled)
    break_box(other.path)
    console = FakeConsole(["y"])
    toolhooks.leftovers(tooled.paths, console)
    assert console.asked == []
    assert [k for k, _ in console.lines] == ["warn"]
    assert console.lines[0][1] == (
        f"tools left by finished boxes were not checked: {other.path.name} cannot be read"
    )
    assert "kerbrute" in load_installed(tooled.paths)


def corrupt_installed(session):
    session.paths.tools_state.write_text("not toml [", encoding="utf-8")


def test_export_with_an_unreadable_installed_list_still_writes_the_archive(tooled):
    corrupt_installed(tooled)
    path = export_box(tooled, fix=lambda p: 0)
    assert path is not None and path.exists()
    assert any("tool data was not copied" in t for t in lines(tooled, "warn"))
    assert not lines(tooled, "fail")


def test_finish_with_an_unreadable_installed_list_stops_before_any_question(tooled):
    corrupt_installed(tooled)
    say(tooled)
    assert finish_box(tooled, **SAVED) is None
    failed = lines(tooled, "fail")
    assert len(failed) == 1 and "cannot be read; fix or remove it, then finish again" in failed[0]
    assert str(tooled.paths.tools_state) in failed[0]
    assert tooled.console.asked == []
    assert load_box(tooled.box.path).status == "active"


def test_summary_is_empty_when_the_installed_list_is_unreadable(tooled):
    corrupt_installed(tooled)
    assert toolhooks.summary(tooled) == []


def test_restore_keeps_a_user_the_listing_could_not_load(tooled, other):
    item = load_installed(tooled.paths)["kerbrute"]
    item.users = [other.id, "lost-box"]
    toolstate.save_installed(tooled.paths, {"kerbrute": item})
    (tooled.paths.active / "broken").mkdir()
    (tooled.paths.active / "broken" / "box.toml").write_text("nope [", encoding="utf-8")
    say(tooled, "y")
    toolhooks.restore(tooled)
    users = load_installed(tooled.paths)["kerbrute"].users
    assert "lost-box" in users and tooled.box.id in users


# ---- home data copied in full


def deny_copy(monkeypatch, name):
    real = toolhooks.tooldata.shutil.copy2

    def flaky(src, dst, **kw):
        if str(src).replace("\\", "/").endswith(name):
            raise PermissionError("denied")
        return real(src, dst, **kw)

    monkeypatch.setattr(toolhooks.tooldata.shutil, "copy2", flaky)


def test_finish_keeps_a_home_folder_that_was_not_copied_in_full(tooled, user, monkeypatch):
    (user / ".kerb" / "locked.txt").write_text("root's")
    deny_copy(monkeypatch, ".kerb/locked.txt")
    say(tooled, "y", "n")
    path = finish_box(tooled, **SAVED)
    assert path is not None
    assert (user / ".kerb" / "locked.txt").read_text() == "root's"
    assert (user / ".kerb" / "found.txt").exists()
    assert f"{user / '.kerb'} was not copied in full; kept" in lines(tooled, "warn")
    names = archive_names(path)
    assert any(n.endswith("tooldata/kerbrute/home/.kerb/found.txt") for n in names)
    assert not any(n.endswith("locked.txt") for n in names)
    assert load_installed(tooled.paths) == {}


def test_undo_deletes_nothing_when_nothing_was_copied_first(tooled, user):
    toolhooks.undo(tooled)
    assert (user / ".kerb" / "found.txt").exists()
    assert f"{user / '.kerb'} was not copied in full; kept" in lines(tooled, "warn")
    assert load_installed(tooled.paths) == {}


def test_pre_pack_remembers_only_what_was_copied_in_full(tooled, user, monkeypatch):
    assert tooled.copied_in_full == set()
    toolhooks.pre_pack(tooled)
    assert tooled.copied_in_full == {user / ".kerb"}
    deny_copy(monkeypatch, "found.txt")
    toolhooks.pre_pack(tooled)
    assert tooled.copied_in_full == set()


def test_a_reinstall_keeps_the_earlier_installs_copy_in_the_box(tooled, shop, user):
    assert export_box(tooled, fix=lambda p: 0) is not None
    # as on a second VM: the tool and its home data are not there until installed again
    wipe(tooled)
    tooled.box.tools = []
    shutil.rmtree(user / ".kerb")
    later = NOW.replace(year=NOW.year + 1)
    toolinstall.install(
        tooled.paths, tooled.box, shop.entry, shop.zip,
        installed={}, unfinished={tooled.box.id: tooled.box.name},
        home=user, console=FakeConsole(), now=later, on_path=lambda n: None,
    )  # fmt: skip
    (user / ".kerb").mkdir()
    (user / ".kerb" / "second.txt").write_text("second run")
    say(tooled, "y", "n")
    path = finish_box(tooled, **SAVED)
    names = archive_names(path)
    assert any(n.endswith("tooldata/kerbrute/home-1/.kerb/found.txt") for n in names)
    assert any(n.endswith("tooldata/kerbrute/home/.kerb/second.txt") for n in names)
    assert not (user / ".kerb").exists()


# ---- root's home


@pytest.fixture
def rootdir(tmp_path, monkeypatch, user):
    folder = tmp_path / "rootdir"
    folder.mkdir()
    monkeypatch.setattr(toolhooks.tooldata, "homes", lambda h, **k: [h, folder])
    return folder


def install_kerbrute(session, shop, user):
    session.settings = replace(session.settings, tools_index=str(shop.folder))
    toolinstall.install(
        session.paths, session.box, shop.entry, shop.zip,
        installed={}, unfinished={session.box.id: session.box.name},
        home=user, console=FakeConsole(), now=NOW, on_path=lambda n: None,
    )  # fmt: skip


def test_a_path_that_was_in_roots_home_before_is_kept(session, shop, user, rootdir, registered):
    (rootdir / ".kerb").mkdir()
    (rootdir / ".kerb" / "mine.txt").write_text("root had it")
    install_kerbrute(session, shop, user)
    assert load_installed(session.paths)["kerbrute"].root_home == {".kerb": True, ".old": False}
    (user / ".kerb").mkdir()
    (user / ".kerb" / "found.txt").write_text("user run")
    say(session, "y", "n")
    path = finish_box(session, **SAVED)
    names = archive_names(path)
    assert any(n.endswith("tooldata/kerbrute/home/.kerb/found.txt") for n in names)
    assert (rootdir / ".kerb" / "mine.txt").read_text() == "root had it"
    assert not (user / ".kerb").exists()
    assert f"{rootdir / '.kerb'}   existed before kerbrute was installed; kept" in lines(session, "warn")


def test_a_path_made_in_roots_home_after_install_is_collected_and_deleted(
    session, shop, user, rootdir, registered
):
    install_kerbrute(session, shop, user)
    (rootdir / ".kerb").mkdir()
    (rootdir / ".kerb" / "found.txt").write_text("sudo run")
    say(session, "y", "n")
    path = finish_box(session, **SAVED)
    assert any(
        n.endswith("tooldata/kerbrute/home-root/.kerb/found.txt") for n in archive_names(path)
    )
    assert not (rootdir / ".kerb").exists()


def test_finish_warns_when_roots_home_cannot_be_read(tooled, monkeypatch):
    monkeypatch.setattr(toolhooks.tooldata, "root_unchecked", lambda h, **k: True)
    say(tooled, "y", "n")
    assert finish_box(tooled, **SAVED) is not None
    assert "root's home could not be checked for kerbrute's data" in lines(tooled, "warn")


def test_a_user_whose_home_is_roots_sees_no_difference(session, shop, tmp_path, monkeypatch, registered):
    home = tmp_path / "user"
    home.mkdir()
    monkeypatch.setattr(toolhooks, "user_home", lambda: home)
    monkeypatch.setattr(toolhooks.tooldata, "_posix", lambda: True)
    monkeypatch.setattr(toolhooks.tooldata, "_root_home", lambda: home)
    install_kerbrute(session, shop, home)
    assert load_installed(session.paths)["kerbrute"].root_home == {}
    (home / ".kerb").mkdir()
    (home / ".kerb" / "found.txt").write_text("result")
    say(session, "y", "n")
    path = finish_box(session, **SAVED)
    assert any(n.endswith("tooldata/kerbrute/home/.kerb/found.txt") for n in archive_names(path))
    assert not (home / ".kerb").exists()
    assert not any("root's home" in t for t in lines(session, "warn"))


# ---- undo always saves the box


def test_undo_goes_on_after_any_error_and_still_saves_every_record(tooled, shop, user, monkeypatch):
    other_command = [{"name": "other-tool", "type": "binary", "path": "files/kerbrute"}]
    zip2, entry2 = toolkit.make_entry(
        shop.folder.parent / "pkg2", {"name": "other-tool", "command": other_command}
    )
    toolinstall.install(
        tooled.paths, tooled.box, entry2, zip2,
        installed=load_installed(tooled.paths), unfinished={tooled.box.id: "forest"},
        home=user, console=FakeConsole(), now=NOW, on_path=lambda n: None,
    )  # fmt: skip
    real = toolinstall.release

    def release(paths, box, name, **kw):
        if name == "kerbrute":
            raise ValueError("odd value")
        return real(paths, box, name, **kw)

    monkeypatch.setattr(toolhooks.toolinstall, "release", release)
    with pytest.raises(ToolError, match="kerbrute: odd value"):
        toolhooks.undo(tooled)
    assert "other-tool" not in load_installed(tooled.paths)
    assert [t.name for t in load_box(tooled.box.path).tools] == ["kerbrute", "other-tool"]


def test_undo_saves_the_records_even_when_interrupted(tooled, monkeypatch):
    real = toolinstall.release

    def interrupt(*a, **k):
        real(*a, **k)  # the record is dropped and saved, then the interrupt lands
        raise KeyboardInterrupt

    monkeypatch.setattr(toolhooks.toolinstall, "release", interrupt)
    with pytest.raises(KeyboardInterrupt):
        toolhooks.undo(tooled)
    assert [t.name for t in load_box(tooled.box.path).tools] == ["kerbrute"]


# ---- files left by an interrupted install


SWEEP_QUESTION = "remove files left by an interrupted install?"


def plant_strays(paths):
    strays = [
        paths.tools / "kerbrute" / "0.9-1",
        paths.tools / "ghost",
        paths.upload / "ghost",
        paths.bin / "ghost-cmd",
    ]
    (strays[0] / "files").mkdir(parents=True)
    (strays[0] / "files" / "kerbrute").write_text("old build")
    (strays[1] / "1-1" / "files").mkdir(parents=True)
    (strays[2]).mkdir(parents=True)
    (strays[2] / "agent").write_text("A")
    strays[3].write_bytes(b"#!/bin/sh\n# pwn-broker tool: ghost\nexec x\n")
    return strays


def test_files_left_by_an_interrupted_install_are_offered_and_removed(tooled):
    paths = tooled.paths
    strays = plant_strays(paths)
    plain = paths.bin / "plain"
    plain.write_bytes(b"#!/bin/sh\necho mine\n")
    extra = paths.bin / "kerbrute-extra"
    extra.write_bytes(b"#!/bin/sh\n# pwn-broker tool: kerbrute\n")
    keep = sorted(
        p.relative_to(paths.opt).as_posix()
        for p in paths.opt.rglob("*")
        if not any(p == s or s in p.parents for s in strays)
    )
    console = FakeConsole(["y"])
    toolhooks.leftovers(paths, console)
    assert console.asked == [SWEEP_QUESTION]
    assert [t for k, t in console.lines if k == "info"] == [f"left      {s}" for s in sorted(strays)]
    assert [t for k, t in console.lines if k == "ok"] == [f"removed {s}" for s in sorted(strays)]
    assert not any(os.path.lexists(s) for s in strays)
    assert sorted(p.relative_to(paths.opt).as_posix() for p in paths.opt.rglob("*")) == keep
    assert plain.exists() and extra.exists() and (paths.bin / "kerbrute").exists()


def test_files_left_by_an_interrupted_install_stay_on_no(tooled):
    strays = plant_strays(tooled.paths)
    toolhooks.leftovers(tooled.paths, FakeConsole(["n"]))
    assert all(os.path.lexists(s) for s in strays)


def test_files_left_by_a_first_install_are_found_with_no_tool_installed(paths):
    stray = paths.tools / "kerbrute" / "1.0.3-1"
    stray.mkdir(parents=True)
    paths.bin.mkdir(parents=True)
    launcher = paths.bin / "kerbrute"
    launcher.write_bytes(b"#!/bin/sh\n# pwn-broker tool: kerbrute\n")
    console = FakeConsole(["y"])
    toolhooks.leftovers(paths, console)
    assert console.asked == [SWEEP_QUESTION]
    assert not (paths.tools / "kerbrute").exists() and not launcher.exists()


def test_nothing_is_swept_while_the_installed_list_cannot_be_read(tooled):
    strays = plant_strays(tooled.paths)
    tooled.paths.tools_state.write_text("not toml [", encoding="utf-8")
    console = FakeConsole(["y"])
    toolhooks.leftovers(tooled.paths, console)
    assert console.asked == [] and [k for k, _ in console.lines] == ["warn"]
    assert all(os.path.lexists(s) for s in strays)


def test_a_clean_root_asks_nothing(tooled):
    (tooled.paths.bin / "plain").write_bytes(b"#!/bin/sh\n")
    console = FakeConsole()
    toolhooks.leftovers(tooled.paths, console)
    assert console.asked == [] and console.lines == []


@pytest.mark.skipif(sys.platform == "win32", reason="needs symlinks")
def test_links_are_never_followed_or_removed(tooled, tmp_path):
    outside = tmp_path / "outside"
    (outside / "1-1").mkdir(parents=True)
    (tooled.paths.tools / "ghost").symlink_to(outside, target_is_directory=True)
    (tooled.paths.upload).mkdir(parents=True, exist_ok=True)
    (tooled.paths.upload / "ghost").symlink_to(outside, target_is_directory=True)
    target = tmp_path / "launcher"
    target.write_bytes(b"#!/bin/sh\n# pwn-broker tool: ghost\n")
    (tooled.paths.bin / "ghost-cmd").symlink_to(target)
    console = FakeConsole(["y"])
    toolhooks.leftovers(tooled.paths, console)
    assert console.asked == []
    assert (outside / "1-1").is_dir() and target.exists()


def test_a_removed_orphans_home_paths_are_named_not_deleted(tooled, user):
    finish_without_undo(tooled)
    console = FakeConsole(["y"])
    toolhooks.leftovers(tooled.paths, console)
    assert load_installed(tooled.paths) == {}
    assert (user / ".kerb" / "found.txt").exists()
    assert (
        "warn",
        f"{user / '.kerb'} was left by kerbrute; remove it by hand if it is not needed",
    ) in console.lines


# ---- runtimes

RUNTIME_QUESTION = "remove runtimes no installed tool requires?"
RT_LINE = ("ok", "python-3.13 3.13.18 installed (runtime, 1 MB)")
RT_GONE = ("ok", "python-3.13 3.13.18 removed (runtime)")
RT_SUMMARY = "runtimes  python-3.13 3.13.18   (will be removed)"


@pytest.fixture
def pyshop(shop, monkeypatch):
    # certipy and bloodhound both require python-3.13
    calls = toolkit.no_real_venv(monkeypatch)
    _z, runtime = toolkit.make_runtime(shop.folder)
    _z, certipy = toolkit.make_python_tool(shop.folder)
    _z, bloodhound = toolkit.make_python_tool(shop.folder, "bloodhound", "1.8.0", build=1)
    entries = [shop.entry, runtime, certipy, bloodhound]
    toolkit.write_index(shop.folder, entries)
    return SimpleNamespace(
        runtime=runtime, certipy=certipy, bloodhound=bloodhound, entries=entries, calls=calls
    )


def put(session, entry, box=None):
    # installs a tool, and the runtime it requires, for the box (the session's by default)
    installed = load_installed(session.paths)
    box = box or session.box
    index = toolindex.load_index(session.paths, session.settings, now=NOW)
    for name in entry.requires:
        rt_entry = toolindex.pick_build(toolindex.find_runtime(index, name), None)
        zip_path = toolindex.fetch_zip(session.paths, session.settings, rt_entry)
        toolinstall.install_runtime(
            session.paths, rt_entry, zip_path, installed=installed, console=FakeConsole()
        )
    toolinstall.install(
        session.paths, box, entry, toolindex.fetch_zip(session.paths, session.settings, entry),
        installed=installed, unfinished={box.id: box.name}, home=toolhooks.user_home(),
        console=FakeConsole(), now=NOW, on_path=lambda n: None,
        runtime=installed.get(entry.requires[0]) if entry.requires else None,
    )  # fmt: skip


def runtime_row(paths):
    return load_installed(paths).get("python-3.13")


def wipe_all(session):
    # the machine has none of the tools or runtimes the box recorded
    installed = load_installed(session.paths)
    for item in installed.values():
        if item.kind == "runtime":
            toolinstall.remove_runtime(session.paths, item)
        else:
            toolinstall.remove_files(session.paths, item)
    toolstate.save_installed(session.paths, {})


def test_summary_lists_the_runtimes_that_will_go(tooled, pyshop):
    put(tooled, pyshop.certipy)
    shown = toolhooks.summary(say(tooled))
    assert shown[:2] == ["tools     kerbrute 1.0.3, certipy 5.1.0   (will be removed)", RT_SUMMARY]


def test_summary_keeps_a_runtime_a_tool_of_another_unfinished_box_requires(tooled, pyshop, other):
    put(tooled, pyshop.certipy)
    put(tooled, pyshop.bloodhound, box=other)
    assert RT_SUMMARY not in toolhooks.summary(say(tooled))
    # the same holds when the other box shares the very tool
    put(tooled, pyshop.certipy, box=other)
    toolinstall.release(
        tooled.paths, other, "bloodhound",
        installed=load_installed(tooled.paths), unfinished={other.id: other.name}, removed=NOW,
    )  # fmt: skip
    assert RT_SUMMARY not in toolhooks.summary(say(tooled))


def test_summary_lists_no_runtime_while_a_box_cannot_be_read(tooled, pyshop, other):
    put(tooled, pyshop.certipy)
    break_box(other.path)
    assert RT_SUMMARY not in toolhooks.summary(say(tooled))


def test_finish_removes_the_runtime_with_the_last_tool(tooled, pyshop, user):
    put(tooled, pyshop.certipy)
    shown = []
    say(tooled, "y", "y")
    original = tooled.console.confirm
    tooled.console.confirm = lambda q, default=False: (
        shown.extend(tooled.console.lines) or original(q, default)
    )
    path = finish_box(tooled, **SAVED)
    assert path is not None and path.exists()
    assert ("info", RT_SUMMARY) in shown
    assert RT_GONE in tooled.console.lines
    assert load_installed(tooled.paths) == {}
    assert not (tooled.paths.tools / "python-3.13").exists()
    # nothing kept the working folder: finish went on to offer its removal
    assert tooled.console.asked[-1] == "remove working folder?"
    assert not tooled.box.path.exists()
    # the finished box still names the runtime its tool ran on
    archived = [t for t in tooled.box.tools if t.name == "certipy"]
    assert archived[0].runtime.name == "python-3.13"


def test_finish_keeps_a_runtime_a_tool_of_another_unfinished_box_requires(tooled, pyshop, other):
    put(tooled, pyshop.certipy)
    put(tooled, pyshop.bloodhound, box=other)
    say(tooled, "y")
    assert finish_box(tooled, **SAVED) is not None
    assert RT_GONE not in tooled.console.lines
    assert set(load_installed(tooled.paths)) == {"bloodhound", "python-3.13"}


def test_finish_keeps_every_runtime_while_a_box_cannot_be_read(tooled, pyshop, other):
    put(tooled, pyshop.certipy)
    break_box(other.path)
    say(tooled, "y")
    assert finish_box(tooled, **SAVED) is not None
    assert lines(tooled, "warn")[-1] == f"python-3.13 kept: {other.path.name} cannot be read"
    assert runtime_row(tooled.paths) is not None


def test_a_runtime_finish_cannot_remove_is_a_warn_and_offered_at_launch(
    tooled, pyshop, monkeypatch
):
    put(tooled, pyshop.certipy)
    real = toolinstall.remove_runtime

    def stuck(paths, item):
        raise ToolError("the folder is busy")

    monkeypatch.setattr(toolinstall, "remove_runtime", stuck)
    say(tooled, "y", "y")
    assert finish_box(tooled, **SAVED) is not None
    assert ("warn", "python-3.13 3.13.18   the folder is busy") in tooled.console.lines
    assert lines(tooled, "fail") == []
    assert tooled.console.asked[-1] == "remove working folder?"
    assert not tooled.box.path.exists()
    assert list(load_installed(tooled.paths)) == ["python-3.13"]
    monkeypatch.setattr(toolinstall, "remove_runtime", real)
    console = FakeConsole(["y"])
    toolhooks.leftovers(tooled.paths, console)
    assert console.asked == [RUNTIME_QUESTION]
    assert ("ok", "removed python-3.13 3.13.18 (runtime)") in console.lines
    assert load_installed(tooled.paths) == {}
    assert not (tooled.paths.tools / "python-3.13").exists()


def test_import_installs_the_runtime_before_the_tool(tooled, pyshop, tmp_path):
    put(tooled, pyshop.certipy)
    archive = export_box(tooled, fix=lambda p: 0)
    wipe_all(tooled)
    paths = fresh_paths(tooled, tmp_path)
    console = FakeConsole(["y"])
    box = import_box(paths, tooled.settings, console, archive, lambda: NOW)
    assert box is not None
    oks = [t for k, t in console.lines if k == "ok"]
    assert oks.index(RT_LINE[1]) < oks.index("certipy 5.1.0 installed")
    assert not any("now runs on" in t for t in oks)
    installed = load_installed(paths)
    assert box.id in installed["certipy"].users and installed["python-3.13"].build == 1


def restore_after(tooled, pyshop, runtime_entries):
    # the box recorded certipy on python-3.13 3.13.18-1; the index now lists other runtimes
    put(tooled, pyshop.certipy)
    wipe_all(tooled)
    others = [e for e in pyshop.entries if e.name != "python-3.13"]
    toolkit.write_index(pyshop_folder(tooled), [*others, *runtime_entries])
    say(tooled, "y")
    toolhooks.restore(tooled)


def pyshop_folder(session):
    return Path(session.settings.tools_index)


@pytest.mark.parametrize(
    "version, build, note",
    [
        ("3.13.19", 1, "certipy now runs on python-3.13 3.13.19; this box used 3.13.18 before"),
        ("3.13.18", 2, "certipy now runs on python-3.13 3.13.18-2; this box used 3.13.18-1 before"),
    ],
)
def test_import_on_another_runtime_build_says_so_and_carries_on(
    tooled, pyshop, version, build, note
):
    _z, newer = toolkit.make_runtime(pyshop_folder(tooled), version=version, build=build)
    restore_after(tooled, pyshop, [newer])
    assert ("ok", note) in tooled.console.lines
    assert lines(tooled, "warn") == []
    [record] = [t for t in load_box(tooled.box.path).tools if t.name == "certipy"]
    assert (record.runtime.version, record.runtime.build) == (version, build)
    assert runtime_row(tooled.paths).version == version


def test_import_uses_the_runtime_already_installed_at_another_build(tooled, pyshop, other):
    put(tooled, pyshop.certipy)
    wipe_all(tooled)
    _z, newer = toolkit.make_runtime(pyshop_folder(tooled), build=2)
    toolkit.write_index(pyshop_folder(tooled), [*pyshop.entries, newer])
    put(tooled, pyshop.bloodhound, box=other)  # brings 3.13.18-2, the index's latest
    toolkit.write_index(pyshop_folder(tooled), pyshop.entries)
    say(tooled, "y")
    toolhooks.restore(tooled)
    assert RT_LINE not in tooled.console.lines
    assert (
        "ok", "certipy now runs on python-3.13 3.13.18-2; this box used 3.13.18-1 before"
    ) in tooled.console.lines
    assert runtime_row(tooled.paths).build == 2


def test_import_warns_for_a_tool_whose_runtime_the_index_no_longer_lists(tooled, pyshop):
    restore_after(tooled, pyshop, [])
    assert lines(tooled, "warn") == [
        "certipy 5.1.0   no runtime named 'python-3.13' in the index"
    ]
    installed = load_installed(tooled.paths)
    assert "kerbrute" in installed  # the others carry on
    assert "certipy" not in installed and "python-3.13" not in installed


def test_import_takes_away_a_runtime_it_brought_for_a_tool_that_fails(
    tooled, pyshop, monkeypatch
):
    put(tooled, pyshop.certipy)
    wipe_all(tooled)
    toolkit.no_real_venv(monkeypatch, fail="pip")
    say(tooled, "y")
    toolhooks.restore(tooled)
    assert RT_LINE in tooled.console.lines
    assert any(t.startswith("certipy 5.1.0   pip failed") for t in lines(tooled, "warn"))
    installed = load_installed(tooled.paths)
    assert "kerbrute" in installed and "python-3.13" not in installed
    assert not (tooled.paths.tools / "python-3.13").exists()


def test_a_box_that_recorded_a_schema_1_python_tool_gets_that_build(tooled, pyshop, user):
    folder = pyshop_folder(tooled)
    wheel = toolkit.make_wheel(folder / "w1", "certipy-py", "1.0", module="tool", entry="certipy")
    manifest = toolkit.sample_manifest(
        name="certipy", version="5.1.0", build=2, arch=machine_arch(),
        command=[{"name": "certipy", "type": "python-entry", "entry": "certipy"}],
        python={"versions": ["3.13"], "lock": "wheels.lock", "wheels": "wheels"},
    )  # fmt: skip
    zip_path, size, sha = toolkit.make_package(folder, manifest, {}, wheels=[wheel])
    old = toolindex.BuildEntry(
        "certipy", "5.1.0", 2, "kali", False, ["certipy"], zip_path.name, "", size, sha
    )
    # the index's latest certipy is build 3, on the runtime; the box recorded build 2
    toolkit.write_index(folder, [shop_entry(pyshop), pyshop.runtime, old, pyshop.certipy])
    tooled.box.tools.append(ToolRecord("certipy", "5.1.0", 2, sha, NOW))
    save_box(tooled.box)
    say(tooled, "y")
    toolhooks.restore(tooled)
    assert ("ok", "certipy 5.1.0 installed") in tooled.console.lines
    assert pyshop.calls[0][:3] == ["python3", "-I", "-c"]  # Kali's own Python
    installed = load_installed(tooled.paths)
    assert installed["certipy"].build == 2 and "python-3.13" not in installed
    [record] = [t for t in load_box(tooled.box.path).tools if t.name == "certipy"]
    assert record.build == 2 and record.runtime is None


def shop_entry(pyshop):
    return pyshop.entries[0]


def test_leftovers_offer_the_runtime_of_a_tool_they_removed(tooled, pyshop):
    put(tooled, pyshop.certipy)
    finish_without_undo(tooled)
    console = FakeConsole(["y", "y"])
    toolhooks.leftovers(tooled.paths, console)
    assert console.asked == ["remove tools left by finished boxes?", RUNTIME_QUESTION]
    assert ("info", "runtimes  python-3.13 3.13.18") in console.lines
    assert load_installed(tooled.paths) == {}
    assert not (tooled.paths.tools / "python-3.13").exists()


def test_leftovers_keep_a_runtime_a_tool_still_requires(tooled, pyshop):
    put(tooled, pyshop.certipy)
    finish_without_undo(tooled)
    console = FakeConsole(["n"])
    toolhooks.leftovers(tooled.paths, console)
    # the tools stay, so the runtime their tool requires is not offered
    assert console.asked == ["remove tools left by finished boxes?"]
    assert runtime_row(tooled.paths) is not None


def test_leftovers_offer_no_runtime_while_a_box_cannot_be_read(tooled, pyshop, other):
    put(tooled, pyshop.certipy)
    installed = load_installed(tooled.paths)
    toolinstall.release(
        tooled.paths, tooled.box, "certipy", installed=installed, unfinished={}, removed=NOW
    )
    break_box(other.path)
    console = FakeConsole(["y", "y"])
    toolhooks.leftovers(tooled.paths, console)
    assert RUNTIME_QUESTION not in console.asked
    assert runtime_row(tooled.paths) is not None


def test_a_runtime_folder_with_no_row_is_a_stray(tooled, pyshop):
    put(tooled, pyshop.certipy)
    installed = load_installed(tooled.paths)
    del installed["python-3.13"]
    toolstate.save_installed(tooled.paths, installed)
    console = FakeConsole(["y"])
    toolhooks.leftovers(tooled.paths, console)
    assert console.asked == [SWEEP_QUESTION]
    assert ("info", f"left      {tooled.paths.tools / 'python-3.13'}") in console.lines


# ---- removed tools


def remove_row(session, name="kerbrute"):
    # the box took the tool off with tool remove; its row stays, with the time
    session.box.tools = [
        replace(t, removed=NOW) if t.name == name and t.removed is None else t
        for t in session.box.tools
    ]
    save_box(session.box)


def hand_to_other(session, other):
    item = load_installed(session.paths)["kerbrute"]
    item.users = [other.id]
    toolstate.save_installed(session.paths, {"kerbrute": item})


def test_a_removed_tool_does_not_block_finish(tooled, other):
    hand_to_other(tooled, other)
    remove_row(tooled)
    mark(tooled)
    assert toolhooks.block(tooled, alive=lambda pid: True, started=lambda pid: None) is None


def test_a_removed_tool_is_left_out_of_the_summary_and_the_copy(tooled, other):
    hand_to_other(tooled, other)
    remove_row(tooled)
    assert toolhooks.summary(tooled) == []
    toolhooks.pre_pack(tooled)
    assert not (tooled.box.path / "tooldata").exists()


def test_finish_does_not_remove_a_removed_tool_again(tooled, other):
    hand_to_other(tooled, other)
    remove_row(tooled)
    rows = list(tooled.box.tools)
    toolhooks.undo(tooled)
    assert load_installed(tooled.paths)["kerbrute"].users == [other.id]
    assert load_box(tooled.box.path).tools == rows
    assert log_lines(tooled.paths) == []


def test_a_removed_tool_is_not_offered_again(tooled):
    wipe(tooled)
    remove_row(tooled)
    say(tooled, "y")
    toolhooks.restore(tooled)
    assert tooled.console.asked == [] and tooled.console.lines == []
    assert load_installed(tooled.paths) == {}


def test_import_offers_only_the_tools_the_box_still_had(tooled, pyshop, tmp_path):
    put(tooled, pyshop.certipy)
    remove_row(tooled, "certipy")
    archive = export_box(tooled, fix=lambda p: 0)
    wipe_all(tooled)
    paths = fresh_paths(tooled, tmp_path)
    console = FakeConsole(["y"])
    box = import_box(paths, tooled.settings, console, archive, lambda: NOW)
    assert ("info", "tools     kerbrute 1.0.3") in console.lines
    assert set(load_installed(paths)) == {"kerbrute"}
    # the tool installed again keeps its row; the removed one stays removed
    assert [(t.name, t.removed) for t in box.tools] == [("kerbrute", None), ("certipy", NOW)]


def test_finish_keeps_removed_rows_removed_and_current_rows_current(tooled, user):
    tooled.box.tools.insert(0, ToolRecord("ligolo-ng", "0.9.2", 1, "cd" * 32, NOW, removed=NOW))
    save_box(tooled.box)
    say(tooled, "y", "n")
    assert finish_box(tooled, **SAVED) is not None
    saved = load_box(tooled.box.path)
    assert [(t.name, t.removed) for t in saved.tools] == [("ligolo-ng", NOW), ("kerbrute", None)]
    assert [t.name for t in current_tools(saved)] == ["kerbrute"]


# ---- the tool log

LOGGED_AT = "2026-11-14T13:00:00+02:00"  # the session's clock, an hour after NOW
FOREST = "forest (2026-11-14_htb_forest)"


def log_lines(paths):
    if not paths.tool_log.exists():
        return []
    return paths.tool_log.read_bytes().decode("utf-8").splitlines()


def logged(event, entry, box=FOREST, at=LOGGED_AT, runtime=False):
    line = f"{at}  {event:<7}  {box}  {entry.name} {entry.version}-{entry.build}"
    line += f"  sha256:{entry.sha256}"
    return line + "  runtime" if runtime else line


def index_of(session):
    return toolindex.load_index(session.paths, session.settings, now=NOW)


def install_through_hooks(session, entry, unfinished=None, **kw):
    return toolhooks.install_tool(
        session, index_of(session), entry,
        installed=load_installed(session.paths),
        unfinished=unfinished or {session.box.id: session.box.name}, **kw,
    )  # fmt: skip


def test_an_install_logs_the_runtime_it_brought_then_the_tool(tooled, pyshop):
    install_through_hooks(tooled, pyshop.certipy, on_path=lambda n: None)
    assert log_lines(tooled.paths) == [
        logged("install", pyshop.runtime, runtime=True),
        logged("install", pyshop.certipy),
    ]
    # the next tool on the same runtime brings none
    install_through_hooks(tooled, pyshop.bloodhound, on_path=lambda n: None)
    assert log_lines(tooled.paths)[2:] == [logged("install", pyshop.bloodhound)]


def test_a_failed_install_logs_nothing(tooled, pyshop, monkeypatch):
    toolkit.no_real_venv(monkeypatch, fail="pip")
    with pytest.raises(ToolError):
        install_through_hooks(tooled, pyshop.certipy, on_path=lambda n: None)
    assert log_lines(tooled.paths) == []


def test_joining_a_tool_another_box_installed_logs_an_install_for_this_box(tooled, shop, other):
    hand_to_other(tooled, other)
    tooled.box.tools = []
    save_box(tooled.box)
    both = {tooled.box.id: tooled.box.name, other.id: other.name}
    install_through_hooks(tooled, shop.entry, unfinished=both, on_path=lambda n: None)
    assert load_installed(tooled.paths)["kerbrute"].users == [other.id, tooled.box.id]
    assert log_lines(tooled.paths) == [logged("install", shop.entry)]


def test_finish_logs_each_tool_and_the_runtime_taken_off(tooled, pyshop, shop):
    put(tooled, pyshop.certipy)
    say(tooled, "y", "y")
    assert finish_box(tooled, **SAVED) is not None
    assert log_lines(tooled.paths) == [
        logged("finish", shop.entry),
        logged("finish", pyshop.certipy),
        logged("finish", pyshop.runtime, runtime=True),
    ]


def test_finish_logs_a_tool_another_box_keeps_but_not_its_runtime(tooled, pyshop, shop, other):
    put(tooled, pyshop.certipy)
    installed = load_installed(tooled.paths)
    installed["certipy"].users.append(other.id)  # both boxes use it
    toolstate.save_installed(tooled.paths, installed)
    toolhooks.undo(tooled)
    assert load_installed(tooled.paths)["certipy"].users == [other.id]
    assert runtime_row(tooled.paths) is not None
    assert log_lines(tooled.paths) == [
        logged("finish", shop.entry), logged("finish", pyshop.certipy),
    ]  # fmt: skip


def test_import_logs_each_tool_it_installs_again(tooled, pyshop, shop, tmp_path):
    put(tooled, pyshop.certipy)
    archive = export_box(tooled, fix=lambda p: 0)
    wipe_all(tooled)
    paths = fresh_paths(tooled, tmp_path)
    box = import_box(paths, tooled.settings, FakeConsole(["y"]), archive, lambda: NOW)
    at = NOW.isoformat()
    named = f"{box.name} ({box.id})"
    assert log_lines(paths) == [
        logged("install", shop.entry, box=named, at=at),
        logged("install", pyshop.runtime, box=named, at=at, runtime=True),
        logged("install", pyshop.certipy, box=named, at=at),
    ]
    # the log follows the home setting: the first home's log has none of this
    assert log_lines(tooled.paths) == []


def make_log_unwritable(session, how):
    log = session.paths.tool_log
    if how == "a folder in its place":
        log.mkdir(parents=True)
    elif how == "a read-only file":
        log.write_bytes(b"")
        log.chmod(0o400)
    else:  # a file where its folder should be; the install itself only uses the app's folder
        taken = session.paths.opt.parent / "taken"
        taken.write_text("not a folder")
        session.paths = AppPaths(opt=session.paths.opt, home=taken / "home")


UNWRITABLE = [
    "a folder in its place",
    pytest.param(
        "a read-only file",
        marks=pytest.mark.skipif(
            sys.platform == "win32" or os.geteuid() == 0, reason="needs POSIX modes, not root"
        ),
    ),
    "no folder for it",
]


@pytest.mark.parametrize("how", UNWRITABLE)
def test_a_log_that_cannot_be_written_warns_once_and_the_install_goes_on(tooled, pyshop, how):
    make_log_unwritable(tooled, how)
    install_through_hooks(tooled, pyshop.certipy, on_path=lambda n: None)
    install_through_hooks(tooled, pyshop.bloodhound, on_path=lambda n: None)
    warned = lines(tooled, "warn")
    assert len(warned) == 1
    log = str(tooled.paths.tool_log)
    assert warned[0].startswith(f"{log} could not be written: ")
    assert warned[0].count(log) == 1  # the path is named once
    assert {"certipy", "bloodhound", "python-3.13"} <= set(load_installed(tooled.paths))
    assert [t.name for t in current_tools(load_box(tooled.box.path))] == [
        "kerbrute", "certipy", "bloodhound",
    ]  # fmt: skip


def test_a_log_that_cannot_be_written_does_not_stop_finish(tooled, user):
    tooled.paths.tool_log.mkdir(parents=True)
    say(tooled, "y", "n")
    assert finish_box(tooled, **SAVED) is not None
    assert load_installed(tooled.paths) == {}
    assert sum("could not be written" in t for t in lines(tooled, "warn")) == 1
    assert lines(tooled, "fail") == []


def test_a_value_with_a_line_break_is_not_logged(tooled, pyshop):
    entry = replace(pyshop.certipy, sha256="ab\ncd")
    tool = load_installed(tooled.paths)["kerbrute"]
    toolhooks.log_tool(tooled, "install", replace(tool, sha256="ab\ncd"))
    toolhooks.log_tool(tooled, "install", entry)
    assert not tooled.paths.tool_log.exists()
    [warned] = lines(tooled, "warn")
    assert warned == f"{tooled.paths.tool_log} could not be written: 'ab\\ncd' holds a line break"


def test_finish_after_a_declined_reopen_logs_nothing(tooled):
    wipe(tooled)  # reopened, and the offer to install the tools again declined
    say(tooled, "y", "n")
    assert finish_box(tooled, **SAVED) is not None
    assert log_lines(tooled.paths) == []


def test_a_retried_finish_logs_each_tool_once(tooled, shop):
    toolhooks.undo(tooled)
    toolhooks.undo(tooled)
    assert log_lines(tooled.paths) == [logged("finish", shop.entry)]


def test_finish_logs_nothing_for_a_tool_only_another_box_holds(tooled, other):
    hand_to_other(tooled, other)
    toolhooks.undo(tooled)
    assert log_lines(tooled.paths) == []
    assert load_installed(tooled.paths)["kerbrute"].users == [other.id]


def test_reopening_keeps_when_the_tool_was_first_installed(tooled, pyshop):
    put(tooled, pyshop.certipy)
    first = {t.name: t.installed for t in tooled.box.tools}
    wipe_all(tooled)
    _z, newer = toolkit.make_runtime(pyshop_folder(tooled), build=2)
    toolkit.write_index(pyshop_folder(tooled), [*pyshop.entries, newer])
    tooled.clock = lambda: NOW + timedelta(days=2)
    say(tooled, "y")
    toolhooks.restore(tooled)
    rows = load_box(tooled.box.path).tools
    assert {t.name: t.installed for t in rows} == first
    [certipy] = [t for t in rows if t.name == "certipy"]
    assert certipy.runtime.build == 2  # the note says what it runs on now
    assert [line.split()[1] for line in log_lines(tooled.paths)] == ["install"] * 3
