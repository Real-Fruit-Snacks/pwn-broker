import sys
import tarfile
from dataclasses import replace
from types import SimpleNamespace

import pytest

import toolkit
from helpers import NOW
from pwn_broker import lifecycle, toolhooks, toolinstall, toolstate
from pwn_broker.archive import archive_path
from pwn_broker.console import FakeConsole
from pwn_broker.lifecycle import export_box, finish_box, import_box
from pwn_broker.model import ToolRecord
from pwn_broker.paths import AppPaths
from pwn_broker.store import load_box, save_box
from pwn_broker.toolpkg import ToolError
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


# ---- review fixes


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
