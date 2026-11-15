import errno
import os
import sys
from datetime import timedelta
from pathlib import Path

import pytest

from pwn_broker import tooldata
from pwn_broker.model import Box
from pwn_broker.toolpkg import ToolError
from pwn_broker.toolstate import Installed
from tests.helpers import NOW

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="needs symlinks")


def make_item(**overrides) -> Installed:
    values = dict(
        name="burp", version="1", build=1, sha256="0" * 64, folder="/opt/x",
        commands=["burp"], uploads=[], needs_root=False, users=[], home={},
    )  # fmt: skip
    values.update(overrides)
    return Installed(**values)


def make_box(tmp_path: Path) -> Box:
    folder = tmp_path / "box"
    folder.mkdir()
    return Box(
        id="1", name="forest", platform="htb", os="linux", difficulty="easy",
        status="active", started=NOW, finished=None, last_target=None, flags={},
        path=folder,
    )  # fmt: skip


@pytest.fixture
def home(tmp_path):
    folder = tmp_path / "home"
    folder.mkdir()
    return folder


@pytest.fixture
def root_home(tmp_path):
    folder = tmp_path / "rootdir"
    folder.mkdir()
    return folder


def collect(box, item, homes, installed=NOW):
    return [c.dest for c in tooldata.collect(box, item, homes, installed)]


def write(path: Path, text: str = "x") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# homes


@pytest.fixture
def on_linux(monkeypatch):
    monkeypatch.setattr(tooldata, "_posix", lambda: True)


def test_homes_adds_a_different_readable_root_home(home, root_home, on_linux):
    assert tooldata.homes(home, root_home=root_home) == [home, root_home]


def test_homes_is_just_home_when_both_are_the_same(home, on_linux):
    assert tooldata.homes(home, root_home=home) == [home]


def test_homes_skips_a_missing_root_home(home, tmp_path, on_linux):
    assert tooldata.homes(home, root_home=tmp_path / "nope") == [home]


def test_homes_skips_a_root_home_that_is_not_absolute(home, tmp_path, monkeypatch, on_linux):
    # with no root account, "~root" comes back unexpanded and would resolve against the cwd
    monkeypatch.chdir(tmp_path)
    (tmp_path / "~root").mkdir()
    assert tooldata.homes(home, root_home=Path("~root")) == [home]


def test_homes_skips_an_unreadable_root_home(home, root_home, monkeypatch, on_linux):
    monkeypatch.setattr(tooldata.os, "access", lambda path, mode: False)
    assert tooldata.homes(home, root_home=root_home) == [home]


def test_homes_on_windows_is_just_home(home, root_home, monkeypatch):
    monkeypatch.setattr(tooldata, "_posix", lambda: False)
    assert tooldata.homes(home, root_home=root_home) == [home]


# collect


def test_collect_copies_a_file_and_a_folder(tmp_path, home):
    box = make_box(tmp_path)
    write(home / ".burp.cfg", "cfg")
    write(home / ".config" / "burp" / "a.txt", "a")
    write(home / ".config" / "burp" / "sub" / "b.txt", "b")
    item = make_item(home={".burp.cfg": False, ".config/burp": False})
    copied = collect(box, item, [home])
    assert copied == [
        "tooldata/burp/home/.burp.cfg",
        "tooldata/burp/home/.config/burp",
    ]
    base = box.path / "tooldata" / "burp" / "home"
    assert (base / ".burp.cfg").read_text() == "cfg"
    assert (base / ".config" / "burp" / "a.txt").read_text() == "a"
    assert (base / ".config" / "burp" / "sub" / "b.txt").read_text() == "b"


LATER = NOW + timedelta(days=2)


def test_collect_keeps_a_copy_from_an_earlier_install(tmp_path, home):
    # export on one VM, import on another, install again, finish: both runs stay in the box
    box = make_box(tmp_path)
    item = make_item(home={"d": False})
    write(home / "d" / "first.txt", "first")
    collect(box, item, [home], NOW)
    (home / "d" / "first.txt").unlink()
    write(home / "d" / "second.txt", "second")
    assert collect(box, item, [home], LATER) == ["tooldata/burp/home/d"]
    base = box.path / "tooldata" / "burp"
    assert (base / "home-1" / "d" / "first.txt").read_text() == "first"
    assert (base / "home" / "d" / "second.txt").read_text() == "second"
    assert not (base / "home" / "d" / "first.txt").exists()
    assert (base / ".install").read_text(encoding="utf-8") == LATER.isoformat()


def test_collect_keeps_a_copy_with_no_stamp_and_takes_the_next_free_number(tmp_path, home):
    box = make_box(tmp_path)
    base = box.path / "tooldata" / "burp"
    write(base / "home" / "f", "unstamped")
    write(base / "home-1" / "f", "older")
    write(base / "home-root" / "f", "root")
    write(home / "f", "new")
    collect(box, make_item(home={"f": False}), [home])
    assert (base / "home-1" / "f").read_text() == "older"
    assert (base / "home-2" / "f").read_text() == "unstamped"
    assert (base / "home-root-1" / "f").read_text() == "root"
    assert not (base / "home-root").exists()
    assert (base / "home" / "f").read_text() == "new"
    assert (base / ".install").read_text(encoding="utf-8") == NOW.isoformat()


def test_two_collects_in_one_install_leave_one_copy_with_the_latest_files(tmp_path, home):
    box = make_box(tmp_path)
    item = make_item(home={"d": False, "f": False})
    write(home / "d" / "old.txt", "old")
    write(home / "f", "one")
    collect(box, item, [home])
    (home / "d" / "old.txt").unlink()
    write(home / "d" / "new.txt", "new")
    write(home / "f", "two")
    collect(box, item, [home])
    base = box.path / "tooldata" / "burp"
    assert sorted(p.name for p in base.iterdir()) == [".install", "home"]
    assert sorted(p.name for p in (base / "home" / "d").iterdir()) == ["new.txt"]
    assert (base / "home" / "f").read_text() == "two"
    assert sorted(p.name for p in (base / "home").iterdir()) == ["d", "f"]


def test_a_partial_second_copy_leaves_the_first_in_place(tmp_path, home, monkeypatch):
    box = make_box(tmp_path)
    item = make_item(home={"d": False})
    write(home / "d" / "a.txt", "a1")
    write(home / "d" / "b.txt", "b1")
    assert [c.full for c in tooldata.collect(box, item, [home], NOW)] == [True]
    write(home / "d" / "a.txt", "a2")
    write(home / "d" / "b.txt", "b2")
    real = tooldata.shutil.copy2

    def flaky(src, dst, **kw):
        if Path(src).name == "b.txt":
            raise PermissionError("denied")
        return real(src, dst, **kw)

    monkeypatch.setattr(tooldata.shutil, "copy2", flaky)
    again = tooldata.collect(box, item, [home], NOW)
    assert [(c.dest, c.full) for c in again] == [("tooldata/burp/home/d", False)]
    base = box.path / "tooldata" / "burp" / "home" / "d"
    assert (base / "a.txt").read_text() == "a1" and (base / "b.txt").read_text() == "b1"
    assert sorted(p.name for p in base.parent.iterdir()) == ["d"]


def test_collect_says_which_entries_were_copied_in_full(tmp_path, home, monkeypatch):
    box = make_box(tmp_path)
    write(home / "d" / "bad.txt", "bad")
    write(home / "d" / "good.txt", "good")
    write(home / "f", "f")
    real = tooldata.shutil.copy2

    def flaky(src, dst, **kw):
        if Path(src).name == "bad.txt":
            raise PermissionError("denied")
        return real(src, dst, **kw)

    monkeypatch.setattr(tooldata.shutil, "copy2", flaky)
    got = tooldata.collect(box, make_item(home={"d": False, "f": False}), [home], NOW)
    assert [(c.source, c.dest, c.full) for c in got] == [
        (home / "d", "tooldata/burp/home/d", False),
        (home / "f", "tooldata/burp/home/f", True),
    ]


def test_an_unlistable_subfolder_means_not_full(tmp_path, home, monkeypatch):
    box = make_box(tmp_path)
    write(home / "d" / "sub" / "f", "x")
    write(home / "d" / "ok", "y")
    real = os.scandir

    def deny(path):
        if Path(path).name == "sub":
            raise PermissionError("denied")
        return real(path)

    monkeypatch.setattr(tooldata.os, "scandir", deny)
    assert [c.full for c in tooldata.collect(box, make_item(home={"d": False}), [home], NOW)] == [
        False
    ]


@posix_only
def test_a_link_inside_a_folder_means_not_full(tmp_path, home):
    box = make_box(tmp_path)
    write(home / "d" / "real.txt", "r")
    (home / "d" / "link.txt").symlink_to(home / "d" / "real.txt")
    assert [c.full for c in tooldata.collect(box, make_item(home={"d": False}), [home], NOW)] == [
        False
    ]


def test_collect_leaves_no_temporary_copy_after_running_out_of_space(tmp_path, home, monkeypatch):
    box = make_box(tmp_path)
    write(home / "d" / "a", "a")

    def full(src, dst, **kw):
        raise OSError(errno.ENOSPC, "no space")

    monkeypatch.setattr(tooldata.shutil, "copy2", full)
    with pytest.raises(ToolError):
        collect(box, make_item(home={"d": False}), [home])
    assert sorted(p.name for p in (box.path / "tooldata" / "burp" / "home").iterdir()) == []


# root's home


def test_collect_uses_roots_own_answers_for_roots_home(tmp_path, home, root_home):
    box = make_box(tmp_path)
    for folder in (home, root_home):
        write(folder / "was", "w")
        write(folder / "new", "n")
        write(folder / "unasked", "u")
    item = make_item(
        home={"was": False, "new": False, "unasked": False},
        root_home={"was": True, "new": False},
    )
    assert collect(box, item, [home, root_home]) == [
        "tooldata/burp/home-root/new",
        "tooldata/burp/home-root/unasked",
        "tooldata/burp/home/new",
        "tooldata/burp/home/unasked",
        "tooldata/burp/home/was",
    ]


def test_to_delete_and_kept_use_roots_own_answers(home, root_home):
    for folder in (home, root_home):
        for name in ("was", "new", "unasked"):
            write(folder / name)
    item = make_item(
        home={"was": False, "new": False, "unasked": False},
        root_home={"was": True, "new": False},
    )
    assert tooldata.to_delete(item, [home, root_home], False) == sorted(
        [home / "was", home / "new", home / "unasked", root_home / "new"]
    )
    # with no answer recorded for root's home, its copy counts as having been there before
    assert tooldata.kept(item, [home, root_home]) == sorted([root_home / "was", root_home / "unasked"])


def test_root_unchecked_only_for_a_different_unreadable_root_home(home, root_home, tmp_path, monkeypatch, on_linux):
    assert tooldata.root_unchecked(home, root_home=root_home) is False
    assert tooldata.root_unchecked(home, root_home=home) is False
    assert tooldata.root_unchecked(home, root_home=tmp_path / "nope") is False
    monkeypatch.setattr(tooldata.os, "access", lambda path, mode: False)
    assert tooldata.root_unchecked(home, root_home=root_home) is True
    assert tooldata.root_unchecked(home, root_home=home) is False


def test_root_unchecked_is_false_on_windows(home, root_home, monkeypatch):
    monkeypatch.setattr(tooldata, "_posix", lambda: False)
    monkeypatch.setattr(tooldata.os, "access", lambda path, mode: False)
    assert tooldata.root_unchecked(home, root_home=root_home) is False


def test_roots_home_is_looked_up_not_assumed(home, root_home, monkeypatch, on_linux):
    monkeypatch.setattr(tooldata, "_root_home", lambda: root_home)
    assert tooldata.homes(home) == [home, root_home]


def test_collect_leaves_alone_what_existed_before_or_is_unlisted(tmp_path, home):
    box = make_box(tmp_path)
    write(home / "before", "1")
    write(home / "unlisted", "2")
    write(home / "new", "3")
    item = make_item(home={"before": True, "new": False})
    assert collect(box, item, [home]) == ["tooldata/burp/home/new"]
    assert not (box.path / "tooldata" / "burp" / "home" / "before").exists()
    assert not (box.path / "tooldata" / "burp" / "home" / "unlisted").exists()


def test_collect_skips_missing_paths(tmp_path, home):
    box = make_box(tmp_path)
    assert collect(box, make_item(home={"gone": False}), [home]) == []


def test_collect_keeps_the_two_homes_apart(tmp_path, home, root_home):
    box = make_box(tmp_path)
    write(home / "cfg", "user")
    write(root_home / "cfg", "root")
    copied = collect(box, make_item(home={"cfg": False}), [home, root_home])
    assert copied == ["tooldata/burp/home-root/cfg", "tooldata/burp/home/cfg"]
    base = box.path / "tooldata" / "burp"
    assert (base / "home" / "cfg").read_text() == "user"
    assert (base / "home-root" / "cfg").read_text() == "root"


def test_collect_survives_an_unreadable_file(tmp_path, home, monkeypatch):
    box = make_box(tmp_path)
    write(home / "d" / "bad.txt", "bad")
    write(home / "d" / "good.txt", "good")
    write(home / "other", "o")
    real = tooldata.shutil.copy2

    def flaky(src, dst, **kw):
        if Path(src).name in ("bad.txt", "other"):
            raise PermissionError("denied")
        return real(src, dst, **kw)

    monkeypatch.setattr(tooldata.shutil, "copy2", flaky)
    item = make_item(home={"d": False, "other": False})
    copied = collect(box, item, [home])
    assert copied == ["tooldata/burp/home/d"]
    base = box.path / "tooldata" / "burp" / "home"
    assert (base / "d" / "good.txt").read_text() == "good"
    assert not (base / "d" / "bad.txt").exists()


@posix_only
def test_collect_skips_symlinks_inside_a_folder_and_special_files(tmp_path, home):
    box = make_box(tmp_path)
    secret = write(tmp_path / "secret.txt", "secret")
    write(home / "d" / "real.txt", "r")
    (home / "d" / "link.txt").symlink_to(secret)
    (home / "d" / "linkdir").symlink_to(tmp_path)
    os.mkfifo(home / "d" / "pipe")
    collect(box, make_item(home={"d": False}), [home])
    copied = box.path / "tooldata" / "burp" / "home" / "d"
    assert sorted(p.name for p in copied.iterdir()) == ["real.txt"]


@posix_only
def test_collect_skips_a_symlink_entry_and_one_below_a_symlink(tmp_path, home):
    box = make_box(tmp_path)
    outside = tmp_path / "outside"
    write(outside / "inner.txt", "i")
    (home / "link").symlink_to(outside)
    (home / "filelink").symlink_to(outside / "inner.txt")
    item = make_item(home={"link": False, "link/inner.txt": False, "filelink": False})
    assert collect(box, item, [home]) == []


# to_delete and kept


def test_to_delete_lists_new_existing_paths_sorted(home):
    write(home / "b")
    write(home / "a")
    write(home / "old")
    item = make_item(home={"b": False, "a": False, "old": True, "missing": False})
    assert tooldata.to_delete(item, [home], False) == [home / "a", home / "b"]


def test_to_delete_is_empty_when_others_use_the_tool(home):
    write(home / "a")
    assert tooldata.to_delete(make_item(home={"a": False}), [home], True) == []


def test_to_delete_ignores_unlisted_entries(home):
    write(home / "a")
    assert tooldata.to_delete(make_item(home={}), [home], False) == []


def test_to_delete_covers_both_homes(home, root_home):
    write(home / "a")
    write(root_home / "a")
    item = make_item(home={"a": False}, root_home={"a": False})
    got = tooldata.to_delete(item, [home, root_home], False)
    assert got == sorted([home / "a", root_home / "a"])


@posix_only
def test_to_delete_skips_symlinks_and_paths_below_them(tmp_path, home):
    outside = tmp_path / "outside"
    write(outside / "inner.txt")
    (home / "link").symlink_to(outside)
    (home / "filelink").symlink_to(outside / "inner.txt")
    item = make_item(home={"link": False, "link/inner.txt": False, "filelink": False})
    assert tooldata.to_delete(item, [home], False) == []


def test_kept_lists_existing_paths_marked_as_before(home, root_home):
    write(home / "b")
    write(root_home / "a")
    write(home / "new")
    item = make_item(home={"b": True, "a": True, "new": False, "gone": True})
    assert tooldata.kept(item, [home, root_home]) == sorted([home / "b", root_home / "a"])


# delete


def test_delete_removes_files_and_folders(home):
    f = write(home / "f")
    d = write(home / "d" / "x" / "y.txt").parent.parent
    keep = write(home / "keep")
    tooldata.delete([f, d], [home])
    assert not f.exists() and not d.exists()
    assert keep.exists()


def test_delete_skips_a_path_that_is_already_gone(home):
    f = write(home / "f")
    tooldata.delete([home / "gone", f], [home])
    assert not f.exists()


def test_delete_refuses_a_path_outside_every_home(tmp_path, home):
    outside = write(tmp_path / "outside.txt")
    inside = write(home / "inside")
    with pytest.raises(ToolError):
        tooldata.delete([inside, outside], [home])
    assert outside.exists() and inside.exists()  # nothing was deleted


def test_delete_refuses_a_sibling_with_the_same_prefix(tmp_path, home):
    sibling = write(tmp_path / "home2" / "f")
    with pytest.raises(ToolError):
        tooldata.delete([sibling], [home])
    assert sibling.exists()


def test_delete_refuses_a_home_folder_itself(home, root_home):
    with pytest.raises(ToolError):
        tooldata.delete([root_home], [home, root_home])
    assert root_home.exists()


def test_delete_refuses_dot_dot_paths(tmp_path, home):
    victim = write(tmp_path / "victim.txt")
    write(home / "sub" / "f")
    with pytest.raises(ToolError):
        tooldata.delete([home / "sub" / ".." / ".." / "victim.txt"], [home])
    with pytest.raises(ToolError):
        tooldata.delete([home / "sub" / ".." / "sub" / "f"], [home])
    assert victim.exists()
    assert (home / "sub" / "f").exists()


def test_delete_accepts_a_path_in_the_second_home(home, root_home):
    f = write(root_home / "f")
    tooldata.delete([f], [home, root_home])
    assert not f.exists()


@posix_only
def test_delete_refuses_symlinks_and_paths_below_them(tmp_path, home):
    outside = tmp_path / "outside"
    inner = write(outside / "inner.txt")
    (home / "link").symlink_to(outside)
    (home / "filelink").symlink_to(inner)
    for bad in (home / "link", home / "link" / "inner.txt", home / "filelink"):
        with pytest.raises(ToolError):
            tooldata.delete([bad], [home])
    assert inner.exists()


# hardening

BAD_ENTRIES = ["", ".", "..", "a/../../b", "a/./b", "/abs", "a//b", "a\b", "C:/x", "../x"]


@pytest.mark.parametrize("entry", BAD_ENTRIES)
def test_bad_entries_touch_nothing(tmp_path, home, entry):
    box = make_box(tmp_path)
    write(home / "a" / "f", "1")
    sentinel = write(box.path / "tooldata" / "burp" / "home-root" / "s", "s")
    sentinel2 = write(box.path / "root.txt", "r")
    outside = write(tmp_path / "b", "b")
    item = make_item(home={entry: False})
    assert collect(box, item, [home]) == []
    assert tooldata.to_delete(item, [home], False) == []
    assert tooldata.kept(make_item(home={entry: True}), [home]) == []
    assert sentinel.exists() and sentinel2.exists() and outside.exists()
    assert (home / "a" / "f").exists()


@pytest.mark.parametrize("name", ["", "..", "../x", "a/b", "/abs", "A B"])
def test_bad_tool_name(tmp_path, home, name):
    box = make_box(tmp_path)
    write(home / "f")
    item = make_item(name=name, home={"f": False})
    with pytest.raises(ToolError):
        collect(box, item, [home])
    assert tooldata.to_delete(item, [home], False) == []
    assert tooldata.kept(make_item(name=name, home={"f": True}), [home]) == []
    assert sorted(p.name for p in tmp_path.iterdir()) == ["box", "home"]


def linked_box(tmp_path, home, link):
    box = make_box(tmp_path)
    write(home / "d" / "f", "new")
    target = tmp_path / "target"
    victims = [
        write(target / "d" / "keep.txt", "keep"),
        write(target / "burp" / "home" / "d" / "keep.txt", "keep"),
    ]
    parts = link.split("/")
    if link == "dest":
        (box.path / "tooldata" / "burp" / "home").mkdir(parents=True)
        (box.path / "tooldata" / "burp" / "home" / "d").symlink_to(target / "d")
    else:
        if len(parts) > 1:
            (box.path / Path(*parts[:-1])).mkdir(parents=True)
        (box.path / Path(*parts)).symlink_to(target, target_is_directory=True)
    return box, target, victims


@posix_only
@pytest.mark.parametrize("link", ["tooldata", "tooldata/burp"])
def test_collect_refuses_a_linked_destination(tmp_path, home, link):
    box, target, victims = linked_box(tmp_path, home, link)
    with pytest.raises(ToolError):
        collect(box, make_item(home={"d": False}), [home])
    assert [v.read_text() for v in victims] == ["keep", "keep"]
    assert not (target / "d" / "f").exists()


@posix_only
@pytest.mark.parametrize("link", ["tooldata/burp/home", "dest"])
def test_collect_refuses_a_link_in_this_installs_copy(tmp_path, home, link):
    box, target, victims = linked_box(tmp_path, home, link)
    # the stamp says the copy in the box is this install's, so it would be written into
    write(box.path / "tooldata" / "burp" / tooldata.STAMP, NOW.isoformat())
    with pytest.raises(ToolError):
        collect(box, make_item(home={"d": False}), [home])
    assert [v.read_text() for v in victims] == ["keep", "keep"]
    assert not (target / "d" / "f").exists()


@posix_only
@pytest.mark.parametrize("link", ["tooldata/burp/home", "dest"])
def test_collect_moves_a_linked_earlier_copy_aside_without_following_it(tmp_path, home, link):
    box, target, victims = linked_box(tmp_path, home, link)
    # no stamp: what is in the box is an earlier install's, kept under a new name
    assert collect(box, make_item(home={"d": False}), [home]) == ["tooldata/burp/home/d"]
    tool_root = box.path / "tooldata" / "burp"
    assert os.path.lexists(tool_root / "home-1")
    assert not (tool_root / "home").is_symlink() and not (tool_root / "home" / "d").is_symlink()
    assert (tool_root / "home" / "d" / "f").read_text() == "new"
    assert [v.read_text() for v in victims] == ["keep", "keep"]
    assert not (target / "d" / "f").exists()


def test_enospc_stops_collect_and_leaves_no_partial_file(tmp_path, home, monkeypatch):
    box = make_box(tmp_path)
    write(home / "a", "a")
    write(home / "b", "b")

    def full(src, dst, **kw):
        Path(dst).write_text("par")
        raise OSError(errno.ENOSPC, "no space")

    monkeypatch.setattr(tooldata.shutil, "copy2", full)
    with pytest.raises(ToolError):
        collect(box, make_item(home={"a": False, "b": False}), [home])
    base = box.path / "tooldata" / "burp" / "home"
    assert not (base / "a").exists() and not (base / "b").exists()


def test_other_oserror_removes_partial_file_and_does_not_report_it(tmp_path, home, monkeypatch):
    box = make_box(tmp_path)
    write(home / "a", "a")
    write(home / "b", "b")
    real = tooldata.shutil.copy2

    def flaky(src, dst, **kw):
        if Path(src).name == "a":
            Path(dst).write_text("par")
            raise OSError(errno.EIO, "io")
        return real(src, dst, **kw)

    monkeypatch.setattr(tooldata.shutil, "copy2", flaky)
    copied = collect(box, make_item(home={"a": False, "b": False}), [home])
    assert copied == ["tooldata/burp/home/b"]
    assert not (box.path / "tooldata" / "burp" / "home" / "a").exists()


def test_unlistable_folder_is_not_created_or_reported(tmp_path, home, monkeypatch):
    box = make_box(tmp_path)
    write(home / "d" / "f", "x")
    real = os.scandir

    def deny(path):
        if Path(path).name == "d":
            raise PermissionError("denied")
        return real(path)

    monkeypatch.setattr(tooldata.os, "scandir", deny)
    assert collect(box, make_item(home={"d": False}), [home]) == []
    assert not (box.path / "tooldata" / "burp" / "home" / "d").exists()


def test_unlistable_subfolder_is_not_created(tmp_path, home, monkeypatch):
    box = make_box(tmp_path)
    write(home / "d" / "sub" / "f", "x")
    write(home / "d" / "ok", "y")
    real = os.scandir

    def deny(path):
        if Path(path).name == "sub":
            raise PermissionError("denied")
        return real(path)

    monkeypatch.setattr(tooldata.os, "scandir", deny)
    assert collect(box, make_item(home={"d": False}), [home]) == ["tooldata/burp/home/d"]
    base = box.path / "tooldata" / "burp" / "home" / "d"
    assert (base / "ok").exists() and not (base / "sub").exists()


def test_depth_limit(tmp_path, home, monkeypatch):
    box = make_box(tmp_path)
    write(home / "d" / "a" / "b" / "c" / "f", "x")
    monkeypatch.setattr(tooldata, "_MAX_DEPTH", 2)
    with pytest.raises(ToolError):
        collect(box, make_item(home={"d": False}), [home])
    monkeypatch.setattr(tooldata, "_MAX_DEPTH", 3)
    assert collect(box, make_item(home={"d": False}), [home])


def test_nested_homes_are_dropped(tmp_path, home, on_linux):
    inner = home / "inner"
    inner.mkdir()
    assert tooldata.homes(home, root_home=inner) == [home]
    assert tooldata.homes(inner, root_home=home) == [inner]


def test_delete_rechecks_before_each_removal(tmp_path, home, monkeypatch):
    first = write(home / "one")
    second = write(home / "two")
    real = tooldata._inside
    calls = []

    def flaky(path, folder):
        calls.append(path)
        if len(calls) > 3:  # passes both first-loop checks and the first recheck
            return False
        return real(path, folder)

    monkeypatch.setattr(tooldata, "_inside", flaky)
    with pytest.raises(ToolError):
        tooldata.delete([first, second], [home])
    assert not first.exists()
    assert second.exists()


def test_delete_oserror_becomes_toolerror(home, monkeypatch):
    f = write(home / "f")

    def boom(self, *a, **k):
        raise PermissionError("denied")

    monkeypatch.setattr(Path, "unlink", boom)
    with pytest.raises(ToolError, match="f"):
        tooldata.delete([f], [home])


@posix_only
def test_rmtree_removes_a_link_inside_a_folder_not_its_target(tmp_path, home):
    outside = write(tmp_path / "outside" / "keep.txt", "keep")
    d = home / "d"
    d.mkdir()
    (d / "link").symlink_to(outside.parent, target_is_directory=True)
    tooldata.delete([d], [home])
    assert not d.exists()
    assert outside.read_text() == "keep"
