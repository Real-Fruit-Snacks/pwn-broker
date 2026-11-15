import os
import sys
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


def write(path: Path, text: str = "x") -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")
    return path


# homes


@pytest.fixture
def on_linux(monkeypatch):
    monkeypatch.setattr(tooldata.sys, "platform", "linux")


def test_homes_adds_a_different_readable_root_home(home, root_home, on_linux):
    assert tooldata.homes(home, root_home=root_home) == [home, root_home]


def test_homes_is_just_home_when_both_are_the_same(home, on_linux):
    assert tooldata.homes(home, root_home=home) == [home]


def test_homes_skips_a_missing_root_home(home, tmp_path, on_linux):
    assert tooldata.homes(home, root_home=tmp_path / "nope") == [home]


def test_homes_skips_an_unreadable_root_home(home, root_home, monkeypatch, on_linux):
    monkeypatch.setattr(tooldata.os, "access", lambda path, mode: False)
    assert tooldata.homes(home, root_home=root_home) == [home]


def test_homes_on_windows_is_just_home(home, root_home, monkeypatch):
    monkeypatch.setattr(tooldata.sys, "platform", "win32")
    assert tooldata.homes(home, root_home=root_home) == [home]


# collect


def test_collect_copies_a_file_and_a_folder(tmp_path, home):
    box = make_box(tmp_path)
    write(home / ".burp.cfg", "cfg")
    write(home / ".config" / "burp" / "a.txt", "a")
    write(home / ".config" / "burp" / "sub" / "b.txt", "b")
    item = make_item(home={".burp.cfg": False, ".config/burp": False})
    copied = tooldata.collect(box, item, [home])
    assert copied == [
        "tooldata/burp/home/.burp.cfg",
        "tooldata/burp/home/.config/burp",
    ]
    base = box.path / "tooldata" / "burp" / "home"
    assert (base / ".burp.cfg").read_text() == "cfg"
    assert (base / ".config" / "burp" / "a.txt").read_text() == "a"
    assert (base / ".config" / "burp" / "sub" / "b.txt").read_text() == "b"


def test_collect_replaces_an_earlier_copy(tmp_path, home):
    box = make_box(tmp_path)
    write(home / "d" / "new.txt", "new")
    old = write(box.path / "tooldata" / "burp" / "home" / "d" / "old.txt", "old")
    tooldata.collect(box, make_item(home={"d": False}), [home])
    assert not old.exists()
    assert (box.path / "tooldata" / "burp" / "home" / "d" / "new.txt").exists()


def test_collect_replaces_an_earlier_file_copy(tmp_path, home):
    box = make_box(tmp_path)
    write(home / "f", "new")
    write(box.path / "tooldata" / "burp" / "home" / "f", "old")
    tooldata.collect(box, make_item(home={"f": False}), [home])
    assert (box.path / "tooldata" / "burp" / "home" / "f").read_text() == "new"


def test_collect_leaves_alone_what_existed_before_or_is_unlisted(tmp_path, home):
    box = make_box(tmp_path)
    write(home / "before", "1")
    write(home / "unlisted", "2")
    write(home / "new", "3")
    item = make_item(home={"before": True, "new": False})
    assert tooldata.collect(box, item, [home]) == ["tooldata/burp/home/new"]
    assert not (box.path / "tooldata" / "burp" / "home" / "before").exists()
    assert not (box.path / "tooldata" / "burp" / "home" / "unlisted").exists()


def test_collect_skips_missing_paths(tmp_path, home):
    box = make_box(tmp_path)
    assert tooldata.collect(box, make_item(home={"gone": False}), [home]) == []


def test_collect_keeps_the_two_homes_apart(tmp_path, home, root_home):
    box = make_box(tmp_path)
    write(home / "cfg", "user")
    write(root_home / "cfg", "root")
    copied = tooldata.collect(box, make_item(home={"cfg": False}), [home, root_home])
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
    copied = tooldata.collect(box, item, [home])
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
    tooldata.collect(box, make_item(home={"d": False}), [home])
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
    assert tooldata.collect(box, item, [home]) == []


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
    got = tooldata.to_delete(make_item(home={"a": False}), [home, root_home], False)
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
