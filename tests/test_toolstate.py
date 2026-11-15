import tomllib

import pytest
import tomli_w

from pwn_broker import toolstate
from pwn_broker.boxes import acquire_open, release_open
from pwn_broker.model import Box
from pwn_broker.store import save_box
from pwn_broker.toolpkg import ToolError
from pwn_broker.toolstate import (
    Installed,
    clear_open_box,
    load_installed,
    mark_path,
    open_box,
    orphans,
    running,
    save_installed,
    unfinished_boxes,
    unreadable_boxes,
    write_open_box,
)


def yes(pid):
    return True


def no(pid):
    return False


def item(name="nmap-x", users=None, home=None):
    return Installed(
        name=name,
        version="1.2",
        build=3,
        sha256="ab" * 32,
        folder=f"tools/{name}/1.2-3",
        commands=["a", "b"],
        uploads=["u.bin"],
        needs_root=True,
        users=users if users is not None else ["id-1"],
        home=home if home is not None else {".cache/x": False, ".config/y": True},
    )


def test_installed_round_trip(paths):
    data = {"one": item("one"), "two": item("two", users=[], home={})}
    save_installed(paths, data)
    assert load_installed(paths) == data


def test_installed_missing_file_is_empty(paths):
    assert load_installed(paths) == {}


def test_installed_unreadable_names_file(paths):
    paths.tools_state.parent.mkdir(parents=True)
    paths.tools_state.write_text("not [valid", encoding="utf-8")
    with pytest.raises(ToolError, match="installed.toml"):
        load_installed(paths)


def test_installed_bad_schema_duplicate_and_types(paths):
    paths.tools_state.parent.mkdir(parents=True)
    paths.tools_state.write_text("schema = 2\n", encoding="utf-8")
    with pytest.raises(ToolError, match="installed.toml"):
        load_installed(paths)
    save_installed(paths, {"a": item("a")})
    text = paths.tools_state.read_text(encoding="utf-8")
    body = text.split("[[tool]]", 1)[1]
    paths.tools_state.write_text(text + "[[tool]]" + body, encoding="utf-8")
    with pytest.raises(ToolError, match="installed.toml"):
        load_installed(paths)
    paths.tools_state.write_text(text.replace("build = 3", 'build = "3"'), encoding="utf-8")
    with pytest.raises(ToolError, match="installed.toml"):
        load_installed(paths)
    paths.tools_state.write_text(text.replace("build = 3", "build = true"), encoding="utf-8")
    with pytest.raises(ToolError, match="installed.toml"):
        load_installed(paths)


def test_installed_keeps_roots_answers_and_reads_a_file_without_them(paths):
    one = item("one")
    one.root_home = {".cache/x": True}
    save_installed(paths, {"one": one})
    assert load_installed(paths)["one"].root_home == {".cache/x": True}
    data = tomllib.loads(paths.tools_state.read_text(encoding="utf-8"))
    del data["tool"][0]["root_home"]
    paths.tools_state.write_text(tomli_w.dumps(data), encoding="utf-8")
    older = load_installed(paths)["one"]
    assert older.root_home == {} and older.home == one.home


@pytest.mark.parametrize("text", ["", "tool = []\n"])
def test_installed_without_a_schema_cannot_be_read(paths, text):
    paths.tools_state.parent.mkdir(parents=True)
    paths.tools_state.write_text(text, encoding="utf-8")
    with pytest.raises(ToolError) as err:
        load_installed(paths)
    assert str(err.value) == f"{paths.tools_state} cannot be read"


def test_installed_with_another_schema_says_to_upgrade(paths):
    paths.tools_state.parent.mkdir(parents=True)
    paths.tools_state.write_text("schema = 2\n", encoding="utf-8")
    with pytest.raises(ToolError, match="unsupported schema 2; upgrade pwn-broker"):
        load_installed(paths)


def test_orphans():
    data = {
        "a": item("a", users=["x"]),
        "b": item("b", users=[]),
        "c": item("c", users=["y", "z"]),
    }
    assert sorted(t.name for t in orphans(data, {"x"})) == ["b", "c"]
    assert sorted(t.name for t in orphans(data, set())) == ["a", "b", "c"]
    assert [t.name for t in orphans(data, {"x", "z"})] == ["b"]


def test_open_box_round_trip_and_format(paths, tmp_path):
    folder = tmp_path / "box folder"
    write_open_box(paths, folder, 42)
    raw = paths.run_box.read_bytes()
    lines = raw.decode().split("\n")
    assert raw.endswith(b"\n") and b"\r" not in raw
    assert lines[0] == folder.resolve().as_posix()
    assert lines[1] == "42"
    assert open_box(paths, alive=yes) == folder.resolve()


def test_open_box_dead_missing_malformed(paths, tmp_path):
    assert open_box(paths, alive=yes) is None
    write_open_box(paths, tmp_path, 42)
    assert open_box(paths, alive=no) is None
    for text in ("", "only-one-line\n", "/x\nabc\n", "/x\n0\n", "/x\n-3\n", "\n5\n"):
        paths.run_box.write_text(text, encoding="utf-8")
        assert open_box(paths, alive=yes) is None


def test_clear_open_box(paths, tmp_path):
    clear_open_box(paths, 1)
    write_open_box(paths, tmp_path, 42)
    clear_open_box(paths, 7)
    assert paths.run_box.exists()
    clear_open_box(paths, 42)
    assert not paths.run_box.exists()
    paths.run_box.write_text("garbage", encoding="utf-8")
    clear_open_box(paths, 42)
    assert paths.run_box.exists()


def test_acquire_and_release_write_and_clear(paths, box):
    acquire_open(paths, box, pid=100, alive=yes)
    assert open_box(paths, alive=yes) == box.path.resolve()
    release_open(paths, pid=100)
    assert not paths.run_box.exists()


def test_failed_acquire_leaves_run_box(paths, box, other):
    from pwn_broker.boxes import BoxError

    acquire_open(paths, box, pid=100, alive=yes)
    with pytest.raises(BoxError):
        acquire_open(paths, other, pid=200, alive=yes)
    assert open_box(paths, alive=yes) == box.path.resolve()


def test_release_by_other_pid_keeps_both_files(paths, box):
    acquire_open(paths, box, pid=100, alive=yes)
    release_open(paths, pid=200)
    assert paths.run_box.exists()
    assert (paths.run / "open.toml").exists()


def test_run_box_write_failure_does_not_block_open(paths, box, monkeypatch):
    def boom(*args):
        raise OSError("disk full")

    monkeypatch.setattr(toolstate, "write_open_box", boom)
    acquire_open(paths, box, pid=100, alive=yes)
    assert (paths.run / "open.toml").exists()
    release_open(paths, pid=100)
    assert not (paths.run / "open.toml").exists()


def test_running_markers(paths):
    folder = paths.run_tools
    assert running(paths, alive=yes) == []
    folder.mkdir(parents=True)
    (folder / "tool-a.20").write_text("", encoding="utf-8")
    (folder / "tool-a.3").write_text("", encoding="utf-8")
    (folder / "tool.b.v2.9").write_text("", encoding="utf-8")
    (folder / "dead.55").write_text("", encoding="utf-8")
    (folder / "junk.abc").write_text("", encoding="utf-8")
    (folder / "zero.0").write_text("", encoding="utf-8")
    (folder / "nodot").write_text("", encoding="utf-8")

    def alive(pid):
        return pid != 55

    assert running(paths, alive=alive) == [("tool-a", 3), ("tool-a", 20), ("tool.b.v2", 9)]
    assert not (folder / "dead.55").exists()
    assert not (folder / "junk.abc").exists()
    assert not (folder / "zero.0").exists()
    assert not (folder / "nodot").exists()
    assert running(paths, ["tool-a"], alive=alive) == [("tool-a", 3), ("tool-a", 20)]
    assert mark_path(paths, "tool-a", 3) == folder / "tool-a.3"


def test_running_ignores_undeletable_marker(paths, monkeypatch):
    paths.run_tools.mkdir(parents=True)
    (paths.run_tools / "dead.55").write_text("", encoding="utf-8")
    from pathlib import Path

    def boom(self, missing_ok=False):
        raise OSError("busy")

    monkeypatch.setattr(Path, "unlink", boom)
    assert running(paths, alive=no) == []


def test_unfinished_boxes(paths, box, other):
    other.status = "finished"
    save_box(other)
    broken = paths.active / "broken"
    broken.mkdir()
    (broken / "box.toml").write_text("nope [", encoding="utf-8")
    assert unfinished_boxes(paths) == {box.id: box.name}
    assert isinstance(box, Box)


def test_write_open_box_refuses_newline_in_folder(paths, tmp_path):
    write_open_box(paths, tmp_path, 42)
    with pytest.raises(OSError, match="line break"):
        write_open_box(paths, tmp_path / "a\nb", 42)
    assert not paths.run_box.exists()
    with pytest.raises(OSError):
        write_open_box(paths, tmp_path / "a\rb", 42)


def test_failed_write_in_acquire_removes_old_run_box(paths, box, monkeypatch, tmp_path):
    write_open_box(paths, tmp_path, 9)

    def boom(*args):
        raise OSError("no")

    monkeypatch.setattr(toolstate, "write_open_box", boom)
    acquire_open(paths, box, pid=100, alive=yes)
    assert not paths.run_box.exists()
    assert (paths.run / "open.toml").exists()


def test_open_box_rejects_forms_the_writer_never_makes(paths):
    paths.run.mkdir(parents=True)
    for text in ("/x\n 5\n", "/x\n5 \n", "/x\r\n5\r\n", "/x\r\n5\n", "/x\n５\n"):
        paths.run_box.write_text(text, encoding="utf-8", newline="")
        assert open_box(paths, alive=yes) is None
    paths.run_box.write_text("/x\n5\n", encoding="utf-8", newline="")
    assert open_box(paths, alive=yes).as_posix() == "/x"


def _marker(paths, name, content):
    paths.run_tools.mkdir(parents=True, exist_ok=True)
    path = paths.run_tools / name
    path.write_text(content, encoding="utf-8")
    return path


def test_running_start_time_match_is_reported(paths):
    _marker(paths, "t.5", "777\n")
    assert running(paths, alive=yes, started=lambda pid: "777") == [("t", 5)]


def test_running_start_time_mismatch_is_stale(paths):
    path = _marker(paths, "t.5", "777")
    assert running(paths, alive=yes, started=lambda pid: "999") == []
    assert not path.exists()


def test_running_empty_marker_or_unknown_start_falls_back_to_liveness(paths):
    _marker(paths, "a.5", "")
    _marker(paths, "b.6", "123")
    assert running(paths, alive=yes, started=lambda pid: "1" if pid == 5 else None) == [
        ("a", 5),
        ("b", 6),
    ]


def test_parse_start_time():
    rest = ["S"] + [str(n) for n in range(1, 19)] + ["424242", "0", "0"]
    line = "1234 (my (odd) name) " + " ".join(rest) + "\n"
    assert toolstate.parse_start_time(line) == "424242"
    assert toolstate.parse_start_time("1234 no parens here") is None
    assert toolstate.parse_start_time("1234 (x) S 1 2") is None
    assert toolstate.parse_start_time("") is None


def test_process_start_is_none_for_missing_process():
    assert toolstate.process_start(2**22 + 12345) is None


def test_unreadable_boxes_names_the_folders_that_cannot_be_loaded(paths, box):
    assert unreadable_boxes(paths) == []
    broken = paths.active / "broken"
    broken.mkdir()
    (broken / "box.toml").write_text("nope [", encoding="utf-8")
    [problem] = unreadable_boxes(paths)
    assert problem.startswith("broken: ")


def test_holding_boxes_drops_the_box_being_released(paths, box, other):
    found = toolstate.holding_boxes(paths, {}, excluding=box.id)
    assert found == {other.id: other.name}


def test_holding_boxes_keeps_every_unknown_user_while_a_box_cannot_be_read(paths, box, other):
    (paths.active / "broken").mkdir()
    (paths.active / "broken" / "box.toml").write_text("nope [", encoding="utf-8")
    ghost = item("ghost", users=["gone-box", box.id])
    found = toolstate.holding_boxes(paths, {"ghost": ghost}, excluding=box.id)
    assert found == {other.id: other.name, "gone-box": "a box that cannot be read"}
