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


def notes_item(name, root, users):
    found = item(name, users=users, home={})
    found.commands, found.uploads, found.needs_root = [], [], False
    found.notes = root.as_posix()
    return found


def test_notes_survive_the_installed_list(paths, tmp_path):
    data = {"playbooks": notes_item("playbooks", tmp_path / "root", ["id-1"]), "nmap-x": item()}
    save_installed(paths, data)
    assert load_installed(paths) == data
    rows = tomllib.loads(paths.tools_state.read_text(encoding="utf-8"))["tool"]
    assert rows[0]["notes"] == (tmp_path / "root").as_posix()
    assert "notes" not in rows[1]
    assert item().notes == ""


def test_write_notes_file(paths, box, tmp_path):
    mine, theirs, gone = tmp_path / "mine", tmp_path / "theirs", tmp_path / "gone"
    mine.mkdir()
    theirs.mkdir()
    save_installed(paths, {
        "playbooks": notes_item("playbooks", mine, [box.id]),
        "other-notes": notes_item("other-notes", theirs, ["someone-else"]),
        "old-notes": notes_item("old-notes", gone, [box.id]),
        "nmap-x": item(users=[box.id]),
    })  # fmt: skip
    toolstate.write_notes_file(paths, box)
    assert paths.run_notes.read_text(encoding="utf-8") == mine.as_posix() + "\n"


def test_write_notes_file_with_an_unreadable_list_writes_none(paths, box):
    paths.tools_state.parent.mkdir(parents=True)
    paths.tools_state.write_text("nope [", encoding="utf-8")
    toolstate.write_notes_file(paths, box)
    assert paths.run_notes.read_text(encoding="utf-8") == ""


def test_clear_notes_file(paths, box):
    toolstate.write_notes_file(paths, box)
    assert paths.run_notes.exists()
    toolstate.clear_notes_file(paths)
    assert not paths.run_notes.exists()
    toolstate.clear_notes_file(paths)


def test_open_writes_and_release_clears_run_notes(paths, box, tmp_path):
    root = tmp_path / "root"
    root.mkdir()
    save_installed(paths, {"playbooks": notes_item("playbooks", root, [box.id])})
    acquire_open(paths, box, pid=100, alive=yes)
    assert paths.run_notes.read_text(encoding="utf-8") == root.as_posix() + "\n"
    release_open(paths, pid=100)
    assert not paths.run_notes.exists()


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


def runtime(name="python-3.13"):
    return Installed(
        name=name,
        version="3.13.18",
        build=1,
        sha256="cd" * 32,
        folder=f"/opt/pwn-broker/tools/{name}/3.13.18-1",
        commands=[],
        uploads=[],
        needs_root=False,
        users=[],
        home={},
        kind="runtime",
        python=f"/opt/pwn-broker/tools/{name}/3.13.18-1/root/python/bin/python3.13",
    )


def test_installed_round_trip_with_a_runtime_and_a_tool_that_requires_it(paths):
    tool = item("certipy")
    tool.requires = ["python-3.13"]
    data = {"python-3.13": runtime(), "certipy": tool}
    save_installed(paths, data)
    assert load_installed(paths) == data
    rows = tomllib.loads(paths.tools_state.read_text(encoding="utf-8"))["tool"]
    assert (rows[0]["kind"], rows[0]["python"]) == ("runtime", data["python-3.13"].python)
    assert rows[1]["requires"] == ["python-3.13"]
    assert "runtime_version" not in rows[1] and "runtime_build" not in rows[1]


def test_a_tool_row_keeps_the_runtime_build_it_was_made_on(paths):
    tool = item("certipy")
    tool.requires = ["python-3.13"]
    tool.runtime_version, tool.runtime_build = "3.13.18", 1
    save_installed(paths, {"certipy": tool})
    assert load_installed(paths)["certipy"] == tool
    [row] = tomllib.loads(paths.tools_state.read_text(encoding="utf-8"))["tool"]
    assert (row["runtime_version"], row["runtime_build"]) == ("3.13.18", 1)


def test_an_installed_list_without_runtimes_is_written_as_before(paths):
    save_installed(paths, {"one": item("one")})
    [row] = tomllib.loads(paths.tools_state.read_text(encoding="utf-8"))["tool"]
    assert sorted(row) == sorted(
        "name version build sha256 folder commands uploads needs_root users home root_home".split()
    )


def test_rows_written_before_runtimes_load_as_tools(paths):
    save_installed(paths, {"one": item("one")})
    one = load_installed(paths)["one"]
    assert (one.kind, one.requires, one.python) == ("tool", [], "")


@pytest.mark.parametrize(
    "key, value",
    [("kind", "library"), ("kind", 1), ("requires", "python-3.13"), ("requires", [1]),
     ("python", 3), ("runtime_version", 3), ("runtime_build", "1"), ("runtime_build", True)],
)  # fmt: skip
def test_bad_runtime_fields_are_refused(paths, key, value):
    save_installed(paths, {"one": item("one")})
    data = tomllib.loads(paths.tools_state.read_text(encoding="utf-8"))
    data["tool"][0][key] = value
    paths.tools_state.write_text(tomli_w.dumps(data), encoding="utf-8")
    with pytest.raises(ToolError, match=f"invalid content .*{key}"):
        load_installed(paths)


def test_needed_and_idle_runtimes():
    a, b = item("a"), item("b")
    a.requires = ["python-3.13"]
    data = {"a": a, "b": b, "python-3.13": runtime(), "python-3.14": runtime("python-3.14")}
    assert toolstate.needed_runtimes(data) == {"python-3.13"}
    assert [t.name for t in toolstate.idle_runtimes(data)] == ["python-3.14"]
    del data["a"]
    assert toolstate.needed_runtimes(data) == set()
    assert [t.name for t in toolstate.idle_runtimes(data)] == ["python-3.13", "python-3.14"]


def test_a_runtime_is_never_an_orphan():
    data = {"a": item("a", users=[]), "python-3.13": runtime()}
    assert [t.name for t in orphans(data, set())] == ["a"]


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


def test_open_box_records_the_start_time(paths, tmp_path):
    write_open_box(paths, tmp_path, 42, "5000")
    assert paths.run_box.read_text().split("\n")[:3] == [tmp_path.resolve().as_posix(), "42", "5000"]
    assert open_box(paths, alive=yes, started=lambda pid: "5000") == tmp_path.resolve()
    assert open_box(paths, alive=yes, started=lambda pid: None) == tmp_path.resolve()
    # the pid now belongs to another process
    assert open_box(paths, alive=yes, started=lambda pid: "9000") is None


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
