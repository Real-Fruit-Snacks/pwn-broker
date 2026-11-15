import os
import sys
from datetime import datetime, timezone

import pytest

from helpers import NOW
from pwn_broker import toollog
from pwn_broker.paths import AppPaths

SHA = "a3" * 32
WHEN = datetime(2026, 11, 15, 14, 32, 7, 123456, tzinfo=timezone.utc)


def append(paths, box, **overrides):
    fields = dict(
        when=WHEN, event="install", box=box,
        name="certipy", version="5.1.0", build=3, sha256=SHA,
    )  # fmt: skip
    fields.update(overrides)
    toollog.append(paths, **fields)


def read(paths):
    return paths.tool_log.read_bytes().decode("utf-8")


def test_a_line_holds_the_time_event_box_tool_and_hash(paths, box):
    append(paths, box)
    assert read(paths) == (
        "2026-11-15T14:32:07+00:00  install  forest (2026-11-14_htb_forest)"
        f"  certipy 5.1.0-3  sha256:{SHA}\n"
    )


def test_a_runtime_line_ends_with_runtime(paths, box):
    append(paths, box, name="python-3.13", version="3.13.18", build=1, kind="runtime")
    assert read(paths).endswith(f"  python-3.13 3.13.18-1  sha256:{SHA}  runtime\n")


def test_events_are_padded_so_the_columns_line_up(paths, box):
    for event in ("install", "remove", "finish"):
        append(paths, box, event=event)
    lines = read(paths).splitlines()
    assert [line[27:36] for line in lines] == ["install  ", "remove   ", "finish   "]
    assert {line.index("forest") for line in lines} == {36}


def test_the_time_keeps_its_own_offset(paths, box):
    append(paths, box, when=NOW)
    assert read(paths).startswith("2026-11-14T12:00:00+02:00  install  ")


def test_lines_are_added_to_what_is_there(paths, box):
    paths.tool_log.write_bytes(b"an earlier line\n")
    append(paths, box)
    append(paths, box, event="remove")
    lines = read(paths).split("\n")
    assert lines[0] == "an earlier line"
    assert lines[1].split()[1] == "install" and lines[2].split()[1] == "remove"
    assert lines[3] == "" and len(lines) == 4


def test_the_folder_is_made_when_missing(box, tmp_path):
    paths = AppPaths(opt=tmp_path / "opt", home=tmp_path / "not-yet" / "home")
    append(paths, box)
    assert paths.tool_log.is_file()


@pytest.mark.parametrize("field", ["box id", "name", "version", "sha256"])
@pytest.mark.parametrize("brk", ["\n", "\r", "\u2028"])
def test_a_value_with_a_line_break_is_refused(paths, box, field, brk):
    if field == "box id":
        box.id = f"id{brk}x"
        overrides = {}
    else:
        overrides = {field: f"x{brk}y"}
    with pytest.raises(ValueError, match="line break"):
        append(paths, box, **overrides)
    assert not paths.tool_log.exists()


def test_a_box_name_cannot_break_the_columns_or_reach_the_terminal(paths, box):
    # the name may come from someone else's archive
    box.name = "x (id)  evil\t1-1\x1b[31m  sha256:ab\nnext\u2028line"
    append(paths, box)
    [line] = read(paths).splitlines()
    assert "  x (id) evil?1-1?[31m sha256:ab?next line (2026-11-14_htb_forest)  " in line
    assert line.split("  ")[2] == "x (id) evil?1-1?[31m sha256:ab?next line (2026-11-14_htb_forest)"


def test_a_box_name_cannot_reorder_how_the_line_shows(paths, box):
    # a right-to-left override and a zero-width space are format characters, not controls
    box.name = "for‮est​x"
    append(paths, box)
    [line] = read(paths).splitlines()
    assert line.split("  ")[2] == "for?est?x (2026-11-14_htb_forest)"


def test_an_event_that_is_not_known_is_refused(paths, box):
    with pytest.raises(ValueError, match="event"):
        append(paths, box, event="installed\nfake line")
    assert not paths.tool_log.exists()


def test_a_time_with_no_offset_is_refused(paths, box):
    with pytest.raises(ValueError, match="offset"):
        append(paths, box, when=datetime(2026, 11, 15, 14, 32))
    assert not paths.tool_log.exists()


def test_each_line_is_one_write_to_a_file_opened_for_append(paths, box, monkeypatch):
    calls = []
    real_open, real_write = toollog.os.open, toollog.os.write

    def spy_open(path, flags, mode=0o777):
        calls.append(("open", flags, mode))
        return real_open(path, flags, mode)

    def spy_write(fd, data):
        calls.append(("write", data))
        return real_write(fd, data)

    monkeypatch.setattr(toollog.os, "open", spy_open)
    monkeypatch.setattr(toollog.os, "write", spy_write)
    append(paths, box)
    (_o, flags, mode), (_w, data) = calls
    for flag in (os.O_WRONLY, os.O_APPEND, os.O_CREAT):
        assert flags & flag
    assert not flags & os.O_TRUNC
    assert mode == 0o600
    assert data.endswith(b"\n") and data.count(b"\n") == 1


@pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX file modes")
def test_a_log_made_readable_by_others_is_made_private_again(paths, box):
    paths.tool_log.write_bytes(b"an earlier line\n")
    paths.tool_log.chmod(0o644)
    append(paths, box)
    assert paths.tool_log.stat().st_mode & 0o777 == 0o600
    assert read(paths).startswith("an earlier line\n")


@pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX file modes")
def test_the_log_is_readable_only_by_its_owner(paths, box):
    old = os.umask(0)
    try:
        append(paths, box)
    finally:
        os.umask(old)
    assert paths.tool_log.stat().st_mode & 0o777 == 0o600


def test_a_log_that_cannot_be_opened_raises_os_error(paths, box):
    paths.tool_log.mkdir(parents=True)  # a folder where the file should be
    with pytest.raises(OSError):
        append(paths, box)


def test_a_log_whose_folder_cannot_be_made_raises_os_error(box, tmp_path):
    (tmp_path / "taken").write_text("a file where the folder should be")
    paths = AppPaths(opt=tmp_path / "opt", home=tmp_path / "taken" / "home")
    with pytest.raises(OSError):
        append(paths, box)
