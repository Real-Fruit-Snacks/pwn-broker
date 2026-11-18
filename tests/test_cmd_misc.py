import io
import threading
import time
from datetime import timedelta

import pytest

from helpers import NOW, make_cred
from pwn_broker import checks, notewindow
from pwn_broker import shell  # noqa: F401  (fills the command registry)
from pwn_broker.boxes import TARGET_FOLDERS, add_target
from pwn_broker.checks import CheckResult
from pwn_broker.config import Settings
from pwn_broker.console import FakeConsole, TermConsole
from pwn_broker.model import FileRecord, Flag
from pwn_broker.shell.commands import COMMANDS, USAGES, dispatch
from pwn_broker.store import load_box, save_files
from pwn_broker.vpn import Tunnel

FLAG = "e5e4e47ae7022664cda6eb013fb0d9ed"


def _raw(console):
    return [text for kind, text in console.lines if kind == "raw"]


def _info(console):
    return [text for kind, text in console.lines if kind == "info"]


def _fails(console):
    return [text for kind, text in console.lines if kind == "fail"]


def _fields(console):
    return [text for kind, text in console.lines if kind == "field"]


def _term(session):
    out = io.StringIO()
    session.console = TermConsole({"NO_COLOR": "1"}, out=out)
    return out


def _record(path, target, seen, size):
    return FileRecord(path=path, target=target, first_seen=seen, size=size, mtime=0.0, sha256="")


def test_flag_user_records_value_and_time(session):
    session.console = FakeConsole([FLAG])
    dispatch(session, "flag user")
    assert load_box(session.box.path).flags["user"] == Flag(FLAG, session.clock())
    assert ("ok", "user flag recorded") in session.console.lines


def test_flag_empty_saves_nothing(session):
    session.console = FakeConsole([""])
    dispatch(session, "flag root")
    assert load_box(session.box.path).flags == {}
    assert len(_fails(session.console)) == 1


def test_flag_replacing_asks_first(session):
    session.box.flags["root"] = Flag("old", NOW)
    session.console = FakeConsole(["new", "n"])
    dispatch(session, "flag root")
    assert session.console.asked == ["flag", "replace the root flag?"]
    assert session.box.flags["root"].value == "old"
    session.console = FakeConsole([" new ", "keep", "y"])
    dispatch(session, "flag root")
    assert load_box(session.box.path).flags["root"] == Flag(" new ", session.clock())


def test_flag_multiline_paste_is_asked_again(session):
    session.console = FakeConsole([FLAG + "\n" + FLAG, FLAG])
    dispatch(session, "flag user")
    assert session.console.asked == ["flag", "flag"]
    assert len(_fails(session.console)) == 1
    assert load_box(session.box.path).flags["user"].value == FLAG


@pytest.mark.parametrize("answer,stored", [("keep", f" {FLAG}"), ("trim", FLAG)])
def test_flag_edge_space_asks_keep_or_trim(session, answer, stored):
    session.console = FakeConsole([f" {FLAG}", answer])
    dispatch(session, "flag user")
    assert session.console.asked == ["flag", "keep or trim"]
    assert load_box(session.box.path).flags["user"].value == stored


def test_path_prints_target_folder_and_subfolder(session):
    box = session.box.path
    for line in ("path", "path scans", "path lists", "path screenshots"):
        dispatch(session, line)
    assert _raw(session.console) == [
        str(box / "targets" / "dc01"),
        str(box / "targets" / "dc01" / "scans"),
        str(box / "lists"),
        str(box / "screenshots"),
    ]


def test_path_without_current_target(session):
    session.current = None
    for line in ("path", "path lists", "path loot"):
        dispatch(session, line)
    assert _raw(session.console) == [str(session.box.path), str(session.box.path / "lists")]
    assert len(_fails(session.console)) == 1


def test_path_unknown_folder_fails(session):
    dispatch(session, "path nope")
    (message,) = _fails(session.console)
    for name in (*TARGET_FOLDERS, "lists"):
        assert name in message


def test_files_lists_records_for_one_target(session):
    add_target(
        session.box, session.targets, ips=["10.10.10.2"], hostnames=[],
        scope="external", name="web", now=NOW,
    )  # fmt: skip
    today = session.clock()
    save_files(session.box, [
        _record("targets/dc01/loot/a.txt", "dc01", today, 100),
        _record("targets/dc01/scans/b.xml", "dc01", NOW - timedelta(days=2), 2048),
        _record("targets/dc01/files/c.bin", "dc01", today, 5 * 1024 * 1024),
        _record("targets/web/loot/d.txt", "web", today, 1),
    ])  # fmt: skip
    dispatch(session, "files dc")
    columns, rows = session.console.tables[0]
    assert columns == ["file", "added", "size"]
    assert rows == [
        ["targets/dc01/loot/a.txt", "13:00", "100 B"],
        ["targets/dc01/scans/b.xml", "2026-11-12", "2.0 KB"],
        ["targets/dc01/files/c.bin", "13:00", "5.0 MB"],
    ]
    dispatch(session, "files")
    assert len(session.console.tables[1][1]) == 4
    # the file is the one column cut on a narrow terminal
    assert session.console.events == [("table", "file")] * 2


def test_files_none(session):
    dispatch(session, "files")
    assert session.console.lines == [("info", "no files yet")]


def test_note_command_reopens_window(session, monkeypatch):
    monkeypatch.setattr(notewindow, "open_note", lambda *a: True)
    dispatch(session, "note")
    assert ("ok", "note opened") in session.console.lines
    monkeypatch.setattr(notewindow, "open_note", lambda *a: False)
    dispatch(session, "note")
    kind, text = session.console.lines[-1]
    assert kind == "warn"
    assert " ".join(notewindow.vim_command(session.paths, session.box.path / "notes.md")) in text


def test_status_shows_box_at_a_glance(session):
    session.creds.append(make_cred())
    session.box.flags["user"] = Flag(FLAG, NOW)
    save_files(session.box, [_record("targets/dc01/a", "dc01", NOW, 1)])
    dispatch(session, "status")
    lines = _fields(session.console)
    assert lines == [
        "box  forest (htb)",
        "started  2026-11-14",
        "status  active",
        "targets  1",
        "tools  0",
        "vpn  not up",
        "creds  1",
        "files  1",
        "recordings  0",
        "user flag  recorded 12:00",
        "root flag  -",
    ]
    assert [kind for kind, _ in session.console.lines] == ["field"] * 11
    assert FLAG not in "".join(lines)


def test_status_aligns_its_values_in_one_column(session):
    out = _term(session)
    dispatch(session, "status")
    lines = out.getvalue().splitlines()
    assert lines[0] == "  box         forest (htb)"
    assert lines[8] == "  recordings  0"
    assert lines[9] == "  user flag   -"
    assert len(lines) == 11


def test_check_command_reruns_checks(session, monkeypatch):
    calls = []

    def fake(paths, settings, env, home, include_version=True, tunnel=None):
        calls.append((paths, settings, include_version, tunnel))
        return [CheckResult("vim", "ok", "/usr/bin/vim")]

    monkeypatch.setattr(checks, "launch_checks", fake)
    monkeypatch.setattr(checks, "version_check", lambda settings: CheckResult("version", "warn", "9.9 is available"))
    dispatch(session, "check")
    assert calls == [(session.paths, session.settings, False, session.tunnel)]
    assert session.console.lines == [("ok", "1 check passed"), ("warn", "version   9.9 is available")]


def test_check_command_does_not_wait_long_for_the_update_check(session, monkeypatch):
    release = threading.Event()
    monkeypatch.setattr(checks, "run_checks", lambda *a, **k: [CheckResult("vim", "ok", "x")])
    monkeypatch.setattr(checks, "version_check", lambda settings: release.wait(10))
    started = time.monotonic()
    try:
        dispatch(session, "check")
    finally:
        release.set()
    assert time.monotonic() - started < 5
    assert session.console.lines == [("ok", "1 check passed")]


def test_launch_checks_repairs_path_and_adds_version(paths, tmp_path, monkeypatch):
    newer = CheckResult("version", "warn", "9.9 is available, this is 0.1")
    monkeypatch.setattr(checks, "version_check", lambda settings: newer)
    results = checks.launch_checks(paths, Settings(), {"PATH": ""}, tmp_path, tunnel=lambda: None)
    assert results[-1] is newer
    next(r for r in results if r.name == "path").repair()
    assert paths.bin.as_posix() in (tmp_path / ".zshrc").read_text(encoding="utf-8")
    monkeypatch.setattr(checks, "version_check", lambda settings: None)
    results = checks.launch_checks(paths, Settings(), {}, tmp_path, tunnel=lambda: None)
    assert all(r.name != "version" for r in results)


ONE_WORD = ["check", "clear", "exit", "export", "files", "finish", "help", "note", "path", "quit", "replay", "status"]
FAMILIES = ["cred", "flag", "host", "serve", "target", "tool", "vpn"]
# the longest command name, two spaces, then the description
DESCRIPTION_COLUMN = 2 + len("tool cache clear") + 2


def _groups(events):
    """The command names in each group help printed, split where it asked for a gap."""
    groups = [[]]
    for kind, text in events:
        if kind == "gap":
            groups.append([])
        else:
            assert kind == "field"
            groups[-1].append(text.split("  ", 1)[0])
    return groups


def test_help_lists_the_one_word_commands_then_each_family(session):
    dispatch(session, "help")
    groups = _groups(session.console.events)
    assert groups[0] == ONE_WORD
    assert [group[0].split()[0] for group in groups[1:]] == FAMILIES
    for first, group in zip(FAMILIES, groups[1:]):
        assert group == sorted(n for n in COMMANDS if n.split()[0] == first)
    # host is a command of its own and the head of its family
    assert groups[3][:2] == ["host", "host add"]
    assert sorted(n for group in groups for n in group) == sorted(COMMANDS)
    assert ("field", "help  list the commands") in session.console.lines


def _description_columns(text):
    columns = set()
    for line in text.splitlines():
        name = next(n for n in sorted(COMMANDS, key=len, reverse=True) if line.startswith(f"  {n}  "))
        rest = line[2 + len(name) :]
        columns.add(2 + len(name) + len(rest) - len(rest.lstrip(" ")))
    return columns


def test_help_aligns_both_columns_across_every_group(session):
    out = _term(session)
    dispatch(session, "help")
    text = out.getvalue()
    assert len(text.split("\n\n")) == 1 + len(FAMILIES)
    assert "\n\n\n" not in text and not text.startswith("\n") and not text.endswith("\n\n")
    assert _description_columns(text.replace("\n\n", "\n")) == {DESCRIPTION_COLUMN}
    assert "\n  help              list the commands\n" in text


@pytest.mark.parametrize("line", ["tool", "cred", "host file", "flag", "tool cache"])
def test_a_family_name_lists_its_commands_aligned_as_help_does(session, line):
    dispatch(session, line)
    names = [text.split("  ", 1)[0] for text in _fields(session.console)]
    assert names == sorted(n for n in COMMANDS if n.startswith(line + " "))
    assert [kind for kind, _ in session.console.lines] == ["field"] * len(names)
    out = _term(session)
    dispatch(session, line)
    assert _description_columns(out.getvalue()) == {DESCRIPTION_COLUMN}


def test_help_with_an_argument_is_an_error_with_its_usage(session):
    dispatch(session, "help tool")
    assert session.console.lines == [("fail", "too many arguments: tool"), ("detail", "usage: help")]


def test_clear_asks_the_console_to_clear_the_screen(session):
    dispatch(session, "clear")
    assert session.console.events == [("clear", "")]
    session.console = FakeConsole()
    dispatch(session, "clear x")
    assert session.console.lines == [("fail", "too many arguments: x"), ("detail", "usage: clear")]
    assert ("clear", "") not in session.console.events


@pytest.mark.parametrize(
    "line", ["status x", "check x", "note x", "help x", "flag user a b", "path a b", "files a b"]
)
def test_extra_arguments_fail_with_the_usage(session, line, monkeypatch):
    monkeypatch.setattr(checks, "launch_checks", lambda *a: [])
    dispatch(session, line)
    assert len(_fails(session.console)) == 1
    name = max((n for n in COMMANDS if line.startswith(n + " ")), key=len)
    assert session.console.lines[-1] == ("detail", USAGES[name])


def test_every_command_has_a_usage_line():
    assert USAGES.keys() == COMMANDS.keys()
    assert all(usage == f"usage: {name}" or usage.startswith(f"usage: {name} ") for name, usage in USAGES.items())
    assert USAGES["files"] == "usage: files [<target>]"
    assert USAGES["path"] == "usage: path [<folder>]"
    assert USAGES["status"] == "usage: status"


def test_files_added_uses_the_clock_timezone(session):
    from datetime import timezone

    seen = session.clock().astimezone(timezone.utc).replace(hour=23, minute=30)
    seen = seen - timedelta(days=1)
    # 23:30 UTC the day before is 01:30 on the clock's date at +02:00
    save_files(session.box, [_record("targets/dc01/a", "dc01", seen, 1)])
    dispatch(session, "files")
    assert session.console.tables[0][1][0][1] == "01:30"


def test_note_command_recreates_a_missing_note(session, monkeypatch):
    monkeypatch.setattr(notewindow, "open_note", lambda *a: True)
    note = session.box.path / "notes.md"
    note.unlink()
    dispatch(session, "note")
    text = note.read_text(encoding="utf-8")
    assert text.startswith("#" * 64 + "\n#  Box:         forest ") and "\nTarget: dc01   " in text
    assert ("ok", "note created") in session.console.lines


def test_status_shows_the_tunnel(session, system):
    system.tunnel_found = Tunnel("tun0", "10.10.14.7")
    dispatch(session, "status")
    assert "vpn  10.10.14.7 on tun0" in _fields(session.console)


def test_check_command_hands_the_session_tunnel_reader_to_the_checks(session, system, monkeypatch):
    system.tunnel_found = Tunnel("tun0", "10.10.14.7")
    monkeypatch.setattr(checks, "newer_release_within", lambda settings: None)
    dispatch(session, "check")
    assert ("warn", "vpn   no VPN tunnel is up") not in session.console.lines
    assert system.tunnel_reads == 1


def test_status_counts_recordings_and_those_recording_now(session, system):
    from casts import recording_now, write_cast

    folder = session.box.path / "targets/dc01/recordings"
    write_cast(folder / "2026-11-14_1000.cast", [(0, "o", "a")])
    write_cast(session.box.path / "targets/web01/recordings/2026-11-14_1100.cast", [(0, "o", "a")])
    dispatch(session, "status")
    assert "recordings  2" in _fields(session.console)
    recording_now(session, system, "dc01")
    session.console = FakeConsole()
    dispatch(session, "status")
    assert "recordings  3 (1 recording now)" in _fields(session.console)


def test_note_command_does_not_open_a_second_window(session, monkeypatch):
    opened = []
    monkeypatch.setattr(notewindow, "find_note", lambda paths, box: 99)
    monkeypatch.setattr(notewindow, "open_note", lambda *a: opened.append(a) or True)
    dispatch(session, "note")
    assert opened == []
    assert session.console.lines[-1] == ("ok", "the note is already open")
    assert ("ok", "note opened") not in session.console.lines
