import os
import signal
from pathlib import Path

import pytest

from conftest import REAL_OWN_PROCESSES, REAL_PARENT_PID
from pwn_broker.config import Settings
from pwn_broker.notewindow import (
    close_note,
    find_note,
    has_display,
    note_unsaved,
    open_note,
    shut_note,
    vim_command,
)


def test_vim_command(paths):
    assert vim_command(paths, Path("/b/notes.md")) == [
        "vim",
        "-u",
        str(paths.vim_dir / "vimrc"),
        str(Path("/b/notes.md")),
    ]


def test_has_display():
    assert has_display({"DISPLAY": ":0"})
    assert has_display({"WAYLAND_DISPLAY": "wayland-0"})
    assert not has_display({})
    assert not has_display({"DISPLAY": "", "WAYLAND_DISPLAY": ""})


def test_open_note_spawns_terminal(paths, box):
    seen = []
    ok = open_note(
        paths, Settings(terminal="xterm"), box, {"DISPLAY": ":0"},
        spawn=lambda argv, cwd: seen.append((argv, cwd)),
    )  # fmt: skip
    assert ok
    assert seen == [(["xterm", "-e", *vim_command(paths, box.path / "notes.md")], box.path)]


def test_open_note_without_display(paths, box):
    seen = []
    assert open_note(paths, Settings(), box, {}, spawn=lambda a, c: seen.append(a)) is False
    assert seen == []


def test_open_note_terminal_missing(paths, box):
    def boom(argv, cwd):
        raise OSError("no such terminal")

    assert open_note(paths, Settings(), box, {"DISPLAY": ":0"}, spawn=boom) is False


def test_note_unsaved(box):
    assert note_unsaved(box) is False
    (box.path / ".note-state").write_text("1\n")
    assert note_unsaved(box) is True
    (box.path / ".note-state").write_text("0\n")
    assert note_unsaved(box) is False


def test_note_unsaved_ignores_garbage(box):
    state = box.path / ".note-state"
    state.write_bytes(b"\xff\xfe\x00garbage")
    assert note_unsaved(box) is False
    state.write_text("yes please")
    assert note_unsaved(box) is False


def note_argv(paths, box, first="vim"):
    return [first, *vim_command(paths, box.path / "notes.md")[1:]]


def listing(*rows):
    return lambda: list(rows)


def test_find_note_finds_the_vim(paths, box):
    rows = listing((7, ["bash"]), (42, note_argv(paths, box)))
    assert find_note(paths, box, processes=rows) == 42


def test_find_note_accepts_a_path_to_vim(paths, box):
    assert find_note(paths, box, processes=listing((5, note_argv(paths, box, "/usr/bin/vim")))) == 5


def test_find_note_ignores_the_terminal_around_the_vim(paths, box):
    wrapper = ["x-terminal-emulator", "-e", *note_argv(paths, box)]
    assert find_note(paths, box, processes=listing((9, wrapper))) is None


def test_find_note_needs_the_exact_command(paths, box):
    argv = note_argv(paths, box)
    for other in (
        [*argv, "extra"],
        argv[:1] + ["-u", "/elsewhere/vimrc"] + argv[3:],
        [*argv[:3], str(box.path / "other.md")],
        ["nvim", *argv[1:]],
        ["vimdiff", *argv[1:]],
        ["vim", "-n", *argv[1:]],
        [],
    ):
        assert find_note(paths, box, processes=listing((3, other))) is None


def test_find_note_never_matches_another_boxes_note(paths, box, other):
    rows = listing((11, note_argv(paths, other)))
    assert find_note(paths, box, processes=rows) is None
    assert find_note(paths, other, processes=rows) == 11


def test_find_note_compares_resolved_paths(paths, box):
    argv = note_argv(paths, box)
    argv[3] = str(box.path / ".." / box.path.name / "notes.md")
    assert find_note(paths, box, processes=listing((4, argv))) == 4


def test_find_note_with_the_real_listing_finds_no_such_vim(paths, box):
    # on Windows there is no /proc and the listing is empty; on Linux no vim has this note
    assert find_note(paths, box, processes=REAL_OWN_PROCESSES) is None


def test_close_note_sends_term_to_the_vim_only(paths, box):
    sent = []
    rows = listing((7, ["x-terminal-emulator", "-e", *note_argv(paths, box)]), (42, note_argv(paths, box)))
    ok = close_note(
        paths, box, kill=lambda pid, sig: sent.append((pid, sig)), processes=rows, sleep=lambda s: None
    )  # fmt: skip
    assert ok and sent == [(42, signal.SIGTERM)]


def test_close_note_with_nothing_open(paths, box, other):
    sent = []
    rows = listing((11, note_argv(paths, other)), (2, ["bash"]))
    assert close_note(paths, box, kill=lambda *a: sent.append(a), processes=rows) is False
    assert sent == []


def test_close_note_waits_a_bounded_time(paths, box):
    sleeps = []
    rows = listing((42, note_argv(paths, box)))
    assert close_note(paths, box, kill=lambda *a: None, processes=rows, sleep=sleeps.append, wait=0.5)
    assert 4 <= len(sleeps) <= 6


def test_close_note_stops_waiting_when_it_is_gone(paths, box):
    state = [[(42, note_argv(paths, box))], []]
    sleeps = []
    close_note(
        paths, box, kill=lambda *a: None, sleep=sleeps.append,
        processes=lambda: state.pop(0) if len(state) > 1 else state[0],
    )  # fmt: skip
    assert len(sleeps) <= 1


def test_find_note_never_matches_a_relative_note_path(paths, box, monkeypatch):
    # a vim started by hand in this folder as `vim -u <vimrc> notes.md`: its folder is not the app's
    monkeypatch.chdir(box.path)
    argv = note_argv(paths, box)
    argv[3] = "notes.md"
    assert find_note(paths, box, processes=listing((6, argv))) is None


def test_find_note_never_matches_a_relative_vimrc_path(paths, box, monkeypatch):
    paths.vim_dir.mkdir(parents=True)
    monkeypatch.chdir(paths.vim_dir.parent)
    argv = note_argv(paths, box)
    argv[2] = f"{paths.vim_dir.name}/vimrc"
    assert find_note(paths, box, processes=listing((6, argv))) is None


def test_close_note_sends_nothing_when_the_pid_changed_since_the_listing(paths, box):
    sent = []
    seen = [[(42, note_argv(paths, box))], [(42, ["bash"])]]
    ok = close_note(
        paths, box, kill=lambda *a: sent.append(a), sleep=lambda s: None,
        processes=lambda: seen.pop(0) if len(seen) > 1 else seen[0],
    )  # fmt: skip
    assert ok is False and sent == []


def test_command_line_arguments_are_decoded_as_file_names():
    from pwn_broker.notewindow import _parse_cmdline

    assert _parse_cmdline(b"vim\0-u\0/a/vimrc\0/b/notes.md\0") == ["vim", "-u", "/a/vimrc", "/b/notes.md"]


@pytest.mark.skipif(os.name == "nt", reason="file names are bytes only on Linux")
def test_a_note_path_that_is_not_utf8_still_matches(tmp_path):
    from pwn_broker.notewindow import _parse_cmdline

    odd = os.fsdecode(os.fsencode(tmp_path) + b"/b\xff")
    assert _parse_cmdline(os.fsencode(odd) + b"\0") == [odd]


class World:
    """A table of processes where a signal ends the process, the way TERM ends a vim and a terminal."""

    def __init__(self, *rows):
        self.table = dict(rows)
        self.sent = []
        self.stays = set()

    def listing(self):
        return list(self.table.items())

    def kill(self, pid, sig):
        self.sent.append(pid)
        if pid not in self.stays:
            self.table.pop(pid, None)


def terminal_argv(paths, box, first="x-terminal-emulator"):
    return [first, "-e", *note_argv(paths, box)]


def shut(world, paths, box, parent_of):
    return shut_note(
        paths, box, kill=world.kill, processes=world.listing, sleep=lambda s: None,
        parent=parent_of.get,
    )  # fmt: skip


def test_the_terminal_made_for_the_note_is_closed_after_the_vim(paths, box):
    world = World((7, terminal_argv(paths, box)), (42, note_argv(paths, box)))
    assert shut(world, paths, box, {42: 7}) is False
    assert world.sent == [42, 7] and world.table == {}


def test_a_shell_is_never_signalled(paths, box):
    world = World((7, ["bash"]), (42, note_argv(paths, box)))
    assert shut(world, paths, box, {42: 7}) is False
    assert world.sent == [42] and 7 in world.table


def test_a_terminal_server_without_the_tail_is_never_signalled(paths, box):
    world = World((7, ["qterminal"]), (42, note_argv(paths, box)))
    shut(world, paths, box, {42: 7})
    assert world.sent == [42]


def test_a_tail_that_differs_by_one_argument_is_never_signalled(paths, box):
    argv = terminal_argv(paths, box)
    argv[-1] = str(box.path / "other.md")
    world = World((7, argv), (42, note_argv(paths, box)))
    shut(world, paths, box, {42: 7})
    assert world.sent == [42]


def test_a_terminal_with_more_after_the_vim_arguments_is_never_signalled(paths, box):
    world = World((7, [*terminal_argv(paths, box), "extra"]), (42, note_argv(paths, box)))
    shut(world, paths, box, {42: 7})
    assert world.sent == [42]


def test_another_users_terminal_is_never_signalled(paths, box):
    # the listing holds only the current user's processes, so the parent is not in it
    world = World((42, note_argv(paths, box)))
    shut(world, paths, box, {42: 7})
    assert world.sent == [42]


def test_a_terminal_that_closed_with_the_vim_is_not_signalled(paths, box):
    # xterm: the window closes by itself once the vim is signalled
    world = World((7, terminal_argv(paths, box)), (42, note_argv(paths, box)))
    kill = world.kill

    def kill_both(pid, sig):
        kill(pid, sig)
        world.table.pop(7, None)

    assert shut_note(
        paths, box, kill=kill_both, processes=world.listing, sleep=lambda s: None, parent={42: 7}.get
    ) is False  # fmt: skip
    assert world.sent == [42]


def test_a_terminal_that_stays_after_its_wait_is_reported(paths, box):
    world = World((7, terminal_argv(paths, box)), (42, note_argv(paths, box)))
    world.stays.add(7)
    sleeps = []
    left = shut_note(
        paths, box, kill=world.kill, processes=world.listing, sleep=sleeps.append,
        parent={42: 7}.get, wait=0.3,
    )  # fmt: skip
    assert left is True and world.sent == [42, 7] and 1 <= len(sleeps) <= 4


def test_a_vim_that_stays_is_reported_and_its_terminal_left_alone(paths, box):
    world = World((7, terminal_argv(paths, box)), (42, note_argv(paths, box)))
    world.stays.add(42)
    left = shut_note(
        paths, box, kill=world.kill, processes=world.listing, sleep=lambda s: None,
        parent={42: 7}.get, wait=0.2,
    )  # fmt: skip
    assert left is True and world.sent == [42]


def test_the_terminal_is_read_again_right_before_its_signal(paths, box):
    world = World((7, terminal_argv(paths, box)), (42, note_argv(paths, box)))
    calls = {"after_vim_gone": 0}

    def listing():
        rows = world.listing()
        if 42 not in world.table:
            calls["after_vim_gone"] += 1
            # the first reads (the wait, then the terminal's match) see the terminal; the read made
            # right before its signal finds that pid now runs something else
            if calls["after_vim_gone"] > 3:
                return [(7, ["bash"])]
        return rows

    shut_note(
        paths, box, kill=world.kill, processes=listing, sleep=lambda s: None, parent={42: 7}.get
    )  # fmt: skip
    assert world.sent == [42]


def test_nothing_is_signalled_when_the_parent_cannot_be_read(paths, box):
    world = World((7, terminal_argv(paths, box)), (42, note_argv(paths, box)))
    assert shut(world, paths, box, {}) is False
    assert world.sent == [42]


def test_the_parent_of_a_process_is_read_from_its_stat_line(monkeypatch):
    from pwn_broker import notewindow

    class Stat:
        def __init__(self, text):
            self.text = text

        def read_text(self, **kwargs):
            return self.text

    monkeypatch.setattr(notewindow, "Path", lambda p: Stat("42 (vim (x) y) S 7 42 42 0 -1"))
    assert REAL_PARENT_PID(42) == 7
