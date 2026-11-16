import signal
from pathlib import Path

from conftest import REAL_OWN_PROCESSES
from pwn_broker.config import Settings
from pwn_broker.notewindow import (
    close_note,
    find_note,
    has_display,
    note_unsaved,
    open_note,
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
