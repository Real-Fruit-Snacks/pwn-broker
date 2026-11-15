from pathlib import Path

from pwn_broker.config import Settings
from pwn_broker.notewindow import has_display, note_unsaved, open_note, vim_command


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
