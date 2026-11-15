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
    ok = open_note(paths, Settings(terminal="xterm"), box, {"DISPLAY": ":0"}, spawn=seen.append)
    assert ok and seen == [["xterm", "-e", *vim_command(paths, box.path / "notes.md")]]


def test_open_note_without_display(paths, box):
    seen = []
    assert open_note(paths, Settings(), box, {}, spawn=seen.append) is False
    assert seen == []


def test_open_note_terminal_missing(paths, box):
    def boom(argv):
        raise OSError("no such terminal")

    assert open_note(paths, Settings(), box, {"DISPLAY": ":0"}, spawn=boom) is False


def test_note_unsaved(box):
    assert note_unsaved(box) is False
    (box.path / ".note-state").write_text("1\n")
    assert note_unsaved(box) is True
    (box.path / ".note-state").write_text("0\n")
    assert note_unsaved(box) is False
