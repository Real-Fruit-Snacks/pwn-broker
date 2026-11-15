import subprocess
from collections.abc import Callable, Mapping
from pathlib import Path

from pwn_broker.config import Settings
from pwn_broker.model import Box
from pwn_broker.note import NOTE_NAME
from pwn_broker.paths import AppPaths


def vim_command(paths: AppPaths, note: Path) -> list[str]:
    return ["vim", "-u", str(paths.vim_dir / "vimrc"), str(note)]


def has_display(env: Mapping[str, str]) -> bool:
    return bool(env.get("DISPLAY") or env.get("WAYLAND_DISPLAY"))


def _spawn(argv: list[str], cwd: Path) -> None:
    subprocess.Popen(
        argv,
        cwd=cwd,
        start_new_session=True,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
    )


def open_note(
    paths: AppPaths,
    settings: Settings,
    box: Box,
    env: Mapping[str, str],
    spawn: Callable[[list[str], Path], None] = _spawn,
) -> bool:
    if not has_display(env):
        return False
    argv = [settings.terminal, "-e", *vim_command(paths, box.path / NOTE_NAME)]
    try:
        spawn(argv, box.path)
    except OSError:
        return False
    return True


def note_unsaved(box: Box) -> bool:
    try:
        return (box.path / ".note-state").read_text(encoding="utf-8").strip() == "1"
    except (OSError, UnicodeDecodeError):
        return False
