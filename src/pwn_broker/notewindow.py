import os
import signal
import subprocess
import time
from collections.abc import Callable, Iterable, Iterator, Mapping
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


# a running process of the current user: its pid and its command line, one argument each
Process = tuple[int, list[str]]


def _own_processes() -> Iterator[Process]:
    # Linux only; elsewhere there is no /proc and nothing is found
    try:
        me = os.getuid()
        entries = list(Path("/proc").iterdir())
    except (AttributeError, OSError):
        return
    for entry in entries:
        if not entry.name.isdigit():
            continue
        try:
            if entry.stat().st_uid != me:
                continue
            raw = (entry / "cmdline").read_bytes()
        except OSError:
            continue
        if raw:
            yield int(entry.name), _parse_cmdline(raw)


def _parse_cmdline(raw: bytes) -> list[str]:
    return [os.fsdecode(arg) for arg in raw.rstrip(b"\0").split(b"\0")]


def _same_path(a: str, b: Path) -> bool:
    # the app starts vim with absolute paths; a relative one is relative to a folder not known here
    if not Path(a).is_absolute():
        return False
    try:
        return Path(a).resolve() == b.resolve()
    except (OSError, RuntimeError, ValueError):
        return False


def _is_note_vim(argv: list[str], paths: AppPaths, box: Box) -> bool:
    if len(argv) != 4 or argv[1] != "-u":
        return False
    if argv[0] != "vim" and not argv[0].endswith("/vim"):
        return False
    return _same_path(argv[2], paths.vim_dir / "vimrc") and _same_path(argv[3], box.path / NOTE_NAME)


def find_note(
    paths: AppPaths,
    box: Box,
    *,
    processes: Callable[[], Iterable[Process]] | None = None,
) -> int | None:
    # the vim itself, never the terminal around it: its command line is exactly the vim command
    for pid, argv in (processes or _own_processes)():
        if _is_note_vim(argv, paths, box):
            return pid
    return None


def close_note(
    paths: AppPaths,
    box: Box,
    *,
    kill: Callable[[int, int], None] = os.kill,
    processes: Callable[[], Iterable[Process]] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    wait: float = 1.0,
) -> bool:
    pid = find_note(paths, box, processes=processes)
    if pid is None:
        return False
    # read again right before the signal: that pid must still be the note's vim
    if find_note(paths, box, processes=processes) != pid:
        return False
    try:
        kill(pid, signal.SIGTERM)
    except OSError:
        return False
    # a short, bounded wait: a window that stays is reported by the caller
    waited = 0.0
    while waited < wait and find_note(paths, box, processes=processes) is not None:
        sleep(0.1)
        waited += 0.1
    return True
