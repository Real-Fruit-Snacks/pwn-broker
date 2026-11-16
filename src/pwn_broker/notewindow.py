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


def _find_vim(
    paths: AppPaths, box: Box, processes: Callable[[], Iterable[Process]] | None
) -> Process | None:
    # the vim itself, never the terminal around it: its command line is exactly the vim command
    for pid, argv in (processes or _own_processes)():
        if _is_note_vim(argv, paths, box):
            return pid, argv
    return None


def find_note(
    paths: AppPaths,
    box: Box,
    *,
    processes: Callable[[], Iterable[Process]] | None = None,
) -> int | None:
    found = _find_vim(paths, box, processes)
    return None if found is None else found[0]


def _parent_pid(pid: int) -> int | None:
    # field 4 of /proc/<pid>/stat; the command name in field 2 may hold spaces and brackets
    try:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8", errors="replace")
        return int(text[text.rindex(")") + 1 :].split()[1])
    except (OSError, ValueError, IndexError):
        return None


def _alive(pid: int, argv: list[str], processes: Callable[[], Iterable[Process]] | None) -> bool:
    return any(p == pid and a == argv for p, a in (processes or _own_processes)())


def _wait_gone(gone: Callable[[], bool], sleep: Callable[[float], None], wait: float) -> None:
    waited = 0.0
    while waited < wait and not gone():
        sleep(0.1)
        waited += 0.1


def _close(
    paths: AppPaths,
    box: Box,
    kill: Callable[[int, int], None],
    processes: Callable[[], Iterable[Process]] | None,
    sleep: Callable[[float], None],
    wait: float,
    parent: Callable[[int], int | None],
) -> tuple[bool, bool]:
    """Signal the note's vim, then the terminal made only for it: (signalled, something is left)."""
    found = _find_vim(paths, box, processes)
    if found is None:
        return False, False
    pid, argv = found
    # read again right before the signal: that pid must still be the note's vim
    again = _find_vim(paths, box, processes)
    if again is None or again[0] != pid:
        return False, False
    holder = parent(pid)
    try:
        kill(pid, signal.SIGTERM)
    except OSError:
        return False, True
    _wait_gone(lambda: find_note(paths, box, processes=processes) is None, sleep, wait)
    if find_note(paths, box, processes=processes) is not None:
        return True, True
    if holder is None or holder == pid:
        return True, False
    # a terminal started only to run this vim ends its command line with -e and the vim's own arguments
    tail = ["-e", *argv]
    holder_argv = next((a for p, a in (processes or _own_processes)() if p == holder), None)
    if holder_argv is None or holder_argv[-len(tail) :] != tail or len(holder_argv) <= len(tail):
        return True, False
    # and once more right before its signal
    if not _alive(holder, holder_argv, processes):
        return True, False
    try:
        kill(holder, signal.SIGTERM)
    except OSError:
        return True, True
    _wait_gone(lambda: not _alive(holder, holder_argv, processes), sleep, wait)
    return True, _alive(holder, holder_argv, processes)


def close_note(
    paths: AppPaths,
    box: Box,
    *,
    kill: Callable[[int, int], None] = os.kill,
    processes: Callable[[], Iterable[Process]] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    wait: float = 1.0,
    parent: Callable[[int], int | None] = _parent_pid,
) -> bool:
    return _close(paths, box, kill, processes, sleep, wait, parent)[0]


def shut_note(
    paths: AppPaths,
    box: Box,
    *,
    kill: Callable[[int, int], None] = os.kill,
    processes: Callable[[], Iterable[Process]] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    wait: float = 1.0,
    parent: Callable[[int], int | None] = _parent_pid,
) -> bool:
    """Close the note's window; True when the vim, or the terminal made for it, is still there."""
    return _close(paths, box, kill, processes, sleep, wait, parent)[1]
