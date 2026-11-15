"""Which windows are recording: one marker per `record` process in run/recordings/."""

from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from pwn_broker import boxes, cast as casts, toolstate
from pwn_broker.model import Box
from pwn_broker.paths import AppPaths
from pwn_broker.store import write_text


@dataclass(frozen=True)
class Recording:
    pid: int
    target: str
    cast: Path


def windows(count: int) -> str:
    """`1 window is` or `<n> windows are`, for the lines that count recording windows."""
    return "1 window is" if count == 1 else f"{count} windows are"


def marker_path(paths: AppPaths, pid: int) -> Path:
    return paths.run_recordings / str(pid)


def mark(paths: AppPaths, pid: int, start: str, target: str, cast: Path) -> Path:
    """Write the marker: the process start time, the target and the cast, one per line."""
    fields = (start, target, str(cast))
    if any("\n" in f or "\r" in f for f in fields):
        # a line break would shift every field after it; no marker is better than a wrong one
        raise OSError(f"{cast} holds a line break and cannot go in a recording marker")
    path = marker_path(paths, pid)
    write_text(path, "".join(f"{f}\n" for f in fields))
    return path


def clear(paths: AppPaths, pid: int) -> None:
    _discard(marker_path(paths, pid))


def _discard(marker: Path) -> None:
    try:
        marker.unlink(missing_ok=True)
    except OSError:
        pass


def _read(marker: Path) -> tuple[str, str, Path] | None:
    try:
        text = marker.read_text(encoding="utf-8")
    except (OSError, UnicodeDecodeError):
        return None
    lines = text.split("\n")
    if len(lines) != 4 or lines[3] or not lines[1] or not lines[2]:
        return None
    return lines[0], lines[1], Path(lines[2])


def _inside(cast: Path, box: Box) -> bool:
    try:
        return cast.resolve().is_relative_to(box.path.resolve())
    except OSError:
        return False


def recording(
    paths: AppPaths,
    box: Box | None = None,
    *,
    alive: Callable[[int], bool] | None = None,
    started: Callable[[int], str | None] | None = None,
) -> list[Recording]:
    """The windows still recording, optionally only into `box`; stale markers are cleared."""
    check = alive if alive is not None else boxes.pid_alive
    start_of = started if started is not None else toolstate.process_start
    try:
        markers = sorted(paths.run_recordings.iterdir())
    except OSError:
        return []
    found: list[Recording] = []
    for marker in markers:
        name = marker.name
        if not (name.isascii() and name.isdecimal()):
            # not a marker; a marker being written has a temporary name like this
            continue
        pid = int(name)
        held = _read(marker)
        if pid < 1 or held is None or not check(pid):
            _discard(marker)
            continue
        recorded, target, cast = held
        now = start_of(pid) if recorded else None
        if recorded and now is not None and recorded != now:
            _discard(marker)  # the pid now belongs to another process
            continue
        if box is not None and not _inside(cast, box):
            continue
        found.append(Recording(pid, target, cast))
    return sorted(found, key=lambda r: r.pid)


def live_casts(
    paths: AppPaths,
    box: Box,
    *,
    alive: Callable[[int], bool] | None = None,
    started: Callable[[int], str | None] | None = None,
) -> dict[str, int]:
    """Each cast being recorded into the box, by box-relative path, to its size up to its last whole line."""
    root = box.path.resolve()
    sizes: dict[str, int] = {}
    for item in recording(paths, box, alive=alive, started=started):
        try:
            sizes[item.cast.resolve().relative_to(root).as_posix()] = casts.whole_size(item.cast)
        except (OSError, ValueError):
            continue  # the cast has vanished
    return sizes
