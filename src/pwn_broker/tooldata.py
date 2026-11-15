import errno
import os
import shutil
import sys
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from pwn_broker.filescan import TEMP_PREFIX, TEMP_SUFFIX
from pwn_broker.model import Box
from pwn_broker.store import write_text
from pwn_broker.toolpkg import ToolError, valid_tool_name
from pwn_broker.toolstate import Installed

_MAX_DEPTH = 64
_NO_SPACE = {errno.ENOSPC, getattr(errno, "EDQUOT", errno.ENOSPC)}
STAMP = ".install"
_LABELS = ("home", "home-root")


@dataclass(frozen=True)
class Copied:
    source: Path
    dest: str  # relative to the box
    full: bool  # every file and folder under the source was copied


# a module-level hook so tests can stand in for the platform without touching sys
def _posix() -> bool:
    return sys.platform != "win32"


def _root_home() -> Path:
    return Path(os.path.expanduser("~root"))


def _nested(a: Path, b: Path) -> bool:
    x, y = a.parts, b.parts
    n = min(len(x), len(y))
    return x[:n] == y[:n]


def _root_state(home: Path, root_home: Path | None) -> str:
    # "same" when root's home is the user's or nested with it; else missing, readable or unreadable
    if not _posix():
        return "same"
    other = _root_home() if root_home is None else root_home
    try:
        if _nested(other.resolve(), home.resolve()):
            return "same"
        if not other.is_dir():
            return "missing"
        return "readable" if os.access(other, os.R_OK | os.X_OK) else "unreadable"
    except OSError:
        return "unreadable"


def homes(home: Path, *, root_home: Path | None = None) -> list[Path]:
    """The user's home first, then root's when it is a different folder that can be read."""
    if _root_state(home, root_home) != "readable":
        return [home]
    return [home, _root_home() if root_home is None else root_home]


def root_unchecked(home: Path, *, root_home: Path | None = None) -> bool:
    return _root_state(home, root_home) == "unreadable"


def _answers(item: Installed, index: int) -> dict[str, bool]:
    return item.home if index == 0 else item.root_home


def _valid_entry(entry: str) -> bool:
    if not entry or "\\" in entry or entry.startswith("/"):
        return False
    parts = entry.split("/")
    if ":" in parts[0]:
        return False
    return all(part not in ("", ".", "..") for part in parts)


def _path(folder: Path, entry: str) -> Path:
    return folder.joinpath(*entry.split("/"))


def _qualifies(folder: Path, entry: str) -> bool:
    if not _valid_entry(entry):
        return False
    # no link is followed: the entry and every folder between it and the home must be real
    current = folder
    for part in entry.split("/"):
        current = current / part
        if os.path.islink(current):
            return False
    return os.path.exists(current)


def _full(exc: OSError) -> bool:
    return exc.errno in _NO_SPACE


def _copy_file(source: Path | str, dest: Path) -> bool:
    try:
        shutil.copy2(source, dest)
    except OSError as exc:
        try:
            os.unlink(dest)  # never leave a truncated copy behind
        except OSError:
            pass
        if _full(exc):
            raise ToolError(f"out of space while copying {source}") from exc
        return False
    return True


def _copy_tree(source: Path, dest: Path) -> bool:
    # True only when everything under the source was copied
    try:
        top = list(os.scandir(source))
    except OSError:
        return False
    try:
        dest.mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        if _full(exc):
            raise ToolError(f"out of space while copying {source}") from exc
        return False
    made = [(source, dest)]
    pending = [(top, dest, 0)]
    complete = True
    while pending:
        entries, dst, depth = pending.pop()
        for entry in entries:
            target = dst / entry.name
            try:
                # links and special files are never copied, so the copy is not the whole folder
                if entry.is_symlink():
                    complete = False
                    continue
                is_dir = entry.is_dir(follow_symlinks=False)
                is_file = entry.is_file(follow_symlinks=False)
            except OSError:
                complete = False
                continue
            if is_file:
                if not _copy_file(entry.path, target):
                    complete = False
            elif is_dir:
                if depth + 1 > _MAX_DEPTH:
                    raise ToolError(f"{source} is nested more than {_MAX_DEPTH} folders deep")
                try:
                    inner = list(os.scandir(entry.path))
                except OSError:
                    complete = False
                    continue
                try:
                    target.mkdir(exist_ok=True)
                except OSError as exc:
                    if _full(exc):
                        raise ToolError(f"out of space while copying {source}") from exc
                    complete = False
                    continue
                made.append((Path(entry.path), target))
                pending.append((inner, target, depth + 1))
            else:
                complete = False
    for src, dst in reversed(made):
        try:
            shutil.copystat(src, dst)
        except OSError:
            pass
    return complete


def _clear(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    elif os.path.lexists(path):
        path.unlink()


def _prepare(box_root: Path, tool_root: Path, dest: Path) -> None:
    # every folder from the box down to the destination must be a real folder, never a link
    box_parts = Path(os.path.abspath(box_root)).parts
    root_parts = Path(os.path.abspath(tool_root)).parts
    dest_parts = Path(os.path.abspath(dest)).parts
    if len(dest_parts) <= len(root_parts) or dest_parts[: len(root_parts)] != root_parts:
        raise ToolError(f"{dest} is not inside {tool_root}")
    current = Path(*box_parts)
    for part in dest_parts[len(box_parts) : -1]:
        current = current / part
        if os.path.islink(current):
            raise ToolError(f"{current} is a link; tool data was not copied")
        if not current.exists():
            current.mkdir()
    if os.path.islink(dest):
        raise ToolError(f"{dest} is a link; tool data was not copied")


def _temp(dest: Path, tag: str = "") -> Path:
    return dest.parent / f"{TEMP_PREFIX}{dest.name}{tag}{TEMP_SUFFIX}"


def _copy_entry(source: Path, dest: Path) -> tuple[bool, bool]:
    """Copy beside dest, then swap it in. Returns (a copy is at dest, this run's copy is full)."""
    new = _temp(dest)
    if os.path.lexists(new):
        _clear(new)  # this function's own copy, left by a run that was cut short
    try:
        if source.is_dir():
            full = _copy_tree(source, new)
        elif source.is_file():
            full = _copy_file(source, new)
        else:
            full = False
    except BaseException:
        try:
            _clear(new)
        except OSError:
            pass
        raise
    if not os.path.lexists(new):
        return os.path.lexists(dest), False
    if not os.path.lexists(dest):
        os.rename(new, dest)
        return True, full
    if not full:
        # a partial copy never replaces the one already in the box
        _clear(new)
        return True, False
    old = _temp(dest, ".old")
    if os.path.lexists(old):
        _clear(old)
    os.rename(dest, old)
    os.rename(new, dest)
    _clear(old)
    return True, True


def _free_name(folder: Path, label: str) -> Path:
    n = 1
    while os.path.lexists(folder / f"{label}-{n}"):
        n += 1
    return folder / f"{label}-{n}"


def _claim(box_root: Path, tool_root: Path, stamp: str) -> None:
    # a copy made by an earlier install of the tool is kept under a new name, never replaced
    stamp_path = tool_root / STAMP
    _prepare(box_root, tool_root, stamp_path)
    try:
        current = stamp_path.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        current = None
    if current == stamp:
        return
    for label in _LABELS:
        folder = tool_root / label
        if os.path.lexists(folder):
            os.rename(folder, _free_name(tool_root, label))
    write_text(stamp_path, stamp)


def collect(box: Box, item: Installed, homes: list[Path], installed: datetime) -> list[Copied]:
    """Copy the tool's new home paths into the box; installed is the box record's install time."""
    if not valid_tool_name(item.name):
        raise ToolError(f"{item.name!r} is not a valid tool name")
    tool_root = box.path / "tooldata" / item.name
    claimed = False
    copied: list[Copied] = []
    for index, folder in enumerate(homes):
        base = tool_root / _LABELS[min(index, 1)]
        answers = _answers(item, index)
        for entry in item.home:
            # an entry with no answer for this home may be the tool's: copied, never deleted
            if answers.get(entry) is True or not _qualifies(folder, entry):
                continue
            if not claimed:
                _claim(box.path, tool_root, installed.isoformat())
                claimed = True
            source = _path(folder, entry)
            dest = _path(base, entry)
            _prepare(box.path, tool_root, dest)
            landed, full = _copy_entry(source, dest)
            if landed:
                copied.append(Copied(source, dest.relative_to(box.path).as_posix(), full))
    return sorted(copied, key=lambda c: c.dest)


def to_delete(item: Installed, homes: list[Path], others: bool) -> list[Path]:
    if others or not valid_tool_name(item.name):
        return []
    found = [
        _path(folder, entry)
        for index, folder in enumerate(homes)
        for entry in item.home
        if _answers(item, index).get(entry) is False and _qualifies(folder, entry)
    ]
    return sorted(found)


def kept(item: Installed, homes: list[Path]) -> list[Path]:
    # a path with no answer recorded for its home counts as having been there before
    if not valid_tool_name(item.name):
        return []
    found = [
        _path(folder, entry)
        for index, folder in enumerate(homes)
        for entry in item.home
        if _answers(item, index).get(entry, True)
        and _valid_entry(entry)
        and os.path.lexists(_path(folder, entry))
    ]
    return sorted(found)


def _inside(path: Path, folder: Path) -> bool:
    if ".." in path.parts:
        return False
    target = Path(os.path.abspath(path)).parts
    base = Path(os.path.abspath(folder)).parts
    if len(target) <= len(base) or target[: len(base)] != base:
        return False
    current = Path(*base)
    for part in target[len(base) :]:
        current = current / part
        if os.path.islink(current):
            return False
    return True


def delete(paths_to_delete: list[Path], homes: list[Path]) -> None:
    def check(path: Path) -> None:
        if not any(_inside(path, folder) for folder in homes):
            raise ToolError(f"{path} is not strictly inside the home folder; nothing was deleted")

    for path in paths_to_delete:
        check(path)
    for path in paths_to_delete:
        # checked again right before removing: this narrows the window in which a folder
        # can be swapped for a link, it does not close it
        check(path)
        try:
            if path.is_dir():
                shutil.rmtree(path)
            elif os.path.lexists(path):
                path.unlink()
        except OSError as exc:
            raise ToolError(f"could not delete {path}: {exc}") from exc
