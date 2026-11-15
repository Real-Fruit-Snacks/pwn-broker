import errno
import os
import shutil
import sys
from pathlib import Path

from pwn_broker.model import Box
from pwn_broker.toolpkg import ToolError, valid_tool_name
from pwn_broker.toolstate import Installed

_MAX_DEPTH = 64
_NO_SPACE = {errno.ENOSPC, getattr(errno, "EDQUOT", errno.ENOSPC)}


# a module-level hook so tests can stand in for the platform without touching sys
def _posix() -> bool:
    return sys.platform != "win32"


def _nested(a: Path, b: Path) -> bool:
    x, y = a.parts, b.parts
    n = min(len(x), len(y))
    return x[:n] == y[:n]


def homes(home: Path, *, root_home: Path | None = None) -> list[Path]:
    found = [home]
    if not _posix():
        return found
    other = Path("/root") if root_home is None else root_home
    try:
        apart = not _nested(other.resolve(), home.resolve())
        usable = other.is_dir() and os.access(other, os.R_OK | os.X_OK)
    except OSError:
        return found
    if usable and apart:
        found.append(other)
    return found


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
    while pending:
        entries, dst, depth = pending.pop()
        for entry in entries:
            target = dst / entry.name
            try:
                if entry.is_symlink():
                    continue
                is_dir = entry.is_dir(follow_symlinks=False)
                is_file = entry.is_file(follow_symlinks=False)
            except OSError:
                continue
            if is_file:
                _copy_file(entry.path, target)
            elif is_dir:
                if depth + 1 > _MAX_DEPTH:
                    raise ToolError(f"{source} is nested more than {_MAX_DEPTH} folders deep")
                try:
                    inner = list(os.scandir(entry.path))
                except OSError:
                    continue
                try:
                    target.mkdir(exist_ok=True)
                except OSError as exc:
                    if _full(exc):
                        raise ToolError(f"out of space while copying {source}") from exc
                    continue
                made.append((Path(entry.path), target))
                pending.append((inner, target, depth + 1))
    for src, dst in reversed(made):
        try:
            shutil.copystat(src, dst)
        except OSError:
            pass
    return True


def _clear(path: Path) -> None:
    if path.is_dir():
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


def collect(box: Box, item: Installed, homes: list[Path]) -> list[str]:
    if not valid_tool_name(item.name):
        raise ToolError(f"{item.name!r} is not a valid tool name")
    tool_root = box.path / "tooldata" / item.name
    copied: list[str] = []
    for index, folder in enumerate(homes):
        label = "home" if index == 0 else "home-root"
        base = tool_root / label
        for entry, existed in item.home.items():
            if existed or not _qualifies(folder, entry):
                continue
            source = _path(folder, entry)
            dest = _path(base, entry)
            _prepare(box.path, tool_root, dest)
            try:
                _clear(dest)
            except OSError:
                continue
            if source.is_dir():
                done = _copy_tree(source, dest)
            elif source.is_file():
                done = _copy_file(source, dest)
            else:
                done = False
            if done:
                copied.append(dest.relative_to(box.path).as_posix())
    return sorted(copied)


def to_delete(item: Installed, homes: list[Path], others: bool) -> list[Path]:
    if others or not valid_tool_name(item.name):
        return []
    found = [
        _path(folder, entry)
        for folder in homes
        for entry, existed in item.home.items()
        if existed is False and _qualifies(folder, entry)
    ]
    return sorted(found)


def kept(item: Installed, homes: list[Path]) -> list[Path]:
    if not valid_tool_name(item.name):
        return []
    found = [
        _path(folder, entry)
        for folder in homes
        for entry, existed in item.home.items()
        if existed and _valid_entry(entry) and os.path.lexists(_path(folder, entry))
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
