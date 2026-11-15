import os
import shutil
import sys
from pathlib import Path

from pwn_broker.model import Box
from pwn_broker.toolpkg import ToolError
from pwn_broker.toolstate import Installed


def homes(home: Path, *, root_home: Path | None = None) -> list[Path]:
    found = [home]
    if sys.platform == "win32":
        return found
    other = Path("/root") if root_home is None else root_home
    try:
        same = other.resolve() == home.resolve()
        usable = other.is_dir() and os.access(other, os.R_OK | os.X_OK)
    except OSError:
        return found
    if usable and not same:
        found.append(other)
    return found


def _path(folder: Path, entry: str) -> Path:
    return folder.joinpath(*entry.split("/"))


def _qualifies(folder: Path, entry: str) -> bool:
    # no link is followed: the entry and every folder between it and the home must be real
    current = folder
    for part in entry.split("/"):
        current = current / part
        if os.path.islink(current):
            return False
    return os.path.exists(current)


def _copy_tree(source: Path, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    try:
        entries = list(os.scandir(source))
    except OSError:
        return
    for entry in entries:
        target = dest / entry.name
        try:
            if entry.is_symlink():
                continue
            if entry.is_dir(follow_symlinks=False):
                _copy_tree(Path(entry.path), target)
            elif entry.is_file(follow_symlinks=False):
                shutil.copy2(entry.path, target)
        except OSError:
            continue


def _clear(path: Path) -> None:
    if path.is_dir() and not path.is_symlink():
        shutil.rmtree(path)
    elif os.path.lexists(path):
        path.unlink()


def collect(box: Box, item: Installed, homes: list[Path]) -> list[str]:
    copied: list[str] = []
    for index, folder in enumerate(homes):
        label = "home" if index == 0 else "home-root"
        base = box.path / "tooldata" / item.name / label
        for entry, existed in item.home.items():
            if existed or not _qualifies(folder, entry):
                continue
            source = _path(folder, entry)
            dest = _path(base, entry)
            try:
                _clear(dest)
                if source.is_dir():
                    _copy_tree(source, dest)
                elif source.is_file():
                    dest.parent.mkdir(parents=True, exist_ok=True)
                    shutil.copy2(source, dest)
                else:
                    continue
            except OSError:
                continue
            copied.append(dest.relative_to(box.path).as_posix())
    return sorted(copied)


def to_delete(item: Installed, homes: list[Path], others: bool) -> list[Path]:
    if others:
        return []
    found = [
        _path(folder, entry)
        for folder in homes
        for entry, existed in item.home.items()
        if existed is False and _qualifies(folder, entry)
    ]
    return sorted(found)


def kept(item: Installed, homes: list[Path]) -> list[Path]:
    found = [
        _path(folder, entry)
        for folder in homes
        for entry, existed in item.home.items()
        if existed and os.path.lexists(_path(folder, entry))
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
    for path in paths_to_delete:
        if not any(_inside(path, folder) for folder in homes):
            raise ToolError(f"{path} is not strictly inside the home folder; nothing was deleted")
    for path in paths_to_delete:
        if os.path.islink(path):
            raise ToolError(f"{path} became a link; stopped")
        if path.is_dir():
            shutil.rmtree(path)
        elif os.path.lexists(path):
            path.unlink()
