"""What only its owner may read: a box's credentials, lists, note and command history, and the
archives a box is packed into.

Each of those files is 0600 and its folder 0700, whatever the umask. A file or folder that is
already tighter than that is left as it is: a mode is only ever taken away here, never given.
Links are not followed: a mode is changed on the thing the name itself is, or not at all.
"""

import os
import shutil
import stat
from pathlib import Path
from typing import BinaryIO

from pwn_broker.model import Box
from pwn_broker.note import NOTE_NAME
from pwn_broker.paths import AppPaths

FILE = 0o600
FOLDER = 0o700

# a box's own files that hold what was typed or found; the files under lists/ are with them
_BOX_FILES = ("creds.toml", NOTE_NAME, ".history")
_LISTS = "lists"
_ARCHIVE = ".tar.gz"


def tighten(path: Path, mask: int) -> bool:
    """Takes from a file or folder the permissions outside `mask`; true when it had any.

    Nothing is changed on a link, on anything that is not there, or on a file when a folder's
    mask is given and the other way round."""
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return False
    wanted = stat.S_ISDIR if mask == FOLDER else stat.S_ISREG
    if not wanted(info.st_mode):
        return False
    mode = stat.S_IMODE(info.st_mode)
    if mode & ~mask == 0:
        return False
    os.chmod(path, mode & mask)
    return True


def _tighten_quietly(path: Path, mask: int) -> None:
    # where a write is about to happen: a folder on a file system that keeps no modes, or one
    # another user owns, must not stop the write. Opening the box says what could not be done.
    try:
        tighten(path, mask)
    except OSError:
        pass


def folder(path: Path) -> None:
    """Makes the folder, for its owner alone, with any folders above it that are missing; one
    that is there loses what others could do in it."""
    path.parent.mkdir(parents=True, exist_ok=True)
    try:
        path.mkdir(mode=FOLDER)
    except FileExistsError:
        if not path.is_dir():
            # a file in its place is the caller's to report, as mkdir itself would have it
            raise
        _tighten_quietly(path, FOLDER)


def create(path: Path) -> BinaryIO:
    """A new file its owner alone can read, open for writing. Whatever was under the name is
    removed first, and the file is never made through a link left in its place."""
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    return os.fdopen(os.open(path, flags, FILE), "wb")


def copy(source: Path, dest: Path) -> None:
    """A copy of the file's bytes that its owner alone can read. No mode or time is copied
    from the source, which a FAT or exFAT folder could not take anyway."""
    with open(source, "rb") as src, create(dest) as out:
        shutil.copyfileobj(src, out, 1024 * 1024)


def keep(path: Path) -> None:
    """A file something else appends to, such as the prompt's history: made empty for its owner
    alone when it is not there, and tightened when it is."""
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    try:
        os.close(os.open(path, flags, FILE))
    except FileExistsError:
        _tighten_quietly(path, FILE)


def _box_paths(paths: AppPaths, box: Box) -> list[tuple[Path, int]]:
    found = [(box.path, FOLDER), (box.path / _LISTS, FOLDER)]
    found += [(box.path / name, FILE) for name in _BOX_FILES]
    for folder_, suffix in ((box.path / _LISTS, ""), (paths.wrapped, _ARCHIVE)):
        try:
            names = sorted(os.listdir(folder_))
        except OSError:
            # not there, or not a folder: nothing in it to tighten
            names = []
        found += [(folder_ / name, FILE) for name in names if name.endswith(suffix)]
    return [*found, (paths.wrapped, FOLDER)]


def unpacked(top: Path) -> None:
    """A box's folder just unpacked from an archive, before it is moved into active/."""
    _tighten_quietly(top, FOLDER)


def tighten_box(paths: AppPaths, box: Box) -> list[tuple[Path, OSError]]:
    """Takes from an opened box's secrets, and from the archives in wrapped/, what an earlier
    version or a loose umask let others do with them. Returns what could not be changed, with
    why: a file another user owns, for one."""
    failed: list[tuple[Path, OSError]] = []
    for path, mask in _box_paths(paths, box):
        try:
            tighten(path, mask)
        except OSError as exc:
            failed.append((path, exc))
    return failed
