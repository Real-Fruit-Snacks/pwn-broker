import hashlib
import os
import stat
from collections.abc import Callable, Mapping
from datetime import datetime
from fnmatch import fnmatchcase
from pathlib import Path

from pwn_broker.model import Box, FileRecord

HASH_NOW_LIMIT = 64 * 1024 * 1024
# The app's own files. Only these are ever left out of the records, and only where the app puts
# them: anything else in a box is the user's, whatever it is called.
ROOT_APP_FILES = frozenset({"files.toml", "manifest.toml", ".note-state", ".history"})
# of those, the ones that are not packed either
ROOT_TRANSIENT_FILES = frozenset({".note-state"})
# folders at the top of a box that belong to the app and are never recorded or packed
BOX_PRIVATE_FOLDERS = frozenset({"vpn"})
NOTE_SWAP = ".notes.md.sw?"
# store.write_text's temp files, in the destination's folder at any depth
TEMP_PREFIX = ".pwn-broker-"
TEMP_SUFFIX = ".tmp"
# why scan leaves out a file that files.toml, which is UTF-8, cannot name
NOT_UTF8 = "its name is not UTF-8, so it is not listed"

_CHUNK = 1024 * 1024


def is_temp_name(name: str) -> bool:
    return name.startswith(TEMP_PREFIX) and name.endswith(TEMP_SUFFIX)


def is_app_file(rel_path: str) -> bool:
    folder, _, name = rel_path.rpartition("/")
    if is_temp_name(name) or rel_path.split("/", 1)[0] in BOX_PRIVATE_FOLDERS:
        return True
    return not folder and (name in ROOT_APP_FILES or fnmatchcase(name, NOTE_SWAP))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def sha256_head(path: Path, size: int) -> str:
    """The SHA-256 of the first `size` bytes of the file."""
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while size > 0 and (chunk := fh.read(min(_CHUNK, size))):
            digest.update(chunk)
            size -= len(chunk)
    return digest.hexdigest()


def _is_utf8(text: str) -> bool:
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        return False
    return True


def _reason(exc: OSError) -> str:
    return "disappeared" if isinstance(exc, FileNotFoundError) else "cannot read"


def _target_of(rel: str) -> str:
    parts = rel.split("/")
    return parts[1] if parts[0] == "targets" and len(parts) > 2 else ""


def packed_records(records: list[FileRecord], packed: Mapping, *, now: datetime) -> list[FileRecord]:
    """The records of a box as it went into an archive.

    `records` is the box as it was last scanned and `packed` what the archive then took, by
    path: anything with a size, a sha256 and an mtime. Each file that was packed keeps the
    time it was first seen and gets the size, SHA-256 and time it was packed with, which is
    not what the scan found when something was still writing to it. A file made since the
    scan is first seen now, and one that was gone by the time it was reached has no record.
    What a scan never lists is not listed here either: the app's own files, and a name that
    is not UTF-8.
    """
    known = {r.path: r for r in records}
    found = []
    for rel in sorted(packed):
        if is_app_file(rel) or not _is_utf8(rel):
            continue
        took = packed[rel]
        old = known.get(rel)
        found.append(
            FileRecord(
                path=rel,
                target=_target_of(rel),
                first_seen=old.first_seen if old else now,
                size=took.size,
                mtime=took.mtime,
                sha256=took.sha256,
            )
        )
    return found


def scan(
    box: Box,
    records: list[FileRecord],
    *,
    now: datetime,
    hash_all: bool = False,
    limit: int = HASH_NOW_LIMIT,
    on_skip: Callable[[str, str], None] | None = None,
    live: Mapping[str, int] | None = None,
) -> list[FileRecord]:
    """Record every file in the box, reusing the record of a file whose size and mtime are unchanged.

    `live` maps each recording still being written to the size of its whole lines. Such a file is
    never hashed between commands; a hash_all scan records exactly that much of it.
    """
    live = live or {}
    previous = {r.path: r for r in records}
    found: list[FileRecord] = []

    def skip(rel: str, exc: OSError) -> None:
        if on_skip is not None:
            on_skip(rel, _reason(exc))

    unreadable: list[str] = []

    def dir_failed(exc: OSError) -> None:
        rel = Path(exc.filename).relative_to(box.path).as_posix()
        unreadable.append(rel)
        skip(rel, exc)

    for root, dirs, files in os.walk(box.path, followlinks=False, onerror=dir_failed):
        if Path(root) == box.path:
            dirs[:] = [d for d in dirs if d not in BOX_PRIVATE_FOLDERS]
        for name in files:
            full = Path(root) / name
            rel = full.relative_to(box.path).as_posix()
            if is_app_file(rel):
                continue
            if not _is_utf8(rel):
                # files.toml and the manifest are UTF-8 and cannot hold the name. The file is
                # still packed, under the name it has.
                if on_skip is not None:
                    on_skip(rel, NOT_UTF8)
                continue
            try:
                st = os.lstat(full)
                if stat.S_ISLNK(st.st_mode):
                    continue
                # decided from the stat alone: opening a FIFO would block the shell
                if not stat.S_ISREG(st.st_mode):
                    if on_skip is not None:
                        on_skip(rel, "not a regular file")
                    continue
                old = previous.get(rel)
                size = st.st_size
                wants_hash = hash_all or st.st_size <= limit
                if rel in live:
                    # it grows with every second recorded; the empty checksum gets it hashed once it stops
                    size = live[rel] if hash_all else st.st_size
                    checksum = sha256_head(full, size) if hash_all else ""
                elif old and old.size == st.st_size and old.mtime == st.st_mtime:
                    if old.sha256 or not wants_hash:
                        found.append(old)
                        continue
                    checksum = sha256_file(full)
                else:
                    checksum = sha256_file(full) if wants_hash else ""
            except OSError as exc:
                skip(rel, exc)
                continue
            found.append(
                FileRecord(
                    path=rel,
                    target=_target_of(rel),
                    first_seen=old.first_seen if old else now,
                    size=size,
                    mtime=st.st_mtime,
                    sha256=checksum,
                )
            )
    # keep what was recorded under a folder we could not list, so first_seen survives
    for r in records:
        if any(r.path.startswith(d + "/") for d in unreadable):
            found.append(r)
    return sorted(found, key=lambda r: r.path)
