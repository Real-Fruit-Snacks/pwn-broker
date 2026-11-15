import hashlib
import os
import stat
from collections.abc import Callable
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
NOTE_SWAP = ".notes.md.sw?"
# store.write_text's temp files, in the destination's folder at any depth
TEMP_PREFIX = ".pwn-broker-"
TEMP_SUFFIX = ".tmp"

_CHUNK = 1024 * 1024


def is_temp_name(name: str) -> bool:
    return name.startswith(TEMP_PREFIX) and name.endswith(TEMP_SUFFIX)


def is_app_file(rel_path: str) -> bool:
    folder, _, name = rel_path.rpartition("/")
    if is_temp_name(name):
        return True
    return not folder and (name in ROOT_APP_FILES or fnmatchcase(name, NOTE_SWAP))


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def _reason(exc: OSError) -> str:
    return "disappeared" if isinstance(exc, FileNotFoundError) else "cannot read"


def scan(
    box: Box,
    records: list[FileRecord],
    *,
    now: datetime,
    hash_all: bool = False,
    limit: int = HASH_NOW_LIMIT,
    on_skip: Callable[[str, str], None] | None = None,
) -> list[FileRecord]:
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
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for name in files:
            full = Path(root) / name
            rel = full.relative_to(box.path).as_posix()
            if is_app_file(rel):
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
                wants_hash = hash_all or st.st_size <= limit
                if old and old.size == st.st_size and old.mtime == st.st_mtime:
                    if old.sha256 or not wants_hash:
                        found.append(old)
                        continue
                    checksum = sha256_file(full)
                else:
                    checksum = sha256_file(full) if wants_hash else ""
            except OSError as exc:
                skip(rel, exc)
                continue
            parts = rel.split("/")
            found.append(
                FileRecord(
                    path=rel,
                    target=parts[1] if parts[0] == "targets" and len(parts) > 2 else "",
                    first_seen=old.first_seen if old else now,
                    size=st.st_size,
                    mtime=st.st_mtime,
                    sha256=checksum,
                )
            )
    # keep what was recorded under a folder we could not list, so first_seen survives
    for r in records:
        if any(r.path.startswith(d + "/") for d in unreadable):
            found.append(r)
    return sorted(found, key=lambda r: r.path)
