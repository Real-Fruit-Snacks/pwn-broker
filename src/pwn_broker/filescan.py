import hashlib
import os
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from pwn_broker.model import Box, FileRecord

HASH_NOW_LIMIT = 64 * 1024 * 1024
SKIP_NAMES = {"files.toml", "manifest.toml", ".note-state"}
# ".tmp" also covers the temp files store.write_text leaves mid-write
SKIP_SUFFIXES = (".swp", ".swo", ".part", ".tmp", "~")

_CHUNK = 1024 * 1024


def is_skipped(name: str) -> bool:
    return name in SKIP_NAMES or name.endswith(SKIP_SUFFIXES)


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

    for root, dirs, files in os.walk(box.path, followlinks=False):
        dirs[:] = [d for d in dirs if not d.startswith(".")]
        for name in files:
            if is_skipped(name):
                continue
            full = Path(root) / name
            rel = full.relative_to(box.path).as_posix()
            try:
                if full.is_symlink():
                    continue
                st = os.stat(full)
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
    return sorted(found, key=lambda r: r.path)
