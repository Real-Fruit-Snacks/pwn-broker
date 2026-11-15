import hashlib
import os
import secrets
import shutil
import stat
import tarfile
import tempfile
import tomllib
import zlib
from collections.abc import Iterable, Mapping
from dataclasses import asdict
from datetime import datetime
from fnmatch import fnmatchcase
from pathlib import Path

from pwn_broker.filescan import BOX_PRIVATE_FOLDERS, NOTE_SWAP, ROOT_TRANSIENT_FILES, is_temp_name, sha256_file
from pwn_broker.model import Box, FileRecord
from pwn_broker.paths import AppPaths
from pwn_broker.store import SCHEMA, write_toml

MANIFEST = "manifest.toml"
_CHUNK = 1024 * 1024
_MANIFEST_LIMIT = 64 * 1024 * 1024
_READ_ERRORS = (tarfile.TarError, OSError, EOFError, zlib.error)


class ArchiveError(Exception):
    pass


def archive_path(paths: AppPaths, box: Box, kind: str) -> Path:
    return paths.wrapped / f"{box.path.name}.{kind}.tar.gz"


def write_manifest(box: Box, records: list[FileRecord], *, kind: str, now: datetime) -> Path:
    described = {
        "id": box.id,
        "name": box.name,
        "platform": box.platform,
        "os": box.os,
        "difficulty": box.difficulty,
        "started": box.started,
        "finished": box.finished,
    }
    path = box.path / MANIFEST
    write_toml(
        path,
        {
            "schema": SCHEMA,
            "kind": kind,
            "packed": now,
            "box": {k: v for k, v in described.items() if v is not None},
            "file": [asdict(r) for r in records],
        },
    )
    return path


def _left_out(rel_path: str) -> bool:
    # narrower than filescan.is_app_file: files.toml, manifest.toml and .history are packed
    folder, _, name = rel_path.rpartition("/")
    if is_temp_name(name):
        return True
    return not folder and (name in ROOT_TRANSIENT_FILES or fnmatchcase(name, NOTE_SWAP))


def _raise(exc: OSError) -> None:
    raise exc


def _entries(root: Path) -> tuple[list[tuple[str, Path]], list[str]]:
    # also returns the links and special files, which are never packed
    found = [("", root)]
    special: list[str] = []
    for current, dirs, files in os.walk(root, followlinks=False, onerror=_raise):
        here = Path(current)
        keep = []
        for name in dirs:
            if here == root and name in BOX_PRIVATE_FOLDERS:
                continue
            rel = (here / name).relative_to(root).as_posix()
            if stat.S_ISDIR(os.lstat(here / name).st_mode):
                keep.append(name)
                found.append((rel, here / name))
            else:
                special.append(rel)
        dirs[:] = keep
        for name in files:
            rel = (here / name).relative_to(root).as_posix()
            if _left_out(rel):
                continue
            if stat.S_ISREG(os.lstat(here / name).st_mode):
                found.append((rel, here / name))
            else:
                special.append(rel)
    return sorted(found, key=lambda e: e[0]), sorted(special)


def _discard(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


class _Head:
    """A file read no further than its first `size` bytes."""

    def __init__(self, fh, size: int) -> None:
        self._fh = fh
        self._left = size

    def read(self, n: int = -1) -> bytes:
        n = self._left if n is None or n < 0 else min(n, self._left)
        data = self._fh.read(n)
        self._left -= len(data)
        return data


def _add_cut(tar: tarfile.TarFile, full: Path, arcname: str, rel: str, size: int) -> None:
    info = tar.gettarinfo(full, arcname=arcname)
    if info.size < size:
        raise ArchiveError(f"{rel} is shorter than the {size} bytes recorded for it")
    info.size = size
    with open(full, "rb") as fh:
        # tarfile fails on its own if the file is cut short while it is read
        tar.addfile(info, _Head(fh, size))


def pack(box: Box, dest: Path, cut: Mapping[str, int] | None = None) -> list[str]:
    """Write the box to dest; a path in `cut` is packed only up to that many bytes.

    Returns the links and special files that were left out, relative to the box.
    """
    cut = cut or {}
    part = dest.with_name(dest.name + ".part")
    top = box.path.name
    try:
        dest.parent.mkdir(parents=True, exist_ok=True)
        entries, special = _entries(box.path)
        with tarfile.open(part, "w:gz") as tar:
            for rel, full in entries:
                arcname = f"{top}/{rel}" if rel else top
                if rel in cut:
                    _add_cut(tar, full, arcname, rel, cut[rel])
                else:
                    tar.add(full, arcname=arcname, recursive=False)
        verify(part)
        os.replace(part, dest)
    except BaseException as exc:
        _discard(part)
        if isinstance(exc, ArchiveError) or not isinstance(exc, Exception):
            raise
        raise ArchiveError(f"cannot pack {top}: {exc}") from exc
    return special


def _top_folder(members: Iterable[tarfile.TarInfo]) -> str:
    top = None
    top_member = None
    for member in members:
        if member.name in ("", "."):
            raise ArchiveError(f"archive has an entry named {member.name!r}")
        first = member.name.split("/", 1)[0]
        if first in ("", ".", ".."):
            raise ArchiveError(f"archive entry {member.name!r} is not inside a folder")
        if top is None:
            top = first
        elif first != top:
            raise ArchiveError(f"archive has more than one top-level folder ({top!r}, {first!r})")
        if member.name == top:
            top_member = member
    if top is None:
        raise ArchiveError("archive is empty")
    if top_member is not None and not top_member.isdir():
        raise ArchiveError(f"archive entry {top!r} is not a folder")
    return top


def _open(archive: Path) -> tarfile.TarFile:
    try:
        return tarfile.open(archive, "r:gz")
    except _READ_ERRORS as exc:
        raise ArchiveError(f"{archive}: cannot open as a gzip tar ({exc})") from exc


def peek_folder(archive: Path) -> str:
    try:
        with _open(archive) as tar:
            return _top_folder(tar)
    except ArchiveError:
        raise
    except _READ_ERRORS as exc:
        raise ArchiveError(f"{archive}: cannot read archive ({exc})") from exc


def _manifest_rows(tar: tarfile.TarFile, member: tarfile.TarInfo | None) -> list[dict]:
    if member is None or not member.isreg():
        raise ArchiveError(f"{MANIFEST} is missing from the archive")
    if member.size > _MANIFEST_LIMIT:
        raise ArchiveError(f"{MANIFEST} is too large ({member.size} bytes)")
    try:
        data = tomllib.loads(tar.extractfile(member).read().decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ArchiveError(f"{MANIFEST} cannot be read ({exc})") from exc
    rows = data.get("file", [])
    if data.get("schema") != SCHEMA or not isinstance(rows, list):
        raise ArchiveError(f"{MANIFEST} is not a schema {SCHEMA} manifest")
    for row in rows:
        if not (
            isinstance(row, dict)
            and isinstance(row.get("path"), str)
            and isinstance(row.get("size"), int)
            and not isinstance(row["size"], bool)
            and row["size"] >= 0
            and isinstance(row.get("sha256"), str)
        ):
            raise ArchiveError(f"{MANIFEST} has a malformed file record: {row!r}")
    return rows


def verify(archive: Path) -> None:
    try:
        with _open(archive) as tar:
            members = tar.getmembers()
            top = _top_folder(members)
            by_name = {m.name: m for m in members}
            rows = _manifest_rows(tar, by_name.get(f"{top}/{MANIFEST}"))
            wanted = []
            for row in rows:
                path, size, checksum = row.get("path"), row.get("size"), row.get("sha256")
                if not checksum:
                    raise ArchiveError(f"{path}: no checksum recorded")
                member = by_name.get(f"{top}/{path}")
                if member is None or not member.isreg():
                    raise ArchiveError(f"{path}: missing from the archive")
                if member.size != size:
                    raise ArchiveError(f"{path}: size differs from the manifest")
                wanted.append((member, path, checksum))
            # archive order, so the gzip stream is only ever read forwards
            for member, path, checksum in sorted(wanted, key=lambda w: w[0].offset_data):
                digest = hashlib.sha256()
                with tar.extractfile(member) as fh:
                    while chunk := fh.read(_CHUNK):
                        digest.update(chunk)
                if digest.hexdigest() != checksum:
                    raise ArchiveError(f"{path}: checksum differs from the manifest")
    except ArchiveError:
        raise
    except _READ_ERRORS as exc:
        raise ArchiveError(f"{archive}: cannot read archive ({exc})") from exc


def _backslash_separates() -> bool:
    # on Linux a backslash is an ordinary file name character; elsewhere it separates paths
    return os.sep == "\\"


def _check_member(member: tarfile.TarInfo) -> None:
    name = member.name
    parts = name.split("/")
    if name.startswith("/") or (_backslash_separates() and "\\" in name) or ".." in parts:
        raise ArchiveError(f"archive entry {name!r} would write outside the destination")
    if not (member.isreg() or member.isdir()):
        raise ArchiveError(f"archive entry {name!r} is not a regular file or folder")


def unpack(archive: Path, active: Path, *, replace: bool = False) -> Path:
    if not hasattr(tarfile, "data_filter"):
        raise ArchiveError("this Python cannot unpack archives safely; install a newer Python 3.11 patch release")
    tmp: Path | None = None
    try:
        with _open(archive) as tar:
            members = tar.getmembers()
            for member in members:
                _check_member(member)
            top = _top_folder(members)
            final = active / top
            if os.path.lexists(final) and not replace:
                raise ArchiveError(f"{final} already exists")
            active.mkdir(parents=True, exist_ok=True)
            tmp = Path(tempfile.mkdtemp(prefix=".import-", dir=active))
            tar.extractall(tmp, filter=tarfile.data_filter)
        _move_into_place(tmp / top, final, replace)
        return final
    except ArchiveError:
        raise
    except (*_READ_ERRORS, ValueError) as exc:
        raise ArchiveError(f"cannot unpack {archive}: {exc}") from exc
    finally:
        if tmp is not None:
            shutil.rmtree(tmp, ignore_errors=True)


def _move_into_place(new: Path, final: Path, replace: bool) -> None:
    parked = None
    try:
        if os.path.lexists(final):
            if not replace:
                raise ArchiveError(f"{final} already exists")
            # a sibling, never inside the temp folder, so no cleanup can delete the old box
            parked = final.with_name(f".{final.name}.replaced-{secrets.token_hex(4)}")
            os.replace(final, parked)
        os.replace(new, final)
    except BaseException as exc:
        if parked is not None and os.path.lexists(parked):
            if os.path.lexists(final):
                if not isinstance(exc, Exception):
                    raise
                raise ArchiveError(
                    f"could not move the new box into place and {final} is in the way; "
                    f"the old box is kept at {parked} ({exc})"
                ) from exc
            try:
                os.replace(parked, final)
            except OSError as restore_exc:
                raise ArchiveError(
                    f"could not put the old box back; it is kept at {parked} ({restore_exc})"
                ) from exc
        raise
    if parked is not None:
        # the new box is in place; a leftover parked folder is harmless
        shutil.rmtree(parked, ignore_errors=True)


def copy_out(archive: Path, copy_to: Path) -> Path:
    if not copy_to.is_dir():
        raise ArchiveError(f"{copy_to} is not a folder that exists")
    final = copy_to / archive.name
    part = copy_to / (archive.name + ".part")
    try:
        shutil.copyfile(archive, part)
        if sha256_file(part) != sha256_file(archive):
            raise ArchiveError(f"copy to {copy_to} failed: checksum differs from the original")
        os.replace(part, final)
    except BaseException as exc:
        _discard(part)
        if isinstance(exc, OSError):
            raise ArchiveError(f"cannot copy to {copy_to}: {exc}") from exc
        raise
    return final
