import gzip
import hashlib
import os
import re
import secrets
import shutil
import stat
import tarfile
import tempfile
import tomllib
from collections.abc import Callable, Iterable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import asdict, dataclass
from datetime import datetime
from fnmatch import fnmatchcase
from pathlib import Path

from pwn_broker import private
from pwn_broker.filescan import BOX_PRIVATE_FOLDERS, NOTE_SWAP, ROOT_TRANSIENT_FILES, is_temp_name, sha256_file
from pwn_broker.model import Box, FileRecord
from pwn_broker.paths import BOX_FOLDER, AppPaths
from pwn_broker.store import MAX_SMALL_TOML_BYTES, MAX_TOML_BYTES, SCHEMA, write_toml

MANIFEST = "manifest.toml"
# the manifest's list of the scans that were still running when the box was packed
RUNNING_SCANS = "running_scans"
# the most an archive is read at once: see _Capped
_PIECE = 64 * 1024
_MIB = 1024 * 1024
# the manifest lists the same files as the box's files.toml, and is read as it is
_MANIFEST_LIMIT = MAX_TOML_BYTES
# What an archive may hold. A box of more files than this could not be listed in a manifest
# of that size anyway, and every entry costs memory while the archive is checked.
MAX_ENTRIES = 300_000
MAX_NAME_BYTES = 4096
_MAX_NAMES_BYTES = 64 * 1024 * 1024
# What may be read between one entry and the next: its headers. As the app writes them an
# entry costs 1.5 KiB, and one with a long or non-ASCII name that much and its name again.
# _ENTRY_HEADER_BYTES stops the reading of one entry; once its name is known, it may have
# cost _HEADER_ROOM and twice its name. What makes a header slow to read is the number of
# records in it, each of which ends a line: the app writes eight at most (path, time, size,
# owner and group by number and by name, and the character set), so an entry may have
# _HEADER_LINES line ends in its headers, and two more for each one in its name.
_ENTRY_HEADER_BYTES = 16 * 1024
_HEADER_ROOM = 2048
_HEADER_LINES = 16
_MAX_OWNER = 2**32 - 1


class ArchiveError(Exception):
    pass


class Shrunk(ArchiveError):
    """A file got shorter while it was being read into the archive, which cannot be put right
    in an archive already part written: the pack has to start again."""


@dataclass(frozen=True)
class Packed:
    """One file as it went into an archive: how many bytes, their SHA-256, and the file's time
    when they were read."""

    size: int
    sha256: str
    mtime: float


KINDS = ("finished", "exported")


def packed_id(archive: Path) -> str | None:
    """The ID of the box an archive holds, from the box.toml in it. None for a file that is not
    a box's archive, or that cannot be read: whose it is, is then not known."""
    try:
        with _open(archive) as tar:
            for member in tar:
                parts = member.name.split("/")
                if len(parts) == 2 and parts[1] == "box.toml":
                    if not member.isreg() or member.issparse() or not 0 <= member.size <= MAX_SMALL_TOML_BYTES:
                        return None
                    tar.fileobj.entries_read()
                    found = tomllib.loads(b"".join(_pieces(tar, member)).decode("utf-8")).get("id")
                    return found if isinstance(found, str) else None
                tar.fileobj.next_entry()
    except Exception:
        # an unreadable file is nobody's: it is neither replaced nor offered for replacing
        pass
    return None


def _another_s(wrapped: Path, name: str, box_id: str) -> bool:
    # an archive under this name that is there and does not hold this box
    for kind in KINDS:
        archive = wrapped / f"{name}.{kind}.tar.gz"
        if os.path.lexists(archive) and packed_id(archive) != box_id:
            return True
    return False


def free_name(paths: AppPaths, name: str, box_id: str) -> str:
    """The name a box's folder and archives go under, given the one it has or came with: that
    name, unless wrapped/ holds an archive of another box under it. Then the first of name-2,
    name-3 and on that is neither another box's folder nor another box's archive, as a second
    new box of a name gets. So one box's archive is never replaced by another's."""
    number = 1
    while True:
        found = name if number == 1 else f"{name}-{number}"
        taken = number > 1 and os.path.lexists(paths.active / found)
        if not taken and not _another_s(paths.wrapped, found, box_id):
            return found
        number += 1


def archive_path(paths: AppPaths, box: Box, kind: str) -> Path:
    return paths.wrapped / f"{free_name(paths, box.path.name, box.id)}.{kind}.tar.gz"


def write_manifest(
    box: Box,
    records: list[FileRecord],
    *,
    kind: str,
    now: datetime,
    running_scans: list[dict] | None = None,
) -> Path:
    """Writes manifest.toml into the box: what kind of archive, when, whose, and each file with
    its size and SHA-256. `running_scans` names the scans that were still writing into the box
    when it was packed, each by target, plan and start; the key is left out when there were none."""
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
    data = {
        "schema": SCHEMA,
        "kind": kind,
        "packed": now,
        "box": {k: v for k, v in described.items() if v is not None},
    }
    if running_scans:
        data[RUNNING_SCANS] = running_scans
    # the files last, as they always were: every reader finds each key by its name
    data["file"] = [asdict(r) for r in records]
    write_toml(path, data)
    return path


# what a scan's plan reads as: its modes in order, as scanning writes them into its marker
_PLAN = re.compile(r"[a-z]{1,16}( then [a-z]{1,16}){0,7}")
_TARGET = re.compile(r"[a-z0-9][a-z0-9.-]{0,254}")


def running_scans(folder: Path) -> list[dict]:
    """The scans a box's manifest.toml says were still running when it was packed, each with
    its target and plan. A manifest without the list, one that cannot be read, and a row that
    is not as the app writes it give none: this is said to the user, and decides nothing."""
    try:
        path = folder / MANIFEST
        if path.stat().st_size > _MANIFEST_LIMIT:
            return []
        rows = tomllib.loads(path.read_text(encoding="utf-8")).get(RUNNING_SCANS, [])
    except (OSError, ValueError, RecursionError, MemoryError):
        return []
    found = []
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, dict):
            continue
        target, plan = row.get("target"), row.get("plan")
        if (
            isinstance(target, str)
            and isinstance(plan, str)
            and _TARGET.fullmatch(target)
            and _PLAN.fullmatch(plan)
        ):
            found.append({"target": target, "plan": plan})
    return found


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
    """A file read no further than its first `size` bytes, with the SHA-256 of what was read."""

    def __init__(self, fh, size: int) -> None:
        self._fh = fh
        self.left = size
        self.digest = hashlib.sha256()

    def read(self, n: int = -1) -> bytes:
        n = self.left if n is None or n < 0 else min(n, self.left)
        data = self._fh.read(n)
        self.left -= len(data)
        self.digest.update(data)
        return data


def _info(tar: tarfile.TarFile, full: Path, arcname: str, rel: str, root: str) -> tarfile.TarInfo:
    # A folder on the way that was swapped for a link since the walk would lead out of the box,
    # and what is there would be packed as the box's. The folder is resolved again just before
    # the entry is read: that narrows the gap to the read itself, it does not close it.
    above = rel.rpartition("/")[0]
    expected = os.path.join(root, *above.split("/")) if above else root
    if rel and os.path.realpath(full.parent) != expected:
        raise ArchiveError(f"{rel} is no longer inside the box: a folder on the way to it is now a link")
    info = tar.gettarinfo(full, arcname=arcname)
    if info is None:
        raise ArchiveError(f"{rel} is not a file or folder that can be packed")
    if info.islnk():
        # a second name of a file already packed: tarfile would write a link to the first, and
        # the manifest lists each name as a file of its own
        info.type = tarfile.REGTYPE
        info.linkname = ""
        info.size = os.lstat(full).st_size
    return info


def _add(
    tar: tarfile.TarFile, full: Path, arcname: str, rel: str, root: str, size: int | None = None
) -> Packed | None:
    """Adds one file or folder, and for a file returns what went in.

    A file is packed as long as it is at the moment it is opened, or up to `size` when one is
    given (a recording still being written, up to its last whole line). Something may be
    writing to it: what it gains after that moment is not packed, and the bytes that are
    packed are the bytes hashed, so the manifest made from this can only agree with the archive.
    """
    info = _info(tar, full, arcname, rel, root)
    if not info.isreg():
        tar.addfile(info)
        return None
    with open(full, "rb") as fh:
        found = os.fstat(fh.fileno())
        if size is None:
            size = found.st_size
        elif found.st_size < size:
            raise ArchiveError(f"{rel} is shorter than the {size} bytes recorded for it")
        # the header says how long the entry is before any of it is read
        info.size = size
        info.mtime = found.st_mtime
        head = _Head(fh, size)
        try:
            tar.addfile(info, head)
        except OSError as exc:
            if head.left:
                # tarfile stops when the file ends before its header's length: the entry is
                # cut short in the archive, which cannot be mended from here
                raise Shrunk(f"{rel} got shorter while it was being packed") from exc
            raise
    return Packed(size, head.digest.hexdigest(), found.st_mtime)


def pack(
    box: Box,
    dest: Path,
    cut: Mapping[str, int] | None = None,
    manifest: Callable[[dict[str, Packed]], object] | None = None,
) -> list[str]:
    """Write the box to dest; a path in `cut` is packed only up to that many bytes.

    `manifest` is how the archive comes to describe itself. Every other file is packed first;
    then it is called with what went in, each file's size, SHA-256 and time by its path in the
    box, and writes the box's manifest.toml from that; the manifest is then packed last. So a
    file something is still writing to, a scan's output for one, is listed as it was packed and
    not as it was when the box was last read. Without it the manifest.toml already in the box
    is packed where it falls, like any file.

    A file that is gone by the time it is reached is left out, as it is from what `manifest`
    is given. Returns the links and special files that were left out, relative to the box.
    """
    cut = cut or {}
    part = dest.with_name(dest.name + ".part")
    top = box.path.name
    try:
        # an archive holds the box's credentials and its note: wrapped/ and the archive are
        # their owner's alone, from the first byte written
        private.folder(dest.parent)
        entries, special = _entries(box.path)
        root = os.path.realpath(box.path)
        if len(entries) > MAX_ENTRIES:
            # said before an archive that could not be read back is written
            raise ArchiveError(
                f"the box holds {len(entries)} files and folders, and an archive holds {MAX_ENTRIES} at most"
            )
        with private.create(part) as out, tarfile.open(part, "w:gz", fileobj=out) as tar:
            packed: dict[str, Packed] = {}
            for rel, full in entries:
                if manifest is not None and rel == MANIFEST:
                    # the one a packing before this left: this archive's own goes in last
                    continue
                arcname = f"{top}/{rel}" if rel else top
                try:
                    done = _add(tar, full, arcname, rel, root, cut.get(rel))
                except FileNotFoundError:
                    # removed since the box was walked: nothing of it has been written
                    continue
                if done is not None:
                    packed[rel] = done
            if manifest is not None:
                manifest(packed)
                _add(tar, box.path / MANIFEST, f"{top}/{MANIFEST}", MANIFEST, root)
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
        if first.startswith("."):
            # the app's own temporary folders in active/ start with one, and no list shows such a folder
            raise ArchiveError(f"archive's folder {first[:60]!r} starts with a dot, which a box's never does")
        if not BOX_FOLDER.fullmatch(first):
            # the name becomes a folder in active/ and is printed in paths meant to be copied
            raise ArchiveError(
                f"archive's folder {first[:60]!a} is not named as a box's folder is: "
                "lowercase letters, digits, dots, hyphens and underscores, a letter or digit first"
            )
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


_TOO_MUCH_HEADER = "archive has more header than a box's archive ever has"


class _Capped:
    """The unzipped archive as tarfile reads it, 64 KiB at a time at most.

    tarfile reads an extended header or a long name whole, or a megabyte of it at a time, at
    whatever length the archive gives for it, and a megabyte of gzip can give one of a gigabyte.
    Everything a box's archive really holds is read in smaller pieces: its headers are a few
    kilobytes, and file data is read _PIECE at a time, by _pieces here and by tarfile when it
    unpacks (copybufsize). tarfile's own reader for one entry is not used: it asks for as much
    as Python's default buffer holds, which is more than this from Python 3.14 on.
    """

    def __init__(self, fh) -> None:
        self._fh = fh
        # header bytes, and line ends in them, read since the last entry, while the entries
        # are being read
        self.entry_bytes = 0
        self.entry_lines = 0
        self._headers = True

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0 or size > _PIECE:
            raise ArchiveError("archive has a header longer than 64 KiB, which a box's archive never has")
        data = self._fh.read(size)
        if self._headers:
            # a sparse entry's map is read a block at a time, for as long as the archive says
            # there is more of it, and no single read is large
            self.entry_bytes += len(data)
            self.entry_lines += data.count(b"\n")
            if self.entry_bytes > _ENTRY_HEADER_BYTES:
                raise ArchiveError(_TOO_MUCH_HEADER)
        return data

    def next_entry(self) -> None:
        self.entry_bytes = 0
        self.entry_lines = 0

    def entries_read(self) -> None:
        # from here on only file data is read
        self._headers = False

    def seek(self, *args) -> int:
        return self._fh.seek(*args)

    def tell(self) -> int:
        return self._fh.tell()


def _said(exc: Exception) -> str:
    return str(exc) or type(exc).__name__


def _unreadable(archive: Path, exc: Exception) -> ArchiveError:
    # whatever tarfile raises on an archive it cannot make sense of: it has more kinds of error
    # than it documents (a ValueError for a size too large to seek to, for one)
    return ArchiveError(f"{archive}: cannot read archive ({_said(exc)})")


@contextmanager
def _open(archive: Path) -> Iterator[tarfile.TarFile]:
    try:
        unzipped = gzip.GzipFile(archive)
    except OSError as exc:
        raise ArchiveError(f"{archive}: cannot open as a gzip tar ({exc})") from exc
    with unzipped:
        try:
            tar = tarfile.open(fileobj=_Capped(unzipped), mode="r:", copybufsize=_PIECE)
        except ArchiveError:
            raise
        except Exception as exc:
            raise ArchiveError(f"{archive}: cannot open as a gzip tar ({_said(exc)})") from exc
        with tar:
            yield tar


def _pieces(tar: tarfile.TarFile, member: tarfile.TarInfo) -> Iterator[bytes]:
    # the entry's data, straight from the archive. No entry is sparse (_check_member), so its
    # data is one run of member.size bytes.
    tar.fileobj.seek(member.offset_data)
    left = member.size
    while left:
        piece = tar.fileobj.read(min(_PIECE, left))
        if not piece:
            raise ArchiveError(f"archive ends inside {member.name!r}")
        left -= len(piece)
        yield piece


def _members(tar: tarfile.TarFile) -> list[tarfile.TarInfo]:
    """Every entry of the archive, each one checked as it is read.

    Read one at a time, not all first: an archive of nothing but entries is refused at the
    limit, before the rest of it is held in memory.
    """
    members: list[tarfile.TarInfo] = []
    names = 0
    for member in tar:
        if tar.pax_headers:
            # its records are copied onto every entry that follows
            raise ArchiveError("archive has a global extended header, which a box's archive never has")
        _check_member(member)
        # tarfile keeps the records of each entry's own extended header, and the owner's names,
        # which such a record may make as long as a header may be; nothing here reads them
        member.pax_headers = {}
        member.uname = member.gname = ""
        name_bytes = len(member.name.encode("utf-8", "surrogateescape"))
        if tar.fileobj.entry_bytes > _HEADER_ROOM + 2 * name_bytes:
            raise ArchiveError(_TOO_MUCH_HEADER)
        if tar.fileobj.entry_lines > _HEADER_LINES + 2 * member.name.count("\n"):
            raise ArchiveError(_TOO_MUCH_HEADER)
        names += name_bytes
        if len(members) == MAX_ENTRIES or names > _MAX_NAMES_BYTES:
            raise ArchiveError(f"archive has more than {MAX_ENTRIES} entries, or names too long to hold")
        members.append(member)
        tar.fileobj.next_entry()
    tar.fileobj.entries_read()
    return members


def peek_folder(archive: Path) -> str:
    try:
        with _open(archive) as tar:
            return _top_folder(_members(tar))
    except ArchiveError:
        raise
    except Exception as exc:
        raise _unreadable(archive, exc) from exc


def _manifest_rows(tar: tarfile.TarFile, member: tarfile.TarInfo | None) -> list[dict]:
    if member is None or not member.isreg():
        raise ArchiveError(f"{MANIFEST} is missing from the archive")
    if member.size > _MANIFEST_LIMIT:
        raise ArchiveError(f"{MANIFEST} is too large ({member.size} bytes)")
    try:
        data = tomllib.loads(b"".join(_pieces(tar, member)).decode("utf-8"))
    except (RecursionError, MemoryError) as exc:
        raise ArchiveError(f"{MANIFEST} is nested too deeply, or too large, to read") from exc
    except ValueError as exc:  # not UTF-8, not TOML, or a number too long to read
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
            members = _members(tar)
            top = _top_folder(members)
            by_name = {m.name: m for m in members}
            rows = _manifest_rows(tar, by_name.get(f"{top}/{MANIFEST}"))
            wanted = []
            listed: set[str] = set()
            for row in rows:
                path, size, checksum = row.get("path"), row.get("size"), row.get("sha256")
                if not checksum:
                    raise ArchiveError(f"{path}: no checksum recorded")
                if path in listed:
                    # each row is hashed, and a few bytes can list one file a million times
                    raise ArchiveError(f"{path}: listed twice in the manifest")
                listed.add(path)
                member = by_name.get(f"{top}/{path}")
                if member is None or not member.isreg():
                    raise ArchiveError(f"{path}: missing from the archive")
                if member.size != size:
                    raise ArchiveError(f"{path}: size differs from the manifest")
                wanted.append((member, path, checksum))
            # archive order, so the gzip stream is only ever read forwards
            for member, path, checksum in sorted(wanted, key=lambda w: w[0].offset_data):
                digest = hashlib.sha256()
                for piece in _pieces(tar, member):
                    digest.update(piece)
                if digest.hexdigest() != checksum:
                    raise ArchiveError(f"{path}: checksum differs from the manifest")
    except ArchiveError:
        raise
    except Exception as exc:
        raise _unreadable(archive, exc) from exc


def _backslash_separates() -> bool:
    # on Linux a backslash is an ordinary file name character; elsewhere it separates paths
    return os.sep == "\\"


def _check_member(member: tarfile.TarInfo) -> None:
    name = member.name
    parts = name.split("/")
    if name.startswith("/") or (_backslash_separates() and "\\" in name) or ".." in parts:
        raise ArchiveError(f"archive entry {name!r} would write outside the destination")
    if len(name.encode("utf-8", "surrogateescape")) > MAX_NAME_BYTES:
        raise ArchiveError(f"archive entry {name[:60]!r}... has a name longer than a path may be")
    if not (member.isreg() or member.isdir()):
        raise ArchiveError(f"archive entry {name!r} is not a regular file or folder")
    if member.linkname:
        # kept on every entry, and an extended header can make it as long as a header may be
        raise ArchiveError(f"archive entry {name[:60]!r} names a link target, which a file or folder has none of")
    # An extended header can give these as numbers thousands of digits long, and tarfile keeps
    # each one on the entry. A folder holds no data; an owner is a 32-bit number.
    if member.size < 0 or (member.isdir() and member.size):
        raise ArchiveError(f"archive entry {name[:60]!r} has a size no file or folder has")
    if not (0 <= member.uid <= _MAX_OWNER and 0 <= member.gid <= _MAX_OWNER):
        raise ArchiveError(f"archive entry {name[:60]!r} has an owner number no user or group has")
    if member.issparse():
        # a few hundred bytes can stand for any number of gigabytes of zeros
        raise ArchiveError(f"archive entry {name!r} is a sparse file, which a box's archive never holds")


def _check_room(members: list[tarfile.TarInfo], active: Path) -> None:
    # a megabyte of gzip can hold a gigabyte of zeros: known before the disk is full, not after
    needed = sum(member.size for member in members if member.isreg())
    free = shutil.disk_usage(active).free
    if needed > free:
        raise ArchiveError(
            f"the archive unpacks to {needed // _MIB + 1} MiB and {active} has {free // _MIB} MiB free"
        )


def unpack(
    archive: Path,
    active: Path,
    *,
    replace: bool = False,
    check: Callable[[Path], object] | None = None,
) -> Path:
    """Unpacks the archive's one folder into active and returns it.

    `check` is given the folder where it was unpacked, before anything in active is moved: what
    it raises stops the unpack with the folder that was there, if any, untouched. It may return
    another name for the folder to have in active, which must be free.
    """
    if not hasattr(tarfile, "data_filter"):
        raise ArchiveError("this Python cannot unpack archives safely; install a newer Python 3.11 patch release")
    tmp: Path | None = None
    try:
        try:
            with _open(archive) as tar:
                members = _members(tar)
                top = _top_folder(members)
                final = active / top
                if os.path.lexists(final) and not replace:
                    raise ArchiveError(f"{final} already exists")
                active.mkdir(parents=True, exist_ok=True)
                _check_room(members, active)
                tmp = Path(tempfile.mkdtemp(prefix=".import-", dir=active))
                tar.extractall(tmp, filter=tarfile.data_filter)
                # unpacked, a folder has the mode the umask gives: the box's is its owner's
                # alone before it is moved to where others could look
                private.unpacked(tmp / top)
        except ArchiveError:
            raise
        except Exception as exc:
            # whatever tarfile raises on an archive it cannot make sense of: it has more kinds
            # of error than it documents (a ValueError for a size too large to seek to, for one)
            raise ArchiveError(f"cannot unpack {archive}: {_said(exc)}") from exc
        # what the caller's check raises is the caller's: it is not an error in the archive
        if check is not None:
            renamed = check(tmp / top)
            if isinstance(renamed, str) and renamed != top:
                if not BOX_FOLDER.fullmatch(renamed):
                    raise ArchiveError(f"{renamed!a} is not a name for a box's folder")
                # never over a folder that is there: the question was about the archive's own name
                final, replace = active / renamed, False
        try:
            _move_into_place(tmp / top, final, replace)
        except OSError as exc:
            raise ArchiveError(f"cannot unpack {archive}: {_said(exc)}") from exc
        return final
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
        # as private as the archive, wherever copy_to is
        private.copy(archive, part)
        if sha256_file(part) != sha256_file(archive):
            raise ArchiveError(f"copy to {copy_to} failed: checksum differs from the original")
        os.replace(part, final)
    except BaseException as exc:
        _discard(part)
        if isinstance(exc, OSError):
            raise ArchiveError(f"cannot copy to {copy_to}: {exc}") from exc
        raise
    return final
