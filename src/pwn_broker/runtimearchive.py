"""Unpacking a runtime's archive: a gzip tar holding a self-contained Python.

The whole archive is read and every member checked before anything is written, and each one is
then written here rather than by tarfile's extraction, whose filters differ across Python 3.11
patch releases.
"""

import gzip
import os
import shutil
import tarfile
import tempfile
import zlib
from collections import deque
from collections.abc import Iterable, Iterator
from pathlib import Path

from pwn_broker.filescan import TEMP_PREFIX, TEMP_SUFFIX
from pwn_broker.toolpkg import MAX_PART_BYTES, MAX_PATH_BYTES, ToolError
from pwn_broker.toolpkg import bad_characters as _bad_characters
from pwn_broker.toolpkg import shown as _shown
from pwn_broker.toolpkg import too_long as _too_long

MAX_MEMBERS = 20_000
MAX_BYTES = 1024**3
# as many links as Linux follows in one lookup
MAX_LINK_HOPS = 40
# what an entry may take beyond its own data: its headers, a PAX record holding a name and a
# target at the limits, and the padding and end blocks after the last entry
_HEADER_ALLOWANCE = 16 * 1024

_CHUNK = 1024 * 1024
_BLOCK = tarfile.BLOCKSIZE
_READ_ERRORS = (tarfile.TarError, OSError, EOFError, zlib.error)
# what tarfile raises, beyond its own errors, for a header it cannot parse
_HEADER_ERRORS = (*_READ_ERRORS, ValueError, UnicodeError, OverflowError)


def _is_file(member: tarfile.TarInfo) -> bool:
    # tarfile counts a sparse file as regular; its body is not laid out as a plain file's is
    return member.isreg() and member.type != tarfile.GNUTYPE_SPARSE and not member.issparse()


def _check_name(member: tarfile.TarInfo) -> str:
    # judged as text; returns the name without a folder's trailing slash
    name = member.name
    if fault := _too_long(name):
        raise ToolError(f"runtime archive entry {_shown(name)} has a name {fault}")
    bare = name[:-1] if name.endswith("/") and member.isdir() else name
    parts = bare.split("/")
    if name.startswith("/") or ".." in parts:
        raise ToolError(f"runtime archive entry {name!r} would write outside the runtime's folder")
    if _bad_characters(name):
        raise ToolError(
            f"runtime archive entry {name!r} has a backslash, colon or control character "
            "in its name"
        )
    if any(p in ("", ".") for p in parts):
        raise ToolError(f"runtime archive entry {name!r} has an empty or '.' part in its name")
    return bare


def _check_target(name: str, target: str) -> None:
    if not target:
        raise ToolError(f"runtime archive link {name!r} has an empty target")
    if fault := _too_long(target):
        raise ToolError(f"runtime archive link {name!r} has a target {fault}")
    if target.startswith("/"):
        raise ToolError(f"runtime archive link {name!r} has the absolute target {target!r}")
    if _bad_characters(target):
        raise ToolError(
            f"runtime archive link {name!r} has a backslash, colon or control character "
            "in its target"
        )


# A tree of the archive's links by path part: each node maps a part to the node below it, and a
# link's node holds its target under the key None. Each step of a resolution is then one lookup.
_Node = dict


def _link_tree(links: dict[str, str]) -> _Node:
    root: _Node = {}
    for name, target in links.items():
        node = root
        for part in name.split("/"):
            node = node.setdefault(part, {})
        node[None] = target
    return root


def _resolve(name: str, root: _Node) -> None:
    """Follows the link `name` as the system would, through the archive's other links, as text.

    A `..` that would climb above the destination, or a result that is the destination itself,
    is refused, so the link can only reach a place inside the destination.
    """
    outside = f"runtime archive link {name!r} points outside the runtime's folder"
    # the node of each part resolved so far; None once the path leaves every link's folder
    stack: list[_Node | None] = [root]
    *folder, last = name.split("/")
    node = root
    for part in folder:
        # the link's own folder is in the tree, since the link is
        node = node[part]
        stack.append(node)
    pending = deque(node[last][None].split("/"))
    hops = 1
    while pending:
        part = pending.popleft()
        if part in ("", "."):
            continue
        if part == "..":
            if len(stack) == 1:
                raise ToolError(outside)
            stack.pop()
            continue
        node = stack[-1].get(part) if stack[-1] is not None else None
        if node is not None and None in node:
            hops += 1
            if hops > MAX_LINK_HOPS:
                raise ToolError(f"runtime archive link {name!r} goes through too many links")
            pending.extendleft(reversed(node[None].split("/")))
            continue
        stack.append(node)
    if len(stack) == 1:
        raise ToolError(outside)


def _checked(members: Iterable[tarfile.TarInfo]) -> dict[str, tarfile.TarInfo]:
    seen: dict[str, tarfile.TarInfo] = {}
    total = 0
    for member in members:
        if len(seen) >= MAX_MEMBERS:
            raise ToolError(f"runtime archive has too many entries; the limit is {MAX_MEMBERS}")
        if not (_is_file(member) or member.isdir() or member.issym()):
            raise ToolError(
                f"runtime archive entry {_shown(member.name)} is not a regular file, folder or "
                "symbolic link"
            )
        bare = _check_name(member)
        if bare in seen:
            raise ToolError(f"runtime archive entry {member.name!r} appears twice")
        if member.issym():
            _check_target(member.name, member.linkname)
        if _is_file(member):
            total += member.size
            if total > MAX_BYTES:
                raise ToolError(f"runtime archive unpacks to more than {MAX_BYTES} bytes")
        seen[bare] = member
    return seen


def check(members: Iterable[tarfile.TarInfo]) -> None:
    """Raises ToolError for the first member that breaks a rule. Reads no file system."""
    _check_all(members)


def _check_all(members: Iterable[tarfile.TarInfo]) -> dict[str, tarfile.TarInfo]:
    seen = _checked(members)
    for bare in seen:
        # nothing may be written through a link or inside a file
        parent = bare.rpartition("/")[0]
        while parent:
            above = seen.get(parent)
            if above is not None and above.issym():
                raise ToolError(
                    f"runtime archive entry {bare!r} would be written through the link {parent!r}"
                )
            if above is not None and not above.isdir():
                raise ToolError(f"runtime archive entry {bare!r} sits inside the file {parent!r}")
            parent = parent.rpartition("/")[0]
    links = {bare: m.linkname for bare, m in seen.items() if m.issym()}
    root = _link_tree(links)
    for bare in links:
        _resolve(bare, root)
    return seen


# ---- reading


class _Bounded:
    """The archive's decompressed bytes, which may not be read or skipped past `limit`.

    The limit starts at one entry's allowance and moves on only as each entry passes the
    checks, so no header, however large it claims to be, is read beyond what an entry may take,
    and no archive makes the app decompress more than MAX_BYTES plus an allowance per entry.
    """

    def __init__(self, stream: gzip.GzipFile):
        self._stream = stream
        self.limit = _HEADER_ALLOWANCE

    def _allow(self, end: int) -> None:
        if end > self.limit:
            raise ToolError("runtime archive holds more data than its entries declare")

    def tell(self) -> int:
        return self._stream.tell()

    def seek(self, pos: int, whence: int = os.SEEK_SET) -> int:
        if whence != os.SEEK_SET:
            raise ValueError("only absolute seeks are supported")
        self._allow(pos)
        return self._stream.seek(pos)

    def read(self, size: int = -1) -> bytes:
        if size is None or size < 0:
            raise ValueError("reads must name a size")
        self._allow(self.tell() + size)
        return self._stream.read(size)

    def read_to_end(self) -> None:
        # the gzip stream's CRC and length are checked as its end is read
        while (room := self.limit - self.tell()) > 0:
            if not self._stream.read(min(_CHUNK, room)):
                return
        if self._stream.read(1):
            raise ToolError("runtime archive holds more data than its entries declare")


def _allowing(tar: tarfile.TarFile, reader: _Bounded) -> Iterator[tarfile.TarInfo]:
    for member in tar:
        yield member
        # the member passed the checks: its data, and the next header, may now be read
        data = -(-member.size // _BLOCK) * _BLOCK if _is_file(member) else 0
        reader.limit = member.offset_data + data + _HEADER_ALLOWANCE


def _read_all(tar: tarfile.TarFile, reader: _Bounded) -> dict[str, tarfile.TarInfo]:
    seen = _check_all(_allowing(tar, reader))
    # tarfile ends quietly at a damaged header or at a cut, so the end is checked here: a tar
    # ends with two blocks of zeros, and tarfile stops at the first without looking for the second
    reader.seek(tar.offset)
    if reader.read(2 * _BLOCK) != bytes(2 * _BLOCK):
        raise ToolError("runtime archive is incomplete or damaged: it does not end as a tar does")
    reader.read_to_end()
    return seen


# ---- writing


def _make_folder(root: Path, parts: list[str]) -> Path:
    folder = root
    for part in parts:
        folder = folder / part
        if not folder.is_dir():
            folder.mkdir()
            # set after making, so the umask has no say
            folder.chmod(0o755)
    return folder


def _write_file(tar: tarfile.TarFile, member: tarfile.TarInfo, target: Path) -> None:
    mode = 0o755 if member.mode & 0o111 else 0o644
    src = tar.extractfile(member)
    if src is None:
        raise ToolError(f"runtime archive entry {member.name!r} has no data")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    total = 0
    with src, os.fdopen(os.open(target, flags, mode), "wb") as out:
        while chunk := src.read(_CHUNK):
            total += len(chunk)
            if total > member.size:
                break
            out.write(chunk)
    if total != member.size:
        raise ToolError(f"runtime archive entry {member.name!r} is not the size it declares")
    target.chmod(mode)


def _extract(tar: tarfile.TarFile, seen: dict[str, tarfile.TarInfo], root: Path) -> None:
    # folders and files first, links last, so nothing is written through a link
    for bare, member in seen.items():
        parts = bare.split("/")
        if member.isdir():
            _make_folder(root, parts)
        elif _is_file(member):
            _write_file(tar, member, _make_folder(root, parts[:-1]) / parts[-1])
    for bare, member in seen.items():
        if member.issym():
            parts = bare.split("/")
            try:
                os.symlink(member.linkname, _make_folder(root, parts[:-1]) / parts[-1])
            except (OSError, NotImplementedError) as exc:
                raise ToolError(f"cannot make the link {bare!r}: {exc}") from exc


def _remove(tmp: Path) -> str | None:
    try:
        shutil.rmtree(tmp)
    except OSError as exc:
        return f"the temporary folder {tmp} could not be removed ({exc})"
    return None


def unpack(archive: Path, dest: Path) -> None:
    """Unpacks the runtime's gzip tar into dest, which must not exist, or leaves nothing.

    The archive is unpacked into a temporary folder beside dest and renamed into place. The
    caller must own dest's parent folder and hold the install for itself, as the app's commands
    do, and no one else may be able to write to that folder: on Linux a rename replaces an empty
    folder, so a dest made by someone else between the check and the rename would be replaced.
    """
    if os.path.lexists(dest):
        raise ToolError(f"{dest} already exists")
    tmp: Path | None = None
    try:
        try:
            raw = open(archive, "rb")
        except OSError as exc:
            raise ToolError(f"cannot unpack {archive.name}: {exc}") from exc
        with raw, gzip.GzipFile(fileobj=raw, mode="rb") as stream:
            reader = _Bounded(stream)
            damaged = f"cannot unpack {archive.name}: the archive is incomplete or damaged"
            try:
                tar = tarfile.open(fileobj=reader, mode="r:")
            except _HEADER_ERRORS as exc:
                raise ToolError(f"{damaged} ({exc})") from exc
            with tar:
                try:
                    seen = _read_all(tar, reader)
                except _HEADER_ERRORS as exc:
                    raise ToolError(f"{damaged} ({exc})") from exc
                try:
                    tmp = Path(
                        tempfile.mkdtemp(prefix=TEMP_PREFIX, suffix=TEMP_SUFFIX, dir=dest.parent)
                    )
                    tmp.chmod(0o755)
                    # every header has been read, so this reads only the files' data
                    _extract(tar, seen, tmp)
                except _READ_ERRORS as exc:
                    raise ToolError(f"cannot unpack {archive.name}: {exc}") from exc
        try:
            if os.path.lexists(dest):
                raise ToolError(f"{dest} already exists")
            os.rename(tmp, dest)
        except OSError as exc:
            raise ToolError(f"cannot unpack {archive.name}: {exc}") from exc
    except BaseException as exc:
        failed = _remove(tmp) if tmp is not None else None
        if failed is None:
            raise
        if isinstance(exc, ToolError):
            raise ToolError(f"{exc}; {failed}") from exc
        exc.add_note(failed)
        raise
