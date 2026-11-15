"""Unpacking a runtime's archive: a gzip tar holding a self-contained Python.

Every member is checked before anything is written, and each one is then written here rather
than by tarfile's extraction, whose filters differ across Python 3.11 patch releases.
"""

import os
import shutil
import tarfile
import tempfile
import unicodedata
import zlib
from collections.abc import Iterable
from pathlib import Path

from pwn_broker.filescan import TEMP_PREFIX, TEMP_SUFFIX
from pwn_broker.toolpkg import ToolError

MAX_MEMBERS = 20_000
MAX_BYTES = 1024**3
# as many links as Linux follows in one lookup
MAX_LINK_HOPS = 40

_CHUNK = 1024 * 1024
_READ_ERRORS = (tarfile.TarError, OSError, EOFError, zlib.error)


def _bad_characters(text: str) -> bool:
    return any(c in "\\:" or unicodedata.category(c) == "Cc" for c in text)


def _is_file(member: tarfile.TarInfo) -> bool:
    # tarfile counts a sparse file as regular; its body is not laid out as a plain file's is
    return member.isreg() and member.type != tarfile.GNUTYPE_SPARSE and not member.issparse()


def _check_name(member: tarfile.TarInfo) -> str:
    # judged as text; returns the name without a folder's trailing slash
    name = member.name
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
    if target.startswith("/"):
        raise ToolError(f"runtime archive link {name!r} has the absolute target {target!r}")
    if _bad_characters(target):
        raise ToolError(
            f"runtime archive link {name!r} has a backslash, colon or control character "
            "in its target"
        )


def _resolve(name: str, links: dict[str, str]) -> None:
    """Follows the link `name` as the system would, through the archive's other links, as text.

    A `..` that would climb above the destination, or a result that is the destination itself,
    is refused, so the link can only reach a place inside the destination.
    """
    outside = f"runtime archive link {name!r} points outside the runtime's folder"
    resolved = name.split("/")[:-1]
    pending = links[name].split("/")
    hops = 1
    while pending:
        part = pending.pop(0)
        if part in ("", "."):
            continue
        if part == "..":
            if not resolved:
                raise ToolError(outside)
            resolved.pop()
            continue
        resolved.append(part)
        target = links.get("/".join(resolved))
        if target is not None:
            hops += 1
            if hops > MAX_LINK_HOPS:
                raise ToolError(f"runtime archive link {name!r} goes through too many links")
            resolved.pop()
            pending = target.split("/") + pending
    if not resolved:
        raise ToolError(outside)


def _checked(members: Iterable[tarfile.TarInfo]) -> dict[str, tarfile.TarInfo]:
    seen: dict[str, tarfile.TarInfo] = {}
    total = 0
    for member in members:
        if len(seen) >= MAX_MEMBERS:
            raise ToolError(f"runtime archive has too many entries; the limit is {MAX_MEMBERS}")
        if not (_is_file(member) or member.isdir() or member.issym()):
            raise ToolError(
                f"runtime archive entry {member.name!r} is not a regular file, folder or "
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
    for bare in links:
        _resolve(bare, links)
    return seen


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


def unpack(archive: Path, dest: Path) -> None:
    """Unpacks the runtime's gzip tar into dest, which must not exist, or leaves nothing."""
    if os.path.lexists(dest):
        raise ToolError(f"{dest} already exists")
    tmp: Path | None = None
    try:
        with tarfile.open(archive, "r:gz") as tar:
            # iterating the archive reads one header at a time, so the member limit stops a
            # huge archive before all of it is read
            seen = _check_all(tar)
            tmp = Path(tempfile.mkdtemp(prefix=TEMP_PREFIX, suffix=TEMP_SUFFIX, dir=dest.parent))
            tmp.chmod(0o755)
            _extract(tar, seen, tmp)
        if os.path.lexists(dest):
            raise ToolError(f"{dest} already exists")
        os.rename(tmp, dest)
    except BaseException as exc:
        if tmp is not None:
            shutil.rmtree(tmp, ignore_errors=True)
        if isinstance(exc, ToolError) or not isinstance(exc, Exception):
            raise
        raise ToolError(f"cannot unpack {archive.name}: {exc}") from exc
