import ipaddress
import os
import re
import secrets
import stat
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from pwn_broker import privilege

DEFAULT_PATH = Path("/etc/hosts")

BOX_ID = re.compile(r"[A-Za-z0-9._-]+")
LABEL = re.compile(r"[A-Za-z0-9](?:[A-Za-z0-9-]*[A-Za-z0-9])?")
# ipaddress accepts an IPv6 scope ID holding any character, spaces and line breaks included
IP_CHARS = re.compile(r"[0-9A-Fa-f.:]+")
MARKER = re.compile(rb"# pwn-broker ([A-Za-z0-9._-]+)[ \t]*")
FIELD_GAP = re.compile(rb"[ \t]+")
CHANGED = "changed"


class HostsError(Exception):
    """/etc/hosts cannot be read, written or given the requested line."""


@dataclass
class Wanted:
    target: str
    ip: str
    names: list[str]


@dataclass
class Outcome:
    text: bytes
    written: list[str]
    taken_out: list[tuple[str, str]]
    already: list[tuple[str, str]]
    blocked: list[tuple[str, str, int, str]]


def valid_hostname(name: str) -> bool:
    if not 1 <= len(name) <= 253:
        return False
    return all(LABEL.fullmatch(label) for label in name.split("."))


def _check_id(box_id: str) -> None:
    if not BOX_ID.fullmatch(box_id):
        raise HostsError(f"not a box ID: {box_id!r}")


def _parse_ip(value: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address:
    if IP_CHARS.fullmatch(value):
        try:
            return ipaddress.ip_address(value)
        except ValueError:
            pass
    raise HostsError(f"not an IP address: {value!r}")


def _check(wanted: Wanted) -> None:
    _parse_ip(wanted.ip)
    for name in wanted.names:
        if not valid_hostname(name):
            raise HostsError(f"not a plain hostname: {name!r}")


def line(wanted: Wanted, box_id: str) -> str:
    _check(wanted)
    _check_id(box_id)
    if not wanted.names:
        raise HostsError(f"no hostnames for {wanted.target}")
    ip = str(_parse_ip(wanted.ip))
    return f"{ip} {' '.join(wanted.names)}  # pwn-broker {box_id}"


def _split(text: bytes) -> list[bytes]:
    # Only \n ends a line, as for the resolver; each piece keeps its ending.
    parts = text.split(b"\n")
    pieces = [part + b"\n" for part in parts[:-1]]
    if parts[-1]:
        pieces.append(parts[-1])
    return pieces


def _content(raw: bytes) -> bytes:
    if raw.endswith(b"\r\n"):
        return raw[:-2]
    if raw.endswith(b"\n"):
        return raw[:-1]
    return raw


def _owner(content: bytes) -> str | None:
    """The box ID a line is marked for, or None for an unmarked line."""
    hash_at = content.find(b"#")
    if hash_at < 0 or not content[:hash_at].strip():
        return None
    found = MARKER.fullmatch(content, hash_at)
    return found.group(1).decode("ascii") if found else None


def _key(name: str) -> bytes:
    # a valid hostname is ASCII; only ASCII letters are folded, so no Unicode case rule applies
    return name.encode("ascii").lower()


def _entry(content: bytes):
    """(address, lowercased names) of a line, or None when its first field is not an address."""
    # the resolver splits fields on space and tab only
    fields = [field for field in FIELD_GAP.split(content.split(b"#", 1)[0]) if field]
    if not fields:
        return None
    try:
        address = ipaddress.ip_address(fields[0].decode("ascii"))
    except (UnicodeDecodeError, ValueError):
        return None
    # bytes.lower() folds ASCII letters only; a non-ASCII name never equals a valid hostname
    return address, {field.lower() for field in fields[1:]}


def _decode(content: bytes) -> str:
    return content.decode("utf-8", "replace")


def marked(text: bytes) -> dict[str, list[str]]:
    found: dict[str, list[str]] = {}
    for raw in _split(text):
        content = _content(raw)
        owner = _owner(content)
        if owner is not None:
            found.setdefault(owner, []).append(_decode(content))
    return found


def strip(text: bytes, box_ids: set[str]) -> bytes:
    return b"".join(raw for raw in _split(text) if _owner(_content(raw)) not in box_ids)


def _ending(pieces: list[bytes]) -> bytes:
    ended = [raw for raw in pieces if raw.endswith(b"\n")]
    if ended and all(raw.endswith(b"\r\n") for raw in ended):
        return b"\r\n"
    return b"\n"


def rewrite(text: bytes, box_id: str, wanted: list[Wanted]) -> Outcome:
    _check_id(box_id)
    for entry in wanted:
        _check(entry)
    pieces = _split(text)
    ending = _ending(pieces)
    wanted_keys = {_key(name) for entry in wanted for name in entry.names}
    # Another of my boxes' line naming a wanted host is taken out whatever this box ends up
    # writing: left in place, it could win over an unmarked line with the same name.
    out: list[bytes] = []
    taken_out: list[tuple[str, str]] = []
    # (line number in the original file, content, address, keys) of every unmarked entry
    unmarked = []
    for number, raw in enumerate(pieces, start=1):
        content = _content(raw)
        owner = _owner(content)
        if owner == box_id:
            continue
        parsed = _entry(content)
        if owner is not None:
            if parsed is not None and parsed[1] & wanted_keys:
                taken_out.append((owner, _decode(content)))
                continue
        elif parsed is not None:
            unmarked.append((number, content, *parsed))
        out.append(raw)

    already: list[tuple[str, str]] = []
    blocked: list[tuple[str, str, int, str]] = []
    written: list[str] = []
    claimed: dict[bytes, tuple[ipaddress.IPv4Address | ipaddress.IPv6Address, str]] = {}
    for entry in wanted:
        address = _parse_ip(entry.ip)
        names = []
        for name in entry.names:
            key = _key(name)
            if key in claimed:
                first_address, first_line = claimed[key]
                if first_address == address:
                    already.append((entry.target, name))
                else:
                    blocked.append((entry.target, name, 0, first_line))
                continue
            clash = next((item for item in unmarked if key in item[3]), None)
            if clash is None:
                names.append(name)
            elif clash[2] == address:
                already.append((entry.target, name))
            else:
                blocked.append((entry.target, name, clash[0], _decode(clash[1])))
        if not names:
            continue
        new = line(Wanted(entry.target, entry.ip, names), box_id)
        written.append(new)
        for name in names:
            claimed[_key(name)] = (address, new)

    if written and out and not out[-1].endswith(b"\n"):
        out[-1] += ending
    out.extend(value.encode("ascii") + ending for value in written)
    return Outcome(b"".join(out), written, taken_out, already, blocked)


def read(path: Path) -> bytes:
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        raise HostsError(f"{path} is missing") from None
    except OSError as exc:
        raise HostsError(f"cannot read {path}: {exc.strerror or exc}") from exc
    if stat.S_ISLNK(info.st_mode):
        raise HostsError(f"{path} is a link")
    if not stat.S_ISREG(info.st_mode):
        raise HostsError(f"{path} is not a regular file")
    try:
        return path.read_bytes()
    except OSError as exc:
        raise HostsError(f"cannot read {path}: {exc.strerror or exc}") from exc


def _write_in_place(path: Path, after: bytes) -> None:
    # In place, never renamed over: the file can be a mount, and its owner and mode must stay.
    flags = os.O_WRONLY | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    try:
        handle = os.open(path, flags)
    except OSError as exc:
        raise HostsError(f"cannot write {path}: {exc.strerror or exc}") from exc
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(after)
            stream.truncate(len(after))
            stream.flush()
            os.fsync(stream.fileno())
    except OSError as exc:
        raise HostsError(f"cannot write {path}: {exc.strerror or exc}") from exc


def _copy_into_place(path: Path, after: bytes, scratch: Path, run) -> None:
    # random part too, so a file left by a crashed process with the same ID never blocks a write
    staged = scratch / f"hosts-{os.getpid()}-{secrets.token_hex(8)}.new"
    flags = os.O_CREAT | os.O_EXCL | os.O_WRONLY | getattr(os, "O_BINARY", 0)
    try:
        handle = os.open(staged, flags, 0o600)
    except OSError as exc:
        raise HostsError(f"cannot write {staged}: {exc.strerror or exc}") from exc
    try:
        with os.fdopen(handle, "wb") as stream:
            stream.write(after)
        result = run(["cp", str(staged), str(path)])
    except KeyboardInterrupt:
        # Ctrl-C at sudo's password prompt is a no, like any other refusal
        raise HostsError("sudo was cancelled") from None
    except OSError as exc:
        raise HostsError(f"cannot copy into {path}: {exc.strerror or exc}") from exc
    finally:
        staged.unlink(missing_ok=True)
    if result.returncode != 0:
        raise HostsError(f"cp exited {result.returncode}")


def write(
    path: Path,
    before: bytes,
    after: bytes,
    *,
    root: bool,
    scratch: Path,
    run=privilege.run_privileged,
) -> None:
    if before == after:
        return
    if read(path) != before:
        raise HostsError(CHANGED)
    if root:
        _write_in_place(path, after)
    else:
        _copy_into_place(path, after, scratch, run)


def _update_once(path: Path, change: Callable[[bytes], bytes], write_args) -> tuple[bytes, bytes]:
    before = read(path)
    after = change(before)
    write(path, before, after, **write_args)
    return before, after


def update(path: Path, change: Callable[[bytes], bytes], **write_args) -> tuple[bytes, bytes]:
    try:
        return _update_once(path, change, write_args)
    except HostsError as exc:
        if exc.args != (CHANGED,):
            raise
    # another program changed the file between reading and writing: start over once
    return _update_once(path, change, write_args)
