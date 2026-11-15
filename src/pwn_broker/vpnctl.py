"""Starting and stopping the OpenVPN process the app owns, and knowing it is still the same one."""

import hashlib
import math
import os
import shutil
import stat
import sys
import tempfile
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from pwn_broker import boxes, privilege, toolstate
from pwn_broker.filescan import TEMP_PREFIX, TEMP_SUFFIX
from pwn_broker.model import Box, VpnRecord
from pwn_broker.paths import AppPaths
from pwn_broker.store import StoreError, read_toml, save_box, write_toml
from pwn_broker.vpn import Tunnel

COMMAND = "openvpn"
DAEMON_NAME = "pwn-broker-vpn"
MAX_SIZE = 1024 * 1024
POLL = 0.5
# how long openvpn's background process has to write its process ID after the start returns
PID_WAIT = 5.0
LOG_LINES = 5
NONE_RUNNING = "no VPN started by pwn-broker is running"
INSTALL = "openvpn is not installed. install it with: apt install openvpn"


class VpnError(Exception):
    def __init__(self, message: str, log: list[str] | None = None) -> None:
        super().__init__(message)
        self.log = list(log or [])


@dataclass
class Marker:
    pid: int
    start: str
    box_id: str
    box_name: str
    file: str
    sha256: str
    started: datetime


def _marker_path(paths: AppPaths) -> Path:
    return paths.run_vpn / "marker.toml"


def _config_path(paths: AppPaths) -> Path:
    return paths.run_vpn / "config.ovpn"


def _pid_path(paths: AppPaths) -> Path:
    return paths.run_vpn / "openvpn.pid"


def _log_path(paths: AppPaths) -> Path:
    return paths.run_vpn / "openvpn.log"


# ---- the real process checks; ours() looks them up when called, so tests can refuse them


def pid_alive(pid: int) -> bool:
    return boxes.pid_alive(pid)


def process_start(pid: int) -> str | None:
    return toolstate.process_start(pid)


def process_comm(pid: int) -> str | None:
    if sys.platform == "win32":
        return None
    try:
        with open(f"/proc/{pid}/comm", encoding="utf-8", errors="replace") as fh:
            return fh.read().strip()
    except OSError:
        return None


# ---- the marker


def _read_marker(paths: AppPaths) -> Marker | None:
    try:
        data = read_toml(_marker_path(paths))
    except StoreError:
        return None
    kinds = {
        "pid": int, "start": str, "box_id": str, "box_name": str,
        "file": str, "sha256": str, "started": datetime,
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
    comm: Callable[[int], str | None] | None = None,
) -> Marker | None:
    """The marker, only while its process is alive, has the recorded start time and is openvpn."""
    marker = _read_marker(paths)
    if marker is None:
        return None
    if not (alive if alive is not None else pid_alive)(marker.pid):
        try:
            _marker_path(paths).unlink(missing_ok=True)
        except OSError:
            pass
        return None
    # a process ID can be reused; only the recorded start time and name make it the same process
    if (started if started is not None else process_start)(marker.pid) != marker.start:
        return None
    if (comm if comm is not None else process_comm)(marker.pid) != COMMAND:
        return None
    return marker


# ---- the box's copy


def _write_private(path: Path, data: bytes) -> None:
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=TEMP_PREFIX, suffix=TEMP_SUFFIX)
    try:
        with os.fdopen(fd, "wb") as fh:
            fh.write(data)
        os.chmod(tmp_name, 0o600)
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def _read_source(source: Path) -> bytes:
    try:
        info = os.stat(source)
    except FileNotFoundError:
        raise VpnError(f"no such file: {source}") from None
    if not stat.S_ISREG(info.st_mode):
        raise VpnError(f"not a regular file: {source}")
    with open(source, "rb") as fh:
        data = fh.read(MAX_SIZE + 1)
    if len(data) > MAX_SIZE:
        raise VpnError(f"{source} is larger than 1 MiB")
    return data


def _same_file(path: Path, data: bytes) -> bool:
    try:
        info = os.lstat(path)
        if not stat.S_ISREG(info.st_mode) or info.st_size != len(data):
            return False
        return path.read_bytes() == data
    except OSError:
        return False


def copy_into_box(box: Box, source: Path) -> Path:
    """Copy the file into the box's vpn/ folder, readable only by me; the same content is reused."""
    data = _read_source(source)
    folder = box.path / "vpn"
    if os.path.lexists(folder):
        if folder.is_symlink() or not folder.is_dir():
            raise VpnError(f"{folder} is not a folder")
    else:
        folder.mkdir(mode=0o700)
    stem, suffix = Path(source.name).stem, Path(source.name).suffix
    number = 1
    while True:
        dest = folder / (source.name if number == 1 else f"{stem}-{number}{suffix}")
        if not os.path.lexists(dest):
            _write_private(dest, data)
            return dest
        if _same_file(dest, data):
            return dest
        number += 1


# ---- starting and stopping


def _tail(paths: AppPaths) -> list[str]:
    return log_tail(paths, LOG_LINES)


def _fresh_file(path: Path, run: Callable) -> None:
    """Replace whatever an earlier run left with an empty file of my own, mode 600.

    Run through sudo, openvpn would create its log and pid file as root, and with a strict umask
    neither could be read back. It opens an existing file without O_EXCL, so mine keeps my owner
    while root writes to it. Made here with O_EXCL, the file holds only what this start writes.
    """
    try:
        path.unlink(missing_ok=True)
    except OSError:
        # left by a root openvpn in a folder this user cannot change
        run(["rm", "-f", str(path)])
    if os.path.lexists(path):
        raise VpnError(f"cannot remove the old {path}")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, 0o600)
    try:
        os.chmod(path, 0o600)
    finally:
        os.close(fd)


def _read_pid(paths: AppPaths) -> int | None:
    try:
        text = _pid_path(paths).read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return None
    if not (text.isascii() and text.isdecimal()) or int(text) < 1:
        return None
    return int(text)


def _wait_for_pid(paths: AppPaths, sleep: Callable[[float], None]) -> int | None:
    polls = math.ceil(PID_WAIT / POLL)
    for attempt in range(polls + 1):
        pid = _read_pid(paths)
        if pid is not None:
            return pid
        if attempt < polls:
            sleep(POLL)
    return None


def start(
    paths: AppPaths,
    box: Box,
    source: Path,
    *,
    copy: Path,
    before: Tunnel | None = None,
    run: Callable = privilege.run_privileged,
    tunnel: Callable[[], Tunnel | None],
    clock: Callable[[], datetime],
    sleep: Callable[[float], None] = time.sleep,
    wait: float = 15.0,
    which: Callable[[str], str | None] = shutil.which,
    alive: Callable[[int], bool] | None = None,
    started: Callable[[int], str | None] | None = None,
    comm: Callable[[int], str | None] | None = None,
) -> tuple[Marker, Tunnel | None]:
    if which(COMMAND) is None:
        raise VpnError(INSTALL)
    """Start openvpn from the box's copy, in the original file's folder.

    `before` is the tunnel that was up already, if any: only a different one counts as this VPN.
    """
    checks = dict(alive=alive, started=started, comm=comm)
    data = copy.read_bytes()
    folder = paths.run_vpn
    folder.mkdir(mode=0o700, parents=True, exist_ok=True)
    config = _config_path(paths)
    _write_private(config, data)
    _fresh_file(_log_path(paths), run)
    _fresh_file(_pid_path(paths), run)
    argv = [
        COMMAND, "--cd", str(source.absolute().parent), "--config", str(config),
        "--daemon", DAEMON_NAME, "--writepid", str(_pid_path(paths)),
        "--log", str(_log_path(paths)),
    ]  # fmt: skip
    # not captured: openvpn may ask for a username or password before it goes to the background
    done = run(argv)
    if done.returncode != 0:
        raise VpnError(f"openvpn exited with status {done.returncode}", _tail(paths))
    pid = _wait_for_pid(paths, sleep)
    if pid is None:
        raise VpnError("openvpn did not write its process ID", _tail(paths))
    begun = (started if started is not None else process_start)(pid)
    if not begun:
        raise VpnError("openvpn is not running", _tail(paths))
    sha256 = hashlib.sha256(data).hexdigest()
    marker = Marker(pid, begun, box.id, box.name, copy.name, sha256, clock())
    write_toml(_marker_path(paths), asdict(marker))
    record = VpnRecord(marker.file, marker.sha256, marker.started)
    box.vpn.append(record)
    save_box(box)
    polls = math.ceil(wait / POLL)
    for attempt in range(polls + 1):
        found = tunnel()
        if found is not None and found != before:
            return marker, found
        if ours(paths, **checks) is None:
            # a VPN that never came up is neither running nor something the box used
            _forget(paths, box, record)
            raise VpnError("openvpn ended before the tunnel came up", _tail(paths))
        if attempt < polls:
            sleep(POLL)
    return marker, None


def _forget(paths: AppPaths, box: Box, record: VpnRecord) -> None:
    try:
        _marker_path(paths).unlink(missing_ok=True)
    except OSError:
        pass
    if box.vpn and box.vpn[-1] is record:
        box.vpn.pop()
        save_box(box)


def stop(
    paths: AppPaths,
    *,
    run: Callable = privilege.run_privileged,
    sleep: Callable[[float], None] = time.sleep,
    wait: float = 5.0,
    **checks,
) -> bool:
    """Signal the process only once ours() has checked its ID, start time and name."""
    marker = ours(paths, **checks)
    if marker is None:
        raise VpnError(NONE_RUNNING)
    run(["kill", "-TERM", str(marker.pid)])
    polls = math.ceil(wait / POLL)
    for attempt in range(polls + 1):
        if ours(paths, **checks) is None:
            return True
        if attempt < polls:
            sleep(POLL)
    return False


def log_tail(paths: AppPaths, lines: int = 20) -> list[str]:
    try:
        text = _log_path(paths).read_bytes().decode("utf-8", "replace")
    except OSError:
        return []
    return text.splitlines()[-lines:] if lines > 0 else []


def use(paths: AppPaths, box: Box, marker: Marker, now: datetime) -> None:
    """Record that this box used the running VPN, unless its last record is already this file."""
    last = box.vpn[-1] if box.vpn else None
    if last is not None and (last.file, last.sha256) == (marker.file, marker.sha256):
        return
    box.vpn.append(VpnRecord(marker.file, marker.sha256, now))
    save_box(box)
