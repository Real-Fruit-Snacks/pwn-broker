"""nmap scans of a target, run in the background into its scans/ folder.

A scan is a plan of modes run one after another: quick, full, udp, or quick then full for a bare
`scan`. The prompt starts a runner of its own, through a short-lived middle process, in a session
of its own, so it outlives `quit` and is reaped by init when it ends. The runner runs nmap for
each stage, and when a mode is done appends a record that the prompt reads before the next
command and says in one line. A marker per target names the runner by its process ID, its start
time and its command line, as the file server's does.
"""

import ipaddress
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass
from datetime import datetime
from pathlib import Path

from pwn_broker import boxes, toolstate
from pwn_broker.model import Box, Target
from pwn_broker.paths import AppPaths
from pwn_broker.store import StoreError, read_toml, write_toml

MODULE = "pwn_broker.scanning"
MODES = ("quick", "full", "udp")
BARE = ("quick", "full")
DEFAULT_FLAGS = {"quick": "-sC -sV", "full": "-p- --min-rate 5000", "udp": "-sU --top-ports 100"}
# the second stage of full: scripts and versions on the ports the first found
FULL_DETAIL = ["-sC", "-sV"]
NOT_INSTALLED = "nmap is not installed. install it with: apt install nmap"
SCANS = "scans"
POLL = 0.1
LOG_LINES = 20


class ScanError(Exception):
    pass


@dataclass
class Marker:
    pid: int
    start: str
    box_id: str
    box_name: str
    target: str
    ip: str
    plan: str
    started: datetime


@dataclass
class Done:
    target: str
    mode: str
    status: int
    ports: list[str]
    file: str
    finished: datetime


def _folder(paths: AppPaths, box_id: str) -> Path:
    return paths.run / "scans" / box_id


def _marker_path(paths: AppPaths, box_id: str, target: str) -> Path:
    return _folder(paths, box_id) / f"{target}.toml"


def log_path(paths: AppPaths, box_id: str, target: str) -> Path:
    return _folder(paths, box_id) / f"{target}.log"


def _done_folder(paths: AppPaths, box_id: str) -> Path:
    return _folder(paths, box_id) / "done"


def parse_flags(text: str, mode: str) -> list[str]:
    try:
        return shlex.split(text)
    except ValueError as exc:
        raise ScanError(f"scan_{mode} cannot be read as nmap options: {exc}") from None


# ---- the runner's process, as the prompt sees it


def pid_alive(pid: int) -> bool:
    return boxes.pid_alive(pid)


def process_start(pid: int) -> str | None:
    return toolstate.process_start(pid)


def _read_marker(path: Path) -> Marker | None:
    try:
        data = read_toml(path)
    except StoreError:
        return None
    kinds = {
        "pid": int, "start": str, "box_id": str, "box_name": str, "target": str, "ip": str,
        "plan": str, "started": datetime,
    }  # fmt: skip
    for key, kind in kinds.items():
        value = data.get(key)
        if not isinstance(value, kind) or isinstance(value, bool):
            return None
    if data["pid"] < 1 or not data["start"]:
        return None
    return Marker(**{key: data[key] for key in kinds})


def _alive(path: Path, alive, started, cmdline) -> Marker | None:
    marker = _read_marker(path)
    if marker is None:
        return None
    if not (alive if alive is not None else pid_alive)(marker.pid):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass
        return None
    if (started if started is not None else process_start)(marker.pid) != marker.start:
        return None
    from pwn_broker.serving import process_cmdline

    argv = (cmdline if cmdline is not None else process_cmdline)(marker.pid) or []
    if not any(MODULE in part for part in argv):
        return None
    return marker


def running(
    paths: AppPaths, box_id: str, target: str | None = None, *, alive=None, started=None, cmdline=None
) -> list[Marker]:
    """The scans running for the box, or for one of its targets, by target name."""
    folder = _folder(paths, box_id)
    if target is not None:
        found = _alive(_marker_path(paths, box_id, target), alive, started, cmdline)
        return [found] if found is not None else []
    try:
        names = sorted(p for p in folder.glob("*.toml"))
    except OSError:
        return []
    return [m for p in names if (m := _alive(p, alive, started, cmdline)) is not None]


# ---- starting and stopping


LAUNCH = (
    "import subprocess, sys; out = open(sys.argv[1], 'ab'); "
    "child = subprocess.Popen(sys.argv[2:], stdin=subprocess.DEVNULL, stdout=out, stderr=out, "
    "cwd='/', start_new_session=True); print(child.pid)"
)


def spawn(argv: list[str], log: Path) -> int | None:
    """Start the runner through a middle process; its process ID, or None when it did not start."""
    done = subprocess.run(
        [sys.executable, "-I", "-c", LAUNCH, str(log), *argv],
        stdin=subprocess.DEVNULL, capture_output=True, text=True, cwd="/", timeout=10, check=False,
    )  # fmt: skip
    text = done.stdout.strip()
    return int(text) if done.returncode == 0 and text.isdecimal() else None


def runner_argv(spec: dict) -> list[str]:
    here = str(Path(__file__).resolve().parent.parent)
    code = f"import sys; sys.path.insert(0, {here!r}); import {MODULE} as s; s.main(sys.argv[2:])"
    return [sys.executable, "-I", "-c", code, MODULE, json.dumps(spec)]


def scans_folder(box: Box, target: Target) -> Path:
    return box.path / "targets" / target.name / SCANS


def start(
    paths: AppPaths,
    box: Box,
    target: Target,
    plan: list[str],
    *,
    nmap: str,
    flags: dict[str, list[str]],
    clock: Callable[[], datetime],
    spawn: Callable[[list[str], Path], int | None] = spawn,
    alive: Callable[[int], bool] | None = None,
    started: Callable[[int], str | None] | None = None,
    sleep: Callable[[float], None] = time.sleep,
) -> Marker:
    if not target.ips:
        raise ScanError(f"{target.name} has no IP address to scan")
    ip = target.ips[0]
    folder = scans_folder(box, target)
    folder.mkdir(parents=True, exist_ok=True)
    run = _folder(paths, box.id)
    run.mkdir(mode=0o700, parents=True, exist_ok=True)
    _done_folder(paths, box.id).mkdir(mode=0o700, exist_ok=True)
    now = clock()
    log = log_path(paths, box.id, target.name)
    with open(log, "w", encoding="utf-8") as fh:
        fh.write(f"{now:%Y-%m-%d %H:%M:%S}  scan {' then '.join(plan)} of {target.name} ({ip})\n")
    os.chmod(log, 0o600)
    spec = {
        "nmap": nmap, "ip": ip, "plan": plan, "flags": flags, "folder": str(folder),
        "stamp": f"{now:%Y-%m-%d_%H%M%S}", "target": target.name,
        "done": str(_done_folder(paths, box.id)),
    }  # fmt: skip
    pid = spawn(runner_argv(spec), log)
    if pid is None:
        raise ScanError("the scan did not start; see: scan log")
    begun = None
    for _ in range(20):
        begun = (started if started is not None else process_start)(pid)
        if begun or not (alive if alive is not None else pid_alive)(pid):
            break
        sleep(POLL)
    if not begun:
        raise ScanError("the scan did not start; see: scan log")
    marker = Marker(pid, begun, box.id, box.name, target.name, ip, " then ".join(plan), now)
    write_toml(_marker_path(paths, box.id, target.name), asdict(marker))
    return marker


def stop(
    paths: AppPaths,
    box_id: str,
    target: str,
    *,
    killpg: Callable[[int, int], None] | None = None,
    sleep: Callable[[float], None] = time.sleep,
    wait: float = 3.0,
    **checks,
) -> Marker:
    """Signal the runner and the nmap it runs, its whole session, once the marker checks out."""
    found = running(paths, box_id, target, **checks)
    if not found:
        raise ScanError(f"no scan of {target} is running")
    marker = found[0]
    try:
        (killpg if killpg is not None else os.killpg)(marker.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    for _ in range(max(1, int(wait / POLL))):
        if not running(paths, box_id, target, **checks):
            break
        sleep(POLL)
    else:
        raise ScanError(f"the scan (process {marker.pid}) did not stop")
    try:
        _marker_path(paths, box_id, target).unlink(missing_ok=True)
    except OSError:
        pass
    return marker


def take_done(paths: AppPaths, box_id: str) -> list[Done]:
    """The modes finished since the last look, oldest first; each is said once, then forgotten."""
    folder = _done_folder(paths, box_id)
    try:
        files = sorted(folder.glob("*.toml"))
    except OSError:
        return []
    found = []
    for path in files:
        try:
            data = read_toml(path)
            found.append(Done(
                str(data["target"]), str(data["mode"]), int(data["status"]),
                [str(p) for p in data["ports"]], str(data["file"]), data["finished"],
            ))  # fmt: skip
        except (StoreError, KeyError, TypeError, ValueError):
            pass
        try:
            path.unlink()
        except OSError:
            pass
    return found


def log_tail(paths: AppPaths, box_id: str, target: str, lines: int = LOG_LINES) -> list[str]:
    try:
        text = log_path(paths, box_id, target).read_bytes().decode("utf-8", "replace")
    except OSError:
        return []
    return text.splitlines()[-lines:] if lines > 0 else []


# ---- the runner


_PORT = re.compile(r"(\d+)/open/(tcp|udp)/")


def open_ports(gnmap: Path) -> list[str]:
    """The open ports nmap's grepable output lists, as `22/tcp`, in order, once each."""
    try:
        text = gnmap.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    found: list[str] = []
    for line in text.splitlines():
        if "Ports:" not in line:
            continue
        for number, proto in _PORT.findall(line.split("Ports:", 1)[1]):
            port = f"{number}/{proto}"
            if port not in found:
                found.append(port)
    return found


def _run(argv: list[str]) -> int:
    print("$ " + " ".join(shlex.quote(a) for a in argv), flush=True)
    return subprocess.run(argv, stdin=subprocess.DEVNULL, check=False).returncode


def _record(spec: dict, mode: str, status: int, ports: list[str], base: Path) -> None:
    done = Path(spec["done"])
    when = datetime.now().astimezone()
    path = done / f"{when:%Y%m%d%H%M%S%f}-{spec['target']}-{mode}.toml"
    write_toml(path, {
        "target": spec["target"], "mode": mode, "status": status, "ports": ports,
        "file": f"targets/{spec['target']}/{SCANS}/{base.name}.nmap", "finished": when,
    })  # fmt: skip


def run_plan(spec: dict, run: Callable[[list[str]], int] = _run) -> None:
    nmap, ip, folder = spec["nmap"], spec["ip"], Path(spec["folder"])
    # nmap takes an IPv6 address only with -6
    six = ["-6"] if ipaddress.ip_address(ip).version == 6 else []
    for mode in spec["plan"]:
        base = folder / f"{spec['stamp']}-{mode}"
        if mode == "full":
            first = folder / f"{spec['stamp']}-full-ports"
            status = run([nmap, *six, *spec["flags"]["full"], "-oA", str(first), ip])
            ports = open_ports(first.with_suffix(".gnmap"))
            # flags of the user's own can find UDP ports alone: then no TCP port is left to detail
            listed = ",".join(p.split("/")[0] for p in ports if p.endswith("/tcp"))
            if status == 0 and listed:
                status = run([nmap, *six, *FULL_DETAIL, "-p", listed, "-oA", str(base), ip])
                ports = open_ports(base.with_suffix(".gnmap")) or ports
            else:
                base = first
        else:
            status = run([nmap, *six, *spec["flags"][mode], "-oA", str(base), ip])
            ports = open_ports(base.with_suffix(".gnmap"))
        _record(spec, mode, status, ports, base)


def main(argv: list[str]) -> None:
    spec = json.loads(argv[0])
    # stopped by scan stop or at finish: the whole session gets the signal, nmap included
    signal.signal(signal.SIGTERM, lambda *_: sys.exit(143))
    run_plan(spec)
