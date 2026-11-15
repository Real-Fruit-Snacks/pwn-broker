"""`record [target]`: records the terminal window it is typed in, under the pinned asciinema."""

import ipaddress
import os
import signal
import subprocess
import sys
from collections.abc import Callable, Iterator, Mapping
from contextlib import contextmanager
from dataclasses import dataclass
from datetime import datetime
from pathlib import Path

from pwn_broker import boxes, boxlock, casttext, config, hosts, privilege, questions, recorder
from pwn_broker import recstate, targetflow, toolstate, vpn
from pwn_broker.boxes import BoxError
from pwn_broker.cast import CastError
from pwn_broker.config import ConfigError, Settings
from pwn_broker.console import Cancelled, Console, TermConsole
from pwn_broker.model import Box, Target
from pwn_broker.paths import AppPaths
from pwn_broker.ping import Result as PingResult, once as ping_once
from pwn_broker.session import Session, load_session
from pwn_broker.store import StoreError, load_box, load_targets
from pwn_broker.toolpkg import ToolError

LOCK_WAIT = 5
USAGE = "usage: record [target]"
NO_TARGETS = "this box has no targets; add one in the prompt with: target add"
BUSY = "the prompt is in the middle of a command; finish it, then run record again"


@dataclass
class Env:
    paths: AppPaths
    settings: Settings
    console: Console
    clock: Callable[[], datetime]
    environ: Mapping[str, str]
    pid: int
    run: Callable[..., subprocess.CompletedProcess] = subprocess.run
    start_of: Callable[[int], str | None] = toolstate.process_start
    alive: Callable[[int], bool] = boxes.pid_alive
    owner: Callable[[Path], str | None] = privilege.wrong_owner
    present: Callable[[AppPaths], bool] = recorder.present
    # what a target added from record reaches /etc/hosts, root, sudo and ping through
    hosts_path: Path = hosts.DEFAULT_PATH
    is_root: Callable[[], bool] = privilege.is_root
    run_privileged: Callable = privilege.run_privileged
    ping: Callable[[str], PingResult] = ping_once
    tunnel: Callable[[], vpn.Tunnel | None] = vpn.tunnel


def cast_path(folder: Path, now: datetime) -> Path:
    """`<YYYY-MM-DD_HHMM>.cast` in `folder`, numbered from -2 while that name or its text is taken."""
    stem = now.strftime("%Y-%m-%d_%H%M")
    name, n = stem, 1
    while (folder / f"{name}.cast").exists() or (folder / f"{name}.txt").exists():
        n += 1
        name = f"{stem}-{n}"
    return folder / f"{name}.cast"


def _session(env: Env, box: Box) -> Session:
    session = load_session(env.paths, env.settings, env.console, box, env.clock)
    session.hosts_path = env.hosts_path
    session.is_root = env.is_root
    session.run_privileged = env.run_privileged
    session.ping = env.ping
    session.tunnel = env.tunnel
    return session


def _by_address(targets: list[Target], text: str) -> list[Target]:
    wanted = text.casefold()
    return [t for t in targets if text in t.ips or any(h.casefold() == wanted for h in t.hostnames)]


def _add(env: Env, folder: Path, box: Box, targets: list[Target], text: str) -> Target | None:
    """Section 7.3: offer to add an address that is not a target, then add it under the lock."""
    console = env.console
    if not console.confirm(f"{text} is not a target of {box.name}. add it?", default=False):
        return None
    try:
        ipaddress.ip_address(text)
        prefill = {"ips": [text]}
    except ValueError:
        prefill = {"hostnames": [text]}
    answers = questions.ask_target(console, taken={t.name for t in targets}, **prefill)
    try:
        with boxlock.held(env.paths, wait=LOCK_WAIT):
            try:
                # read again under the lock: the prompt may have written since
                session = _session(env, load_box(folder))
                return targetflow.add(session, answers, make_current=False)
            except (BoxError, StoreError, OSError, ValueError) as exc:
                console.fail(f"could not add the target: {exc}")
                return None
    except boxlock.Busy:
        console.fail(BUSY)
    except OSError as exc:
        console.fail(f"could not use the lock file {env.paths.box_lock}: {exc}")
    return None


def _target(env: Env, folder: Path, box: Box, targets: list[Target], text: str | None) -> Target | None:
    console = env.console
    if text is None:
        if not targets:
            console.fail(NO_TARGETS)
            return None
        return next((t for t in targets if t.name == box.last_target), targets[0])
    named = [t for t in targets if t.name == text]
    if named:
        return named[0]
    found = _by_address(targets, text)
    if len(found) > 1:
        names = ", ".join(t.name for t in found)
        console.fail(f"{text} is an address of more than one target: {names}; name one")
        return None
    if found:
        return found[0]
    if any(t.name.startswith(text) for t in targets):
        try:
            return boxes.find_target(targets, text)
        except BoxError as exc:
            console.fail(str(exc))
            return None
    return _add(env, folder, box, targets, text)


@contextmanager
def _interrupts_ignored() -> Iterator[None]:
    """Ctrl-C belongs to the recorded shell while it runs, not to record.

    A handler that does nothing, rather than SIG_IGN: an ignored signal stays ignored in the
    programs started under asciinema, and Ctrl-C would no longer stop them.
    """
    if sys.platform == "win32":
        yield
        return
    previous = signal.signal(signal.SIGINT, lambda signum, frame: None)
    try:
        yield
    finally:
        signal.signal(signal.SIGINT, previous)


def _length(minutes: int) -> str:
    return "under a minute" if minutes < 1 else f"{minutes} min"


def run(env: Env, argv: list[str]) -> int:
    console = env.console
    if argv in (["--help"], ["-h"]):
        console.info(USAGE)
        return 0
    # an option is never a target name, IP or hostname, and must not be offered as one
    if len(argv) > 1 or (argv and argv[0].startswith("-")):
        console.fail(USAGE)
        return 2
    owner = env.owner(env.paths.opt)
    if owner is not None:
        console.fail(
            f"record must run as {owner}, the user who installed pwn-broker. "
            "run record first, then sudo inside it"
        )
        return 1
    already = env.environ.get("PWN_BROKER_RECORDING")
    if already:
        console.fail(f"this window is already recording for {already}")
        return 1
    folder = boxes.open_box_folder(env.paths, alive=env.alive)
    if folder is None:
        console.fail("no box is open; nothing is recorded")
        return 1
    if not env.present(env.paths):
        console.fail("asciinema is missing or does not match its checksum; run check in the prompt")
        return 1
    try:
        box = load_box(folder)
        targets = load_targets(box)
    except (StoreError, OSError) as exc:
        console.fail(f"could not read the box: {exc}")
        return 1
    try:
        target = _target(env, folder, box, targets, argv[0] if argv else None)
    except Cancelled:
        console.info("cancelled")
        return 1
    if target is None:
        return 1
    return _record(env, box, target)


def _record(env: Env, box: Box, target: Target) -> int:
    console = env.console
    paths = env.paths

    def shown(path: Path) -> str:
        return path.relative_to(box.path).as_posix()

    shell = env.environ.get("SHELL") or "/bin/sh"
    try:
        recorder.shell_files(paths)
        for sub in ("config", "state"):
            (paths.run_asciinema / sub).mkdir(parents=True, exist_ok=True)
        command, extra = recorder.record_command(paths, shell, environ=env.environ)
        folder = box.path / "targets" / target.name / "recordings"
        folder.mkdir(parents=True, exist_ok=True)
        started = env.clock()
        cast = cast_path(folder, started)
    except (OSError, ToolError) as exc:
        console.fail(f"could not start the recording: {exc}")
        return 1
    argv = recorder.rec_argv(paths, cast, f"{box.name} {target.name} {box.id}", command)
    environment = {**recorder.base_env(paths, env.environ, target.name), **extra}

    # the marker first, so the ok lines are printed only for a window that is recorded
    try:
        recstate.mark(paths, env.pid, env.start_of(env.pid) or "", target.name, cast)
    except OSError as exc:
        console.fail(f"could not write the recording marker: {exc}")
        return 1
    status: int | None = None
    error: OSError | None = None
    try:
        console.ok(f"recording this window for {target.name} ({box.name})")
        console.info(f"    {shown(cast)}")
        console.info("    exit this shell to stop")
        try:
            with _interrupts_ignored():
                status = env.run(argv, env=environment).returncode
        except OSError as exc:
            error = exc
    finally:
        recstate.clear(paths, env.pid)

    if error is not None:
        console.fail(f"asciinema could not be started: {error}")
    elif status != 0:
        console.warn(f"asciinema ended with status {status}; the recording may be incomplete")
    if not cast.exists():
        if error is None:
            console.fail("no recording was saved")
        return 1
    text: Path | None = None
    try:
        text = casttext.write(
            cast, box_name=box.name, box_id=box.id, target=target.name, tz=env.clock().tzinfo
        )
    except (CastError, OSError) as exc:
        console.warn(f"no text copy of {shown(cast)}: {exc}")
    minutes = int((env.clock() - started).total_seconds() // 60)
    console.ok(f"recording saved, {_length(minutes)}")
    console.info(f"    {shown(cast)}")
    if text is not None:
        console.info(f"    {shown(text)}")
    return 0


def main() -> int:
    try:
        paths, settings = config.load(os.environ, Path.home())
    except ConfigError as exc:
        TermConsole(os.environ).fail(str(exc))
        return 1
    env = Env(
        paths=paths,
        settings=settings,
        console=TermConsole(os.environ),
        clock=lambda: datetime.now().astimezone(),
        environ=os.environ,
        pid=os.getpid(),
    )
    try:
        return run(env, sys.argv[1:])
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        env.console.fail(f"unexpected error: {type(exc).__name__}: {exc}")
        return 1


if __name__ == "__main__":
    sys.exit(main())
