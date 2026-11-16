import shutil
import subprocess
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from pathlib import Path

from pwn_broker import hosts, privilege, recstate, vpn, vpnctl
from pwn_broker.config import Settings
from pwn_broker.console import Console
from pwn_broker.filescan import scan
from pwn_broker.lists import ListSummary, rebuild_lists
from pwn_broker.model import Box, Cred, FileRecord, Target
from pwn_broker.note import NOTE_NAME, NoteError, read_note, render_note, update_box, write_note
from pwn_broker.paths import AppPaths
from pwn_broker.ping import Result as PingResult, once as ping_once
from pwn_broker.setup import load_template
from pwn_broker.store import (
    load_box,
    load_creds,
    load_files,
    load_targets,
    save_box,
    save_creds,
    save_files,
)


# the key in Session.warned for a note that could not be updated; no file path holds a NUL
NOTE_WARNED = "\0note"


@dataclass
class Session:
    paths: AppPaths
    settings: Settings
    console: Console
    box: Box
    targets: list[Target]
    creds: list[Cred]
    current: Target | None
    clock: Callable[[], datetime]
    # paths already reported as skipped, so a periodic rescan does not repeat itself
    warned: set[str] = field(default_factory=set)
    # home paths the last copy before archiving took in full; only these may be deleted after
    copied_in_full: set[Path] = field(default_factory=set)
    # stamp(box) as of the last read or write by this prompt; a different stamp means another program wrote
    seen: tuple = ()
    # what the session reaches outside the box through; tests give each session stand-ins
    hosts_path: Path = hosts.DEFAULT_PATH
    is_root: Callable[[], bool] = privilege.is_root
    run_privileged: Callable = privilege.run_privileged
    ping: Callable[[str], PingResult] = ping_once
    tunnel: Callable[[], vpn.Tunnel | None] = vpn.tunnel
    which: Callable[[str], str | None] = shutil.which
    sleep: Callable[[float], None] = time.sleep
    # how a marker's process is told from one that reuses its ID: the app's OpenVPN, a recording window
    pid_alive: Callable[[int], bool] = vpnctl.pid_alive
    pid_started: Callable[[int], str | None] = vpnctl.process_start
    vpn_comm: Callable[[int], str | None] = vpnctl.process_comm
    # how replay plays a recording in this window: play(argv, env=...)
    play: Callable[..., subprocess.CompletedProcess] = subprocess.run
    # the last tunnel read and when it was made, so a redrawn status bar does not run `ip` each time
    tunnel_read: tuple[datetime, vpn.Tunnel | None] | None = None
    # the same for the number of windows recording for the box
    recordings_read: tuple[datetime, int] | None = None
    # things said once per session
    notices: set[str] = field(default_factory=set)


TUNNEL_AGE = timedelta(seconds=10)


def _old(now: datetime, last: tuple | None) -> bool:
    return last is None or not timedelta(0) <= now - last[0] < TUNNEL_AGE


def current_tunnel(session: Session, *, fresh: bool = False) -> vpn.Tunnel | None:
    """The tunnel as last read, read again when asked to or when the answer is ten seconds old."""
    now = session.clock()
    last = session.tunnel_read
    if fresh or _old(now, last):
        last = session.tunnel_read = (now, session.tunnel())
    return last[1]


def process_checks(session: Session) -> dict:
    """The checks that a marker's process is still the one that wrote it."""
    return dict(alive=session.pid_alive, started=session.pid_started)


def vpn_checks(session: Session) -> dict:
    """The process checks for vpnctl.ours, start and stop."""
    return dict(**process_checks(session), comm=session.vpn_comm)


def recordings(session: Session) -> list[recstate.Recording]:
    """The windows recording into the box now."""
    return recstate.recording(session.paths, session.box, **process_checks(session))


def recording_count(session: Session, *, fresh: bool = False) -> int:
    """The number of windows recording for the box, under the tunnel's ten-second rule."""
    now = session.clock()
    last = session.recordings_read
    if fresh or _old(now, last):
        last = session.recordings_read = (now, len(recordings(session)))
    return last[1]


def load_session(
    paths: AppPaths,
    settings: Settings,
    console: Console,
    box: Box,
    clock: Callable[[], datetime],
) -> Session:
    targets = load_targets(box)
    current = next((t for t in targets if t.name == box.last_target), None)
    if current is None and targets:
        current = targets[0]
    session = Session(paths, settings, console, box, targets, load_creds(box), current, clock)
    mark_seen(session)
    return session


def stamp(box: Box) -> tuple:
    """Modification time and size of every file that holds the box's data; absent files count as None."""
    files = [box.path / "box.toml", box.path / "creds.toml"]
    files += sorted((box.path / "targets").glob("*/target.toml"))
    found = []
    for file in files:
        try:
            info = file.stat()
            found.append((file.relative_to(box.path).as_posix(), info.st_mtime_ns, info.st_size))
        except OSError:
            found.append((file.relative_to(box.path).as_posix(), None, None))
    return tuple(found)


def mark_seen(session: Session) -> None:
    session.seen = stamp(session.box)


def reload_if_changed(session: Session) -> bool:
    """Read the box, targets and credentials again when another program changed them."""
    if stamp(session.box) == session.seen:
        return False
    # read the stamp first: a write that lands during the reload is then noticed next time
    seen = stamp(session.box)
    box = load_box(session.box.path)
    targets = load_targets(box)
    creds = load_creds(box)
    name = session.current.name if session.current else None
    current = next((t for t in targets if t.name == name), None)
    if current is None and targets:
        current = targets[0]
    session.box, session.targets, session.creds, session.current = box, targets, creds, current
    session.seen = seen
    return True


def write_new_note(paths: AppPaths, box: Box, targets: list[Target]) -> None:
    write_note(box, render_note(load_template(paths), box, targets))


def set_current(session: Session, target: Target | None) -> None:
    session.current = target
    session.box.last_target = target.name if target else None
    save_box(session.box)


def refresh(session: Session) -> ListSummary:
    box = session.box
    save_creds(box, session.creds)
    summary = rebuild_lists(box, session.targets, session.creds)
    if (box.path / NOTE_NAME).exists():
        try:
            text = read_note(box)
            drawn = update_box(text, box, session.targets)
            # an unchanged note is not written, so vim has nothing to reload
            if drawn != text:
                write_note(box, drawn)
            session.warned.discard(NOTE_WARNED)
        except NoteError as exc:
            # every cred command refreshes, so a broken box is reported once, not each time
            if NOTE_WARNED not in session.warned:
                session.warned.add(NOTE_WARNED)
                session.console.warn(str(exc))
    return summary


def rescan(
    session: Session, *, hash_all: bool = False, live: Mapping[str, int] | None = None
) -> list[FileRecord]:
    """Scan the box and save files.toml; `live` is recstate.live_casts, read here when not given."""

    def on_skip(path: str, reason: str) -> None:
        if hash_all or path not in session.warned:
            session.warned.add(path)
            session.console.warn(f"{path}   {reason}")

    box = session.box
    if live is None:
        live = recstate.live_casts(session.paths, box, **process_checks(session))
    records = scan(
        box, load_files(box), now=session.clock(), hash_all=hash_all, on_skip=on_skip, live=live
    )
    save_files(box, records)
    return records
