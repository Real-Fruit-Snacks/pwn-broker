import os
import re
from collections.abc import Iterable, Mapping
from datetime import datetime

from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import Completer, Completion, PathCompleter
from prompt_toolkit.document import Document
from prompt_toolkit.history import FileHistory
from prompt_toolkit.styles import Style

from pwn_broker import boxlock, toolindex, toolstate
from pwn_broker.boxes import TARGET_FOLDERS
from pwn_broker.model import current_tools
from pwn_broker.session import (
    Session, current_tunnel, mark_seen, recording_count, reload_if_changed, rescan,
)  # fmt: skip
from pwn_broker.shell.commands import COMMANDS, Quit, dispatch, resolve
from pwn_broker.store import StoreError
from pwn_broker.theme import color_enabled, prompt_style

# These commands come from later tasks, so their names live here rather than in the registry.
TARGET_ARG_COMMANDS = (
    "target use", "target show", "target edit", "target rename", "target remove",
    "host file on", "host file off",
)  # fmt: skip
PATH_COMMAND = "path"
PATH_FOLDERS = tuple(sorted({*TARGET_FOLDERS, "lists", "screenshots"}))
IMPORT_COMMAND = "cred import "
# seconds a command waits for record to finish adding a target
LOCK_WAIT = 30
# the command lines that leave the shell
LEAVING = (("quit", []), ("exit", []))

_TARGET_ARG = re.compile(r"(" + "|".join(TARGET_ARG_COMMANDS) + r") (\S*)")
_TOOL_INDEX_ARG = re.compile(r"(tool install|tool info) (\S*)")
_TOOL_BOX_ARG = re.compile(r"(tool remove) (\S*)")
_PATH_ARG = re.compile(re.escape(PATH_COMMAND) + r" (\S*)")
_HOST_REMOVE_ARG = re.compile(r"(host remove (?:\S+ +)*)(\S*)")


def prompt_text(session: Session) -> str:
    if session.current is not None:
        return f"{session.box.name}/{session.current.name} > "
    return f"{session.box.name} > "


def toolbar_text(session: Session, now: datetime) -> str:
    parts = [session.box.name]
    target = session.current
    if target is not None:
        address = (target.ips or target.hostnames or [""])[0]
        parts.append(f"{target.name}  {address}" if address else target.name)
    count = len(session.targets)
    parts.append(f"{count} target" if count == 1 else f"{count} targets")
    tools = toolstate.present_count(session.paths, session.box)
    if tools:
        parts.append(f"{tools} tool" if tools == 1 else f"{tools} tools")
    found = current_tunnel(session)
    parts.append(f"vpn {found.address}" if found else "no vpn")
    recording = recording_count(session)
    if recording:
        parts.append(f"rec {recording}")
    scanning = _scan_part(session)
    if scanning:
        parts.append(scanning)
    minutes = max(0, int((now - session.box.started).total_seconds())) // 60
    parts.append(f"{minutes // 60:02d}:{minutes % 60:02d}")
    return " " + "   ".join(parts)


def _scan_part(session: Session) -> str | None:
    from pwn_broker.shell import cmd_scan

    try:
        return cmd_scan.toolbar_part(session)
    except OSError:
        return None


def _tool_names(session: Session, text: str) -> set[str]:
    # only what is already on disk: a completion must never fetch or wait
    try:
        match = _TOOL_INDEX_ARG.fullmatch(text)
        if match:
            names = toolindex.known_names(session.paths, session.settings)
        else:
            match = _TOOL_BOX_ARG.fullmatch(text)
            if not match:
                return set()
            names = [t.name for t in current_tools(session.box)]
        return {f"{match[1]} {n}" for n in names if n.startswith(match[2])}
    except Exception:
        return set()


def completions(session: Session, text: str) -> list[str]:
    found = {name for name in COMMANDS if name.startswith(text)}
    match = _TARGET_ARG.fullmatch(text)
    if match:
        command, partial = match.groups()
        found.update(
            f"{command} {t.name}" for t in session.targets if t.name.startswith(partial)
        )
    found.update(_tool_names(session, text))
    match = _PATH_ARG.fullmatch(text)
    if match:
        found.update(
            f"{PATH_COMMAND} {folder}" for folder in PATH_FOLDERS if folder.startswith(match[1])
        )
    match = _HOST_REMOVE_ARG.fullmatch(text)
    if match and session.current is not None:
        typed = set(match[1].split()[2:])
        found.update(
            match[1] + name
            for name in session.current.hostnames
            if name.startswith(match[2]) and name not in typed
        )
    return sorted(found)


class ShellCompleter(Completer):
    def __init__(self, session: Session) -> None:
        self._session = session
        self._paths = PathCompleter(expanduser=True)

    def get_completions(self, document: Document, complete_event) -> Iterable[Completion]:
        text = document.text_before_cursor
        if text.startswith(IMPORT_COMMAND):
            tail = Document(text[len(IMPORT_COMMAND) :])
            yield from self._paths.get_completions(tail, complete_event)
            return
        for candidate in completions(self._session, text):
            yield Completion(candidate, start_position=-len(text))


def shell_style(env: Mapping[str, str]) -> Style | None:
    return prompt_style() if color_enabled(env) else None


def _read_status(session: Session) -> None:
    """Fresh reads for the status bar; one that fails is said and the command still runs."""
    for what, read in (
        ("read the VPN tunnel", lambda: current_tunnel(session, fresh=True)),
        ("count the windows recording", lambda: recording_count(session, fresh=True)),
    ):
        try:
            read()
        except OSError as exc:
            session.console.fail(f"could not {what}: {exc}")


def run_shell(session: Session) -> None:
    console = session.console
    prompt = PromptSession(
        lambda: [("class:prompt", prompt_text(session))],
        history=FileHistory(str(session.box.path / ".history")),
        auto_suggest=AutoSuggestFromHistory(),
        completer=ShellCompleter(session),
        bottom_toolbar=lambda: [("class:toolbar", toolbar_text(session, session.clock()))],
        style=shell_style(os.environ),
        complete_while_typing=True,
        refresh_interval=30,
    )
    while True:
        try:
            line = prompt.prompt()
        except KeyboardInterrupt:
            continue
        except EOFError:
            if "quit" not in COMMANDS:
                break
            line = "quit"
        # the command line is on screen; what the command prints is one block below it
        console.typed()
        with console.block():
            if not _run_line(session, line):
                break


def _scan_notices(session: Session) -> None:
    # a scan that finished since the last command is said after this one's output
    from pwn_broker.shell import cmd_scan

    try:
        cmd_scan.notices(session)
    except OSError as exc:
        session.console.warn(f"finished scans could not be read: {exc}")


def _run_line(session: Session, line: str) -> bool:
    """Run one command line under the box lock; false once the session is to end."""
    console = session.console
    try:
        # an OSError here is the lock file itself: every error inside is handled below
        with boxlock.held(session.paths, wait=LOCK_WAIT):
            try:
                reload_if_changed(session)
            except (StoreError, OSError) as exc:
                if resolve(line) in LEAVING:
                    # what could not be read cannot be exported; leaving must still work
                    console.warn(f"{session.box.name} was not exported because it could not be read")
                    raise Quit from None
                # acting on stale data, or marking the new state as seen, would hide the change
                console.fail(f"could not reload the box: {exc}")
                return True
            try:
                _read_status(session)
                try:
                    rescan(session)
                except (StoreError, OSError) as exc:
                    console.warn(str(exc))
                try:
                    dispatch(session, line)
                finally:
                    # after the command's own lines, so a clear cannot wipe them, and a quit still says them
                    _scan_notices(session)
            finally:
                try:
                    mark_seen(session)
                except OSError as exc:
                    # the next command reads the box again, which costs nothing but time
                    console.fail(f"could not note the box's files as read: {exc}")
    except boxlock.Busy:
        console.fail("record is adding a target in another window; try again")
    except OSError as exc:
        console.fail(f"could not use the lock file {session.paths.box_lock}: {exc}")
    except Quit:
        return False
    except KeyboardInterrupt:
        console.info("cancelled")
    return True
