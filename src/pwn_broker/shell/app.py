import re
from collections.abc import Iterable
from datetime import datetime

from prompt_toolkit import PromptSession
from prompt_toolkit.auto_suggest import AutoSuggestFromHistory
from prompt_toolkit.completion import Completer, Completion, PathCompleter
from prompt_toolkit.document import Document
from prompt_toolkit.history import FileHistory

from pwn_broker.boxes import TARGET_FOLDERS
from pwn_broker.session import Session, rescan
from pwn_broker.shell.commands import COMMANDS, Quit, dispatch
from pwn_broker.store import StoreError
from pwn_broker.theme import prompt_style

# These commands come from later tasks, so their names live here rather than in the registry.
TARGET_ARG_COMMANDS = ("target use", "target show", "target edit", "target rename", "target remove")
PATH_COMMAND = "path"
PATH_FOLDERS = tuple(sorted({*TARGET_FOLDERS, "lists", "screenshots"}))
IMPORT_COMMAND = "cred import "

_TARGET_ARG = re.compile(r"(" + "|".join(TARGET_ARG_COMMANDS) + r") (\S*)")
_PATH_ARG = re.compile(re.escape(PATH_COMMAND) + r" (\S*)")


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
    minutes = max(0, int((now - session.box.started).total_seconds())) // 60
    parts.append(f"{minutes // 60:02d}:{minutes % 60:02d}")
    return " " + "   ".join(parts)


def completions(session: Session, text: str) -> list[str]:
    found = {name for name in COMMANDS if name.startswith(text)}
    match = _TARGET_ARG.fullmatch(text)
    if match:
        command, partial = match.groups()
        found.update(
            f"{command} {t.name}" for t in session.targets if t.name.startswith(partial)
        )
    match = _PATH_ARG.fullmatch(text)
    if match:
        found.update(
            f"{PATH_COMMAND} {folder}" for folder in PATH_FOLDERS if folder.startswith(match[1])
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


def run_shell(session: Session) -> None:
    console = session.console
    prompt = PromptSession(
        lambda: [("class:prompt", prompt_text(session))],
        history=FileHistory(str(session.box.path / ".history")),
        auto_suggest=AutoSuggestFromHistory(),
        completer=ShellCompleter(session),
        bottom_toolbar=lambda: [("class:toolbar", toolbar_text(session, session.clock()))],
        style=prompt_style(),
        complete_while_typing=True,
        enable_history_search=True,
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
        try:
            rescan(session)
        except (StoreError, OSError) as exc:
            console.warn(str(exc))
        try:
            dispatch(session, line)
        except Quit:
            break
        except KeyboardInterrupt:
            console.info("cancelled")
