import difflib
from collections.abc import Callable

from pwn_broker.archive import ArchiveError
from pwn_broker.boxes import BoxError
from pwn_broker.console import Cancelled
from pwn_broker.creds import CredError
from pwn_broker.note import NoteError
from pwn_broker.session import Session
from pwn_broker.store import StoreError

Handler = Callable[[Session, list[str]], None]


class Quit(Exception):
    pass


COMMANDS: dict[str, tuple[Handler, str]] = {}

_HANDLED = (BoxError, CredError, StoreError, ArchiveError, NoteError, ValueError, OSError)


def command(name: str, help: str) -> Callable[[Handler], Handler]:
    def register(handler: Handler) -> Handler:
        if name in COMMANDS:
            raise ValueError(f"command already registered: {name}")
        COMMANDS[name] = (handler, help)
        return handler

    return register


def resolve(line: str) -> tuple[str, list[str]] | None:
    words = line.split()
    for count in range(len(words), 0, -1):
        name = " ".join(words[:count])
        if name in COMMANDS:
            return name, words[count:]
    return None


def suggest(line: str) -> str | None:
    words = line.split()
    for guess in (" ".join(words[:2]), " ".join(words[:1])):
        if not guess:
            continue
        found = difflib.get_close_matches(guess, list(COMMANDS), n=1, cutoff=0.6)
        if found:
            return found[0]
    return None


def dispatch(session: Session, line: str) -> None:
    words = line.split()
    if not words:
        return
    console = session.console
    found = resolve(line)
    if found is None:
        group = [name for name in sorted(COMMANDS) if name.startswith(" ".join(words) + " ")]
        if group:
            for name in group:
                console.info(f"{name}   {COMMANDS[name][1]}")
            return
        message = f"unknown command: {' '.join(words[:2])}"
        suggestion = suggest(line)
        if suggestion:
            message += f". did you mean: {suggestion}"
        console.fail(message)
        return
    name, args = found
    try:
        COMMANDS[name][0](session, args)
    except Cancelled:
        console.info("cancelled")
    except _HANDLED as exc:
        console.fail(str(exc))
