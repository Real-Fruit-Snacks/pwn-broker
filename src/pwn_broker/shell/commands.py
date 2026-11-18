import difflib
from collections.abc import Callable

from pwn_broker.archive import ArchiveError
from pwn_broker.boxes import BoxError
from pwn_broker.console import Cancelled, Console
from pwn_broker.creds import CredError
from pwn_broker.note import NoteError
from pwn_broker.scanning import ScanError
from pwn_broker.serving import ServeError
from pwn_broker.session import Session
from pwn_broker.store import StoreError
from pwn_broker.toolpkg import ToolError
from pwn_broker.vpnctl import VpnError

Handler = Callable[[Session, list[str]], None]


class Quit(Exception):
    pass


class ArgumentError(ValueError):
    """The wrong arguments for a command; dispatch prints the command's usage under the fail line."""


COMMANDS: dict[str, tuple[Handler, str]] = {}
# each command's usage line, by name
USAGES: dict[str, str] = {}

_HANDLED = (
    BoxError, CredError, StoreError, ArchiveError, NoteError, ToolError, VpnError, ServeError, ScanError,
    ValueError, OSError,
)  # fmt: skip


def command(name: str, help: str, usage: str | None = None) -> Callable[[Handler], Handler]:
    """Register a command; `usage` is what follows its name in its usage line, such as `<target>`."""

    def register(handler: Handler) -> Handler:
        if name in COMMANDS:
            raise ValueError(f"command already registered: {name}")
        COMMANDS[name] = (handler, help)
        USAGES[name] = f"usage: {name} {usage}" if usage else f"usage: {name}"
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


def list_commands(console: Console, names: list[str]) -> None:
    """Each command with what it does, both columns aligned with every other command list."""
    console.fields([(name, COMMANDS[name][1]) for name in names], align_to=COMMANDS)


def family(prefix: str) -> list[str]:
    """The commands under a family name such as `tool` or `host file`, in order."""
    return [name for name in sorted(COMMANDS) if name.startswith(prefix + " ")]


def help_groups() -> list[list[str]]:
    """The one-word commands, then each family: `host` is a command and also heads its family."""
    families = sorted({name.split()[0] for name in COMMANDS if " " in name})
    alone = [name for name in sorted(COMMANDS) if " " not in name and name not in families]
    groups = [alone] if alone else []
    for first in families:
        groups.append([name for name in sorted(COMMANDS) if name == first or name.startswith(first + " ")])
    return groups


def dispatch(session: Session, line: str) -> None:
    words = line.split()
    if not words:
        return
    console = session.console
    found = resolve(line)
    if found is None:
        group = family(" ".join(words))
        if group:
            list_commands(console, group)
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
    except Quit:
        raise
    except Cancelled:
        console.info("cancelled")
    except ArgumentError as exc:
        console.fail(str(exc))
        console.detail(USAGES[name])
    except _HANDLED as exc:
        console.fail(str(exc))
    except Exception as exc:
        # a handler bug must not end a session that has been open for hours
        console.fail(f"unexpected error: {type(exc).__name__}: {exc}")


def take_args(
    args: list[str], required: tuple[str, ...] = (), optional: tuple[str, ...] = ()
) -> list[str | None]:
    # Raises ArgumentError, which dispatch turns into a fail line and the command's usage.
    if len(args) < len(required):
        raise ArgumentError(f"missing argument: {required[len(args)]}")
    limit = len(required) + len(optional)
    if len(args) > limit:
        raise ArgumentError(f"too many arguments: {' '.join(args[limit:])}")
    return [*args, *[None] * (limit - len(args))]
