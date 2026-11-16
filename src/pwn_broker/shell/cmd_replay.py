import os
from datetime import datetime
from pathlib import Path

from pwn_broker import boxes, casttext, recorder, recstate
from pwn_broker.cast import CastError, read_header
from pwn_broker.model import Target
from pwn_broker.session import Session, recordings
from pwn_broker.shell.cmd_host import NO_CURRENT
from pwn_broker.shell.cmd_misc import human_size
from pwn_broker.shell.commands import command, take_args

# a cast is named by its start time to the minute, maybe with -2, -3 after it
_NAME_TIME = "%Y-%m-%d_%H%M"
_NAME_LENGTH = len("2026-11-14_1432")


def _parse(session: Session, args: list[str]) -> tuple[Target, int | None]:
    """The target and the recording number; a lone argument of digits is the number."""
    name, number = take_args(args, optional=("target name", "recording number"))
    if number is None and name is not None and name.isascii() and name.isdecimal():
        name, number = None, name
    if name is not None:
        target = boxes.find_target(session.targets, name)
    elif session.current is not None:
        target = session.current
    else:
        raise ValueError(NO_CURRENT)
    if number is None:
        return target, None
    if not (number.isascii() and number.isdecimal()):
        raise ValueError(f"{number} is not a recording number")
    return target, int(number)


def _from_name(cast: Path, session: Session) -> datetime | None:
    try:
        named = datetime.strptime(cast.stem[:_NAME_LENGTH], _NAME_TIME)
    except ValueError:
        return None
    return named.replace(tzinfo=session.clock().tzinfo)


def _row(session: Session, n: int, cast: Path, live: bool) -> list[str]:
    tz = session.clock().tzinfo
    try:
        header = read_header(cast)
    except CastError:
        header = None
    start = None
    if header is not None and header.timestamp is not None:
        try:
            start = datetime.fromtimestamp(header.timestamp, tz)
        except (OverflowError, ValueError, OSError):
            header = None  # a start time no date can show: its length cannot be told either
    if start is None:
        start = _from_name(cast, session)
    started = start.strftime("%Y-%m-%d %H:%M") if start else cast.stem
    if live:
        return [str(n), started, "recording now", ""]
    try:
        info = cast.stat()
    except OSError:
        return [str(n), started, "-", "-"]  # gone since it was listed
    if header is None or start is None:
        length = "-"
    else:
        length = recstate.length(max(0.0, info.st_mtime - start.timestamp()))
    return [str(n), started, length, human_size(info.st_size)]


def _live(session: Session) -> set[Path]:
    return {r.cast.resolve() for r in recordings(session)}


def _play(session: Session, n: int, casts: list[Path]) -> None:
    console = session.console
    if not 1 <= n <= len(casts):
        choices = "1" if len(casts) == 1 else f"1 to {len(casts)}"
        raise ValueError(f"no recording {n}; use {choices}")
    cast = casts[n - 1]
    if cast.resolve() in _live(session):
        raise ValueError(f"recording {n} is still being recorded; exit its window first")
    if not recorder.present(session.paths):
        raise ValueError(
            "asciinema is missing or does not match its checksum; run the installer again"
        )
    try:
        for folder in recorder.settings_env(session.paths).values():
            Path(folder).mkdir(parents=True, exist_ok=True)
    except OSError as exc:
        console.fail(f"could not make asciinema's settings folder: {exc}")
        return
    # the app's own settings folders, as for recording, and no PWN_BROKER_RECORDING: playing records nothing
    env = {k: v for k, v in os.environ.items() if k != "PWN_BROKER_RECORDING"}
    env.update(recorder.settings_env(session.paths))
    # the playback starts below a blank line, as a recorded shell does
    console.handover()
    try:
        status: int | None = session.play(recorder.play_argv(session.paths, cast), env=env).returncode
    except KeyboardInterrupt:
        status = None  # Ctrl-C is how a replay is stopped
    except OSError as exc:
        console.fail(f"asciinema could not be started: {exc}")
        return
    # asciinema wrote to the window; what follows starts below a blank line
    console.typed()
    console.gap()
    if status is not None and status != 0:
        console.warn(f"asciinema ended with status {status}")


@command("replay", "list a target's recordings, or play one", "[<target>] [<n>]")
def replay(session: Session, args: list[str]) -> None:
    target, n = _parse(session, args)
    casts = casttext.cast_files(session.box, target.name)
    if not casts:
        none = f"no recordings of {target.name} yet"
        if n is not None:
            raise ValueError(none)
        session.console.info(none)
        return
    casttext.refresh(session.box, session.console, tz=session.clock().tzinfo, target=target.name)
    if n is not None:
        _play(session, n, casts)
        return
    live = _live(session)
    rows = [_row(session, i, cast, cast.resolve() in live) for i, cast in enumerate(casts, start=1)]
    session.console.table(["n", "started", "length", "size"], rows)
