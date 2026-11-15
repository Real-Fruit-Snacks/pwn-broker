import os
from pathlib import Path

from pwn_broker import boxes, checks, notewindow, store
from pwn_broker.model import FileRecord, Flag
from pwn_broker.note import NOTE_NAME
from pwn_broker.session import Session
from pwn_broker.shell.commands import COMMANDS, command, take_args

BOX_FOLDERS = ("lists", "screenshots")


def human_size(size: int) -> str:
    if size < 1024:
        return f"{size} B"
    value = float(size)
    for unit in ("KB", "MB", "GB"):
        value /= 1024
        if value < 1024 or unit == "GB":
            return f"{value:.1f} {unit}"
    raise AssertionError("unreachable")


def _added(session: Session, record: FileRecord) -> str:
    seen = record.first_seen
    if seen.date() == session.clock().date():
        return seen.strftime("%H:%M")
    return seen.strftime("%Y-%m-%d")


@command("files", "list the files saved for a target or the whole box")
def files(session: Session, args: list[str]) -> None:
    (name,) = take_args(args, optional=("target name",))
    records = store.load_files(session.box)
    if name is not None:
        target = boxes.find_target(session.targets, name)
        records = [r for r in records if r.target == target.name]
    if not records:
        session.console.info("no files yet")
        return
    rows = [[r.path, _added(session, r), human_size(r.size)] for r in records]
    session.console.table(["file", "added", "size"], rows)


def _flag(which: str):
    def handler(session: Session, args: list[str]) -> None:
        take_args(args)
        console = session.console
        value = console.ask("flag")
        if value == "":
            console.fail("no flag typed")
            return
        if which in session.box.flags and not console.confirm(f"replace the {which} flag?"):
            return
        session.box.flags[which] = Flag(value, session.clock())
        store.save_box(session.box)
        console.ok(f"{which} flag recorded")

    return handler


command("flag user", "record the user flag")(_flag("user"))
command("flag root", "record the root flag")(_flag("root"))


@command("path", "print a folder's full path")
def path(session: Session, args: list[str]) -> None:
    (name,) = take_args(args, optional=("folder",))
    box = session.box.path
    if name is None:
        folder = box / "targets" / session.current.name if session.current else box
    elif name in BOX_FOLDERS:
        folder = box / name
    elif name in boxes.TARGET_FOLDERS:
        if session.current is None:
            raise ValueError(f"no current target for {name}")
        folder = box / "targets" / session.current.name / name
    else:
        valid = ", ".join(sorted({*boxes.TARGET_FOLDERS, *BOX_FOLDERS}))
        raise ValueError(f"unknown folder {name}. use one of: {valid}")
    session.console.info(str(folder))


@command("note", "open the note in vim")
def note(session: Session, args: list[str]) -> None:
    take_args(args)
    if notewindow.open_note(session.paths, session.settings, session.box, os.environ):
        session.console.ok("note opened")
        return
    manual = notewindow.vim_command(session.paths, session.box.path / NOTE_NAME)
    session.console.warn(f"could not open a window. run: {' '.join(manual)}")


def _flag_line(session: Session, which: str) -> str:
    flag = session.box.flags.get(which)
    return f"recorded {flag.at.strftime('%H:%M')}" if flag else "-"


@command("status", "show the box at a glance")
def status(session: Session, args: list[str]) -> None:
    take_args(args)
    box = session.box
    rows = [
        ("box", f"{box.name} ({box.platform})"),
        ("started", box.started.date().isoformat()),
        ("status", box.status),
        ("targets", str(len(session.targets))),
        ("creds", str(len(session.creds))),
        ("files", str(len(store.load_files(box)))),
        ("user flag", _flag_line(session, "user")),
        ("root flag", _flag_line(session, "root")),
    ]
    for label, value in rows:
        session.console.info(f"{label:<10}{value}")


@command("check", "run the setup checks again")
def check(session: Session, args: list[str]) -> None:
    take_args(args)
    results = checks.launch_checks(session.paths, session.settings, os.environ, Path.home())
    checks.report(session.console, results)


@command("help", "list the commands")
def help_(session: Session, args: list[str]) -> None:
    take_args(args)
    rows = [[name, COMMANDS[name][1]] for name in sorted(COMMANDS)]
    session.console.table(["command", "does"], rows)
