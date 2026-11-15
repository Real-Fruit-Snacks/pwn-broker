import copy
from collections.abc import Callable
from pathlib import Path
from typing import TypeVar

from pwn_broker import boxes, creds, store
from pwn_broker.lists import ListSummary
from pwn_broker.model import Cred
from pwn_broker.questions import ask_cred, ask_domain, ask_found_on
from pwn_broker.session import Session, refresh
from pwn_broker.shell.commands import command, take_args
from pwn_broker.store import save_box


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


def _number(text: str) -> int:
    if not (text.isascii() and text.isdigit()) or int(text) < 1:
        raise ValueError(f"not a credential number: {text}")
    return int(text)


def _get(session: Session, text: str) -> Cred:
    return creds.find_cred(session.creds, _number(text))


T = TypeVar("T")


def _guarded(session: Session, change: Callable[[], T]) -> T:
    # memory must not run ahead of disk, so a failed save puts the list back
    snapshot = copy.deepcopy(session.creds)
    try:
        return change()
    except BaseException:
        session.creds[:] = snapshot
        # the change may have reached disk before the step that failed; put that back too
        try:
            store.save_creds(session.box, session.creds)
        except Exception:
            pass
        raise


def _remember_numbers(session: Session) -> None:
    # numbers are never reused, so the highest one ever issued outlives removals
    extra = session.box.extra
    highest = max([extra.get("last_cred_n", 0), *(c.n for c in session.creds)])
    if highest != extra.get("last_cred_n"):
        extra["last_cred_n"] = highest
        save_box(session.box)


def _report_lists(session: Session, summary: ListSummary) -> None:
    console = session.console
    console.ok(
        "lists updated: "
        f"{_count(summary.usernames, 'username')}, "
        f"{_count(summary.passwords, 'password')}, "
        f"{_count(summary.pairs, 'pair')}"
    )
    for name in summary.skipped:
        console.warn(f"{name} contains a colon and is left out of the colon-separated lists")


@command("cred add", "save a credential")
def cred_add(session: Session, args: list[str]) -> None:
    take_args(args)
    answers = ask_cred(session.console, session)

    def change() -> tuple[Cred, ListSummary]:
        cred = creds.add_cred(
            session.creds,
            username=answers.username,
            domain=answers.domain,
            secret=answers.secret,
            kind=answers.kind,
            found_on=answers.found_on,
            note=answers.note,
            now=session.clock(),
            floor=session.box.extra.get("last_cred_n", 0),
        )
        _remember_numbers(session)
        return cred, refresh(session)

    cred, summary = _guarded(session, change)
    where = f", found on {cred.found_on}" if cred.found_on else ""
    session.console.ok(f"cred {cred.n} saved{where}")
    _report_lists(session, summary)


@command("cred list", "list the credentials")
def cred_list(session: Session, args: list[str]) -> None:
    take_args(args)
    if not session.creds:
        session.console.info("no creds yet")
        return
    rows = [
        [str(c.n), c.username, c.domain, c.secret, c.kind, c.found_on, ", ".join(c.works_on)]
        for c in session.creds
    ]
    session.console.table(
        ["n", "user", "domain", "secret", "kind", "found on", "works on"], rows
    )


@command("cred show", "print one secret and nothing else")
def cred_show(session: Session, args: list[str]) -> None:
    (text,) = take_args(args, ("cred number",))
    cred = _get(session, text)
    if cred.secret == "":
        session.console.fail(f"cred {cred.n} has no secret")
        return
    session.console.raw(cred.secret)


@command("cred edit", "change a credential")
def cred_edit(session: Session, args: list[str]) -> None:
    (text,) = take_args(args, ("cred number",))
    cred = _get(session, text)
    a = ask_cred(session.console, session, cred)

    def change() -> ListSummary:
        creds.edit_cred(
            session.creds,
            cred.n,
            username=a.username,
            domain=a.domain,
            secret=a.secret,
            kind=a.kind,
            found_on=a.found_on,
            works_on=a.works_on,
            note=a.note,
        )
        return refresh(session)

    summary = _guarded(session, change)
    session.console.ok(f"cred {cred.n} updated")
    _report_lists(session, summary)


@command("cred works", "record where a credential works")
def cred_works(session: Session, args: list[str]) -> None:
    if not args:
        raise ValueError("missing argument: cred number")
    cred = _get(session, args[0])
    if args[1:]:
        names = [boxes.find_target(session.targets, word).name for word in args[1:]]
    elif session.current is not None:
        names = [session.current.name]
    else:
        raise ValueError("no current target; name one")

    def change() -> ListSummary:
        creds.mark_works(session.creds, cred.n, names)
        return refresh(session)

    summary = _guarded(session, change)
    session.console.ok(f"cred {cred.n} works on {', '.join(dict.fromkeys(names))}")
    _report_lists(session, summary)


@command("cred remove", "delete a credential")
def cred_remove(session: Session, args: list[str]) -> None:
    (text,) = take_args(args, ("cred number",))
    cred = _get(session, text)
    console = session.console
    console.info(f"{cred.username}, found on {cred.found_on}" if cred.found_on else cred.username)
    if not console.confirm(f"remove cred {cred.n}?"):
        return

    def change() -> ListSummary:
        _remember_numbers(session)
        creds.remove_cred(session.creds, cred.n)
        return refresh(session)

    summary = _guarded(session, change)
    console.ok(f"cred {cred.n} removed")
    _report_lists(session, summary)


def _read_names(text: str) -> list[str]:
    path = Path(text).expanduser()
    if not path.is_file():
        raise ValueError(f"{path} is not a file")
    try:
        with open(path, encoding="utf-8-sig", newline="") as handle:
            return handle.readlines()
    except UnicodeDecodeError:
        raise ValueError(f"{path} is not valid UTF-8 text") from None


@command("cred import", "add usernames from a file, one per line")
def cred_import(session: Session, args: list[str]) -> None:
    if not args:
        raise ValueError("missing argument: file")
    lines = _read_names(" ".join(args))
    console = session.console
    domain = ask_domain(console, session)
    found_on = ask_found_on(console, session)

    def change() -> tuple[int, ListSummary | None]:
        added = creds.import_usernames(
            session.creds,
            lines,
            domain=domain,
            found_on=found_on,
            now=session.clock(),
            floor=session.box.extra.get("last_cred_n", 0),
        )
        if added == 0:
            return 0, None
        _remember_numbers(session)
        return added, refresh(session)

    added, summary = _guarded(session, change)
    console.ok(f"{_count(added, 'username')} added")
    if summary is not None:
        _report_lists(session, summary)
