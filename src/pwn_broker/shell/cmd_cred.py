from pathlib import Path

from pwn_broker import boxes, creds
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
    n = _number(text)
    for cred in session.creds:
        if cred.n == n:
            return cred
    raise creds.CredError(f"no credential numbered {n}")


def _remember_numbers(session: Session) -> None:
    # numbers are never reused, so the highest one ever issued outlives removals
    extra = session.box.extra
    highest = max([extra.get("last_cred_n", 0), *(c.n for c in session.creds)])
    if highest != extra.get("last_cred_n"):
        extra["last_cred_n"] = highest
        save_box(session.box)


def _refresh_and_report(session: Session) -> None:
    summary = refresh(session)
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
    where = f", found on {cred.found_on}" if cred.found_on else ""
    session.console.ok(f"cred {cred.n} saved{where}")
    _refresh_and_report(session)


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
    session.console.info(cred.secret)


@command("cred edit", "change a credential")
def cred_edit(session: Session, args: list[str]) -> None:
    (text,) = take_args(args, ("cred number",))
    cred = _get(session, text)
    a = ask_cred(session.console, session, cred)
    creds.edit_cred(
        session.creds,
        cred.n,
        username=a.username,
        domain=a.domain,
        secret=a.secret,
        kind=a.kind,
        found_on=a.found_on,
        note=a.note,
    )
    session.console.ok(f"cred {cred.n} updated")
    _refresh_and_report(session)


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
    creds.mark_works(session.creds, cred.n, names)
    session.console.ok(f"cred {cred.n} works on {', '.join(dict.fromkeys(names))}")
    _refresh_and_report(session)


@command("cred remove", "delete a credential")
def cred_remove(session: Session, args: list[str]) -> None:
    (text,) = take_args(args, ("cred number",))
    cred = _get(session, text)
    console = session.console
    console.info(f"{cred.username}, found on {cred.found_on}" if cred.found_on else cred.username)
    if not console.confirm(f"remove cred {cred.n}?"):
        return
    creds.remove_cred(session.creds, cred.n)
    console.ok(f"cred {cred.n} removed")
    _refresh_and_report(session)


def _read_names(text: str) -> list[str]:
    path = Path(text).expanduser()
    if not path.is_file():
        raise ValueError(f"{path} is not a file")
    try:
        with open(path, encoding="utf-8", newline="") as handle:
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
    added = creds.import_usernames(
        session.creds,
        lines,
        domain=domain,
        found_on=found_on,
        now=session.clock(),
        floor=session.box.extra.get("last_cred_n", 0),
    )
    if added == 0:
        console.ok("0 usernames added")
        return
    _remember_numbers(session)
    console.ok(f"{_count(added, 'username')} added")
    _refresh_and_report(session)
