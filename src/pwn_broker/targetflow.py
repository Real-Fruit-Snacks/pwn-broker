"""Adding a target, from wherever it is added."""

from collections.abc import Callable

from pwn_broker import boxes, hostflow, note, setup
from pwn_broker.console import Cancelled
from pwn_broker.model import Target
from pwn_broker.note import NoteError
from pwn_broker.questions import TargetAnswers
from pwn_broker.session import Session, refresh, set_current
from pwn_broker.store import StoreError

PING_MISSING = "ping"


def update_note(session: Session, change: Callable[[str], str]) -> None:
    # The target already exists on disk by now, so a broken note must not stop the rest.
    if not (session.box.path / note.NOTE_NAME).exists():
        return
    try:
        text = note.read_note(session.box)
        changed = change(text)
        if changed != text:
            note.write_note(session.box, changed)
    except (OSError, NoteError, StoreError) as exc:
        session.console.warn(f"the note could not be updated: {exc}")


def add(session: Session, answers: TargetAnswers, *, make_current: bool) -> Target:
    target = boxes.add_target(
        session.box,
        session.targets,
        ips=answers.ips,
        hostnames=answers.hostnames,
        scope=answers.scope,
        name=answers.name,
        now=session.clock(),
    )

    def add_section(text: str) -> str:
        # the section and the redrawn box go into one write, so vim reloads once
        _, section = note.split_template(setup.load_template(session.paths))
        text = note.append_section(text, section, target, session.box)
        try:
            return note.update_box(text, session.box, session.targets)
        except NoteError:
            # refresh says what is wrong with the box
            return text

    update_note(session, add_section)
    refresh(session)
    if make_current:
        set_current(session, target)
    session.console.ok(f"target {target.name} created")
    after_add(session, target)
    return target


def _ping(session: Session, ip: str) -> None:
    console = session.console
    try:
        result = session.ping(ip)
    except KeyboardInterrupt:
        console.info("cancelled")
        return
    if not result.checked:
        if PING_MISSING not in session.notices:
            session.notices.add(PING_MISSING)
            console.warn("ping is not installed; the target was not checked")
    elif not result.answered:
        console.warn(f"{ip} did not answer a ping; Windows targets often do not")
    elif result.ms is None:
        console.ok(f"{ip} answered")
    else:
        console.ok(f"{ip} answered in {round(result.ms)} ms")


def after_add(session: Session, target: Target) -> None:
    try:
        hostflow.offer(session, target)
    except Cancelled:
        # the target is made; only the line is skipped
        session.console.info("cancelled")
    except (StoreError, OSError) as exc:
        session.console.warn(f"the /etc/hosts line could not be recorded: {exc}")
    if target.ips:
        _ping(session, target.ips[0])
