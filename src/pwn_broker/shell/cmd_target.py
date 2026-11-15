from pwn_broker import boxes, note, setup
from pwn_broker.note import NoteError
from pwn_broker.paths import safe_name
from pwn_broker.questions import ask_target
from pwn_broker.session import Session, refresh, set_current
from pwn_broker.shell.commands import command, take_args
from pwn_broker.store import StoreError


def _has_note(session: Session) -> bool:
    return (session.box.path / note.NOTE_NAME).exists()


def _update_note(session: Session, change) -> None:
    # The target already exists on disk by now, so a broken note must not stop the rest.
    if not _has_note(session):
        return
    try:
        note.write_note(session.box, change(note.read_note(session.box)))
    except (OSError, NoteError, StoreError) as exc:
        session.console.warn(f"the note could not be updated: {exc}")


@command("target add", "add a target to this box")
def target_add(session: Session, args: list[str]) -> None:
    take_args(args)
    console = session.console
    answers = ask_target(console, taken={t.name for t in session.targets})
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
        _, section = note.split_template(setup.load_template(session.paths))
        return note.append_section(text, section, target)

    _update_note(session, add_section)
    set_current(session, target)
    refresh(session)
    console.ok(f"target {target.name} created")


@command("target list", "list the targets")
def target_list(session: Session, args: list[str]) -> None:
    take_args(args)
    if not session.targets:
        session.console.info("no targets yet")
        return
    rows = [
        [t.name, ", ".join(t.ips) or "-", ", ".join(t.hostnames) or "-", t.scope]
        for t in session.targets
    ]
    session.console.table(["name", "ip", "hostname", "scope"], rows)


@command("target use", "switch to a target")
def target_use(session: Session, args: list[str]) -> None:
    (name,) = take_args(args, ("target name",))
    target = boxes.find_target(session.targets, name)
    set_current(session, target)
    session.console.ok(f"now on {target.name}")


@command("target show", "show one target")
def target_show(session: Session, args: list[str]) -> None:
    (name,) = take_args(args, optional=("target name",))
    if name is not None:
        target = boxes.find_target(session.targets, name)
    elif session.current is not None:
        target = session.current
    else:
        raise ValueError("no current target")
    folder = session.box.path / "targets" / target.name
    rows = [
        ("name", target.name),
        ("ips", " ".join(target.ips) or "-"),
        ("hostnames", " ".join(target.hostnames) or "-"),
        ("scope", target.scope),
        ("added", target.added.strftime("%Y-%m-%d %H:%M")),
        ("folder", str(folder)),
    ]
    for label, value in rows:
        session.console.info(f"{label:<10}{value}")


@command("target edit", "change a target's addresses or scope")
def target_edit(session: Session, args: list[str]) -> None:
    (name,) = take_args(args, ("target name",))
    target = boxes.find_target(session.targets, name)
    answers = ask_target(session.console, taken=set(), defaults=target, ask_name=False)
    boxes.edit_target(
        session.box,
        session.targets,
        target.name,
        ips=answers.ips,
        hostnames=answers.hostnames,
        scope=answers.scope,
    )
    refresh(session)
    session.console.ok(f"target {target.name} updated")


@command("target rename", "rename a target and its folder")
def target_rename(session: Session, args: list[str]) -> None:
    (name,) = take_args(args, ("target name",))
    target = boxes.find_target(session.targets, name)
    old = target.name
    new = session.console.ask("new name")
    try:
        unchanged = safe_name(new) == old
    except ValueError:
        unchanged = False
    if unchanged:
        raise ValueError(f"{old} is already its name")
    boxes.rename_target(session.box, session.targets, old, new)
    if session.current is target:
        set_current(session, target)
    _update_note(session, lambda text: note.rename_heading(text, old, target.name))
    refresh(session)
    session.console.ok(f"target {old} is now {target.name}")


@command("target remove", "remove an empty target")
def target_remove(session: Session, args: list[str]) -> None:
    (name,) = take_args(args, ("target name",))
    target = boxes.find_target(session.targets, name)
    boxes.ensure_removable(session.box, target.name)
    if not session.console.confirm(f"remove target {target.name}?"):
        return
    boxes.remove_target(session.box, session.targets, target.name)
    if session.current is target:
        set_current(session, session.targets[0] if session.targets else None)
    refresh(session)
    session.console.ok(f"target {target.name} removed")
