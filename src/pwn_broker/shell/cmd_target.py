from pwn_broker import boxes, hostflow, note, targetflow
from pwn_broker.paths import safe_name
from pwn_broker.questions import ask_target
from pwn_broker.session import Session, refresh, set_current
from pwn_broker.shell.commands import command, take_args
from pwn_broker.targetflow import update_note


@command("target add", "add a target to this box")
def target_add(session: Session, args: list[str]) -> None:
    take_args(args)
    answers = ask_target(session.console, taken={t.name for t in session.targets})
    targetflow.add(session, answers, make_current=True)


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
    before = note.title_text(target)
    boxes.edit_target(
        session.box,
        session.targets,
        target.name,
        ips=answers.ips,
        hostnames=answers.hostnames,
        scope=answers.scope,
    )
    had_line = target.name in session.box.hosts
    hostflow.forget_if_unwanted(session, target)
    update_note(session, lambda text: note.retitle(text, before, note.title_text(target)))
    refresh(session)
    session.console.ok(f"target {target.name} updated")
    if had_line:
        hostflow.sync(session)
    else:
        hostflow.offer(session, target)


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
    before = note.title_text(target)
    had_line = old in session.box.hosts
    boxes.rename_target(session.box, session.targets, old, new, creds=session.creds)
    if session.current is target:
        set_current(session, target)
    update_note(session, lambda text: note.retitle(text, before, note.title_text(target)))
    refresh(session)
    session.console.ok(f"target {old} is now {target.name}")
    if had_line:
        hostflow.sync(session)


@command("target remove", "remove an empty target")
def target_remove(session: Session, args: list[str]) -> None:
    (name,) = take_args(args, ("target name",))
    target = boxes.find_target(session.targets, name)
    boxes.ensure_removable(session.box, target.name)
    if not session.console.confirm(f"remove target {target.name}?"):
        return
    had_line = target.name in session.box.hosts
    boxes.remove_target(session.box, session.targets, target.name)
    if session.current is target:
        set_current(session, session.targets[0] if session.targets else None)
    refresh(session)
    session.console.ok(f"target {target.name} removed")
    if had_line:
        hostflow.sync(session)
