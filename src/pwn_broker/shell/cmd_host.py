from pwn_broker import boxes, hostflow, hosts, note
from pwn_broker.model import Target
from pwn_broker.session import Session, refresh
from pwn_broker.shell.commands import COMMANDS, command, take_args
from pwn_broker.targetflow import update_note

NO_CURRENT = "no current target; pick one with: target use <name>"


def _current(session: Session) -> Target:
    if session.current is None:
        raise ValueError(NO_CURRENT)
    return session.current


def _named_or_current(session: Session, args: list[str]) -> Target:
    (name,) = take_args(args, optional=("target name",))
    if name is not None:
        return boxes.find_target(session.targets, name)
    return _current(session)


def _names(args: list[str]) -> list[str]:
    if not args:
        raise ValueError("missing argument: hostname")
    return args


def _count(target: Target) -> str:
    count = len(target.hostnames)
    return f"{target.name} now answers to {count} name" + ("" if count == 1 else "s")


def _set_hostnames(session: Session, target: Target, hostnames: list[str]) -> None:
    before = note.title_text(target)
    boxes.edit_target(
        session.box,
        session.targets,
        target.name,
        ips=target.ips,
        hostnames=hostnames,
        scope=target.scope,
    )
    update_note(session, lambda text: note.retitle(text, before, note.title_text(target)))
    refresh(session)


@command("host add", "add hostnames to the current target")
def host_add(session: Session, args: list[str]) -> None:
    target = _current(session)
    names = _names(args)
    owners = {
        name.lower(): other.name
        for other in session.targets
        if other is not target
        for name in other.hostnames
    }
    # every name is checked before anything changes
    for name in names:
        if not hosts.valid_hostname(name):
            raise ValueError(f"not a plain hostname: {name}")
        if name.lower() in owners:
            raise ValueError(f"{name} is already a hostname of {owners[name.lower()]}")
    hostnames = list(target.hostnames)
    have = {name.lower() for name in hostnames}
    for name in names:
        if name.lower() in have:
            session.console.ok(f"{name} is already a hostname of {target.name}")
            continue
        have.add(name.lower())
        hostnames.append(name)
    if hostnames == target.hostnames:
        return
    _set_hostnames(session, target, hostnames)
    session.console.ok(_count(target))
    if target.name in session.box.hosts:
        hostflow.sync(session)
    else:
        hostflow.offer(session, target)


@command("host remove", "take hostnames off the current target")
def host_remove(session: Session, args: list[str]) -> None:
    target = _current(session)
    names = _names(args)
    have = {name.lower() for name in target.hostnames}
    for name in names:
        if name.lower() not in have:
            raise ValueError(f"{target.name} has no hostname {name}")
    going = {name.lower() for name in names}
    hostnames = [name for name in target.hostnames if name.lower() not in going]
    if not hostnames and not target.ips:
        raise ValueError(f"{target.name} has no IP address, so it keeps at least one hostname")
    _set_hostnames(session, target, hostnames)
    session.console.ok(_count(target))
    if target.name not in session.box.hosts:
        return
    hostflow.forget_if_unwanted(session, target)
    hostflow.sync(session)


@command("host", "every hostname in the box and whether it is in /etc/hosts")
def host_list(session: Session, args: list[str]) -> None:
    take_args(args)
    rows = [[t.name, name] for t in session.targets for name in t.hostnames]
    if not rows:
        session.console.info("no hostnames yet")
        return
    listed = hostflow.listed(session)
    for row in rows:
        if listed is None:
            row.append("unknown")
        else:
            row.append("yes" if row[1].lower() in listed else "no")
    session.console.table(["target", "name", "in /etc/hosts"], rows)


@command("host file", "the target's line in /etc/hosts")
def host_file(session: Session, args: list[str]) -> None:
    take_args(args)
    for name in sorted(COMMANDS):
        if name.startswith("host file "):
            session.console.info(f"{name}   {COMMANDS[name][1]}")


@command("host file on", "put the target's line into /etc/hosts")
def host_file_on(session: Session, args: list[str]) -> None:
    hostflow.file_on(session, _named_or_current(session, args))


@command("host file off", "take the target's line out of /etc/hosts and forget it")
def host_file_off(session: Session, args: list[str]) -> None:
    hostflow.file_off(session, _named_or_current(session, args))
