"""The box's lines in /etc/hosts, kept in step with box.hosts and the targets."""

from pwn_broker import hosts, toolstate
from pwn_broker.model import Target
from pwn_broker.session import Session
from pwn_broker.store import save_box

FILE = "/etc/hosts"
MARK = "  # pwn-broker "


def _names(target: Target) -> list[str]:
    return [name for name in target.hostnames if hosts.valid_hostname(name)]


def wanted(session: Session) -> list[hosts.Wanted]:
    by_name = {t.name: t for t in session.targets}
    found = []
    for name in session.box.hosts:
        target = by_name.get(name)
        if target is None or not target.ips:
            continue
        names = _names(target)
        if names:
            found.append(hosts.Wanted(target.name, target.ips[0], names))
    return found


def _reason(exc: hosts.HostsError) -> str:
    if exc.args == (hosts.CHANGED,):
        return "another program changed it while it was being written"
    return str(exc)


def _box_names(session: Session) -> dict[str, str]:
    try:
        return toolstate.unfinished_boxes(session.paths)
    except OSError:
        # a name is only a courtesy; the ID still says which box
        return {}


def _not_changed(session: Session, exc: hosts.HostsError, want: list[hosts.Wanted]) -> None:
    console = session.console
    console.warn(f"{FILE} was not changed: {_reason(exc)}")
    try:
        present = set(hosts.marked(hosts.read(session.hosts_path)).get(session.box.id, []))
    except hosts.HostsError:
        present = set()
    for entry in want:
        try:
            text = hosts.line(entry, session.box.id)
        except hosts.HostsError:
            continue
        if text not in present:
            console.info("add this line yourself:")
            console.raw(text)


def _report(
    session: Session, outcome: hosts.Outcome, changed: bool, want: list[hosts.Wanted]
) -> None:
    console = session.console
    if changed:
        console.ok(f"{FILE} updated")
        for text in outcome.written:
            console.info("    " + text.split(MARK, 1)[0])
    if outcome.taken_out:
        names = _box_names(session)
        for box_id, text in outcome.taken_out:
            name = names.get(box_id, box_id)
            console.warn(
                f"took out a line of box {name} that names the same host; "
                f"it returns when {name} is opened"
            )
            console.info("    " + text)
    ips = {entry.target: entry.ip for entry in want}
    for target, name in outcome.already:
        console.ok(f"{name} already resolves to {ips[target]}")
    for target, name, number, text in outcome.blocked:
        where = f"line {number} of {FILE}" if number else f"another line for this box in {FILE}"
        console.warn(
            f"{name} is on {where} with another address. "
            f"remove it there, then: host file on {target}"
        )
        console.info("    " + text)


def sync(session: Session) -> bool:
    """Rewrite the box's lines from box.hosts; false when the file could not be changed."""
    want = wanted(session)
    outcomes: list[hosts.Outcome] = []

    def change(text: bytes) -> bytes:
        outcome = hosts.rewrite(text, session.box.id, want)
        # update may start over once; the last outcome is the one written
        outcomes.append(outcome)
        return outcome.text

    root = session.is_root()
    try:
        if not root:
            try:
                session.paths.run.mkdir(parents=True, exist_ok=True)
            except OSError as exc:
                reason = exc.strerror or exc
                raise hosts.HostsError(f"cannot use {session.paths.run}: {reason}") from exc
        before, after = hosts.update(
            session.hosts_path,
            change,
            root=root,
            scratch=session.paths.run,
            run=session.run_privileged,
        )
    except hosts.HostsError as exc:
        _not_changed(session, exc, want)
        return False
    _report(session, outcomes[-1], before != after, want)
    return True


def _check(target: Target) -> None:
    if not target.ips:
        raise ValueError(f"{target.name} has no IP address")
    if not target.hostnames:
        raise ValueError(f"{target.name} has no hostname")


def _first_bad(target: Target) -> str | None:
    if _names(target):
        return None
    return target.hostnames[0]


def _record(session: Session, target: Target) -> None:
    box = session.box
    if target.name in box.hosts:
        sync(session)
        return
    box.hosts.append(target.name)
    save_box(box)
    if not sync(session):
        # the record follows the file: nothing was written, so nothing is recorded
        box.hosts.remove(target.name)
        save_box(box)


def offer(session: Session, target: Target) -> None:
    if target.name in session.box.hosts or not target.ips or not target.hostnames:
        return
    bad = _first_bad(target)
    if bad is not None:
        session.console.warn(
            f"{bad} is not a plain hostname, so {target.name} cannot have a line in {FILE}"
        )
        return
    if session.console.confirm(f"add {target.name}'s hostnames to {FILE}?", default=True):
        _record(session, target)


def file_on(session: Session, target: Target) -> None:
    _check(target)
    bad = _first_bad(target)
    if bad is not None:
        raise ValueError(f"not a plain hostname: {bad}")
    _record(session, target)


def file_off(session: Session, target: Target) -> None:
    box = session.box
    if target.name not in box.hosts:
        session.console.ok(f"{target.name} has no line in {FILE}")
        return
    at = box.hosts.index(target.name)
    box.hosts.remove(target.name)
    save_box(box)
    if not sync(session):
        # the line is still in the file, so the record keeps it
        box.hosts.insert(at, target.name)
        save_box(box)


def listed(session: Session) -> set[str] | None:
    """Every hostname in the file, lowercased; None when the file cannot be read."""
    try:
        text = hosts.read(session.hosts_path)
    except hosts.HostsError:
        return None
    found = set()
    for raw in text.split(b"\n"):
        fields = raw.split(b"#", 1)[0].split()
        found.update(field.decode("utf-8", "replace").lower() for field in fields[1:])
    return found
