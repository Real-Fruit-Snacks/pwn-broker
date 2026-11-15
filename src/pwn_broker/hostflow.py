"""The box's lines in /etc/hosts, kept in step with box.hosts and the targets."""

from collections.abc import Callable
from pathlib import Path

from pwn_broker import boxes, hosts, privilege, toolstate
from pwn_broker.console import Cancelled, Console
from pwn_broker.model import Target
from pwn_broker.paths import AppPaths
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
        present = hosts.marked(hosts.read(session.hosts_path)).get(session.box.id, [])
    except hosts.HostsError:
        present = []
    lines = []
    for entry in want:
        try:
            lines.append(hosts.line(entry, session.box.id))
        except hosts.HostsError:
            continue
    for text in lines:
        if text not in present:
            console.info("add this line yourself:")
            console.raw(text)
    for text in present:
        if text not in lines:
            console.info("remove this line yourself:")
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


def _left_out(session: Session, want: list[hosts.Wanted]) -> None:
    by_name = {t.name: t for t in session.targets}
    for entry in want:
        for name in by_name[entry.target].hostnames:
            notice = f"left out {entry.target} {name}"
            if hosts.valid_hostname(name) or notice in session.notices:
                continue
            session.notices.add(notice)
            session.console.warn(
                f"{name} is not a plain hostname, so it was left out of "
                f"{entry.target}'s line in {FILE}"
            )


def forget_if_unwanted(session: Session, target: Target) -> None:
    """Take a target off box.hosts once it can no longer have a line, so the record stays true."""
    box = session.box
    if target.name in box.hosts and not (target.ips and _names(target)):
        box.hosts.remove(target.name)
        save_box(box)


def _update(
    paths: AppPaths,
    hosts_path: Path,
    root: bool,
    run: Callable,
    change: Callable[[bytes], bytes],
) -> tuple[bytes, bytes]:
    if not root:
        try:
            paths.run.mkdir(parents=True, exist_ok=True)
        except OSError as exc:
            reason = exc.strerror or exc
            raise hosts.HostsError(f"cannot use {paths.run}: {reason}") from exc
    return hosts.update(hosts_path, change, root=root, scratch=paths.run, run=run)


def sync(session: Session) -> bool:
    """Rewrite the box's lines from box.hosts; false when the file could not be changed."""
    want = wanted(session)
    outcomes: list[hosts.Outcome] = []

    def change(text: bytes) -> bytes:
        outcome = hosts.rewrite(text, session.box.id, want)
        # update may start over once; the last outcome is the one written
        outcomes.append(outcome)
        return outcome.text

    _left_out(session, want)
    try:
        before, after = _update(
            session.paths, session.hosts_path, session.is_root(), session.run_privileged, change
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
    try:
        save_box(box)
    except BaseException:
        box.hosts.remove(target.name)
        raise
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
    box.hosts.remove(target.name)
    save_box(box)
    # if the write fails, sync prints the line to remove by hand; the next sync takes it out too
    sync(session)


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


# ---- finish, opening a box and launch


def _count(lines: int) -> str:
    return "1 line" if lines == 1 else f"{lines} lines"


def _own_lines(session: Session) -> int | None:
    try:
        return len(hosts.marked(hosts.read(session.hosts_path)).get(session.box.id, []))
    except hosts.HostsError:
        return None


def summary(session: Session) -> list[str]:
    found = _own_lines(session)
    if not found:
        return []
    return [f"hosts     {_count(found)} to remove from {FILE}"]


def undo(session: Session) -> None:
    """Take the box's lines out at finish; a problem is reported, never raised."""
    if not session.box.hosts and not _own_lines(session):
        return
    box_id = session.box.id
    try:
        before, after = _update(
            session.paths,
            session.hosts_path,
            session.is_root(),
            session.run_privileged,
            lambda text: hosts.strip(text, {box_id}),
        )
    except hosts.HostsError as exc:
        # the box is finished anyway; the next launch offers to remove them again
        _not_changed(session, exc, [])
        return
    if before != after:
        removed = len(hosts.marked(before).get(box_id, []))
        session.console.ok(f"removed {_count(removed)} from {FILE}")


def on_open(session: Session) -> None:
    if session.box.hosts:
        sync(session)


def leftovers(
    paths: AppPaths,
    console: Console,
    *,
    hosts_path: Path = hosts.DEFAULT_PATH,
    is_root: Callable[[], bool] = privilege.is_root,
    run: Callable = privilege.run_privileged,
) -> None:
    """Offer to remove lines marked with the ID of a box that is finished or gone."""
    folders, problems = boxes.list_boxes(paths)
    if problems:
        return
    try:
        found = hosts.marked(hosts.read(hosts_path))
    except hosts.HostsError:
        return
    names = {b.id: b.name for b in folders}
    active = {b.id for b in folders if b.status == "active"}
    try:
        for box_id in sorted(found):
            if box_id in active:
                continue
            lines = found[box_id]
            label = names.get(box_id, box_id)
            number, noun = len(lines), "line" if len(lines) == 1 else "lines"
            question = f"remove {number} {FILE} {noun} left by {label}?"
            if not console.confirm(question, default=True):
                continue
            _remove_left(paths, console, hosts_path, is_root, run, box_id)
    except Cancelled:
        pass


def _remove_left(
    paths: AppPaths,
    console: Console,
    hosts_path: Path,
    is_root: Callable[[], bool],
    run: Callable,
    box_id: str,
) -> None:
    try:
        before, _after = _update(
            paths, hosts_path, is_root(), run, lambda text: hosts.strip(text, {box_id})
        )
    except hosts.HostsError as exc:
        console.warn(f"{FILE} was not changed: {_reason(exc)}")
        try:
            present = hosts.marked(hosts.read(hosts_path)).get(box_id, [])
        except hosts.HostsError:
            present = []
        for text in present:
            console.info("remove this line yourself:")
            console.raw(text)
        return
    console.ok(f"removed {_count(len(hosts.marked(before).get(box_id, [])))} from {FILE}")
