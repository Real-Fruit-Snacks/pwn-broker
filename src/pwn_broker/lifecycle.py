import os
import shutil
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from pwn_broker import recstate
from pwn_broker.archive import (
    ArchiveError,
    archive_path,
    copy_out,
    pack,
    peek_folder,
    unpack,
    verify,
    write_manifest,
)
from pwn_broker.config import Settings
from pwn_broker.console import Cancelled, Console
from pwn_broker.model import Box
from pwn_broker.notewindow import note_unsaved
from pwn_broker.paths import AppPaths
from pwn_broker.privilege import fix_ownership
from pwn_broker.session import Session, load_session, process_checks, refresh, rescan
from pwn_broker.store import StoreError, load_box, save_box
from pwn_broker.toolpkg import ToolError

BLOCK_HOOKS: list[Callable[[Session], str | None]] = []
# each gives the label and value rows it adds to the summary before finish
SUMMARY_HOOKS: list[Callable[[Session], list[tuple[str, str]]]] = []
PRE_PACK_HOOKS: list[Callable[[Session], None]] = []
UNDO_HOOKS: list[Callable[[Session], None]] = []
RESTORE_HOOKS: list[Callable[[Session], None]] = []

_FAILURES = (ArchiveError, StoreError, OSError, ToolError)
_SHOWN = 10


def reopen_box(box: Box) -> None:
    box.status = "active"
    box.finished = None
    save_box(box)


def _pack(session: Session, kind: str) -> tuple[Path, list[str]]:
    box = session.box
    refresh(session)
    # read once: the manifest and the archive must hold the same length of each live recording
    live = recstate.live_casts(session.paths, box, **process_checks(session))
    records = rescan(session, hash_all=True, live=live)
    write_manifest(box, records, kind=kind, now=session.clock())
    dest = archive_path(session.paths, box, kind)
    return dest, pack(box, dest, cut=live)


def _report_left_out(console: Console, left_out: list[str]) -> None:
    for rel in left_out[:_SHOWN]:
        console.warn(f"{rel}   not archived: a link or special file")
    if len(left_out) > _SHOWN:
        console.warn(f"and {len(left_out) - _SHOWN} more")


def _copy(session: Session, dest: Path) -> Path | None:
    copy_to = session.settings.copy_to
    return copy_out(dest, copy_to) if copy_to else None


def _rollback(box: Box) -> None:
    box.status = "active"
    box.finished = None
    try:
        save_box(box)
    except Exception:
        # the original failure is the one worth reporting
        pass


def export_box(
    session: Session, *, fix: Callable[[Path], int] = fix_ownership, strict_copy: bool = False
) -> Path | None:
    # strict_copy makes a failed copy a failed export: copy_to is how the work outlives the VM
    try:
        # ownership first: as a normal user a root-owned file cannot be hashed or packed
        fix(session.box.path)
        for hook in PRE_PACK_HOOKS:
            hook(session)
        dest, left_out = _pack(session, "exported")
    except _FAILURES as exc:
        session.console.fail(f"export failed: {exc}")
        return None
    session.console.ok(f"archive {dest}")
    _report_left_out(session.console, left_out)
    try:
        copy = _copy(session, dest)
    except _FAILURES as exc:
        message = f"the export was written to {dest}, but the copy to {session.settings.copy_to} failed: {exc}"
        if strict_copy:
            session.console.fail(message)
            return None
        session.console.warn(message)
        return dest
    if copy is not None:
        session.console.ok(f"copy {copy}")
    return dest


def _remove_folder(session: Session) -> None:
    folder = session.box.path
    active = session.paths.active.resolve()
    if active not in folder.resolve().parents:
        session.console.warn(f"{folder} is not inside {session.paths.active}; left in place")
        return
    try:
        shutil.rmtree(folder)
    except OSError as exc:
        session.console.warn(f"could not remove {folder}: {exc}")
        return
    session.console.ok(f"removed {folder}")


def finish_box(
    session: Session,
    *,
    unsaved: Callable[[Box], bool] = note_unsaved,
    fix: Callable[[Path], int] = fix_ownership,
) -> Path | None:
    box = session.box
    console = session.console
    reasons = [reason for reason in (hook(session) for hook in BLOCK_HOOKS) if reason]
    for reason in reasons:
        console.fail(reason)
    if unsaved(box):
        console.fail(
            "the note has unsaved changes; save it in vim with :w, "
            "or run note to reopen the window if it is closed"
        )
        return None
    if reasons:
        return None

    dest = archive_path(session.paths, box, "finished")
    try:
        files = rescan(session)
    except _FAILURES as exc:
        console.fail(f"cannot read the box: {exc}")
        return None
    rows = [
        ("box", f"{box.name} ({box.platform}), started {box.started:%Y-%m-%d}"),
        ("targets", str(len(session.targets))),
        ("files", str(len(files))),
        ("archive", str(dest)),
    ]
    for hook in SUMMARY_HOOKS:
        rows.extend(hook(session))
    console.fields(rows)

    if not console.confirm("finish this box?"):
        return None
    if dest.exists() and not console.confirm("replace the existing archive?"):
        return None

    packed: Path | None = None
    try:
        fix(box.path)
        for hook in PRE_PACK_HOOKS:
            hook(session)
        # saved before the rescan so the manifest holds the checksum of the box.toml that gets archived
        box.status = "finished"
        box.finished = session.clock()
        save_box(box)
        packed, left_out = _pack(session, "finished")
        copy = _copy(session, packed)
    except _FAILURES as exc:
        _rollback(box)
        if packed is None:
            console.fail(f"finish failed, the box is still active: {exc}")
        else:
            console.fail(
                f"the archive was written to {packed}, but the copy to {session.settings.copy_to} "
                f"failed: {exc}; the box is still active"
            )
        return None
    except BaseException:
        _rollback(box)
        raise

    dest = packed
    console.ok(f"archive {dest}")
    if copy is not None:
        console.ok(f"copy {copy}")
    _report_left_out(console, left_out)
    undo_failed = False
    for hook in UNDO_HOOKS:
        try:
            hook(session)
        except Exception as exc:
            undo_failed = True
            console.fail(f"{getattr(hook, '__name__', repr(hook))} failed: {exc}")

    if undo_failed:
        console.warn(f"the working folder {box.path} was kept because an undo step failed")
        return dest
    if left_out:
        count = "1 item is" if len(left_out) == 1 else f"{len(left_out)} items are"
        console.warn(f"{count} not in the archive and will be deleted with the folder")
    try:
        remove = console.confirm("remove working folder?")
    except Cancelled:
        remove = False
    if remove:
        _remove_folder(session)
    return dest


def import_box(
    paths: AppPaths,
    settings: Settings,
    console: Console,
    archive: Path,
    clock: Callable[[], datetime],
) -> Box | None:
    try:
        verify(archive)
        folder = peek_folder(archive)
        replace = False
        if os.path.lexists(paths.active / folder):
            replace = console.confirm(f"a box named {folder} is already here. replace it?")
            if not replace:
                return None
        box = load_box(unpack(archive, paths.active, replace=replace))
        if box.status == "finished":
            reopen_box(box)
        session = load_session(paths, settings, console, box, clock)
        for hook in RESTORE_HOOKS:
            hook(session)
    except _FAILURES as exc:
        console.fail(f"import failed: {exc}")
        return None
    console.ok(f"unpacked to {box.path}")
    console.ok(f"{len(session.targets)} targets")
    return box
