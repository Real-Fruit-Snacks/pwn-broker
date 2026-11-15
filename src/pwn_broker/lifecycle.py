import os
import shutil
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

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
from pwn_broker.session import Session, load_session, refresh, rescan
from pwn_broker.store import StoreError, load_box, save_box

UNDO_HOOKS: list[Callable[[Session], None]] = []
RESTORE_HOOKS: list[Callable[[Session], None]] = []

_FAILURES = (ArchiveError, StoreError, OSError)


def reopen_box(box: Box) -> None:
    box.status = "active"
    box.finished = None
    save_box(box)


def _pack(session: Session, kind: str) -> Path:
    box = session.box
    refresh(session)
    records = rescan(session, hash_all=True)
    write_manifest(box, records, kind=kind, now=session.clock())
    dest = archive_path(session.paths, box, kind)
    pack(box, dest)
    return dest


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


def export_box(session: Session, *, fix: Callable[[Path], int] = fix_ownership) -> Path | None:
    try:
        # ownership first: as a normal user a root-owned file cannot be hashed or packed
        fix(session.box.path)
        dest = _pack(session, "exported")
    except _FAILURES as exc:
        session.console.fail(f"export failed: {exc}")
        return None
    session.console.ok(f"archive {dest}")
    try:
        copy = _copy(session, dest)
    except _FAILURES as exc:
        session.console.warn(f"the export was written to {dest}, but the copy to {session.settings.copy_to} failed: {exc}")
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
    if unsaved(box):
        console.fail(
            "the note has unsaved changes; save it in vim with :w, "
            "or run note to reopen the window if it is closed"
        )
        return None

    dest = archive_path(session.paths, box, "finished")
    try:
        files = rescan(session)
    except _FAILURES as exc:
        console.fail(f"cannot read the box: {exc}")
        return None
    console.info(f"box       {box.name} ({box.platform}), started {box.started:%Y-%m-%d}")
    console.info(f"targets   {len(session.targets)}")
    console.info(f"files     {len(files)}")
    console.info(f"archive   {dest}")

    if not console.confirm("finish this box?"):
        return None
    if dest.exists() and not console.confirm("replace the existing archive?"):
        return None

    packed: Path | None = None
    try:
        fix(box.path)
        # saved before the rescan so the manifest holds the checksum of the box.toml that gets archived
        box.status = "finished"
        box.finished = session.clock()
        save_box(box)
        packed = _pack(session, "finished")
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
    for hook in UNDO_HOOKS:
        try:
            hook(session)
        except Exception as exc:
            console.fail(f"{getattr(hook, '__name__', repr(hook))} failed: {exc}")

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
