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
from pwn_broker.filescan import NOT_UTF8, scan, sha256_file
from pwn_broker.model import Box, FileRecord
from pwn_broker.note import NOTE_NAME
from pwn_broker.notewindow import note_unsaved, shut_note
from pwn_broker.paths import AppPaths
from pwn_broker.privilege import fix_ownership
from pwn_broker.session import Session, load_session, process_checks, refresh, rescan
from pwn_broker.store import (
    StoreError,
    load_box,
    load_creds,
    load_files,
    load_targets,
    save_box,
)
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


def _recorded_note(records: list[FileRecord]) -> str | None:
    # the checksum the archive step recorded for the note; None when it had no note
    for record in records:
        if record.path == NOTE_NAME:
            return record.sha256
    return None


def _note_is_archived(box: Box, recorded: str | None) -> bool:
    try:
        return sha256_file(box.path / NOTE_NAME) == recorded
    except FileNotFoundError:
        return recorded is None
    except OSError:
        return False


# the box's own record, which the steps after the archive write again
_REWRITTEN = frozenset({"box.toml"})


_Seen = dict[str, tuple[int, float]]


def _look(session: Session) -> tuple[_Seen, _Seen, list[str]]:
    """The size and time of every file in the box, with none of them read.

    Returns the files the records list, the files they cannot (a name that is not UTF-8), and
    what could not be looked at. A link or special file is in none of them: it is never archived.
    """
    unlisted: _Seen = {}
    unread: list[str] = []

    def on_skip(rel: str, reason: str) -> None:
        if reason == NOT_UTF8:
            try:
                st = os.lstat(os.path.join(session.box.path, rel))
            except OSError:
                unread.append(rel)
            else:
                unlisted[rel] = (st.st_size, st.st_mtime)
        elif reason == "cannot read":
            unread.append(rel)

    # a limit below any size: no file is hashed, only its size and time are taken
    found = scan(session.box, [], now=session.clock(), limit=-1, on_skip=on_skip)
    return {r.path: (r.size, r.mtime) for r in found}, unlisted, unread


def _changed_since(session: Session, archived: list[FileRecord], unlisted: _Seen) -> list[str] | None:
    """The files made or changed in the box since the archive was packed, by size and time.

    `archived` is what the manifest lists, and `unlisted` the files it cannot name, as they were
    just before the archive was packed. None when the box could not be read again. Nothing is
    hashed: a scan in another terminal can still be writing, and the folder is about to be deleted.
    """
    packed = {r.path: (r.size, r.mtime) for r in archived} | unlisted
    try:
        listed, odd, unread = _look(session)
    except OSError:
        return None
    changed = {
        rel for rel, seen in (listed | odd).items() if rel not in _REWRITTEN and packed.get(rel) != seen
    }
    # a file or folder that cannot be looked at now may be new too
    changed.update(rel for rel in unread if rel not in packed)
    return sorted(changed)


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


def close_window(
    console: Console,
    paths: AppPaths,
    box: Box,
    *,
    close: Callable[[AppPaths, Box], bool] = shut_note,
) -> None:
    # the window of a note whose folder is about to go; one that stays is said once
    # close says whether the vim, or the terminal made for it, is still there
    if close(paths, box):
        console.warn("the note window did not close")


def finish_box(
    session: Session,
    *,
    unsaved: Callable[[Box], bool] = note_unsaved,
    close: Callable[[AppPaths, Box], bool] = shut_note,
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
        # the records cannot hold a name that is not UTF-8, so those files are noted here
        unlisted = _look(session)[1]
        packed, left_out = _pack(session, "finished")
        archived = load_files(box)
        archived_note = _recorded_note(archived)
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
    if remove and unsaved(box):
        console.warn("the note has unsaved changes; the folder was kept")
    elif remove and not _note_is_archived(box, archived_note):
        console.warn("the note changed after the archive was made; the folder was kept")
    elif remove and (changed := _changed_since(session, archived, unlisted)) != []:
        if changed is None:
            console.warn("the box could not be read again after the archive was made; the folder was kept")
        else:
            more = f" and {len(changed) - 1} more" if len(changed) > 1 else ""
            console.warn(f"{changed[0]}{more} changed after the archive was made; the folder was kept")
    elif remove and close(session.paths, box):
        # the vim, or the terminal made for it, is still there: the window would show a folder that is gone
        console.warn("the note window did not close; the folder was kept")
    elif remove:
        _remove_folder(session)
    return dest


def _close_replaced(
    paths: AppPaths,
    console: Console,
    folder: str,
    unsaved: Callable[[Box], bool],
    close: Callable[[AppPaths, Box], bool],
) -> None:
    try:
        old = load_box(paths.active / folder)
    except StoreError:
        # not a box of ours: it has no note window
        return
    if unsaved(old):
        raise ArchiveError(f"the note of {folder} has unsaved changes; save it and import again")
    close_window(console, paths, old, close=close)


def _opens(folder: Path) -> Box:
    # everything opening a box reads, read where the archive was unpacked: a box that cannot be
    # opened never takes the place of one that can
    try:
        box = load_box(folder)
        load_targets(box)
        load_creds(box)
        load_files(box)
    except StoreError as exc:
        reason = str(exc).replace(str(folder) + os.sep, "")
        raise ArchiveError(f"the box in the archive cannot be opened: {reason}") from exc
    return box


def _same_box_elsewhere(paths: AppPaths, box_id: str, folder: str) -> str | None:
    # the folder of another box here with this id. Tools are held by a box's id, so two boxes
    # with one id would each take the other's off the machine.
    if not paths.active.is_dir():
        return None
    for other in sorted(paths.active.iterdir()):
        if other.name == folder or other.name.startswith(".") or not other.is_dir():
            continue
        try:
            if load_box(other).id == box_id:
                return other.name
        except StoreError:
            continue
    return None


def import_box(
    paths: AppPaths,
    settings: Settings,
    console: Console,
    archive: Path,
    clock: Callable[[], datetime],
    *,
    unsaved: Callable[[Box], bool] = note_unsaved,
    close: Callable[[AppPaths, Box], bool] = shut_note,
) -> Box | None:
    if archive.is_dir():
        console.fail(f"{archive} is a folder, not an exported box")
        return None
    try:
        verify(archive)
        folder = peek_folder(archive)
        replace = False
        if os.path.lexists(paths.active / folder):
            replace = console.confirm(f"a box named {folder} is already here. replace it?")
            if not replace:
                return None
            _close_replaced(paths, console, folder, unsaved, close)
        def check(unpacked: Path) -> None:
            twin = _same_box_elsewhere(paths, _opens(unpacked).id, folder)
            if twin is not None:
                raise ArchiveError(f"this box is already here as {twin}, under another folder name")

        box = load_box(unpack(archive, paths.active, replace=replace, check=check))
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
