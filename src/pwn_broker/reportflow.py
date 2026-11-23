"""The report at finish. When the box has the report tool, finish runs pwn-report on the finished
archive, after the archive is written and copied and before the tools come off, and the report
folder goes beside the archive. pwn-broker never imports pwn-report: it runs the installed command,
with no shell, the environment other tool runs get, and a time limit. A report is extra: whatever
happens to it is a warn line, and finish goes on."""

from __future__ import annotations

import os
import shutil
import subprocess
from pathlib import Path

from pwn_broker.console import shown
from pwn_broker.model import current_tools
from pwn_broker.session import Session
from pwn_broker.toolinstall import _clean_environment

PACKAGE = "report"
COMMAND = "pwn-report"
# seconds pwn-report has to build the report, then seconds after SIGTERM before it is killed
TIMEOUT = 600
KILL_AFTER = 5

_SUFFIX = ".tar.gz"


def report_folder(archive: Path) -> Path:
    """<archive minus .tar.gz>.report beside it, or the first free .report-2, .report-3, ...: an
    existing report, from a box finished before it was reopened, is never replaced."""
    name = archive.name
    stem = name[: -len(_SUFFIX)] if name.endswith(_SUFFIX) else name
    folder = archive.with_name(f"{stem}.report")
    number = 2
    while os.path.lexists(folder):
        folder = archive.with_name(f"{stem}.report-{number}")
        number += 1
    return folder


def _command(session: Session) -> Path:
    return session.paths.bin / COMMAND


def _launcher(session: Session) -> list[str]:
    return [str(_command(session))]


def wanted(session: Session) -> bool:
    """The box has the report tool now, and its command is installed."""
    return any(tool.name == PACKAGE for tool in current_tools(session.box)) and _command(session).is_file()


def summary_rows(session: Session) -> list[tuple[str, str]]:
    """finish's summary says, before the archive is made, whether a report will be built."""
    if wanted(session):
        return [("report", "will be built beside the archive")]
    return [("report", f"none: tool install {PACKAGE} adds the tool that builds one")]


def build(session: Session, archive: Path) -> Path | None:
    """Builds the report beside the archive and copies it to copy_to when that is set. Returns the
    report folder, or None when no report was built; never raises for what pwn-report does."""
    console = session.console
    folder = report_folder(archive)
    console.fields([("report", "building beside the archive")])
    problem = _run(session, archive, folder)
    if problem is not None:
        _remove_staging(folder)
        console.warn(f"the report was not built: {problem}")
        return None
    console.ok(f"report {folder}")
    _copy(session, folder)
    return folder


def _run(session: Session, archive: Path, folder: Path) -> str | None:
    """Runs pwn-report; None when it built the report, else why not, in one line."""
    argv = [*_launcher(session), "build", str(archive), "-o", str(folder)]
    try:
        process = subprocess.Popen(
            argv,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            errors="replace",
            cwd=str(archive.parent),
            env=_clean_environment(),
        )
    except OSError as exc:
        return f"{COMMAND} could not run: {exc}"
    try:
        _, err = _wait(process, TIMEOUT)
    except subprocess.TimeoutExpired:
        _end(process)
        return f"it took longer than {TIMEOUT} seconds"
    except KeyboardInterrupt:
        # Ctrl-C stops the report, not the finish
        _end(process)
        return "interrupted"
    if process.returncode != 0:
        return _fail_line(err) or f"{COMMAND} exited with status {process.returncode}"
    if not folder.is_dir():
        return f"{COMMAND} wrote no {folder}"
    return None


def _wait(process: subprocess.Popen, timeout: float) -> tuple[str, str]:
    return process.communicate(timeout=timeout)


def _end(process: subprocess.Popen) -> None:
    """SIGTERM, which pwn-report answers by removing its staging folder, then SIGKILL."""
    try:
        process.terminate()
        process.communicate(timeout=KILL_AFTER)
    except (subprocess.TimeoutExpired, KeyboardInterrupt):
        process.kill()
        process.communicate()


def _fail_line(err: str) -> str | None:
    """pwn-report's own reason: its last line on stderr, without the fail word."""
    lines = [line.strip() for line in err.splitlines() if line.strip()]
    if not lines:
        return None
    line = lines[-1]
    if line.startswith("fail "):
        line = line[len("fail") :].strip()
    return shown(line)


def _remove_staging(folder: Path) -> None:
    """A run ended before it could clean up leaves its .<report>.tmp-* folder beside the archive."""
    prefix = f".{folder.name}.tmp-"
    try:
        entries = list(folder.parent.iterdir())
    except OSError:
        return
    for entry in entries:
        if entry.name.startswith(prefix) and entry.is_dir() and not entry.is_symlink():
            shutil.rmtree(entry, ignore_errors=True)


def _copy(session: Session, folder: Path) -> None:
    """A copy of the report folder in copy_to, as the archive has; a failed copy is a warning."""
    copy_to = session.settings.copy_to
    if not copy_to:
        return
    final = copy_to / folder.name
    part = copy_to / f"{folder.name}.part"
    try:
        if os.path.lexists(final):
            raise OSError(f"{final.name} is there already")
        shutil.copytree(folder, part)
        os.replace(part, final)
    except OSError as exc:
        shutil.rmtree(part, ignore_errors=True)
        session.console.warn(f"the report was not copied to {copy_to}: {exc}")
        return
    session.console.ok(f"copy {final}")
