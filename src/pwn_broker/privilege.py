import os
import subprocess
import sys
from pathlib import Path


def is_root() -> bool:
    if sys.platform == "win32":
        return False
    return os.geteuid() == 0


def privileged_argv(argv: list[str], *, root: bool) -> list[str]:
    return list(argv) if root else ["sudo", *argv]


def run_privileged(argv: list[str]) -> subprocess.CompletedProcess:
    # No capture: sudo may need to ask for a password on the terminal.
    return subprocess.run(privileged_argv(argv, root=is_root()), check=False)


def wrong_owner(path: Path) -> str | None:
    if sys.platform == "win32":
        return None
    try:
        uid = os.stat(path).st_uid
    except FileNotFoundError:
        return None
    if uid == os.geteuid():
        return None
    import pwd

    try:
        return pwd.getpwuid(uid).pw_name
    except KeyError:
        return str(uid)


def foreign_files(folder: Path) -> int:
    if sys.platform == "win32":
        return 0
    me = os.geteuid()
    count = 0
    pending = [folder]
    while pending:
        current = pending.pop()
        try:
            info = os.lstat(current)
        except FileNotFoundError:
            if current == folder:
                return 0
            continue
        except OSError:
            count += 1
            continue
        if info.st_uid != me:
            count += 1
        if not (info.st_mode & 0o170000) == 0o040000:
            continue
        try:
            pending.extend(Path(entry.path) for entry in os.scandir(current))
        except OSError:
            # Contents cannot be checked, so they cannot be called mine.
            count += 1
    return count


def fix_ownership(folder: Path) -> int:
    count = foreign_files(folder)
    if count == 0:
        return 0
    result = run_privileged(["chown", "-R", f"{os.geteuid()}:{os.getegid()}", str(folder)])
    if result.returncode != 0:
        raise OSError(f"could not take ownership of {folder} (chown exit {result.returncode})")
    return count
