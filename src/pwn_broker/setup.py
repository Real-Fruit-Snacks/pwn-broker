import hashlib
import importlib.resources
import os
from pathlib import Path

from pwn_broker.paths import AppPaths
from pwn_broker.store import write_text

PATH_MARK = "# pwn-broker"


TEMPLATE_NAME = "notes.md"
# sha256 of default templates shipped before; an installed template still equal to one of them was
# never edited, so it is replaced by the current default
OLD_DEFAULT_TEMPLATES = frozenset({"bb34a399fb0f7d5d8ba8c10febcd74b4d6eec51189366d5008f4bb1da587dcad"})


def _packaged(name: str) -> str:
    return importlib.resources.files("pwn_broker.data").joinpath(name).read_text(encoding="utf-8")


def _vim_files() -> dict[str, str]:
    """Every file for vim in the package data, by path relative to the data folder."""
    found: dict[str, str] = {}

    def walk(folder, prefix: str) -> None:
        for entry in folder.iterdir():
            if entry.is_dir():
                if entry.name != "__pycache__":
                    walk(entry, f"{prefix}{entry.name}/")
            elif entry.name not in ("__init__.py", TEMPLATE_NAME) and not entry.name.endswith(".pyc"):
                found[prefix + entry.name] = entry.read_text(encoding="utf-8")

    walk(importlib.resources.files("pwn_broker.data"), "")
    return found


def _template_is_old_default(template: Path) -> bool:
    try:
        return hashlib.sha256(template.read_bytes()).hexdigest() in OLD_DEFAULT_TEMPLATES
    except OSError:
        return False


def install_data(paths: AppPaths) -> None:
    folders = (
        paths.run, paths.bin, paths.templates, paths.vim_dir,
        paths.tools, paths.upload, paths.cache, paths.run_tools,
        paths.run_recordings, paths.run_vpn, paths.run_shell, paths.run_asciinema,
        paths.active, paths.wrapped,
    )  # fmt: skip
    for folder in folders:
        folder.mkdir(parents=True, exist_ok=True)
    template = paths.templates / TEMPLATE_NAME
    if not template.exists() or _template_is_old_default(template):
        write_text(template, _packaged(TEMPLATE_NAME))
    for name, text in _vim_files().items():
        target = paths.vim_dir / name
        target.parent.mkdir(parents=True, exist_ok=True)
        write_text(target, text)


def write_launcher(paths: AppPaths, python: Path) -> Path:
    # -I: with -m, python puts the current folder first on its path, and the app is started from
    # box folders that hold files taken from targets
    launcher = paths.bin / "pwn-broker"
    write_text(launcher, f'#!/bin/sh\nexec "{python.as_posix()}" -I -m pwn_broker "$@"\n')
    os.chmod(launcher, 0o755)
    record = paths.record_launcher
    write_text(record, f'#!/bin/sh\nexec "{python.as_posix()}" -I -m pwn_broker.record "$@"\n')
    os.chmod(record, 0o755)
    return launcher


def path_line(opt_bin: Path) -> str:
    return f'export PATH="{opt_bin.as_posix()}:$PATH"  {PATH_MARK}'


def ensure_path_line(rc: Path, opt_bin: Path) -> bool:
    line = path_line(opt_bin)
    # a dotfiles symlink stays a link: the file it points at is the one that changes
    rc = rc.resolve()
    try:
        # surrogateescape carries bytes that are not UTF-8 through unchanged
        with open(rc, encoding="utf-8", errors="surrogateescape", newline="") as fh:
            existing = fh.read()
    except FileNotFoundError:
        write_text(rc, line + "\n", newline="")
        return True
    if any(PATH_MARK in row for row in existing.splitlines()):
        return False
    lead = "" if not existing or existing.endswith("\n") else "\n"
    write_text(rc, existing + lead + line + "\n", newline="", errors="surrogateescape")
    return True


def load_template(paths: AppPaths) -> str:
    try:
        return (paths.templates / TEMPLATE_NAME).read_text(encoding="utf-8")
    except OSError:
        return _packaged(TEMPLATE_NAME)
