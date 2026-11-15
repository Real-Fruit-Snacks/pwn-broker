import importlib.resources
import os
from pathlib import Path

from pwn_broker.paths import AppPaths
from pwn_broker.store import write_text

PATH_MARK = "# pwn-broker"


def _packaged(name: str) -> str:
    return importlib.resources.files("pwn_broker.data").joinpath(name).read_text(encoding="utf-8")


def install_data(paths: AppPaths) -> None:
    for folder in (paths.run, paths.bin, paths.templates, paths.vim_dir):
        folder.mkdir(parents=True, exist_ok=True)
    template = paths.templates / "notes.md"
    if not template.exists():
        write_text(template, _packaged("notes.md"))
    for name in ("vimrc", "nightshift.vim"):
        write_text(paths.vim_dir / name, _packaged(name))


def write_launcher(paths: AppPaths, python: Path) -> Path:
    launcher = paths.bin / "pwn-broker"
    write_text(launcher, f'#!/bin/sh\nexec "{python.as_posix()}" -m pwn_broker "$@"\n')
    os.chmod(launcher, 0o755)
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
        return (paths.templates / "notes.md").read_text(encoding="utf-8")
    except OSError:
        return _packaged("notes.md")
