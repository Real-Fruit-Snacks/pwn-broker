"""Finding text in a box: one target's folder and its section of the note, or the whole box."""

import os
from dataclasses import dataclass
from pathlib import Path

from pwn_broker.note import FOLD_END, FOLD_START, NOTE_NAME

# a file larger than this is skipped, not read
MAX_FILE = 16 * 1024 * 1024
# a NUL in this much of the start makes a file binary
SNIFF = 8192
MAX_HITS = 200
MAX_LINE = 200
# never searched: the VPN files hold a key, and a recording's .cast has a text copy beside it
SKIPPED_FOLDERS = {"vpn"}
SKIPPED_SUFFIXES = {".cast"}


@dataclass
class Hit:
    path: str
    line: int
    text: str


@dataclass
class Result:
    hits: list[Hit]
    more: int
    files: int
    too_large: list[str]


def _shown(line: str) -> str:
    text = "".join(c if c.isprintable() or c == "\t" else "?" for c in line.strip()).replace("\t", " ")
    return text if len(text) <= MAX_LINE else text[: MAX_LINE - 3] + "..."


def _files(root: Path, base: Path) -> list[Path]:
    """Every regular file under root, in order: no links, no dot names, no skipped folder."""
    found: list[Path] = []
    try:
        entries = sorted(os.scandir(root), key=lambda e: e.name)
    except OSError:
        return found
    for entry in entries:
        if entry.name.startswith(".") or entry.is_symlink():
            continue
        if entry.is_dir(follow_symlinks=False):
            if root == base and entry.name in SKIPPED_FOLDERS:
                continue
            found += _files(Path(entry.path), base)
        elif entry.is_file(follow_symlinks=False) and Path(entry.name).suffix not in SKIPPED_SUFFIXES:
            found.append(Path(entry.path))
    return found


def _text(path: Path) -> str | None:
    """The file as text, or None when it is binary or cannot be read."""
    try:
        with open(path, "rb") as fh:
            data = fh.read(MAX_FILE + 1)
    except OSError:
        return None
    if b"\0" in data[:SNIFF]:
        return None
    return data.decode("utf-8", "replace")


def note_section(text: str, target: str) -> list[tuple[int, str]]:
    """The lines of one target's section of the note, with their line numbers: from its fold's
    start to the matching end, nested folds included. Empty when the target has none."""
    lines = text.splitlines()
    for n, line in enumerate(lines):
        if not line.startswith("Target: ") or n == 0 or lines[n - 1].strip() != FOLD_START:
            continue
        if line[len("Target: ") :].split("   ")[0].strip() != target:
            continue
        depth, section = 0, []
        for m in range(n - 1, len(lines)):
            stripped = lines[m].strip()
            if stripped == FOLD_START:
                depth += 1
            elif stripped == FOLD_END:
                depth -= 1
            section.append((m + 1, lines[m]))
            if depth == 0:
                break
        return section
    return []


def search(box_path: Path, text: str, target: str | None) -> Result:
    """Every line holding `text`, any case: in one target's folder and its note section, or, with
    no target, in the whole box."""
    wanted = text.casefold()
    hits: list[Hit] = []
    more = files = 0
    too_large: list[str] = []

    def look(rel: str, numbered) -> None:
        nonlocal more, files
        found = False
        for number, line in numbered:
            if wanted in line.casefold():
                found = True
                if len(hits) < MAX_HITS:
                    hits.append(Hit(rel, number, _shown(line)))
                else:
                    more += 1
        files += found

    if target is None:
        roots = [box_path]
    else:
        roots = [box_path / "targets" / target]
        note = box_path / NOTE_NAME
        body = _text(note) if note.is_file() and not note.is_symlink() else None
        if body is not None:
            look(NOTE_NAME, note_section(body, target))
    for root in roots:
        for path in _files(root, box_path):
            rel = path.relative_to(box_path).as_posix()
            try:
                if path.stat().st_size > MAX_FILE:
                    too_large.append(rel)
                    continue
            except OSError:
                continue
            body = _text(path)
            if body is not None:
                look(rel, enumerate(body.splitlines(), start=1))
    return Result(hits, more, files, too_large)
