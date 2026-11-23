"""Playbooks: the ones installed for a box, what playbook show prints of one, and which of their
lines in the note are still template text."""

import re
from dataclasses import dataclass
from pathlib import Path

from pwn_broker.note import FOLD_END, FOLD_START
from pwn_broker.toolstate import Installed

# the same pattern the note's highlighting colours: a capital letter, then single spaces between
# words, as in <TargetIP> or <Target Host>
PLACEHOLDER = re.compile(r"<[A-Z][0-9A-Za-z_-]*(?: [0-9A-Za-z_-]+)*>")
PLAYBOOK_PREFIX = "Playbook: "
# the first and last lines of a playbook's run block
RUN_BLOCK_START = "my"
RUN_BLOCK_END = "'y"
# a built playbook's last line inside its fold
END_LINE = re.compile(r"END OF \S+ PLAYBOOK")
# the Playbook: line holds its title, its path and its release, three spaces apart
FIELD_GAP = "   "


@dataclass(frozen=True)
class Playbook:
    # the file name without .md, which :Pb and playbook show take
    name: str
    # its path under the package's folder of notes, without .md, such as 02-enum/smb
    rel: str
    package: str
    version: str
    file: Path


def installed(packages: list[Installed]) -> list[Playbook]:
    """Every playbook in the notes packages, sorted by its path as :Pb lists them."""
    found = []
    for package in packages:
        root = Path(package.notes)
        for file in root.rglob("*.md"):
            if file.is_file():
                rel = file.relative_to(root).with_suffix("").as_posix()
                found.append(Playbook(file.stem, rel, package.name, package.version, file))
    return sorted(found, key=lambda p: (p.rel, p.package))


def find(playbooks: list[Playbook], wanted: str) -> list[Playbook]:
    """The playbooks `wanted` names: by file name as :Pb takes it, by path, or by package and path."""
    return [p for p in playbooks if wanted in (p.name, p.rel, f"{p.package}/{p.rel}")]


def read_lines(file: Path) -> list[str]:
    # a package's text, so a byte that is not UTF-8 is shown, not refused
    return file.read_text(encoding="utf-8", errors="replace").splitlines()


def heading(lines: list[str]) -> str | None:
    """The Playbook: line, when the file starts as pwn-playbooks builds one."""
    if len(lines) > 1 and lines[0].strip() == FOLD_START and lines[1].startswith(PLAYBOOK_PREFIX):
        return lines[1]
    return None


def title(lines: list[str]) -> str:
    """The playbook's title from its Playbook: line, or nothing for a file not built that way."""
    line = heading(lines)
    if line is None:
        return ""
    fields = line[len(PLAYBOOK_PREFIX) :].rsplit(FIELD_GAP, 2)
    return fields[0].strip() if len(fields) == 3 else line[len(PLAYBOOK_PREFIX) :].strip()


def shown(lines: list[str]) -> tuple[str | None, list[str]]:
    """What playbook show prints: the Playbook: line, then the playbook without its fold markers,
    run block and END OF line. A file not built that way has no Playbook: line and is shown whole."""
    line = heading(lines)
    if line is None:
        body = list(lines)
    else:
        end = _end(lines, 0)
        body = lines[2:end] if lines[end].strip() == FOLD_END else lines[2:]
        if body and body[0] == RUN_BLOCK_START and RUN_BLOCK_END in body:
            body = body[body.index(RUN_BLOCK_END) + 1 :]
        filled = [n for n, text in enumerate(body) if text.strip()]
        if filled and END_LINE.fullmatch(body[filled[-1]]):
            body = body[: filled[-1]]
    while body and not body[0].strip():
        body.pop(0)
    while body and not body[-1].strip():
        body.pop()
    return line, body


def _end(lines: list[str], start: int) -> int:
    """The index of the fold end matching the fold start at `start`, or the last line."""
    depth = 0
    for n in range(start, len(lines)):
        stripped = lines[n].strip()
        if stripped == FOLD_START:
            depth += 1
        elif stripped == FOLD_END:
            depth -= 1
            if depth == 0:
                return n
    return len(lines) - 1


def template_lines(lines: list[str]) -> set[int]:
    """The 1-based numbers of the note's lines that are still a playbook's template text: each
    playbook's run block, and any other line of a playbook that still holds a placeholder."""
    found: set[int] = set()
    n = 0
    while n < len(lines) - 1:
        if lines[n].strip() != FOLD_START or not lines[n + 1].startswith(PLAYBOOK_PREFIX):
            n += 1
            continue
        end = _end(lines, n)
        # a run block is there only while its first line follows the Playbook: line and its last
        # line is still in the playbook; once deleted, only the placeholder rule applies
        m = n + 1
        if n + 2 < end and lines[n + 2] == RUN_BLOCK_START and RUN_BLOCK_END in lines[n + 2 : end]:
            m = lines.index(RUN_BLOCK_END, n + 2)
            found.update(range(n + 3, m + 2))
        for k in range(m + 1, end):
            if lines[k].strip() not in (FOLD_START, FOLD_END) and PLACEHOLDER.search(lines[k]):
                found.add(k + 1)
        n = end + 1
    return found
