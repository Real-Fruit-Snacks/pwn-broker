import re
from string import Template

from pwn_broker.model import Box, Target
from pwn_broker.store import write_text

SECTION_MARK = "<!-- pwn-broker:section -->"
NOTE_NAME = "notes.md"
# vim folds on these two strings; each target's section sits between them
FOLD_START = "##########@@@@@@@@@@"
FOLD_END = "@@@@@@@@@@##########"
BOX_WIDTH = 64
_BORDER = 6
_LABEL = 13
_RULE_MIN = 20
_DAMAGED = (
    "the box at the top of the note is missing or damaged "
    "(it starts and ends with a line of # characters), so the note was left alone"
)


class NoteError(Exception):
    pass


def split_template(text: str) -> tuple[str, str]:
    lines = text.splitlines(keepends=True)
    for i, line in enumerate(lines):
        if line.rstrip("\r\n") == SECTION_MARK:
            return "".join(lines[:i]), "".join(lines[i + 1 :])
    return text, ""


def _lines(text: str) -> list[str]:
    # split on \n only, so every other character, \r included, stays inside its line
    return [line for line in re.split(r"(?<=\n)", text) if line]


def _fields(target: Target) -> list[str]:
    return [target.name, ", ".join(target.ips) or "-", ", ".join(target.hostnames) or "-", target.scope]


def title_text(target: Target) -> str:
    return "   ".join(_fields(target))


def _target_rows(targets: list[Target]) -> list[str]:
    rows = [_fields(t) for t in targets]
    widths = [max(len(row[col]) for row in rows) + 3 for col in range(3)] if rows else []
    return ["".join(cell.ljust(width) for cell, width in zip(row, widths)) + row[3] for row in rows]


def box_lines(box: Box, targets: list[Target]) -> list[str]:
    details = [
        ("Box:", box.name),
        ("Platform:", box.platform),
        ("Date:", box.started.date().isoformat()),
        ("OS:", box.os or "-"),
        ("Difficulty:", box.difficulty or "-"),
    ]
    rows = ["  " + row for row in _target_rows(targets)] or ["  none yet"]
    content = [label.ljust(_LABEL) + value for label, value in details] + ["", "Targets:", *rows]
    width = max(BOX_WIDTH, max(len(line) for line in content) + _BORDER)
    rule = "#" * width
    return [rule, *(f"#  {line.ljust(width - _BORDER)}  #" for line in content), rule]


def _box_values(box: Box) -> dict[str, str]:
    return {
        "name": box.name,
        "platform": box.platform,
        "date": box.started.date().isoformat(),
        "os": box.os or "",
        "difficulty": box.difficulty or "",
    }


def _section(section_template: str, target: Target, values: dict[str, str]) -> str:
    return Template(section_template).safe_substitute(values, target=target.name, title=title_text(target))


def render_note(template: str, box: Box, targets: list[Target]) -> str:
    header, section = split_template(template)
    values = {
        **_box_values(box),
        "box": "\n".join(box_lines(box, targets)),
        "targets": "\n".join(_target_rows(targets)),
    }
    text = Template(header).safe_substitute(values)
    for target in targets:
        text = _join(text, _section(section, target, values))
    return text.rstrip("\r\n") + "\n" if text else text


def _line_end(line: str) -> str:
    return "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""


def _is_rule(line: str) -> bool:
    bare = line.rstrip()
    return len(bare) >= _RULE_MIN and bare == "#" * len(bare)


def update_box(text: str, box: Box, targets: list[Target]) -> str:
    new = box_lines(box, targets)
    if not text:
        return "\n".join(new) + "\n"
    lines = _lines(text)
    if not _is_rule(lines[0]):
        raise NoteError(_DAMAGED)
    # the closing rule is as wide as the opening one, so a rule of my own below a box whose
    # closing line I deleted is not taken for it
    width = len(lines[0].rstrip())
    for end in range(1, len(lines)):
        line = lines[end]
        if _is_rule(line) and len(line.rstrip()) == width:
            break
        if not line.startswith("#") or FOLD_START in line:
            raise NoteError(_DAMAGED)
    else:
        raise NoteError(_DAMAGED)
    eol = _line_end(lines[0])
    last = eol if _line_end(lines[end]) else ""
    drawn = "".join(line + eol for line in new[:-1]) + new[-1] + last
    return drawn + "".join(lines[end + 1 :])


def _join(text: str, block: str) -> str:
    base = text.rstrip("\r\n")
    return f"{base}\n\n{block}" if base else block


def append_section(text: str, section_template: str, target: Target, box: Box | None = None) -> str:
    if not section_template:
        return text
    values = _box_values(box) if box is not None else {}
    section = _section(section_template, target, values).rstrip("\r\n") + "\n"
    return _join(text, section)


def retitle(text: str, old_title: str, new_title: str) -> str:
    lines = _lines(text)
    old = "Target: " + old_title
    for i in range(1, len(lines)):
        line = lines[i]
        if line.rstrip("\r\n") == old and lines[i - 1].rstrip() == FOLD_START:
            lines[i] = "Target: " + new_title + _line_end(line)
    return "".join(lines)


def read_note(box: Box) -> str:
    path = box.path / NOTE_NAME
    try:
        with open(path, encoding="utf-8", newline="") as fh:
            return fh.read()
    except UnicodeDecodeError as exc:
        raise NoteError(f"{path} is not valid UTF-8 text, so it was left as it is ({exc.reason})") from None


def write_note(box: Box, text: str) -> None:
    # the note holds what was found, passwords among it: its owner's alone
    write_text(box.path / NOTE_NAME, text, newline="", private=True)
