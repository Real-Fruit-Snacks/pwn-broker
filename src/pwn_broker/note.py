import re
from string import Template

from pwn_broker.model import Box, Target
from pwn_broker.store import write_text

TABLE_BEGIN = "<!-- pwn-broker:targets -->"
TABLE_END = "<!-- /pwn-broker:targets -->"
SECTION_MARK = "<!-- pwn-broker:section -->"
NOTE_NAME = "notes.md"


class NoteError(Exception):
    pass


def split_template(text: str) -> tuple[str, str]:
    lines = text.splitlines(keepends=True)
    for i, line in enumerate(lines):
        if line.rstrip("\r\n") == SECTION_MARK:
            return "".join(lines[:i]), "".join(lines[i + 1 :])
    return text, ""


def table_lines(targets: list[Target]) -> list[str]:
    rows = [
        [t.name, ", ".join(t.ips) or "-", ", ".join(t.hostnames) or "-", t.scope]
        for t in targets
    ]
    widths = [max(len(row[col]) for row in rows) + 3 for col in range(3)] if rows else []
    return [
        "".join(cell.ljust(width) for cell, width in zip(row, widths)) + row[3]
        for row in rows
    ]


def _box_values(box: Box) -> dict[str, str]:
    return {
        "name": box.name,
        "platform": box.platform,
        "date": box.started.date().isoformat(),
        "os": box.os or "",
        "difficulty": box.difficulty or "",
    }


def render_note(template: str, box: Box, targets: list[Target]) -> str:
    header, section = split_template(template)
    values = {**_box_values(box), "targets": "\n".join(table_lines(targets))}
    parts = [Template(header).safe_substitute(values)]
    for target in targets:
        parts.append("\n" + Template(section).safe_substitute(values, target=target.name))
    return "".join(parts)


def _line_end(line: str) -> str:
    return "\r\n" if line.endswith("\r\n") else "\n" if line.endswith("\n") else ""


def _append(text: str, block: str) -> str:
    if text and not text.endswith("\n"):
        text += "\n"
    if text:
        text += "\n"
    return text + block


def update_table(text: str, targets: list[Target]) -> str:
    lines = text.splitlines(keepends=True)
    begins = [i for i, line in enumerate(lines) if line.rstrip() == TABLE_BEGIN]
    ends = [i for i, line in enumerate(lines) if line.rstrip() == TABLE_END]
    rows = table_lines(targets)
    if not begins and not ends:
        block = "".join(f"{line}\n" for line in ["## targets", TABLE_BEGIN, *rows, TABLE_END])
        return _append(text, block)
    if len(begins) != 1 or len(ends) != 1 or ends[0] < begins[0]:
        raise NoteError(
            f"the targets table needs exactly one {TABLE_BEGIN} line followed by one {TABLE_END} line; "
            "restore them in the note"
        )
    begin, end = begins[0], ends[0]
    eol = _line_end(lines[begin]) or "\n"
    new = [row + eol for row in rows]
    return "".join(lines[: begin + 1] + new + lines[end:])


def append_section(text: str, section_template: str, target: Target, box: Box | None = None) -> str:
    if not section_template:
        return text
    values = _box_values(box) if box is not None else {}
    section = Template(section_template).safe_substitute(values, target=target.name)
    section = section.rstrip("\r\n") + "\n"
    base = text.rstrip("\r\n")
    return f"{base}\n\n{section}" if base else section


def rename_heading(text: str, old: str, new: str) -> str:
    pattern = re.compile(r"^## " + re.escape(old) + r"(?=\r?$)", re.MULTILINE)
    return pattern.sub(lambda _: "## " + new, text)


def read_note(box: Box) -> str:
    path = box.path / NOTE_NAME
    try:
        with open(path, encoding="utf-8", newline="") as fh:
            return fh.read()
    except UnicodeDecodeError as exc:
        raise NoteError(f"{path} is not valid UTF-8 text, so it was left as it is ({exc.reason})") from None


def write_note(box: Box, text: str) -> None:
    write_text(box.path / NOTE_NAME, text, newline="")
