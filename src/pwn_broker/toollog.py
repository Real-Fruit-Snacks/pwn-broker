"""The tool log: one line for each tool a box installed or took off, across every box."""

import os
import unicodedata
from datetime import datetime

from pwn_broker.model import Box
from pwn_broker.paths import AppPaths
from pwn_broker.toolpkg import build_id

EVENTS = ("install", "remove", "finish")
KINDS = ("tool", "runtime")
# the event column is as wide as its longest word, so the columns after it line up
_WIDTH = max(len(e) for e in EVENTS)
# O_BINARY keeps a line ending as written on Windows; elsewhere it does not exist
_FLAGS = os.O_WRONLY | os.O_APPEND | os.O_CREAT | getattr(os, "O_BINARY", 0)


def _one_line(value: str) -> str:
    # for the values the app checks itself; splitlines knows every line break, not only \n
    if len(f"{value}.".splitlines()) != 1:
        raise ValueError(f"{value!r} holds a line break")
    return value


def _plain(text: str) -> str:
    # free text, which may come from someone else's archive: no control character reaches the
    # terminal that reads the log, and no run of spaces looks like the gap between two fields
    shown = "".join("?" if unicodedata.category(c) == "Cc" else c for c in text)
    return " ".join(shown.split())


def append(
    paths: AppPaths,
    *,
    when: datetime,
    event: str,
    box: Box,
    name: str,
    version: str,
    build: int,
    sha256: str,
    kind: str = "tool",
) -> None:
    """Adds one line to the log. It is only ever added to: never read back, replaced or trimmed."""
    if event not in EVENTS:
        raise ValueError(f"{event!r} is not a tool log event")
    if kind not in KINDS:
        raise ValueError(f"{kind!r} is not a kind of package")
    if when.utcoffset() is None:
        raise ValueError("the time of a tool log line must have an offset")
    fields = [
        when.isoformat(timespec="seconds"),
        f"{event:<{_WIDTH}}",
        f"{_plain(box.name)} ({_one_line(box.id)})",
        f"{_one_line(name)} {_one_line(build_id(version, build))}",
        f"sha256:{_one_line(sha256)}",
    ]
    if kind == "runtime":
        fields.append("runtime")
    line = ("  ".join(fields) + "\n").encode("utf-8")
    path = paths.tool_log
    path.parent.mkdir(parents=True, exist_ok=True)
    # appended in one write, readable only by its owner; not store.write_text, which replaces
    fd = os.open(path, _FLAGS, 0o600)
    try:
        if hasattr(os, "fchmod"):
            # the mode given to open only applies to a new file
            os.fchmod(fd, 0o600)
        os.write(fd, line)
    finally:
        os.close(fd)
