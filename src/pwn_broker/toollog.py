"""The tool log: one line for each tool a box installed or took off, across every box."""

import os
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


def _one_line(value: str, path) -> str:
    # splitlines knows every line break, not only \n
    if len(f"{value}.".splitlines()) != 1:
        raise ValueError(f"{value!r} holds a line break and cannot go in {path}")
    return value


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
    path = paths.tool_log
    if event not in EVENTS:
        raise ValueError(f"{event!r} is not a tool log event")
    if kind not in KINDS:
        raise ValueError(f"{kind!r} is not a kind of package")
    if when.utcoffset() is None:
        raise ValueError("the time of a tool log line must have an offset")
    fields = [
        when.isoformat(timespec="seconds"),
        f"{event:<{_WIDTH}}",
        f"{_one_line(box.name, path)} ({_one_line(box.id, path)})",
        f"{_one_line(name, path)} {_one_line(build_id(version, build), path)}",
        f"sha256:{_one_line(sha256, path)}",
    ]
    if kind == "runtime":
        fields.append("runtime")
    line = ("  ".join(fields) + "\n").encode("utf-8")
    path.parent.mkdir(parents=True, exist_ok=True)
    # appended in one write, readable only by its owner; not store.write_text, which replaces
    fd = os.open(path, _FLAGS, 0o600)
    try:
        os.write(fd, line)
    finally:
        os.close(fd)
