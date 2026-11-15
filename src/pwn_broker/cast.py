"""Reading asciicast v3, the format the pinned asciinema writes."""

import json
import math
import os
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path

MAX_SIZE = 1000
_BLOCK = 64 * 1024


class CastError(Exception):
    pass


@dataclass(frozen=True)
class Header:
    cols: int
    rows: int
    timestamp: int | None
    title: str


def _whole_number(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def read_header(path: Path) -> Header:
    try:
        with path.open("rb") as fh:
            first = fh.readline()
    except OSError as exc:
        raise CastError(f"cannot read {path}: {exc.strerror or exc}") from exc
    if not first.strip():
        raise CastError(f"{path}: empty file")
    try:
        data = json.loads(first)
    except (ValueError, RecursionError) as exc:
        raise CastError(f"{path}: the first line is not JSON") from exc
    if not isinstance(data, dict):
        raise CastError(f"{path}: the first line is not a JSON object")
    if data.get("version") != 3:
        raise CastError(f"{path}: version {data.get('version')!r} is not asciicast version 3")
    term = data.get("term")
    if not isinstance(term, dict):
        raise CastError(f"{path}: the header has no term")
    for key in ("cols", "rows"):
        value = term.get(key)
        if not _whole_number(value) or not 1 <= value <= MAX_SIZE:
            raise CastError(f"{path}: term {key} {value!r} is not between 1 and {MAX_SIZE}")
    timestamp = data.get("timestamp")
    if timestamp is not None and not _whole_number(timestamp):
        raise CastError(f"{path}: timestamp {timestamp!r} is not a whole number")
    title = data.get("title", "")
    if not isinstance(title, str):
        raise CastError(f"{path}: the title is not text")
    return Header(cols=term["cols"], rows=term["rows"], timestamp=timestamp, title=title)


def _event(line: bytes) -> tuple[float, str, str]:
    try:
        value = json.loads(line)  # ValueError, UnicodeDecodeError included
    except RecursionError:
        raise ValueError("nested too deeply") from None
    if not isinstance(value, list) or len(value) != 3:
        raise ValueError("not an [interval, code, data] array")
    interval, code, data = value
    if isinstance(interval, bool) or not isinstance(interval, (int, float)):
        raise ValueError("the interval is not a number")
    if not math.isfinite(interval) or interval < 0:
        raise ValueError("the interval is not a time")
    if not isinstance(code, str) or not isinstance(data, str):
        raise ValueError("the code or the data is not text")
    try:
        data.encode("utf-8")
    except UnicodeEncodeError:
        raise ValueError("the data holds a lone surrogate") from None
    return interval, code, data


def events(path: Path) -> Iterator[tuple[float, str, str]]:
    """(seconds since the start, code, data) for each event, read line by line."""
    try:
        with path.open("rb") as fh:
            fh.readline()  # the header
            elapsed = 0.0
            bad: tuple[int, str] | None = None
            for number, raw in enumerate(fh, start=2):
                if bad is not None:
                    raise CastError(f"{path}: line {bad[0]} is not a valid event ({bad[1]})")
                if not raw.endswith(b"\n"):
                    return  # cut off where the writing stopped
                if not raw.strip() or raw.startswith(b"#"):
                    continue
                try:
                    interval, code, data = _event(raw)
                except ValueError as exc:
                    bad = (number, str(exc))  # quiet if nothing follows it
                    continue
                elapsed += interval
                yield elapsed, code, data
    except OSError as exc:
        raise CastError(f"cannot read {path}: {exc.strerror or exc}") from exc


def whole_size(path: Path) -> int:
    """The size of the file up to and including its last line break."""
    with path.open("rb") as fh:
        end = fh.seek(0, os.SEEK_END)
        while end > 0:
            start = max(0, end - _BLOCK)
            fh.seek(start)
            found = fh.read(end - start).rfind(b"\n")
            if found >= 0:
                return start + found + 1
            end = start
    return 0
