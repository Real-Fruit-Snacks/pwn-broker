import json
from datetime import datetime, timedelta, timezone
from pathlib import Path

# The VM's local time in these tests: a fixed offset, so nothing depends on the machine.
TZ = timezone(timedelta(hours=2))
# 2026-11-14 14:32:07 in TZ
START = int(datetime(2026, 11, 14, 14, 32, 7, tzinfo=TZ).timestamp())


def header(*, cols=80, rows=24, timestamp: int | None = START, title="forest dc01 id") -> dict:
    value: dict = {"version": 3, "term": {"cols": cols, "rows": rows, "type": "xterm-256color"}}
    if timestamp is not None:
        value["timestamp"] = timestamp
    value["title"] = title
    return value


def cast_text(events, *, first: dict | None = None, **header_args) -> str:
    """A .cast file: the header, then one line per (interval, code, data) event."""
    lines = [json.dumps(first if first is not None else header(**header_args))]
    lines += [json.dumps([interval, code, data]) for interval, code, data in events]
    return "\n".join(lines) + "\n"


def write_cast(path: Path, events, **kwargs) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(cast_text(events, **kwargs).encode("utf-8"))
    return path
