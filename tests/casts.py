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


def recording_now(
    session, system, target: str, name: str = "2026-11-14_1432", *, pid: int = 5150, events=None, **header_args
) -> Path:
    """A cast in the session's box with a live marker for it, as a window that is still recording."""
    from pwn_broker import recstate

    folder = session.box.path / "targets" / target / "recordings"
    events = events if events is not None else [(0, "o", "hello\r\n")]
    cast = write_cast(folder / f"{name}.cast", events, **header_args)
    system.processes[pid] = ("777", "zsh")
    recstate.mark(session.paths, pid, "777", target, cast)
    return cast
