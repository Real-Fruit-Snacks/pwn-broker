import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass
from pathlib import Path

from pwn_broker.paths import AppPaths
from pwn_broker.store import SCHEMA, StoreError, read_toml, write_text, write_toml
from pwn_broker.toolpkg import ToolError

# boxes imports this module, so boxes is only imported inside the functions that need it


@dataclass
class Installed:
    name: str
    version: str
    build: int
    sha256: str
    folder: str
    commands: list[str]
    uploads: list[str]
    needs_root: bool
    users: list[str]
    home: dict[str, bool]


_STRINGS = ("name", "version", "sha256", "folder")
_LISTS = ("commands", "uploads", "users")


def _is_int(value: object) -> bool:
    return isinstance(value, int) and not isinstance(value, bool)


def _installed(row: object) -> Installed:
    if not isinstance(row, dict):
        raise TypeError("tool is not a table")
    for key in _STRINGS:
        if not isinstance(row[key], str):
            raise TypeError(f"{key} must be a string")
    if not _is_int(row["build"]):
        raise TypeError("build must be an integer")
    if not isinstance(row["needs_root"], bool):
        raise TypeError("needs_root must be true or false")
    for key in _LISTS:
        if not isinstance(row[key], list) or not all(isinstance(v, str) for v in row[key]):
            raise TypeError(f"{key} must be a list of strings")
    home = row["home"]
    if not isinstance(home, dict) or not all(isinstance(v, bool) for v in home.values()):
        raise TypeError("home must map paths to true or false")
    return Installed(
        name=row["name"],
        version=row["version"],
        build=row["build"],
        sha256=row["sha256"],
        folder=row["folder"],
        commands=list(row["commands"]),
        uploads=list(row["uploads"]),
        needs_root=row["needs_root"],
        users=list(row["users"]),
        home=dict(home),
    )


def load_installed(paths: AppPaths) -> dict[str, Installed]:
    path = paths.tools_state
    if not path.exists():
        return {}
    try:
        data = read_toml(path)
    except StoreError as exc:
        raise ToolError(str(exc)) from exc
    if data.get("schema") != SCHEMA:
        raise ToolError(f"{path}: unsupported schema {data.get('schema')!r}; upgrade pwn-broker")
    rows = data.get("tool", [])
    if not isinstance(rows, list):
        raise ToolError(f"{path}: invalid content (tool must be a list of tables)")
    result: dict[str, Installed] = {}
    for row in rows:
        try:
            tool = _installed(row)
        except (KeyError, TypeError) as exc:
            raise ToolError(f"{path}: invalid content ({type(exc).__name__}: {exc})") from exc
        if tool.name in result:
            raise ToolError(f"{path}: {tool.name} is listed twice")
        result[tool.name] = tool
    return result


def save_installed(paths: AppPaths, installed: dict[str, Installed]) -> None:
    rows = [
        {
            "name": t.name,
            "version": t.version,
            "build": t.build,
            "sha256": t.sha256,
            "folder": t.folder,
            "commands": list(t.commands),
            "uploads": list(t.uploads),
            "needs_root": t.needs_root,
            "users": list(t.users),
            "home": dict(t.home),
        }
        for t in installed.values()
    ]
    write_toml(paths.tools_state, {"schema": SCHEMA, "tool": rows})


def orphans(installed: dict[str, Installed], unfinished_ids: set[str]) -> list[Installed]:
    return [t for t in installed.values() if not unfinished_ids.intersection(t.users)]


def unfinished_boxes(paths: AppPaths) -> dict[str, str]:
    from pwn_broker import boxes

    found, _problems = boxes.list_boxes(paths)
    return {b.id: b.name for b in found if b.status == "active"}


def unreadable_boxes(paths: AppPaths) -> list[str]:
    from pwn_broker import boxes

    _found, problems = boxes.list_boxes(paths)
    return problems


def _resolve_alive(alive: Callable[[int], bool] | None) -> Callable[[int], bool]:
    if alive is not None:
        return alive
    from pwn_broker import boxes

    return boxes.pid_alive


def write_open_box(paths: AppPaths, folder: Path, pid: int) -> None:
    # a plain two-line file: launcher scripts read it with sed -n 1p and sed -n 2p
    text = folder.resolve().as_posix()
    if "\n" in text or "\r" in text:
        # a line break would push the pid off line 2; no file is better than a wrong one
        try:
            paths.run_box.unlink(missing_ok=True)
        except OSError:
            pass
        raise OSError(f"{text!r} holds a line break and cannot go in {paths.run_box}")
    write_text(paths.run_box, f"{text}\n{pid}\n")


def _read_open_box(paths: AppPaths) -> tuple[str, int] | None:
    try:
        text = paths.run_box.read_bytes().decode("utf-8")  # bytes: keep any CR visible
    except (OSError, UnicodeDecodeError):
        return None
    lines = text.split("\n")
    if len(lines) < 2 or not lines[0] or "\r" in lines[0]:
        return None
    if not (lines[1].isascii() and lines[1].isdecimal()):
        return None
    pid = int(lines[1])
    if pid < 1:
        return None
    return lines[0], pid


def clear_open_box(paths: AppPaths, pid: int) -> None:
    held = _read_open_box(paths)
    if held is None or held[1] != pid:
        return
    try:
        paths.run_box.unlink(missing_ok=True)
    except OSError:
        pass


def open_box(paths: AppPaths, *, alive: Callable[[int], bool] | None = None) -> Path | None:
    held = _read_open_box(paths)
    if held is None or not _resolve_alive(alive)(held[1]):
        return None
    return Path(held[0])


def mark_path(paths: AppPaths, tool: str, pid: int) -> Path:
    return paths.run_tools / f"{tool}.{pid}"


def running(
    paths: AppPaths,
    tools: Iterable[str] | None = None,
    *,
    alive: Callable[[int], bool] | None = None,
    started: Callable[[int], str | None] | None = None,
) -> list[tuple[str, int]]:
    check = _resolve_alive(alive)
    start_of = started if started is not None else process_start
    wanted = None if tools is None else set(tools)
    try:
        markers = sorted(paths.run_tools.iterdir())
    except OSError:
        return []
    found: list[tuple[str, int]] = []
    for marker in markers:
        tool, dot, tail = marker.name.rpartition(".")
        pid = int(tail) if dot and tool and tail.isascii() and tail.isdecimal() else 0
        if pid < 1:
            _discard(marker)
            continue
        if wanted is not None and tool not in wanted:
            continue
        if not check(pid):
            _discard(marker)
            continue
        recorded = _recorded_start(marker)
        now = start_of(pid) if recorded else None
        if recorded and now is not None and recorded != now:
            _discard(marker)  # the pid now belongs to another process
            continue
        found.append((tool, pid))
    return sorted(found)


def _discard(marker: Path) -> None:
    try:
        marker.unlink(missing_ok=True)
    except OSError:
        pass


def _recorded_start(marker: Path) -> str:
    try:
        return marker.read_text(encoding="utf-8").strip()
    except (OSError, UnicodeDecodeError):
        return ""


def parse_start_time(line: str) -> str | None:
    # the command name may hold spaces and parentheses, so count from the last ")"
    _head, close, rest = line.rpartition(")")
    fields = rest.split()
    if not close or len(fields) < 20:
        return None
    return fields[19]


def process_start(pid: int) -> str | None:
    if sys.platform == "win32":
        return None
    try:
        with open(f"/proc/{pid}/stat", encoding="utf-8", errors="replace") as fh:
            return parse_start_time(fh.read())
    except OSError:
        return None
