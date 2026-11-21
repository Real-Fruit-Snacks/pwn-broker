import sys
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from pathlib import Path

from pwn_broker.model import Box, current_tools
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
    # whether each home entry existed in root's home before install; only recorded when that
    # is a different folder from the user's and could be read
    root_home: dict[str, bool] = field(default_factory=dict)
    # "tool" or "runtime"; a runtime has no commands, uploads, users or home entries
    kind: str = "tool"
    # the runtimes a tool requires, by name
    requires: list[str] = field(default_factory=list)
    # a runtime's interpreter, as an absolute path
    python: str = ""
    # for a tool that requires a runtime: the build its environment was made by, which is the
    # only build that serves it (the environment points into that build's folder)
    runtime_version: str = ""
    runtime_build: int = 0
    # for a notes package: its folder of notes, as an absolute path
    notes: str = ""


KINDS = ("tool", "runtime")
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
    root_home = row.get("root_home", {})
    if not isinstance(root_home, dict) or not all(isinstance(v, bool) for v in root_home.values()):
        raise TypeError("root_home must map paths to true or false")
    kind = row.get("kind", "tool")
    if kind not in KINDS:
        raise TypeError(f"kind must be one of {', '.join(KINDS)}")
    requires = row.get("requires", [])
    if not isinstance(requires, list) or not all(isinstance(v, str) for v in requires):
        raise TypeError("requires must be a list of strings")
    python = row.get("python", "")
    if not isinstance(python, str):
        raise TypeError("python must be a string")
    runtime_version = row.get("runtime_version", "")
    if not isinstance(runtime_version, str):
        raise TypeError("runtime_version must be a string")
    runtime_build = row.get("runtime_build", 0)
    if not _is_int(runtime_build):
        raise TypeError("runtime_build must be an integer")
    notes = row.get("notes", "")
    if not isinstance(notes, str):
        raise TypeError("notes must be a string")
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
        root_home=dict(root_home),
        kind=kind,
        requires=list(requires),
        python=python,
        runtime_version=runtime_version,
        runtime_build=runtime_build,
        notes=notes,
    )


def load_installed(paths: AppPaths) -> dict[str, Installed]:
    path = paths.tools_state
    if not path.exists():
        return {}
    try:
        data = read_toml(path)
    except StoreError as exc:
        raise ToolError(str(exc)) from exc
    if "schema" not in data:
        # an empty or cut-short file, not one from a newer version
        raise ToolError(f"{path} cannot be read")
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


def _row(t: Installed) -> dict:
    row = {
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
        "root_home": dict(t.root_home),
    }
    # only what a runtime brings is added, so a list without runtimes is written as before
    if t.kind != "tool":
        row["kind"] = t.kind
    if t.requires:
        row["requires"] = list(t.requires)
    if t.python:
        row["python"] = t.python
    if t.runtime_version:
        row["runtime_version"] = t.runtime_version
        row["runtime_build"] = t.runtime_build
    if t.notes:
        row["notes"] = t.notes
    return row


def save_installed(paths: AppPaths, installed: dict[str, Installed]) -> None:
    rows = [_row(t) for t in installed.values()]
    write_toml(paths.tools_state, {"schema": SCHEMA, "tool": rows})


def present(paths: AppPaths, box: Box) -> set[str]:
    """The box's tools this machine has for it: listed, used by the box, and its folder there."""
    installed = load_installed(paths)
    found = set()
    for record in current_tools(box):
        item = installed.get(record.name)
        if item is None or box.id not in item.users or not item.folder:
            continue
        if Path(item.folder).is_dir():
            found.add(record.name)
    return found


def present_count(paths: AppPaths, box: Box) -> int:
    # for the status bar and status: an unreadable list confirms nothing, so nothing is counted
    try:
        return len(present(paths, box))
    except (ToolError, OSError):
        return 0


def orphans(installed: dict[str, Installed], unfinished_ids: set[str]) -> list[Installed]:
    # a runtime has no users; whether it is needed is the tools' question (idle_runtimes)
    return [
        t
        for t in installed.values()
        if t.kind != "runtime" and not unfinished_ids.intersection(t.users)
    ]


def needed_runtimes(installed: dict[str, Installed]) -> set[str]:
    """The runtimes any installed tool requires."""
    return {r for t in installed.values() if t.kind != "runtime" for r in t.requires}


def tools_requiring(installed: dict[str, Installed], name: str) -> list[str]:
    """The installed tools that require the runtime of that name, sorted."""
    return sorted(t.name for t in installed.values() if t.kind != "runtime" and name in t.requires)


def idle_runtimes(installed: dict[str, Installed]) -> list[Installed]:
    """The installed runtimes no installed tool requires."""
    needed = needed_runtimes(installed)
    return [t for t in installed.values() if t.kind == "runtime" and t.name not in needed]


def unfinished_boxes(paths: AppPaths) -> dict[str, str]:
    from pwn_broker import boxes

    found, _problems = boxes.list_boxes(paths)
    return {b.id: b.name for b in found if b.status == "active"}


def unreadable_boxes(paths: AppPaths) -> list[str]:
    from pwn_broker import boxes

    _found, problems = boxes.list_boxes(paths)
    return problems


def holding_boxes(
    paths: AppPaths, installed: dict[str, Installed], *, excluding: str | None = None
) -> dict[str, str]:
    """The boxes that count as still using tools, id to name.

    The box being released is left out. While any box cannot be read, every user of a tool
    that is not a box the listing could load is kept, so nothing is removed on a guess.
    """
    from pwn_broker import boxes

    found, problems = boxes.list_boxes(paths)
    holding = {b.id: b.name for b in found if b.status == "active"}
    if excluding is not None:
        holding.pop(excluding, None)
    if problems:
        known = {b.id for b in found}
        for item in installed.values():
            for user in item.users:
                if user != excluding and user not in known:
                    holding[user] = "a box that cannot be read"
    return holding


def write_notes_file(paths: AppPaths, box: Box) -> None:
    """Lists, one per line, the notes folders installed for the box, for the note window's :Pb.

    Never raises: a box must still open, and with no file the note window says it has none.
    """
    try:
        installed = load_installed(paths)
    except (ToolError, OSError):
        installed = {}
    roots = sorted(
        t.notes
        for t in installed.values()
        if t.notes and box.id in t.users and "\n" not in t.notes and "\r" not in t.notes
        and Path(t.notes).is_dir()
    )
    try:
        write_text(paths.run_notes, "".join(f"{r}\n" for r in roots))
    except OSError:
        pass


def clear_notes_file(paths: AppPaths) -> None:
    try:
        paths.run_notes.unlink(missing_ok=True)
    except OSError:
        pass


def _resolve_alive(alive: Callable[[int], bool] | None) -> Callable[[int], bool]:
    if alive is not None:
        return alive
    from pwn_broker import boxes

    return boxes.pid_alive


def write_open_box(paths: AppPaths, folder: Path, pid: int, start: str | None = None) -> None:
    # a plain file of lines, read by launcher scripts with sed -n 1p, 2p and 3p: the folder, the
    # prompt's pid, and that process's start time when it is known
    text = folder.resolve().as_posix()
    if "\n" in text or "\r" in text:
        # a line break would push the pid off line 2; no file is better than a wrong one
        try:
            paths.run_box.unlink(missing_ok=True)
        except OSError:
            pass
        raise OSError(f"{text!r} holds a line break and cannot go in {paths.run_box}")
    third = f"{start}\n" if start and start.isascii() and start.isdecimal() else ""
    write_text(paths.run_box, f"{text}\n{pid}\n{third}")


def _read_open_box(paths: AppPaths) -> tuple[str, int, str] | None:
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
    start = lines[2] if len(lines) > 2 and lines[2].isascii() and lines[2].isdecimal() else ""
    return lines[0], pid, start


def clear_open_box(paths: AppPaths, pid: int) -> None:
    held = _read_open_box(paths)
    if held is None or held[1] != pid:
        return
    try:
        paths.run_box.unlink(missing_ok=True)
    except OSError:
        pass


def open_box(
    paths: AppPaths,
    *,
    alive: Callable[[int], bool] | None = None,
    started: Callable[[int], str | None] | None = None,
) -> Path | None:
    held = _read_open_box(paths)
    if held is None or not _resolve_alive(alive)(held[1]):
        return None
    if held[2]:
        now = (started if started is not None else process_start)(held[1])
        if now is not None and now != held[2]:
            return None  # the pid now belongs to another process
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
