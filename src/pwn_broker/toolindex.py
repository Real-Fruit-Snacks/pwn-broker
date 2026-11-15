import difflib
import os
import re
import shutil
import tomllib
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from pwn_broker import config
from pwn_broker.checks import _fetch
from pwn_broker.config import Settings
from pwn_broker.paths import AppPaths
from pwn_broker.store import write_text
from pwn_broker.toolpkg import KINDS, ToolError, build_id, verify_zip

INDEX_FILE = "index.toml"
STAMP_FILE = "index.fetched"
MAX_AGE = timedelta(days=1)
QUICK_TIMEOUT = 2
FORCED_TIMEOUT = 30
ZIP_TIMEOUT = 300

_NAME = re.compile(r"[a-z0-9][a-z0-9-]*")
_SHA256 = re.compile(r"[0-9a-fA-F]{64}")


@dataclass
class BuildEntry:
    name: str
    version: str
    build: int
    kind: str
    needs_root: bool
    commands: list[str]
    file: str
    url: str
    size: int
    sha256: str


@dataclass
class ToolEntry:
    name: str
    description: str
    tags: list[str]
    licence: str
    upstream: str
    latest: str
    builds: list[BuildEntry]


@dataclass
class Index:
    tools: list[ToolEntry]


# ---- parsing


def _text(table: dict, key: str, label: str) -> str:
    value = table.get(key)
    if not isinstance(value, str) or not value:
        raise ToolError(f"{label}: must be a non-empty string")
    return value


def _optional_text(table: dict, key: str, label: str) -> str:
    value = table.get(key, "")
    if not isinstance(value, str):
        raise ToolError(f"{label}: must be a string")
    return value


def _strings(table: dict, key: str, label: str) -> list[str]:
    value = table.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ToolError(f"{label}: must be a list of strings")
    return list(value)


def _plain_zip_name(name: object, label: str) -> str:
    if (
        not isinstance(name, str)
        or not name.endswith(".zip")
        or name in (".zip",)
        or any(c in name for c in ("/", "\\", "\0", ":"))
        or name.startswith(".")
    ):
        raise ToolError(f"{label}: {name!r} must be a plain file name ending .zip")
    return name


def _build(tool: str, row: object, label: str) -> BuildEntry:
    if not isinstance(row, dict):
        raise ToolError(f"{label}: must be a table")
    version = _text(row, "version", f"{label}.version")
    if re.search(r"[/\\\s]", version):
        raise ToolError(f"{label}.version: {version!r} must not contain a slash, backslash or space")
    number = row.get("build")
    if not isinstance(number, int) or isinstance(number, bool) or number < 1:
        raise ToolError(f"{label}.build: must be a whole number of 1 or more")
    kind = row.get("kind")
    if kind not in KINDS:
        raise ToolError(f"{label}.kind: must be one of {', '.join(KINDS)}")
    needs_root = row.get("needs_root", False)
    if not isinstance(needs_root, bool):
        raise ToolError(f"{label}.needs_root: must be true or false")
    size = row.get("size")
    if not isinstance(size, int) or isinstance(size, bool) or size < 1:
        raise ToolError(f"{label}.size: must be a positive whole number")
    sha256 = row.get("sha256")
    if not isinstance(sha256, str) or not _SHA256.fullmatch(sha256):
        raise ToolError(f"{label}.sha256: must be 64 hexadecimal characters")
    return BuildEntry(
        name=tool,
        version=version,
        build=number,
        kind=kind,
        needs_root=needs_root,
        commands=_strings(row, "commands", f"{label}.commands"),
        file=_plain_zip_name(row.get("file"), f"{label}.file"),
        url=_optional_text(row, "url", f"{label}.url"),
        size=size,
        sha256=sha256.lower(),
    )


def _tool(row: object, index: int) -> ToolEntry:
    label = f"tool[{index}]"
    if not isinstance(row, dict):
        raise ToolError(f"{label}: must be a table")
    name = _text(row, "name", f"{label}.name")
    if not _NAME.fullmatch(name):
        raise ToolError(f"{label}.name: {name!r} must be lower-case letters, digits and hyphens")
    label = f"tool {name}"
    rows = row.get("build", [])
    if not isinstance(rows, list):
        raise ToolError(f"{label}.build: must be a list of tables")
    if not rows:
        raise ToolError(f"{label}: has no builds")
    builds = [_build(name, r, f"{label}.build[{i}]") for i, r in enumerate(rows)]
    seen = set()
    for b in builds:
        bid = build_id(b.version, b.build)
        if bid in seen:
            raise ToolError(f"{label}: build {bid} appears more than once")
        seen.add(bid)
    latest = _text(row, "latest", f"{label}.latest")
    if latest not in seen:
        raise ToolError(f"{label}.latest: {latest!r} is not one of its builds")
    return ToolEntry(
        name=name,
        description=_text(row, "description", f"{label}.description"),
        tags=_strings(row, "tags", f"{label}.tags"),
        licence=_text(row, "licence", f"{label}.licence"),
        upstream=_text(row, "upstream", f"{label}.upstream"),
        latest=latest,
        builds=builds,
    )


def parse_index(data: dict) -> Index:
    schema = data.get("schema")
    if schema != 1 or isinstance(schema, bool):
        raise ToolError("schema: this index needs a newer pwn-broker; upgrade pwn-broker")
    rows = data.get("tool", [])
    if not isinstance(rows, list):
        raise ToolError("tool: must be a list of tables")
    tools = [_tool(r, i) for i, r in enumerate(rows)]
    names = set()
    for tool in tools:
        if tool.name in names:
            raise ToolError(f"tool {tool.name}: appears more than once")
        names.add(tool.name)
    return Index(tools)


def _parse_bytes(raw: bytes) -> Index:
    try:
        return parse_index(tomllib.loads(raw.decode("utf-8")))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ToolError(f"the index cannot be read ({exc})") from exc


# ---- loading


def location(settings: Settings) -> str:
    return settings.tools_index or config.DEFAULT_TOOLS_INDEX


def is_url(text: str) -> bool:
    return text.startswith(("http://", "https://"))


def _not_found(where: str, reason: str = "") -> ToolError:
    extra = f" ({reason})" if reason else ""
    return ToolError(
        f"no tool index found at {where}{extra}; "
        "set tools_index in config.toml to point at a folder that holds index.toml"
    )


def _read_cached(paths: AppPaths) -> Index | None:
    try:
        return _parse_bytes((paths.cache / INDEX_FILE).read_bytes())
    except (OSError, ToolError):
        return None


def _is_fresh(paths: AppPaths, now: datetime) -> bool:
    try:
        text = (paths.cache / STAMP_FILE).read_text(encoding="utf-8").strip()
        fetched = datetime.fromisoformat(text)
        return now - fetched <= MAX_AGE
    except (OSError, ValueError, TypeError):
        # unreadable, or a naive time that cannot be compared with now
        return False


def load_index(
    paths: AppPaths,
    settings: Settings,
    *,
    now: datetime,
    fetch: Callable[[str, float], bytes] = _fetch,
    force: bool = False,
) -> Index:
    where = location(settings)
    if not is_url(where):
        file = Path(where) / INDEX_FILE
        try:
            raw = file.read_bytes()
        except OSError as exc:
            raise _not_found(str(file), str(exc)) from exc
        return _parse_bytes(raw)

    cached = _read_cached(paths)
    if cached is not None and not force and _is_fresh(paths, now):
        return cached
    try:
        raw = fetch(where, FORCED_TIMEOUT if force else QUICK_TIMEOUT)
        fresh = _parse_bytes(raw)
    except Exception as exc:
        if cached is not None and not force:
            return cached
        if isinstance(exc, ToolError):
            raise
        raise _not_found(where, str(exc) or type(exc).__name__) from exc
    # the download parsed, so it may replace the cached copy
    write_text(paths.cache / INDEX_FILE, raw.decode("utf-8"))
    write_text(paths.cache / STAMP_FILE, now.isoformat() + "\n")
    return fresh


# ---- lookups


def find_tool(index: Index, name: str) -> ToolEntry:
    for tool in index.tools:
        if tool.name == name:
            return tool
    close = difflib.get_close_matches(name, [t.name for t in index.tools], n=1)
    hint = f"; did you mean {close[0]}" if close else ""
    raise ToolError(f"no tool named {name!r} in the index{hint}")


def pick_build(tool: ToolEntry, wanted: str | None) -> BuildEntry:
    if wanted is None:
        for b in tool.builds:
            if build_id(b.version, b.build) == tool.latest:
                return b
        raise ToolError(f"{tool.name}: latest {tool.latest!r} is not one of its builds")
    same = [b for b in tool.builds if b.version == wanted]
    if same:
        return max(same, key=lambda b: b.build)
    for b in tool.builds:
        if build_id(b.version, b.build) == wanted:
            return b
    versions = ", ".join(dict.fromkeys(b.version for b in tool.builds))
    raise ToolError(f"{tool.name} has no version {wanted!r}; versions: {versions}")


def search(index: Index, words: list[str]) -> list[ToolEntry]:
    wanted = [w.lower() for w in words]
    found = []
    for tool in index.tools:
        haystack = " ".join([tool.name, tool.description, *tool.tags]).lower()
        if all(w in haystack for w in wanted):
            found.append(tool)
    return found


# ---- zips


def _remove(path: Path) -> None:
    try:
        path.unlink()
    except OSError:
        pass


def fetch_zip(
    paths: AppPaths,
    settings: Settings,
    entry: BuildEntry,
    *,
    fetch: Callable[[str, float], bytes] = _fetch,
) -> Path:
    # entries can be built directly, so the name is judged again before any path exists
    _plain_zip_name(entry.file, "file")
    target = paths.cache / entry.file
    if target.is_file():
        try:
            verify_zip(target, size=entry.size, sha256=entry.sha256)
            return target
        except ToolError:
            _remove(target)

    where = location(settings)
    if is_url(where) and not entry.url:
        raise ToolError(f"{entry.name} {entry.version}: the index gives no download address")
    paths.cache.mkdir(parents=True, exist_ok=True)
    part = paths.cache / (entry.file + ".part")
    try:
        if is_url(where):
            try:
                part.write_bytes(fetch(entry.url, ZIP_TIMEOUT))
            except Exception as exc:
                raise ToolError(
                    f"cannot download {entry.url}: {str(exc) or type(exc).__name__}"
                ) from exc
        else:
            source = Path(where) / entry.file
            try:
                shutil.copyfile(source, part)
            except OSError as exc:
                raise ToolError(f"cannot copy {source}: {exc}") from exc
        verify_zip(part, size=entry.size, sha256=entry.sha256)
        os.replace(part, target)
    except BaseException:
        _remove(part)
        raise
    return target


def clear_cache(paths: AppPaths) -> int:
    removed = 0
    if not paths.cache.is_dir():
        return 0
    for item in paths.cache.iterdir():
        if item.is_file() and item.suffix in (".zip", ".part"):
            try:
                item.unlink()
            except OSError:
                continue
            if item.suffix == ".zip":
                removed += 1
    return removed
