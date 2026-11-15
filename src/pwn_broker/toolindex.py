import difflib
import os
import re
import shutil
import stat
import threading
import time
import tomllib
import urllib.parse
import urllib.request
from collections.abc import Callable
from dataclasses import dataclass
from datetime import datetime, timedelta
from pathlib import Path

from pwn_broker import config
from pwn_broker.config import Settings
from pwn_broker.paths import AppPaths
from pwn_broker.store import write_text
from pwn_broker.toolpkg import KINDS, ToolError, build_id, verify_zip

INDEX_FILE = "index.toml"
STAMP_FILE = "index.fetched"
MAX_AGE = timedelta(days=1)
QUICK_TIMEOUT = 2
FORCED_TIMEOUT = 30
ZIP_TIMEOUT = 300.0
MAX_INDEX_BYTES = 5 * 1024 * 1024
_CHUNK = 64 * 1024

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
    if "schema" not in data:
        # an empty or cut-short file, not one from a newer version
        raise ToolError("the index cannot be read (it has no schema)")
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


# ---- network


class _SafeRedirect(urllib.request.HTTPRedirectHandler):
    # urllib follows a redirect to ftp:// on its own; only http and https are followed here
    def http_error_302(self, req, fp, code, msg, headers):
        target = headers.get("location") or headers.get("uri")
        if target is not None:
            full = urllib.parse.urljoin(req.full_url, target)
            if not is_url(full):
                fp.close()
                raise ToolError(f"{req.full_url} redirects to {full}, which is not http or https")
        return super().http_error_302(req, fp, code, msg, headers)

    http_error_301 = http_error_303 = http_error_307 = http_error_308 = http_error_302


def _opener(*extra: urllib.request.BaseHandler) -> urllib.request.OpenerDirector:
    return urllib.request.build_opener(_SafeRedirect, *extra)


_OPENER = _opener()


def _open(url: str, timeout: float):
    request = urllib.request.Request(url, headers={"User-Agent": "pwn-broker"})
    return _OPENER.open(request, timeout=timeout)


def _fetch_index(url: str, timeout: float) -> bytes:
    with _open(url, timeout) as response:
        body = response.read(MAX_INDEX_BYTES + 1)
    if len(body) > MAX_INDEX_BYTES:
        raise ToolError(f"the index is more than {MAX_INDEX_BYTES} bytes")
    return body


def download(url: str, dest: Path, limit: int, timeout: float) -> None:
    # streamed to disk and cut off as soon as it passes the size the index promised
    deadline = time.monotonic() + timeout
    total = 0
    with _open(url, timeout) as response, open(dest, "wb") as out:
        while chunk := response.read(_CHUNK):
            total += len(chunk)
            if total > limit:
                raise ToolError(f"the download is more than the {limit} bytes the index gives")
            if time.monotonic() > deadline:
                raise ToolError("the download took too long")
            out.write(chunk)


def _with_deadline(fetch: Callable[[str, float], bytes], url: str, timeout: float) -> bytes:
    # urlopen's timeout is per socket operation, so the total time is enforced here
    box: list = []

    def run() -> None:
        try:
            box.append((True, fetch(url, timeout)))
        except BaseException as exc:
            box.append((False, exc))

    thread = threading.Thread(target=run, daemon=True)
    thread.start()
    thread.join(timeout)
    if not box:
        raise ToolError(f"no answer from {url} within {timeout:g} seconds")
    ok, value = box[0]
    if not ok:
        raise value
    if len(value) > MAX_INDEX_BYTES:
        raise ToolError(f"the index is more than {MAX_INDEX_BYTES} bytes")
    return value


# ---- loading


def location(settings: Settings) -> str:
    return settings.tools_index or config.DEFAULT_TOOLS_INDEX


def is_url(text: str) -> bool:
    return text.startswith(("http://", "https://"))


def _not_found(where: str, reason: str = "") -> ToolError:
    # every failure with nothing to fall back on ends the same way: where, why, and the setting
    extra = f" ({reason})" if reason else ""
    return ToolError(
        f"no usable tool index at {where}{extra}; "
        "set tools_index in config.toml to point at a folder that holds index.toml"
    )


def _stamp(paths: AppPaths) -> tuple[datetime | None, str | None]:
    try:
        lines = (paths.cache / STAMP_FILE).read_text(encoding="utf-8").splitlines()
        fetched = datetime.fromisoformat(lines[0].strip())
    except (OSError, ValueError, IndexError):
        return None, None
    return fetched, lines[1].strip() if len(lines) > 1 else None


def _read_cached(paths: AppPaths, where: str) -> Index | None:
    _, source = _stamp(paths)
    if source is not None and source != where:
        # a copy of some other index must not stand in for this one
        return None
    try:
        return _parse_bytes((paths.cache / INDEX_FILE).read_bytes())
    except (OSError, ToolError):
        return None


def _is_fresh(paths: AppPaths, where: str, now: datetime) -> bool:
    fetched, source = _stamp(paths)
    if fetched is None or source != where:
        return False
    try:
        return timedelta(0) <= now - fetched <= MAX_AGE
    except TypeError:
        # a naive time cannot be compared with now
        return False


def load_index(
    paths: AppPaths,
    settings: Settings,
    *,
    now: datetime,
    fetch: Callable[[str, float], bytes] = _fetch_index,
    force: bool = False,
) -> Index:
    where = location(settings)
    if not is_url(where):
        file = Path(where) / INDEX_FILE
        try:
            return _parse_bytes(file.read_bytes())
        except OSError as exc:
            raise _not_found(str(file), str(exc)) from exc
        except ToolError as exc:
            raise _not_found(str(file), str(exc)) from exc

    cached = _read_cached(paths, where)
    if cached is not None and not force and _is_fresh(paths, where, now):
        return cached
    try:
        raw = _with_deadline(fetch, where, FORCED_TIMEOUT if force else QUICK_TIMEOUT)
        fresh = _parse_bytes(raw)
    except Exception as exc:
        if cached is not None and not force:
            return cached
        raise _not_found(where, str(exc) or type(exc).__name__) from exc
    # the download parsed, so it may replace the cached copy; a cache that cannot be
    # written costs only the saving, not the answer
    try:
        write_text(paths.cache / INDEX_FILE, raw.decode("utf-8"))
        write_text(paths.cache / STAMP_FILE, f"{now.isoformat()}\n{where}\n")
    except OSError:
        pass
    return fresh


# path -> ((mtime_ns, size), names); completions ask on every key press
_NAMES: dict[str, tuple[tuple[int, int], list[str]]] = {}


def _read_capped(file: Path) -> bytes:
    with open(file, "rb") as fh:
        raw = fh.read(MAX_INDEX_BYTES + 1)
    if len(raw) > MAX_INDEX_BYTES:
        raise ToolError(f"{file} is larger than {MAX_INDEX_BYTES} bytes")
    return raw


def known_names(paths: AppPaths, settings: Settings) -> list[str]:
    # for completions: only what is already on disk, never a fetch
    where = location(settings)
    try:
        if is_url(where):
            _, source = _stamp(paths)
            if source is not None and source != where:
                return []
            file = paths.cache / INDEX_FILE
        else:
            file = Path(where) / INDEX_FILE
        info = file.stat()
        if info.st_size > MAX_INDEX_BYTES:
            return []
        signature = (info.st_mtime_ns, info.st_size)
        hit = _NAMES.get(str(file))
        if hit is not None and hit[0] == signature:
            return list(hit[1])
        try:
            names = sorted(t.name for t in _parse_bytes(_read_capped(file)).tools)
        except (OSError, ToolError):
            names = []
        _NAMES[str(file)] = (signature, names)
        return list(names)
    except Exception:
        return []


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
    download: Callable[[str, Path, int, float], None] = download,
) -> Path:
    # entries can be built directly, so the name is judged again before any path exists
    _plain_zip_name(entry.file, "file")
    target = paths.cache / entry.file
    if target.is_file():
        try:
            verify_zip(target, size=entry.size, sha256=entry.sha256)
            return target
        except ToolError:
            # nothing unverified is ever returned: a bad copy is dropped and fetched afresh
            _remove(target)

    where = location(settings)
    if is_url(where):
        if not entry.url:
            raise ToolError(f"{entry.name} {entry.version}: the index gives no download address")
        if not is_url(entry.url):
            raise ToolError(f"{entry.name} {entry.version}: {entry.url!r} is not an http or https address")
    paths.cache.mkdir(parents=True, exist_ok=True)
    part = paths.cache / (entry.file + ".part")
    try:
        if is_url(where):
            try:
                download(entry.url, part, entry.size, ZIP_TIMEOUT)
            except ToolError:
                raise
            except Exception as exc:
                raise ToolError(
                    f"cannot download {entry.url}: {str(exc) or type(exc).__name__}"
                ) from exc
        else:
            source = Path(where) / entry.file
            try:
                if not stat.S_ISREG(source.lstat().st_mode):
                    raise ToolError(f"{source} is not a regular file")
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
