import os
import platform
import re
import shutil
import stat
import tomllib
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from pwn_broker.filescan import sha256_file

KINDS = ("kali", "upload", "both")
COMMAND_TYPES = ("binary", "python-entry", "python-script")
MANIFEST = "manifest.toml"

_CHUNK = 1024 * 1024
_MANIFEST_LIMIT = 1024 * 1024
MAX_MEMBERS = 10_000
MAX_UNPACKED_BYTES = 1024**3
_NAME = re.compile(r"[a-z0-9][a-z0-9-]*")
_COMMAND_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_TOP_FILES = (MANIFEST, "LICENSE", "wheels.lock")
LOCK_LIMIT = 1024 * 1024
# pip obeys options, URLs and markers in a requirements file; only exact pins with hashes pass
_LOCK_LINE = re.compile(
    r"[A-Za-z0-9][A-Za-z0-9._-]*==[A-Za-z0-9][A-Za-z0-9.!+_-]*( --hash=sha256:[0-9a-f]{64})+"
)
_TOP_FOLDERS = ("files", "wheels")


class ToolError(Exception):
    pass


@dataclass
class Command:
    name: str
    type: str
    path: str = ""
    entry: str = ""
    script: str = ""
    env: dict[str, str] = field(default_factory=dict)
    args: list[str] = field(default_factory=list)


@dataclass
class Upload:
    path: str
    as_name: str
    note: str = ""


@dataclass
class PythonSpec:
    versions: list[str]
    lock: str
    wheels: str


@dataclass
class Manifest:
    name: str
    version: str
    build: int
    kind: str
    description: str
    tags: list[str]
    upstream: str
    licence: str
    arch: str
    needs_root: bool
    examples: list[str]
    commands: list[Command]
    uploads: list[Upload]
    python: PythonSpec | None
    home: list[str]


def valid_tool_name(name: str) -> bool:
    return _NAME.fullmatch(name) is not None


def valid_command_name(name: str) -> bool:
    return _COMMAND_NAME.fullmatch(name) is not None


def build_id(version: str, build: int) -> str:
    return f"{version}-{build}"


def zip_name(name: str, version: str, build: int) -> str:
    return f"{name}-{build_id(version, build)}.zip"


def machine_arch() -> str:
    machine = platform.machine().lower()
    if machine in ("x86_64", "amd64"):
        return "x86_64"
    if machine in ("aarch64", "arm64"):
        return "arm64"
    return machine


# ---- manifest


def _text(table: dict, key: str, label: str, *, required: bool = True) -> str:
    value = table.get(key)
    if value is None and not required:
        return ""
    if not isinstance(value, str) or not value:
        raise ToolError(f"{label}: must be a non-empty string")
    return value


def _strings(table: dict, key: str, label: str) -> list[str]:
    value = table.get(key, [])
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise ToolError(f"{label}: must be a list of strings")
    return list(value)


def _relative(value: str, label: str, *, under: str = "") -> str:
    if not isinstance(value, str) or not value:
        raise ToolError(f"{label}: must be a relative path")
    parts = value.split("/")
    if (
        value.startswith("/")
        or "\\" in value
        or "\0" in value
        or any(p in ("", ".", "..") for p in parts)
        or parts[0].endswith(":")
    ):
        raise ToolError(f"{label}: {value!r} is not a relative path inside the package")
    if under and parts[0] != under:
        raise ToolError(f"{label}: {value!r} must start with {under}/")
    return value


def _table_list(data: dict, key: str) -> list[dict]:
    rows = data.get(key, [])
    if not isinstance(rows, list) or not all(isinstance(r, dict) for r in rows):
        raise ToolError(f"{key}: must be a list of tables")
    return rows


def _command(row: dict, index: int) -> Command:
    label = f"command[{index}]"
    name = _text(row, "name", f"{label}.name")
    if not _COMMAND_NAME.fullmatch(name):
        raise ToolError(f"{label}.name: {name!r} is not a valid command name")
    kind = row.get("type")
    if kind not in COMMAND_TYPES:
        raise ToolError(f"{label}.type: must be one of {', '.join(COMMAND_TYPES)}")
    env = row.get("env", {})
    if not isinstance(env, dict) or not all(
        isinstance(k, str) and isinstance(v, str) for k, v in env.items()
    ):
        raise ToolError(f"{label}.env: must be a table of strings")
    cmd = Command(name, kind, env=dict(env), args=_strings(row, "args", f"{label}.args"))
    if kind == "binary":
        cmd.path = _relative(_text(row, "path", f"{label}.path"), f"{label}.path", under="files")
    elif kind == "python-script":
        cmd.script = _relative(
            _text(row, "script", f"{label}.script"), f"{label}.script", under="files"
        )
    else:
        entry = _text(row, "entry", f"{label}.entry")
        if "/" in entry or "\\" in entry or "\0" in entry or entry in (".", ".."):
            raise ToolError(f"{label}.entry: {entry!r} must be a plain file name")
        cmd.entry = entry
    return cmd


def _upload(row: dict, index: int) -> Upload:
    label = f"upload[{index}]"
    path = _relative(_text(row, "path", f"{label}.path"), f"{label}.path", under="files")
    as_name = _text(row, "as", f"{label}.as")
    if "/" in as_name or "\\" in as_name or "\0" in as_name or as_name in (".", ".."):
        raise ToolError(f"{label}.as: {as_name!r} must be a plain file name")
    note = row.get("note", "")
    if not isinstance(note, str):
        raise ToolError(f"{label}.note: must be a string")
    return Upload(path, as_name, note)


def _python(data: dict, needed: bool) -> PythonSpec | None:
    table = data.get("python")
    if table is None:
        if needed:
            raise ToolError("python: a python-entry or python-script command needs a [python] table")
        return None
    if not needed:
        raise ToolError("python: a [python] table is only for packages with a Python command")
    if not isinstance(table, dict):
        raise ToolError("python: must be a table")
    versions = _strings(table, "versions", "python.versions")
    if not versions or not all(versions):
        raise ToolError("python.versions: needs at least one version")
    spec = PythonSpec(versions, "", "")
    for key in ("lock", "wheels"):
        value = _relative(_text(table, key, f"python.{key}"), f"python.{key}")
        if value.split("/")[0] == "files":
            raise ToolError(f"python.{key}: {value!r} must not be under files/")
        setattr(spec, key, value)
    return spec


def parse_manifest(data: dict) -> Manifest:
    if data.get("schema") != 1 or isinstance(data.get("schema"), bool):
        raise ToolError("schema: this package needs a newer pwn-broker; upgrade pwn-broker")
    name = _text(data, "name", "name")
    if not _NAME.fullmatch(name):
        raise ToolError(f"name: {name!r} must be lower-case letters, digits and hyphens")
    version = _text(data, "version", "version")
    if re.search(r"[/\\\s]", version):
        raise ToolError(f"version: {version!r} must not contain a slash, backslash or space")
    build = data.get("build")
    if not isinstance(build, int) or isinstance(build, bool) or build < 1:
        raise ToolError("build: must be a whole number of 1 or more")
    kind = data.get("kind")
    if kind not in KINDS:
        raise ToolError(f"kind: must be one of {', '.join(KINDS)}")
    needs_root = data.get("needs_root", False)
    if not isinstance(needs_root, bool):
        raise ToolError("needs_root: must be true or false")

    commands = [_command(r, i) for i, r in enumerate(_table_list(data, "command"))]
    uploads = [_upload(r, i) for i, r in enumerate(_table_list(data, "upload"))]
    seen = set()
    for cmd in commands:
        if cmd.name in seen:
            raise ToolError(f"command.name: {cmd.name!r} appears more than once")
        seen.add(cmd.name)
    if kind in ("kali", "both") and not commands:
        raise ToolError(f"command: a {kind} package needs at least one command")
    if kind == "upload" and commands:
        raise ToolError("command: an upload package has no commands")
    if kind in ("upload", "both") and not uploads:
        raise ToolError(f"upload: a {kind} package needs at least one upload")
    if kind == "kali" and uploads:
        raise ToolError("upload: a kali package has no uploads")

    python = _python(data, any(c.type != "binary" for c in commands))

    home_table = data.get("data", {})
    if not isinstance(home_table, dict):
        raise ToolError("data: must be a table")
    home = _strings(home_table, "home", "data.home")
    for entry in home:
        _relative(entry, "data.home")

    return Manifest(
        name=name,
        version=version,
        build=build,
        kind=kind,
        description=_text(data, "description", "description"),
        tags=_strings(data, "tags", "tags"),
        upstream=_text(data, "upstream", "upstream"),
        licence=_text(data, "licence", "licence"),
        arch=_text(data, "arch", "arch"),
        needs_root=needs_root,
        examples=_strings(data, "examples", "examples"),
        commands=commands,
        uploads=uploads,
        python=python,
        home=home,
    )


def _parse_text(raw: bytes, label: str) -> Manifest:
    try:
        return parse_manifest(tomllib.loads(raw.decode("utf-8")))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise ToolError(f"{label} cannot be read ({exc})") from exc


def read_manifest(path: Path) -> Manifest:
    try:
        raw = path.read_bytes()
    except OSError as exc:
        raise ToolError(f"cannot read {path}: {exc}") from exc
    return _parse_text(raw, str(path))


# ---- wheels.lock


def check_lock(raw: bytes, label: str = "wheels.lock") -> None:
    """Refuse a lock file unless every line is name==version followed by sha256 hashes."""
    if len(raw) > LOCK_LIMIT:
        raise ToolError(f"{label} is too large (more than {LOCK_LIMIT} bytes)")
    try:
        text = raw.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ToolError(f"{label} is not UTF-8 ({exc})") from exc
    if not text:
        raise ToolError(f"{label} is empty")
    lines = text.split("\n")
    if lines[-1] != "":
        raise ToolError(f"{label} line {len(lines)} does not end with a line break")
    for number, line in enumerate(lines[:-1], start=1):
        if not _LOCK_LINE.fullmatch(line):
            raise ToolError(
                f"{label} line {number} is not name==version followed by --hash=sha256: values"
            )


# ---- zips


def verify_zip(path: Path, *, size: int, sha256: str) -> None:
    try:
        actual = path.stat().st_size
        if actual != size:
            raise ToolError(f"{path.name}: size is {actual} bytes, expected {size}")
        if sha256_file(path) != sha256.lower():
            raise ToolError(f"{path.name}: SHA-256 differs from the index")
    except OSError as exc:
        raise ToolError(f"cannot read {path}: {exc}") from exc


def _check_name(name: str) -> str:
    # judged as text before any path is built; returns the name without a folder's trailing slash
    bare = name[:-1] if name.endswith("/") else name
    parts = bare.split("/")
    if (
        not bare
        or name.startswith("/")
        or "\\" in name
        or "\0" in name
        or any(p in ("", ".", "..") for p in parts)
        or parts[0].endswith(":")
    ):
        raise ToolError(f"package entry {name!r} would write outside the tool's folder")
    return bare


def _check_entries(infos: list[zipfile.ZipInfo]) -> dict[str, zipfile.ZipInfo]:
    if len(infos) > MAX_MEMBERS:
        raise ToolError(f"package has {len(infos)} entries; the limit is {MAX_MEMBERS}")
    if sum(i.file_size for i in infos) > MAX_UNPACKED_BYTES:
        raise ToolError(f"package unpacks to more than {MAX_UNPACKED_BYTES} bytes")
    seen: dict[str, zipfile.ZipInfo] = {}
    for info in infos:
        if info.compress_type != zipfile.ZIP_STORED:
            # packages are stored, so there is nothing to decompress and no bomb to fear
            raise ToolError(f"package entry {info.filename!r} is compressed")
        bare = _check_name(info.filename)
        if bare in seen:
            raise ToolError(f"package entry {info.filename!r} appears twice")
        mode = info.external_attr >> 16
        if stat.S_IFMT(mode) not in (0, stat.S_IFREG, stat.S_IFDIR):
            raise ToolError(f"package entry {info.filename!r} is a link or special file")
        if info.flag_bits & 0x1:
            raise ToolError(f"package entry {info.filename!r} is encrypted")
        top = bare.split("/")[0]
        if info.is_dir():
            allowed = top in _TOP_FOLDERS
        elif "/" in bare:
            allowed = top in _TOP_FOLDERS
        else:
            allowed = bare in _TOP_FILES
        if not allowed:
            raise ToolError(f"package entry {info.filename!r} is not part of the package layout")
        seen[bare] = info
    for bare, info in seen.items():
        # a file cannot also be a folder another entry lives in
        parent = bare.rpartition("/")[0]
        while parent:
            if parent in seen and not seen[parent].is_dir():
                raise ToolError(f"package entry {bare!r} sits inside the file {parent!r}")
            parent = parent.rpartition("/")[0]
    return seen


def _is_file(seen: dict[str, zipfile.ZipInfo], name: str) -> bool:
    return name in seen and not seen[name].is_dir()


def _check_named_files(manifest: Manifest, seen: dict[str, zipfile.ZipInfo]) -> None:
    named = [c.path for c in manifest.commands if c.path]
    named += [c.script for c in manifest.commands if c.script]
    named += [u.path for u in manifest.uploads]
    for name in named:
        if not _is_file(seen, name):
            raise ToolError(f"{name}: named in the manifest but missing from the package")
    if manifest.python is not None:
        if not _is_file(seen, manifest.python.lock):
            raise ToolError(f"{manifest.python.lock}: the lock file is missing from the package")
        if seen[manifest.python.lock].file_size > LOCK_LIMIT:
            raise ToolError(f"{manifest.python.lock} is too large (more than {LOCK_LIMIT} bytes)")
        prefix = manifest.python.wheels + "/"
        if not any(not i.is_dir() and b.startswith(prefix) for b, i in seen.items()):
            raise ToolError(f"{manifest.python.wheels}: the package holds no wheels")


def _write_member(zf: zipfile.ZipFile, info: zipfile.ZipInfo, target: Path) -> None:
    total = 0
    with zf.open(info) as src, open(target, "xb") as out:
        while chunk := src.read(_CHUNK):
            total += len(chunk)
            if total > info.file_size:
                break
            out.write(chunk)
    if total != info.file_size:
        raise ToolError(f"package entry {info.filename!r} is not the size it declares")


def _make_dest(dest: Path, created: list[Path]) -> None:
    # records each folder this call makes, outermost first, so a failure removes only those
    missing = []
    for folder in (dest, *dest.parents):
        if folder.exists():
            break
        missing.append(folder)
    for folder in reversed(missing):
        folder.mkdir()
        created.append(folder)


def _clean_up(created: list[Path], dest: Path) -> None:
    for folder in reversed(created):
        if folder == dest:
            shutil.rmtree(folder, ignore_errors=True)
        else:
            try:
                folder.rmdir()
            except OSError:
                pass


def unpack(zip_path: Path, dest: Path) -> Manifest:
    if os.path.lexists(dest):
        raise ToolError(f"{dest} already exists")
    created: list[Path] = []
    try:
        with zipfile.ZipFile(zip_path) as zf:
            seen = _check_entries(zf.infolist())
            info = seen.get(MANIFEST)
            if info is None or info.is_dir():
                raise ToolError(f"{MANIFEST} is missing from the package")
            if info.file_size > _MANIFEST_LIMIT:
                raise ToolError(f"{MANIFEST} is too large")
            manifest = _parse_text(zf.read(info), MANIFEST)
            _check_named_files(manifest, seen)
            if manifest.python is not None:
                lock = manifest.python.lock
                check_lock(zf.read(seen[lock]), lock)
            _make_dest(dest, created)
            _extract(zf, seen, dest)
    except BaseException as exc:
        _clean_up(created, dest)
        if isinstance(exc, ToolError) or not isinstance(exc, Exception):
            raise
        raise ToolError(f"cannot unpack {zip_path.name}: {exc}") from exc
    return manifest


def _extract(zf: zipfile.ZipFile, seen: dict[str, zipfile.ZipInfo], dest: Path) -> None:
    for bare, info in seen.items():
        target = dest.joinpath(*bare.split("/"))
        if info.is_dir():
            target.mkdir(parents=True, exist_ok=True)
            continue
        target.parent.mkdir(parents=True, exist_ok=True)
        _write_member(zf, info, target)
        if bare.startswith("files/"):
            target.chmod(0o755)
