import os
import platform
import re
import shutil
import stat
import tomllib
import unicodedata
import zipfile
from dataclasses import dataclass, field
from pathlib import Path

from pwn_broker.filescan import sha256_file

KINDS = ("kali", "upload", "both", "runtime")
SCHEMAS = (1, 2)
COMMAND_TYPES = ("binary", "python-entry", "python-script")
MANIFEST = "manifest.toml"

_CHUNK = 1024 * 1024
_MANIFEST_LIMIT = 1024 * 1024
# how many files and folders a package may make: its entries, and every folder on the way to
# one. A name of 64 parts makes 63 folders, each a block on disk that no entry accounts for.
MAX_MEMBERS = 10_000
MAX_UNPACKED_BYTES = 1024**3
# the zip's own list of its entries, which zipfile reads whole before one entry can be counted:
# room for MAX_MEMBERS entries whose names are far longer than a package's
MAX_DIRECTORY_BYTES = 4 * 1024 * 1024
# the Linux limits on a path and on one part of it
MAX_PATH_BYTES = 4096
MAX_PART_BYTES = 255
# how many parts a name in a package may have. Every folder on the way to a file is looked at
# again for each file, and each look walks the whole path, so a name 1,900 parts deep made 20
# files take six seconds; and a tree that deep cannot always be removed again. The Python
# runtime's deepest name has 11 parts.
MAX_DEPTH = 64
# a dot only between other characters, so a name is never ".", "..", hidden or ends with a dot
_NAME = re.compile(r"[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*")
_SERIES = re.compile(r"[0-9]+\.[0-9]+")
# a version is part of a folder's name and is printed: no slash, space or control character
_VERSION = re.compile(r"[A-Za-z0-9][A-Za-z0-9._+~-]{0,99}")
VERSION_RULE = (
    "must start with a letter or digit and hold only letters, digits and . _ + ~ -, "
    "100 characters at most"
)
_COMMAND_NAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]*")
_TOP_FILES = (MANIFEST, "LICENSE", "wheels.lock")
# A launcher by one of these names, first on PATH, would stand in for something the user,
# sudo or the app itself relies on. It is a list of what must never be stood in for, not of
# everything Kali has: a tool may take the name of Kali's own copy of it, and install says so.
RESERVED_COMMANDS = frozenset(
    # shells, and what starts a program for one
    "sh bash dash zsh fish env "
    # what asks for a password or changes who you are
    "sudo sudoedit su doas pkexec run0 passwd login newgrp visudo "
    "ssh scp sftp ssh-agent ssh-add ssh-keygen gpg "
    # Python and pip; python3.13, python3.13t, pip3.13 and the like are refused by _VERSIONED_PYTHON
    "python python3 pip pip3 "
    # what the app runs by name, which a test checks against the app's own code
    "chown cp rm kill ip ping tar vim openvpn x-terminal-emulator pwn-broker record asciinema "
    # what a shell's start-up files, its prompt and everyday lines run
    "sed cut mkdir cat ls mv ln vi grep awk find head tail chmod id uname test "
    "whoami hostname sleep touch tee which ps tput dircolors xargs timeout nohup "
    # what other programs start by name to show or edit something
    "less more pager man nano editor "
    # what installs and manages the system
    "apt apt-get dpkg systemctl mount umount "
    # what fetches something to run
    "curl wget git".split()
)
_VERSIONED_PYTHON = re.compile(r"(?:python|pip)[0-9][A-Za-z0-9._-]*")
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
    versions: list[str]  # empty in schema 2, where the runtime's series decides
    lock: str
    wheels: str


@dataclass
class RuntimeSpec:
    archive: str
    python: str
    series: str


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
    schema: int = 1
    requires: list[str] = field(default_factory=list)
    runtime: RuntimeSpec | None = None


def valid_tool_name(name: str) -> bool:
    return isinstance(name, str) and _NAME.fullmatch(name) is not None


def reserved_command_name(name: str) -> bool:
    return name in RESERVED_COMMANDS or _VERSIONED_PYTHON.fullmatch(name) is not None


def valid_command_name(name: str) -> bool:
    return _COMMAND_NAME.fullmatch(name) is not None and not reserved_command_name(name)


def valid_version(version: object) -> bool:
    return isinstance(version, str) and _VERSION.fullmatch(version) is not None


def shown(text: str) -> str:
    return repr(text) if len(text) <= 100 else f"{text[:100]!r}..."


def bad_characters(text: str) -> bool:
    """A backslash, a colon or a control character, none of which a name in a package holds."""
    return any(c in "\\:" or unicodedata.category(c) == "Cc" for c in text)


def _byte_length(text: str) -> int:
    try:
        return len(text.encode("utf-8", "surrogateescape"))
    except UnicodeEncodeError:
        return len(text.encode("utf-8", "surrogatepass"))


def too_long(text: str) -> str | None:
    """What is wrong with the length of a name, to follow "has a name" or "has a target"."""
    if _byte_length(text) > MAX_PATH_BYTES:
        return f"longer than {MAX_PATH_BYTES} bytes"
    # the slash that marks a folder is not one more part
    parts = (text[:-1] if text.endswith("/") else text).split("/")
    if any(_byte_length(part) > MAX_PART_BYTES for part in parts):
        return f"with a part longer than {MAX_PART_BYTES} bytes"
    if len(parts) > MAX_DEPTH:
        return f"with more than {MAX_DEPTH} parts"
    return None


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

# finish moves what a tool wrote under these names into the box and deletes it from the home
# folder, so a manifest may not claim places that hold the user's own keys or settings, or that
# run something at login; a tool's own folder inside a shared one (.config/<tool>) is fine.
# Neither list can name every such place: they hold the ones every Kali home has or soon gets.
# _PRIVATE_HOME is refused with everything under it, _SHARED_HOME by its exact name.
_PRIVATE_HOME = (
    ".ssh", ".gnupg", ".aws", ".azure", ".kube", ".docker", ".password-store", ".mozilla", ".pki",
    ".vim", ".bashrc.d", ".config/gcloud", ".config/gh", ".config/git", ".config/fish",
    ".config/chromium", ".config/autostart", ".config/systemd", ".config/environment.d",
    ".local/bin", ".local/share/keyrings", ".local/share/applications",
)  # fmt: skip
_SHARED_HOME = frozenset(
    ".config .local .local/share .local/state .cache .bashrc .zshrc .profile .bash_profile "
    ".bash_login .bash_logout .bash_aliases .zshenv .zprofile .zlogin .zlogout .bash_history "
    ".zsh_history .inputrc .xprofile .xinitrc .xsession .Xauthority .vimrc .tmux.conf "
    ".gitconfig .git-credentials .netrc .pgpass "
    "Desktop Documents Downloads Music Pictures Public Templates Videos".split()
)


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
    if reserved_command_name(name):
        raise ToolError(f"{label}.name: {name!r} is reserved and cannot be a tool's command")
    if not valid_command_name(name):
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


def _python(data: dict, needed: bool, schema: int) -> PythonSpec | None:
    table = data.get("python")
    if table is None:
        if needed:
            raise ToolError("python: a python-entry or python-script command needs a [python] table")
        return None
    if not needed:
        raise ToolError("python: a [python] table is only for packages with a Python command")
    if not isinstance(table, dict):
        raise ToolError("python: must be a table")
    if schema == 1:
        versions = _strings(table, "versions", "python.versions")
        if not versions or not all(versions):
            raise ToolError("python.versions: needs at least one version")
    elif "versions" in table:
        raise ToolError(
            "python.versions: schema 2 has no versions; the wheels are for the required runtime"
        )
    else:
        versions = []
    spec = PythonSpec(versions, "", "")
    for key in ("lock", "wheels"):
        value = _relative(_text(table, key, f"python.{key}"), f"python.{key}")
        if value.split("/")[0] == "files":
            raise ToolError(f"python.{key}: {value!r} must not be under files/")
        setattr(spec, key, value)
    return spec


def _requires(data: dict, name: str, schema: int) -> list[str]:
    if "requires" not in data:
        return []
    if schema == 1:
        raise ToolError("requires: a schema 1 package cannot require anything; it needs schema 2")
    requires = _strings(data, "requires", "requires")
    seen = set()
    for wanted in requires:
        if not valid_tool_name(wanted):
            raise ToolError(f"requires: {wanted!r} is not a valid package name")
        if wanted == name:
            raise ToolError(f"requires: {name} cannot require itself")
        if wanted in seen:
            raise ToolError(f"requires: {wanted!r} appears more than once")
        seen.add(wanted)
    return requires


def _runtime(data: dict) -> RuntimeSpec:
    # a runtime is nothing but its archive: no commands, uploads, home data or wheels
    for key, table in (
        ("command", "[[command]]"),
        ("upload", "[[upload]]"),
        ("data", "[data]"),
        ("python", "[python]"),
    ):
        if key in data:
            raise ToolError(f"{key}: a runtime has no {table}")
    table = data.get("runtime")
    if table is None:
        raise ToolError("runtime: a runtime package needs a [runtime] table")
    if not isinstance(table, dict):
        raise ToolError("runtime: must be a table")
    archive = _relative(
        _text(table, "archive", "runtime.archive"), "runtime.archive", under="files"
    )
    python = _relative(_text(table, "python", "runtime.python"), "runtime.python")
    series = _text(table, "series", "runtime.series")
    if not _SERIES.fullmatch(series):
        raise ToolError(f"runtime.series: {series!r} must be a Python series such as 3.13")
    return RuntimeSpec(archive, python, series)


def parse_manifest(data: dict) -> Manifest:
    if "schema" not in data:
        # an empty or cut-short file, not one from a newer version
        raise ToolError("the manifest cannot be read (it has no schema)")
    schema = data.get("schema")
    if isinstance(schema, bool) or schema not in SCHEMAS:
        raise ToolError("schema: this package needs a newer pwn-broker; upgrade pwn-broker")
    name = _text(data, "name", "name")
    if not valid_tool_name(name):
        raise ToolError(
            f"name: {name!r} must be lower-case letters, digits, hyphens and dots, "
            "starting with a letter or digit, with no two dots together and none at the end"
        )
    version = _text(data, "version", "version")
    if not valid_version(version):
        raise ToolError(f"version: {shown(version)} {VERSION_RULE}")
    build = data.get("build")
    if not isinstance(build, int) or isinstance(build, bool) or build < 1:
        raise ToolError("build: must be a whole number of 1 or more")
    kind = data.get("kind")
    if kind not in KINDS:
        raise ToolError(f"kind: must be one of {', '.join(KINDS)}")
    needs_root = data.get("needs_root", False)
    if not isinstance(needs_root, bool):
        raise ToolError("needs_root: must be true or false")
    if kind == "runtime" and schema == 1:
        raise ToolError("kind: a runtime needs schema 2")
    requires = _requires(data, name, schema)
    runtime = None
    if kind == "runtime":
        if requires:
            raise ToolError("requires: a runtime requires nothing")
        runtime = _runtime(data)

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

    python = _python(data, any(c.type != "binary" for c in commands), schema)
    if schema == 2 and kind != "runtime":
        # schema 2 is only for what schema 1 cannot say, so published builds stay as they are
        if python is not None and len(requires) != 1:
            raise ToolError(
                f"requires: a Python tool requires exactly one runtime; this one names {len(requires)}"
            )
        if python is None and requires:
            raise ToolError("requires: a tool that is not Python requires nothing")
        if not requires:
            raise ToolError(
                "schema: a package that is not a runtime and requires nothing must be schema 1"
            )

    home_table = data.get("data", {})
    if not isinstance(home_table, dict):
        raise ToolError("data: must be a table")
    home = _strings(home_table, "home", "data.home")
    for entry in home:
        _relative(entry, "data.home")
        private = any(entry == tree or entry.startswith(tree + "/") for tree in _PRIVATE_HOME)
        if private or entry in _SHARED_HOME:
            raise ToolError(
                f"data.home: {entry!r} is shared with everything else in the home folder"
            )

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
        schema=schema,
        requires=requires,
        runtime=runtime,
    )


def _parse_text(raw: bytes, label: str) -> Manifest:
    try:
        return parse_manifest(tomllib.loads(raw.decode("utf-8")))
    except RecursionError as exc:
        raise ToolError(f"{label} cannot be read (it is nested too deeply)") from exc
    except ValueError as exc:
        # not UTF-8, not TOML, or a number too long to read
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
    if fault := too_long(name):
        raise ToolError(f"package entry {shown(name)} has a name {fault}")
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
    if bad_characters(name):
        raise ToolError(
            f"package entry {name!r} has a backslash, colon or control character in its name"
        )
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
        if info.compress_size != info.file_size:
            # a stored entry holds exactly its bytes; zipfile reads as many as the first says
            raise ToolError(f"package entry {info.filename!r} does not hold the bytes it declares")
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
    folders: set[str] = set()
    made = len(seen)
    for bare, info in seen.items():
        # a file cannot also be a folder another entry lives in
        parent = bare.rpartition("/")[0]
        while parent and parent not in folders:
            if parent in seen and not seen[parent].is_dir():
                raise ToolError(f"package entry {bare!r} sits inside the file {parent!r}")
            folders.add(parent)
            if parent not in seen:
                # counted as it is found, so the folders are never gathered beyond the limit
                made += 1
                if made > MAX_MEMBERS:
                    raise ToolError(f"package would make more than {MAX_MEMBERS} files and folders")
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
    if manifest.runtime is not None and not _is_file(seen, manifest.runtime.archive):
        raise ToolError(
            f"{manifest.runtime.archive}: the runtime's archive is missing from the package"
        )
    if manifest.python is not None:
        if not _is_file(seen, manifest.python.lock):
            raise ToolError(f"{manifest.python.lock}: the lock file is missing from the package")
        if seen[manifest.python.lock].file_size > LOCK_LIMIT:
            raise ToolError(f"{manifest.python.lock} is too large (more than {LOCK_LIMIT} bytes)")
        prefix = manifest.python.wheels + "/"
        if not any(not i.is_dir() and b.startswith(prefix) for b, i in seen.items()):
            raise ToolError(f"{manifest.python.wheels}: the package holds no wheels")


def make_folder(folder: Path) -> None:
    """Makes one folder, mode 755 whatever the umask, and at no moment looser than that."""
    folder.mkdir(mode=0o700)
    folder.chmod(0o755)


def make_folders(root: Path, parts: list[str], what: str) -> Path:
    """The folder `parts` below root, making what is missing; a link is never taken for a folder."""
    folder = root
    for part in parts:
        folder = folder / part
        try:
            found = os.lstat(folder)
        except FileNotFoundError:
            make_folder(folder)
            continue
        if not stat.S_ISDIR(found.st_mode):
            raise ToolError(f"cannot unpack {what}: {folder} is in the way and is not a folder")
    return folder


def _write_member(zf: zipfile.ZipFile, info: zipfile.ZipInfo, target: Path, mode: int) -> None:
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_BINARY", 0)
    total = 0
    with zf.open(info) as src, os.fdopen(os.open(target, flags, mode), "wb") as out:
        while chunk := src.read(_CHUNK):
            total += len(chunk)
            if total > info.file_size:
                break
            out.write(chunk)
    if total != info.file_size:
        raise ToolError(f"package entry {info.filename!r} is not the size it declares")
    target.chmod(mode)


def _make_dest(dest: Path, created: list[Path]) -> None:
    # records each folder this call makes, outermost first, so a failure removes only those
    missing = []
    for folder in (dest, *dest.parents):
        if folder.exists():
            break
        missing.append(folder)
    for folder in reversed(missing):
        folder.mkdir(mode=0o700)
        created.append(folder)
        folder.chmod(0o755)


def _clean_up(created: list[Path], dest: Path) -> None:
    for folder in reversed(created):
        if folder == dest:
            shutil.rmtree(folder, ignore_errors=True)
        else:
            try:
                folder.rmdir()
            except OSError:
                pass


def _read_package(zf: zipfile.ZipFile) -> tuple[Manifest, dict[str, zipfile.ZipInfo]]:
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
    return manifest, seen


class _Limited:
    """The zip's file, on which no one read may be larger than MAX_DIRECTORY_BYTES.

    zipfile reads the zip's list of entries in one read, of whatever size the zip says the list
    is, and builds an object for each entry before unpack can count them: a zip of nothing but
    two million entries cost 800 MiB that way. Every other read zipfile makes, or this module
    asks of it, is no larger than a manifest, a lock file or one _CHUNK.
    """

    def __init__(self, raw):
        self._raw = raw

    def read(self, size: int | None = -1) -> bytes:
        if size is None or size < 0:
            data = self._raw.read(MAX_DIRECTORY_BYTES + 1)
            if len(data) > MAX_DIRECTORY_BYTES:
                raise ToolError(_DIRECTORY_TOO_LARGE)
            return data
        if size > MAX_DIRECTORY_BYTES:
            raise ToolError(_DIRECTORY_TOO_LARGE)
        return self._raw.read(size)

    def __getattr__(self, name: str):
        return getattr(self._raw, name)


_DIRECTORY_TOO_LARGE = "the package's list of entries is larger than a package's may be"


def package_manifest(zip_path: Path) -> Manifest:
    """The manifest of a package, checked as unpack checks it, without writing anything."""
    try:
        with open(zip_path, "rb") as raw, zipfile.ZipFile(_Limited(raw)) as zf:
            return _read_package(zf)[0]
    except ToolError:
        raise
    except Exception as exc:
        raise ToolError(f"cannot read {zip_path.name}: {exc}") from exc


def unpack(zip_path: Path, dest: Path) -> Manifest:
    if os.path.lexists(dest):
        raise ToolError(f"{dest} already exists")
    created: list[Path] = []
    try:
        with open(zip_path, "rb") as raw, zipfile.ZipFile(_Limited(raw)) as zf:
            manifest, seen = _read_package(zf)
            _make_dest(dest, created)
            _extract(zf, seen, dest)
    except BaseException as exc:
        _clean_up(created, dest)
        if isinstance(exc, ToolError) or not isinstance(exc, Exception):
            raise
        raise ToolError(f"cannot unpack {zip_path.name}: {exc}") from exc
    return manifest


def _extract(zf: zipfile.ZipFile, seen: dict[str, zipfile.ZipInfo], dest: Path) -> None:
    # every folder and file gets its mode set here, as a runtime's do, whatever the umask is:
    # under a loose one, a file a launcher runs would be writable by anyone on the machine
    for bare, info in seen.items():
        parts = bare.split("/")
        if info.is_dir():
            make_folders(dest, parts, "the package")
            continue
        mode = 0o755 if parts[0] == "files" else 0o644
        _write_member(zf, info, make_folders(dest, parts[:-1], "the package") / parts[-1], mode)
