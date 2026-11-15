import os
import re
import shutil
import subprocess
from collections.abc import Callable
from dataclasses import replace
from datetime import datetime
from pathlib import Path

from pwn_broker import runtimearchive, tooldata
from pwn_broker.console import Console
from pwn_broker.model import Box, RuntimeRecord, ToolRecord, current_tools
from pwn_broker.paths import AppPaths
from pwn_broker.store import save_box, write_text
from pwn_broker.toolindex import BuildEntry
from pwn_broker.toolpkg import (
    LOCK_LIMIT,
    Command,
    Manifest,
    ToolError,
    build_id,
    check_lock,
    machine_arch,
    package_manifest,
    unpack,
    valid_command_name,
    valid_tool_name,
    verify_zip,
)
from pwn_broker.toolstate import Installed, needed_runtimes, save_installed, tools_requiring

_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_MARK = "# pwn-broker tool: "
_DATA = "{data}"
_OWN_VARIABLES = ("data", "box", "run", "pid")


def runtime_refusal(name: str) -> str:
    return f"{name} is a runtime; it is installed with the tools that need it"


# ---- launchers


def sh_quote(text: str) -> str:
    if "\n" in text or "\0" in text:
        raise ToolError(f"{text!r} holds a line break or NUL and cannot go in a launcher")
    return "'" + text.replace("'", "'\\''") + "'"


def _value(text: str) -> str:
    # $data is only known to the launcher at run time, so it sits between quoted pieces
    pieces: list[str] = []
    for i, part in enumerate(text.split(_DATA)):
        if i:
            pieces.append('"$data"')
        if part:
            pieces.append(sh_quote(part))
    return "".join(pieces) or "''"


def _target(manifest_folder: Path, command: Command) -> list[str]:
    if command.type == "binary":
        return [sh_quote((manifest_folder / Path(*command.path.split("/"))).as_posix())]
    venv_bin = manifest_folder / "venv" / "bin"
    if command.type == "python-entry":
        return [sh_quote((venv_bin / command.entry).as_posix())]
    script = manifest_folder / Path(*command.script.split("/"))
    return [sh_quote((venv_bin / "python").as_posix()), sh_quote(script.as_posix())]


def launcher_text(paths: AppPaths, manifest: Manifest, command: Command, folder: Path) -> str:
    tool = manifest.name
    if not valid_tool_name(tool):
        raise ToolError(f"{tool!r} is not a valid tool name")
    uses_data = any(_DATA in v for v in command.env.values()) or any(
        _DATA in a for a in command.args
    )
    marker = f'"$run/tools/{tool}.$$"'
    # helpers are run with command -p: the app's bin comes first on PATH, and a tool's own
    # command of the same name must never be picked up in their place
    lines = [
        "#!/bin/sh",
        f"{_MARK}{tool}",
        f"run={sh_quote(paths.run.as_posix())}",
        "box=''",
        'if [ -r "$run/box" ]; then',
        '    box="$(command -p sed -n 1p "$run/box")"',
        '    pid="$(command -p sed -n 2p "$run/box")"',
        "    kill -0 \"$pid\" 2>/dev/null || box=''",
        "fi",
        # the process start time lets a later reader tell a reused process ID from this run
        # a failed redirection must not end the shell, so the whole group is silenced and forgiven
        "{ { command -p sed 's/.*) //' \"/proc/$$/stat\" | command -p cut -d' ' -f20; } "
        f"> {marker}; }} 2>/dev/null || true",
    ]
    if uses_data:
        lines += [
            "data=''",
            f'if [ -n "$box" ]; then data="$box/tooldata/{tool}"; command -p mkdir -p "$data"; fi',
        ]
    for name, value in command.env.items():
        if not _ENV_NAME.fullmatch(name) or name in _OWN_VARIABLES:
            raise ToolError(f"{name!r} is not a valid environment variable name")
        export = f"export {name}={_value(value)}"
        if _DATA in value:
            lines.append(f'if [ -n "$data" ]; then {export}; fi')
        else:
            lines.append(export)
    target = " ".join(_target(folder, command))
    if any(_DATA in a for a in command.args):
        # an option without its value would swallow the user's first argument, so with no box
        # open none of the manifest's arguments are given
        args = " ".join(_value(a) for a in command.args)
        lines.append(f'if [ -n "$data" ]; then set -- {args} "$@"; fi')
        lines.append(f'exec {target} "$@"')
    else:
        args = "".join(f" {_value(a)}" for a in command.args)
        lines.append(f'exec {target}{args} "$@"')
    return "\n".join(lines) + "\n"


# ---- helpers


def python_version(python: str, folder: Path, run=subprocess.run) -> str:
    # run as venv and pip are: from the tool's folder, isolated, with none of the caller's settings
    code = "import sys; print('%d.%d' % sys.version_info[:2])"
    try:
        result = run(
            [python, "-I", "-c", code],
            capture_output=True, text=True, cwd=str(folder), env=_clean_environment(),
        )  # fmt: skip
    except OSError as exc:
        raise ToolError(f"python3 was not found ({exc})") from exc
    if result.returncode != 0:
        raise ToolError("python3 was not found or did not run")
    version = (result.stdout or "").strip()
    if not version:
        raise ToolError("python3 could not report its version")
    return version


def _tail(result) -> str:
    text = f"{result.stdout or ''}{result.stderr or ''}"
    return "\n".join(text.strip().splitlines()[-10:])


def _clean_environment() -> dict[str, str]:
    # a PYTHONPATH or PIP_TARGET of the caller's would change what runs or where pip writes
    env = {
        k: v for k, v in os.environ.items() if not k.upper().startswith(("PYTHON", "PIP_"))
    }
    env["PIP_CONFIG_FILE"] = os.devnull  # no user or system pip configuration is read
    return env


def _run_checked(run, argv: list[str], what: str, folder: Path) -> None:
    # run from the tool's own folder: the caller's folder could hold a venv.py or a pip/
    try:
        result = run(
            argv, capture_output=True, text=True, cwd=str(folder), env=_clean_environment()
        )
    except OSError as exc:
        raise ToolError(f"{what} could not run: {exc}") from exc
    if result.returncode != 0:
        raise ToolError(f"{what} failed (exit {result.returncode}):\n{_tail(result)}")


def _inside(path: Path, root: Path, *, resolve_root: bool = True) -> bool:
    # strictly inside: the root itself does not count
    try:
        resolved = path.resolve()
        base = root.resolve() if resolve_root else root
    except (OSError, RuntimeError):
        return False
    return resolved != base and base in resolved.parents


def _check_inside(path: Path, root: Path, what: str, *, resolve_root: bool = True) -> None:
    if not _inside(path, root, resolve_root=resolve_root):
        raise ToolError(f"refusing to touch {what} {path}: it is not inside {root}")


def _delete_tree(path: Path) -> None:
    if path.is_symlink() or path.is_file():
        path.unlink()
    elif path.is_dir():
        shutil.rmtree(path)


def _show(
    paths: AppPaths, console: Console, item: Installed, version: str | None = None
) -> None:
    if version is not None:
        console.ok(f"{item.name} {version} installed")
    for command in item.commands:
        console.info(f"run   {command}   from any terminal")
    if item.needs_root:
        for command in item.commands:
            console.info(f"      sudo {(paths.bin / command).as_posix()}")
    if item.uploads:
        folder = (paths.upload / item.name).as_posix()
        console.info(f"files {folder}   {'  '.join(item.uploads)}")


def _existing(folder: Path, entries: list[str]) -> dict[str, bool]:
    return {p: os.path.lexists(folder / Path(*p.split("/"))) for p in entries}


def _sudo_lines(
    paths: AppPaths, console: Console, item: Installed, on_path: Callable[[str], str | None]
) -> None:
    # sudo searches its own folders, not PATH, so it finds the other copy, never this one
    if not item.needs_root:
        return
    for command in item.commands:
        other = on_path(command)
        if other and not _inside(Path(other), paths.bin):
            full = (paths.bin / command).as_posix()
            console.warn(f"sudo {command} runs {other}; use sudo {full}")


def _record(box: Box, record: ToolRecord) -> None:
    # the same build installed again (reopen, import) keeps its place, with this install's
    # time and runtime: the time stamps the tool's data, so an earlier install's copy is kept
    # apart from this one's. Otherwise the tool gets a new row. Removed rows stay either way.
    same = (record.name, record.version, record.build)
    if any(t.removed is None and (t.name, t.version, t.build) == same for t in box.tools):
        box.tools = [
            replace(t, installed=record.installed, runtime=record.runtime)
            if t.removed is None and (t.name, t.version, t.build) == same
            else t
            for t in box.tools
        ]
        return
    box.tools = [t for t in box.tools if t.name != record.name or t.removed is not None]
    box.tools.append(record)


def _mark_removed(box: Box, name: str, when: datetime) -> None:
    # a new row, not a change to the old one: a caller may hold the list from before
    box.tools = [
        replace(t, removed=when) if t.name == name and t.removed is None else t for t in box.tools
    ]


def _runtime_note(
    name: str, requires: list[str], runtime: Installed | None
) -> RuntimeRecord | None:
    # a tool requires at most one runtime, and must be given that one
    if not requires:
        if runtime is not None:
            raise ToolError(f"{name} requires no runtime, but was given {runtime.name}")
        return None
    wanted = f"{name} requires the runtime {requires[0]}"
    if runtime is None:
        raise ToolError(f"{wanted}, and none was given")
    if runtime.kind != "runtime":
        raise ToolError(f"{wanted}; {runtime.name} is not a runtime")
    if runtime.name != requires[0]:
        raise ToolError(f"{wanted}, not {runtime.name}")
    return RuntimeRecord(runtime.name, runtime.version, runtime.build, runtime.sha256)


# ---- install


def _ask_for(name: str, version: str, build: int, entry: BuildEntry, which: str) -> str:
    # builds change under one version, so a version alone cannot ask for the build there is
    if version != entry.version:
        return ""
    return f", or ask for the build {which}: tool install {name}@{build_id(version, build)}"


def _already_has(box: Box, name: str, version: str, build: int, entry: BuildEntry) -> ToolError:
    return ToolError(
        f"{box.name} already has {name} {build_id(version, build)}, not "
        f"{build_id(entry.version, entry.build)}; run tool remove {name} first"
        f"{_ask_for(name, version, build, entry, 'it has')}"
    )


def check_recorded(box: Box, entry: BuildEntry) -> None:
    wanted = build_id(entry.version, entry.build)
    for record in current_tools(box):
        if record.name == entry.name and build_id(record.version, record.build) != wanted:
            raise _already_has(box, entry.name, record.version, record.build, entry)


def _check_commands(installed: dict[str, Installed], name: str, commands: list[str]) -> None:
    taken = {c: t.name for t in installed.values() if t.name != name for c in t.commands}
    for command in commands:
        if command in taken:
            raise ToolError(f"the command {command} already belongs to {taken[command]}")


def check_install(
    box: Box, entry: BuildEntry, *, installed: dict[str, Installed], unfinished: dict[str, str]
) -> None:
    """Raises the error install would raise for this box before anything is fetched or written."""
    name = entry.name
    if not valid_tool_name(name):
        raise ToolError(f"{name!r} is not a valid tool name")
    current = installed.get(name)
    if entry.kind == "runtime" or (current is not None and current.kind == "runtime"):
        raise ToolError(runtime_refusal(name))
    check_recorded(box, entry)
    if current is not None:
        users = [u for u in current.users if u in unfinished]
        others = [u for u in users if u != box.id]
        if build_id(current.version, current.build) != build_id(entry.version, entry.build):
            if box.id in users:
                raise _already_has(box, name, current.version, current.build, entry)
            if others:
                raise ToolError(
                    f"{name} {build_id(current.version, current.build)} is in use by "
                    f"{unfinished[others[0]]}; finish or remove it there before installing "
                    f"{build_id(entry.version, entry.build)}"
                    f"{_ask_for(name, current.version, current.build, entry, 'in use')}"
                )
    _check_commands(installed, name, entry.commands)


def install(
    paths: AppPaths,
    box: Box,
    entry: BuildEntry,
    zip_path: Path,
    *,
    installed: dict[str, Installed],
    unfinished: dict[str, str],
    home: Path,
    console: Console,
    now: datetime,
    python: str = "python3",
    run=subprocess.run,
    on_path: Callable[[str], str | None] = shutil.which,
    runtime: Installed | None = None,
) -> Installed:
    """Installs a tool for the box. A tool that requires a runtime is given it, installed."""
    check_install(box, entry, installed=installed, unfinished=unfinished)
    name = entry.name
    current = installed.get(name)
    wanted = build_id(entry.version, entry.build)

    if current is not None:
        users = [u for u in current.users if u in unfinished]
        others = [u for u in users if u != box.id]
        same = build_id(current.version, current.build) == wanted
        if same and (others or Path(current.folder).is_dir()):
            note = _runtime_note(name, current.requires, runtime)
            joined = _join(paths, box, current, users, installed, console, now, note)
            _sudo_lines(paths, console, joined, on_path)
            return joined
        if not others:
            # nobody is using it and it is not wanted as it is: take it off first
            remove_files(paths, current)
            del installed[name]
            save_installed(paths, installed)

    folder = paths.tools / name / wanted
    _check_inside(folder, paths.tools, "the tool folder")
    uploads_dir = paths.upload / name
    _check_inside(uploads_dir, paths.upload, "the upload folder")

    made_launchers: list[Path] = []
    made_uploads = False
    saved_installed = False
    old_tools = list(box.tools)
    try:
        verify_zip(zip_path, size=entry.size, sha256=entry.sha256)
        package = package_manifest(zip_path)
        named = {c.name for c in package.commands}
        if named != set(entry.commands):
            # tool list shows what the index says, so the two must agree
            raise ToolError(
                f"the package's commands ({', '.join(sorted(named)) or 'none'}) are not the "
                f"commands the index lists ({', '.join(sorted(entry.commands)) or 'none'})"
            )
        if package.requires != list(entry.requires):
            # the caller installed the runtimes the index named, so the two must agree
            raise ToolError(
                f"the package requires {', '.join(package.requires) or 'nothing'}; "
                f"the index lists {', '.join(entry.requires) or 'nothing'}"
            )
        note = _runtime_note(name, package.requires, runtime)
        if os.path.lexists(folder):
            _delete_tree(folder)
        manifest = unpack(zip_path, folder)
        if (manifest.name, manifest.version, manifest.build) != (
            entry.name, entry.version, entry.build,
        ):  # fmt: skip
            raise ToolError(
                f"the package is {manifest.name} {manifest.version}-{manifest.build}, "
                f"not {name} {wanted}"
            )
        if manifest.arch != machine_arch():
            raise ToolError(f"{name} is built for {manifest.arch}, this machine is {machine_arch()}")
        if manifest.python is not None:
            _build_venv(manifest, folder, python, run, runtime)
        _write_launchers(paths, manifest, folder, installed, console, on_path, made_launchers)
        if manifest.uploads:
            made_uploads = True
            _copy_uploads(manifest, folder, uploads_dir)
        found = tooldata.homes(home)
        item = Installed(
            name=name,
            version=entry.version,
            build=entry.build,
            sha256=entry.sha256,
            folder=folder.resolve().as_posix(),
            commands=[c.name for c in manifest.commands],
            uploads=[u.as_name for u in manifest.uploads],
            needs_root=manifest.needs_root,
            users=[box.id],
            home=_existing(home, manifest.home),
            # root's home is only asked about when it is a different folder that can be read
            root_home=_existing(found[1], manifest.home) if len(found) > 1 else {},
            requires=list(manifest.requires),
            runtime_version=note.version if note else "",
            runtime_build=note.build if note else 0,
        )
        _record(box, ToolRecord(name, entry.version, entry.build, entry.sha256, now, note))
        installed[name] = item
        saved_installed = True  # set first: an interrupt inside the save must still be undone
        save_installed(paths, installed)
        save_box(box)
    except BaseException as exc:
        box.tools = old_tools
        installed.pop(name, None)
        for launcher in made_launchers:
            try:
                launcher.unlink()
            except OSError:
                pass
        if made_uploads:
            shutil.rmtree(uploads_dir, ignore_errors=True)
        shutil.rmtree(folder, ignore_errors=True)
        try:
            folder.parent.rmdir()
        except OSError:
            pass
        if saved_installed:
            _restore_list(paths, installed, exc)
        raise
    _show(paths, console, item, entry.version)
    _sudo_lines(paths, console, item, on_path)
    return item


def _restore_list(paths: AppPaths, installed: dict[str, Installed], cause: BaseException) -> None:
    try:
        save_installed(paths, installed)
    except OSError:
        raise ToolError(
            f"the installed list could not be restored; check {paths.tools_state}"
        ) from cause


def _join(
    paths: AppPaths,
    box: Box,
    current: Installed,
    users: list[str],
    installed: dict[str, Installed],
    console: Console,
    now: datetime,
    note: RuntimeRecord | None = None,
) -> Installed:
    old_users, old_tools = current.users, list(box.tools)
    old_runtime = (current.runtime_version, current.runtime_build)
    current.users = users if box.id in users else users + [box.id]
    if note is not None and not current.runtime_version:
        # a row from before the runtime's build was kept: the runtime it runs on now is the one
        current.runtime_version, current.runtime_build = note.version, note.build
    record = ToolRecord(current.name, current.version, current.build, current.sha256, now, note)
    _record(box, record)
    saved = False
    try:
        saved = True
        save_installed(paths, installed)
        save_box(box)
    except BaseException as exc:
        current.users, box.tools = old_users, old_tools
        current.runtime_version, current.runtime_build = old_runtime
        if saved:
            _restore_list(paths, installed, exc)
        raise
    _show(paths, console, current, current.version)
    return current


def _build_venv(
    manifest: Manifest, folder: Path, python: str, run, runtime: Installed | None
) -> None:
    spec = manifest.python
    if runtime is not None:
        # the wheels are built for the runtime's series, so there is no version to check
        python = runtime.python
    else:
        found = python_version(python, folder, run)
        if found not in spec.versions:
            raise ToolError(
                f"{manifest.name} supports Python {', '.join(spec.versions)}; "
                f"this machine has {found}"
            )
    venv = folder / "venv"
    _run_checked(
        run, [python, "-I", "-m", "venv", str(venv)], "creating the virtual environment", folder
    )
    lock = folder / Path(*spec.lock.split("/"))
    try:
        with open(lock, "rb") as fh:
            raw = fh.read(LOCK_LIMIT + 1)
    except OSError as exc:
        raise ToolError(f"cannot read {spec.lock}: {exc}") from exc
    check_lock(raw, spec.lock)  # checked again here: this is the file pip is about to read
    pip = [
        str(venv / "bin" / "python"), "-I", "-m", "pip", "--isolated", "install",
        "--no-index", "--find-links", str(folder / Path(*spec.wheels.split("/"))),
        "--only-binary", ":all:", "--require-hashes",
        "--disable-pip-version-check", "--no-input",
        "-r", str(lock),
    ]  # fmt: skip
    _run_checked(run, pip, "pip", folder)


def _write_launchers(
    paths: AppPaths,
    manifest: Manifest,
    folder: Path,
    installed: dict[str, Installed],
    console: Console,
    on_path: Callable[[str], str | None],
    made: list[Path],
) -> None:
    _check_commands(installed, manifest.name, [c.name for c in manifest.commands])
    for command in manifest.commands:
        dest = paths.bin / command.name
        _check_inside(dest, paths.bin, "a launcher")
        if os.path.lexists(dest) and not _is_ours(dest, manifest.name):
            raise ToolError(f"{dest} exists and is not a {manifest.name} launcher; not touching it")
    texts = [launcher_text(paths, manifest, c, folder) for c in manifest.commands]
    for command, text in zip(manifest.commands, texts, strict=True):
        other = on_path(command.name)
        if other and not _inside(Path(other), paths.bin):
            console.warn(f"{command.name} also exists at {other}; the installed one wins")
        dest = paths.bin / command.name
        made.append(dest)  # listed first, so a failure or interrupt in the write removes it
        write_text(dest, text)
        dest.chmod(0o755)


def _copy_uploads(manifest: Manifest, folder: Path, target: Path) -> None:
    names = [u.as_name for u in manifest.uploads]
    if len(set(names)) != len(names):
        raise ToolError("two uploads have the same name")
    if os.path.lexists(target):
        _delete_tree(target)  # a leftover; no installed tool owns it
    target.mkdir(parents=True)
    for upload in manifest.uploads:
        shutil.copy(folder / Path(*upload.path.split("/")), target / upload.as_name)


# ---- runtimes

# the folder inside a runtime's own that its archive is unpacked into
_RUNTIME_ROOT = "root"


def megabytes(size: int) -> int:
    return max(1, round(size / (1024 * 1024)))


def _check_interpreter(python: Path, root: Path, shown: str) -> None:
    # links inside the unpacked archive are followed; where they end must still be inside it
    try:
        real = python.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise ToolError(f"the runtime's interpreter {shown} is missing") from exc
    if not _inside(real, root):
        raise ToolError(f"the runtime's interpreter {shown} leads outside the runtime's folder")
    if not real.is_file():
        raise ToolError(f"the runtime's interpreter {shown} is not a regular file")


def runtime_intact(paths: AppPaths, item: Installed | None) -> bool:
    """Whether a row is a runtime whose files are in place and can be used as they are."""
    if item is None or item.kind != "runtime":
        return False
    folder = Path(item.folder)
    # the row is only believed where it points into the runtime's own place: a hand-edited
    # list must not make an install run another program
    home = paths.tools.resolve() / item.name
    if not item.python or not _inside(folder, home, resolve_root=False) or not folder.is_dir():
        return False
    try:
        _check_interpreter(Path(item.python), folder / _RUNTIME_ROOT, item.python)
    except ToolError:
        return False
    return True


def _drop_row(paths: AppPaths, installed: dict[str, Installed], name: str) -> None:
    # the list in memory must say what the file says, whether or not the save succeeds
    before = dict(installed)
    del installed[name]
    try:
        save_installed(paths, installed)
    except OSError as exc:
        installed.clear()
        installed.update(before)
        raise ToolError(
            f"the installed list could not be saved; check {paths.tools_state}"
        ) from exc


def damaged_runtime_refusal(shown: str, tools: list[str], why: str) -> str:
    """What to say when a runtime installed tools require is damaged and cannot be put back
    as the build their environments were made by. `shown` names the runtime, and its build
    when that is known."""
    if len(tools) == 1:
        needed = f"{tools[0]} requires it: remove {tools[0]} and install it again"
    else:
        needed = f"{', '.join(tools)} require it: remove them and install them again"
    return f"{shown} is missing or damaged, and {why}; {needed}"


def same_runtime_build(item: Installed, entry: BuildEntry) -> bool:
    return (item.version, item.build, item.sha256.lower()) == (
        entry.version, entry.build, entry.sha256.lower(),
    )  # fmt: skip


def install_runtime(
    paths: AppPaths,
    entry: BuildEntry,
    zip_path: Path,
    *,
    installed: dict[str, Installed],
    console: Console,
    ignoring: str | None = None,
) -> Installed:
    """Installs a runtime, or returns the one already there, at any build, unchanged.

    The row returned is the very object already in `installed` when the runtime was there, so a
    caller can tell whether this call brought it, and undo it with forget_runtime if so. A
    damaged runtime that installed tools require is only replaced by the build it was: their
    environments point into its folder. Given another build, nothing is touched. `ignoring`
    names a tool that is about to be installed afresh, so it does not count as requiring it.
    Its row stays until the new one is saved, so a failed attempt leaves it to the next.
    """
    name = entry.name
    if not valid_tool_name(name):
        raise ToolError(f"{name!r} is not a valid package name")
    if entry.kind != "runtime":
        raise ToolError(f"{name} is not a runtime")
    current = installed.get(name)
    if current is not None:
        if current.kind != "runtime":
            raise ToolError(f"{name} is installed as a tool, not a runtime")
        if runtime_intact(paths, current):
            return current
        tools = [t for t in tools_requiring(installed, name) if t != ignoring]
        if tools and not same_runtime_build(current, entry):
            why = f"{build_id(entry.version, entry.build)} is not that build"
            shown = f"{name} {build_id(current.version, current.build)}"
            raise ToolError(damaged_runtime_refusal(shown, tools, why))
        # its files are gone or damaged: whatever is left under its name goes; the row stays
        # until the new one replaces it, so a failure here leaves the next attempt the same path
        leftover = paths.tools / name
        _check_inside(leftover, paths.tools, "the runtime folder")
        try:
            if os.path.lexists(leftover):
                _delete_tree(leftover)
        except OSError as exc:
            raise ToolError(f"cannot remove {leftover}: {exc}") from exc

    folder = paths.tools / name / build_id(entry.version, entry.build)
    _check_inside(folder, paths.tools, "the runtime folder")
    saved_installed = False
    try:
        verify_zip(zip_path, size=entry.size, sha256=entry.sha256)
        if os.path.lexists(folder):
            _delete_tree(folder)
        manifest = unpack(zip_path, folder)
        if (manifest.name, manifest.version, manifest.build) != (
            entry.name, entry.version, entry.build,
        ):  # fmt: skip
            raise ToolError(
                f"the package is {manifest.name} {manifest.version}-{manifest.build}, "
                f"not {name} {build_id(entry.version, entry.build)}"
            )
        if manifest.runtime is None:
            raise ToolError(f"the package {name} is not a runtime")
        if manifest.arch != machine_arch():
            raise ToolError(f"{name} is built for {manifest.arch}, this machine is {machine_arch()}")
        archive = folder / Path(*manifest.runtime.archive.split("/"))
        root = folder / _RUNTIME_ROOT
        runtimearchive.unpack(archive, root)
        here = folder.resolve()
        python = here / _RUNTIME_ROOT / Path(*manifest.runtime.python.split("/"))
        _check_interpreter(python, here / _RUNTIME_ROOT, manifest.runtime.python)
        # unpacked, the archive is only a second copy; the zip stays in the download cache
        archive.unlink()
        item = Installed(
            name=name,
            version=entry.version,
            build=entry.build,
            sha256=entry.sha256,
            folder=here.as_posix(),
            commands=[],
            uploads=[],
            needs_root=False,
            users=[],
            home={},
            kind="runtime",
            python=python.as_posix(),
        )
        installed[name] = item
        saved_installed = True  # set first: an interrupt inside the save must still be undone
        save_installed(paths, installed)
    except BaseException as exc:
        # a stale row is put back as it was
        if current is not None:
            installed[name] = current
        else:
            installed.pop(name, None)
        shutil.rmtree(folder, ignore_errors=True)
        try:
            folder.parent.rmdir()
        except OSError:
            pass
        if saved_installed:
            _restore_list(paths, installed, exc)
        raise
    console.ok(f"{name} {entry.version} installed (runtime, {megabytes(entry.size)} MB)")
    return item


def remove_runtime(paths: AppPaths, item: Installed) -> None:
    name = item.name
    if not valid_tool_name(name):
        raise ToolError(f"{name!r} is not a valid package name")
    if item.kind != "runtime":
        raise ToolError(f"{name} is not a runtime")
    raw = Path(item.folder)
    # the root is resolved, the runtime's own folder name is not followed
    _check_inside(raw, paths.tools.resolve() / name, "the runtime folder", resolve_root=False)
    try:
        if os.path.lexists(raw):
            _delete_tree(raw)
    except OSError as exc:
        raise ToolError(f"cannot remove {raw}: {exc}") from exc
    try:
        (paths.tools / name).rmdir()
    except OSError:
        pass


def forget_runtime(paths: AppPaths, installed: dict[str, Installed], name: str) -> bool:
    """Removes a runtime and its row; returns whether it did.

    A runtime an installed tool requires is kept, files and row. If its files cannot be removed
    the row stays.
    """
    item = installed.get(name)
    if item is None or name in needed_runtimes(installed):
        return False
    remove_runtime(paths, item)
    _drop_row(paths, installed, name)
    return True


# ---- remove


def release(
    paths: AppPaths,
    box: Box,
    name: str,
    *,
    installed: dict[str, Installed],
    unfinished: dict[str, str],
    removed: datetime | None,
) -> bool:
    """Takes a tool off the box, and deletes its files when no unfinished box still uses it.

    With a time, as for tool remove, the box's row is kept and marked removed then. With None,
    as at finish, the row stays current, so that reopening the box can offer the tool again.
    """
    if removed is not None:
        _mark_removed(box, name, removed)
    item = installed.get(name)
    if item is None:
        save_box(box)
        return False
    item.users = [u for u in item.users if u in unfinished and u != box.id]
    if item.users:
        save_installed(paths, installed)
        save_box(box)
        return False
    try:
        remove_files(paths, item)
    except ToolError:
        # the entry stays, with no users, so the next launch can offer to finish the job
        save_installed(paths, installed)
        save_box(box)
        raise
    del installed[name]
    save_installed(paths, installed)
    save_box(box)
    return True


def _owner(path: Path) -> str | None:
    # the tool a launcher was written for, from its marker line; None for anything else
    if path.is_symlink() or not path.is_file():
        return None
    try:
        with open(path, "rb") as fh:
            head = fh.read(4096).split(b"\n")
    except OSError:
        return None
    mark = _MARK.encode()
    if len(head) < 2 or not head[1].startswith(mark):
        return None
    return head[1][len(mark) :].decode("utf-8", errors="replace")


def _is_ours(path: Path, name: str) -> bool:
    return _owner(path) == name


def remove_files(paths: AppPaths, item: Installed) -> None:
    name = item.name
    if not valid_tool_name(name):
        raise ToolError(f"{name!r} is not a valid tool name")
    raw = Path(item.folder)
    # the root is resolved, the tool's own folder name is not followed
    _check_inside(raw, paths.tools.resolve() / name, "the tool folder", resolve_root=False)
    launchers = []
    for command in item.commands:
        if not valid_command_name(command):
            raise ToolError(f"{command!r} is not a valid command name")
        # judged where it sits, not where a link leads: the name has no separator
        launchers.append(paths.bin / command)

    problems: list[str] = []
    for launcher in launchers:
        if not os.path.lexists(launcher):
            continue
        if not _is_ours(launcher, name):
            problems.append(f"{launcher} is not a {name} launcher and was left alone")
            continue
        try:
            launcher.unlink()
        except OSError as exc:
            problems.append(f"cannot remove {launcher}: {exc}")
    for target in (paths.upload / name, raw):
        try:
            if os.path.lexists(target):
                _delete_tree(target)
        except OSError as exc:
            problems.append(f"cannot remove {target}: {exc}")
    try:
        (paths.tools / name).rmdir()
    except OSError:
        pass
    if problems:
        raise ToolError("; ".join(problems))


# ---- files an interrupted install left behind


def _entries(folder: Path) -> list[os.DirEntry]:
    try:
        return sorted(os.scandir(folder), key=lambda e: e.name)
    except OSError:
        return []


def _real_folder(entry: os.DirEntry) -> bool:
    try:
        return entry.is_dir(follow_symlinks=False)
    except OSError:
        return False


def stray_files(paths: AppPaths, installed: dict[str, Installed]) -> list[Path]:
    """Folders and launchers the installed list does not account for. Links are never followed."""
    found: list[Path] = []
    for entry in _entries(paths.tools):
        if not _real_folder(entry):
            continue
        item = installed.get(entry.name)
        if item is None:
            found.append(Path(entry.path))
            continue
        builds = {build_id(item.version, item.build), Path(item.folder).name}
        found += [
            Path(e.path)
            for e in _entries(Path(entry.path))
            if _real_folder(e) and e.name not in builds
        ]
    # a runtime has a folder of its own under tools/, and no uploads or launchers
    tools = {name for name, item in installed.items() if item.kind != "runtime"}
    found += [
        Path(e.path) for e in _entries(paths.upload) if _real_folder(e) and e.name not in tools
    ]
    for entry in _entries(paths.bin):
        owner = _owner(Path(entry.path))
        if owner is not None and owner not in tools:
            found.append(Path(entry.path))
    return sorted(found)


def remove_stray(paths: AppPaths, path: Path) -> None:
    roots = (
        (paths.tools, "a tool folder"),
        (paths.upload, "an upload folder"),
        (paths.bin, "a launcher"),
    )
    for root, what in roots:
        if root in (path.parent, path.parent.parent):
            break
    else:
        raise ToolError(f"refusing to touch {path}: it is not inside {paths.opt}")
    _check_inside(path, root, what)
    _delete_tree(path)
