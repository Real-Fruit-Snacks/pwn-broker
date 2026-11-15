import os
import re
import shutil
import subprocess
from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from pwn_broker.console import Console
from pwn_broker.model import Box, ToolRecord
from pwn_broker.paths import AppPaths
from pwn_broker.store import save_box, write_text
from pwn_broker.toolindex import BuildEntry
from pwn_broker.toolpkg import (
    Command,
    Manifest,
    ToolError,
    build_id,
    machine_arch,
    unpack,
    valid_command_name,
    valid_tool_name,
    verify_zip,
)
from pwn_broker.toolstate import Installed, save_installed

_ENV_NAME = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")
_MARK = "# pwn-broker tool: "
_DATA = "{data}"
_OWN_VARIABLES = ("data", "box", "run", "pid")


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
    lines = [
        "#!/bin/sh",
        f"{_MARK}{tool}",
        f"run={sh_quote(paths.run.as_posix())}",
        "box=''",
        'if [ -r "$run/box" ]; then',
        '    box="$(sed -n 1p "$run/box")"',
        '    pid="$(sed -n 2p "$run/box")"',
        "    kill -0 \"$pid\" 2>/dev/null || box=''",
        "fi",
        # the process start time lets a later reader tell a reused process ID from this run
        # a failed redirection must not end the shell, so the whole group is silenced and forgiven
        "{ { sed 's/.*) //' \"/proc/$$/stat\" | cut -d' ' -f20; } > "
        f"{marker}; }} 2>/dev/null || true",
    ]
    if uses_data:
        lines += [
            "data=''",
            f'if [ -n "$box" ]; then data="$box/tooldata/{tool}"; mkdir -p "$data"; fi',
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
        # arguments go in front of the user's own, last one first
        for arg in reversed(command.args):
            setter = f'set -- {_value(arg)} "$@"'
            lines.append(f'if [ -n "$data" ]; then {setter}; fi' if _DATA in arg else setter)
        lines.append(f'exec {target} "$@"')
    else:
        args = "".join(f" {_value(a)}" for a in command.args)
        lines.append(f'exec {target}{args} "$@"')
    return "\n".join(lines) + "\n"


# ---- helpers


def python_version(python: str, run=subprocess.run) -> str:
    code = "import sys; print('%d.%d' % sys.version_info[:2])"
    try:
        result = run([python, "-c", code], capture_output=True, text=True)
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


def _run_checked(run, argv: list[str], what: str) -> None:
    try:
        result = run(argv, capture_output=True, text=True)
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


def _record(box: Box, record: ToolRecord) -> None:
    box.tools = [t for t in box.tools if t.name != record.name] + [record]


# ---- install


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
) -> Installed:
    name = entry.name
    if not valid_tool_name(name):
        raise ToolError(f"{name!r} is not a valid tool name")
    wanted = build_id(entry.version, entry.build)

    for record in box.tools:
        if record.name == name and build_id(record.version, record.build) != wanted:
            raise ToolError(
                f"{box.name} already has {name} {build_id(record.version, record.build)}; "
                f"run tool remove {name} first"
            )

    current = installed.get(name)
    if current is not None:
        users = [u for u in current.users if u in unfinished]
        others = [u for u in users if u != box.id]
        same = build_id(current.version, current.build) == wanted
        if box.id in users and not same:
            raise ToolError(
                f"{box.name} already has {name} {current.version}; run tool remove {name} first"
            )
        if others and not same:
            raise ToolError(
                f"{name} {current.version} is in use by {unfinished[others[0]]}; "
                f"finish or remove it there before installing {entry.version}"
            )
        if same and (others or Path(current.folder).is_dir()):
            return _join(paths, box, current, users, installed, console, now)
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
            _build_venv(manifest, folder, python, run)
        _write_launchers(paths, manifest, folder, installed, console, on_path, made_launchers)
        if manifest.uploads:
            made_uploads = True
            _copy_uploads(manifest, folder, uploads_dir)
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
            home={p: os.path.lexists(home / Path(*p.split("/"))) for p in manifest.home},
        )
        _record(box, ToolRecord(name, entry.version, entry.build, entry.sha256, now))
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
) -> Installed:
    old_users, old_tools = current.users, list(box.tools)
    current.users = users if box.id in users else users + [box.id]
    _record(box, ToolRecord(current.name, current.version, current.build, current.sha256, now))
    saved = False
    try:
        saved = True
        save_installed(paths, installed)
        save_box(box)
    except BaseException as exc:
        current.users, box.tools = old_users, old_tools
        if saved:
            _restore_list(paths, installed, exc)
        raise
    _show(paths, console, current, current.version)
    return current


def _build_venv(manifest: Manifest, folder: Path, python: str, run) -> None:
    spec = manifest.python
    found = python_version(python, run)
    if found not in spec.versions:
        raise ToolError(
            f"{manifest.name} supports Python {', '.join(spec.versions)}; this machine has {found}"
        )
    venv = folder / "venv"
    _run_checked(run, [python, "-m", "venv", str(venv)], "creating the virtual environment")
    pip = [
        str(venv / "bin" / "python"), "-m", "pip", "install",
        "--no-index", "--find-links", str(folder / Path(*spec.wheels.split("/"))),
        "--only-binary", ":all:", "--require-hashes",
        "--disable-pip-version-check", "--no-input",
        "-r", str(folder / Path(*spec.lock.split("/"))),
    ]  # fmt: skip
    _run_checked(run, pip, "pip")


def _write_launchers(
    paths: AppPaths,
    manifest: Manifest,
    folder: Path,
    installed: dict[str, Installed],
    console: Console,
    on_path: Callable[[str], str | None],
    made: list[Path],
) -> None:
    taken = {
        c: t.name for t in installed.values() if t.name != manifest.name for c in t.commands
    }
    for command in manifest.commands:
        if command.name in taken:
            raise ToolError(f"the command {command.name} already belongs to {taken[command.name]}")
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


# ---- remove


def release(
    paths: AppPaths,
    box: Box,
    name: str,
    *,
    installed: dict[str, Installed],
    unfinished: dict[str, str],
) -> bool:
    box.tools = [t for t in box.tools if t.name != name]
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


def _is_ours(path: Path, name: str) -> bool:
    if path.is_symlink() or not path.is_file():
        return False
    try:
        with open(path, "rb") as fh:
            head = fh.read(4096).split(b"\n")
    except OSError:
        return False
    return len(head) > 1 and head[1] == f"{_MARK}{name}".encode()


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
