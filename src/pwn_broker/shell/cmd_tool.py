import os
import re
import shutil
from pathlib import Path

from pwn_broker import tooldata, toolhooks, toolindex, toolinstall, toolstate
from pwn_broker.session import Session, current_tunnel
from pwn_broker.shell.commands import command, take_args
from pwn_broker.toolindex import BuildEntry, Index, ToolEntry
from pwn_broker.toolpkg import MANIFEST, ToolError, build_id, read_manifest
from pwn_broker.toolstate import Installed

# tests replace this; the lookup never runs anything
_lookup = shutil.which

_PLACEHOLDER = re.compile(r"\{(ip|hostname|domain|lhost)\}")
_LABEL = 12


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


def _index(session: Session) -> Index:
    return toolindex.load_index(session.paths, session.settings, now=session.clock())


def _latest(tool: ToolEntry) -> BuildEntry | None:
    try:
        return toolindex.pick_build(tool, None)
    except ToolError:
        return None


def _outside_bin(session: Session) -> str:
    own = os.path.normcase(os.path.normpath(str(session.paths.bin)))
    kept = [
        folder
        for folder in os.environ.get("PATH", "").split(os.pathsep)
        if folder and os.path.normcase(os.path.normpath(folder)) != own
    ]
    return os.pathsep.join(kept)


def _on_kali(session: Session, commands: list[str]) -> str:
    search = _outside_bin(session)
    return "yes" if any(_lookup(name, path=search) for name in commands) else "no"


def _have(session: Session) -> set[str]:
    return {t.name for t in session.box.tools}


def _status(session: Session) -> dict[str, str]:
    # installed only when the machine has it for this box, not merely because the box records it
    try:
        here = toolstate.present(session.paths, session.box)
    except ToolError as exc:
        # the index can still be shown when the installed list cannot be read
        session.console.warn(str(exc))
        return {t.name: "unknown" for t in session.box.tools}
    return {t.name: "installed" if t.name in here else "not installed" for t in session.box.tools}


def _run_column(session: Session, item: Installed) -> str:
    if item.commands:
        return ", ".join(item.commands)
    return (session.paths.upload / item.name).as_posix()


@command("tool list", "list the tools in the index; --installed shows this box's")
def tool_list(session: Session, args: list[str]) -> None:
    (option,) = take_args(args, optional=("--installed",))
    if option is not None and option != "--installed":
        raise ValueError(f"unknown option: {option}")
    console = session.console
    status = _status(session)
    if option is None:
        rows = []
        for tool in sorted(_index(session).tools, key=lambda t: t.name):
            build = _latest(tool)
            rows.append(
                [
                    tool.name,
                    tool.latest,
                    build.kind if build else "",
                    status.get(tool.name, ""),
                    _on_kali(session, build.commands) if build else "no",
                ]
            )
        if not rows:
            console.info("no tools in the index")
            return
        console.table(["name", "version", "kind", "status", "kali"], rows)
        return

    if not session.box.tools:
        console.info(f"no tools installed for {session.box.name}")
        return
    installed = toolstate.load_installed(session.paths)
    try:
        known = {t.name: t for t in _index(session).tools}
    except ToolError:
        # the box's own tools are listed even when the index cannot be reached
        known = {}
    rows = []
    for record in sorted(session.box.tools, key=lambda r: r.name):
        item = installed.get(record.name)
        entry = known.get(record.name)
        build = _latest(entry) if entry else None
        rows.append(
            [
                record.name,
                build_id(record.version, record.build),
                build.kind if build else "",
                status[record.name],
                _on_kali(session, item.commands) if item else "no",
                _run_column(session, item) if item else "",
            ]
        )
    console.table(["name", "version", "kind", "status", "kali", "run"], rows)


@command("tool search", "search the index by name, description or tag")
def tool_search(session: Session, args: list[str]) -> None:
    if not args:
        raise ValueError("search for what? give at least one word")
    found = toolindex.search(_index(session), args)
    if not found:
        session.console.info(f"no tools match {' '.join(args)}")
        return
    status = _status(session)
    rows = []
    for tool in sorted(found, key=lambda t: t.name):
        build = _latest(tool)
        rows.append(
            [
                tool.name,
                tool.latest,
                build.kind if build else "",
                status.get(tool.name, ""),
                tool.description,
            ]
        )
    session.console.table(["name", "version", "kind", "status", "description"], rows)


def _last_domain(session: Session) -> str:
    for cred in reversed(session.creds):
        if cred.domain:
            return cred.domain
    return ""


def fill_examples(session: Session, text: str) -> str:
    target = session.current
    tunnel = current_tunnel(session)
    values = {
        "ip": target.ips[0] if target and target.ips else "",
        "hostname": target.hostnames[0] if target and target.hostnames else "",
        "domain": _last_domain(session),
        "lhost": tunnel.address if tunnel else "",
    }
    # one pass of plain replacement: a filled value is never read as a placeholder again
    return _PLACEHOLDER.sub(lambda m: values[m[1]] or f"<{m[1]}>", text)


def _line(session: Session, label: str, text: str) -> None:
    session.console.info(f"{label:<{_LABEL}}{text}")


@command("tool info", "show a tool's details, how to run it and its examples")
def tool_info(session: Session, args: list[str]) -> None:
    (name,) = take_args(args, required=("tool name",))
    index = _index(session)
    item = toolstate.load_installed(session.paths).get(name) if name in _have(session) else None
    try:
        tool = toolindex.find_tool(index, name)
    except ToolError:
        if item is None:
            raise
        session.console.warn(f"{name} is not in the index")
    else:
        build = _latest(tool)
        _line(session, "name", f"{tool.name} {tool.latest}")
        _line(session, "description", tool.description)
        _line(session, "kind", build.kind if build else "")
        _line(session, "licence", tool.licence)
        _line(session, "upstream", tool.upstream)
        _line(session, "versions", ", ".join(build_id(b.version, b.build) for b in tool.builds))
    if item is None:
        return
    paths = session.paths
    if item.commands:
        _line(session, "run", ", ".join(item.commands))
        if item.needs_root:
            for cmd in item.commands:
                _line(session, "", f"sudo {(paths.bin / cmd).as_posix()}")
    _line(session, "folder", item.folder)
    if item.uploads:
        _line(session, "upload", f"{(paths.upload / item.name).as_posix()}   {'  '.join(item.uploads)}")
    if item.home:
        _line(session, "home", "  ".join(item.home))
    if not item.folder:
        return
    try:
        manifest = read_manifest(Path(item.folder) / MANIFEST)
    except ToolError as exc:
        session.console.warn(f"the examples could not be read: {exc}")
        return
    for example in manifest.examples:
        _line(session, "example", fill_examples(session, example))


@command("tool install", "install a tool; name@version picks a version")
def tool_install(session: Session, args: list[str]) -> None:
    (spec,) = take_args(args, required=("tool name",))
    name, at, version = spec.partition("@")
    if not name or (at and not version):
        raise ValueError(f"expected <name> or <name>@<version>, not {spec}")
    box, console = session.box, session.console
    tool = toolindex.find_tool(_index(session), name)
    build = toolindex.pick_build(tool, version if at else None)
    installed = toolstate.load_installed(session.paths)
    toolinstall.check_recorded(box, build)

    wanted = build_id(build.version, build.build)
    current = installed.get(name)
    for record in box.tools:
        if (
            record.name == name
            and build_id(record.version, record.build) == wanted
            and current is not None
            and build_id(current.version, current.build) == wanted
        ):
            console.info(f"{name} {build.version} is already installed for {box.name}")
            return

    unfinished = toolstate.holding_boxes(session.paths, installed)
    unfinished[box.id] = box.name
    sharing = []
    if current is not None and current.home:
        sharing = [unfinished[u] for u in current.users if u != box.id and u in unfinished]

    zip_path = toolindex.fetch_zip(session.paths, session.settings, build)
    toolinstall.install(
        session.paths,
        box,
        build,
        zip_path,
        installed=installed,
        unfinished=unfinished,
        home=toolhooks.user_home(),
        console=console,
        now=session.clock(),
        # the app's own bin is left out, so another copy is found even once a launcher exists
        on_path=lambda cmd: _lookup(cmd, path=_outside_bin(session)),
    )
    if sharing:
        console.warn(
            f"{name} writes to the home folder and {', '.join(sharing)} also uses it; "
            "its data may hold both boxes' results"
        )


@command("tool remove", "take a tool off this box")
def tool_remove(session: Session, args: list[str]) -> None:
    (name,) = take_args(args, required=("tool name",))
    box, console = session.box, session.console
    if name not in _have(session):
        raise ToolError(f"{name} is not installed for {box.name}")
    found = toolstate.running(session.paths, tools=[name])
    if found:
        raise ToolError(toolhooks.running_text(session.paths, *found[0]))
    installed = toolstate.load_installed(session.paths)
    holding = toolstate.holding_boxes(session.paths, installed, excluding=box.id)
    item = installed.get(name)
    # the last box to let go takes the tool's home data with it, as finish does
    last = item is not None and bool(item.home) and not any(u in holding for u in item.users)
    homes = toolhooks.user_homes() if last else []
    named = tooldata.to_delete(item, homes, False) if last else []
    for path in named:
        console.info(f"home      {path}   (will be deleted)")
    if not console.confirm(f"remove {name}?"):
        console.info("nothing removed")
        return
    doomed: list[Path] = []
    if last:
        full: set[Path] = set()
        if named:
            record = next(t for t in box.tools if t.name == name)
            full = toolhooks.collect_tool(box, item, record, homes, console)
        doomed = toolhooks.home_to_delete(console, item, homes, False, full)
    gone = toolinstall.release(session.paths, box, name, installed=installed, unfinished=holding)
    tooldata.delete(doomed, homes)
    item = installed.get(name)
    if gone or item is None or not item.users:
        console.ok(f"{name} removed; its files are deleted" if gone else f"{name} removed from {box.name}")
        return
    users = [holding.get(u, "another box") for u in item.users]
    verb = "still uses" if len(users) == 1 else "still use"
    console.ok(f"{name} removed from {box.name}; {', '.join(users)} {verb} it, so its files stay")


@command("tool refresh", "fetch the tool index now")
def tool_refresh(session: Session, args: list[str]) -> None:
    take_args(args)
    index = toolindex.load_index(
        session.paths, session.settings, now=session.clock(), force=True
    )
    session.console.ok(f"index refreshed: {_count(len(index.tools), 'tool')}")


@command("tool cache clear", "empty the download cache")
def tool_cache_clear(session: Session, args: list[str]) -> None:
    take_args(args)
    if not session.console.confirm("empty the download cache?"):
        session.console.info("nothing removed")
        return
    removed = toolindex.clear_cache(session.paths)
    session.console.ok(f"{_count(removed, 'file')} removed")
