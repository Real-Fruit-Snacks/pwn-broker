import os
import re
import shlex
import shutil
import subprocess
from datetime import datetime
from pathlib import Path

from pwn_broker import hosts, tooldata, tooldeps, toolhooks, toolindex, toolinstall, toolstate
from pwn_broker.model import current_tools
from pwn_broker.session import Session, current_tunnel
from pwn_broker.shell.commands import ArgumentError, command, take_args
from pwn_broker.toolindex import BuildEntry, Index, ToolEntry
from pwn_broker.toolpkg import MANIFEST, ToolError, build_id, read_manifest, valid_apt_name
from pwn_broker.toolstate import Installed

# tests replace these; neither the lookup nor diagnostics runs a backend command
_lookup = shutil.which
_run = subprocess.run

_PLACEHOLDER = re.compile(r"\{(ip|hostname|domain|lhost)\}")


def _count(n: int, noun: str) -> str:
    return f"{n} {noun}" if n == 1 else f"{n} {noun}s"


def _index(session: Session) -> Index:
    return toolindex.load_index(session.paths, session.settings, now=session.clock())


def _tools(index: Index) -> list[ToolEntry]:
    # runtimes come with the tools that need them and are never shown on their own
    return [t for t in index.tools if not toolindex.is_runtime(t)]


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
    return {t.name for t in current_tools(session.box)}


def _status(session: Session) -> dict[str, str]:
    # installed only when the machine has it for this box, not merely because the box records it
    records = current_tools(session.box)
    try:
        here = toolstate.present(session.paths, session.box)
    except ToolError as exc:
        # the index can still be shown when the installed list cannot be read
        session.console.warn(str(exc))
        return {t.name: "unknown" for t in records}
    return {t.name: "installed" if t.name in here else "not installed" for t in records}


def _run_column(session: Session, item: Installed) -> str:
    if item.commands:
        return ", ".join(item.commands)
    if item.notes:
        return ":Pb <name>"
    return (session.paths.upload / item.name).as_posix()


@command("tool list", "list the tools in the index; --installed shows this box's", "[--installed]")
def tool_list(session: Session, args: list[str]) -> None:
    (option,) = take_args(args, optional=("--installed",))
    if option is not None and option != "--installed":
        raise ArgumentError(f"unknown option: {option}")
    console = session.console
    status = _status(session)
    if option is None:
        rows = []
        for tool in sorted(_tools(_index(session)), key=lambda t: t.name):
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
        # no column here is long, so none is cut
        console.table(["name", "version", "kind", "status", "kali"], rows)
        return

    records = current_tools(session.box)
    if not records:
        console.info(f"no tools installed for {session.box.name}")
        return
    installed = toolstate.load_installed(session.paths)
    try:
        known = {t.name: t for t in _index(session).tools}
    except ToolError:
        # the box's own tools are listed even when the index cannot be reached
        known = {}
    rows = []
    for record in sorted(records, key=lambda r: r.name):
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
    console.table(["name", "version", "kind", "status", "kali", "run"], rows, cut="run")


@command("tool search", "search the index by name, description or tag", "<word>...")
def tool_search(session: Session, args: list[str]) -> None:
    if not args:
        raise ArgumentError("search for what? give at least one word")
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
    session.console.table(["name", "version", "kind", "status", "description"], rows, cut="description")


def _last_domain(session: Session) -> str:
    for cred in reversed(session.creds):
        if cred.domain:
            return cred.domain
    return ""


def _plain(value: str) -> str:
    # the examples are pasted into a shell: only a plain name or an address goes in
    if hosts.valid_hostname(value) or hosts.plain_ip(value):
        return value
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
    values = {key: _plain(value) if value else "" for key, value in values.items()}
    # one pass of plain replacement: a filled value is never read as a placeholder again
    return _PLACEHOLDER.sub(lambda m: values[m[1]] or f"<{m[1]}>", text)


def _requirement(session: Session, index: Index, name: str) -> str:
    try:
        runtime = _latest(toolindex.find_runtime(index, name))
    except ToolError:
        runtime = None
    if runtime is None:
        return f"{name} (not in the index)"
    try:
        here = toolinstall.runtime_intact(
            session.paths, toolstate.load_installed(session.paths).get(name)
        )
    except ToolError:
        here = False
    state = "installed" if here else "not installed"
    return f"{name} ({toolinstall.megabytes(runtime.size)} MB, {state})"


@command("tool info", "show a tool's details, how to run it and its examples", "<name>")
def tool_info(session: Session, args: list[str]) -> None:
    (name,) = take_args(args, required=("tool name",))
    console = session.console
    index = _index(session)
    item = toolstate.load_installed(session.paths).get(name) if name in _have(session) else None
    rows: list[tuple[str, str]] = []
    try:
        tool = toolindex.find_tool(index, name)
    except ToolError:
        if item is None:
            raise
        console.warn(f"{name} is not in the index")
    else:
        build = _latest(tool)
        rows += [
            ("name", f"{tool.name} {tool.latest}"),
            ("description", tool.description),
            ("kind", build.kind if build else ""),
            ("licence", tool.licence),
            ("upstream", tool.upstream),
            ("versions", ", ".join(build_id(b.version, b.build) for b in tool.builds)),
        ]
        # the build this box has installed, or else the one an install would take
        requires = item.requires if item is not None else build.requires if build else []
        rows += [("requires", _requirement(session, index, runtime)) for runtime in requires]
    if item is None:
        console.fields(rows)
        return
    paths = session.paths
    if item.commands:
        rows.append(("run", ", ".join(item.commands)))
        if item.needs_root:
            # under the run row's value, as a row of its own
            rows += [("", f"sudo {(paths.bin / cmd).as_posix()}") for cmd in item.commands]
    rows.append(("folder", item.folder))
    if item.uploads:
        rows.append(("upload", f"{(paths.upload / item.name).as_posix()}   {'  '.join(item.uploads)}"))
    if item.home:
        rows.append(("home", "  ".join(item.home)))
    problem = None
    if item.folder:
        try:
            manifest = read_manifest(Path(item.folder) / MANIFEST)
        except ToolError as exc:
            problem = f"the examples could not be read: {exc}"
        else:
            rows += [("example", fill_examples(session, example)) for example in manifest.examples]
    # one list, so every value starts in the same column
    console.fields(rows)
    if problem is not None:
        console.warn(problem)


def _backend_command(session: Session, commands: list[str]) -> str | None:
    # A pwn-shop launcher and a Kali executable both make a backend available to the tool.
    folders = [str(session.paths.bin), _outside_bin(session)]
    search = os.pathsep.join(folder for folder in folders if folder)
    for command in commands:
        found = _lookup(command, path=search)
        if found:
            return found
    return None


def _apt_backends(session: Session, entry: BuildEntry) -> list[tuple[str, list[str]]]:
    # Package-backed backends always use pwn-shop, even if a manifest also names apt packages.
    return [
        (backend.name, list(backend.apt))
        for backend in entry.backends
        if not backend.package
        and backend.apt
        and _backend_command(session, backend.commands) is None
    ]


# What the simulation and the install are both given: no recommended packages, and each name
# taken as one package's own name. Without Pattern-Only, apt-get takes a name with a dot that
# no package has as a regular expression and installs whatever matches it.
_APT_INSTALL = ("apt-get", "install", "--no-install-recommends", "-o", "APT::Cmd::Pattern-Only=true")
# a package's own set-up questions take their defaults too
_APT_QUIET = {"DEBIAN_FRONTEND": "noninteractive"}
# a step of the plan apt-get --simulate prints: "Inst nmap (7.95 ...)" for a new package,
# "Inst nmap [7.94] (7.95 ...)" for one it upgrades, "Remv" or "Purg" for one it takes off
_APT_STEP = re.compile(r"(Inst|Remv|Purg) (\S+)( \[)?")
_APT_ROW = 64


def _apt_tail(result) -> str:
    output = f"{result.stdout or ''}{result.stderr or ''}".strip()
    return "\n".join(output.splitlines()[-10:])


def _run_apt(argv: list[str], env: dict[str, str]):
    # apt-get is never left to ask: with its output captured, its question would be a hang.
    # sudo still asks for a password, on the terminal itself.
    try:
        return _run(
            argv, capture_output=True, text=True, stdin=subprocess.DEVNULL,
            env={**os.environ, **env},
        )  # fmt: skip
    except OSError as exc:
        raise ToolError(f"apt-get could not run: {exc}") from exc


def _apt_plan(packages: list[str]) -> tuple[list[str], list[str], list[str]]:
    """What apt-get would install, upgrade and remove for these packages, by its own account:
    a simulation, which needs no root and changes nothing."""
    result = _run_apt([*_APT_INSTALL, "--simulate", "--", *packages], {"LC_ALL": "C"})
    if result.returncode:
        raise ToolError(
            f"apt-get could not plan the install (exit {result.returncode}):\n{_apt_tail(result)}"
        )
    installs, upgrades, removes = [], [], []
    for line in (result.stdout or "").splitlines():
        step = _APT_STEP.match(line)
        if step is None:
            continue
        if step[1] != "Inst":
            removes.append(step[2])
        elif step[3]:
            upgrades.append(step[2])
        else:
            installs.append(step[2])
    return sorted(installs), sorted(upgrades), sorted(removes)


def _apt_rows(label: str, names: list[str]) -> list[tuple[str, str]]:
    # the label once; a long list goes over several rows and never breaks inside a name. A
    # row that is not the last ends with its comma, so the list reads on
    rows: list[str] = []
    for name in names:
        if rows and len(rows[-1]) + len(name) + 3 <= _APT_ROW:
            rows[-1] += f", {name}"
        else:
            rows.append(name)
    last = len(rows) - 1
    return [
        (label if n == 0 else "", row if n == last else f"{row},") for n, row in enumerate(rows)
    ]


def _install_apt(session: Session, entry: BuildEntry) -> None:
    missing = _apt_backends(session, entry)
    if not missing:
        return
    console = session.console
    packages = list(dict.fromkeys(package for _name, rows in missing for package in rows))
    for package in packages:
        # judged again where it is used: an entry can be built without the index's own check
        if not valid_apt_name(package):
            raise ToolError(f"{package!r} is not a Debian package name")
    backends = [("backend", f"{name}: apt {', '.join(rows)}") for name, rows in missing]
    installs, upgrades, removes = _apt_plan(packages)
    if removes:
        # an install that takes packages off the system is not what was asked for
        console.fields(backends + _apt_rows("removes", removes))
        console.warn(
            f"apt would remove {_count(len(removes), 'package')} to install these; "
            "apt-backed backends were not installed"
        )
        return
    if not installs and not upgrades:
        console.fields(backends)
        console.warn(
            f"apt has nothing to install for these; tool doctor {entry.name} shows what is missing"
        )
        return
    # --no-remove: should the system change between the plan and the run, apt-get stops
    # rather than remove what the plan did not show. --force-confold: a settings file edited
    # on this machine is kept as it is, which dpkg would otherwise stop to ask about
    argv = [
        *_APT_INSTALL, "-y", "--no-remove", "-o", "Dpkg::Options::=--force-confold",
        "--", *packages,
    ]  # fmt: skip
    quiet = " ".join(f"{name}={value}" for name, value in _APT_QUIET.items())
    if getattr(os, "geteuid", lambda: 1)() != 0:
        # given to sudo as well, which hands a clean environment to what it runs
        argv = ["sudo", quiet, *argv]
        shown = shlex.join(argv)
    else:
        shown = f"{quiet} {shlex.join(argv)}"
    console.fields(
        backends
        + _apt_rows("installs", installs)
        + _apt_rows("upgrades", upgrades)
        + [("command", shown)]
    )
    asked = []
    if installs:
        asked.append(f"install {_count(len(installs), 'apt package')}")
    if upgrades:
        count = len(upgrades) if installs else _count(len(upgrades), "apt package")
        asked.append(f"upgrade {count}")
    if not console.confirm(f"{' and '.join(asked)} for {entry.name}?"):
        console.warn("apt-backed backends were not installed")
        return
    console.info("apt is installing them; nothing more shows until it ends")
    result = _run_apt(argv, _APT_QUIET)
    if result.returncode:
        raise ToolError(f"apt-get failed (exit {result.returncode}):\n{_apt_tail(result)}")
    console.ok(f"installed with apt: {', '.join(packages)}")
    # Apt packages are system-owned. A later pwn-shop failure never rolls them back.


@command("tool doctor", "show a tool's backend commands and enabled features", "<name>")
def tool_doctor(session: Session, args: list[str]) -> None:
    (name,) = take_args(args, required=("tool name",))
    index = _index(session)
    tool = toolindex.find_tool(index, name)
    installed = toolstate.load_installed(session.paths)
    item = installed.get(name) if name in _have(session) else None
    wanted = build_id(item.version, item.build) if item is not None else ""
    build = next((b for b in tool.builds if build_id(b.version, b.build) == wanted), None)
    if build is None:
        build = toolindex.pick_build(tool, None)
    rows = [
        ("name", f"{name} {build.version}-{build.build}"),
        ("runtime", ", ".join(build.requires) or "none"),
        ("depends", ", ".join(build.depends) or "none"),
    ]
    # the backends this box selected with --full, not what another box chose for the same tool
    record = next((t for t in current_tools(session.box) if t.name == name), None)
    chosen = tooldeps.selected(record, item) if record is not None else []
    if chosen:
        rows.append(("optional", ", ".join(chosen)))
    session.console.fields(rows)
    if not build.backends:
        session.console.info("no optional backends declared")
        return
    table = []
    for backend in build.backends:
        found = _backend_command(session, backend.commands)
        provider = f"pwn-shop: {backend.package}" if backend.package else f"apt: {', '.join(backend.apt)}"
        table.append(
            [
                backend.name,
                "enabled" if found else "missing",
                found or " or ".join(backend.commands),
                provider,
                backend.description if found else "not enabled",
            ]
        )
    session.console.table(["backend", "status", "command", "provider", "feature"], table, cut="feature")


@command(
    "tool install", "install a tool; name@version picks a version; --full adds backends",
    "<name>[@<version>[-<build>]] [--full]",
)
def tool_install(session: Session, args: list[str]) -> None:
    spec, option = take_args(args, required=("tool name",), optional=("--full",))
    if option is not None and option != "--full":
        raise ArgumentError(f"unknown option: {option}")
    full = option == "--full"
    name, at, version = spec.partition("@")
    if not name or (at and not version):
        raise ValueError(f"expected <name> or <name>@<version>, not {spec}")
    box, console = session.box, session.console
    index = _index(session)
    tool = toolindex.find_tool(index, name)
    if toolindex.is_runtime(tool):
        raise ToolError(toolinstall.runtime_refusal(name))
    build = toolindex.pick_build(tool, version if at else None)
    installed = toolstate.load_installed(session.paths)
    toolinstall.check_recorded(box, build)

    wanted = build_id(build.version, build.build)
    current = installed.get(name)
    already = False
    for record in current_tools(box):
        if (
            record.name == name
            and build_id(record.version, record.build) == wanted
            and current is not None
            and build_id(current.version, current.build) == wanted
        ):
            already = True
            if not full and not record.dependency:
                console.info(f"{name} {build.version} is already installed for {box.name}")
                return

    unfinished = toolstate.holding_boxes(session.paths, installed)
    unfinished[box.id] = box.name
    sharing = []
    if current is not None and current.home:
        sharing = [unfinished[u] for u in current.users if u != box.id and u in unfinished]

    toolhooks.install_tool(
        session,
        index,
        build,
        installed=installed,
        unfinished=unfinished,
        full=full,
        before_download=(lambda: _install_apt(session, build)) if full else None,
        # the app's own bin is left out, so another copy is found even once a launcher exists
        on_path=lambda cmd: _lookup(cmd, path=_outside_bin(session)),
    )
    if full and already:
        console.info(f"{name} {build.version} dependency and backend check complete")
    if sharing:
        console.warn(
            f"{name} writes to the home folder and {', '.join(sharing)} also uses it; "
            "its data may hold both boxes' results"
        )


@command("tool remove", "take a tool off this box, with its orphaned dependencies", "<name>")
def tool_remove(session: Session, args: list[str]) -> None:
    (name,) = take_args(args, required=("tool name",))
    box, console = session.box, session.console
    if name not in _have(session):
        if _is_runtime_name(session, name):
            raise ToolError(toolinstall.runtime_refusal(name))
        raise ToolError(f"{name} is not installed for {box.name}")
    installed = toolstate.load_installed(session.paths)
    parents = tooldeps.parents(box, installed, name)
    if parents:
        raise ToolError(f"{name} is required by {', '.join(parents)}; remove the parent first")
    names = [name, *tooldeps.orphaned(box, installed, {name})]
    found = toolstate.running(session.paths, tools=names)
    if found:
        raise ToolError(toolhooks.running_text(session.paths, *found[0]))
    holding = toolstate.holding_boxes(session.paths, installed, excluding=box.id)
    plans = []
    for tool_name in names:
        item = installed.get(tool_name)
        record = next(t for t in current_tools(box) if t.name == tool_name)
        # the last box to let go takes the tool's home data with it, as finish does
        last = item is not None and bool(item.home) and not any(u in holding for u in item.users)
        homes = toolhooks.user_homes() if last else []
        named = tooldata.to_delete(item, homes, False) if last else []
        plans.append((record, item, homes, named))
    if len(names) > 1:
        console.info(f"automatic dependencies no longer needed: {', '.join(names[1:])}")
    console.fields(
        [("home", f"{path}   (will be deleted)") for _r, _i, _h, named in plans for path in named]
    )
    if not console.confirm(f"remove {name}?"):
        console.info("nothing removed")
        return
    required: set[str] = set()
    for record, item, homes, named in plans:
        tool_name = record.name
        doomed: list[Path] = []
        if homes:
            collected: set[Path] = set()
            if named:
                collected = toolhooks.collect_tool(box, item, record, homes, console)
            doomed = toolhooks.home_to_delete(console, item, homes, False, collected)
        gone = toolhooks.release_tool(
            session, record, "remove", installed=installed, unfinished=holding
        )
        tooldata.delete(doomed, homes)
        if item is not None:
            required.update(item.requires)
        after = installed.get(tool_name)
        if gone or after is None or not after.users:
            console.ok(
                f"{tool_name} removed; its files are deleted" if gone
                else f"{tool_name} removed from {box.name}"
            )
        else:
            users = [holding.get(u, "another box") for u in after.users]
            verb = "still uses" if len(users) == 1 else "still use"
            console.ok(
                f"{tool_name} removed from {box.name}; {', '.join(users)} {verb} it, "
                "so its files stay"
            )
    for runtime in toolhooks.remove_idle_runtimes(session.paths, installed, console):
        if runtime.name in required:
            toolhooks.log_tool(session, "remove", runtime, kind="runtime")


def _shown_time(session: Session, when: datetime) -> str:
    return when.astimezone(session.clock().tzinfo).strftime("%Y-%m-%d %H:%M")


@command("tool history", "list every tool this box has had, removed ones too")
def tool_history(session: Session, args: list[str]) -> None:
    take_args(args)
    box = session.box
    if not box.tools:
        session.console.info(f"no tools were installed for {box.name}")
        return
    rows = []
    # astimezone gives every time an offset, so a row written without one still sorts
    for record in sorted(box.tools, key=lambda r: r.installed.astimezone()):
        ran_on = record.runtime
        rows.append(
            [
                record.name,
                build_id(record.version, record.build),
                _shown_time(session, record.installed),
                _shown_time(session, record.removed) if record.removed else "-",
                f"{ran_on.name} {build_id(ran_on.version, ran_on.build)}" if ran_on else "-",
            ]
        )
    session.console.table(["tool", "version", "installed", "removed", "runtime"], rows)


def _is_runtime_name(session: Session, name: str) -> bool:
    # only asked once the box is known not to have the name, so a failed lookup means no
    try:
        item = toolstate.load_installed(session.paths).get(name)
    except ToolError:
        item = None
    if item is not None:
        return item.kind == "runtime"
    try:
        toolindex.find_runtime(_index(session), name)
    except ToolError:
        return False
    return True


@command("tool refresh", "fetch the tool index now")
def tool_refresh(session: Session, args: list[str]) -> None:
    take_args(args)
    index = toolindex.load_index(
        session.paths, session.settings, now=session.clock(), force=True
    )
    session.console.ok(f"index refreshed: {_count(len(_tools(index)), 'tool')}")


@command("tool cache clear", "empty the download cache")
def tool_cache_clear(session: Session, args: list[str]) -> None:
    take_args(args)
    if not session.console.confirm("empty the download cache?"):
        session.console.info("nothing removed")
        return
    removed = toolindex.clear_cache(session.paths)
    session.console.ok(f"{_count(removed, 'file')} removed")
