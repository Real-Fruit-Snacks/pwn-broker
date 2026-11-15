from collections.abc import Callable
from datetime import datetime
from pathlib import Path

from pwn_broker import lifecycle, tooldata, toolindex, toolinstall, toollog, toolstate
from pwn_broker.console import Cancelled, Console
from pwn_broker.model import Box, RuntimeRecord, ToolRecord, current_tools
from pwn_broker.paths import AppPaths
from pwn_broker.session import Session
from pwn_broker.store import StoreError, save_box
from pwn_broker.toolindex import BuildEntry, Index
from pwn_broker.toolpkg import ToolError, build_id
from pwn_broker.toolstate import Installed, load_installed, unfinished_boxes


def user_home() -> Path:
    return Path.home()


def register() -> None:
    for hooks, hook in (
        (lifecycle.BLOCK_HOOKS, block),
        (lifecycle.SUMMARY_HOOKS, summary),
        (lifecycle.PRE_PACK_HOOKS, pre_pack),
        (lifecycle.UNDO_HOOKS, undo),
        (lifecycle.RESTORE_HOOKS, restore),
    ):
        if hook not in hooks:
            hooks.append(hook)


def user_homes() -> list[Path]:
    return tooldata.homes(user_home())


def _others(item: Installed, box_id: str, unfinished: dict[str, str]) -> bool:
    return any(u != box_id and u in unfinished for u in item.users)


# ---- the tool log

# the key in Session.notices once the log has been found unwritable
LOG_NOTICE = "tool log"


def log_tool(
    session: Session,
    event: str,
    item: ToolRecord | Installed,
    *,
    kind: str = "tool",
    when: datetime | None = None,
) -> None:
    """Adds a line for the session's box to the tool log. A log that cannot be written never
    stops the install or removal; it is said once a session."""
    try:
        toollog.append(
            session.paths,
            when=session.clock() if when is None else when,
            event=event,
            box=session.box,
            name=item.name,
            version=item.version,
            build=item.build,
            sha256=item.sha256,
            kind=kind,
        )
    except (OSError, ValueError) as exc:
        if LOG_NOTICE not in session.notices:
            session.notices.add(LOG_NOTICE)
            # an OSError's own text names the path again
            reason = exc.strerror if isinstance(exc, OSError) and exc.strerror else exc
            session.console.warn(f"{session.paths.tool_log} could not be written: {reason}")


def release_tool(
    session: Session,
    record: ToolRecord,
    event: str,
    *,
    installed: dict[str, Installed],
    unfinished: dict[str, str],
) -> bool:
    """Takes one of the box's tools off and logs it: at remove its row is marked removed, at
    finish it stays current."""
    when = session.clock()
    box = session.box
    before = installed.get(record.name)
    held = before is not None and box.id in before.users
    try:
        return toolinstall.release(
            session.paths, box, record.name, installed=installed, unfinished=unfinished,
            removed=when if event == "remove" else None,
        )  # fmt: skip
    finally:
        # logged even when the files could not be deleted after
        if event == "remove":
            # the user took it off the box, whether or not the machine still had it
            done = all(t.name != record.name for t in current_tools(box))
        else:
            # a finish only takes off what the box held: not a tool a declined reopen left
            # uninstalled, nor one a finish before this already took off
            after = installed.get(record.name)
            done = held and (after is None or box.id not in after.users)
        if done:
            log_tool(session, event, record, when=when)


# ---- runtimes


def install_tool(
    session: Session,
    index: Index,
    entry: BuildEntry,
    *,
    installed: dict[str, Installed],
    unfinished: dict[str, str],
    **options,
) -> Installed:
    """Installs a tool for the session's box, with the runtime it requires installed first.

    A runtime already on the machine, at any build, is used as it is; otherwise the index's
    latest build is installed. A damaged one that installed tools require is installed again at
    the build it was, or refused if the index no longer lists it. If the tool then cannot be
    installed, a runtime this call brought is removed again; one that was there before is left
    alone.
    """
    paths, console = session.paths, session.console
    # a tool the box would refuse costs no download; nor does a runtime the index lacks
    toolinstall.check_install(session.box, entry, installed=installed, unfinished=unfinished)
    missing = [
        _runtime_build(index, installed, name)
        for name in entry.requires
        if not toolinstall.runtime_intact(paths, installed.get(name))
    ]
    brought: list[Installed] = []
    try:
        for runtime_entry in missing:
            before = installed.get(runtime_entry.name)
            zip_path = toolindex.fetch_zip(paths, session.settings, runtime_entry)
            item = toolinstall.install_runtime(
                paths, runtime_entry, zip_path, installed=installed, console=console
            )
            if item is not before:
                brought.append(item)
        runtime = installed.get(entry.requires[0]) if entry.requires else None
        zip_path = toolindex.fetch_zip(paths, session.settings, entry)
        tool = toolinstall.install(
            paths,
            session.box,
            entry,
            zip_path,
            installed=installed,
            unfinished=unfinished,
            home=user_home(),
            console=console,
            now=session.clock(),
            runtime=runtime,
            **options,
        )
    except BaseException:
        for item in brought:
            try:
                removed = toolinstall.forget_runtime(paths, installed, item.name)
            except Exception as exc:  # the install's own error is the one to report
                console.warn(f"{item.name} {item.version}   {exc}")
                continue
            if removed:
                console.ok(f"{item.name} {item.version} removed (runtime)")
        raise
    # nothing is logged until the tool is in: a runtime taken away again was never the box's
    for runtime_item in brought:
        log_tool(session, "install", runtime_item, kind="runtime")
    log_tool(session, "install", tool)
    return tool


def _runtime_build(index: Index, installed: dict[str, Installed], name: str) -> BuildEntry:
    # the build to install for a runtime that is not there as it should be
    current = installed.get(name)
    tools = toolstate.tools_requiring(installed, name)
    if current is None or current.kind != "runtime" or not tools:
        return toolindex.pick_build(toolindex.find_runtime(index, name), None)
    # the tools' environments point into the folder of the build they were made by
    try:
        builds = toolindex.find_runtime(index, name).builds
    except ToolError:
        builds = []
    for build in builds:
        if toolinstall.same_runtime_build(current, build):
            return build
    why = "the index no longer lists that build"
    raise ToolError(toolinstall.damaged_runtime_refusal(current, tools, why))


def _unreadable_names(paths: AppPaths) -> str:
    return ", ".join(p.split(":", 1)[0] for p in toolstate.unreadable_boxes(paths))


def remove_idle_runtimes(
    paths: AppPaths, installed: dict[str, Installed], console: Console
) -> list[Installed]:
    """Removes the runtimes no installed tool requires, and returns those it removed.

    A failure is a warn line, never raised.
    """
    idle = toolstate.idle_runtimes(installed)
    if not idle:
        return []
    # a box that cannot be read may have tools of its own, so nothing is judged unused
    unreadable = _unreadable_names(paths)
    if unreadable:
        console.warn(f"{', '.join(t.name for t in idle)} kept: {unreadable} cannot be read")
        return []
    gone = []
    for item in idle:
        try:
            removed = toolinstall.forget_runtime(paths, installed, item.name)
        except Exception as exc:  # the launch check offers it again
            console.warn(f"{item.name} {item.version}   {exc}")
            continue
        if removed:
            console.ok(f"{item.name} {item.version} removed (runtime)")
            gone.append(item)
    return gone


def _freed_runtimes(
    session: Session, installed: dict[str, Installed], holding: dict[str, str]
) -> list[Installed]:
    # the runtimes no tool will require once this box's tools are released
    box = session.box
    if toolstate.unreadable_boxes(session.paths):
        return []
    mine = {t.name for t in current_tools(box)}
    staying = {
        name: item
        for name, item in installed.items()
        if item.kind == "runtime" or name not in mine or _others(item, box.id, holding)
    }
    return toolstate.idle_runtimes(staying)


# ---- finish and export


def running_text(paths: AppPaths, tool: str, pid: int) -> str:
    marker = toolstate.mark_path(paths, tool, pid)
    return f"{tool} is still running (process {pid}); stop it first, or remove {marker} if it is not"


def block(
    session: Session,
    *,
    alive: Callable[[int], bool] | None = None,
    started: Callable[[int], str | None] | None = None,
) -> str | None:
    names = [t.name for t in current_tools(session.box)]
    if not names:
        return None
    found = toolstate.running(session.paths, names, alive=alive, started=started)
    if found:
        return running_text(session.paths, *found[0])
    try:
        load_installed(session.paths)
    except ToolError:
        return f"{session.paths.tools_state} cannot be read; fix or remove it, then finish again"
    return None


def summary(session: Session) -> list[str]:
    box = session.box
    records = current_tools(box)
    if not records:
        return []
    try:
        installed = load_installed(session.paths)
    except (ToolError, OSError):
        return []
    names = ", ".join(f"{t.name} {t.version}" for t in records)
    shown = [f"tools     {names}   (will be removed)"]
    try:
        holding = toolstate.holding_boxes(session.paths, installed, excluding=box.id)
        freed = _freed_runtimes(session, installed, holding)
    except (ToolError, OSError) as exc:
        session.console.warn(f"the runtimes to remove could not be listed: {exc}")
        freed = []
    if freed:
        runtimes = ", ".join(f"{t.name} {t.version}" for t in freed)
        shown.append(f"runtimes  {runtimes}   (will be removed)")
    try:
        unfinished = unfinished_boxes(session.paths)
        homes = user_homes()
        for record in records:
            item = installed.get(record.name)
            if item is None:
                continue
            for path in tooldata.to_delete(item, homes, _others(item, box.id, unfinished)):
                shown.append(f"home      {path}   (will be deleted)")
    except (ToolError, OSError) as exc:
        session.console.warn(f"the tool data to delete could not be listed: {exc}")
    return shown


def collect_tool(
    box: Box, item: Installed, record: ToolRecord, homes: list[Path], console: Console
) -> set[Path]:
    """Copy one tool's home data into the box; returns the home paths copied in full."""
    try:
        copied = tooldata.collect(box, item, homes, record.installed)
    except OSError as exc:
        raise ToolError(f"{record.name}: tool data could not be copied: {exc}") from exc
    if copied:
        console.ok(f"tool data {record.name}   {len(copied)} copied into the box")
    return {c.source for c in copied if c.full}


def home_to_delete(
    console: Console, item: Installed, homes: list[Path], others: bool, full: set[Path]
) -> list[Path]:
    """Warn about the home paths that stay, and return those that may be deleted."""
    name = item.name
    if item.home and tooldata.root_unchecked(user_home()):
        console.warn(f"root's home could not be checked for {name}'s data")
    for path in tooldata.kept(item, homes):
        console.warn(f"{path}   existed before {name} was installed; kept")
    doomed = []
    for path in tooldata.to_delete(item, homes, others):
        if path in full:
            doomed.append(path)
        else:
            console.warn(f"{path} was not copied in full; kept")
    return doomed


def pre_pack(session: Session) -> None:
    session.copied_in_full = set()
    box = session.box
    records = current_tools(box)
    if not records:
        return
    try:
        installed = load_installed(session.paths)
    except ToolError as exc:
        # the box's own files are fine; an export must still be written
        session.console.warn(f"tool data was not copied: {exc}")
        return
    homes = user_homes()
    for record in records:
        item = installed.get(record.name)
        if item is None:
            continue
        session.copied_in_full |= collect_tool(box, item, record, homes, session.console)


def _undo_one(
    session: Session,
    record: ToolRecord,
    installed: dict[str, Installed],
    unfinished: dict[str, str],
    homes: list[Path],
) -> None:
    box, name = session.box, record.name
    item = installed.get(name)
    doomed: list[Path] = []
    if item is not None:
        others = _others(item, box.id, unfinished)
        doomed = home_to_delete(session.console, item, homes, others, session.copied_in_full)
    release_tool(session, record, "finish", installed=installed, unfinished=unfinished)
    tooldata.delete(doomed, homes)


def undo(session: Session) -> None:
    box = session.box
    records = current_tools(box)
    if not records:
        return
    installed = load_installed(session.paths)
    # the box being finished is freed whatever its status reads at this moment
    unfinished = toolstate.holding_boxes(session.paths, installed, excluding=box.id)
    homes = user_homes()
    problems: list[str] = []
    try:
        for record in records:
            try:
                _undo_one(session, record, installed, unfinished, homes)
            except Exception as exc:  # one tool failing must not stop the rest
                problems.append(f"{record.name}: {exc}")
    finally:
        # the rows stay current: the finished box keeps them so that reopening can offer the tools
        try:
            save_box(box)
        except (OSError, StoreError) as exc:
            problems.append(f"the box record could not be saved: {exc}")
    # a runtime left behind is only a warn: the launch check offers it again
    try:
        for item in remove_idle_runtimes(session.paths, installed, session.console):
            log_tool(session, "finish", item, kind="runtime")
    except Exception as exc:
        session.console.warn(f"runtimes could not be checked: {exc}")
    if problems:
        raise ToolError("; ".join(problems))


# ---- import, reopen and launch


def _needs_install(box_id: str, record: ToolRecord, installed: dict[str, Installed]) -> bool:
    item = installed.get(record.name)
    if item is None or box_id not in item.users:
        return True
    same = build_id(item.version, item.build) == build_id(record.version, record.build)
    return not (same and Path(item.folder).is_dir())


def restore(session: Session) -> None:
    console = session.console
    try:
        _restore(session)
    except Cancelled:
        pass
    except Exception as exc:  # a box must open whatever state the tools are in
        console.warn(f"tools could not be installed again: {exc}")


def _restore(session: Session) -> None:
    box, console = session.box, session.console
    if not current_tools(box):
        return
    installed = load_installed(session.paths)
    wanted = [r for r in current_tools(box) if _needs_install(box.id, r, installed)]
    if not wanted:
        return
    console.info("tools     " + ", ".join(f"{r.name} {r.version}" for r in wanted))
    if not console.confirm("install these tools again?", default=True):
        return
    try:
        index = toolindex.load_index(session.paths, session.settings, now=session.clock())
    except ToolError as exc:
        console.warn(f"the tool index could not be loaded: {exc}")
        return
    unfinished = toolstate.holding_boxes(session.paths, installed)
    unfinished[box.id] = box.name
    for record in wanted:
        label = f"{record.name} {record.version}"
        try:
            try:
                entry = toolindex.pick_build(
                    toolindex.find_tool(index, record.name), build_id(record.version, record.build)
                )
            except ToolError:
                console.warn(f"{label}   not in the tool index; skipped")
                continue
            if entry.sha256.lower() != record.sha256.lower():
                console.warn(f"{label}   the index lists a different SHA-256 than the box; skipped")
                continue
            ran_on = record.runtime
            install_tool(session, index, entry, installed=installed, unfinished=unfinished)
            _runtime_changed(console, record.name, ran_on, installed)
        except Exception as exc:  # one tool failing must not stop the rest
            console.warn(f"{label}   {exc}")


def _runtime_changed(
    console: Console, tool: str, ran_on: RuntimeRecord | None, installed: dict[str, Installed]
) -> None:
    # any build of a runtime serves its series; the box's record now names the one it has
    now = installed.get(ran_on.name) if ran_on is not None else None
    if now is None or (now.version, now.build) == (ran_on.version, ran_on.build):
        return
    if now.version == ran_on.version:
        shown, before = build_id(now.version, now.build), build_id(ran_on.version, ran_on.build)
    else:
        shown, before = now.version, ran_on.version
    console.ok(f"{tool} now runs on {now.name} {shown}; this box used {before} before")


def leftovers(paths: AppPaths, console: Console) -> None:
    try:
        installed = load_installed(paths)
    except Exception as exc:  # the prompt must open whatever state the tools are in
        console.warn(f"tools left by finished boxes could not be checked: {exc}")
        return
    try:
        _orphans(paths, console, installed)
    except Cancelled:
        pass
    except Exception as exc:
        console.warn(f"tools left by finished boxes could not be checked: {exc}")
    try:
        _idle(paths, console, installed)
    except Cancelled:
        pass
    except Exception as exc:
        console.warn(f"runtimes no tool requires could not be checked: {exc}")
    # the installed list is the authority on what belongs; it was read, so the rest can be judged
    try:
        _strays(paths, console, installed)
    except Cancelled:
        pass
    except Exception as exc:
        console.warn(f"files left by an interrupted install could not be checked: {exc}")


def _orphans(paths: AppPaths, console: Console, installed: dict[str, Installed]) -> None:
    if not installed:
        return
    unreadable = toolstate.unreadable_boxes(paths)
    if unreadable:
        names = ", ".join(p.split(":", 1)[0] for p in unreadable)
        console.warn(f"tools left by finished boxes were not checked: {names} cannot be read")
        return
    orphans = toolstate.orphans(installed, set(unfinished_boxes(paths)))
    if not orphans:
        return
    console.info("tools     " + ", ".join(f"{t.name} {t.version}" for t in orphans))
    if not console.confirm("remove tools left by finished boxes?", default=True):
        return
    homes = user_homes()
    for item in orphans:
        try:
            toolinstall.remove_files(paths, item)
        except ToolError as exc:
            console.warn(f"{item.name}   {exc}")
            continue
        del installed[item.name]
        toolstate.save_installed(paths, installed)
        console.ok(f"removed {item.name} {item.version}")
        # nothing was copied into a box, so the tool's home data is only named
        for path in tooldata.to_delete(item, homes, False):
            console.warn(f"{path} was left by {item.name}; remove it by hand if it is not needed")


def _idle(paths: AppPaths, console: Console, installed: dict[str, Installed]) -> None:
    idle = toolstate.idle_runtimes(installed)
    # while a box cannot be read nothing is judged unused; _orphans has said so already
    if not idle or toolstate.unreadable_boxes(paths):
        return
    console.info("runtimes  " + ", ".join(f"{t.name} {t.version}" for t in idle))
    if not console.confirm("remove runtimes no installed tool requires?", default=True):
        return
    for item in idle:
        try:
            removed = toolinstall.forget_runtime(paths, installed, item.name)
        except ToolError as exc:
            console.warn(f"{item.name}   {exc}")
            continue
        if removed:
            console.ok(f"removed {item.name} {item.version} (runtime)")


def _strays(paths: AppPaths, console: Console, installed: dict[str, Installed]) -> None:
    strays = toolinstall.stray_files(paths, installed)
    if not strays:
        return
    for path in strays:
        console.info(f"left      {path}")
    if not console.confirm("remove files left by an interrupted install?", default=True):
        return
    for path in strays:
        try:
            toolinstall.remove_stray(paths, path)
        except (ToolError, OSError) as exc:
            console.warn(f"{path}   {exc}")
            continue
        console.ok(f"removed {path}")
