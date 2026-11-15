from collections.abc import Callable
from pathlib import Path

from pwn_broker import lifecycle, tooldata, toolindex, toolinstall, toolstate
from pwn_broker.console import Cancelled, Console
from pwn_broker.model import Box, ToolRecord
from pwn_broker.paths import AppPaths
from pwn_broker.session import Session
from pwn_broker.store import StoreError, save_box
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
    names = [t.name for t in session.box.tools]
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
    if not box.tools:
        return []
    try:
        installed = load_installed(session.paths)
    except (ToolError, OSError):
        return []
    names = ", ".join(f"{t.name} {t.version}" for t in box.tools)
    shown = [f"tools     {names}   (will be removed)"]
    try:
        unfinished = unfinished_boxes(session.paths)
        homes = user_homes()
        for record in box.tools:
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
    if not box.tools:
        return
    try:
        installed = load_installed(session.paths)
    except ToolError as exc:
        # the box's own files are fine; an export must still be written
        session.console.warn(f"tool data was not copied: {exc}")
        return
    homes = user_homes()
    for record in box.tools:
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
    toolinstall.release(session.paths, box, name, installed=installed, unfinished=unfinished)
    tooldata.delete(doomed, homes)


def undo(session: Session) -> None:
    box = session.box
    if not box.tools:
        return
    installed = load_installed(session.paths)
    # the box being finished is freed whatever its status reads at this moment
    unfinished = toolstate.holding_boxes(session.paths, installed, excluding=box.id)
    homes = user_homes()
    problems: list[str] = []
    kept_records = list(box.tools)
    try:
        for record in kept_records:
            try:
                _undo_one(session, record, installed, unfinished, homes)
            except Exception as exc:  # one tool failing must not stop the rest
                problems.append(f"{record.name}: {exc}")
    finally:
        # release drops the records; the finished box keeps them so that reopening can offer the tools
        box.tools = kept_records
        try:
            save_box(box)
        except (OSError, StoreError) as exc:
            problems.append(f"the box record could not be saved: {exc}")
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
    if not box.tools:
        return
    installed = load_installed(session.paths)
    wanted = [r for r in box.tools if _needs_install(box.id, r, installed)]
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
            zip_path = toolindex.fetch_zip(session.paths, session.settings, entry)
            toolinstall.install(
                session.paths,
                box,
                entry,
                zip_path,
                installed=installed,
                unfinished=unfinished,
                home=user_home(),
                console=console,
                now=session.clock(),
            )
        except Exception as exc:  # one tool failing must not stop the rest
            console.warn(f"{label}   {exc}")


def leftovers(paths: AppPaths, console: Console) -> None:
    try:
        installed = load_installed(paths)
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
        for item in orphans:
            try:
                toolinstall.remove_files(paths, item)
            except ToolError as exc:
                console.warn(f"{item.name}   {exc}")
                continue
            del installed[item.name]
            toolstate.save_installed(paths, installed)
            console.ok(f"removed {item.name} {item.version}")
    except Cancelled:
        pass
    except Exception as exc:  # the prompt must open whatever state the tools are in
        console.warn(f"tools left by finished boxes could not be checked: {exc}")
