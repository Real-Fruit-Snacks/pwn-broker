from collections.abc import Callable
from pathlib import Path

from pwn_broker import lifecycle, tooldata, toolindex, toolinstall, toolstate
from pwn_broker.console import Cancelled, Console
from pwn_broker.model import ToolRecord
from pwn_broker.paths import AppPaths
from pwn_broker.session import Session
from pwn_broker.toolpkg import ToolError, build_id
from pwn_broker.toolstate import Installed, load_installed, unfinished_boxes


def _user_home() -> Path:
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


def _homes() -> list[Path]:
    return tooldata.homes(_user_home())


def _others(item: Installed, box_id: str, unfinished: dict[str, str]) -> bool:
    return any(u != box_id and u in unfinished for u in item.users)


# ---- finish and export


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
    if not found:
        return None
    tool, pid = found[0]
    return f"{tool} is still running (process {pid}); stop it first"


def summary(session: Session) -> list[str]:
    box = session.box
    if not box.tools:
        return []
    names = ", ".join(f"{t.name} {t.version}" for t in box.tools)
    shown = [f"tools     {names}   (will be removed)"]
    try:
        installed = load_installed(session.paths)
        unfinished = unfinished_boxes(session.paths)
        homes = _homes()
        for record in box.tools:
            item = installed.get(record.name)
            if item is None:
                continue
            for path in tooldata.to_delete(item, homes, _others(item, box.id, unfinished)):
                shown.append(f"home      {path}   (will be deleted)")
    except (ToolError, OSError) as exc:
        session.console.warn(f"the tool data to delete could not be listed: {exc}")
    return shown


def pre_pack(session: Session) -> None:
    box = session.box
    if not box.tools:
        return
    installed = load_installed(session.paths)
    homes = _homes()
    for record in box.tools:
        item = installed.get(record.name)
        if item is None:
            continue
        try:
            copied = tooldata.collect(box, item, homes)
        except ToolError:
            raise
        except OSError as exc:
            raise ToolError(f"{record.name}: tool data could not be copied: {exc}") from exc
        if copied:
            session.console.ok(f"tool data {record.name}   {len(copied)} copied into the box")


def undo(session: Session) -> None:
    box = session.box
    if not box.tools:
        return
    installed = load_installed(session.paths)
    unfinished = unfinished_boxes(session.paths)
    # the box being finished is freed whatever its status reads at this moment
    unfinished.pop(box.id, None)
    homes = _homes()
    problems: list[str] = []
    for record in list(box.tools):
        name = record.name
        item = installed.get(name)
        doomed: list[Path] = []
        if item is not None:
            try:
                doomed = tooldata.to_delete(item, homes, _others(item, box.id, unfinished))
                for path in tooldata.kept(item, homes):
                    session.console.warn(f"{path}   existed before {name} was installed; kept")
            except (ToolError, OSError) as exc:
                problems.append(f"{name}: {exc}")
                continue
        try:
            toolinstall.release(
                session.paths, box, name, installed=installed, unfinished=unfinished
            )
            tooldata.delete(doomed, homes)
        except (ToolError, OSError) as exc:
            problems.append(f"{name}: {exc}")
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
    except Exception as exc:  # a box must always open
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
    unfinished = unfinished_boxes(session.paths)
    unfinished[box.id] = box.name
    for record in wanted:
        label = f"{record.name} {record.version}"
        try:
            entry = next(
                (
                    b
                    for tool in index.tools
                    if tool.name == record.name
                    for b in tool.builds
                    if (b.version, b.build) == (record.version, record.build)
                ),
                None,
            )
            if entry is None:
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
                home=_user_home(),
                console=console,
                now=session.clock(),
            )
        except Exception as exc:
            console.warn(f"{label}   {exc}")


def leftovers(paths: AppPaths, console: Console) -> None:
    try:
        installed = load_installed(paths)
        if not installed:
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
    except Exception as exc:  # the prompt must still open
        console.warn(f"tools left by finished boxes could not be checked: {exc}")
