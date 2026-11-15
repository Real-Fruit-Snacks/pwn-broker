import ipaddress
import os
import shutil
import sys
import uuid
from collections.abc import Callable
from datetime import date, datetime
from pathlib import Path

from pwn_broker.model import Box, Target
from pwn_broker.paths import AppPaths, box_folder_name, safe_name
from pwn_broker.store import (
    SCHEMA,
    StoreError,
    load_box,
    load_creds,
    load_files,
    read_toml,
    save_box,
    save_creds,
    save_files,
    save_target,
    write_toml,
)

TARGET_FOLDERS = ("creds", "files", "loot", "scans", "exploits", "screenshots", "recordings")
SCOPES = ("external", "internal")


class BoxError(Exception):
    pass


def _new_id() -> str:
    return str(uuid.uuid4())


def create_box(
    paths: AppPaths,
    *,
    name: str,
    platform: str,
    day: date,
    os_name: str,
    difficulty: str,
    now: datetime,
    new_id: Callable[[], str] = _new_id,
) -> Box:
    try:
        base = box_folder_name(day, platform, name)
    except ValueError as exc:
        raise BoxError(str(exc)) from exc
    folder = paths.active / base
    suffix = 2
    while folder.exists():
        folder = paths.active / f"{base}-{suffix}"
        suffix += 1
    started = now if day == now.date() else now.replace(year=day.year, month=day.month, day=day.day)
    box = Box(
        id=new_id(),
        name=name,
        platform=platform,
        os=os_name,
        difficulty=difficulty,
        status="active",
        started=started,
        finished=None,
        last_target=None,
        flags={},
        extra={},
        path=folder,
    )
    for sub in ("lists", "screenshots", "targets"):
        (folder / sub).mkdir(parents=True)
    save_box(box)
    return box


def list_boxes(paths: AppPaths) -> tuple[list[Box], list[str]]:
    boxes: list[Box] = []
    problems: list[str] = []
    if not paths.active.is_dir():
        return boxes, problems
    for folder in sorted(paths.active.iterdir()):
        if folder.name.startswith(".") or not folder.is_dir():
            continue
        try:
            boxes.append(load_box(folder))
        except StoreError as exc:
            problems.append(f"{folder.name}: {exc}")
    boxes.sort(key=lambda b: b.started)
    return boxes, problems


def parse_values(text: str) -> list[str]:
    return text.split()


def _validate(ips: list[str], hostnames: list[str], scope: str) -> None:
    if not ips and not hostnames:
        raise BoxError("a target needs at least one IP address or hostname")
    for ip in ips:
        try:
            ipaddress.ip_address(ip)
        except ValueError as exc:
            raise BoxError(f"not an IP address: {ip}") from exc
    if scope not in SCOPES:
        raise BoxError(f"scope must be external or internal, not {scope}")


def _safe_target_name(text: str) -> str:
    try:
        return safe_name(text)
    except ValueError as exc:
        raise BoxError(str(exc)) from exc


def add_target(
    box: Box,
    targets: list[Target],
    *,
    ips: list[str],
    hostnames: list[str],
    scope: str,
    name: str | None,
    now: datetime,
) -> Target:
    _validate(ips, hostnames, scope)
    name = _safe_target_name(name if name else (hostnames or ips)[0])
    if any(t.name == name for t in targets):
        raise BoxError(f"a target named {name} already exists")
    target = Target(
        box_id=box.id,
        box=box.name,
        name=name,
        ips=list(ips),
        hostnames=list(hostnames),
        scope=scope,
        added=now,
    )
    folder = box.path / "targets" / name
    for sub in TARGET_FOLDERS:
        (folder / sub).mkdir(parents=True, exist_ok=True)
    save_target(box, target)
    targets.append(target)
    return target


def edit_target(
    box: Box, targets: list[Target], name: str, *, ips: list[str], hostnames: list[str], scope: str
) -> Target:
    target = find_target(targets, name)
    _validate(ips, hostnames, scope)
    target.ips = list(ips)
    target.hostnames = list(hostnames)
    target.scope = scope
    save_target(box, target)
    return target


def rename_target(box: Box, targets: list[Target], old: str, new: str) -> Target:
    target = find_target(targets, old)
    new = _safe_target_name(new)
    if new == target.name:
        return target
    if any(t.name == new for t in targets):
        raise BoxError(f"a target named {new} already exists")
    old = target.name
    base = box.path / "targets"
    (base / old).rename(base / new)
    target.name = new
    save_target(box, target)

    if box.last_target == old:
        box.last_target = new
        save_box(box)

    creds = load_creds(box)
    changed = False
    for cred in creds:
        if cred.found_on == old:
            cred.found_on = new
            changed = True
        if old in cred.works_on:
            cred.works_on = [new if n == old else n for n in cred.works_on]
            changed = True
    if changed:
        save_creds(box, creds)

    prefix = f"targets/{old}/"
    records = load_files(box)
    changed = False
    for record in records:
        if record.target == old:
            record.target = new
            changed = True
        if record.path.startswith(prefix):
            record.path = f"targets/{new}/" + record.path[len(prefix) :]
            changed = True
    if changed:
        save_files(box, records)
    return target


def target_contents(box: Box, name: str) -> list[str]:
    folder = box.path / "targets" / name
    return sorted(
        p.relative_to(folder).as_posix()
        for p in folder.rglob("*")
        if p.is_file() and p.relative_to(folder).as_posix() != "target.toml"
    )


def ensure_removable(box: Box, name: str) -> None:
    found = target_contents(box, name)
    if found:
        shown = ", ".join(found[:5])
        raise BoxError(f"{name} still has {len(found)} file(s): {shown}")


def remove_target(box: Box, targets: list[Target], name: str) -> None:
    target = find_target(targets, name)
    ensure_removable(box, target.name)
    folder = box.path / "targets" / target.name
    shutil.rmtree(folder)
    targets.remove(target)


def find_target(targets: list[Target], text: str) -> Target:
    for target in targets:
        if target.name == text:
            return target
    matches = [t for t in targets if t.name.startswith(text)] if text else []
    if len(matches) == 1:
        return matches[0]
    if matches:
        raise BoxError(f"{text} matches more than one target: {', '.join(t.name for t in matches)}")
    raise BoxError(f"no target named {text}")


def pid_alive(pid: int) -> bool:
    if sys.platform == "win32":
        return False
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _lock_file(paths: AppPaths) -> Path:
    return paths.run / "open.toml"


def _read_lock(paths: AppPaths) -> dict | None:
    try:
        data = read_toml(_lock_file(paths))
    except StoreError:
        return None
    if (
        isinstance(data.get("pid"), int)
        and isinstance(data.get("box_id"), str)
        and isinstance(data.get("folder"), str)
    ):
        return data
    return None


def acquire_open(
    paths: AppPaths, box: Box, *, pid: int, alive: Callable[[int], bool] = pid_alive
) -> None:
    held = _read_lock(paths)
    if held is not None and alive(held["pid"]):
        mine = held["pid"] == pid and held["box_id"] == box.id
        if not mine:
            raise BoxError(f"{Path(held['folder']).name} is already open (pid {held['pid']})")
    write_toml(_lock_file(paths), {"schema": SCHEMA, "box_id": box.id, "folder": str(box.path), "pid": pid})


def release_open(paths: AppPaths, *, pid: int) -> None:
    held = _read_lock(paths)
    if held is not None and held["pid"] == pid:
        _lock_file(paths).unlink(missing_ok=True)


def open_box_folder(paths: AppPaths, *, alive: Callable[[int], bool] = pid_alive) -> Path | None:
    held = _read_lock(paths)
    if held is None or not alive(held["pid"]):
        return None
    return Path(held["folder"])
