import ipaddress
import os
import shutil
import tempfile
import tomllib
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

import tomli_w

from pwn_broker.filescan import TEMP_PREFIX, TEMP_SUFFIX
from pwn_broker.hosts import BOX_ID
from pwn_broker.paths import safe_name
from pwn_broker.model import (
    Box,
    Cred,
    FileRecord,
    Flag,
    RuntimeRecord,
    Target,
    ToolRecord,
    VpnRecord,
)

SCHEMA = 1


class StoreError(Exception):
    pass


def write_text(path: Path, text: str, *, newline: str = "\n", errors: str = "strict") -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp_name = tempfile.mkstemp(dir=path.parent, prefix=TEMP_PREFIX, suffix=TEMP_SUFFIX)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", errors=errors, newline=newline) as fh:
            fh.write(text)
        # mkstemp makes the file 0600; keep the old mode, or the usual default for a new file
        if path.exists():
            shutil.copymode(path, tmp_name)
        else:
            umask = os.umask(0)
            os.umask(umask)
            os.chmod(tmp_name, 0o666 & ~umask)
        os.replace(tmp_name, path)
    except BaseException:
        try:
            os.unlink(tmp_name)
        except OSError:
            pass
        raise


def write_toml(path: Path, data: dict) -> None:
    write_text(path, tomli_w.dumps(data))


# The most of one of a box's files that is read, and so the largest manifest an archive may
# hold: about 250,000 files' worth of records. A megabyte of gzip unpacks to a gigabyte of
# box.toml, and each megabyte read can cost twenty-five of memory.
MAX_TOML_BYTES = 64 * 1024 * 1024
# box.toml and a target's file hold a few kilobytes, and box.toml is read for every box at
# every launch
MAX_SMALL_TOML_BYTES = 1024 * 1024


def read_toml(path: Path, limit: int | None = None) -> dict:
    limit = MAX_TOML_BYTES if limit is None else limit
    try:
        if path.stat().st_size > limit:
            raise StoreError(f"cannot read {path}: it is larger than {limit // 1048576} MiB")
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except RecursionError as exc:
        raise StoreError(f"cannot read {path}: it is nested too deeply") from exc
    except (OSError, ValueError) as exc:  # ValueError: not UTF-8, not TOML, or a number too long to read
        raise StoreError(f"cannot read {path}: {exc}") from exc


def _read_checked(path: Path, limit: int | None = None) -> dict:
    data = read_toml(path, limit)
    if data.get("schema") != SCHEMA:
        raise StoreError(f"{path}: unsupported schema {data.get('schema')!r}")
    return data


def _without_none(values: dict) -> dict:
    return {k: v for k, v in values.items() if v is not None}


def _build(path: Path, make):
    try:
        return make()
    except (KeyError, TypeError, ValueError, AttributeError) as exc:
        raise StoreError(f"{path}: invalid content ({type(exc).__name__}: {exc})") from exc


def save_box(box: Box) -> None:
    data: dict = {
        "schema": SCHEMA,
        **_without_none(
            {
                "id": box.id,
                "name": box.name,
                "platform": box.platform,
                "os": box.os,
                "difficulty": box.difficulty,
                "status": box.status,
                "started": box.started,
                "finished": box.finished,
                "last_target": box.last_target,
            }
        ),
        "flags": {k: {"value": f.value, "at": f.at} for k, f in box.flags.items()},
    }
    if box.tools:
        # a tool with no runtime and no removal time is written as before these existed
        data["tools"] = [_without_none(asdict(t)) for t in box.tools]
    if box.hosts:
        data["hosts"] = list(box.hosts)
    if box.vpn:
        data["vpn"] = [asdict(v) for v in box.vpn]
    for key, value in box.extra.items():
        data.setdefault(key, value)
    write_toml(box.path / "box.toml", data)


def _is_a(value, kind) -> bool:
    # tomllib gives bool for true/false and int for numbers: a bool is not a number. A list is a
    # list of strings: the model holds no other kind.
    if isinstance(value, bool):
        return False
    if kind is datetime:
        # a year the app can still convert between time zones
        return isinstance(value, datetime) and 1970 <= value.year < 9000
    if kind is float:
        return isinstance(value, (int, float))
    if kind is list:
        return isinstance(value, list) and all(isinstance(v, str) for v in value)
    return isinstance(value, kind)


def _checked(row: dict, kinds: dict, label: str) -> dict:
    if not isinstance(row, dict):
        raise TypeError(f"{label} must be a table")
    for key, kind in kinds.items():
        if not _is_a(row[key], kind):
            raise TypeError(f"{label}.{key} has the wrong type")
    return {key: _aware(row[key]) for key in kinds}


def _aware(value):
    # every time the app writes carries its offset. One written by hand without it is taken as
    # local time, so that it can be put in order with the others.
    if isinstance(value, datetime) and value.tzinfo is None:
        try:
            return value.astimezone()
        except (OverflowError, OSError, ValueError) as exc:
            raise TypeError("a time without an offset is too early to take as local time") from exc
    return value


def _optional(row: dict, key: str, kind, label: str):
    if key not in row:
        return None
    return _checked(row, {key: kind}, label)[key]


_BOX = {
    "id": str, "name": str, "platform": str, "os": str, "difficulty": str, "status": str,
    "started": datetime,
}  # fmt: skip
_TARGET = {
    "box_id": str, "box": str, "name": str, "ips": list, "hostnames": list, "scope": str,
    "added": datetime,
}  # fmt: skip
_CRED = {
    "n": int, "username": str, "domain": str, "secret": str, "kind": str, "found_on": str,
    "works_on": list, "note": str, "added": datetime,
}  # fmt: skip
_FILE = {
    "path": str, "target": str, "first_seen": datetime, "size": int, "mtime": float, "sha256": str,
}  # fmt: skip


def _box_id(value: str) -> str:
    # the id names the box's folders under /opt/pwn-broker/run and marks its /etc/hosts lines:
    # one plain name, as the hosts file takes it
    if not BOX_ID.fullmatch(value) or value in (".", ".."):
        raise ValueError(f"not a box ID: {value!r}")
    return value


def _target(file: Path, data: dict) -> Target:
    # as the app makes one: an imported archive's target names paths in the box and gives nmap
    # its address, so a name that is not its folder's, or an address that is not one, is refused
    target = _row(Target, data, _TARGET, "target")
    if target.name != file.parent.name or safe_name(target.name) != target.name:
        raise ValueError(f"the target name {target.name!r} is not the name of its folder")
    for ip in target.ips:
        if not isinstance(ip, str):
            raise TypeError("target.ips has the wrong type")
        ipaddress.ip_address(ip)
    return target


def _row(cls, row, kinds: dict, label: str):
    # the listed fields have the right types; a field the model does not have is still refused
    return cls(**{**row, **_checked(row, kinds, label)})


def _flags(value) -> dict[str, Flag]:
    if not isinstance(value, dict):
        raise TypeError("flags must be a table")
    kinds = {"value": str, "at": datetime}
    return {name: Flag(**_checked(flag, kinds, "flags")) for name, flag in value.items()}


def _runtime(value) -> RuntimeRecord:
    if not isinstance(value, dict):
        raise TypeError("tools.runtime must be a table")
    kinds = {"name": str, "version": str, "build": int, "sha256": str}
    return RuntimeRecord(**_checked(value, kinds, "tools.runtime"))


def _tool(row: dict) -> ToolRecord:
    kinds = {"name": str, "version": str, "build": int, "sha256": str, "installed": datetime}
    record = ToolRecord(**_checked(row, kinds, "tools"))
    if "runtime" in row:
        # absent in boxes written before runtimes existed
        record.runtime = _runtime(row["runtime"])
    if "removed" in row:
        # absent in boxes written before removed tools were kept
        record.removed = _checked(row, {"removed": datetime}, "tools")["removed"]
    return record


def _vpn(row: dict) -> VpnRecord:
    kinds = {"file": str, "sha256": str, "started": datetime}
    return VpnRecord(**_checked(row, kinds, "vpn"))


def _rows(value, label: str) -> list:
    if not isinstance(value, list):
        raise TypeError(f"{label} must be a list of tables")
    return value


def _hosts(value) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise TypeError("hosts must be a list of strings")
    return list(value)


def load_box(folder: Path) -> Box:
    path = folder / "box.toml"
    data = _read_checked(path, MAX_SMALL_TOML_BYTES)

    def make() -> Box:
        known = {
            "schema", "id", "name", "platform", "os", "difficulty", "status",
            "started", "finished", "last_target", "flags", "tools", "hosts", "vpn",
        }  # fmt: skip
        fields = _checked(data, _BOX, "box")
        _box_id(fields["id"])
        return Box(
            **fields,
            finished=_optional(data, "finished", datetime, "box"),
            last_target=_optional(data, "last_target", str, "box"),
            flags=_flags(data.get("flags", {})),
            tools=[_tool(row) for row in _rows(data.get("tools", []), "tools")],
            hosts=_hosts(data.get("hosts", [])),
            vpn=[_vpn(row) for row in _rows(data.get("vpn", []), "vpn")],
            extra={k: v for k, v in data.items() if k not in known},
            path=folder,
        )

    return _build(path, make)


def save_target(box: Box, target: Target) -> None:
    data = {"schema": SCHEMA, **_without_none(asdict(target))}
    write_toml(box.path / "targets" / target.name / "target.toml", data)


def load_targets(box: Box) -> list[Target]:
    targets = []
    for file in sorted((box.path / "targets").glob("*/target.toml")):
        data = _read_checked(file, MAX_SMALL_TOML_BYTES)
        data.pop("schema")
        targets.append(_build(file, lambda file=file, data=data: _target(file, data)))
    return sorted(targets, key=lambda t: t.added)


def save_creds(box: Box, creds: list[Cred]) -> None:
    write_toml(
        box.path / "creds.toml",
        {"schema": SCHEMA, "box_id": box.id, "cred": [_without_none(asdict(c)) for c in creds]},
    )


def load_creds(box: Box) -> list[Cred]:
    path = box.path / "creds.toml"
    if not path.exists():
        return []
    data = _read_checked(path)
    return _build(
        path, lambda: [_row(Cred, row, _CRED, "cred") for row in _rows(data.get("cred", []), "cred")]
    )


def save_files(box: Box, records: list[FileRecord]) -> None:
    write_toml(
        box.path / "files.toml",
        {"schema": SCHEMA, "box_id": box.id, "file": [_without_none(asdict(r)) for r in records]},
    )


def load_files(box: Box) -> list[FileRecord]:
    path = box.path / "files.toml"
    if not path.exists():
        return []
    data = _read_checked(path)
    return _build(
        path,
        lambda: [_row(FileRecord, row, _FILE, "file") for row in _rows(data.get("file", []), "file")],
    )
