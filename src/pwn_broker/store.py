import os
import shutil
import tempfile
import tomllib
from dataclasses import asdict
from datetime import datetime
from pathlib import Path

import tomli_w

from pwn_broker.filescan import TEMP_PREFIX, TEMP_SUFFIX
from pwn_broker.model import Box, Cred, FileRecord, Flag, Target, ToolRecord, VpnRecord

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


def read_toml(path: Path) -> dict:
    try:
        return tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as exc:
        raise StoreError(f"cannot read {path}: {exc}") from exc


def _read_checked(path: Path) -> dict:
    data = read_toml(path)
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
        data["tools"] = [asdict(t) for t in box.tools]
    if box.hosts:
        data["hosts"] = list(box.hosts)
    if box.vpn:
        data["vpn"] = [asdict(v) for v in box.vpn]
    for key, value in box.extra.items():
        data.setdefault(key, value)
    write_toml(box.path / "box.toml", data)


def _tool(row: dict) -> ToolRecord:
    # tomllib gives bool for true/false and int for numbers; a bool is not a build number
    kinds = {"name": str, "version": str, "build": int, "sha256": str, "installed": datetime}
    for key, kind in kinds.items():
        if not isinstance(row[key], kind) or (kind is int and isinstance(row[key], bool)):
            raise TypeError(f"tools.{key} has the wrong type")
    return ToolRecord(**{key: row[key] for key in kinds})


def _vpn(row: dict) -> VpnRecord:
    kinds = {"file": str, "sha256": str, "started": datetime}
    for key, kind in kinds.items():
        if not isinstance(row[key], kind):
            raise TypeError(f"vpn.{key} has the wrong type")
    return VpnRecord(**{key: row[key] for key in kinds})


def _hosts(value) -> list[str]:
    if not isinstance(value, list) or not all(isinstance(v, str) for v in value):
        raise TypeError("hosts must be a list of strings")
    return list(value)


def load_box(folder: Path) -> Box:
    path = folder / "box.toml"
    data = _read_checked(path)

    def make() -> Box:
        known = {
            "schema", "id", "name", "platform", "os", "difficulty", "status",
            "started", "finished", "last_target", "flags", "tools", "hosts", "vpn",
        }  # fmt: skip
        return Box(
            id=data["id"],
            name=data["name"],
            platform=data["platform"],
            os=data["os"],
            difficulty=data["difficulty"],
            status=data["status"],
            started=data["started"],
            finished=data.get("finished"),
            last_target=data.get("last_target"),
            flags={k: Flag(value=v["value"], at=v["at"]) for k, v in data.get("flags", {}).items()},
            tools=[_tool(row) for row in data.get("tools", [])],
            hosts=_hosts(data.get("hosts", [])),
            vpn=[_vpn(row) for row in data.get("vpn", [])],
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
        data = _read_checked(file)
        data.pop("schema")
        targets.append(_build(file, lambda data=data: Target(**data)))
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
    return _build(path, lambda: [Cred(**row) for row in data.get("cred", [])])


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
    return _build(path, lambda: [FileRecord(**row) for row in data.get("file", [])])
