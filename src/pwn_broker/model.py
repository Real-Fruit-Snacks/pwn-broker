from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class Flag:
    value: str
    at: datetime


@dataclass
class ToolRecord:
    name: str
    version: str
    build: int
    sha256: str
    installed: datetime


@dataclass
class VpnRecord:
    file: str
    sha256: str
    started: datetime


@dataclass
class Box:
    id: str
    name: str
    platform: str
    os: str
    difficulty: str
    status: str
    started: datetime
    finished: datetime | None
    last_target: str | None
    flags: dict[str, Flag]
    tools: list[ToolRecord] = field(default_factory=list)
    hosts: list[str] = field(default_factory=list)
    vpn: list[VpnRecord] = field(default_factory=list)
    extra: dict = field(default_factory=dict)
    path: Path = Path()


@dataclass
class Target:
    box_id: str
    box: str
    name: str
    ips: list[str]
    hostnames: list[str]
    scope: str
    added: datetime


@dataclass
class Cred:
    n: int
    username: str
    domain: str
    secret: str
    kind: str
    found_on: str
    works_on: list[str]
    note: str
    added: datetime


@dataclass
class FileRecord:
    path: str
    target: str
    first_seen: datetime
    size: int
    mtime: float
    sha256: str
