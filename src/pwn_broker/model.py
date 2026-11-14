from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class Flag:
    value: str
    at: datetime


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
