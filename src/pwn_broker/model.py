from dataclasses import dataclass, field
from datetime import datetime
from pathlib import Path


@dataclass
class Flag:
    value: str
    at: datetime


@dataclass
class RuntimeRecord:
    # a note of the runtime a tool ran on, not a pin: any build of its series serves the tool
    name: str
    version: str
    build: int
    sha256: str


@dataclass
class ToolRecord:
    name: str
    version: str
    build: int
    sha256: str
    installed: datetime
    runtime: RuntimeRecord | None = None
    # set by tool remove; the row stays, so the box shows every tool it ever used
    removed: datetime | None = None
    # true when this row was brought in for another tool, not explicitly requested
    dependency: bool = False
    # the package backends tool install --full chose for this tool in this box, by name. Kept
    # here and not in the machine's list: another box with the same tool chose for itself, and
    # this row is what is read when the box is reopened or imported
    optional: list[str] = field(default_factory=list)


def current_tools(box: "Box") -> list[ToolRecord]:
    """The tools the box has now: its rows with no removal time, at most one per name."""
    return [t for t in box.tools if t.removed is None]


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
