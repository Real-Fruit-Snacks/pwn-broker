"""The SHA-256 an index first gave for each build, kept on this machine.

The index says what a package's SHA-256 is and carries no signature, and pwn-shop never changes
or replaces a build once it is published. So the first hash an index gives for a build is kept,
in tools/seen.toml, and an index that later gives the same build another is refused, whichever
index it is: the published one, a mirror or a folder. Nothing here forgets a build on its own;
tool forget is the user saying that one build was rebuilt on purpose.

Every caller is a command, a launch or an import, which the box lock or the terminal puts one
after another. Two that do meet each write a whole file and one replaces the other's: a row lost
that way is a build not yet kept, which the next read of the index keeps again.
"""

import re
from collections.abc import Iterable
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Protocol

from pwn_broker.paths import AppPaths
from pwn_broker.store import StoreError, read_toml, write_toml
from pwn_broker.toolpkg import ToolError, build_id

SCHEMA = 1
_SHA256 = re.compile(r"[0-9a-f]{64}")

Key = tuple[str, str, int]


class Build(Protocol):
    name: str
    version: str
    build: int
    sha256: str


@dataclass(frozen=True)
class Seen:
    name: str
    version: str
    build: int
    sha256: str
    # when an index first gave the build, and which index that was
    seen: datetime
    source: str


class BuildChanged(ToolError):
    """An index gives a build another SHA-256 than the one kept for it."""


def differs(build: Build, *, held: str, holder: str) -> str:
    """What to say of a build whose SHA-256 in the index is not the one a witness holds: the
    build and both hashes, whoever the witness is (this machine, a box's row, an installed copy)."""
    return (
        f"{build.name} {build_id(build.version, build.build)}: the index gives it the SHA-256 "
        f"{build.sha256.lower()}, and {holder} {held.lower()}"
    )


def _unreadable(paths: AppPaths, why: str) -> ToolError:
    return ToolError(
        f"{paths.tools_seen} cannot be read ({why}); correct it, or delete it to take every "
        "build as the index gives it now"
    )


def _row(row: object) -> Seen:
    if not isinstance(row, dict):
        raise TypeError("build is not a table")
    for key in ("name", "version", "sha256", "source"):
        if not isinstance(row[key], str):
            raise TypeError(f"{key} must be a string")
    number = row["build"]
    if not isinstance(number, int) or isinstance(number, bool):
        raise TypeError("build must be a whole number")
    sha256 = row["sha256"].lower()
    if not _SHA256.fullmatch(sha256):
        raise ValueError("sha256 must be 64 hexadecimal characters")
    seen = row["seen"]
    if not isinstance(seen, datetime):
        raise TypeError("seen must be a date and time")
    if seen.tzinfo is None:
        # written by hand without an offset: taken as local time, as a box's times are
        seen = seen.astimezone()
    return Seen(row["name"], row["version"], number, sha256, seen, row["source"])


def load(paths: AppPaths) -> dict[Key, Seen]:
    """The builds kept, by name, version and build. A file that is not there holds none; one
    that cannot be read is an error and never an empty list, which would take any hash."""
    path = paths.tools_seen
    if not path.exists() and not path.is_symlink():
        return {}
    try:
        data = read_toml(path)
    except StoreError as exc:
        raise _unreadable(paths, str(exc).removeprefix(f"cannot read {path}: ")) from exc
    if "schema" not in data:
        # an empty or cut-short file, not one from a newer version
        raise _unreadable(paths, "it has no schema")
    if data["schema"] != SCHEMA or isinstance(data["schema"], bool):
        raise ToolError(f"{path}: unsupported schema {data['schema']!r}; upgrade pwn-broker")
    rows = data.get("build", [])
    if not isinstance(rows, list):
        raise _unreadable(paths, "build must be a list of tables")
    kept: dict[Key, Seen] = {}
    for number, row in enumerate(rows):
        try:
            item = _row(row)
        except (KeyError, TypeError, ValueError, OverflowError, OSError) as exc:
            why = f"it has no {exc}" if isinstance(exc, KeyError) else str(exc)
            raise _unreadable(paths, f"build[{number}]: {why}") from exc
        key = (item.name, item.version, item.build)
        if key in kept and kept[key].sha256 != item.sha256:
            shown = f"{item.name} {build_id(item.version, item.build)}"
            raise _unreadable(paths, f"{shown} is there with two SHA-256")
        kept.setdefault(key, item)
    return kept


def _save(paths: AppPaths, kept: dict[Key, Seen]) -> None:
    rows = [asdict(kept[key]) for key in sorted(kept)]
    try:
        # written whole beside the old file and moved over it, so a stop part of the way
        # through leaves the list as it was
        write_toml(paths.tools_seen, {"schema": SCHEMA, "build": rows})
    except OSError as exc:
        raise ToolError(f"{paths.tools_seen} could not be written: {exc.strerror or exc}") from exc


def _changed(build: Build, kept: Seen, where: str, more: int) -> BuildChanged:
    name = f"{build.name}@{build_id(build.version, build.build)}"
    others = ""
    if more:
        others = f" ({more} more {'build differs' if more == 1 else 'builds differ'} as well)"
    # the index that first gave the build is named when it is another than the one refused
    first = f", when {kept.source} gave it" if kept.source != where else ""
    return BuildChanged(
        f"{differs(build, held=kept.sha256, holder='this machine has kept')} since "
        f"{kept.seen:%Y-%m-%d}{first}{others}. A published build is never changed, so nothing "
        f"is taken from {where}. If the build was made again on purpose, tool forget {name} "
        "forgets the SHA-256 kept"
    )


def check(paths: AppPaths, builds: Iterable[Build], *, where: str, now: datetime) -> None:
    """Holds an index to the builds kept, then keeps the builds it gives for the first time.

    Raises BuildChanged when it gives one build another SHA-256 than the one kept, and then
    keeps nothing of it: an index that changed one build is not asked about the others.
    """
    kept = load(paths)
    new: dict[Key, Seen] = {}
    changed: list[tuple[Build, Seen]] = []
    now = now.replace(microsecond=0)
    for build in builds:
        key = (build.name, build.version, build.build)
        sha256 = build.sha256.lower()
        row = kept.get(key)
        if row is None:
            new.setdefault(key, Seen(build.name, build.version, build.build, sha256, now, where))
        elif row.sha256 != sha256:
            changed.append((build, row))
    if changed:
        raise _changed(*changed[0], where, len(changed) - 1)
    if new:
        _save(paths, kept | new)


def check_one(paths: AppPaths, build: Build, *, where: str) -> None:
    """Refuses one build whose SHA-256 is not the one kept for it; keeps nothing."""
    row = load(paths).get((build.name, build.version, build.build))
    if row is not None and row.sha256 != build.sha256.lower():
        raise _changed(build, row, where, 0)


def of_tool(paths: AppPaths, name: str) -> list[Seen]:
    """The builds kept under one package name, in order."""
    kept = load(paths)
    return [kept[key] for key in sorted(kept) if key[0] == name]


def forget(paths: AppPaths, item: Seen) -> bool:
    """Drops one build from the list; false when it is no longer there as `item` has it, which
    is the row that was shown before the question."""
    kept = load(paths)
    key = (item.name, item.version, item.build)
    if key not in kept or kept[key].sha256 != item.sha256:
        return False
    del kept[key]
    _save(paths, kept)
    return True
