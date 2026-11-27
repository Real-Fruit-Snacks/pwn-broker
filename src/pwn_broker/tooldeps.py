"""Dependency planning for ordinary pwn-shop tools.

Runtime requirements stay in toolhooks: this module resolves only schema 4's ordinary
`depends` edges and package-backed optional backends. Nothing here downloads or writes.
"""

from dataclasses import dataclass, field
from pathlib import Path

from pwn_broker.model import Box, current_tools
from pwn_broker.toolindex import BuildEntry, Index, pick_build
from pwn_broker.toolpkg import ToolError, build_id
from pwn_broker.toolstate import Installed


@dataclass
class Plan:
    # dependencies before the tools that need them; the requested tool is last
    entries: list[BuildEntry] = field(default_factory=list)
    # package backends selected for the requested tool by --full, never for its dependencies
    optional: dict[str, list[str]] = field(default_factory=dict)


def _existing_build(index: Index, entry: BuildEntry, installed: dict[str, Installed]) -> BuildEntry:
    """Reuse an installed ordinary tool at its own build, as runtimes are reused.

    Dependencies are names, not upgrades. An installed build must still be represented and
    hash-pinned by the index so a reinstall or another box joining it remains reproducible.
    """
    current = installed.get(entry.name)
    if current is None or current.kind == "runtime":
        return entry
    wanted = build_id(current.version, current.build)
    for tool in index.tools:
        if tool.name != entry.name:
            continue
        for build in tool.builds:
            if build_id(build.version, build.build) == wanted:
                if build.sha256.lower() != current.sha256.lower():
                    raise ToolError(
                        f"{entry.name} {wanted}: the index lists a different SHA-256 than the install"
                    )
                return build
    raise ToolError(f"{entry.name} {wanted}: the installed build is not in the index")


def resolve(
    index: Index,
    requested: BuildEntry,
    *,
    installed: dict[str, Installed],
    full: bool = False,
) -> Plan:
    """Return a topological install plan, refusing missing packages, runtimes and cycles."""
    if requested.kind in ("runtime", "notes") and (requested.depends or full):
        raise ToolError(f"{requested.name}: this package kind has no dependency installation plan")
    plan = Plan()
    visiting: list[str] = []
    visited: set[str] = set()

    def visit(candidate: BuildEntry, *, root: bool = False) -> None:
        name = candidate.name
        if name in visiting:
            cycle = " -> ".join([*visiting[visiting.index(name) :], name])
            raise ToolError(f"ordinary tool dependency cycle: {cycle}")
        if name in visited:
            return
        entry = candidate if root else _existing_build(index, candidate, installed)
        if entry.kind == "runtime" or (entry.kind == "notes" and not root):
            raise ToolError(f"{name}: ordinary dependencies must be installable tools, not {entry.kind}")
        visiting.append(name)
        for wanted in entry.depends:
            try:
                tool = next(t for t in index.tools if t.name == wanted)
            except StopIteration as exc:
                raise ToolError(f"{name}: ordinary dependency {wanted!r} is not in the index") from exc
            visit(pick_build(tool, None))
        if root and full:
            selected = []
            for backend in entry.backends:
                if not backend.package:
                    continue
                selected.append(backend.package)
                try:
                    tool = next(t for t in index.tools if t.name == backend.package)
                except StopIteration as exc:
                    raise ToolError(
                        f"{name}: backend package {backend.package!r} is not in the index"
                    ) from exc
                visit(pick_build(tool, None))
            if selected:
                plan.optional[name] = selected
        visiting.pop()
        visited.add(name)
        plan.entries.append(entry)

    visit(requested, root=True)
    return plan


def satisfied(box: Box, entry: BuildEntry, installed: dict[str, Installed]) -> bool:
    """Whether this box already has this exact usable build; joining another box is not enough."""
    item = installed.get(entry.name)
    if item is None or item.kind == "runtime" or box.id not in item.users:
        return False
    wanted = (entry.name, entry.version, entry.build)
    if (item.name, item.version, item.build) != wanted or not Path(item.folder).is_dir():
        return False
    return any(
        (r.name, r.version, r.build) == wanted and r.sha256.lower() == item.sha256.lower()
        for r in current_tools(box)
    )


def required_names(item: Installed) -> set[str]:
    return {*item.depends, *item.optional}


def users_of(installed: dict[str, Installed], name: str) -> list[str]:
    return sorted(
        item.name for item in installed.values()
        if item.kind != "runtime" and name in required_names(item)
    )  # fmt: skip


def orphaned(box: Box, installed: dict[str, Installed], removed: set[str]) -> list[str]:
    """Automatic dependencies this box no longer needs after removing `removed`.

    Explicitly installed tools are never included. Repeated passes release dependency chains,
    while an edge from any remaining tool keeps its target. Missing state keeps a dependency.
    """
    doomed = set(removed)
    answer: list[str] = []
    while True:
        records = {r.name: r for r in current_tools(box) if r.name not in doomed}
        needed = set()
        for name in records:
            item = installed.get(name)
            if item is None:
                # conservative: damaged state must not turn into deletion of another package
                return answer
            needed.update(required_names(item))
        found = [
            name for name, record in records.items()
            if record.dependency and name not in needed and name not in doomed
        ]  # fmt: skip
        if not found:
            return answer
        for name in sorted(found):
            answer.append(name)
            doomed.add(name)
