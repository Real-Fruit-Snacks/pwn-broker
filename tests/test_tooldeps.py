from dataclasses import replace
from types import SimpleNamespace

import pytest

import toolkit
from helpers import NOW
from pwn_broker import shell  # noqa: F401  (fills the command registry)
from pwn_broker import toolhooks, toolindex, toolinstall, toolstate
from pwn_broker.console import FakeConsole
from pwn_broker.model import current_tools
from pwn_broker.shell import cmd_tool
from pwn_broker.shell.commands import dispatch
from pwn_broker.toolpkg import ToolError, parse_manifest


def run(session, line, *answers):
    session.console = FakeConsole(list(answers))
    dispatch(session, line)
    return session.console


def package(folder, name, *, depends=(), backends=()):
    overrides = {
        "name": name,
        "command": [{"name": f"{name}-cmd", "type": "binary", "path": "files/tool"}],
    }
    if name == "netexec":
        overrides["command"] = [{"name": "nxc", "type": "binary", "path": "files/tool"}]
    if depends or backends:
        overrides["schema"] = 4
    if depends:
        overrides["depends"] = list(depends)
    if backends:
        overrides["backend"] = list(backends)
    return toolkit.make_entry(folder, overrides, {"files/tool": b"#!/bin/sh\nexit 0\n"})[1]


BACKENDS = [
    {
        "name": "netexec",
        "description": "SMB, WinRM and other network protocols",
        "commands": ["nxc", "netexec"],
        "package": "netexec",
    },
    {
        "name": "nmap",
        "description": "service discovery",
        "commands": ["nmap"],
        "apt": ["nmap"],
    },
    {
        "name": "freerdp",
        "description": "RDP connections",
        "commands": ["xfreerdp3", "xfreerdp"],
        "apt": ["freerdp3-x11"],
    },
]


@pytest.fixture
def graph(tmp_path, session, monkeypatch):
    folder = tmp_path / "index"
    home = tmp_path / "user"
    home.mkdir()
    monkeypatch.setattr(toolhooks, "user_home", lambda: home)
    monkeypatch.setattr(toolhooks.tooldata, "_root_home", lambda: tmp_path / "no-root-home")
    monkeypatch.setattr(cmd_tool, "_lookup", lambda command, path=None: None)
    entries = {
        "leaf-tool": package(folder, "leaf-tool"),
        "mid-tool": package(folder, "mid-tool", depends=["leaf-tool"]),
        "netexec": package(folder, "netexec"),
    }
    entries["root-tool"] = package(
        folder, "root-tool", depends=["mid-tool"], backends=BACKENDS
    )
    toolkit.write_index(folder, list(entries.values()))
    session.settings = replace(session.settings, tools_index=str(folder))
    return SimpleNamespace(folder=folder, home=home, entries=entries)


def records(session):
    return {record.name: record for record in current_tools(session.box)}


def test_minimal_install_is_topological_and_does_not_select_optional_backends(
    session, graph, monkeypatch
):
    order = []
    original = toolinstall.install

    def watched(*args, **kwargs):
        order.append(args[2].name)
        return original(*args, **kwargs)

    monkeypatch.setattr(toolhooks.toolinstall, "install", watched)
    console = run(session, "tool install root-tool")
    assert not lines_matching(console, "fail")
    assert order == ["leaf-tool", "mid-tool", "root-tool"]
    installed = toolstate.load_installed(session.paths)
    assert set(installed) == {"leaf-tool", "mid-tool", "root-tool"}
    assert installed["root-tool"].depends == ["mid-tool"]
    assert installed["root-tool"].optional == []
    assert records(session)["root-tool"].dependency is False
    assert records(session)["mid-tool"].dependency is True
    assert records(session)["leaf-tool"].dependency is True
    assert console.asked == []


def lines_matching(console, kind):
    return [text for found, text in console.lines if found == kind]


def test_full_install_selects_package_backends_without_apt_when_commands_exist(
    session, graph, monkeypatch
):
    monkeypatch.setattr(
        cmd_tool,
        "_lookup",
        lambda command, path=None: f"/usr/bin/{command}"
        if command in {"nmap", "xfreerdp3"}
        else None,
    )
    console = run(session, "tool install root-tool --full")
    assert not lines_matching(console, "fail")
    installed = toolstate.load_installed(session.paths)
    assert set(installed) == {"leaf-tool", "mid-tool", "netexec", "root-tool"}
    assert installed["root-tool"].optional == ["netexec"]
    assert records(session)["netexec"].dependency is True
    assert console.asked == []


def test_full_apt_plan_is_shown_confirmed_and_run_without_a_shell(session, graph, monkeypatch):
    calls = []
    monkeypatch.setattr(cmd_tool.os, "geteuid", lambda: 1000, raising=False)

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        return SimpleNamespace(returncode=0, stdout="", stderr="")

    monkeypatch.setattr(cmd_tool, "_run", fake_run)
    console = run(session, "tool install root-tool --full", "y")
    argv, kwargs = calls[0]
    assert argv == [
        "sudo", "apt-get", "install", "--no-install-recommends", "nmap", "freerdp3-x11",
    ]
    assert kwargs == {"capture_output": True, "text": True}
    assert "shell" not in kwargs
    assert any("sudo apt-get install --no-install-recommends nmap freerdp3-x11" in text
               for kind, text in console.lines if kind == "field")
    assert set(toolstate.load_installed(session.paths)) == {
        "leaf-tool", "mid-tool", "netexec", "root-tool",
    }


def test_declined_apt_plan_never_runs_and_is_explicitly_reported(session, graph, monkeypatch):
    monkeypatch.setattr(
        cmd_tool, "_run", lambda *args, **kwargs: pytest.fail("apt must not run")
    )
    console = run(session, "tool install root-tool --full", "n")
    assert lines_matching(console, "warn") == ["apt-backed backends were not installed"]
    assert "root-tool" in toolstate.load_installed(session.paths)


def test_failed_apt_plan_aborts_before_any_package_download(session, graph, monkeypatch):
    monkeypatch.setattr(cmd_tool.os, "geteuid", lambda: 0, raising=False)
    monkeypatch.setattr(
        cmd_tool, "_run",
        lambda *args, **kwargs: SimpleNamespace(returncode=7, stdout="", stderr="offline"),
    )
    console = run(session, "tool install root-tool --full", "y")
    assert "apt-get failed (exit 7)" in lines_matching(console, "fail")[0]
    assert toolstate.load_installed(session.paths) == {}
    assert current_tools(session.box) == []


def test_doctor_accepts_freerdp_alternative_and_does_not_change_anything(
    session, graph, monkeypatch
):
    run(session, "tool install root-tool")
    monkeypatch.setattr(
        cmd_tool, "_lookup",
        lambda command, path=None: "/usr/bin/xfreerdp" if command == "xfreerdp" else None,
    )
    before = session.paths.tools_state.read_bytes()
    console = run(session, "tool doctor root-tool")
    columns, rows = console.tables[0]
    assert columns == ["backend", "status", "command", "provider", "feature"]
    by_name = {row[0]: row for row in rows}
    assert by_name["freerdp"][1:3] == ["enabled", "/usr/bin/xfreerdp"]
    assert by_name["netexec"][1] == "missing"
    assert by_name["nmap"][1] == "missing"
    assert console.asked == []
    assert session.paths.tools_state.read_bytes() == before


def test_direct_dependency_removal_is_refused_while_a_parent_uses_it(session, graph):
    run(session, "tool install root-tool")
    console = run(session, "tool remove mid-tool")
    assert lines_matching(console, "fail") == [
        "mid-tool is required by root-tool; remove the parent first"
    ]
    assert set(records(session)) == {"leaf-tool", "mid-tool", "root-tool"}


def test_parent_removal_releases_only_orphaned_automatic_dependencies(session, graph):
    run(session, "tool install root-tool")
    run(session, "tool install leaf-tool")  # an explicit request takes ownership
    assert records(session)["leaf-tool"].dependency is False
    console = run(session, "tool remove root-tool", "y")
    assert not lines_matching(console, "fail")
    assert set(records(session)) == {"leaf-tool"}
    assert set(toolstate.load_installed(session.paths)) == {"leaf-tool"}
    assert any("mid-tool" in text for text in lines_matching(console, "info"))


def test_dependency_reuse_and_removal_preserve_another_box(session, graph, other):
    run(session, "tool install root-tool")
    first = session.box
    session.box = other
    run(session, "tool install root-tool")
    installed = toolstate.load_installed(session.paths)
    assert set(installed["mid-tool"].users) == {first.id, other.id}
    run(session, "tool remove root-tool", "y")
    installed = toolstate.load_installed(session.paths)
    assert set(installed) == {"leaf-tool", "mid-tool", "root-tool"}
    assert all(item.users == [first.id] for item in installed.values())
    assert all(__import__("pathlib").Path(item.folder).is_dir() for item in installed.values())


def test_partial_failure_rolls_back_new_tools_records_and_logs(session, graph, monkeypatch):
    original = toolinstall.install

    def fail_root(*args, **kwargs):
        if args[2].name == "root-tool":
            raise ToolError("stand-in failure")
        return original(*args, **kwargs)

    monkeypatch.setattr(toolhooks.toolinstall, "install", fail_root)
    console = run(session, "tool install root-tool")
    assert lines_matching(console, "fail") == ["stand-in failure"]
    assert current_tools(session.box) == []
    assert toolstate.load_installed(session.paths) == {}
    assert not session.paths.tool_log.exists() or not session.paths.tool_log.read_text()


def test_dependency_cycle_is_refused_before_download(session, graph):
    entries = dict(graph.entries)
    entries["leaf-tool"] = replace(entries["leaf-tool"], depends=["root-tool"])
    toolkit.write_index(graph.folder, list(entries.values()))
    console = run(session, "tool install root-tool")
    assert "ordinary tool dependency cycle" in lines_matching(console, "fail")[0]
    assert toolstate.load_installed(session.paths) == {}


def test_missing_dependency_is_refused_before_download(session, graph):
    entries = dict(graph.entries)
    entries["root-tool"] = replace(entries["root-tool"], depends=["not-present"])
    toolkit.write_index(graph.folder, list(entries.values()))
    console = run(session, "tool install root-tool")
    assert "ordinary dependency 'not-present' is not in the index" in lines_matching(console, "fail")[0]
    assert toolstate.load_installed(session.paths) == {}


def test_schema_4_mixed_catalog_keeps_notes_and_round_trips_backend_metadata(session, graph):
    _zip, notes = toolkit.make_notes_entry(graph.folder)
    toolkit.write_index(graph.folder, [*graph.entries.values(), notes])
    index = toolindex.load_index(session.paths, session.settings, now=NOW)
    builds = {tool.name: tool.builds[-1] for tool in index.tools}
    assert builds["playbooks"].kind == "notes"
    assert builds["root-tool"].depends == ["mid-tool"]
    backend = builds["root-tool"].backends[2]
    assert (backend.name, backend.commands, backend.apt) == ("freerdp", ["xfreerdp3", "xfreerdp"], ["freerdp3-x11"])


@pytest.mark.parametrize(
    "overrides, message",
    [
        ({"depends": ["root-tool"]}, "cannot depend on itself"),
        ({"depends": []}, "schema 4 needs ordinary dependencies or optional backends"),
        (
            {"depends": ["netexec"], "backend": [BACKENDS[0]]},
            "both a dependency and an optional backend",
        ),
        (
            {"depends": ["leaf-tool"], "backend": [{**BACKENDS[1], "commands": []}]},
            "needs plain executable names",
        ),
    ],
)
def test_invalid_schema_4_metadata_is_refused(overrides, message):
    data = toolkit.sample_manifest(schema=4, name="root-tool", **overrides)
    with pytest.raises(ToolError, match=message):
        parse_manifest(data)


def test_restore_preserves_dependency_ownership_for_later_orphan_removal(session, graph):
    run(session, "tool install root-tool")
    installed = toolstate.load_installed(session.paths)
    for item in installed.values():
        toolinstall.remove_files(session.paths, item)
    toolstate.save_installed(session.paths, {})

    console = run(session, "tool doctor root-tool")  # diagnostics do not restore anything
    assert console.asked == []
    session.console = FakeConsole(["y"])
    toolhooks.restore(session)
    assert not lines_matching(session.console, "warn")
    assert records(session)["root-tool"].dependency is False
    assert records(session)["mid-tool"].dependency is True
    assert records(session)["leaf-tool"].dependency is True

    console = run(session, "tool remove root-tool", "y")
    assert not lines_matching(console, "fail")
    assert current_tools(session.box) == []
    assert toolstate.load_installed(session.paths) == {}
