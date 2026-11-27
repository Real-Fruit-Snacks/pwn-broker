import subprocess
import tomllib
from dataclasses import replace
from types import SimpleNamespace

import pytest
import tomli_w

import toolkit
from helpers import NOW
from pwn_broker import shell  # noqa: F401  (fills the command registry)
from pwn_broker import lifecycle, toolhooks, toolindex, toolinstall, toolstate
from pwn_broker.console import FakeConsole
from pwn_broker.lifecycle import export_box, finish_box, import_box
from pwn_broker.model import current_tools
from pwn_broker.paths import AppPaths
from pwn_broker.session import load_session
from pwn_broker.shell import cmd_tool
from pwn_broker.shell.commands import dispatch
from pwn_broker.store import StoreError, load_box, save_box
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
    assert records(session)["root-tool"].optional == []
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
    assert records(session)["root-tool"].optional == ["netexec"]
    assert records(session)["netexec"].dependency is True
    assert console.asked == []


# what apt-get install --simulate prints on a Kali with neither package, cut to what matters:
# the two asked for bring three more, and one package already there is upgraded for them
PLAN = """\
NOTE: This is only a simulation!
      apt-get needs root privileges for real execution.
Reading package lists...
Building dependency tree...
The following additional packages will be installed:
  libfreerdp3-3 liblinear4 libwinpr3-3
The following NEW packages will be installed:
  freerdp3-x11 libfreerdp3-3 liblinear4 libwinpr3-3 nmap
The following packages will be upgraded:
  libssl3t64
1 upgraded, 5 newly installed, 0 to remove and 78 not upgraded.
Inst libssl3t64 [3.5.0-1] (3.5.4-1 kali-rolling [amd64]) []
Inst liblinear4 (2.3.0+dfsg-5+b2 kali-rolling [amd64])
Inst nmap (7.99+dfsg-1kali1 kali-rolling [amd64])
Inst libwinpr3-3 (3.16.0+dfsg-2 kali-rolling [amd64])
Inst libfreerdp3-3 (3.16.0+dfsg-2 kali-rolling [amd64])
Inst freerdp3-x11 (3.16.0+dfsg-2 kali-rolling [amd64])
Conf libssl3t64 (3.5.4-1 kali-rolling [amd64])
Conf nmap (7.99+dfsg-1kali1 kali-rolling [amd64])
"""
APT = ["apt-get", "install", "--no-install-recommends", "-o", "APT::Cmd::Pattern-Only=true"]
SIMULATE = [*APT, "--simulate", "--", "nmap", "freerdp3-x11"]
INSTALL = [
    *APT, "-y", "--no-remove", "-o", "Dpkg::Options::=--force-confold",
    "--", "nmap", "freerdp3-x11",
]  # fmt: skip


def apt(monkeypatch, plan=PLAN, *, planned=0, ran=0, said="", uid=1000):
    """A stand-in apt-get: `plan` is what its simulation prints. Returns the calls made."""
    calls = []
    monkeypatch.setattr(cmd_tool.os, "geteuid", lambda: uid, raising=False)

    def fake_run(argv, **kwargs):
        calls.append((argv, kwargs))
        if "--simulate" in argv:
            return SimpleNamespace(returncode=planned, stdout=plan, stderr=said)
        return SimpleNamespace(returncode=ran, stdout="", stderr=said)

    monkeypatch.setattr(cmd_tool, "_run", fake_run)
    return calls


def test_full_shows_apts_own_plan_then_runs_it_without_a_question_left_to_ask(
    session, graph, monkeypatch
):
    calls = apt(monkeypatch)
    console = run(session, "tool install root-tool --full", "y")
    assert not lines_matching(console, "fail")
    (planned, plan_kwargs), (ran, run_kwargs) = calls

    # the plan is apt's own, from a simulation that needs no root
    assert planned == SIMULATE
    assert plan_kwargs["env"]["LC_ALL"] == "C"
    # what the user agreed to is shown whole: every package apt adds, and the line it runs
    line = "sudo DEBIAN_FRONTEND=noninteractive " + " ".join(INSTALL)
    assert lines_matching(console, "field") == [
        "backend  nmap: apt nmap",
        "backend  freerdp: apt freerdp3-x11",
        "installs  freerdp3-x11, libfreerdp3-3, liblinear4, libwinpr3-3, nmap",
        "upgrades  libssl3t64",
        f"command  {line}",
    ]
    assert console.asked == ["install 5 apt packages and upgrade 1 for root-tool?"]

    # apt-get is told yes and given nothing to read, so it cannot stop at a question nobody sees
    assert ran == ["sudo", "DEBIAN_FRONTEND=noninteractive", *INSTALL]
    for kwargs in (plan_kwargs, run_kwargs):
        assert kwargs["stdin"] is subprocess.DEVNULL
        assert (kwargs["capture_output"], kwargs["text"]) == (True, True)
        assert "shell" not in kwargs
    assert run_kwargs["env"]["DEBIAN_FRONTEND"] == "noninteractive"
    assert "installed with apt: nmap, freerdp3-x11" in lines_matching(console, "ok")
    assert set(toolstate.load_installed(session.paths)) == {
        "leaf-tool", "mid-tool", "netexec", "root-tool",
    }


def test_as_root_apt_runs_without_sudo(session, graph, monkeypatch):
    calls = apt(monkeypatch, uid=0)
    console = run(session, "tool install root-tool --full", "y")
    assert [argv for argv, _kwargs in calls] == [SIMULATE, INSTALL]
    assert calls[1][1]["env"]["DEBIAN_FRONTEND"] == "noninteractive"
    assert f"command  DEBIAN_FRONTEND=noninteractive {' '.join(INSTALL)}" in lines_matching(
        console, "field"
    )


def test_declined_apt_plan_never_runs_and_is_explicitly_reported(session, graph, monkeypatch):
    calls = apt(monkeypatch)
    console = run(session, "tool install root-tool --full", "n")
    assert [argv for argv, _kwargs in calls] == [SIMULATE]
    assert lines_matching(console, "warn") == ["apt-backed backends were not installed"]
    assert "root-tool" in toolstate.load_installed(session.paths)


def test_an_apt_plan_that_removes_a_package_is_not_offered(session, graph, monkeypatch):
    plan = PLAN + "Remv freerdp2-x11 [2.11.7+dfsg1-6]\nPurg old-thing [1.0]\n"
    calls = apt(monkeypatch, plan)
    console = run(session, "tool install root-tool --full")
    assert [argv for argv, _kwargs in calls] == [SIMULATE]
    assert console.asked == []
    assert "removes  freerdp2-x11, old-thing" in lines_matching(console, "field")
    assert lines_matching(console, "warn") == [
        "apt would remove 2 packages to install these; apt-backed backends were not installed"
    ]
    # the pwn-shop packages still come, as when the plan is declined
    assert set(toolstate.load_installed(session.paths)) == {
        "leaf-tool", "mid-tool", "netexec", "root-tool",
    }


def test_an_apt_plan_with_nothing_to_install_asks_nothing(session, graph, monkeypatch):
    plan = "nmap is already the newest version (7.99+dfsg-1kali1).\n0 upgraded, 0 newly installed\n"
    calls = apt(monkeypatch, plan)
    console = run(session, "tool install root-tool --full")
    assert [argv for argv, _kwargs in calls] == [SIMULATE]
    assert console.asked == []
    assert lines_matching(console, "warn") == [
        "apt has nothing to install for these; tool doctor root-tool shows what is missing"
    ]
    assert "root-tool" in toolstate.load_installed(session.paths)


def test_an_upgrade_alone_is_asked_about_as_one(session, graph, monkeypatch):
    apt(monkeypatch, "Inst libssl3t64 [3.5.0-1] (3.5.4-1 kali-rolling [amd64])\n")
    console = run(session, "tool install root-tool --full", "n")
    assert console.asked == ["upgrade 1 apt package for root-tool?"]


def test_a_long_apt_plan_is_shown_over_several_rows(session, graph, monkeypatch):
    names = [f"libsomething-with-a-long-name{n}" for n in range(1, 6)]
    apt(monkeypatch, "".join(f"Inst {name} (1.0 kali-rolling [amd64])\n" for name in names))
    console = run(session, "tool install root-tool --full", "n")
    fields = lines_matching(console, "field")
    assert fields[2:5] == [
        f"installs  {names[0]}, {names[1]},",
        f"  {names[2]}, {names[3]},",
        f"  {names[4]}",
    ]


def test_an_apt_plan_that_cannot_be_made_aborts_before_any_package_download(
    session, graph, monkeypatch
):
    calls = apt(monkeypatch, "", planned=100, said="E: Unable to locate package freerdp3-x11")
    console = run(session, "tool install root-tool --full", "y")
    assert lines_matching(console, "fail") == [
        "apt-get could not plan the install (exit 100):\nE: Unable to locate package freerdp3-x11"
    ]
    assert len(calls) == 1 and console.asked == []
    assert toolstate.load_installed(session.paths) == {}
    assert current_tools(session.box) == []


def test_failed_apt_run_aborts_before_any_package_download(session, graph, monkeypatch):
    apt(monkeypatch, ran=7, said="offline", uid=0)
    console = run(session, "tool install root-tool --full", "y")
    assert lines_matching(console, "fail") == ["apt-get failed (exit 7):\noffline"]
    assert toolstate.load_installed(session.paths) == {}
    assert current_tools(session.box) == []


def test_an_apt_name_built_outside_the_parser_is_judged_again(session, graph, monkeypatch):
    # the index and the manifest refuse such a name; an entry need not have come through them
    calls = apt(monkeypatch)
    monkeypatch.setattr(cmd_tool, "_apt_backends", lambda session, entry: [("nmap", ["nmap-"])])
    console = run(session, "tool install root-tool --full", "y")
    assert lines_matching(console, "fail") == ["'nmap-' is not a Debian package name"]
    assert calls == []
    assert toolstate.load_installed(session.paths) == {}


@pytest.mark.parametrize(
    "name",
    [
        "nmap-", "python3-", "x.-", "a.b+", "g++", "nmap.", "a", "", "-y", "--reinstall",
        "nmap=7.95", "nmap/kali-rolling", "nmap:amd64", "nma*", "nma?", "Nmap", "nmap ", "nmap\n",
        "^task",
    ],
)  # fmt: skip
def test_an_apt_name_apt_get_would_read_as_something_else_is_refused(name):
    # nmap- asks apt-get install to remove nmap, and nmap+ to install it; the others are an
    # option, a version, a release, an architecture or a pattern
    backend = {**BACKENDS[1], "apt": [name]}
    data = toolkit.sample_manifest(schema=4, name="root-tool", backend=[backend])
    with pytest.raises(ToolError, match="package names must be lower-case Debian names"):
        parse_manifest(data)
    with pytest.raises(ToolError, match=r"tool x\.build\[0\]\.backend\[0\]\.apt: package names"):
        toolindex.parse_backends([backend], "x", 4, "tool x.build[0].backend")


@pytest.mark.parametrize(
    "name", ["nmap", "freerdp3-x11", "python3.13", "libstdc++6", "g++-14", "0ad", "sl"]
)
def test_debian_package_names_are_accepted(name):
    backend = {**BACKENDS[1], "apt": [name]}
    data = toolkit.sample_manifest(schema=4, name="root-tool", backend=[backend])
    assert parse_manifest(data).backends[0].apt == [name]


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


# ---- the --full selection belongs to the box


SAVED = dict(fix=lambda path: 0, unsaved=lambda box: False)
HOOK_LISTS = ("BLOCK_HOOKS", "SUMMARY_HOOKS", "PRE_PACK_HOOKS", "UNDO_HOOKS", "RESTORE_HOOKS", "IMPORT_HOOKS")


@pytest.fixture
def registered(monkeypatch):
    for name in HOOK_LISTS:
        monkeypatch.setattr(lifecycle, name, [])
    toolhooks.register()


def kali_has(monkeypatch, *commands):
    monkeypatch.setattr(
        cmd_tool, "_lookup",
        lambda command, path=None: f"/usr/bin/{command}" if command in commands else None,
    )


@pytest.fixture
def full(session, graph, monkeypatch):
    """root-tool installed with --full, and solo-tool, which nothing needs, beside it.

    nmap and FreeRDP are on Kali, so --full asks nothing and NetExec is its one package backend.
    """
    kali_has(monkeypatch, "nmap", "xfreerdp3")
    solo = package(graph.folder, "solo-tool")
    toolkit.write_index(graph.folder, [*graph.entries.values(), solo])
    run(session, "tool install root-tool --full")
    run(session, "tool install solo-tool")
    return session


def wipe_machine(session):
    """A machine with none of the box's tools: another one, or this one after the finish."""
    for item in toolstate.load_installed(session.paths).values():
        toolinstall.remove_files(session.paths, item)
    toolstate.save_installed(session.paths, {})


def tool_rows(box):
    """The box's current tool rows as box.toml holds them."""
    data = tomllib.loads((box.path / "box.toml").read_text(encoding="utf-8"))
    return {row["name"]: row for row in data["tools"] if "removed" not in row}


def test_the_full_selection_is_written_on_the_boxs_own_row_and_nowhere_else(full):
    rows = tool_rows(full.box)
    assert rows["root-tool"]["optional"] == ["netexec"]
    # a tool installed without --full has the row it always had
    assert all("optional" not in row for name, row in rows.items() if name != "root-tool")
    assert load_box(full.box.path).tools == full.box.tools
    # the machine's list holds no selection: it is the box's, not the machine's
    assert all(item.optional == [] for item in toolstate.load_installed(full.paths).values())


def test_a_box_from_before_the_selection_was_kept_still_loads(session, graph):
    run(session, "tool install root-tool")
    before = (session.box.path / "box.toml").read_bytes()
    assert b"optional" not in before
    box = load_box(session.box.path)
    assert [t.optional for t in box.tools] == [[], [], []]
    save_box(box)
    assert (box.path / "box.toml").read_bytes() == before


def test_a_selection_that_is_not_a_list_of_names_is_refused(full):
    file = full.box.path / "box.toml"
    data = tomllib.loads(file.read_text(encoding="utf-8"))
    for row in data["tools"]:
        if row["name"] == "root-tool":
            row["optional"] = [1]
    file.write_text(tomli_w.dumps(data), encoding="utf-8")
    with pytest.raises(StoreError, match="tools.optional has the wrong type"):
        load_box(full.box.path)


def test_finish_and_reopen_keep_the_full_selection(full, registered):
    full.console = FakeConsole(["y", "n"])  # finish this box, keep its working folder
    assert finish_box(full, **SAVED) is not None
    assert toolstate.load_installed(full.paths) == {}

    # as the menu reopens it: the box as it is on disk, then the restore hooks
    box = load_box(full.box.path)
    lifecycle.reopen_box(box)
    session = load_session(full.paths, full.settings, FakeConsole(["y"]), box, full.clock)
    for hook in lifecycle.RESTORE_HOOKS:
        hook(session)
    assert session.console.asked == ["install these tools again?"]
    assert not lines_matching(session.console, "warn")
    assert records(session)["root-tool"].optional == ["netexec"]
    assert box.id in toolstate.load_installed(session.paths)["netexec"].users

    console = run(session, "tool remove solo-tool", "y")
    assert not any("automatic dependencies" in text for text in lines_matching(console, "info"))
    assert set(toolstate.load_installed(session.paths)) == {
        "leaf-tool", "mid-tool", "netexec", "root-tool",
    }
    assert "netexec" in records(session)


def test_export_and_import_keep_the_full_selection(full, registered, tmp_path):
    archive = export_box(full, fix=lambda p: 0)
    assert archive is not None
    wipe_machine(full)
    paths = AppPaths(opt=full.paths.opt, home=tmp_path / "another-home")
    console = FakeConsole(["y"])
    box = import_box(paths, full.settings, console, archive, full.clock)
    assert box is not None
    assert not lines_matching(console, "warn")
    assert {t.name: t.optional for t in current_tools(box)}["root-tool"] == ["netexec"]

    session = load_session(paths, full.settings, FakeConsole(), box, full.clock)
    console = run(session, "tool remove solo-tool", "y")
    assert not any("automatic dependencies" in text for text in lines_matching(console, "info"))
    assert "netexec" in toolstate.load_installed(paths)
    console = run(session, "tool remove netexec")
    assert lines_matching(console, "fail") == [
        "netexec is required by root-tool; remove the parent first"
    ]


def test_reopen_selects_the_recorded_backends_again_with_the_tool(full):
    # the tool's row is what says so: the backend comes back even when its own row is gone
    full.box.tools = [t for t in full.box.tools if t.name != "netexec"]
    save_box(full.box)
    wipe_machine(full)
    full.console = FakeConsole(["y"])
    toolhooks.restore(full)
    assert not lines_matching(full.console, "warn")
    assert records(full)["netexec"].dependency is True
    assert full.box.id in toolstate.load_installed(full.paths)["netexec"].users
    assert records(full)["root-tool"].optional == ["netexec"]


def test_removing_the_parent_takes_its_selected_backends_with_it(full):
    console = run(full, "tool remove root-tool", "y")
    assert not lines_matching(console, "fail")
    assert lines_matching(console, "info") == [
        "automatic dependencies no longer needed: mid-tool, netexec, leaf-tool"
    ]
    assert set(records(full)) == {"solo-tool"}


def test_a_second_box_that_installed_minimally_stays_minimal(full, other, registered):
    first = full.box
    session = full
    session.box = other
    run(session, "tool install root-tool")
    assert set(records(session)) == {"leaf-tool", "mid-tool", "root-tool"}
    assert records(session)["root-tool"].optional == []
    assert "optional" not in tool_rows(other)["root-tool"]
    console = run(session, "tool doctor root-tool")
    assert not any(text.startswith("optional") for text in lines_matching(console, "field"))

    # finished and reopened, the second box gets back what it had and no more
    toolhooks.undo(session)
    session.console = FakeConsole(["y"])
    toolhooks.restore(session)
    assert set(records(session)) == {"leaf-tool", "mid-tool", "root-tool"}
    installed = toolstate.load_installed(session.paths)
    assert installed["netexec"].users == [first.id]
    assert set(installed["root-tool"].users) == {first.id, other.id}

    session.box = first
    console = run(session, "tool doctor root-tool")
    assert "optional  netexec" in lines_matching(console, "field")


def test_another_boxs_selection_does_not_hold_a_dependency_in_this_one(full, graph, other):
    first = full.box
    # nx-user needs NetExec outright; the second box has root-tool without its backends
    user = package(graph.folder, "nx-user", depends=["netexec"])
    solo = package(graph.folder, "solo-tool")
    toolkit.write_index(graph.folder, [*graph.entries.values(), solo, user])
    session = full
    session.box = other
    run(session, "tool install root-tool")
    run(session, "tool install nx-user")
    assert records(session)["netexec"].dependency is True

    console = run(session, "tool remove nx-user", "y")
    assert lines_matching(console, "info") == ["automatic dependencies no longer needed: netexec"]
    assert set(records(session)) == {"leaf-tool", "mid-tool", "root-tool"}
    # the first box selected it, so its files stay
    assert toolstate.load_installed(session.paths)["netexec"].users == [first.id]


def test_full_on_a_box_that_has_the_tool_records_the_selection(session, graph, monkeypatch):
    kali_has(monkeypatch, "nmap", "xfreerdp3")
    run(session, "tool install root-tool")
    assert records(session)["root-tool"].optional == []
    console = run(session, "tool install root-tool --full")
    assert not lines_matching(console, "fail")
    assert records(session)["root-tool"].optional == ["netexec"]
    assert records(session)["root-tool"].dependency is False
    assert tool_rows(session.box)["root-tool"]["optional"] == ["netexec"]


def test_a_selection_0_1_14_kept_for_the_machine_still_holds_its_backends(full):
    # 0.1.14 wrote the selection in the machine's list and none on the box's row
    installed = toolstate.load_installed(full.paths)
    installed["root-tool"].optional = ["netexec"]
    toolstate.save_installed(full.paths, installed)
    full.box.tools = [replace(t, optional=[]) for t in full.box.tools]
    save_box(full.box)

    console = run(full, "tool remove solo-tool", "y")
    assert not any("automatic dependencies" in text for text in lines_matching(console, "info"))
    assert "netexec" in records(full)
    assert toolstate.load_installed(full.paths)["root-tool"].optional == ["netexec"]
    console = run(full, "tool remove netexec")
    assert lines_matching(console, "fail") == [
        "netexec is required by root-tool; remove the parent first"
    ]
    console = run(full, "tool doctor root-tool")
    assert "optional  netexec" in lines_matching(console, "field")


def test_a_recorded_backend_the_build_does_not_declare_is_not_installed(full, graph):
    # a row edited by hand names a package the index has and one it has not
    extra = package(graph.folder, "extra-tool")
    solo = package(graph.folder, "solo-tool")
    toolkit.write_index(graph.folder, [*graph.entries.values(), solo, extra])
    full.box.tools = [
        replace(t, optional=["netexec", "extra-tool", "no-such-tool"]) if t.name == "root-tool" else t
        for t in full.box.tools
    ]
    save_box(full.box)
    wipe_machine(full)
    full.console = FakeConsole(["y"])
    toolhooks.restore(full)
    assert not lines_matching(full.console, "warn")
    assert set(toolstate.load_installed(full.paths)) == {
        "leaf-tool", "mid-tool", "netexec", "root-tool", "solo-tool",
    }
