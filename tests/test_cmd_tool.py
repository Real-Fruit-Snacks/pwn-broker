from dataclasses import replace
from types import SimpleNamespace

import pytest

import toolkit
from helpers import NOW, make_cred
from pwn_broker import shell  # noqa: F401  (fills the command registry)
from pwn_broker import toolhooks, toolinstall, toolstate
from pwn_broker.config import Settings
from pwn_broker.console import FakeConsole
from pwn_broker.shell import cmd_tool
from pwn_broker.shell.app import completions, toolbar_text
from pwn_broker.shell.commands import COMMANDS, dispatch
from pwn_broker.store import load_box
from pwn_broker.toolindex import BuildEntry
from pwn_broker.toolpkg import ToolError, machine_arch

EXAMPLE = "kerbrute userenum -d {domain} --dc {ip} {hostname} {lhost} {nope} {0}"


@pytest.fixture
def shop(tmp_path, session, monkeypatch):
    folder = tmp_path / "index"
    home = tmp_path / "user"
    home.mkdir()
    monkeypatch.setattr(toolhooks, "_user_home", lambda: home)
    monkeypatch.setattr(cmd_tool, "_lookup", lambda command, path=None: None)
    entries = []
    for version in ("1.0.2", "1.0.3"):
        _zip, entry = toolkit.make_entry(
            folder, {"version": version, "examples": [EXAMPLE], "data": {"home": [".kerb"]}}
        )
        entries.append(entry)
    _zip, ligolo = toolkit.make_entry(
        folder,
        {
            "name": "ligolo-ng", "version": "0.9.2", "kind": "both", "needs_root": True,
            "command": [{"name": "ligolo-proxy", "type": "binary", "path": "files/proxy"}],
            "upload": [{"path": "files/agent", "as": "agent"}],
        },
        {"files/proxy": b"#!/bin/sh\n", "files/agent": b"A"},
    )  # fmt: skip
    entries.append(ligolo)
    toolkit.write_index(folder, entries)
    session.settings = replace(session.settings, tools_index=str(folder))
    return SimpleNamespace(folder=folder, home=home, entries=entries)


def run(session, line, *answers):
    session.console = FakeConsole(list(answers))
    dispatch(session, line)
    return session.console


def lines(console, kind):
    return [text for k, text in console.lines if k == kind]


def table(console):
    assert len(console.tables) == 1
    return console.tables[0]


def install_for(box, shop, entry, paths):
    # another box takes the tool first
    toolinstall.install(
        paths, box, entry, shop.folder / entry.file,
        installed=toolstate.load_installed(paths), unfinished={box.id: box.name},
        home=shop.home, console=FakeConsole(), now=NOW, on_path=lambda n: None,
    )  # fmt: skip


def test_commands_are_registered_with_help():
    for name in (
        "tool list", "tool search", "tool info", "tool install", "tool remove",
        "tool refresh", "tool cache clear",
    ):  # fmt: skip
        assert COMMANDS[name][1]


# ---- list and search


def test_list_shows_every_tool_with_status_and_kali(session, shop, monkeypatch):
    run(session, "tool install kerbrute")
    seen = []

    def lookup(command, path=None):
        seen.append((command, path))
        return "/usr/bin/ligolo-proxy" if command == "ligolo-proxy" else None

    monkeypatch.setattr(cmd_tool, "_lookup", lookup)
    monkeypatch.setenv("PATH", f"{session.paths.bin}{cmd_tool.os.pathsep}/usr/bin")
    columns, rows = table(run(session, "tool list"))
    assert columns == ["name", "version", "kind", "status", "kali"]
    assert rows == [
        ["kerbrute", "1.0.3-1", "kali", "installed", "no"],
        ["ligolo-ng", "0.9.2-1", "both", "", "yes"],
    ]
    # the app's own bin folder is never part of the search
    assert seen and all(path == "/usr/bin" for _c, path in seen)


def test_list_installed_adds_the_run_column(session, shop):
    run(session, "tool install kerbrute")
    run(session, "tool install ligolo-ng")
    columns, rows = table(run(session, "tool list --installed"))
    assert columns == ["name", "version", "kind", "status", "kali", "run"]
    assert [r[0] for r in rows] == ["kerbrute", "ligolo-ng"]
    assert rows[0][5] == "kerbrute"
    assert rows[1][5] == "ligolo-proxy"


def test_list_installed_for_an_upload_only_tool_shows_the_upload_folder(session, shop):
    manifest = toolkit.sample_manifest(
        name="chisel", kind="upload", arch=machine_arch(),
        upload=[{"path": "files/chisel", "as": "chisel"}],
    )  # fmt: skip
    del manifest["command"]
    zip_path, size, sha = toolkit.make_package(shop.folder, manifest, {"files/chisel": b"C"})
    built = BuildEntry("chisel", "1.0.3", 1, "upload", False, [], zip_path.name, "", size, sha)
    toolkit.write_index(shop.folder, [*shop.entries, built])
    run(session, "tool install chisel")
    _columns, rows = table(run(session, "tool list --installed"))
    assert rows[0][0] == "chisel"
    assert rows[0][5] == (session.paths.upload / "chisel").as_posix()


def test_list_installed_with_nothing_is_one_info_line(session, shop):
    console = run(session, "tool list --installed")
    assert lines(console, "info") == ["no tools installed for forest"]
    assert console.tables == []


def test_list_with_an_empty_index_is_one_info_line(session, shop):
    toolkit.write_index(shop.folder, [])
    console = run(session, "tool list")
    assert lines(console, "info") == ["no tools in the index"]


def test_list_rejects_an_unknown_option(session, shop):
    assert lines(run(session, "tool list --all"), "fail") == ["unknown option: --all"]


def test_list_without_an_index_is_one_fail_line_with_the_location(session, tmp_path):
    session.settings = replace(session.settings, tools_index=str(tmp_path / "nowhere"))
    console = run(session, "tool list")
    failed = lines(console, "fail")
    assert len(failed) == 1
    assert str(tmp_path / "nowhere") in failed[0]
    assert console.tables == []


def test_search_matches_every_word(session, shop):
    columns, rows = table(run(session, "tool search stand-in ker"))
    assert columns == ["name", "version", "kind", "status", "description"]
    assert rows == [["kerbrute", "1.0.3-1", "kali", "", "kerbrute stand-in"]]


def test_search_without_words_fails(session, shop):
    console = run(session, "tool search")
    assert len(lines(console, "fail")) == 1
    assert console.tables == []


def test_search_with_no_match_is_an_info_line(session, shop):
    console = run(session, "tool search zzz")
    assert lines(console, "info") == ["no tools match zzz"]


# ---- info


def test_info_for_a_tool_that_is_not_installed(session, shop):
    console = run(session, "tool info kerbrute")
    text = "\n".join(lines(console, "info"))
    assert "kerbrute 1.0.3-1" in text
    assert "kerbrute stand-in" in text
    assert "kali" in text and "MIT" in text
    assert "https://example.invalid/kerbrute" in text
    assert "1.0.2" in text and "1.0.3" in text
    assert "userenum" not in text
    assert not lines(console, "fail")


def test_info_for_an_unknown_tool_is_one_fail_line(session, shop):
    console = run(session, "tool info kerbrut")
    assert len(lines(console, "fail")) == 1
    assert "kerbrute" in lines(console, "fail")[0]


def test_info_for_an_installed_tool_fills_the_examples(session, shop):
    session.creds.append(make_cred(domain="OLD"))
    session.creds.append(make_cred(n=2, domain=""))
    session.creds.append(make_cred(n=3, domain="HTB.LOCAL"))
    run(session, "tool install kerbrute")
    joined = "\n".join(lines(run(session, "tool info kerbrute"), "info"))
    folder = toolstate.load_installed(session.paths)["kerbrute"].folder
    assert folder in joined
    assert ".kerb" in joined
    assert (
        "kerbrute userenum -d HTB.LOCAL --dc 10.10.10.161 forest.htb.local <lhost> {nope} {0}"
        in joined
    )


def test_info_shows_missing_values_as_placeholders(session, shop):
    run(session, "tool install kerbrute")
    session.current = None
    joined = "\n".join(lines(run(session, "tool info kerbrute"), "info"))
    assert "kerbrute userenum -d <domain> --dc <ip> <hostname> <lhost> {nope} {0}" in joined


def test_info_shows_sudo_and_upload_details_for_a_root_tool(session, shop):
    run(session, "tool install ligolo-ng")
    joined = "\n".join(lines(run(session, "tool info ligolo-ng"), "info"))
    assert f"sudo {(session.paths.bin / 'ligolo-proxy').as_posix()}" in joined
    assert (session.paths.upload / "ligolo-ng").as_posix() in joined
    assert "agent" in joined


def test_a_value_that_looks_like_a_placeholder_is_not_filled_again(session, shop):
    session.creds.append(make_cred(domain="{ip}"))
    run(session, "tool install kerbrute")
    joined = "\n".join(lines(run(session, "tool info kerbrute"), "info"))
    assert "-d {ip} --dc 10.10.10.161" in joined


def test_info_shows_no_install_details_for_a_tool_another_box_installed(session, shop, other):
    install_for(other, shop, shop.entries[1], session.paths)
    joined = "\n".join(lines(run(session, "tool info kerbrute"), "info"))
    assert "userenum" not in joined


# ---- install


def test_install_prints_the_install_output_and_records_the_tool(session, shop):
    console = run(session, "tool install kerbrute")
    assert lines(console, "ok") == ["kerbrute 1.0.3 installed"]
    assert any(t.startswith("run   kerbrute") for t in lines(console, "info"))
    assert [t.name for t in load_box(session.box.path).tools] == ["kerbrute"]
    assert (session.paths.bin / "kerbrute").exists()
    assert session.box.id in toolstate.load_installed(session.paths)["kerbrute"].users


def test_install_a_root_tool_prints_the_sudo_form(session, shop):
    console = run(session, "tool install ligolo-ng")
    assert f"      sudo {(session.paths.bin / 'ligolo-proxy').as_posix()}" in lines(console, "info")
    assert any(t.startswith("files ") for t in lines(console, "info"))


def test_install_at_a_version_takes_that_version(session, shop):
    console = run(session, "tool install kerbrute@1.0.2")
    assert lines(console, "ok") == ["kerbrute 1.0.2 installed"]


def test_install_an_unknown_version_lists_the_versions(session, shop):
    console = run(session, "tool install kerbrute@9.9.9")
    failed = lines(console, "fail")
    assert len(failed) == 1
    assert "1.0.2" in failed[0] and "1.0.3" in failed[0]
    assert not (session.paths.bin / "kerbrute").exists()
    assert load_box(session.box.path).tools == []


def test_install_an_unknown_tool_is_one_fail_line(session, shop):
    assert len(lines(run(session, "tool install nothing"), "fail")) == 1


def test_install_with_no_index_says_where_it_looked_and_does_nothing(session, tmp_path):
    session.settings = replace(session.settings, tools_index=str(tmp_path / "nowhere"))
    console = run(session, "tool install kerbrute")
    failed = lines(console, "fail")
    assert len(failed) == 1 and str(tmp_path / "nowhere") in failed[0]
    assert not session.paths.tools.exists() or not any(session.paths.tools.iterdir())
    assert load_box(session.box.path).tools == []


def test_install_needs_a_name_and_a_version_after_the_at_sign(session, shop):
    assert lines(run(session, "tool install"), "fail") == ["missing argument: tool name"]
    assert len(lines(run(session, "tool install kerbrute@"), "fail")) == 1
    assert len(lines(run(session, "tool install @1.0.3"), "fail")) == 1


def test_install_twice_is_one_info_line(session, shop):
    run(session, "tool install kerbrute")
    console = run(session, "tool install kerbrute")
    assert len(console.lines) == 1 and console.lines[0][0] == "info"
    assert "already installed" in console.lines[0][1]


def test_install_another_build_is_refused_with_one_fail_line(session, shop):
    run(session, "tool install kerbrute@1.0.2")
    console = run(session, "tool install kerbrute@1.0.3")
    failed = lines(console, "fail")
    assert len(failed) == 1 and "tool remove kerbrute" in failed[0]
    assert lines(console, "ok") == []


def test_install_a_tool_with_home_paths_warns_when_another_box_uses_it(session, shop, other):
    install_for(other, shop, shop.entries[1], session.paths)
    console = run(session, "tool install kerbrute")
    warned = lines(console, "warn")
    assert len(warned) == 1
    assert "Cascade" in warned[0] and "both boxes" in warned[0]
    assert lines(console, "ok") == ["kerbrute 1.0.3 installed"]


def test_install_without_home_paths_never_warns(session, shop, other):
    install_for(other, shop, shop.entries[2], session.paths)
    console = run(session, "tool install ligolo-ng")
    assert lines(console, "warn") == []


def test_install_reports_a_tool_error_as_one_fail_line(session, shop, monkeypatch):
    def boom(*a, **k):
        raise ToolError("the zip is wrong")

    monkeypatch.setattr(cmd_tool.toolinstall, "install", boom)
    assert lines(run(session, "tool install kerbrute"), "fail") == ["the zip is wrong"]


# ---- remove


def test_remove_deletes_the_files_when_no_other_box_uses_the_tool(session, shop):
    run(session, "tool install kerbrute")
    console = run(session, "tool remove kerbrute", "y")
    assert console.asked == ["remove kerbrute?"]
    assert lines(console, "ok") == ["kerbrute removed; its files are deleted"]
    assert not (session.paths.bin / "kerbrute").exists()
    assert load_box(session.box.path).tools == []
    assert toolstate.load_installed(session.paths) == {}


def test_remove_defaults_to_no(session, shop):
    run(session, "tool install kerbrute")
    run(session, "tool remove kerbrute", "")
    assert (session.paths.bin / "kerbrute").exists()
    assert [t.name for t in load_box(session.box.path).tools] == ["kerbrute"]


def test_remove_a_tool_the_box_does_not_have_fails(session, shop):
    console = run(session, "tool remove kerbrute")
    assert len(lines(console, "fail")) == 1
    assert console.asked == []


def test_remove_needs_a_name(session, shop):
    assert lines(run(session, "tool remove"), "fail") == ["missing argument: tool name"]


def test_remove_stops_while_the_tool_is_running(session, shop, monkeypatch):
    run(session, "tool install kerbrute")
    marker = toolstate.mark_path(session.paths, "kerbrute", 4321)
    marker.parent.mkdir(parents=True, exist_ok=True)
    marker.write_text("55\n")
    monkeypatch.setattr(toolstate, "_resolve_alive", lambda alive: lambda pid: True)
    monkeypatch.setattr(toolstate, "process_start", lambda pid: None)
    console = run(session, "tool remove kerbrute", "y")
    assert lines(console, "fail") == [toolhooks.running_text(session.paths, "kerbrute", 4321)]
    assert console.asked == []
    assert (session.paths.bin / "kerbrute").exists()


def test_remove_keeps_the_files_another_unfinished_box_uses(session, shop, other):
    install_for(other, shop, shop.entries[1], session.paths)
    run(session, "tool install kerbrute")
    console = run(session, "tool remove kerbrute", "y")
    assert lines(console, "ok") == [
        "kerbrute removed from forest; Cascade still uses it, so its files stay"
    ]
    assert (session.paths.bin / "kerbrute").exists()
    assert load_box(session.box.path).tools == []
    assert toolstate.load_installed(session.paths)["kerbrute"].users == [other.id]


def test_remove_keeps_the_files_while_a_box_cannot_be_read(session, shop):
    run(session, "tool install kerbrute")
    installed = toolstate.load_installed(session.paths)
    installed["kerbrute"].users.append("lost-box")
    toolstate.save_installed(session.paths, installed)
    (session.paths.active / "broken").mkdir()
    (session.paths.active / "broken" / "box.toml").write_text("nope [", encoding="utf-8")
    console = run(session, "tool remove kerbrute", "y")
    assert "still uses it" in lines(console, "ok")[0]
    assert (session.paths.bin / "kerbrute").exists()


def test_remove_leaves_home_data_alone(session, shop):
    run(session, "tool install kerbrute")
    (shop.home / ".kerb").mkdir()
    (shop.home / ".kerb" / "found.txt").write_text("result")
    run(session, "tool remove kerbrute", "y")
    assert (shop.home / ".kerb" / "found.txt").read_text() == "result"


def test_remove_shows_a_failed_removal_as_one_fail_line(session, shop, monkeypatch):
    run(session, "tool install kerbrute")

    def boom(*a, **k):
        raise ToolError("cannot remove it")

    monkeypatch.setattr(cmd_tool.toolinstall, "release", boom)
    assert lines(run(session, "tool remove kerbrute", "y"), "fail") == ["cannot remove it"]


# ---- refresh and cache


def test_refresh_fetches_and_counts_the_tools(session, shop, monkeypatch):
    seen = {}
    real = cmd_tool.toolindex.load_index

    def spy(*a, **k):
        seen.update(k)
        return real(*a, **k)

    monkeypatch.setattr(cmd_tool.toolindex, "load_index", spy)
    assert lines(run(session, "tool refresh"), "ok") == ["index refreshed: 2 tools"]
    assert seen["force"] is True


def test_refresh_with_one_tool_is_singular(session, shop):
    toolkit.write_index(shop.folder, shop.entries[:1])
    assert lines(run(session, "tool refresh"), "ok") == ["index refreshed: 1 tool"]


def test_cache_clear_asks_and_counts(session, shop):
    session.paths.cache.mkdir(parents=True)
    (session.paths.cache / "a-1.0-1.zip").write_bytes(b"x")
    (session.paths.cache / "b-1.0-1.zip").write_bytes(b"x")
    console = run(session, "tool cache clear", "y")
    assert console.asked == ["empty the download cache?"]
    assert lines(console, "ok") == ["2 files removed"]
    assert list(session.paths.cache.glob("*.zip")) == []


def test_cache_clear_defaults_to_no(session, shop):
    session.paths.cache.mkdir(parents=True)
    (session.paths.cache / "a-1.0-1.zip").write_bytes(b"x")
    run(session, "tool cache clear", "")
    assert (session.paths.cache / "a-1.0-1.zip").exists()


def test_cache_clear_with_one_file(session, shop):
    session.paths.cache.mkdir(parents=True)
    (session.paths.cache / "a-1.0-1.zip").write_bytes(b"x")
    assert lines(run(session, "tool cache clear", "y"), "ok") == ["1 file removed"]


# ---- status bar, status, completions


def test_toolbar_counts_the_boxes_tools_after_targets(session, shop):
    start = session.box.started
    assert toolbar_text(session, start) == " forest   dc01  10.10.10.161   1 target   00:00"
    run(session, "tool install kerbrute")
    assert toolbar_text(session, start).endswith("1 target   1 tool   00:00")
    run(session, "tool install ligolo-ng")
    assert toolbar_text(session, start).endswith("1 target   2 tools   00:00")


def test_status_shows_the_tool_count(session, shop):
    assert "tools     0" in lines(run(session, "status"), "info")
    run(session, "tool install kerbrute")
    shown = lines(run(session, "status"), "info")
    assert shown.index("tools     1") == shown.index("targets   1") + 1


def test_completions_for_install_and_info_come_from_the_cached_index(session, shop):
    assert completions(session, "tool install ") == [
        "tool install kerbrute",
        "tool install ligolo-ng",
    ]
    assert completions(session, "tool info l") == ["tool info ligolo-ng"]
    assert completions(session, "tool install z") == []


def test_completions_for_remove_are_this_boxs_tools(session, shop):
    run(session, "tool install kerbrute")
    assert completions(session, "tool remove ") == ["tool remove kerbrute"]
    assert completions(session, "tool remove x") == []


def test_completions_without_an_index_give_nothing_and_no_error(session, tmp_path):
    session.settings = replace(session.settings, tools_index=str(tmp_path / "nowhere"))
    assert completions(session, "tool install ") == []


def test_completions_never_fetch(session, monkeypatch):
    def boom(*a, **k):
        raise AssertionError("fetched")

    monkeypatch.setattr(cmd_tool.toolindex, "load_index", boom)
    session.settings = Settings(tools_index="https://example.invalid/index.toml")
    assert completions(session, "tool install ") == []


def test_completions_survive_a_failing_lookup(session, monkeypatch):
    def boom(*a, **k):
        raise RuntimeError("broken")

    monkeypatch.setattr("pwn_broker.shell.app.toolindex.known_names", boom)
    assert completions(session, "tool install ") == []
