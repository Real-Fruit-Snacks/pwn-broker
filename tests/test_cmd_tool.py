import shutil
from dataclasses import replace
from datetime import datetime, timedelta, timezone
from pathlib import Path
from types import SimpleNamespace

import pytest

import toolkit
from helpers import NOW, make_cred
from pwn_broker import shell  # noqa: F401  (fills the command registry)
from pwn_broker import toolhooks, toolinstall, toolstate
from pwn_broker.config import Settings
from pwn_broker.console import FakeConsole
from pwn_broker.model import ToolRecord, current_tools
from pwn_broker.shell import cmd_tool
from pwn_broker.shell.app import completions, toolbar_text
from pwn_broker.vpn import Tunnel
from pwn_broker.shell.commands import COMMANDS, dispatch
from pwn_broker.store import load_box
from pwn_broker.toolindex import BuildEntry
from pwn_broker.toolpkg import ToolError, machine_arch

LATER = NOW + timedelta(hours=1)  # the session's clock
EXAMPLE = "kerbrute userenum -d {domain} --dc {ip} {hostname} {lhost} {nope} {0}"


@pytest.fixture
def shop(tmp_path, session, monkeypatch):
    folder = tmp_path / "index"
    home = tmp_path / "user"
    home.mkdir()
    monkeypatch.setattr(toolhooks, "user_home", lambda: home)
    # root's home is a folder that does not exist, whoever runs the tests
    monkeypatch.setattr(toolhooks.tooldata, "_root_home", lambda: tmp_path / "no-root-home")
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
        "tool history", "tool refresh", "tool cache clear",
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
    # the box keeps the tool on record, with the time it was removed
    assert [(t.name, t.installed, t.removed) for t in load_box(session.box.path).tools] == [
        ("kerbrute", LATER, LATER)
    ]
    assert current_tools(session.box) == []
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
    assert current_tools(load_box(session.box.path)) == []
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


def kerb_result(shop):
    (shop.home / ".kerb").mkdir()
    (shop.home / ".kerb" / "found.txt").write_text("result")


def test_remove_by_the_last_user_moves_the_home_data_into_the_box(session, shop):
    run(session, "tool install kerbrute")
    kerb_result(shop)
    shown = []
    console = FakeConsole(["y"])
    original = console.confirm
    console.confirm = lambda q, default=False: shown.extend(console.lines) or original(q, default)
    session.console = console
    dispatch(session, "tool remove kerbrute")
    assert shown == [("info", f"home      {shop.home / '.kerb'}   (will be deleted)")]
    copy = session.box.path / "tooldata" / "kerbrute" / "home" / ".kerb" / "found.txt"
    assert copy.read_text() == "result"
    assert not (shop.home / ".kerb").exists()
    assert lines(console, "ok")[-1] == "kerbrute removed; its files are deleted"
    assert lines(console, "warn") == []
    run(session, "tool install kerbrute")
    assert toolstate.load_installed(session.paths)["kerbrute"].home == {".kerb": False}


def test_remove_keeps_home_data_another_box_still_uses(session, shop, other):
    install_for(other, shop, shop.entries[1], session.paths)
    run(session, "tool install kerbrute")
    kerb_result(shop)
    console = run(session, "tool remove kerbrute", "y")
    assert lines(console, "info") == []
    assert (shop.home / ".kerb" / "found.txt").read_text() == "result"
    assert not (session.box.path / "tooldata").exists()


def test_remove_keeps_a_home_path_that_was_there_before(session, shop):
    kerb_result(shop)
    run(session, "tool install kerbrute")
    console = run(session, "tool remove kerbrute", "y")
    assert lines(console, "warn") == [
        f"{shop.home / '.kerb'}   existed before kerbrute was installed; kept"
    ]
    assert (shop.home / ".kerb" / "found.txt").read_text() == "result"
    assert not (session.box.path / "tooldata").exists()


def test_remove_keeps_a_home_path_not_copied_in_full(session, shop, monkeypatch):
    run(session, "tool install kerbrute")
    kerb_result(shop)

    def denied(src, dst, **kw):
        raise PermissionError("denied")

    monkeypatch.setattr(toolhooks.tooldata.shutil, "copy2", denied)
    console = run(session, "tool remove kerbrute", "y")
    assert lines(console, "warn") == [f"{shop.home / '.kerb'} was not copied in full; kept"]
    assert (shop.home / ".kerb" / "found.txt").exists()
    assert toolstate.load_installed(session.paths) == {}


def test_remove_by_the_last_user_warns_when_roots_home_cannot_be_read(session, shop, monkeypatch):
    run(session, "tool install kerbrute")
    monkeypatch.setattr(toolhooks.tooldata, "root_unchecked", lambda h, **k: True)
    console = run(session, "tool remove kerbrute", "y")
    assert lines(console, "warn") == ["root's home could not be checked for kerbrute's data"]


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
    assert toolbar_text(session, start) == " forest   dc01  10.10.10.161   1 target   no vpn   00:00"
    run(session, "tool install kerbrute")
    assert toolbar_text(session, start).endswith("1 target   1 tool   no vpn   00:00")
    run(session, "tool install ligolo-ng")
    assert toolbar_text(session, start).endswith("1 target   2 tools   no vpn   00:00")


def test_status_shows_the_tool_count(session, shop):
    assert "tools      0" in lines(run(session, "status"), "info")
    run(session, "tool install kerbrute")
    shown = lines(run(session, "status"), "info")
    assert shown.index("tools      1") == shown.index("targets    1") + 1


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


# ---- guards


def break_a_box(session):
    (session.paths.active / "broken").mkdir()
    (session.paths.active / "broken" / "box.toml").write_text("nope [", encoding="utf-8")


def test_install_keeps_a_user_the_listing_could_not_load(session, shop, other):
    install_for(other, shop, shop.entries[1], session.paths)
    installed = toolstate.load_installed(session.paths)
    installed["kerbrute"].users.append("lost-box")
    toolstate.save_installed(session.paths, installed)
    break_a_box(session)
    run(session, "tool install kerbrute")
    users = toolstate.load_installed(session.paths)["kerbrute"].users
    assert "lost-box" in users and session.box.id in users and other.id in users


def test_install_of_another_build_stops_before_anything_is_fetched(session, shop, monkeypatch):
    run(session, "tool install kerbrute@1.0.2")

    def boom(*a, **k):
        raise AssertionError("fetched")

    monkeypatch.setattr(cmd_tool.toolindex, "fetch_zip", boom)
    failed = lines(run(session, "tool install kerbrute@1.0.3"), "fail")
    assert len(failed) == 1 and "tool remove kerbrute" in failed[0]


def test_typed_values_are_shown_literally(session, shop):
    assert "[red]x[/red]" in lines(run(session, "tool install [red]x[/red]"), "fail")[0]
    assert "[red]" in lines(run(session, "tool install kerbrute@[red]"), "fail")[0]
    assert lines(run(session, "tool search [red]"), "info") == ["no tools match [red]"]
    assert "[red]x[/red]" in lines(run(session, "tool info [red]x[/red]"), "fail")[0]


def test_info_without_the_installed_manifest_warns_after_the_lines_before_it(session, shop):
    run(session, "tool install kerbrute")
    item = toolstate.load_installed(session.paths)["kerbrute"]
    (Path(item.folder) / "manifest.toml").unlink()
    console = run(session, "tool info kerbrute")
    assert len(lines(console, "warn")) == 1
    assert any(t.startswith("folder") for t in lines(console, "info"))
    assert not any("userenum" in t for t in lines(console, "info"))


def test_info_with_an_empty_installed_folder_skips_the_examples(session, shop):
    run(session, "tool install kerbrute")
    installed = toolstate.load_installed(session.paths)
    installed["kerbrute"].folder = ""
    toolstate.save_installed(session.paths, installed)
    console = run(session, "tool info kerbrute")
    assert lines(console, "warn") == [] and lines(console, "fail") == []
    assert not any("userenum" in t for t in lines(console, "info"))


def test_info_for_an_installed_tool_missing_from_the_index(session, shop):
    run(session, "tool install kerbrute")
    toolkit.write_index(shop.folder, shop.entries[2:])
    console = run(session, "tool info kerbrute")
    assert lines(console, "warn") == ["kerbrute is not in the index"]
    shown = "\n".join(lines(console, "info"))
    assert "run         kerbrute" in shown and "folder" in shown and "userenum" in shown
    assert lines(console, "fail") == []


def test_info_for_a_tool_neither_installed_nor_indexed_is_one_fail_line(session, shop):
    toolkit.write_index(shop.folder, shop.entries[2:])
    console = run(session, "tool info kerbrute")
    assert len(lines(console, "fail")) == 1 and lines(console, "warn") == []


def test_cache_clear_leaves_the_index_and_other_files(session, shop):
    cache = session.paths.cache
    cache.mkdir(parents=True)
    for name in ("index.toml", "index.fetched", "notes.txt"):
        (cache / name).write_text("x")
    (cache / "a-1.0-1.zip").write_bytes(b"x")
    (cache / "b-1.0-1.zip.part").write_bytes(b"x")
    run(session, "tool cache clear", "y")
    assert sorted(p.name for p in cache.iterdir()) == ["index.fetched", "index.toml", "notes.txt"]


def test_refresh_with_the_index_unreachable_is_one_fail_line(session, tmp_path):
    session.settings = replace(session.settings, tools_index=str(tmp_path / "nowhere"))
    console = run(session, "tool refresh")
    assert len(console.lines) == 1 and console.lines[0][0] == "fail"
    assert str(tmp_path / "nowhere") in console.lines[0][1]



# ---- what counts as installed


def lose_the_tool(session, how):
    installed = toolstate.load_installed(session.paths)
    item = installed["kerbrute"]
    if how == "not listed":
        del installed["kerbrute"]
    elif how == "not a user":
        item.users = ["someone-else"]
    else:
        import shutil

        shutil.rmtree(item.folder)
    toolstate.save_installed(session.paths, installed)


@pytest.mark.parametrize("how", ["not listed", "not a user", "folder gone"])
def test_a_tool_the_box_records_but_the_machine_lacks_is_not_installed(session, shop, how):
    start = session.box.started
    run(session, "tool install kerbrute")
    run(session, "tool install ligolo-ng")
    lose_the_tool(session, how)
    _columns, rows = table(run(session, "tool list"))
    assert [r[3] for r in rows] == ["not installed", "installed"]
    _columns, rows = table(run(session, "tool list --installed"))
    assert [r[3] for r in rows] == ["not installed", "installed"]
    _columns, rows = table(run(session, "tool search stand-in"))
    assert [r[3] for r in rows] == ["not installed", "installed"]
    assert toolbar_text(session, start).endswith("1 target   1 tool   no vpn   00:00")
    assert "tools      1" in lines(run(session, "status"), "info")


def test_the_toolbar_counts_nothing_while_the_installed_list_cannot_be_read(session, shop):
    start = session.box.started
    run(session, "tool install kerbrute")
    session.paths.tools_state.write_text("not toml [", encoding="utf-8")
    assert toolbar_text(session, start).endswith("1 target   no vpn   00:00")


def test_the_index_is_still_listed_while_the_installed_list_cannot_be_read(session, shop):
    run(session, "tool install kerbrute")
    session.paths.tools_state.write_text("not toml [", encoding="utf-8")
    console = run(session, "tool list")
    _columns, rows = table(console)
    assert "kerbrute" in [r[0] for r in rows]
    assert [r[3] for r in rows if r[0] == "kerbrute"] == ["unknown"]
    assert len(lines(console, "warn")) == 1 and not lines(console, "fail")


def test_installing_a_root_tool_names_the_copy_sudo_would_run(session, shop, monkeypatch):
    seen = []

    def lookup(command, path=None):
        seen.append(path)
        return "/usr/bin/ligolo-proxy" if command == "ligolo-proxy" else None

    monkeypatch.setattr(cmd_tool, "_lookup", lookup)
    monkeypatch.setenv("PATH", f"{session.paths.bin}{cmd_tool.os.pathsep}/usr/bin")
    console = run(session, "tool install ligolo-ng")
    full = (session.paths.bin / "ligolo-proxy").as_posix()
    assert lines(console, "warn")[-1] == (
        f"sudo ligolo-proxy runs /usr/bin/ligolo-proxy; use sudo {full}"
    )
    assert seen and all(path == "/usr/bin" for path in seen)


def test_info_fills_lhost_from_the_tunnel(session, shop, system):
    system.tunnel_found = Tunnel("tun0", "10.10.14.7")
    run(session, "tool install kerbrute")
    joined = "\n".join(lines(run(session, "tool info kerbrute"), "info"))
    assert "--dc 10.10.10.161 forest.htb.local 10.10.14.7 {nope} {0}" in joined
    assert "<lhost>" not in joined


# ---- tools on a runtime

RT_LINE = "python-3.13 3.13.18 installed (runtime, 1 MB)"
RT_GONE = "python-3.13 3.13.18 removed (runtime)"
REFUSED = "python-3.13 is a runtime; it is installed with the tools that need it"


@pytest.fixture
def pyshop(session, shop, monkeypatch):
    # certipy and bloodhound both require python-3.13; kerbrute and ligolo-ng require nothing
    calls = toolkit.no_real_venv(monkeypatch)
    _z, runtime = toolkit.make_runtime(shop.folder)
    _z, certipy = toolkit.make_python_tool(shop.folder)
    _z, bloodhound = toolkit.make_python_tool(shop.folder, "bloodhound", "1.8.0", build=1)
    entries = [*shop.entries, runtime, certipy, bloodhound]
    toolkit.write_index(shop.folder, entries)
    fetched = []
    real = cmd_tool.toolindex.fetch_zip

    def spy(paths, settings, entry, **kw):
        fetched.append(entry.name)
        return real(paths, settings, entry, **kw)

    monkeypatch.setattr(cmd_tool.toolindex, "fetch_zip", spy)
    return SimpleNamespace(
        runtime=runtime, certipy=certipy, bloodhound=bloodhound, entries=entries,
        calls=calls, fetched=fetched,
    )  # fmt: skip


def runtime_row(session):
    return toolstate.load_installed(session.paths).get("python-3.13")


def nothing_of(session, *names):
    installed = toolstate.load_installed(session.paths)
    for name in names:
        assert name not in installed
        assert not (session.paths.tools / name).exists()


def test_install_brings_the_runtime_first(session, shop, pyshop):
    console = run(session, "tool install certipy")
    assert lines(console, "ok") == [RT_LINE, "certipy 5.1.0 installed"]
    assert pyshop.fetched == ["python-3.13", "certipy"]
    rt = runtime_row(session)
    assert rt.kind == "runtime" and rt.users == []
    # the environment is made by the runtime's interpreter
    assert pyshop.calls[0][0] == rt.python
    [record] = load_box(session.box.path).tools
    assert (record.runtime.name, record.runtime.version, record.runtime.build) == (
        "python-3.13", "3.13.18", 1,
    )  # fmt: skip
    assert toolstate.load_installed(session.paths)["certipy"].requires == ["python-3.13"]


def test_install_uses_the_runtime_already_there_without_fetching_it(session, shop, pyshop):
    run(session, "tool install certipy")
    pyshop.fetched.clear()
    console = run(session, "tool install bloodhound")
    assert lines(console, "ok") == ["bloodhound 1.8.0 installed"]
    assert pyshop.fetched == ["bloodhound"]


def test_a_newer_runtime_in_the_index_does_not_replace_the_installed_one(session, shop, pyshop):
    run(session, "tool install certipy")
    _z, newer = toolkit.make_runtime(shop.folder, build=2)
    toolkit.write_index(shop.folder, [*pyshop.entries, newer])
    console = run(session, "tool install bloodhound")
    assert lines(console, "ok") == ["bloodhound 1.8.0 installed"]
    assert runtime_row(session).build == 1


def test_a_runtime_missing_from_the_index_stops_before_anything_is_fetched(session, shop, pyshop):
    toolkit.write_index(shop.folder, [e for e in pyshop.entries if e.name != "python-3.13"])
    console = run(session, "tool install certipy")
    assert lines(console, "fail") == ["no runtime named 'python-3.13' in the index"]
    assert pyshop.fetched == []
    nothing_of(session, "certipy", "python-3.13")
    assert load_box(session.box.path).tools == []


def take_the_command(session, shop):
    # another tool already owns the command name certipy
    command = {"name": "certipy", "type": "binary", "path": "files/kerbrute"}
    _z, taker = toolkit.make_entry(shop.folder / "taker", {"name": "taker", "command": [command]})
    toolinstall.install(
        session.paths, session.box, taker, shop.folder / "taker" / taker.file,
        installed=toolstate.load_installed(session.paths), unfinished={session.box.id: "forest"},
        home=shop.home, console=FakeConsole(), now=NOW, on_path=lambda n: None,
    )  # fmt: skip


TOOL_FAULTS = ["venv", "pip", "a command name", "the download"]
# the faults found only once the tool's own package is being installed
LATE_FAULTS = ["venv", "pip", "the download"]


def break_the_tool(session, shop, pyshop, monkeypatch, fault):
    if fault in ("venv", "pip"):
        toolkit.no_real_venv(monkeypatch, fail=fault)
    elif fault == "a command name":
        take_the_command(session, shop)
    else:
        (shop.folder / pyshop.certipy.file).unlink()


@pytest.mark.parametrize("fault", LATE_FAULTS)
def test_a_failed_install_takes_the_runtime_it_brought_away_again(
    session, shop, pyshop, monkeypatch, fault
):
    break_the_tool(session, shop, pyshop, monkeypatch, fault)
    console = run(session, "tool install certipy")
    assert len(lines(console, "fail")) == 1
    assert lines(console, "ok") == [RT_LINE, RT_GONE]  # installed, then taken away again
    nothing_of(session, "certipy", "python-3.13")
    assert load_box(session.box.path).tools == []


def schema_1_certipy(shop, pyshop):
    # certipy 5.1.0-2 on Kali's own Python, beside build 3 on the runtime
    wheel = toolkit.make_wheel(
        shop.folder / "w1", "certipy-py", "1.0", module="tool", entry="certipy"
    )
    manifest = toolkit.sample_manifest(
        name="certipy", version="5.1.0", build=2, arch=machine_arch(),
        command=[{"name": "certipy", "type": "python-entry", "entry": "certipy"}],
        python={"versions": ["3.13"], "lock": "wheels.lock", "wheels": "wheels"},
    )  # fmt: skip
    zip_path, size, sha = toolkit.make_package(shop.folder, manifest, {}, wheels=[wheel])
    old = BuildEntry(
        "certipy", "5.1.0", 2, "kali", False, ["certipy"], zip_path.name, "", size, sha
    )
    toolkit.write_index(shop.folder, [*shop.entries, pyshop.runtime, old, pyshop.certipy])
    return old


REFUSALS = ["another box has another build", "a command name"]


@pytest.mark.parametrize("refusal", REFUSALS)
def test_an_install_the_box_refuses_fetches_nothing(session, shop, pyshop, other, refusal):
    if refusal == "a command name":
        take_the_command(session, shop)
    else:
        install_for(other, shop, schema_1_certipy(shop, pyshop), session.paths)
    pyshop.fetched.clear()
    console = run(session, "tool install certipy")
    failed = lines(console, "fail")
    assert len(failed) == 1
    said = (
        "the command certipy already belongs to taker"
        if refusal == "a command name"
        else "certipy 5.1.0-2 is in use by Cascade; finish or remove it there before installing "
        "5.1.0-3, or ask for the build in use: tool install certipy@5.1.0-2"
    )
    assert failed == [said]
    assert pyshop.fetched == [] and lines(console, "ok") == []
    nothing_of(session, "python-3.13")


def test_the_build_a_refusal_names_can_be_asked_for(session, shop, pyshop, other):
    install_for(other, shop, schema_1_certipy(shop, pyshop), session.paths)
    hint = lines(run(session, "tool install certipy"), "fail")[0].rsplit(": ", 1)[1]
    assert hint == "tool install certipy@5.1.0-2"
    console = run(session, hint)
    assert lines(console, "ok") == ["certipy 5.1.0 installed"]
    assert toolstate.load_installed(session.paths)["certipy"].users == [other.id, session.box.id]


def test_install_tool_refuses_another_build_of_the_boxs_own_before_fetching(session, shop, pyshop):
    from pwn_broker import toolindex
    from pwn_broker.model import ToolRecord

    old = schema_1_certipy(shop, pyshop)
    session.box.tools.append(ToolRecord("certipy", "5.1.0", 2, old.sha256, NOW))
    index = toolindex.load_index(session.paths, session.settings, now=NOW)
    with pytest.raises(ToolError) as err:
        toolhooks.install_tool(
            session, index, pyshop.certipy,
            installed=toolstate.load_installed(session.paths),
            unfinished={session.box.id: session.box.name},
        )  # fmt: skip
    assert str(err.value) == (
        "forest already has certipy 5.1.0-2, not 5.1.0-3; run tool remove certipy first, "
        "or ask for the build it has: tool install certipy@5.1.0-2"
    )
    assert pyshop.fetched == []
    nothing_of(session, "python-3.13")


@pytest.mark.parametrize("fault", TOOL_FAULTS)
def test_a_failed_install_leaves_a_runtime_that_was_already_there(
    session, shop, pyshop, monkeypatch, fault
):
    run(session, "tool install bloodhound")
    before = runtime_row(session)
    break_the_tool(session, shop, pyshop, monkeypatch, fault)
    console = run(session, "tool install certipy")
    assert len(lines(console, "fail")) == 1 and lines(console, "ok") == []
    nothing_of(session, "certipy")
    assert runtime_row(session) == before and Path(before.python).is_file()


def test_a_runtime_whose_removal_fails_after_a_failed_install_is_a_warn(
    session, shop, pyshop, monkeypatch
):
    toolkit.no_real_venv(monkeypatch, fail="pip")

    def stuck(paths, item):
        raise ToolError("the folder is busy")

    monkeypatch.setattr(cmd_tool.toolinstall, "remove_runtime", stuck)
    console = run(session, "tool install certipy")
    assert lines(console, "warn") == ["python-3.13 3.13.18   the folder is busy"]
    assert len(lines(console, "fail")) == 1 and "pip" in lines(console, "fail")[0]
    assert runtime_row(session) is not None  # the launch check offers it again


def test_a_schema_1_build_of_a_python_tool_installs_as_before(session, shop, pyshop):
    schema_1_certipy(shop, pyshop)
    console = run(session, "tool install certipy@5.1.0-2")
    assert lines(console, "ok") == ["certipy 5.1.0 installed"]
    assert pyshop.calls[0][:3] == ["python3", "-I", "-c"]
    assert runtime_row(session) is None
    assert load_box(session.box.path).tools[0].runtime is None


def test_a_schema_1_build_that_cannot_make_its_environment_says_to_install_python3(
    session, shop, pyshop, monkeypatch
):
    schema_1_certipy(shop, pyshop)
    toolkit.no_real_venv(monkeypatch, fail="venv")
    [fail] = lines(run(session, "tool install certipy@5.1.0-2"), "fail")
    assert fail.endswith(
        ". certipy 5.1.0-2 runs on Kali's own python3: apt install python3 python3-venv, "
        "or install a build that requires a runtime"
    )


def test_a_build_on_a_runtime_that_fails_does_not_mention_kalis_python(
    session, shop, pyshop, monkeypatch
):
    toolkit.no_real_venv(monkeypatch, fail="venv")
    [fail] = lines(run(session, "tool install certipy"), "fail")
    assert "Kali" not in fail and "apt install" not in fail


def test_install_refuses_a_runtime(session, shop, pyshop):
    console = run(session, "tool install python-3.13")
    assert lines(console, "fail") == [REFUSED]
    assert pyshop.fetched == [] and runtime_row(session) is None
    assert lines(run(session, "tool install python-3.13@3.13.18"), "fail") == [REFUSED]


def test_remove_refuses_a_runtime_installed_or_not(session, shop, pyshop):
    assert lines(run(session, "tool remove python-3.13", "y"), "fail") == [REFUSED]
    run(session, "tool install certipy")
    console = run(session, "tool remove python-3.13", "y")
    assert lines(console, "fail") == [REFUSED] and console.asked == []
    assert runtime_row(session) is not None


def test_listings_completions_and_counts_leave_runtimes_out(session, shop, pyshop):
    start = session.box.started
    run(session, "tool install certipy")
    _columns, rows = table(run(session, "tool list"))
    assert [r[0] for r in rows] == ["bloodhound", "certipy", "kerbrute", "ligolo-ng"]
    _columns, rows = table(run(session, "tool list --installed"))
    assert [r[0] for r in rows] == ["certipy"]
    assert lines(run(session, "tool search python"), "info") == ["no tools match python"]
    assert "tool install python-3.13" not in completions(session, "tool install ")
    assert completions(session, "tool info p") == []
    assert completions(session, "tool remove ") == ["tool remove certipy"]
    assert toolbar_text(session, start).endswith("1 target   1 tool   no vpn   00:00")
    assert "tools      1" in lines(run(session, "status"), "info")
    assert lines(run(session, "tool refresh"), "ok") == ["index refreshed: 4 tools"]


def info_lines(session, name):
    return lines(run(session, f"tool info {name}"), "info")


def test_info_names_the_runtime_a_tool_requires(session, shop, pyshop):
    shown = info_lines(session, "certipy")
    after = shown[shown.index("versions    5.1.0-3") + 1]
    assert after == "requires    python-3.13 (1 MB, not installed)"
    run(session, "tool install bloodhound")
    assert "requires    python-3.13 (1 MB, installed)" in info_lines(session, "certipy")
    assert not any(t.startswith("requires") for t in info_lines(session, "kerbrute"))


def test_info_shows_what_the_installed_build_requires(session, shop, pyshop):
    schema_1_certipy(shop, pyshop)
    run(session, "tool install certipy@5.1.0-2")
    assert not any(t.startswith("requires") for t in info_lines(session, "certipy"))
    run(session, "tool remove certipy", "y")
    assert "requires    python-3.13 (1 MB, not installed)" in info_lines(session, "certipy")
    run(session, "tool install certipy")
    assert "requires    python-3.13 (1 MB, installed)" in info_lines(session, "certipy")


def test_info_for_a_tool_whose_runtime_is_not_in_the_index(session, shop, pyshop):
    toolkit.write_index(shop.folder, [e for e in pyshop.entries if e.name != "python-3.13"])
    assert "requires    python-3.13 (not in the index)" in info_lines(session, "certipy")


def test_remove_takes_the_runtime_with_the_last_tool_that_requires_it(session, shop, pyshop):
    run(session, "tool install certipy")
    console = run(session, "tool remove certipy", "y")
    assert lines(console, "ok") == ["certipy removed; its files are deleted", RT_GONE]
    assert toolstate.load_installed(session.paths) == {}
    assert not (session.paths.tools / "python-3.13").exists()


def test_two_tools_share_a_runtime_until_the_last_is_removed(session, shop, pyshop):
    run(session, "tool install certipy")
    run(session, "tool install bloodhound")
    console = run(session, "tool remove certipy", "y")
    assert lines(console, "ok") == ["certipy removed; its files are deleted"]
    assert runtime_row(session) is not None
    console = run(session, "tool remove bloodhound", "y")
    assert lines(console, "ok") == ["bloodhound removed; its files are deleted", RT_GONE]
    assert runtime_row(session) is None


def install_on_runtime_for(box, session, shop, pyshop, entry):
    # another unfinished box installs a tool on the runtime
    paths = session.paths
    installed = toolstate.load_installed(paths)
    rt = toolinstall.install_runtime(
        paths, pyshop.runtime, shop.folder / pyshop.runtime.file,
        installed=installed, console=FakeConsole(),
    )  # fmt: skip
    toolinstall.install(
        paths, box, entry, shop.folder / entry.file,
        installed=installed, unfinished={box.id: box.name},
        home=shop.home, console=FakeConsole(), now=NOW, on_path=lambda n: None, runtime=rt,
    )  # fmt: skip


def test_a_runtime_a_tool_of_another_unfinished_box_requires_stays(session, shop, pyshop, other):
    install_on_runtime_for(other, session, shop, pyshop, pyshop.certipy)
    run(session, "tool install bloodhound")
    console = run(session, "tool remove bloodhound", "y")
    assert lines(console, "ok") == ["bloodhound removed; its files are deleted"]
    assert runtime_row(session) is not None
    assert toolstate.load_installed(session.paths)["certipy"].users == [other.id]


def test_a_runtime_under_a_tool_another_box_shares_stays(session, shop, pyshop, other):
    install_on_runtime_for(other, session, shop, pyshop, pyshop.certipy)
    console = run(session, "tool install certipy")
    assert lines(console, "ok") == ["certipy 5.1.0 installed"]
    console = run(session, "tool remove certipy", "y")
    assert "Cascade still uses it" in lines(console, "ok")[0]
    assert runtime_row(session) is not None


def damage_the_runtime(session):
    # the row stays; the interpreter the tools' environments were made by is gone
    rt = runtime_row(session)
    Path(rt.python).unlink()
    return rt


def files_under(folder):
    return sorted(p.relative_to(folder).as_posix() for p in folder.rglob("*"))


def test_a_damaged_runtime_tools_require_is_installed_again_at_its_own_build(
    session, shop, pyshop, other
):
    install_on_runtime_for(other, session, shop, pyshop, pyshop.certipy)
    before = damage_the_runtime(session)
    _z, newer = toolkit.make_runtime(shop.folder, build=2)
    toolkit.write_index(shop.folder, [*pyshop.entries, newer])
    console = run(session, "tool install certipy")
    assert lines(console, "ok") == [RT_LINE, "certipy 5.1.0 installed"]
    assert lines(console, "fail") == []
    rt = runtime_row(session)
    # the same folder and interpreter, so the environment certipy was made with works again
    assert (rt.build, rt.folder, rt.python) == (1, before.folder, before.python)
    assert Path(rt.python).is_file()
    assert [p.name for p in (session.paths.tools / "python-3.13").iterdir()] == ["3.13.18-1"]
    certipy = toolstate.load_installed(session.paths)["certipy"]
    assert certipy.users == [other.id, session.box.id]


def test_a_failed_install_keeps_a_damaged_runtime_it_put_back_for_other_tools(
    session, shop, pyshop, other, monkeypatch
):
    install_on_runtime_for(other, session, shop, pyshop, pyshop.certipy)
    before = damage_the_runtime(session)
    toolkit.no_real_venv(monkeypatch, fail="pip")
    console = run(session, "tool install bloodhound")
    assert len(lines(console, "fail")) == 1 and lines(console, "ok") == [RT_LINE]
    nothing_of(session, "bloodhound")
    # certipy still requires it, so it stays, working again
    assert runtime_row(session).folder == before.folder and Path(before.python).is_file()
    assert load_box(session.box.path).tools == []


def test_a_damaged_runtime_whose_build_the_index_lost_is_refused_and_kept(
    session, shop, pyshop, other
):
    install_on_runtime_for(other, session, shop, pyshop, pyshop.certipy)
    damage_the_runtime(session)
    _z, newer = toolkit.make_runtime(shop.folder, build=2)
    others = [e for e in pyshop.entries if e.name != "python-3.13"]
    toolkit.write_index(shop.folder, [*others, newer])
    state = session.paths.tools_state.read_bytes()
    kept = files_under(session.paths.tools)
    pyshop.fetched.clear()
    console = run(session, "tool install bloodhound")
    assert lines(console, "fail") == [
        "python-3.13 3.13.18-1 is missing or damaged, and the index no longer lists that "
        "build; certipy requires it: remove certipy and install it again"
    ]
    assert lines(console, "ok") == [] and pyshop.fetched == []
    assert session.paths.tools_state.read_bytes() == state
    assert files_under(session.paths.tools) == kept
    assert load_box(session.box.path).tools == []


def test_the_refusal_names_every_tool_that_requires_the_damaged_runtime(
    session, shop, pyshop, other
):
    install_on_runtime_for(other, session, shop, pyshop, pyshop.certipy)
    install_on_runtime_for(other, session, shop, pyshop, pyshop.bloodhound)
    damage_the_runtime(session)
    toolkit.write_index(shop.folder, [e for e in pyshop.entries if e.name != "python-3.13"])
    console = run(session, "tool install certipy")
    assert lines(console, "fail") == [
        "python-3.13 3.13.18-1 is missing or damaged, and the index no longer lists that "
        "build; bloodhound, certipy require it: remove them and install them again"
    ]


def with_build_2(shop, pyshop, keep_build_1=True):
    # the index's latest runtime is build 2
    _z, newer = toolkit.make_runtime(shop.folder, build=2)
    entries = [e for e in pyshop.entries if keep_build_1 or e.name != "python-3.13"]
    toolkit.write_index(shop.folder, [*entries, newer])


def lose_the_runtime(session):
    # no row and no files: an older failure, or a hand-edited list
    installed = toolstate.load_installed(session.paths)
    toolinstall.remove_runtime(session.paths, installed.pop("python-3.13"))
    toolstate.save_installed(session.paths, installed)


def test_a_failed_attempt_to_put_a_runtime_back_keeps_its_row_for_the_next(
    session, shop, pyshop, other, monkeypatch
):
    install_on_runtime_for(other, session, shop, pyshop, pyshop.certipy)
    before = damage_the_runtime(session)
    with_build_2(shop, pyshop)

    real = toolinstall.runtimearchive.unpack
    failures = [ToolError("the disk is full")]

    def once(archive, root):
        if failures:
            raise failures.pop()
        return real(archive, root)

    monkeypatch.setattr(toolinstall.runtimearchive, "unpack", once)
    state = session.paths.tools_state.read_bytes()
    console = run(session, "tool install bloodhound")
    assert lines(console, "fail") == ["the disk is full"] and lines(console, "ok") == []
    # the stale row stays, so the next attempt takes the same path; only the damaged folder went
    assert session.paths.tools_state.read_bytes() == state
    assert not (session.paths.tools / "python-3.13").exists()
    console = run(session, "tool install certipy")
    assert lines(console, "ok") == [RT_LINE, "certipy 5.1.0 installed"]
    rt = runtime_row(session)
    assert (rt.build, rt.folder, rt.python) == (1, before.folder, before.python)


def test_a_missing_runtime_row_is_put_back_at_the_build_its_tools_record(
    session, shop, pyshop, other
):
    install_on_runtime_for(other, session, shop, pyshop, pyshop.certipy)
    certipy = toolstate.load_installed(session.paths)["certipy"]
    assert (certipy.runtime_version, certipy.runtime_build) == ("3.13.18", 1)
    lose_the_runtime(session)
    with_build_2(shop, pyshop)
    console = run(session, "tool install bloodhound")
    assert lines(console, "ok") == [RT_LINE, "bloodhound 1.8.0 installed"]
    assert runtime_row(session).build == 1
    assert toolstate.load_installed(session.paths)["bloodhound"].runtime_build == 1


def test_a_tool_row_from_before_falls_back_to_the_box_records(session, shop, pyshop, other):
    install_on_runtime_for(other, session, shop, pyshop, pyshop.certipy)
    installed = toolstate.load_installed(session.paths)
    installed["certipy"].runtime_version, installed["certipy"].runtime_build = "", 0
    toolstate.save_installed(session.paths, installed)
    lose_the_runtime(session)
    with_build_2(shop, pyshop)
    run(session, "tool install bloodhound")
    assert runtime_row(session).build == 1  # Cascade's record says certipy ran on build 1


def test_a_missing_runtime_whose_build_is_gone_or_in_doubt_is_refused(
    session, shop, pyshop, other
):
    install_on_runtime_for(other, session, shop, pyshop, pyshop.certipy)
    install_on_runtime_for(other, session, shop, pyshop, pyshop.bloodhound)
    lose_the_runtime(session)
    with_build_2(shop, pyshop, keep_build_1=False)
    console = run(session, "tool install bloodhound")
    assert lines(console, "fail") == [
        "python-3.13 3.13.18-1 is missing or damaged, and the index no longer lists that "
        "build; bloodhound, certipy require it: remove them and install them again"
    ]
    installed = toolstate.load_installed(session.paths)
    installed["bloodhound"].runtime_build = 2
    toolstate.save_installed(session.paths, installed)
    with_build_2(shop, pyshop)
    pyshop.fetched.clear()
    console = run(session, "tool install bloodhound")
    assert lines(console, "fail") == [
        "python-3.13 is missing or damaged, and the tools that require it were made on "
        "3.13.18-1 and 3.13.18-2; bloodhound, certipy require it: remove them and install "
        "them again"
    ]
    assert pyshop.fetched == [] and runtime_row(session) is None


@pytest.mark.parametrize("row", ["stale", "missing"])
def test_a_tool_no_unfinished_box_holds_does_not_pin_the_runtime_it_is_replacing(
    session, shop, pyshop, other, row
):
    install_on_runtime_for(other, session, shop, pyshop, pyshop.certipy)
    installed = toolstate.load_installed(session.paths)
    installed["certipy"].users = []  # left by a finished box, its files gone
    shutil.rmtree(installed["certipy"].folder)
    toolstate.save_installed(session.paths, installed)
    damage_the_runtime(session) if row == "stale" else lose_the_runtime(session)
    with_build_2(shop, pyshop, keep_build_1=False)
    console = run(session, "tool install certipy")
    assert lines(console, "fail") == []
    assert lines(console, "ok") == [RT_LINE, "certipy 5.1.0 installed"]
    assert runtime_row(session).build == 2


def test_no_runtime_is_removed_while_a_box_cannot_be_read(session, shop, pyshop):
    run(session, "tool install certipy")
    break_a_box(session)
    console = run(session, "tool remove certipy", "y")
    assert lines(console, "ok") == ["certipy removed; its files are deleted"]
    assert lines(console, "warn") == ["python-3.13 kept: broken cannot be read"]
    assert runtime_row(session) is not None


def test_a_runtime_that_cannot_be_removed_is_a_warn(session, shop, pyshop, monkeypatch):
    run(session, "tool install certipy")

    def stuck(paths, item):
        raise ToolError("the folder is busy")

    monkeypatch.setattr(cmd_tool.toolinstall, "remove_runtime", stuck)
    console = run(session, "tool remove certipy", "y")
    assert lines(console, "ok") == ["certipy removed; its files are deleted"]
    assert lines(console, "warn") == ["python-3.13 3.13.18   the folder is busy"]
    assert lines(console, "fail") == []
    assert runtime_row(session) is not None


# ---- removed tools and history


def test_a_removed_tool_is_not_listed_counted_completed_or_removed_again(session, shop):
    start = session.box.started
    run(session, "tool install kerbrute")
    run(session, "tool remove kerbrute", "y")
    assert lines(run(session, "tool list --installed"), "info") == ["no tools installed for forest"]
    _columns, rows = table(run(session, "tool list"))
    assert [r[3] for r in rows] == ["", ""]
    assert toolbar_text(session, start).endswith("1 target   no vpn   00:00")
    assert "tools      0" in lines(run(session, "status"), "info")
    assert completions(session, "tool remove ") == []
    console = run(session, "tool remove kerbrute", "y")
    assert lines(console, "fail") == ["kerbrute is not installed for forest"]
    assert console.asked == []
    shown = lines(run(session, "tool info kerbrute"), "info")
    assert not any(t.startswith("folder") for t in shown)


def test_a_removed_tool_another_box_uses_is_not_counted(session, shop, other):
    install_for(other, shop, shop.entries[1], session.paths)
    run(session, "tool install kerbrute")
    run(session, "tool remove kerbrute", "y")
    assert "tools      0" in lines(run(session, "status"), "info")
    _columns, rows = table(run(session, "tool list"))
    assert [r[3] for r in rows if r[0] == "kerbrute"] == [""]


def test_installing_again_after_a_removal_adds_a_row(session, shop):
    run(session, "tool install kerbrute@1.0.2")
    run(session, "tool remove kerbrute", "y")
    again = LATER + timedelta(hours=1)
    session.clock = lambda: again
    # another build is no longer refused: the box no longer has the first
    assert lines(run(session, "tool install kerbrute@1.0.3"), "ok") == ["kerbrute 1.0.3 installed"]
    rows = load_box(session.box.path).tools
    assert [(t.version, t.installed, t.removed) for t in rows] == [
        ("1.0.2", LATER, LATER), ("1.0.3", again, None),
    ]  # fmt: skip
    console = run(session, "tool install kerbrute@1.0.3")
    assert lines(console, "info") == ["kerbrute 1.0.3 is already installed for forest"]
    assert len(load_box(session.box.path).tools) == 2


def at(hours):
    return NOW + timedelta(hours=hours)


def test_history_lists_every_tool_the_box_had_in_install_order(session, shop, pyshop):
    session.clock = lambda: at(1)
    run(session, "tool install kerbrute@1.0.2")
    session.clock = lambda: at(2)
    run(session, "tool install certipy")
    session.clock = lambda: at(3)
    run(session, "tool remove kerbrute", "y")
    session.clock = lambda: at(4)
    run(session, "tool install kerbrute")
    # a row written in another time zone is shown in the session's
    utc = datetime(2026, 11, 14, 9, 30, tzinfo=timezone.utc)
    session.box.tools.append(ToolRecord("ligolo-ng", "0.9.2", 1, "cd" * 32, utc, removed=utc))
    columns, rows = table(run(session, "tool history"))
    assert columns == ["tool", "version", "installed", "removed", "runtime"]
    assert rows == [
        ["ligolo-ng", "0.9.2-1", "2026-11-14 11:30", "2026-11-14 11:30", "-"],
        ["kerbrute", "1.0.2-1", "2026-11-14 13:00", "2026-11-14 15:00", "-"],
        ["certipy", "5.1.0-3", "2026-11-14 14:00", "-", "python-3.13 3.13.18-1"],
        ["kerbrute", "1.0.3-1", "2026-11-14 16:00", "-", "-"],
    ]


def test_history_of_a_box_with_no_tools(session, shop):
    console = run(session, "tool history")
    assert lines(console, "info") == ["no tools were installed for forest"]
    assert console.tables == []


def test_history_takes_no_arguments(session, shop):
    assert len(lines(run(session, "tool history kerbrute"), "fail")) == 1


LOGGED_AT = LATER.isoformat()
FOREST = "forest (2026-11-14_htb_forest)"


def log_lines(session):
    path = session.paths.tool_log
    return path.read_bytes().decode("utf-8").splitlines() if path.exists() else []


def logged(event, entry, box=FOREST, runtime=False):
    line = f"{LOGGED_AT}  {event:<7}  {box}  {entry.name} {entry.version}-{entry.build}"
    line += f"  sha256:{entry.sha256}"
    return line + "  runtime" if runtime else line


def test_install_and_remove_are_logged_with_the_runtime_beside_the_tool(session, shop, pyshop):
    run(session, "tool install certipy")
    run(session, "tool remove certipy", "y")
    assert log_lines(session) == [
        logged("install", pyshop.runtime, runtime=True),
        logged("install", pyshop.certipy),
        logged("remove", pyshop.certipy),
        logged("remove", pyshop.runtime, runtime=True),
    ]


def leave_the_runtime_idle(session):
    # a runtime no tool requires, left by a removal that did not take it (as one kept while a
    # box could not be read is)
    toolinstall.release(
        session.paths, session.box, "certipy", installed=toolstate.load_installed(session.paths),
        unfinished={}, removed=NOW,
    )  # fmt: skip
    assert [t.name for t in toolstate.idle_runtimes(toolstate.load_installed(session.paths))] == [
        "python-3.13"
    ]


def test_a_runtime_that_was_idle_before_is_removed_but_not_logged(session, shop, pyshop):
    run(session, "tool install certipy")
    leave_the_runtime_idle(session)
    run(session, "tool install kerbrute")
    console = run(session, "tool remove kerbrute", "y")
    assert lines(console, "ok") == ["kerbrute removed; its files are deleted", RT_GONE]
    assert runtime_row(session) is None
    # this box took kerbrute off; the runtime it removed was nobody's
    assert log_lines(session)[2:] == [
        logged("install", shop.entries[1]),
        logged("remove", shop.entries[1]),
    ]


def test_a_remove_is_logged_for_this_box_while_another_keeps_the_tool(session, shop, other):
    install_for(other, shop, shop.entries[1], session.paths)
    run(session, "tool install kerbrute")
    run(session, "tool remove kerbrute", "y")
    assert log_lines(session) == [
        logged("install", shop.entries[1]),
        logged("remove", shop.entries[1]),
    ]


def test_a_refused_or_declined_command_logs_nothing(session, shop):
    run(session, "tool install kerbrute@1.0.2")
    run(session, "tool install kerbrute@1.0.3")
    run(session, "tool install kerbrute@1.0.2")
    run(session, "tool remove kerbrute", "n")
    assert log_lines(session) == [logged("install", shop.entries[0])]


def test_removing_a_tool_the_machine_no_longer_has_is_logged(session, shop):
    run(session, "tool install kerbrute")
    toolstate.save_installed(session.paths, {})
    run(session, "tool remove kerbrute", "y")
    assert log_lines(session)[-1] == logged("remove", shop.entries[1])
    assert current_tools(load_box(session.box.path)) == []


def test_a_removal_whose_files_stay_is_still_logged(session, shop, monkeypatch):
    run(session, "tool install kerbrute")

    def stuck(paths, item):
        raise ToolError("cannot remove it")

    monkeypatch.setattr(cmd_tool.toolinstall, "remove_files", stuck)
    console = run(session, "tool remove kerbrute", "y")
    assert lines(console, "fail") == ["cannot remove it"]
    assert log_lines(session)[-1] == logged("remove", shop.entries[1])
    assert current_tools(load_box(session.box.path)) == []


def test_a_log_that_cannot_be_written_warns_once_and_the_removal_goes_on(session, shop):
    session.paths.tool_log.mkdir(parents=True)
    console = run(session, "tool install kerbrute")
    assert len(lines(console, "warn")) == 1
    session.console = FakeConsole(["y", "y"])
    dispatch(session, "tool remove kerbrute")
    dispatch(session, "tool install ligolo-ng")
    assert lines(session.console, "warn") == []
    assert lines(session.console, "ok")[0] == "kerbrute removed; its files are deleted"
    assert toolstate.load_installed(session.paths).keys() == {"ligolo-ng"}
