from dataclasses import replace
from types import SimpleNamespace

import pytest

import toolkit
from pwn_broker import shell  # noqa: F401  (fills the command registry)
from pwn_broker import toolhooks
from pwn_broker.console import FakeConsole
from pwn_broker.shell import cmd_playbook
from pwn_broker.shell.app import completions
from pwn_broker.shell.commands import COMMANDS, USAGES, dispatch

NONE = "no playbooks for this box: tool install playbooks gets them"
SMB_LINE = "Playbook: SMB enumeration   02-enum/smb   2026.11.19"


@pytest.fixture
def shop(tmp_path, session, monkeypatch):
    folder = tmp_path / "index"
    home = tmp_path / "user"
    home.mkdir()
    monkeypatch.setattr(toolhooks, "user_home", lambda: home)
    monkeypatch.setattr(toolhooks.tooldata, "_root_home", lambda: tmp_path / "no-root-home")
    _zip, entry = toolkit.make_notes_entry(folder)
    toolkit.write_index(folder, [entry])
    session.settings = replace(session.settings, tools_index=str(folder))
    return SimpleNamespace(folder=folder, entries=[entry])


def run(session, line, *answers):
    session.console = FakeConsole(list(answers))
    dispatch(session, line)
    return session.console


def lines(console, kind):
    return [text for k, text in console.lines if k == kind]


def table(console):
    assert len(console.tables) == 1
    return console.tables[0]


def add_package(session, shop, name, files, version="1.0"):
    _zip, entry = toolkit.make_notes_entry(shop.folder, files, name=name, version=version)
    shop.entries.append(entry)
    toolkit.write_index(shop.folder, shop.entries)
    run(session, f"tool install {name}")


def test_commands_are_registered_with_help_and_usage():
    assert COMMANDS["playbook list"][1] and COMMANDS["playbook show"][1]
    assert USAGES["playbook list"] == "usage: playbook list [<word>...]"
    assert USAGES["playbook show"] == "usage: playbook show <name>"


def test_playbook_alone_lists_its_two_commands(session):
    console = run(session, "playbook")
    shown = [text for _kind, text in console.lines]
    assert len(shown) == 2
    assert shown[0].startswith("playbook list") and shown[1].startswith("playbook show")


# ---- list


def test_list_without_playbooks_says_how_to_get_them(session, shop):
    console = run(session, "playbook list")
    assert lines(console, "info") == [NONE]
    assert console.tables == []


def test_list_shows_each_playbook_by_path_with_its_folder_and_title(session, shop):
    run(session, "tool install playbooks")
    console = run(session, "playbook list")
    assert table(console) == (
        ["name", "folder", "title"],
        [
            ["smb", "02-enum", "SMB enumeration"],
            ["services", "06-privesc/windows", "Windows privesc: services"],
        ],
    )
    assert lines(console, "info") == ["2 playbooks in playbooks 2026.11.19; playbook show <name> prints one"]


def test_list_with_words_keeps_the_playbooks_holding_every_word(session, shop):
    run(session, "tool install playbooks")
    console = run(session, "playbook list WINDOWS serv")
    assert [row[0] for row in table(console)[1]] == ["services"]
    assert lines(console, "info") == ["1 of 2 playbooks in playbooks 2026.11.19; playbook show <name> prints one"]
    # the folder counts too, and the title
    assert [row[0] for row in table(run(session, "playbook list 02-enum"))[1]] == ["smb"]
    assert [row[0] for row in table(run(session, "playbook list enumeration"))[1]] == ["smb"]


def test_list_with_words_that_match_nothing_says_so(session, shop):
    run(session, "tool install playbooks")
    console = run(session, "playbook list kerberos")
    assert lines(console, "info") == ["no playbooks match kerberos"]
    assert console.tables == []


def test_list_with_two_packages_adds_a_package_column(session, shop):
    run(session, "tool install playbooks")
    smb = toolkit.built_playbook("smb", "SMB, my way", "02-enum/smb", ["<TargetIP>"], "nxc smb <TargetIP>\n")
    add_package(session, shop, "extra", {"files/playbooks/02-enum/smb.md": smb.encode()})
    console = run(session, "playbook list")
    columns, rows = table(console)
    assert columns == ["name", "package", "folder", "title"]
    assert rows == [
        ["smb", "extra", "02-enum", "SMB, my way"],
        ["smb", "playbooks", "02-enum", "SMB enumeration"],
        ["services", "playbooks", "06-privesc/windows", "Windows privesc: services"],
    ]
    assert lines(console, "info") == [
        "3 playbooks in extra 1.0 and playbooks 2026.11.19; playbook show <name> prints one"
    ]


def test_list_leaves_out_a_file_that_is_not_markdown_and_titles_a_plain_one_with_nothing(session, shop):
    files = {
        "files/playbooks/notes/mine.md": b"# My own\n\nid\n",
        "files/playbooks/notes/readme.txt": b"not a playbook\n",
    }
    add_package(session, shop, "extra", files)
    assert table(run(session, "playbook list"))[1] == [["mine", "notes", ""]]


def test_list_after_the_playbooks_are_removed_has_none(session, shop):
    run(session, "tool install playbooks")
    run(session, "tool remove playbooks", "y")
    assert lines(run(session, "playbook list"), "info") == [NONE]


def test_list_leaves_out_another_boxs_playbooks(session, shop, monkeypatch):
    run(session, "tool install playbooks")
    monkeypatch.setattr(session, "box", replace(session.box, id="2026-11-15_htb_other"))
    assert lines(run(session, "playbook list"), "info") == [NONE]


# ---- show


def test_show_prints_the_playbook_without_its_fold_run_block_or_end_line(session, shop):
    run(session, "tool install playbooks")
    console = run(session, "playbook show smb")
    assert lines(console, "heading") == [SMB_LINE]
    assert lines(console, "log") == [
        "Fill in:  <TargetIP>  <Username>",
        "",
        *toolkit.SMB_BODY.rstrip("\n").split("\n"),
    ]
    # flush left for copying, and never raw: a package's control characters are shown as ?
    assert lines(console, "raw") == [] and lines(console, "fail") == []


def test_show_takes_a_path_as_well_as_a_name(session, shop):
    run(session, "tool install playbooks")
    console = run(session, "playbook show 06-privesc/windows/services")
    assert lines(console, "heading") == [
        "Playbook: Windows privesc: services   06-privesc/windows/services   2026.11.19"
    ]
    assert lines(console, "log")[-1] == "sc.exe qc <Service>"


def test_show_a_plain_file_whole_under_its_path(session, shop):
    add_package(session, shop, "extra", {"files/playbooks/notes/mine.md": b"# My own\n\nid\n"})
    console = run(session, "playbook show mine")
    assert lines(console, "heading") == ["notes/mine"]
    assert lines(console, "log") == ["# My own", "", "id"]


def test_show_a_name_in_two_packages_asks_for_the_package(session, shop):
    run(session, "tool install playbooks")
    smb = toolkit.built_playbook("smb", "SMB, my way", "02-enum/smb", ["<TargetIP>"], "nxc smb <TargetIP>\n")
    add_package(session, shop, "extra", {"files/playbooks/02-enum/smb.md": smb.encode()})
    console = run(session, "playbook show smb")
    assert lines(console, "fail") == [
        "smb is in more than one package; give one of extra/02-enum/smb, playbooks/02-enum/smb"
    ]
    assert lines(console, "log") == []
    console = run(session, "playbook show extra/02-enum/smb")
    assert lines(console, "heading") == ["Playbook: SMB, my way   02-enum/smb   2026.11.19"]


def test_show_an_unknown_name_points_at_the_list(session, shop):
    run(session, "tool install playbooks")
    console = run(session, "playbook show smbx")
    assert lines(console, "fail") == ["no playbook named smbx; playbook list shows them"]


def test_show_without_playbooks_says_how_to_get_them(session, shop):
    assert lines(run(session, "playbook show smb"), "fail") == [NONE]


def test_show_without_a_name_gives_its_usage(session, shop):
    console = run(session, "playbook show")
    assert lines(console, "fail") == ["missing argument: playbook name"]
    assert lines(console, "detail") == ["usage: playbook show <name>"]
    console = run(session, "playbook show smb services")
    assert lines(console, "fail") == ["too many arguments: services"]


# ---- completion


def test_completion_offers_names_from_any_part_in_any_case(session, shop):
    run(session, "tool install playbooks")
    assert completions(session, "playbook show ") == ["playbook show services", "playbook show smb"]
    assert completions(session, "playbook show SERV") == ["playbook show services"]
    assert completions(session, "playbook show s") == ["playbook show services", "playbook show smb"]
    assert completions(session, "playbook show x") == []
    assert completions(session, "playbook s") == ["playbook show"]


def test_completion_without_playbooks_or_with_a_broken_list_gives_nothing(session, shop, monkeypatch):
    assert completions(session, "playbook show ") == []

    def boom(_session):
        raise RuntimeError("broken")

    monkeypatch.setattr(cmd_playbook, "box_playbooks", boom)
    assert completions(session, "playbook show ") == []
