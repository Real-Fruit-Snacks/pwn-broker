import sys
from dataclasses import replace

import pytest

from helpers import NOW
from pwn_broker import search as finder
from pwn_broker.boxes import add_target
from pwn_broker.console import FakeConsole
from pwn_broker.note import FOLD_END, FOLD_START
from pwn_broker.shell.commands import dispatch


def lines(session, kind=None):
    return [t for k, t in session.console.lines if kind is None or k == kind]


@pytest.fixture
def two(session):
    """dc01, the current target, and web01, each with a file that mentions a password; the note
    has a section for each."""
    web = add_target(session.box, session.targets, ips=["10.10.10.5"], hostnames=["web.htb"],
                     scope="internal", name="web01", now=NOW)  # fmt: skip
    box = session.box.path
    (box / "targets" / "dc01" / "loot" / "web.config").write_text(
        "<config>\n  <add key=\"DbPassword\" value=\"Sup3r!\" />\n</config>\n"
    )
    (box / "targets" / "dc01" / "recordings").mkdir(exist_ok=True)
    (box / "targets" / "dc01" / "recordings" / "01.txt").write_text("$ cat creds\nadmin password: hunter2\n")
    (box / "targets" / "dc01" / "recordings" / "01.cast").write_text('[0.1, "o", "admin password: hunter2"]\n')
    (box / "targets" / "web01" / "files" / "notes.txt").write_text("the PASSWORD for ftp is reused\n")
    (box / "vpn").mkdir(exist_ok=True)
    (box / "vpn" / "lab.ovpn").write_text("password in the key\n")
    (box / "notes.md").write_text(
        "#####\n# box\n#####\n"
        f"{FOLD_START}\nTarget: dc01   10.10.10.161   forest.htb.local   external\n## enumeration\ndc01 password guess\n"
        f"{FOLD_START}\nnested password\n{FOLD_END}\n{FOLD_END}\n"
        f"{FOLD_START}\nTarget: web01   10.10.10.5   web.htb   internal\nweb01 password\n{FOLD_END}\n"
    )
    return web


def test_search_looks_in_the_current_target_and_its_section_of_the_note(session, two):
    dispatch(session, "search password")
    assert session.console.lines == [
        ("info", "notes.md"),
        ("detail", "    7  dc01 password guess"),
        ("detail", "    9  nested password"),
        ("info", "targets/dc01/loot/web.config"),
        ("detail", '    2  <add key="DbPassword" value="Sup3r!" />'),
        ("info", "targets/dc01/recordings/01.txt"),
        ("detail", "    2  admin password: hunter2"),
        ("info", "4 hits in 3 files in dc01"),
    ]


def test_search_names_another_target_without_switching_to_it(session, two):
    dispatch(session, "search web01 password")
    assert lines(session) == [
        "notes.md", "   14  web01 password",
        "targets/web01/files/notes.txt", "    1  the PASSWORD for ftp is reused",
        "2 hits in 2 files in web01",
    ]
    assert session.current.name == "dc01"


def test_search_all_looks_through_the_whole_box_but_never_vpn(session, two):
    dispatch(session, "search all password")
    shown = lines(session)
    assert "targets/web01/files/notes.txt" in shown and "targets/dc01/loot/web.config" in shown
    assert "vpn/lab.ovpn" not in shown and not any(".cast" in t for t in shown)
    assert shown[-1] == "6 hits in 4 files in the box"


def test_a_first_word_that_is_no_scope_is_searched_for(session, two):
    dispatch(session, "search admin password")
    assert lines(session)[-1] == "1 hit in 1 file in dc01"
    session.console = FakeConsole()
    # a target's name alone is what is looked for
    dispatch(session, "search web01")
    assert lines(session) == ["no hits for web01 in dc01"]


def test_search_with_no_hits(session, two):
    dispatch(session, "search all nothing-like-this")
    assert lines(session) == ["no hits for nothing-like-this in the box"]


def test_search_needs_text(session):
    dispatch(session, "search")
    assert lines(session, "fail") == ["missing argument: text"]


def test_search_without_a_target_points_at_all(session, two):
    session.current = None
    dispatch(session, "search password")
    assert lines(session, "fail") == ["no target is selected; search all <text> searches the whole box"]


def test_binary_and_large_files_are_skipped(session, two, monkeypatch):
    loot = session.box.path / "targets" / "dc01" / "loot"
    (loot / "SAM").write_bytes(b"\0\0password\0")
    (loot / "big.log").write_text("password\n" * 2000)
    monkeypatch.setattr(finder, "MAX_FILE", 10000)
    dispatch(session, "search password")
    shown = lines(session)
    assert "targets/dc01/loot/SAM" not in shown
    assert shown[-1] == "skipped as larger than 16 MiB: targets/dc01/loot/big.log"


def test_only_the_first_hits_are_shown(session, two, monkeypatch):
    (session.box.path / "targets" / "dc01" / "loot" / "many.txt").write_text("password\n" * 10)
    monkeypatch.setattr(finder, "MAX_HITS", 3)
    dispatch(session, "search password")
    # the note first, then the files in name order: many.txt before web.config
    assert lines(session, "detail") == ["    7  dc01 password guess", "    9  nested password", "    1  password"]
    assert lines(session, "info")[-2:] == ["14 hits in 4 files in dc01", "the first 3 are shown; narrow the search for the rest"]


def test_a_long_or_odd_line_is_cut_and_made_printable(session, two):
    (session.box.path / "targets" / "dc01" / "loot" / "odd.txt").write_text("x\x1b[31mpassword" + "y" * 300 + "\n")
    dispatch(session, "search password")
    [shown] = [t for t in lines(session, "detail") if "x?[31m" in t]
    assert shown.startswith("    1  x?[31mpassword") and shown.endswith("...") and len(shown) == 7 + finder.MAX_LINE


@pytest.mark.skipif(sys.platform == "win32", reason="links need a POSIX file system")
def test_links_are_not_followed(session, two, tmp_path):
    outside = tmp_path / "outside.txt"
    outside.write_text("password outside the box\n")
    (session.box.path / "targets" / "dc01" / "loot" / "link.txt").symlink_to(outside)
    dispatch(session, "search outside")
    assert lines(session) == ["no hits for outside in dc01"]


def test_note_section_stops_at_its_own_end_with_nested_folds_inside():
    text = f"{FOLD_START}\nTarget: a   -   -   external\n{FOLD_START}\ninner\n{FOLD_END}\nafter inner\n{FOLD_END}\noutside\n"
    assert [line for _, line in finder.note_section(text, "a")] == [
        FOLD_START, "Target: a   -   -   external", FOLD_START, "inner", FOLD_END, "after inner", FOLD_END,
    ]
    assert finder.note_section(text, "b") == []
