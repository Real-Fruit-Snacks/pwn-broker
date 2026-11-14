from dataclasses import replace
from importlib import resources

import pytest

from pwn_broker.note import (
    NOTE_NAME,
    NoteError,
    SECTION_MARK,
    TABLE_BEGIN,
    TABLE_END,
    append_section,
    read_note,
    rename_heading,
    render_note,
    split_template,
    table_lines,
    update_table,
    write_note,
)

TEMPLATE = resources.files("pwn_broker.data").joinpath("notes.md").read_text(encoding="utf-8")


def test_template_is_stored_with_lf_and_one_final_newline():
    raw = resources.files("pwn_broker.data").joinpath("notes.md").read_bytes()
    assert b"\r" not in raw
    assert raw.endswith(b"### privilege escalation\n")


def test_split_template_drops_the_marker_line():
    header, section = split_template(TEMPLATE)
    assert header.endswith(TABLE_END + "\n")
    assert section.startswith("## $target\n")
    assert SECTION_MARK not in header + section


def test_render_fills_box_details_and_sections(box, dc01):
    text = render_note(TEMPLATE, box, [dc01])
    assert text.startswith(
        "# forest\nplatform     htb\ndate         2026-11-14\nos           windows\ndifficulty   easy\n"
    )
    assert "dc01   10.10.10.161   forest.htb.local   external" in text
    assert "\n## dc01\n### enumeration\n### foothold\n### privilege escalation\n" in text
    assert SECTION_MARK not in text


def test_render_leaves_empty_os_and_difficulty_blank(box):
    bare = replace(box, os="", difficulty="")
    text = render_note(TEMPLATE, bare, [])
    assert "\nos           \ndifficulty   \n" in text


def test_table_columns_align(dc01):
    long = replace(dc01, name="web-frontend-01", ips=["10.10.10.2"])
    first, second = table_lines([dc01, long])
    assert first.index("10.10.10.161") == second.index("10.10.10.2") == len("web-frontend-01") + 3
    assert first.index("forest.htb.local") == second.index("forest.htb.local")


def test_table_joins_several_addresses(dc01):
    multi = replace(dc01, ips=["10.10.10.1", "10.10.10.2"], hostnames=[])
    (line,) = table_lines([multi])
    assert line == "dc01   10.10.10.1, 10.10.10.2   -   external"
    assert not line.endswith(" ")


def test_update_table_touches_only_the_block(box, dc01):
    web01 = replace(dc01, name="web01", ips=["10.10.10.5"])
    before = render_note(TEMPLATE, box, [dc01]) + "\nmy own notes [x] $HOME\n"
    after = update_table(before, [dc01, web01])
    assert after.split(TABLE_END)[1] == before.split(TABLE_END)[1]
    assert after.split(TABLE_BEGIN)[0] == before.split(TABLE_BEGIN)[0]
    assert "web01" in after


def test_update_table_keeps_crlf_and_missing_final_newline(dc01):
    web01 = replace(dc01, name="web01")
    before = f"top\r\n{TABLE_BEGIN}\r\nold\r\n{TABLE_END}\r\nmine\r\nno newline"
    after = update_table(before, [web01])
    assert after.startswith(f"top\r\n{TABLE_BEGIN}\r\nweb01   ")
    assert after.endswith(f"{TABLE_END}\r\nmine\r\nno newline")
    assert "old" not in after


def test_update_table_when_markers_were_deleted(dc01):
    before = "# forest\nmy notes\n"
    after = update_table(before, [dc01])
    assert after.startswith(before)
    assert after[len(before):] == "\n## targets\n" + TABLE_BEGIN + "\n" + table_lines([dc01])[0] + "\n" + TABLE_END + "\n"


def test_append_section_goes_at_the_end(dc01):
    section = split_template(TEMPLATE)[1]
    out = append_section("# forest\nnotes\n\n\n", section, dc01)
    assert out == "# forest\nnotes\n\n## dc01\n### enumeration\n### foothold\n### privilege escalation\n"
    assert append_section("no newline", section, dc01).startswith("no newline\n\n## dc01\n")


def test_rename_heading_only_exact_line():
    text = "## dc01\nsee dc01 and ## dc01x\n## dc01x\n"
    assert rename_heading(text, "dc01", "dc") == "## dc\nsee dc01 and ## dc01x\n## dc01x\n"


def test_rename_heading_keeps_crlf_and_regex_characters():
    text = "## a.b\r\nx\r\n## aXb\r\n"
    assert rename_heading(text, "a.b", "c\1") == "## c\1\r\nx\r\n## aXb\r\n"


def test_dollar_signs_in_the_template_are_safe(box, dc01):
    template = "$5 and $unknown for $name\n" + SECTION_MARK + "\n$5 $target\n"
    text = render_note(template, box, [dc01])
    assert text == "$5 and $unknown for forest\n\n$5 dc01\n"


def test_note_round_trip_keeps_line_endings(box):
    text = "a\r\nb\nc"
    write_note(box, text)
    assert (box.path / NOTE_NAME).read_bytes() == b"a\r\nb\nc"
    assert read_note(box) == text
    assert [p.name for p in box.path.iterdir() if p.suffix == ".tmp"] == []


def _broken(dc01, text):
    before = f"mine\n{text}\nmy own writing\n"
    for _ in range(2):
        with pytest.raises(NoteError):
            update_table(before, [dc01])
    return before


def test_update_table_refuses_when_only_end_is_missing(dc01):
    _broken(dc01, f"{TABLE_BEGIN}\nrow")


def test_update_table_refuses_when_only_begin_is_missing(dc01):
    _broken(dc01, f"row\n{TABLE_END}")


def test_update_table_refuses_when_end_comes_first(dc01):
    _broken(dc01, f"{TABLE_END}\nrow\n{TABLE_BEGIN}")


def test_update_table_refuses_duplicated_marker(dc01):
    _broken(dc01, f"{TABLE_BEGIN}\n{TABLE_BEGIN}\nrow\n{TABLE_END}")


def test_update_table_accepts_markers_with_trailing_spaces(dc01):
    before = f"{TABLE_BEGIN}  \nold\n{TABLE_END}\t\n"
    after = update_table(before, [dc01])
    assert "old" not in after and "dc01" in after


def test_append_section_with_empty_template_changes_nothing(dc01):
    assert append_section("text\n\n", "", dc01) == "text\n\n"
