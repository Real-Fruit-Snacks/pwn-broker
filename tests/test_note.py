from dataclasses import replace
from importlib import resources

import pytest

from pwn_broker.note import (
    FOLD_END,
    FOLD_START,
    NOTE_NAME,
    NoteError,
    SECTION_MARK,
    append_section,
    box_lines,
    read_note,
    render_note,
    retitle,
    split_template,
    title_text,
    update_box,
    write_note,
)

TEMPLATE = resources.files("pwn_broker.data").joinpath("notes.md").read_text(encoding="utf-8")

FOREST = """\
################################################################
#  Box:         forest                                         #
#  Platform:    htb                                            #
#  Date:        2026-11-14                                     #
#  OS:          windows                                        #
#  Difficulty:  easy                                           #
#                                                              #
#  Targets:                                                    #
#    dc01   10.10.10.161   forest.htb.local   external         #
################################################################

##########@@@@@@@@@@
Target: dc01   10.10.10.161   forest.htb.local   external

## enumeration

## foothold

## privilege escalation

@@@@@@@@@@##########
"""


def _box_text(box, targets):
    return "".join(line + "\n" for line in box_lines(box, targets))


def test_fold_markers():
    assert FOLD_START == "##########@@@@@@@@@@"
    assert FOLD_END == "@@@@@@@@@@##########"


def test_template_is_exactly_the_default():
    raw = resources.files("pwn_broker.data").joinpath("notes.md").read_bytes()
    assert raw == (
        b"$box\n<!-- pwn-broker:section -->\n##########@@@@@@@@@@\nTarget: $title\n\n"
        b"## enumeration\n\n## foothold\n\n## privilege escalation\n\n@@@@@@@@@@##########\n"
    )


def test_split_template_drops_the_marker_line():
    header, section = split_template(TEMPLATE)
    assert header == "$box\n"
    assert section.startswith(FOLD_START + "\nTarget: $title\n")
    assert SECTION_MARK not in header + section


def test_new_note_for_forest_is_exactly_the_agreed_layout(box, dc01):
    assert render_note(TEMPLATE, box, [dc01]) == FOREST


def test_box_lines_all_have_the_same_width_and_borders(box, dc01):
    lines = box_lines(box, [dc01])
    assert {len(line) for line in lines} == {64}
    assert lines[0] == lines[-1] == "#" * 64
    for line in lines[1:-1]:
        assert line.startswith("#  ") and line.endswith("  #")


def test_box_widens_for_a_long_row(box, dc01):
    long = replace(dc01, name="web", hostnames=["a-very-long-hostname.internal.forest.htb.local"])
    lines = box_lines(box, [dc01, long])
    rows = [line for line in lines if "  dc01" in line or "  web" in line]
    widest = max(len(line[3:-3].rstrip()) for line in rows)
    assert {len(line) for line in lines} == {widest + 6}
    assert widest + 6 > 64


def test_box_rows_align_and_join_several_values(box, dc01):
    web = replace(dc01, name="web-frontend-01", ips=["10.10.10.1", "10.10.10.2"], hostnames=[])
    lines = box_lines(box, [dc01, web])
    first, second = (line for line in lines if line.startswith("#    ") and line[5] != " ")
    assert first.index("10.10.10.161") == second.index("10.10.10.1") == 3 + 2 + len("web-frontend-01") + 3
    assert first.index("forest.htb.local") == second.index("   -   ") + 3
    assert second == "#    web-frontend-01   10.10.10.1, 10.10.10.2   -" + " " * 18 + "external  #"
    assert first == "#    dc01" + " " * 14 + "10.10.10.161" + " " * 13 + "forest.htb.local   external  #"


def test_box_with_no_targets_and_blank_os(box):
    bare = replace(box, os="", difficulty="")
    lines = box_lines(bare, [])
    assert "#    none yet" + " " * (64 - 6 - 10) + "  #" in lines
    assert any(line.startswith("#  OS:          -  ") for line in lines)
    assert any(line.startswith("#  Difficulty:  -  ") for line in lines)


def test_title_text_is_not_padded(dc01):
    assert title_text(dc01) == "dc01   10.10.10.161   forest.htb.local   external"
    bare = replace(dc01, ips=["10.10.10.1", "10.10.10.2"], hostnames=[])
    assert title_text(bare) == "dc01   10.10.10.1, 10.10.10.2   -   external"


def test_render_with_two_targets_has_one_blank_line_between_parts(box, dc01):
    web = replace(dc01, name="web", ips=["10.10.10.5"], hostnames=[])
    text = render_note(TEMPLATE, box, [dc01, web])
    assert text.endswith(FOLD_END + "\n") and not text.endswith("\n\n")
    assert f"{FOLD_END}\n\n{FOLD_START}\nTarget: web   10.10.10.5   -   external\n" in text
    assert text.startswith(_box_text(box, [dc01, web]) + "\n" + FOLD_START + "\n")
    assert SECTION_MARK not in text


def test_old_placeholders_keep_working(box, dc01):
    template = "# $name $platform $date $os $difficulty\n" + SECTION_MARK + "\n## $target ($title)\n"
    text = render_note(template, box, [dc01])
    assert text == (
        "# forest htb 2026-11-14 windows easy\n\n"
        "## dc01 (dc01   10.10.10.161   forest.htb.local   external)\n"
    )


def test_dollar_signs_in_the_template_are_safe(box, dc01):
    template = "$5 and $unknown for $name\n" + SECTION_MARK + "\n$5 $target\n"
    text = render_note(template, box, [dc01])
    assert text == "$5 and $unknown for forest\n\n$5 dc01\n"


# update_box


def test_update_box_redraws_only_the_box(box, dc01):
    web = replace(dc01, name="web01", ips=["10.10.10.5"])
    before = render_note(TEMPLATE, box, [dc01]) + "\nmy own notes [x] $HOME <DomainUser>\n"
    after = update_box(before, box, [dc01, web])
    old_box = _box_text(box, [dc01])
    assert after == _box_text(box, [dc01, web]) + before[len(old_box):]
    assert "web01" in after.split(FOLD_START)[0]


def test_update_box_with_nothing_changed_is_identical(box, dc01):
    text = render_note(TEMPLATE, box, [dc01]) + "free text\n"
    assert update_box(text, box, [dc01]) == text


def test_update_box_keeps_crlf_and_missing_final_newline(box, dc01):
    before = "#" * 30 + "\r\n# old stuff\r\n" + "#" * 30 + "\r\nmine\r\nno newline"
    after = update_box(before, box, [dc01])
    assert after == "".join(line + "\r\n" for line in box_lines(box, [dc01])) + "mine\r\nno newline"


def test_update_box_when_the_note_is_only_the_box(box, dc01):
    before = "#" * 20 + "\n#\n" + "#" * 20
    after = update_box(before, box, [dc01])
    assert after == _box_text(box, [dc01])[:-1]


def test_update_box_accepts_rules_with_trailing_spaces(box, dc01):
    before = "#" * 25 + "  \n# x\n" + "#" * 25 + "\t\nafter\n"
    assert update_box(before, box, [dc01]) == _box_text(box, [dc01]) + "after\n"


def test_update_box_on_empty_text_returns_the_box(box, dc01):
    assert update_box("", box, [dc01]) == _box_text(box, [dc01])


def test_update_box_closing_rule_has_the_opening_rule_width(box, dc01):
    before = "#" * 64 + "\n# a\n" + "#" * 30 + "\n# mine\n" + "#" * 64 + "\nafter\n"
    assert update_box(before, box, [dc01]) == _box_text(box, [dc01]) + "after\n"


def test_update_box_ends_at_the_first_closing_rule(box, dc01):
    rule = "#" * 40
    before = f"{rule}\n# a\n{rule}\nmine\n{rule}\n"
    assert update_box(before, box, [dc01]) == _box_text(box, [dc01]) + f"mine\n{rule}\n"


@pytest.mark.parametrize(
    "text",
    [
        "free text first\n" + "#" * 64 + "\n",
        "#" * 19 + "\n# a\n" + "#" * 19 + "\n",
        "#" * 64 + "\n# a\n# b\n",
        "#" * 64 + "\n# a\n" + "#" * 40 + "\n## my heading\n",
        "#" * 64 + "\n# a\n" + "#" * 65 + "\n",
        "#" * 64 + "\n# a\nnot a box line\n" + "#" * 64 + "\n",
        "#" * 64 + "\n# a\n" + FOLD_START + "\nTarget: x\n" + FOLD_END + "\n" + "#" * 64 + "\n",
        " " + "#" * 64 + "\n# a\n" + "#" * 64 + "\n",
    ],
)
def test_update_box_refuses_a_damaged_box(box, dc01, text):
    with pytest.raises(NoteError, match="box at the top of the note is missing or damaged") as err:
        update_box(text, box, [dc01])
    message = str(err.value)
    assert "line of #" in message and "left alone" in message


# sections and titles


def test_append_section_goes_at_the_end(box, dc01):
    section = split_template(TEMPLATE)[1]
    out = append_section("mine\nnotes\n\n\n", section, dc01, box)
    assert out == "mine\nnotes\n\n" + FOREST.split("\n\n", 1)[1]
    assert append_section("no newline", section, dc01).startswith(f"no newline\n\n{FOLD_START}\n")


def test_append_section_with_empty_template_changes_nothing(dc01):
    assert append_section("text\n\n", "", dc01) == "text\n\n"


def test_append_section_fills_the_box_fields_like_render_note(box, dc01):
    section = "## $target on $name ($platform, $os, $difficulty, $date) $5\n"
    out = append_section("top\n", section, dc01, box)
    assert out == "top\n\n## dc01 on forest (htb, windows, easy, 2026-11-14) $5\n"
    assert render_note(SECTION_MARK + "\n" + section, box, [dc01]).endswith(out[len("top\n\n"):])
    assert append_section("", section, dc01) == "## dc01 on $name ($platform, $os, $difficulty, $date) $5\n"


def test_retitle_changes_only_a_title_under_a_fold_start():
    old, new = "dc01   10.10.10.161   -   external", "dc   10.10.10.161   -   external"
    text = (
        f"Target: {old}\n"
        f"{FOLD_START}\nTarget: {old}\nmore\n"
        f"see Target: {old}\n"
        f"{FOLD_START}\nTarget: {old} extra\n"
    )
    assert retitle(text, old, new) == text.replace(f"{FOLD_START}\nTarget: {old}\n", f"{FOLD_START}\nTarget: {new}\n")
    assert retitle(text, old, new).count(f"Target: {new}") == 1


def test_retitle_keeps_crlf_and_regex_characters():
    text = f"{FOLD_START}  \r\nTarget: a.b $1\r\nx\r\n{FOLD_START}\r\nTarget: aXb $1\r\n"
    assert retitle(text, "a.b $1", "c\\1") == text.replace("Target: a.b $1\r\n", "Target: c\\1\r\n")


def test_retitle_leaves_a_title_the_user_changed():
    text = f"{FOLD_START}\nTarget: dc01 my main box\nnotes"
    assert retitle(text, "dc01", "dc") == text


def test_retitle_at_end_of_file_without_newline():
    assert retitle(f"{FOLD_START}\nTarget: a", "a", "b") == f"{FOLD_START}\nTarget: b"


def test_note_round_trip_keeps_line_endings(box):
    text = "a\r\nb\nc"
    write_note(box, text)
    assert (box.path / NOTE_NAME).read_bytes() == b"a\r\nb\nc"
    assert read_note(box) == text
    assert [p.name for p in box.path.iterdir() if p.suffix == ".tmp"] == []


def test_read_note_that_is_not_utf8_raises_note_error_naming_it(box):
    (box.path / NOTE_NAME).write_bytes(b"# forest\n\xff\xfe broken\n")
    with pytest.raises(NoteError, match="notes.md"):
        read_note(box)
