from pwn_broker.note import FOLD_END, FOLD_START
from pwn_broker.playbooks import find, installed, read_lines, shown, template_lines, title
from pwn_broker.toolstate import Installed
from toolkit import built_playbook

BODY = "## Null session\nnxc smb <TargetIP>\nnxc smb 10.10.10.161\nplain prose\n"


def numbered(text):
    return {n: line for n, line in enumerate(text.splitlines(), start=1)}


def test_template_lines():
    text = "before <TargetIP>\n" + built_playbook("smb", "SMB", "02-enum/smb", ["<TargetIP>"], BODY) + "after <TargetIP>\n"
    lines = numbered(text)
    skipped = {lines[n] for n in template_lines(text.splitlines())}
    assert skipped == {
        "my",
        "/^\\%>'yEND OF smb PLAYBOOK$",
        "mz",
        ":'y,'zs/<TargetIP>/<Replace>/ge",
        "'y",
        "Fill in:  <TargetIP>",
        "nxc smb <TargetIP>",
    }
    assert "nxc smb 10.10.10.161" not in skipped and "plain prose" not in skipped
    numbers = template_lines(text.splitlines())
    for n, line in lines.items():
        if line in (FOLD_START, FOLD_END) or line.startswith("Playbook: ") or line.startswith(("before", "after")):
            assert n not in numbers


def test_template_lines_finds_a_playbook_inside_a_target_fold():
    text = (
        f"{FOLD_START}\nTarget: dc01   10.10.10.161   -   external\n"
        + built_playbook("smb", "SMB", "02-enum/smb", ["<TargetIP>"], BODY)
        + f"dc01 <TargetIP> note of my own\n{FOLD_END}\n"
    )
    lines = numbered(text)
    skipped = {lines[n] for n in template_lines(text.splitlines())}
    assert "nxc smb <TargetIP>" in skipped
    assert "dc01 <TargetIP> note of my own" not in skipped


def test_a_playbook_whose_run_block_was_deleted_keeps_its_filled_lines_searchable():
    text = built_playbook("smb", "SMB", "02-enum/smb", ["<TargetIP>"], BODY)
    lines = text.splitlines()
    start, end = lines.index("my"), lines.index("'y")
    del lines[start : end + 1]
    skipped = {lines[n - 1] for n in template_lines(lines)}
    assert skipped == {"Fill in:  <TargetIP>", "nxc smb <TargetIP>"}


def test_template_lines_without_playbooks_is_empty():
    assert template_lines([FOLD_START, "Target: a", "<TargetIP>", FOLD_END]) == set()


# ---- what playbook list and show read


def notes(name, root, version="2026.11.19"):
    return Installed(name, version, 1, "", "", [], [], False, ["id-1"], {}, notes=root.as_posix())


def write(path, text):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(text, encoding="utf-8")


def test_installed_lists_every_playbook_by_path(tmp_path):
    one, two = tmp_path / "one", tmp_path / "two"
    write(one / "02-enum" / "smb.md", "a")
    write(one / "06-privesc" / "windows" / "services.md", "b")
    write(one / "02-enum" / "readme.txt", "not a playbook")
    write(two / "02-enum" / "smb.md", "c")
    found = installed([notes("playbooks", one), notes("extra", two, "1.0")])
    assert [(p.name, p.rel, p.package, p.version) for p in found] == [
        ("smb", "02-enum/smb", "extra", "1.0"),
        ("smb", "02-enum/smb", "playbooks", "2026.11.19"),
        ("services", "06-privesc/windows/services", "playbooks", "2026.11.19"),
    ]
    assert found[2].file == one / "06-privesc" / "windows" / "services.md"


def test_find_takes_the_name_the_path_or_the_package_and_path(tmp_path):
    one, two = tmp_path / "one", tmp_path / "two"
    write(one / "02-enum" / "smb.md", "a")
    write(two / "02-enum" / "smb.md", "c")
    found = installed([notes("playbooks", one), notes("extra", two)])
    assert len(find(found, "smb")) == 2
    assert len(find(found, "02-enum/smb")) == 2
    assert [p.package for p in find(found, "extra/02-enum/smb")] == ["extra"]
    assert find(found, "sm") == [] and find(found, "SMB") == []


def test_shown_leaves_out_the_fold_the_run_block_and_the_end_line():
    lines = built_playbook("smb", "SMB enumeration", "02-enum/smb", ["<TargetIP>"], BODY).splitlines()
    line, body = shown(lines)
    assert line == "Playbook: SMB enumeration   02-enum/smb   2026.11.19"
    assert body == ["Fill in:  <TargetIP>", "", *BODY.rstrip("\n").split("\n")]
    assert title(lines) == "SMB enumeration"


def test_shown_without_placeholders_has_no_run_block_to_leave_out():
    # as pwn-playbooks builds one with nothing to fill in: no run block and no Fill in line
    lines = [FOLD_START, "Playbook: Linux enumeration   06-privesc/linux/linux-enum   2026.11.23", "",
             "## Who am I", "id", "", "END OF linux-enum PLAYBOOK", FOLD_END]  # fmt: skip
    line, body = shown(lines)
    assert line.startswith("Playbook: Linux enumeration")
    assert body == ["## Who am I", "id"]
    assert title(lines) == "Linux enumeration"


def test_shown_keeps_a_body_line_that_only_looks_like_the_run_block_or_the_end():
    lines = [FOLD_START, "Playbook: Odd   odd   1", "", "my", "END OF odd PLAYBOOK", "more", FOLD_END]
    assert shown(lines)[1] == ["my", "END OF odd PLAYBOOK", "more"]


def test_shown_without_a_fold_end_shows_to_the_last_line():
    lines = [FOLD_START, "Playbook: Cut   cut   1", "", "## Half", "id"]
    assert shown(lines) == ("Playbook: Cut   cut   1", ["## Half", "id"])


def test_a_file_not_built_as_a_playbook_is_shown_whole():
    lines = ["", "# My own note", "", "id", ""]
    assert shown(lines) == (None, ["# My own note", "", "id"])
    assert title(lines) == ""


def test_title_of_a_playbook_line_without_three_fields_is_the_rest_of_it():
    assert title([FOLD_START, "Playbook: Just a title"]) == "Just a title"


def test_read_lines_shows_bytes_that_are_not_utf8(tmp_path):
    path = tmp_path / "bad.md"
    path.write_bytes(b"ok\n\xff\n")
    assert read_lines(path) == ["ok", "\ufffd"]
