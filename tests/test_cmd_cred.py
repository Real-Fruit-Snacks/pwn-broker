import pytest

from helpers import NASTY, NOW, make_cred
from pwn_broker import shell  # noqa: F401  (fills the command registry)
from pwn_broker.boxes import add_target
from pwn_broker.config import Settings
from pwn_broker.console import FakeConsole
from pwn_broker.creds import KINDS, has_edge_space
from pwn_broker.questions import CredAnswers, ask_cred, ask_value
from pwn_broker.session import Session
from pwn_broker.shell.commands import dispatch
from pwn_broker.store import load_box, load_creds


def _lines(session, kind):
    return [text for k, text in session.console.lines if k == kind]


def _seed(session, **overrides):
    cred = make_cred(**{"works_on": [], "found_on": "dc01", **overrides})
    session.creds.append(cred)
    return cred


def _add_answers(secret):
    answers = ["u", "", secret]
    if has_edge_space(secret):
        answers.append("keep")
    if secret:
        answers.append("")
    return answers + ["", ""]


def test_ask_value_refuses_multiline_and_asks_again():
    console = FakeConsole(["a\nb", "ab"])
    assert ask_value(console, "secret") == "ab"
    assert [k for k, _ in console.lines] == ["fail"]
    assert console.asked == ["secret", "secret"]


def test_ask_value_keep_trim_and_reask():
    console = FakeConsole([" pw ", "maybe", "trim"])
    assert ask_value(console, "secret") == "pw"
    assert console.asked == ["secret", "keep or trim", "keep or trim"]
    assert [k for k, _ in console.lines] == ["info"]
    assert ask_value(FakeConsole([" pw ", ""]), "secret") == " pw "


def test_ask_value_default():
    assert ask_value(FakeConsole([""]), "secret", "old") == "old"


def test_ask_cred_blank_secret_skips_kind(session):
    console = FakeConsole(["bob", "-", "", "", "n"])
    got = ask_cred(console, session)
    assert got == CredAnswers("bob", "", "", "", "dc01", "n")
    assert console.asked == ["username", "domain", "secret", "found on", "note"]


def test_ask_cred_bad_kind_and_empty_username(session):
    console = FakeConsole(["", "bob", "", "pw", "key", "hash", "", ""])
    got = ask_cred(console, session)
    assert got.kind == "hash"
    fails = [t for k, t in console.lines if k == "fail"]
    assert len(fails) == 2 and all(kind in fails[1] for kind in KINDS)


def test_ask_cred_no_targets_accepts_only_blank(paths, box):
    console = FakeConsole(["bob", "", "", "dc01", "", ""])
    bare = Session(paths, Settings(), console, box, [], [], None, lambda: NOW)
    got = ask_cred(console, bare)
    assert got.found_on == ""
    assert len(_lines(bare, "fail")) == 1


def test_cred_add_question_order_and_result(session):
    session.console = FakeConsole(["svc-alfresco", "", 'p@ss "word" with spaces\\', "", "", ""])
    dispatch(session, "cred add")
    [c] = load_creds(session.box)
    assert (c.username, c.secret, c.kind, c.found_on) == (
        "svc-alfresco", 'p@ss "word" with spaces\\', "password", "dc01",
    )  # fmt: skip
    assert session.console.asked == ["username", "domain", "secret", "kind", "found on", "note"]
    assert session.console.lines == [
        ("ok", "cred 1 saved, found on dc01"),
        ("ok", "lists updated: 1 username, 1 password, 1 pair"),
    ]


def test_cred_add_blank_secret_skips_kind(session):
    session.console = FakeConsole(["bob", "", "", "", ""])
    dispatch(session, "cred add")
    assert "kind" not in session.console.asked
    [c] = load_creds(session.box)
    assert (c.secret, c.kind) == ("", "")
    assert _lines(session, "ok")[-1] == "lists updated: 1 username, 0 passwords, 0 pairs"


def test_cred_add_without_found_on(session):
    session.targets.clear()
    session.current = None
    session.console = FakeConsole(["bob", "", "", "", ""])
    dispatch(session, "cred add")
    assert _lines(session, "ok")[0] == "cred 1 saved"


def test_cred_add_domain_defaults_to_last_used(session):
    _seed(session, domain="CORP")
    session.console = FakeConsole(["bob", "", "", "", ""])
    dispatch(session, "cred add")
    assert load_creds(session.box)[-1].domain == "CORP"


def test_cred_add_domain_dash_means_none(session):
    _seed(session, domain="CORP")
    session.console = FakeConsole(["bob", "-", "", "", ""])
    dispatch(session, "cred add")
    assert load_creds(session.box)[-1].domain == ""


@pytest.mark.parametrize("answer, stored", [("keep", " pw "), ("trim", "pw")])
def test_cred_add_edge_space_asks_keep_or_trim(session, answer, stored):
    session.console = FakeConsole(["bob", "", " pw ", answer, "", "", ""])
    dispatch(session, "cred add")
    assert load_creds(session.box)[0].secret == stored


def test_cred_add_cancel_saves_nothing(session):
    session.console = FakeConsole(["bob", "", "pw"])
    dispatch(session, "cred add")
    assert session.creds == []
    assert load_creds(session.box) == []
    assert _lines(session, "info") == ["cancelled"]


def test_cred_add_found_on_must_be_a_target(session):
    session.console = FakeConsole(["bob", "", "", "nope", "dc", ""])
    dispatch(session, "cred add")
    assert len(_lines(session, "fail")) == 1
    assert load_creds(session.box)[0].found_on == "dc01"


@pytest.mark.parametrize("secret", NASTY)
def test_secret_is_exact_on_disk_in_the_table_and_in_show(session, secret):
    session.console = FakeConsole(_add_answers(secret))
    dispatch(session, "cred add")
    assert load_creds(session.box)[0].secret == secret
    session.console = FakeConsole()
    dispatch(session, "cred list")
    columns, rows = session.console.tables[0]
    assert columns == ["n", "user", "domain", "secret", "kind", "found on", "works on"]
    assert rows[0][3] == secret
    dispatch(session, "cred show 1")
    if secret:
        assert session.console.lines == [("info", secret)]
    else:
        assert session.console.lines == [("fail", "cred 1 has no secret")]


@pytest.mark.parametrize("value", NASTY[:-1])
def test_username_and_note_are_exact(session, value):
    answers = [value, "", "", "", value]
    if has_edge_space(value):
        answers.insert(1, "keep")
    session.console = FakeConsole(answers)
    dispatch(session, "cred add")
    [c] = load_creds(session.box)
    assert (c.username, c.note) == (value, value)


def test_cred_list_shows_values_literally(session):
    _seed(session, secret="[red]x[/red]", works_on=["dc01", "web"], note="a  b")
    _seed(session, n=2, secret="", kind="", found_on="", domain="")
    dispatch(session, "cred list")
    _, rows = session.console.tables[0]
    assert rows[0] == ["1", "administrator", "HTB", "[red]x[/red]", "password", "dc01", "dc01, web"]
    assert rows[1] == ["2", "administrator", "", "", "", "", ""]


def test_cred_list_empty(session):
    dispatch(session, "cred list")
    assert session.console.lines == [("info", "no creds yet")]


def test_cred_show_unknown_and_bad_number(session):
    _seed(session)
    for line in ("cred show 9", "cred show x", "cred show 0", "cred show -1"):
        session.console = FakeConsole()
        dispatch(session, line)
        assert [k for k, _ in session.console.lines] == ["fail"], line


def test_cred_edit_defaults_are_current_values(session):
    _seed(session, secret=" pw ", domain="CORP", note="n1", kind="hash")
    session.console = FakeConsole(["", "", "", "", "", "", "", "", ""])
    dispatch(session, "cred edit 1")
    assert session.console.asked[:3] == ["username", "domain", "secret"]
    [c] = load_creds(session.box)
    assert (c.username, c.domain, c.secret, c.kind, c.found_on, c.note) == (
        "administrator", "CORP", " pw ", "hash", "dc01", "n1",
    )  # fmt: skip
    assert _lines(session, "ok")[0] == "cred 1 updated"


def test_cred_edit_changes_a_field_and_refreshes_lists(session):
    _seed(session, secret="old")
    session.console = FakeConsole(["", "", "new", "", "", ""])
    dispatch(session, "cred edit 1")
    assert load_creds(session.box)[0].secret == "new"
    assert "new" in (session.box.path / "lists" / "passwords.txt").read_text(encoding="utf-8")


def test_cred_works_defaults_to_current_target(session):
    _seed(session)
    dispatch(session, "cred works 1")
    assert load_creds(session.box)[0].works_on == ["dc01"]
    assert (session.box.path / "lists" / "works-dc01-userpass.txt").exists()
    assert _lines(session, "ok")[0] == "cred 1 works on dc01"


def test_cred_works_prefix_and_several(session):
    _seed(session)
    add_target(
        session.box, session.targets, ips=["10.0.0.2"], hostnames=[], scope="external",
        name="web", now=NOW,
    )  # fmt: skip
    dispatch(session, "cred works 1 we dc01")
    assert load_creds(session.box)[0].works_on == ["web", "dc01"]
    assert _lines(session, "ok")[0] == "cred 1 works on web, dc01"


def test_cred_works_unknown_target_fails(session):
    _seed(session)
    dispatch(session, "cred works 1 nope")
    assert [k for k, _ in session.console.lines] == ["fail"]
    assert session.creds[0].works_on == []


def test_cred_works_without_any_target_fails(session):
    _seed(session)
    session.current = None
    dispatch(session, "cred works 1")
    assert [k for k, _ in session.console.lines] == ["fail"]


def test_cred_remove_asks(session):
    _seed(session, username="bob")
    session.console = FakeConsole(["n"])
    dispatch(session, "cred remove 1")
    assert len(session.creds) == 1
    assert _lines(session, "info") == ["bob, found on dc01"]
    session.console = FakeConsole(["y"])
    dispatch(session, "cred remove 1")
    assert session.creds == [] and load_creds(session.box) == []
    assert "bob" not in (session.box.path / "lists" / "usernames.txt").read_text(encoding="utf-8")
    assert _lines(session, "ok")[0] == "cred 1 removed"


def test_cred_numbers_are_never_reused(session):
    for _ in range(2):
        session.console = FakeConsole(["bob", "", "", "", ""])
        dispatch(session, "cred add")
    session.console = FakeConsole(["y"])
    dispatch(session, "cred remove 2")
    session.console = FakeConsole(["carl", "", "", "", ""])
    dispatch(session, "cred add")
    assert [c.n for c in load_creds(session.box)] == [1, 3]
    assert load_box(session.box.path).extra["last_cred_n"] == 3

    # a restart: everything is read back from disk
    session.box = load_box(session.box.path)
    session.creds = load_creds(session.box)
    session.console = FakeConsole(["y"])
    dispatch(session, "cred remove 3")
    session.console = FakeConsole(["dave", "", "", "", ""])
    dispatch(session, "cred add")
    assert [c.n for c in load_creds(session.box)] == [1, 4]


def test_cred_import_reports_count(session, tmp_path):
    _seed(session, username="known")
    names = tmp_path / "names.txt"
    names.write_bytes(b"known\r\n new one\r\n\r\nother\r\n")
    session.console = FakeConsole(["CORP", ""])
    dispatch(session, f"cred import {names}")
    assert session.console.asked == ["domain", "found on"]
    assert _lines(session, "ok")[0] == "2 usernames added"
    added = load_creds(session.box)[1:]
    assert [(c.username, c.domain, c.found_on, c.n) for c in added] == [
        (" new one", "CORP", "dc01", 2), ("other", "CORP", "dc01", 3),
    ]  # fmt: skip
    assert _lines(session, "ok")[1].startswith("lists updated:")


def test_cred_import_nothing_new(session, tmp_path):
    names = tmp_path / "names.txt"
    names.write_text("\n\n", encoding="utf-8")
    session.console = FakeConsole(["", ""])
    dispatch(session, f"cred import {names}")
    assert session.console.lines == [("ok", "0 usernames added")]


def test_cred_import_single_name_is_singular(session, tmp_path):
    names = tmp_path / "names.txt"
    names.write_text("solo\n", encoding="utf-8")
    session.console = FakeConsole(["", ""])
    dispatch(session, f"cred import {names}")
    assert _lines(session, "ok")[0] == "1 username added"


def test_cred_import_path_with_spaces(session, tmp_path):
    folder = tmp_path / "my files"
    folder.mkdir()
    (folder / "n.txt").write_text("solo\n", encoding="utf-8")
    session.console = FakeConsole(["", ""])
    dispatch(session, f"cred import {folder / 'n.txt'}")
    assert _lines(session, "ok")[0] == "1 username added"


def test_cred_import_missing_directory_and_binary_fail(session, tmp_path):
    binary = tmp_path / "b.bin"
    binary.write_bytes(b"\xff\xfe\x00bad\xff")
    for target in (tmp_path / "missing.txt", tmp_path, binary):
        session.console = FakeConsole()
        dispatch(session, f"cred import {target}")
        [(kind, text)] = session.console.lines
        assert kind == "fail" and str(target) in text
        assert session.console.asked == []
    assert session.creds == []


def test_colon_username_prints_warn(session):
    session.console = FakeConsole(["a:b", "", "pw", "", "", ""])
    dispatch(session, "cred add")
    assert _lines(session, "warn") == [
        "a:b contains a colon and is left out of the colon-separated lists"
    ]
