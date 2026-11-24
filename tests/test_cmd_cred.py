import io

import pytest

from helpers import NASTY, NOW, make_cred
from pwn_broker import session as session_module
from pwn_broker import shell  # noqa: F401  (fills the command registry)
from pwn_broker import store
from pwn_broker.boxes import add_target
from pwn_broker.config import Settings
from pwn_broker.console import Cancelled, FakeConsole, TermConsole
from pwn_broker.creds import KINDS, has_edge_space
from pwn_broker.questions import CredAnswers, ask_cred, ask_value
from pwn_broker.session import Session
from pwn_broker.shell.commands import dispatch
from pwn_broker.store import StoreError, load_box, load_creds


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
    assert console.lines == [("warn", "the secret starts or ends with a space")]
    assert ask_value(FakeConsole([" pw ", ""]), "secret") == " pw "


def test_ask_value_default():
    assert ask_value(FakeConsole([""]), "secret", "old") == "old"


def test_ask_cred_catches_a_multiline_domain_at_the_question(session):
    console = FakeConsole(["bob", "HTB\nCORP", "CORP", "", "", ""])
    got = ask_cred(console, session, heading="New credential")
    assert got.domain == "CORP"
    assert console.asked[:3] == ["username", "domain", "domain"]
    assert len([k for k, _ in console.lines if k == "fail"]) == 1


def test_ask_cred_domain_dash_is_not_an_edge_space_question(session):
    _seed(session, domain="CORP")
    console = FakeConsole(["bob", "-", "", "", ""])
    assert ask_cred(console, session, heading="New credential").domain == ""
    assert "keep or trim" not in console.asked


@pytest.mark.parametrize("answer, stored", [("keep", " CORP "), ("trim", "CORP")])
def test_ask_cred_domain_edge_space_asks_keep_or_trim(session, answer, stored):
    console = FakeConsole(["bob", " CORP ", answer, "", "", ""])
    assert ask_cred(console, session, heading="New credential").domain == stored
    assert console.asked[:3] == ["username", "domain", "keep or trim"]


def test_ask_cred_catches_a_multiline_note_and_edge_spaces_at_the_question(session):
    console = FakeConsole(["bob", "", "", "", "line one\nline two", " n ", "trim"])
    assert ask_cred(console, session, heading="New credential").note == "n"
    assert console.asked[-3:] == ["note", "note", "keep or trim"]


def test_ask_cred_blank_secret_skips_kind(session):
    console = FakeConsole(["bob", "-", "", "", "n"])
    got = ask_cred(console, session, heading="New credential")
    assert got == CredAnswers("bob", "", "", "", "dc01", "n")
    assert console.asked == ["username", "domain", "secret", "found on", "note"]


def test_ask_cred_bad_kind_and_empty_username(session):
    console = FakeConsole(["", "bob", "", "pw", "key", "hash", "", ""])
    got = ask_cred(console, session, heading="New credential")
    assert got.kind == "hash"
    fails = [t for k, t in console.lines if k == "fail"]
    assert len(fails) == 2 and all(kind in fails[1] for kind in KINDS)


def test_ask_cred_no_targets_accepts_only_blank(paths, box):
    console = FakeConsole(["bob", "", "", "dc01", "", ""])
    bare = Session(paths, Settings(), console, box, [], [], None, lambda: NOW)
    got = ask_cred(console, bare, heading="New credential")
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
        ("heading", "New credential"),
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


def _disk(session):
    box = session.box.path
    lists = {p.name: p.read_bytes() for p in (box / "lists").glob("*")} if (box / "lists").exists() else {}
    creds_file = box / "creds.toml"
    return (
        (box / "box.toml").read_bytes(),
        creds_file.read_bytes() if creds_file.exists() else None,
        lists,
    )


def test_cred_add_cancel_saves_nothing(session):
    before = _disk(session)
    session.console = FakeConsole(["bob", "", "pw"])
    dispatch(session, "cred add")
    assert session.creds == []
    assert _disk(session) == before
    assert _lines(session, "info") == ["cancelled"]


def test_cred_edit_cancel_changes_nothing(session):
    _seed(session, secret="old")
    dispatch(session, "cred works 1")
    before = _disk(session)
    session.console = FakeConsole(["bob", "", "new"])
    dispatch(session, "cred edit 1")
    assert session.creds[0].secret == "old" and session.creds[0].username == "administrator"
    assert _disk(session) == before
    assert _lines(session, "info") == ["cancelled"]


def test_cred_import_cancel_at_second_question_changes_nothing(session, tmp_path):
    names = tmp_path / "n.txt"
    names.write_text("a\nb\n", encoding="utf-8")
    before = _disk(session)
    session.console = FakeConsole(["CORP"])
    dispatch(session, f"cred import {names}")
    assert session.creds == []
    assert _disk(session) == before
    assert _lines(session, "info") == ["cancelled"]


def test_failed_save_leaves_the_list_unchanged(session, monkeypatch):
    def broken(box, creds):
        raise StoreError("disk full")

    monkeypatch.setattr(session_module, "save_creds", broken)
    session.console = FakeConsole(["bob", "", "pw", "", "", ""])
    dispatch(session, "cred add")
    assert session.creds == []
    assert _lines(session, "ok") == []
    assert len(_lines(session, "fail")) == 1


def test_failed_save_restores_edit_remove_and_works(session, monkeypatch):
    _seed(session, secret="old")
    before = [(c.secret, list(c.works_on)) for c in session.creds]

    def broken(box, creds):
        raise StoreError("disk full")

    monkeypatch.setattr(session_module, "save_creds", broken)
    for line, answers in (
        ("cred edit 1", ["", "", "new", "", "", "", ""]),
        ("cred works 1", []),
        ("cred remove 1", ["y"]),
    ):
        session.console = FakeConsole(answers)
        dispatch(session, line)
        assert [(c.secret, list(c.works_on)) for c in session.creds] == before, line
        assert _lines(session, "ok") == [], line


def _break_lists(monkeypatch):
    def broken(box, targets, creds):
        raise OSError("lists folder is read-only")

    monkeypatch.setattr(session_module, "rebuild_lists", broken)


def test_failure_after_the_save_puts_disk_back_too(session, monkeypatch):
    _seed(session, secret="old")
    session_module.save_creds(session.box, session.creds)
    _break_lists(monkeypatch)
    session.console = FakeConsole(["bob", "", "pw", "", "", ""])
    dispatch(session, "cred add")
    assert [c.username for c in session.creds] == ["administrator"]
    assert load_creds(session.box) == session.creds
    assert _lines(session, "fail") == ["lists folder is read-only"]


def test_failure_of_the_second_save_is_ignored(session, monkeypatch):
    _break_lists(monkeypatch)
    real = store.save_creds
    calls = []

    def flaky(box, creds):
        calls.append(len(creds))
        if len(calls) > 1:
            raise OSError("disk gone")
        real(box, creds)

    monkeypatch.setattr(session_module, "save_creds", flaky)
    monkeypatch.setattr(store, "save_creds", flaky)
    session.console = FakeConsole(["bob", "", "pw", "", "", ""])
    dispatch(session, "cred add")
    assert calls == [1, 0]
    assert session.creds == []
    assert _lines(session, "fail") == ["lists folder is read-only"]


def test_remove_remembers_the_number_on_an_old_box(session):
    _seed(session)
    assert "last_cred_n" not in session.box.extra
    session.console = FakeConsole(["y"])
    dispatch(session, "cred remove 1")
    assert load_box(session.box.path).extra["last_cred_n"] == 1


def test_cred_import_skips_a_byte_order_mark(session, tmp_path):
    names = tmp_path / "n.txt"
    names.write_bytes(b"\xef\xbb\xbfalice\nbob\n")
    session.console = FakeConsole(["", ""])
    dispatch(session, f"cred import {names}")
    assert [c.username for c in load_creds(session.box)] == ["alice", "bob"]


def test_edit_found_on_blank_when_stored_target_is_gone(session):
    _seed(session, found_on="gone")
    session.console = FakeConsole(["", "", "", "", "", "", ""])
    dispatch(session, "cred edit 1")
    assert load_creds(session.box)[0].found_on == ""
    assert session.console.asked[-3] == "found on"
    assert _lines(session, "fail") == []


def test_edit_found_on_nonblank_is_still_resolved(session):
    _seed(session, found_on="")
    session.console = FakeConsole(["", "", "", "", "nope", "dc", "", ""])
    dispatch(session, "cred edit 1")
    assert len(_lines(session, "fail")) == 1
    assert load_creds(session.box)[0].found_on == "dc01"


def test_missing_cred_number_is_one_fail_line(session):
    dispatch(session, "cred show 4")
    assert session.console.lines == [("fail", "no credential numbered 4")]


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
    session.console = FakeConsole()
    dispatch(session, "cred show 1")
    if secret:
        assert session.console.lines == [("raw", secret)]
    else:
        assert session.console.lines == [("fail", "cred 1 has no secret")]


@pytest.mark.parametrize("value", NASTY[:-1])
def test_username_and_note_are_exact(session, value):
    answers = [value, "", "", "", value]
    if has_edge_space(value):
        answers.insert(1, "keep")
        answers.append("keep")
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
    # the secret is the one column cut on a narrow terminal
    assert session.console.events == [("table", "secret")]


@pytest.mark.parametrize(
    "line, message, usage",
    [
        ("cred show", "missing argument: cred number", "usage: cred show <n>"),
        ("cred edit 1 2", "too many arguments: 2", "usage: cred edit <n>"),
        ("cred remove", "missing argument: cred number", "usage: cred remove <n>"),
        ("cred works", "missing argument: cred number", "usage: cred works <n> [<target>...]"),
        ("cred import", "missing argument: file", "usage: cred import <file>"),
        ("cred add x", "too many arguments: x", "usage: cred add"),
        ("cred list x", "too many arguments: x", "usage: cred list"),
    ],
)
def test_a_wrong_number_of_arguments_shows_the_usage(session, line, message, usage):
    _seed(session)
    dispatch(session, line)
    assert session.console.lines == [("fail", message), ("detail", usage)]
    assert session.console.asked == []


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
    session.console = FakeConsole(["", "", "", "", "", "", "", ""])
    dispatch(session, "cred edit 1")
    assert session.console.asked == [
        "username", "domain", "secret", "keep or trim", "kind", "found on", "works on", "note",
    ]  # fmt: skip
    [c] = load_creds(session.box)
    assert (c.username, c.domain, c.secret, c.kind, c.found_on, c.note) == (
        "administrator", "CORP", " pw ", "hash", "dc01", "n1",
    )  # fmt: skip
    assert _lines(session, "ok")[0] == "cred 1 updated"


def test_cred_edit_changes_a_field_and_refreshes_lists(session):
    _seed(session, secret="old")
    session.console = FakeConsole(["", "", "new", "", "", "", ""])
    dispatch(session, "cred edit 1")
    assert load_creds(session.box)[0].secret == "new"
    assert "new" in (session.box.path / "lists" / "passwords.txt").read_text(encoding="utf-8")


def _two_targets(session):
    add_target(
        session.box, session.targets, ips=["10.0.0.2"], hostnames=[], scope="external",
        name="web", now=NOW,
    )  # fmt: skip
    _seed(session, works_on=["dc01", "web"])
    dispatch(session, "cred works 1 dc01")
    lists = session.box.path / "lists"
    assert (lists / "works-web-userpass.txt").exists()
    return lists


def _edit_works_on(session, answers):
    # username, domain, secret, kind, found on, works on..., note
    session.console = FakeConsole(["", "", "", "", "", *answers, ""])
    dispatch(session, "cred edit 1")
    assert session.console.asked[5] == "works on" and session.console.asked[-1] == "note"
    return load_creds(session.box)[0].works_on


def test_cred_edit_takes_a_target_off_works_on(session):
    lists = _two_targets(session)
    assert _edit_works_on(session, ["dc01"]) == ["dc01"]
    assert session.creds[0].works_on == ["dc01"]
    assert not (lists / "works-web-userpass.txt").exists()
    assert (lists / "works-dc01-userpass.txt").exists()


def test_cred_edit_clears_works_on_with_a_dash(session):
    lists = _two_targets(session)
    assert _edit_works_on(session, ["-"]) == []
    assert list(lists.glob("works-*")) == []


def test_cred_edit_keeps_works_on_with_enter(session):
    _two_targets(session)
    assert _edit_works_on(session, [""]) == ["dc01", "web"]


def test_cred_edit_works_on_resolves_prefixes_and_drops_duplicates(session):
    _two_targets(session)
    assert _edit_works_on(session, ["nope dc01", "we dc01 web"]) == ["web", "dc01"]
    assert len(_lines(session, "fail")) == 1
    assert session.console.asked[5:7] == ["works on", "works on"]


def test_cred_edit_works_on_keeps_a_name_that_is_no_longer_a_target(session):
    _seed(session, works_on=["gone", "dc01"])
    assert _edit_works_on(session, [""]) == ["gone", "dc01"]
    assert _lines(session, "fail") == []


def test_cred_add_does_not_ask_works_on(session):
    session.console = FakeConsole(["bob", "", "", "", ""])
    dispatch(session, "cred add")
    assert "works on" not in session.console.asked
    assert load_creds(session.box)[0].works_on == []


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
    assert session.console.lines == [("heading", "Import usernames"), ("ok", "0 usernames added")]


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


def test_cred_add_works_with_a_note_that_is_not_utf8(session):
    note = session.box.path / "notes.md"
    note.write_bytes(b"# forest\n\xff broken\n")
    session.console = FakeConsole(["bob", "", "pw", "", "", ""])
    dispatch(session, "cred add")
    assert [c.username for c in load_creds(session.box)] == ["bob"]
    assert _lines(session, "ok")[0] == "cred 1 saved, found on dc01"
    [warn] = _lines(session, "warn")
    assert "notes.md" in warn
    assert note.read_bytes() == b"# forest\n\xff broken\n"


def test_colon_username_prints_warn(session):
    session.console = FakeConsole(["a:b", "", "pw", "", "", ""])
    dispatch(session, "cred add")
    assert _lines(session, "warn") == [
        "a:b contains a colon and is left out of the colon-separated lists"
    ]


@pytest.mark.parametrize("env", [{"NO_COLOR": "1"}, {}])
def test_cred_show_writes_a_tab_secret_exactly_to_the_terminal(session, env):
    out = io.StringIO()
    session.console = TermConsole(env, out=out)
    _seed(session, secret="tab\there  ")
    dispatch(session, "cred show 1")
    assert out.getvalue() == "tab\there  \n"


def _clear_seed(session, **overrides):
    return _seed(session, secret="s3cret", note="a note", works_on=["dc01"], **overrides)


def test_cred_clear_secret(session):
    _clear_seed(session, username="bob")
    session.console = FakeConsole(["y"])
    dispatch(session, "cred clear 1 secret")
    [c] = load_creds(session.box)
    assert (c.secret, c.kind, c.works_on, c.note) == ("", "", [], "a note")
    assert [c.secret for c in session.creds] == [""]
    lists = session.box.path / "lists"
    assert "s3cret" not in (lists / "passwords.txt").read_text(encoding="utf-8")
    assert "s3cret" not in (lists / "userpass.txt").read_text(encoding="utf-8")
    assert not (lists / "works-dc01-userpass.txt").exists()
    assert (lists / "usernames.txt").read_text(encoding="utf-8").splitlines() == ["bob"]
    assert session.console.asked == ["clear the secret of cred 1?"]
    assert session.console.lines[0] == ("info", "bob, found on dc01")
    assert session.console.lines[1:3] == [
        ("ok", "cred 1 secret cleared"),
        ("ok", "cred 1 no longer marked as working on dc01"),
    ]
    assert session.console.lines[3][1].startswith("lists updated: ")


def test_cred_clear_secret_without_works_on_has_one_ok_line_before_lists(session):
    _seed(session, secret="s3cret", found_on="")
    session.console = FakeConsole(["y"])
    dispatch(session, "cred clear 1 secret")
    assert session.console.lines[0] == ("info", "administrator")
    assert session.console.lines[1] == ("ok", "cred 1 secret cleared")
    assert session.console.lines[2][1].startswith("lists updated: ")
    assert len(session.console.lines) == 3


def test_cred_clear_note(session):
    _clear_seed(session)
    session.console = FakeConsole(["y"])
    dispatch(session, "cred clear 1 note")
    [c] = load_creds(session.box)
    assert (c.note, c.secret, c.kind, c.works_on) == ("", "s3cret", "password", ["dc01"])
    assert session.console.asked == ["clear the note of cred 1?"]
    assert ("ok", "cred 1 note cleared") in session.console.lines
    assert not any("no longer marked" in t for _, t in session.console.lines)


@pytest.mark.parametrize("answers", [[""], ["n"], ["maybe", "n"]])
def test_cred_clear_declined_changes_nothing(session, answers):
    _clear_seed(session)
    session_module.save_creds(session.box, session.creds)
    before = (session.box.path / "creds.toml").read_bytes()
    session.console = FakeConsole(answers)
    dispatch(session, "cred clear 1 secret")
    assert (session.box.path / "creds.toml").read_bytes() == before
    assert session.creds[0].secret == "s3cret"
    assert _lines(session, "ok") == []
    assert session.console.asked == ["clear the secret of cred 1?"] * len(answers)
    assert _lines(session, "fail") == ["answer y or n"] * (len(answers) - 1)


@pytest.mark.parametrize("field", ["secret", "note"])
def test_cred_clear_already_empty(session, field):
    _seed(session, secret="", kind="", note="")
    dispatch(session, f"cred clear 1 {field}")
    assert session.console.lines == [("fail", f"cred 1 has no {field}")]
    assert session.console.asked == []


def test_cred_clear_bad_field(session):
    _clear_seed(session)
    dispatch(session, "cred clear 1 kind")
    assert session.console.lines == [("fail", "field must be secret or note: kind")]
    assert session.creds[0].secret == "s3cret"


@pytest.mark.parametrize("line", ["cred clear x note", "cred clear 0 note", "cred clear 9 note"])
def test_cred_clear_bad_arguments(session, line):
    _clear_seed(session)
    dispatch(session, line)
    assert [k for k, _ in session.console.lines] == ["fail"]
    assert session.creds[0].note == "a note"


@pytest.mark.parametrize(
    "line, message",
    [
        ("cred clear", "missing argument: cred number"),
        ("cred clear 1", "missing argument: field"),
        ("cred clear 1 note x", "too many arguments: x"),
    ],
)
def test_cred_clear_with_the_wrong_number_of_arguments_shows_its_usage(session, line, message):
    _clear_seed(session)
    dispatch(session, line)
    assert session.console.lines == [("fail", message), ("detail", "usage: cred clear <n> <field>")]
    assert session.creds[0].note == "a note"


def test_cred_clear_cancel_leaves_the_file_alone(session, monkeypatch):
    _clear_seed(session)
    session_module.save_creds(session.box, session.creds)
    before = (session.box.path / "creds.toml").read_bytes()

    def cancel(question, default=False):
        raise Cancelled()

    session.console.confirm = cancel
    dispatch(session, "cred clear 1 secret")
    assert (session.box.path / "creds.toml").read_bytes() == before
    assert session.creds[0].secret == "s3cret"
    assert session.console.lines[-1] == ("info", "cancelled")


def _list(session):
    session.console = FakeConsole()
    dispatch(session, "cred list")
    return session.console.tables[0][1], _lines(session, "info")


NOTE_ONE = "* the table cannot show this secret exactly. use: cred show {}"


def test_cred_list_flags_a_secret_with_a_tab(session):
    _seed(session, secret="plain")
    _seed(session, n=2, secret="tab\there")
    rows, info = _list(session)
    assert [r[0] for r in rows] == ["1", "2*"]
    assert rows[1][3] == "tab\there"
    assert info == [NOTE_ONE.format(2)]


@pytest.mark.parametrize(
    "secret",
    [" lead", "trail ", "  both  ", "\u00a0nbsp", "x\x1b[0m", "a\x00b",
     # the format characters and separators the console shows as ?
     "pass\u202eword", "pass\u200bword", "pass\u2028word", "pass\u2029word"],
)  # fmt: skip
def test_cred_list_flags_edge_space_and_control_characters(session, secret):
    _seed(session, secret=secret)
    rows, info = _list(session)
    assert rows[0][0] == "1*"
    assert rows[0][3] == secret
    assert info == [NOTE_ONE.format(1)]


def test_cred_list_two_flagged_rows_give_the_generic_line(session):
    _seed(session, secret=" a")
    _seed(session, n=2, secret="plain")
    _seed(session, n=3, secret="b\t")
    rows, info = _list(session)
    assert [r[0] for r in rows] == ["1*", "2", "3*"]
    assert info == [NOTE_ONE.format("<n>")]


@pytest.mark.parametrize("secret", ["", "Passw0rd!", "a b", "[red]x[/red]", "pässwörd", "'"])
def test_cred_list_does_not_flag_a_plain_secret(session, secret):
    _seed(session, secret=secret)
    rows, info = _list(session)
    assert rows[0][0] == "1" and rows[0][3] == secret
    assert info == []
