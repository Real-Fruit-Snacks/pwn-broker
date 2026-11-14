from datetime import timedelta

import pytest

from conftest import NOW, make_cred
from pwn_broker.creds import (
    KINDS,
    CredError,
    add_cred,
    check_field,
    edit_cred,
    has_edge_space,
    import_usernames,
    last_domain,
    mark_works,
    remove_cred,
)

FIELDS = dict(
    username="alice", domain="htb.local", secret="Passw0rd!", kind="password",
    found_on="dc01", note="", now=NOW,
)  # fmt: skip


def test_kinds():
    assert KINDS == ("password", "hash", "token", "other")


def test_add_assigns_numbers_that_are_never_reused():
    creds = []
    a = add_cred(creds, **FIELDS)
    b = add_cred(creds, **FIELDS)
    remove_cred(creds, b.n)
    c = add_cred(creds, floor=b.n, **FIELDS)
    assert (a.n, b.n, c.n) == (1, 2, 3)


def test_add_without_floor_uses_highest_in_list():
    creds = [make_cred(n=7)]
    assert add_cred(creds, **FIELDS).n == 8


def test_add_appends_to_list_and_sets_added():
    creds = []
    c = add_cred(creds, **FIELDS)
    assert creds == [c] and c.added == NOW and c.works_on == []


def test_blank_secret_has_no_kind():
    creds = []
    c = add_cred(creds, **{**FIELDS, "secret": "", "kind": "hash"})
    assert c.kind == ""
    edited = edit_cred(creds, c.n, kind="token")
    assert edited.kind == ""


def test_edit_blank_secret_clears_kind():
    creds = []
    c = add_cred(creds, **FIELDS)
    edit_cred(creds, c.n, secret="")
    assert c.kind == ""


def test_edit_setting_secret_requires_valid_kind():
    creds = []
    c = add_cred(creds, **{**FIELDS, "secret": ""})
    with pytest.raises(CredError):
        edit_cred(creds, c.n, secret="x")
    assert c.secret == "" and c.kind == ""
    edit_cred(creds, c.n, secret="x", kind="hash")
    assert (c.secret, c.kind) == ("x", "hash")


def test_unknown_kind_rejected():
    with pytest.raises(CredError):
        add_cred([], **{**FIELDS, "kind": "key"})


def test_empty_username_rejected():
    with pytest.raises(CredError):
        add_cred([], **{**FIELDS, "username": ""})
    creds = []
    c = add_cred(creds, **FIELDS)
    with pytest.raises(CredError):
        edit_cred(creds, c.n, username="")


def test_empty_optional_fields_allowed():
    c = add_cred([], **{**FIELDS, "domain": "", "found_on": "", "note": "", "secret": ""})
    assert (c.domain, c.found_on, c.secret) == ("", "", "")


def test_multi_line_value_refused():
    for bad in ("a\nb", "a\r\nb", "a\rb"):
        with pytest.raises(CredError, match="creds/"):
            check_field("secret", bad)


def test_multi_line_refused_in_every_field_on_add_and_edit():
    creds = []
    c = add_cred(creds, **FIELDS)
    for name in ("username", "domain", "secret", "found_on", "note"):
        with pytest.raises(CredError, match=name):
            add_cred([], **{**FIELDS, name: "a\nb"})
        with pytest.raises(CredError, match=name):
            edit_cred(creds, c.n, **{name: "a\rb"})
    assert creds == [c] and c.username == "alice"


def test_has_edge_space():
    assert has_edge_space(" x") and has_edge_space("x ") and has_edge_space("x\t")
    assert not has_edge_space("x y")


def test_add_keeps_values_exactly():
    odd_user = " a\"b" + chr(92) + "c' "
    odd_secret = "  p\"w" + chr(92) + "d'$x  "
    c = add_cred([], **{**FIELDS, "username": odd_user, "secret": odd_secret})
    assert c.username == odd_user and c.secret == odd_secret


def test_edit_changes_only_named_fields():
    creds = []
    c = add_cred(creds, **FIELDS)
    before = make_cred(**vars(c))
    edit_cred(creds, c.n, note=" new note ", works_on=["web01"])
    assert c.note == " new note " and c.works_on == ["web01"]
    for name in ("n", "username", "domain", "secret", "kind", "found_on", "added"):
        assert getattr(c, name) == getattr(before, name)


def test_edit_rejects_unknown_number_and_field():
    creds = []
    c = add_cred(creds, **FIELDS)
    with pytest.raises(CredError):
        edit_cred(creds, 99, note="x")
    for bad in ("colour", "n", "added"):
        with pytest.raises(CredError):
            edit_cred(creds, c.n, **{bad: 5})


def test_failed_edit_changes_nothing():
    creds = []
    c = add_cred(creds, **FIELDS)
    with pytest.raises(CredError):
        edit_cred(creds, c.n, note="fine", kind="key")
    assert c.note == "" and c.kind == "password"


def test_remove_returns_cred_and_rejects_unknown():
    creds = []
    c = add_cred(creds, **FIELDS)
    assert remove_cred(creds, c.n) is c and creds == []
    with pytest.raises(CredError):
        remove_cred(creds, c.n)


def test_mark_works_no_duplicates():
    creds = []
    c = add_cred(creds, **FIELDS)
    mark_works(creds, c.n, ["dc01"])
    mark_works(creds, c.n, ["dc01"])
    mark_works(creds, c.n, ["web01"])
    assert c.works_on == ["dc01", "web01"]


def test_mark_works_order_and_unknown():
    creds = []
    c = add_cred(creds, **FIELDS)
    mark_works(creds, c.n, ["b", "a", "b"])
    assert c.works_on == ["b", "a"]
    with pytest.raises(CredError):
        mark_works(creds, 42, ["a"])


def test_import_skips_blanks_and_existing():
    creds = []
    add_cred(creds, **FIELDS)
    n = import_usernames(
        creds, ["alice", "", "bob", "  ", "bob", "Alice"],
        domain="htb.local", found_on="dc01", now=NOW,
    )  # fmt: skip
    assert n == 2 and [c.username for c in creds] == ["alice", "bob", "Alice"]
    imported = creds[1]
    assert (imported.secret, imported.kind, imported.note, imported.works_on) == ("", "", "", [])
    assert (imported.domain, imported.found_on, imported.added) == ("htb.local", "dc01", NOW)
    assert [c.n for c in creds] == [1, 2, 3]


def test_import_strips_only_the_line_ending():
    creds = []
    n = import_usernames(
        creds, ["bob \n", "carol\r\n", "dave\r", " eve"],
        domain="", found_on="", now=NOW,
    )  # fmt: skip
    assert n == 4
    assert [c.username for c in creds] == ["bob ", "carol", "dave", " eve"]


def test_import_skips_embedded_carriage_return():
    creds = []
    n = import_usernames(creds, ["a\rb\n", "ok\n"], domain="", found_on="", now=NOW)
    assert n == 1 and [c.username for c in creds] == ["ok"]


def test_import_accepts_a_file(tmp_path):
    f = tmp_path / "users.txt"
    f.write_bytes(b"x\r\ny\n")
    creds = []
    with open(f, newline="") as handle:
        assert import_usernames(creds, handle, domain="", found_on="", now=NOW) == 2
    assert [c.username for c in creds] == ["x", "y"]


def test_last_domain():
    assert last_domain([]) == ""
    creds = [
        make_cred(n=1, domain="OLD", added=NOW),
        make_cred(n=2, domain="NEW", added=NOW + timedelta(hours=1)),
        make_cred(n=3, domain="", added=NOW + timedelta(hours=2)),
    ]
    assert last_domain(creds) == "NEW"
    creds.append(make_cred(n=4, domain="TIE", added=NOW + timedelta(hours=1)))
    assert last_domain(creds) == "TIE"
    assert last_domain([make_cred(domain="")]) == ""


def test_import_respects_floor():
    creds = [make_cred(n=1), make_cred(n=2)]
    import_usernames(creds, ["bob"], domain="", found_on="", now=NOW, floor=3)
    assert creds[-1].n == 4


def test_floor_below_highest_is_ignored():
    creds = [make_cred(n=5)]
    assert add_cred(creds, floor=2, **FIELDS).n == 6


def test_bare_string_targets_rejected():
    creds = []
    c = add_cred(creds, **FIELDS)
    with pytest.raises(CredError):
        mark_works(creds, c.n, "dc01")
    with pytest.raises(CredError):
        edit_cred(creds, c.n, works_on="dc01")
    assert c.works_on == []


def test_multi_line_target_rejected():
    creds = []
    c = add_cred(creds, **FIELDS)
    with pytest.raises(CredError, match="creds/"):
        mark_works(creds, c.n, ["ok", "a\nb"])
    with pytest.raises(CredError, match="creds/"):
        edit_cred(creds, c.n, works_on=["a\rb"])
    assert c.works_on == []


def test_edit_works_on_drops_duplicates_keeping_order():
    creds = []
    c = add_cred(creds, **FIELDS)
    edit_cred(creds, c.n, works_on=["b", "a", "b"])
    assert c.works_on == ["b", "a"]


def test_import_multi_line_domain_or_found_on_adds_nothing():
    creds = []
    with pytest.raises(CredError):
        import_usernames(creds, ["bob"], domain="a\nb", found_on="", now=NOW)
    with pytest.raises(CredError):
        import_usernames(creds, ["bob"], domain="", found_on="a\rb", now=NOW)
    assert creds == []
