from conftest import NOW, make_cred
from pwn_broker.boxes import add_target
from pwn_broker.lists import rebuild_lists

FIXED = [
    "usernames.txt", "passwords.txt", "userpass.txt", "hashes.txt", "userhash.txt",
    "pair-users.txt", "pair-passwords.txt", "ips.txt", "hostnames.txt", "hosts.txt",
]  # fmt: skip


def cred(username, secret, kind, **kw):
    return make_cred(username=username, secret=secret, kind=kind, works_on=kw.pop("works_on", []), **kw)


def read(box, name):
    return (box.path / "lists" / name).read_bytes().decode("utf-8")


def test_basic_files(box, dc01):
    creds = [
        cred("svc", "s3rvice", "password"),
        cred("admin", "aad3b:31d6c", "hash"),
        cred("svc", "s3rvice", "password"),
        cred("guest", "", ""),
    ]
    s = rebuild_lists(box, [dc01], creds)
    assert read(box, "usernames.txt") == "svc\nadmin\nguest\n"
    assert read(box, "passwords.txt") == "s3rvice\n"
    assert read(box, "userpass.txt") == "svc:s3rvice\n"
    assert read(box, "hashes.txt") == "aad3b:31d6c\n"
    assert read(box, "userhash.txt") == "admin:aad3b:31d6c\n"
    assert read(box, "pair-users.txt") == "svc\n" and read(box, "pair-passwords.txt") == "s3rvice\n"
    assert (s.usernames, s.passwords, s.pairs, s.hashes, s.skipped) == (3, 1, 1, 1, [])


def test_secrets_written_byte_for_byte(box):
    secret = ' [red]p@ss "x"\\ :# é '
    rebuild_lists(box, [], [cred("u", secret, "password")])
    assert read(box, "passwords.txt") == secret + "\n"
    assert read(box, "userpass.txt") == "u:" + secret + "\n"


def test_line_endings_are_lf_only(box, dc01):
    rebuild_lists(box, [dc01], [cred("u", "p", "password", works_on=["dc01"]), cred("v", "h", "hash")])
    for name in (box.path / "lists").iterdir():
        assert b"\r" not in name.read_bytes()


def test_exact_match_dedupe(box):
    rebuild_lists(box, [], [cred("Admin", "a", "password"), cred("admin", "a", "password")])
    assert read(box, "usernames.txt") == "Admin\nadmin\n"
    assert read(box, "passwords.txt") == "a\n"
    assert read(box, "userpass.txt") == "Admin:a\nadmin:a\n"


def test_domain_never_in_lists(box):
    rebuild_lists(box, [], [cred("svc", "pw", "password", domain="htb.local")])
    assert read(box, "usernames.txt") == "svc\n"
    assert read(box, "userpass.txt") == "svc:pw\n"
    assert "htb" not in "".join(read(box, n) for n in FIXED)


def test_colon_username_skipped_from_colon_files(box):
    s = rebuild_lists(
        box, [], [cred("a:b", "pw", "password"), cred("a:b", "other", "password"), cred("c:d", "h", "hash")]
    )
    assert read(box, "userpass.txt") == "" and read(box, "userhash.txt") == ""
    assert read(box, "usernames.txt") == "a:b\nc:d\n"
    assert read(box, "pair-users.txt") == "a:b\na:b\n"
    assert read(box, "pair-passwords.txt") == "pw\nother\n"
    assert s.skipped == ["a:b", "c:d"]
    assert s.pairs == 0


def test_tokens_and_other_stay_out(box):
    s = rebuild_lists(box, [], [cred("t", "tok", "token"), cred("o", "oth", "other")])
    assert read(box, "usernames.txt") == "t\no\n"
    for name in FIXED[1:7]:
        assert read(box, name) == ""
    assert (s.usernames, s.passwords, s.pairs, s.hashes) == (2, 0, 0, 0)


def test_pair_files_share_order_and_length(box):
    creds = [cred("a", "1", "password"), cred("b:c", "2", "password"), cred("d", "3", "hash"), cred("a", "1", "password")]
    rebuild_lists(box, [], creds)
    assert read(box, "pair-users.txt") == "a\nb:c\n"
    assert read(box, "pair-passwords.txt") == "1\n2\n"


def test_target_lists(box, dc01):
    web01 = add_target(box, [dc01], ips=["10.10.10.162"], hostnames=[], scope="external", name="web01", now=NOW)
    dc01.hostnames = ["forest.htb.local", "dc01.forest.htb.local"]
    rebuild_lists(box, [dc01, web01], [])
    assert read(box, "ips.txt") == "10.10.10.161\n10.10.10.162\n"
    assert read(box, "hostnames.txt") == "forest.htb.local\ndc01.forest.htb.local\n"
    assert read(box, "hosts.txt") == "10.10.10.161 forest.htb.local dc01.forest.htb.local\n"


def test_target_lists_dedupe_across_targets(box, dc01):
    # two targets sharing a hostname, as a box made before a hostname belonged to one target can
    web01 = add_target(box, [], ips=["10.10.10.161", "10.10.10.9"], hostnames=["forest.htb.local"], scope="external", name="web01", now=NOW)
    rebuild_lists(box, [dc01, web01], [])
    assert read(box, "ips.txt") == "10.10.10.161\n10.10.10.9\n"
    assert read(box, "hostnames.txt") == "forest.htb.local\n"
    assert read(box, "hosts.txt").splitlines()[-1] == "10.10.10.9 forest.htb.local"


def test_works_files_appear_and_disappear(box, dc01):
    c = cred("svc", "pw", "password", works_on=["dc01"])
    rebuild_lists(box, [dc01], [c])
    assert read(box, "works-dc01-userpass.txt") == "svc:pw\n"
    assert not (box.path / "lists/works-dc01-userhash.txt").exists()
    c.works_on = []
    rebuild_lists(box, [dc01], [c])
    assert not (box.path / "lists/works-dc01-userpass.txt").exists()


def test_works_ignores_unknown_target_and_keeps_other_files(box, dc01):
    keep = box.path / "lists" / "notes.txt"
    keep.parent.mkdir(exist_ok=True)
    keep.write_text("mine")
    stale = box.path / "lists" / "works-gone-userhash.txt"
    stale.write_text("x")
    rebuild_lists(box, [dc01], [cred("a", "h", "hash", works_on=["ghost", "dc01"])])
    assert read(box, "works-dc01-userhash.txt") == "a:h\n"
    assert not (box.path / "lists/works-ghost-userhash.txt").exists()
    assert not stale.exists() and keep.read_text() == "mine"


def test_empty_box_writes_empty_files(box):
    s = rebuild_lists(box, [], [])
    for name in FIXED:
        assert read(box, name) == ""
    assert (s.usernames, s.passwords, s.pairs, s.hashes, s.skipped) == (0, 0, 0, 0, [])
