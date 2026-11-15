import os
import subprocess
import sys
from pathlib import Path

import pytest

from pwn_broker import hosts
from pwn_broker.hosts import HostsError, Wanted

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX links and inodes")

ME = "2026-11-14_htb_forest"
OTHER = "2026-11-10_htb_sauna"

BASE = (
    b"127.0.0.1\tlocalhost\n"
    b"127.0.1.1\tkali\n"
    b"\n"
    b"# The following lines are desirable for IPv6\n"
    b"::1     localhost ip6-localhost ip6-loopback\n"
)


def mine(ip, *names, box_id=ME):
    return f"{ip} {' '.join(names)}  # pwn-broker {box_id}".encode()


# valid_hostname and line


@pytest.mark.parametrize(
    "name",
    ["forest.htb.local", "dc01", "a-b.c-d", "A1.HTB", "x" * 253, "1.2.3.4"],
)
def test_valid_hostname_accepts(name):
    assert hosts.valid_hostname(name)


@pytest.mark.parametrize(
    "name",
    [
        "",
        "x" * 254,
        "a b",
        "a#b",
        "a\tb",
        "a\nb",
        "a.htb\n",
        "a.htb\r",
        "a\r\nb",
        "-a.htb",
        "a-.htb",
        "a.-b",
        ".a.htb",
        "a.htb.",
        "a..htb",
        "a_b.htb",
        "a/b",
        "ä.htb",
        "a\x00b",
    ],
)
def test_valid_hostname_refuses(name):
    assert not hosts.valid_hostname(name)


def test_line_format():
    wanted = Wanted("dc01", "10.10.10.161", ["forest.htb.local", "dc01.htb.local"])
    assert (
        hosts.line(wanted, ME)
        == f"10.10.10.161 forest.htb.local dc01.htb.local  # pwn-broker {ME}"
    )


@pytest.mark.parametrize(
    "name",
    ["a b", "a#b", "a\tb", "a\nb", "a.htb\n10.0.0.1 evil.htb", "a.htb # x", "", "a..b"],
)
def test_line_refuses_bad_hostname(name):
    with pytest.raises(HostsError):
        hosts.line(Wanted("dc01", "10.10.10.161", ["ok.htb", name]), ME)


@pytest.mark.parametrize(
    "ip",
    [
        "",
        "10.10.10.161 evil.htb",
        "10.10.10.161#",
        "10.10.10.161\t",
        "10.10.10.161\n",
        "10.10.10.161\n10.0.0.1",
        " 10.10.10.161",
        "999.1.1.1",
        "dc01",
        "fe80::1%eth0",
        "fe80::1%a b",
        "fe80::1%a#b",
        "fe80::1%x\n10.0.0.1 evil.htb",
    ],
)
def test_line_refuses_bad_ip(ip):
    with pytest.raises(HostsError):
        hosts.line(Wanted("dc01", ip, ["dc01.htb"]), ME)


@pytest.mark.parametrize("box_id", ["", "a b", "a#b", "a\nb", "x/y"])
def test_line_refuses_bad_box_id(box_id):
    with pytest.raises(HostsError):
        hosts.line(Wanted("dc01", "10.10.10.161", ["dc01.htb"]), box_id)


def test_line_refuses_no_names():
    with pytest.raises(HostsError):
        hosts.line(Wanted("dc01", "10.10.10.161", []), ME)


def test_rewrite_refuses_bad_entry_and_bad_id():
    with pytest.raises(HostsError):
        hosts.rewrite(BASE, ME, [Wanted("dc01", "10.10.10.161", ["a b"])])
    with pytest.raises(HostsError):
        hosts.rewrite(BASE, "a b", [])


# marked


def test_marked_groups_lines_by_id():
    text = (
        BASE
        + mine("10.10.10.161", "forest.htb") + b"\n"
        + mine("10.10.10.175", "sauna.htb", box_id=OTHER) + b"\r\n"
        + mine("10.10.10.162", "web.htb") + b"\n"
    )
    assert hosts.marked(text) == {
        ME: [
            f"10.10.10.161 forest.htb  # pwn-broker {ME}",
            f"10.10.10.162 web.htb  # pwn-broker {ME}",
        ],
        OTHER: [f"10.10.10.175 sauna.htb  # pwn-broker {OTHER}"],
    }


@pytest.mark.parametrize(
    "text",
    [
        b"10.0.0.1 a.htb  # pwn-broker\n",
        b"10.0.0.1 a.htb  # pwn-broker \n",
        b"10.0.0.1 a.htb  # pwn-broker a b\n",
        b"10.0.0.1 a.htb  # pwn-broker a/b\n",
        b"10.0.0.1 a.htb  # pwn-brokers x\n",
        b"10.0.0.1 a.htb  #pwn-broker x\n",
        b"10.0.0.1 a.htb  # note # pwn-broker x\n",
        b"# pwn-broker x\n",
        b"10.0.0.1 a.htb  # pwn-broker x\rmore\n",
    ],
)
def test_marked_ignores_lookalikes(text):
    assert hosts.marked(text) == {}
    assert hosts.rewrite(text, "x", []).text == text
    assert hosts.strip(text, {"x"}) == text


def test_marked_allows_trailing_whitespace():
    text = b"10.0.0.1 a.htb  # pwn-broker x \t\n"
    assert hosts.marked(text) == {"x": ["10.0.0.1 a.htb  # pwn-broker x \t"]}


# rewrite: adding, replacing, removing


def test_rewrite_adds_line():
    outcome = hosts.rewrite(BASE, ME, [Wanted("dc01", "10.10.10.161", ["forest.htb", "dc01.htb"])])
    expected = mine("10.10.10.161", "forest.htb", "dc01.htb")
    assert outcome.text == BASE + expected + b"\n"
    assert outcome.written == [expected.decode()]
    assert outcome.taken_out == []
    assert outcome.already == []
    assert outcome.blocked == []


def test_rewrite_replaces_existing_line_in_place_of_old():
    text = b"127.0.0.1 localhost\n" + mine("10.10.10.161", "old.htb") + b"\n# end\n"
    outcome = hosts.rewrite(text, ME, [Wanted("dc01", "10.10.10.161", ["new.htb"])])
    assert outcome.text == b"127.0.0.1 localhost\n# end\n" + mine("10.10.10.161", "new.htb") + b"\n"
    assert outcome.written == [mine("10.10.10.161", "new.htb").decode()]


def test_rewrite_with_nothing_wanted_removes_lines():
    text = BASE + mine("10.10.10.161", "forest.htb") + b"\n" + mine("10.10.10.162", "web.htb") + b"\n"
    outcome = hosts.rewrite(text, ME, [])
    assert outcome.text == BASE
    assert outcome.written == []


def test_rewrite_is_idempotent():
    wanted = [Wanted("dc01", "10.10.10.161", ["forest.htb"])]
    first = hosts.rewrite(BASE, ME, wanted).text
    assert hosts.rewrite(first, ME, wanted).text == first


def test_rewrite_writes_one_line_per_entry():
    wanted = [
        Wanted("dc01", "10.10.10.161", ["forest.htb"]),
        Wanted("web01", "10.10.10.162", ["web.htb"]),
    ]
    outcome = hosts.rewrite(BASE, ME, wanted)
    lines = [mine("10.10.10.161", "forest.htb"), mine("10.10.10.162", "web.htb")]
    assert outcome.text == BASE + b"\n".join(lines) + b"\n"
    assert outcome.written == [value.decode() for value in lines]


# rewrite: the four file shapes come back byte for byte


ODD = (
    b"127.0.0.1\tlocalhost  \n"
    b"\t\n"
    b"  # indented comment\n"
    b"not an address here\n"
    b"\xff\xfe odd bytes\n"
    b"10.0.0.9 a.htb  # pwn-broker\n"
    b"fe80::1%eth0 link.local\n"
)


@pytest.mark.parametrize(
    "original",
    [
        pytest.param(b"127.0.0.1 localhost\n127.0.1.1 kali", id="no-final-break"),
        pytest.param(b"127.0.0.1 localhost\r\n127.0.1.1 kali\r\n\r\n", id="crlf"),
        pytest.param(b"127.0.0.1\t\tlocalhost\t\n\t127.0.1.1 \t kali\t# x\t\n", id="tabs"),
        pytest.param(
            b"127.0.0.1 localhost\n"
            + mine("10.10.10.200", "unknown.htb", box_id="never-seen-1.2_x")
            + b"\n127.0.1.1 kali\n",
            id="unknown-id",
        ),
        pytest.param(ODD, id="odd-lines"),
        pytest.param(b"", id="empty"),
    ],
)
def test_file_shapes_preserved_around_app_lines(original):
    wanted = [Wanted("dc01", "10.10.10.161", ["forest.htb", "dc01.htb"])]
    added = hosts.rewrite(original, ME, wanted)
    assert added.text.startswith(original)
    tail = added.text[len(original):]
    ending = b"\r\n" if original.endswith(b"\r\n") else b"\n"
    lead = ending if original and not original.endswith(b"\n") else b""
    assert tail == lead + mine("10.10.10.161", "forest.htb", "dc01.htb") + ending
    removed = hosts.rewrite(added.text, ME, [])
    assert removed.text == original + lead
    assert hosts.strip(added.text, {ME}) == original + lead


def test_own_line_in_middle_of_odd_file_replaced_and_rest_untouched():
    head = b"127.0.0.1\tlocalhost  \r\n\xff odd\n"
    tail = b"\t# trailing comment\n10.0.0.1 x.htb"
    text = head + mine("10.10.10.161", "old.htb") + b"\n" + tail
    outcome = hosts.rewrite(text, ME, [Wanted("dc01", "10.10.10.161", ["new.htb"])])
    assert outcome.text == head + tail + b"\n" + mine("10.10.10.161", "new.htb") + b"\n"


def test_own_last_line_without_break_removed_cleanly():
    text = b"127.0.0.1 localhost\n" + mine("10.10.10.161", "forest.htb")
    assert hosts.rewrite(text, ME, []).text == b"127.0.0.1 localhost\n"


def test_crlf_used_only_when_every_line_has_it():
    text = b"127.0.0.1 localhost\r\n127.0.1.1 kali\n"
    outcome = hosts.rewrite(text, ME, [Wanted("dc01", "10.10.10.161", ["forest.htb"])])
    assert outcome.text == text + mine("10.10.10.161", "forest.htb") + b"\n"


# rewrite: clashes


def test_other_box_line_taken_out_whole_and_reported():
    theirs = mine("10.10.10.175", "shared.htb", "sauna.htb", box_id=OTHER)
    keep = mine("10.10.10.176", "else.htb", box_id=OTHER)
    text = BASE + theirs + b"\n" + keep + b"\n"
    outcome = hosts.rewrite(text, ME, [Wanted("dc01", "10.10.10.161", ["SHARED.htb"])])
    assert outcome.text == BASE + keep + b"\n" + mine("10.10.10.161", "SHARED.htb") + b"\n"
    assert outcome.taken_out == [(OTHER, theirs.decode())]
    assert outcome.already == []
    assert outcome.blocked == []


def test_other_box_line_before_same_ip_unmarked_line_taken_out():
    theirs = mine("10.0.0.9", "foo.htb", box_id=OTHER)
    text = theirs + b"\n10.0.0.5 foo.htb\n"
    outcome = hosts.rewrite(text, ME, [Wanted("t", "10.0.0.5", ["foo.htb"])])
    assert outcome.text == b"10.0.0.5 foo.htb\n"
    assert outcome.taken_out == [(OTHER, theirs.decode())]
    assert outcome.already == [("t", "foo.htb")]
    assert outcome.blocked == []
    assert outcome.written == []


def test_other_box_line_before_different_ip_unmarked_line_taken_out():
    theirs = mine("10.0.0.9", "foo.htb", box_id=OTHER)
    text = theirs + b"\n10.0.0.7 foo.htb\n"
    outcome = hosts.rewrite(text, ME, [Wanted("t", "10.0.0.5", ["foo.htb"])])
    assert outcome.text == b"10.0.0.7 foo.htb\n"
    assert outcome.taken_out == [(OTHER, theirs.decode())]
    assert outcome.already == []
    assert outcome.blocked == [("t", "foo.htb", 2, "10.0.0.7 foo.htb")]
    assert outcome.written == []


def test_other_box_line_after_unmarked_line_taken_out():
    theirs = mine("10.0.0.9", "foo.htb", box_id=OTHER)
    text = b"10.0.0.5 foo.htb\n" + theirs + b"\n"
    outcome = hosts.rewrite(text, ME, [Wanted("t", "10.0.0.5", ["foo.htb"])])
    assert outcome.text == b"10.0.0.5 foo.htb\n"
    assert outcome.taken_out == [(OTHER, theirs.decode())]
    assert outcome.already == [("t", "foo.htb")]


def test_non_ascii_name_never_equals_ascii_name():
    # U+212A KELVIN SIGN lowers to "k" under Unicode rules
    text = "10.0.0.1 K.htb\n".encode()
    outcome = hosts.rewrite(text, ME, [Wanted("t", "10.0.0.5", ["k.htb"])])
    assert outcome.blocked == []
    assert outcome.already == []
    assert outcome.text == text + mine("10.0.0.5", "k.htb") + b"\n"


def test_non_ascii_name_on_other_box_line_never_takes_it_out():
    theirs = "10.0.0.9 K.htb  # pwn-broker other".encode()
    outcome = hosts.rewrite(theirs + b"\n", ME, [Wanted("t", "10.0.0.5", ["k.htb"])])
    assert outcome.taken_out == []


@pytest.mark.parametrize(
    "text",
    [
        b"10.0.0.7\x0bk.htb\n",
        b"10.0.0.7 a.htb\x0bk.htb\n",
        b"10.0.0.7 a.htb\x0ck.htb\n",
        b"10.0.0.7 a.htb\rk.htb\n",
        b"10.0.0.7 k.htb\r",
    ],
)
def test_fields_split_on_space_and_tab_only(text):
    outcome = hosts.rewrite(text, ME, [Wanted("t", "10.0.0.5", ["k.htb"])])
    assert outcome.blocked == []
    assert outcome.already == []


def test_fields_split_on_tab():
    outcome = hosts.rewrite(b"10.0.0.7\tx.htb\t\tk.htb\n", ME, [Wanted("t", "10.0.0.5", ["k.htb"])])
    assert outcome.blocked == [("t", "k.htb", 1, "10.0.0.7\tx.htb\t\tk.htb")]


def test_same_ip_on_unmarked_line_reported_already_and_left_off():
    text = b"127.0.0.1 localhost\n10.10.10.161\tforest.htb  # added by hand\n"
    outcome = hosts.rewrite(text, ME, [Wanted("dc01", "10.10.10.161", ["Forest.HTB", "dc01.htb"])])
    assert outcome.text == text + mine("10.10.10.161", "dc01.htb") + b"\n"
    assert outcome.already == [("dc01", "Forest.HTB")]
    assert outcome.blocked == []
    assert outcome.written == [mine("10.10.10.161", "dc01.htb").decode()]


def test_different_ip_on_unmarked_line_blocked_with_line_number():
    text = b"127.0.0.1 localhost\n\n10.10.10.99 other.htb FOREST.htb\n10.10.10.98 forest.htb\n"
    outcome = hosts.rewrite(text, ME, [Wanted("dc01", "10.10.10.161", ["forest.htb", "dc01.htb"])])
    assert outcome.text == text + mine("10.10.10.161", "dc01.htb") + b"\n"
    assert outcome.blocked == [("dc01", "forest.htb", 3, "10.10.10.99 other.htb FOREST.htb")]
    assert outcome.already == []


def test_line_with_only_blocked_or_known_names_not_written():
    text = b"10.10.10.99 forest.htb\n10.10.10.161 dc01.htb\n"
    outcome = hosts.rewrite(text, ME, [Wanted("dc01", "10.10.10.161", ["forest.htb", "dc01.htb"])])
    assert outcome.text == text
    assert outcome.written == []
    assert outcome.blocked == [("dc01", "forest.htb", 1, "10.10.10.99 forest.htb")]
    assert outcome.already == [("dc01", "dc01.htb")]


def test_same_ip_compares_parsed_addresses():
    text = b"::ffff:10.10.10.161 forest.htb\n"
    outcome = hosts.rewrite(text, ME, [Wanted("dc01", "::ffff:10.10.10.161", ["forest.htb"])])
    assert outcome.already == [("dc01", "forest.htb")]


def test_unparseable_first_field_never_clashes():
    text = b"not-an-ip forest.htb\n# 10.0.0.1 forest.htb\n"
    outcome = hosts.rewrite(text, ME, [Wanted("dc01", "10.10.10.161", ["forest.htb"])])
    assert outcome.text == text + mine("10.10.10.161", "forest.htb") + b"\n"
    assert outcome.blocked == []
    assert outcome.already == []


def test_names_in_comment_of_unmarked_line_never_clash():
    text = b"10.0.0.1 a.htb # forest.htb\n"
    outcome = hosts.rewrite(text, ME, [Wanted("dc01", "10.10.10.161", ["forest.htb"])])
    assert outcome.blocked == []


def test_own_old_line_never_clashes_with_new():
    text = mine("10.10.10.150", "forest.htb") + b"\n"
    outcome = hosts.rewrite(text, ME, [Wanted("dc01", "10.10.10.161", ["forest.htb"])])
    assert outcome.text == mine("10.10.10.161", "forest.htb") + b"\n"
    assert outcome.blocked == []
    assert outcome.taken_out == []


def test_duplicate_name_within_box():
    wanted = [
        Wanted("dc01", "10.10.10.161", ["forest.htb"]),
        Wanted("dc02", "10.10.10.161", ["FOREST.htb", "dc02.htb"]),
        Wanted("web01", "10.10.10.162", ["forest.htb"]),
    ]
    outcome = hosts.rewrite(b"", ME, wanted)
    first = mine("10.10.10.161", "forest.htb").decode()
    assert outcome.written == [first, mine("10.10.10.161", "dc02.htb").decode()]
    assert outcome.already == [("dc02", "FOREST.htb")]
    assert outcome.blocked == [("web01", "forest.htb", 0, first)]


# strip


def test_strip_removes_only_given_ids():
    a = mine("10.0.0.1", "a.htb", box_id="a")
    b = mine("10.0.0.2", "b.htb", box_id="b")
    c = mine("10.0.0.3", "c.htb", box_id="c")
    text = BASE + a + b"\n" + b + b"\r\n" + c
    assert hosts.strip(text, {"a", "c"}) == BASE + b + b"\r\n"
    assert hosts.strip(text, set()) == text
    assert hosts.strip(text, {"zzz"}) == text


# read


def test_read_returns_bytes(tmp_path):
    path = tmp_path / "hosts"
    path.write_bytes(b"127.0.0.1 localhost\r\n")
    assert hosts.read(path) == b"127.0.0.1 localhost\r\n"


def test_read_refuses_missing_file(tmp_path):
    with pytest.raises(HostsError, match="missing"):
        hosts.read(tmp_path / "hosts")


def test_read_refuses_folder(tmp_path):
    path = tmp_path / "hosts"
    path.mkdir()
    with pytest.raises(HostsError, match="not a regular file"):
        hosts.read(path)


@posix_only
def test_read_refuses_symlink(tmp_path):
    real = tmp_path / "real"
    real.write_bytes(b"127.0.0.1 localhost\n")
    path = tmp_path / "hosts"
    path.symlink_to(real)
    with pytest.raises(HostsError, match="link"):
        hosts.read(path)


# write


class FakeRun:
    def __init__(self, status=0, copy=True):
        self.status = status
        self.copy = copy
        self.calls = []
        self.scratch_seen = []

    def __call__(self, argv):
        self.calls.append(argv)
        source = Path(argv[1])
        self.scratch_seen.append(source.read_bytes())
        if sys.platform != "win32":
            self.scratch_seen.append(oct(os.stat(source).st_mode & 0o777))
        if self.copy and self.status == 0:
            Path(argv[2]).write_bytes(source.read_bytes())
        return subprocess.CompletedProcess(argv, self.status)


def never_run(argv):
    raise AssertionError(f"unexpected command {argv}")


@pytest.fixture
def file(tmp_path):
    path = tmp_path / "hosts"
    path.write_bytes(b"127.0.0.1 localhost\n")
    return path


@pytest.fixture
def scratch(tmp_path):
    folder = tmp_path / "run"
    folder.mkdir()
    return folder


def test_write_noop_when_equal(file, scratch):
    before = file.read_bytes()
    hosts.write(file, before, before, root=False, scratch=scratch, run=never_run)
    hosts.write(file, before, before, root=True, scratch=scratch, run=never_run)
    assert file.read_bytes() == before


def test_write_as_root_writes_in_place_and_truncates(file, scratch):
    long = b"127.0.0.1 localhost\n" + mine("10.10.10.161", "forest.htb") + b"\n"
    hosts.write(file, file.read_bytes(), long, root=True, scratch=scratch, run=never_run)
    assert file.read_bytes() == long
    hosts.write(file, long, b"x\r\n", root=True, scratch=scratch, run=never_run)
    assert file.read_bytes() == b"x\r\n"
    assert list(scratch.iterdir()) == []


@posix_only
def test_write_as_root_keeps_inode_and_mode(file, scratch):
    os.chmod(file, 0o644)
    before = os.stat(file)
    after_text = b"127.0.0.1 localhost\n10.0.0.1 a.htb\n"
    hosts.write(file, file.read_bytes(), after_text, root=True, scratch=scratch, run=never_run)
    assert file.read_bytes() == after_text
    after = os.stat(file)
    assert after.st_ino == before.st_ino
    assert after.st_mode == before.st_mode


def test_write_as_user_copies_through_run_and_cleans_up(file, scratch):
    after = b"127.0.0.1 localhost\r\n10.0.0.1 a.htb\n"
    run = FakeRun()
    hosts.write(file, file.read_bytes(), after, root=False, scratch=scratch, run=run)
    assert len(run.calls) == 1
    argv = run.calls[0]
    assert argv[0] == "cp"
    assert argv[2] == str(file)
    assert Path(argv[1]).parent == scratch
    assert run.scratch_seen[0] == after
    if sys.platform != "win32":
        assert run.scratch_seen[1] == "0o600"
    assert file.read_bytes() == after
    assert list(scratch.iterdir()) == []


def test_write_as_user_survives_leftover_scratch_file(file, scratch):
    leftover = scratch / f"hosts-{os.getpid()}.new"
    leftover.write_bytes(b"left by a crashed run\n")
    run = FakeRun()
    after = b"127.0.0.1 localhost\n10.0.0.1 a.htb\n"
    hosts.write(file, file.read_bytes(), after, root=False, scratch=scratch, run=run)
    assert file.read_bytes() == after
    assert Path(run.calls[0][1]) != leftover
    assert list(scratch.iterdir()) == [leftover]
    assert leftover.read_bytes() == b"left by a crashed run\n"


def test_write_as_user_scratch_names_differ_between_writes(file, scratch):
    run = FakeRun()
    first = file.read_bytes()
    hosts.write(file, first, b"one\n", root=False, scratch=scratch, run=run)
    hosts.write(file, b"one\n", b"two\n", root=False, scratch=scratch, run=run)
    assert run.calls[0][1] != run.calls[1][1]
    assert Path(run.calls[0][1]).name.startswith(f"hosts-{os.getpid()}-")


def test_write_as_user_failure_raises_and_cleans_up(file, scratch):
    before = file.read_bytes()
    run = FakeRun(status=1)
    with pytest.raises(HostsError):
        hosts.write(file, before, b"new\n", root=False, scratch=scratch, run=run)
    assert file.read_bytes() == before
    assert list(scratch.iterdir()) == []


def test_write_as_user_run_raising_cleans_up(file, scratch):
    def broken(argv):
        raise FileNotFoundError("sudo")

    with pytest.raises(HostsError):
        hosts.write(file, file.read_bytes(), b"new\n", root=False, scratch=scratch, run=broken)
    assert list(scratch.iterdir()) == []


def test_write_as_user_ctrl_c_at_sudo_is_a_hosts_error_and_cleans_up(file, scratch):
    before = file.read_bytes()

    def interrupted(argv):
        raise KeyboardInterrupt

    with pytest.raises(HostsError, match="^sudo was cancelled$"):
        hosts.write(file, before, b"new\n", root=False, scratch=scratch, run=interrupted)
    assert file.read_bytes() == before
    assert list(scratch.iterdir()) == []


@pytest.mark.parametrize("root", [True, False])
def test_write_refuses_when_file_changed_since_read(file, scratch, root):
    before = file.read_bytes()
    file.write_bytes(b"127.0.0.1 localhost\n10.9.9.9 someone.else\n")
    with pytest.raises(HostsError, match="^changed$"):
        hosts.write(file, before, b"mine\n", root=root, scratch=scratch, run=never_run)
    assert file.read_bytes() == b"127.0.0.1 localhost\n10.9.9.9 someone.else\n"
    assert list(scratch.iterdir()) == []


def test_write_refuses_missing_file(tmp_path, scratch):
    with pytest.raises(HostsError, match="missing"):
        hosts.write(tmp_path / "hosts", b"a\n", b"b\n", root=True, scratch=scratch, run=never_run)
    assert not (tmp_path / "hosts").exists()


# update


def test_update_reads_changes_and_writes(file, scratch):
    def change(text):
        return hosts.rewrite(text, ME, [Wanted("dc01", "10.10.10.161", ["forest.htb"])]).text

    before, after = hosts.update(file, change, root=True, scratch=scratch, run=never_run)
    assert before == b"127.0.0.1 localhost\n"
    assert after == before + mine("10.10.10.161", "forest.htb") + b"\n"
    assert file.read_bytes() == after


def test_update_starts_over_once_when_file_changes(file, scratch):
    seen = []

    def change(text):
        seen.append(text)
        if len(seen) == 1:
            file.write_bytes(text + b"10.9.9.9 someone.else\n")
        return text + b"10.0.0.1 a.htb\n"

    before, after = hosts.update(file, change, root=True, scratch=scratch, run=never_run)
    assert seen == [b"127.0.0.1 localhost\n", b"127.0.0.1 localhost\n10.9.9.9 someone.else\n"]
    assert before == seen[1]
    assert after == seen[1] + b"10.0.0.1 a.htb\n"
    assert file.read_bytes() == after


def test_update_gives_up_after_second_change(file, scratch):
    calls = []

    def change(text):
        calls.append(text)
        file.write_bytes(text + b"# again\n")
        return text + b"10.0.0.1 a.htb\n"

    with pytest.raises(HostsError, match="^changed$"):
        hosts.update(file, change, root=False, scratch=scratch, run=never_run)
    assert len(calls) == 2
    assert file.read_bytes() == b"127.0.0.1 localhost\n# again\n# again\n"
    assert list(scratch.iterdir()) == []


def test_update_does_not_retry_other_failures(file, scratch):
    calls = []
    run = FakeRun(status=1)

    def change(text):
        calls.append(text)
        return text + b"10.0.0.1 a.htb\n"

    with pytest.raises(HostsError):
        hosts.update(file, change, root=False, scratch=scratch, run=run)
    assert len(calls) == 1
    assert len(run.calls) == 1
    assert file.read_bytes() == b"127.0.0.1 localhost\n"
