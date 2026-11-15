import pytest

from helpers import NOW
from pwn_broker import shell  # noqa: F401  (fills the command registry)
from pwn_broker.boxes import add_target
from pwn_broker.console import FakeConsole
from pwn_broker.note import FOLD_START
from pwn_broker.shell.commands import dispatch
from pwn_broker.store import load_box, load_targets

NO_CURRENT = "no current target; pick one with: target use <name>"


def _fails(session):
    return [text for kind, text in session.console.lines if kind == "fail"]


def _add(session, name, ips, hostnames):
    return add_target(
        session.box, session.targets, ips=ips, hostnames=hostnames,
        scope="external", name=name, now=NOW,
    )  # fmt: skip


def _line(session, rest):
    return f"{rest}  # pwn-broker {session.box.id}"


def _text(session):
    return session.hosts_path.read_text(encoding="utf-8")


def _saved(session, name="dc01"):
    return next(t for t in load_targets(session.box) if t.name == name)


def _file_on(session):
    dispatch(session, "host file on")
    session.console = FakeConsole()


def test_host_add_updates_the_target_note_and_lists_then_offers(session):
    session.console = FakeConsole(["n"])
    dispatch(session, "host add crm.forest.htb dev.forest.htb")
    names = ["forest.htb.local", "crm.forest.htb", "dev.forest.htb"]
    assert session.targets[0].hostnames == names and _saved(session).hostnames == names
    note = (session.box.path / "notes.md").read_text(encoding="utf-8")
    assert f"{FOLD_START}\nTarget: dc01   10.10.10.161   {', '.join(names)}   external\n" in note
    hosts_txt = (session.box.path / "lists" / "hosts.txt").read_text(encoding="utf-8")
    assert hosts_txt == f"10.10.10.161 {' '.join(names)}\n"
    assert session.console.lines == [("ok", "dc01 now answers to 3 names")]
    assert session.console.asked == ["add dc01's hostnames to /etc/hosts?"]
    assert _text(session) == "127.0.0.1 localhost\n"


def test_host_add_rewrites_the_line_without_asking(session):
    _file_on(session)
    dispatch(session, "host add crm.forest.htb")
    assert session.console.asked == []
    assert session.console.lines == [
        ("ok", "dc01 now answers to 2 names"),
        ("ok", "/etc/hosts updated"),
        ("info", "    10.10.10.161 forest.htb.local crm.forest.htb"),
    ]
    assert _text(session) == "127.0.0.1 localhost\n" + _line(
        session, "10.10.10.161 forest.htb.local crm.forest.htb"
    ) + "\n"


def test_host_add_skips_a_name_the_target_has(session):
    session.console = FakeConsole(["n"])
    dispatch(session, "host add FOREST.htb.local crm.forest.htb crm.forest.htb")
    assert session.targets[0].hostnames == ["forest.htb.local", "crm.forest.htb"]
    assert session.console.lines == [
        ("ok", "FOREST.htb.local is already a hostname of dc01"),
        ("ok", "crm.forest.htb is already a hostname of dc01"),
        ("ok", "dc01 now answers to 2 names"),
    ]


def test_host_add_with_nothing_new_changes_nothing(session):
    dispatch(session, "host add forest.htb.local")
    assert session.console.lines == [("ok", "forest.htb.local is already a hostname of dc01")]
    assert session.console.asked == []


def test_host_add_refuses_a_name_another_target_has(session):
    _add(session, "web", ["10.10.10.5"], ["web.htb"])
    dispatch(session, "host add crm.forest.htb WEB.htb")
    assert _fails(session) == ["WEB.htb is already a hostname of web"]
    assert session.targets[0].hostnames == ["forest.htb.local"]
    assert _saved(session).hostnames == ["forest.htb.local"]


def test_host_add_refuses_a_name_that_is_not_plain(session):
    dispatch(session, "host add crm.forest.htb bad_name")
    assert _fails(session) == ["not a plain hostname: bad_name"]
    assert session.targets[0].hostnames == ["forest.htb.local"]


def test_host_add_needs_a_name(session):
    dispatch(session, "host add")
    assert _fails(session) == ["missing argument: hostname"]


def test_host_add_says_one_name(session):
    web = _add(session, "web", ["10.10.10.5"], [])
    session.current = web
    session.console = FakeConsole(["y"])
    dispatch(session, "host add web.htb")
    assert session.console.lines[0] == ("ok", "web now answers to 1 name")
    assert _line(session, "10.10.10.5 web.htb") in _text(session)
    assert load_box(session.box.path).hosts == ["web"]


@pytest.mark.parametrize(
    "line", ["host add x.htb", "host remove x.htb", "host file on", "host file off"]
)
def test_host_commands_need_a_current_target(session, line):
    session.current = None
    dispatch(session, line)
    assert _fails(session) == [NO_CURRENT]


def test_host_remove_takes_names_off_and_rewrites_the_line(session):
    session.targets[0].hostnames = ["forest.htb.local", "crm.forest.htb"]
    _file_on(session)
    dispatch(session, "host remove CRM.forest.htb")
    assert session.targets[0].hostnames == ["forest.htb.local"]
    assert _saved(session).hostnames == ["forest.htb.local"]
    assert (session.box.path / "lists" / "hosts.txt").read_text(encoding="utf-8") == (
        "10.10.10.161 forest.htb.local\n"
    )
    assert session.console.lines == [
        ("ok", "dc01 now answers to 1 name"),
        ("ok", "/etc/hosts updated"),
        ("info", "    10.10.10.161 forest.htb.local"),
    ]


def test_host_remove_of_the_last_name_takes_the_line_out(session):
    _file_on(session)
    dispatch(session, "host remove forest.htb.local")
    assert session.targets[0].hostnames == []
    assert load_box(session.box.path).hosts == []
    assert _text(session) == "127.0.0.1 localhost\n"
    assert session.console.lines == [
        ("ok", "dc01 now answers to 0 names"),
        ("ok", "/etc/hosts updated"),
    ]


def test_host_remove_keeps_one_name_on_a_target_without_an_ip(session):
    named = _add(session, "named", [], ["named.htb"])
    session.current = named
    dispatch(session, "host remove named.htb")
    assert _fails(session) == ["named has no IP address, so it keeps at least one hostname"]
    assert named.hostnames == ["named.htb"]


def test_host_remove_refuses_a_name_the_target_does_not_have(session):
    dispatch(session, "host remove forest.htb.local other.htb")
    assert _fails(session) == ["dc01 has no hostname other.htb"]
    assert session.targets[0].hostnames == ["forest.htb.local"]


def test_host_remove_needs_a_name(session):
    dispatch(session, "host remove")
    assert _fails(session) == ["missing argument: hostname"]


def test_host_lists_every_hostname_and_whether_it_is_in_the_file(session):
    session.targets[0].hostnames = ["forest.htb.local", "crm.forest.htb"]
    _add(session, "web", ["10.10.10.5"], ["web.htb"])
    _add(session, "bare", ["10.10.10.6"], [])
    session.hosts_path.write_text(
        "127.0.0.1 localhost\n10.10.10.5 WEB.htb\n# 10.10.10.161 crm.forest.htb\n", encoding="utf-8"
    )
    _file_on(session)
    dispatch(session, "host")
    assert session.console.tables == [
        (
            ["target", "name", "in /etc/hosts"],
            [
                ["dc01", "forest.htb.local", "yes"],
                ["dc01", "crm.forest.htb", "yes"],
                ["web", "web.htb", "yes"],
            ],
        )
    ]
    session.hosts_path.write_text("127.0.0.1 localhost\n", encoding="utf-8")
    session.console = FakeConsole()
    dispatch(session, "host")
    assert [row[2] for row in session.console.tables[0][1]] == ["no", "no", "no"]


def test_host_says_unknown_when_the_file_cannot_be_read(session):
    session.hosts_path.unlink()
    dispatch(session, "host")
    assert [row[2] for row in session.console.tables[0][1]] == ["unknown"]


def test_host_with_no_hostnames(session):
    session.targets[0].hostnames = []
    dispatch(session, "host")
    assert session.console.lines == [("info", "no hostnames yet")]
    assert session.console.tables == []


def test_host_file_on_and_off(session):
    dispatch(session, "host file on")
    assert session.console.asked == []
    assert load_box(session.box.path).hosts == ["dc01"]
    assert _line(session, "10.10.10.161 forest.htb.local") in _text(session)
    session.console = FakeConsole()
    dispatch(session, "host file off")
    assert load_box(session.box.path).hosts == []
    assert _text(session) == "127.0.0.1 localhost\n"
    assert session.targets[0].hostnames == ["forest.htb.local"]


def test_host_file_on_a_named_target(session):
    _add(session, "web", ["10.10.10.5"], ["web.htb"])
    dispatch(session, "host file on we")
    assert load_box(session.box.path).hosts == ["web"]
    assert _line(session, "10.10.10.5 web.htb") in _text(session)
    session.console = FakeConsole()
    dispatch(session, "host file off web")
    assert load_box(session.box.path).hosts == []


def test_host_file_on_says_what_is_missing(session):
    _add(session, "web", ["10.10.10.5"], [])
    dispatch(session, "host file on web")
    assert _fails(session) == ["web has no hostname"]


def test_host_file_off_without_a_line(session):
    dispatch(session, "host file off")
    assert session.console.lines == [("ok", "dc01 has no line in /etc/hosts")]


def test_host_remove_leaving_only_an_invalid_name_forgets_the_line(session):
    session.targets[0].hostnames = ["forest.htb.local", "bad_name"]
    _file_on(session)
    dispatch(session, "host remove forest.htb.local")
    assert session.targets[0].hostnames == ["bad_name"]
    assert load_box(session.box.path).hosts == []
    assert _text(session) == "127.0.0.1 localhost\n"


def test_host_file_alone_lists_on_and_off(session):
    dispatch(session, "host file")
    assert session.console.lines == [
        ("info", "host file off   take the target's line out of /etc/hosts and forget it"),
        ("info", "host file on   put the target's line into /etc/hosts"),
    ]
