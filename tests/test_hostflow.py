import pytest

from helpers import NOW
from pwn_broker import hostflow
from pwn_broker.boxes import add_target
from pwn_broker.console import FakeConsole
from pwn_broker.hosts import Wanted
from pwn_broker.store import load_box

QUESTION = "add dc01's hostnames to /etc/hosts?"


def _line(session, rest):
    return f"{rest}  # pwn-broker {session.box.id}"


def _text(session):
    return session.hosts_path.read_text(encoding="utf-8")


def _recorded(session):
    return load_box(session.box.path).hosts


def _add(session, name, ips, hostnames):
    return add_target(
        session.box, session.targets, ips=ips, hostnames=hostnames,
        scope="external", name=name, now=NOW,
    )  # fmt: skip


def test_wanted_takes_the_first_ip_and_the_valid_hostnames(session):
    dc01 = session.targets[0]
    dc01.ips = ["10.10.10.161", "10.10.10.162"]
    dc01.hostnames = ["forest.htb.local", "bad_name", "dc01.htb.local"]
    _add(session, "web", ["10.10.10.5"], [])
    _add(session, "named", [], ["named.htb"])
    _add(session, "left", ["10.10.10.6"], ["left.htb"])
    session.box.hosts = ["dc01", "web", "named", "gone"]
    assert hostflow.wanted(session) == [
        Wanted("dc01", "10.10.10.161", ["forest.htb.local", "dc01.htb.local"])
    ]


def test_offer_asks_with_yes_as_the_default_and_records_the_target(session):
    session.console = FakeConsole([""])
    hostflow.offer(session, session.targets[0])
    assert session.console.asked == [QUESTION]
    assert _recorded(session) == ["dc01"]
    assert _text(session) == "127.0.0.1 localhost\n" + _line(session, "10.10.10.161 forest.htb.local") + "\n"
    assert session.console.lines == [
        ("ok", "/etc/hosts updated"),
        ("info", "    10.10.10.161 forest.htb.local"),
    ]


def test_offer_records_nothing_on_no(session):
    session.console = FakeConsole(["n"])
    hostflow.offer(session, session.targets[0])
    assert session.console.asked == [QUESTION]
    assert _recorded(session) == [] and session.box.hosts == []
    assert _text(session) == "127.0.0.1 localhost\n"
    assert session.console.lines == []


def test_offer_does_not_ask_for_a_target_that_has_a_line(session):
    session.box.hosts = ["dc01"]
    session.console = FakeConsole([])
    hostflow.offer(session, session.targets[0])
    assert session.console.asked == [] and session.console.lines == []


@pytest.mark.parametrize("ips, hostnames", [([], ["web.htb"]), (["10.10.10.5"], [])])
def test_offer_does_not_ask_without_an_ip_and_a_hostname(session, ips, hostnames):
    web = _add(session, "web", ips, hostnames)
    session.console = FakeConsole([])
    hostflow.offer(session, web)
    assert session.console.asked == [] and session.console.lines == []


def test_offer_warns_once_when_no_hostname_can_go_in_the_file(session):
    web = _add(session, "web", ["10.10.10.5"], ["bad_one", "bad two"])
    session.console = FakeConsole([])
    hostflow.offer(session, web)
    assert session.console.asked == []
    [(kind, text)] = session.console.lines
    assert kind == "warn" and "bad_one" in text and "bad two" not in text


def test_offer_takes_the_record_back_when_the_write_fails(session):
    session.hosts_path.unlink()
    session.console = FakeConsole(["y"])
    hostflow.offer(session, session.targets[0])
    assert session.box.hosts == [] and _recorded(session) == []
    assert session.console.lines[0] == ("warn", f"/etc/hosts was not changed: {session.hosts_path} is missing")
    assert session.console.lines[1:] == [
        ("info", "add this line yourself:"),
        ("raw", _line(session, "10.10.10.161 forest.htb.local")),
    ]


def test_a_normal_user_writes_through_sudo(session, system):
    session.is_root = lambda: False
    system.privileged_status = 0
    session.console = FakeConsole(["y"])
    hostflow.offer(session, session.targets[0])
    [argv] = system.privileged
    assert argv[0] == "cp" and argv[2] == str(session.hosts_path)
    # the stand-in copies nothing, so the file is as it was; the record stays
    assert _recorded(session) == ["dc01"]


def test_a_declined_sudo_changes_nothing_and_prints_the_line(session, system):
    session.is_root = lambda: False
    session.console = FakeConsole(["y"])
    hostflow.offer(session, session.targets[0])
    assert _recorded(session) == []
    assert session.console.lines == [
        ("warn", "/etc/hosts was not changed: cp exited 1"),
        ("info", "add this line yourself:"),
        ("raw", _line(session, "10.10.10.161 forest.htb.local")),
    ]
    assert _text(session) == "127.0.0.1 localhost\n"


def test_a_failed_sync_only_prints_lines_the_file_lacks(session):
    web = _add(session, "web", ["10.10.10.5"], ["web.htb"])
    present = _line(session, "10.10.10.161 forest.htb.local")
    session.hosts_path.write_text(f"127.0.0.1 localhost\n{present}\n", encoding="utf-8")
    session.box.hosts = ["dc01"]
    session.is_root = lambda: False
    session.console = FakeConsole(["y"])
    hostflow.offer(session, web)
    assert session.box.hosts == ["dc01"]
    assert session.console.lines[1:] == [
        ("info", "add this line yourself:"),
        ("raw", _line(session, "10.10.10.5 web.htb")),
    ]


def test_sync_prints_nothing_when_the_file_needs_no_change(session):
    session.box.hosts = ["dc01"]
    assert hostflow.sync(session) is True
    session.console = FakeConsole()
    before = session.hosts_path.read_bytes()
    assert hostflow.sync(session) is True
    assert session.console.lines == []
    assert session.hosts_path.read_bytes() == before


def test_sync_names_the_box_whose_line_it_took_out(session, other):
    theirs = "10.10.10.99 forest.htb.local  # pwn-broker id-other"
    gone = "10.10.10.98 forest.htb.local  # pwn-broker id-gone"
    session.hosts_path.write_text(f"{theirs}\n{gone}\n", encoding="utf-8")
    session.box.hosts = ["dc01"]
    assert hostflow.sync(session) is True
    assert session.console.lines == [
        ("ok", "/etc/hosts updated"),
        ("info", "    10.10.10.161 forest.htb.local"),
        ("warn", "took out a line of box Cascade that names the same host; it returns when Cascade is opened"),
        ("info", f"    {theirs}"),
        ("warn", "took out a line of box id-gone that names the same host; it returns when id-gone is opened"),
        ("info", f"    {gone}"),
    ]
    assert _text(session) == _line(session, "10.10.10.161 forest.htb.local") + "\n"


def test_sync_says_a_name_already_resolves(session):
    session.hosts_path.write_text("10.10.10.161 FOREST.htb.local\n", encoding="utf-8")
    session.box.hosts = ["dc01"]
    assert hostflow.sync(session) is True
    assert session.console.lines == [("ok", "forest.htb.local already resolves to 10.10.10.161")]
    assert _text(session) == "10.10.10.161 FOREST.htb.local\n"


def test_sync_shows_a_line_that_blocks_a_name(session):
    session.targets[0].hostnames = ["forest.htb.local", "dc01.htb.local"]
    session.hosts_path.write_text("127.0.0.1 localhost\n10.10.10.9 forest.htb.local\n", encoding="utf-8")
    session.box.hosts = ["dc01"]
    assert hostflow.sync(session) is True
    assert session.console.lines == [
        ("ok", "/etc/hosts updated"),
        ("info", "    10.10.10.161 dc01.htb.local"),
        ("warn", "forest.htb.local is on line 2 of /etc/hosts with another address. "
                 "remove it there, then: host file on dc01"),
        ("info", "    10.10.10.9 forest.htb.local"),
    ]  # fmt: skip


def test_sync_gives_up_when_the_file_keeps_changing(session, monkeypatch):
    from pwn_broker import hosts

    def busy(path, before, after, **kwargs):
        raise hosts.HostsError(hosts.CHANGED)

    monkeypatch.setattr(hosts, "write", busy)
    session.box.hosts = ["dc01"]
    assert hostflow.sync(session) is False
    assert session.console.lines[0] == (
        "warn", "/etc/hosts was not changed: another program changed it while it was being written"
    )


def test_file_on_writes_without_asking(session):
    session.console = FakeConsole([])
    hostflow.file_on(session, session.targets[0])
    assert _recorded(session) == ["dc01"]
    assert _line(session, "10.10.10.161 forest.htb.local") in _text(session)


def test_file_on_puts_back_a_missing_line_of_a_recorded_target(session):
    session.box.hosts = ["dc01"]
    hostflow.file_on(session, session.targets[0])
    assert _line(session, "10.10.10.161 forest.htb.local") in _text(session)


@pytest.mark.parametrize(
    "ips, hostnames, missing",
    [([], ["web.htb"], "no IP address"), (["10.10.10.5"], [], "no hostname")],
)
def test_file_on_says_what_is_missing(session, ips, hostnames, missing):
    web = _add(session, "web", ips, hostnames)
    with pytest.raises(ValueError, match=f"web has {missing}"):
        hostflow.file_on(session, web)
    assert session.box.hosts == []


def test_file_on_refuses_names_that_cannot_go_in_the_file(session):
    web = _add(session, "web", ["10.10.10.5"], ["bad_one"])
    with pytest.raises(ValueError, match="bad_one"):
        hostflow.file_on(session, web)
    assert session.box.hosts == []


def test_file_off_takes_the_line_out_and_forgets_it(session):
    hostflow.file_on(session, session.targets[0])
    session.console = FakeConsole()
    hostflow.file_off(session, session.targets[0])
    assert _recorded(session) == [] and session.targets[0].hostnames == ["forest.htb.local"]
    assert _text(session) == "127.0.0.1 localhost\n"
    assert session.console.lines == [("ok", "/etc/hosts updated")]


def test_file_off_for_a_target_with_no_line_changes_nothing(session):
    before = session.hosts_path.read_bytes()
    hostflow.file_off(session, session.targets[0])
    assert session.console.lines == [("ok", "dc01 has no line in /etc/hosts")]
    assert session.hosts_path.read_bytes() == before


def test_file_off_keeps_the_record_when_the_write_fails(session):
    hostflow.file_on(session, session.targets[0])
    session.is_root = lambda: False
    session.console = FakeConsole()
    hostflow.file_off(session, session.targets[0])
    assert _recorded(session) == ["dc01"]
    assert session.console.lines == [("warn", "/etc/hosts was not changed: cp exited 1")]
