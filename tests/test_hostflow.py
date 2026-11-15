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


def test_file_off_that_cannot_write_says_which_line_to_remove(session):
    hostflow.file_on(session, session.targets[0])
    session.is_root = lambda: False
    session.console = FakeConsole()
    hostflow.file_off(session, session.targets[0])
    assert _recorded(session) == []
    assert session.console.lines == [
        ("warn", "/etc/hosts was not changed: cp exited 1"),
        ("info", "remove this line yourself:"),
        ("raw", _line(session, "10.10.10.161 forest.htb.local")),
    ]


def test_a_name_left_out_of_the_line_is_warned_about_once(session):
    session.targets[0].hostnames = ["forest.htb.local", "bad_name"]
    session.box.hosts = ["dc01"]
    assert hostflow.sync(session) is True
    warning = "bad_name is not a plain hostname, so it was left out of dc01's line in /etc/hosts"
    assert ("warn", warning) in session.console.lines
    session.console = FakeConsole()
    session.targets[0].hostnames.append("crm.forest.htb")
    assert hostflow.sync(session) is True
    assert not any(kind == "warn" for kind, _ in session.console.lines)


# ---- finish, opening a box and launch

OTHER_ID = "2026-11-10_htb_cascade"
LOCALHOST = "127.0.0.1 localhost\n"


def _lines(*pairs):
    return "".join(f"{rest}  # pwn-broker {box_id}\n" for box_id, rest in pairs)


def _put(session, text):
    session.hosts_path.write_text(text, encoding="utf-8", newline="")


def _unwritable(session):
    import subprocess

    session.is_root = lambda: False
    session.run_privileged = lambda argv: subprocess.CompletedProcess(argv, 1)


def test_undo_removes_only_this_boxes_lines(session):
    box_id = session.box.id
    session.box.hosts = ["dc01"]
    _put(
        session,
        LOCALHOST
        + _lines((box_id, "10.10.10.161 forest.htb"), (OTHER_ID, "10.10.10.5 cascade.htb"))
        + "10.0.0.9 plain.example\n",
    )
    hostflow.undo(session)
    assert _text(session) == (
        LOCALHOST + _lines((OTHER_ID, "10.10.10.5 cascade.htb")) + "10.0.0.9 plain.example\n"
    )
    assert session.console.lines == [("ok", "removed 1 line from /etc/hosts")]
    assert session.box.hosts == ["dc01"]


def test_undo_says_nothing_when_the_box_has_no_lines(session):
    hostflow.undo(session)
    assert session.console.lines == []
    assert _text(session) == LOCALHOST


def test_undo_survives_an_unwritable_file_and_prints_the_lines(session):
    box_id = session.box.id
    session.box.hosts = ["dc01"]
    text = LOCALHOST + _lines((box_id, "10.10.10.161 forest.htb"))
    _put(session, text)
    _unwritable(session)
    hostflow.undo(session)
    assert _text(session) == text
    assert session.console.lines == [
        ("warn", "/etc/hosts was not changed: cp exited 1"),
        ("info", "remove this line yourself:"),
        ("raw", f"10.10.10.161 forest.htb  # pwn-broker {box_id}"),
    ]


def test_undo_survives_a_missing_file(session):
    session.box.hosts = ["dc01"]
    session.hosts_path.unlink()
    hostflow.undo(session)
    assert session.console.lines == [
        ("warn", f"/etc/hosts was not changed: {session.hosts_path} is missing")
    ]


def test_on_open_does_nothing_for_a_box_without_lines(session):
    hostflow.on_open(session)
    assert session.console.lines == []
    assert _text(session) == LOCALHOST


def test_on_open_puts_a_missing_line_back(session):
    session.box.hosts = ["dc01"]
    hostflow.on_open(session)
    assert _text(session) == LOCALHOST + _lines((session.box.id, "10.10.10.161 forest.htb.local"))
    assert session.console.lines[0] == ("ok", "/etc/hosts updated")
    assert session.console.asked == []


def test_on_open_takes_out_another_boxes_clashing_line_with_a_warning(session):
    session.box.hosts = ["dc01"]
    _put(session, LOCALHOST + _lines((OTHER_ID, "10.10.10.99 forest.htb.local")))
    hostflow.on_open(session)
    assert OTHER_ID not in _text(session)
    assert _text(session).endswith(_lines((session.box.id, "10.10.10.161 forest.htb.local")))
    warns = [text for kind, text in session.console.lines if kind == "warn"]
    assert warns == [
        f"took out a line of box {OTHER_ID} that names the same host; "
        f"it returns when {OTHER_ID} is opened"
    ]


def test_summary_counts_the_lines_in_the_file(session):
    box_id = session.box.id
    assert hostflow.summary(session) == []
    _put(session, LOCALHOST + _lines((box_id, "10.10.10.161 a.htb")))
    assert hostflow.summary(session) == ["hosts     1 line to remove from /etc/hosts"]
    _put(
        session,
        LOCALHOST
        + _lines(
            (box_id, "10.10.10.161 a.htb"),
            (box_id, "10.10.10.6 b.htb"),
            (OTHER_ID, "10.0.0.1 c.htb"),
        ),
    )
    assert hostflow.summary(session) == ["hosts     2 lines to remove from /etc/hosts"]


def test_summary_shows_nothing_when_the_file_cannot_be_read(session):
    session.hosts_path.unlink()
    assert hostflow.summary(session) == []


class Launch:
    """What leftovers is given at launch: a hosts file, root and a privileged runner."""

    def __init__(self, paths, path):
        self.paths, self.path, self.root = paths, path, True

    def run(self, console):
        import subprocess

        hostflow.leftovers(
            self.paths,
            console,
            hosts_path=self.path,
            is_root=lambda: self.root,
            run=lambda argv: subprocess.CompletedProcess(argv, 1),
        )

    @property
    def text(self):
        return self.path.read_text(encoding="utf-8")


@pytest.fixture
def launch(paths, system):
    return Launch(paths, system.hosts_path)


def _finished(session):
    from pwn_broker.store import save_box

    session.box.status = "finished"
    save_box(session.box)


def test_leftovers_offers_the_lines_of_a_finished_box_by_name(session, launch):
    box_id = session.box.id
    _finished(session)
    _put(session, LOCALHOST + _lines((box_id, "10.10.10.161 a.htb"), (box_id, "10.10.10.6 b.htb")))
    console = FakeConsole([""])
    launch.run(console)
    assert console.asked == ["remove 2 /etc/hosts lines left by forest?"]
    assert launch.text == LOCALHOST
    assert console.lines == [("ok", "removed 2 lines from /etc/hosts")]


def test_leftovers_offers_the_lines_of_an_id_with_no_folder(session, launch):
    _put(session, LOCALHOST + _lines(("ghost-id", "10.10.10.7 g.htb")))
    console = FakeConsole(["y"])
    launch.run(console)
    assert console.asked == ["remove 1 /etc/hosts line left by ghost-id?"]
    assert launch.text == LOCALHOST


def test_leftovers_keeps_the_lines_on_no(session, launch):
    text = LOCALHOST + _lines(("ghost-id", "10.10.10.7 g.htb"))
    _put(session, text)
    launch.run(FakeConsole(["n"]))
    assert launch.text == text


def test_leftovers_leaves_an_unfinished_boxes_lines(session, launch):
    text = LOCALHOST + _lines((session.box.id, "10.10.10.161 a.htb"))
    _put(session, text)
    console = FakeConsole()
    launch.run(console)
    assert console.asked == [] and console.lines == []
    assert launch.text == text


def test_leftovers_asks_in_sorted_order_and_stops_when_cancelled(session, launch):
    _put(session, LOCALHOST + _lines(("b-id", "10.0.0.2 b.htb"), ("a-id", "10.0.0.1 a.htb")))
    console = FakeConsole(["y"])
    launch.run(console)
    assert console.asked == [
        "remove 1 /etc/hosts line left by a-id?",
        "remove 1 /etc/hosts line left by b-id?",
    ]
    assert launch.text == LOCALHOST + _lines(("b-id", "10.0.0.2 b.htb"))


def test_leftovers_is_silent_when_a_box_folder_cannot_be_read(session, launch):
    text = LOCALHOST + _lines(("ghost-id", "10.10.10.7 g.htb"))
    _put(session, text)
    (session.paths.active / "broken").mkdir()
    console = FakeConsole(["y"])
    launch.run(console)
    assert console.asked == [] and console.lines == []
    assert launch.text == text


def test_leftovers_is_silent_when_the_file_cannot_be_read(session, launch):
    launch.path.unlink()
    console = FakeConsole(["y"])
    launch.run(console)
    assert console.asked == [] and console.lines == []


def test_leftovers_prints_the_line_when_the_removal_fails(session, launch):
    text = LOCALHOST + _lines(("ghost-id", "10.10.10.7 g.htb"))
    _put(session, text)
    launch.root = False
    console = FakeConsole([""])
    launch.run(console)
    assert launch.text == text
    assert console.lines == [
        ("warn", "/etc/hosts was not changed: cp exited 1"),
        ("info", "remove this line yourself:"),
        ("raw", "10.10.10.7 g.htb  # pwn-broker ghost-id"),
    ]
