import os

import pytest

from helpers import NOW, make_cred
from pwn_broker import note
from pwn_broker.note import FOLD_END, FOLD_START
from pwn_broker import shell  # noqa: F401  (fills the command registry)
from pwn_broker.boxes import add_target
from pwn_broker.console import FakeConsole
from pwn_broker.questions import TargetAnswers, ask_target
from pwn_broker.session import refresh
from pwn_broker.shell.commands import dispatch
from pwn_broker.store import load_box, load_creds, load_targets


def _fails(console):
    return [text for kind, text in console.lines if kind == "fail"]


def _add(session, name, ip, **extra):
    return add_target(
        session.box, session.targets, ips=[ip], hostnames=[], scope="external",
        name=name, now=NOW, **extra,
    )  # fmt: skip


def test_ask_target_defaults():
    a = ask_target(FakeConsole(["10.10.10.161", "forest.htb.local", "", ""]), taken=set())
    assert a == TargetAnswers(["10.10.10.161"], ["forest.htb.local"], "external", "forest.htb.local")


def test_ask_target_prefills_an_address_for_a_new_target():
    a = ask_target(FakeConsole(["", "", "", ""]), taken=set(), ips=["10.10.10.200"])
    assert a == TargetAnswers(["10.10.10.200"], [], "external", "10.10.10.200")
    a = ask_target(FakeConsole(["", "", "", ""]), taken=set(), hostnames=["crm.board.htb"])
    assert a == TargetAnswers([], ["crm.board.htb"], "external", "crm.board.htb")
    # a prefilled address can be replaced
    a = ask_target(FakeConsole(["10.10.10.9", "", "", ""]), taken=set(), ips=["10.10.10.200"])
    assert a.ips == ["10.10.10.9"]


def test_ask_target_reasks_until_ip_or_hostname():
    console = FakeConsole(["", "", "10.10.10.5", "", "", ""])
    a = ask_target(console, taken=set())
    assert a == TargetAnswers(["10.10.10.5"], [], "external", "10.10.10.5")
    assert len(_fails(console)) == 1
    assert console.asked[:5] == ["ip", "hostname", "ip", "hostname", "scope"]


def test_ask_target_reasks_bad_ip():
    console = FakeConsole(["10.10.10", "10.10.10.9", "", "", ""])
    a = ask_target(console, taken=set())
    assert a.ips == ["10.10.10.9"]
    assert len(_fails(console)) == 1


def test_ask_target_reasks_bad_scope_and_taken_name():
    console = FakeConsole(["10.10.10.5", "", "dmz", "internal", "dc01", "!!!", "web"])
    a = ask_target(console, taken={"dc01"})
    assert a == TargetAnswers(["10.10.10.5"], [], "internal", "web")
    assert len(_fails(console)) == 3


def test_ask_target_takes_several_values():
    a = ask_target(FakeConsole(["10.10.10.1 10.10.10.2", "a.htb b.htb", "", ""]), taken=set())
    assert a.ips == ["10.10.10.1", "10.10.10.2"]
    assert a.hostnames == ["a.htb", "b.htb"]
    assert a.name == "a.htb"


def test_ask_target_with_defaults_and_no_name(dc01):
    console = FakeConsole(["", "", ""])
    a = ask_target(console, taken=set(), defaults=dc01, ask_name=False)
    assert a == TargetAnswers(["10.10.10.161"], ["forest.htb.local"], "external", "dc01")
    assert "name" not in console.asked


def test_target_show_prints_one_target(session):
    dispatch(session, "target show")
    text = "\n".join(t for kind, t in session.console.lines if kind == "info")
    folder = str(session.box.path / "targets" / "dc01")
    for part in ("10.10.10.161", "forest.htb.local", "external", folder):
        assert part in text
    assert "name      dc01" in text


def test_target_show_extra_arguments_fail(session):
    dispatch(session, "target show dc01 extra")
    assert len(_fails(session.console)) == 1


def test_target_add_updates_everything(session):
    session.console = FakeConsole(["10.10.10.50", "", "", "web01"])
    dispatch(session, "target add")
    box = session.box
    assert (box.path / "targets" / "web01").is_dir()
    assert [t.name for t in load_targets(box)] == ["dc01", "web01"]
    note = (box.path / "notes.md").read_text(encoding="utf-8")
    top = note.split(FOLD_START)[0]
    assert any(line.startswith("#    web01 ") and "10.10.10.50" in line for line in top.splitlines())
    assert note.endswith(
        f"{FOLD_END}\n\n{FOLD_START}\nTarget: web01   10.10.10.50   -   external\n\n"
        f"## enumeration\n\n## foothold\n\n## privilege escalation\n\n{FOLD_END}\n"
    )
    assert "10.10.10.50" in (box.path / "lists" / "ips.txt").read_text(encoding="utf-8")
    assert session.current.name == "web01"
    assert load_box(box.path).last_target == "web01"
    assert ("ok", "target web01 created") in session.console.lines


def test_target_add_refuses_a_hostname_another_target_has(session, system):
    session.console = FakeConsole(["10.10.10.50", "web.htb FOREST.htb.local", "", "web01"])
    dispatch(session, "target add")
    assert _fails(session.console) == ["FOREST.htb.local is already a hostname of dc01"]
    assert [kind for kind, _ in session.console.lines] == ["fail"]
    assert not (session.box.path / "targets" / "web01").exists()
    assert [t.name for t in load_targets(session.box)] == ["dc01"]
    assert system.pings == []


def test_target_edit_refuses_a_hostname_another_target_has(session):
    add_target(
        session.box, session.targets, ips=["10.10.10.2"], hostnames=["web.htb"],
        scope="external", name="web", now=NOW,
    )  # fmt: skip
    session.console = FakeConsole(["", "forest.htb.local web.htb", ""])
    dispatch(session, "target edit dc01")
    assert [kind for kind, _ in session.console.lines] == ["fail"]
    assert _fails(session.console) == ["web.htb is already a hostname of web"]
    assert session.targets[0].hostnames == ["forest.htb.local"]
    assert load_targets(session.box)[0].hostnames == ["forest.htb.local"]


def test_target_add_writes_the_note_once(session, monkeypatch):
    from pwn_broker import session as session_module

    writes = []
    real = note.write_note

    def counted(box, text):
        writes.append(text)
        real(box, text)

    monkeypatch.setattr(note, "write_note", counted)
    monkeypatch.setattr(session_module, "write_note", counted)
    session.console = FakeConsole(["10.10.10.50", "", "", "web01"])
    dispatch(session, "target add")
    assert len(writes) == 1
    assert "#    web01 " in writes[0] and "Target: web01   10.10.10.50" in writes[0]


def test_target_add_with_a_damaged_box_still_appends_the_section(session):
    path = session.box.path / "notes.md"
    path.write_text("mine\n", encoding="utf-8", newline="")
    session.console = FakeConsole(["10.10.10.50", "", "", "web01"])
    dispatch(session, "target add")
    assert path.read_text(encoding="utf-8").startswith(f"mine\n\n{FOLD_START}\nTarget: web01 ")
    assert [kind for kind, _ in session.console.lines].count("warn") == 1


def test_target_add_section_template_can_use_box_fields(session):
    session.paths.templates.mkdir(parents=True)
    template = f"# $name\n{note.SECTION_MARK}\n## $target on $name ($platform)\n"
    (session.paths.templates / "notes.md").write_text(template, encoding="utf-8")
    session.console = FakeConsole(["10.10.10.50", "", "", "web01"])
    dispatch(session, "target add")
    text = (session.box.path / "notes.md").read_text(encoding="utf-8")
    assert text.rstrip().endswith("## web01 on forest (htb)")


def test_target_add_without_a_note(session):
    (session.box.path / "notes.md").unlink()
    session.console = FakeConsole(["10.10.10.50", "", "", "web01"])
    dispatch(session, "target add")
    assert not (session.box.path / "notes.md").exists()
    assert ("ok", "target web01 created") in session.console.lines


def test_target_list_table(session):
    add_target(
        session.box, session.targets, ips=["10.10.10.2", "10.10.10.3"], hostnames=[],
        scope="internal", name="web", now=NOW,
    )  # fmt: skip
    dispatch(session, "target list")
    columns, rows = session.console.tables[0]
    assert columns == ["name", "ip", "hostname", "scope"]
    assert rows == [
        ["dc01", "10.10.10.161", "forest.htb.local", "external"],
        ["web", "10.10.10.2, 10.10.10.3", "-", "internal"],
    ]


def test_target_list_empty(session):
    session.targets.clear()
    dispatch(session, "target list")
    assert session.console.lines == [("info", "no targets yet")]


def test_target_use_prefix_and_ambiguous(session):
    dc01 = session.current
    web1 = _add(session, "web01", "10.10.10.2")
    _add(session, "web02", "10.10.10.3")
    dispatch(session, "target use we")
    assert session.current is dc01
    assert len(_fails(session.console)) == 1
    dispatch(session, "target use web01")
    assert session.current is web1
    assert load_box(session.box.path).last_target == "web01"
    assert ("ok", "now on web01") in session.console.lines
    dispatch(session, "target use dc")
    assert session.current is dc01


def test_target_edit_keeps_name_and_updates_lists(session):
    session.console = FakeConsole(["10.10.10.200", "", "", "n"])
    dispatch(session, "target edit dc01")
    assert session.console.asked == ["ip", "hostname", "scope", "add dc01's hostnames to /etc/hosts?"]
    assert load_targets(session.box)[0].ips == ["10.10.10.200"]
    text = (session.box.path / "notes.md").read_text(encoding="utf-8")
    assert "#    dc01   10.10.10.200   forest.htb.local   external " in text
    assert f"{FOLD_START}\nTarget: dc01   10.10.10.200   forest.htb.local   external\n" in text
    assert "10.10.10.161" not in text
    assert "10.10.10.200" in (session.box.path / "lists" / "ips.txt").read_text(encoding="utf-8")
    assert ("ok", "target dc01 updated") in session.console.lines


def test_target_edit_leaves_a_title_the_user_changed(session):
    path = session.box.path / "notes.md"
    text = path.read_text(encoding="utf-8").replace("Target: dc01   10.10", "Target: dc01 the DC   10.10")
    path.write_text(text, encoding="utf-8", newline="")
    session.console = FakeConsole(["10.10.10.200", "", "", "n"])
    dispatch(session, "target edit dc01")
    after = path.read_text(encoding="utf-8")
    assert after.split(FOLD_START, 1)[1] == text.split(FOLD_START, 1)[1]
    assert "#    dc01   10.10.10.200 " in after


def test_target_edit_with_no_change_does_not_rewrite_the_note(session):
    path = session.box.path / "notes.md"
    before = path.read_bytes()
    os.utime(path, ns=(1_000_000_000_000_000_000, 1_000_000_000_000_000_000))
    session.console = FakeConsole(["", "", "", "n"])
    dispatch(session, "target edit dc01")
    assert ("ok", "target dc01 updated") in session.console.lines
    assert path.read_bytes() == before
    assert path.stat().st_mtime_ns == 1_000_000_000_000_000_000


def test_target_edit_survives_a_broken_note(session, monkeypatch):
    _break_note_writes(monkeypatch)
    session.console = FakeConsole(["10.10.10.200", "", "", "n"])
    dispatch(session, "target edit dc01")
    kinds = [kind for kind, _ in session.console.lines]
    assert kinds.count("warn") == 1
    assert ("ok", "target dc01 updated") in session.console.lines
    assert load_targets(session.box)[0].ips == ["10.10.10.200"]


def test_target_rename_changes_note_title(session):
    note = session.box.path / "notes.md"
    text = note.read_text(encoding="utf-8")
    title = "Target: dc01   10.10.10.161   forest.htb.local   external"
    mine = f"\nsee dc01 for details\n{title}\n"
    note.write_text(text + mine, encoding="utf-8", newline="")
    session.console = FakeConsole(["dc"])
    dispatch(session, "target rename dc01")
    text = note.read_text(encoding="utf-8")
    assert f"{FOLD_START}\nTarget: dc   10.10.10.161   forest.htb.local   external\n" in text
    assert "#    dc   10.10.10.161 " in text
    assert text.endswith(mine)
    assert session.current.name == "dc"
    assert load_box(session.box.path).last_target == "dc"
    assert (session.box.path / "targets" / "dc").is_dir()
    assert session.console.asked == ["new name"]
    assert ("ok", "target dc01 is now dc") in session.console.lines


def _working_cred(session):
    session.creds.append(make_cred(username="svc", secret="pw", found_on="dc01", works_on=["dc01"]))
    refresh(session)
    return session.box.path / "lists"


def test_target_rename_carries_creds_and_works_lists(session):
    lists = _working_cred(session)
    ips = (lists / "ips.txt").read_bytes()
    assert (lists / "works-dc01-userpass.txt").read_text(encoding="utf-8") == "svc:pw\n"
    session.console = FakeConsole(["dc"])
    dispatch(session, "target rename dc01")
    assert ("ok", "target dc01 is now dc") in session.console.lines
    [saved] = load_creds(session.box)
    assert (saved.found_on, saved.works_on) == ("dc", ["dc"])
    assert (session.creds[0].found_on, session.creds[0].works_on) == ("dc", ["dc"])
    assert (lists / "works-dc-userpass.txt").read_text(encoding="utf-8") == "svc:pw\n"
    assert not (lists / "works-dc01-userpass.txt").exists()
    assert (lists / "ips.txt").read_bytes() == ips


def test_target_rename_stops_before_moving_on_a_corrupt_files_toml(session):
    _working_cred(session)
    (session.box.path / "files.toml").write_text("= broken", encoding="utf-8")
    session.console = FakeConsole(["dc"])
    dispatch(session, "target rename dc01")
    assert len(_fails(session.console)) == 1 and "files.toml" in _fails(session.console)[0]
    assert (session.box.path / "targets" / "dc01").is_dir()
    assert not (session.box.path / "targets" / "dc").exists()
    assert [t.name for t in session.targets] == ["dc01"] and session.creds[0].found_on == "dc01"
    assert load_targets(session.box)[0].name == "dc01"
    assert load_creds(session.box)[0].found_on == "dc01"


def test_target_remove_asks_and_refuses_non_empty(session):
    web = _add(session, "web", "10.10.10.2")
    session.console = FakeConsole(["n"])
    dispatch(session, "target remove web")
    assert web in session.targets
    assert session.console.asked == ["remove target web?"]
    (session.box.path / "targets" / "web" / "loot" / "x.txt").write_text("x")
    session.console = FakeConsole(["y"])
    dispatch(session, "target remove web")
    assert web in session.targets
    assert len(_fails(session.console)) == 1


def test_target_remove_current_moves_to_another(session):
    web = _add(session, "web", "10.10.10.2")
    session.console = FakeConsole(["y"])
    dispatch(session, "target remove dc01")
    assert session.current is web
    assert load_box(session.box.path).last_target == "web"
    assert not (session.box.path / "targets" / "dc01").exists()
    assert ("ok", "target dc01 removed") in session.console.lines
    assert f"{FOLD_START}\nTarget: dc01   " in (session.box.path / "notes.md").read_text(encoding="utf-8")
    session.console = FakeConsole(["y"])
    dispatch(session, "target remove web")
    assert session.current is None
    assert load_box(session.box.path).last_target is None


@pytest.mark.parametrize("line", ["target use", "target rename", "target remove", "target edit"])
def test_missing_target_argument_fails(session, line):
    dispatch(session, line)
    assert len(_fails(session.console)) == 1


def _break_note_writes(monkeypatch):
    def broken(box, text):
        raise OSError("disk full")

    monkeypatch.setattr(note, "write_note", broken)


def test_target_add_survives_a_broken_note(session, monkeypatch):
    original = note.write_note
    calls = []

    def broken(box, text):
        calls.append(1)
        raise OSError("disk full")

    monkeypatch.setattr(note, "write_note", broken)
    session.console = FakeConsole(["10.10.10.50", "", "", "web01"])
    dispatch(session, "target add")
    monkeypatch.setattr(note, "write_note", original)
    kinds = [kind for kind, _ in session.console.lines]
    assert kinds.count("warn") == 1 and ("ok", "target web01 created") in session.console.lines
    assert session.current.name == "web01"
    assert load_box(session.box.path).last_target == "web01"
    assert "10.10.10.50" in (session.box.path / "lists" / "ips.txt").read_text(encoding="utf-8")


def test_target_rename_survives_a_broken_note(session, monkeypatch):
    _break_note_writes(monkeypatch)
    session.console = FakeConsole(["dc"])
    dispatch(session, "target rename dc01")
    kinds = [kind for kind, _ in session.console.lines]
    assert kinds.count("warn") == 1
    assert ("ok", "target dc01 is now dc") in session.console.lines
    assert session.current.name == "dc"
    assert [t.name for t in session.targets] == ["dc"]
    assert (session.box.path / "targets" / "dc").is_dir()
    assert load_box(session.box.path).last_target == "dc"


def test_target_rename_refuses_while_a_window_records_for_it(session, system):
    from casts import recording_now

    cast = recording_now(session, system, "dc01")
    session.console = FakeConsole(["dc"])
    dispatch(session, "target rename dc01")
    assert session.console.lines == [
        ("fail", "1 window is still recording for dc01. exit it, then rename it")
    ]
    assert session.console.asked == []
    assert cast.exists() and [t.name for t in session.targets] == ["dc01"]
    recording_now(session, system, "dc01", "2026-11-14_1600", pid=5151)
    session.console = FakeConsole(["dc"])
    dispatch(session, "target rename dc01")
    assert session.console.lines == [
        ("fail", "2 windows are still recording for dc01. exit them, then rename it")
    ]


def test_target_rename_goes_ahead_while_a_window_records_for_another_target(session, system):
    from casts import recording_now

    _add(session, "web", "10.10.10.2")
    recording_now(session, system, "web")
    session.console = FakeConsole(["dc"])
    dispatch(session, "target rename dc01")
    assert ("ok", "target dc01 is now dc") in session.console.lines


def test_target_remove_refuses_while_a_window_records_for_it(session, system):
    from casts import recording_now

    web = _add(session, "web", "10.10.10.2")
    recording_now(session, system, "web")
    session.console = FakeConsole(["y"])
    dispatch(session, "target remove web")
    assert session.console.lines == [
        ("fail", "1 window is still recording for web. exit it, then remove it")
    ]
    assert session.console.asked == [] and web in session.targets


def test_target_remove_checks_emptiness_before_asking(session):
    (session.box.path / "targets" / "dc01" / "loot" / "x.txt").write_text("x")
    session.console = FakeConsole(["y"])
    dispatch(session, "target remove dc01")
    assert session.console.asked == []
    assert len(_fails(session.console)) == 1


def test_target_rename_to_same_name_fails(session):
    session.console = FakeConsole(["DC01"])
    dispatch(session, "target rename dc01")
    assert len(_fails(session.console)) == 1
    assert (session.box.path / "targets" / "dc01").is_dir()
    assert not any(kind == "ok" for kind, _ in session.console.lines)


def test_ask_target_dash_clears_a_field_when_editing(dc01):
    a = ask_target(FakeConsole(["", "-", ""]), taken=set(), defaults=dc01, ask_name=False)
    assert a.hostnames == [] and a.ips == ["10.10.10.161"]
    console = FakeConsole(["-", "-", "10.10.10.7", "", ""])
    a = ask_target(console, taken=set(), defaults=dc01, ask_name=False)
    assert a.ips == ["10.10.10.7"]
    assert len(_fails(console)) == 1


def _hosts_line(session, rest):
    return f"{rest}  # pwn-broker {session.box.id}"


def _hosts_text(session):
    return session.hosts_path.read_text(encoding="utf-8")


def test_target_add_offers_the_hosts_line_and_pings(session, system):
    session.console = FakeConsole(["10.10.10.50", "web.htb", "", "web01", ""])
    dispatch(session, "target add")
    assert session.console.asked[-1] == "add web01's hostnames to /etc/hosts?"
    assert _hosts_line(session, "10.10.10.50 web.htb") in _hosts_text(session)
    assert load_box(session.box.path).hosts == ["web01"]
    assert system.pings == ["10.10.10.50"]
    assert session.console.lines[0] == ("ok", "target web01 created")
    assert session.console.lines[-1] == ("ok", "10.10.10.50 answered in 1 ms")


def test_target_edit_offers_the_line_when_the_target_has_none(session):
    session.console = FakeConsole(["", "", "", ""])
    dispatch(session, "target edit dc01")
    assert load_box(session.box.path).hosts == ["dc01"]
    assert _hosts_line(session, "10.10.10.161 forest.htb.local") in _hosts_text(session)


def test_target_edit_rewrites_the_line_without_asking(session):
    session.console = FakeConsole(["", "", "", ""])
    dispatch(session, "target edit dc01")
    session.console = FakeConsole(["10.10.10.200", "dc01.htb.local", ""])
    dispatch(session, "target edit dc01")
    assert session.console.asked == ["ip", "hostname", "scope"]
    assert _hosts_text(session) == "127.0.0.1 localhost\n" + _hosts_line(
        session, "10.10.10.200 dc01.htb.local"
    ) + "\n"


def test_target_rename_keeps_the_line(session):
    session.console = FakeConsole(["", "", "", ""])
    dispatch(session, "target edit dc01")
    before = _hosts_text(session)
    session.console = FakeConsole(["dc"])
    dispatch(session, "target rename dc01")
    assert load_box(session.box.path).hosts == ["dc"]
    assert _hosts_text(session) == before
    assert session.console.lines == [("ok", "target dc01 is now dc")]


def test_target_remove_takes_the_line_out(session):
    session.console = FakeConsole(["", "", "", ""])
    dispatch(session, "target edit dc01")
    session.console = FakeConsole(["y"])
    dispatch(session, "target remove dc01")
    assert load_box(session.box.path).hosts == []
    assert _hosts_text(session) == "127.0.0.1 localhost\n"
    assert session.console.lines == [("ok", "target dc01 removed"), ("ok", "/etc/hosts updated")]


def test_target_remove_of_a_target_without_a_line_leaves_the_file(session):
    web = _add(session, "web", "10.10.10.2")
    before = session.hosts_path.read_bytes()
    session.console = FakeConsole(["y"])
    dispatch(session, "target remove web")
    assert web not in session.targets
    assert session.console.lines == [("ok", "target web removed")]
    assert session.hosts_path.read_bytes() == before


def test_target_edit_that_clears_the_hostnames_forgets_the_line(session):
    session.console = FakeConsole(["", "", "", ""])
    dispatch(session, "target edit dc01")
    session.console = FakeConsole(["", "-", ""])
    dispatch(session, "target edit dc01")
    assert session.box.hosts == [] and load_box(session.box.path).hosts == []
    assert _hosts_text(session) == "127.0.0.1 localhost\n"


def test_target_edit_that_clears_the_ip_forgets_the_line(session):
    session.console = FakeConsole(["", "", "", ""])
    dispatch(session, "target edit dc01")
    session.console = FakeConsole(["-", "", ""])
    dispatch(session, "target edit dc01")
    assert load_box(session.box.path).hosts == []
    assert _hosts_text(session) == "127.0.0.1 localhost\n"


def test_target_remove_that_cannot_write_says_which_line_to_remove(session):
    session.console = FakeConsole(["", "", "", ""])
    dispatch(session, "target edit dc01")
    session.is_root = lambda: False
    session.console = FakeConsole(["y"])
    dispatch(session, "target remove dc01")
    assert session.console.lines[1:] == [
        ("warn", "/etc/hosts was not changed: cp exited 1"),
        ("info", "remove this line yourself:"),
        ("raw", _hosts_line(session, "10.10.10.161 forest.htb.local")),
    ]
