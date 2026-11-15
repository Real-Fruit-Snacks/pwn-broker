import pytest

from helpers import NOW
from pwn_broker import shell  # noqa: F401  (fills the command registry)
from pwn_broker.boxes import add_target
from pwn_broker.console import FakeConsole
from pwn_broker.questions import TargetAnswers, ask_target
from pwn_broker.shell.commands import dispatch
from pwn_broker.store import load_box, load_targets


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
    assert any(line.startswith("web01") and "10.10.10.50" in line for line in note.splitlines())
    assert note.rstrip().splitlines()[-1] == "### privilege escalation"
    assert "\n## web01\n" in note
    assert "10.10.10.50" in (box.path / "lists" / "ips.txt").read_text(encoding="utf-8")
    assert session.current.name == "web01"
    assert load_box(box.path).last_target == "web01"
    assert ("ok", "target web01 created") in session.console.lines


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
    session.console = FakeConsole(["10.10.10.200", "", ""])
    dispatch(session, "target edit dc01")
    assert session.console.asked == ["ip", "hostname", "scope"]
    assert load_targets(session.box)[0].ips == ["10.10.10.200"]
    assert "10.10.10.200" in (session.box.path / "notes.md").read_text(encoding="utf-8")
    assert "10.10.10.200" in (session.box.path / "lists" / "ips.txt").read_text(encoding="utf-8")
    assert ("ok", "target dc01 updated") in session.console.lines


def test_target_rename_changes_note_heading(session):
    note = session.box.path / "notes.md"
    text = note.read_text(encoding="utf-8")
    note.write_text(text + "\nsee dc01 for details\n", encoding="utf-8", newline="")
    session.console = FakeConsole(["dc"])
    dispatch(session, "target rename dc01")
    text = note.read_text(encoding="utf-8")
    assert "\n## dc\n" in text
    assert "## dc01" not in text
    assert "see dc01 for details" in text
    assert session.current.name == "dc"
    assert load_box(session.box.path).last_target == "dc"
    assert (session.box.path / "targets" / "dc").is_dir()
    assert session.console.asked == ["new name"]
    assert ("ok", "target dc01 is now dc") in session.console.lines


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
    assert "## dc01" in (session.box.path / "notes.md").read_text(encoding="utf-8")
    session.console = FakeConsole(["y"])
    dispatch(session, "target remove web")
    assert session.current is None
    assert load_box(session.box.path).last_target is None


@pytest.mark.parametrize("line", ["target use", "target rename", "target remove", "target edit"])
def test_missing_target_argument_fails(session, line):
    dispatch(session, line)
    assert len(_fails(session.console)) == 1
