from datetime import timedelta

from helpers import NOW
from pwn_broker import session as session_module
from pwn_broker.boxes import add_target
from pwn_broker.config import Settings
from pwn_broker.console import FakeConsole
from pwn_broker.creds import add_cred
from pwn_broker.note import NOTE_NAME, TABLE_END, read_note
from pwn_broker.session import load_session, refresh, rescan, set_current
from pwn_broker.store import load_box


def reload(session):
    return load_session(session.paths, session.settings, session.console, session.box, session.clock)


def test_load_session_picks_last_target(session):
    web = add_target(
        session.box, session.targets, ips=["10.10.10.2"], hostnames=[],
        scope="external", name="web", now=NOW + timedelta(minutes=1),
    )  # fmt: skip
    session.box.last_target = "web"
    assert reload(session).current == web
    session.box.last_target = None
    assert reload(session).current.name == "dc01"
    session.box.last_target = "gone"
    assert reload(session).current.name == "dc01"


def test_load_session_without_targets(paths, box):
    loaded = load_session(paths, Settings(), FakeConsole(), box, lambda: NOW)
    assert loaded.current is None and loaded.targets == [] and loaded.creds == []


def test_set_current_saves_last_target(session):
    set_current(session, session.targets[0])
    assert load_box(session.box.path).last_target == "dc01"
    set_current(session, None)
    assert session.current is None
    assert load_box(session.box.path).last_target is None


def test_refresh_writes_lists_and_table(session):
    add_target(
        session.box, session.targets, ips=["10.10.10.2"], hostnames=["web.htb"],
        scope="internal", name="web", now=NOW,
    )  # fmt: skip
    add_cred(
        session.creds, username="svc", domain="HTB", secret="pw", kind="password",
        found_on="forest", note="", now=NOW,
    )  # fmt: skip
    summary = refresh(session)
    assert summary.usernames == 1
    assert (session.box.path / "lists" / "usernames.txt").read_text() == "svc\n"
    assert (session.box.path / "creds.toml").exists()
    table = read_note(session.box).split(TABLE_END)[0]
    assert "web" in table and "10.10.10.2" in table


def test_refresh_warns_when_markers_are_damaged(session):
    note = session.box.path / NOTE_NAME
    note.write_text(read_note(session.box).replace(TABLE_END, ""), encoding="utf-8", newline="")
    before = note.read_text(encoding="utf-8")
    refresh(session)
    assert note.read_text(encoding="utf-8") == before
    assert [k for k, _ in session.console.lines] == ["warn"]


def test_refresh_without_a_note_is_silent(session):
    (session.box.path / NOTE_NAME).unlink()
    refresh(session)
    assert session.console.lines == []
    assert not (session.box.path / NOTE_NAME).exists()


def test_rescan_warns_per_skipped_file(session, monkeypatch):
    def fake_scan(box, records, *, now, hash_all, on_skip):
        on_skip("a.txt", "cannot read")
        on_skip("b.txt", "disappeared")
        return []

    monkeypatch.setattr(session_module, "scan", fake_scan)
    rescan(session)
    assert session.console.lines == [("warn", "a.txt   cannot read"), ("warn", "b.txt   disappeared")]
    rescan(session)
    assert len(session.console.lines) == 2
    rescan(session, hash_all=True)
    assert len(session.console.lines) == 4


def test_rescan_records_files_and_saves(session):
    (session.box.path / "targets" / "dc01" / "loot" / "x.txt").write_text("hi")
    records = rescan(session)
    assert "targets/dc01/loot/x.txt" in [r.path for r in records]
    assert (session.box.path / "files.toml").exists()
