import os
from datetime import timedelta

from helpers import NOW
from pwn_broker import session as session_module
from pwn_broker.boxes import add_target
from pwn_broker.config import Settings
from pwn_broker.console import FakeConsole
from pwn_broker.creds import add_cred
from pwn_broker.note import FOLD_START, NOTE_NAME, read_note
from pwn_broker.session import load_session, refresh, rescan, set_current
from pwn_broker.store import load_box, save_creds


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
    top = read_note(session.box).split(FOLD_START)[0]
    assert "#    web " in top and "10.10.10.2" in top


def test_refresh_warns_when_markers_are_damaged(session):
    note = session.box.path / NOTE_NAME
    note.write_text("my own first line\n" + read_note(session.box), encoding="utf-8", newline="")
    before = note.read_text(encoding="utf-8")
    refresh(session)
    assert note.read_text(encoding="utf-8") == before
    assert [k for k, _ in session.console.lines] == ["warn"]
    assert "left alone" in session.console.lines[0][1]


def test_refresh_warns_about_a_missing_box_once(session):
    note = session.box.path / NOTE_NAME
    note.write_text("no box here\n", encoding="utf-8", newline="")
    for _ in range(3):
        refresh(session)
    assert [k for k, _ in session.console.lines] == ["warn"]
    assert note.read_text(encoding="utf-8") == "no box here\n"


def test_refresh_without_a_target_change_does_not_rewrite_the_note(session):
    note = session.box.path / NOTE_NAME
    refresh(session)
    before = note.read_bytes()
    os.utime(note, ns=(1_000_000_000_000_000_000, 1_000_000_000_000_000_000))
    refresh(session)
    assert note.read_bytes() == before
    assert note.stat().st_mtime_ns == 1_000_000_000_000_000_000


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


# reloading the box when another program changed it

def test_stamp_changes_when_a_target_is_added_edited_or_removed(session):
    from pwn_broker.boxes import edit_target
    from pwn_broker.session import stamp

    before = stamp(session.box)
    assert stamp(session.box) == before
    web = add_target(
        session.box, session.targets, ips=["10.10.10.2"], hostnames=[],
        scope="external", name="web", now=NOW,
    )  # fmt: skip
    added = stamp(session.box)
    assert added != before
    edit_target(session.box, session.targets, "web", ips=["10.10.10.3"], hostnames=[], scope="external")
    # the same size, so only the time can tell; a coarse filesystem clock must not hide it
    file = session.box.path / "targets" / "web" / "target.toml"
    info = file.stat()
    os.utime(file, ns=(info.st_atime_ns, info.st_mtime_ns + 5_000_000_000))
    edited = stamp(session.box)
    assert edited != added
    (session.box.path / "targets" / web.name / "target.toml").unlink()
    assert stamp(session.box) != edited


def test_stamp_changes_with_creds_and_box_files(session):
    from pwn_broker.session import stamp

    before = stamp(session.box)
    (session.box.path / "creds.toml").write_text("x = 1\n", encoding="utf-8")
    with_creds = stamp(session.box)
    assert with_creds != before
    (session.box.path / "box.toml").write_text("y = 2\n", encoding="utf-8")
    assert stamp(session.box) != with_creds


def test_stamp_of_missing_files_is_not_an_error(tmp_path, box):
    from pwn_broker.session import stamp

    (box.path / "box.toml").unlink()
    assert isinstance(stamp(box), tuple)


def test_load_session_marks_what_it_read(session):
    from pwn_broker.session import reload_if_changed, stamp

    loaded = reload(session)
    assert loaded.seen == stamp(loaded.box)
    assert loaded.seen
    assert reload_if_changed(loaded) is False


def _add_elsewhere(session, name="web", address="10.10.10.2"):
    other = reload(session)
    return add_target(
        other.box, other.targets, ips=[address], hostnames=[],
        scope="external", name=name, now=NOW + timedelta(minutes=1),
    )  # fmt: skip


def test_reload_picks_up_a_target_added_on_disk(session):
    from pwn_broker.session import load_session, reload_if_changed

    mine = load_session(session.paths, session.settings, session.console, session.box, session.clock)
    _add_elsewhere(session)
    assert [t.name for t in mine.targets] == ["dc01"]
    assert reload_if_changed(mine) is True
    assert [t.name for t in mine.targets] == ["dc01", "web"]
    assert mine.current.name == "dc01"
    assert reload_if_changed(mine) is False


def test_reload_drops_to_the_first_target_when_current_is_gone(session):
    import shutil

    from pwn_broker.session import load_session, reload_if_changed

    _add_elsewhere(session)
    mine = load_session(session.paths, session.settings, session.console, session.box, session.clock)
    mine.current = mine.targets[1]
    shutil.rmtree(session.box.path / "targets" / "web")
    assert reload_if_changed(mine) is True
    assert mine.current.name == "dc01"
    shutil.rmtree(session.box.path / "targets" / "dc01")
    assert reload_if_changed(mine) is True
    assert mine.current is None
    assert mine.targets == []


def test_reload_updates_the_same_object_and_keeps_other_fields(session):
    from pwn_broker.session import load_session, reload_if_changed

    mine = load_session(session.paths, session.settings, session.console, session.box, session.clock)
    mine.warned.add("x")
    mine.copied_in_full.add(session.box.path)
    settings, console, clock = mine.settings, mine.console, mine.clock
    _add_elsewhere(session)
    reload_if_changed(mine)
    assert mine.warned == {"x"}
    assert mine.copied_in_full == {session.box.path}
    assert (mine.settings, mine.console, mine.clock) == (settings, console, clock)
    assert mine.box.path == session.box.path


def test_reload_picks_up_creds_on_disk(session):
    from pwn_broker.session import load_session, reload_if_changed

    mine = load_session(session.paths, session.settings, session.console, session.box, session.clock)
    creds = []
    add_cred(
        creds, username="bob", domain="", secret="pw", kind="password",
        found_on="forest", note="", now=NOW,
    )  # fmt: skip
    save_creds(session.box, creds)
    assert mine.creds == []
    assert reload_if_changed(mine) is True
    assert [c.username for c in mine.creds] == ["bob"]


def test_own_writes_do_not_cause_a_reload_after_mark_seen(session):
    from pwn_broker.session import load_session, mark_seen, reload_if_changed

    mine = load_session(session.paths, session.settings, session.console, session.box, session.clock)
    add_target(
        mine.box, mine.targets, ips=["10.10.10.9"], hostnames=[],
        scope="external", name="own", now=NOW,
    )  # fmt: skip
    mark_seen(mine)
    assert reload_if_changed(mine) is False
    assert [t.name for t in mine.targets] == ["dc01", "own"]


def test_refresh_after_reload_keeps_the_new_target_in_note_and_lists(session):
    from pwn_broker.session import load_session, reload_if_changed

    mine = load_session(session.paths, session.settings, session.console, session.box, session.clock)
    _add_elsewhere(session, name="web", address="10.10.10.2")
    assert reload_if_changed(mine) is True
    refresh(mine)
    assert "10.10.10.2" in read_note(mine.box)
    assert "web" in read_note(mine.box)
    listed = "\n".join(
        p.read_text(encoding="utf-8") for p in (mine.box.path / "lists").iterdir() if p.is_file()
    )
    assert "10.10.10.2" in listed
