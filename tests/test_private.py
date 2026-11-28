"""A box's secrets are their owner's alone: the real modes, read back after each way of writing
them. Linux only: Windows keeps no such modes."""

import os
import stat
import sys
import tarfile
from pathlib import Path

import pytest

from helpers import NOW
from pwn_broker import archive, private, reportflow, shell  # noqa: F401  (the commands)
from pwn_broker import cli, store
from pwn_broker.boxes import create_box
from pwn_broker.config import Settings
from pwn_broker.console import FakeConsole
from pwn_broker.lifecycle import export_box, finish_box, import_box
from pwn_broker.model import ToolRecord
from pwn_broker.note import read_note, write_note
from pwn_broker.paths import AppPaths
from pwn_broker.session import refresh, rescan, write_new_note
from pwn_broker.shell import app
from pwn_broker.shell.commands import dispatch

pytestmark = pytest.mark.skipif(os.name == "nt", reason="needs file modes")

NOFIX = dict(fix=lambda path: 0)
SECRETS = ("creds.toml", "notes.md", ".history")


def mode(path) -> int:
    return stat.S_IMODE(os.lstat(path).st_mode)


def modes(folder: Path) -> dict[str, int]:
    return {p.name: mode(p) for p in sorted(folder.iterdir())}


@pytest.fixture(params=[0o022, 0o002, 0o000, 0o077], ids=lambda m: f"umask {m:03o}")
def umask(request):
    old = os.umask(request.param)
    yield request.param
    os.umask(old)


@pytest.fixture
def loose_umask():
    old = os.umask(0o022)
    yield
    os.umask(old)


def run(session, line, *answers):
    session.console = FakeConsole(list(answers))
    dispatch(session, line)
    return session.console


def add_cred(session, secret="Passw0rd!"):
    # username, domain, secret, kind, found on, note
    return run(session, "cred add", "svc", "HTB", secret, "password", "", "")


def loosen(paths: AppPaths, box) -> None:
    """The box as 0.1.15 and a umask of 022 left it: everything readable by anyone."""
    os.chmod(box.path, 0o755)
    for path in box.path.rglob("*"):
        os.chmod(path, 0o755 if path.is_dir() else 0o644)
    if paths.wrapped.is_dir():
        os.chmod(paths.wrapped, 0o755)
        for path in paths.wrapped.iterdir():
            os.chmod(path, 0o755 if path.is_dir() else 0o644)


def assert_private(paths: AppPaths, box) -> None:
    assert mode(box.path) == 0o700
    assert mode(box.path / "lists") == 0o700
    for name in SECRETS:
        if (box.path / name).exists():
            assert mode(box.path / name) == 0o600, name
    assert set(modes(box.path / "lists").values()) <= {0o600}
    if paths.wrapped.is_dir():
        assert mode(paths.wrapped) == 0o700
        found = {p.name: mode(p) for p in paths.wrapped.iterdir() if p.name.endswith(".tar.gz")}
        assert set(found.values()) <= {0o600}, found


# ---- each writer, under each umask


def test_a_new_box_s_folder_and_its_lists_are_the_owner_s_alone(paths, umask):
    box = create_box(
        paths, name="Forest", platform="htb", day=NOW.date(), os_name="", difficulty="", now=NOW
    )
    assert mode(box.path) == 0o700 and mode(box.path / "lists") == 0o700
    # the folders that hold no secret of their own are inside it, as the umask made them
    assert mode(box.path / "targets") == 0o777 & ~umask


def test_the_note_is_the_owner_s_alone_when_it_is_made_and_each_time_it_is_drawn_again(
    session, umask
):
    (session.box.path / "notes.md").unlink()
    write_new_note(session.paths, session.box, session.targets)
    assert mode(session.box.path / "notes.md") == 0o600
    run(session, "target add", "10.10.10.5", "web01.htb.local", "", "web01")
    assert "web01" in read_note(session.box)
    assert mode(session.box.path / "notes.md") == 0o600


def test_cred_add_writes_the_credentials_and_every_list_for_the_owner_alone(session, umask):
    add_cred(session)
    box = session.box.path
    assert "Passw0rd!" in (box / "creds.toml").read_text()
    assert mode(box / "creds.toml") == 0o600 and mode(box / "lists") == 0o700
    found = modes(box / "lists")
    assert "passwords.txt" in found and "ips.txt" in found
    assert set(found.values()) == {0o600}, found


def test_the_other_credential_commands_keep_them_so(session, loose_umask):
    add_cred(session)
    box = session.box.path
    for line, answers in (
        ("cred works 1 dc01", ()),
        ("cred edit 1", ("svc", "HTB", "N3w!", "password", "", "dc01", "")),
        ("cred add", ("admin", "", "aad3b435b51404ee", "hash", "", "")),
        ("cred remove 2", ("y",)),
    ):
        run(session, line, *answers)
        assert mode(box / "creds.toml") == 0o600, line
        assert set(modes(box / "lists").values()) == {0o600}, line
    assert "N3w!" in (box / "lists" / "passwords.txt").read_text()


def test_a_file_that_was_readable_by_others_stops_being_so_when_it_is_written(session, loose_umask):
    add_cred(session)
    loosen(session.paths, session.box)
    # a target more, so the credentials, every list and the note's box are written again
    run(session, "target add", "10.10.10.5", "", "", "web01")
    box = session.box.path
    assert mode(box / "creds.toml") == 0o600 and mode(box / "notes.md") == 0o600
    assert mode(box / "lists") == 0o700 and set(modes(box / "lists").values()) == {0o600}


def test_a_mode_tighter_than_the_owner_s_alone_is_kept(session, loose_umask):
    add_cred(session)
    box = session.box.path
    os.chmod(box / "creds.toml", 0o400)
    os.chmod(box / "notes.md", 0o400)
    os.chmod(box / "lists" / "passwords.txt", 0o400)
    refresh(session)
    write_note(session.box, read_note(session.box) + "more\n")
    assert mode(box / "creds.toml") == 0o400 and mode(box / "notes.md") == 0o400
    assert mode(box / "lists" / "passwords.txt") == 0o400
    assert private.tighten_box(session.paths, session.box) == []
    assert mode(box / "creds.toml") == 0o400


def test_the_other_files_of_a_box_keep_the_umask_s_mode(session, loose_umask):
    # box.toml is written the way it always was: the folder around it is what keeps it private
    store.save_box(session.box)
    assert mode(session.box.path / "box.toml") == 0o644
    os.chmod(session.box.path / "box.toml", 0o640)
    store.save_box(session.box)
    assert mode(session.box.path / "box.toml") == 0o640


def test_an_export_is_the_owner_s_alone_and_so_is_wrapped(session, umask):
    add_cred(session)
    dest = export_box(session, **NOFIX)
    assert dest is not None and mode(dest) == 0o600
    assert mode(session.paths.wrapped) == 0o700
    assert not list(session.paths.wrapped.glob("*.part"))
    # and again over the one that is there
    assert mode(export_box(session, **NOFIX)) == 0o600


def test_an_export_into_a_wrapped_folder_others_could_read_closes_it(session, loose_umask):
    session.paths.wrapped.mkdir(parents=True)
    os.chmod(session.paths.wrapped, 0o755)
    dest = export_box(session, **NOFIX)
    assert mode(dest) == 0o600 and mode(session.paths.wrapped) == 0o700


def test_an_archive_is_never_readable_by_others_while_it_is_written(session, loose_umask, monkeypatch):
    seen = []
    real = archive.verify

    def watch(path):
        seen.append((path.name, mode(path)))
        return real(path)

    monkeypatch.setattr(archive, "verify", watch)
    dest = export_box(session, **NOFIX)
    assert seen == [(dest.name + ".part", 0o600)]


def test_a_part_file_left_readable_is_not_written_into(session, loose_umask):
    wrapped = session.paths.wrapped
    wrapped.mkdir(parents=True)
    part = wrapped / f"{session.box.path.name}.exported.tar.gz.part"
    part.write_bytes(b"left by a stopped export")
    os.chmod(part, 0o644)
    assert mode(export_box(session, **NOFIX)) == 0o600


def test_a_link_left_where_the_part_file_goes_is_not_written_through(session, loose_umask, tmp_path):
    wrapped = session.paths.wrapped
    wrapped.mkdir(parents=True)
    victim = tmp_path / "victim"
    victim.write_bytes(b"mine")
    (wrapped / f"{session.box.path.name}.exported.tar.gz.part").symlink_to(victim)
    dest = export_box(session, **NOFIX)
    assert dest is not None and not dest.is_symlink() and mode(dest) == 0o600
    assert victim.read_bytes() == b"mine"


def test_finish_writes_its_archive_for_the_owner_alone(session, umask):
    session.console = FakeConsole(["y", "n"])
    dest = finish_box(session, fix=lambda p: 0, unsaved=lambda box: False)
    assert dest is not None and dest.name.endswith(".finished.tar.gz")
    assert mode(dest) == 0o600 and mode(session.paths.wrapped) == 0o700


def test_the_copy_in_copy_to_is_the_owner_s_alone_whatever_the_folder_is(session, tmp_path, umask):
    out = tmp_path / "shared"
    out.mkdir()
    os.chmod(out, 0o777)
    session.settings = Settings(copy_to=out)
    dest = export_box(session, **NOFIX)
    copy = out / dest.name
    assert copy.read_bytes() == dest.read_bytes() and mode(copy) == 0o600
    # the folder is the user's own, a share or a stick: it is not changed
    assert mode(out) == 0o777


def test_a_copy_replaces_an_earlier_one_that_others_could_read(session, tmp_path, loose_umask):
    out = tmp_path / "shared"
    out.mkdir()
    session.settings = Settings(copy_to=out)
    dest = export_box(session, **NOFIX)
    os.chmod(out / dest.name, 0o644)
    (out / (dest.name + ".part")).write_bytes(b"left")
    os.chmod(out / (dest.name + ".part"), 0o644)
    export_box(session, **NOFIX)
    assert mode(out / dest.name) == 0o600 and os.listdir(out) == [dest.name]


def test_the_report_s_copy_is_the_owner_s_alone(session, tmp_path, loose_umask, monkeypatch):
    wrapped = session.paths.wrapped
    wrapped.mkdir(parents=True)
    made = wrapped / "2026-11-14_htb_forest.finished.tar.gz"
    made.write_bytes(b"an archive")
    script = tmp_path / "stand-in.py"
    # what pwn-report would leave if it took no care at all
    script.write_text(
        "import os, sys\n"
        "folder = sys.argv[sys.argv.index('-o') + 1]\n"
        "os.makedirs(os.path.join(folder, 'evidence'), mode=0o755)\n"
        "for name in ('report.md', 'evidence/notes.md'):\n"
        "    with open(os.path.join(folder, name), 'w') as fh:\n"
        "        fh.write('# a report\\n')\n"
        "    os.chmod(os.path.join(folder, name), 0o644)\n",
        encoding="utf-8",
    )
    session.box.tools.append(ToolRecord("report", "0.1.0", 1, "ab" * 32, NOW))
    session.paths.bin.mkdir(parents=True, exist_ok=True)
    (session.paths.bin / "pwn-report").write_text("")
    monkeypatch.setattr(reportflow, "_launcher", lambda s: [sys.executable, str(script)])
    out = tmp_path / "shared"
    out.mkdir()
    session.settings = Settings(copy_to=out)
    session.console = FakeConsole()
    folder = reportflow.build(session, made)
    copy = out / folder.name
    assert (copy / "evidence" / "notes.md").read_text() == "# a report\n"
    assert mode(copy) == 0o700 and mode(copy / "evidence") == 0o700
    assert mode(copy / "report.md") == 0o600 and mode(copy / "evidence" / "notes.md") == 0o600


# ---- import, and opening a box an earlier version made


def earlier_archive(session, tmp_path) -> Path:
    """An archive as 0.1.15 packed it under a umask of 022: every folder 0755, every file 0644."""
    add_cred(session)
    box = session.box
    (box.path / ".history").write_text("+cred add\n")
    # packed without the export's own rewrite of the credentials, which would tighten them
    archive.write_manifest(box, rescan(session, hash_all=True), kind="exported", now=NOW)
    loosen(session.paths, box)
    dest = archive.archive_path(session.paths, box, "exported")
    archive.pack(box, dest)
    loosen(session.paths, box)
    with tarfile.open(dest) as tar:
        packed = {m.name.split("/", 1)[-1]: m.mode for m in tar.getmembers()}
    assert packed["creds.toml"] == 0o644 and packed["lists/passwords.txt"] == 0o644
    return dest


def test_an_imported_box_is_the_owner_s_alone_though_its_archive_was_not(session, tmp_path, loose_umask):
    dest = earlier_archive(session, tmp_path)
    paths = AppPaths(opt=tmp_path / "opt2", home=tmp_path / "home2")
    console = FakeConsole()
    box = import_box(paths, Settings(), console, dest, lambda: NOW)
    assert box is not None and [k for k, _t in console.lines if k == "warn"] == []
    assert_private(paths, box)
    assert mode(box.path / "creds.toml") == 0o600 and mode(box.path / ".history") == 0o600
    assert mode(box.path / "lists" / "passwords.txt") == 0o600
    # nothing of the import is left in active/ for others to look into
    assert [p.name for p in paths.active.iterdir()] == [box.path.name]


def test_the_folder_is_the_owner_s_alone_before_it_is_moved_into_active(session, tmp_path, loose_umask):
    dest = earlier_archive(session, tmp_path)
    paths = AppPaths(opt=tmp_path / "opt2", home=tmp_path / "home2")
    seen = []
    archive.unpack(dest, paths.active, check=lambda folder: seen.append(mode(folder)))
    assert seen == [0o700]


def test_opening_a_box_tightens_what_an_earlier_version_left_and_says_nothing(
    env, session, tmp_path, loose_umask
):
    earlier_archive(session, tmp_path)
    box, paths = session.box, session.paths
    assert mode(box.path) == 0o755 and mode(box.path / "creds.toml") == 0o644
    opened = cli._load(env, box)
    assert opened.box.path == box.path and env.console.lines == []
    assert_private(paths, box)
    assert mode(box.path / ".history") == 0o600
    assert mode(paths.wrapped / f"{box.path.name}.exported.tar.gz") == 0o600
    # what holds no secret of its own is not touched
    assert mode(box.path / "box.toml") == 0o644 and mode(box.path / "targets") == 0o755


def test_resume_goes_through_the_same_door(env, session, tmp_path, loose_umask, monkeypatch):
    earlier_archive(session, tmp_path)
    opened = cli._resume(env, "forest")
    assert opened is not None and env.console.lines == []
    assert_private(session.paths, session.box)


def test_opening_changes_nothing_that_is_a_link_or_is_not_the_box_s(env, session, tmp_path, loose_umask):
    outside = tmp_path / "outside.txt"
    outside.write_text("someone else's")
    os.chmod(outside, 0o644)
    folder = tmp_path / "outside"
    folder.mkdir()
    os.chmod(folder, 0o755)
    lists = session.box.path / "lists"
    lists.mkdir(exist_ok=True)
    (lists / "linked.txt").symlink_to(outside)
    (lists / "sub").symlink_to(folder, target_is_directory=True)
    wrapped = session.paths.wrapped
    wrapped.mkdir(parents=True)
    (wrapped / "linked.finished.tar.gz").symlink_to(outside)
    (wrapped / "notes.txt").write_text("mine, and not an archive")
    os.chmod(wrapped / "notes.txt", 0o644)
    cli._load(env, session.box)
    assert env.console.lines == []
    assert mode(outside) == 0o644 and mode(folder) == 0o755
    assert mode(wrapped / "notes.txt") == 0o644 and mode(wrapped) == 0o700


def test_what_cannot_be_tightened_is_one_warn_line_and_the_box_still_opens(
    env, session, tmp_path, loose_umask, monkeypatch
):
    earlier_archive(session, tmp_path)
    box = session.box
    real = os.chmod
    refused = {str(box.path / "creds.toml"), str(box.path / "lists" / "passwords.txt")}

    def chmod(path, new, **kwargs):
        if str(path) in refused:
            raise PermissionError(1, "Operation not permitted", str(path))
        return real(path, new, **kwargs)

    monkeypatch.setattr(private.os, "chmod", chmod)
    opened = cli._load(env, box)
    assert opened.box.path == box.path
    assert env.console.lines == [
        (
            "warn",
            f"{box.path / 'creds.toml'} could not be made readable by you alone, nor 1 more: "
            "Operation not permitted",
        )
    ]
    # the rest was done all the same
    assert mode(box.path) == 0o700 and mode(box.path / "notes.md") == 0o600
    assert mode(box.path / "creds.toml") == 0o644


def test_a_folder_that_cannot_be_tightened_does_not_stop_an_export(session, loose_umask, monkeypatch):
    # a wrapped/ on a file system that keeps no modes: the archive is still written
    session.paths.wrapped.mkdir(parents=True)
    os.chmod(session.paths.wrapped, 0o755)
    real = os.chmod

    def chmod(path, new, **kwargs):
        if Path(path) == session.paths.wrapped:
            raise PermissionError(1, "Operation not permitted", str(path))
        return real(path, new, **kwargs)

    monkeypatch.setattr(private.os, "chmod", chmod)
    dest = export_box(session, **NOFIX)
    assert dest is not None and mode(dest) == 0o600


# ---- the prompt's history


class OneLine:
    """Stands in for the prompt: keeps one line in the history it was given, then ends."""

    def __init__(self, *args, history=None, **kwargs):
        self.history = history

    def prompt(self):
        self.history.store_string("cred add svc HTB Passw0rd!")
        raise EOFError


def test_the_prompt_s_history_is_made_for_the_owner_alone(session, umask, monkeypatch):
    monkeypatch.setattr(app, "PromptSession", OneLine)
    history = session.box.path / ".history"
    assert not history.exists()
    session.console = FakeConsole(["n"])
    app.run_shell(session)
    assert "Passw0rd!" in history.read_text() and mode(history) == 0o600


def test_a_history_others_could_read_is_closed_before_the_prompt_adds_to_it(
    session, loose_umask, monkeypatch
):
    monkeypatch.setattr(app, "PromptSession", OneLine)
    history = session.box.path / ".history"
    history.write_text("+an earlier line\n")
    os.chmod(history, 0o644)
    session.console = FakeConsole(["n"])
    app.run_shell(session)
    assert "an earlier line" in history.read_text() and "Passw0rd!" in history.read_text()
    assert mode(history) == 0o600


# ---- the pieces


def test_tighten_takes_away_and_never_gives(tmp_path):
    file = tmp_path / "f"
    file.write_text("x")
    for before, after in ((0o644, 0o600), (0o664, 0o600), (0o755, 0o600), (0o600, 0o600), (0o400, 0o400), (0o040, 0)):
        os.chmod(file, before)
        assert private.tighten(file, private.FILE) is (before & 0o600 != before)
        assert mode(file) == before & 0o600 == after
    folder = tmp_path / "d"
    folder.mkdir()
    for before, after in ((0o755, 0o700), (0o777, 0o700), (0o700, 0o700), (0o500, 0o500)):
        os.chmod(folder, before)
        private.tighten(folder, private.FOLDER)
        assert mode(folder) == after


def test_tighten_leaves_alone_what_is_not_there_or_not_of_the_kind(tmp_path):
    assert private.tighten(tmp_path / "missing", private.FILE) is False
    folder = tmp_path / "d"
    folder.mkdir()
    os.chmod(folder, 0o755)
    assert private.tighten(folder, private.FILE) is False and mode(folder) == 0o755
    file = tmp_path / "f"
    file.write_text("x")
    os.chmod(file, 0o644)
    assert private.tighten(file, private.FOLDER) is False and mode(file) == 0o644
    link = tmp_path / "l"
    link.symlink_to(file)
    assert private.tighten(link, private.FILE) is False and mode(file) == 0o644


def test_folder_makes_the_last_folder_private_and_the_ones_above_it_as_usual(tmp_path, loose_umask):
    private.folder(tmp_path / "home" / "wrapped")
    assert mode(tmp_path / "home" / "wrapped") == 0o700 and mode(tmp_path / "home") == 0o755
    private.folder(tmp_path / "home" / "wrapped")
    assert mode(tmp_path / "home" / "wrapped") == 0o700


def test_create_replaces_what_was_there_and_copy_takes_no_mode_from_its_source(tmp_path, umask):
    source = tmp_path / "source"
    source.write_bytes(b"bytes")
    os.chmod(source, 0o644)
    dest = tmp_path / "dest"
    dest.write_bytes(b"old")
    os.chmod(dest, 0o666)
    private.copy(source, dest)
    assert dest.read_bytes() == b"bytes" and mode(dest) == 0o600 and mode(source) == 0o644


def test_private_writes_do_not_change_what_write_text_does_for_other_files(tmp_path, loose_umask):
    plain = tmp_path / "plain.txt"
    store.write_text(plain, "a")
    assert mode(plain) == 0o644
    secret = tmp_path / "secret.txt"
    store.write_text(secret, "a", private=True)
    assert mode(secret) == 0o600
    os.chmod(plain, 0o644)
    store.write_text(plain, "b", private=True)
    assert mode(plain) == 0o600 and plain.read_text() == "b"
    assert sorted(p.name for p in tmp_path.iterdir()) == ["plain.txt", "secret.txt"]


def test_the_note_s_terminal_is_started_with_a_umask_of_077(monkeypatch, tmp_path):
    from pwn_broker import notewindow

    seen = {}

    def popen(argv, **kwargs):
        seen.update(kwargs)

    monkeypatch.setattr(notewindow.subprocess, "Popen", popen)
    notewindow._spawn(["xterm", "-e", "vim"], tmp_path)
    assert seen["umask"] == 0o077


def test_a_real_child_of_that_spawn_makes_its_files_for_the_owner_alone(
    tmp_path, loose_umask, monkeypatch
):
    from pwn_broker import notewindow

    made = tmp_path / "made"
    started = []
    real = notewindow.subprocess.Popen
    monkeypatch.setattr(
        notewindow.subprocess, "Popen", lambda *a, **k: started.append(real(*a, **k))
    )
    notewindow._spawn(["sh", "-c", 'echo x > "$1"', "sh", str(made)], tmp_path)
    assert started[0].wait(timeout=30) == 0
    assert mode(made) == 0o600



# ---- wrapped/ from the moment it is made


def test_setup_makes_wrapped_for_the_owner_alone(paths, loose_umask):
    from pwn_broker import setup

    setup.install_data(paths)
    assert mode(paths.wrapped) == 0o700 and mode(paths.active) == 0o755
    os.chmod(paths.wrapped, 0o755)
    setup.install_data(paths)
    assert mode(paths.wrapped) == 0o700


def test_the_launch_check_makes_wrapped_for_the_owner_alone(paths, loose_umask):
    from pwn_broker import checks

    env = {"DISPLAY": ":0", "PATH": f"{paths.bin}{os.pathsep}/usr/bin"}
    results = checks.run_checks(
        paths, Settings(), env, which=lambda name: "/usr/bin/" + name, tunnel=lambda: None
    )
    assert ("folders", "ok") in [(r.name, r.status) for r in results]
    assert mode(paths.wrapped) == 0o700 and mode(paths.active) == 0o755


def test_a_file_where_wrapped_goes_is_still_said_by_the_launch_check(paths, loose_umask):
    from pwn_broker import checks

    paths.home.mkdir(parents=True)
    paths.wrapped.write_text("in the way")
    env = {"DISPLAY": ":0", "PATH": f"{paths.bin}{os.pathsep}/usr/bin"}
    results = checks.run_checks(
        paths, Settings(), env, which=lambda name: "/usr/bin/" + name, tunnel=lambda: None
    )
    (folders,) = [r for r in results if r.name == "folders"]
    assert folders.status == "warn" and str(paths.wrapped) in folders.message
