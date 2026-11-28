"""export packs what is there: a file something is still writing to goes in as it is when the
pack reaches it, and the manifest is written from what went in."""

import hashlib
import os
import sys
import tarfile
import time
import tomllib
from pathlib import Path

import pytest

from helpers import NOW
from pwn_broker import archive, lifecycle, scanning, serving
from pwn_broker.archive import MANIFEST, ArchiveError, Packed, Shrunk, pack, verify
from pwn_broker.config import Settings
from pwn_broker.console import FakeConsole
from pwn_broker.filescan import packed_records
from pwn_broker.lifecycle import export_box, finish_box, import_box
from pwn_broker.model import FileRecord
from pwn_broker.paths import AppPaths
from pwn_broker.shell import cmd_scan
from pwn_broker.shell.commands import dispatch
from pwn_broker.store import load_files

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="a forked runner and a shell script need Linux")

NOFIX = dict(fix=lambda path: 0)
SCAN = "targets/dc01/scans/full.nmap"
FIRST = b"# Nmap scan report\n22/tcp open ssh\n"
MORE = b"80/tcp open http\n445/tcp open microsoft-ds\n"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def put(session, rel: str, data: bytes):
    path = session.box.path / rel
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)
    return path


def packed_bytes(dest) -> dict[str, bytes]:
    """Each file in the archive, by its path in the box."""
    found = {}
    with tarfile.open(dest) as tar:
        for member in tar.getmembers():
            if member.isreg():
                found[member.name.split("/", 1)[1]] = tar.extractfile(member).read()
    return found


def manifest_of(dest) -> dict:
    return tomllib.loads(packed_bytes(dest)[MANIFEST].decode("utf-8"))


def listed(dest) -> dict[str, dict]:
    return {row["path"]: row for row in manifest_of(dest)["file"]}


def assert_manifest_is_the_archive(dest) -> None:
    """Every file the manifest lists is in the archive with that size and SHA-256, and every
    file of the box that is in the archive is listed."""
    verify(dest)
    files, rows = packed_bytes(dest), listed(dest)
    for path, row in rows.items():
        assert (row["size"], row["sha256"]) == (len(files[path]), sha(files[path])), path
    unlisted = set(files) - set(rows)
    assert unlisted <= {MANIFEST, "files.toml", ".history"}, unlisted


def between_scan_and_pack(monkeypatch, change):
    """Runs `change` after the box has been read for its records and before a file is packed:
    where a scan in the background writes."""
    real = lifecycle.pack

    def later(box, dest, **kwargs):
        change()
        return real(box, dest, **kwargs)

    monkeypatch.setattr(lifecycle, "pack", later)


def lines(session, kind):
    return [text for k, text in session.console.lines if k == kind]


# ---- a file that changes between the reading of the box and the pack


def test_a_file_that_grew_since_the_box_was_read_is_packed_as_it_is(session, monkeypatch):
    path = put(session, SCAN, FIRST)
    between_scan_and_pack(monkeypatch, lambda: path.write_bytes(FIRST + MORE))
    dest = export_box(session, **NOFIX)
    assert dest is not None and lines(session, "fail") == []
    assert packed_bytes(dest)[SCAN] == FIRST + MORE
    row = listed(dest)[SCAN]
    assert (row["size"], row["sha256"]) == (len(FIRST + MORE), sha(FIRST + MORE))
    assert_manifest_is_the_archive(dest)


def test_a_file_written_over_at_the_same_length_is_listed_as_it_was_packed(session, monkeypatch):
    path = put(session, SCAN, b"A" * 64)
    between_scan_and_pack(monkeypatch, lambda: path.write_bytes(b"B" * 64))
    dest = export_box(session, **NOFIX)
    assert listed(dest)[SCAN]["sha256"] == sha(b"B" * 64)
    assert_manifest_is_the_archive(dest)


def test_a_file_that_got_shorter_since_the_box_was_read_is_packed_as_it_is(session, monkeypatch):
    path = put(session, SCAN, FIRST + MORE)
    between_scan_and_pack(monkeypatch, lambda: path.write_bytes(FIRST))
    dest = export_box(session, **NOFIX)
    assert packed_bytes(dest)[SCAN] == FIRST and listed(dest)[SCAN]["size"] == len(FIRST)
    assert_manifest_is_the_archive(dest)


def test_a_file_removed_since_the_box_was_read_is_in_neither(session, monkeypatch):
    path = put(session, SCAN, FIRST)
    put(session, "targets/dc01/loot/kept.txt", b"kept")
    between_scan_and_pack(monkeypatch, path.unlink)
    dest = export_box(session, **NOFIX)
    assert dest is not None and lines(session, "fail") == []
    assert SCAN not in packed_bytes(dest) and SCAN not in listed(dest)
    assert "targets/dc01/loot/kept.txt" in listed(dest)
    assert_manifest_is_the_archive(dest)


def test_a_file_made_since_the_box_was_read_is_in_both(session, monkeypatch):
    between_scan_and_pack(monkeypatch, lambda: put(session, SCAN, FIRST))
    dest = export_box(session, **NOFIX)
    row = listed(dest)[SCAN]
    assert (row["size"], row["sha256"], row["target"]) == (len(FIRST), sha(FIRST), "dc01")
    # first seen when it was packed: the box's own record had not met it yet
    assert row["first_seen"] == session.clock()
    assert_manifest_is_the_archive(dest)


def test_a_file_that_grows_while_it_is_read_is_packed_as_long_as_it_was_when_opened(
    session, monkeypatch
):
    path = put(session, SCAN, FIRST)
    real = archive._Head.read
    grown = []

    def read(self, n=-1):
        if not grown and Path(self._fh.name) == path:
            grown.append(True)
            with open(path, "ab") as fh:
                fh.write(MORE)
        return real(self, n)

    monkeypatch.setattr(archive._Head, "read", read)
    dest = export_box(session, **NOFIX)
    assert grown and path.read_bytes() == FIRST + MORE
    # what was there when the pack reached it, whole, and listed as that
    assert packed_bytes(dest)[SCAN] == FIRST
    assert listed(dest)[SCAN]["sha256"] == sha(FIRST)
    assert_manifest_is_the_archive(dest)


def test_the_manifest_is_the_last_thing_in_the_archive_and_is_there_once(session):
    put(session, SCAN, FIRST)
    export_box(session, **NOFIX)
    # a second export finds the first one's manifest.toml in the box
    dest = export_box(session, **NOFIX)
    with tarfile.open(dest) as tar:
        names = [m.name.split("/", 1)[-1] for m in tar.getmembers() if "/" in m.name]
    assert names.count(MANIFEST) == 1 and names[-1] == MANIFEST
    assert (session.box.path / MANIFEST).read_bytes() == packed_bytes(dest)[MANIFEST]


def test_what_the_manifest_never_lists_is_still_not_listed(session):
    (session.box.path / ".history").write_text("+status\n")
    dest = export_box(session, **NOFIX)
    rows = listed(dest)
    assert {".history", "files.toml", MANIFEST} & set(rows) == set()
    assert {"box.toml", "notes.md"} <= set(rows) and ".history" in packed_bytes(dest)


def test_the_box_s_own_record_of_its_files_is_left_as_the_scan_wrote_it(session, monkeypatch):
    # files.toml is the box as it was last read; the next command reads the grown file again
    path = put(session, SCAN, FIRST)
    between_scan_and_pack(monkeypatch, lambda: path.write_bytes(FIRST + MORE))
    export_box(session, **NOFIX)
    kept = {r.path: r for r in load_files(session.box)}
    assert kept[SCAN].size == len(FIRST)


# ---- a file that gets shorter while it is read


def halved_when_read(monkeypatch, path, times):
    """The file loses its second half between its header being written and its first byte being
    read, the first `times` times it is packed; returns the lengths it had each time."""
    real = archive._Head.read
    had = []

    def read(self, n=-1):
        if Path(self._fh.name) == path and len(had) < times and self._fh.tell() == 0:
            had.append(os.path.getsize(path))
            os.truncate(path, had[-1] // 2)
        return real(self, n)

    monkeypatch.setattr(archive._Head, "read", read)
    return had


def test_a_file_that_gets_shorter_while_it_is_read_starts_the_pack_again(session, monkeypatch):
    path = put(session, SCAN, os.urandom(300_000))
    had = halved_when_read(monkeypatch, path, times=1)
    dest = export_box(session, **NOFIX)
    assert had == [300_000] and dest is not None and lines(session, "fail") == []
    assert len(packed_bytes(dest)[SCAN]) == 150_000
    assert_manifest_is_the_archive(dest)
    assert not list(session.paths.wrapped.glob("*.part"))


def test_a_file_that_keeps_getting_shorter_fails_the_export_and_names_it(session, monkeypatch):
    path = put(session, SCAN, os.urandom(300_000))
    had = halved_when_read(monkeypatch, path, times=5)
    assert export_box(session, **NOFIX) is None
    # tried twice, and not a third time
    assert had == [300_000, 150_000]
    assert lines(session, "fail") == [f"export failed: {SCAN} got shorter while it was being packed"]
    assert not list(session.paths.wrapped.glob("*"))


# ---- pack itself


def test_pack_gives_the_manifest_writer_what_went_in(session, tmp_path):
    put(session, SCAN, FIRST)
    box = session.box
    seen = {}

    def manifest(packed):
        seen.update(packed)
        records = packed_records([], packed, now=NOW)
        archive.write_manifest(box, records, kind="exported", now=NOW)

    dest = tmp_path / "out.tar.gz"
    assert pack(box, dest, manifest=manifest) == []
    took = seen[SCAN]
    assert isinstance(took, Packed) and (took.size, took.sha256) == (len(FIRST), sha(FIRST))
    assert took.mtime == os.stat(box.path / SCAN).st_mtime
    # folders are not files, and the manifest it writes is not in what it is given
    assert "targets" not in seen and MANIFEST not in seen
    verify(dest)


def test_pack_without_a_manifest_writer_packs_the_manifest_that_is_there(session, tmp_path):
    put(session, SCAN, FIRST)
    box = session.box
    records = [FileRecord(SCAN, "dc01", NOW, len(FIRST), 0.0, sha(FIRST))]
    archive.write_manifest(box, records, kind="exported", now=NOW)
    dest = tmp_path / "out.tar.gz"
    pack(box, dest)
    assert list(listed(dest)) == [SCAN] and listed(dest)[SCAN]["size"] == len(FIRST)
    # and is held to it: the file as it is now is not the file that manifest lists
    (box.path / SCAN).write_bytes(FIRST + MORE)
    with pytest.raises(ArchiveError, match="size differs from the manifest"):
        pack(box, dest)


def test_a_manifest_writer_that_fails_leaves_no_archive(session, tmp_path):
    def manifest(packed):
        raise OSError("disk full")

    dest = tmp_path / "out.tar.gz"
    with pytest.raises(ArchiveError, match="disk full"):
        pack(session.box, dest, manifest=manifest)
    assert list(tmp_path.glob("out*")) == []


def test_shrunk_is_an_archive_error():
    assert issubclass(Shrunk, ArchiveError)


def test_packed_records_keep_first_seen_and_take_the_packed_size_hash_and_time():
    old = FileRecord("targets/dc01/scans/a.nmap", "dc01", NOW, 5, 1.0, "aa" * 32)
    gone = FileRecord("targets/dc01/scans/gone.nmap", "dc01", NOW, 5, 1.0, "bb" * 32)
    later = NOW.replace(hour=13)
    packed = {
        "targets/dc01/scans/a.nmap": Packed(9, "cc" * 32, 2.0),
        "loot.txt": Packed(1, "dd" * 32, 3.0),
        "files.toml": Packed(1, "ee" * 32, 3.0),
        ".history": Packed(1, "ee" * 32, 3.0),
        "manifest.toml": Packed(1, "ee" * 32, 3.0),
    }
    assert packed_records([old, gone], packed, now=later) == [
        FileRecord("loot.txt", "", later, 1, 3.0, "dd" * 32),
        FileRecord("targets/dc01/scans/a.nmap", "dc01", NOW, 9, 2.0, "cc" * 32),
    ]


# ---- finish


def test_finish_writes_its_manifest_from_what_it_packed_too(session, monkeypatch):
    path = put(session, "targets/dc01/loot/tool-output.txt", FIRST)
    between_scan_and_pack(monkeypatch, lambda: path.write_bytes(FIRST + MORE))
    session.console = FakeConsole(["y", "y"])
    dest = finish_box(session, fix=lambda p: 0, unsaved=lambda box: False, close=lambda p, b: False)
    assert dest is not None
    assert_manifest_is_the_archive(dest)
    assert packed_bytes(dest)["targets/dc01/loot/tool-output.txt"] == FIRST + MORE
    # nothing changed after the archive was made, so the folder went
    assert not session.box.path.exists()


def test_finish_keeps_the_folder_when_a_file_grew_after_it_was_packed(session, monkeypatch):
    path = put(session, "targets/dc01/loot/tool-output.txt", FIRST)
    real = lifecycle.pack

    def then_more(box, dest, **kwargs):
        found = real(box, dest, **kwargs)
        with open(path, "ab") as fh:
            fh.write(MORE)
        return found

    monkeypatch.setattr(lifecycle, "pack", then_more)
    session.console = FakeConsole(["y", "y"])
    dest = finish_box(session, fix=lambda p: 0, unsaved=lambda box: False, close=lambda p, b: False)
    assert packed_bytes(dest)["targets/dc01/loot/tool-output.txt"] == FIRST
    assert lines(session, "warn") == [
        "targets/dc01/loot/tool-output.txt changed after the archive was made; the folder was kept"
    ]
    assert path.read_bytes() == FIRST + MORE


# ---- a scan still running: the export says so, on screen and in the archive


@pytest.fixture
def scan_hooks(monkeypatch):
    """The two hooks a scan has in an export and a finish, and none of the others."""
    monkeypatch.setattr(lifecycle, "RUNNING_HOOKS", [cmd_scan.still_running])
    monkeypatch.setattr(lifecycle, "BLOCK_HOOKS", [cmd_scan.block])


@pytest.fixture
def scanning_dc01(session, system, scan_hooks):
    system.programs["nmap"] = "/usr/bin/nmap"
    dispatch(session, "scan full")
    session.console = FakeConsole()
    return session


def test_an_export_while_a_scan_runs_says_which_and_writes_it_into_the_manifest(scanning_dc01):
    session = scanning_dc01
    dest = export_box(session, **NOFIX)
    assert dest is not None
    assert lines(session, "warn") == [
        "a scan is still running: dc01 (full); the export holds its files as they are now"
    ]
    assert manifest_of(dest)["running_scans"] == [
        {"target": "dc01", "plan": "full", "started": session.clock()}
    ]
    assert_manifest_is_the_archive(dest)


def test_two_scans_are_both_named(scanning_dc01):
    session = scanning_dc01
    session.console = FakeConsole(["10.10.10.5", "", "", "web01"])
    dispatch(session, "target add")
    dispatch(session, "target use web01")
    dispatch(session, "scan")
    session.console = FakeConsole()
    dest = export_box(session, **NOFIX)
    assert lines(session, "warn") == [
        "scans are still running: dc01 (full), web01 (quick then full); "
        "the export holds its files as they are now"
    ]
    assert [(r["target"], r["plan"]) for r in manifest_of(dest)["running_scans"]] == [
        ("dc01", "full"), ("web01", "quick then full"),
    ]  # fmt: skip


def test_an_export_with_no_scan_running_says_nothing_and_its_manifest_has_no_such_key(
    session, scan_hooks
):
    dest = export_box(session, **NOFIX)
    assert lines(session, "warn") == [] and "running_scans" not in manifest_of(dest)
    assert list(manifest_of(dest)) == ["schema", "kind", "packed", "box", "file"]


def test_finish_still_refuses_while_a_scan_runs(scanning_dc01):
    session = scanning_dc01
    assert finish_box(session, fix=lambda p: 0, unsaved=lambda box: False) is None
    assert lines(session, "fail") == [
        "a scan is still running: dc01 (full). wait for it or scan stop, then finish again"
    ]
    assert session.console.asked == [] and not session.paths.wrapped.exists()


def test_import_says_the_archive_was_made_while_a_scan_ran(scanning_dc01, tmp_path):
    session = scanning_dc01
    dest = export_box(session, **NOFIX)
    paths = AppPaths(opt=tmp_path / "opt2", home=tmp_path / "home2")
    console = FakeConsole()
    box = import_box(paths, Settings(), console, dest, lambda: NOW)
    assert box is not None
    assert [t for k, t in console.lines if k == "warn"] == [
        "this archive was made while a scan was still running: dc01 (full); "
        "its files hold what the scan had written by then"
    ]


def test_import_of_an_archive_made_with_no_scan_says_nothing_of_one(session, tmp_path):
    dest = export_box(session, **NOFIX)
    paths = AppPaths(opt=tmp_path / "opt2", home=tmp_path / "home2")
    console = FakeConsole()
    assert import_box(paths, Settings(), console, dest, lambda: NOW) is not None
    assert [t for k, t in console.lines if k == "warn"] == []


@pytest.mark.parametrize(
    "text",
    [
        "running_scans = 3\n",
        'running_scans = ["dc01"]\n',
        '[[running_scans]]\ntarget = "dc01"\n',
        '[[running_scans]]\ntarget = 7\nplan = "full"\n',
        '[[running_scans]]\ntarget = "../x"\nplan = "full"\n',
        '[[running_scans]]\ntarget = "dc01"\nplan = "full; rm -rf"\n',
        '[[running_scans]]\ntarget = "dc01"\nplan = "\\u001b[2Jfull"\n',
        "not toml [",
    ],
)
def test_a_list_of_scans_that_is_not_as_the_app_writes_it_is_not_repeated(tmp_path, text):
    (tmp_path / MANIFEST).write_text(text, encoding="utf-8")
    assert archive.running_scans(tmp_path) == []
    assert archive.running_scans(tmp_path / "missing") == []


def test_many_scans_in_a_manifest_are_cut_short(tmp_path):
    rows = "".join(f'[[running_scans]]\ntarget = "t{n}"\nplan = "full"\n' for n in range(40))
    (tmp_path / MANIFEST).write_text(rows, encoding="utf-8")
    console = FakeConsole()
    box = type("B", (), {"path": tmp_path})()
    lifecycle._say_running_scans(console, box)
    ((kind, said),) = console.lines
    assert kind == "warn" and said.count("(full)") == 10 and "t9 (full) and 30 more; its files" in said
    assert said.startswith("this archive was made while scans were still running: t0 (full), ")


# ---- a real scan runner, with a stand-in nmap that goes on writing


SLOW_NMAP = """#!/bin/sh
base=""; prev=""
for a in "$@"; do
  if [ "$prev" = "-oA" ]; then base="$a"; fi
  prev="$a"
done
echo "# Nmap scan" > "$base.nmap"
echo started > "$(dirname "$base")/started"
n=0
while [ ! -e "$(dirname "$base")/stop" ]; do
  n=$((n + 1))
  echo "$n/tcp open  service-$n  a line as long as one nmap writes for a port it has found" >> "$base.nmap"
  # some hundreds of lines a second: always writing, and never a file too large to pack quickly
  sleep 0.002
done
printf 'Host: 10.10.10.161 ()\\tPorts: 22/open/tcp//ssh///\\n' > "$base.gnmap"
echo '<nmaprun/>' > "$base.xml"
"""


@posix_only
def test_an_export_while_a_real_scan_writes_its_file_verifies_and_is_listed_as_packed(
    session, tmp_path, scan_hooks
):
    # the real process table: the session's stand-ins know no real process
    session.pid_alive, session.pid_started = scanning.pid_alive, scanning.process_start
    session.cmdline = serving.process_cmdline
    nmap = tmp_path / "nmap"
    nmap.write_text(SLOW_NMAP)
    nmap.chmod(0o755)
    flags = {m: scanning.parse_flags(scanning.DEFAULT_FLAGS[m], m) for m in scanning.MODES}
    scans = session.box.path / "targets" / "dc01" / "scans"
    # packed before the scan's file, and slow to pack: the scan writes on while it goes in
    put(session, "targets/dc01/loot/big.bin", os.urandom(6 * 1024 * 1024))
    marker = scanning.start(
        session.paths, session.box, session.current, ["full"], nmap=str(nmap), flags=flags,
        clock=lambda: NOW,
    )  # fmt: skip
    try:
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and not (scans / "started").exists():
            time.sleep(0.05)
        (growing,) = scans.glob("*.nmap")
        rel = growing.relative_to(session.box.path).as_posix()
        for _ in range(3):
            before = growing.stat().st_size
            session.console = FakeConsole()
            dest = export_box(session, **NOFIX)
            after = growing.stat().st_size
            assert dest is not None, session.console.lines
            assert_manifest_is_the_archive(dest)
            row = listed(dest)[rel]
            # it went on growing while the box was packed: the archive holds it as long as
            # it was when the pack reached it, which is longer than when the export began
            assert before < row["size"] <= after
            packed = packed_bytes(dest)[rel]
            assert packed.startswith(b"# Nmap scan\n") and len(packed) == row["size"]
            assert sha(packed) == row["sha256"]
        assert any("a scan is still running: dc01 (full)" in t for t in lines(session, "warn"))
        assert [(r["target"], r["plan"]) for r in manifest_of(dest)["running_scans"]] == [("dc01", "full")]
    finally:
        (scans / "stop").write_text("")
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline and scanning.pid_alive(marker.pid):
            time.sleep(0.05)
        if scanning.pid_alive(marker.pid):
            scanning.stop(session.paths, session.box.id, "dc01")
