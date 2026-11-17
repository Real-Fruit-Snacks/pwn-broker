import gzip
import hashlib
import io
import os
import shutil
import sys
import tarfile
from dataclasses import replace as dc_replace

import pytest
import tomli_w

from helpers import NOW, odd_name
from pwn_broker import archive
from pwn_broker.archive import (
    ArchiveError,
    archive_path,
    copy_out,
    pack,
    peek_folder,
    unpack,
    verify,
    write_manifest,
)
from pwn_broker.filescan import scan, sha256_file
from pwn_broker.model import FileRecord
from pwn_broker.store import load_box, read_toml, save_files

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="needs symlinks and FIFOs")


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def record(path: str, data: bytes, **overrides) -> FileRecord:
    values = dict(path=path, target="", first_seen=NOW, size=len(data), mtime=0.0, sha256=sha(data))
    values.update(overrides)
    return FileRecord(**values)


def add_bytes(tar: tarfile.TarFile, name: str, data: bytes) -> None:
    info = tarfile.TarInfo(name)
    info.size = len(data)
    tar.addfile(info, io.BytesIO(data))


def add_dir(tar: tarfile.TarFile, name: str) -> None:
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    tar.addfile(info)


def manifest_bytes(records: list[FileRecord]) -> bytes:
    rows = [
        {"path": r.path, "size": r.size, "sha256": r.sha256, "target": r.target, "mtime": r.mtime,
         "first_seen": r.first_seen}
        for r in records
    ]  # fmt: skip
    return tomli_w.dumps({"schema": 1, "kind": "exported", "packed": NOW, "file": rows}).encode()


def hand_archive(dest, files, listed=None, top="b", manifest=True):
    # `listed` overrides what the manifest claims, so a test can make it lie
    listed = listed if listed is not None else [record(p, d) for p, d in files.items()]
    with tarfile.open(dest, "w:gz") as tar:
        add_dir(tar, top)
        if manifest:
            add_bytes(tar, f"{top}/manifest.toml", manifest_bytes(listed))
        for path, data in files.items():
            add_bytes(tar, f"{top}/{path}", data)
    return dest


def raw_archive(dest, build):
    with tarfile.open(dest, "w:gz") as tar:
        build(tar)
    return dest


def member_names(path):
    with tarfile.open(path, "r:gz") as tar:
        return tar.getnames()


def inside(path):
    return {n.split("/", 1)[1] for n in member_names(path) if "/" in n}


def raising(exc):
    def fail(*args, **kwargs):
        raise exc

    return fail


@pytest.fixture
def filled(box):
    (box.path / "notes.md").write_text("hello")
    (box.path / "targets/dc01/loot").mkdir(parents=True)
    (box.path / "targets/dc01/loot/SAM.bak").write_bytes(b"\x00\x01binary")
    records = scan(box, [], now=NOW)
    save_files(box, records)
    write_manifest(box, records, kind="exported", now=NOW)
    return box


def part_of(dest):
    return dest.with_name(dest.name + ".part")


# --- manifest ---


def test_archive_path(paths, box):
    assert archive_path(paths, box, "finished") == paths.wrapped / "2026-11-14_htb_forest.finished.tar.gz"
    assert archive_path(paths, box, "exported").name == "2026-11-14_htb_forest.exported.tar.gz"


def test_manifest_contents(box):
    records = [record("a.txt", b"a"), record("targets/dc01/x", b"xx", target="dc01")]
    path = write_manifest(box, records, kind="exported", now=NOW)
    m = read_toml(path)
    assert path == box.path / "manifest.toml"
    assert m["schema"] == 1 and m["kind"] == "exported" and m["packed"] == NOW
    assert m["box"]["id"] == box.id and m["box"]["name"] == "forest"
    assert {m["box"][k] for k in ("platform", "os", "difficulty")} == {"htb", "windows", "easy"}
    assert m["box"]["started"] == NOW and "finished" not in m["box"]
    assert {f["path"] for f in m["file"]} == {r.path for r in records}


def test_manifest_records_finished_when_set(box):
    done = dc_replace(box, finished=NOW)
    m = read_toml(write_manifest(done, [], kind="finished", now=NOW))
    assert m["box"]["finished"] == NOW


# --- pack and verify ---


def test_pack_then_verify(filled, tmp_path):
    dest = tmp_path / "out" / "forest.tar.gz"
    assert pack(filled, dest) == []
    assert dest.is_file() and not part_of(dest).exists()
    verify(dest)
    assert peek_folder(dest) == filled.path.name


def test_pack_members_sorted_under_one_folder(filled, tmp_path):
    dest = tmp_path / "forest.tar.gz"
    pack(filled, dest)
    names = member_names(dest)
    top = filled.path.name
    assert names == sorted(names)
    assert names[0] == top
    assert all(n == top or n.startswith(top + "/") for n in names)
    assert {f"{top}/manifest.toml", f"{top}/files.toml", f"{top}/targets/dc01/loot/SAM.bak"} <= set(names)
    assert not any("\\" in n for n in names)


def test_pack_leaves_out_only_the_apps_transient_files(filled, tmp_path):
    transient = (".note-state", ".notes.md.swp", ".notes.md.swo", ".pwn-broker-k3j9.tmp")
    for name in transient:
        (filled.path / name).write_text("junk")
    (filled.path / "targets/dc01/loot/.pwn-broker-a1b2.tmp").write_text("junk")
    kept = (".history", ".a.swp", "x.part", "x.tmp", "backup~", "targets/dc01/.note-state",
            "targets/dc01/.notes.md.swp")  # fmt: skip
    for rel in kept:
        (filled.path / rel).write_text("kept")
    dest = tmp_path / "forest.tar.gz"
    pack(filled, dest)
    names = inside(dest)
    assert names.isdisjoint(transient) and "targets/dc01/loot/.pwn-broker-a1b2.tmp" not in names
    assert {"notes.md", "files.toml", "manifest.toml", *kept} <= names


LOOT_NAMES = (".index.php.swp", "config.php~", "backup.tmp", "x.part", "files.toml")


def test_loot_with_common_names_is_packed_listed_and_verified(box, tmp_path):
    loot = box.path / "targets/dc01/loot"
    loot.mkdir(parents=True)
    for name in LOOT_NAMES:
        (loot / name).write_bytes(f"loot {name}".encode())
    records = scan(box, [], now=NOW)
    save_files(box, records)
    write_manifest(box, records, kind="exported", now=NOW)
    dest = tmp_path / "forest.tar.gz"
    pack(box, dest)
    verify(dest)
    wanted = {f"targets/dc01/loot/{n}" for n in LOOT_NAMES}
    assert wanted <= {r.path for r in records}
    assert wanted <= inside(dest)
    assert wanted <= {f["path"] for f in read_toml(box.path / "manifest.toml")["file"]}


@posix_only
def test_pack_leaves_out_links_and_special_files(filled, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret").write_text("s")
    (filled.path / "link").symlink_to(outside / "secret")
    (filled.path / "dirlink").symlink_to(outside)
    os.mkfifo(filled.path / "pipe")
    (filled.path / "targets/dc01/loot/deep").symlink_to(outside / "secret")
    (filled.path / ".pwn-broker-x.tmp").symlink_to(outside / "secret")
    dest = tmp_path / "forest.tar.gz"
    left_out = pack(filled, dest)
    assert inside(dest).isdisjoint({"link", "dirlink", "dirlink/secret", "pipe", "targets/dc01/loot/deep"})
    verify(dest)
    assert left_out == ["dirlink", "link", "pipe", "targets/dc01/loot/deep"]


def test_pack_replaces_an_existing_archive(filled, tmp_path):
    dest = tmp_path / "forest.tar.gz"
    dest.write_bytes(b"old")
    pack(filled, dest)
    verify(dest)


def test_pack_leaves_nothing_on_failure(filled, tmp_path, monkeypatch):
    dest = tmp_path / "forest.tar.gz"
    monkeypatch.setattr(archive, "verify", raising(ArchiveError("boom")))
    with pytest.raises(ArchiveError, match="boom"):
        pack(filled, dest)
    assert not dest.exists() and not part_of(dest).exists()


def test_failed_pack_keeps_the_previous_archive(filled, tmp_path, monkeypatch):
    dest = tmp_path / "forest.tar.gz"
    dest.write_bytes(b"previous")
    monkeypatch.setattr(archive, "verify", raising(ArchiveError("boom")))
    with pytest.raises(ArchiveError):
        pack(filled, dest)
    assert dest.read_bytes() == b"previous"
    assert not part_of(dest).exists()


def test_pack_wraps_other_errors_with_the_cause(filled, tmp_path, monkeypatch):
    dest = tmp_path / "forest.tar.gz"
    cause = RuntimeError("odd")
    monkeypatch.setattr(archive, "verify", raising(cause))
    with pytest.raises(ArchiveError) as caught:
        pack(filled, dest)
    assert caught.value.__cause__ is cause
    assert not dest.exists() and not part_of(dest).exists()


def test_pack_interrupt_cleans_up_and_is_not_wrapped(filled, tmp_path, monkeypatch):
    dest = tmp_path / "forest.tar.gz"
    monkeypatch.setattr(archive, "verify", raising(KeyboardInterrupt()))
    with pytest.raises(KeyboardInterrupt):
        pack(filled, dest)
    assert not dest.exists() and not part_of(dest).exists()


def test_pack_missing_box_folder(box, tmp_path):
    shutil.rmtree(box.path)
    dest = tmp_path / "forest.tar.gz"
    with pytest.raises(ArchiveError):
        pack(box, dest)
    assert not dest.exists() and not part_of(dest).exists()


def test_pack_without_a_manifest_does_not_produce_an_archive(box, tmp_path):
    dest = tmp_path / "forest.tar.gz"
    with pytest.raises(ArchiveError, match="manifest"):
        pack(box, dest)
    assert not dest.exists() and not part_of(dest).exists()


def test_verify_detects_changed_and_missing_files(tmp_path):
    good = {"a.txt": b"alpha", "d/b.txt": b"beta"}
    wrong_sum = hand_archive(
        tmp_path / "sum.tar.gz", good,
        [record("a.txt", b"alpha"), record("d/b.txt", b"beta", sha256=sha(b"other"))],
    )  # fmt: skip
    with pytest.raises(ArchiveError, match=r"d/b\.txt"):
        verify(wrong_sum)
    wrong_size = hand_archive(
        tmp_path / "size.tar.gz", good,
        [record("a.txt", b"alpha", size=99), record("d/b.txt", b"beta")],
    )  # fmt: skip
    with pytest.raises(ArchiveError, match=r"a\.txt"):
        verify(wrong_size)
    listed = [*(record(p, d) for p, d in good.items()), record("lost.txt", b"x")]
    with pytest.raises(ArchiveError, match=r"lost\.txt"):
        verify(hand_archive(tmp_path / "gone.tar.gz", good, listed))
    verify(hand_archive(tmp_path / "ok.tar.gz", good))


def test_verify_rejects_empty_checksum(tmp_path):
    listed = [record("a.txt", b"alpha", sha256="")]
    arc = hand_archive(tmp_path / "a.tar.gz", {"a.txt": b"alpha"}, listed)
    with pytest.raises(ArchiveError, match=r"a\.txt"):
        verify(arc)


def test_verify_requires_a_manifest(tmp_path):
    arc = hand_archive(tmp_path / "a.tar.gz", {"a.txt": b"alpha"}, manifest=False)
    with pytest.raises(ArchiveError, match="manifest"):
        verify(arc)


def test_verify_rejects_unreadable_manifest(tmp_path):
    def build(tar):
        add_dir(tar, "b")
        add_bytes(tar, "b/manifest.toml", b"= not toml")

    with pytest.raises(ArchiveError, match="manifest"):
        verify(raw_archive(tmp_path / "a.tar.gz", build))


def test_verify_ignores_a_manifest_in_a_subfolder(tmp_path):
    arc = raw_archive(tmp_path / "a.tar.gz", lambda t: add_bytes(t, "b/sub/manifest.toml", manifest_bytes([])))
    with pytest.raises(ArchiveError, match="manifest"):
        verify(arc)


def test_verify_rejects_things_that_are_not_gzip_tars(tmp_path):
    junk = tmp_path / "junk.tar.gz"
    junk.write_bytes(b"this is not an archive")
    with pytest.raises(ArchiveError):
        verify(junk)
    with pytest.raises(ArchiveError):
        verify(tmp_path / "missing.tar.gz")


def test_verify_rejects_a_truncated_archive(filled, tmp_path):
    dest = tmp_path / "forest.tar.gz"
    pack(filled, dest)
    cut = tmp_path / "cut.tar.gz"
    cut.write_bytes(dest.read_bytes()[: dest.stat().st_size // 2])
    with pytest.raises(ArchiveError):
        verify(cut)


def test_verify_does_not_extract(filled, tmp_path):
    dest = tmp_path / "forest.tar.gz"
    pack(filled, dest)
    before = set(os.listdir(tmp_path))
    verify(dest)
    assert set(os.listdir(tmp_path)) == before


def test_verify_listed_directory_is_not_a_file(tmp_path):
    def build(tar):
        add_dir(tar, "b")
        add_bytes(tar, "b/manifest.toml", manifest_bytes([record("dd", b"")]))
        add_dir(tar, "b/dd")

    with pytest.raises(ArchiveError, match="dd"):
        verify(raw_archive(tmp_path / "a.tar.gz", build))


# --- peek_folder ---


def test_peek_folder_rejects_two_top_level_folders(tmp_path):
    arc = raw_archive(tmp_path / "a.tar.gz", lambda t: (add_bytes(t, "one/a", b"1"), add_bytes(t, "two/a", b"2")))
    with pytest.raises(ArchiveError):
        peek_folder(arc)


@pytest.mark.parametrize("name", [".", "./b", "/b/a", ""])
def test_peek_folder_rejects_odd_names(tmp_path, name):
    def build(tar):
        add_bytes(tar, "b/a", b"1")
        info = tarfile.TarInfo(name)
        info.type = tarfile.DIRTYPE
        tar.addfile(info)

    with pytest.raises(ArchiveError):
        peek_folder(raw_archive(tmp_path / "a.tar.gz", build))


def test_peek_folder_rejects_an_empty_archive(tmp_path):
    with pytest.raises(ArchiveError):
        peek_folder(raw_archive(tmp_path / "a.tar.gz", lambda t: None))


def test_peek_folder_rejects_a_bare_file(tmp_path):
    with pytest.raises(ArchiveError):
        peek_folder(raw_archive(tmp_path / "a.tar.gz", lambda t: add_bytes(t, "loose.txt", b"1")))


# --- unpack ---


def test_unpack_restores_the_box(filled, tmp_path):
    dest = tmp_path / "forest.tar.gz"
    pack(filled, dest)
    active = tmp_path / "elsewhere" / "active"
    folder = unpack(dest, active)
    assert folder == active / filled.path.name
    assert dc_replace(load_box(folder), path=filled.path) == load_box(filled.path)
    for rel in ("notes.md", "targets/dc01/loot/SAM.bak", "files.toml", "manifest.toml"):
        assert (folder / rel).read_bytes() == (filled.path / rel).read_bytes()
    assert os.listdir(active) == [filled.path.name]


def test_unpack_refuses_existing_folder(filled, tmp_path):
    dest = tmp_path / "forest.tar.gz"
    pack(filled, dest)
    active = tmp_path / "active"
    existing = active / filled.path.name
    existing.mkdir(parents=True)
    (existing / "mine.txt").write_text("keep")
    with pytest.raises(ArchiveError, match=filled.path.name):
        unpack(dest, active)
    assert (existing / "mine.txt").read_text() == "keep"
    assert os.listdir(active) == [filled.path.name]


def test_unpack_replace_swaps_the_folder(filled, tmp_path):
    dest = tmp_path / "forest.tar.gz"
    pack(filled, dest)
    active = tmp_path / "active"
    existing = active / filled.path.name
    existing.mkdir(parents=True)
    (existing / "old-only.txt").write_text("old")
    folder = unpack(dest, active, replace=True)
    assert not (folder / "old-only.txt").exists()
    assert (folder / "notes.md").read_text() == "hello"
    assert os.listdir(active) == [filled.path.name]


def test_unpack_replace_keeps_old_folder_when_archive_is_refused(tmp_path):
    def build(tar):
        add_dir(tar, "b")
        add_bytes(tar, "b/ok", b"1")
        add_bytes(tar, "b/../../evil", b"x")

    arc = raw_archive(tmp_path / "a.tar.gz", build)
    active = tmp_path / "active"
    (active / "b").mkdir(parents=True)
    (active / "b/old.txt").write_text("old")
    with pytest.raises(ArchiveError):
        unpack(arc, active, replace=True)
    assert (active / "b/old.txt").read_text() == "old"
    assert os.listdir(active) == ["b"]


def test_unpack_replace_keeps_old_folder_when_extraction_fails(filled, tmp_path, monkeypatch):
    dest = tmp_path / "forest.tar.gz"
    pack(filled, dest)
    active = tmp_path / "active"
    existing = active / filled.path.name
    existing.mkdir(parents=True)
    (existing / "old.txt").write_text("old")
    real = tarfile.TarFile.extractall

    def partial(self, path=".", members=None, **kwargs):
        real(self, path, members=list(self)[:2], **kwargs)
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(tarfile.TarFile, "extractall", partial)
    with pytest.raises(ArchiveError):
        unpack(dest, active, replace=True)
    assert (existing / "old.txt").read_text() == "old"
    assert os.listdir(active) == [filled.path.name]


def test_unpack_replace_without_an_existing_folder_just_unpacks(filled, tmp_path):
    dest = tmp_path / "forest.tar.gz"
    pack(filled, dest)
    folder = unpack(dest, tmp_path / "active", replace=True)
    assert (folder / "notes.md").is_file()


@pytest.mark.parametrize(
    "name",
    ["/etc/passwd", "../evil", "box/../../evil", "box/../evil", "box\\..\\evil", "box\\evil", "C:\\evil"],
)
def test_unpack_refuses_escaping_entries(tmp_path, name):
    def build(tar):
        add_dir(tar, "box")
        add_bytes(tar, "box/fine.txt", b"fine")
        add_bytes(tar, name, b"evil")

    arc = raw_archive(tmp_path / "a.tar.gz", build)
    active = tmp_path / "home" / "active"
    with pytest.raises(ArchiveError):
        unpack(arc, active)
    assert not (tmp_path / "home" / "evil").exists() and not (tmp_path / "evil").exists()
    assert not active.exists() or os.listdir(active) == []


def test_unpack_refuses_escaping_entry_listed_first(tmp_path):
    arc = raw_archive(tmp_path / "a.tar.gz", lambda t: add_bytes(t, "../evil", b"evil"))
    with pytest.raises(ArchiveError):
        unpack(arc, tmp_path / "home" / "active")
    assert not (tmp_path / "home" / "evil").exists()


@pytest.mark.parametrize(
    "kind,extra",
    [
        (tarfile.SYMTYPE, {"linkname": "/etc/passwd"}),
        (tarfile.SYMTYPE, {"linkname": "../../outside"}),
        (tarfile.SYMTYPE, {"linkname": "sibling"}),
        (tarfile.LNKTYPE, {"linkname": "box/fine.txt"}),
        (tarfile.FIFOTYPE, {}),
        (tarfile.CHRTYPE, {"devmajor": 1, "devminor": 3}),
        (tarfile.BLKTYPE, {"devmajor": 8, "devminor": 0}),
    ],
)
def test_unpack_refuses_links_and_special_members(tmp_path, kind, extra):
    def build(tar):
        add_dir(tar, "box")
        add_bytes(tar, "box/fine.txt", b"fine")
        info = tarfile.TarInfo("box/odd")
        info.type = kind
        for key, value in extra.items():
            setattr(info, key, value)
        tar.addfile(info)

    arc = raw_archive(tmp_path / "a.tar.gz", build)
    active = tmp_path / "active"
    with pytest.raises(ArchiveError, match="odd"):
        unpack(arc, active)
    assert not active.exists()


def test_unpack_refuses_two_top_level_folders(tmp_path):
    arc = raw_archive(tmp_path / "a.tar.gz", lambda t: (add_bytes(t, "one/a", b"1"), add_bytes(t, "two/a", b"2")))
    active = tmp_path / "active"
    with pytest.raises(ArchiveError):
        unpack(arc, active)
    assert not (active / "one").exists() and not (active / "two").exists()


def test_unpack_refuses_a_top_level_file(tmp_path):
    arc = raw_archive(tmp_path / "a.tar.gz", lambda t: add_bytes(t, "box", b"a file, not a folder"))
    with pytest.raises(ArchiveError):
        unpack(arc, tmp_path / "active")


def test_unpack_refuses_a_corrupt_archive_and_leaves_no_temp_folder(tmp_path):
    junk = tmp_path / "junk.tar.gz"
    junk.write_bytes(b"not a tar")
    active = tmp_path / "active"
    active.mkdir()
    with pytest.raises(ArchiveError):
        unpack(junk, active)
    assert os.listdir(active) == []


def test_unpack_needs_data_filter(tmp_path, monkeypatch):
    arc = hand_archive(tmp_path / "a.tar.gz", {"a.txt": b"1"})
    monkeypatch.delattr(tarfile, "data_filter")
    with pytest.raises(ArchiveError, match="Python"):
        unpack(arc, tmp_path / "active")


def test_unpack_cleans_temp_folder_when_the_move_fails(filled, tmp_path, monkeypatch):
    dest = tmp_path / "forest.tar.gz"
    pack(filled, dest)
    active = tmp_path / "active"
    real = os.replace
    top = filled.path.name

    def fail_into_place(src, dst):
        if os.path.basename(dst) == top:
            raise OSError("nope")
        return real(src, dst)

    monkeypatch.setattr(archive.os, "replace", fail_into_place)
    with pytest.raises(ArchiveError):
        unpack(dest, active)
    assert os.listdir(active) == []


# --- copy_out ---


def test_copy_out(filled, tmp_path):
    src = tmp_path / "forest.exported.tar.gz"
    pack(filled, src)
    target = tmp_path / "usb"
    target.mkdir()
    result = copy_out(src, target)
    assert result == target / src.name
    assert sha256_file(result) == sha256_file(src)
    assert os.listdir(target) == [src.name]
    assert src.exists()


def test_copy_out_missing_folder(tmp_path):
    src = tmp_path / "a.tar.gz"
    src.write_bytes(b"x")
    gone = tmp_path / "no-such-usb"
    with pytest.raises(ArchiveError, match="no-such-usb"):
        copy_out(src, gone)
    assert not gone.exists()


def test_copy_out_target_is_a_file(tmp_path):
    src = tmp_path / "a.tar.gz"
    src.write_bytes(b"x")
    notdir = tmp_path / "plainfile"
    notdir.write_text("x")
    with pytest.raises(ArchiveError, match="plainfile"):
        copy_out(src, notdir)


def test_copy_out_disk_full_leaves_no_part_file(tmp_path, monkeypatch):
    src = tmp_path / "a.tar.gz"
    src.write_bytes(b"payload")
    target = tmp_path / "usb"
    target.mkdir()

    def full(s, d, **kwargs):
        with open(d, "wb") as fh:
            fh.write(b"pay")
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(archive.shutil, "copyfile", full)
    with pytest.raises(ArchiveError):
        copy_out(src, target)
    assert os.listdir(target) == []


def test_copy_out_detects_a_bad_copy(tmp_path, monkeypatch):
    src = tmp_path / "a.tar.gz"
    src.write_bytes(b"payload")
    target = tmp_path / "usb"
    target.mkdir()

    def empty_copy(s, d, **kwargs):
        open(d, "wb").close()

    monkeypatch.setattr(archive.shutil, "copyfile", empty_copy)
    with pytest.raises(ArchiveError, match="checksum"):
        copy_out(src, target)
    assert os.listdir(target) == []


def test_copy_out_keeps_an_existing_copy_when_it_fails(tmp_path, monkeypatch):
    src = tmp_path / "a.tar.gz"
    src.write_bytes(b"payload")
    target = tmp_path / "usb"
    target.mkdir()
    (target / "a.tar.gz").write_bytes(b"earlier")
    monkeypatch.setattr(archive.shutil, "copyfile", raising(OSError("x")))
    with pytest.raises(ArchiveError):
        copy_out(src, target)
    assert (target / "a.tar.gz").read_bytes() == b"earlier"
    assert os.listdir(target) == ["a.tar.gz"]


# --- replace rollback ---


@pytest.fixture
def replacing(filled, tmp_path):
    dest = tmp_path / "forest.tar.gz"
    pack(filled, dest)
    active = tmp_path / "active"
    existing = active / filled.path.name
    existing.mkdir(parents=True)
    (existing / "old.txt").write_text("old")
    return dest, active, existing


def fail_move_into(monkeypatch, top, *, times, exc):
    real = os.replace
    calls = []

    def flaky(src, dst):
        if os.path.basename(dst) == top:
            calls.append(src)
            if len(calls) <= times:
                raise exc
        return real(src, dst)

    monkeypatch.setattr(archive.os, "replace", flaky)


def test_replace_restores_old_box_when_the_move_fails(replacing, monkeypatch):
    dest, active, existing = replacing
    fail_move_into(monkeypatch, existing.name, times=1, exc=OSError("nope"))
    with pytest.raises(ArchiveError):
        unpack(dest, active, replace=True)
    assert (existing / "old.txt").read_text() == "old"
    assert os.listdir(active) == [existing.name]


def test_replace_reports_where_the_old_box_is_when_restore_fails(replacing, monkeypatch):
    dest, active, existing = replacing
    fail_move_into(monkeypatch, existing.name, times=2, exc=OSError("nope"))
    with pytest.raises(ArchiveError) as caught:
        unpack(dest, active, replace=True)
    [parked] = [active / n for n in os.listdir(active) if ".replaced-" in n]
    assert str(parked) in str(caught.value)
    assert (parked / "old.txt").read_text() == "old"
    assert not any(n.startswith(".import-") for n in os.listdir(active))


def test_replace_names_the_parked_box_when_the_destination_reappears(replacing, monkeypatch):
    dest, active, existing = replacing
    real = os.replace

    def blocked(src, dst):
        if os.path.basename(dst) == existing.name and ".import-" in os.fspath(src):
            os.mkdir(dst)
            raise OSError("destination is in use")
        return real(src, dst)

    monkeypatch.setattr(archive.os, "replace", blocked)
    with pytest.raises(ArchiveError) as caught:
        unpack(dest, active, replace=True)
    [parked] = [active / n for n in os.listdir(active) if ".replaced-" in n]
    assert str(parked) in str(caught.value)
    assert (parked / "old.txt").read_text() == "old"


def test_replace_restores_old_box_on_interrupt(replacing, monkeypatch):
    dest, active, existing = replacing
    fail_move_into(monkeypatch, existing.name, times=1, exc=KeyboardInterrupt())
    with pytest.raises(KeyboardInterrupt):
        unpack(dest, active, replace=True)
    assert (existing / "old.txt").read_text() == "old"
    assert os.listdir(active) == [existing.name]


def test_replace_success_leaves_no_helper_folders(replacing):
    dest, active, existing = replacing
    unpack(dest, active, replace=True)
    assert os.listdir(active) == [existing.name]


def test_replace_survives_failure_to_delete_the_parked_box(replacing, monkeypatch):
    dest, active, existing = replacing
    monkeypatch.setattr(archive.shutil, "rmtree", lambda *a, **k: None)
    folder = unpack(dest, active, replace=True)
    assert (folder / "notes.md").read_text() == "hello"


# --- malformed manifests, limits, names ---


def toml_archive(tmp_path, text: bytes):
    def build(tar):
        add_dir(tar, "b")
        add_bytes(tar, "b/manifest.toml", text)

    return raw_archive(tmp_path / "m.tar.gz", build)


@pytest.mark.parametrize(
    "body",
    [
        b"file = [1]",
        b'file = ["x"]',
        b'file = "x"',
        b'[[file]]\nsize = 1\nsha256 = "aa"',
        b'[[file]]\npath = "a"\nsize = -1\nsha256 = "aa"',
        b'[[file]]\npath = "a"\nsize = true\nsha256 = "aa"',
        b'[[file]]\npath = "a"\nsize = 1\nsha256 = 5',
        b'[[file]]\npath = 3\nsize = 1\nsha256 = "aa"',
    ],
)
def test_verify_rejects_malformed_manifest_rows(tmp_path, body):
    with pytest.raises(ArchiveError, match="manifest.toml"):
        verify(toml_archive(tmp_path, b"schema = 1\n" + body))


def test_verify_accepts_a_manifest_without_files(tmp_path):
    verify(toml_archive(tmp_path, b"schema = 1\n"))


def test_verify_rejects_an_oversized_manifest(tmp_path, monkeypatch):
    monkeypatch.setattr(archive, "_MANIFEST_LIMIT", 10)
    with pytest.raises(ArchiveError, match="too large"):
        verify(toml_archive(tmp_path, b"schema = 1\n"))


def backslash_archive(tmp_path):
    return hand_archive(tmp_path / "a.tar.gz", {"a\\b.txt": b"data"})


def test_member_check_accepts_a_backslash_where_it_is_a_file_name_character(tmp_path, monkeypatch):
    monkeypatch.setattr(archive, "_backslash_separates", lambda: False)
    with tarfile.open(backslash_archive(tmp_path), "r:gz") as tar:
        for member in tar.getmembers():
            archive._check_member(member)


def test_unpack_refuses_a_backslash_where_it_separates_paths(tmp_path, monkeypatch):
    monkeypatch.setattr(archive, "_backslash_separates", lambda: True)
    active = tmp_path / "active"
    with pytest.raises(ArchiveError, match="outside the destination"):
        unpack(backslash_archive(tmp_path), active)
    assert not active.exists() or os.listdir(active) == []


@posix_only
def test_a_file_name_with_a_backslash_survives_pack_verify_and_unpack(box, tmp_path):
    loot = box.path / "targets/dc01/loot"
    loot.mkdir(parents=True)
    data = b"\x00odd\r\nbytes"
    (loot / "a\\b.txt").write_bytes(data)
    records = scan(box, [], now=NOW)
    save_files(box, records)
    write_manifest(box, records, kind="exported", now=NOW)
    dest = tmp_path / "forest.tar.gz"
    pack(box, dest)
    verify(dest)
    folder = unpack(dest, tmp_path / "elsewhere")
    assert (folder / "targets/dc01/loot/a\\b.txt").read_bytes() == data


def test_pack_leaves_out_the_vpn_folder_silently(filled, tmp_path):
    (filled.path / "vpn" / "a").mkdir(parents=True)
    (filled.path / "vpn" / "lab.ovpn").write_text("secret")
    (filled.path / "vpn" / "a" / "b").write_text("secret")
    (filled.path / "targets/dc01/vpn").mkdir()
    (filled.path / "targets/dc01/vpn/x").write_text("x")
    (filled.path / "vpn.txt").write_text("x")
    dest = tmp_path / "out" / "b.tar.gz"
    assert pack(filled, dest) == []
    names = member_names(dest)
    top = filled.path.name
    assert f"{top}/targets/dc01/vpn/x" in names and f"{top}/vpn.txt" in names
    assert not any(n == f"{top}/vpn" or n.startswith(f"{top}/vpn/") for n in names)


# --- a recording still being written ---

CAST = "targets/dc01/recordings/2026-11-14_1432.cast"
WHOLE = b'{"version": 3}\n[0, "o", "a"]\n'


def _live_box(box):
    cast = box.path / CAST
    cast.parent.mkdir(parents=True)
    cast.write_bytes(WHOLE + b'[1, "o", "b')
    records = scan(box, [], now=NOW, hash_all=True, live={CAST: len(WHOLE)})
    write_manifest(box, records, kind="exported", now=NOW)
    return cast


def test_pack_cuts_a_live_cast_and_verifies_while_it_grows(box, tmp_path):
    cast = _live_box(box)
    cast.write_bytes(cast.read_bytes() + b'"]\n[2, "o", "c"]\n')
    dest = tmp_path / "forest.tar.gz"
    pack(box, dest, cut={CAST: len(WHOLE)})
    verify(dest)
    with tarfile.open(dest) as tar:
        member = tar.getmember(f"{box.path.name}/{CAST}")
        assert member.size == len(WHOLE)
        assert tar.extractfile(member).read() == WHOLE
    folder = unpack(dest, tmp_path / "elsewhere")
    assert (folder / CAST).read_bytes() == WHOLE
    assert cast.stat().st_size > len(WHOLE)


def test_pack_refuses_a_cut_longer_than_the_file(box, tmp_path):
    cast = _live_box(box)
    cast.write_bytes(WHOLE[:5])
    dest = tmp_path / "forest.tar.gz"
    with pytest.raises(ArchiveError, match="recordings"):
        pack(box, dest, cut={CAST: len(WHOLE)})
    assert not dest.exists() and not part_of(dest).exists()


# --- what a box can hold, and what an archive may not ---


def test_two_names_of_one_file_are_each_packed_as_a_file(filled, tmp_path):
    first = filled.path / "targets/dc01/loot/SAM.bak"
    try:
        os.link(first, filled.path / "targets/dc01/loot/SAM.copy")
    except OSError:
        pytest.skip("no hard links here")
    records = scan(filled, [], now=NOW)
    save_files(filled, records)
    write_manifest(filled, records, kind="exported", now=NOW)
    dest = tmp_path / "out.tar.gz"
    pack(filled, dest)
    verify(dest)
    top = filled.path.name
    with tarfile.open(dest) as tar:
        for name in ("SAM.bak", "SAM.copy"):
            member = tar.getmember(f"{top}/targets/dc01/loot/{name}")
            assert member.isreg() and tar.extractfile(member).read() == b"\x00\x01binary"
    folder = unpack(dest, tmp_path / "elsewhere")
    assert (folder / "targets/dc01/loot/SAM.copy").read_bytes() == b"\x00\x01binary"


def sparse_header(name: str, real_size: int) -> bytes:
    # an old GNU sparse entry: no data stored, and a header that says how long the file really is
    info = tarfile.TarInfo(name)
    info.type = tarfile.GNUTYPE_SPARSE
    block = bytearray(info.tobuf(tarfile.GNU_FORMAT))
    block[386:410] = tarfile.itn(0, 12, tarfile.GNU_FORMAT) + tarfile.itn(0, 12, tarfile.GNU_FORMAT)
    block[483:495] = tarfile.itn(real_size, 12, tarfile.GNU_FORMAT)
    block[148:156] = b"        "
    block[148:156] = b"%06o\0 " % tarfile.calc_chksums(bytes(block))[0]
    return bytes(block)


def sparse_archive(dest, real_size=64 * 1024**2):
    data = b"x"
    plain = io.BytesIO()
    with tarfile.open(fileobj=plain, mode="w") as tar:
        add_dir(tar, "b")
        add_bytes(tar, "b/manifest.toml", manifest_bytes([record("big", data, size=real_size)]))
    # the two blocks of zeros that end the tar are replaced by the sparse entry and a new end
    body = plain.getvalue().rstrip(b"\0")
    body += b"\0" * (-len(body) % 512)
    dest.write_bytes(gzip.compress(body + sparse_header("b/big", real_size) + b"\0" * 1024))
    return dest


def test_the_stand_in_sparse_archive_is_one_tarfile_reads_as_sparse(tmp_path):
    with tarfile.open(sparse_archive(tmp_path / "s.tar.gz")) as tar:
        member = tar.getmember("b/big")
        assert member.issparse() and member.size == 64 * 1024**2


def test_verify_refuses_a_sparse_entry_before_reading_it(tmp_path, monkeypatch):
    dest = sparse_archive(tmp_path / "s.tar.gz")
    monkeypatch.setattr(tarfile.TarFile, "extractfile", raising(AssertionError("read")))
    with pytest.raises(ArchiveError, match="sparse"):
        verify(dest)


def test_unpack_refuses_a_sparse_entry(tmp_path):
    dest = sparse_archive(tmp_path / "s.tar.gz")
    with pytest.raises(ArchiveError, match="sparse"):
        unpack(dest, tmp_path / "active")
    assert not (tmp_path / "active").exists() or list((tmp_path / "active").iterdir()) == []


@pytest.mark.parametrize("nested", ["file = " + "[" * 100_000, "x = " + "{a=" * 100_000])
def test_a_manifest_nested_too_deeply_is_refused_with_a_message(tmp_path, nested):
    dest = raw_archive(
        tmp_path / "deep.tar.gz",
        lambda tar: (add_dir(tar, "b"), add_bytes(tar, "b/manifest.toml", f"schema = 1\n{nested}".encode())),
    )
    with pytest.raises(ArchiveError, match="manifest.toml"):
        verify(dest)


def test_verify_refuses_an_entry_that_is_not_a_file_or_folder(tmp_path):
    def build(tar):
        add_dir(tar, "b")
        add_bytes(tar, "b/manifest.toml", manifest_bytes([]))
        link = tarfile.TarInfo("b/link")
        link.type = tarfile.SYMTYPE
        link.linkname = "/etc/passwd"
        tar.addfile(link)

    with pytest.raises(ArchiveError, match="not a regular file or folder"):
        verify(raw_archive(tmp_path / "l.tar.gz", build))


def test_unpack_checks_the_folder_before_it_replaces_anything(filled, tmp_path):
    dest = tmp_path / "out.tar.gz"
    pack(filled, dest)
    active = tmp_path / "active"
    old = active / filled.path.name
    old.mkdir(parents=True)
    (old / "work.txt").write_text("mine")
    seen = []

    def check(folder):
        seen.append((folder.parent.parent == active, (folder / "notes.md").read_text(), (old / "work.txt").exists()))
        raise ArchiveError("not a box")

    with pytest.raises(ArchiveError, match="not a box"):
        unpack(dest, active, replace=True, check=check)
    assert seen == [(True, "hello", True)]
    assert (old / "work.txt").read_text() == "mine"
    assert sorted(p.name for p in active.iterdir()) == [filled.path.name]


def test_a_file_whose_name_is_not_utf8_is_packed_and_unpacked_under_that_name(filled, tmp_path):
    if odd_name(filled.path / "targets/dc01/loot") is None:
        pytest.skip("no file here can have a name that is not UTF-8")
    records = scan(filled, [], now=NOW)
    save_files(filled, records)
    write_manifest(filled, records, kind="exported", now=NOW)
    dest = tmp_path / "out.tar.gz"
    assert pack(filled, dest) == []
    verify(dest)
    folder = unpack(dest, tmp_path / "elsewhere")
    with open(os.path.join(os.fsencode(folder / "targets/dc01/loot"), b"caf\xe9 \xff.txt"), "rb") as fh:
        assert fh.read() == b"loot"
