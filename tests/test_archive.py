import hashlib
import io
import os
import shutil
import sys
import tarfile
from dataclasses import replace as dc_replace

import pytest
import tomli_w

from helpers import NOW
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
    assert pack(filled, dest) is None
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
    dest = tmp_path / "forest.tar.gz"
    pack(filled, dest)
    assert inside(dest).isdisjoint({"link", "dirlink", "dirlink/secret", "pipe"})
    verify(dest)


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


@posix_only
def test_pack_refuses_a_name_with_a_backslash(filled, tmp_path):
    (filled.path / "bad\name.txt").write_text("x")
    dest = tmp_path / "forest.tar.gz"
    with pytest.raises(ArchiveError, match="rename"):
        pack(filled, dest)
    assert not dest.exists() and not part_of(dest).exists()
