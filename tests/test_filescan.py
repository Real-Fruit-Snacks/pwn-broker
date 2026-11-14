import hashlib
import os
import sys
from datetime import timedelta

import pytest

from conftest import NOW
from pwn_broker import filescan
from pwn_broker.filescan import is_skipped, scan, sha256_file


@pytest.fixture
def loot(box):
    folder = box.path / "targets/dc01/loot"
    folder.mkdir(parents=True)
    return folder


def test_new_file_recorded(box, loot):
    (loot / "SAM.bak").write_bytes(b"abc")
    [r] = [r for r in scan(box, [], now=NOW) if r.path.endswith("SAM.bak")]
    assert (r.path, r.target, r.size, r.first_seen) == ("targets/dc01/loot/SAM.bak", "dc01", 3, NOW)
    assert r.sha256 == hashlib.sha256(b"abc").hexdigest()


def test_box_level_file_has_no_target(box):
    (box.path / "notes.md").write_text("hi")
    [r] = [r for r in scan(box, [], now=NOW) if r.path == "notes.md"]
    assert r.target == ""


def test_hidden_file_at_top_level_recorded_hidden_dirs_not_entered(box):
    (box.path / ".history").write_text("ls")
    (box.path / ".git").mkdir()
    (box.path / ".git/config").write_text("x")
    (box.path / "targets/dc01/.cache").mkdir(parents=True)
    (box.path / "targets/dc01/.cache/a").write_text("x")
    paths = {r.path for r in scan(box, [], now=NOW)}
    assert ".history" in paths
    assert not any("/.cache/" in p or p.startswith(".git/") for p in paths)


def test_first_seen_survives_a_change(box, loot):
    f = loot / "a.txt"
    f.write_bytes(b"abc")
    first = scan(box, [], now=NOW)
    f.write_bytes(b"abcdef")
    os.utime(f, (1, 1))
    later = scan(box, first, now=NOW + timedelta(hours=1))
    [r] = [r for r in later if r.path.endswith("a.txt")]
    assert r.first_seen == NOW
    assert r.size == 6
    assert r.sha256 == hashlib.sha256(b"abcdef").hexdigest()


def test_unchanged_file_is_not_rehashed(box, loot, monkeypatch):
    (loot / "a.txt").write_bytes(b"abc")
    first = scan(box, [], now=NOW)
    calls = []
    monkeypatch.setattr(filescan, "sha256_file", lambda p: calls.append(p) or "x")
    again = scan(box, first, now=NOW + timedelta(hours=1))
    assert calls == []
    assert again == first


def test_deleted_file_drops_out(box, loot):
    f = loot / "a.txt"
    f.write_bytes(b"abc")
    first = scan(box, [], now=NOW)
    f.unlink()
    assert not [r for r in scan(box, first, now=NOW) if r.path.endswith("a.txt")]


def test_large_file_hash_deferred(box, loot):
    (loot / "big.bin").write_bytes(b"abc")
    [r] = [r for r in scan(box, [], now=NOW, limit=2) if r.path.endswith("big.bin")]
    assert r.sha256 == ""
    deferred = scan(box, [r], now=NOW, limit=2)
    assert [x.sha256 for x in deferred if x.path.endswith("big.bin")] == [""]
    filled = scan(box, [r], now=NOW, limit=2, hash_all=True)
    [r2] = [x for x in filled if x.path.endswith("big.bin")]
    assert r2.sha256 == hashlib.sha256(b"abc").hexdigest()
    assert r2.first_seen == r.first_seen


def test_skipped_names(box):
    for name in ["files.toml", "manifest.toml", ".note-state", ".notes.md.swp", "x.part", "n.md~"]:
        (box.path / name).write_text("x")
    (box.path / "notes.md").write_text("x")
    paths = {r.path for r in scan(box, [], now=NOW)}
    assert "notes.md" in paths
    assert paths.isdisjoint(
        {"files.toml", "manifest.toml", ".note-state", ".notes.md.swp", "x.part", "n.md~"}
    )


def test_is_skipped():
    assert is_skipped("files.toml")
    assert is_skipped("creds.toml.abc123.tmp")
    assert is_skipped("a.swo")
    assert not is_skipped("notes.md")
    assert not is_skipped(".history")


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_symlinks_are_not_followed(box, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("x")
    (outside / "f.txt").write_text("x")
    (box.path / "link").symlink_to(outside, target_is_directory=True)
    (box.path / "flink").symlink_to(outside / "f.txt")
    assert not [r for r in scan(box, [], now=NOW) if r.path.startswith(("link", "flink"))]


def test_unreadable_file_is_skipped_with_reason(box, loot, monkeypatch):
    (loot / "good.txt").write_bytes(b"ok")
    (loot / "bad.txt").write_bytes(b"no")
    real = filescan.sha256_file

    def fake(path):
        if path.name == "bad.txt":
            raise PermissionError("denied")
        return real(path)

    monkeypatch.setattr(filescan, "sha256_file", fake)
    skipped = []
    result = scan(box, [], now=NOW, on_skip=lambda p, why: skipped.append((p, why)))
    paths = [r.path for r in result]
    assert "targets/dc01/loot/good.txt" in paths
    assert "targets/dc01/loot/bad.txt" not in paths
    assert skipped == [("targets/dc01/loot/bad.txt", "cannot read")]


def test_file_vanishing_mid_scan(box, loot, monkeypatch):
    (loot / "a.txt").write_bytes(b"x")
    (loot / "b.txt").write_bytes(b"x")
    real_stat = os.stat

    def fake_stat(path, *args, **kwargs):
        if os.fspath(path).endswith("a.txt"):
            raise FileNotFoundError(path)
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(filescan.os, "stat", fake_stat)
    skipped = []
    result = scan(box, [], now=NOW, on_skip=lambda p, why: skipped.append((p, why)))
    assert not [r for r in result if r.path.endswith("a.txt")]
    assert [r for r in result if r.path.endswith("b.txt")]
    assert skipped == [("targets/dc01/loot/a.txt", "disappeared")]


def test_result_sorted_by_path(box, loot):
    (loot / "b").write_text("1")
    (loot / "a").write_text("1")
    (box.path / "notes.md").write_text("1")
    paths = [r.path for r in scan(box, [], now=NOW)]
    assert paths == sorted(paths)


def test_sha256_file_reads_in_chunks(tmp_path):
    f = tmp_path / "f"
    data = b"z" * (3 * 1024 * 1024 + 5)
    f.write_bytes(data)
    assert sha256_file(f) == hashlib.sha256(data).hexdigest()
