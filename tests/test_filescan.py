import hashlib
import os
import stat
import sys
from datetime import timedelta

import pytest

from helpers import NOW
from pwn_broker import filescan
from pwn_broker.filescan import is_app_file, scan, sha256_file


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
    (box.path / ".hidden-note").write_text("ls")
    (box.path / ".git").mkdir()
    (box.path / ".git/config").write_text("x")
    (box.path / "targets/dc01/.cache").mkdir(parents=True)
    (box.path / "targets/dc01/.cache/a").write_text("x")
    paths = {r.path for r in scan(box, [], now=NOW)}
    assert ".hidden-note" in paths
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


def test_app_files_are_not_recorded(box):
    own = ["files.toml", "manifest.toml", ".note-state", ".history", ".notes.md.swp", ".notes.md.swo"]
    own.append(".pwn-broker-k3j9.tmp")
    for name in own:
        (box.path / name).write_text("x")
    (box.path / "targets/dc01/loot").mkdir(parents=True)
    (box.path / "targets/dc01/loot/.pwn-broker-a1b2.tmp").write_text("x")
    (box.path / "notes.md").write_text("x")
    paths = {r.path for r in scan(box, [], now=NOW)}
    assert "notes.md" in paths
    assert paths.isdisjoint(own) and "targets/dc01/loot/.pwn-broker-a1b2.tmp" not in paths


def test_files_with_common_names_are_recorded_anywhere(box, loot):
    names = [".index.php.swp", "config.php~", "backup.tmp", "x.part", "files.toml"]
    names += [".note-state", ".notes.md.swp", "manifest.toml", ".history"]
    for name in names:
        (loot / name).write_bytes(name.encode())
    for name in ["x.part", "n.md~", "backup.tmp", ".a.swp"]:
        (box.path / name).write_text("x")
    paths = {r.path for r in scan(box, [], now=NOW)}
    assert {f"targets/dc01/loot/{n}" for n in names} <= paths
    assert {"x.part", "n.md~", "backup.tmp", ".a.swp"} <= paths


def test_prompt_history_is_not_a_box_file(box):
    (box.path / ".history").write_text("target list")
    (box.path / "notes.md").write_text("x")
    paths = {r.path for r in scan(box, [], now=NOW)}
    assert "notes.md" in paths and ".history" not in paths


APP_FILES = [
    "files.toml", "manifest.toml", ".note-state", ".history", ".notes.md.swp", ".notes.md.swx",
    ".pwn-broker-abc.tmp", "targets/dc01/.pwn-broker-abc.tmp", "targets/dc01/loot/.pwn-broker-x.tmp",
]  # fmt: skip
NOT_APP_FILES = [
    "notes.md", "creds.toml", "box.toml", "a.swo", "x.tmp", "x.part", "n.md~", ".notes.md.swpp", ".notes.md",
    "targets/dc01/files.toml", "targets/dc01/.history", "targets/dc01/.notes.md.swp", "targets/dc01/.note-state",
    ".pwn-broker-abc", "pwn-broker-abc.tmp",
]  # fmt: skip


@pytest.mark.parametrize("rel", APP_FILES)
def test_is_app_file(rel):
    assert is_app_file(rel)


@pytest.mark.parametrize("rel", NOT_APP_FILES)
def test_is_not_app_file(rel):
    assert not is_app_file(rel)


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_symlinks_are_not_followed(box, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (outside / "secret.txt").write_text("x")
    (outside / "f.txt").write_text("x")
    (box.path / "link").symlink_to(outside, target_is_directory=True)
    (box.path / "flink").symlink_to(outside / "f.txt")
    assert [r.path for r in scan(box, [], now=NOW)] == ["box.toml"]


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
    real_stat = os.lstat

    def fake_stat(path, *args, **kwargs):
        if os.fspath(path).endswith("a.txt"):
            raise FileNotFoundError(path)
        return real_stat(path, *args, **kwargs)

    monkeypatch.setattr(filescan.os, "lstat", fake_stat)
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


def test_file_directly_under_targets_has_no_target(box):
    (box.path / "targets").mkdir()
    (box.path / "targets/stray.txt").write_text("x")
    [r] = [r for r in scan(box, [], now=NOW) if r.path.startswith("targets/")]
    assert (r.path, r.target) == ("targets/stray.txt", "")


def test_changed_file_over_limit_keeps_first_seen_and_defers_hash(box, loot):
    f = loot / "big.bin"
    f.write_bytes(b"abc")
    first = scan(box, [], now=NOW)
    f.write_bytes(b"abcdefgh")
    os.utime(f, (1, 1))
    [r] = [r for r in scan(box, first, now=NOW + timedelta(hours=1), limit=2) if r.path.endswith("big.bin")]
    assert (r.first_seen, r.size, r.sha256) == (NOW, 8, "")


def test_unlistable_directory_keeps_its_records(box, loot, monkeypatch):
    (loot / "a.txt").write_bytes(b"abc")
    (box.path / "notes.md").write_text("n")
    first = scan(box, [], now=NOW)
    real = os.scandir

    def fake(path="."):
        if os.fspath(path).replace("\\", "/").endswith("targets/dc01"):
            raise PermissionError(13, "denied", os.fspath(path))
        return real(path)

    monkeypatch.setattr(os, "scandir", fake)
    skipped = []
    later = scan(box, first, now=NOW + timedelta(hours=1), on_skip=lambda p, why: skipped.append((p, why)))
    assert skipped == [("targets/dc01", "cannot read")]
    assert later == first


def test_non_regular_file_is_never_opened(box, loot, monkeypatch):
    (loot / "pipe").write_bytes(b"")
    (loot / "ok.txt").write_bytes(b"x")
    real = os.lstat

    def fake(path, *args, **kwargs):
        st = real(path, *args, **kwargs)
        if os.fspath(path).endswith("pipe"):
            values = list(st)
            values[0] = stat.S_IFIFO | 0o644
            return os.stat_result(values)
        return st

    monkeypatch.setattr(filescan.os, "lstat", fake)
    opened = []
    real_hash = filescan.sha256_file
    monkeypatch.setattr(filescan, "sha256_file", lambda p: opened.append(p.name) or real_hash(p))
    skipped = []
    result = scan(box, [], now=NOW, on_skip=lambda p, why: skipped.append((p, why)))
    assert "pipe" not in opened
    assert "targets/dc01/loot/ok.txt" in [r.path for r in result]
    assert "targets/dc01/loot/pipe" not in [r.path for r in result]
    assert skipped == [("targets/dc01/loot/pipe", "not a regular file")]


@pytest.mark.skipif(not hasattr(os, "mkfifo"), reason="needs mkfifo")
def test_real_fifo_does_not_hang(box, loot):
    os.mkfifo(loot / "rev")
    skipped = []
    result = scan(box, [], now=NOW, on_skip=lambda p, why: skipped.append(why))
    assert not [r for r in result if r.path.endswith("rev")]
    assert skipped == ["not a regular file"]
