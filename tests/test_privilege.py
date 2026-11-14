import os
import subprocess
import sys

import pytest

from pwn_broker import privilege
from pwn_broker.privilege import (
    fix_ownership,
    foreign_files,
    is_root,
    privileged_argv,
    run_privileged,
    wrong_owner,
)

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX ownership")


def test_privileged_argv():
    assert privileged_argv(["chown", "x"], root=True) == ["chown", "x"]
    assert privileged_argv(["chown", "x"], root=False) == ["sudo", "chown", "x"]


def test_is_root_matches_euid():
    expected = False if sys.platform == "win32" else os.geteuid() == 0
    assert is_root() is expected


def test_run_privileged_uses_prefix_without_shell_or_capture(monkeypatch):
    seen = {}

    def fake_run(argv, **kwargs):
        seen["argv"] = argv
        seen["kwargs"] = kwargs
        return subprocess.CompletedProcess(argv, 0)

    monkeypatch.setattr(privilege.subprocess, "run", fake_run)
    monkeypatch.setattr(privilege, "is_root", lambda: False)
    result = run_privileged(["chown", "x"])
    assert result.returncode == 0
    assert seen["argv"] == ["sudo", "chown", "x"]
    assert seen["kwargs"] == {"check": False}


def test_wrong_owner_none_for_own_folder(tmp_path):
    assert wrong_owner(tmp_path) is None


def test_wrong_owner_none_for_missing_path(tmp_path):
    assert wrong_owner(tmp_path / "nope") is None


def test_foreign_files_missing_folder_is_zero(tmp_path):
    assert foreign_files(tmp_path / "nope") == 0


def test_foreign_files_own_tree_is_zero(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "f.txt").write_text("x")
    assert foreign_files(tmp_path) == 0


@posix_only
def test_wrong_owner_names_other_user(tmp_path, monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: os.stat(tmp_path).st_uid + 1)
    assert wrong_owner(tmp_path) is not None


@posix_only
def test_foreign_files_counts_folder_and_entries(tmp_path, monkeypatch):
    (tmp_path / "f.txt").write_text("x")
    monkeypatch.setattr(os, "geteuid", lambda: os.stat(tmp_path).st_uid + 1)
    assert foreign_files(tmp_path) == 2


def test_fix_ownership_does_nothing_when_all_mine(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(privilege, "run_privileged", lambda argv: calls.append(argv))
    assert fix_ownership(tmp_path) == 0
    assert calls == []


def _fake_ids(monkeypatch):
    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
    monkeypatch.setattr(os, "getegid", lambda: 1001, raising=False)
    monkeypatch.setattr(privilege, "foreign_files", lambda folder: 3)


def test_fix_ownership_runs_chown(tmp_path, monkeypatch):
    _fake_ids(monkeypatch)
    calls = []
    monkeypatch.setattr(
        privilege,
        "run_privileged",
        lambda argv: calls.append(argv) or subprocess.CompletedProcess(argv, 0),
    )
    assert fix_ownership(tmp_path) == 3
    assert calls == [["chown", "-R", "1000:1001", str(tmp_path)]]


def test_fix_ownership_raises_when_chown_fails(tmp_path, monkeypatch):
    _fake_ids(monkeypatch)
    monkeypatch.setattr(
        privilege, "run_privileged", lambda argv: subprocess.CompletedProcess(argv, 1)
    )
    with pytest.raises(OSError) as info:
        fix_ownership(tmp_path)
    assert str(tmp_path) in str(info.value)
