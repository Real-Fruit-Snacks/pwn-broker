import os
import sys
from datetime import timedelta

import pytest
from helpers import NASTY, NOW, make_cred

from pwn_broker import store
from pwn_broker.model import FileRecord, Flag, Target, ToolRecord
from pwn_broker.store import (
    StoreError,
    load_box,
    load_creds,
    load_files,
    load_targets,
    read_toml,
    save_box,
    save_creds,
    save_files,
    save_target,
    write_text,
    write_toml,
)


def test_box_round_trip(box):
    box.finished = NOW + timedelta(days=1)
    box.last_target = "dc01"
    box.flags = {"user": Flag("abc123", NOW), "root": Flag("def456", NOW + timedelta(hours=1))}
    save_box(box)
    got = load_box(box.path)
    assert got == box
    assert got.started.tzinfo is not None
    assert got.flags["root"].at.utcoffset() == NOW.utcoffset()


def test_box_keeps_unknown_tables(box):
    (box.path / "box.toml").write_text(
        (box.path / "box.toml").read_text(encoding="utf-8") + '\n[hosts]\nfoo = "bar"\n',
        encoding="utf-8",
    )
    loaded = load_box(box.path)
    assert loaded.extra == {"hosts": {"foo": "bar"}}
    save_box(loaded)
    assert read_toml(box.path / "box.toml")["hosts"] == {"foo": "bar"}


def test_target_round_trip(box):
    later = Target(box.id, box.name, "dc02", ["10.0.0.2"], [], "", NOW + timedelta(minutes=5))
    first = Target(box.id, box.name, "dc01", ["10.0.0.1"], ["dc01.htb"], "in scope", NOW)
    save_target(box, later)
    save_target(box, first)
    assert load_targets(box) == [first, later]
    assert (box.path / "targets" / "dc01" / "target.toml").is_file()


@pytest.mark.parametrize("secret", NASTY)
def test_cred_secret_is_unchanged(box, secret):
    save_creds(box, [make_cred(secret=secret, username=secret)])
    got = load_creds(box)[0]
    assert got.secret == secret and got.username == secret


def test_creds_round_trip(box):
    creds = [make_cred(n=1), make_cred(n=2, works_on=[], note="spray")]
    save_creds(box, creds)
    assert load_creds(box) == creds


def test_files_round_trip(box):
    records = [
        FileRecord("loot/a.txt", "dc01", NOW, 12, 1700000000.5, "ab" * 32),
        FileRecord("notes.md", "", NOW, 0, 0.0, ""),
    ]
    save_files(box, records)
    assert load_files(box) == records


def test_creds_and_files_carry_the_box_id(box):
    save_creds(box, [make_cred()])
    save_files(box, [FileRecord("notes.md", "", NOW, 0, 0.0, "")])
    for name in ("creds.toml", "files.toml"):
        data = read_toml(box.path / name)
        assert data["box_id"] == box.id and data["schema"] == 1


def test_creds_and_files_without_a_box_id_still_load(box):
    older = """schema = 1
[[cred]]
n = 1
username = "u"
domain = ""
secret = "s"
kind = "password"
found_on = ""
works_on = []
note = ""
added = 2026-11-14T12:00:00+02:00
"""
    (box.path / "creds.toml").write_text(older, encoding="utf-8")
    (box.path / "files.toml").write_text("schema = 1\n", encoding="utf-8")
    assert [c.username for c in load_creds(box)] == ["u"] and load_files(box) == []
    (box.path / "files.toml").write_text('schema = 1\nbox_id = "another"\n', encoding="utf-8")
    assert load_files(box) == []


def test_missing_creds_and_files_load_empty(box):
    assert load_creds(box) == []
    assert load_files(box) == []
    assert load_targets(box) == []


def test_truncated_file_raises_store_error_naming_it(tmp_path):
    (tmp_path / "box.toml").write_text('schema = 1\nname = "for')
    with pytest.raises(StoreError, match="box.toml"):
        load_box(tmp_path)


def test_unknown_schema_raises_store_error(box):
    text = (box.path / "box.toml").read_text(encoding="utf-8").replace("schema = 1", "schema = 2")
    (box.path / "box.toml").write_text(text, encoding="utf-8")
    with pytest.raises(StoreError, match="box.toml"):
        load_box(box.path)


def test_missing_field_raises_store_error(tmp_path):
    (tmp_path / "box.toml").write_text('schema = 1\nname = "x"\n')
    with pytest.raises(StoreError, match="box.toml"):
        load_box(tmp_path)


def test_write_is_atomic(tmp_path, monkeypatch):
    target = tmp_path / "x.toml"
    write_toml(target, {"schema": 1, "a": "old"})

    def boom(src, dst):
        raise OSError("disk gone")

    monkeypatch.setattr(store.os, "replace", boom)
    with pytest.raises(OSError):
        write_toml(target, {"schema": 1, "a": "new"})
    assert read_toml(target)["a"] == "old"
    assert [p.name for p in tmp_path.iterdir()] == ["x.toml"]


def test_write_text_temp_file_is_named_for_the_app(tmp_path, monkeypatch):
    seen = []
    real = os.replace
    monkeypatch.setattr(store.os, "replace", lambda src, dst: seen.append((src, dst)) or real(src, dst))
    write_text(tmp_path / "creds.toml", "x")
    [(src, dst)] = seen
    name = os.path.basename(src)
    assert os.path.dirname(src) == str(tmp_path) and dst == tmp_path / "creds.toml"
    assert name.startswith(".pwn-broker-") and name.endswith(".tmp")


def test_write_uses_lf_newlines(tmp_path):
    write_toml(tmp_path / "x.toml", {"schema": 1, "a": 1})
    assert b"\r" not in (tmp_path / "x.toml").read_bytes()


def test_none_values_are_omitted_and_read_back_as_none(box):
    assert "finished" not in read_toml(box.path / "box.toml")
    got = load_box(box.path)
    assert got.finished is None and got.last_target is None


def test_write_text_writes_content_and_leaves_no_temp_file(tmp_path):
    target = tmp_path / "sub" / "a.txt"
    write_text(target, "x\ny", newline="")
    write_text(target, "a\r\nb", newline="")
    assert target.read_bytes() == b"a\r\nb"
    assert [p.name for p in target.parent.iterdir()] == ["a.txt"]


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_write_text_keeps_existing_mode(tmp_path):
    target = tmp_path / "a.txt"
    target.write_text("old")
    target.chmod(0o640)
    write_text(target, "new")
    assert target.stat().st_mode & 0o777 == 0o640


@pytest.mark.skipif(sys.platform == "win32", reason="POSIX permission bits")
def test_write_text_new_file_uses_umask_default(tmp_path):
    old = os.umask(0o022)
    try:
        write_text(tmp_path / "a.txt", "new")
    finally:
        os.umask(old)
    assert (tmp_path / "a.txt").stat().st_mode & 0o777 == 0o644


def _tool(name="chisel", build=1):
    return ToolRecord(name, "1.10.0", build, "ab" * 32, NOW)


def test_tool_records_round_trip(box):
    box.tools = [_tool(), _tool("ligolo", 2)]
    save_box(box)
    assert read_toml(box.path / "box.toml")["tools"][0]["name"] == "chisel"
    got = load_box(box.path)
    assert got == box and got.tools == box.tools
    assert "tools" not in got.extra


def test_box_without_tools_loads_empty(box):
    save_box(box)
    assert "tools" not in read_toml(box.path / "box.toml")
    assert load_box(box.path).tools == []


def test_old_box_keeps_unknown_tables_beside_tools(box):
    box.tools = [_tool()]
    save_box(box)
    path = box.path / "box.toml"
    path.write_text(path.read_text(encoding="utf-8") + '\n[hosts]\nfoo = "bar"\n', encoding="utf-8")
    loaded = load_box(box.path)
    assert loaded.extra == {"hosts": {"foo": "bar"}}
    save_box(loaded)
    data = read_toml(path)
    assert data["hosts"] == {"foo": "bar"} and len(data["tools"]) == 1


@pytest.mark.parametrize("drop", ["name", "version", "build", "sha256", "installed"])
def test_tool_entry_missing_field(box, drop):
    box.tools = [_tool()]
    save_box(box)
    path = box.path / "box.toml"
    data = read_toml(path)
    del data["tools"][0][drop]
    write_toml(path, data)
    with pytest.raises(StoreError, match="box.toml"):
        load_box(box.path)


@pytest.mark.parametrize("key,value", [("build", "one"), ("name", 3), ("installed", "soon")])
def test_tool_entry_wrong_type(box, key, value):
    box.tools = [_tool()]
    save_box(box)
    path = box.path / "box.toml"
    data = read_toml(path)
    data["tools"][0][key] = value
    write_toml(path, data)
    with pytest.raises(StoreError, match="box.toml"):
        load_box(box.path)
