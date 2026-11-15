import os
import sys
from datetime import timedelta

import pytest
from helpers import NASTY, NOW, make_cred

from pwn_broker import store
from pwn_broker.model import FileRecord, Flag, RuntimeRecord, Target, ToolRecord, VpnRecord
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
        (box.path / "box.toml").read_text(encoding="utf-8") + '\n[mystery]\nfoo = "bar"\n',
        encoding="utf-8",
    )
    loaded = load_box(box.path)
    assert loaded.extra == {"mystery": {"foo": "bar"}}
    save_box(loaded)
    assert read_toml(box.path / "box.toml")["mystery"] == {"foo": "bar"}


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
    path.write_text(path.read_text(encoding="utf-8") + '\n[mystery]\nfoo = "bar"\n', encoding="utf-8")
    loaded = load_box(box.path)
    assert loaded.extra == {"mystery": {"foo": "bar"}}
    save_box(loaded)
    data = read_toml(path)
    assert data["mystery"] == {"foo": "bar"} and len(data["tools"]) == 1


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


def _runtime(build=1):
    return RuntimeRecord("python-3.13", "3.13.18", build, "cd" * 32)


def test_tool_record_runtime_round_trip(box):
    box.tools = [
        ToolRecord("certipy", "5.1.0", 3, "ab" * 32, NOW, runtime=_runtime()),
        _tool(),
    ]
    save_box(box)
    data = read_toml(box.path / "box.toml")
    # written inside the tool's own row, not as a list of its own
    rows = data["tools"]
    assert rows[0]["runtime"] == {
        "name": "python-3.13", "version": "3.13.18", "build": 1, "sha256": "cd" * 32
    }  # fmt: skip
    assert "runtime" not in rows[1]
    assert set(data) == {"schema", "id", "name", "platform", "os", "difficulty", "status",
                         "started", "flags", "tools"}  # fmt: skip
    got = load_box(box.path)
    assert got.tools == box.tools
    assert got.tools[0].runtime == _runtime() and got.tools[1].runtime is None
    assert "tools" not in got.extra


def test_tool_record_runtime_defaults_to_none():
    assert _tool().runtime is None


def test_a_box_written_before_runtimes_loads_unchanged(tmp_path):
    folder = tmp_path / "old-box"
    folder.mkdir()
    old = (
        'schema = 1\nid = "forest-1"\nname = "forest"\nplatform = "htb"\nos = "windows"\n'
        'difficulty = "easy"\nstatus = "active"\nstarted = 2026-11-01T10:00:00\n\n[flags]\n\n'
        '[[tools]]\nname = "certipy"\nversion = "5.1.0"\nbuild = 2\n'
        f'sha256 = "{"ef" * 32}"\ninstalled = 2026-11-01T10:05:00\n'
    )
    (folder / "box.toml").write_text(old, encoding="utf-8")
    box = load_box(folder)
    assert box.tools == [ToolRecord("certipy", "5.1.0", 2, "ef" * 32, box.tools[0].installed)]
    assert box.tools[0].runtime is None and box.extra == {}
    save_box(box)
    again = read_toml(folder / "box.toml")
    assert "runtime" not in again["tools"][0]
    assert load_box(folder) == box


@pytest.mark.parametrize(
    "runtime",
    [
        "python-3.13",
        {"name": "python-3.13", "version": "3.13.18", "build": "1", "sha256": "cd" * 32},
        {"name": "python-3.13", "version": "3.13.18", "build": True, "sha256": "cd" * 32},
        {"name": 3, "version": "3.13.18", "build": 1, "sha256": "cd" * 32},
        {"name": "python-3.13", "version": 3.13, "build": 1, "sha256": "cd" * 32},
        {"name": "python-3.13", "version": "3.13.18", "build": 1, "sha256": 5},
        {"name": "python-3.13", "version": "3.13.18", "build": 1},
    ],
)
def test_tool_record_runtime_wrong_type(box, runtime):
    box.tools = [_tool()]
    save_box(box)
    path = box.path / "box.toml"
    data = read_toml(path)
    data["tools"][0]["runtime"] = runtime
    write_toml(path, data)
    with pytest.raises(StoreError, match="box.toml"):
        load_box(box.path)


def _vpn(file="lab.ovpn"):
    return VpnRecord(file, "cd" * 32, NOW)


def test_hosts_and_vpn_round_trip(box):
    box.hosts = ["dc01", "web"]
    box.vpn = [_vpn(), _vpn("other.ovpn")]
    save_box(box)
    data = read_toml(box.path / "box.toml")
    assert data["hosts"] == ["dc01", "web"] and data["vpn"][0]["file"] == "lab.ovpn"
    got = load_box(box.path)
    assert got == box and got.hosts == box.hosts and got.vpn == box.vpn
    assert "hosts" not in got.extra and "vpn" not in got.extra


def test_box_without_hosts_or_vpn_loads_empty(box):
    save_box(box)
    data = read_toml(box.path / "box.toml")
    assert "hosts" not in data and "vpn" not in data
    got = load_box(box.path)
    assert got.hosts == [] and got.vpn == []


def test_unknown_tables_still_land_in_extra_beside_hosts_and_vpn(box):
    box.hosts = ["dc01"]
    box.vpn = [_vpn()]
    save_box(box)
    path = box.path / "box.toml"
    path.write_text(path.read_text(encoding="utf-8") + '\n[mystery]\nfoo = "bar"\n', encoding="utf-8")
    loaded = load_box(box.path)
    assert loaded.extra == {"mystery": {"foo": "bar"}}


@pytest.mark.parametrize("key,value", [("file", 3), ("sha256", 3), ("started", "soon")])
def test_vpn_entry_wrong_type(box, key, value):
    box.vpn = [_vpn()]
    save_box(box)
    path = box.path / "box.toml"
    data = read_toml(path)
    data["vpn"][0][key] = value
    write_toml(path, data)
    with pytest.raises(StoreError, match="box.toml"):
        load_box(box.path)


@pytest.mark.parametrize("drop", ["file", "sha256", "started"])
def test_vpn_entry_missing_field(box, drop):
    box.vpn = [_vpn()]
    save_box(box)
    path = box.path / "box.toml"
    data = read_toml(path)
    del data["vpn"][0][drop]
    write_toml(path, data)
    with pytest.raises(StoreError, match="box.toml"):
        load_box(box.path)


@pytest.mark.parametrize("value", ["dc01", [1], {"a": "b"}])
def test_hosts_wrong_type(box, value):
    save_box(box)
    path = box.path / "box.toml"
    data = read_toml(path)
    data["hosts"] = value
    write_toml(path, data)
    with pytest.raises(StoreError, match="box.toml"):
        load_box(box.path)
