import ast
import io
import os
import stat
import subprocess
import sys
import venv
import zipfile
from pathlib import Path

import pytest
import tomli_w

from pwn_broker import config, toolpkg, vpnctl
from pwn_broker.toolpkg import ToolError, parse_manifest, unpack
from toolkit import make_package, make_wheel, notes_files, sample_manifest


def python_manifest(kind="kali", **command):
    cmd = {"name": "impacket", "type": "python-entry", "entry": "impacket-smbserver"}
    cmd.update(command)
    return sample_manifest(
        kind=kind,
        command=[cmd],
        python={"versions": ["3.12", "3.13"], "lock": "wheels.lock", "wheels": "wheels"},
    )


def both_manifest():
    return sample_manifest(
        kind="both",
        upload=[{"path": "files/agent.exe", "as": "agent.exe", "note": "Windows"}],
        data={"home": [".kerbrute"]},
    )


# ---- parse_manifest


def test_kali_manifest_parses():
    m = parse_manifest(sample_manifest())
    assert (m.name, m.version, m.build, m.kind) == ("kerbrute", "1.0.3", 1, "kali")
    assert m.commands[0].type == "binary" and m.commands[0].path == "files/kerbrute"
    assert m.uploads == [] and m.python is None and m.home == []
    assert m.needs_root is False


def test_both_manifest_parses():
    m = parse_manifest(both_manifest())
    assert m.uploads[0].as_name == "agent.exe" and m.uploads[0].note == "Windows"
    assert m.home == [".kerbrute"]


def test_upload_manifest_parses():
    m = parse_manifest(
        sample_manifest(kind="upload", command=[], upload=[{"path": "files/a", "as": "a"}])
    )
    assert m.commands == [] and m.uploads[0].note == ""


def test_python_entry_and_script_parse():
    m = parse_manifest(python_manifest())
    assert m.commands[0].entry == "impacket-smbserver"
    assert m.python.versions == ["3.12", "3.13"] and m.python.lock == "wheels.lock"
    m = parse_manifest(
        python_manifest(type="python-script", script="files/tool.py", entry="")
    )
    assert m.commands[0].script == "files/tool.py"


def test_command_env_and_args():
    data = sample_manifest(
        command=[
            {
                "name": "k",
                "type": "binary",
                "path": "files/k",
                "env": {"HOME": "{data}"},
                "args": ["--a"],
            }
        ]
    )
    c = parse_manifest(data).commands[0]
    assert c.env == {"HOME": "{data}"} and c.args == ["--a"]


def test_defaults_for_optional_fields():
    data = sample_manifest()
    del data["tags"], data["examples"], data["needs_root"]
    m = parse_manifest(data)
    assert m.tags == [] and m.examples == [] and m.needs_root is False


def expect_error(data, field):
    with pytest.raises(ToolError) as info:
        parse_manifest(data)
    assert field in str(info.value)


@pytest.mark.parametrize("schema", [4, 0, "1", True, None])
def test_an_unknown_schema_says_to_upgrade(schema):
    with pytest.raises(ToolError, match="upgrade pwn-broker"):
        parse_manifest(sample_manifest(schema=schema))


def test_a_manifest_without_a_schema_cannot_be_read():
    data = sample_manifest()
    del data["schema"]
    with pytest.raises(ToolError) as err:
        parse_manifest(data)
    assert "cannot be read" in str(err.value) and "upgrade" not in str(err.value)


@pytest.mark.parametrize(
    "name",
    ["", "Upper", "-lead", "a b", "a/b", "a_b", 5, ".a", "a.", "a..b", "..", ".", "a\\b", "a/.b"],
)
def test_bad_name(name):
    expect_error(sample_manifest(name=name), "name")


@pytest.mark.parametrize(
    "version",
    [
        "", "1/2", "1\\2", "1 2", "1\t2", 1, "1\x00x", "1.0\x1b[2J", "1\n2", "..", ".", "-1", "+1",
        "1:2", "1.0\u202e", "1.0é", "1" * 101,
    ],
)  # fmt: skip
def test_bad_version(version):
    expect_error(sample_manifest(version=version), "version")


@pytest.mark.parametrize(
    "version", ["1.0.3", "2026.11.14", "5.1.0", "3.13.18", "1.0~rc1", "1.0+git5", "v1_2", "7", "1" * 100]
)
def test_the_versions_packages_use_are_allowed(version):
    assert parse_manifest(sample_manifest(version=version)).version == version


@pytest.mark.parametrize("build", [0, -1, "1", 1.0, True])
def test_bad_build(build):
    expect_error(sample_manifest(build=build), "build")


def test_bad_kind():
    expect_error(sample_manifest(kind="other"), "kind")


@pytest.mark.parametrize("field", ["description", "upstream", "licence", "arch"])
def test_required_strings(field):
    expect_error(sample_manifest(**{field: ""}), field)
    data = sample_manifest()
    del data[field]
    expect_error(data, field)


def test_bad_tags_examples_needs_root():
    expect_error(sample_manifest(tags="x"), "tags")
    expect_error(sample_manifest(examples=[1]), "examples")
    expect_error(sample_manifest(needs_root="yes"), "needs_root")


def test_kind_command_upload_rules():
    up = [{"path": "files/a", "as": "a"}]
    expect_error(sample_manifest(command=[]), "command")
    expect_error(sample_manifest(upload=up), "upload")
    expect_error(sample_manifest(kind="upload", command=[], upload=[]), "upload")
    expect_error(sample_manifest(kind="upload", upload=up), "command")
    expect_error(sample_manifest(kind="both"), "upload")
    expect_error(sample_manifest(kind="both", command=[], upload=up), "command")


def test_command_name_rules():
    expect_error(sample_manifest(command=[{"name": "-x", "type": "binary", "path": "files/x"}]), "name")
    dup = {"name": "x", "type": "binary", "path": "files/x"}
    expect_error(sample_manifest(command=[dup, dict(dup)]), "name")


def test_command_type_and_target_fields():
    expect_error(sample_manifest(command=[{"name": "x", "type": "shell", "path": "files/x"}]), "type")
    expect_error(sample_manifest(command=[{"name": "x", "type": "binary"}]), "path")
    expect_error(python_manifest(entry=""), "entry")
    expect_error(python_manifest(type="python-script", entry=""), "script")


def test_entry_is_a_plain_name():
    expect_error(python_manifest(entry="bin/tool"), "entry")


def test_python_table_exactly_when_python_commands():
    data = python_manifest()
    del data["python"]
    expect_error(data, "python")
    data = sample_manifest(python={"versions": ["3.12"], "lock": "wheels.lock", "wheels": "wheels"})
    expect_error(data, "python")


def test_python_needs_a_version_and_clean_paths():
    base = {"versions": ["3.12"], "lock": "wheels.lock", "wheels": "wheels"}
    for change in (
        {"versions": []},
        {"versions": [3]},
        {"lock": ""},
        {"lock": "files/wheels.lock"},
        {"lock": "/wheels.lock"},
        {"wheels": "../wheels"},
        {"wheels": "files/w"},
    ):
        data = python_manifest()
        data["python"] = {**base, **change}
        expect_error(data, "python." + next(iter(change)))


@pytest.mark.parametrize("path", ["/files/x", "files/../x", "files\\x", "other/x", "x", "", "files/./x"])
def test_binary_path_rules(path):
    expect_error(sample_manifest(command=[{"name": "x", "type": "binary", "path": path}]), "path")


def test_script_path_rules():
    expect_error(python_manifest(type="python-script", script="tool.py", entry=""), "script")
    expect_error(python_manifest(type="python-script", script="files/../t", entry=""), "script")


@pytest.mark.parametrize("path", ["/files/x", "files/../x", "x", ""])
def test_upload_path_rules(path):
    data = both_manifest()
    data["upload"][0]["path"] = path
    expect_error(data, "upload")


@pytest.mark.parametrize("as_name", ["", "a/b", "a\\b", "..", "."])
def test_upload_as_is_a_plain_name(as_name):
    data = both_manifest()
    data["upload"][0]["as"] = as_name
    expect_error(data, "as")


@pytest.mark.parametrize("home", [[""], ["."], ["/x"], ["../x"], ["a/../b"], [1], "x"])
def test_home_rules(home):
    data = both_manifest()
    data["data"] = {"home": home}
    expect_error(data, "home")


def test_read_manifest(tmp_path):
    path = tmp_path / "manifest.toml"
    path.write_text(tomli_w.dumps(sample_manifest()), encoding="utf-8")
    assert toolpkg.read_manifest(path).name == "kerbrute"
    path.write_text("schema = [", encoding="utf-8")
    with pytest.raises(ToolError):
        toolpkg.read_manifest(path)
    with pytest.raises(ToolError):
        toolpkg.read_manifest(tmp_path / "missing.toml")


def test_names():
    assert toolpkg.build_id("1.0.3", 1) == "1.0.3-1"
    assert toolpkg.zip_name("kerbrute", "1.0.3", 1) == "kerbrute-1.0.3-1.zip"


@pytest.mark.parametrize(
    "machine, expected",
    [
        ("x86_64", "x86_64"),
        ("AMD64", "x86_64"),
        ("amd64", "x86_64"),
        ("aarch64", "arm64"),
        ("arm64", "arm64"),
        ("RISCV64", "riscv64"),
    ],
)
def test_machine_arch(monkeypatch, machine, expected):
    monkeypatch.setattr(toolpkg.platform, "machine", lambda: machine)
    assert toolpkg.machine_arch() == expected


# ---- verify_zip


def test_verify_zip(tmp_path):
    path, size, digest = make_package(tmp_path, sample_manifest(), {"files/kerbrute": b"bin"})
    toolpkg.verify_zip(path, size=size, sha256=digest)
    with pytest.raises(ToolError, match="size"):
        toolpkg.verify_zip(path, size=size + 1, sha256=digest)
    with pytest.raises(ToolError, match="SHA-256"):
        toolpkg.verify_zip(path, size=size, sha256="0" * 64)
    altered = bytearray(path.read_bytes())
    altered[-1] ^= 1
    path.write_bytes(bytes(altered))
    with pytest.raises(ToolError, match="SHA-256"):
        toolpkg.verify_zip(path, size=size, sha256=digest)
    path.write_bytes(bytes(altered)[:-10])
    with pytest.raises(ToolError, match="size"):
        toolpkg.verify_zip(path, size=size, sha256=digest)
    with pytest.raises(ToolError):
        toolpkg.verify_zip(tmp_path / "gone.zip", size=1, sha256=digest)


# ---- unpack


def test_unpack_restores_files(tmp_path):
    files = {"files/kerbrute": b"bin", "files/sub/data.txt": b"d"}
    path, _, _ = make_package(tmp_path / "pkg", sample_manifest(), files)
    dest = tmp_path / "out" / "kerbrute-1.0.3-1"
    m = unpack(path, dest)
    assert m.name == "kerbrute"
    assert (dest / "files/kerbrute").read_bytes() == b"bin"
    assert (dest / "files/sub/data.txt").read_bytes() == b"d"
    assert (dest / "manifest.toml").is_file() and (dest / "LICENSE").is_file()
    if sys.platform != "win32":
        assert stat.S_IMODE((dest / "files/kerbrute").stat().st_mode) == 0o755


def test_unpack_python_package(tmp_path):
    wheel = make_wheel(tmp_path / "w", "impacket", "0.12.0", module="impacket", entry="impacket-smbserver")
    path, _, _ = make_package(tmp_path / "pkg", python_manifest(), {}, wheels=[wheel])
    dest = tmp_path / "dest"
    m = unpack(path, dest)
    assert m.python is not None
    assert (dest / "wheels" / wheel.name).is_file()
    assert "--hash=sha256:" in (dest / "wheels.lock").read_text()


def test_unpack_accepts_directory_entries(tmp_path):
    path = tmp_path / "p.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("manifest.toml", tomli_w.dumps(sample_manifest()))
        zf.writestr("files/", b"")
        zf.writestr("files/empty/", b"")
        zf.writestr("files/kerbrute", b"x")
    unpack(path, tmp_path / "d")
    assert (tmp_path / "d/files/empty").is_dir()


def test_unpack_refuses_existing_dest(tmp_path):
    path, _, _ = make_package(tmp_path / "pkg", sample_manifest(), {"files/kerbrute": b"x"})
    dest = tmp_path / "dest"
    dest.mkdir()
    (dest / "keep").write_text("k")
    with pytest.raises(ToolError, match="exists"):
        unpack(path, dest)
    assert (dest / "keep").read_text() == "k"


def raw_zip(tmp_path, members, manifest=None):
    """members: (name, data, mode or None); the name is kept exactly as given."""
    path = tmp_path / "hostile.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("manifest.toml", tomli_w.dumps(manifest or sample_manifest()))
        for name, data, mode in members:
            info = zipfile.ZipInfo("placeholder")
            info.filename = name
            if mode is not None:
                info.external_attr = mode << 16
            zf.writestr(info, data)
    return path


def tree(root):
    return sorted(root.rglob("*"))


def refused(tmp_path, members, manifest=None):
    path = raw_zip(tmp_path, members, manifest)
    assert_clean_failure(tmp_path, path)


def assert_clean_failure(tmp_path, path, exc=ToolError):
    # dest sits two levels below a folder that exists, so parents made on the way are caught
    work = tmp_path / "work"
    work.mkdir(exist_ok=True)
    dest = work / "p" / "q" / "dest"
    before = tree(tmp_path)
    with pytest.raises(exc) as info:
        unpack(path, dest)
    assert not dest.exists()
    assert tree(tmp_path) == before
    return info.value


GOOD = ("files/kerbrute", b"x", None)


@pytest.mark.parametrize(
    "name",
    [
        "/etc/passwd",
        "files/../../escape",
        "../escape",
        "files/a\\..\\b",
        "C:/x",
        "c:",
        "files//x",
        "files/./x",
        "other.txt",
        "files",
        "wheels",
        "manifest.toml/x",
        "LICENSE2",
    ],
)
def test_hostile_names_refused(tmp_path, name):
    refused(tmp_path, [GOOD, (name, b"bad", None)])


def test_link_refused(tmp_path):
    refused(tmp_path, [GOOD, ("files/link", b"/etc/passwd", stat.S_IFLNK | 0o777)])


def test_special_file_refused(tmp_path):
    refused(tmp_path, [GOOD, ("files/fifo", b"", stat.S_IFIFO | 0o644)])


def test_duplicate_entry_refused(tmp_path):
    with pytest.warns(UserWarning, match="Duplicate"):
        path = raw_zip(tmp_path, [GOOD, ("files/kerbrute", b"y", None)])
    with pytest.raises(ToolError, match="twice"):
        unpack(path, tmp_path / "dest")
    assert not (tmp_path / "dest").exists()


def test_duplicate_manifest_refused(tmp_path):
    with pytest.warns(UserWarning, match="Duplicate"):
        path = raw_zip(tmp_path, [GOOD, ("manifest.toml", b"schema = 1", None)])
    with pytest.raises(ToolError):
        unpack(path, tmp_path / "dest")


def test_file_under_directory_clash_refused(tmp_path):
    refused(tmp_path, [GOOD, ("files/kerbrute/inner", b"y", None)])


def test_missing_or_bad_manifest(tmp_path):
    path = tmp_path / "p.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("files/kerbrute", b"x")
    with pytest.raises(ToolError, match="manifest.toml"):
        unpack(path, tmp_path / "d1")
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("manifest.toml", "name = [")
    with pytest.raises(ToolError):
        unpack(path, tmp_path / "d2")
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("manifest.toml", tomli_w.dumps(sample_manifest(schema=4)))
    with pytest.raises(ToolError, match="upgrade"):
        unpack(path, tmp_path / "d3")
    assert not (tmp_path / "d1").exists() and not (tmp_path / "d2").exists()


def test_not_a_zip(tmp_path):
    path = tmp_path / "p.zip"
    path.write_bytes(b"not a zip at all")
    with pytest.raises(ToolError):
        unpack(path, tmp_path / "d")


def test_named_files_must_exist(tmp_path):
    refused(tmp_path, [])  # the command's binary is missing
    refused(
        tmp_path,
        [GOOD],
        both_manifest(),  # the upload is missing
    )
    refused(tmp_path, [("files/kerbrute/", b"", None)])  # a folder is not a file


def test_python_files_must_exist(tmp_path):
    wheel = make_wheel(tmp_path / "w", "impacket", "0.12.0", module="impacket", entry="x")
    data = python_manifest()
    with zipfile.ZipFile(tmp_path / "nolock.zip", "w") as zf:
        zf.writestr("manifest.toml", tomli_w.dumps(data))
        zf.writestr(f"wheels/{wheel.name}", wheel.read_bytes())
    with pytest.raises(ToolError, match="wheels.lock"):
        unpack(tmp_path / "nolock.zip", tmp_path / "d1")
    with zipfile.ZipFile(tmp_path / "nowheel.zip", "w") as zf:
        zf.writestr("manifest.toml", tomli_w.dumps(data))
        zf.writestr("wheels.lock", "x==1 --hash=sha256:00\n")
    with pytest.raises(ToolError, match="wheels"):
        unpack(tmp_path / "nowheel.zip", tmp_path / "d2")
    assert not (tmp_path / "d1").exists() and not (tmp_path / "d2").exists()


def test_failure_midway_removes_dest(tmp_path, monkeypatch):
    path, _, _ = make_package(
        tmp_path / "pkg", sample_manifest(), {"files/kerbrute": b"x", "files/more": b"y"}
    )
    real = toolpkg._write_member
    calls = []

    def flaky(zf, info, target, mode):
        calls.append(info.filename)
        if len(calls) == 3:
            raise OSError("disk full")
        real(zf, info, target, mode)

    monkeypatch.setattr(toolpkg, "_write_member", flaky)
    err = assert_clean_failure(tmp_path, path)
    assert "disk full" in str(err)


def test_size_mismatch_refused(tmp_path):
    path = raw_zip(tmp_path, [GOOD])
    data = bytearray(path.read_bytes())
    # lie about the uncompressed size in the central directory entry for files/kerbrute
    start = data.rindex(b"PK\x01\x02")  # the last central entry is files/kerbrute
    data[start + 24 : start + 28] = (5).to_bytes(4, "little")
    path.write_bytes(bytes(data))
    assert_clean_failure(tmp_path, path)


def test_encrypted_member_refused(tmp_path):
    path = raw_zip(tmp_path, [GOOD])
    data = bytearray(path.read_bytes())
    pos = data.rindex(b"PK\x01\x02")
    data[pos + 8] |= 1  # general purpose flag bit 0
    path.write_bytes(bytes(data))
    assert_clean_failure(tmp_path, path)


def test_bad_utf8_name_with_utf8_flag(tmp_path):
    path = raw_zip(tmp_path, [GOOD])
    data = bytearray(path.read_bytes())
    start = data.rindex(b"PK\x01\x02")
    data[start + 9] |= 0x08  # UTF-8 name flag
    data[start + 46 + 13] = 0xFF  # last character of the name
    path.write_bytes(bytes(data))
    assert_clean_failure(tmp_path, path)


def test_corrupt_local_header_mid_extraction(tmp_path):
    path = raw_zip(tmp_path, [GOOD])
    data = bytearray(path.read_bytes())
    local = data.rindex(b"PK")  # the last member is files/kerbrute
    assert data[local : local + 4] == b"PK\x03\x04"
    data[local + 7] |= 0x08
    data[local + 30 + 13] = 0xFF
    path.write_bytes(bytes(data))
    assert_clean_failure(tmp_path, path)


def test_case_only_collision(tmp_path):
    path = raw_zip(tmp_path, [GOOD, ("files/KERBRUTE", b"y", None)])
    work = tmp_path / "work"
    work.mkdir()
    dest = work / "p" / "q" / "dest"
    before = tree(tmp_path)
    try:
        unpack(path, dest)
    except ToolError:
        # a case-insensitive file system: nothing may be left behind
        assert tree(tmp_path) == before
    else:
        assert dest.is_dir()


def test_compressed_member_refused(tmp_path):
    path = tmp_path / "c.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("manifest.toml", tomli_w.dumps(sample_manifest()))
        zf.writestr("files/kerbrute", b"x" * 1000, compress_type=zipfile.ZIP_DEFLATED)
    assert "compressed" in str(assert_clean_failure(tmp_path, path))


def test_too_many_members(tmp_path, monkeypatch):
    path = raw_zip(tmp_path, [GOOD, ("files/b", b"y", None)])
    monkeypatch.setattr(toolpkg, "MAX_MEMBERS", 2)
    assert "entries" in str(assert_clean_failure(tmp_path, path))


def test_too_much_declared_size(tmp_path, monkeypatch):
    path = raw_zip(tmp_path, [GOOD])
    monkeypatch.setattr(toolpkg, "MAX_UNPACKED_BYTES", 10)
    assert "bytes" in str(assert_clean_failure(tmp_path, path))


def test_interrupt_propagates_and_cleans_up(tmp_path, monkeypatch):
    path, _, _ = make_package(
        tmp_path / "pkg", sample_manifest(), {"files/kerbrute": b"x", "files/more": b"y"}
    )
    calls = []

    def interrupted(zf, info, target, mode):
        calls.append(info.filename)
        if len(calls) == 2:
            raise KeyboardInterrupt
        target.write_bytes(b"partial")

    monkeypatch.setattr(toolpkg, "_write_member", interrupted)
    assert_clean_failure(tmp_path, path, KeyboardInterrupt)


def test_existing_dest_is_left_alone(tmp_path):
    path = raw_zip(tmp_path, [GOOD])
    dest = tmp_path / "dest"
    (dest / "inner").mkdir(parents=True)
    with pytest.raises(ToolError, match="exists"):
        unpack(path, dest)
    assert (dest / "inner").is_dir()


@pytest.mark.parametrize("name", ["", "/x", "a\\b", "a/../b", "a\0b", "C:/x", "x:", "a/b/.."])
def test_check_name_text(name):
    with pytest.raises(ToolError):
        toolpkg._check_name(name)


# ---- the wheel helper


@pytest.mark.skipif(
    os.environ.get("PWN_SKIP_PIP_TEST") == "1", reason="PWN_SKIP_PIP_TEST is set"
)
def test_make_wheel_installs_with_pip(tmp_path):
    folder = tmp_path / "wheels"
    make_wheel(folder, "toy-dist", "1.2.3", module="toymod", entry="toy")
    env = tmp_path / "env"
    venv.EnvBuilder(with_pip=False).create(env)
    scripts = env / ("Scripts" if sys.platform == "win32" else "bin")
    python = scripts / ("python.exe" if sys.platform == "win32" else "python")
    done = subprocess.run(
        [sys.executable, "-m", "pip", "--python", str(python), "install",
         "--no-index", "--find-links", str(folder), "toy-dist"],
        capture_output=True,
        text=True,
    )
    assert done.returncode == 0, done.stdout + done.stderr
    ran = subprocess.run(
        [str(python), "-c", "import toymod; toymod.main()"], capture_output=True, text=True
    )
    assert ran.stdout.strip() == "toy-dist 1.2.3"
    console = scripts / ("toy.exe" if sys.platform == "win32" else "toy")
    assert console.exists()


# ---- wheels.lock


LOCK_HASH = "--hash=sha256:" + "0123456789abcdef" * 4


def test_check_lock_accepts_pins_with_hashes():
    toolpkg.check_lock(f"a==1.0 {LOCK_HASH}\nb.c_d-e==2!1.0+local {LOCK_HASH} {LOCK_HASH}\n".encode())


def test_the_lock_the_test_packages_carry_passes(tmp_path):
    wheel = make_wheel(tmp_path / "w", "kerbrute-py", "1.0", module="kmod", entry="kerbrute")
    data = sample_manifest(
        command=[{"name": "kerbrute", "type": "python-entry", "entry": "kerbrute"}],
        python={"versions": ["3.13"], "lock": "wheels.lock", "wheels": "wheels"},
    )
    zip_path, _size, _sha = make_package(tmp_path / "pkg", data, {}, wheels=[wheel])
    with zipfile.ZipFile(zip_path) as zf:
        toolpkg.check_lock(zf.read("wheels.lock"))
    assert unpack(zip_path, tmp_path / "out").python is not None


@pytest.mark.parametrize(
    ("raw", "where"),
    [
        (b"", "empty"),
        (f"a==1 {LOCK_HASH}".encode(), "line 1"),
        (f"a==1 {LOCK_HASH}\n# note\n".encode(), "line 2"),
        (f"a==1 {LOCK_HASH.upper()}\n".encode(), "line 1"),
        (f"a==1  {LOCK_HASH}\n".encode(), "line 1"),
        (f"a==1 {LOCK_HASH} \n".encode(), "line 1"),
        (f"a>=1 {LOCK_HASH}\n".encode(), "line 1"),
        (f"a==1 --hash=sha512:{'0' * 128}\n".encode(), "line 1"),
        (b"\xff\xfe\n", "UTF-8"),
        (f"a==1 {LOCK_HASH}\r\n".encode(), "line 1"),
    ],
)
def test_check_lock_refuses_and_names_the_line(raw, where):
    with pytest.raises(ToolError, match=where):
        toolpkg.check_lock(raw)


def test_check_lock_has_a_size_cap():
    line = f"a==1 {LOCK_HASH}\n".encode()
    with pytest.raises(ToolError, match="too large"):
        toolpkg.check_lock(line * (1024 * 1024 // len(line) + 1))


# ---- command names


RESERVED = (
    "sh bash dash zsh fish env "
    "sudo sudoedit su doas pkexec run0 passwd login ssh scp sftp gpg "
    "python python3 pip pip3 "
    "chown cp rm kill ip ping tar vim openvpn x-terminal-emulator pwn-broker record asciinema "
    "sed cut mkdir cat ls mv ln vi grep awk find head tail chmod id uname test "
    "whoami hostname sleep touch tee which ps tput dircolors xargs timeout nohup "
    "less more pager man nano editor "
    "ssh-agent ssh-add ssh-keygen newgrp visudo "
    "apt apt-get dpkg systemctl mount umount "
    "curl wget git"
).split()


def test_the_reserved_names_are_exactly_these():
    assert sorted(toolpkg.RESERVED_COMMANDS) == sorted(RESERVED)
    assert len(RESERVED) == len(set(RESERVED))


@pytest.mark.parametrize("name", RESERVED)
def test_reserved_command_names_are_refused(name):
    assert not toolpkg.valid_command_name(name)
    data = sample_manifest(command=[{"name": name, "type": "binary", "path": "files/kerbrute"}])
    with pytest.raises(ToolError, match=f"{name!r} is reserved"):
        parse_manifest(data)


def test_names_that_only_look_reserved_are_allowed():
    for name in ("sed2", "Sudo", "pythonic", "pipx", "python-ldap", "kerbrute"):
        assert toolpkg.valid_command_name(name)


@pytest.mark.parametrize(
    "name",
    [
        "python3.13", "python3.14", "python2", "python3.", "pip3.13", "pip2", "python3.13t",
        "python3.14t", "python3.13d", "python3-config", "python3.13-config", "pip3.13t",
    ],
)  # fmt: skip
def test_python_and_pip_under_a_versioned_name_are_refused(name):
    assert not toolpkg.valid_command_name(name)
    data = sample_manifest(command=[{"name": name, "type": "binary", "path": "files/kerbrute"}])
    with pytest.raises(ToolError, match="is reserved"):
        parse_manifest(data)


_CALLS_THAT_RUN = {"run", "Popen", "call", "check_call", "check_output", "run_privileged", "privileged_argv"}


def _programs_named_at_call_sites() -> set[str]:
    """The first word of every argument list written out where the app starts a program."""
    found = set()
    for path in sorted(Path(toolpkg.__file__).parent.rglob("*.py")):
        for node in ast.walk(ast.parse(path.read_text(encoding="utf-8"))):
            if not isinstance(node, ast.Call):
                continue
            called = getattr(node.func, "attr", None) or getattr(node.func, "id", None)
            if called not in _CALLS_THAT_RUN:
                continue
            for arg in node.args:
                if isinstance(arg, ast.List) and arg.elts:
                    first = arg.elts[0]
                    if isinstance(first, ast.Constant) and isinstance(first.value, str):
                        found.add(first.value)
    return found


def test_every_program_the_app_runs_by_name_is_reserved():
    # /opt/pwn-broker/bin is first on PATH, so a launcher by one of these names would be run by
    # the app itself, as root when the app is. The scan sees only an argument list written out
    # where a program is started; one built in a variable or returned from a function has to be
    # named in `named` below by hand, as vim, sudo, the VPN and the terminal are
    scanned = _programs_named_at_call_sites()
    assert {"chown", "cp", "ping", "ip", "kill"} <= scanned  # the scan still finds them
    named = scanned | {"sudo", "vim", vpnctl.COMMAND, config.Settings().terminal}
    assert sorted(n for n in named if "/" not in n and toolpkg.valid_command_name(n)) == []


# ---- home entries


SHARED = (
    ".config .local .local/share .local/bin .cache .bashrc .zshrc .profile .bash_profile "
    ".bash_history .zsh_history .vimrc .gitconfig Desktop Documents Downloads"
).split()


@pytest.mark.parametrize(
    "entry", [".ssh", ".ssh/id_ed25519", ".ssh/x/y", ".gnupg", ".gnupg/pubring.kbx", *SHARED]
)
def test_home_entries_that_are_shared_places_are_refused(entry):
    data = both_manifest()
    data["data"] = {"home": [".kerbrute", entry]}
    with pytest.raises(ToolError, match=f"data.home: {entry!r}"):
        parse_manifest(data)


@pytest.mark.parametrize("entry", [".config/kerbrute", ".local/share/kerbrute", ".cache/kerbrute"])
def test_home_entries_inside_shared_places_are_allowed(entry):
    data = both_manifest()
    data["data"] = {"home": [entry]}
    assert parse_manifest(data).home == [entry]


@pytest.mark.parametrize("entry", [".sshx", "desktop", ".Config"])
def test_home_entries_that_only_look_shared_are_still_not_the_tools_own(entry):
    data = both_manifest()
    data["data"] = {"home": [entry]}
    with pytest.raises(ToolError, match="is not this tool's own folder"):
        parse_manifest(data)


# ---- names with dots


@pytest.mark.parametrize("name", ["python-3.13", "a", "0", "a.b.c", "a-.b", "kerbrute", "x-1.2-3"])
def test_valid_tool_names(name):
    assert toolpkg.valid_tool_name(name)
    assert parse_manifest(sample_manifest(name=name)).name == name


@pytest.mark.parametrize(
    "name", ["", ".a", "a.", "a..b", ".", "..", "-a", "A", "a_b", "a/b", "a\\b", "a b", "a.\n", "a\n"]
)
def test_invalid_tool_names(name):
    assert not toolpkg.valid_tool_name(name)


def test_a_bad_name_message_gives_the_rule():
    with pytest.raises(ToolError) as info:
        parse_manifest(sample_manifest(name="a..b"))
    assert "name: 'a..b' must be lower-case letters, digits, hyphens and dots" in str(info.value)


def test_zip_name_with_a_dot():
    assert toolpkg.zip_name("python-3.13", "3.13.18", 1) == "python-3.13-3.13.18-1.zip"


def test_kinds_and_schemas():
    assert toolpkg.KINDS == ("kali", "upload", "both", "runtime", "notes")
    # pwn-shop pins the same pattern, so the two repositories accept the same names
    assert toolpkg._NAME.pattern == r"[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*"
    assert toolpkg.SCHEMAS == (1, 2, 3)


# ---- schema 1 as before


def test_schema_1_manifests_parse_as_before():
    m = parse_manifest(python_manifest())
    assert (m.schema, m.requires, m.runtime) == (1, [], None)
    assert m.python.versions == ["3.12", "3.13"]
    assert parse_manifest(sample_manifest()).schema == 1


def test_schema_1_refuses_requires():
    with pytest.raises(ToolError, match="requires: a schema 1 package cannot require anything"):
        parse_manifest(python_manifest() | {"requires": ["python-3.13"]})
    with pytest.raises(ToolError, match="requires: a schema 1"):
        parse_manifest(sample_manifest() | {"requires": []})


def test_schema_1_refuses_kind_runtime():
    with pytest.raises(ToolError, match="kind: a runtime needs schema 2"):
        parse_manifest(sample_manifest(kind="runtime", schema=1))


def test_manifest_fields_have_defaults_for_positional_callers():
    m = parse_manifest(sample_manifest())
    rebuilt = toolpkg.Manifest(
        m.name, m.version, m.build, m.kind, m.description, m.tags, m.upstream, m.licence,
        m.arch, m.needs_root, m.examples, m.commands, m.uploads, m.python, m.home,
    )  # fmt: skip
    assert rebuilt == m


# ---- schema 2: a runtime


def test_runtime_manifest_parses():
    m = parse_manifest(sample_manifest(kind="runtime"))
    assert (m.schema, m.name, m.version, m.kind) == (2, "python-3.13", "3.13.18", "runtime")
    assert m.runtime == toolpkg.RuntimeSpec(
        archive="files/python.tar.gz", python="python/bin/python3.13", series="3.13"
    )
    assert m.commands == [] and m.uploads == [] and m.python is None and m.home == []
    assert m.requires == []


@pytest.mark.parametrize(
    "key, value, message",
    [
        ("command", [{"name": "py", "type": "binary", "path": "files/py"}], "command: a runtime has no [[command]]"),
        ("command", [], "command: a runtime has no [[command]]"),
        ("upload", [{"path": "files/a", "as": "a"}], "upload: a runtime has no [[upload]]"),
        ("data", {"home": [".py"]}, "data: a runtime has no [data]"),
        ("python", {"lock": "wheels.lock", "wheels": "wheels"}, "python: a runtime has no [python]"),
    ],
)
def test_a_runtime_refuses_tool_tables(key, value, message):
    with pytest.raises(ToolError) as info:
        parse_manifest(sample_manifest(kind="runtime", **{key: value}))
    assert message in str(info.value)


def test_a_runtime_requires_nothing():
    with pytest.raises(ToolError, match="requires: a runtime requires nothing"):
        parse_manifest(sample_manifest(kind="runtime", requires=["python-3.12"]))
    assert parse_manifest(sample_manifest(kind="runtime", requires=[])).requires == []


def test_a_runtime_needs_its_table():
    data = sample_manifest(kind="runtime")
    del data["runtime"]
    with pytest.raises(ToolError) as info:
        parse_manifest(data)
    assert "runtime: a runtime package needs a [runtime] table" in str(info.value)
    with pytest.raises(ToolError, match="runtime: must be a table"):
        parse_manifest(sample_manifest(kind="runtime", runtime="files/python.tar.gz"))


# ---- notes packages


def test_notes_manifest_parses():
    m = parse_manifest(sample_manifest(kind="notes"))
    assert m.kind == "notes"
    assert m.notes.root == "files/playbooks"
    assert m.commands == [] and m.uploads == []
    assert m.arch == "any"
    assert m.schema == 3


def test_notes_needs_schema_3():
    with pytest.raises(ToolError, match="kind: notes needs schema 3"):
        parse_manifest(sample_manifest(kind="notes", schema=2))


@pytest.mark.parametrize("kind", ["kali", "runtime"])
def test_schema_3_is_only_for_notes(kind):
    with pytest.raises(ToolError, match="schema: only a notes package is schema 3"):
        parse_manifest(sample_manifest(kind=kind, schema=3))


@pytest.mark.parametrize(
    "key, value, message",
    [
        ("command", [{"name": "x", "type": "binary", "path": "files/x"}],
         "command: a notes package has no commands"),
        ("upload", [{"path": "files/x", "as": "x"}], "upload: a notes package has no uploads"),
        ("python", {"lock": "wheels.lock", "wheels": "wheels"},
         "python: a notes package has no Python"),
        ("requires", ["python-3.13"], "requires: a notes package requires nothing"),
        ("data", {"home": [".x"]}, "data: a notes package keeps no tool data"),
        ("needs_root", True, "needs_root: a notes package never needs root"),
        ("arch", "x86_64", 'arch: a notes package is for any machine (arch = "any")'),
    ],
)
def test_notes_refuses_what_it_cannot_have(key, value, message):
    with pytest.raises(ToolError) as info:
        parse_manifest(sample_manifest(kind="notes", **{key: value}))
    assert message in str(info.value)


def test_notes_root_must_be_under_files():
    with pytest.raises(ToolError, match="notes.root"):
        parse_manifest(sample_manifest(kind="notes", notes={"root": "playbooks"}))
    data = sample_manifest(kind="notes")
    del data["notes"]
    with pytest.raises(ToolError) as info:
        parse_manifest(data)
    assert "notes: a notes package needs a [notes] table" in str(info.value)


def test_notes_package_must_hold_a_playbook(tmp_path):
    path, _size, _sha = make_package(
        tmp_path, sample_manifest(kind="notes"), {"files/playbooks/readme.txt": b"no playbook\n"}
    )
    with pytest.raises(ToolError) as info:
        toolpkg.package_manifest(path)
    assert "files/playbooks: the package holds no .md files" in str(info.value)


def test_notes_package_with_playbooks_passes_its_checks(tmp_path):
    path, _size, _sha = make_package(tmp_path, sample_manifest(kind="notes"), notes_files())
    assert toolpkg.package_manifest(path).kind == "notes"


def test_arch_fits():
    assert toolpkg.arch_fits("any")
    assert toolpkg.arch_fits(toolpkg.machine_arch())
    assert not toolpkg.arch_fits("sparc")


@pytest.mark.parametrize(
    "change, field",
    [
        ({"archive": ""}, "runtime.archive"),
        ({"archive": "python.tar.gz"}, "runtime.archive"),
        ({"archive": "wheels/python.tar.gz"}, "runtime.archive"),
        ({"archive": "files/../python.tar.gz"}, "runtime.archive"),
        ({"archive": "/files/python.tar.gz"}, "runtime.archive"),
        ({"archive": "files\\python.tar.gz"}, "runtime.archive"),
        ({"archive": 5}, "runtime.archive"),
        ({"python": ""}, "runtime.python"),
        ({"python": "python/../../bin/python3"}, "runtime.python"),
        ({"python": "../python3"}, "runtime.python"),
        ({"python": "/usr/bin/python3"}, "runtime.python"),
        ({"python": "python\\bin\\python3"}, "runtime.python"),
        ({"python": "C:/python"}, "runtime.python"),
        ({"series": ""}, "runtime.series"),
        ({"series": "3"}, "runtime.series"),
        ({"series": "3.13.1"}, "runtime.series"),
        ({"series": "py3.13"}, "runtime.series"),
        ({"series": "3.13\n"}, "runtime.series"),
        ({"series": 3.13}, "runtime.series"),
    ],
)
def test_runtime_table_rules(change, field):
    data = sample_manifest(kind="runtime")
    data["runtime"] = {**data["runtime"], **change}
    expect_error(data, field)


def test_runtime_series_accepts_two_numbers():
    data = sample_manifest(kind="runtime")
    data["runtime"] = {**data["runtime"], "series": "3.10"}
    assert parse_manifest(data).runtime.series == "3.10"


# ---- schema 2: a tool that requires a runtime


def test_schema_2_python_tool_parses():
    m = parse_manifest(sample_manifest(requires=["python-3.13"]))
    assert (m.schema, m.requires, m.runtime) == (2, ["python-3.13"], None)
    assert m.python == toolpkg.PythonSpec([], "wheels.lock", "wheels")


def test_schema_2_python_tool_refuses_versions():
    data = sample_manifest(requires=["python-3.13"])
    data["python"]["versions"] = ["3.13"]
    with pytest.raises(ToolError, match="python.versions: schema 2 has no versions"):
        parse_manifest(data)


@pytest.mark.parametrize(
    "requires, message",
    [
        (["python-3.13", "python-3.13"], "requires: 'python-3.13' appears more than once"),
        (["kerbrute"], "requires: kerbrute cannot require itself"),
        (["Python-3.13"], "requires: 'Python-3.13' is not a valid package name"),
        (["python..3"], "requires: 'python..3' is not a valid package name"),
        (["../x"], "requires: '../x' is not a valid package name"),
        ([], "requires: a Python tool requires exactly one runtime; this one names 0"),
        (["python-3.13", "python-3.12"], "requires: a Python tool requires exactly one runtime; this one names 2"),
        ("python-3.13", "requires: must be a list of strings"),
        ([3], "requires: must be a list of strings"),
    ],
)
def test_requires_rules(requires, message):
    with pytest.raises(ToolError) as info:
        parse_manifest(sample_manifest(requires=requires))
    assert message in str(info.value)


def test_a_tool_that_is_not_python_requires_nothing():
    data = sample_manifest(requires=["python-3.13"])
    data["command"] = [{"name": "kerbrute", "type": "binary", "path": "files/kerbrute"}]
    del data["python"]
    with pytest.raises(ToolError, match="requires: a tool that is not Python requires nothing"):
        parse_manifest(data)


@pytest.mark.parametrize("requires", [None, []])
def test_a_tool_that_requires_nothing_must_be_schema_1(requires):
    data = sample_manifest(schema=2)
    if requires is not None:
        data["requires"] = requires
    with pytest.raises(
        ToolError,
        match="schema: a package that is not a runtime and requires nothing must be schema 1",
    ):
        parse_manifest(data)


def test_a_schema_2_python_tool_without_requires_is_refused():
    data = sample_manifest(requires=["python-3.13"])
    del data["requires"]
    with pytest.raises(ToolError, match="requires: a Python tool requires exactly one runtime"):
        parse_manifest(data)


# ---- schema 2 packages


def test_runtime_package_unpacks(tmp_path):
    path, _, _ = make_package(tmp_path / "pkg", sample_manifest(kind="runtime"), {})
    assert path.name == "python-3.13-3.13.18-1.zip"
    m = unpack(path, tmp_path / "out")
    assert m.runtime.archive == "files/python.tar.gz"
    assert (tmp_path / "out" / "files" / "python.tar.gz").is_file()
    assert toolpkg.package_manifest(path).kind == "runtime"


def test_runtime_archive_must_be_in_the_package(tmp_path):
    path = raw_zip(tmp_path, [("files/other.tar.gz", b"x", None)], sample_manifest(kind="runtime"))
    err = assert_clean_failure(tmp_path, path)
    assert "files/python.tar.gz: the runtime's archive is missing from the package" in str(err)


def test_runtime_archive_must_be_a_file(tmp_path):
    members = [("files/python.tar.gz/", b"", None), ("files/python.tar.gz/x", b"x", None)]
    path = raw_zip(tmp_path, members, sample_manifest(kind="runtime"))
    err = assert_clean_failure(tmp_path, path)
    assert "the runtime's archive is missing" in str(err)


def test_schema_2_python_package_unpacks(tmp_path):
    wheel = make_wheel(tmp_path / "w", "kerbrute-py", "1.0", module="kmod", entry="kerbrute")
    data = sample_manifest(requires=["python-3.13"])
    path, _, _ = make_package(tmp_path / "pkg", data, {}, wheels=[wheel])
    m = unpack(path, tmp_path / "out")
    assert m.requires == ["python-3.13"] and m.python.versions == []


# ---- modes


@pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX modes")
@pytest.mark.parametrize("mask", [0o000, 0o002, 0o077])
def test_unpack_sets_its_modes_whatever_the_umask(tmp_path, mask):
    files = {
        "files/kerbrute": b"bin",
        "files/sub/data.txt": b"d",
        "wheels/x-1-py3-none-any.whl": b"w",
        "wheels.lock": b"x\n",
    }
    path, _, _ = make_package(tmp_path / "pkg", sample_manifest(), files)
    dest = tmp_path / "out" / "tools" / "kerbrute-1.0.3-1"
    old = os.umask(mask)
    try:
        unpack(path, dest)
    finally:
        os.umask(old)

    def mode(rel):
        return stat.S_IMODE((dest / rel).stat().st_mode)

    assert mode("..") == 0o755 and mode("../..") == 0o755  # made on the way to dest
    for folder in (".", "files", "files/sub", "wheels"):
        assert mode(folder) == 0o755, folder
    for run in ("files/kerbrute", "files/sub/data.txt"):
        assert mode(run) == 0o755, run
    for plain in ("manifest.toml", "LICENSE", "wheels.lock", "wheels/x-1-py3-none-any.whl"):
        assert mode(plain) == 0o644, plain


# ---- names of entries


@pytest.mark.parametrize(
    "name",
    ["files/a\nb", "files/\x1b[2J", "files/a\x7fb", "files/tab\there", "files/C:/evil", "files/a:b", "files/a\rb"],
)
def test_an_entry_name_with_a_colon_or_control_character_is_refused(tmp_path, name):
    path = raw_zip(tmp_path, [GOOD, (name, b"x", None)])
    assert "backslash, colon or control character" in str(assert_clean_failure(tmp_path, path))


def test_an_entry_name_longer_than_a_path_may_be_is_refused(tmp_path):
    name = "files/" + "/".join(["d"] * 2100)
    path = raw_zip(tmp_path, [GOOD, (name, b"x", None)])
    assert "longer than 4096 bytes" in str(assert_clean_failure(tmp_path, path))


def test_an_entry_name_with_a_part_longer_than_a_file_name_may_be_is_refused(tmp_path):
    path = raw_zip(tmp_path, [GOOD, ("files/" + "n" * 256, b"x", None)])
    assert "a part longer than 255 bytes" in str(assert_clean_failure(tmp_path, path))


def test_an_entry_as_deep_as_a_name_may_be_unpacks(tmp_path):
    name = "/".join(["files", *["d"] * (toolpkg.MAX_DEPTH - 2), "x"])
    assert len(name.split("/")) == toolpkg.MAX_DEPTH
    path = raw_zip(tmp_path, [GOOD, (name, b"deep", None)])
    dest = tmp_path / "out"
    unpack(path, dest)
    assert dest.joinpath(*name.split("/")).read_bytes() == b"deep"


def test_an_entry_deeper_than_a_name_may_be_is_refused(tmp_path):
    # every level is looked at again for every file under it, so depth is what makes an unpack slow
    name = "/".join(["files", *["d"] * (toolpkg.MAX_DEPTH - 1), "x"])
    path = raw_zip(tmp_path, [GOOD, (name, b"deep", None)])
    assert f"more than {toolpkg.MAX_DEPTH} parts" in str(assert_clean_failure(tmp_path, path))


# ---- the list of entries


def test_a_list_of_entries_too_large_is_refused_before_it_is_counted(tmp_path, monkeypatch):
    path = raw_zip(tmp_path, [GOOD] + [(f"files/f{i}", b"", None) for i in range(200)])
    monkeypatch.setattr(toolpkg, "MAX_DIRECTORY_BYTES", 4096)
    # were the entries read and counted first, this would be the message
    monkeypatch.setattr(toolpkg, "MAX_MEMBERS", 2)
    assert "list of entries" in str(assert_clean_failure(tmp_path, path))
    with pytest.raises(ToolError, match="list of entries"):
        toolpkg.package_manifest(path)


def test_the_list_of_entries_is_read_in_one_piece(tmp_path, monkeypatch):
    # the limit is on that one read; if zipfile began reading the list in pieces, the limit would
    # stop nothing, and this is where it would show
    path = raw_zip(tmp_path, [GOOD] + [(f"files/f{i}", b"", None) for i in range(200)])
    sizes = []
    real = toolpkg._Limited.read

    def watch(self, size=-1):
        sizes.append(size)
        return real(self, size)

    monkeypatch.setattr(toolpkg._Limited, "read", watch)
    toolpkg.package_manifest(path)
    with zipfile.ZipFile(path) as zf:
        directory = sum(46 + len(i.filename.encode()) + len(i.extra) + len(i.comment) for i in zf.infolist())
    assert directory in sizes


def test_a_package_with_two_thousand_entries_is_within_the_limits(tmp_path):
    members = [GOOD] + [(f"files/lib/python3.13/site-packages/module_{i:04}.py", b"", None) for i in range(2000)]
    path = raw_zip(tmp_path, members)
    assert toolpkg.package_manifest(path).name == "kerbrute"


def test_a_manifest_larger_than_its_limit_is_refused(tmp_path, monkeypatch):
    path = raw_zip(tmp_path, [GOOD])
    monkeypatch.setattr(toolpkg, "_MANIFEST_LIMIT", 10)
    assert "manifest.toml is too large" in str(assert_clean_failure(tmp_path, path))


def test_an_entry_shorter_than_it_declares_is_refused(tmp_path, monkeypatch):
    path = raw_zip(tmp_path, [("files/kerbrute", b"x" * 10, None)])
    real = zipfile.ZipFile.open

    def short(self, name, *args, **kwargs):
        if getattr(name, "filename", name) == "files/kerbrute":
            return io.BytesIO(b"xx")
        return real(self, name, *args, **kwargs)

    monkeypatch.setattr(zipfile.ZipFile, "open", short)
    assert "is not the size it declares" in str(assert_clean_failure(tmp_path, path))


# ---- a manifest read from disk


def test_read_manifest_wraps_a_manifest_nested_too_deeply(tmp_path):
    path = tmp_path / "manifest.toml"
    path.write_text("a = " + "[" * 100_000 + "]" * 100_000 + "\n", encoding="utf-8")
    with pytest.raises(ToolError, match="cannot be read"):
        toolpkg.read_manifest(path)


def test_read_manifest_wraps_a_number_too_long_to_read(tmp_path):
    path = tmp_path / "manifest.toml"
    path.write_text("schema = 1\nbuild = " + "9" * 5000 + "\n", encoding="utf-8")
    with pytest.raises(ToolError, match="cannot be read"):
        toolpkg.read_manifest(path)


# ---- data.home


@pytest.mark.parametrize(
    "entry",
    [
        ".aws", ".aws/credentials", ".kube/config", ".docker/config.json", ".netrc", ".pgpass",
        ".password-store", ".mozilla", ".pki", ".local/share/keyrings", ".config/autostart",
        ".config/autostart/x.desktop", ".local/share/applications", ".config/gh", ".zshenv",
        ".zprofile", ".zlogin", ".bash_logout", ".ssh/config", ".gnupg/private-keys-v1.d",
        ".bash_aliases", ".bashrc.d", ".bashrc.d/x.sh", ".xprofile", ".xinitrc", ".xsession",
        ".Xauthority", ".inputrc", ".git-credentials", ".config/git", ".config/git/config",
        ".config/environment.d", ".config/fish", ".config/fish/config.fish", ".config/chromium",
        ".tmux.conf", ".vim", ".vim/plugin/x.vim", ".local/state", "Pictures", "Music", "Videos",
        "Public", "Templates",
    ],
)  # fmt: skip
def test_data_home_may_not_claim_what_holds_keys_or_runs_at_login(entry):
    expect_error(sample_manifest(data={"home": [entry]}), "data.home")


@pytest.mark.parametrize(
    "entry",
    [
        ".kerbrute", ".kerbrute/sub/deeper", ".config/kerbrute", ".config/kerbrute/settings.toml",
        ".local/share/kerbrute", ".local/state/kerbrute", ".cache/kerbrute", ".Kerbrute",
    ],
)  # fmt: skip
def test_data_home_may_claim_a_folder_named_after_the_tool(entry):
    assert parse_manifest(sample_manifest(data={"home": [entry]})).home == [entry]


@pytest.mark.parametrize("entry", [".ligolo-proxy", ".config/ligolo-proxy", ".cache/Ligolo-Proxy/x"])
def test_data_home_may_claim_a_folder_named_after_one_of_its_commands(entry):
    data = sample_manifest(
        name="ligolo-ng",
        command=[{"name": "ligolo-proxy", "type": "binary", "path": "files/kerbrute"}],
        data={"home": [entry]},
    )
    assert parse_manifest(data).home == [entry]


@pytest.mark.parametrize(
    "entry",
    [
        ".ligolo-proxy", ".config/certipy", ".local/share/other", ".kerb", ".kerbrutex",
        ".kerbrute-data", "kerbrute", "kerbrute/data", "Documents/kerbrute", ".config/sub/kerbrute",
        ".config/.kerbrute", ".local/kerbrute", ".Config/kerbrute", ".tool", ".config",
        ".xyz/kerbrute", "..kerbrute", ".",
    ],
)  # fmt: skip
def test_data_home_may_not_claim_a_folder_that_is_not_the_tools_own(entry):
    # finish moves what is there into the box and deletes it from the home folder, so a tool
    # may only name a folder that is plainly its own
    expect_error(sample_manifest(data={"home": [entry]}), "data.home")


def test_a_tool_named_like_a_private_place_still_may_not_claim_it():
    for name, entry in (("ssh", ".ssh"), ("aws", ".aws/credentials"), ("vim", ".vim")):
        data = sample_manifest(
            name=name,
            command=[{"name": "x-" + name, "type": "binary", "path": "files/kerbrute"}],
            data={"home": [entry]},
        )
        with pytest.raises(ToolError, match="is shared with everything else"):
            parse_manifest(data)


# ---- round 2: sizes, the limit on one read, folders made closed


def test_a_stored_entry_whose_two_sizes_differ_is_refused(tmp_path):
    path = raw_zip(tmp_path, [GOOD])
    with zipfile.ZipFile(path) as zf:
        infos = zf.infolist()
    infos[0].compress_size = infos[0].file_size + 5 * 1024 * 1024
    with pytest.raises(ToolError, match="does not hold the bytes it declares"):
        toolpkg._check_entries(infos)


def test_no_one_read_of_the_zip_may_be_larger_than_the_limit(monkeypatch):
    monkeypatch.setattr(toolpkg, "MAX_DIRECTORY_BYTES", 10)
    limited = toolpkg._Limited(io.BytesIO(b"0123456789abcdef"))
    assert limited.read(10) == b"0123456789"
    assert limited.tell() == 10 and limited.seek(0) == 0
    with pytest.raises(ToolError, match="list of entries"):
        limited.read(11)
    limited.seek(0)
    with pytest.raises(ToolError, match="list of entries"):
        limited.read()
    limited.seek(6)
    assert limited.read() == b"6789abcdef"
    assert limited.read(-1) == b""


def test_a_zip64_list_of_entries_over_the_real_limit_is_refused(tmp_path):
    # more than 65,535 entries, so the zip ends with the zip64 records; no limit is patched
    path = tmp_path / "many.zip"
    with zipfile.ZipFile(path, "w") as zf:
        zf.writestr("manifest.toml", tomli_w.dumps(sample_manifest()))
        for number in range(70_000):
            zf.writestr(f"files/{number:030}", b"")
    with pytest.raises(ToolError, match="list of entries"):
        toolpkg.package_manifest(path)
    assert "list of entries" in str(assert_clean_failure(tmp_path, path))


@pytest.mark.skipif(sys.platform == "win32", reason="needs POSIX modes")
def test_no_folder_is_ever_looser_than_it_ends_up(tmp_path, monkeypatch):
    files = {"files/kerbrute": b"bin", "files/sub/deep/data.txt": b"d"}
    path, _, _ = make_package(tmp_path / "pkg", sample_manifest(), files)
    made = []
    real = Path.mkdir

    def watch(self, *args, **kwargs):
        real(self, *args, **kwargs)
        made.append((self.name, stat.S_IMODE(os.stat(self).st_mode)))

    monkeypatch.setattr(Path, "mkdir", watch)
    old = os.umask(0)
    try:
        unpack(path, tmp_path / "out" / "tools" / "kerbrute-1.0.3-1")
    finally:
        os.umask(old)
    assert len(made) >= 6
    assert [entry for entry in made if entry[1] & 0o077] == []


@pytest.mark.skipif(sys.platform == "win32", reason="needs symbolic links")
def test_a_link_that_appears_where_a_folder_goes_is_not_followed(tmp_path, monkeypatch):
    files = {"files/kerbrute": b"bin", "files/sub/data.txt": b"d"}
    path, _, _ = make_package(tmp_path / "pkg", sample_manifest(), files)
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    dest = tmp_path / "out"
    real = toolpkg._write_member

    def plant(zf, info, target, mode):
        real(zf, info, target, mode)
        link = dest / "files" / "sub"
        if link.parent.is_dir() and not os.path.lexists(link):
            link.symlink_to(elsewhere, target_is_directory=True)

    monkeypatch.setattr(toolpkg, "_write_member", plant)
    with pytest.raises(ToolError, match="is not a folder"):
        unpack(path, dest)
    assert list(elsewhere.iterdir()) == []
    assert not os.path.lexists(dest)


# ---- round 3: the folders an entry's name makes


def test_the_folders_names_would_make_count_towards_the_limit(tmp_path, monkeypatch):
    # manifest.toml, files/kerbrute and files/a/b/c/x, and the folders files, a, b and c: seven
    path = raw_zip(tmp_path, [GOOD, ("files/a/b/c/x", b"", None)])
    monkeypatch.setattr(toolpkg, "MAX_MEMBERS", 6)
    assert "more than 6 files and folders" in str(assert_clean_failure(tmp_path, path))
    monkeypatch.setattr(toolpkg, "MAX_MEMBERS", 7)
    assert toolpkg.package_manifest(path).name == "kerbrute"


def test_a_folder_that_is_also_an_entry_is_counted_once(tmp_path, monkeypatch):
    path = raw_zip(tmp_path, [GOOD, ("files/a/", b"", None), ("files/a/x", b"", None)])
    # manifest.toml, files/kerbrute, files/a/ and files/a/x, and the folder files: five
    monkeypatch.setattr(toolpkg, "MAX_MEMBERS", 5)
    assert toolpkg.package_manifest(path).name == "kerbrute"
    monkeypatch.setattr(toolpkg, "MAX_MEMBERS", 4)
    with pytest.raises(ToolError, match="more than 4 files and folders"):
        toolpkg.package_manifest(path)


def test_a_folder_entry_listed_after_what_is_in_it_is_counted_once(tmp_path, monkeypatch):
    path = raw_zip(tmp_path, [GOOD, ("files/a/x", b"", None), ("files/a/", b"", None)])
    monkeypatch.setattr(toolpkg, "MAX_MEMBERS", 5)
    assert toolpkg.package_manifest(path).name == "kerbrute"
    monkeypatch.setattr(toolpkg, "MAX_MEMBERS", 4)
    with pytest.raises(ToolError, match="more than 4 files and folders"):
        toolpkg.package_manifest(path)


def test_a_few_entries_that_would_make_thousands_of_folders_are_refused(tmp_path):
    # each name makes 62 folders of its own; no limit is patched
    deep = "/".join(["a"] * (toolpkg.MAX_DEPTH - 3))
    members = [GOOD] + [(f"files/p{number}/{deep}/f", b"", None) for number in range(200)]
    path = raw_zip(tmp_path, members)
    assert "files and folders" in str(assert_clean_failure(tmp_path, path))


def test_a_folder_entry_as_deep_as_a_name_may_be_is_allowed(tmp_path):
    # the slash that marks a folder is not one more part
    name = "/".join(["files", *["d"] * (toolpkg.MAX_DEPTH - 1)]) + "/"
    path = raw_zip(tmp_path, [GOOD, (name, b"", None)])
    assert toolpkg.package_manifest(path).name == "kerbrute"


def test_make_folders_refuses_a_file_in_the_way(tmp_path):
    (tmp_path / "a").mkdir()
    (tmp_path / "a" / "b").write_bytes(b"a file")
    with pytest.raises(ToolError, match="is in the way and is not a folder"):
        toolpkg.make_folders(tmp_path, ["a", "b", "c"], "the package")
    assert (tmp_path / "a" / "b").read_bytes() == b"a file"


@pytest.mark.skipif(sys.platform == "win32", reason="needs symbolic links")
@pytest.mark.parametrize("target", ["folder", "file", "nothing"])
def test_make_folders_refuses_a_link_in_the_way(tmp_path, target):
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    aim = elsewhere / "aim"
    if target == "folder":
        aim.mkdir()
    elif target == "file":
        aim.write_bytes(b"x")
    root = tmp_path / "root"
    (root / "a").mkdir(parents=True)
    (root / "a" / "b").symlink_to(aim)
    with pytest.raises(ToolError, match="is in the way and is not a folder"):
        toolpkg.make_folders(root, ["a", "b", "c"], "the package")
    assert sorted(p.name for p in elsewhere.iterdir()) == (["aim"] if target != "nothing" else [])
    if target == "folder":
        assert list(aim.iterdir()) == []


# ---- round 4


@pytest.mark.parametrize("order", ["file first", "file last"])
def test_an_entry_inside_a_file_is_refused(tmp_path, order):
    members = [("files/a", b"a file", None), ("files/a/b", b"inside it", None)]
    if order == "file last":
        members.reverse()
    path = raw_zip(tmp_path, [GOOD, *members, ("files/a/c/d", b"deeper", None)])
    assert "sits inside the file 'files/a'" in str(assert_clean_failure(tmp_path, path))


def test_the_count_of_folders_stops_at_the_limit(tmp_path, monkeypatch):
    # names with long parts, each making 62 folders of its own: gathered whole before the limit
    # was looked at, the names of all those folders took 60 MiB here and 247 MiB at the limits
    import tracemalloc

    long_parts = "/".join(["p" * 240] * 13)
    short_parts = "/".join(["a"] * 47)
    members = [GOOD] + [(f"files/{number:04}/{long_parts}/{short_parts}/f", b"", None) for number in range(300)]
    path = raw_zip(tmp_path, members)
    monkeypatch.setattr(toolpkg, "MAX_MEMBERS", 400)
    tracemalloc.start()
    try:
        with pytest.raises(ToolError, match="more than 400 files and folders"):
            toolpkg.package_manifest(path)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 20 * 1024 * 1024


@pytest.mark.parametrize(
    ("command", "entry"),
    [
        ("config", ".config/google-chrome"),
        ("config", ".config/rclone/rclone.conf"),
        ("Config", ".config/xfce4"),
        ("local", ".local/share/kwalletd"),
        ("local", ".local/lib/python3.13/site-packages"),
        ("cache", ".cache/huggingface"),
        ("cache", ".Cache/huggingface"),
        ("bashrc", ".bashrc/x"),
        ("gnupg", ".GnuPG/private-keys-v1.d"),
    ],
)
def test_a_command_named_like_a_shared_place_does_not_own_what_is_inside_it(command, entry):
    data = sample_manifest(
        command=[{"name": command, "type": "binary", "path": "files/kerbrute"}],
        data={"home": [entry]},
    )
    expect_error(data, "data.home")


@pytest.mark.parametrize("name", ["config", "local", "cache"])
def test_a_tool_named_like_a_shared_place_does_not_own_what_is_inside_it(name):
    data = sample_manifest(
        name=name,
        command=[{"name": "x-" + name, "type": "binary", "path": "files/kerbrute"}],
        data={"home": [f".{name}/BraveSoftware"]},
    )
    expect_error(data, "data.home")


@pytest.mark.parametrize(
    ("command", "entry"),
    [("config", ".config/config"), ("cache", ".cache/cache/x"), ("local", ".local/share/local")],
)
def test_a_command_named_like_a_shared_place_still_owns_its_folder_inside_one(command, entry):
    data = sample_manifest(
        command=[{"name": command, "type": "binary", "path": "files/kerbrute"}],
        data={"home": [entry]},
    )
    assert parse_manifest(data).home == [entry]
