import os
import stat
import subprocess
import sys
import venv
import zipfile
from pathlib import Path

import pytest
import tomli_w

from pwn_broker import toolpkg
from pwn_broker.toolpkg import ToolError, parse_manifest, unpack
from toolkit import make_package, make_wheel, sample_manifest


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


@pytest.mark.parametrize("schema", [3, 0, "1", True, None])
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


@pytest.mark.parametrize("version", ["", "1/2", "1\\2", "1 2", "1\t2", 1])
def test_bad_version(version):
    expect_error(sample_manifest(version=version), "version")


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
        zf.writestr("manifest.toml", tomli_w.dumps(sample_manifest(schema=3)))
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

    def flaky(zf, info, target):
        calls.append(info.filename)
        if len(calls) == 3:
            raise OSError("disk full")
        real(zf, info, target)

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

    def interrupted(zf, info, target):
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
    "sh bash dash zsh fish sudo su doas env python python3 pip pip3 sed cut mkdir kill cat rm "
    "ls cp mv ln tar vim vi pwn-broker record asciinema openvpn ping ip"
).split()


@pytest.mark.parametrize("name", RESERVED)
def test_reserved_command_names_are_refused(name):
    assert not toolpkg.valid_command_name(name)
    data = sample_manifest(command=[{"name": name, "type": "binary", "path": "files/kerbrute"}])
    with pytest.raises(ToolError, match=f"{name!r} is reserved"):
        parse_manifest(data)


def test_names_that_only_look_reserved_are_allowed():
    for name in ("sed2", "Sudo", "python3.13", "kerbrute"):
        assert toolpkg.valid_command_name(name)


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
    data["data"] = {"home": [".kerb", entry]}
    with pytest.raises(ToolError, match=f"data.home: {entry!r}"):
        parse_manifest(data)


@pytest.mark.parametrize(
    "entry", [".config/kerbrute", ".local/share/kerbrute", ".cache/kerbrute", ".sshx", "desktop", ".Config"]
)
def test_home_entries_inside_shared_places_are_allowed(entry):
    data = both_manifest()
    data["data"] = {"home": [entry]}
    assert parse_manifest(data).home == [entry]


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
    assert toolpkg.KINDS == ("kali", "upload", "both", "runtime")
    # pwn-shop pins the same pattern, so the two repositories accept the same names
    assert toolpkg._NAME.pattern == r"[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)*"
    assert toolpkg.SCHEMAS == (1, 2)


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
