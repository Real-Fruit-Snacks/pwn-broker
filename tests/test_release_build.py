"""release/build.py: the release file built from pinned inputs.

The network, the pinned interpreter, hatchling and pip download are stand-ins here: `fetch`
writes prepared bytes and `run` drops prepared wheels where each command says.
"""

import gzip
import hashlib
import importlib.util
import io
import os
import re
import struct
import subprocess
import sys
import tarfile
import tempfile
import tomllib
import zlib
from pathlib import Path

import pytest

from pwn_broker import recorder, toolpkg

REPO = Path(__file__).resolve().parent.parent
_spec = importlib.util.spec_from_file_location("release_build", REPO / "release" / "build.py")
build = importlib.util.module_from_spec(_spec)
sys.modules["release_build"] = build
_spec.loader.exec_module(build)

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="needs file modes")

PYTHON_URL = "https://example.invalid/cpython-stand-in.tar.gz"
VERSION = "0.1.0"
TOP = f"pwn-broker-{VERSION}"
RELEASE = f"{TOP}-linux-x86_64.tar.gz"
LICENCE = b"MIT License\n\nstand-in licence text\n"
ASCIINEMA = b"asciinema stand-in\n"


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def norm(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def stand_in_python() -> bytes:
    """A gzip tar laid out as the upstream build is: python/bin/python3."""
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w", format=tarfile.USTAR_FORMAT) as tf:
        for name in ("python", "python/bin"):
            info = tarfile.TarInfo(name)
            info.type = tarfile.DIRTYPE
            info.mode = 0o755
            tf.addfile(info)
        body = b"#!/bin/sh\n"
        info = tarfile.TarInfo("python/bin/python3")
        info.size = len(body)
        info.mode = 0o755
        tf.addfile(info, io.BytesIO(body))
    return gzip.compress(buf.getvalue(), mtime=0)


# the locked dependencies: wheel file name -> (lock name, version)
WHEELS = {
    "prompt_toolkit-3.0.53-py3-none-any.whl": ("prompt-toolkit", "3.0.53"),
    "rich-15.0.0-py3-none-any.whl": ("rich", "15.0.0"),
    "tomli_w-1.2.0-py3-none-any.whl": ("tomli-w", "1.2.0"),
}


def wheel_bytes(name: str) -> bytes:
    return f"stand-in wheel {name}\n".encode()


def lock_text(wheels: dict[str, tuple[str, str]]) -> str:
    lines = [
        f"{dist}=={version} --hash=sha256:{digest(wheel_bytes(file))}"
        for file, (dist, version) in wheels.items()
    ]
    return "".join(line + "\n" for line in sorted(lines, key=lambda ln: norm(ln.split("==")[0])))


class FakeNet:
    """Stands in for build.fetch: writes the prepared bytes of a URL; never the network."""

    def __init__(self):
        self.files = {PYTHON_URL: stand_in_python(), recorder.URL: ASCIINEMA}
        self.calls: list[tuple[str, Path, int, str]] = []
        self.mtime: float | None = None

    def __call__(self, url, dest, size, sha256):
        self.calls.append((url, dest, size, sha256))
        dest.parent.mkdir(parents=True, exist_ok=True)
        dest.write_bytes(self.files[url])
        if self.mtime is not None:
            os.utime(dest, (self.mtime, self.mtime))


class FakeTools:
    """Stands in for `run`: the pinned interpreter, its venv, pip and hatchling.

    pip download drops `wheels` (file name -> bytes) into its -d folder; hatchling drops `app`.
    `reverse` writes them in the other order, `mtime` and `mode` change what they carry on disk.
    """

    def __init__(self, version=VERSION):
        self.wheels = {name: wheel_bytes(name) for name in WHEELS}
        self.app = {f"pwn_broker-{version}-py3-none-any.whl": b"stand-in app wheel\n"}
        self.reverse = False
        self.mtime: float | None = None
        self.mode: int | None = None
        self.fail: str | None = None
        self.calls: list[list[str]] = []
        self.envs: list[dict] = []
        self.cwds: list = []

    def _drop(self, folder: Path, files: dict[str, bytes]) -> None:
        names = sorted(files, reverse=self.reverse)
        for i, name in enumerate(names):
            path = folder / name
            path.write_bytes(files[name])
            if self.mtime is not None:
                os.utime(path, (self.mtime + i * 997, self.mtime + i * 997))
            if self.mode is not None:
                path.chmod(self.mode)

    def __call__(self, cmd, **kwargs):
        cmd = [str(c) for c in cmd]
        self.calls.append(cmd)
        self.envs.append(kwargs.get("env"))
        self.cwds.append(kwargs.get("cwd"))
        module = cmd[3]
        if self.fail == module:
            return subprocess.CompletedProcess(cmd, 1, "", "first line\nERROR: it went wrong\n")

        def arg(flag):
            return cmd[cmd.index(flag) + 1]

        if module == "venv":
            (Path(cmd[4]) / "bin").mkdir(parents=True)
        elif module == "hatchling":
            self._drop(Path(arg("-d")), self.app)
        elif module == "pip" and "download" in cmd:
            self._drop(Path(arg("-d")), self.wheels)
        return subprocess.CompletedProcess(cmd, 0, "", "")


class Kit:
    """A stand-in checkout with its fake network and tools, and a build of it."""

    def __init__(self, tmp_path: Path, name: str = "repo", version: str = VERSION):
        self.tmp_path = tmp_path
        self.repo = tmp_path / name
        release = self.repo / "release"
        release.mkdir(parents=True)
        python = stand_in_python()
        (release / "pins.toml").write_text(
            f'[python]\nversion = "3.13.18"\nurl = "{PYTHON_URL}"\n'
            f'size = {len(python)}\nsha256 = "{digest(python)}"\n',
            encoding="utf-8", newline="\n",
        )
        (release / "requirements.lock").write_text(lock_text(WHEELS), encoding="utf-8", newline="\n")
        (release / "build-requirements.lock").write_text(
            f"hatchling==1.33.0 --hash=sha256:{'a' * 64}\n", encoding="utf-8", newline="\n"
        )
        (self.repo / "pyproject.toml").write_text(
            f'[project]\nname = "pwn-broker"\nversion = "{version}"\n', encoding="utf-8", newline="\n"
        )
        (self.repo / "LICENSE").write_bytes(LICENCE)
        self.net = FakeNet()
        self.tools = FakeTools(version)
        self.out = tmp_path / f"{name}-out"
        self.cache = tmp_path / f"{name}-cache"

    def build(self, **kwargs) -> Path:
        kwargs.setdefault("fetch", self.net)
        kwargs.setdefault("run", self.tools)
        kwargs.setdefault("platform_ok", lambda: True)
        return build.build_release(self.repo, self.out, self.cache, **kwargs)

    def refused(self, words: str) -> None:
        with pytest.raises(build.BuildError, match=words):
            self.build()
        assert list(self.out.glob("*")) == []
        assert list(self.out.glob(".*")) == []


@pytest.fixture(autouse=True)
def no_real_network_or_tools(monkeypatch, tmp_path):
    """The build's own defaults would download and run real programs; make that an error.
    Its temporary folders go under tmp_path, so a test can see that they are removed."""

    def refuse(*args, **kwargs):
        raise AssertionError("a test reached the network or a real program; pass a stand-in")

    monkeypatch.setattr(build.fetch, "__kwdefaults__", {**build.fetch.__kwdefaults__, "download": refuse})
    defaults = {**build.build_release.__kwdefaults__, "fetch": refuse, "run": refuse}
    monkeypatch.setattr(build.build_release, "__kwdefaults__", defaults)
    temp = tmp_path / "system-temp"
    temp.mkdir()
    monkeypatch.setattr(tempfile, "tempdir", str(temp))
    return temp


@pytest.fixture
def kit(tmp_path):
    return Kit(tmp_path)


def members(path: Path) -> list[tarfile.TarInfo]:
    with tarfile.open(path, "r:gz") as tf:
        return tf.getmembers()


def member_bytes(path: Path, name: str) -> bytes:
    with tarfile.open(path, "r:gz") as tf:
        return tf.extractfile(name).read()


# ---- Review focus 1: the same checkout gives the same bytes


def test_two_builds_of_one_checkout_are_byte_identical(tmp_path):
    first = Kit(tmp_path, "one")
    second = Kit(tmp_path, "two")
    a = first.build()
    b = second.build()
    assert a.name == b.name == RELEASE
    assert a.read_bytes() == b.read_bytes()
    assert (first.out / "SHA256SUMS.txt").read_bytes() == (second.out / "SHA256SUMS.txt").read_bytes()


def test_other_order_times_and_modes_on_disk_give_the_same_bytes(tmp_path):
    first = Kit(tmp_path, "one")
    second = Kit(tmp_path, "two")
    second.tools.reverse = True
    second.tools.mtime = 1_700_000_000
    second.net.mtime = 1_600_000_000
    if sys.platform != "win32":
        second.tools.mode = 0o600
        (second.repo / "LICENSE").chmod(0o600)
    os.utime(second.repo / "LICENSE", (1_500_000_000, 1_500_000_000))
    assert first.build().read_bytes() == second.build().read_bytes()


def make_tree(root: Path, order: list[str], *, mtime: float, mode: int | None) -> None:
    files = {
        "b.txt": b"bee\n",
        "a/inner.txt": b"inner\n",
        "a-b/file": b"dash\n",
        "z/y/x.bin": bytes(range(256)),
        "empty/": None,
    }
    for name in order:
        data = files[name]
        path = root / name
        if data is None:
            path.mkdir(parents=True, exist_ok=True)
            continue
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        os.utime(path, (mtime, mtime))
        if mode is not None:
            path.chmod(mode)


def test_write_archive_ignores_creation_order_times_and_modes(tmp_path):
    names = ["b.txt", "a/inner.txt", "a-b/file", "z/y/x.bin", "empty/"]
    make_tree(tmp_path / "t1", names, mtime=1_000_000_000, mode=None)
    make_tree(
        tmp_path / "t2", list(reversed(names)), mtime=1_800_000_000,
        mode=None if sys.platform == "win32" else 0o640,
    )  # fmt: skip
    build.write_archive(tmp_path / "t1", tmp_path / "one.tar.gz", "top")
    build.write_archive(tmp_path / "t2", tmp_path / "two.tar.gz", "top")
    assert (tmp_path / "one.tar.gz").read_bytes() == (tmp_path / "two.tar.gz").read_bytes()


def test_archive_members_are_sorted_with_fixed_times_owners_and_modes(tmp_path):
    names = ["b.txt", "a/inner.txt", "a-b/file", "z/y/x.bin", "empty/"]
    make_tree(tmp_path / "t", names, mtime=1_234_567_890, mode=None)
    out = tmp_path / "out.tar.gz"
    build.write_archive(tmp_path / "t", out, "top")
    found = members(out)
    listed = [m.name for m in found]
    assert listed == sorted(listed)
    assert listed == [
        "top", "top/a", "top/a-b", "top/a-b/file", "top/a/inner.txt", "top/b.txt",
        "top/empty", "top/z", "top/z/y", "top/z/y/x.bin",
    ]  # fmt: skip
    for m in found:
        assert m.mtime == build.EPOCH == 315532800
        assert (m.uid, m.gid, m.uname, m.gname) == (0, 0, "", "")
        assert m.mode == (0o755 if m.isdir() else 0o644)
        assert m.isdir() or m.isreg()
    assert member_bytes(out, "top/z/y/x.bin") == bytes(range(256))


@posix_only
def test_an_executable_file_gets_755_and_others_644(tmp_path):
    tree = tmp_path / "t"
    tree.mkdir()
    (tree / "tool").write_bytes(b"run me\n")
    (tree / "tool").chmod(0o700)
    (tree / "data").write_bytes(b"read me\n")
    (tree / "data").chmod(0o600)
    out = tmp_path / "out.tar.gz"
    build.write_archive(tree, out, "top")
    modes = {m.name: m.mode for m in members(out)}
    assert modes == {"top": 0o755, "top/data": 0o644, "top/tool": 0o755}


def test_archive_is_ustar_in_stored_gzip_blocks(tmp_path):
    tree = tmp_path / "t"
    tree.mkdir()
    big = os.urandom(200_000)
    (tree / "big.bin").write_bytes(big)
    out = tmp_path / "out.tar.gz"
    build.write_archive(tree, out, "top")
    raw = out.read_bytes()
    assert raw[:10] == bytes.fromhex("1f8b08000000000000ff")
    # the deflate stream is stored blocks only, each at most 65,535 bytes, the last one final
    pos, data, finals = 10, b"", []
    while True:
        head = raw[pos]
        assert head in (0, 1)
        length, inverse = struct.unpack("<HH", raw[pos + 1 : pos + 5])
        assert length <= 65535 and inverse == length ^ 0xFFFF
        data += raw[pos + 5 : pos + 5 + length]
        pos += 5 + length
        finals.append(head)
        if head == 1:
            break
    assert finals == [0] * (len(finals) - 1) + [1] and len(finals) >= 4
    crc, size = struct.unpack("<II", raw[pos:])
    assert crc == zlib.crc32(data) and size == len(data)
    assert gzip.decompress(raw) == data
    with tarfile.open(fileobj=io.BytesIO(data)) as tf:
        assert tf.getnames() == ["top", "top/big.bin"]
        assert tf.extractfile("top/big.bin").read() == big
        offsets = [m.offset for m in tf.getmembers()]
    for offset in offsets:
        assert data[offset + 257 : offset + 265] == b"ustar\x0000"


def test_archive_refuses_a_name_that_does_not_fit_ustar(tmp_path):
    tree = tmp_path / "t"
    tree.mkdir()
    (tree / ("x" * 101)).write_bytes(b"long\n")
    out = tmp_path / "out" / "release.tar.gz"
    out.parent.mkdir()
    with pytest.raises(build.BuildError, match="x{101}.* does not fit"):
        build.write_archive(tree, out, "top")
    assert list(out.parent.iterdir()) == []


def test_a_release_build_has_fixed_members_and_the_gzip_header(kit):
    path = kit.build()
    assert path.read_bytes()[:10] == bytes.fromhex("1f8b08000000000000ff")
    found = members(path)
    listed = [m.name for m in found]
    assert listed == sorted(listed)
    assert listed == [
        TOP,
        f"{TOP}/asciinema",
        f"{TOP}/licences",
        f"{TOP}/licences/pwn-broker.txt",
        f"{TOP}/python.tar.gz",
        f"{TOP}/wheels",
        f"{TOP}/wheels.lock",
        *(f"{TOP}/wheels/{name}" for name in sorted([*WHEELS, "pwn_broker-0.1.0-py3-none-any.whl"])),
    ]
    for m in found:
        assert m.mtime == build.EPOCH
        assert (m.uid, m.gid, m.uname, m.gname) == (0, 0, "", "")
        if m.isdir():
            assert m.mode == 0o755
        elif m.name != f"{TOP}/asciinema":
            assert m.mode == 0o644


@posix_only
def test_asciinema_in_the_release_has_mode_755(kit):
    modes = {m.name: m.mode for m in members(kit.build())}
    assert modes[f"{TOP}/asciinema"] == 0o755


def test_the_release_holds_its_inputs(kit):
    path = kit.build()
    assert member_bytes(path, f"{TOP}/python.tar.gz") == stand_in_python()
    assert member_bytes(path, f"{TOP}/asciinema") == ASCIINEMA
    assert member_bytes(path, f"{TOP}/licences/pwn-broker.txt") == LICENCE
    app = b"stand-in app wheel\n"
    assert member_bytes(path, f"{TOP}/wheels/pwn_broker-0.1.0-py3-none-any.whl") == app
    for name in WHEELS:
        assert member_bytes(path, f"{TOP}/wheels/{name}") == wheel_bytes(name)
    lock = member_bytes(path, f"{TOP}/wheels.lock")
    toolpkg.check_lock(lock)
    expected = (
        f"prompt-toolkit==3.0.53 --hash=sha256:{digest(wheel_bytes('prompt_toolkit-3.0.53-py3-none-any.whl'))}\n"
        f"pwn-broker==0.1.0 --hash=sha256:{digest(app)}\n"
        f"rich==15.0.0 --hash=sha256:{digest(wheel_bytes('rich-15.0.0-py3-none-any.whl'))}\n"
        f"tomli-w==1.2.0 --hash=sha256:{digest(wheel_bytes('tomli_w-1.2.0-py3-none-any.whl'))}\n"
    )
    assert lock.decode() == expected


def test_sha256sums_names_the_file_with_its_real_sha256(kit):
    path = kit.build()
    assert path == kit.out / RELEASE
    sums = (kit.out / "SHA256SUMS.txt").read_bytes()
    assert sums == f"{digest(path.read_bytes())}  {RELEASE}\n".encode()
    assert sorted(p.name for p in kit.out.iterdir()) == ["SHA256SUMS.txt", RELEASE]


def test_the_version_comes_from_pyproject(tmp_path):
    kit = Kit(tmp_path, version="9.8.7")
    path = kit.build()
    assert path.name == "pwn-broker-9.8.7-linux-x86_64.tar.gz"
    assert members(path)[0].name == "pwn-broker-9.8.7"
    lock = member_bytes(path, "pwn-broker-9.8.7/wheels.lock").decode()
    assert "\npwn-broker==9.8.7 --hash=sha256:" in lock


def test_the_build_leaves_no_temporary_folder(kit, no_real_network_or_tools):
    kit.build()
    assert list(no_real_network_or_tools.iterdir()) == []
    kit.tools.fail = "hatchling"
    with pytest.raises(build.BuildError):
        kit.build()
    assert list(no_real_network_or_tools.iterdir()) == []


# ---- Review focus 2: every wheel named by wheels.lock, every line with its wheel


def test_a_wheel_that_wheels_lock_does_not_name_is_refused(kit):
    kit.tools.wheels["pyte-0.8.2-py3-none-any.whl"] = b"unlisted\n"
    kit.refused(r"wheels/pyte-0\.8\.2-py3-none-any\.whl is not named by any line of wheels\.lock")


def test_a_wheel_of_another_version_is_refused(kit):
    del kit.tools.wheels["rich-15.0.0-py3-none-any.whl"]
    kit.tools.wheels["rich-14.0.0-py3-none-any.whl"] = wheel_bytes("rich-15.0.0-py3-none-any.whl")
    kit.refused(r"wheels/rich-14\.0\.0-py3-none-any\.whl is not named by any line of wheels\.lock")


def test_a_lock_line_with_no_wheel_is_refused(kit):
    del kit.tools.wheels["rich-15.0.0-py3-none-any.whl"]
    kit.refused(r"wheels\.lock line 3 \(rich==15\.0\.0\) names a wheel that is not in wheels/")


def test_a_wheel_whose_sha256_is_not_its_lines_is_refused(kit):
    kit.tools.wheels["rich-15.0.0-py3-none-any.whl"] = b"changed\n"
    kit.refused(
        rf"wheels/rich-15\.0\.0-py3-none-any\.whl has SHA-256 {digest(b'changed' + bytes([10]))}, "
        rf"but wheels\.lock line 3 gives {digest(wheel_bytes('rich-15.0.0-py3-none-any.whl'))}"
    )


def test_two_wheels_for_one_line_are_refused(kit):
    kit.tools.wheels["rich-15.0.0-py2.py3-none-any.whl"] = wheel_bytes("rich-15.0.0-py3-none-any.whl")
    kit.refused(r"wheels\.lock line 3 names more than one wheel")


def test_a_file_that_is_not_a_wheel_is_refused(kit):
    kit.tools.wheels["rich-15.0.0.tar.gz"] = b"source\n"
    kit.refused(r"wheels/rich-15\.0\.0\.tar\.gz is not a wheel")


@pytest.mark.parametrize(
    "line",
    [
        "--index-url https://example.invalid/simple",
        "rich @ https://example.invalid/rich-15.0.0-py3-none-any.whl",
        f"rich==15.0.0; python_version > '3' --hash=sha256:{'b' * 64}",
        "-r other.txt",
    ],
)
def test_a_lock_line_that_is_an_option_a_url_or_a_marker_is_refused(kit, line):
    lock = kit.repo / "release" / "requirements.lock"
    lock.write_text(lock.read_text(encoding="utf-8") + line + "\n", encoding="utf-8", newline="\n")
    kit.refused(r"requirements\.lock line 4 is not name==version followed by --hash=sha256: values")
    assert kit.net.calls == [] and kit.tools.calls == []


def test_the_app_pinned_in_requirements_lock_is_refused(kit):
    lock = kit.repo / "release" / "requirements.lock"
    lock.write_text(
        lock.read_text(encoding="utf-8") + f"pwn_broker==0.1.0 --hash=sha256:{'c' * 64}\n",
        encoding="utf-8", newline="\n",
    )
    kit.refused(r"wheels\.lock line \d: pwn-broker is already pinned on line \d")


@pytest.mark.parametrize(
    "app, words",
    [
        ({}, r"hatchling made no wheel"),
        (
            {"pwn_broker-0.1.0-py3-none-any.whl": b"a", "pwn_broker-0.1.0-py2-none-any.whl": b"b"},
            r"hatchling made 2 files",
        ),
        (
            {"other-0.1.0-py3-none-any.whl": b"a"},
            r"hatchling made other-0\.1\.0-py3-none-any\.whl, which is not a wheel of pwn-broker 0\.1\.0",
        ),
        ({"pwn_broker-0.2.0-py3-none-any.whl": b"a"}, r"is not a wheel of pwn-broker 0\.1\.0"),
    ],
)
def test_hatchling_must_make_exactly_the_apps_wheel(kit, app, words):
    kit.tools.app = app
    kit.refused(words)


def test_a_failed_command_is_refused_with_its_last_lines(kit):
    kit.tools.fail = "hatchling"
    kit.refused(r"cannot build the app's wheel: first line / ERROR: it went wrong")


# ---- the commands


def test_every_command_runs_isolated_with_a_clean_environment(kit, monkeypatch):
    monkeypatch.setenv("PYTHONPATH", "/somewhere")
    monkeypatch.setenv("PYTHONHOME", "/elsewhere")
    monkeypatch.setenv("PIP_INDEX_URL", "https://example.invalid/simple")
    monkeypatch.setenv("PIP_REQUIRE_VIRTUALENV", "1")
    kit.build()
    calls = kit.tools.calls
    assert [c[2:4] for c in calls] == [["-m", "venv"], ["-m", "pip"], ["-m", "hatchling"], ["-m", "pip"]]
    for cmd, env in zip(calls, kit.tools.envs):
        assert cmd[1] == "-I"
        assert env["PIP_CONFIG_FILE"] == os.devnull
        assert [k for k in env if k.upper().startswith(("PYTHON", "PIP_"))] == ["PIP_CONFIG_FILE"]
    for cmd in (c for c in calls if c[3] == "pip"):
        assert cmd[4] == "--isolated"
        assert "--require-hashes" in cmd
        assert cmd[cmd.index("--only-binary") + 1] == ":all:"


def test_the_commands_use_the_pinned_interpreter_and_the_lock_files(kit):
    kit.build()
    venv, install, hatch, download = kit.tools.calls
    base = Path(venv[0])
    assert base.parts[-3:] == ("python", "bin", "python3")
    env_python = Path(venv[4]) / "bin" / "python"
    assert {Path(install[0]), Path(hatch[0]), Path(download[0])} == {env_python}
    assert install[5] == "install"
    assert Path(install[install.index("-r") + 1]) == kit.repo / "release" / "build-requirements.lock"
    assert hatch[3:9] == ["hatchling", "build", "-t", "wheel", "-d", hatch[8]]
    assert len(hatch) == 9
    assert Path(kit.tools.cwds[2]) == kit.repo
    assert kit.tools.envs[2]["SOURCE_DATE_EPOCH"] == "315532800"
    assert download[5] == "download"
    for flag in ("--no-deps", "--no-cache-dir"):
        assert flag in download
    assert Path(download[download.index("-r") + 1]) == kit.repo / "release" / "requirements.lock"


def test_the_python_build_and_asciinema_are_fetched_with_their_pins(kit):
    kit.build()
    python = stand_in_python()
    assert [(url, size, sha) for url, _dest, size, sha in kit.net.calls] == [
        (PYTHON_URL, len(python), digest(python)),
        (recorder.URL, recorder.SIZE, recorder.SHA256),
    ]
    assert all(dest.parent == kit.cache for _url, dest, _size, _sha in kit.net.calls)


def test_the_build_refuses_a_machine_that_is_not_x86_64_linux(kit):
    with pytest.raises(
        build.BuildError, match="a release is built on x86_64 Linux: the build runs the Python it packs"
    ):
        kit.build(platform_ok=lambda: False)
    assert kit.net.calls == [] and kit.tools.calls == []
    assert list(kit.out.glob("*")) == []


# ---- fetch


class Downloads:
    def __init__(self, data: bytes):
        self.data = data
        self.calls: list[str] = []

    def __call__(self, url, path, limit):
        self.calls.append(url)
        path.write_bytes(self.data)


def test_fetch_reuses_a_good_cached_file(tmp_path):
    dest = tmp_path / "cache" / "file"
    dest.parent.mkdir()
    dest.write_bytes(b"good")
    downloads = Downloads(b"never")
    build.fetch("https://example.invalid/file", dest, 4, digest(b"good"), download=downloads)
    assert downloads.calls == []
    assert dest.read_bytes() == b"good"


def test_fetch_replaces_a_wrong_cached_file(tmp_path):
    dest = tmp_path / "cache" / "file"
    dest.parent.mkdir()
    dest.write_bytes(b"bad!")
    downloads = Downloads(b"good")
    build.fetch("https://example.invalid/file", dest, 4, digest(b"good"), download=downloads)
    assert downloads.calls == ["https://example.invalid/file"]
    assert dest.read_bytes() == b"good"
    assert list(dest.parent.iterdir()) == [dest]


@pytest.mark.parametrize("data", [b"evil", b"too long"])
def test_fetch_refuses_a_wrong_download_and_leaves_nothing(tmp_path, data):
    dest = tmp_path / "cache" / "file"
    dest.parent.mkdir()
    dest.write_bytes(b"bad!")
    with pytest.raises(build.BuildError) as caught:
        build.fetch("https://example.invalid/file", dest, 4, digest(b"good"), download=Downloads(data))
    message = str(caught.value)
    assert message.startswith("file: ")
    assert f"expected 4 bytes with SHA-256 {digest(b'good')}" in message
    assert f"found {len(data)} bytes with SHA-256 {digest(data)}" in message
    assert list(dest.parent.iterdir()) == []


def test_the_real_download_refuses_an_address_that_is_not_https(tmp_path):
    with pytest.raises(build.BuildError, match="only https addresses are accepted"):
        build._download("http://example.invalid/file", tmp_path / "file", 10)
    assert not (tmp_path / "file").exists()


# ---- read_lock


def write_lock(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "requirements.lock"
    path.write_bytes(text.encode())
    return path


def test_read_lock_gives_name_version_and_sha256(tmp_path):
    path = write_lock(tmp_path, f"Rich==15.0.0 --hash=sha256:{'a' * 64}\ntomli_w==1.2.0 --hash=sha256:{'b' * 64}\n")
    assert build.read_lock(path) == [("Rich", "15.0.0", "a" * 64), ("tomli_w", "1.2.0", "b" * 64)]


@pytest.mark.parametrize(
    "text, words",
    [
        (
            f"rich==15.0.0 --hash=sha256:{'a' * 64} --hash=sha256:{'b' * 64}\n",
            r"requirements\.lock line 1: rich has 2 hashes; a line holds exactly one",
        ),
        (
            f"tomli-w==1.2.0 --hash=sha256:{'a' * 64}\nTomli_W==1.2.0 --hash=sha256:{'b' * 64}\n",
            r"requirements\.lock line 2: Tomli_W is already pinned on line 1",
        ),
        (
            f"markdown-it-py==4.3.0 --hash=sha256:{'a' * 64}\nmarkdown.it__py==4.3.0 --hash=sha256:{'b' * 64}\n",
            r"line 2: markdown\.it__py is already pinned on line 1",
        ),
        ("--extra-index-url https://example.invalid/simple\n", r"requirements\.lock line 1 is not name==version"),
        (f"rich==15.0.0 --hash=sha256:{'a' * 64}", r"requirements\.lock line 1 does not end with a line break"),
        ("", r"requirements\.lock is empty"),
    ],
)
def test_read_lock_refusals(tmp_path, text, words):
    with pytest.raises(build.BuildError, match=words):
        build.read_lock(write_lock(tmp_path, text))


# ---- the repository's own pins and locks


def test_the_pins_file_loads():
    pin = build.load_pins(REPO / "release" / "pins.toml")
    assert pin == build.Pin(
        version="3.13.18",
        url=(
            "https://github.com/astral-sh/python-build-standalone/releases/download/20261110/"
            "cpython-3.13.18+20261110-x86_64-unknown-linux-gnu-install_only_stripped.tar.gz"
        ),
        size=35596130,
        sha256="f2d2199eb25880e07863b391cf7124e7ffa1338b0d65600dfcec117c4223a7fb",
    )


@pytest.mark.parametrize(
    "table, words",
    [
        ("", r"no \[python\] table"),
        ('[python]\nversion = "3"\nurl = "http://x/y"\nsize = 1\nsha256 = "' + "a" * 64 + '"\n', "url"),
        ('[python]\nversion = "3"\nurl = "https://x/y"\nsize = 0\nsha256 = "' + "a" * 64 + '"\n', "size"),
        ('[python]\nversion = "3"\nurl = "https://x/y"\nsize = 1\nsha256 = "ABC"\n', "sha256"),
        ('[python]\nurl = "https://x/y"\nsize = 1\nsha256 = "' + "a" * 64 + '"\n', "version"),
    ],
)
def test_load_pins_refusals(tmp_path, table, words):
    path = tmp_path / "pins.toml"
    path.write_text(table, encoding="utf-8", newline="\n")
    with pytest.raises(build.BuildError, match=words):
        build.load_pins(path)


def test_kali_cycle_carries_the_same_python_pin():
    text = (REPO / ".github" / "scripts" / "kali-cycle.sh").read_text(encoding="utf-8")

    def value(name):
        (found,) = re.findall(rf'^{name}="?([^"\n]*)"?$', text, re.MULTILINE)
        return found

    pin = build.load_pins(REPO / "release" / "pins.toml")
    assert value("RUNTIME_URL") == pin.url
    assert int(value("RUNTIME_SIZE")) == pin.size
    assert value("RUNTIME_SHA256") == pin.sha256


def test_every_dependency_of_the_app_is_in_requirements_lock():
    project = tomllib.loads((REPO / "pyproject.toml").read_text(encoding="utf-8"))["project"]
    wanted = {norm(re.match(r"[A-Za-z0-9][A-Za-z0-9._-]*", d).group()) for d in project["dependencies"]}
    assert len(wanted) == 4
    locked = {norm(name) for name, _v, _h in build.read_lock(REPO / "release" / "requirements.lock")}
    assert wanted <= locked


@pytest.mark.parametrize("name", ["requirements.lock", "build-requirements.lock"])
def test_the_lock_files_are_strict_with_one_hash_per_line(name):
    path = REPO / "release" / name
    toolpkg.check_lock(path.read_bytes(), name)
    pins = build.read_lock(path)
    assert [norm(n) for n, _v, _h in pins] == sorted(norm(n) for n, _v, _h in pins)
    assert all(line.count("--hash=") == 1 for line in path.read_text(encoding="utf-8").splitlines())


def test_build_requirements_lock_pins_hatchling():
    names = [norm(n) for n, _v, _h in build.read_lock(REPO / "release" / "build-requirements.lock")]
    assert "hatchling" in names


# ---- main


def test_main_prints_ok_lines_and_what_it_wrote(tmp_path, monkeypatch, capsys):
    kit = Kit(tmp_path)
    real = build.build_release

    def fake_build(repo, out, cache):
        assert repo == REPO
        assert (out, cache) == (tmp_path / "o", tmp_path / "c")
        return real(kit.repo, out, cache, fetch=kit.net, run=kit.tools, platform_ok=lambda: True)

    monkeypatch.setattr(build, "build_release", fake_build)
    assert build.main(["--out", str(tmp_path / "o"), "--cache", str(tmp_path / "c")]) == 0
    path = tmp_path / "o" / RELEASE
    lines = capsys.readouterr().out.splitlines()
    assert lines and all(line.startswith("ok    ") for line in lines)
    assert lines[-1] == (
        f"ok    wrote {path} ({path.stat().st_size} bytes, SHA-256 {digest(path.read_bytes())})"
    )


def test_main_defaults_to_dist_and_the_repositorys_cache(monkeypatch, tmp_path):
    seen = []

    def fake_build(repo, out, cache):
        seen.append((out, cache))
        raise build.BuildError("stop here")

    monkeypatch.setattr(build, "build_release", fake_build)
    assert build.main([]) == 1
    assert seen == [(REPO / "dist", REPO / ".cache" / "release")]


@pytest.mark.parametrize("error", [build.BuildError("the lock is wrong"), OSError("disk full")])
def test_main_prints_one_fail_line_and_returns_1(monkeypatch, capsys, error):
    def fake_build(repo, out, cache):
        raise error

    monkeypatch.setattr(build, "build_release", fake_build)
    assert build.main(["--out", "x"]) == 1
    captured = capsys.readouterr()
    assert captured.out == ""
    assert captured.err == f"fail  {error}\n"
