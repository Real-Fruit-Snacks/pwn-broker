import os
import shutil
import subprocess
import sys
from types import SimpleNamespace

import pytest

import toolkit
from helpers import NOW
from pwn_broker import toolstate
from pwn_broker.console import FakeConsole
from pwn_broker.store import load_box
from pwn_broker.toolindex import BuildEntry
from pwn_broker.toolinstall import (
    install,
    launcher_text,
    python_version,
    release,
    remove_files,
    sh_quote,
)
from pwn_broker.toolpkg import Command, ToolError, machine_arch, unpack
from pwn_broker.toolstate import Installed, load_installed

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="needs a Linux virtual environment")

SCRIPT = b"#!/bin/sh\necho hello from tool \"$@\"\n"


def build(tmp_path, files=None, wheels=(), lock=None, **overrides):
    manifest = toolkit.sample_manifest(**{"arch": machine_arch(), **overrides})
    manifest = {k: v for k, v in manifest.items() if v is not None}
    if files is None:
        files = {"files/kerbrute": SCRIPT}
    zip_path, size, sha = toolkit.make_package(
        tmp_path / "zips", manifest, files, wheels=list(wheels), lock=lock
    )
    entry = BuildEntry(
        name=manifest["name"],
        version=manifest["version"],
        build=manifest["build"],
        kind=manifest["kind"],
        needs_root=manifest.get("needs_root", False),
        commands=[c["name"] for c in manifest.get("command", [])],
        file=zip_path.name,
        url="https://example.invalid/" + zip_path.name,
        size=size,
        sha256=sha,
    )
    return zip_path, entry


def python_manifest(**extra):
    manifest = dict(
        command=[{"name": "kerbrute", "type": "python-entry", "entry": "kerbrute"}],
        python={"versions": ["3.13"], "lock": "wheels.lock", "wheels": "wheels"},
    )
    manifest.update(extra)
    return manifest


class FakeRun:
    def __init__(self, version="3.13", fail_at=None, output="line\n" * 12):
        self.calls = []
        self.version = version
        self.fail_at = fail_at
        self.output = output

    def __call__(self, argv, **kwargs):
        assert kwargs == {"capture_output": True, "text": True}
        self.calls.append(list(argv))
        index = len(self.calls) - 1
        if argv[1] == "-c":
            return SimpleNamespace(returncode=0, stdout=self.version + "\n", stderr="")
        if index == self.fail_at:
            return SimpleNamespace(returncode=1, stdout=self.output, stderr="boom\n")
        return SimpleNamespace(returncode=0, stdout="", stderr="")


def do_install(paths, box, entry, zip_path, tmp_path, *, installed=None, unfinished=None, **kw):
    installed = {} if installed is None else installed
    console = kw.pop("console", None) or FakeConsole()
    kw.setdefault("run", FakeRun())
    kw.setdefault("on_path", lambda name: None)
    item = install(
        paths, box, entry, zip_path,
        installed=installed,
        unfinished={box.id: box.name} if unfinished is None else unfinished,
        home=tmp_path / "user", console=console, now=NOW, **kw,
    )  # fmt: skip
    return item, console, installed


def snapshot(paths):
    # files only: an empty bin/ or upload/ folder is not something the install left behind
    found = paths.opt.rglob("*") if paths.opt.exists() else []
    return sorted(p.relative_to(paths.opt).as_posix() for p in found if p.is_file())


# ---- launcher text


def manifest_of(tmp_path, **overrides):
    zip_path, _entry = build(tmp_path, **overrides)
    return unpack(zip_path, tmp_path / "unpacked")


def test_sh_quote():
    assert sh_quote("a b") == "'a b'"
    assert sh_quote("it's") == "'it'\\''s'"
    assert sh_quote("") == "''"
    for bad in ("a\nb", "a\0b"):
        with pytest.raises(ToolError):
            sh_quote(bad)


def test_binary_launcher_text(paths, tmp_path):
    manifest = manifest_of(tmp_path)
    folder = paths.tools / "kerbrute" / "1.0.3-1"
    text = launcher_text(paths, manifest, manifest.commands[0], folder)
    lines = text.split("\n")
    assert lines[0] == "#!/bin/sh"
    assert lines[1] == "# pwn-broker tool: kerbrute"
    assert lines[2] == f"run='{paths.run.as_posix()}'"
    assert (
        "{ { sed 's/.*) //' \"/proc/$$/stat\" | cut -d' ' -f20; } > \"$run/tools/kerbrute.$$\"; } "
        "2>/dev/null || true"
    ) in lines
    assert 'data=' not in text
    assert lines[-2] == f"exec '{folder.as_posix()}/files/kerbrute' \"$@\""
    assert text.endswith("\n")


def test_python_launchers(paths, tmp_path):
    wheel = toolkit.make_wheel(tmp_path / "w", "kerbrute-py", "1.0", module="kmod", entry="kerbrute")
    manifest = manifest_of(
        tmp_path, files={"files/s.py": b"print(1)\n"}, wheels=[wheel], **python_manifest()
    )
    folder = paths.tools / "kerbrute" / "1.0.3-1"
    entry = Command("k", "python-entry", entry="kerbrute")
    assert f"exec '{folder.as_posix()}/venv/bin/kerbrute' \"$@\"" in launcher_text(
        paths, manifest, entry, folder
    )
    script = Command("k", "python-script", script="files/s.py")
    assert (
        f"exec '{folder.as_posix()}/venv/bin/python' '{folder.as_posix()}/files/s.py' \"$@\""
        in launcher_text(paths, manifest, script, folder)
    )


def test_launcher_env_and_args_without_data(paths, tmp_path):
    manifest = manifest_of(tmp_path)
    cmd = Command("kerbrute", "binary", path="files/kerbrute", env={"A": "x y"}, args=["-v", "it's"])
    text = launcher_text(paths, manifest, cmd, paths.tools / "kerbrute" / "1")
    assert "export A='x y'" in text
    assert text.split("\n")[-2].endswith(" '-v' 'it'\\''s' \"$@\"")
    assert "data=" not in text


def test_launcher_with_data(paths, tmp_path):
    manifest = manifest_of(tmp_path)
    cmd = Command(
        "kerbrute", "binary", path="files/kerbrute",
        env={"HOME_X": "{data}/home", "PLAIN": "p", "Q": "a'b{data}c"},
        args=["--out", "{data}", "last"],
    )  # fmt: skip
    text = launcher_text(paths, manifest, cmd, paths.tools / "kerbrute" / "1")
    lines = text.split("\n")
    assert "data=''" in lines
    assert 'if [ -n "$box" ]; then data="$box/tooldata/kerbrute"; mkdir -p "$data"; fi' in lines
    assert "if [ -n \"$data\" ]; then export HOME_X=\"$data\"'/home'; fi" in lines
    assert "export PLAIN='p'" in lines
    assert "if [ -n \"$data\" ]; then export Q='a'\\''b'\"$data\"'c'; fi" in lines
    assert "set -- 'last' \"$@\"" in lines
    assert 'if [ -n "$data" ]; then set -- "$data" "$@"; fi' in lines
    assert lines.index("set -- 'last' \"$@\"") < lines.index('if [ -n "$data" ]; then set -- "$data" "$@"; fi')
    assert lines[-2].startswith("exec '") and lines[-2].endswith(" \"$@\"")


def test_launcher_refuses_line_breaks_and_bad_env_names(paths, tmp_path):
    manifest = manifest_of(tmp_path)
    folder = paths.tools / "kerbrute" / "1"
    for cmd in (
        *(Command("k", "binary", path="files/kerbrute", env={v: "x"}) for v in
          ("data", "box", "run", "pid")),
        Command("k", "binary", path="files/kerbrute", env={"A": "a\nb"}),
        Command("k", "binary", path="files/kerbrute", args=["a\0b"]),
        Command("k", "binary", path="files/kerbrute", env={"A B": "x"}),
    ):
        with pytest.raises(ToolError):
            launcher_text(paths, manifest, cmd, folder)


def run_sh(args, env_extra=None, shell="sh", **kw):
    env = {"PATH": "/usr/bin:/bin"}
    env.update(env_extra or {})
    env = {**os.environ, **env}
    return subprocess.run([shell, *args], capture_output=True, text=True, env=env, **kw)


@pytest.mark.skipif(shutil.which("sh") is None, reason="needs sh")
def test_binary_launcher_runs_under_sh(paths, tmp_path):
    manifest = manifest_of(tmp_path)
    folder = tmp_path / "unpacked"
    (paths.run / "tools").mkdir(parents=True)
    cmd = Command(
        "kerbrute", "binary", path="files/kerbrute", env={"X": "q'uote"}, args=["--first"]
    )
    script = tmp_path / "launcher.sh"
    text = launcher_text(paths, manifest, cmd, folder)
    script.write_bytes(text.encode())
    (folder / "files" / "kerbrute").write_bytes(b"#!/bin/sh\necho \"$X $*\"\n")
    result = run_sh([script.as_posix(), "-a", "b c"])
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "q'uote --first -a b c"
    assert len(list((paths.run / "tools").glob("kerbrute.*"))) == 1


SHELLS = [s for s in ("sh", "dash") if shutil.which(s)]


@pytest.mark.skipif(not SHELLS, reason="needs sh")
@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("state", ["missing", "a file"])
def test_launcher_survives_an_unwritable_marker_folder(paths, tmp_path, shell, state):
    manifest = manifest_of(tmp_path)
    folder = tmp_path / "unpacked"
    paths.run.mkdir(parents=True)
    if state == "a file":
        (paths.run / "tools").write_text("not a folder")
    cmd = Command("kerbrute", "binary", path="files/kerbrute")
    script = tmp_path / "launcher.sh"
    script.write_bytes(launcher_text(paths, manifest, cmd, folder).encode())
    (folder / "files" / "kerbrute").write_bytes(b"#!/bin/sh\necho ran\nexit 7\n")
    result = run_sh([script.as_posix()], shell=shell)
    assert (result.returncode, result.stdout.strip(), result.stderr) == (7, "ran", "")


# ---- python_version


def test_python_version():
    fake = FakeRun(version="3.12")
    assert python_version("py", fake) == "3.12"
    assert fake.calls == [["py", "-c", "import sys; print('%d.%d' % sys.version_info[:2])"]]

    def missing(argv, **kw):
        raise FileNotFoundError("nope")

    def failing(argv, **kw):
        return SimpleNamespace(returncode=2, stdout="", stderr="")

    for bad in (missing, failing):
        with pytest.raises(ToolError, match="python3 was not found"):
            python_version("py", bad)
    with pytest.raises(ToolError, match="could not report"):
        python_version("py", FakeRun(version=""))


# ---- install: kali tools


def test_install_binary(paths, box, tmp_path):
    zip_path, entry = build(tmp_path)
    item, console, installed = do_install(paths, box, entry, zip_path, tmp_path)
    folder = paths.tools / "kerbrute" / "1.0.3-1"
    assert (folder / "files" / "kerbrute").is_file()
    launcher = paths.bin / "kerbrute"
    text = launcher.read_text(encoding="utf-8")
    assert text.split("\n")[1] == "# pwn-broker tool: kerbrute"
    if sys.platform != "win32":
        assert launcher.stat().st_mode & 0o777 == 0o755
    assert item == installed["kerbrute"]
    assert item.folder == folder.resolve().as_posix()
    assert item.users == [box.id] and item.commands == ["kerbrute"] and item.sha256 == entry.sha256
    assert load_installed(paths)["kerbrute"] == item
    saved = load_box(box.path)
    assert [(t.name, t.version, t.build, t.sha256, t.installed) for t in saved.tools] == [
        ("kerbrute", "1.0.3", 1, entry.sha256, NOW)
    ]
    assert console.lines == [
        ("ok", "kerbrute 1.0.3 installed"),
        ("info", "run   kerbrute   from any terminal"),
    ]


def test_install_records_home_paths(paths, box, tmp_path):
    (tmp_path / "user" / ".there").mkdir(parents=True)
    zip_path, entry = build(tmp_path, data={"home": [".there", ".absent"]})
    item, _c, _i = do_install(paths, box, entry, zip_path, tmp_path)
    assert item.home == {".there": True, ".absent": False}


def test_needs_root_and_uploads_print_lines(paths, box, tmp_path):
    zip_path, entry = build(
        tmp_path,
        files={"files/proxy": SCRIPT, "files/agent": b"A", "files/agent.exe": b"B"},
        name="ligolo-ng", kind="both", needs_root=True,
        command=[{"name": "ligolo-proxy", "type": "binary", "path": "files/proxy"}],
        upload=[
            {"path": "files/agent", "as": "agent"},
            {"path": "files/agent.exe", "as": "agent.exe"},
        ],
    )  # fmt: skip
    item, console, _i = do_install(paths, box, entry, zip_path, tmp_path)
    assert console.lines == [
        ("ok", "ligolo-ng 1.0.3 installed"),
        ("info", "run   ligolo-proxy   from any terminal"),
        ("info", f"      sudo {(paths.bin / 'ligolo-proxy').as_posix()}"),
        ("info", f"files {(paths.upload / 'ligolo-ng').as_posix()}   agent  agent.exe"),
    ]
    assert (paths.upload / "ligolo-ng" / "agent.exe").read_bytes() == b"B"
    assert item.uploads == ["agent", "agent.exe"]


@posix_only
def test_upload_is_executable(paths, box, tmp_path):
    # unpacking marks everything under files/ executable, and the copy keeps that
    zip_path, entry = build(
        tmp_path, files={"files/tool.sh": SCRIPT}, kind="upload",
        command=None, upload=[{"path": "files/tool.sh", "as": "tool.sh"}],
    )  # fmt: skip
    do_install(paths, box, entry, zip_path, tmp_path)
    assert (paths.upload / "kerbrute" / "tool.sh").stat().st_mode & 0o111


def test_leftover_folders_are_replaced(paths, box, tmp_path):
    leftover = paths.tools / "kerbrute" / "1.0.3-1"
    leftover.mkdir(parents=True)
    (leftover / "stale").write_text("x")
    (paths.upload / "kerbrute").mkdir(parents=True)
    (paths.upload / "kerbrute" / "stale").write_text("x")
    zip_path, entry = build(
        tmp_path, files={"files/kerbrute": SCRIPT, "files/up": b"U"},
        kind="both", upload=[{"path": "files/up", "as": "up"}],
    )  # fmt: skip
    do_install(paths, box, entry, zip_path, tmp_path)
    assert not (leftover / "stale").exists()
    assert sorted(p.name for p in (paths.upload / "kerbrute").iterdir()) == ["up"]


# ---- install: shared tools


def installed_by(paths, box, tmp_path, **overrides):
    zip_path, entry = build(tmp_path, **overrides)
    do_install(paths, box, entry, zip_path, tmp_path)
    return zip_path, entry


def test_same_build_for_second_box_adds_user(paths, box, other, tmp_path):
    zip_path, entry = build(tmp_path)
    unfinished = {box.id: box.name, other.id: other.name}
    _item, _c, installed = do_install(
        paths, box, entry, zip_path, tmp_path, unfinished=unfinished
    )
    zip_path.unlink()  # a second install must not need the zip
    console = FakeConsole()
    item, _c, _i = do_install(
        paths, other, entry, zip_path, tmp_path,
        installed=installed, unfinished=unfinished, console=console,
    )  # fmt: skip
    assert item.users == [box.id, other.id]
    assert [t.name for t in load_box(other.path).tools] == ["kerbrute"]
    assert load_installed(paths)["kerbrute"].users == [box.id, other.id]
    assert ("info", "run   kerbrute   from any terminal") in console.lines


def test_different_build_names_the_other_box(paths, box, other, tmp_path):
    zip_path, entry = build(tmp_path)
    unfinished = {box.id: box.name, other.id: other.name}
    _i, _c, installed = do_install(paths, box, entry, zip_path, tmp_path, unfinished=unfinished)
    zip2, entry2 = build(tmp_path, build=2)
    with pytest.raises(ToolError, match=box.name):
        do_install(paths, other, entry2, zip2, tmp_path, installed=installed, unfinished=unfinished)
    assert installed["kerbrute"].users == [box.id]
    assert other.tools == []


def test_finished_users_do_not_count(paths, box, other, tmp_path):
    zip_path, entry = build(tmp_path)
    _i, _c, installed = do_install(paths, box, entry, zip_path, tmp_path)
    zip2, entry2 = build(tmp_path, build=2)
    # box is no longer unfinished: the old build is replaced
    item, _c, _i = do_install(
        paths, other, entry2, zip2, tmp_path, installed=installed, unfinished={other.id: other.name}
    )
    assert item.build == 2 and item.users == [other.id]
    assert not (paths.tools / "kerbrute" / "1.0.3-1").exists()
    assert (paths.tools / "kerbrute" / "1.0.3-2").is_dir()


def test_unused_same_build_is_reused(paths, box, other, tmp_path):
    zip_path, entry = build(tmp_path)
    _i, _c, installed = do_install(paths, box, entry, zip_path, tmp_path)
    marker = paths.tools / "kerbrute" / "1.0.3-1" / "marker"
    marker.write_text("kept")
    item, _c, _i = do_install(
        paths, other, entry, zip_path, tmp_path, installed=installed, unfinished={other.id: other.name}
    )
    assert item.users == [other.id]
    assert marker.read_text() == "kept"


# ---- install: refusals and failures


def assert_nothing_left(paths):
    left = [p for p in snapshot(paths) if p != "tools/installed.toml"]
    assert left == [], left


def test_wrong_arch(paths, box, tmp_path):
    zip_path, entry = build(tmp_path, arch="sparc")
    installed = {}
    with pytest.raises(ToolError, match="sparc"):
        do_install(paths, box, entry, zip_path, tmp_path, installed=installed)
    assert_nothing_left(paths)
    assert installed == {} and box.tools == []


def test_manifest_must_match_entry(paths, box, tmp_path):
    zip_path, entry = build(tmp_path)
    entry.version = "9.9.9"  # the file is untouched, so only the manifest check can catch it
    with pytest.raises(ToolError, match="not kerbrute 9.9.9-1"):
        do_install(paths, box, entry, zip_path, tmp_path)
    assert_nothing_left(paths)


def test_bad_zip_hash(paths, box, tmp_path):
    zip_path, entry = build(tmp_path)
    entry.sha256 = "0" * 64
    with pytest.raises(ToolError, match="SHA-256"):
        do_install(paths, box, entry, zip_path, tmp_path)
    assert_nothing_left(paths)


def test_python_tool_runs_venv_and_pip(paths, box, tmp_path):
    wheel = toolkit.make_wheel(tmp_path / "w", "kerbrute-py", "1.0", module="kmod", entry="kerbrute")
    zip_path, entry = build(tmp_path, wheels=[wheel], files={}, **python_manifest())
    fake = FakeRun()
    do_install(paths, box, entry, zip_path, tmp_path, run=fake, python="py3")
    folder = paths.tools / "kerbrute" / "1.0.3-1"
    venv_python = str(folder / "venv" / "bin" / "python")
    assert fake.calls == [
        ["py3", "-c", "import sys; print('%d.%d' % sys.version_info[:2])"],
        ["py3", "-m", "venv", str(folder / "venv")],
        [
            venv_python, "-m", "pip", "install", "--no-index",
            "--find-links", str(folder / "wheels"),
            "--only-binary", ":all:", "--require-hashes",
            "--disable-pip-version-check", "--no-input",
            "-r", str(folder / "wheels.lock"),
        ],
    ]  # fmt: skip
    assert "venv/bin/kerbrute" in (paths.bin / "kerbrute").read_text(encoding="utf-8")


def python_zip(tmp_path):
    wheel = toolkit.make_wheel(tmp_path / "w", "kerbrute-py", "1.0", module="kmod", entry="kerbrute")
    return build(tmp_path, wheels=[wheel], files={}, **python_manifest())


def test_wrong_python_version(paths, box, tmp_path):
    zip_path, entry = python_zip(tmp_path)
    with pytest.raises(ToolError, match="3.13"):
        do_install(paths, box, entry, zip_path, tmp_path, run=FakeRun(version="3.9"))
    assert_nothing_left(paths)


HASH = "--hash=sha256:" + "a" * 64
GOOD_LINE = f"kerbrute-py==1.0 {HASH}\n".encode()
BAD_LOCKS = {
    "an option": GOOD_LINE + b"--no-binary :all:\n",
    "find links": b"-f https://example.invalid/\n" + GOOD_LINE,
    "another file": GOOD_LINE + b"-r other.txt\n",
    "a url": f"kerbrute-py @ https://example.invalid/x.whl {HASH}\n".encode(),
    "a marker": f'kerbrute-py==1.0 ; python_version < "3.13" {HASH}\n'.encode(),
    "a marker after the hash": f'kerbrute-py==1.0 {HASH} ; python_version < "3.13"\n'.encode(),
    "no hash": b"kerbrute-py==1.0\n",
    "a blank line": GOOD_LINE + b"\n" + GOOD_LINE,
    "a carriage return": GOOD_LINE.replace(b"\n", b"\r\n"),
    "a continuation": f"kerbrute-py==1.0 \\\n    {HASH}\n".encode(),
}


@pytest.mark.parametrize("bad", BAD_LOCKS.values(), ids=BAD_LOCKS.keys())
def test_a_lock_pip_could_misread_is_refused_before_anything_runs(paths, box, tmp_path, bad):
    wheel = toolkit.make_wheel(tmp_path / "w", "kerbrute-py", "1.0", module="kmod", entry="kerbrute")
    zip_path, entry = build(tmp_path, wheels=[wheel], files={}, lock=bad, **python_manifest())
    fake = FakeRun()
    with pytest.raises(ToolError, match="wheels.lock"):
        do_install(paths, box, entry, zip_path, tmp_path, run=fake)
    assert fake.calls == []
    assert_nothing_left(paths)


def test_the_lock_is_checked_again_right_before_pip(paths, box, tmp_path, monkeypatch):
    from pwn_broker import toolinstall

    zip_path, entry = python_zip(tmp_path)
    real = toolinstall.unpack

    def swapped(zip_file, dest):
        manifest = real(zip_file, dest)
        (dest / "wheels.lock").write_bytes(b"--find-links https://example.invalid/\n")
        return manifest

    monkeypatch.setattr(toolinstall, "unpack", swapped)
    fake = FakeRun()
    with pytest.raises(ToolError, match="wheels.lock line 1"):
        do_install(paths, box, entry, zip_path, tmp_path, run=fake)
    assert not any("pip" in call for call in fake.calls)
    assert_nothing_left(paths)


@pytest.mark.parametrize("step", [1, 2])
def test_venv_or_pip_failure_leaves_nothing(paths, box, tmp_path, step):
    zip_path, entry = python_zip(tmp_path)
    installed = {}
    with pytest.raises(ToolError) as caught:
        do_install(
            paths, box, entry, zip_path, tmp_path,
            installed=installed, run=FakeRun(fail_at=step),
        )  # fmt: skip
    message = str(caught.value)
    assert "boom" in message
    assert message.count("line") == 9  # last ten lines: nine "line" plus "boom"
    assert_nothing_left(paths)
    assert installed == {} and box.tools == []
    assert load_box(box.path).tools == []


def test_command_name_taken(paths, box, other, tmp_path):
    zip_path, entry = build(tmp_path)
    _i, _c, installed = do_install(paths, box, entry, zip_path, tmp_path)
    zip2, entry2 = build(
        tmp_path, name="other-tool",
        command=[{"name": "kerbrute", "type": "binary", "path": "files/kerbrute"}],
    )  # fmt: skip
    before = (paths.bin / "kerbrute").read_text(encoding="utf-8")
    with pytest.raises(ToolError, match="kerbrute"):
        do_install(paths, other, entry2, zip2, tmp_path, installed=installed)
    assert (paths.bin / "kerbrute").read_text(encoding="utf-8") == before
    assert "other-tool" not in installed
    assert not (paths.tools / "other-tool").exists()


def test_warns_about_a_name_elsewhere_on_path(paths, box, tmp_path):
    zip_path, entry = build(tmp_path)
    seen = {"kerbrute": "/usr/bin/kerbrute"}
    _item, console, _i = do_install(
        paths, box, entry, zip_path, tmp_path, on_path=lambda name: seen.get(name)
    )
    warns = [text for kind, text in console.lines if kind == "warn"]
    assert len(warns) == 1 and "/usr/bin/kerbrute" in warns[0]
    # a copy in our own bin is not worth a warning
    paths2_console = FakeConsole()
    do_install(
        paths, box, entry, zip_path, tmp_path, console=paths2_console,
        on_path=lambda name: str(paths.bin / name),
        installed={}, unfinished={box.id: box.name},
    )  # fmt: skip
    assert not [1 for kind, _t in paths2_console.lines if kind == "warn"]


def test_failure_in_launcher_step_removes_earlier_launchers(paths, box, tmp_path, monkeypatch):
    from pwn_broker import toolinstall

    zip_path, entry = build(
        tmp_path, files={"files/a": SCRIPT, "files/b": SCRIPT},
        command=[
            {"name": "first", "type": "binary", "path": "files/a"},
            {"name": "second", "type": "binary", "path": "files/b"},
        ],
    )  # fmt: skip
    real = toolinstall.write_text
    written = []

    def flaky(path, text, **kw):
        if written:
            raise OSError("disk full")
        real(path, text, **kw)
        written.append(path)

    monkeypatch.setattr(toolinstall, "write_text", flaky)
    with pytest.raises(OSError):
        do_install(paths, box, entry, zip_path, tmp_path)
    assert written and not written[0].exists()
    assert_nothing_left(paths)


def test_foreign_launchers_are_never_overwritten_or_removed(paths, box, tmp_path):
    zip_path, entry = build(
        tmp_path, files={"files/a": SCRIPT, "files/b": SCRIPT},
        command=[
            {"name": "first", "type": "binary", "path": "files/a"},
            {"name": "second", "type": "binary", "path": "files/b"},
        ],
    )  # fmt: skip
    paths.bin.mkdir(parents=True)
    foreign = paths.bin / "second"
    foreign.write_bytes(b"#!/bin/sh\necho mine\n")
    with pytest.raises(ToolError, match="second"):
        do_install(paths, box, entry, zip_path, tmp_path)
    assert foreign.read_bytes() == b"#!/bin/sh\necho mine\n"
    assert not (paths.bin / "first").exists()
    assert not (paths.tools / "kerbrute").exists()


@posix_only
def test_symlink_at_a_launcher_path_is_refused(paths, box, tmp_path):
    zip_path, entry = build(tmp_path)
    target = tmp_path / "elsewhere"
    target.write_bytes(b"#!/bin/sh\n# pwn-broker tool: kerbrute\n")
    paths.bin.mkdir(parents=True)
    (paths.bin / "kerbrute").symlink_to(target)
    with pytest.raises(ToolError, match="kerbrute"):
        do_install(paths, box, entry, zip_path, tmp_path)
    assert (paths.bin / "kerbrute").is_symlink()
    assert target.read_bytes() == b"#!/bin/sh\n# pwn-broker tool: kerbrute\n"


@pytest.mark.parametrize("where", ["upload copy", "save_box"])
def test_interrupt_leaves_nothing(paths, box, tmp_path, monkeypatch, where):
    from pwn_broker import toolinstall

    zip_path, entry = build(
        tmp_path, files={"files/kerbrute": SCRIPT, "files/a": b"A"}, kind="both",
        upload=[{"path": "files/a", "as": "a"}],
    )  # fmt: skip

    def interrupt(*_a, **_k):
        raise KeyboardInterrupt

    monkeypatch.setattr(toolinstall, "_copy_uploads" if where == "upload copy" else "save_box", interrupt)
    installed = {}
    with pytest.raises(KeyboardInterrupt):
        do_install(paths, box, entry, zip_path, tmp_path, installed=installed)
    assert installed == {} and box.tools == []
    assert [p for p in snapshot(paths) if p != "tools/installed.toml"] == []
    assert load_installed(paths) == {}


def test_unrestorable_installed_list_is_reported(paths, box, tmp_path, monkeypatch):
    from pwn_broker import toolinstall

    zip_path, entry = build(tmp_path)
    calls = []

    def save(_paths, _installed):
        calls.append(1)
        if len(calls) > 1:
            raise OSError("read-only")

    def boom(_box):
        raise OSError("disk full")

    monkeypatch.setattr(toolinstall, "save_installed", save)
    monkeypatch.setattr(toolinstall, "save_box", boom)
    with pytest.raises(ToolError, match="installed.toml") as caught:
        do_install(paths, box, entry, zip_path, tmp_path)
    assert isinstance(caught.value.__cause__, OSError) and "disk full" in str(caught.value.__cause__)


def test_join_failure_restores_the_saved_users(paths, box, other, tmp_path, monkeypatch):
    from pwn_broker import toolinstall

    zip_path, entry = build(tmp_path)
    unfinished = {box.id: box.name, other.id: other.name}
    _i, _c, installed = do_install(paths, box, entry, zip_path, tmp_path, unfinished=unfinished)

    def boom(_box):
        raise OSError("disk full")

    monkeypatch.setattr(toolinstall, "save_box", boom)
    with pytest.raises(OSError):
        do_install(paths, other, entry, zip_path, tmp_path, installed=installed, unfinished=unfinished)
    assert installed["kerbrute"].users == [box.id]
    assert load_installed(paths)["kerbrute"].users == [box.id]
    assert other.tools == []


def test_box_with_another_build_is_refused_untouched(paths, box, tmp_path):
    zip_path, entry = build(tmp_path)
    _i, _c, installed = do_install(paths, box, entry, zip_path, tmp_path)
    zip2, entry2 = build(tmp_path, build=2)
    files = {
        "launcher": (paths.bin / "kerbrute").read_bytes(),
        "state": paths.tools_state.read_bytes(),
        "box": (box.path / "box.toml").read_bytes(),
    }
    with pytest.raises(ToolError, match="tool remove kerbrute"):
        do_install(paths, box, entry2, zip2, tmp_path, installed=installed)
    assert (paths.tools / "kerbrute" / "1.0.3-1" / "files" / "kerbrute").is_file()
    assert not (paths.tools / "kerbrute" / "1.0.3-2").exists()
    assert (paths.bin / "kerbrute").read_bytes() == files["launcher"]
    assert paths.tools_state.read_bytes() == files["state"]
    assert (box.path / "box.toml").read_bytes() == files["box"]
    assert installed["kerbrute"].build == 1


def test_failure_in_upload_step_removes_launchers_and_folders(paths, box, tmp_path):
    zip_path, entry = build(
        tmp_path, files={"files/kerbrute": SCRIPT, "files/a": b"A", "files/b": b"B"},
        kind="both",
        upload=[{"path": "files/a", "as": "same"}, {"path": "files/b", "as": "same"}],
    )  # fmt: skip
    with pytest.raises(ToolError, match="same name"):
        do_install(paths, box, entry, zip_path, tmp_path)
    assert_nothing_left(paths)


def test_failure_when_saving_removes_everything(paths, box, tmp_path, monkeypatch):
    zip_path, entry = build(
        tmp_path, files={"files/kerbrute": SCRIPT, "files/a": b"A"}, kind="both",
        upload=[{"path": "files/a", "as": "a"}],
    )  # fmt: skip

    def boom(_box):
        raise OSError("disk full")

    monkeypatch.setattr("pwn_broker.toolinstall.save_box", boom)
    installed = {}
    with pytest.raises(OSError):
        do_install(paths, box, entry, zip_path, tmp_path, installed=installed)
    assert installed == {} and box.tools == []
    assert load_installed(paths) == {}
    assert [p for p in snapshot(paths) if p != "tools/installed.toml"] == []


# ---- release and remove_files


def test_release_with_one_user_removes_everything(paths, box, tmp_path):
    zip_path, entry = build(
        tmp_path, files={"files/kerbrute": SCRIPT, "files/a": b"A"}, kind="both",
        upload=[{"path": "files/a", "as": "a"}],
    )  # fmt: skip
    _i, _c, installed = do_install(paths, box, entry, zip_path, tmp_path)
    assert release(paths, box, "kerbrute", installed=installed, unfinished={box.id: box.name})
    assert installed == {} and load_installed(paths) == {} and box.tools == []
    assert load_box(box.path).tools == []
    assert [p for p in snapshot(paths) if p != "tools/installed.toml"] == []


def test_release_with_two_users_keeps_the_tool(paths, box, other, tmp_path):
    zip_path, entry = build(tmp_path)
    unfinished = {box.id: box.name, other.id: other.name}
    _i, _c, installed = do_install(paths, box, entry, zip_path, tmp_path, unfinished=unfinished)
    do_install(paths, other, entry, zip_path, tmp_path, installed=installed, unfinished=unfinished)
    assert not release(paths, box, "kerbrute", installed=installed, unfinished=unfinished)
    assert installed["kerbrute"].users == [other.id]
    assert (paths.bin / "kerbrute").exists()
    assert box.tools == [] and load_box(box.path).tools == []
    assert [t.name for t in load_box(other.path).tools] == ["kerbrute"]
    # now the last one goes; the departing box counts as gone even while unfinished
    assert release(paths, other, "kerbrute", installed=installed, unfinished=unfinished)
    assert not (paths.bin / "kerbrute").exists()


def test_release_ignores_finished_users(paths, box, other, tmp_path):
    zip_path, entry = build(tmp_path)
    unfinished = {box.id: box.name, other.id: other.name}
    _i, _c, installed = do_install(paths, box, entry, zip_path, tmp_path, unfinished=unfinished)
    do_install(paths, other, entry, zip_path, tmp_path, installed=installed, unfinished=unfinished)
    # box has since finished
    assert release(paths, other, "kerbrute", installed=installed, unfinished={other.id: other.name})
    assert installed == {}


def test_release_of_unknown_tool_only_cleans_the_box(paths, box):
    assert not release(paths, box, "nothing", installed={}, unfinished={})


def item_for(paths, **overrides):
    values = dict(
        name="kerbrute", version="1", build=1, sha256="0" * 64,
        folder=(paths.tools / "kerbrute" / "1-1").as_posix(),
        commands=["kerbrute"], uploads=[], needs_root=False, users=[], home={},
    )  # fmt: skip
    values.update(overrides)
    return Installed(**values)


def test_remove_files_refuses_folders_outside_the_root(paths, tmp_path):
    outside = tmp_path / "precious"
    outside.mkdir()
    (outside / "f").write_text("x")
    for folder in (
        outside,
        paths.opt,
        paths.tools,
        paths.tools.parent,
        paths.tools / "kerbrute" / ".." / ".." / ".." / "precious",
        paths.tools / "installed.toml",
        paths.tools / "another" / "1-1",
    ):
        with pytest.raises(ToolError):
            remove_files(paths, item_for(paths, folder=str(folder).replace("\\", "/")))
    assert (outside / "f").read_text() == "x"


def test_remove_files_refuses_bad_names(paths):
    with pytest.raises(ToolError):
        remove_files(paths, item_for(paths, name="../x"))
    with pytest.raises(ToolError):
        remove_files(paths, item_for(paths, commands=["../../evil"]))


def test_remove_files_leaves_foreign_launchers(paths, tmp_path):
    folder = paths.tools / "kerbrute" / "1-1"
    folder.mkdir(parents=True)
    paths.bin.mkdir(parents=True)
    # bytes: write_text would turn the line breaks into CRLF on Windows
    (paths.bin / "kerbrute").write_bytes(b"#!/bin/sh\n# pwn-broker tool: someone-else\n")
    (paths.bin / "mine").write_bytes(b"#!/bin/sh\n# pwn-broker tool: kerbrute\nexec x\n")
    (paths.bin / "plain").write_bytes(b"#!/bin/sh\necho hi\n")
    item = item_for(paths, commands=["kerbrute", "mine", "plain"])
    with pytest.raises(ToolError, match="left alone"):
        remove_files(paths, item)
    assert (paths.bin / "kerbrute").exists() and (paths.bin / "plain").exists()
    assert not (paths.bin / "mine").exists()
    assert not folder.exists()


@posix_only
def test_remove_files_with_a_symlinked_launcher(paths, tmp_path):
    folder = paths.tools / "kerbrute" / "1-1"
    folder.mkdir(parents=True)
    (paths.upload / "kerbrute").mkdir(parents=True)
    paths.bin.mkdir(parents=True)
    target = tmp_path / "outside.txt"
    target.write_text("keep")
    (paths.bin / "kerbrute").symlink_to(target)
    with pytest.raises(ToolError, match=r"bin.kerbrute"):
        remove_files(paths, item_for(paths, uploads=["x"]))
    assert not folder.exists() and not (paths.upload / "kerbrute").exists()
    assert (paths.bin / "kerbrute").is_symlink() and target.read_text() == "keep"


@posix_only
def test_remove_files_does_not_follow_a_symlinked_tool_folder(paths, tmp_path):
    victim = paths.tools / "victim" / "1-1"
    victim.mkdir(parents=True)
    (paths.tools / "kerbrute").symlink_to(paths.tools / "victim")
    with pytest.raises(ToolError):
        remove_files(paths, item_for(paths))
    assert victim.is_dir()


def test_failed_release_keeps_an_orphan_entry(paths, box, tmp_path):
    zip_path, entry = build(tmp_path)
    _i, _c, installed = do_install(paths, box, entry, zip_path, tmp_path)
    (paths.bin / "kerbrute").write_bytes(b"#!/bin/sh\n# pwn-broker tool: other\n")
    with pytest.raises(ToolError):
        release(paths, box, "kerbrute", installed=installed, unfinished={box.id: box.name})
    assert load_installed(paths)["kerbrute"].users == []
    assert load_box(box.path).tools == []


# ---- real environment


def read_launcher_output(launcher, *args):
    return subprocess.run([str(launcher), *args], capture_output=True, text=True)


@posix_only
def test_real_python_entry_install(paths, box, tmp_path):
    (paths.run / "tools").mkdir(parents=True)
    wheel = toolkit.make_wheel(tmp_path / "w", "kerbrute-py", "1.0", module="kmod", entry="kerbrute")
    zip_path, entry = build(tmp_path, wheels=[wheel], files={}, **python_manifest(
        python={"versions": [f"{sys.version_info[0]}.{sys.version_info[1]}"],
                "lock": "wheels.lock", "wheels": "wheels"}))  # fmt: skip
    do_install(paths, box, entry, zip_path, tmp_path, python=sys.executable, run=subprocess.run)
    result = read_launcher_output(paths.bin / "kerbrute")
    assert result.returncode == 0, result.stderr
    assert result.stdout.strip() == "kerbrute-py 1.0"
    assert list((paths.run / "tools").glob("kerbrute.*"))
    assert toolstate.running(paths) == []


@posix_only
def test_real_binary_install(paths, box, tmp_path):
    zip_path, entry = build(tmp_path)
    do_install(paths, box, entry, zip_path, tmp_path)
    result = read_launcher_output(paths.bin / "kerbrute", "a")
    assert result.stdout.strip() == "hello from tool a"


@posix_only
def test_real_data_in_env(paths, box, tmp_path):
    import os

    files = {"files/kerbrute": b'#!/bin/sh\necho "data=${TOOL_DATA:-unset}"\n'}
    zip_path, entry = build(
        tmp_path, files=files,
        command=[{"name": "kerbrute", "type": "binary", "path": "files/kerbrute",
                  "env": {"TOOL_DATA": "{data}"}}],
    )  # fmt: skip
    do_install(paths, box, entry, zip_path, tmp_path)
    launcher = paths.bin / "kerbrute"
    assert read_launcher_output(launcher).stdout.strip() == "data=unset"
    toolstate.write_open_box(paths, box.path, os.getpid())
    out = read_launcher_output(launcher).stdout.strip()
    assert out == f"data={box.path.resolve().as_posix()}/tooldata/kerbrute"
    assert (box.path / "tooldata" / "kerbrute").is_dir()
    # no box open: back to the tool's own defaults
    paths.run_box.unlink()
    assert read_launcher_output(launcher).stdout.strip() == "data=unset"
