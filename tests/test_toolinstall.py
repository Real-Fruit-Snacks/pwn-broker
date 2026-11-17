import os
import shutil
import subprocess
import sys
from dataclasses import replace
from datetime import timedelta
from pathlib import Path
from types import SimpleNamespace

import pytest

import toolkit
from helpers import NOW
from pwn_broker import toolstate
from pwn_broker.console import FakeConsole
from pwn_broker.model import RuntimeRecord, ToolRecord, current_tools
from pwn_broker.store import load_box
from pwn_broker.toolindex import BuildEntry
from pwn_broker.toolinstall import (
    forget_runtime,
    install,
    install_runtime,
    launcher_text,
    megabytes,
    python_version,
    release,
    remove_files,
    remove_runtime,
    remove_stray,
    sh_quote,
    stray_files,
)
from pwn_broker.toolpkg import Command, ToolError, machine_arch, unpack
from pwn_broker.toolstate import Installed, load_installed

LATER = NOW + timedelta(hours=3)
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
        requires=list(manifest.get("requires", [])),
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
        self.kwargs = []
        self.version = version
        self.fail_at = fail_at
        self.output = output

    def __call__(self, argv, **kwargs):
        # every program an install runs gets the tool's folder and a cleaned environment
        assert set(kwargs) == {"capture_output", "text", "cwd", "env"}
        self.calls.append(list(argv))
        self.kwargs.append(kwargs)
        index = len(self.calls) - 1
        if argv[1:3] == ["-I", "-c"]:
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
        "{ { command -p sed 's/.*) //' \"/proc/$$/stat\" | command -p cut -d' ' -f20; } "
        "> \"$run/tools/kerbrute.$$\"; } 2>/dev/null || true"
    ) in lines
    assert '    box="$(command -p sed -n 1p "$run/box")"' in lines
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
    assert (
        'if [ -n "$box" ]; then data="$box/tooldata/kerbrute"; command -p mkdir -p "$data"; fi'
    ) in lines
    assert "if [ -n \"$data\" ]; then export HOME_X=\"$data\"'/home'; fi" in lines
    assert "export PLAIN='p'" in lines
    assert "if [ -n \"$data\" ]; then export Q='a'\\''b'\"$data\"'c'; fi" in lines
    # an option and its value go in together, or not at all when no box is open
    assert lines[-3] == 'if [ -n "$data" ]; then set -- \'--out\' "$data" \'last\' "$@"; fi'
    assert lines[-2].startswith("exec '") and lines[-2].endswith("/files/kerbrute' \"$@\"")


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


def shell_launcher(paths, tmp_path, cmd, body):
    manifest = manifest_of(tmp_path)
    folder = tmp_path / "unpacked"
    script = tmp_path / "launcher.sh"
    script.write_bytes(launcher_text(paths, manifest, cmd, folder).encode())
    (folder / "files" / "kerbrute").write_bytes(body)
    return script


def run_with_box(shell, script, paths, box_dir, *args, env_extra=None):
    # run/box names the shell that then becomes the launcher, so the box counts as open
    opener = (
        f'printf "%s\\n%s\\n" {sh_quote(box_dir.as_posix())} "$$" > '
        f'{sh_quote(paths.run_box.as_posix())}; exec {shell} {sh_quote(script.as_posix())} "$@"'
    )
    return run_sh(["-c", opener, shell, *args], env_extra=env_extra, shell=shell)


PRINT_ARGS = b'#!/bin/sh\nfor a in "$@"; do printf "[%s]" "$a"; done\n'


@pytest.mark.skipif(not SHELLS, reason="needs sh")
@pytest.mark.parametrize("shell", SHELLS)
def test_args_that_need_a_box_are_added_only_while_one_is_open(paths, tmp_path, shell):
    paths.run.mkdir(parents=True)
    cmd = Command(
        "kerbrute", "binary", path="files/kerbrute", args=["--out", "{data}/out.txt", "-q"]
    )
    script = shell_launcher(paths, tmp_path, cmd, PRINT_ARGS)
    alone = run_sh([script.as_posix(), "mine"], shell=shell)
    assert (alone.returncode, alone.stdout, alone.stderr) == (0, "[mine]", "")
    box_dir = tmp_path / "boxdir"
    box_dir.mkdir()
    opened = run_with_box(shell, script, paths, box_dir, "mine")
    data = f"{box_dir.as_posix()}/tooldata/kerbrute"
    assert (opened.returncode, opened.stderr) == (0, "")
    assert opened.stdout == f"[--out][{data}/out.txt][-q][mine]"
    assert (box_dir / "tooldata" / "kerbrute").is_dir()


@pytest.mark.skipif(not SHELLS, reason="needs sh")
@pytest.mark.parametrize("shell", SHELLS)
@pytest.mark.parametrize("state", ["present", "missing", "a file"])
def test_the_launcher_never_runs_a_sed_cut_or_mkdir_from_path(paths, tmp_path, shell, state):
    fake = tmp_path / "fakebin"
    fake.mkdir()
    ran = tmp_path / "fake-ran"
    for name in ("sed", "cut", "mkdir"):
        tool = fake / name
        tool.write_bytes(f"#!/bin/sh\necho {name} >> '{ran.as_posix()}'\necho /elsewhere\n".encode())
        tool.chmod(0o755)
    paths.run.mkdir(parents=True)
    if state == "present":
        (paths.run / "tools").mkdir()
    elif state == "a file":
        (paths.run / "tools").write_text("not a folder")
    cmd = Command("kerbrute", "binary", path="files/kerbrute", env={"OUT": "{data}"})
    script = shell_launcher(paths, tmp_path, cmd, b'#!/bin/sh\necho "ran $OUT"\nexit 7\n')
    box_dir = tmp_path / "boxdir"
    box_dir.mkdir()
    env = {"PATH": f"{fake.as_posix()}:/usr/bin:/bin"}
    result = run_with_box(shell, script, paths, box_dir, env_extra=env)
    data = f"{box_dir.as_posix()}/tooldata/kerbrute"
    assert (result.returncode, result.stdout.strip(), result.stderr) == (7, f"ran {data}", "")
    assert not ran.exists()
    assert (box_dir / "tooldata" / "kerbrute").is_dir()
    markers = list((paths.run / "tools").glob("kerbrute.*")) if state == "present" else []
    if state == "present":
        assert len(markers) == 1
        assert markers[0].read_text(encoding="utf-8").strip().isdecimal()


@posix_only
@pytest.mark.skipif(not SHELLS, reason="needs sh")
@pytest.mark.parametrize("shell", SHELLS)
def test_the_launcher_starts_when_the_marker_folder_is_read_only(paths, tmp_path, shell):
    (paths.run / "tools").mkdir(parents=True)
    (paths.run / "tools").chmod(0o500)
    try:
        cmd = Command("kerbrute", "binary", path="files/kerbrute")
        script = shell_launcher(paths, tmp_path, cmd, b"#!/bin/sh\necho ran\nexit 7\n")
        result = run_sh([script.as_posix()], shell=shell)
    finally:
        (paths.run / "tools").chmod(0o700)
    assert (result.returncode, result.stdout.strip(), result.stderr) == (7, "ran", "")


# ---- python_version


def test_python_version(tmp_path):
    fake = FakeRun(version="3.12")
    assert python_version("py", tmp_path, fake) == "3.12"
    assert fake.calls == [["py", "-I", "-c", "import sys; print('%d.%d' % sys.version_info[:2])"]]
    assert fake.kwargs[0]["cwd"] == str(tmp_path) and "PIP_CONFIG_FILE" in fake.kwargs[0]["env"]

    def missing(argv, **kw):
        raise FileNotFoundError("nope")

    def failing(argv, **kw):
        return SimpleNamespace(returncode=2, stdout="", stderr="")

    for bad in (missing, failing):
        with pytest.raises(ToolError, match="python3 was not found"):
            python_version("py", tmp_path, bad)
    with pytest.raises(ToolError, match="could not report"):
        python_version("py", tmp_path, FakeRun(version=""))


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
    (tmp_path / "user" / ".kerbrute").mkdir(parents=True)
    zip_path, entry = build(tmp_path, data={"home": [".kerbrute", ".cache/kerbrute"]})
    item, _c, _i = do_install(paths, box, entry, zip_path, tmp_path)
    assert item.home == {".kerbrute": True, ".cache/kerbrute": False}


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
        ("detail", f"sudo {(paths.bin / 'ligolo-proxy').as_posix()}"),
        ("info", f"files {(paths.upload / 'ligolo-ng').as_posix()}   agent  agent.exe"),
    ]
    assert (paths.upload / "ligolo-ng" / "agent.exe").read_bytes() == b"B"
    assert item.uploads == ["agent", "agent.exe"]
    # on screen the sudo form starts under the command it is for
    import io

    from pwn_broker import toolinstall
    from pwn_broker.console import TermConsole

    out = io.StringIO()
    toolinstall._show(paths, TermConsole({"NO_COLOR": "1"}, out=out), item)
    run_line, sudo_line = out.getvalue().splitlines()[:2]
    assert run_line.index("ligolo-proxy") == sudo_line.index("sudo") == 8


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
    with pytest.raises(ToolError) as err:
        do_install(paths, other, entry2, zip2, tmp_path, installed=installed, unfinished=unfinished)
    assert str(err.value) == (
        "kerbrute 1.0.3-1 is in use by forest; finish or remove it there before installing "
        "1.0.3-2, or ask for the build in use: tool install kerbrute@1.0.3-1"
    )
    assert installed["kerbrute"].users == [box.id]
    assert other.tools == []
    # another version: the version is enough to ask for it
    zip3, entry3 = build(tmp_path, version="1.0.4")
    with pytest.raises(ToolError) as err:
        do_install(paths, other, entry3, zip3, tmp_path, installed=installed, unfinished=unfinished)
    assert str(err.value) == (
        "kerbrute 1.0.3-1 is in use by forest; finish or remove it there before installing 1.0.4-1"
    )


def test_a_box_the_installed_list_names_with_another_build_is_refused(paths, box, tmp_path):
    zip_path, entry = build(tmp_path)
    _i, _c, installed = do_install(paths, box, entry, zip_path, tmp_path)
    box.tools = []  # the list still names the box, its record does not
    for version, build_no, said in [
        ("1.0.3", 2, ", or ask for the build it has: tool install kerbrute@1.0.3-1"),
        ("1.0.4", 1, ""),
    ]:
        zip2, entry2 = build(tmp_path, version=version, build=build_no)
        with pytest.raises(ToolError) as err:
            do_install(paths, box, entry2, zip2, tmp_path, installed=installed)
        assert str(err.value) == (
            f"forest already has kerbrute 1.0.3-1, not {version}-{build_no}; "
            f"run tool remove kerbrute first{said}"
        )


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


@pytest.mark.parametrize("commands", [[], ["other"], ["kerbrute", "extra"]])
def test_commands_must_match_the_index_before_anything_is_written(paths, box, tmp_path, commands):
    zip_path, entry = build(tmp_path)
    entry.commands = commands
    fake = FakeRun()
    with pytest.raises(ToolError, match="commands"):
        do_install(paths, box, entry, zip_path, tmp_path, run=fake)
    assert snapshot(paths) == [] and fake.calls == []
    assert box.tools == []


def test_commands_in_another_order_still_match(paths, box, tmp_path):
    zip_path, entry = build(
        tmp_path, files={"files/a": SCRIPT, "files/b": SCRIPT},
        command=[
            {"name": "first", "type": "binary", "path": "files/a"},
            {"name": "second", "type": "binary", "path": "files/b"},
        ],
    )  # fmt: skip
    entry.commands = ["second", "first"]
    item, _c, _i = do_install(paths, box, entry, zip_path, tmp_path)
    assert item.commands == ["first", "second"]


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
        ["py3", "-I", "-c", "import sys; print('%d.%d' % sys.version_info[:2])"],
        ["py3", "-I", "-m", "venv", str(folder / "venv")],
        [
            venv_python, "-I", "-m", "pip", "--isolated", "install", "--no-index",
            "--find-links", str(folder / "wheels"),
            "--only-binary", ":all:", "--require-hashes",
            "--disable-pip-version-check", "--no-input",
            "-r", str(folder / "wheels.lock"),
        ],
    ]  # fmt: skip
    assert "venv/bin/kerbrute" in (paths.bin / "kerbrute").read_text(encoding="utf-8")


PY_VERSION = "import sys; print('%d.%d' % sys.version_info[:2])"
SHADOWS = ("PYTHONPATH", "PYTHONHOME", "PYTHONSTARTUP", "PIP_TARGET", "PIP_PREFIX", "PIP_INDEX_URL")


@pytest.mark.parametrize("schema", [1, 2])
def test_venv_and_pip_run_in_the_tool_folder_with_none_of_the_callers_settings(
    paths, box, tmp_path, monkeypatch, schema
):
    # a venv.py or pip/ in the caller's folder, or these variables, would change what runs
    for name in SHADOWS:
        monkeypatch.setenv(name, (tmp_path / "elsewhere").as_posix())
    monkeypatch.setenv("PIP_CONFIG_FILE", (tmp_path / "pip.conf").as_posix())
    kw = {}
    if schema == 1:
        zip_path, entry = python_zip(tmp_path)
    else:
        kw["runtime"], _c, kw["installed"] = rt_install(paths, tmp_path)
        zip_path, entry = runtime_tool(tmp_path)
    fake = FakeRun()
    do_install(paths, box, entry, zip_path, tmp_path, run=fake, **kw)
    folder = paths.tools / "kerbrute" / "1.0.3-1"
    made = list(zip(fake.calls, fake.kwargs))
    steps = [["-c", PY_VERSION]] if schema == 1 else []  # Kali's own Python is asked its version
    assert [call[2:4] for call, _kw in made] == [*steps, ["-m", "venv"], ["-m", "pip"]]
    for call, kwargs in made:
        assert call[1] == "-I"
        assert kwargs["cwd"] == str(folder)
        env = kwargs["env"]
        assert not set(SHADOWS) & set(env)
        assert env["PIP_CONFIG_FILE"] == os.devnull
        assert env["PATH"] == os.environ["PATH"]  # everything else is passed on


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


def ligolo(tmp_path, **overrides):
    return build(
        tmp_path,
        files={"files/proxy": SCRIPT}, name="ligolo-ng", needs_root=True,
        command=[{"name": "ligolo-proxy", "type": "binary", "path": "files/proxy"}],
        **overrides,
    )  # fmt: skip


def test_a_root_tool_with_another_copy_on_path_names_what_sudo_runs(paths, box, other, tmp_path):
    zip_path, entry = ligolo(tmp_path)
    elsewhere = {"ligolo-proxy": "/usr/bin/ligolo-proxy"}
    unfinished = {box.id: box.name, other.id: other.name}
    _item, console, installed = do_install(
        paths, box, entry, zip_path, tmp_path, unfinished=unfinished, on_path=elsewhere.get
    )
    full = (paths.bin / "ligolo-proxy").as_posix()
    line = ("warn", f"sudo ligolo-proxy runs /usr/bin/ligolo-proxy; use sudo {full}")
    assert console.lines[-1] == line
    # a second box taking the same build hears it too
    _item, console, _i = do_install(
        paths, other, entry, zip_path, tmp_path,
        installed=installed, unfinished=unfinished, on_path=elsewhere.get,
    )  # fmt: skip
    assert console.lines[-1] == line


def test_no_sudo_line_without_root_or_without_another_copy(paths, box, tmp_path):
    zip_path, entry = build(tmp_path)
    _i, console, _installed = do_install(
        paths, box, entry, zip_path, tmp_path, on_path=lambda name: "/usr/bin/" + name
    )
    assert not any(t.startswith("sudo ") for k, t in console.lines if k == "warn")
    zip2, entry2 = ligolo(tmp_path / "second")
    _i, console, _installed = do_install(
        paths, box, entry2, zip2, tmp_path, on_path=lambda name: str(paths.bin / name)
    )
    assert not any(k == "warn" for k, _t in console.lines)


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
    with pytest.raises(ToolError) as err:
        do_install(paths, box, entry2, zip2, tmp_path, installed=installed)
    assert str(err.value) == (
        "forest already has kerbrute 1.0.3-1, not 1.0.3-2; run tool remove kerbrute first, "
        "or ask for the build it has: tool install kerbrute@1.0.3-1"
    )
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
    assert release(
        paths, box, "kerbrute", installed=installed, unfinished={box.id: box.name}, removed=LATER
    )
    assert installed == {} and load_installed(paths) == {} and current_tools(box) == []
    # the box keeps the tool on record, with the time it was removed
    assert [(t.name, t.installed, t.removed) for t in load_box(box.path).tools] == [
        ("kerbrute", NOW, LATER)
    ]
    assert [p for p in snapshot(paths) if p != "tools/installed.toml"] == []


def test_release_with_two_users_keeps_the_tool(paths, box, other, tmp_path):
    zip_path, entry = build(tmp_path)
    unfinished = {box.id: box.name, other.id: other.name}
    _i, _c, installed = do_install(paths, box, entry, zip_path, tmp_path, unfinished=unfinished)
    do_install(paths, other, entry, zip_path, tmp_path, installed=installed, unfinished=unfinished)
    assert not release(
        paths, box, "kerbrute", installed=installed, unfinished=unfinished, removed=LATER
    )
    assert installed["kerbrute"].users == [other.id]
    assert (paths.bin / "kerbrute").exists()
    assert current_tools(box) == [] and current_tools(load_box(box.path)) == []
    assert [t.removed for t in load_box(box.path).tools] == [LATER]
    assert [t.name for t in current_tools(load_box(other.path))] == ["kerbrute"]
    # now the last one goes; the departing box counts as gone even while unfinished
    assert release(
        paths, other, "kerbrute", installed=installed, unfinished=unfinished, removed=LATER
    )
    assert not (paths.bin / "kerbrute").exists()


def test_release_ignores_finished_users(paths, box, other, tmp_path):
    zip_path, entry = build(tmp_path)
    unfinished = {box.id: box.name, other.id: other.name}
    _i, _c, installed = do_install(paths, box, entry, zip_path, tmp_path, unfinished=unfinished)
    do_install(paths, other, entry, zip_path, tmp_path, installed=installed, unfinished=unfinished)
    # box has since finished
    assert release(
        paths, other, "kerbrute", installed=installed, unfinished={other.id: other.name},
        removed=LATER,
    )  # fmt: skip
    assert installed == {}


def test_release_of_unknown_tool_only_cleans_the_box(paths, box):
    box.tools = [ToolRecord("nothing", "1", 1, "ab" * 32, NOW)]
    assert not release(paths, box, "nothing", installed={}, unfinished={}, removed=LATER)
    assert load_box(box.path).tools == [
        ToolRecord("nothing", "1", 1, "ab" * 32, NOW, removed=LATER)
    ]


def test_release_at_finish_leaves_the_row_current(paths, box, tmp_path):
    zip_path, entry = build(tmp_path)
    _i, _c, installed = do_install(paths, box, entry, zip_path, tmp_path)
    before = list(box.tools)
    assert release(
        paths, box, "kerbrute", installed=installed, unfinished={box.id: box.name}, removed=None
    )
    assert installed == {}
    assert box.tools == before and load_box(box.path).tools == before
    assert before[0].removed is None


def test_release_marks_only_the_current_row(paths, box, tmp_path):
    earlier = ToolRecord("kerbrute", "1.0.2", 1, "cd" * 32, NOW, removed=NOW)
    box.tools = [earlier]
    zip_path, entry = build(tmp_path)
    _i, _c, installed = do_install(paths, box, entry, zip_path, tmp_path)
    release(paths, box, "kerbrute", installed=installed, unfinished={}, removed=LATER)
    assert [(t.version, t.removed) for t in load_box(box.path).tools] == [
        ("1.0.2", NOW), ("1.0.3", LATER),
    ]  # fmt: skip


def test_reinstalling_after_a_removal_adds_a_row_and_keeps_the_removed_one(paths, box, tmp_path):
    zip_path, entry = build(tmp_path)
    _i, _c, installed = do_install(paths, box, entry, zip_path, tmp_path)
    release(paths, box, "kerbrute", installed=installed, unfinished={}, removed=LATER)
    again = LATER + timedelta(hours=1)
    install(
        paths, box, entry, zip_path, installed=installed, unfinished={box.id: box.name},
        home=tmp_path / "user", console=FakeConsole(), now=again, run=FakeRun(),
        on_path=lambda name: None,
    )  # fmt: skip
    rows = load_box(box.path).tools
    assert [(t.name, t.build, t.installed, t.removed) for t in rows] == [
        ("kerbrute", 1, NOW, LATER), ("kerbrute", 1, again, None),
    ]  # fmt: skip
    assert box.id in load_installed(paths)["kerbrute"].users


def test_the_same_build_installed_again_keeps_its_row_with_a_new_install_time(
    paths, box, tmp_path
):
    zip_path, entry = build(tmp_path)
    # the box recorded the build; this machine does not have it (reopen, import)
    box.tools = [ToolRecord("kerbrute", "1.0.3", 1, entry.sha256, NOW)]
    install(
        paths, box, entry, zip_path, installed={}, unfinished={box.id: box.name},
        home=tmp_path / "user", console=FakeConsole(), now=LATER, run=FakeRun(),
        on_path=lambda name: None,
    )  # fmt: skip
    # a new install on the machine: its own time, so its tool data is told from the last's
    assert load_box(box.path).tools == [ToolRecord("kerbrute", "1.0.3", 1, entry.sha256, LATER)]


def test_a_removed_row_at_another_build_does_not_stop_an_install(paths, box, tmp_path):
    box.tools = [ToolRecord("kerbrute", "1.0.2", 1, "cd" * 32, NOW, removed=NOW)]
    zip_path, entry = build(tmp_path)
    item, _c, _i = do_install(paths, box, entry, zip_path, tmp_path)
    assert item.version == "1.0.3"
    assert [t.version for t in current_tools(load_box(box.path))] == ["1.0.3"]
    assert len(load_box(box.path).tools) == 2


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
        release(
            paths, box, "kerbrute", installed=installed, unfinished={box.id: box.name},
            removed=LATER,
        )  # fmt: skip
    assert load_installed(paths)["kerbrute"].users == []
    assert current_tools(load_box(box.path)) == []


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


def test_remove_stray_refuses_anything_outside_the_apps_folders(paths, tmp_path):
    victim = tmp_path / "precious"
    victim.mkdir()
    for path in (victim, paths.opt, paths.tools, paths.run / "tools", paths.tools / "a" / "b" / "c"):
        with pytest.raises(ToolError):
            remove_stray(paths, path)
    assert victim.is_dir()


# ---- runtimes


def rt_install(paths, tmp_path, zip_path=None, entry=None, *, installed=None, console=None):
    if zip_path is None:
        zip_path, entry = toolkit.make_runtime(tmp_path / "rtzips")
    installed = {} if installed is None else installed
    console = console or FakeConsole()
    item = install_runtime(paths, entry, zip_path, installed=installed, console=console)
    return item, console, installed


def rt_folder(paths, build=1):
    return paths.tools / "python-3.13" / f"3.13.18-{build}"


def test_install_runtime_unpacks_and_records_it(paths, tmp_path):
    item, console, installed = rt_install(paths, tmp_path)
    folder = rt_folder(paths)
    python = folder / "root" / "python" / "bin" / "python3.13"
    assert python.read_bytes() == toolkit.stand_in_python()
    assert (folder / "manifest.toml").is_file() and (folder / "LICENSE").is_file()
    # the archive is unpacked, so the copy in the package is not kept
    assert not (folder / "files" / "python.tar.gz").exists()
    assert item.kind == "runtime"
    assert item.python == python.resolve().as_posix()
    assert item.folder == folder.resolve().as_posix()
    assert (item.commands, item.uploads, item.users, item.home) == ([], [], [], {})
    assert installed == {"python-3.13": item}
    assert load_installed(paths) == installed
    assert console.lines == [("ok", "python-3.13 3.13.18 installed (runtime, 1 MB)")]
    assert not (paths.bin.exists() and list(paths.bin.iterdir()))


def test_runtime_size_is_shown_in_whole_megabytes():
    assert [megabytes(n) for n in (1, 524_288, 37_748_736, 38_797_312)] == [1, 1, 36, 37]


@posix_only
def test_an_installed_runtime_is_executable(paths, tmp_path):
    item, _c, _i = rt_install(paths, tmp_path)
    assert os.stat(item.python).st_mode & 0o777 == 0o755


@pytest.mark.parametrize("build", [1, 2])
def test_an_installed_runtime_is_used_as_it_is(paths, tmp_path, build):
    first, _c, installed = rt_install(paths, tmp_path)
    before = paths.tools_state.read_bytes()
    zip_path, entry = toolkit.make_runtime(tmp_path / "newer", build=build)
    zip_path.unlink()  # nothing is read from the package
    item, console, _i = rt_install(paths, tmp_path, zip_path, entry, installed=installed)
    assert item is first
    assert console.lines == []
    assert paths.tools_state.read_bytes() == before
    assert not rt_folder(paths, 2).exists()


@pytest.mark.parametrize("missing", ["folder", "interpreter"])
def test_a_runtime_whose_files_are_gone_is_installed_afresh(paths, tmp_path, missing):
    _first, _c, installed = rt_install(paths, tmp_path)
    old = rt_folder(paths)
    if missing == "folder":
        shutil.rmtree(old)
    else:
        (old / "root" / "python" / "bin" / "python3.13").unlink()
    (paths.tools / "python-3.13" / "leftover").mkdir()
    zip_path, entry = toolkit.make_runtime(tmp_path / "newer", build=2)
    item, console, _i = rt_install(paths, tmp_path, zip_path, entry, installed=installed)
    assert item.build == 2 and installed == {"python-3.13": item}
    assert load_installed(paths) == installed
    assert sorted(p.name for p in (paths.tools / "python-3.13").iterdir()) == ["3.13.18-2"]
    assert console.lines == [("ok", "python-3.13 3.13.18 installed (runtime, 1 MB)")]


def a_tool_on(runtime: Installed) -> Installed:
    # a row for a tool whose environment was made by the runtime's interpreter
    return Installed(
        name="certipy", version="5.1.0", build=3, sha256="ab" * 32,
        folder="/opt/pwn-broker/tools/certipy/5.1.0-3", commands=["certipy"], uploads=[],
        needs_root=False, users=["box"], home={}, requires=[runtime.name],
    )  # fmt: skip


def test_a_damaged_runtime_a_tool_requires_is_only_replaced_by_its_own_build(paths, tmp_path):
    first, _c, installed = rt_install(paths, tmp_path)
    installed["certipy"] = a_tool_on(first)
    python = Path(first.python)
    python.unlink()
    before = snapshot(paths)
    zip_path, entry = toolkit.make_runtime(tmp_path / "newer", build=2)
    with pytest.raises(ToolError, match="python-3.13 3.13.18-1 is missing or damaged") as err:
        rt_install(paths, tmp_path, zip_path, entry, installed=installed)
    assert "certipy requires it: remove certipy and install it again" in str(err.value)
    assert snapshot(paths) == before and installed["python-3.13"] is first
    # the build it was: the same folder and interpreter again
    zip_path, entry = toolkit.make_runtime(tmp_path / "same")
    item, console, _i = rt_install(paths, tmp_path, zip_path, entry, installed=installed)
    assert (item.folder, item.python) == (first.folder, first.python)
    assert python.is_file() and load_installed(paths)["python-3.13"] == item
    assert console.lines == [("ok", "python-3.13 3.13.18 installed (runtime, 1 MB)")]


def test_install_runtime_refuses_a_package_that_is_not_a_runtime(paths, tmp_path):
    zip_path, entry = build(tmp_path)
    installed = {}
    with pytest.raises(ToolError, match="kerbrute is not a runtime"):
        rt_install(paths, tmp_path, zip_path, entry, installed=installed)
    assert snapshot(paths) == [] and installed == {}


def test_install_runtime_refuses_a_tool_package_listed_as_a_runtime(paths, tmp_path):
    zip_path, entry = build(tmp_path)
    entry.kind = "runtime"
    with pytest.raises(ToolError, match="not a runtime"):
        rt_install(paths, tmp_path, zip_path, entry)
    assert snapshot(paths) == []


def test_install_runtime_refuses_the_name_of_an_installed_tool(paths, box, tmp_path):
    zip_path, entry = build(tmp_path, name="python-3.13")
    _i, _c, installed = do_install(paths, box, entry, zip_path, tmp_path)
    before = snapshot(paths)
    rt_zip, rt_entry = toolkit.make_runtime(tmp_path / "rtzips")
    with pytest.raises(ToolError, match="python-3.13 is installed as a tool"):
        rt_install(paths, tmp_path, rt_zip, rt_entry, installed=installed)
    assert snapshot(paths) == before


RT_FAULTS = {
    "not a gzip tar": (b"not an archive", "incomplete or damaged"),
    "a name that leaves": (
        toolkit.runtime_archive({"python/bin/python3.13": b"x", "../evil": b"x"}),
        "would write outside",
    ),
    "no interpreter": (
        toolkit.runtime_archive({"python/bin/python3": b"x"}),
        "python/bin/python3.13 is missing",
    ),
    "a folder for an interpreter": (
        toolkit.runtime_archive({"python/bin/python3.13/inside": b"x"}),
        "python/bin/python3.13 is not a regular file",
    ),
}


@pytest.mark.parametrize("archive, words", RT_FAULTS.values(), ids=RT_FAULTS.keys())
def test_a_bad_runtime_archive_leaves_nothing(paths, tmp_path, archive, words):
    zip_path, entry = toolkit.make_runtime(tmp_path / "rtzips", archive=archive)
    installed = {}
    console = FakeConsole()
    with pytest.raises(ToolError, match=words):
        rt_install(paths, tmp_path, zip_path, entry, installed=installed, console=console)
    assert snapshot(paths) == [] and installed == {} and console.lines == []
    assert not (paths.tools / "python-3.13").exists()


def test_a_runtime_with_a_bad_hash_leaves_nothing(paths, tmp_path):
    zip_path, entry = toolkit.make_runtime(tmp_path / "rtzips")
    entry.sha256 = "0" * 64
    with pytest.raises(ToolError, match="SHA-256"):
        rt_install(paths, tmp_path, zip_path, entry)
    assert snapshot(paths) == []


def test_a_runtime_unlike_its_entry_leaves_nothing(paths, tmp_path):
    zip_path, entry = toolkit.make_runtime(tmp_path / "rtzips")
    entry.version = "3.13.99"
    with pytest.raises(ToolError, match="not python-3.13 3.13.99-1"):
        rt_install(paths, tmp_path, zip_path, entry)
    assert snapshot(paths) == []


@posix_only
def test_an_interpreter_that_leads_outside_the_runtime_is_refused(paths, tmp_path, monkeypatch):
    from pwn_broker import toolinstall

    real = toolinstall.runtimearchive.unpack

    def linked_out(archive, dest):
        real(archive, dest)
        python = dest / "python" / "bin" / "python3.13"
        python.unlink()
        python.symlink_to(sys.executable)

    monkeypatch.setattr(toolinstall.runtimearchive, "unpack", linked_out)
    with pytest.raises(ToolError, match="outside the runtime's folder"):
        rt_install(paths, tmp_path)
    assert snapshot(paths) == []


@pytest.mark.parametrize("where", ["unpack", "save"])
def test_an_interrupted_runtime_install_leaves_nothing(paths, tmp_path, monkeypatch, where):
    from pwn_broker import toolinstall

    real = toolinstall.save_installed

    def interrupt(*_a, **_k):
        raise KeyboardInterrupt

    def save_then_interrupt(paths_, installed_):
        real(paths_, installed_)
        if installed_:
            raise KeyboardInterrupt

    if where == "unpack":
        monkeypatch.setattr(toolinstall.runtimearchive, "unpack", interrupt)
    else:
        monkeypatch.setattr(toolinstall, "save_installed", save_then_interrupt)
    installed = {}
    with pytest.raises(KeyboardInterrupt):
        rt_install(paths, tmp_path, installed=installed)
    assert installed == {}
    assert [p for p in snapshot(paths) if p != "tools/installed.toml"] == []
    assert load_installed(paths) == {}


def test_remove_runtime_removes_its_folder(paths, tmp_path):
    item, _c, _i = rt_install(paths, tmp_path)
    remove_runtime(paths, item)
    assert not (paths.tools / "python-3.13").exists()


def test_remove_runtime_refuses_what_is_not_a_runtime_folder(paths, tmp_path):
    item, _c, _i = rt_install(paths, tmp_path)
    outside = tmp_path / "precious"
    outside.mkdir()
    for folder in (
        outside,
        paths.tools,
        paths.tools / "python-3.13",
        paths.tools / "other" / "3.13.18-1",
        paths.tools / "python-3.13" / ".." / ".." / ".." / "precious",
    ):
        with pytest.raises(ToolError, match="refusing"):
            remove_runtime(paths, replace(item, folder=folder.as_posix()))
    with pytest.raises(ToolError, match="kerbrute is not a runtime"):
        remove_runtime(paths, item_for(paths))
    with pytest.raises(ToolError):
        remove_runtime(paths, replace(item, name="../x"))
    assert outside.is_dir() and Path(item.python).is_file()


def test_forget_runtime_removes_it_and_its_row(paths, tmp_path):
    _item, _c, installed = rt_install(paths, tmp_path)
    forget_runtime(paths, installed, "python-3.13")
    assert installed == {} and load_installed(paths) == {}
    assert not (paths.tools / "python-3.13").exists()


def test_a_runtime_that_cannot_be_removed_keeps_its_row(paths, tmp_path, monkeypatch):
    from pwn_broker import toolinstall

    _item, _c, installed = rt_install(paths, tmp_path)

    def busy(path):
        raise OSError("busy")

    monkeypatch.setattr(toolinstall, "_delete_tree", busy)
    with pytest.raises(ToolError, match="busy"):
        forget_runtime(paths, installed, "python-3.13")
    assert list(installed) == list(load_installed(paths)) == ["python-3.13"]


def test_forget_runtime_keeps_a_runtime_another_tool_requires(paths, box, tmp_path):
    rt, _c, installed = rt_install(paths, tmp_path)
    zip_path, entry = runtime_tool(tmp_path)
    do_install(paths, box, entry, zip_path, tmp_path, installed=installed, runtime=rt)
    # its row goes stale, so the next install brings it afresh and looks like this command's own
    Path(rt.python).unlink()
    again_zip, again = toolkit.make_runtime(tmp_path / "again")
    fresh, _c, _i = rt_install(paths, tmp_path, again_zip, again, installed=installed)
    assert fresh is not rt
    assert forget_runtime(paths, installed, "python-3.13") is False
    assert installed["python-3.13"] is fresh and load_installed(paths)["python-3.13"] == fresh
    assert Path(fresh.python).is_file()


def test_forget_runtime_says_whether_it_removed_the_runtime(paths, tmp_path):
    _item, _c, installed = rt_install(paths, tmp_path)
    assert forget_runtime(paths, installed, "python-3.13") is True
    assert forget_runtime(paths, installed, "python-3.13") is False


def test_a_recorded_interpreter_outside_the_unpacked_archive_is_not_used(paths, tmp_path):
    first, _c, installed = rt_install(paths, tmp_path)
    # inside the runtime's folder, but not part of the archive
    first.python = (rt_folder(paths) / "LICENSE").resolve().as_posix()
    zip_path, entry = toolkit.make_runtime(tmp_path / "again", build=2)
    item, console, _i = rt_install(paths, tmp_path, zip_path, entry, installed=installed)
    assert item is not first and item.build == 2
    assert Path(item.python).read_bytes() == toolkit.stand_in_python()
    assert console.lines == [("ok", "python-3.13 3.13.18 installed (runtime, 1 MB)")]


STRANGER = b"#!/bin/sh\necho not the runtime\n"


@pytest.mark.parametrize("where", ["a folder elsewhere", "an interpreter elsewhere"])
def test_a_hand_edited_row_cannot_make_an_install_run_another_program(paths, tmp_path, where):
    first, _c, installed = rt_install(paths, tmp_path)
    elsewhere = tmp_path / "elsewhere"
    (elsewhere / "root").mkdir(parents=True)
    program = elsewhere / "root" / "python3.13"
    program.write_bytes(STRANGER)
    if where == "a folder elsewhere":
        first.folder = elsewhere.resolve().as_posix()
    first.python = program.resolve().as_posix()
    zip_path, entry = toolkit.make_runtime(tmp_path / "again", build=2)
    item, _c, _i = rt_install(paths, tmp_path, zip_path, entry, installed=installed)
    assert item is not first and item.python.startswith(paths.tools.resolve().as_posix())
    assert program.read_bytes() == STRANGER  # nothing outside the root is touched


def test_a_stale_row_that_cannot_be_saved_away_is_reported_and_kept(paths, tmp_path, monkeypatch):
    from pwn_broker import toolinstall

    first, _c, installed = rt_install(paths, tmp_path)
    shutil.rmtree(rt_folder(paths))

    def full(_paths, _installed):
        raise OSError("no space left")

    monkeypatch.setattr(toolinstall, "save_installed", full)
    zip_path, entry = toolkit.make_runtime(tmp_path / "again", build=2)
    with pytest.raises(ToolError, match="the installed list could not be restored"):
        rt_install(paths, tmp_path, zip_path, entry, installed=installed)
    # the file still lists the runtime, and so does the list in memory
    assert installed == {"python-3.13": first} and load_installed(paths) == installed
    assert not rt_folder(paths, 2).exists()


def test_stray_files_counts_a_recorded_runtime_as_recorded(paths, tmp_path):
    _item, _c, installed = rt_install(paths, tmp_path)
    assert stray_files(paths, installed) == []
    assert stray_files(paths, {}) == [paths.tools / "python-3.13"]
    # an upload folder under a runtime's name belongs to no tool
    (paths.upload / "python-3.13").mkdir(parents=True)
    assert stray_files(paths, installed) == [paths.upload / "python-3.13"]


# ---- a tool built on a runtime


def runtime_tool(tmp_path, **overrides):
    wheel = toolkit.make_wheel(tmp_path / "w", "kerbrute-py", "1.0", module="kmod", entry="kerbrute")
    return build(tmp_path, wheels=[wheel], files={}, requires=["python-3.13"], **overrides)


def test_a_tool_on_a_runtime_makes_its_environment_with_the_runtimes_python(paths, box, tmp_path):
    rt, _c, installed = rt_install(paths, tmp_path)
    zip_path, entry = runtime_tool(tmp_path)
    fake = FakeRun()
    item, console, _i = do_install(
        paths, box, entry, zip_path, tmp_path, installed=installed, run=fake, runtime=rt
    )
    folder = paths.tools / "kerbrute" / "1.0.3-1"
    venv = folder / "venv"
    # no version check: the wheels are built for the runtime's series
    assert fake.calls == [
        [rt.python, "-I", "-m", "venv", str(venv)],
        [
            str(venv / "bin" / "python"), "-I", "-m", "pip", "--isolated", "install", "--no-index",
            "--find-links", str(folder / "wheels"),
            "--only-binary", ":all:", "--require-hashes",
            "--disable-pip-version-check", "--no-input",
            "-r", str(folder / "wheels.lock"),
        ],
    ]  # fmt: skip
    assert item.requires == ["python-3.13"]
    assert load_installed(paths)["kerbrute"].requires == ["python-3.13"]
    note = RuntimeRecord("python-3.13", "3.13.18", 1, rt.sha256)
    assert [t.runtime for t in box.tools] == [note]
    assert [t.runtime for t in load_box(box.path).tools] == [note]
    assert console.lines[0] == ("ok", "kerbrute 1.0.3 installed")


def test_a_second_box_joining_a_tool_on_a_runtime_records_the_runtime(paths, box, other, tmp_path):
    rt, _c, installed = rt_install(paths, tmp_path)
    zip_path, entry = runtime_tool(tmp_path)
    unfinished = {box.id: box.name, other.id: other.name}
    kw = dict(installed=installed, unfinished=unfinished, runtime=rt)
    do_install(paths, box, entry, zip_path, tmp_path, **kw)
    do_install(paths, other, entry, zip_path, tmp_path, **kw)
    assert installed["kerbrute"].users == [box.id, other.id]
    assert [t.runtime.name for t in load_box(other.path).tools] == ["python-3.13"]


@pytest.mark.parametrize("given", ["none", "another runtime", "a tool"])
def test_a_tool_on_a_runtime_needs_the_one_it_requires(paths, box, tmp_path, given):
    rt, _c, installed = rt_install(paths, tmp_path)
    runtime = {
        "none": None,
        "another runtime": replace(rt, name="python-3.14"),
        "a tool": replace(rt, kind="tool"),
    }[given]
    zip_path, entry = runtime_tool(tmp_path)
    before = snapshot(paths)
    fake = FakeRun()
    with pytest.raises(ToolError, match="kerbrute requires the runtime python-3.13"):
        do_install(
            paths, box, entry, zip_path, tmp_path, installed=installed, run=fake, runtime=runtime
        )
    assert fake.calls == [] and snapshot(paths) == before and box.tools == []


def test_a_tool_that_requires_nothing_refuses_a_runtime(paths, box, tmp_path):
    rt, _c, installed = rt_install(paths, tmp_path)
    zip_path, entry = python_zip(tmp_path)
    fake = FakeRun()
    with pytest.raises(ToolError, match="kerbrute requires no runtime"):
        do_install(paths, box, entry, zip_path, tmp_path, installed=installed, run=fake, runtime=rt)
    assert fake.calls == [] and box.tools == [] and "kerbrute" not in installed


def test_the_index_and_package_must_agree_on_what_is_required(paths, box, tmp_path):
    rt, _c, installed = rt_install(paths, tmp_path)
    zip_path, entry = runtime_tool(tmp_path)
    entry.requires = []
    fake = FakeRun()
    with pytest.raises(ToolError, match="requires python-3.13; the index lists nothing"):
        do_install(paths, box, entry, zip_path, tmp_path, installed=installed, run=fake, runtime=rt)
    assert fake.calls == [] and box.tools == []


def test_a_schema_1_python_tool_still_uses_kalis_python(paths, box, tmp_path):
    zip_path, entry = python_zip(tmp_path)
    fake = FakeRun()
    item, _c, _i = do_install(paths, box, entry, zip_path, tmp_path, run=fake)
    assert [call[:3] for call in fake.calls[:2]] == [["python3", "-I", "-c"], ["python3", "-I", "-m"]]
    assert item.requires == [] and box.tools[0].runtime is None
    assert "requires" not in paths.tools_state.read_text(encoding="utf-8")


KALI_PYTHON = (
    ". kerbrute 1.0.3-1 runs on Kali's own python3: apt install python3 python3-venv, "
    "or install a build that requires a runtime"
)


class NoPython(FakeRun):
    """Kali's python3 cannot be found, cannot run, or reports nothing."""

    def __init__(self, how):
        super().__init__(version="")
        self.how = how

    def __call__(self, argv, **kwargs):
        if argv[1:3] == ["-I", "-c"] and self.how == "missing":
            self.calls.append(list(argv))
            raise FileNotFoundError("python3")
        if argv[1:3] == ["-I", "-c"] and self.how == "exits":
            self.calls.append(list(argv))
            return SimpleNamespace(returncode=127, stdout="", stderr="")
        return super().__call__(argv, **kwargs)


@pytest.mark.parametrize(
    "how,said",
    [
        ("missing", "python3 was not found (python3)"),
        ("exits", "python3 was not found or did not run"),
        ("silent", "python3 could not report its version"),
    ],
)
def test_a_schema_1_tool_says_what_to_do_when_kalis_python_is_not_usable(
    paths, box, tmp_path, how, said
):
    zip_path, entry = python_zip(tmp_path)
    with pytest.raises(ToolError) as caught:
        do_install(paths, box, entry, zip_path, tmp_path, run=NoPython(how))
    assert str(caught.value) == said + KALI_PYTHON
    assert_nothing_left(paths)


def test_a_schema_1_tool_says_what_to_do_when_the_environment_cannot_be_made(paths, box, tmp_path):
    zip_path, entry = python_zip(tmp_path)
    with pytest.raises(ToolError) as caught:
        do_install(paths, box, entry, zip_path, tmp_path, run=FakeRun(fail_at=1))
    message = str(caught.value)
    assert message.startswith("creating the virtual environment failed (exit 1):")
    assert message.endswith("boom" + KALI_PYTHON)
    assert_nothing_left(paths)


def test_a_schema_1_tool_does_not_get_the_sentence_for_a_pip_failure(paths, box, tmp_path):
    zip_path, entry = python_zip(tmp_path)
    with pytest.raises(ToolError) as caught:
        do_install(paths, box, entry, zip_path, tmp_path, run=FakeRun(fail_at=2))
    assert "python3" not in str(caught.value) and "boom" in str(caught.value)


@pytest.mark.parametrize("failure", ["environment", "interpreter cannot run"])
def test_a_tool_on_a_runtime_never_gets_the_sentence(paths, box, tmp_path, failure):
    rt, _c, installed = rt_install(paths, tmp_path)
    zip_path, entry = runtime_tool(tmp_path)

    class Broken(FakeRun):
        def __call__(self, argv, **kwargs):
            super().__call__(argv, **kwargs)
            if failure == "interpreter cannot run":
                raise FileNotFoundError(argv[0])
            return SimpleNamespace(returncode=1, stdout="", stderr="no venv\n")

    with pytest.raises(ToolError) as caught:
        do_install(
            paths, box, entry, zip_path, tmp_path, installed=installed, run=Broken(), runtime=rt
        )
    assert "creating the virtual environment" in str(caught.value)
    assert "runs on Kali" not in str(caught.value) and "apt install" not in str(caught.value)


def test_install_refuses_a_runtime(paths, box, tmp_path):
    zip_path, entry = toolkit.make_runtime(tmp_path / "rtzips")
    with pytest.raises(ToolError, match="python-3.13 is a runtime; it is installed with the tools"):
        do_install(paths, box, entry, zip_path, tmp_path)
    assert snapshot(paths) == [] and box.tools == []


TOOL_FAULTS = ["the environment", "pip", "a command name"]


def failing_tool_install(paths, box, other, tmp_path, fault, installed, rt):
    zip_path, entry = runtime_tool(tmp_path)
    run = FakeRun()
    if fault == "the environment":
        run = FakeRun(fail_at=0)
    elif fault == "pip":
        run = FakeRun(fail_at=1)
    else:
        taker_zip, taker = build(
            tmp_path / "taker", name="taker",
            command=[{"name": "kerbrute", "type": "binary", "path": "files/kerbrute"}],
        )  # fmt: skip
        do_install(paths, other, taker, taker_zip, tmp_path, installed=installed)
    with pytest.raises(ToolError):
        do_install(paths, box, entry, zip_path, tmp_path, installed=installed, run=run, runtime=rt)


@pytest.mark.parametrize("fault", TOOL_FAULTS)
def test_a_failed_tool_and_the_runtime_it_brought_leave_nothing(paths, box, other, tmp_path, fault):
    # the caller installed the runtime for this tool, so it takes the runtime off again
    installed = {}
    rt, _c, _i = rt_install(paths, tmp_path, installed=installed)
    failing_tool_install(paths, box, other, tmp_path, fault, installed, rt)
    forget_runtime(paths, installed, rt.name)
    assert not (paths.tools / "kerbrute").exists()
    assert not (paths.tools / "python-3.13").exists()
    assert "kerbrute" not in installed and "python-3.13" not in installed
    assert not {"kerbrute", "python-3.13"} & set(load_installed(paths))
    assert box.tools == [] and load_box(box.path).tools == []


@pytest.mark.parametrize("fault", TOOL_FAULTS)
def test_a_failed_tool_leaves_a_runtime_that_was_already_there(paths, box, other, tmp_path, fault):
    installed = {}
    rt_install(paths, tmp_path, installed=installed)
    before = installed["python-3.13"]
    zip_path, entry = toolkit.make_runtime(tmp_path / "again")
    rt, _c, _i = rt_install(paths, tmp_path, zip_path, entry, installed=installed)
    assert rt is before  # so the caller can tell this command did not bring it
    failing_tool_install(paths, box, other, tmp_path, fault, installed, rt)
    assert not (paths.tools / "kerbrute").exists()
    assert Path(rt.python).is_file()
    assert load_installed(paths)["python-3.13"] == rt
    assert "kerbrute" not in load_installed(paths)
    assert box.tools == []


@posix_only
def test_real_install_of_a_tool_on_the_stand_in_runtime(paths, box, tmp_path):
    (paths.run / "tools").mkdir(parents=True)
    rt, _c, installed = rt_install(paths, tmp_path)
    ran = subprocess.run([rt.python, "-c", "print('ok')"], capture_output=True, text=True)
    assert ran.stdout == "ok\n", f"the stand-in runtime did not run: {ran.returncode} {ran.stderr}"
    zip_path, entry = runtime_tool(tmp_path)
    do_install(
        paths, box, entry, zip_path, tmp_path,
        installed=installed, runtime=rt, run=subprocess.run,
    )  # fmt: skip
    venv = paths.tools / "kerbrute" / "1.0.3-1" / "venv"
    assert (venv / "pyvenv.cfg").is_file(), f"no environment was made at {venv}"
    launcher = paths.bin / "kerbrute"
    result = read_launcher_output(launcher)
    assert result.returncode == 0, (
        f"{launcher} exited {result.returncode}\nstdout: {result.stdout}\nstderr: {result.stderr}"
    )
    assert result.stdout.strip() == "kerbrute-py 1.0", f"the tool printed {result.stdout!r}"
