import hashlib
import io
import os
import re
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

import pytest

from pwn_broker.setup import path_line

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "install.sh"
needs_sh = pytest.mark.skipif(shutil.which("sh") is None, reason="needs sh")
not_on_windows = pytest.mark.skipif(sys.platform == "win32", reason="file modes need a POSIX file system")

SHELLS = [s for s in ("sh", "dash") if shutil.which(s)]
shells = pytest.mark.parametrize("shell", SHELLS)

VERSION = "0.4.0"
RELEASE_NAME = f"pwn-broker-{VERSION}-linux-x86_64.tar.gz"
NOT_A_RELEASE_FILE_HINT = (
    "fail  --from takes a release file, pwn-broker-<version>-linux-x86_64.tar.gz. "
    "build one from a checkout with: python3 release/build.py"
)


def sh_path(path):
    """A path as the shell writes it: Git Bash on Windows spells C:\\x as /c/x."""
    if sys.platform != "win32":
        return str(path)
    drive, rest = os.path.splitdrive(str(path))
    return f"/{drive.rstrip(':').lower()}{rest.replace(os.sep, '/')}"


def run_script(shell, *args):
    return subprocess.run([shell, str(SCRIPT), *args], capture_output=True, text=True)


@needs_sh
def test_install_sh_parses():
    assert subprocess.run(["sh", "-n", str(SCRIPT)]).returncode == 0


def test_install_sh_is_posix_script_with_unix_endings():
    raw = SCRIPT.read_bytes()
    assert b"\r" not in raw
    assert raw.startswith(b"#!/bin/sh\n")
    assert b"set -eu" in raw


def test_install_sh_path_line_matches_the_app():
    text = SCRIPT.read_text(encoding="utf-8")
    found = re.search(r"printf '(export PATH=.*# pwn-broker)\\n' \"\$OPT\"", text)
    assert found
    assert found.group(1).replace("%s", "/opt/pwn-broker") == path_line(Path("/opt/pwn-broker/bin"))


@shells
def test_install_sh_syntax_in_each_shell(shell):
    assert subprocess.run([shell, "-n", str(SCRIPT)]).returncode == 0


@shells
def test_install_sh_option_errors(shell):
    assert run_script(shell, "--help").returncode == 0
    for args in (["--nope"], ["--config"], ["--from"], ["--from", ""], ["--config", ""], ["--no-asciinema"]):
        result = run_script(shell, *args)
        assert result.returncode == 2 and "usage" in result.stderr, args


@shells
def test_install_sh_help_lists_the_four_options_and_no_other(shell):
    helped = run_script(shell, "--help")
    assert helped.returncode == 0
    lines = helped.stdout.splitlines()
    assert lines[0] == "usage: install.sh [--from <file>] [--config <path>] [--no-path] [--help]"
    assert set(re.findall(r"--[a-z][a-z-]*", helped.stdout)) == {"--from", "--config", "--no-path", "--help"}
    assert "asciinema" not in helped.stdout


@shells
def test_install_sh_missing_from_or_config_fails_before_installing(shell, tmp_path):
    gone = str(tmp_path / "gone")
    for args in (["--from", gone], ["--config", gone]):
        result = run_script(shell, *args)
        assert result.returncode == 1
        assert result.stderr.strip() == f"fail  {gone} does not exist"


def test_install_sh_runs_nothing_before_main():
    lines = SCRIPT.read_text(encoding="utf-8").splitlines()
    assert [row for row in lines if row.strip()][-1] == 'main "$@"'
    top_level = []
    in_function = False
    for row in lines[1:]:
        if in_function:
            in_function = row != "}"
        elif row.strip() and not row.startswith("#"):
            if row.endswith("() {"):
                in_function = True
            else:
                top_level.append(row)
    assert top_level == ["set -eu", 'main "$@"']


def test_install_sh_removes_only_its_own_folders():
    text = SCRIPT.read_text(encoding="utf-8")
    removed = re.findall(r"\brm -rf (.*?)(?:;|\s*\|\||\s*$)", text, flags=re.MULTILINE)
    assert removed
    for target in removed:
        assert target in ('"$OPT/python"', '"$OPT/app"', '"$WORK"'), target


def test_install_sh_unpacks_without_taking_owners_from_the_file():
    unpacks = [row for row in SCRIPT.read_text(encoding="utf-8").splitlines() if re.search(r"\btar -", row)]
    assert len(unpacks) == 2
    for row in unpacks:
        assert "tar -xzf - --no-same-owner -C " in row


def test_install_sh_exports_the_install_folder_for_setup():
    text = SCRIPT.read_text(encoding="utf-8")
    assert text.index("export PWN_BROKER_OPT") < text.index("-m pwn_broker setup")


# A stand-in for the bundled Python. Each call appends one line to $FAKE_PY_LOG: how it was
# called, PIP_CONFIG_FILE, PWN_BROKER_OPT and its arguments, separated by tabs. The step named
# by $FAKE_PY_FAIL (run, venv, pip or setup) exits with $FAKE_PY_STATUS.
FAKE_PYTHON = """#!/bin/sh
printf '%s\\t' "$0" "${PIP_CONFIG_FILE-}" "${PWN_BROKER_OPT-}" "$@" >>"$FAKE_PY_LOG"
printf '\\n' >>"$FAKE_PY_LOG"
step=""
case "$1 $2" in
    "-I -c") step=run ;;
    "-I -m")
        case "$3" in
            venv) step=venv ;;
            pip) step=pip ;;
        esac
        ;;
    "-m pwn_broker") step=setup ;;
esac
if [ "$step" = "${FAKE_PY_FAIL-}" ]; then
    exit "${FAKE_PY_STATUS:-1}"
fi
case "$step" in
    run) echo 3.13.9 ;;
    venv)
        mkdir -p "$4/bin"
        cp "$0" "$4/bin/python"
        echo "home = $(dirname "$0")" >"$4/pyvenv.cfg"
        ;;
esac
exit 0
"""

# Stands in for curl -fsSL -o <out> <url>: copies the url's last part from $FAKE_DOWNLOADS.
FAKE_CURL = """#!/bin/sh
out=""
url=""
while [ "$#" -gt 0 ]; do
    case "$1" in
        -o) out="$2"; shift 2 ;;
        -*) shift ;;
        *) url="$1"; shift ;;
    esac
done
cp "$FAKE_DOWNLOADS/${url##*/}" "$out"
"""

# The machine's python3: it must never run.
FAKE_MACHINE_PYTHON = """#!/bin/sh
echo "$*" >>"$FAKE_MACHINE_LOG"
exit 1
"""


def add_file(tar, name, data, mode=0o644):
    info = tarfile.TarInfo(name)
    info.size = len(data)
    info.mode = mode
    tar.addfile(info, io.BytesIO(data))


def add_folder(tar, name):
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE
    info.mode = 0o755
    tar.addfile(info)


def python_archive():
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as tar:
        add_folder(tar, "python")
        add_folder(tar, "python/bin")
        add_file(tar, "python/bin/python3", FAKE_PYTHON.encode(), 0o755)
        add_file(tar, "python/lib/README", b"stand-in\n")
    return buffer.getvalue()


def write_release(path, top=f"pwn-broker-{VERSION}", members=None, extra_tops=()):
    """A stand-in release file. members maps names inside the top folder to bytes (None: a folder)."""
    if members is None:
        members = {
            "python.tar.gz": python_archive(),
            "wheels": None,
            f"wheels/pwn_broker-{VERSION}-py3-none-any.whl": b"wheel\n",
            "wheels.lock": b"pwn-broker==" + VERSION.encode() + b" --hash=sha256:" + b"0" * 64 + b"\n",
            "asciinema": b"asciinema stand-in\n",
            "licences": None,
        }
    with tarfile.open(path, mode="w:gz") as tar:
        for name in (top, *extra_tops):
            add_folder(tar, name)
        for name, data in members.items():
            if data is None:
                add_folder(tar, f"{top}/{name}")
            else:
                add_file(tar, f"{top}/{name}", data, 0o755 if name == "asciinema" else 0o644)
    return path


class Rig:
    def __init__(self, shell, tmp_path):
        self.shell = shell
        self.tmp = tmp_path
        self.opt = tmp_path / "opt"
        self.home = tmp_path / "home"
        self.home.mkdir()
        self.log = tmp_path / "python.log"
        self.machine_log = tmp_path / "machine-python.log"
        self.downloads = tmp_path / "downloads"
        self.downloads.mkdir()
        self.fakebin = tmp_path / "fakebin"
        self.fakebin.mkdir()
        for name, text in (("curl", FAKE_CURL), ("python3", FAKE_MACHINE_PYTHON)):
            (self.fakebin / name).write_bytes(text.encode())
            (self.fakebin / name).chmod(0o755)
        self.release = write_release(tmp_path / RELEASE_NAME)

    def run(self, *args, cwd=None, **extra_env):
        env = {
            **os.environ,
            "PWN_BROKER_OPT": self.opt.as_posix(),
            "HOME": self.home.as_posix(),
            "PATH": f"{self.fakebin}{os.pathsep}{os.environ['PATH']}",
            "FAKE_PY_LOG": self.log.as_posix(),
            "FAKE_MACHINE_LOG": self.machine_log.as_posix(),
            "FAKE_DOWNLOADS": self.downloads.as_posix(),
            **extra_env,
        }
        return subprocess.run([self.shell, str(SCRIPT), *args], capture_output=True, text=True, env=env, cwd=cwd)

    def install(self, *args, **extra_env):
        return self.run("--from", sh_path(self.release), *args, **extra_env)

    def calls(self):
        if not self.log.exists():
            return []
        return [row.split("\t")[:-1] for row in self.log.read_text().splitlines()]

    def work_folders(self):
        return sorted(p.name for p in self.opt.glob(".install.*")) if self.opt.exists() else []


@pytest.fixture(params=SHELLS)
def rig(request, tmp_path):
    return Rig(request.param, tmp_path)


def snapshot(folder):
    """Everything under a folder: each path with its type and contents."""
    found = {}
    for path in sorted(folder.rglob("*")):
        name = path.relative_to(folder).as_posix()
        if path.is_symlink():
            found[name] = ("link", os.readlink(path))
        elif path.is_dir():
            found[name] = ("folder", None)
        else:
            found[name] = ("file", path.read_bytes())
    return found


def ok_lines(result):
    return [row for row in result.stdout.splitlines() if row.startswith("ok")]


def test_a_full_install_runs_every_step_in_order(rig):
    result = rig.install()
    assert result.returncode == 0, result.stderr
    opt = rig.opt.as_posix()
    digest = hashlib.sha256(rig.release.read_bytes()).hexdigest()
    zshrc = (rig.home / ".zshrc").as_posix()
    if sys.platform == "win32":
        # Git Bash hands the script $HOME in its own spelling
        zshrc = ok_lines(result)[6].removeprefix("ok    PATH line added to ")
        assert zshrc.endswith("/home/.zshrc")
    assert ok_lines(result) == [
        f"ok    install folder {opt}",
        f"ok    release file {RELEASE_NAME}, SHA-256 {digest}",
        f"ok    Python 3.13.9 in {opt}/python",
        f"ok    virtual environment created in {opt}/app",
        f"ok    pwn-broker {VERSION} installed",
        f"ok    launcher and data written in {opt}",
        f"ok    PATH line added to {zshrc}",
        "ok    open a new terminal, then run: pwn-broker",
    ]
    assert result.stderr == ""

    calls = rig.calls()
    assert [c[3:] for c in calls[:2]] == [["-I", "-c", "import sys"], ["-I", "-c", calls[1][5]]]
    work = calls[0][0].split("/py/python/bin/python3")[0]
    assert work.startswith(f"{opt}/.install.")
    assert calls[0][0] == calls[1][0] == f"{work}/py/python/bin/python3"
    top = f"{work}/release/pwn-broker-{VERSION}"
    assert calls[2] == [f"{opt}/python/bin/python3", "", opt, "-I", "-m", "venv", f"{opt}/app"]
    assert calls[3] == [
        f"{opt}/app/bin/python",
        "/dev/null",
        opt,
        "-I", "-m", "pip", "--isolated", "install", "--quiet", "--no-index",
        "--find-links", f"{top}/wheels",
        "--only-binary", ":all:",
        "--require-hashes", "-r", f"{top}/wheels.lock",
    ]  # fmt: skip
    assert calls[4] == [f"{opt}/app/bin/python", "", opt, "-m", "pwn_broker", "setup"]
    assert len(calls) == 5

    assert (rig.opt / "python/bin/python3").read_bytes() == FAKE_PYTHON.encode()
    assert (rig.opt / "python/lib/README").exists()
    assert (rig.opt / "app/pyvenv.cfg").exists()
    assert (rig.opt / "app/bin/asciinema").read_bytes() == b"asciinema stand-in\n"
    assert rig.work_folders() == []
    assert not rig.machine_log.exists()

    again = rig.install()
    assert again.returncode == 0, again.stderr
    assert f"ok    PATH line already in {zshrc}" in again.stdout
    assert (rig.home / ".zshrc").read_text().count("# pwn-broker") == 1
    assert rig.work_folders() == []


@not_on_windows
def test_asciinema_is_installed_with_mode_755(rig):
    assert rig.install("--no-path").returncode == 0
    assert (rig.opt / "app/bin/asciinema").stat().st_mode & 0o777 == 0o755


def test_from_prints_the_real_sha256(rig):
    other = rig.tmp / "elsewhere"
    other.mkdir()
    release = write_release(other / "pwn-broker-1.2.3+local-linux-x86_64.tar.gz", top="pwn-broker-1.2.3+local")
    result = rig.run("--from", sh_path(release), "--no-path")
    assert result.returncode == 0, result.stderr
    digest = hashlib.sha256(release.read_bytes()).hexdigest()
    assert f"ok    release file pwn-broker-1.2.3+local-linux-x86_64.tar.gz, SHA-256 {digest}\n" in result.stdout
    assert "ok    pwn-broker 1.2.3+local installed" in result.stdout


def test_a_relative_from_is_read_from_the_current_folder(rig):
    result = rig.run("--from", RELEASE_NAME, "--no-path", cwd=rig.tmp)
    assert result.returncode == 0, result.stderr
    assert f"ok    pwn-broker {VERSION} installed" in result.stdout


def test_an_upgrade_replaces_python_and_app_and_nothing_else(rig):
    assert rig.install("--no-path").returncode == 0
    (rig.opt / "python/old-python.txt").write_text("old")
    (rig.opt / "app/old-app.txt").write_text("old")
    (rig.opt / "config.toml").write_text("theme = 'dark'\n")
    (rig.opt / "tools").mkdir()
    (rig.opt / "tools/installed.toml").write_text("[tools]\n")
    (rig.opt / "run").mkdir()
    (rig.opt / "run/box").write_text("forest\n")
    box = rig.home / "active/2026-11-14_htb_forest"
    box.mkdir(parents=True)
    (box / "notes.md").write_text("# forest\n")

    result = rig.install("--no-path")
    assert result.returncode == 0, result.stderr
    assert not (rig.opt / "python/old-python.txt").exists()
    assert not (rig.opt / "app/old-app.txt").exists()
    assert (rig.opt / "python/bin/python3").exists() and (rig.opt / "app/pyvenv.cfg").exists()
    assert (rig.opt / "config.toml").read_text() == "theme = 'dark'\n"
    assert (rig.opt / "tools/installed.toml").read_text() == "[tools]\n"
    assert (rig.opt / "run/box").read_text() == "forest\n"
    assert (box / "notes.md").read_text() == "# forest\n"
    assert rig.work_folders() == []


def test_config_is_copied_after_setup(rig):
    settings = rig.tmp / "settings.toml"
    settings.write_text("x = 1\n")
    result = rig.install("--no-path", "--config", str(settings))
    assert result.returncode == 0, result.stderr
    assert ok_lines(result)[-2] == f"ok    settings copied to {rig.opt.as_posix()}/config.toml"
    assert (rig.opt / "config.toml").read_text() == "x = 1\n"


def previous_install(rig):
    """An install folder as a user has it: an app of its own and data that must survive."""
    (rig.opt / "python/bin").mkdir(parents=True)
    (rig.opt / "python/bin/python3").write_text("old python\n")
    (rig.opt / "app").mkdir()
    (rig.opt / "app/pyvenv.cfg").write_text("home = old\n")
    (rig.opt / "config.toml").write_text("theme = 'dark'\n")
    (rig.opt / "tools").mkdir()
    (rig.opt / "tools/installed.toml").write_text("[tools]\n")


def broken_releases(tmp):
    good = write_release(tmp / "good.tar.gz").read_bytes()
    truncated = tmp / RELEASE_NAME
    truncated.write_bytes(good[: len(good) // 2])
    wrong_layout = write_release(tmp / "layout" / RELEASE_NAME, members={"python.tar.gz": python_archive()})
    two_tops = write_release(tmp / "two" / RELEASE_NAME, extra_tops=("pwn-broker-0.5.0",))
    wrong_name = write_release(tmp / "name" / RELEASE_NAME, top="something-0.4.0")
    bad_version = write_release(tmp / "version" / RELEASE_NAME, top="pwn-broker-0.4;0")
    plain = tmp / "plain" / RELEASE_NAME
    plain.write_bytes(b"not an archive\n")
    return {
        "truncated": truncated,
        "wrong layout": wrong_layout,
        "two top folders": two_tops,
        "wrong top folder": wrong_name,
        "unsafe version": bad_version,
        "not an archive": plain,
    }


def test_a_file_that_is_not_a_release_changes_nothing(rig):
    for sub in ("layout", "two", "name", "version", "plain"):
        (rig.tmp / sub).mkdir()
    previous_install(rig)
    before = snapshot(rig.opt)
    for case, release in broken_releases(rig.tmp).items():
        result = rig.run("--from", sh_path(release), "--no-path")
        assert result.returncode == 1, case
        assert result.stderr.splitlines() == [f"fail  {release.name} is not a pwn-broker release file"], case
        assert snapshot(rig.opt) == before, case
    assert rig.calls() == []


def test_a_wheel_or_a_folder_is_refused_before_anything_happens(rig):
    wheel = rig.tmp / f"pwn_broker-{VERSION}-py3-none-any.whl"
    wheel.write_bytes(b"PK\x03\x04")
    for given in (wheel, rig.tmp, ROOT):
        result = rig.run("--from", sh_path(given), "--no-path")
        assert result.returncode == 1, given
        assert result.stderr.splitlines() == [NOT_A_RELEASE_FILE_HINT], given
    assert not rig.opt.exists()


def test_a_python_folder_that_is_not_ours_is_refused(rig):
    (rig.opt / "python").mkdir(parents=True)
    (rig.opt / "python/keep.txt").write_text("someone else's")
    before = snapshot(rig.opt)
    result = rig.install("--no-path")
    assert result.returncode == 1
    assert result.stderr.splitlines() == [
        f"fail  {rig.opt.as_posix()}/python exists and is not a pwn-broker Python. move it or choose another folder"
    ]
    assert snapshot(rig.opt) == before


def test_an_app_folder_that_is_not_ours_is_refused_and_python_is_kept(rig):
    previous_install(rig)
    (rig.opt / "app/pyvenv.cfg").unlink()
    (rig.opt / "app/keep.txt").write_text("someone else's")
    before = snapshot(rig.opt)
    result = rig.install("--no-path")
    assert result.returncode == 1
    assert result.stderr.splitlines() == [
        f"fail  {rig.opt.as_posix()}/app exists and is not a pwn-broker environment. move it or choose another folder"
    ]
    assert snapshot(rig.opt) == before


def test_a_python_that_does_not_run_changes_nothing(rig):
    previous_install(rig)
    before = snapshot(rig.opt)
    result = rig.install("--no-path", FAKE_PY_FAIL="run")
    assert result.returncode == 1
    assert result.stderr.splitlines() == [
        "fail  the Python in this release does not run on this machine. pwn-broker needs x86_64 Linux with glibc"
    ]
    assert snapshot(rig.opt) == before


def test_another_architecture_is_refused(rig):
    (rig.fakebin / "uname").write_bytes(b"#!/bin/sh\necho aarch64\n")
    (rig.fakebin / "uname").chmod(0o755)
    result = rig.install("--no-path")
    assert result.returncode == 1
    assert result.stderr.splitlines() == ["fail  pwn-broker is built for x86_64 Linux. this machine is aarch64"]
    assert not rig.opt.exists()


@pytest.mark.parametrize(
    ("step", "line"),
    [
        ("venv", "fail  cannot create the virtual environment in {opt}/app. run the installer again"),
        ("pip", f"fail  pip could not install the wheels in {RELEASE_NAME}. run the installer again"),
        ("setup", "fail  pwn-broker setup failed. run the installer again"),
    ],
)
def test_a_failing_step_says_to_run_the_installer_again(rig, step, line):
    previous_install(rig)
    result = rig.install("--no-path", FAKE_PY_FAIL=step)
    assert result.returncode == 1
    assert result.stderr.splitlines() == [line.format(opt=rig.opt.as_posix())]
    assert rig.work_folders() == []
    assert (rig.opt / "config.toml").read_text() == "theme = 'dark'\n"
    # once the step passes, the same folder installs
    assert rig.install("--no-path").returncode == 0


def publish(rig, sums):
    shutil.copy(rig.release, rig.downloads / RELEASE_NAME)
    (rig.downloads / "SHA256SUMS.txt").write_text(sums)


def test_a_download_is_checked_against_sha256sums(rig):
    digest = hashlib.sha256(rig.release.read_bytes()).hexdigest()
    publish(rig, f"{digest}  {RELEASE_NAME}\n")
    result = rig.run("--no-path")
    assert result.returncode == 0, result.stderr
    assert ok_lines(result)[1] == f"ok    checksum verified for {RELEASE_NAME}"
    assert f"ok    pwn-broker {VERSION} installed" in result.stdout
    assert rig.work_folders() == []


def test_a_download_that_does_not_match_changes_nothing(rig):
    previous_install(rig)
    before = snapshot(rig.opt)
    publish(rig, f"{'0' * 64}  {RELEASE_NAME}\n")
    result = rig.run("--no-path")
    assert result.returncode == 1
    assert result.stderr.splitlines() == [
        f"fail  checksum of {RELEASE_NAME} does not match SHA256SUMS.txt. nothing was installed"
    ]
    assert snapshot(rig.opt) == before
    assert rig.calls() == []


@pytest.mark.parametrize(
    ("sums", "line"),
    [
        ("", "fail  SHA256SUMS.txt lists no release file"),
        (
            f"{'0' * 64}  {RELEASE_NAME}\n{'1' * 64}  pwn-broker-0.5.0-linux-x86_64.tar.gz\n",
            "fail  SHA256SUMS.txt lists more than one release file",
        ),
        (
            f"{'0' * 64}  ../pwn-broker-0.4.0-linux-x86_64.tar.gz\n",
            "fail  SHA256SUMS.txt names an unsafe file: ../pwn-broker-0.4.0-linux-x86_64.tar.gz",
        ),
    ],
)
def test_sha256sums_must_name_one_safe_release_file(rig, sums, line):
    publish(rig, sums)
    result = rig.run("--no-path")
    assert result.returncode == 1
    assert result.stderr.splitlines() == [line]
    assert rig.work_folders() == []
