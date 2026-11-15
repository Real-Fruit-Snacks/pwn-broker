import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from pwn_broker.setup import path_line

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "install.sh"
needs_sh = pytest.mark.skipif(shutil.which("sh") is None, reason="needs sh")


@pytest.mark.skipif(shutil.which("sh") is None or sys.platform == "win32", reason="needs a POSIX shell")
def test_install_from_local_source(tmp_path):
    env = {**os.environ, "PWN_BROKER_OPT": str(tmp_path / "opt"), "HOME": str(tmp_path / "home")}
    (tmp_path / "home").mkdir()
    subprocess.run(["sh", "install.sh", "--from", ".", "--no-asciinema"], check=True, env=env, cwd=ROOT)
    assert (tmp_path / "opt/bin/pwn-broker").exists() and (tmp_path / "opt/vim/vimrc").exists()
    assert "# pwn-broker" in (tmp_path / "home/.zshrc").read_text()
    subprocess.run(["sh", "install.sh", "--from", ".", "--no-asciinema"], check=True, env=env, cwd=ROOT)
    assert (tmp_path / "home/.zshrc").read_text().count("# pwn-broker") == 1


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


@needs_sh
def test_install_sh_help_and_unknown_option():
    helped = subprocess.run(["sh", str(SCRIPT), "--help"], capture_output=True, text=True)
    assert helped.returncode == 0 and "--from" in helped.stdout
    bad = subprocess.run(["sh", str(SCRIPT), "--nope"], capture_output=True, text=True)
    assert bad.returncode == 2 and "usage" in bad.stderr
    missing = subprocess.run(["sh", str(SCRIPT), "--from"], capture_output=True, text=True)
    assert missing.returncode == 2


SHELLS = [s for s in ("sh", "dash") if shutil.which(s)]
shells = pytest.mark.parametrize("shell", SHELLS)


def run_script(shell, *args):
    return subprocess.run([shell, str(SCRIPT), *args], capture_output=True, text=True)


@shells
def test_install_sh_help_lists_no_asciinema(shell):
    helped = run_script(shell, "--help")
    assert helped.returncode == 0
    assert "--no-asciinema   do not download asciinema; record and replay will not work" in helped.stdout
    assert "[--no-asciinema]" in helped.stdout


def test_install_sh_skips_asciinema_through_the_setup_variable():
    text = SCRIPT.read_text(encoding="utf-8")
    assert "NO_ASCIINEMA=1" in text
    assert "PWN_BROKER_SKIP_ASCIINEMA=1" in text
    # exported before the setup step reads it
    assert text.index("export PWN_BROKER_SKIP_ASCIINEMA") < text.index("-m pwn_broker setup")


@shells
def test_install_sh_syntax_in_each_shell(shell):
    assert subprocess.run([shell, "-n", str(SCRIPT)]).returncode == 0


@shells
def test_install_sh_option_errors(shell):
    assert run_script(shell, "--help").returncode == 0
    for args in (["--nope"], ["--config"], ["--from"], ["--from", ""], ["--config", ""]):
        result = run_script(shell, *args)
        assert result.returncode == 2 and "usage" in result.stderr


@shells
def test_install_sh_missing_from_or_config_fails_before_installing(shell, tmp_path):
    gone = str(tmp_path / "gone")
    for args in (["--from", gone], ["--config", gone]):
        result = run_script(shell, *args)
        assert result.returncode == 1
        assert result.stderr.strip() == f"fail  {gone} does not exist"


def test_install_sh_removes_the_app_folder_only_when_it_is_ours():
    lines = SCRIPT.read_text(encoding="utf-8").splitlines()
    removals = [i for i, row in enumerate(lines) if 'rm -rf "$OPT/app"' in row]
    assert removals
    for i in removals:
        # the nearest enclosing test decides whether the folder may go
        guard = next(row for row in reversed(lines[: i + 1]) if re.search(r"\b(el)?if\b", row))
        assert "pyvenv.cfg" in guard or "APP_CREATED" in guard, lines[i]


FAKE_PYTHON = """#!/bin/sh
# stands in for python3: every check passes, creating a venv leaves a partial folder and fails
if [ "$1 $2" = "-m venv" ] && [ "$3" != "--help" ]; then
    mkdir -p "$3/bin"
    exit 1
fi
exit 0
"""


def run_with_fake_python(shell, tmp_path, opt):
    fake = tmp_path / "fakebin"
    fake.mkdir()
    (fake / "python3").write_bytes(FAKE_PYTHON.encode())
    (fake / "python3").chmod(0o755)
    env = {**os.environ, "PWN_BROKER_OPT": opt.as_posix(), "PATH": f"{fake}{os.pathsep}{os.environ['PATH']}"}
    return subprocess.run(
        [shell, str(SCRIPT), "--from", str(ROOT), "--no-path", "--no-asciinema"], capture_output=True, text=True, env=env
    )


@shells
def test_install_sh_refuses_an_app_folder_that_is_not_ours(shell, tmp_path):
    opt = tmp_path / "opt"
    (opt / "app").mkdir(parents=True)
    (opt / "app" / "keep.txt").write_text("someone else's")
    result = run_with_fake_python(shell, tmp_path, opt)
    assert result.returncode == 1, result.stderr
    assert result.stderr.strip().splitlines()[-1] == (
        f"fail  {opt.as_posix()}/app exists and is not a pwn-broker environment. move it or choose another folder"
    )
    assert (opt / "app" / "keep.txt").read_text() == "someone else's"


@shells
def test_install_sh_replaces_a_broken_environment_of_its_own(shell, tmp_path):
    opt = tmp_path / "opt"
    (opt / "app").mkdir(parents=True)
    (opt / "app" / "pyvenv.cfg").write_text("home = /usr/bin\n")
    (opt / "app" / "old.txt").write_text("stale")
    result = run_with_fake_python(shell, tmp_path, opt)
    assert result.returncode == 1
    assert "cannot create the virtual environment" in result.stderr
    assert not (opt / "app").exists()


@shells
def test_install_sh_cleans_up_a_folder_it_created(shell, tmp_path):
    opt = tmp_path / "opt"
    opt.mkdir()
    result = run_with_fake_python(shell, tmp_path, opt)
    assert result.returncode == 1
    assert "cannot create the virtual environment" in result.stderr
    assert not (opt / "app").exists()


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
