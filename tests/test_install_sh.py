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
    subprocess.run(["sh", "install.sh", "--from", "."], check=True, env=env, cwd=ROOT)
    assert (tmp_path / "opt/bin/pwn-broker").exists() and (tmp_path / "opt/vim/vimrc").exists()
    assert "# pwn-broker" in (tmp_path / "home/.zshrc").read_text()
    subprocess.run(["sh", "install.sh", "--from", "."], check=True, env=env, cwd=ROOT)
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
