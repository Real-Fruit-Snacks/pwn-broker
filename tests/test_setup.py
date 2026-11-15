import importlib.resources
import os
import sys
from pathlib import Path

import pytest

from pwn_broker.setup import (
    PATH_MARK,
    ensure_path_line,
    install_data,
    load_template,
    path_line,
    write_launcher,
)


def packaged(name):
    return importlib.resources.files("pwn_broker.data").joinpath(name).read_text(encoding="utf-8")


def test_install_data_creates_layout(paths):
    install_data(paths)
    assert paths.run.is_dir()
    assert paths.bin.is_dir()
    assert (paths.templates / "notes.md").is_file()
    assert (paths.vim_dir / "vimrc").is_file()
    assert (paths.vim_dir / "nightshift.vim").is_file()


def test_install_data_keeps_an_edited_template(paths):
    install_data(paths)
    (paths.templates / "notes.md").write_text("mine\n", encoding="utf-8")
    (paths.vim_dir / "vimrc").write_text("stale\n", encoding="utf-8")
    install_data(paths)
    assert (paths.templates / "notes.md").read_text(encoding="utf-8") == "mine\n"
    assert (paths.vim_dir / "vimrc").read_text(encoding="utf-8") == packaged("vimrc")


def test_install_data_on_partly_installed_folder(paths):
    paths.vim_dir.mkdir(parents=True)
    (paths.vim_dir / "nightshift.vim").write_text("old\n", encoding="utf-8")
    install_data(paths)
    assert (paths.vim_dir / "nightshift.vim").read_text(encoding="utf-8") == packaged("nightshift.vim")
    assert (paths.templates / "notes.md").is_file()


def test_launcher_content(paths):
    p = write_launcher(paths, Path("/opt/pwn-broker/app/bin/python"))
    assert p == paths.bin / "pwn-broker"
    assert p.read_bytes() == b'#!/bin/sh\nexec "/opt/pwn-broker/app/bin/python" -m pwn_broker "$@"\n'


@pytest.mark.skipif(sys.platform == "win32", reason="no file modes on Windows")
def test_launcher_is_executable(paths):
    p = write_launcher(paths, Path("/x/python"))
    assert os.stat(p).st_mode & 0o777 == 0o755


def test_path_line():
    assert path_line(Path("/opt/pwn-broker/bin")) == (
        'export PATH="/opt/pwn-broker/bin:$PATH"  # pwn-broker'
    )


def test_ensure_path_line_is_idempotent(tmp_path):
    rc = tmp_path / ".zshrc"
    rc.write_bytes(b"alias a=b\n")
    opt_bin = Path("/opt/pwn-broker/bin")
    assert ensure_path_line(rc, opt_bin) is True
    after = rc.read_bytes()
    assert after == b"alias a=b\n" + path_line(opt_bin).encode() + b"\n"
    assert ensure_path_line(rc, opt_bin) is False
    assert rc.read_bytes() == after


def test_ensure_path_line_adds_newline_when_missing(tmp_path):
    rc = tmp_path / ".zshrc"
    rc.write_bytes(b"alias a=b\r\nlast")
    assert ensure_path_line(rc, Path("/o/bin")) is True
    assert rc.read_bytes() == b"alias a=b\r\nlast\n" + path_line(Path("/o/bin")).encode() + b"\n"


def test_ensure_path_line_skips_any_line_with_the_mark(tmp_path):
    rc = tmp_path / ".zshrc"
    rc.write_text(f"something {PATH_MARK} here\n", encoding="utf-8")
    assert ensure_path_line(rc, Path("/o/bin")) is False
    assert rc.read_text(encoding="utf-8") == f"something {PATH_MARK} here\n"


def test_ensure_path_line_creates_missing_rc(tmp_path):
    rc = tmp_path / ".zshrc"
    assert ensure_path_line(rc, Path("/o/bin")) is True
    assert rc.read_bytes() == path_line(Path("/o/bin")).encode() + b"\n"


def test_load_template_falls_back_to_packaged(paths):
    assert load_template(paths) == packaged("notes.md")
    install_data(paths)
    (paths.templates / "notes.md").write_text("custom\n", encoding="utf-8")
    assert load_template(paths) == "custom\n"


def test_vimrc_has_autocmds_and_lf_only():
    raw = importlib.resources.files("pwn_broker.data").joinpath("vimrc").read_bytes()
    assert b"\r" not in raw
    assert raw.endswith(b"augroup END\n")
    text = raw.decode("utf-8")
    assert "autocmd TextChanged,TextChangedI * call s:Mark(1)" in text
    assert "autocmd BufWritePost * call s:Mark(0)" in text
    assert "autocmd VimLeave * silent! call delete(s:state)" in text


def test_nightshift_palette():
    raw = importlib.resources.files("pwn_broker.data").joinpath("nightshift.vim").read_bytes()
    assert b"\r" not in raw
    text = raw.decode("utf-8")
    assert "3DDC97" not in text.upper()
    assert "let g:colors_name = 'nightshift'" in text
    assert text.startswith("set background=dark\nhighlight clear\n")
    assert "#FF6A3D" in text.upper()
