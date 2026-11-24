import importlib.resources
import os
import shutil
import subprocess
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


def _vim_files():
    root = importlib.resources.files("pwn_broker.data")
    found = {}

    def walk(folder, prefix):
        for entry in folder.iterdir():
            if entry.is_dir():
                if entry.name != "__pycache__":
                    walk(entry, prefix + entry.name + "/")
            elif entry.name not in ("__init__.py", "notes.md"):
                found[prefix + entry.name] = entry.read_bytes()

    walk(root, "")
    return found


def test_install_data_copies_every_vim_file_and_can_run_again(paths):
    files = _vim_files()
    assert {"vimrc", "nightshift.vim", "syntax/pwnnote.vim"} <= set(files)
    for _ in range(2):
        install_data(paths)
        for name, raw in files.items():
            assert (paths.vim_dir / name).read_bytes() == raw, name
    assert not (paths.vim_dir / "notes.md").exists()
    assert not (paths.vim_dir / "__init__.py").exists()


def test_vim_files_are_utf8_with_lf():
    for name, raw in _vim_files().items():
        assert b"\r" not in raw, name
        assert raw.endswith(b"\n") and not raw.endswith(b"\n\n"), name
        raw.decode("utf-8")


# the default template shipped before the note had a box; an install that still has it unedited
# gets the new one
OLD_DEFAULT = (
    "# $name\nplatform     $platform\ndate         $date\nos           $os\ndifficulty   $difficulty\n\n"
    "## targets\n<!-- pwn-broker:targets -->\n$targets\n<!-- /pwn-broker:targets -->\n"
    "<!-- pwn-broker:section -->\n## $target\n### enumeration\n### foothold\n### privilege escalation\n"
)


def test_install_data_replaces_the_previous_default_template(paths):
    paths.templates.mkdir(parents=True)
    template = paths.templates / "notes.md"
    template.write_bytes(OLD_DEFAULT.encode("utf-8"))
    install_data(paths)
    assert template.read_text(encoding="utf-8") == packaged("notes.md")
    edited = OLD_DEFAULT.encode("utf-8") + b"## mine\n"
    template.write_bytes(edited)
    install_data(paths)
    assert template.read_bytes() == edited


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
    assert p.read_bytes() == b'#!/bin/sh\nexec "/opt/pwn-broker/app/bin/python" -I -m pwn_broker "$@"\n'


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


def test_ensure_path_line_keeps_an_rc_that_is_not_utf8(tmp_path):
    rc = tmp_path / ".zshrc"
    rc.write_bytes(b"alias caf\xe9=ls\n")
    assert ensure_path_line(rc, Path("/o/bin")) is True
    assert rc.read_bytes() == b"alias caf\xe9=ls\n" + path_line(Path("/o/bin")).encode() + b"\n"
    assert ensure_path_line(rc, Path("/o/bin")) is False


@pytest.mark.skipif(sys.platform == "win32", reason="symlinks need privileges on Windows")
def test_ensure_path_line_writes_through_a_symlinked_rc(tmp_path):
    dotfiles = tmp_path / "dotfiles"
    dotfiles.mkdir()
    real = dotfiles / "zshrc"
    real.write_text("alias a=b\n", encoding="utf-8")
    rc = tmp_path / ".zshrc"
    rc.symlink_to(real)
    assert ensure_path_line(rc, Path("/o/bin")) is True
    assert rc.is_symlink() and rc.resolve() == real.resolve()
    assert real.read_text(encoding="utf-8") == "alias a=b\n" + path_line(Path("/o/bin")) + "\n"


def test_load_template_falls_back_to_packaged(paths):
    assert load_template(paths) == packaged("notes.md")
    install_data(paths)
    (paths.templates / "notes.md").write_text("custom\n", encoding="utf-8")
    assert load_template(paths) == "custom\n"


def test_vimrc_has_autocmds_and_lf_only():
    raw = importlib.resources.files("pwn_broker.data").joinpath("vimrc").read_bytes()
    assert b"\r" not in raw
    assert raw.endswith(b"endif\n")
    text = raw.decode("utf-8")
    assert "autocmd TextChanged,TextChangedI notes.md call s:Mark(1)" in text
    assert "autocmd BufWritePost notes.md call s:Mark(0)" in text
    assert "fnamemodify(argc() > 0 ? argv(0) : expand('%'), ':p:h')" in text
    assert "timer_start(1000" in text
    assert "silent! call delete(s:state)" in text


def test_nightshift_palette():
    raw = importlib.resources.files("pwn_broker.data").joinpath("nightshift.vim").read_bytes()
    assert b"\r" not in raw
    text = raw.decode("utf-8")
    assert "3DDC97" not in text.upper()
    assert "let g:colors_name = 'nightshift'" in text
    assert text.startswith("set background=dark\nhighlight clear\n")
    assert "#FF9254" in text.upper()
    assert "markdown" not in text.lower()
    for colour in ("#FFC247", "#8F95A6", "#F2F4F8", "#161820", "#0D0E12", "#050507", "#FF5C6C"):
        assert colour in text.upper()


def test_vimrc_basics():
    text = packaged("vimrc")
    for line in (
        "set nomodeline", "set nobackup nowritebackup noswapfile", "set nonumber",
        'let mapleader = ","', "set foldmethod=marker",
        "set foldmarker=##########@@@@@@@@@@,@@@@@@@@@@##########", "set noautoread",
        "set updatetime=1000", "autocmd FocusLost,CursorHold,CursorHoldI * ++nested silent! update",
        "autocmd FocusGained * silent! checktime", "autocmd FileChangedShell notes.md call s:Changed()",
    ):
        assert line in [row.strip() for row in text.splitlines()], line


@pytest.mark.skipif(shutil.which("vim") is None, reason="vim not installed")
def test_vimrc_writes_state_beside_the_note_not_the_cwd(tmp_path):
    folder = tmp_path / "box"
    elsewhere = tmp_path / "cwd"
    folder.mkdir()
    elsewhere.mkdir()
    note = folder / "notes.md"
    note.write_text("hi\n", encoding="utf-8")
    state = folder / ".note-state"
    vimrc = Path(str(importlib.resources.files("pwn_broker.data").joinpath("vimrc")))
    seen = tmp_path / "seen"

    def peek(tag):
        return f"call writefile([join(readfile('{state.as_posix()}'))], '{seen.as_posix()}.{tag}')"

    # Ex mode never reaches the main loop, so TextChanged is fired by hand; the path logic is what is under test
    subprocess.run(
        [
            "vim", "-u", vimrc.as_posix(), "-N", "-es",
            "-c", "normal! ihello",
            "-c", "doautocmd TextChanged notes.md",
            "-c", peek("dirty"),
            "-c", "write",
            "-c", peek("clean"),
            "-c", "qa!",
            note.as_posix(),
        ],
        cwd=elsewhere,
        stdin=subprocess.DEVNULL,
        timeout=30,
        check=True,
    )  # fmt: skip
    assert Path(f"{seen}.dirty").read_text().strip() == "1"
    assert Path(f"{seen}.clean").read_text().strip() == "0"
    assert not (elsewhere / ".note-state").exists()


def test_install_data_creates_tool_folders_and_can_run_again(paths):
    for _ in range(2):
        install_data(paths)
        for folder in (paths.tools, paths.upload, paths.cache, paths.run_tools):
            assert folder.is_dir(), folder


def test_install_data_creates_recording_folders_and_can_run_twice(paths):
    for _ in range(2):
        install_data(paths)
        for folder in (paths.run_recordings, paths.run_vpn, paths.run_shell, paths.run_asciinema):
            assert folder.is_dir()


def test_record_launcher_content(paths):
    write_launcher(paths, Path("/opt/pwn-broker/app/bin/python"))
    assert paths.record_launcher.read_bytes() == (
        b'#!/bin/sh\nexec "/opt/pwn-broker/app/bin/python" -I -m pwn_broker.record "$@"\n'
    )


@pytest.mark.skipif(sys.platform == "win32", reason="no file modes on Windows")
def test_record_launcher_is_executable(paths):
    write_launcher(paths, Path("/x/python"))
    assert os.stat(paths.record_launcher).st_mode & 0o777 == 0o755


def test_the_working_folder_cannot_stand_in_for_a_module_the_app_imports(tmp_path):
    # a box folder holds files taken from targets; with -m, python would put it first on its path
    here = tmp_path / "box"
    here.mkdir()
    planted = 'raise RuntimeError("planted module imported")\n'
    (here / "tomllib.py").write_text(planted, encoding="utf-8")
    shown = f"pwn-broker {__import__('pwn_broker').__version__}"

    def start(*flags):
        return subprocess.run(
            [sys.executable, *flags, "-m", "pwn_broker", "--version"],
            cwd=here, capture_output=True, text=True, timeout=60,
        )  # fmt: skip

    isolated = start("-I")
    assert (isolated.returncode, isolated.stdout.strip(), isolated.stderr) == (0, shown, "")
    # without the flag the planted file is the one imported, so the flag is what protects it
    plain = start()
    assert plain.returncode != 0 and "planted module imported" in plain.stderr
