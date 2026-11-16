import hashlib
import sys
from pathlib import Path

import pytest

from pwn_broker import recorder
from pwn_broker.recorder import present
from pwn_broker.toolinstall import sh_quote

GOOD = b"pretend this is the binary"
SUM = hashlib.sha256(GOOD).hexdigest()


def test_the_pin():
    assert recorder.VERSION == "3.2.1"
    assert recorder.URL == (
        "https://github.com/asciinema/asciinema/releases/download/v3.2.1/asciinema-x86_64-unknown-linux-musl"
    )
    assert recorder.SIZE == 8130064
    assert recorder.SHA256 == "bec9781bc8f297a9d3d74ff60205599507f2abba1183578b8b2f22be4c999214"


def test_present_for_the_right_file(paths):
    paths.asciinema.parent.mkdir(parents=True)
    paths.asciinema.write_bytes(GOOD)
    assert present(paths, sha256=SUM) is True


def test_present_is_false_for_a_wrong_file(paths):
    paths.asciinema.parent.mkdir(parents=True)
    paths.asciinema.write_bytes(GOOD + b"x")
    assert present(paths, sha256=SUM) is False


def test_present_is_false_for_a_folder(paths):
    paths.asciinema.mkdir(parents=True)
    assert present(paths, sha256=SUM) is False


def test_present_is_false_for_nothing(paths):
    assert present(paths, sha256=SUM) is False


def test_present_hashes_the_file_each_time(paths):
    paths.asciinema.parent.mkdir(parents=True)
    paths.asciinema.write_bytes(GOOD)
    assert present(paths, sha256=SUM) is True
    paths.asciinema.write_bytes(b"changed")
    assert present(paths, sha256=SUM) is False


def test_nothing_downloads_asciinema_and_the_pin_is_kept_for_the_build():
    # the release carries asciinema; URL and SIZE are read by release/build.py alone
    assert not hasattr(recorder, "fetch")
    assert not hasattr(recorder, "RecorderError")
    for name in ("VERSION", "URL", "SIZE", "SHA256", "present"):
        assert hasattr(recorder, name)


# -- the window a record command starts --


def shell_text(paths, name):
    return (paths.run_shell / name).read_text(encoding="utf-8")


def test_shell_files_are_written_into_run_shell(paths):
    recorder.shell_files(paths)
    written = sorted(p.relative_to(paths.run_shell).as_posix() for p in paths.run_shell.rglob("*") if p.is_file())
    assert written == ["bashrc", "zsh/.zshenv", "zsh/.zshrc"]


def test_shell_files_are_rewritten_each_time(paths):
    recorder.shell_files(paths)
    (paths.run_shell / "bashrc").write_text("old\n", encoding="utf-8")
    recorder.shell_files(paths)
    assert "PROMPT_COMMAND" in shell_text(paths, "bashrc")


def test_the_zshenv_loads_the_users_own(paths):
    recorder.shell_files(paths)
    text = shell_text(paths, "zsh/.zshenv")
    assert "${PWN_BROKER_ZDOTDIR-}" in text
    assert '[[ -f "${ZDOTDIR:-$HOME}/.zshenv" ]] && source "${ZDOTDIR:-$HOME}/.zshenv"' in text
    # zsh then reads this folder's .zshrc, so ZDOTDIR is pointed back here last
    assert text.rstrip().endswith("ZDOTDIR=" + sh_quote(str(paths.run_shell / "zsh")))


def test_the_zshrc_restores_zdotdir_loads_the_users_own_then_adds_the_prefix(paths):
    recorder.shell_files(paths)
    text = shell_text(paths, "zsh/.zshrc")
    restore = text.index("ZDOTDIR=$PWN_BROKER_ZDOTDIR")
    assert "unset ZDOTDIR" in text
    load = text.index('source "${ZDOTDIR:-$HOME}/.zshrc"')
    hook = text.index("add-zsh-hook precmd _pwn_broker_rec_prefix")
    assert restore < load < hook
    assert 'local prefix="[rec ${PWN_BROKER_RECORDING-}] "' in text
    assert '[[ ${PROMPT-} != "$prefix"* ]]' in text
    assert 'PROMPT="$prefix${PROMPT-}"' in text


def test_the_bashrc_loads_the_system_file_and_the_users_own_then_keeps_the_prefix(paths):
    recorder.shell_files(paths)
    text = shell_text(paths, "bashrc")
    # --rcfile replaces both files bash would otherwise read
    system = text.index("[ -f /etc/bash.bashrc ] && . /etc/bash.bashrc")
    load = text.index('[ -f "$HOME/.bashrc" ] && . "$HOME/.bashrc"')
    hook = text.index("PROMPT_COMMAND=")
    assert system < load < hook
    assert 'local prefix="[rec ${PWN_BROKER_RECORDING-}] "' in text
    assert 'PS1="$prefix${PS1-}"' in text
    # the hook is added once, however often the file is read
    assert "*_pwn_broker_rec_prefix*) ;;" in text
    # a bash started inside inherits an exported PROMPT_COMMAND but not the function
    assert HOOK in text


def test_record_command_for_zsh(paths):
    command, extra = recorder.record_command(paths, "/usr/bin/zsh", environ={"ZDOTDIR": "/home/u/.config/zsh"})
    assert command == "'/usr/bin/zsh'"
    assert extra == {"ZDOTDIR": str(paths.run_shell / "zsh"), "PWN_BROKER_ZDOTDIR": "/home/u/.config/zsh"}


def test_record_command_for_zsh_without_a_zdotdir(paths):
    _command, extra = recorder.record_command(paths, "/bin/zsh", environ={})
    assert extra["PWN_BROKER_ZDOTDIR"] == ""


def test_record_command_for_bash(paths):
    command, extra = recorder.record_command(paths, "/bin/bash", environ={})
    assert command == f"'/bin/bash' --rcfile {sh_quote(str(paths.run_shell / 'bashrc'))}"
    assert extra == {}


def test_record_command_for_another_shell(paths):
    assert recorder.record_command(paths, "/usr/bin/fish", environ={}) == ("'/usr/bin/fish'", {})
    assert recorder.record_command(paths, "/opt/it's/sh", environ={}) == ("'/opt/it'\\''s/sh'", {})


def test_rec_and_play_argv(paths, tmp_path):
    cast = tmp_path / "a.cast"
    assert recorder.rec_argv(paths, cast, "forest dc01 id", "'/bin/zsh'") == [
        str(paths.asciinema), "rec", "--quiet", "--title", "forest dc01 id",
        "--command", "'/bin/zsh'", str(cast),
    ]  # fmt: skip
    assert recorder.play_argv(paths, cast) == [str(paths.asciinema), "play", "--idle-time-limit", "2", str(cast)]


def test_base_env_names_the_target_and_an_asciinema_home_of_its_own(paths):
    env = recorder.base_env(paths, {"PATH": "/usr/bin", "HOME": "/home/u"}, "dc01")
    assert env == {
        "PATH": "/usr/bin",
        "HOME": "/home/u",
        "PWN_BROKER_RECORDING": "dc01",
        "ASCIINEMA_CONFIG_HOME": str(paths.run_asciinema / "config"),
        "ASCIINEMA_STATE_HOME": str(paths.run_asciinema / "state"),
    }


def test_base_env_replaces_asciinema_settings_from_home(paths):
    env = recorder.base_env(paths, {"ASCIINEMA_CONFIG_HOME": "/home/u/.config/asciinema"}, "dc01")
    assert env["ASCIINEMA_CONFIG_HOME"] == str(paths.run_asciinema / "config")


# The real shells run only where zsh or bash is installed, and not on Windows. They check the
# startup files as a user has them: no file of their own, `set -u`, a prompt of their own.

LINUX_ONLY = pytest.mark.skipif(sys.platform == "win32", reason="the startup files are for Linux shells")


HOOK = "declare -F _pwn_broker_rec_prefix >/dev/null && _pwn_broker_rec_prefix"


def _shell(name):
    import shutil

    found = shutil.which(name)
    if sys.platform == "win32":
        # only Git's bash: System32's bash.exe would start WSL
        git = shutil.which("git")
        found = None
        if name == "bash" and git is not None:
            # git.exe sits in Git\cmd or Git\mingw64\bin; bash.exe in Git\bin
            for folder in Path(git).resolve().parents[:3]:
                candidate = folder / "bin" / "bash.exe"
                if candidate.is_file() and (folder / "usr" / "bin").is_dir():
                    found = str(candidate)
                    break
    if found is None:
        pytest.skip(f"{name} is not installed")
    return found


def _run_shell(argv, home, extra, script):
    import subprocess

    env = {"HOME": str(home), "PATH": "/usr/bin:/bin", "TERM": "dumb", **extra}
    return subprocess.run(
        [*argv, "-c", script], env=env, capture_output=True, text=True, timeout=20, cwd=home, stdin=subprocess.DEVNULL
    )


def _home(tmp_path, files):
    home = tmp_path / "home"
    home.mkdir()
    for name, text in files.items():
        path = home / name
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    return home


@pytest.mark.parametrize("files", [{}, {".bashrc": "set -u\nPS1='me> '\n"}])
def test_real_bash_gets_the_prefix_once(paths, tmp_path, files):
    bash = _shell("bash")
    home = _home(tmp_path, files)
    recorder.shell_files(paths)
    command_argv = [bash, "--rcfile", str(paths.run_shell / "bashrc"), "-i"]
    # the hook runs before each prompt; running it twice must not add the prefix twice
    script = 'eval "$PROMPT_COMMAND"; eval "$PROMPT_COMMAND"; printf "%s|%s" "$PS1" "$PROMPT_COMMAND"'
    result = _run_shell(command_argv, home, {"PWN_BROKER_RECORDING": "dc01"}, script)
    assert result.returncode == 0, result.stderr
    shown, _, hooks = result.stdout.partition("|")
    assert shown.startswith("[rec dc01] ") and shown.count("[rec dc01]") == 1
    if files:
        assert shown == "[rec dc01] me> "
    assert hooks.count(HOOK) == 1


def test_real_bash_reading_the_file_again_keeps_one_hook(paths, tmp_path):
    bash = _shell("bash")
    home = _home(tmp_path, {})
    recorder.shell_files(paths)
    rcfile = str(paths.run_shell / "bashrc")
    script = (
        f'. {sh_quote(rcfile)}; PS1="again> "; eval "$PROMPT_COMMAND"; '
        'printf "%s|%s" "$PS1" "$PROMPT_COMMAND"'
    )
    result = _run_shell([bash, "--rcfile", rcfile, "-i"], home, {"PWN_BROKER_RECORDING": "dc01"}, script)
    assert result.returncode == 0, result.stderr
    shown, _, hooks = result.stdout.partition("|")
    assert shown == "[rec dc01] again> "
    assert hooks.count(HOOK) == 1


def _interactive(argv, home, extra, lines):
    """Run an interactive shell on typed lines; its prompts go to stderr, merged here."""
    import subprocess

    env = {"HOME": str(home), "PATH": "/usr/bin:/bin", "TERM": "dumb", **extra}
    return subprocess.run(
        argv, env=env, input=lines, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
        text=True, timeout=20, cwd=home,
    )  # fmt: skip


def test_real_bash_prompt_shows_the_last_status(paths, tmp_path):
    bash = _shell("bash")
    home = _home(tmp_path, {".bashrc": "PS1='[$?]> '\n"})
    recorder.shell_files(paths)
    argv = [bash, "--rcfile", str(paths.run_shell / "bashrc"), "-i"]
    result = _interactive(argv, home, {"PWN_BROKER_RECORDING": "dc01"}, "false\nexit\n")
    assert "[rec dc01] [1]> " in result.stdout


def test_real_bash_inside_a_recorded_bash_with_an_exported_prompt_command(paths, tmp_path):
    bash = _shell("bash")
    home = _home(tmp_path, {
        ".bashrc": "PS1='me> '\nexport PROMPT_COMMAND=\"${PROMPT_COMMAND:+$PROMPT_COMMAND; }true\"\n",
    })  # fmt: skip
    recorder.shell_files(paths)
    argv = [bash, "--rcfile", str(paths.run_shell / "bashrc"), "-i"]
    typed = "bash -i\necho inner\nexit\nexit\n"
    result = _interactive(argv, home, {"PWN_BROKER_RECORDING": "dc01"}, typed)
    assert "command not found" not in result.stdout
    assert "inner" in result.stdout
    assert "[rec dc01] me> " in result.stdout
    assert "[rec dc01] [rec dc01]" not in result.stdout


@LINUX_ONLY
@pytest.mark.parametrize("files", [{}, {".zshenv": "setopt nounset\n", ".zshrc": "PROMPT='me> '\n"}])
def test_real_zsh_gets_the_prefix_once(paths, tmp_path, files):
    zsh = _shell("zsh")
    home = _home(tmp_path, files)
    recorder.shell_files(paths)
    _command, extra = recorder.record_command(paths, zsh, environ={})
    # precmd hooks run before each prompt; run them twice, then say what the shell holds
    script = (
        "for f in $precmd_functions; do $f; done; for f in $precmd_functions; do $f; done; "
        'print -rn -- "$PROMPT|${ZDOTDIR-unset}|${PWN_BROKER_ZDOTDIR-unset}"'
    )
    result = _run_shell([zsh, "-i"], home, {"PWN_BROKER_RECORDING": "dc01", **extra}, script)
    assert result.returncode == 0, result.stderr
    shown, zdotdir, saved = result.stdout.split("|")
    assert shown.startswith("[rec dc01] ") and shown.count("[rec dc01]") == 1
    if files:
        assert shown == "[rec dc01] me> "
    # ZDOTDIR is as it was before record, so a zsh started inside reads the user's files
    assert zdotdir == "unset"
    assert saved == "unset"


@LINUX_ONLY
def test_real_zsh_with_a_zdotdir_of_its_own(paths, tmp_path):
    zsh = _shell("zsh")
    home = _home(tmp_path, {
        ".config/zsh/.zshenv": "FROM_ZSHENV=$ZDOTDIR\n",
        ".config/zsh/.zshrc": "PROMPT='cfg> '\nFROM_ZSHRC=$ZDOTDIR\n",
    })  # fmt: skip
    config = home / ".config" / "zsh"
    recorder.shell_files(paths)
    _command, extra = recorder.record_command(paths, zsh, environ={"ZDOTDIR": str(config)})
    script = 'for f in $precmd_functions; do $f; done; print -rn -- "$PROMPT|$FROM_ZSHENV|$FROM_ZSHRC|$ZDOTDIR"'
    result = _run_shell([zsh, "-i"], home, {"PWN_BROKER_RECORDING": "dc01", **extra}, script)
    assert result.returncode == 0, result.stderr
    assert result.stdout == f"[rec dc01] cfg> |{config}|{config}|{config}"


@LINUX_ONLY
def test_real_zsh_whose_zshenv_moves_zdotdir(paths, tmp_path):
    zsh = _shell("zsh")
    home = _home(tmp_path, {
        ".zshenv": 'ZDOTDIR="$HOME/.config/zsh"\n',
        ".config/zsh/.zshrc": "PROMPT='moved> '\n",
    })  # fmt: skip
    recorder.shell_files(paths)
    _command, extra = recorder.record_command(paths, zsh, environ={})
    script = 'for f in $precmd_functions; do $f; done; print -rn -- "$PROMPT|$ZDOTDIR"'
    result = _run_shell([zsh, "-i"], home, {"PWN_BROKER_RECORDING": "dc01", **extra}, script)
    assert result.returncode == 0, result.stderr
    assert result.stdout == f"[rec dc01] moved> |{home / '.config' / 'zsh'}"


def test_settings_env_is_the_apps_own_asciinema_folders(paths):
    assert recorder.settings_env(paths) == {
        "ASCIINEMA_CONFIG_HOME": str(paths.run_asciinema / "config"),
        "ASCIINEMA_STATE_HOME": str(paths.run_asciinema / "state"),
    }
