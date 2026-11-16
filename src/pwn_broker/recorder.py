import hashlib
import os
from collections.abc import Mapping
from pathlib import Path, PurePosixPath

from pwn_broker.paths import AppPaths
from pwn_broker.store import write_text
from pwn_broker.toolinstall import sh_quote

VERSION = "3.2.1"
# URL and SIZE are read by release/build.py alone: the app downloads nothing, it checks the copy
# the release carries against SHA256
URL = f"https://github.com/asciinema/asciinema/releases/download/v{VERSION}/asciinema-x86_64-unknown-linux-musl"
SIZE = 8130064
SHA256 = "bec9781bc8f297a9d3d74ff60205599507f2abba1183578b8b2f22be4c999214"

_CHUNK = 1 << 16


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as fh:
        while chunk := fh.read(_CHUNK):
            digest.update(chunk)
    return digest.hexdigest()


def present(paths: AppPaths, *, sha256: str = SHA256) -> bool:
    """True when the app's asciinema is a regular file with the pinned checksum."""
    try:
        return paths.asciinema.is_file() and _sha256(paths.asciinema) == sha256
    except OSError:
        return False


# The shell a recorded window runs gets the user's own startup files, then the [rec <target>]
# prefix. Every variable is read with a default, so a user's `set -u` cannot stop them.

_ZSHENV = """# Written by pwn-broker for record; rewritten each time record runs.
# Loads your own .zshenv with ZDOTDIR as it was, then points zsh back here for .zshrc.
if [[ -n ${{PWN_BROKER_ZDOTDIR-}} ]]; then
  ZDOTDIR=$PWN_BROKER_ZDOTDIR
else
  unset ZDOTDIR
fi
[[ -f "${{ZDOTDIR:-$HOME}}/.zshenv" ]] && source "${{ZDOTDIR:-$HOME}}/.zshenv"
# your .zshenv may have moved ZDOTDIR; .zshrc puts back whatever it is now
PWN_BROKER_ZDOTDIR=${{ZDOTDIR-}}
ZDOTDIR={here}
"""

_ZSHRC = """# Written by pwn-broker for record; rewritten each time record runs.
# Puts ZDOTDIR back as it was, loads your own .zshrc, then keeps [rec <target>] in front of
# the prompt. A zsh started inside reads only your own files.
if [[ -n ${PWN_BROKER_ZDOTDIR-} ]]; then
  ZDOTDIR=$PWN_BROKER_ZDOTDIR
else
  unset ZDOTDIR
fi
unset PWN_BROKER_ZDOTDIR
[[ -f "${ZDOTDIR:-$HOME}/.zshrc" ]] && source "${ZDOTDIR:-$HOME}/.zshrc"
_pwn_broker_rec_prefix() {
  local last=$?
  emulate -L zsh
  local prefix="[rec ${PWN_BROKER_RECORDING-}] "
  if [[ ${PROMPT-} != "$prefix"* ]]; then
    PROMPT="$prefix${PROMPT-}"
  fi
  return $last
}
autoload -Uz add-zsh-hook
add-zsh-hook precmd _pwn_broker_rec_prefix
"""

_BASHRC = """# Written by pwn-broker for record; rewritten each time record runs.
# --rcfile stands in for both files bash would read, so this loads the system's and your own,
# then keeps [rec <target>] in front of the prompt.
[ -f /etc/bash.bashrc ] && . /etc/bash.bashrc
[ -f "$HOME/.bashrc" ] && . "$HOME/.bashrc"
_pwn_broker_rec_prefix() {
  local prefix="[rec ${PWN_BROKER_RECORDING-}] "
  case "${PS1-}" in
    "$prefix"*) ;;
    *) PS1="$prefix${PS1-}" ;;
  esac
}
# Last, so a prompt command of your own that sets PS1 runs first. Bash puts $? back for the
# prompt itself. The call is guarded: a bash started inside inherits an exported
# PROMPT_COMMAND but not this function.
case "${PROMPT_COMMAND-}" in
  *_pwn_broker_rec_prefix*) ;;
  *) PROMPT_COMMAND="${PROMPT_COMMAND:+${PROMPT_COMMAND}
}declare -F _pwn_broker_rec_prefix >/dev/null && _pwn_broker_rec_prefix" ;;
esac
"""


def _zsh_folder(paths: AppPaths) -> Path:
    return paths.run_shell / "zsh"


def _bashrc(paths: AppPaths) -> Path:
    return paths.run_shell / "bashrc"


def shell_files(paths: AppPaths) -> None:
    """Write the startup files a recorded zsh or bash starts from."""
    here = _zsh_folder(paths)
    write_text(here / ".zshenv", _ZSHENV.format(here=sh_quote(str(here))))
    write_text(here / ".zshrc", _ZSHRC)
    write_text(_bashrc(paths), _BASHRC)


def record_command(
    paths: AppPaths, shell: str, *, environ: Mapping[str, str] = os.environ
) -> tuple[str, dict[str, str]]:
    """The command asciinema runs for `shell`, and what it adds to the environment."""
    name = PurePosixPath(shell).name
    if name == "zsh":
        extra = {"ZDOTDIR": str(_zsh_folder(paths)), "PWN_BROKER_ZDOTDIR": environ.get("ZDOTDIR", "")}
        return sh_quote(shell), extra
    if name == "bash":
        return f"{sh_quote(shell)} --rcfile {sh_quote(str(_bashrc(paths)))}", {}
    return sh_quote(shell), {}


def rec_argv(paths: AppPaths, cast: Path, title: str, command: str) -> list[str]:
    return [str(paths.asciinema), "rec", "--quiet", "--title", title, "--command", command, str(cast)]


def play_argv(paths: AppPaths, cast: Path) -> list[str]:
    return [str(paths.asciinema), "play", "--idle-time-limit", "2", str(cast)]


def settings_env(paths: AppPaths) -> dict[str, str]:
    """Settings folders of the app's own, so nothing in the home folder changes asciinema."""
    return {
        "ASCIINEMA_CONFIG_HOME": str(paths.run_asciinema / "config"),
        "ASCIINEMA_STATE_HOME": str(paths.run_asciinema / "state"),
    }


def base_env(paths: AppPaths, environ: Mapping[str, str], target: str) -> dict[str, str]:
    """The environment asciinema records in: settings folders of the app's own, and the target."""
    env = dict(environ)
    env["PWN_BROKER_RECORDING"] = target
    env.update(settings_env(paths))
    return env
