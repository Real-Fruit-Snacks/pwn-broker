"""Real recordings: `record` runs the pinned asciinema over a real zsh and bash in a pseudo-terminal.

These run only on Linux with PWN_BROKER_REAL_ASCIINEMA naming the pinned asciinema binary, which
the CI job `recording` fetches once. Everywhere else they skip. The record process is a child
process, so it runs the real code with its real defaults; it is kept to a temporary install
root, home folder and box, and records for a target that already exists.
"""

import json
import os
import re
import shutil
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from pwn_broker import boxes, recorder

REAL = os.environ.get("PWN_BROKER_REAL_ASCIINEMA", "")

pytestmark = pytest.mark.skipif(
    sys.platform != "linux" or not REAL or not os.path.isfile(REAL),
    reason="needs Linux and PWN_BROKER_REAL_ASCIINEMA naming the pinned asciinema",
)

WAIT = 20.0  # seconds for anything the terminal should show
CAST_WAIT = 5.0  # seconds for the cast on disk to catch up with the terminal
ROWS, COLUMNS = 24, 80
COMMAND = "echo marker-$((40+2))"
MARKER = "marker-42"
TIMED_MARKER = re.compile(r"\d\d:\d\d:\d\d  .*marker-42")
ESCAPE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[()][0-9A-Za-z]|[@-_=>78])")


def plain(text: str) -> str:
    """The text without colours and other control sequences."""
    return ESCAPE.sub("", text)


class Terminal:
    """A process on a pseudo-terminal of its own: read what it shows, type to it."""

    def __init__(self, argv: list[str], env: dict[str, str], cwd: Path) -> None:
        import fcntl
        import pty
        import struct
        import termios

        self.master, slave = pty.openpty()
        self.seen = b""
        self.closed = False
        try:
            # asciinema records at the size of the terminal it is started in
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLUMNS, 0, 0))

            def controlling_terminal() -> None:
                fcntl.ioctl(0, termios.TIOCSCTTY, 0)

            self.process = subprocess.Popen(
                argv,
                stdin=slave,
                stdout=slave,
                stderr=slave,
                env=env,
                cwd=cwd,
                start_new_session=True,
                preexec_fn=controlling_terminal,
            )
        except BaseException:
            os.close(self.master)
            raise
        finally:
            os.close(slave)

    def shown(self) -> str:
        return self.seen.decode("utf-8", "replace")

    def transcript(self) -> str:
        """Everything read so far, with escape characters made visible, for a failure message."""
        return self.shown().replace("\x1b", "\\e")

    def fail(self, message: str) -> None:
        self.kill()
        self._drain(0.5)
        pytest.fail(f"{message}\n--- the terminal so far ---\n{self.transcript()}\n--- end ---", pytrace=False)

    def _read(self, timeout: float) -> bool:
        """Read what is waiting, for up to `timeout` seconds; False when nothing came."""
        import select

        if self.closed:
            return False
        ready, _, _ = select.select([self.master], [], [], max(timeout, 0))
        if not ready:
            return False
        try:
            chunk = os.read(self.master, 65536)
        except OSError:
            # EIO: every process holding the other side has gone
            chunk = b""
        if not chunk:
            self.closed = True
            return False
        self.seen += chunk
        return True

    def _drain(self, seconds: float) -> None:
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline and self._read(deadline - time.monotonic()):
            pass

    def wait_for(self, text: str, what: str) -> None:
        deadline = time.monotonic() + WAIT
        while text not in self.shown() and text not in plain(self.shown()):
            left = deadline - time.monotonic()
            if left <= 0:
                self.fail(f"timed out after {WAIT:.0f} s waiting for {what} ({text!r})")
            self._read(min(left, 0.5))
            if self.closed and text not in self.shown() and text not in plain(self.shown()):
                status = self.process.poll()
                self.fail(f"the terminal closed before {what} ({text!r}); record's status: {status}")

    def type(self, text: str) -> None:
        os.write(self.master, text.encode())

    def wait_exit(self, what: str) -> int:
        deadline = time.monotonic() + WAIT
        while self.process.poll() is None:
            left = deadline - time.monotonic()
            if left <= 0:
                self.fail(f"timed out after {WAIT:.0f} s waiting for {what}")
            if not self._read(min(left, 0.2)) and self.closed:
                try:
                    self.process.wait(timeout=max(deadline - time.monotonic(), 0.1))
                except subprocess.TimeoutExpired:
                    self.fail(f"the terminal closed but record did not end, waiting for {what}")
        self._drain(1.0)
        return self.process.returncode

    def kill(self) -> None:
        # the whole group, even after record itself has ended: asciinema or the shell may be left
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass

    def close(self) -> None:
        self.kill()
        os.close(self.master)


def cast_output(path: Path) -> str:
    """What the recording on disk shows so far: the output events after the header, joined."""
    lines = path.read_bytes().split(b"\n")
    shown = []
    # the first line is the header; the last piece is empty or a line still being written
    for line in lines[1:-1]:
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if isinstance(event, list) and len(event) >= 3 and event[1] == "o" and isinstance(event[2], str):
            shown.append(event[2])
    return "".join(shown)


def recordings(box) -> list[Path]:
    return sorted((box.path / "targets" / "dc01" / "recordings").glob("*.cast"))


@pytest.fixture
def installed(paths):
    """The install root as record needs it: the real pinned asciinema in app/bin."""
    paths.asciinema.parent.mkdir(parents=True)
    shutil.copyfile(REAL, paths.asciinema)
    os.chmod(paths.asciinema, 0o755)
    assert recorder.present(paths), (
        f"{REAL} does not match the pinned asciinema {recorder.VERSION}; fetch it again with recorder.fetch"
    )
    return paths


@pytest.fixture
def opened(installed, box, dc01):
    # the box is open for this test's own process, so record finds a live lock holder
    boxes.acquire_open(installed, box, pid=os.getpid())
    return box


# The user's own startup files. zsh starts its new-user wizard without a .zshrc. Ubuntu's
# /etc/zsh/zshrc runs compinit, which stops to ask about the runner's insecure folders, unless
# .zshenv sets skip_global_compinit. The zsh prompt names a variable set in .zshenv, so seeing
# `zprompt-yes> ` proves the user's .zshenv was loaded through the app's own one;
# `zprompt-missing> ` means it was not.
ZSH_FILES = {
    ".zshenv": "skip_global_compinit=1\nzshenv_loaded=yes\n",
    ".zshrc": 'PROMPT="zprompt-${zshenv_loaded:-missing}> "\n',
}
BASH_FILES = {".bashrc": "PS1='bprompt> '\n"}

SHELLS = [
    pytest.param("zsh", ZSH_FILES, "zprompt-yes> ", id="zsh"),
    pytest.param("bash", BASH_FILES, "bprompt> ", id="bash"),
]


@pytest.mark.parametrize(("shell_name", "startup", "prompt"), SHELLS)
def test_a_real_session_is_recorded(tmp_path, installed, opened, shell_name, startup, prompt):
    shell = shutil.which(shell_name)
    if shell is None:
        pytest.fail(f"{shell_name} is not installed; the recording job installs zsh and has bash", pytrace=False)
    user = tmp_path / "user"
    user.mkdir()
    for name, content in startup.items():
        (user / name).write_text(content, encoding="utf-8")
    folders = [str(Path(shell).parent), "/usr/local/bin", "/usr/bin", "/bin"]
    env = {
        "HOME": str(user),
        "PATH": os.pathsep.join(dict.fromkeys(folders)),
        "TERM": "xterm-256color",
        "LANG": "C.UTF-8",
        "SHELL": shell,
        "PWN_BROKER_OPT": str(installed.opt),
        "PWN_BROKER_HOME": str(installed.home),
    }
    box = opened
    terminal = Terminal([sys.executable, "-m", "pwn_broker.record", "dc01"], env, user)
    try:
        terminal.wait_for(prompt, f"{shell_name}'s prompt from {', '.join(startup)}")
        terminal.type(f"{COMMAND}\r")
        terminal.wait_for(MARKER, f"the output of {COMMAND}")

        # the spec's unproven point: asciinema writes each event to the file as it happens
        found = recordings(box)
        if len(found) != 1:
            terminal.fail(f"expected one .cast in {found[0].parent if found else 'the recordings folder'}, found {found}")
        cast = found[0]
        deadline = time.monotonic() + CAST_WAIT
        while MARKER not in cast_output(cast):
            if time.monotonic() > deadline:
                terminal.fail(
                    f"asciinema is holding output back: {MARKER} was on the terminal but {cast.name} "
                    f"({cast.stat().st_size} bytes) still lacks it after {CAST_WAIT:.0f} s"
                )
            time.sleep(0.1)

        # while recording, record's marker names its own process and the cast being written
        folder = installed.run_recordings
        markers = sorted(folder.iterdir()) if folder.is_dir() else []
        if [m.name for m in markers] != [str(terminal.process.pid)]:
            terminal.fail(
                f"while recording, {folder} should hold one marker named {terminal.process.pid}, "
                f"record's process ID; it holds {[m.name for m in markers]}"
            )
        held = markers[0].read_text(encoding="utf-8").split("\n")
        if len(held) != 4 or held[1:] != ["dc01", str(cast), ""]:
            terminal.fail(f"the marker {markers[0]} should name dc01 and {cast}; it holds {held!r}")

        terminal.type("exit\r")
        status = terminal.wait_exit("record to end after exit")
    finally:
        terminal.close()

    shown = terminal.shown()
    seen = f"\n--- the terminal ---\n{terminal.transcript()}\n--- end ---"
    assert status == 0, f"record exited with status {status}{seen}"
    assert "[rec dc01]" in shown or "[rec dc01]" in plain(shown), f"no [rec dc01] prefix on the terminal{seen}"

    assert cast.is_file(), f"{cast} is gone{seen}"
    first = cast.read_text(encoding="utf-8").split("\n", 1)[0]
    try:
        header = json.loads(first)
    except ValueError:
        pytest.fail(f"the first line of {cast.name} is not JSON: {first!r}", pytrace=False)
    assert header.get("version") == 3, f"not a version 3 header: {first}"
    assert box.id in str(header.get("title", "")), f"the title does not hold the box ID {box.id}: {first}"

    text = cast.with_suffix(".txt")
    assert text.is_file(), f"no text copy beside {cast.name}{seen}"
    lines = text.read_text(encoding="utf-8").split("\n")
    copy = "\n--- the text copy ---\n" + "\n".join(lines) + "\n--- end ---"
    assert lines[0] == f"box      {box.name}  {box.id}", f"wrong box line{copy}"
    assert lines[1] == "target   dc01", f"wrong target line{copy}"
    assert re.fullmatch(r"started  \d{4}-\d\d-\d\d \d\d:\d\d:\d\d", lines[2]), f"wrong started line{copy}"
    assert lines[3] == f"cast     {cast.name}", f"wrong cast line{copy}"
    assert lines[4] == "", f"no empty line after the header{copy}"
    assert any(TIMED_MARKER.fullmatch(line) for line in lines[5:]), f"no timed line ending in {MARKER}{copy}"
    # the user's own startup file was loaded: their prompt is still there behind the prefix
    assert any(prompt.strip() in line for line in lines[5:]), f"{prompt.strip()!r} is not in the text copy{copy}"

    markers = sorted(p.name for p in installed.run_recordings.iterdir()) if installed.run_recordings.exists() else []
    assert markers == [], f"markers left in {installed.run_recordings}: {markers}"


def test_the_fetched_asciinema_is_the_pinned_version():
    done = subprocess.run([REAL, "--version"], capture_output=True, text=True, timeout=WAIT)
    assert done.returncode == 0, f"{REAL} --version ended with {done.returncode}: {done.stderr}"
    assert recorder.VERSION in done.stdout, f"{REAL} --version printed {done.stdout!r}"
