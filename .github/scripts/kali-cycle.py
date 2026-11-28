#!/usr/bin/env python3
"""The Kali cycle: one whole box, from the launch to the import, through the real programs.

Runs inside the kalilinux/kali-rolling container as root, after kali-cycle.sh has installed
pwn-broker from the release file with the real installer and the network off, and runs under
the app's bundled Python. Each numbered step drives the app through a pseudo-terminal, then
checks the result on disk or in the system. steps.txt in the evidence folder gets one ok or
fail line per step; the run stops at the first failed step, and the transcripts are written
whatever happens.

The pseudo-terminal helper here is a small one of its own rather than the one in
tests/test_record_real.py: that one reports through pytest, which the app's environment does
not have, and works at a fixed 80x24.

Every text waited for is copied from the code that prints it; the module named beside each one
is where it comes from.
"""

import argparse
import codecs
import fcntl
import hashlib
import os
import pty
import re
import select
import shutil
import signal
import stat
import struct
import subprocess
import sys
import termios
import time
import tomllib
import traceback
from dataclasses import dataclass
from pathlib import Path

OPT = Path("/opt/pwn-broker")
BIN = OPT / "bin"
RUN = OPT / "run"
VIMRC = OPT / "vim" / "vimrc"
HOME = Path("/root")
ACTIVE = HOME / "pwn-broker" / "active"  # config.load: home_dir / "pwn-broker"
WRAPPED = HOME / "pwn-broker" / "wrapped"
HOSTS = Path("/etc/hosts")
REPO = Path(__file__).resolve().parents[2]
TOOL_INDEX = Path("/work/tool-index")
OVPN = HOME / "test.ovpn"

WAIT = 30.0
ROWS, COLUMNS = 40, 120

BOX = "forest"
PLATFORM = "htb"  # config.Settings.default_platform
OS_NAME, DIFFICULTY = "windows", "easy"
HOSTNAME = "forest.htb.local"
LATER = "crm.forest.htb.local"
TARGET = "dc01"
USERNAME, DOMAIN, SECRET = "svc-alfresco", "htb.local", "s3rvice"
TOOL, TOOL_VERSION, TOOL_BUILD = "hello-tool", "1.0.0", 1
TOOL_LINE = "hello-tool ran"
# a Python tool on a real runtime: toolkit.make_python_tool's wheel is the distribution
# "<name>-py" 1.0, whose entry point prints its name and version (toolkit.make_wheel)
PY_TOOL, PY_VERSION, PY_BUILD = "hello-py", "1.0.0", 1
PY_LINE = "hello-py-py 1.0"
RUNTIME, RUNTIME_VERSION, RUNTIME_BUILD = "python-3.13", "3.13.18", 1  # toolkit.make_runtime
# pwn-shop's published report package, served from the folder index on the runtime above
REPORT, REPORT_VERSION, REPORT_BUILD = "report", "0.1.1", 1
REPORT_COMMAND = "pwn-report"
TOOLS = OPT / "tools"
TOOL_LOG = HOME / "pwn-broker" / "tools.log"  # paths.AppPaths.tool_log: home / "tools.log"
INTERPRETER = "import sys; print(tuple(sys.version_info[:2])); print(sys.prefix); print(sys.base_prefix)"
VPN_ADDRESS, VPN_PEER = "10.10.14.7", "10.10.14.8"
COMMAND, MARKER = "echo marker-$((40+2))", "marker-42"

# shell/app.py prompt_text, with a current target; the prompt line is flush left
PROMPT = f"{BOX}/{TARGET} > "
# console.INDENT: before every status line, question, field and table row (not headings or the prompt)
INDENT = "  "
# console.DETAIL_INDENT: a detail line starts under the text of the status line above it
DETAIL = INDENT + " " * len("ok    ")
# checks.report: "1 check passed" or "<n> checks passed", on an ok line (console.status_line)
CHECKS_LINE = re.compile(re.escape(INDENT) + r"ok    \d+ checks? passed")
# the longest label of each list of fields waited for (console.fields pads to it, plus two):
# cmd_misc.status, cmd_vpn.vpn_status, cmd_tool.tool_info for a tool not installed,
# lifecycle.finish_box's summary with toolhooks.summary's rows, toolhooks._restore
STATUS_LONGEST = "recordings"
VPN_STATUS_LONGEST = "started for"
TOOL_INFO_LONGEST = "description"
SUMMARY_LONGEST = "runtimes"
RESTORE_LONGEST = "tools"

# A point-to-point tunnel with no peer and no keys: OpenVPN opens tun0 with its address at
# start-up and waits for a peer that never comes. The allow option is needed by versions that
# refuse to run without TLS; ignore-unknown-option keeps older versions from stopping on it.
OVPN_TEXT = f"""\
dev tun
ifconfig {VPN_ADDRESS} {VPN_PEER}
proto udp
lport 1194
verb 3
ignore-unknown-option allow-deprecated-insecure-static-crypto
allow-deprecated-insecure-static-crypto
"""

VERIFY = "import sys; from pathlib import Path; from pwn_broker.archive import verify; verify(Path(sys.argv[1]))"

CSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
OSC = re.compile(r"\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")
# prompt_toolkit moves the cursor forward over cells it does not need to write
FORWARD = re.compile(r"\x1b\[(\d*)C")
ESCAPE = re.compile(r"\x1b(?:\[[0-?]*[ -/]*[@-~]|\][^\x07\x1b]*(?:\x07|\x1b\\)|[()][0-9A-Za-z]|[@-_=>78])")


def plain(text: str) -> str:
    """The text without colours and other control sequences; a cursor move forward is spaces."""
    text = FORWARD.sub(lambda m: " " * int(m[1] or 1), text)
    return ESCAPE.sub("", text)


def complete(text: str) -> str:
    """The text up to an escape sequence still cut short at its end."""
    cut = text.rfind("\x1b")
    if cut < 0:
        return text
    tail = text[cut:]
    if (
        len(tail) == 1
        or (tail[1] == "[" and not CSI.match(tail))
        or (tail[1] == "]" and not OSC.match(tail))
        or (tail[1] in "()" and len(tail) < 3)
    ):
        return text[:cut]
    return text


def readable(text: str) -> str:
    return text.replace("\r\n", "\n").replace("\r", "\n")


def asked(label: str, default: str | None = None) -> str:
    """console.TermConsole._ask: the indent, the label in 12 columns, an optional [default], then ` > `."""
    suffix = f" [{default}]" if default is not None else ""
    return f"{INDENT}{label:<12}{suffix} > "


def confirm(question: str, default: bool) -> str:
    """console.TermConsole.confirm: the indent, the question, [Y/n] or [y/N], then ` > `."""
    return f"{INDENT}{question} {'[Y/n]' if default else '[y/N]'} > "


def ok(text: str) -> str:
    """console.TermConsole._status: the indent, then console.status_line."""
    return f"{INDENT}ok    {text}"


def warn(text: str) -> str:
    return f"{INDENT}warn  {text}"


def fail(text: str) -> str:
    return f"{INDENT}fail  {text}"


def field_row(label: str, value: str, longest: str) -> str:
    """console.TermConsole.fields: the indent, the label padded to the list's longest label plus two."""
    return f"{INDENT}{label:<{len(longest) + 2}}{value}"


def whole_line(text: str) -> re.Pattern[str]:
    """The text as a line of its own, nothing before or after it on that line."""
    return re.compile(r"(?m)^" + re.escape(text) + r"\r?$")


# ---- evidence


class Failed(Exception):
    """A step did not do what the app says it does."""


class Evidence:
    def __init__(self, folder: Path) -> None:
        folder.mkdir(parents=True, exist_ok=True)
        self.folder = folder
        self._steps = open(folder / "steps.txt", "w", encoding="utf-8")
        self._log = open(folder / "driver-log.txt", "w", encoding="utf-8")
        self._notes: list[str] = []

    def log(self, text: str) -> None:
        line = f"{time.strftime('%H:%M:%S')}  {text}"
        print(line, flush=True)
        self._log.write(line + "\n")
        self._log.flush()

    def note(self, text: str) -> None:
        """A line for steps.txt under the step's own line."""
        self._notes.append(text)
        self.log(f"note  {text}")

    def result(self, number: int, title: str, failure: str | None) -> None:
        if failure is None:
            self._steps.write(f"ok    {number:>2}  {title}\n")
            self.log(f"ok    step {number}, {title}")
        else:
            first = (failure.strip().splitlines() or ["failed"])[0]
            self._steps.write(f"fail  {number:>2}  {title}: {first}\n")
            self.write("failure.txt", f"step {number}, {title}\n\n{failure}\n")
            self.log(f"fail  step {number}, {title}\n{failure}")
        for text in self._notes:
            self._steps.write(f"            {text}\n")
        self._notes = []
        self._steps.flush()

    def write(self, name: str, data: str | bytes) -> Path:
        path = self.folder / name
        if isinstance(data, bytes):
            path.write_bytes(data)
        else:
            path.write_text(data, encoding="utf-8")
        return path

    def close(self) -> None:
        self._steps.close()
        self._log.close()


EVIDENCE: Evidence


def log(text: str) -> None:
    EVIDENCE.log(text)


def note(text: str) -> None:
    EVIDENCE.note(text)


def check(condition: bool, what: str, detail: str = "") -> None:
    """One checked result: an ok line in the log, or a failed step that says what was found."""
    if condition:
        log(f"ok    {what}")
        return
    log(f"fail  {what}")
    raise Failed(what + (f"\n{detail}" if detail else ""))


def wait_until(probe, what: str, timeout: float = 10.0):
    """Poll probe() until it gives something true; that value, or a failed step."""
    deadline = time.monotonic() + timeout
    while True:
        found = probe()
        if found:
            log(f"ok    {what}")
            return found
        if time.monotonic() > deadline:
            raise Failed(f"timed out after {timeout:.0f} s waiting until {what}")
        time.sleep(0.25)


# ---- terminals


TERMINALS: list["Terminal"] = []


def _controlling_terminal() -> None:
    fcntl.ioctl(0, termios.TIOCSCTTY, 0)


def environment() -> dict[str, str]:
    """What a root terminal on Kali gives the programs started in it."""
    folders = [str(BIN), "/usr/local/sbin", "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"]
    env = {
        "HOME": str(HOME),
        "USER": "root",
        "LOGNAME": "root",
        "PATH": os.pathsep.join(folders),
        "TERM": "xterm-256color",
        "LANG": "C.UTF-8",
        "SHELL": "/usr/bin/zsh",
        # prompt_toolkit would otherwise wait for answers to cursor position requests
        "PROMPT_TOOLKIT_NO_CPR": "1",
    }
    if os.environ.get("DISPLAY"):
        env["DISPLAY"] = os.environ["DISPLAY"]
    return env


class Terminal:
    """A program on a pseudo-terminal of its own: read what it shows, type to it.

    `pos` is how far into the plain text the last wait matched; the next wait looks after it.
    """

    def __init__(self, name: str, argv: list[str], env: dict[str, str], cwd: Path = HOME) -> None:
        self.name = name
        self.raw = b""
        self.decoded = ""
        self._decoder = codecs.getincrementaldecoder("utf-8")("replace")
        self._plain = ("", "")
        self.pos = 0
        self.closed = False
        self.master, slave = pty.openpty()
        try:
            fcntl.ioctl(slave, termios.TIOCSWINSZ, struct.pack("HHHH", ROWS, COLUMNS, 0, 0))
            self.process = subprocess.Popen(
                argv,
                stdin=slave,
                stdout=slave,
                stderr=slave,
                env=env,
                cwd=cwd,
                start_new_session=True,
                preexec_fn=_controlling_terminal,
            )
        except BaseException:
            os.close(self.master)
            raise
        finally:
            os.close(slave)
        TERMINALS.append(self)
        log(f"{name}: started {' '.join(argv)} (pid {self.process.pid})")

    def text(self) -> str:
        shown = complete(self.decoded)
        if self._plain[0] != shown:
            self._plain = (shown, plain(shown))
        return self._plain[1]

    def _read(self, timeout: float) -> bool:
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
            self.decoded += self._decoder.decode(b"", final=True)
            return False
        self.raw += chunk
        self.decoded += self._decoder.decode(chunk)
        return True

    def pump(self, seconds: float) -> None:
        """Read whatever comes for this long."""
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            self._read(deadline - time.monotonic())

    def failure(self, message: str) -> str:
        shown = self.text()
        return (
            f"{message}\n"
            f"--- {self.name}: everything it showed ---\n{readable(shown)}\n"
            f"--- {self.name}: what came after the last match ---\n{readable(shown[self.pos:])}\n"
            "--- end ---"
        )

    def _wait(self, find, what: str, wanted: str, timeout: float):
        deadline = time.monotonic() + timeout
        while True:
            shown = self.text()
            found = find(shown)
            if found is not None:
                end, value = found
                self.pos = end
                log(f"{self.name}: saw {what}")
                return value
            if self.closed:
                status = self.process.poll()
                raise Failed(self.failure(f"{self.name} closed before {what} ({wanted}); its exit status: {status}"))
            left = deadline - time.monotonic()
            if left <= 0:
                raise Failed(self.failure(f"timed out after {timeout:.0f} s in {self.name} waiting for {what} ({wanted})"))
            self._read(min(left, 0.5))

    def wait(self, expected: "str | re.Pattern[str]", what: str, timeout: float = WAIT):
        """Wait for a text (returns the plain text since the last match, up to its end) or a pattern (returns the match).

        A text is matched without its trailing spaces: prompt_toolkit places the cursor after a
        question's last space with a cursor move rather than writing the space.
        """
        start = self.pos
        if isinstance(expected, re.Pattern):

            def find(shown: str):
                match = expected.search(shown, start)
                return None if match is None else (match.end(), match)

            return self._wait(find, what, f"/{expected.pattern}/", timeout)

        text = expected.rstrip(" ")

        def find(shown: str):
            at = shown.find(text, start)
            return None if at < 0 else (at + len(text), shown[start : at + len(text)])

        return self._wait(find, what, repr(expected), timeout)

    def wait_any(self, choices: dict[str, str], what: str, timeout: float = WAIT) -> str:
        """Wait for whichever of the texts comes first; its key."""
        start = self.pos

        def find(shown: str):
            texts = [(key, text.rstrip(" ")) for key, text in choices.items()]
            hits = [(shown.find(text, start), key, text) for key, text in texts]
            hits = [hit for hit in hits if hit[0] >= 0]
            if not hits:
                return None
            at, key, text = min(hits)
            return at + len(text), key

        wanted = " or ".join(repr(text) for text in choices.values())
        return self._wait(find, what, wanted, timeout)

    def type(self, text: str) -> None:
        log(f"{self.name}: typed {text!r}")
        os.write(self.master, text.encode())

    def answer(self, question: str, reply: str, what: str) -> None:
        """Wait for a question, then type the reply and Enter."""
        self.wait(question, what)
        self.type(reply + "\r")

    def wait_exit(self, what: str, timeout: float = WAIT) -> int:
        deadline = time.monotonic() + timeout
        while self.process.poll() is None:
            left = deadline - time.monotonic()
            if left <= 0:
                raise Failed(self.failure(f"timed out after {timeout:.0f} s waiting for {what}"))
            if not self._read(min(left, 0.2)) and self.closed:
                try:
                    self.process.wait(timeout=max(deadline - time.monotonic(), 0.1))
                except subprocess.TimeoutExpired:
                    raise Failed(self.failure(f"{self.name} closed but did not end, waiting for {what}")) from None
        self.pump(0.5)
        log(f"{self.name}: ended with status {self.process.returncode}")
        return self.process.returncode

    def save(self) -> None:
        EVIDENCE.write(f"terminal-{self.name}.txt", readable(self.text()))
        EVIDENCE.write(f"terminal-{self.name}.raw.txt", self.decoded.replace("\x1b", "\\e"))

    def kill(self) -> None:
        try:
            os.killpg(self.process.pid, signal.SIGKILL)
        except (ProcessLookupError, PermissionError):
            pass
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            pass


def shell(term: Terminal, line: str, expect: "str | re.Pattern[str] | None" = None, timeout: float = WAIT) -> str:
    """Run a command at the prompt: its output, up to and including the prompt that follows it.

    `expect` is a text the output must hold, waited for before the prompt, so a prompt drawn
    before the output can never end the wait early.
    """
    start = term.pos
    term.type(line + "\r")
    if expect is not None:
        term.wait(expect, f"the output of {line}", timeout)
    term.wait(PROMPT, f"the prompt after {line}", timeout)
    return term.text()[start : term.pos]


def lines_of(text: str) -> list[str]:
    return [line.strip() for line in re.split(r"[\r\n]+", text)]


# ---- the system


@dataclass
class Proc:
    pid: int
    ppid: int
    state: str
    tty: int
    comm: str
    argv: list[str]


def process(pid: int) -> Proc | None:
    try:
        text = Path(f"/proc/{pid}/stat").read_text(encoding="utf-8", errors="replace")
        argv = Path(f"/proc/{pid}/cmdline").read_bytes().split(b"\0")
    except OSError:
        return None
    # the name is in parentheses and may hold spaces; the fields after it are plain
    comm = text[text.index("(") + 1 : text.rindex(")")]
    fields = text[text.rindex(")") + 2 :].split()
    return Proc(
        pid=pid,
        ppid=int(fields[1]),
        state=fields[0],
        tty=int(fields[4]),
        comm=comm,
        argv=[part.decode("utf-8", "replace") for part in argv if part],
    )


def processes() -> list[Proc]:
    found = []
    for entry in os.listdir("/proc"):
        if entry.isdecimal():
            item = process(int(entry))
            if item is not None:
                found.append(item)
    return found


def openvpns() -> list[Proc]:
    return [p for p in processes() if p.comm == "openvpn"]


def run(argv: list[str], timeout: float = 20) -> subprocess.CompletedProcess:
    done = subprocess.run(argv, capture_output=True, text=True, errors="replace", timeout=timeout, env=environment())
    log(f"ran {' '.join(argv)}: status {done.returncode}")
    return done


def shown_run(done: subprocess.CompletedProcess) -> str:
    return f"status {done.returncode}\n--- stdout ---\n{done.stdout}--- stderr ---\n{done.stderr}--- end ---"


def read_toml(path: Path) -> dict:
    return tomllib.loads(path.read_text(encoding="utf-8"))


def tar_names(archive: Path) -> list[str]:
    done = run(["tar", "tzf", str(archive)])
    check(done.returncode == 0, f"tar tzf reads {archive.name}", shown_run(done))
    return [line.rstrip("/") for line in done.stdout.splitlines() if line]


def verify(archive: Path) -> None:
    done = run([sys.executable, "-c", VERIFY, str(archive)])
    check(done.returncode == 0, f"pwn_broker.archive.verify passes on {archive.name}", shown_run(done))


def resolves(name: str, ip: str) -> None:
    done = run(["getent", "hosts", name])
    check(
        done.returncode == 0 and done.stdout.split()[:1] == [ip],
        f"getent hosts {name} gives {ip}",
        shown_run(done),
    )


def tool_runs(command: str = TOOL, line: str = TOOL_LINE) -> None:
    """The installed command, from a plain shell outside the prompt."""
    done = run(["sh", "-c", command])
    check(
        done.returncode == 0 and done.stdout == line + "\n",
        f"{command} run from a plain shell prints {line!r}",
        shown_run(done),
    )


def installed_list() -> dict[str, dict]:
    """tools/installed.toml, by name (toolstate.save_installed)."""
    return {row["name"]: row for row in read_toml(TOOLS / "installed.toml").get("tool", [])}


def mode_is(path: Path, wanted: int) -> None:
    """private.py: what holds a box's secrets is its owner's alone, whatever the umask."""
    found = stat.S_IMODE(path.lstat().st_mode) if os.path.lexists(path) else None
    check(found == wanted, f"{path} has mode {wanted:o}", oct(found) if found is not None else "missing")


def box_is_private(s: "State") -> None:
    mode_is(s.folder, 0o700)
    mode_is(s.folder / "lists", 0o700)
    for name in ("creds.toml", "notes.md", ".history", "lists/passwords.txt", "lists/userpass.txt"):
        mode_is(s.folder / name, 0o600)


def tools_left() -> None:
    left = sorted(p.name for p in TOOLS.iterdir())
    # toolseen: the SHA-256 the index gave for each build stays when the tools go
    check(
        left == ["installed.toml", "seen.toml"],
        f"{TOOLS} holds nothing but installed.toml and seen.toml",
        repr(left),
    )
    seen = {(row["name"], row["version"], row["build"]) for row in read_toml(TOOLS / "seen.toml").get("build", [])}
    check(
        (TOOL, TOOL_VERSION, TOOL_BUILD) in seen,
        f"seen.toml keeps the SHA-256 of {TOOL} {TOOL_VERSION}-{TOOL_BUILD}",
        repr(sorted(seen)),
    )
    check(installed_list() == {}, "installed.toml lists nothing", (TOOLS / "installed.toml").read_text())


def tool_log() -> list[list[str]]:
    """The tool log's lines, split into their fields (toollog.append: two spaces between them)."""
    text = TOOL_LOG.read_text(encoding="utf-8") if TOOL_LOG.is_file() else ""
    return [[field.strip() for field in line.split("  ") if field.strip()] for line in text.splitlines()]


def logged_since(s: "State", start: int, expected: list[tuple[str, str]], what: str) -> None:
    """The log's lines after the first `start` are these (event, "<name> <version>-<build>")
    pairs in this order, each for this box and with its package's SHA-256; a runtime's line
    ends in `runtime`, and every line splits into exactly its fields."""
    lines = tool_log()
    EVIDENCE.write("tools.log", TOOL_LOG.read_bytes() if TOOL_LOG.is_file() else b"")
    box = f"{BOX} ({s.box_id})"
    found = []
    for fields in lines[start:]:
        runtime = len(fields) == 6 and fields[5] == "runtime"
        check(len(fields) == 5 or runtime, f"each new line of {TOOL_LOG} has five fields, or six ending in runtime", repr(fields))
        found.append((fields[1], fields[2], fields[3], fields[4], runtime))
    wanted = [
        (event, box, package, f"sha256:{s.sha256[package.split(' ')[0]]}", package.startswith(RUNTIME + " "))
        for event, package in expected
    ]
    check(found == wanted, what, f"--- expected ---\n{wanted!r}\n--- found ---\n{found!r}\n--- end ---")


def py_runs_on_runtime() -> None:
    """hello-py runs, on the runtime's Python 3.13 rather than on Kali's own."""
    tool_runs(PY_TOOL, PY_LINE)
    row = installed_list().get(PY_TOOL, {})
    python = Path(row.get("folder", "/missing")) / "venv" / "bin" / "python"
    done = run([str(python), "-c", INTERPRETER])
    shown = shown_run(done)
    out = done.stdout.splitlines()
    check(done.returncode == 0 and len(out) == 3, f"{python} runs", shown)
    note(f"{PY_TOOL}'s environment: Python {out[0]}, prefix {out[1]}, base {out[2]}")
    check(out[0] == "(3, 13)", f"{PY_TOOL}'s environment runs Python 3.13", shown)
    check(Path(out[1]).is_relative_to(TOOLS), f"its prefix is under {TOOLS}", shown)
    runtime_folder = TOOLS / RUNTIME
    check(Path(out[2]).is_relative_to(runtime_folder), f"its base prefix is under {runtime_folder}", shown)
    # the command itself runs on that environment: its script names the environment's interpreter
    script = python.parent / PY_TOOL
    first = script.read_text(encoding="utf-8", errors="replace").split("\n", 1)[0] if script.is_file() else ""
    named = first[2:].split()[:1] if first.startswith("#!") else []
    check(
        bool(named) and Path(os.path.realpath(named[0])) == Path(os.path.realpath(python)),
        f"{script}'s first line names the environment's own interpreter",
        repr(first),
    )
    real = Path(os.path.realpath(python))
    check(real.is_relative_to(runtime_folder), f"{python} resolves inside {runtime_folder}", str(real))
    runtime = installed_list().get(RUNTIME, {})
    check(
        runtime.get("kind") == "runtime" and real == Path(runtime.get("python", "/missing")).resolve(),
        f"{python} resolves to the interpreter installed.toml records for {RUNTIME}",
        repr(runtime),
    )


# ---- the cycle


class State:
    def __init__(self) -> None:
        # the date the app offers at the date question, read from the question itself
        self.day = ""
        self.ip = ""
        self.hosts_before = b""
        self.box_id = ""
        self.prompt: Terminal | None = None
        self.record: Terminal | None = None
        self.finished: Path | None = None
        # the upstream archive kali-cycle.sh downloaded and checked
        self.runtime_archive: Path | None = None
        self.report_package: Path | None = None
        self.runtime_sha256 = ""
        # each test package's SHA-256 by name, as the index gives it
        self.sha256: dict[str, str] = {}
        # how many lines the tool log had before the step that is checking it
        self.logged = 0
        # the note window that is open: its vim and the terminal around it, by process ID
        self.window: tuple[int, int] | None = None

    @property
    def folder(self) -> Path:
        # paths.box_folder_name: <date>_<platform>_<name>
        return ACTIVE / f"{self.day}_{PLATFORM}_{BOX}"


def hosts_line(s: State, names: list[str]) -> bytes:
    """hosts.line: the address, the names, two spaces, then the box's mark."""
    return f"{s.ip} {' '.join(names)}  # pwn-broker {s.box_id}\n".encode()


def check_hosts(s: State, expected: bytes, what: str, snapshot: str) -> None:
    now = HOSTS.read_bytes()
    EVIDENCE.write(snapshot, now)
    check(
        now == expected,
        what,
        f"--- expected ---\n{expected.decode('utf-8', 'replace')}--- found ---\n{now.decode('utf-8', 'replace')}--- end ---",
    )


def note_vims(s: State) -> list[Proc]:
    """The vims running on this box's note with the app's vimrc (notewindow.vim_command)."""
    notes = str(s.folder / "notes.md")
    found = []
    for p in processes():
        argv = p.argv
        if argv and Path(argv[0]).name == "vim" and argv[-1] == notes and "-u" in argv:
            if argv[argv.index("-u") + 1 : argv.index("-u") + 2] == [str(VIMRC)]:
                found.append(p)
    return found


def one_note_window(s: State, what: str) -> Proc:
    """Exactly one note vim for the box: one window per box (notewindow.find_note)."""
    notes = s.folder / "notes.md"

    def listing() -> str:
        shown = "\n".join(f"{p.pid} {p.ppid} {p.comm}: {' '.join(p.argv)}" for p in processes())
        return f"--- processes ---\n{shown}\n--- end ---"

    try:
        wait_until(lambda: note_vims(s), f"a vim with -u {VIMRC} is running on {notes}", timeout=WAIT)
    except Failed:
        raise Failed(f"no vim with -u {VIMRC} on {notes} {what}\n{listing()}") from None
    time.sleep(1)  # a second window, if one were opened, has started by now
    found = note_vims(s)
    check(len(found) == 1, f"one note vim for the box {what}", listing())
    return found[0]


def window_closed(s: State, what: str) -> None:
    """lifecycle.finish_box: the note's vim and its terminal have both ended, not even a zombie left."""
    vim, terminal = s.window

    def gone() -> bool:
        left = {p.pid for p in processes()}
        return vim not in left and terminal not in left and not note_vims(s)

    try:
        wait_until(gone, f"the note's vim ({vim}) and its terminal ({terminal}) are gone {what}")
    except Failed:
        listing = "\n".join(f"{p.pid} {p.ppid} {p.state} {p.comm}: {' '.join(p.argv)}" for p in processes())
        raise Failed(f"the note window was left {what}\n--- processes ---\n{listing}\n--- end ---") from None
    s.window = None


def launch(
    name: str, argv: list[str], first: str, repairs: tuple[str, ...] = (), header: bool = True
) -> Terminal:
    """Start pwn-broker; note every warn and fail line; answer the expected repair offers.

    `header` is whether the launch opens with cli.start's header (every launch but an import).
    `repairs` names the checks whose repair offer is expected; any other offer fails, so an
    installer defect cannot hide behind a repair. Fails when a check fails. Returns once
    `first`, the first thing after the launch, is shown.
    """
    from pwn_broker import __version__  # the app's own package, in the Python that runs this script

    term = Terminal(name, argv, environment())
    start = term.pos
    term.wait(CHECKS_LINE, "the launch checks line")
    # console.TermConsole.header: the first line, flush left, then a blank line
    opening = re.match(r"pwn-broker \S+\r?\n\r?\n", term.text())
    if header:
        check(
            opening is not None and opening[0].split()[1] == __version__,
            f"{name}'s launch opens with the header pwn-broker {__version__} and a blank line",
            term.failure("no header"),
        )
    else:
        check(opening is None, f"{name}'s launch has no header", term.failure("a header"))
    # checks._offer_repair asks after a check that can be fixed
    fix = confirm("fix it now?", True)
    while term.wait_any({"fix": fix, "next": first}, f"a repair offer or {first!r}") == "fix":
        # checks.report: the check's warn line, `<name>   <message>`, comes before its offer
        warned = [line for line in lines_of(term.text()[start : term.pos]) if line.startswith("warn  ")]
        check_name = warned[-1].split()[1] if warned else "?"
        check(
            check_name in repairs,
            f"only an expected repair is offered at {name}'s launch (offered: {check_name})",
            term.failure(f"a repair offer for {check_name} at {name}'s launch; expected only {list(repairs)}"),
        )
        note(f"{fix.strip()} for {check_name}, answered with its default, yes")
        term.type("\r")
        # the repair's own line: past the question's redraw, which must not count as another offer
        done = term.wait(re.compile(re.escape(INDENT) + r"(?:ok    \S+ fixed|fail  [^\r\n]*)"), "the repair's result")
        note(done[0].strip())
    flagged = [line for line in lines_of(term.text()[start : term.pos]) if line.startswith(("warn  ", "fail  "))]
    for line in flagged:
        note(line)
    fails = [line for line in flagged if line.startswith("fail")]
    check(not fails, f"no fail line at {name}'s launch", "\n".join(fails))
    return term


def prepare(s: State) -> None:
    """The tool packages and their folder index, tools_index in config.toml, the target address."""
    before = Path(EVIDENCE.folder / "hosts.before")
    s.hosts_before = HOSTS.read_bytes()
    if before.is_file():
        check(
            before.read_bytes() == s.hosts_before,
            "/etc/hosts is as kali-cycle.sh saved it before the unit suite",
            f"--- saved ---\n{before.read_text()}--- now ---\n{s.hosts_before.decode()}--- end ---",
        )
    else:
        EVIDENCE.write("hosts.before", s.hosts_before)
    check(s.hosts_before.endswith(b"\n"), "/etc/hosts ends with a line break")

    done = run(["ip", "route"])
    found = re.search(r"^default via (\S+)", done.stdout, re.M)
    if not found:
        s.ip = "127.0.0.1"
        note("no default route, so the target address is the loopback 127.0.0.1")
    elif run(["ping", "-c", "1", "-W", "2", found[1]]).returncode != 0:
        s.ip = "127.0.0.1"
        note(f"the default gateway {found[1]} did not answer a ping, so the target address is the loopback 127.0.0.1")
    else:
        s.ip = found[1]
        note(f"target address {s.ip}, the default gateway, which answered a ping")

    sys.path.insert(0, str(REPO / "tests"))
    import toolkit  # noqa: E402  (tests/toolkit.py, run with the app's own packages)

    shutil.rmtree(TOOL_INDEX, ignore_errors=True)
    _zip, entry = toolkit.make_entry(
        TOOL_INDEX,
        {
            "name": TOOL,
            "version": TOOL_VERSION,
            "build": TOOL_BUILD,
            "description": "prints one line",
            "tags": [],
            "upstream": "https://example.invalid/hello-tool",
            "examples": [TOOL],
            "command": [{"name": TOOL, "type": "binary", "path": f"files/{TOOL}"}],
        },
        {f"files/{TOOL}": f"#!/bin/sh\necho {TOOL_LINE}\n".encode()},
    )
    # the runtime package around the real upstream archive, and a Python tool that requires it
    archive = s.runtime_archive
    check(archive is not None and archive.is_file(), f"the runtime archive is at {archive}")
    _zip, runtime = toolkit.make_runtime(
        TOOL_INDEX, RUNTIME, RUNTIME_VERSION, "3.13", build=RUNTIME_BUILD, archive=archive.read_bytes()
    )
    s.runtime_sha256 = runtime.sha256
    note(f"{RUNTIME} {RUNTIME_VERSION}-{RUNTIME_BUILD}: {runtime.size} bytes, sha256 {runtime.sha256}")
    _zip, python_tool = toolkit.make_python_tool(
        TOOL_INDEX,
        PY_TOOL,
        PY_VERSION,
        build=PY_BUILD,
        description="prints one line from Python",
        tags=[],
        upstream=f"https://example.invalid/{PY_TOOL}",
        examples=[PY_TOOL],
    )
    check(python_tool.requires == [RUNTIME], f"{PY_TOOL} requires {RUNTIME}", repr(python_tool))
    report = report_entry(s.report_package)
    s.sha256 = {e.name: e.sha256 for e in (entry, runtime, python_tool, report)}
    toolkit.write_index(TOOL_INDEX, [entry, runtime, python_tool, report])
    check((TOOL_INDEX / "index.toml").is_file(), f"a folder index in {TOOL_INDEX}")
    check(read_toml(TOOL_INDEX / "index.toml").get("schema") == 2, "the index is schema 2")

    settings = OPT / "config.toml"
    existing = settings.read_text(encoding="utf-8") if settings.exists() else ""
    check("tools_index" not in existing, f"{settings} has no tools_index yet", existing)
    lead = "" if not existing or existing.endswith("\n") else "\n"
    settings.write_text(f'{existing}{lead}tools_index = "{TOOL_INDEX}"\n', encoding="utf-8")
    EVIDENCE.write("config.toml", settings.read_text(encoding="utf-8"))


def report_entry(package: Path | None):
    """pwn-shop's report zip, as kali-cycle.sh downloaded and checked it, in the folder index with
    the entry pwn-shop's own index gives it."""
    from pwn_broker.filescan import sha256_file
    from pwn_broker.toolindex import BuildEntry

    check(package is not None and package.is_file(), f"the report package is at {package}")
    name = f"{REPORT}-{REPORT_VERSION}-{REPORT_BUILD}.zip"
    shutil.copyfile(package, TOOL_INDEX / name)
    size, sha256 = (TOOL_INDEX / name).stat().st_size, sha256_file(TOOL_INDEX / name)
    note(f"{REPORT} {REPORT_VERSION}-{REPORT_BUILD}: {size} bytes, sha256 {sha256}")
    return BuildEntry(
        name=REPORT, version=REPORT_VERSION, build=REPORT_BUILD, kind="kali", needs_root=False,
        commands=[REPORT_COMMAND], file=name, url="", size=size, sha256=sha256, requires=[RUNTIME],
    )  # fmt: skip


def found_by_zsh(command: str) -> None:
    """The installer's PATH line: Kali's zsh, from root's own .zshrc alone, finds the command."""
    env = environment()
    env["PATH"] = os.pathsep.join(p for p in env["PATH"].split(os.pathsep) if p != str(BIN))
    done = subprocess.run(
        ["zsh", "-ic", f"command -v {command}"],
        capture_output=True, text=True, errors="replace", timeout=20, env=env, cwd=HOME,
    )  # fmt: skip
    log(f"ran zsh -ic 'command -v {command}': status {done.returncode}")
    last = ([line.strip() for line in done.stdout.splitlines() if line.strip()] or [""])[-1]
    check(
        done.returncode == 0 and last == str(BIN / command),
        f"zsh -ic 'command -v {command}' finds {BIN / command} through root's .zshrc",
        shown_run(done),
    )


def step_launch(s: State) -> None:
    found_by_zsh("pwn-broker")
    found_by_zsh("record")
    # setup, run by the installer, makes the box folders; the first launch asks nothing about them
    check(ACTIVE.is_dir() and WRAPPED.is_dir(), f"setup made {ACTIVE} and {WRAPPED} before the first launch")
    s.prompt = launch("prompt", [str(BIN / "pwn-broker"), "new"], asked("box name"))
    # the launch questions are answered in step 2; the vpn check must say no tunnel is up
    shown = s.prompt.text()
    check(warn("vpn   no VPN tunnel is up") in shown, "the vpn check warns that no tunnel is up", readable(shown))
    check(
        not any("folders" in line for line in lines_of(shown)),
        "the first launch says nothing about the box folders",
        readable(shown),
    )
    # questions.ask_box: the New box heading, a line of its own, over its questions
    check(whole_line("New box").search(shown) is not None, "the questions are under the New box heading", readable(shown))


def step_new_box(s: State) -> None:
    t = s.prompt
    t.type(BOX + "\r")
    t.answer(asked("platform", PLATFORM), "", "the platform question")
    # the default is whatever date the app offers; the folder name and summary follow it
    question = asked("date", "DAY").split("DAY")
    offered = t.wait(
        re.compile(re.escape(question[0]) + r"(\d{4}-\d\d-\d\d)" + re.escape(question[1].rstrip(" "))),
        "the date question",
    )
    s.day = offered[1]
    note(f"the date question offered {s.day}")
    t.type("\r")
    t.answer(asked("os"), OS_NAME, "the os question")
    t.answer(asked("difficulty"), DIFFICULTY, "the difficulty question")
    t.answer(confirm("add a target?", True), "", "the add a target question")
    # cli.new_box: questions.ask_target's heading counts the targets
    t.wait(whole_line("Target 1"), "the Target 1 heading")
    t.answer(asked("ip"), s.ip, "the ip question")
    t.answer(asked("hostname"), HOSTNAME, "the hostname question")
    t.answer(asked("scope", "external"), "", "the scope question")
    t.answer(asked("name", HOSTNAME), TARGET, "the target name question")
    t.wait(ok(f"target {TARGET} created"), "the target created line")
    t.answer(confirm("add another?", False), "", "the add another question")

    box = read_toml(s.folder / "box.toml")
    wanted = {"name": BOX, "platform": PLATFORM, "os": OS_NAME, "difficulty": DIFFICULTY, "status": "active"}
    check(all(box.get(k) == v for k, v in wanted.items()), f"{s.folder}/box.toml holds the answers", repr(box))
    s.box_id = box["id"]
    target = read_toml(s.folder / "targets" / TARGET / "target.toml")
    check(
        target.get("ips") == [s.ip] and target.get("hostnames") == [HOSTNAME] and target.get("scope") == "external",
        f"targets/{TARGET}/target.toml holds the address, the hostname and the scope",
        repr(target),
    )


def step_hosts(s: State) -> None:
    t = s.prompt
    t.answer(confirm(f"add {TARGET}'s hostnames to /etc/hosts?", True), "", "the /etc/hosts question")
    t.wait(ok("/etc/hosts updated"), "the /etc/hosts updated line")
    check_hosts(
        s,
        s.hosts_before + hosts_line(s, [HOSTNAME]),
        "/etc/hosts is the old bytes plus one line for the box",
        "hosts.step3",
    )
    resolves(HOSTNAME, s.ip)
    check(read_toml(s.folder / "box.toml").get("hosts") == [TARGET], f"box.toml records {TARGET}'s line")


def step_ping(s: State) -> None:
    # targetflow._ping
    found = s.prompt.wait(re.compile(re.escape(ok(s.ip)) + r" answered in \d+ ms"), "the ping line")
    note(found[0].strip())


def step_box_created(s: State) -> None:
    t = s.prompt
    t.wait(ok(f"box {BOX} created"), "the box created line")
    # cli._offers_for_new_box: the first new box on a machine asks once about each; the index here has no playbooks
    t.answer(confirm("install playbooks in this box and every new box?", True), "n", "the playbooks question")
    t.wait(whole_line(ok("saved: new boxes start without playbooks")), "the line that says the answer is saved")
    t.wait(
        whole_line(f"{DETAIL}for every new box: playbooks = true in {OPT / 'config.toml'}"),
        "the line that says how to change it",
    )
    # then the report tool's: answered no here, so a later step installs it by hand
    t.answer(confirm("install the report tool in this box and every new box?", True), "n", "the report tool's question")
    t.wait(whole_line(ok("saved: new boxes start without the report tool")), "the line that says the report answer is saved")
    t.wait(whole_line(f"{DETAIL}for this box only: tool install {REPORT}"), "the line that says how to install it in this box")
    t.wait(
        whole_line(f"{DETAIL}for every new box: report = true in {OPT / 'config.toml'}"),
        "the line that says how to change the report answer",
    )
    saved = read_toml(OPT / "state.toml")
    check(saved.get("new_box_playbooks") is False, f"{OPT / 'state.toml'} keeps the answer", repr(saved))
    check(saved.get("new_box_report") is False, f"{OPT / 'state.toml'} keeps the report tool's answer", repr(saved))
    t.wait(PROMPT, "the prompt")
    found = one_note_window(s, "after the new box")
    s.window = (found.pid, found.ppid)
    parent = process(found.ppid)
    note(f"vim {found.pid}: {' '.join(found.argv)}; parent {found.ppid} ({parent.comm if parent else 'gone'})")
    # the parent is the terminal x-terminal-emulator resolves to, or the program that one runs
    # when it is a wrapper script (Debian's uxterm and lxterm exec xterm)
    resolved = Path(os.path.realpath(shutil.which("x-terminal-emulator", path=environment()["PATH"]) or "missing"))
    try:
        parent_exe = Path(os.path.realpath(f"/proc/{found.ppid}/exe"))
    except OSError:
        parent_exe = Path("unknown")
    head = resolved.read_bytes()[:4096] if resolved.is_file() else b""
    wrapped = head.startswith(b"#!") and re.search(rb"\b" + re.escape(parent_exe.name.encode()) + rb"\b", head)
    note(f"x-terminal-emulator resolves to {resolved}; vim's parent runs {parent_exe}")
    check(
        parent_exe == resolved or bool(wrapped),
        f"vim's parent is the terminal x-terminal-emulator resolves to ({resolved})",
        f"parent {found.ppid}: {parent_exe}",
    )
    prompt_tty = process(t.process.pid)
    check(
        found.tty != 0 and prompt_tty is not None and found.tty != prompt_tty.tty,
        "vim has a terminal of its own, not the prompt's",
        f"vim tty_nr {found.tty}, prompt tty_nr {prompt_tty.tty if prompt_tty else 'gone'}",
    )
    time.sleep(2)  # the window draws vim's screen
    shot = EVIDENCE.folder / "note-window.png"
    done = run(["import", "-display", os.environ.get("DISPLAY", ":99"), "-window", "root", str(shot)])
    check(done.returncode == 0 and shot.is_file() and shot.stat().st_size > 0, "a screenshot of the display", shown_run(done))
    colours = run(["identify", "-format", "%k", str(shot)])
    count = int(colours.stdout.strip()) if colours.returncode == 0 and colours.stdout.strip().isdecimal() else 0
    note(f"the screenshot has {count} distinct colours")
    check(count > 1, "the screenshot is not one flat colour", shown_run(colours))


def step_cred(s: State) -> None:
    t = s.prompt
    t.type("cred add\r")
    # cmd_cred: questions.ask_cred's heading
    t.wait(whole_line("New credential"), "the New credential heading")
    t.answer(asked("username"), USERNAME, "the username question")
    t.answer(asked("domain"), DOMAIN, "the domain question")
    t.answer(asked("secret"), SECRET, "the secret question")
    t.answer(asked("kind", "password"), "", "the kind question")
    t.answer(asked("found on", TARGET), "", "the found on question")
    t.answer(asked("note"), "", "the note question")
    t.wait(ok(f"cred 1 saved, found on {TARGET}"), "the cred saved line")
    t.wait(ok("lists updated: 1 username, 1 password, 1 pair"), "the lists updated line")
    t.wait(PROMPT, "the prompt after cred add")
    lists = s.folder / "lists"
    for name, value in (("usernames.txt", USERNAME), ("passwords.txt", SECRET), ("userpass.txt", f"{USERNAME}:{SECRET}")):
        found = (lists / name).read_text(encoding="utf-8") if (lists / name).is_file() else None
        check(found == value + "\n", f"lists/{name} holds {value!r}", repr(found))
    box_is_private(s)


def step_host_add(s: State) -> None:
    t = s.prompt
    t.type(f"host add {LATER}\r")
    t.wait(ok(f"{TARGET} now answers to 2 names"), "the hostname count line")
    t.wait(ok("/etc/hosts updated"), "the /etc/hosts updated line")
    t.wait(PROMPT, "the prompt after host add")
    check_hosts(
        s,
        s.hosts_before + hosts_line(s, [HOSTNAME, LATER]),
        "the box's line in /etc/hosts holds both names, and nothing else changed",
        "hosts.step7",
    )
    resolves(HOSTNAME, s.ip)
    resolves(LATER, s.ip)
    out = shell(t, "host", expect=LATER)
    rows = [line.split() for line in lines_of(out)]
    for name in (HOSTNAME, LATER):
        check([TARGET, name, "yes"] in rows, f"host lists {name} with yes", readable(out))


def step_record(s: State) -> None:
    r = s.record = Terminal("record", [str(BIN / "record"), TARGET], environment())
    r.wait(ok(f"recording this window for {TARGET} ({BOX})"), "the recording line")
    # record._record: a detail line, under the text of the line above
    r.wait(DETAIL + "exit this shell to stop", "the exit line")
    r.wait(f"[rec {TARGET}]", f"the recorded zsh's prompt with its [rec {TARGET}] prefix")
    r.pump(1.5)  # the rest of Kali's two-line prompt
    shown = readable(r.text()).split("\n")
    at = next(i for i, line in enumerate(shown) if f"[rec {TARGET}]" in line)
    prompt_lines = shown[at : at + 2]
    EVIDENCE.write("record-prompt.txt", "\n".join(prompt_lines) + "\n")
    for line in prompt_lines:
        note(f"prompt: {line}")
    # Kali's own two-line prompt from root's .zshrc, behind the prefix: bash would also get the
    # prefix, and a zsh without the user's .zshrc would not draw this
    kali = f"[rec {TARGET}] ┌──(root㉿kali)-[~]"
    check(
        len(prompt_lines) == 2 and prompt_lines[0].strip() == kali and prompt_lines[1].startswith("└─#"),
        "the recorded window shows Kali's own zsh prompt behind the prefix",
        "\n".join(prompt_lines),
    )

    def zsh_under_record() -> Proc | None:
        for p in processes():
            if p.comm != "zsh":
                continue
            current = p
            while current is not None and current.pid > 1:
                if current.ppid == r.process.pid:
                    return p
                current = process(current.ppid)
        return None

    shell_proc = wait_until(zsh_under_record, f"a zsh runs under record ({r.process.pid})")
    note(f"zsh {shell_proc.pid}: {' '.join(shell_proc.argv)}")
    r.type(COMMAND + "\r")
    r.wait(MARKER, f"the output of {COMMAND}")
    r.type("id\r")
    r.wait("uid=0(root)", "the output of id")

    casts = sorted((s.folder / "targets" / TARGET / "recordings").glob("*.cast"))
    check(len(casts) == 1, "one .cast is being written", repr(casts))
    markers = sorted(os.listdir(RUN / "recordings"))
    check(markers == [str(r.process.pid)], f"one marker in {RUN / 'recordings'}, named by record's process ID", repr(markers))


def step_while_recording(s: State) -> None:
    t = s.prompt
    out = shell(t, "status", expect="root flag")
    # cmd_misc.status: console.fields, padded to its longest label, recordings; _recordings_line
    check(
        field_row("recordings", "1 (1 recording now)", STATUS_LONGEST) in out,
        "status says one window is recording",
        readable(out),
    )
    start = t.pos
    t.type("finish\r")
    t.wait(
        fail(f"1 window is still recording ({TARGET}). exit it, then finish again"),
        "the still-recording refusal",
    )
    t.wait(PROMPT, "the prompt after finish")
    out = t.text()[start : t.pos]
    check(confirm("finish this box?", False) not in out, "finish asked nothing", readable(out))
    check(read_toml(s.folder / "box.toml").get("status") == "active", "the box is still active")


def step_export(s: State) -> None:
    t = s.prompt
    t.type("export\r")
    t.wait(warn("1 window is still recording; the export holds it up to now"), "the still-recording warning")
    found = t.wait(re.compile(re.escape(ok("archive ")) + r"(\S+\.exported\.tar\.gz)"), "the archive line")
    t.wait(PROMPT, "the prompt after export")
    archive = Path(found[1])
    expected = WRAPPED / f"{s.folder.name}.exported.tar.gz"
    check(archive == expected and archive.is_file(), f"the archive is {expected}", str(archive))
    mode_is(archive, 0o600)
    mode_is(WRAPPED, 0o700)
    names = tar_names(archive)
    recordings = f"{s.folder.name}/targets/{TARGET}/recordings/"
    check(any(n.startswith(recordings) and n.endswith(".cast") for n in names), "tar tzf lists the .cast", "\n".join(names))
    verify(archive)


def step_close_recording(s: State) -> None:
    r = s.record
    r.type("exit\r")
    r.wait(ok("recording saved, "), "the recording saved line")
    status = r.wait_exit("record to end after exit")
    check(status == 0, "record ended with status 0", f"status {status}")
    casts = sorted((s.folder / "targets" / TARGET / "recordings").glob("*.cast"))
    check(len(casts) == 1, "one .cast in the recordings folder", repr(casts))
    cast = casts[0]
    text = cast.with_suffix(".txt")
    check(text.is_file(), f"its text copy {text.name} exists")
    EVIDENCE.write("recording.txt", text.read_bytes())
    EVIDENCE.write("recording.cast", cast.read_bytes())
    body = text.read_text(encoding="utf-8")
    lines = body.split("\n")
    # casttext.write: the four header lines
    check(
        len(lines) > 4
        and lines[0] == f"box      {BOX}  {s.box_id}"
        and lines[1] == f"target   {TARGET}"
        and re.fullmatch(r"started  \d{4}-\d\d-\d\d \d\d:\d\d:\d\d", lines[2]) is not None
        and lines[3] == f"cast     {cast.name}",
        "the text copy has the four header lines",
        body,
    )
    check(re.search(r"^\d\d:\d\d:\d\d  .*marker-42$", body, re.M) is not None, "a timed line ends in marker-42", body)
    left = sorted(os.listdir(RUN / "recordings"))
    check(left == [], f"no marker is left in {RUN / 'recordings'}", repr(left))


def step_replay(s: State) -> None:
    t = s.prompt
    row = re.compile(r"(?m)^ *1 +\d{4}-\d\d-\d\d \d\d:\d\d +(?:under a minute|\d+ min) +\d+(?:\.\d)? (?:B|KB|MB)")
    out = shell(t, "replay", expect=row)
    check("recording now" not in out and not re.search(r"(?m)^ *2 +\d{4}-", out), "replay lists one finished recording", readable(out))
    start, raw_start = t.pos, len(t.decoded)
    t.type("replay 1\r")
    t.wait(MARKER, "marker-42 played back", timeout=60)
    t.wait(PROMPT, "the prompt after the replay", timeout=60)
    t.pump(1.0)
    after = t.text()[start:]
    EVIDENCE.write(
        "replay-after.txt",
        "--- plain ---\n" + readable(after) + "\n--- with escapes shown ---\n" + t.decoded[raw_start:].replace("\x1b", "\\e") + "\n",
    )
    check("asciinema ended with status" not in after, "the replay ended without a status warning", readable(after))
    # the terminal is back: a command still runs and prints
    shell(t, "status", expect="root flag")


def step_vpn(s: State) -> None:
    t = s.prompt
    OVPN.write_text(OVPN_TEXT, encoding="utf-8")
    t.type("vpn start\r")
    t.answer(asked("vpn file"), str(OVPN), "the vpn file question")
    t.wait(ok("copied to vpn/test.ovpn"), "the copied line")
    t.wait(ok(f"vpn up, {VPN_ADDRESS} on tun0"), "the vpn up line", timeout=60)
    t.wait(PROMPT, "the prompt after vpn start")

    done = run(["ip", "-4", "addr", "show", "tun0"])
    check(f"inet {VPN_ADDRESS}" in done.stdout, f"ip shows {VPN_ADDRESS} on tun0", shown_run(done))
    running = openvpns()
    check(len(running) == 1, "one openvpn process is running", repr(running))
    check((RUN / "vpn" / "marker.toml").is_file(), f"{RUN / 'vpn' / 'marker.toml'} exists")
    marked = read_toml(RUN / "vpn" / "marker.toml").get("pid")
    check(running[0].pid == marked, f"the running openvpn is the marker's process {marked}", repr(running[0]))
    config = str(RUN / "vpn" / "config.ovpn")
    check(config in running[0].argv, f"openvpn's command line names {config}", " ".join(running[0].argv))
    copy = s.folder / "vpn" / "test.ovpn"
    mode = stat.S_IMODE(copy.stat().st_mode) if copy.exists() else None
    check(mode == 0o600, f"{copy} has mode 600", oct(mode) if mode is not None else "missing")

    out = shell(t, "vpn status", expect="started for")
    # cmd_vpn.vpn_status: console.fields, padded to its longest label, started for
    check(
        field_row("state", "up", VPN_STATUS_LONGEST) in out
        and field_row("address", f"{VPN_ADDRESS} on tun0", VPN_STATUS_LONGEST) in out
        and field_row("file", "test.ovpn", VPN_STATUS_LONGEST) in out,
        "vpn status shows the tunnel up, its address and the file",
        readable(out),
    )
    log_lines = [line for line in (RUN / "vpn" / "openvpn.log").read_text(errors="replace").splitlines() if line.strip()]
    check(bool(log_lines), "OpenVPN's log has lines")
    out = shell(t, "vpn log", expect=log_lines[-1].strip())
    check("no log yet" not in out, "vpn log prints the log", readable(out))
    out = shell(t, "status", expect="root flag")
    check(field_row("vpn", f"{VPN_ADDRESS} on tun0", STATUS_LONGEST) in out, "status shows the VPN address", readable(out))


def step_vpn_daemon(s: State) -> None:
    t = s.prompt
    pid = read_toml(RUN / "vpn" / "marker.toml")["pid"]
    proc = process(pid)
    check(proc is not None and proc.comm == "openvpn", f"the marker's process {pid} is openvpn", repr(proc))
    chain, current = [], proc
    while current is not None and current.pid > 1:
        chain.append(current.ppid)
        current = process(current.ppid)
    parent = process(proc.ppid)
    note(f"openvpn {pid}: parent {proc.ppid} ({parent.comm if parent else 'gone'}), tty_nr {proc.tty}, ancestors {chain}")
    check(t.process.pid not in chain, f"the prompt ({t.process.pid}) is not among openvpn's parents", repr(chain))
    # inside the container nothing is a subreaper, so a daemon's parent is PID 1
    check(proc.ppid == 1, "openvpn's parent is PID 1", repr(proc))
    check(proc.tty == 0, "openvpn has no controlling terminal", repr(proc))

    shell(t, "vpn stop", expect=ok("vpn stopped"))
    wait_until(lambda: not openvpns(), "no openvpn process is left")
    wait_until(lambda: run(["ip", "link", "show", "tun0"]).returncode != 0, "tun0 is gone")


def step_tool(s: State) -> None:
    t = s.prompt
    out = shell(t, "tool list", expect=TOOL)
    rows = [line.split() for line in lines_of(out)]
    check(any(row[:3] == [TOOL, f"{TOOL_VERSION}-{TOOL_BUILD}", "kali"] for row in rows), f"tool list shows {TOOL}", readable(out))
    s.logged = len(tool_log())
    t.type(f"tool install {TOOL}\r")
    # toolinstall._show
    t.wait(ok(f"{TOOL} {TOOL_VERSION} installed"), "the installed line")
    t.wait(PROMPT, "the prompt after tool install")
    launcher = BIN / TOOL
    check(launcher.is_file() and os.access(launcher, os.X_OK), f"{launcher} exists")
    tool_runs()
    logged_since(s, s.logged, [("install", f"{TOOL} {TOOL_VERSION}-{TOOL_BUILD}")], f"{TOOL_LOG} has an install line for {TOOL}")


# toolinstall.install_runtime: the runtime's line, with the zip's size in MiB
RUNTIME_INSTALLED = re.compile(re.escape(ok(f"{RUNTIME} {RUNTIME_VERSION} installed")) + r" \(runtime, \d+ MB\)")
PY_PACKAGE = f"{PY_TOOL} {PY_VERSION}-{PY_BUILD}"
RUNTIME_PACKAGE = f"{RUNTIME} {RUNTIME_VERSION}-{RUNTIME_BUILD}"


def step_python_tool(s: State) -> None:
    t = s.prompt
    done = run(["python3", "-c", "import sys; print(tuple(sys.version_info[:2]))"])
    kali = done.stdout.strip()
    note(f"Kali's own python3 is {kali}")
    check(done.returncode == 0 and kali not in ("", "(3, 13)"), "Kali's own python3 is not 3.13", shown_run(done))

    out = shell(t, "tool list", expect=PY_TOOL)
    rows = [line.split() for line in lines_of(out)]
    check(any(row[:3] == [PY_TOOL, f"{PY_VERSION}-{PY_BUILD}", "kali"] for row in rows), f"tool list shows {PY_TOOL}", readable(out))
    check(RUNTIME not in out, f"tool list does not show {RUNTIME}", readable(out))
    # cmd_tool._requirement, in tool_info's fields, padded to its longest label, description
    requires = field_row("requires", f"{RUNTIME} (", TOOL_INFO_LONGEST)
    out = shell(t, f"tool info {PY_TOOL}", expect=requires)
    check(
        re.search(re.escape(requires) + r"\d+ MB, not installed\)", out) is not None,
        f"tool info says {PY_TOOL} requires {RUNTIME}, not installed",
        readable(out),
    )

    s.logged = len(tool_log())
    start = t.pos
    t.type(f"tool install {PY_TOOL}\r")
    # toolhooks.install_tool: the runtime first, then the tool
    found = t.wait(RUNTIME_INSTALLED, "the runtime's installed line", timeout=300)
    note(found[0])
    t.wait(ok(f"{PY_TOOL} {PY_VERSION} installed"), "the tool's installed line", timeout=300)
    # toolinstall._show: an info line, indented
    t.wait(f"{INDENT}run   {PY_TOOL}   from any terminal", "the run line")
    t.wait(PROMPT, "the prompt after tool install")
    out = t.text()[start : t.pos]
    check(not any(line.startswith(("warn  ", "fail  ")) for line in lines_of(out)), "tool install printed no warn or fail line", readable(out))
    check((BIN / PY_TOOL).is_file(), f"{BIN / PY_TOOL} exists")
    check(not (BIN / RUNTIME).exists() and not list(BIN.glob("python*")), f"the runtime put nothing in {BIN}", repr(sorted(p.name for p in BIN.iterdir())))
    py_runs_on_runtime()

    listed = installed_list()
    check(listed.get(PY_TOOL, {}).get("requires") == [RUNTIME], f"installed.toml records that {PY_TOOL} requires {RUNTIME}", repr(listed))
    check(listed.get(RUNTIME, {}).get("commands") == [], f"installed.toml records {RUNTIME} with no commands", repr(listed))
    records = {r["name"]: r for r in read_toml(s.folder / "box.toml").get("tools", [])}
    wanted = {"name": RUNTIME, "version": RUNTIME_VERSION, "build": RUNTIME_BUILD, "sha256": s.runtime_sha256}
    check(
        records.get(PY_TOOL, {}).get("runtime") == wanted and RUNTIME not in records,
        f"box.toml records {PY_TOOL} with its runtime, and no row for the runtime itself",
        repr(records),
    )
    logged_since(
        s, s.logged,
        [("install", RUNTIME_PACKAGE), ("install", PY_PACKAGE)],
        f"{TOOL_LOG} has an install line for {RUNTIME}, then one for {PY_TOOL}",
    )
    mode = stat.S_IMODE(TOOL_LOG.stat().st_mode)
    check(mode == 0o600, f"{TOOL_LOG} has mode 600", oct(mode))

    out = shell(t, "tool list", expect=PY_TOOL)
    check(RUNTIME not in out, f"tool list does not show {RUNTIME} once it is installed", readable(out))
    # cmd_tool.tool_history: tool, version, installed (date and time), removed, runtime
    out = shell(t, "tool history", expect=PY_TOOL)
    rows = [line.split() for line in lines_of(out)]
    check(
        any(row[:2] == [PY_TOOL, f"{PY_VERSION}-{PY_BUILD}"] and row[4:] == ["-", RUNTIME, f"{RUNTIME_VERSION}-{RUNTIME_BUILD}"] for row in rows)
        and any(row[:2] == [TOOL, f"{TOOL_VERSION}-{TOOL_BUILD}"] and row[4:] == ["-", "-"] for row in rows),
        f"tool history shows {TOOL}, and {PY_TOOL} on {RUNTIME}",
        readable(out),
    )


REPORT_PACKAGE = f"{REPORT} {REPORT_VERSION}-{REPORT_BUILD}"
REPORT_LINE = f"{REPORT_COMMAND} {REPORT_VERSION}"


def step_report_tool(s: State) -> None:
    t = s.prompt
    s.logged = len(tool_log())
    start = t.pos
    t.type(f"tool install {REPORT}\r")
    # the runtime is in place already, for hello-py
    t.wait(ok(f"{REPORT} {REPORT_VERSION} installed"), "the report tool's installed line", timeout=300)
    t.wait(f"{INDENT}run   {REPORT_COMMAND}   from any terminal", "the report tool's run line")
    t.wait(PROMPT, "the prompt after tool install")
    out = t.text()[start : t.pos]
    check(not any(line.startswith(("warn  ", "fail  ")) for line in lines_of(out)), "tool install printed no warn or fail line", readable(out))
    check(RUNTIME_INSTALLED.search(out) is None, f"{RUNTIME} was not installed again", readable(out))
    tool_runs(f"{REPORT_COMMAND} --version", REPORT_LINE)
    logged_since(s, s.logged, [("install", REPORT_PACKAGE)], f"{TOOL_LOG} has an install line for {REPORT}")


def report_built(folder: Path) -> None:
    """The report finish built: pwn-report's files, and its SHA256SUMS holds."""
    names = sorted(p.name for p in folder.iterdir()) if folder.is_dir() else []
    check({"report.md", "report.json", "report.toml", "SHA256SUMS"} <= set(names), f"{folder} holds the report", repr(names))
    sums = (folder / "SHA256SUMS").read_text(encoding="utf-8").splitlines() if "SHA256SUMS" in names else []
    rows = [line.split("  ", 1) for line in sums]
    wrong = [
        row for row in rows
        if len(row) != 2 or hashlib.sha256((folder / row[1]).read_bytes()).hexdigest() != row[0]
    ]  # fmt: skip
    check(rows and not wrong, f"{folder}'s SHA256SUMS holds for its {len(rows)} files", repr(wrong or sums))
    check(not list(WRAPPED.glob(f".{folder.name}.tmp-*")), f"no staging folder is left beside {folder}")


# toolhooks.summary: the box's tools in the order they were installed, one per row with the
# label on the first (toolhooks._one_per_row), then the runtimes freed; each row a line of its own
TOOLS_SUMMARY = [
    whole_line(field_row("tools", f"{TOOL} {TOOL_VERSION}   (will be removed)", SUMMARY_LONGEST)),
    whole_line(field_row("", f"{PY_TOOL} {PY_VERSION}   (will be removed)", SUMMARY_LONGEST)),
    whole_line(field_row("", f"{REPORT} {REPORT_VERSION}   (will be removed)", SUMMARY_LONGEST)),
]
# lifecycle.finish_box: its own row after the archive's, before the hooks' rows
REPORT_SUMMARY = whole_line(field_row("report", "will be built beside the archive", SUMMARY_LONGEST))
# reportflow.build: a field of its own, then pwn-report's result as an ok line
REPORT_BUILDING = whole_line(field_row("report", "building beside the archive", "report"))
RUNTIMES_SUMMARY = whole_line(field_row("runtimes", f"{RUNTIME} {RUNTIME_VERSION}   (will be removed)", SUMMARY_LONGEST))
# hostflow.summary
HOSTS_SUMMARY = whole_line(field_row("hosts", "1 line to remove from /etc/hosts", SUMMARY_LONGEST))
# toolhooks.remove_idle_runtimes
RUNTIME_REMOVED = ok(f"{RUNTIME} {RUNTIME_VERSION} removed (runtime)")
# lifecycle.finish_box: the line in place of the folder removed line, when the window is left
WINDOW_LEFT = warn("the note window did not close; the folder was kept")


def summary(t: Terminal, s: State | None = None) -> None:
    """lifecycle.finish_box's summary, in its order: box, targets, files, archive, report, then the hooks' rows."""
    if s is not None:
        t.wait(whole_line(field_row("box", f"{BOX} ({PLATFORM}), started {s.day}", SUMMARY_LONGEST)), "the summary's box line")
    t.wait(REPORT_SUMMARY, "the summary's report line")
    for n, row in enumerate(TOOLS_SUMMARY, 1):
        t.wait(row, f"the summary's tools row {n}")
    t.wait(RUNTIMES_SUMMARY, "the summary's runtimes line")
    t.wait(HOSTS_SUMMARY, "the summary's hosts line")
# toolhooks.undo: each tool in the box's order, then the runtime no tool requires any more
FINISHED = [
    ("finish", f"{TOOL} {TOOL_VERSION}-{TOOL_BUILD}"),
    ("finish", PY_PACKAGE),
    ("finish", REPORT_PACKAGE),
    ("finish", RUNTIME_PACKAGE),
]


def step_finish(s: State) -> None:
    t = s.prompt
    t.type("vpn start\r")
    t.answer(asked("vpn file", str(OVPN)), "", "the vpn file question with the last file")
    t.wait(ok("copied to vpn/test.ovpn"), "the copied line")
    t.wait(ok(f"vpn up, {VPN_ADDRESS} on tun0"), "the vpn up line", timeout=60)
    t.wait(PROMPT, "the prompt after vpn start")

    s.logged = len(tool_log())
    start = t.pos
    t.type("finish\r")
    # lifecycle.finish_box's summary, then the hooks' lines: toolhooks registers before kalihooks
    summary(t, s)
    t.answer(confirm("finish this box?", False), "y", "the finish question")
    found = t.wait(re.compile(re.escape(ok("archive ")) + r"(\S+\.finished\.tar\.gz)"), "the archive line")
    # reportflow.build, after the archive and before the undo steps take the report tool off
    report = WRAPPED / f"{s.folder.name}.finished.report"
    t.wait(REPORT_BUILDING, "the report building line")
    t.wait(whole_line(ok(f"report {report}")), "the report line", timeout=120)
    # toolhooks.undo removes the runtime once no tool requires it, before kalihooks' lines
    t.wait(RUNTIME_REMOVED, "the runtime removed line")
    t.wait(ok("removed 1 line from /etc/hosts"), "the hosts lines removed")
    t.answer(confirm(f"the VPN is still up ({VPN_ADDRESS}). stop it?", False), "y", "the VPN question")
    t.wait(ok("vpn stopped"), "the vpn stopped line")
    t.answer(confirm("remove working folder?", False), "y", "the remove folder question")
    # lifecycle.finish_box closes the note window, then removes the folder
    t.wait(ok(f"removed {s.folder}"), "the folder removed line")
    status = t.wait_exit("the prompt to end after finish")
    check(status == 0, "pwn-broker ended with status 0", f"status {status}")
    out = t.text()[start:]
    check(WINDOW_LEFT not in out, "finish did not say the note window was left", readable(out))
    window_closed(s, "after finish")

    check_hosts(s, s.hosts_before, "/etc/hosts is byte for byte what it was before step 3", "hosts.step18")
    wait_until(lambda: not openvpns(), "no openvpn process is left")
    wait_until(lambda: run(["ip", "link", "show", "tun0"]).returncode != 0, "tun0 is gone")
    check(not (BIN / TOOL).exists(), f"{BIN / TOOL} is gone")
    check(not (BIN / PY_TOOL).exists(), f"{BIN / PY_TOOL} is gone")
    check(not (BIN / REPORT_COMMAND).exists(), f"{BIN / REPORT_COMMAND} is gone")
    tools_left()
    logged_since(s, s.logged, FINISHED, f"{TOOL_LOG} has a finish line for {TOOL}, {PY_TOOL}, {REPORT} and {RUNTIME}")
    check(not s.folder.exists(), f"{s.folder} is gone")
    report_built(report)
    archive = s.finished = Path(found[1])
    expected = WRAPPED / f"{s.folder.name}.finished.tar.gz"
    check(archive == expected and archive.is_file(), f"the finished archive is {expected}", str(archive))
    mode_is(archive, 0o600)
    verify(archive)
    names = tar_names(archive)
    shown = "\n".join(names)
    check(not any(n.split("/")[1:2] == ["vpn"] for n in names), "the archive has no vpn/ entry", shown)
    recordings = f"{s.folder.name}/targets/{TARGET}/recordings/"
    for suffix in (".cast", ".txt"):
        check(any(n.startswith(recordings) and n.endswith(suffix) for n in names), f"the archive holds the recording's {suffix}", shown)


def step_import(s: State) -> None:
    s.logged = len(tool_log())
    # cli.start prints no header for an import
    # hostflow.on_import shows the lines the archive asks for and asks before any is written:
    # finish took them out, so they are not in place. The names are under .local, a lab domain,
    # so none is marked
    t = launch(
        "import",
        [str(BIN / "pwn-broker"), "import", str(s.finished)],
        field_row("hosts", f"{s.ip} {HOSTNAME} {LATER}", "hosts"),
        header=False,
    )
    t.answer(confirm("this box wants these lines in /etc/hosts. add them?", False), "y", "the import's /etc/hosts question")
    t.wait(field_row("tools", f"{TOOL} {TOOL_VERSION}, {PY_TOOL} {PY_VERSION}, {REPORT} {REPORT_VERSION}", RESTORE_LONGEST), "the tools row")
    # toolhooks._restore asks first and installs in the box's order, a runtime before the tool
    # that requires it; lifecycle.import_box reports after its hooks; cli.start's
    # hostflow.on_open puts the line back, then opens the note: none is open since finish closed it
    t.answer(confirm("install these tools again?", True), "y", "the install again question")
    t.wait(ok(f"{TOOL} {TOOL_VERSION} installed"), "the installed line")
    t.wait(RUNTIME_INSTALLED, "the runtime's installed line", timeout=300)
    t.wait(ok(f"{PY_TOOL} {PY_VERSION} installed"), f"{PY_TOOL}'s installed line", timeout=300)
    t.wait(ok(f"{REPORT} {REPORT_VERSION} installed"), f"{REPORT}'s installed line", timeout=300)
    t.wait(ok(f"unpacked to {s.folder}"), "the unpacked line")
    t.wait(ok("1 targets"), "the targets line")
    t.wait(ok("/etc/hosts updated"), "the /etc/hosts updated line")
    start = t.pos
    t.wait(PROMPT, "the prompt")
    check("the note is already open" not in t.text()[start : t.pos], "the import opened the note, none being open", readable(t.text()))
    found = one_note_window(s, "after the import")
    s.window = (found.pid, found.ppid)
    note(f"vim {found.pid} on the imported note; its terminal {found.ppid}")
    check((s.folder / "box.toml").is_file(), f"{s.folder} is back")
    box_is_private(s)
    check(read_toml(s.folder / "box.toml").get("status") == "active", "the box is active again")
    check_hosts(
        s,
        s.hosts_before + hosts_line(s, [HOSTNAME, LATER]),
        "/etc/hosts has the box's line again",
        "hosts.step19",
    )
    resolves(LATER, s.ip)
    tool_runs()
    py_runs_on_runtime()
    records = {r["name"]: r for r in read_toml(s.folder / "box.toml").get("tools", [])}
    check(
        records.get(PY_TOOL, {}).get("runtime", {}).get("name") == RUNTIME,
        f"box.toml still records {PY_TOOL} with {RUNTIME}",
        repr(records),
    )
    logged_since(
        s, s.logged,
        [
            ("install", f"{TOOL} {TOOL_VERSION}-{TOOL_BUILD}"), ("install", RUNTIME_PACKAGE),
            ("install", PY_PACKAGE), ("install", REPORT_PACKAGE),
        ],
        f"{TOOL_LOG} has an install line for {TOOL}, then {RUNTIME}, then {PY_TOOL}, then {REPORT}",
    )  # fmt: skip
    tool_runs(f"{REPORT_COMMAND} --version", REPORT_LINE)
    t.type("quit\r")
    t.answer(confirm(f"export {BOX} before you go?", True), "n", "the export question")
    status = t.wait_exit("the prompt to end after quit")
    check(status == 0, "pwn-broker ended with status 0", f"status {status}")


def step_last_finish(s: State) -> None:
    # cli.start: the box's note is still open from the import, so the launch opens no other
    t = launch("resume", [str(BIN / "pwn-broker"), "resume", BOX], ok("the note is already open"))
    t.wait(PROMPT, "the prompt")
    found = one_note_window(s, "after the box is opened again with its note open")
    check(
        (found.pid, found.ppid) == s.window,
        "it is the window the import opened",
        f"vim {found.pid} in {found.ppid}; the import's was {s.window}",
    )
    start = t.pos
    s.logged = len(tool_log())
    t.type("finish\r")
    summary(t, s)
    t.answer(confirm("finish this box?", False), "y", "the finish question")
    t.answer(confirm("replace the existing archive?", False), "y", "the replace archive question")
    found = t.wait(re.compile(re.escape(ok("archive ")) + r"(\S+\.finished\.tar\.gz)"), "the archive line")
    # the first finish's report is never replaced: this one goes beside it
    first, report = (WRAPPED / f"{s.folder.name}.finished.{suffix}" for suffix in ("report", "report-2"))
    t.wait(REPORT_BUILDING, "the report building line")
    t.wait(whole_line(ok(f"report {report}")), "the second report's line", timeout=120)
    t.wait(RUNTIME_REMOVED, "the runtime removed line")
    t.wait(ok("removed 1 line from /etc/hosts"), "the hosts lines removed")
    t.answer(confirm("remove working folder?", False), "y", "the remove folder question")
    t.wait(ok(f"removed {s.folder}"), "the folder removed line")
    status = t.wait_exit("the prompt to end after finish")
    check(status == 0, "pwn-broker ended with status 0", f"status {status}")
    out = t.text()[start:]
    # kalihooks.vpn_question asks only while the app's VPN runs; none was started since step 18
    check("stop it?" not in out, "finish asked no VPN question", readable(out))
    check(WINDOW_LEFT not in out, "finish did not say the note window was left", readable(out))
    window_closed(s, "after the last finish")
    check(not openvpns(), "no openvpn process is running", repr(openvpns()))
    archive = Path(found[1])
    check(archive == s.finished and archive.is_file(), f"the replaced finished archive is {s.finished}", str(archive))
    verify(archive)
    check_hosts(s, s.hosts_before, "/etc/hosts matches the original bytes once more", "hosts.step20")
    tools_left()
    check(not (BIN / TOOL).exists(), f"{BIN / TOOL} is gone")
    check(not (BIN / PY_TOOL).exists(), f"{BIN / PY_TOOL} is gone")
    check(not (BIN / REPORT_COMMAND).exists(), f"{BIN / REPORT_COMMAND} is gone")
    logged_since(s, s.logged, FINISHED, f"{TOOL_LOG} has a finish line for {TOOL}, {PY_TOOL}, {REPORT} and {RUNTIME} again")
    check(not s.folder.exists(), f"{s.folder} is gone")
    report_built(report)
    report_built(first)

    # finish closed each note window it removed the folder of: no vim with the app's vimrc is left
    windows = [
        p for p in processes()
        if p.argv and Path(p.argv[0]).name == "vim" and "-u" in p.argv and str(VIMRC) in p.argv
    ]  # fmt: skip
    check(
        not windows,
        "no note window is open at the end",
        "\n".join(f"vim {p.pid} ({p.state}) on {p.argv[-1]}" for p in windows),
    )


STEPS = [
    (0, "setup", prepare),
    (1, "launch and checks", step_launch),
    (2, "new box and target", step_new_box),
    (3, "the /etc/hosts question", step_hosts),
    (4, "the ping", step_ping),
    (5, "box created, note window", step_box_created),
    (6, "a credential", step_cred),
    (7, "a hostname found later", step_host_add),
    (8, "recording", step_record),
    (9, "the prompt while recording", step_while_recording),
    (10, "export while recording", step_export),
    (11, "close the window", step_close_recording),
    (12, "replay", step_replay),
    (13, "vpn", step_vpn),
    (14, "vpn survives the prompt's terminal", step_vpn_daemon),
    (15, "a tool", step_tool),
    (16, "a Python tool on a real runtime", step_python_tool),
    (17, "the report tool, pwn-shop's own package", step_report_tool),
    (18, "finish, with a report", step_finish),
    (19, "import", step_import),
    (20, "leftovers at the next launch, a second report", step_last_finish),
]


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--evidence", required=True, type=Path)
    parser.add_argument("--runtime-archive", required=True, type=Path, help="the checked upstream Python build")
    parser.add_argument("--report-package", required=True, type=Path, help="pwn-shop's report package, checked")
    args = parser.parse_args()
    global EVIDENCE
    EVIDENCE = Evidence(args.evidence)
    state = State()
    state.runtime_archive = args.runtime_archive
    state.report_package = args.report_package
    status = 0
    try:
        for number, title, step in STEPS:
            log(f"---- step {number}, {title}")
            try:
                step(state)
            except Failed as exc:
                EVIDENCE.result(number, title, str(exc))
                status = 1
                break
            except Exception:
                EVIDENCE.result(number, title, traceback.format_exc())
                status = 1
                break
            EVIDENCE.result(number, title, None)
            for term in TERMINALS:
                term.save()
    finally:
        for term in TERMINALS:
            term.pump(0.2)
            term.save()
            term.kill()
        EVIDENCE.close()
    return status


if __name__ == "__main__":
    sys.exit(main())
