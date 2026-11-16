import pytest

from helpers import NOW, make_cred
from pwn_broker import notewindow as _notewindow
from pwn_broker.model import Box
from pwn_broker.paths import AppPaths
from pwn_broker.store import save_box

# the real listing of the current user's processes, for the one test of it
REAL_OWN_PROCESSES = _notewindow._own_processes

__all__ = ["NOW", "make_cred"]


@pytest.fixture
def paths(tmp_path):
    return AppPaths(opt=tmp_path / "opt", home=tmp_path / "home")


@pytest.fixture
def box(paths):
    folder = paths.active / "2026-11-14_htb_forest"
    folder.mkdir(parents=True)
    value = Box(
        id="2026-11-14_htb_forest",
        name="forest",
        platform="htb",
        os="windows",
        difficulty="easy",
        status="active",
        started=NOW,
        finished=None,
        last_target=None,
        flags={},
        extra={},
        path=folder,
    )
    save_box(value)
    return value


@pytest.fixture
def other(paths):
    from pwn_broker.boxes import create_box

    return create_box(
        paths,
        name="Cascade",
        platform="htb",
        day=NOW.date(),
        os_name="windows",
        difficulty="medium",
        now=NOW,
        new_id=lambda: "id-other",
    )


@pytest.fixture
def dc01(box):
    from pwn_broker.boxes import add_target

    return add_target(
        box, [], ips=["10.10.10.161"], hostnames=["forest.htb.local"],
        scope="external", name="dc01", now=NOW,
    )  # fmt: skip


class System:
    """What test sessions use in place of /etc/hosts, root, sudo and ping."""

    def __init__(self, make_folder):
        self._make_folder = make_folder
        self._hosts_path = None
        self.root = True
        self.privileged: list[list[str]] = []
        self.privileged_status = 1
        self.pings: list[str] = []
        from pwn_broker.ping import Result

        self.answer = Result(True, 1.0, True)
        # the tunnel the stand-in reports; None means no VPN is up
        self.tunnel_found = None
        self.tunnel_reads = 0
        # the paths each asciinema download was asked for; none ever reaches the network
        self.fetches: list = []
        # programs `which` finds, by name; openvpn is not installed unless a test says so
        self.programs: dict[str, str] = {}
        self.sleeps: list[float] = []
        # the process table the VPN and recording checks see: pid to (start time, command name)
        self.processes: dict[int, tuple[str, str]] = {}

    @property
    def hosts_path(self):
        # made on first use, so a test that never builds a session gets no extra folder
        if self._hosts_path is None:
            self._hosts_path = self._make_folder() / "hosts"
            self._hosts_path.write_bytes(b"127.0.0.1 localhost\n")
        return self._hosts_path

    def is_root(self) -> bool:
        return self.root

    def run_privileged(self, argv):
        import subprocess

        self.privileged.append(list(argv))
        return subprocess.CompletedProcess(argv, self.privileged_status)

    def tunnel(self):
        # the real reader runs `ip`; no test may
        self.tunnel_reads += 1
        return self.tunnel_found

    def fetch(self, paths):
        # the real one downloads; this one only notes the call
        self.fetches.append(paths)

    def which(self, name):
        return self.programs.get(name)

    def sleep(self, seconds):
        # never sleeps for real
        self.sleeps.append(seconds)

    def pid_alive(self, pid):
        return pid in self.processes

    def pid_started(self, pid):
        return self.processes[pid][0] if pid in self.processes else None

    def vpn_comm(self, pid):
        return self.processes[pid][1] if pid in self.processes else None

    def ping(self, ip):
        self.pings.append(ip)
        if isinstance(self.answer, BaseException):
            raise self.answer
        return self.answer


@pytest.fixture(autouse=True)
def system(tmp_path_factory, monkeypatch):
    """Every session a test builds, however it is built, starts on these stand-ins."""
    from dataclasses import fields

    from pwn_broker.session import Session

    fake = System(lambda: tmp_path_factory.mktemp("etc"))

    def refuse_asciinema(*args, **kwargs):
        raise AssertionError("a test reached the real asciinema; pass a run or play stand-in")

    defaults = {f.name: f.default for f in fields(Session)}
    original = Session.__init__

    def safe_init(self, *args, **kwargs):
        original(self, *args, **kwargs)
        # an equal path is the same file, so it is compared by value
        if self.hosts_path == defaults["hosts_path"]:
            self.hosts_path = fake.hosts_path
        for name in (
            "is_root", "run_privileged", "ping", "tunnel", "fetch",
            "which", "sleep", "pid_alive", "pid_started", "vpn_comm",
        ):  # fmt: skip
            if getattr(self, name) is defaults[name]:
                setattr(self, name, getattr(fake, name))
        if self.play is defaults["play"]:
            self.play = refuse_asciinema

    monkeypatch.setattr(Session, "__init__", safe_init)

    from pwn_broker.cli import Env

    env_defaults = {f.name: f.default for f in fields(Env)}
    env_original = Env.__init__

    def safe_env_init(self, *args, **kwargs):
        env_original(self, *args, **kwargs)
        if self.hosts_path == env_defaults["hosts_path"]:
            self.hosts_path = fake.hosts_path
        for name in ("is_root", "run_privileged", "tunnel", "fetch"):
            if getattr(self, name) is env_defaults[name]:
                setattr(self, name, getattr(fake, name))

    monkeypatch.setattr(Env, "__init__", safe_env_init)

    from pwn_broker import record

    record_defaults = {f.name: f.default for f in fields(record.Env)}
    record_original = record.Env.__init__

    def safe_record_init(self, *args, **kwargs):
        record_original(self, *args, **kwargs)
        if self.hosts_path == record_defaults["hosts_path"]:
            self.hosts_path = fake.hosts_path
        for name in ("is_root", "run_privileged", "ping", "tunnel"):
            if getattr(self, name) is record_defaults[name]:
                setattr(self, name, getattr(fake, name))
        if self.run is record_defaults["run"]:
            self.run = refuse_asciinema

    monkeypatch.setattr(record.Env, "__init__", safe_record_init)
    return fake


@pytest.fixture
def session(paths, box, dc01, system):
    from datetime import timedelta
    from importlib import resources

    from pwn_broker.config import Settings
    from pwn_broker.console import FakeConsole
    from pwn_broker.note import render_note, write_note
    from pwn_broker.session import Session

    template = resources.files("pwn_broker.data").joinpath("notes.md").read_text(encoding="utf-8")
    write_note(box, render_note(template, box, [dc01]))
    later = NOW + timedelta(hours=1)
    return Session(
        paths, Settings(), FakeConsole(), box, [dc01], [], dc01, lambda: later,
        hosts_path=system.hosts_path, is_root=lambda: True,
        run_privileged=system.run_privileged, ping=system.ping, tunnel=system.tunnel,
    )  # fmt: skip


@pytest.fixture
def ran():
    return []


@pytest.fixture
def env(paths, tmp_path, ran):
    from pwn_broker.cli import Env
    from pwn_broker.config import Settings
    from pwn_broker.console import FakeConsole

    return Env(
        paths=paths,
        settings=Settings(),
        console=FakeConsole(),
        clock=lambda: NOW,
        environ={"DISPLAY": ":0", "PATH": str(paths.bin)},
        cwd=tmp_path,
        pid=4242,
        home=tmp_path / "user",
        run=ran.append,
    )


@pytest.fixture(autouse=True)
def no_real_ip(monkeypatch):
    """vpn.tunnel without a `run` of its own would run `ip`; make that an error."""
    from pwn_broker import vpn

    def refuse(*args, **kwargs):
        raise AssertionError("a test reached the real `ip`; pass a tunnel reader or a run")

    monkeypatch.setattr(vpn.tunnel, "__defaults__", (refuse,))


@pytest.fixture(autouse=True)
def no_real_download(monkeypatch):
    """recorder.fetch's own default would download asciinema; make that an error."""
    from pwn_broker import recorder

    def refuse(*args, **kwargs):
        raise AssertionError("a test reached the network; pass a download stand-in")

    monkeypatch.setattr(recorder.fetch, "__kwdefaults__", {**recorder.fetch.__kwdefaults__, "download": refuse})


@pytest.fixture(autouse=True)
def no_real_vpn(monkeypatch):
    """vpnctl's own defaults would start openvpn, signal or read real processes and sleep."""
    from pwn_broker import vpnctl

    def refuse(*args, **kwargs):
        raise AssertionError("a test reached a real process, openvpn or sleep; pass a stand-in")

    for name in ("pid_alive", "process_start", "process_comm"):
        monkeypatch.setattr(vpnctl, name, refuse)
    for function in (vpnctl.start, vpnctl.stop):
        defaults = dict(function.__kwdefaults__)
        for name in ("run", "sleep", "which"):
            if name in defaults:
                defaults[name] = refuse
        monkeypatch.setattr(function, "__kwdefaults__", defaults)


@pytest.fixture(autouse=True)
def no_real_processes(monkeypatch):
    """No test finds, or signals, a real process: the listing of them is empty unless a test gives one."""
    from pwn_broker import notewindow

    monkeypatch.setattr(notewindow, "_own_processes", lambda: [])

    def refuse(*args, **kwargs):
        raise AssertionError("a test reached a real signal or sleep; pass a kill and sleep stand-in")

    defaults = dict(notewindow.close_note.__kwdefaults__)
    defaults.update(kill=refuse, sleep=refuse)
    monkeypatch.setattr(notewindow.close_note, "__kwdefaults__", defaults)
