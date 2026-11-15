import pytest

from helpers import NOW, make_cred
from pwn_broker.model import Box
from pwn_broker.paths import AppPaths
from pwn_broker.store import save_box

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
    defaults = {f.name: f.default for f in fields(Session)}
    original = Session.__init__

    def safe_init(self, *args, **kwargs):
        original(self, *args, **kwargs)
        for name in ("hosts_path", "is_root", "run_privileged", "ping"):
            if getattr(self, name) is defaults[name]:
                setattr(self, name, getattr(fake, name))

    monkeypatch.setattr(Session, "__init__", safe_init)
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
        run_privileged=system.run_privileged, ping=system.ping,
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
