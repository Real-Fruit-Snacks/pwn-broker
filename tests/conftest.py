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


@pytest.fixture
def session(paths, box, dc01):
    from datetime import timedelta
    from importlib import resources

    from pwn_broker.config import Settings
    from pwn_broker.console import FakeConsole
    from pwn_broker.note import render_note, write_note
    from pwn_broker.session import Session

    template = resources.files("pwn_broker.data").joinpath("notes.md").read_text(encoding="utf-8")
    write_note(box, render_note(template, box, [dc01]))
    later = NOW + timedelta(hours=1)
    return Session(paths, Settings(), FakeConsole(), box, [dc01], [], dc01, lambda: later)
