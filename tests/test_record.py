import io
import os
import subprocess
import sys
from datetime import datetime, timedelta
from pathlib import Path

import pytest

from casts import TZ, cast_text, write_cast
from helpers import NOW
from pwn_broker import boxes, boxlock, privilege, record, recorder
from pwn_broker.boxes import add_target
from pwn_broker.config import Settings
from pwn_broker.console import FakeConsole, TermConsole
from pwn_broker.note import read_note
from pwn_broker.ping import Result
from pwn_broker.record import cast_path
from pwn_broker.session import load_session, mark_seen, refresh, reload_if_changed
from pwn_broker.store import load_box, load_targets, save_box

START = datetime(2026, 11, 14, 14, 32, 7, tzinfo=TZ)


class Clock:
    def __init__(self, now):
        self.now = now

    def __call__(self):
        return self.now


class Asciinema:
    """Stands in for `asciinema rec`: notes what it was given and writes a small cast."""

    def __init__(self, paths, clock, *, status=0, minutes=14, raises=None, writes=True):
        self.paths = paths
        self.clock = clock
        self.status = status
        self.minutes = minutes
        self.raises = raises
        self.writes = writes
        self.calls = []
        self.markers = []

    def __call__(self, argv, **kwargs):
        self.calls.append((argv, kwargs))
        folder = self.paths.run_recordings
        self.markers = {p.name: p.read_text(encoding="utf-8") for p in folder.iterdir()} if folder.is_dir() else {}
        if self.writes:
            write_cast(Path(argv[-1]), [(0.5, "o", "$ whoami\r\nroot\r\n")])
        self.clock.now += timedelta(minutes=self.minutes)
        if self.raises is not None:
            raise self.raises
        return subprocess.CompletedProcess(argv, self.status)


@pytest.fixture
def clock():
    return Clock(START)


@pytest.fixture
def asciinema(paths, clock):
    return Asciinema(paths, clock)


@pytest.fixture
def opened(paths, box):
    # the prompt has the box open; its process is alive as far as the tests' `alive` says
    boxes.acquire_open(paths, box, pid=999, alive=lambda pid: False)
    return box


@pytest.fixture
def web01(box, dc01):
    return add_target(
        box, [dc01], ips=["10.10.10.5"], hostnames=["Board.htb"],
        scope="external", name="web01", now=NOW,
    )  # fmt: skip


@pytest.fixture
def make_env(paths, clock, asciinema, tmp_path):
    def make(answers=(), **overrides):
        values = dict(
            paths=paths,
            settings=Settings(),
            console=FakeConsole(list(answers)),
            clock=clock,
            environ={"SHELL": "/bin/zsh", "HOME": str(tmp_path / "user"), "PATH": "/usr/bin"},
            pid=4242,
            run=asciinema,
            start_of=lambda pid: "777",
            alive=lambda pid: pid == 999,
            owner=lambda path: None,
            present=lambda paths: True,
        )
        values.update(overrides)
        return record.Env(**values)

    return make


def fails(env):
    return [text for kind, text in env.console.lines if kind == "fail"]


# -- refusals --


def test_more_than_one_argument_is_usage(make_env, asciinema):
    env = make_env()
    assert record.run(env, ["dc01", "web01"]) == 2
    assert fails(env) == ["usage: record [target]"]
    assert asciinema.calls == []


def test_another_user_is_refused(make_env, opened, dc01, asciinema):
    seen = []
    env = make_env(owner=lambda path: seen.append(path) or "kali")
    assert record.run(env, []) == 1
    assert env.console.lines == [
        ("fail", "record must run as kali, the user who installed pwn-broker. run record first, then sudo inside it")
    ]
    assert seen == [env.paths.opt]
    assert asciinema.calls == []


def test_a_window_that_is_already_recording_is_refused(make_env, opened, dc01, asciinema):
    env = make_env(environ={"SHELL": "/bin/zsh", "PWN_BROKER_RECORDING": "web01"})
    assert record.run(env, []) == 1
    assert env.console.lines == [("fail", "this window is already recording for web01")]
    assert asciinema.calls == []


def test_no_open_box_records_nothing(make_env, box, dc01, asciinema):
    env = make_env()
    assert record.run(env, []) == 1
    assert env.console.lines == [("fail", "no box is open; nothing is recorded")]
    assert asciinema.calls == []


def test_a_box_whose_prompt_has_gone_is_not_open(make_env, opened, dc01, asciinema):
    env = make_env(alive=lambda pid: False)
    assert record.run(env, []) == 1
    assert env.console.lines == [("fail", "no box is open; nothing is recorded")]


def test_a_missing_asciinema_starts_nothing(make_env, opened, dc01, asciinema):
    env = make_env(present=lambda paths: False)
    assert record.run(env, []) == 1
    assert env.console.lines == [
        ("fail", "asciinema is missing or does not match its checksum; run the installer again")
    ]
    assert asciinema.calls == []


def test_a_box_with_no_targets(make_env, opened, asciinema):
    env = make_env()
    assert record.run(env, []) == 1
    assert env.console.lines == [("fail", "this box has no targets; add one in the prompt with: target add")]
    assert asciinema.calls == []


def test_a_box_that_cannot_be_read(make_env, opened, dc01, asciinema):
    (opened.path / "box.toml").write_text("this is [not toml", encoding="utf-8")
    env = make_env()
    assert record.run(env, []) == 1
    assert len(fails(env)) == 1 and "box.toml" in fails(env)[0]
    assert asciinema.calls == []


def test_a_prefix_of_more_than_one_target_is_refused(make_env, opened, dc01, box, asciinema):
    add_target(box, [dc01], ips=["10.10.10.9"], hostnames=[], scope="external", name="dc02", now=NOW)
    env = make_env()
    assert record.run(env, ["dc"]) == 1
    assert fails(env) == ["dc matches more than one target: dc01, dc02"]
    assert asciinema.calls == []


def test_an_address_of_more_than_one_target_is_refused(make_env, opened, dc01, box, asciinema):
    add_target(box, [dc01], ips=["10.10.10.161"], hostnames=[], scope="external", name="dc01-ldap", now=NOW)
    env = make_env()
    assert record.run(env, ["10.10.10.161"]) == 1
    assert fails(env) == ["10.10.10.161 is an address of more than one target: dc01, dc01-ldap; name one"]
    assert asciinema.calls == []


# -- which target --


def recorded_for(env):
    first = env.console.lines[0]
    assert first[0] == "ok", env.console.lines
    return first[1]


@pytest.mark.parametrize(
    "given, expected",
    [
        ("web01", "web01"),
        ("10.10.10.5", "web01"),
        ("board.htb", "web01"),
        ("BOARD.HTB", "web01"),
        ("we", "web01"),
        ("forest.htb.local", "dc01"),
        ("dc", "dc01"),
    ],
)
def test_the_target_is_found_by_name_ip_hostname_or_prefix(make_env, opened, web01, given, expected, asciinema):
    env = make_env()
    assert record.run(env, [given]) == 0
    assert recorded_for(env) == f"recording this window for {expected} (forest)"
    assert Path(asciinema.calls[0][0][-1]).parent == opened.path / "targets" / expected / "recordings"


def test_an_exact_address_wins_over_a_prefix_of_a_name(make_env, opened, web01, box, asciinema):
    add_target(box, [], ips=["10.10.10.50"], hostnames=[], scope="external", name="10.10.10.50", now=NOW)
    env = make_env()
    assert record.run(env, ["10.10.10.5"]) == 0
    assert recorded_for(env) == "recording this window for web01 (forest)"


def test_no_argument_records_for_the_last_target(make_env, opened, web01, asciinema):
    box = load_box(opened.path)
    box.last_target = "web01"
    save_box(box)
    env = make_env()
    assert record.run(env, []) == 0
    assert recorded_for(env) == "recording this window for web01 (forest)"


def test_no_argument_and_no_last_target_records_for_the_first(make_env, opened, web01, asciinema):
    env = make_env()
    assert record.run(env, []) == 0
    assert recorded_for(env) == "recording this window for dc01 (forest)"


# -- an address that is not a target --


def test_declining_to_add_records_nothing(make_env, opened, dc01, asciinema):
    env = make_env(["n"])
    assert record.run(env, ["10.10.10.200"]) == 1
    assert env.console.asked == ["10.10.10.200 is not a target of forest. add it?"]
    assert [t.name for t in load_targets(opened)] == ["dc01"]
    assert asciinema.calls == []


def test_the_question_defaults_to_no(make_env, opened, dc01, asciinema):
    env = make_env([""])
    assert record.run(env, ["10.10.10.200"]) == 1
    assert [t.name for t in load_targets(opened)] == ["dc01"]


def test_ctrl_c_at_a_question_creates_nothing(make_env, opened, dc01, asciinema):
    # yes, the IP and the hostname, then Ctrl-C at the scope
    env = make_env(["y", "", ""])
    assert record.run(env, ["10.10.10.200"]) == 1
    assert env.console.lines == [("heading", "New target"), ("info", "cancelled")]
    assert [t.name for t in load_targets(opened)] == ["dc01"]
    assert not (opened.path / "targets" / "10.10.10.200").exists()
    assert asciinema.calls == []


def test_an_unknown_ip_is_added_then_recorded(make_env, opened, dc01, asciinema, system):
    env = make_env(["y", "", "", "", ""])
    assert record.run(env, ["10.10.10.200"]) == 0
    assert env.console.asked == [
        "10.10.10.200 is not a target of forest. add it?", "ip", "hostname", "scope", "name",
    ]  # fmt: skip
    again = load_targets(load_box(opened.path))
    added = next(t for t in again if t.name == "10.10.10.200")
    assert added.ips == ["10.10.10.200"] and added.hostnames == []
    assert ("ok", "target 10.10.10.200 created") in env.console.lines
    assert system.pings == ["10.10.10.200"]
    assert recorded_for_after_add(env) == "recording this window for 10.10.10.200 (forest)"
    assert (opened.path / "targets" / "10.10.10.200" / "recordings").is_dir()


def recorded_for_after_add(env):
    return next(text for kind, text in env.console.lines if text.startswith("recording this window"))


def test_an_unknown_hostname_is_prefilled_as_the_hostname(make_env, opened, dc01, asciinema, system):
    env = make_env(["y", "", "", "", ""])
    assert record.run(env, ["crm.board.htb"]) == 0
    added = next(t for t in load_targets(load_box(opened.path)) if t.name == "crm.board.htb")
    assert added.ips == [] and added.hostnames == ["crm.board.htb"]
    assert system.pings == []


def test_an_added_target_may_not_take_another_targets_hostname(make_env, opened, dc01, asciinema, system):
    # yes, the IP as given, dc01's hostname typed in, scope and name
    env = make_env(["y", "", "Forest.htb.local", "", "new"])
    assert record.run(env, ["10.10.10.200"]) == 1
    assert fails(env) == ["could not add the target: Forest.htb.local is already a hostname of dc01"]
    assert [t.name for t in load_targets(load_box(opened.path))] == ["dc01"]
    assert not (opened.path / "targets" / "new").exists()
    assert asciinema.calls == [] and system.pings == []


def test_an_added_target_goes_through_the_hosts_offer(make_env, opened, dc01, asciinema, system):
    # yes, the IP as given, a hostname typed in, scope and name, then yes to /etc/hosts
    env = make_env(["y", "", "new.htb", "", "new", "y"])
    assert record.run(env, ["10.10.10.200"]) == 0
    assert "add new's hostnames to /etc/hosts?" in env.console.asked
    assert "10.10.10.200 new.htb" in system.hosts_path.read_text(encoding="utf-8")
    assert load_box(opened.path).hosts == ["new"]


def test_a_target_added_by_record_is_seen_by_the_prompt(make_env, paths, opened, dc01, asciinema):
    # the prompt read the box before record added a target to it, and must see the new target
    prompt = load_session(paths, Settings(), FakeConsole(), load_box(opened.path), lambda: NOW)
    write_note(prompt)
    prompt.box.last_target = "dc01"
    save_box(prompt.box)
    mark_seen(prompt)
    env = make_env(["y", "", "", "", ""])
    assert record.run(env, ["10.10.10.200"]) == 0

    # a second load sees the target, its note row and its list entry
    second = load_session(paths, Settings(), FakeConsole(), load_box(opened.path), lambda: NOW)
    assert [t.name for t in second.targets] == ["dc01", "10.10.10.200"]
    assert "10.10.10.200" in read_note(second.box)
    assert "10.10.10.200" in (opened.path / "lists" / "ips.txt").read_text(encoding="utf-8")
    # the prompt's current target is unchanged
    assert second.box.last_target == "dc01"

    # the prompt's next command reloads, and its own refresh keeps the row and the address
    assert reload_if_changed(prompt) is True
    assert prompt.current.name == "dc01"
    refresh(prompt)
    assert "10.10.10.200" in read_note(prompt.box)
    assert "10.10.10.200" in (opened.path / "lists" / "ips.txt").read_text(encoding="utf-8")


def write_note(session):
    from importlib import resources

    from pwn_broker.note import render_note, write_note as write

    template = resources.files("pwn_broker.data").joinpath("notes.md").read_text(encoding="utf-8")
    write(session.box, render_note(template, session.box, session.targets))


def test_a_held_lock_adds_nothing_and_records_nothing(make_env, opened, dc01, asciinema, monkeypatch):
    real = boxlock.held
    waits = []

    def held(paths, *, wait):
        # the real lock, without the real five-second wait
        waits.append(wait)
        return real(paths, wait=0)

    monkeypatch.setattr(record.boxlock, "held", held)
    env = make_env(["y", "", "", "", ""])
    with real(env.paths, wait=0):
        assert record.run(env, ["10.10.10.200"]) == 1
    assert waits == [5]
    assert fails(env) == ["the prompt is in the middle of a command; wait for it to end, then run record again"]
    assert [t.name for t in load_targets(opened)] == ["dc01"]
    assert not (opened.path / "targets" / "10.10.10.200").exists()
    assert asciinema.calls == []


def test_a_lock_file_that_cannot_be_used(make_env, opened, dc01, asciinema, monkeypatch):
    def held(paths, *, wait):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(record.boxlock, "held", held)
    env = make_env(["y", "", "", "", ""])
    assert record.run(env, ["10.10.10.200"]) == 1
    assert len(fails(env)) == 1
    assert "lock" in fails(env)[0] and "Permission denied" in fails(env)[0]
    assert asciinema.calls == []


def test_a_name_taken_while_waiting_for_the_lock(make_env, opened, dc01, asciinema, monkeypatch):
    real = boxlock.held

    def held(paths, *, wait):
        # the prompt adds a target of the same name just before record gets the lock
        add_target(load_box(opened.path), [], ips=["10.10.10.201"], hostnames=[], scope="external",
                   name="10.10.10.200", now=NOW)  # fmt: skip
        return real(paths, wait=wait)

    monkeypatch.setattr(record.boxlock, "held", held)
    env = make_env(["y", "", "", "", ""])
    assert record.run(env, ["10.10.10.200"]) == 1
    assert fails(env) == ["could not add the target: a target named 10.10.10.200 already exists"]
    assert asciinema.calls == []


# -- the recording --


def test_the_marker_is_there_while_asciinema_runs_and_gone_after(make_env, opened, dc01, asciinema):
    env = make_env()
    assert record.run(env, []) == 0
    cast = opened.path / "targets" / "dc01" / "recordings" / "2026-11-14_1432.cast"
    assert asciinema.markers == {"4242": f"777\ndc01\n{cast}\n"}
    assert list(env.paths.run_recordings.iterdir()) == []


def test_the_marker_is_gone_after_asciinema_cannot_start(make_env, opened, dc01, paths, clock):
    failing = Asciinema(paths, clock, raises=FileNotFoundError(2, "No such file or directory"), writes=False)
    env = make_env(run=failing)
    assert record.run(env, []) == 1
    assert failing.markers.keys() == {"4242"}
    assert list(paths.run_recordings.iterdir()) == []
    assert fails(env) == ["asciinema could not be started: [Errno 2] No such file or directory"]


def test_the_marker_is_gone_after_any_error(make_env, opened, dc01, paths, clock):
    failing = Asciinema(paths, clock, raises=RuntimeError("boom"))
    env = make_env(run=failing)
    with pytest.raises(RuntimeError):
        record.run(env, [])
    assert list(paths.run_recordings.iterdir()) == []


def test_the_lines_before_and_after(make_env, opened, dc01, asciinema):
    env = make_env()
    assert record.run(env, ["dc01"]) == 0
    assert env.console.lines == [
        ("ok", "recording this window for dc01 (forest)"),
        ("detail", "targets/dc01/recordings/2026-11-14_1432.cast"),
        ("detail", "exit this shell to stop"),
        ("ok", "recording saved, 14 min"),
        ("detail", "targets/dc01/recordings/2026-11-14_1432.cast"),
        ("detail", "targets/dc01/recordings/2026-11-14_1432.txt"),
    ]


def test_what_record_says_is_one_block_with_a_blank_line_around_the_recorded_shell(
    make_env, opened, dc01, paths, clock
):
    out = io.StringIO()

    def run(argv, **kwargs):
        # the recorded shell writes to the same window
        out.write("$ whoami\nroot\n$ exit\n")
        return Asciinema(paths, clock)(argv, **kwargs)

    env = make_env(run=run, console=TermConsole({"NO_COLOR": "1"}, out=out))
    out.write("$ record dc01\n")
    assert record.run(env, ["dc01"]) == 0
    assert out.getvalue() == (
        "$ record dc01\n"
        "\n"
        "  ok    recording this window for dc01 (forest)\n"
        "        targets/dc01/recordings/2026-11-14_1432.cast\n"
        "        exit this shell to stop\n"
        "\n"
        "$ whoami\nroot\n$ exit\n"
        "\n"
        "  ok    recording saved, 14 min\n"
        "        targets/dc01/recordings/2026-11-14_1432.cast\n"
        "        targets/dc01/recordings/2026-11-14_1432.txt\n"
        "\n"
    )


def test_a_refusal_is_one_block_too(make_env, asciinema):
    out = io.StringIO()
    env = make_env(console=TermConsole({"NO_COLOR": "1"}, out=out))
    assert record.run(env, ["a", "b"]) == 2
    assert out.getvalue() == "\n  fail  usage: record [target]\n\n"


def test_help_is_flush_left_with_no_blank_lines(make_env):
    out = io.StringIO()
    env = make_env(console=TermConsole({"NO_COLOR": "1"}, out=out))
    assert record.run(env, ["--help"]) == 0
    assert out.getvalue() == "usage: record [target]\n"


def test_the_text_copy_is_written(make_env, opened, dc01, asciinema):
    env = make_env()
    assert record.run(env, []) == 0
    text = (opened.path / "targets" / "dc01" / "recordings" / "2026-11-14_1432.txt").read_text(encoding="utf-8")
    assert text.startswith(f"box      forest  {opened.id}\ntarget   dc01\n")
    assert "14:32:07  $ whoami\n14:32:07  root\n" in text


def test_a_short_recording_says_under_a_minute(make_env, opened, dc01, paths, clock):
    env = make_env(run=Asciinema(paths, clock, minutes=0))
    assert record.run(env, []) == 0
    assert ("ok", "recording saved, under a minute") in env.console.lines


def test_minutes_are_rounded_down(make_env, opened, dc01, paths, clock):
    quick = Asciinema(paths, clock, minutes=0)
    clock_step = timedelta(minutes=1, seconds=59)

    def run(argv, **kwargs):
        result = quick(argv, **kwargs)
        clock.now += clock_step
        return result

    env = make_env(run=run)
    assert record.run(env, []) == 0
    assert ("ok", "recording saved, 1 min") in env.console.lines


def test_a_failed_asciinema_still_writes_the_text_and_warns_first(make_env, opened, dc01, paths, clock):
    env = make_env(run=Asciinema(paths, clock, status=3))
    assert record.run(env, []) == 0
    assert env.console.lines[3:] == [
        ("warn", "asciinema ended with status 3; the recording may be incomplete"),
        ("ok", "recording saved, 14 min"),
        ("detail", "targets/dc01/recordings/2026-11-14_1432.cast"),
        ("detail", "targets/dc01/recordings/2026-11-14_1432.txt"),
    ]
    assert (opened.path / "targets" / "dc01" / "recordings" / "2026-11-14_1432.txt").exists()


def test_no_cast_afterwards_is_a_failure(make_env, opened, dc01, paths, clock):
    env = make_env(run=Asciinema(paths, clock, status=1, writes=False))
    assert record.run(env, []) == 1
    assert env.console.lines[3:] == [
        ("warn", "asciinema ended with status 1; the recording may be incomplete"),
        ("fail", "no recording was saved"),
    ]


def test_a_cast_that_cannot_be_read_is_a_warning(make_env, opened, dc01, paths, clock):
    def run(argv, **kwargs):
        Path(argv[-1]).write_text("not a cast\n", encoding="utf-8")
        return subprocess.CompletedProcess(argv, 0)

    env = make_env(run=run)
    assert record.run(env, []) == 0
    kinds = [kind for kind, _ in env.console.lines[3:]]
    assert kinds == ["warn", "ok", "detail"]
    assert env.console.lines[3][1] == (
        "no text copy of targets/dc01/recordings/2026-11-14_1432.cast: the first line is not JSON"
    )
    assert not (opened.path / "targets" / "dc01" / "recordings" / "2026-11-14_1432.txt").exists()



def test_a_text_copy_from_before_is_kept_when_the_cast_cannot_be_rendered(make_env, opened, dc01, paths, clock):
    # an export while the window recorded wrote a text copy; the whole cast then fails further in
    def run(argv, **kwargs):
        cast = Path(argv[-1])
        cast.with_suffix(".txt").write_text("box      forest\n\n14:32:07  whoami\n", encoding="utf-8")
        cast.write_text(cast_text([]) + '[broken\n[1, "o", "b"]\n', encoding="utf-8")
        os.utime(cast.with_suffix(".txt"), ns=(1_000_000_000_000, 1_000_000_000_000))
        return subprocess.CompletedProcess(argv, 0)

    env = make_env(run=run)
    assert record.run(env, []) == 0
    assert env.console.lines[3][1].startswith(
        "the text copy of targets/dc01/recordings/2026-11-14_1432.cast is not up to date: line 2 is not a valid event"
    )
    text = (opened.path / "targets" / "dc01" / "recordings" / "2026-11-14_1432.txt").read_text(encoding="utf-8")
    assert "whoami" in text and "\n[the text copy stops here: line 2 is not a valid event (" in text

def _expected_env(env, extra):
    return {**recorder.base_env(env.paths, env.environ, "dc01"), **extra}


def test_zsh_is_run_with_its_startup_folder(make_env, opened, dc01, asciinema):
    env = make_env(environ={"SHELL": "/usr/bin/zsh", "ZDOTDIR": "/home/u/z"})
    assert record.run(env, []) == 0
    [(argv, kwargs)] = asciinema.calls
    cast = opened.path / "targets" / "dc01" / "recordings" / "2026-11-14_1432.cast"
    assert argv == recorder.rec_argv(env.paths, cast, f"forest dc01 {opened.id}", "'/usr/bin/zsh'")
    # nothing is captured: the window is the user's
    assert kwargs == {
        "env": _expected_env(env, {"ZDOTDIR": str(env.paths.run_shell / "zsh"), "PWN_BROKER_ZDOTDIR": "/home/u/z"})
    }
    assert (env.paths.run_shell / "zsh" / ".zshrc").is_file()


def test_bash_is_run_with_its_rcfile(make_env, opened, dc01, asciinema):
    env = make_env(environ={"SHELL": "/bin/bash"})
    assert record.run(env, []) == 0
    [(argv, kwargs)] = asciinema.calls
    command = f"'/bin/bash' --rcfile '{env.paths.run_shell / 'bashrc'}'"
    assert argv[argv.index("--command") + 1] == command
    assert kwargs == {"env": _expected_env(env, {})}
    assert kwargs["env"]["PWN_BROKER_RECORDING"] == "dc01"


def test_another_shell_is_run_as_it_is(make_env, opened, dc01, asciinema):
    env = make_env(environ={"SHELL": "/usr/bin/fish"})
    assert record.run(env, []) == 0
    [(argv, kwargs)] = asciinema.calls
    assert argv[argv.index("--command") + 1] == "'/usr/bin/fish'"
    assert kwargs == {"env": _expected_env(env, {})}


def test_no_shell_set_runs_sh(make_env, opened, dc01, asciinema):
    env = make_env(environ={})
    assert record.run(env, []) == 0
    [(argv, _kwargs)] = asciinema.calls
    assert argv[argv.index("--command") + 1] == "'/bin/sh'"


def test_the_asciinema_folders_exist_before_it_runs(make_env, opened, dc01, asciinema):
    env = make_env()
    assert record.run(env, []) == 0
    assert (env.paths.run_asciinema / "config").is_dir()
    assert (env.paths.run_asciinema / "state").is_dir()


def test_record_does_not_change_the_last_target(make_env, opened, web01, asciinema):
    env = make_env()
    assert record.run(env, ["web01"]) == 0
    assert load_box(opened.path).last_target is None


# -- the file name --


def test_cast_path_is_the_start_time_to_the_minute(tmp_path):
    assert cast_path(tmp_path, START) == tmp_path / "2026-11-14_1432.cast"


def test_cast_path_numbers_a_name_that_is_taken(tmp_path):
    (tmp_path / "2026-11-14_1432.cast").write_text("", encoding="utf-8")
    assert cast_path(tmp_path, START) == tmp_path / "2026-11-14_1432-2.cast"
    (tmp_path / "2026-11-14_1432-2.txt").write_text("", encoding="utf-8")
    assert cast_path(tmp_path, START) == tmp_path / "2026-11-14_1432-3.cast"


def test_a_text_copy_alone_takes_the_name(tmp_path):
    (tmp_path / "2026-11-14_1432.txt").write_text("", encoding="utf-8")
    assert cast_path(tmp_path, START) == tmp_path / "2026-11-14_1432-2.cast"


def test_two_windows_in_one_minute_get_two_files(make_env, opened, dc01, asciinema):
    assert record.run(make_env(), []) == 0
    asciinema.clock.now = START
    assert record.run(make_env(), []) == 0
    names = sorted(p.name for p in (opened.path / "targets" / "dc01" / "recordings").iterdir())
    assert names == ["2026-11-14_1432-2.cast", "2026-11-14_1432-2.txt", "2026-11-14_1432.cast", "2026-11-14_1432.txt"]


# -- the real environment, kept away from the system in tests --


def test_env_has_real_seams_by_default():
    from dataclasses import fields

    from pwn_broker import hosts, ping, toolstate, vpn

    defaults = {f.name: f.default for f in fields(record.Env)}
    assert defaults["run"] is subprocess.run
    assert defaults["start_of"] is toolstate.process_start
    assert defaults["alive"] is boxes.pid_alive
    assert defaults["owner"] is privilege.wrong_owner
    assert defaults["present"] is recorder.present
    assert defaults["hosts_path"] == hosts.DEFAULT_PATH
    assert defaults["is_root"] is privilege.is_root
    assert defaults["run_privileged"] is privilege.run_privileged
    assert defaults["ping"] is ping.once
    assert defaults["tunnel"] is vpn.tunnel


def test_a_test_env_never_reaches_the_system(paths, system):
    from pwn_broker import hosts, ping

    env = record.Env(paths, Settings(), FakeConsole(), lambda: NOW, {}, 1)
    assert env.hosts_path == system.hosts_path != hosts.DEFAULT_PATH
    assert env.is_root is not privilege.is_root
    assert env.run_privileged is not privilege.run_privileged
    assert env.ping is not ping.once
    with pytest.raises(AssertionError, match="asciinema"):
        env.run(["asciinema"])


def test_the_session_record_builds_uses_the_envs_seams(make_env, opened, dc01, asciinema, monkeypatch):
    built = []
    real = record.targetflow.add

    def add(session, answers, *, make_current):
        built.append(session)
        return real(session, answers, make_current=make_current)

    monkeypatch.setattr(record.targetflow, "add", add)
    env = make_env(["y", "", "", "", ""], ping=lambda ip: built.append(ip) or Result(True, 2.0, True))
    assert record.run(env, ["10.10.10.200"]) == 0
    session = built[0]
    assert session.hosts_path == env.hosts_path
    assert session.is_root is env.is_root
    assert session.run_privileged is env.run_privileged
    assert session.ping is env.ping
    assert session.tunnel is env.tunnel
    assert built[1] == "10.10.10.200"


def test_main_runs_with_the_arguments(monkeypatch, paths):
    from pwn_broker import config

    seen = []
    monkeypatch.setattr(config, "load", lambda environ, home: (paths, Settings()))
    monkeypatch.setattr(record, "run", lambda env, argv: seen.append((env, argv)) or 7)
    monkeypatch.setattr("sys.argv", ["record", "dc01"])
    assert record.main() == 7
    env, argv = seen[0]
    assert argv == ["dc01"]
    assert env.paths == paths
    assert env.clock().tzinfo is not None


def test_main_reports_a_bad_config(monkeypatch, capsys):
    from pwn_broker import config
    from pwn_broker.config import ConfigError

    def broken(environ, home):
        raise ConfigError("config.toml: bad")

    monkeypatch.setattr(config, "load", broken)
    monkeypatch.setattr("sys.argv", ["record"])
    assert record.main() == 1
    assert "config.toml: bad" in capsys.readouterr().out


@pytest.mark.skipif(sys.platform == "win32", reason="Ctrl-C is left alone on Windows")
def test_ctrl_c_is_caught_while_asciinema_runs_and_restored_after():
    import signal

    before = signal.getsignal(signal.SIGINT)
    with record._interrupts_ignored():
        during = signal.getsignal(signal.SIGINT)
        # a handler of record's own: SIG_IGN would be inherited by the recorded shell's programs
        assert callable(during) and during not in (signal.SIG_IGN, signal.SIG_DFL, before)
        signal.raise_signal(signal.SIGINT)
    assert signal.getsignal(signal.SIGINT) is before


def test_a_marker_that_cannot_be_written_prints_no_ok_line(make_env, opened, dc01, asciinema, monkeypatch):
    def broken(*args, **kwargs):
        raise PermissionError(13, "Permission denied")

    monkeypatch.setattr(record.recstate, "mark", broken)
    env = make_env()
    assert record.run(env, []) == 1
    assert [kind for kind, _ in env.console.lines] == ["fail"]
    assert "Permission denied" in fails(env)[0]
    assert asciinema.calls == []


def test_the_marker_is_cleared_when_printing_fails_before_asciinema(make_env, opened, dc01, asciinema):
    env = make_env()

    def broken_ok(text):
        raise OSError(5, "Input/output error")

    env.console.ok = broken_ok
    with pytest.raises(OSError):
        record.run(env, [])
    assert list(env.paths.run_recordings.iterdir()) == []
    assert asciinema.calls == []


@pytest.mark.parametrize("flag", ["--help", "-h"])
def test_help_prints_the_usage(make_env, opened, dc01, asciinema, flag):
    env = make_env()
    assert record.run(env, [flag]) == 0
    assert env.console.lines == [("raw", "usage: record [target]")]
    assert env.console.asked == []
    assert asciinema.calls == []


@pytest.mark.parametrize("flag", ["-x", "--title", "-"])
def test_an_option_is_not_a_target(make_env, opened, dc01, asciinema, flag):
    env = make_env(["y"])
    assert record.run(env, [flag]) == 2
    assert fails(env) == ["usage: record [target]"]
    assert env.console.asked == []
    assert [t.name for t in load_targets(opened)] == ["dc01"]
