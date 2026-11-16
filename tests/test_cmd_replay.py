import io
import os
import subprocess

import pytest
from casts import START, recording_now, write_cast

from helpers import NOW
from pwn_broker import recorder
from pwn_broker import shell  # noqa: F401  (fills the command registry)
from pwn_broker.boxes import add_target
from pwn_broker.console import FakeConsole, TermConsole
from pwn_broker.shell import cmd_replay
from pwn_broker.shell.cmd_misc import human_size
from pwn_broker.shell.commands import dispatch


def _cast(session, target, name, *, minutes=0.0, events=((0, "o", "hello\r\n"),), timestamp=START):
    """A cast whose modification time is `minutes` after the start in its header."""
    path = write_cast(
        session.box.path / "targets" / target / "recordings" / f"{name}.cast", list(events),
        timestamp=timestamp,
    )  # fmt: skip
    end = int((timestamp + minutes * 60) * 1_000_000_000)
    os.utime(path, ns=(end, end))
    return path


def _run(session, line):
    session.console = FakeConsole()
    dispatch(session, line)
    return session.console


@pytest.fixture
def played(session, monkeypatch):
    calls = []
    envs = []
    status = [0]

    def play(argv, *, env):
        calls.append(argv)
        envs.append(env)
        if isinstance(status[0], BaseException):
            raise status[0]
        return subprocess.CompletedProcess(argv, status[0])

    session.play = play
    monkeypatch.setattr(cmd_replay.recorder, "present", lambda paths: True)
    session.played_envs = envs  # read by the test that checks the environment
    return calls, status


# ---- listing


def test_no_recordings_yet(session):
    console = _run(session, "replay")
    assert console.lines == [("info", "no recordings of dc01 yet")]
    assert console.tables == []


def test_lists_the_current_targets_recordings_oldest_first(session):
    late = _cast(session, "dc01", "2026-11-14_1510", events=[(0, "o", "b")], timestamp=START + 38 * 60)
    first = _cast(session, "dc01", "2026-11-14_1432", minutes=14.5)
    os.utime(late, ns=((START + 38 * 60 + 59) * 10**9,) * 2)
    _cast(session, "web01", "2026-11-14_1000")
    console = _run(session, "replay")
    assert console.lines == []
    assert console.tables == [
        (
            ["n", "started", "length", "size"],
            [
                ["1", "2026-11-14 14:32", "14 min", human_size(first.stat().st_size)],
                ["2", "2026-11-14 15:10", "under a minute", human_size(late.stat().st_size)],
            ],
        )
    ]


def test_listing_writes_the_missing_text_copies_of_that_target_only(session):
    mine = _cast(session, "dc01", "2026-11-14_1432")
    theirs = _cast(session, "web01", "2026-11-14_1432")
    _run(session, "replay")
    assert mine.with_suffix(".txt").exists() and not theirs.with_suffix(".txt").exists()


def test_a_live_recording_is_listed_as_recording_now(session, system):
    _cast(session, "dc01", "2026-11-14_1432", minutes=14)
    recording_now(session, system, "dc01", "2026-11-14_1510", timestamp=START + 38 * 60)
    [(columns, rows)] = _run(session, "replay").tables
    assert rows[0][2] == "14 min"
    assert rows[1] == ["2", "2026-11-14 15:10", "recording now", ""]


def test_another_target_by_name(session):
    add_target(
        session.box, session.targets, ips=["10.10.10.5"], hostnames=[],
        scope="internal", name="web01", now=NOW,
    )  # fmt: skip
    _cast(session, "dc01", "2026-11-14_1432")
    _cast(session, "web01", "2026-11-14_1000", minutes=7, timestamp=START - 4 * 3600 - 32 * 60 - 7)
    [(columns, rows)] = _run(session, "replay web01").tables
    assert [row[:3] for row in rows] == [["1", "2026-11-14 10:00", "7 min"]]
    assert _run(session, "replay nobody").lines == [("fail", "no target named nobody")]


def test_a_cast_that_cannot_be_read_is_still_listed(session):
    bad = session.box.path / "targets/dc01/recordings/2026-11-14_1432-2.cast"
    bad.parent.mkdir(parents=True, exist_ok=True)
    bad.write_bytes(b"not a cast\n")
    good = _cast(session, "dc01", "2026-11-14_1500", minutes=2, timestamp=START + 28 * 60)
    console = _run(session, "replay")
    [(kind, text)] = console.lines
    assert kind == "warn" and "2026-11-14_1432-2.cast" in text
    [(columns, rows)] = console.tables
    assert rows == [
        ["1", "2026-11-14 14:32", "-", human_size(bad.stat().st_size)],
        ["2", "2026-11-14 15:00", "2 min", human_size(good.stat().st_size)],
    ]
    assert good.with_suffix(".txt").exists()


def test_without_a_current_target(session):
    session.current = None
    assert _run(session, "replay").lines == [
        ("fail", "no current target; pick one with: target use <name>")
    ]


# ---- playing


def test_plays_one_through_the_seam(session, played, monkeypatch):
    calls, status = played
    _cast(session, "dc01", "2026-11-14_1432")
    second = _cast(session, "dc01", "2026-11-14_1510")
    monkeypatch.setenv("PWN_BROKER_RECORDING", "web01")  # as inside a recorded window
    monkeypatch.setenv("ASCIINEMA_CONFIG_HOME", "/home/u/.config/asciinema")
    console = _run(session, "replay 2")
    assert calls == [recorder.play_argv(session.paths, second)]
    assert console.lines == [] and console.tables == []
    [env] = session.played_envs
    assert env["ASCIINEMA_CONFIG_HOME"] == str(session.paths.run_asciinema / "config")
    assert env["ASCIINEMA_STATE_HOME"] == str(session.paths.run_asciinema / "state")
    assert "PWN_BROKER_RECORDING" not in env
    assert env["PATH"] == os.environ["PATH"]
    assert all((session.paths.run_asciinema / sub).is_dir() for sub in ("config", "state"))


def test_playing_writes_the_missing_text_copies_first(session, played):
    first = _cast(session, "dc01", "2026-11-14_1432")
    _run(session, "replay 1")
    assert "14:32:07  hello" in first.with_suffix(".txt").read_text(encoding="utf-8")


def test_a_start_time_too_far_off_does_not_hide_the_other_recordings(session):
    far = _cast(session, "dc01", "2026-11-14_1430", timestamp=253402300799)
    os.utime(far, ns=(START * 10**9,) * 2)
    huge = session.box.path / "targets/dc01/recordings/2026-11-14_1431.cast"
    huge.write_text('{"version": 3, "term": {"cols": 80, "rows": 24}, "timestamp": 100000000000000000000}\n')
    good = _cast(session, "dc01", "2026-11-14_1432", minutes=14)
    console = _run(session, "replay")
    assert [k for k, _ in console.lines] == ["warn", "warn"]
    [(columns, rows)] = console.tables
    assert [row[:3] for row in rows] == [
        ["1", "2026-11-14 14:30", "-"],
        ["2", "2026-11-14 14:31", "-"],
        ["3", "2026-11-14 14:32", "14 min"],
    ]
    assert rows[2][3] == human_size(good.stat().st_size)


def test_plays_one_of_another_target(session, played):
    calls, status = played
    add_target(
        session.box, session.targets, ips=["10.10.10.5"], hostnames=[],
        scope="internal", name="10", now=NOW,
    )  # fmt: skip
    theirs = _cast(session, "10", "2026-11-14_1000")
    _cast(session, "dc01", "2026-11-14_1432")
    _run(session, "replay 10 1")
    assert calls == [recorder.play_argv(session.paths, theirs)]
    # a lone number is always n, never a target
    assert _run(session, "replay 10").lines == [("fail", "no recording 10; use 1")]


def test_a_status_other_than_zero_is_a_warning(session, played):
    calls, status = played
    _cast(session, "dc01", "2026-11-14_1432")
    status[0] = 2
    assert _run(session, "replay 1").lines == [("warn", "asciinema ended with status 2")]


def test_ctrl_c_ends_the_replay(session, played):
    calls, status = played
    _cast(session, "dc01", "2026-11-14_1432")
    status[0] = KeyboardInterrupt()
    assert _run(session, "replay 1").lines == []


def test_asciinema_that_cannot_start_is_a_failure(session, played):
    calls, status = played
    _cast(session, "dc01", "2026-11-14_1432")
    status[0] = PermissionError(13, "Permission denied")
    [(kind, text)] = _run(session, "replay 1").lines
    assert kind == "fail" and text.startswith("asciinema could not be started: ")


PROMPT_LINE = "forest/dc01 > replay 1\n"
FRAMES = "$ whoami\nroot\n$ exit\n"


def _on_screen(session, line=PROMPT_LINE):
    """Run the command as the prompt does, into one stream that the player writes to as well."""
    out = io.StringIO()
    session.console = TermConsole({"NO_COLOR": "1"}, out=out)
    play = session.play

    def drawn(argv, *, env):
        out.write(FRAMES)
        return play(argv, env=env)

    session.play = drawn
    out.write(line)
    session.console.typed()
    with session.console.block():
        dispatch(session, line.split(" > ", 1)[1].strip())
    return out.getvalue()


def test_the_playback_has_a_blank_line_above_and_below(session, played):
    _cast(session, "dc01", "2026-11-14_1432")
    assert _on_screen(session) == f"{PROMPT_LINE}\n{FRAMES}\n"


def test_a_status_warning_follows_the_playback_below_a_blank_line(session, played):
    calls, status = played
    _cast(session, "dc01", "2026-11-14_1432")
    status[0] = 2
    assert _on_screen(session) == f"{PROMPT_LINE}\n{FRAMES}\n  warn  asciinema ended with status 2\n\n"


def test_a_playback_stopped_with_ctrl_c_has_a_blank_line_below(session, played):
    calls, status = played
    _cast(session, "dc01", "2026-11-14_1432")
    status[0] = KeyboardInterrupt()
    assert _on_screen(session) == f"{PROMPT_LINE}\n{FRAMES}\n"


def test_asciinema_that_cannot_start_leaves_one_blank_line_above_the_failure(session, played):
    calls, status = played
    _cast(session, "dc01", "2026-11-14_1432")
    status[0] = PermissionError(13, "Permission denied")
    out = io.StringIO()
    session.console = TermConsole({"NO_COLOR": "1"}, out=out)
    out.write(PROMPT_LINE)
    session.console.typed()
    with session.console.block():
        dispatch(session, "replay 1")
    assert out.getvalue() == f"{PROMPT_LINE}\n  fail  asciinema could not be started: [Errno 13] Permission denied\n\n"


def test_a_cast_that_cannot_be_read_can_still_be_played(session, played):
    calls, status = played
    bad = session.box.path / "targets/dc01/recordings/2026-11-14_1432.cast"
    bad.parent.mkdir(parents=True, exist_ok=True)
    bad.write_bytes(b"not a cast\n")
    _run(session, "replay 1")
    assert calls == [recorder.play_argv(session.paths, bad)]


def test_refuses_a_recording_still_being_made(session, system, played):
    calls, status = played
    recording_now(session, system, "dc01")
    assert _run(session, "replay 1").lines == [
        ("fail", "recording 1 is still being recorded; exit its window first")
    ]
    assert calls == []


def test_refuses_without_asciinema(session, monkeypatch):
    calls = []
    session.play = calls.append
    monkeypatch.setattr(cmd_replay.recorder, "present", lambda paths: False)
    _cast(session, "dc01", "2026-11-14_1432")
    assert _run(session, "replay 1").lines == [
        ("fail", "asciinema is missing or does not match its checksum; run check to download it again")
    ]
    assert calls == []


@pytest.mark.parametrize(
    "line, message",
    [
        ("replay 3", "no recording 3; use 1 to 2"),
        ("replay 0", "no recording 0; use 1 to 2"),
        ("replay dc01 x", "x is not a recording number"),
    ],
)
def test_bad_numbers(session, played, line, message):
    calls, status = played
    _cast(session, "dc01", "2026-11-14_1432")
    _cast(session, "dc01", "2026-11-14_1510")
    assert _run(session, line).lines == [("fail", message)]
    assert calls == []


def test_too_many_arguments_shows_the_usage(session, played):
    calls, status = played
    _cast(session, "dc01", "2026-11-14_1432")
    assert _run(session, "replay dc01 1 2").lines == [
        ("fail", "too many arguments: 2"),
        ("detail", "usage: replay [<target>] [<n>]"),
    ]
    assert calls == []


def test_a_number_with_no_recordings(session, played):
    calls, status = played
    assert _run(session, "replay 1").lines == [("fail", "no recordings of dc01 yet")]
    assert calls == []
