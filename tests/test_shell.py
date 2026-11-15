from datetime import timedelta

import pytest

from helpers import NOW
from pwn_broker.archive import ArchiveError
from pwn_broker.boxes import BoxError, add_target
from pwn_broker.console import Cancelled
from pwn_broker.creds import CredError
from pwn_broker.note import NoteError
from pwn_broker.shell.app import completions, prompt_text, toolbar_text
from pwn_broker.shell.commands import COMMANDS, Quit, command, dispatch, resolve, suggest
from pwn_broker.store import StoreError
from pwn_broker.vpn import Tunnel


@pytest.fixture
def registry():
    saved = dict(COMMANDS)
    COMMANDS.clear()
    yield COMMANDS
    COMMANDS.clear()
    COMMANDS.update(saved)


def _noop(session, args):
    pass


def _register(*names):
    for name in names:
        command(name, f"help for {name}")(_noop)


def test_resolve_longest_match(registry):
    _register("target", "target add")
    assert resolve("target add x y") == ("target add", ["x", "y"])
    assert resolve("target x") == ("target", ["x"])


def test_resolve_keeps_arguments_as_typed(registry):
    _register("target use")
    assert resolve("target use  DC01") == ("target use", ["DC01"])


def test_resolve_nothing(registry):
    _register("files")
    assert resolve("") is None
    assert resolve("   ") is None
    assert resolve("nope") is None


def test_command_rejects_duplicates(registry):
    _register("files")
    with pytest.raises(ValueError):
        command("files", "again")(_noop)


def test_command_returns_the_handler(registry):
    assert command("files", "list files")(_noop) is _noop
    assert COMMANDS["files"] == (_noop, "list files")


def test_registry_is_restored_after_a_test():
    assert COMMANDS.get("files", (None,))[0] is not _noop


def test_suggest_prefers_two_words_then_one(registry):
    _register("target add", "target list", "files")
    assert suggest("taget list") == "target list"
    assert suggest("fiels") == "files"
    assert suggest("zzzzzz") is None
    assert suggest("") is None


def test_dispatch_runs_handler_with_args(session, registry):
    seen = []
    command("target add", "add")(lambda s, args: seen.append((s, args)))
    dispatch(session, "target add 10.0.0.1  x")
    assert seen == [(session, ["10.0.0.1", "x"])]


def test_dispatch_unknown_suggests(session, registry):
    _register("target add", "target list")
    dispatch(session, "taget list")
    assert session.console.lines == [("fail", "unknown command: taget list. did you mean: target list")]


def test_dispatch_unknown_without_suggestion(session, registry):
    _register("files")
    dispatch(session, "qqqqqqqq")
    assert session.console.lines == [("fail", "unknown command: qqqqqqqq")]


def test_dispatch_group_prefix_lists_commands(session, registry):
    _register("target add", "target list", "files")
    dispatch(session, "target")
    assert session.console.lines == [
        ("info", "target add   help for target add"),
        ("info", "target list   help for target list"),
    ]


def test_dispatch_blank_line_does_nothing(session, registry):
    _register("files")
    dispatch(session, "   ")
    assert session.console.lines == []


@pytest.mark.parametrize(
    "error",
    [BoxError, CredError, StoreError, ArchiveError, NoteError, ValueError, OSError],
)
def test_dispatch_turns_errors_into_fail_lines(session, registry, error):
    def boom(s, args):
        raise error("x")

    command("boom", "b")(boom)
    dispatch(session, "boom")
    assert session.console.lines == [("fail", "x")]


def test_dispatch_cancel_inside_a_command(session, registry):
    def cancel(s, args):
        raise Cancelled()

    command("cancel", "c")(cancel)
    dispatch(session, "cancel")
    assert session.console.lines == [("info", "cancelled")]


def test_dispatch_lets_quit_through(session, registry):
    def leave(s, args):
        raise Quit()

    command("quit", "q")(leave)
    with pytest.raises(Quit):
        dispatch(session, "quit")


def test_dispatch_lets_keyboard_interrupt_through(session, registry):
    def interrupt(s, args):
        raise KeyboardInterrupt()

    command("interrupt", "i")(interrupt)
    with pytest.raises(KeyboardInterrupt):
        dispatch(session, "interrupt")


def test_dispatch_survives_a_handler_bug(session, registry):
    def bug(s, args):
        raise KeyError("k")

    command("bug", "b")(bug)
    dispatch(session, "bug")
    assert session.console.lines == [("fail", "unexpected error: KeyError: 'k'")]


def test_shell_style_respects_no_color():
    from pwn_broker.shell.app import shell_style

    assert shell_style({}) is not None
    assert shell_style({"NO_COLOR": "1"}) is None


def test_style_makes_the_toolbar_plain_text():
    from pwn_broker.theme import prompt_style

    rules = dict(prompt_style().style_rules)
    assert "noreverse" in rules["bottom-toolbar"]


def test_prompt_text(session):
    assert prompt_text(session) == "forest/dc01 > "
    session.current = None
    assert prompt_text(session) == "forest > "


def _second_target(session):
    add_target(
        session.box, session.targets, ips=["10.10.10.5"], hostnames=[],
        scope="internal", name="web", now=NOW,
    )  # fmt: skip


def test_toolbar_text(session):
    _second_target(session)
    now = session.box.started + timedelta(hours=1, minutes=42, seconds=59)
    assert toolbar_text(session, now) == " forest   dc01  10.10.10.161   2 targets   no vpn   01:42"


def test_toolbar_without_target(session):
    session.current = None
    session.targets.clear()
    assert toolbar_text(session, session.box.started) == " forest   0 targets   no vpn   00:00"


def test_toolbar_singular_and_hostname_fallback(session):
    session.current.ips = []
    assert (
        toolbar_text(session, session.box.started)
        == " forest   dc01  forest.htb.local   1 target   no vpn   00:00"
    )


def test_toolbar_hours_not_capped_and_never_negative(session):
    start = session.box.started
    assert toolbar_text(session, start + timedelta(hours=100, minutes=5)).endswith("   100:05")
    assert toolbar_text(session, start - timedelta(hours=1)).endswith("   00:00")


def test_completions_commands_and_targets(session, registry):
    _register("target add", "target use", "files")
    _second_target(session)
    assert completions(session, "tar") == ["target add", "target use"]
    assert completions(session, "target use d") == ["target use dc01"]
    assert completions(session, "target use ") == ["target use dc01", "target use web"]
    assert completions(session, "target add d") == []


def test_completions_host_remove_offers_the_current_targets_hostnames(session, registry):
    session.targets[0].hostnames = ["forest.htb.local", "crm.forest.htb"]
    _second_target(session)
    assert completions(session, "host remove ") == [
        "host remove crm.forest.htb", "host remove forest.htb.local",
    ]  # fmt: skip
    assert completions(session, "host remove f") == ["host remove forest.htb.local"]
    assert completions(session, "host remove forest.htb.local c") == [
        "host remove forest.htb.local crm.forest.htb"
    ]
    assert completions(session, "host remove forest.htb.local ") == [
        "host remove forest.htb.local crm.forest.htb"
    ]
    session.current = None
    assert completions(session, "host remove ") == []


@pytest.mark.parametrize("command", ["host file on", "host file off"])
def test_completions_host_file_offers_target_names(session, registry, command):
    _second_target(session)
    assert completions(session, f"{command} ") == [f"{command} dc01", f"{command} web"]
    assert completions(session, f"{command} w") == [f"{command} web"]


def test_completions_path_folders(session, registry):
    assert completions(session, "path lo") == ["path loot"]
    assert completions(session, "path li") == ["path lists"]
    assert "path screenshots" in completions(session, "path ")
    assert completions(session, "path ").count("path screenshots") == 1


def test_completer_replaces_the_whole_line(session, registry):
    from prompt_toolkit.document import Document

    from pwn_broker.shell.app import ShellCompleter

    _register("target add")
    found = list(ShellCompleter(session).get_completions(Document("tar"), None))
    assert [(c.text, c.start_position) for c in found] == [("target add", -3)]


# the prompt loop

class _Lines:
    """Stands in for PromptSession: hands out lines, then ends the input."""

    def __init__(self, lines, between=None):
        self.lines = list(lines)
        self.between = between

    def __call__(self, *args, **kwargs):
        return self

    def prompt(self):
        if self.between:
            self.between(len(self.lines))
        if not self.lines:
            raise EOFError
        return self.lines.pop(0)


@pytest.fixture
def loop(session, registry, monkeypatch):
    from pwn_broker.shell import app

    def start(lines, between=None):
        monkeypatch.setattr(app, "PromptSession", _Lines(lines, between))
        app.run_shell(session)

    return start


def test_a_busy_lock_prints_the_line_and_keeps_the_session_open(session, loop, monkeypatch):
    from pwn_broker import boxlock
    from pwn_broker.shell import app

    ran = []
    command("first", "help")(lambda s, a: ran.append("first"))
    command("second", "help")(lambda s, a: ran.append("second"))
    real = app.boxlock.held
    calls = []

    def held(paths, *, wait):
        calls.append(wait)
        if len(calls) == 1:
            raise boxlock.Busy
        return real(paths, wait=wait)

    monkeypatch.setattr(app.boxlock, "held", held)
    loop(["first", "second"])
    assert ran == ["second"]
    assert calls == [30, 30]
    assert ("fail", "record is adding a target in another window; try again") in session.console.lines


def test_a_command_sees_a_target_added_by_another_program(session, loop):
    seen = []
    command("names", "help")(lambda s, a: seen.append([t.name for t in s.targets]))
    other = reload_from(session)
    add_target(
        other.box, other.targets, ips=["10.10.10.2"], hostnames=[],
        scope="external", name="web", now=NOW + timedelta(minutes=1),
    )  # fmt: skip
    loop(["names", "names"])
    assert seen == [["dc01", "web"], ["dc01", "web"]]


def test_a_command_that_changes_nothing_does_not_reload_next_time(session, loop, monkeypatch):
    from pwn_broker import session as session_module

    session_module.mark_seen(session)
    reloads = []
    real = session_module.reload_if_changed
    monkeypatch.setattr(
        "pwn_broker.shell.app.reload_if_changed", lambda s: reloads.append(real(s)) or reloads[-1]
    )
    command("noop", "help")(_noop)
    command("touch", "help")(
        lambda s, a: add_target(
            s.box, s.targets, ips=["10.10.10.7"], hostnames=[],
            scope="external", name="mine", now=NOW,
        )
    )  # fmt: skip
    loop(["noop", "touch", "noop"])
    assert reloads == [False, False, False]


def test_mark_seen_runs_when_the_command_quits(session, loop):
    def writes_then_quits(s, a):
        add_target(
            s.box, s.targets, ips=["10.10.10.8"], hostnames=[],
            scope="external", name="late", now=NOW,
        )  # fmt: skip
        raise Quit

    command("quit", "help")(writes_then_quits)
    loop(["quit"])
    from pwn_broker.session import reload_if_changed

    assert reload_if_changed(session) is False


def test_the_lock_is_released_between_commands(session, loop):
    from pwn_broker.boxlock import held

    def between(left):
        with held(session.paths, wait=0):
            pass

    command("noop", "help")(_noop)
    loop(["noop"], between=between)


def reload_from(session):
    from pwn_broker.session import load_session

    return load_session(session.paths, session.settings, session.console, session.box, session.clock)


def test_a_target_that_cannot_be_read_stops_the_command_and_is_retried(session, loop):
    from pwn_broker.session import mark_seen

    mark_seen(session)
    ran = []
    command("run", "help")(lambda s, a: ran.append(1))
    elsewhere = add_target(
        session.box, [], ips=["10.10.10.2"], hostnames=[],
        scope="external", name="web", now=NOW + timedelta(minutes=1),
    )  # fmt: skip
    file = session.box.path / "targets" / elsewhere.name / "target.toml"
    good = file.read_bytes()
    file.write_text("this is [not toml", encoding="utf-8")
    fixed = []

    def between(left):
        # before the third prompt, the file is repaired
        if left == 1:
            file.write_bytes(good)
            fixed.append(1)

    loop(["run", "run", "run"], between=between)
    assert fixed
    assert ran == [1]
    failures = [text for kind, text in session.console.lines if kind == "fail"]
    assert len(failures) == 2
    assert [t.name for t in session.targets] == ["dc01", "web"]


def test_a_lock_file_that_cannot_be_used_does_not_end_the_session(session, loop, monkeypatch):
    from pwn_broker.shell import app

    ran = []
    command("first", "help")(lambda s, a: ran.append("first"))
    command("second", "help")(lambda s, a: ran.append("second"))
    real = app.boxlock.held
    calls = []

    def held(paths, *, wait):
        calls.append(1)
        if len(calls) == 1:
            raise PermissionError(13, "Permission denied")
        return real(paths, wait=wait)

    monkeypatch.setattr(app.boxlock, "held", held)
    loop(["first", "second"])
    assert ran == ["second"]
    failures = [text for kind, text in session.console.lines if kind == "fail"]
    assert len(failures) == 1
    assert "lock" in failures[0] and "Permission denied" in failures[0]
    assert "record is adding" not in failures[0]


def test_toolbar_shows_the_tunnel_address_after_the_tools(session, system):
    system.tunnel_found = Tunnel("tun0", "10.10.14.7")
    assert toolbar_text(session, session.box.started).endswith("1 target   vpn 10.10.14.7   00:00")


def test_toolbar_redraw_uses_the_cached_read(session, system):
    toolbar_text(session, session.box.started)
    toolbar_text(session, session.box.started)
    assert system.tunnel_reads == 1


def test_each_command_starts_with_a_fresh_tunnel_read(session, loop, system):
    from pwn_broker.session import current_tunnel

    seen = []
    command("vpnnow", "help")(lambda s, a: seen.append(current_tunnel(s)))
    loop(["vpnnow", "vpnnow"], between=lambda left: setattr(
        system, "tunnel_found", Tunnel("tun0", "10.10.14.7") if left == 1 else None
    ))  # fmt: skip
    assert seen == [None, Tunnel("tun0", "10.10.14.7")]
    assert system.tunnel_reads == 2


def test_toolbar_counts_windows_recording_for_the_box(session, system):
    from casts import recording_now

    from pwn_broker.session import recording_count

    recording_now(session, system, "dc01")
    recording_now(session, system, "dc01", "2026-11-14_1600", pid=5151)
    assert toolbar_text(session, session.box.started).endswith("1 target   no vpn   rec 2   00:00")
    del system.processes[5150], system.processes[5151]
    # a redraw within ten seconds keeps the count it read
    assert toolbar_text(session, session.box.started).endswith("no vpn   rec 2   00:00")
    recording_count(session, fresh=True)
    assert toolbar_text(session, session.box.started).endswith("1 target   no vpn   00:00")


def test_the_recording_count_is_read_again_after_ten_seconds(session, system):
    from casts import recording_now

    clock = [NOW]
    session.clock = lambda: clock[0]
    assert "rec" not in toolbar_text(session, NOW)
    recording_now(session, system, "dc01")
    clock[0] = NOW + timedelta(seconds=9)
    assert "rec" not in toolbar_text(session, NOW)
    clock[0] = NOW + timedelta(seconds=10)
    assert toolbar_text(session, NOW).endswith("rec 1   00:00")


def test_each_command_starts_with_a_fresh_recording_count(session, loop, system):
    from casts import recording_now

    from pwn_broker.session import recording_count

    seen = []
    command("count", "help")(lambda s, a: seen.append(recording_count(s)))
    loop(["count", "count"], between=lambda left: recording_now(session, system, "dc01") if left == 1 else None)
    assert seen == [0, 1]
