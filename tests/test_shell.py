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
    assert toolbar_text(session, now) == " forest   dc01  10.10.10.161   2 targets   01:42"


def test_toolbar_without_target(session):
    session.current = None
    session.targets.clear()
    assert toolbar_text(session, session.box.started) == " forest   0 targets   00:00"


def test_toolbar_singular_and_hostname_fallback(session):
    session.current.ips = []
    assert (
        toolbar_text(session, session.box.started)
        == " forest   dc01  forest.htb.local   1 target   00:00"
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
