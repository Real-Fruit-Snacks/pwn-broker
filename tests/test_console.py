import io
import re

import pytest
from helpers import NASTY
from prompt_toolkit.document import Document
from rich.console import Console as RichConsole

from pwn_broker import theme
from pwn_broker.console import Cancelled, FakeConsole, TermConsole, status_line
from pwn_broker.theme import color_enabled


def test_status_line_format():
    assert status_line("ok", "cred 3 saved") == "ok    cred 3 saved"
    assert status_line("warn", "no tunnel") == "warn  no tunnel"
    assert status_line("fail", "no such target") == "fail  no such target"


def test_term_console_prints_user_text_literally():
    out = io.StringIO()
    c = TermConsole({"NO_COLOR": "1"}, out=out)
    c.ok("secret [red]x[/red] kept")
    c.table(["secret"], [["[bold]y[/bold]"]])
    assert "[red]x[/red]" in out.getvalue() and "[bold]y[/bold]" in out.getvalue()


def test_no_color_emits_no_escape_codes():
    out = io.StringIO()
    c = TermConsole({"NO_COLOR": "1"}, out=out)
    c.fail("x")
    c.info("y")
    c.table(["h"], [["v"]])
    assert "\x1b" not in out.getvalue()


def test_long_lines_are_not_wrapped_off_terminal():
    out = io.StringIO()
    text = "word " * 100
    TermConsole({"NO_COLOR": "1"}, out=out).info(text)
    assert text in out.getvalue()


def test_color_enabled():
    assert color_enabled({}) and not color_enabled({"NO_COLOR": "1"})
    assert color_enabled({"NO_COLOR": ""})


def test_fake_console_answers_and_default():
    c = FakeConsole(["", "typed"])
    assert c.ask("platform", default="htb") == "htb" and c.ask("os") == "typed"
    with pytest.raises(Cancelled):
        c.ask("more")
    assert c.asked == ["platform", "os", "more"]


def test_fake_confirm():
    c = FakeConsole(["", "y", "n"])
    assert c.confirm("go?") is False and c.confirm("go?") is True and c.confirm("go?", default=True) is False


def test_fake_confirm_yes_and_default_true():
    c = FakeConsole(["yes", ""])
    assert c.confirm("a") is True and c.confirm("b", default=True) is True


YES_NO = [
    ("y", False, True), ("Y", False, True), ("yes", False, True), ("Yes", False, True), ("YES", False, True),
    (" y ", False, True), ("n", True, False), ("N", True, False), ("No", True, False), ("NO", True, False),
    ("", True, True), ("", False, False), ("   ", True, True), (" No ", True, False), ("yES", False, True),
]  # fmt: skip

# not a yes or no: the question is asked again, never taken as either
NOT_YES_NO = ["2", "maybe", "yep", "nope", "ja", "y es", "1", "0", "true"]


@pytest.mark.parametrize("answer,default,expected", YES_NO)
def test_fake_confirm_ignores_case_and_edge_spaces(answer, default, expected):
    assert FakeConsole([answer]).confirm("go?", default=default) is expected


def scripted(monkeypatch, *answers):
    queue = list(answers)
    seen = []

    def fake_prompt(message, **kwargs):
        seen.append(message)
        answer = queue.pop(0)
        if isinstance(answer, BaseException):
            raise answer
        return answer

    monkeypatch.setattr("prompt_toolkit.prompt", fake_prompt)
    return TermConsole({"NO_COLOR": "1"}, out=io.StringIO()), seen


@pytest.mark.parametrize("answer,default,expected", YES_NO)
def test_term_confirm_ignores_case_and_edge_spaces(monkeypatch, answer, default, expected):
    console, _ = scripted(monkeypatch, answer)
    assert console.confirm("go?", default=default) is expected


def test_term_ask_returns_the_raw_answer_or_the_default(monkeypatch):
    console, _ = scripted(monkeypatch, "  spaced  ", "", "")
    assert console.ask("user") == "  spaced  "
    assert console.ask("platform", default="htb") == "htb"
    assert console.ask("note") == ""


@pytest.mark.parametrize("exc", [KeyboardInterrupt(), EOFError()])
def test_term_ask_and_confirm_cancel_on_interrupt_and_eof(monkeypatch, exc):
    console, _ = scripted(monkeypatch, exc, exc)
    with pytest.raises(Cancelled):
        console.ask("user")
    with pytest.raises(Cancelled):
        console.confirm("go?")


def _color(style, classes):
    return "#" + style.get_attrs_for_style_str(classes).color.upper()


def test_question_label_is_mute_and_typed_text_is_text_colour(monkeypatch):
    seen = []

    def fake_prompt(message, **kwargs):
        seen.append((message, kwargs))
        return "y"

    monkeypatch.setattr("prompt_toolkit.prompt", fake_prompt)
    console = TermConsole({}, out=io.StringIO())
    console.ask("user")
    console.confirm("go?")
    for message, kwargs in seen:
        assert [cls for cls, _ in message] == ["class:question"]
        style, lexer = kwargs["style"], kwargs["lexer"]
        line = lexer.lex_document(Document("typed"))(0)
        assert [cls for cls, _ in line] == ["class:answer"]
        assert _color(style, "class:question") == theme.MUTE
        assert _color(style, "class:answer") == theme.TEXT
        assert theme.EMBER not in {_color(style, "class:question"), _color(style, "class:answer")}


def test_shell_prompt_is_still_ember():
    assert _color(theme.prompt_style(), "class:prompt") == theme.EMBER


def test_fake_records_lines_and_tables():
    c = FakeConsole()
    c.ok("a")
    c.warn("b")
    c.fail("c")
    c.info("d")
    c.table(["h"], [["v"]])
    assert c.lines == [("ok", "a"), ("warn", "b"), ("fail", "c"), ("info", "d")]
    assert c.tables == [(["h"], [["v"]])]


def test_wide_table_not_cut_off_terminal(monkeypatch):
    out = io.StringIO()
    monkeypatch.setattr("sys.stdout", out)
    c = TermConsole({"NO_COLOR": "1"})
    c.table(["a", "b"], [["x" * 70, "y" * 40]])
    assert "x" * 70 in out.getvalue() and "y" * 40 in out.getvalue()


def test_table_cells_fold_on_narrow_terminal():
    out = io.StringIO()
    c = TermConsole({"NO_COLOR": "1"}, out=out)
    c._rich = RichConsole(file=out, force_terminal=True, width=40, color_system=None)
    c.table(["a", "b"], [["x" * 70, "y" * 40]])
    text = out.getvalue()
    assert "\u2026" not in text
    assert text.count("x") == 70 and text.count("y") == 40


@pytest.mark.parametrize("env", [{"NO_COLOR": "1"}, {}])
@pytest.mark.parametrize("value", [*NASTY, "a\tb", "x" * 300])
def test_raw_writes_the_text_byte_for_byte(env, value):
    out = io.StringIO()
    TermConsole(env, out=out).raw(value)
    assert out.getvalue() == value + "\n"


def test_fake_raw_is_recorded():
    c = FakeConsole()
    c.raw("a\tb")
    assert c.lines == [("raw", "a\tb")]


def test_fake_ask_path_is_ask():
    c = FakeConsole(["", "/tmp/x.ovpn"])
    assert c.ask_path("vpn file", default="/a.ovpn") == "/a.ovpn"
    assert c.ask_path("vpn file") == "/tmp/x.ovpn"
    assert c.asked == ["vpn file", "vpn file"]


def test_term_ask_path_completes_paths_and_takes_the_default(monkeypatch):
    from prompt_toolkit.completion import PathCompleter

    seen = []

    def fake_prompt(message, **kwargs):
        seen.append((message, kwargs))
        return "" if len(seen) == 1 else "~/lab.ovpn"

    monkeypatch.setattr("prompt_toolkit.prompt", fake_prompt)
    console = TermConsole({"NO_COLOR": "1"}, out=io.StringIO())
    assert console.ask_path("vpn file", default="/root/lab.ovpn") == "/root/lab.ovpn"
    assert console.ask_path("vpn file") == "~/lab.ovpn"
    message, kwargs = seen[0]
    assert message == [("class:question", "  vpn file     [/root/lab.ovpn] > ")]
    completer = kwargs["completer"]
    assert isinstance(completer, PathCompleter) and completer.expanduser is True
    console.ask("user")
    assert seen[-1][1]["completer"] is None


# --- layout -------------------------------------------------------------------------------------


def screen(monkeypatch, *answers, env=None, width=None, color=None):
    """A TermConsole whose questions are drawn into the same stream, as a terminal shows them."""
    out = io.StringIO()
    queue = list(answers)

    def fake_prompt(message, **kwargs):
        [(_, question)] = message
        answer = queue.pop(0)
        if isinstance(answer, BaseException):
            out.write(question + "\n")
            raise answer
        out.write(question + answer + "\n")
        return answer

    monkeypatch.setattr("prompt_toolkit.prompt", fake_prompt)
    console = TermConsole({"NO_COLOR": "1"} if env is None else env, out=out)
    if width is not None:
        on_terminal(console, out, width, color)
    return console, out


def on_terminal(console, out, width, color=None):
    console._rich = RichConsole(
        file=out, force_terminal=True, width=width, color_system=color, highlight=False, markup=False, emoji=False
    )


def test_every_kind_of_line_has_its_indent(monkeypatch):
    c, out = screen(monkeypatch, "forest", "")
    c.ok("a")
    c.warn("b")
    c.fail("c")
    c.info("d")
    c.detail("e")
    c.fields([("box", "forest"), ("started", "2026-11-16")])
    c.table(["h", "k"], [["v", "w"]])
    c.ask("name")
    c.confirm("go?", default=True)
    c.raw("r")
    c.heading("New box")
    assert out.getvalue() == (
        "  ok    a\n"
        "  warn  b\n"
        "  fail  c\n"
        "  d\n"
        "        e\n"
        "  box      forest\n"
        "  started  2026-11-16\n"
        "  h  k\n"
        "  v  w\n"
        "  name         > forest\n"
        "  go? [Y/n] > \n"
        "r\n"
        "\n"
        "New box\n"
    )


def test_a_detail_starts_under_the_status_text(monkeypatch):
    c, out = screen(monkeypatch)
    c.warn("vpn   no VPN tunnel is up")
    c.detail("start one with: vpn start")
    first, second = out.getvalue().splitlines()
    assert first.index("vpn") == second.index("start") == 8


def test_fields_pad_to_the_longest_label_and_print_nothing_for_no_rows(monkeypatch):
    c, out = screen(monkeypatch)
    c.fields([])
    assert out.getvalue() == ""
    c.fields([("a", "1"), ("longer", "2")])
    assert out.getvalue() == "  a       1\n  longer  2\n"


def test_gap_after_a_line_writes_one_blank_and_a_second_gap_none(monkeypatch):
    c, out = screen(monkeypatch)
    c.ok("a")
    c.gap()
    c.gap()
    c.ok("b")
    assert out.getvalue() == "  ok    a\n\n  ok    b\n"


def test_gap_and_heading_at_the_very_start_write_no_blank(monkeypatch):
    c, out = screen(monkeypatch)
    c.gap()
    c.heading("Boxes")
    assert out.getvalue() == "Boxes\n"


def test_heading_after_a_gap_has_one_blank_above_and_none_below(monkeypatch):
    c, out = screen(monkeypatch, "forest")
    c.ok("a")
    c.gap()
    c.heading("New box")
    c.ask("name")
    assert out.getvalue() == "  ok    a\n\nNew box\n  name         > forest\n"


def test_an_answered_question_counts_as_a_line(monkeypatch):
    c, out = screen(monkeypatch, "", "")
    c.confirm("add a target?")
    c.gap()
    c.gap()
    c.confirm("add another?")
    c.ok("done")
    assert out.getvalue() == "  add a target? [y/N] > \n\n  add another? [y/N] > \n  ok    done\n"


def test_a_block_that_prints_nothing_writes_nothing(monkeypatch):
    c, out = screen(monkeypatch)
    c.ok("a")
    with c.block():
        pass
    with c.block():
        c.gap()
    c.ok("b")
    assert out.getvalue() == "  ok    a\n  ok    b\n"


def test_a_block_has_one_blank_line_above_and_below(monkeypatch):
    c, out = screen(monkeypatch)
    with c.block():
        c.ok("a")
        c.gap()
        c.gap()
        c.ok("b")
    c.gap()
    assert out.getvalue() == "\n  ok    a\n\n  ok    b\n\n"


def test_a_block_after_a_line_the_console_did_not_write_starts_with_a_blank(monkeypatch):
    c, out = screen(monkeypatch)
    c.ok("a")
    c.gap()
    out.write("forest/dc01 > status\n")  # the prompt line, drawn by the prompt loop
    with c.block():
        c.fields([("box", "forest")])
    assert out.getvalue() == "  ok    a\n\nforest/dc01 > status\n\n  box  forest\n\n"


def test_a_block_ending_in_a_question_has_one_blank_below(monkeypatch):
    c, out = screen(monkeypatch, "y")
    with c.block():
        c.ok("a")
        c.confirm("go?")
    c.gap()
    assert out.getvalue() == "\n  ok    a\n  go? [y/N] > y\n\n"


def test_a_block_starting_with_a_heading_has_one_blank_above(monkeypatch):
    c, out = screen(monkeypatch, "u")
    with c.block():
        c.gap()
        c.heading("New credential")
        c.ask("username")
    assert out.getvalue() == "\nNew credential\n  username     > u\n\n"


def test_nested_blocks_behave_as_one(monkeypatch):
    c, out = screen(monkeypatch)
    with c.block():
        with c.block():
            c.ok("a")
        with c.block():
            pass
        c.ok("b")
    assert out.getvalue() == "\n  ok    a\n  ok    b\n\n"


def test_a_cancelled_block_still_closes_with_a_blank(monkeypatch):
    c, out = screen(monkeypatch, KeyboardInterrupt())
    with pytest.raises(Cancelled), c.block():
        c.ask("name")
    c.ok("cancelled")
    assert out.getvalue() == "\n  name         > \n\n  ok    cancelled\n"


@pytest.mark.parametrize("value", NASTY)
def test_every_line_writes_user_text_literally(monkeypatch, value):
    c, out = screen(monkeypatch)
    c.ok(value)
    c.detail(value)
    c.info(value)
    c.fields([("label", value)])
    c.heading(value)
    assert out.getvalue() == (
        f"  ok    {value}\n        {value}\n  {value}\n  label  {value}\n\n{value}\n"
    )


def test_a_long_detail_is_not_wrapped_on_a_narrow_terminal(monkeypatch):
    c, out = screen(monkeypatch, width=20)
    c.detail("10.10.10.161\tforest.htb.local dc01.forest.htb.local")
    assert out.getvalue() == "        10.10.10.161\tforest.htb.local dc01.forest.htb.local\n"


def _table_lines(out):
    return out.getvalue().splitlines()


def test_only_the_named_column_is_cut_on_a_terminal(monkeypatch):
    c, out = screen(monkeypatch, width=40)
    c.table(["n", "secret", "note"], [["1", "s" * 60, "short"], ["2", "tiny", "x"]], cut="secret")
    lines = _table_lines(out)
    assert all(len(line.rstrip()) <= 40 for line in lines)
    assert lines[1].split() == ["1", "s" * (40 - 2 - 1 - 2 - 2 - 5 - 3) + "...", "short"]
    assert lines[2].split() == ["2", "tiny", "x"]
    assert all(line.startswith("  ") for line in lines)


def test_a_table_that_fits_is_not_cut(monkeypatch):
    c, out = screen(monkeypatch, width=40)
    c.table(["n", "secret"], [["1", "s" * 30]], cut="secret")
    assert "s" * 30 in out.getvalue() and "..." not in out.getvalue()


def test_a_cut_keeps_at_least_eight_characters_then_wraps(monkeypatch):
    c, out = screen(monkeypatch, width=20)
    c.table(["name", "about"], [["w" * 15, "d" * 40]], cut="about")
    text = out.getvalue()
    # still too wide at eight characters, so the table wraps as it always has
    assert text.count("d") == 8 and text.count(".") == 3
    assert text.count("w") == 15
    assert all(line.startswith("  ") for line in text.splitlines())


def test_piped_output_is_never_cut(monkeypatch):
    c, out = screen(monkeypatch)
    c.table(["n", "secret"], [["1", "s" * 300]], cut="secret")
    assert "s" * 300 in out.getvalue() and "..." not in out.getvalue()


def test_a_table_without_cut_wraps_as_before_with_every_row_indented(monkeypatch):
    c, out = screen(monkeypatch, width=40)
    c.table(["a", "b"], [["x" * 70, "y" * 40]])
    text = out.getvalue()
    assert "..." not in text and text.count("x") == 70 and text.count("y") == 40
    lines = text.splitlines()
    assert len(lines) > 2 and all(line.startswith("  ") for line in lines)


def test_cutting_a_column_that_is_not_there_is_an_error(monkeypatch):
    c, _ = screen(monkeypatch)
    with pytest.raises(ValueError):
        c.table(["a"], [["x"]], cut="b")
    with pytest.raises(ValueError):
        FakeConsole().table(["a"], [["x"]], cut="b")


def test_a_markup_cell_is_literal_and_cut_like_any_other(monkeypatch):
    c, out = screen(monkeypatch, width=30)
    c.table(["n", "secret"], [["1", "[red]" + "s" * 40 + "[/red]"]], cut="secret")
    assert "[red]sss" in out.getvalue() and "..." in out.getvalue()


@pytest.mark.parametrize("bad", NOT_YES_NO)
def test_term_confirm_asks_again_until_yes_or_no(monkeypatch, bad):
    c, out = screen(monkeypatch, bad, "n")
    assert c.confirm("fix it now?", default=True) is False
    assert out.getvalue() == (
        f"  fix it now? [Y/n] > {bad}\n  fail  answer y or n\n  fix it now? [Y/n] > n\n"
    )


def test_term_confirm_takes_the_default_after_a_wrong_answer(monkeypatch):
    c, _ = screen(monkeypatch, "2", "  ")
    assert c.confirm("fix it now?", default=True) is True


@pytest.mark.parametrize("exc", [KeyboardInterrupt(), EOFError()])
def test_term_confirm_cancels_on_interrupt_after_a_wrong_answer(monkeypatch, exc):
    c, _ = screen(monkeypatch, "maybe", exc)
    with pytest.raises(Cancelled):
        c.confirm("go?")


@pytest.mark.parametrize("bad", NOT_YES_NO)
def test_fake_confirm_asks_again_until_yes_or_no(bad):
    c = FakeConsole([bad, "y"])
    assert c.confirm("go?") is True
    assert c.asked == ["go?", "go?"]
    assert c.lines == [("fail", "answer y or n")]
    assert c.events == [("confirm", "go?"), ("fail", "answer y or n"), ("confirm", "go?")]


def test_fake_confirm_cancels_when_a_wrong_answer_is_the_last():
    with pytest.raises(Cancelled):
        FakeConsole(["2"]).confirm("go?")


ANSI = re.compile(r"\x1b\[[0-9;]*m")


def _script(c):
    c.ok("a")
    c.warn("b")
    c.detail("c\td")
    c.gap()
    c.heading("Target 1")
    c.fields([("ip", "10.10.10.161")])
    c.info("e")
    c.table(["h", "k"], [["v", "w"]])


def test_no_color_gives_the_same_lines(monkeypatch):
    plain, plain_out = screen(monkeypatch, env={"NO_COLOR": "1"}, width=60)
    colored, colored_out = screen(monkeypatch, env={}, width=60, color="truecolor")
    _script(plain)
    _script(colored)
    assert "\x1b" in colored_out.getvalue() and "\x1b" not in plain_out.getvalue()
    assert ANSI.sub("", colored_out.getvalue()) == plain_out.getvalue()


def test_colours_of_the_new_lines(monkeypatch):
    c, out = screen(monkeypatch, env={}, width=60, color="truecolor")
    c.heading("New box")
    c.detail("d")
    text = out.getvalue()
    assert "\x1b[1;38;2;232;230;225mNew box" in text  # bold, text colour
    assert "\x1b[38;2;138;143;153md" in text  # mute


def test_fake_records_lines_and_events_in_order():
    c = FakeConsole(["forest", "y"])
    with c.block():
        c.heading("New box")
        c.ask("name")
        c.gap()
        c.confirm("add a target?")
        with c.block():
            c.ok("created")
        c.detail("10.10.10.161 forest.htb")
        c.fields([("box", "forest"), ("targets", "1")])
        c.table(["n", "secret"], [["1", "s"]], cut="secret")
        c.table(["h"], [["v"]])
        c.raw("r")
    assert c.lines == [
        ("heading", "New box"),
        ("ok", "created"),
        ("detail", "10.10.10.161 forest.htb"),
        ("field", "box  forest"),
        ("field", "targets  1"),
        ("raw", "r"),
    ]
    assert c.events == [
        ("block", "begin"),
        ("heading", "New box"),
        ("ask", "name"),
        ("gap", ""),
        ("confirm", "add a target?"),
        ("ok", "created"),
        ("detail", "10.10.10.161 forest.htb"),
        ("field", "box  forest"),
        ("field", "targets  1"),
        ("table", "secret"),
        ("table", ""),
        ("raw", "r"),
        ("block", "end"),
    ]
    assert c.tables == [(["n", "secret"], [["1", "s"]]), (["h"], [["v"]])]
    assert c.asked == ["name", "add a target?"]
