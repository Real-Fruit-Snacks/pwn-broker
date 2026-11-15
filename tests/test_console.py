import io

import pytest
from helpers import NASTY
from rich.console import Console as RichConsole

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
