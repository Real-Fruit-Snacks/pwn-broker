import os
from collections.abc import Iterable, Iterator, Mapping
from contextlib import AbstractContextManager, contextmanager
from typing import Protocol, TextIO

from rich.cells import cell_len, set_cell_size
from rich.console import COLOR_SYSTEMS
from rich.console import Console as RichConsole
from rich.padding import Padding
from rich.style import Style
from rich.table import Table
from rich.text import Text

from . import theme

INDENT = "  "
# a cut cell keeps at least this many characters before the "..."
CUT_KEEP = 8


class Cancelled(Exception):
    pass


class Console(Protocol):
    def ask(self, label: str, default: str | None = None) -> str: ...
    def ask_path(self, label: str, default: str | None = None) -> str: ...
    def confirm(self, question: str, default: bool = False) -> bool: ...
    def ok(self, text: str) -> None: ...
    def warn(self, text: str) -> None: ...
    def fail(self, text: str) -> None: ...
    def info(self, text: str) -> None: ...
    def detail(self, text: str) -> None: ...
    def header(self, text: str) -> None: ...
    def heading(self, text: str) -> None: ...
    def fields(self, rows: list[tuple[str, str]], *, align_to: Iterable[str] = ()) -> None: ...
    def gap(self) -> None: ...
    def clear(self) -> None: ...
    def typed(self) -> None: ...
    def block(self) -> AbstractContextManager[None]: ...
    def raw(self, text: str) -> None: ...
    def table(self, columns: list[str], rows: list[list[str]], *, cut: str | None = None) -> None: ...


def status_line(kind: str, text: str) -> str:
    return f"{kind:<4}  {text}"


# a detail starts under the text of the status line above it
DETAIL_INDENT = INDENT + " " * len(status_line("ok", ""))

ANSWER_Y_OR_N = "answer y or n"
# cursor home, then erase the screen
CLEAR_SCREEN = "\x1b[H\x1b[2J"


def _yes_no(answer: str, default: bool) -> bool | None:
    # only a clear yes or no counts; anything else is asked again, so a slip never decides
    answer = answer.strip().lower()
    if answer == "":
        return default
    if answer in ("y", "yes"):
        return True
    if answer in ("n", "no"):
        return False
    return None


# C0 controls but tab, DEL and C1 controls: none of them may move the cursor or change the terminal
_CONTROLS = {code: "?" for code in [*range(0x20), 0x7F, *range(0x80, 0xA0)] if code != 0x09}
_CELL_CONTROLS = {**_CONTROLS, 0x09: " "}


def shown(text: str, *, cell: bool = False) -> str:
    """The text as the console writes it: each control character as "?" (and in a cell, a tab as a space)."""
    return text.translate(_CELL_CONTROLS if cell else _CONTROLS)


def terminal_width(stream: TextIO) -> int | None:
    """The width of the terminal this stream writes to; None when it has none, or the width is not known."""
    # its own file descriptor: not another standard stream, not COLUMNS, and whatever TERM says
    try:
        return os.get_terminal_size(stream.fileno()).columns or None
    except (AttributeError, ValueError, OSError):
        return None


def _cut_column(columns: list[str], cut: str | None) -> int | None:
    if cut is None:
        return None
    if cut not in columns:
        raise ValueError(f"no column {cut!r} to cut")
    return columns.index(cut)


class FakeConsole:
    def __init__(self, answers: list[str] | None = None) -> None:
        self._answers = list(answers or [])
        self.lines: list[tuple[str, str]] = []
        self.tables: list[tuple[list[str], list[list[str]]]] = []
        self.asked: list[str] = []
        self.events: list[tuple[str, str]] = []
        self._depth = 0

    def _next(self, question: str) -> str:
        self.asked.append(question)
        if not self._answers:
            raise Cancelled()
        return self._answers.pop(0)

    def _line(self, kind: str, text: str) -> None:
        self.lines.append((kind, text))
        self.events.append((kind, text))

    def ask(self, label: str, default: str | None = None) -> str:
        self.events.append(("ask", label))
        answer = self._next(label)
        if answer == "" and default is not None:
            return default
        return answer

    def ask_path(self, label: str, default: str | None = None) -> str:
        return self.ask(label, default)

    def confirm(self, question: str, default: bool = False) -> bool:
        # a yes or no question stands on its own: a gap above and below
        self.gap()
        while True:
            self.events.append(("confirm", question))
            answer = _yes_no(self._next(question), default)
            if answer is not None:
                self.gap()
                return answer
            self.fail(ANSWER_Y_OR_N)

    def ok(self, text: str) -> None:
        self._line("ok", text)

    def warn(self, text: str) -> None:
        self._line("warn", text)

    def fail(self, text: str) -> None:
        self._line("fail", text)

    def info(self, text: str) -> None:
        self._line("info", text)

    def detail(self, text: str) -> None:
        self._line("detail", text)

    def header(self, text: str) -> None:
        self._line("header", text)
        self.events.append(("gap", ""))

    def heading(self, text: str) -> None:
        self._line("heading", text)

    def fields(self, rows: list[tuple[str, str]], *, align_to: Iterable[str] = ()) -> None:
        for label, value in rows:
            self._line("field", f"{label}  {value}")

    def gap(self) -> None:
        self.events.append(("gap", ""))

    def clear(self) -> None:
        self.events.append(("clear", ""))

    def typed(self) -> None:
        self.events.append(("typed", ""))

    @contextmanager
    def block(self) -> Iterator[None]:
        self._depth += 1
        if self._depth == 1:
            self.events.append(("block", "begin"))
        try:
            yield
        finally:
            self._depth -= 1
            if self._depth == 0:
                self.events.append(("block", "end"))

    def raw(self, text: str) -> None:
        self._line("raw", text)

    def table(self, columns: list[str], rows: list[list[str]], *, cut: str | None = None) -> None:
        _cut_column(columns, cut)
        self.tables.append((columns, rows))
        self.events.append(("table", cut or ""))


_KIND_COLOR = {"ok": theme.MINT, "warn": theme.AMBER, "fail": theme.RASPBERRY}

# what was last on screen, so a blank line is never written twice in a row
_NOTHING, _BLANK, _LINE = "nothing", "blank", "line"


class TermConsole:
    def __init__(self, env: Mapping[str, str], out: TextIO | None = None, indent: str = INDENT) -> None:
        # indent: what every line but a heading and raw text starts with; setup passes none
        self._indent = indent
        self._color = theme.color_enabled(env)
        # legacy_windows off: every line is written to the stream as text with escape codes, tables too
        options: dict = {"highlight": False, "markup": False, "emoji": False, "legacy_windows": False}
        if not self._color:
            options["color_system"] = None
        if out is not None:
            options["file"] = out
        self._rich = RichConsole(**options)
        # Off a terminal (piped stdout, tests), user text must reach the stream unwrapped.
        if not self._rich.is_terminal:
            self._rich.width = 100_000
        self._last = _NOTHING
        self._depth = 0
        self._block_printed = False

    def _style(self, color: str, bold: bool = False) -> Style:
        return Style(color=color, bold=bold) if self._color else Style()

    # spacing

    def _blank(self) -> None:
        if self._last == _LINE:
            self._rich.file.write("\n")
            self._rich.file.flush()
            self._last = _BLANK

    def _start_line(self) -> None:
        # the blank line above a block is written just before its first line
        if self._depth and not self._block_printed:
            self._block_printed = True
            self._blank()

    def gap(self) -> None:
        if self._depth and not self._block_printed:
            return  # the block writes this blank line before its first line, if it has one
        self._blank()

    def typed(self) -> None:
        # something else wrote a line to the terminal, such as the command line at the prompt
        self._last = _LINE

    def clear(self) -> None:
        # the terminal's own clear sequence; off a terminal there is no screen to clear
        if not self._rich.is_terminal:
            return
        stream = self._rich.file
        stream.write(CLEAR_SCREEN)
        stream.flush()
        self._last = _NOTHING
        if self._depth:
            # the screen is empty: the block has nothing above to leave a blank line under
            self._block_printed = False

    @contextmanager
    def block(self) -> Iterator[None]:
        if self._depth == 0:
            self._block_printed = False
        self._depth += 1
        try:
            yield
        finally:
            self._depth -= 1
            if self._depth == 0 and self._block_printed:
                self._blank()

    # lines

    def _write(self, *parts: tuple[str, Style]) -> None:
        # written straight to the stream: rich would expand tabs and wrap
        self._start_line()
        system = COLOR_SYSTEMS.get(self._rich.color_system or "")
        stream = self._rich.file
        stream.write("".join(style.render(shown(text), color_system=system) for text, style in parts) + "\n")
        stream.flush()
        self._last = _LINE

    def _status(self, kind: str, text: str) -> None:
        full = status_line(kind, text)
        self._write(
            (self._indent, Style()), (full[:4], self._style(_KIND_COLOR[kind])), (full[4:], self._style(theme.TEXT))
        )

    def ok(self, text: str) -> None:
        self._status("ok", text)

    def warn(self, text: str) -> None:
        self._status("warn", text)

    def fail(self, text: str) -> None:
        self._status("fail", text)

    def info(self, text: str) -> None:
        self._write((self._indent, Style()), (text, self._style(theme.MUTE)))

    def detail(self, text: str) -> None:
        self._write((self._indent + DETAIL_INDENT[len(INDENT) :], Style()), (text, self._style(theme.MUTE)))

    def header(self, text: str) -> None:
        # the first line of the launch: flush left with no blank line above it, and one below
        self._write((text, self._style(theme.TEXT, bold=True)))
        self.gap()

    def heading(self, text: str) -> None:
        self.gap()
        self._write((text, self._style(theme.TEXT, bold=True)))

    def fields(self, rows: list[tuple[str, str]], *, align_to: Iterable[str] = ()) -> None:
        # align_to: more labels to pad to, so lists printed apart line up as one
        width = max((len(label) for label in [*(label for label, _ in rows), *align_to]), default=0) + 2
        for label, value in rows:
            self._write(
                (self._indent, Style()), (f"{label:<{width}}", self._style(theme.MUTE)), (value, self._style(theme.TEXT))
            )

    def raw(self, text: str) -> None:
        # this output exists to be copied, so it is written byte for byte and flush left
        self._start_line()
        stream = self._rich.file
        stream.write(text + "\n")
        stream.flush()
        # what is on screen now: an empty text or one ending in a newline leaves a blank line
        self._last = _BLANK if text == "" or text.endswith("\n") else _LINE

    def table(self, columns: list[str], rows: list[list[str]], *, cut: str | None = None) -> None:
        index = _cut_column(columns, cut)
        columns = [shown(name, cell=True) for name in columns]
        rows = [[shown(cell, cell=True) for cell in row] for row in rows]
        width = terminal_width(self._rich.file) if self._rich.is_terminal else None
        if width is not None:
            # rich would measure the standard streams, prefer COLUMNS and take 80 for TERM=dumb or unknown
            self._rich.size = (width, self._rich.height)
            if index is not None:
                rows = self._fit(columns, rows, index, width)
        mute = self._style(theme.MUTE)
        table = Table(box=None, show_edge=False, pad_edge=False)
        for name in columns:
            table.add_column(Text(name, style=self._style(theme.MUTE, bold=True)), overflow="fold")
        for row in rows:
            table.add_row(*(Text(cell, style=mute) for cell in row))
        self._start_line()
        self._rich.print(Padding(table, (0, 0, 0, len(self._indent)), expand=False))
        self._last = _LINE

    def _fit(self, columns: list[str], rows: list[list[str]], index: int, width: int) -> list[list[str]]:
        # shorten the one named column just enough for the table to fit the terminal
        widths = [max([cell_len(name), *(cell_len(row[i]) for row in rows)]) for i, name in enumerate(columns)]
        # columns are two spaces apart
        over = len(self._indent) + sum(widths) + 2 * (len(columns) - 1) - width
        if over <= 0:
            return rows
        keep = max(widths[index] - over, cell_len(columns[index]), CUT_KEEP + 3)

        def shorten(cell: str) -> str:
            return cell if cell_len(cell) <= keep else set_cell_size(cell, keep - 3) + "..."

        return [[*row[:index], shorten(row[index]), *row[index + 1 :]] for row in rows]

    # questions

    def ask(self, label: str, default: str | None = None) -> str:
        return self._ask(label, default)

    def ask_path(self, label: str, default: str | None = None) -> str:
        from prompt_toolkit.completion import PathCompleter

        return self._ask(label, default, completer=PathCompleter(expanduser=True))

    def _ask(self, label: str, default: str | None, completer=None) -> str:
        suffix = f" [{default}]" if default is not None else ""
        answer = self._prompt(f"{self._indent}{label:<12}{suffix} > ", completer=completer)
        if answer == "" and default is not None:
            return default
        return answer

    def confirm(self, question: str, default: bool = False) -> bool:
        hint = "[Y/n]" if default else "[y/N]"
        # a yes or no question stands on its own: a gap above and below
        self.gap()
        while True:
            answer = _yes_no(self._prompt(f"{self._indent}{question} {hint} > "), default)
            if answer is not None:
                self.gap()
                return answer
            self.fail(ANSWER_Y_OR_N)

    def _prompt(self, message: str, completer=None) -> str:
        from prompt_toolkit import prompt
        from prompt_toolkit.lexers import SimpleLexer

        self._start_line()
        try:
            return prompt(
                [("class:question", shown(message))],
                style=theme.prompt_style() if self._color else None,
                lexer=SimpleLexer("class:answer"),
                completer=completer,
            )
        except (KeyboardInterrupt, EOFError):
            raise Cancelled() from None
        finally:
            # prompt_toolkit draws the question itself; once answered the cursor is on a fresh line
            self._last = _LINE
