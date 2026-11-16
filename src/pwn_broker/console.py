from collections.abc import Iterator, Mapping
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
    def heading(self, text: str) -> None: ...
    def fields(self, rows: list[tuple[str, str]]) -> None: ...
    def gap(self) -> None: ...
    def block(self) -> AbstractContextManager[None]: ...
    def raw(self, text: str) -> None: ...
    def table(self, columns: list[str], rows: list[list[str]], *, cut: str | None = None) -> None: ...


def status_line(kind: str, text: str) -> str:
    return f"{kind:<4}  {text}"


# a detail starts under the text of the status line above it
DETAIL_INDENT = INDENT + " " * len(status_line("ok", ""))

ANSWER_Y_OR_N = "answer y or n"


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
        while True:
            self.events.append(("confirm", question))
            answer = _yes_no(self._next(question), default)
            if answer is not None:
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

    def heading(self, text: str) -> None:
        self._line("heading", text)

    def fields(self, rows: list[tuple[str, str]]) -> None:
        for label, value in rows:
            self._line("field", f"{label}  {value}")

    def gap(self) -> None:
        self.events.append(("gap", ""))

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
    def __init__(self, env: Mapping[str, str], out: TextIO | None = None) -> None:
        self._color = theme.color_enabled(env)
        options: dict = {"highlight": False, "markup": False, "emoji": False}
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

    @contextmanager
    def block(self) -> Iterator[None]:
        if self._depth == 0:
            # the line before a block may be one this console did not write, such as the prompt
            self._last = _LINE
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
        stream.write("".join(style.render(text, color_system=system) for text, style in parts) + "\n")
        stream.flush()
        self._last = _LINE

    def _status(self, kind: str, text: str) -> None:
        full = status_line(kind, text)
        self._write(
            (INDENT, Style()), (full[:4], self._style(_KIND_COLOR[kind])), (full[4:], self._style(theme.TEXT))
        )

    def ok(self, text: str) -> None:
        self._status("ok", text)

    def warn(self, text: str) -> None:
        self._status("warn", text)

    def fail(self, text: str) -> None:
        self._status("fail", text)

    def info(self, text: str) -> None:
        self._write((INDENT, Style()), (text, self._style(theme.MUTE)))

    def detail(self, text: str) -> None:
        self._write((DETAIL_INDENT, Style()), (text, self._style(theme.MUTE)))

    def heading(self, text: str) -> None:
        self.gap()
        self._write((text, self._style(theme.TEXT, bold=True)))

    def fields(self, rows: list[tuple[str, str]]) -> None:
        width = max((len(label) for label, _ in rows), default=0) + 2
        for label, value in rows:
            self._write(
                (INDENT, Style()), (f"{label:<{width}}", self._style(theme.MUTE)), (value, self._style(theme.TEXT))
            )

    def raw(self, text: str) -> None:
        # this output exists to be copied, so it is written byte for byte and flush left
        self._start_line()
        stream = self._rich.file
        stream.write(text + "\n")
        stream.flush()
        self._last = _LINE

    def table(self, columns: list[str], rows: list[list[str]], *, cut: str | None = None) -> None:
        index = _cut_column(columns, cut)
        if index is not None and self._rich.is_terminal:
            rows = self._fit(columns, rows, index)
        mute = self._style(theme.MUTE)
        table = Table(box=None, show_edge=False, pad_edge=False)
        for name in columns:
            table.add_column(Text(name, style=self._style(theme.MUTE, bold=True)), overflow="fold")
        for row in rows:
            table.add_row(*(Text(cell, style=mute) for cell in row))
        self._start_line()
        self._rich.print(Padding(table, (0, 0, 0, len(INDENT)), expand=False))
        self._last = _LINE

    def _fit(self, columns: list[str], rows: list[list[str]], index: int) -> list[list[str]]:
        # shorten the one named column just enough for the table to fit the terminal
        widths = [max([cell_len(name), *(cell_len(row[i]) for row in rows)]) for i, name in enumerate(columns)]
        # columns are two spaces apart
        over = len(INDENT) + sum(widths) + 2 * (len(columns) - 1) - self._rich.width
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
        answer = self._prompt(f"{INDENT}{label:<12}{suffix} > ", completer=completer)
        if answer == "" and default is not None:
            return default
        return answer

    def confirm(self, question: str, default: bool = False) -> bool:
        hint = "[Y/n]" if default else "[y/N]"
        while True:
            answer = _yes_no(self._prompt(f"{INDENT}{question} {hint} > "), default)
            if answer is not None:
                return answer
            self.fail(ANSWER_Y_OR_N)

    def _prompt(self, message: str, completer=None) -> str:
        from prompt_toolkit import prompt
        from prompt_toolkit.lexers import SimpleLexer

        self._start_line()
        try:
            return prompt(
                [("class:question", message)],
                style=theme.prompt_style() if self._color else None,
                lexer=SimpleLexer("class:answer"),
                completer=completer,
            )
        except (KeyboardInterrupt, EOFError):
            raise Cancelled() from None
        finally:
            # prompt_toolkit draws the question itself; once answered the cursor is on a fresh line
            self._last = _LINE
