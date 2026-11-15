from collections.abc import Mapping
from typing import Protocol, TextIO

from rich.console import Console as RichConsole
from rich.style import Style
from rich.table import Table
from rich.text import Text

from . import theme


class Cancelled(Exception):
    pass


class Console(Protocol):
    def ask(self, label: str, default: str | None = None) -> str: ...
    def confirm(self, question: str, default: bool = False) -> bool: ...
    def ok(self, text: str) -> None: ...
    def warn(self, text: str) -> None: ...
    def fail(self, text: str) -> None: ...
    def info(self, text: str) -> None: ...
    def raw(self, text: str) -> None: ...
    def table(self, columns: list[str], rows: list[list[str]]) -> None: ...


def status_line(kind: str, text: str) -> str:
    return f"{kind:<4}  {text}"


def _answer_to_bool(answer: str, default: bool) -> bool:
    if answer == "":
        return default
    return answer in ("y", "yes")


class FakeConsole:
    def __init__(self, answers: list[str] | None = None) -> None:
        self._answers = list(answers or [])
        self.lines: list[tuple[str, str]] = []
        self.tables: list[tuple[list[str], list[list[str]]]] = []
        self.asked: list[str] = []

    def _next(self, question: str) -> str:
        self.asked.append(question)
        if not self._answers:
            raise Cancelled()
        return self._answers.pop(0)

    def ask(self, label: str, default: str | None = None) -> str:
        answer = self._next(label)
        if answer == "" and default is not None:
            return default
        return answer

    def confirm(self, question: str, default: bool = False) -> bool:
        return _answer_to_bool(self._next(question), default)

    def ok(self, text: str) -> None:
        self.lines.append(("ok", text))

    def warn(self, text: str) -> None:
        self.lines.append(("warn", text))

    def fail(self, text: str) -> None:
        self.lines.append(("fail", text))

    def info(self, text: str) -> None:
        self.lines.append(("info", text))

    def raw(self, text: str) -> None:
        self.lines.append(("raw", text))

    def table(self, columns: list[str], rows: list[list[str]]) -> None:
        self.tables.append((columns, rows))


_KIND_COLOR = {"ok": theme.MINT, "warn": theme.AMBER, "fail": theme.RASPBERRY}


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

    def _style(self, color: str, bold: bool = False) -> Style:
        return Style(color=color, bold=bold) if self._color else Style()

    def _status(self, kind: str, text: str) -> None:
        line = Text(no_wrap=True)
        full = status_line(kind, text)
        line.append(full[:4], self._style(_KIND_COLOR[kind]))
        line.append(full[4:], self._style(theme.TEXT))
        self._rich.print(line, soft_wrap=True)

    def ok(self, text: str) -> None:
        self._status("ok", text)

    def warn(self, text: str) -> None:
        self._status("warn", text)

    def fail(self, text: str) -> None:
        self._status("fail", text)

    def info(self, text: str) -> None:
        self._rich.print(Text(text, style=self._style(theme.MUTE)), soft_wrap=True)

    def raw(self, text: str) -> None:
        # rich would expand tabs and wrap; this output exists to be copied
        stream = self._rich.file
        stream.write(text + "\n")
        stream.flush()

    def table(self, columns: list[str], rows: list[list[str]]) -> None:
        mute = self._style(theme.MUTE)
        table = Table(box=None, show_edge=False, pad_edge=False)
        for name in columns:
            table.add_column(Text(name, style=self._style(theme.MUTE, bold=True)), overflow="fold")
        for row in rows:
            table.add_row(*(Text(cell, style=mute) for cell in row))
        self._rich.print(table)

    def ask(self, label: str, default: str | None = None) -> str:
        suffix = f" [{default}]" if default is not None else ""
        answer = self._prompt(f"{label:<12}{suffix} > ")
        if answer == "" and default is not None:
            return default
        return answer

    def confirm(self, question: str, default: bool = False) -> bool:
        hint = "[Y/n]" if default else "[y/N]"
        return _answer_to_bool(self._prompt(f"{question} {hint} > "), default)

    def _prompt(self, message: str) -> str:
        from prompt_toolkit import prompt

        try:
            return prompt(
                [("class:prompt", message)],
                style=theme.prompt_style() if self._color else None,
            )
        except (KeyboardInterrupt, EOFError):
            raise Cancelled() from None
