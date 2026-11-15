"""The timed plain-text copy of a recording (design section 7.4)."""

import copy
import unicodedata
from collections import defaultdict
from collections.abc import Iterable, Iterator
from datetime import date, datetime, tzinfo
from glob import escape as glob_escape
from pathlib import Path
from typing import NamedTuple

import pyte

from pwn_broker import store
from pwn_broker.cast import MAX_SIZE, CastError, Header, events, read_header
from pwn_broker.console import Console
from pwn_broker.model import Box

# private modes that switch to the alternate screen
_ALTERNATE = frozenset({1049, 1047, 47})


class _Line(NamedTuple):
    time: float | None  # seconds since the start; None for an empty line
    text: str
    until: float | None = None  # set for the full-screen program line


class _TextScreen(pyte.Screen):
    """A pyte screen that hands over each line as it leaves the screen.

    Per row it keeps the time of the last character drawn (`times`), whether the row continues
    the row above because the line wrapped (`wrapped`), and whether the row was already taken and
    blanked while the cursor stayed below it (`spent`), so it is not taken again as an empty line.
    All three move with the rows.
    """

    def __init__(self, columns: int, lines: int) -> None:
        self.now = 0.0
        self.times: dict[int, float] = {}
        self.wrapped: set[int] = set()
        self.spent: set[int] = set()
        self.taken: list[_Line] = []
        self.alternate = False
        self._drawing = False
        self._pending: list[str] = []
        self._pending_times: list[float] = []
        super().__init__(columns, lines)

    # what was taken

    def _row_text(self, y: int) -> str:
        line = self.buffer.get(y)
        if not line:
            return ""
        return "".join(line[x].data for x in range(self.columns))

    def _last_text_row(self) -> int:
        for y in range(self.lines - 1, -1, -1):
            if self._row_text(y).strip(" "):
                return y
        return -1

    def _flush(self) -> None:
        if not self._pending:
            return
        text = "".join(self._pending).rstrip(" ")
        if not text:
            self.taken.append(_Line(None, ""))
        else:
            when = max(self._pending_times) if self._pending_times else self.now
            self.taken.append(_Line(when, text))
        self._pending = []
        self._pending_times = []

    def _row_end(self, y: int) -> int:
        """The column of the last cell on the row that is not a space, or -1."""
        line = self.buffer.get(y) or {}
        cells = (x for x, char in line.items() if char.data != " " and x < self.columns)
        return max(cells, default=-1)

    def _take(self, y: int) -> None:
        if self.alternate or y in self.spent:
            return
        if y not in self.wrapped:
            self._flush()
        self._pending.append(self._row_text(y))
        if y in self.times:
            self._pending_times.append(self.times[y])

    def _take_rows(self, count: int) -> None:
        """Take the top `count` rows, leaving out blank rows with no text below them."""
        for y in range(min(count, self._last_text_row() + 1)):
            self._take(y)

    def _take_and_clear(self, count: int) -> None:
        """Take the top `count` rows now and blank them, so they are not taken again."""
        for y in range(count):
            self._take(y)
        self._flush()
        for y in range(count):
            self.buffer.pop(y, None)
            self.times.pop(y, None)
            self.wrapped.discard(y)
            self.spent.add(y)
        self.wrapped.discard(count)  # it continued a row that is gone

    def _move_rows(self, top: int, bottom: int, offset: int) -> None:
        """Move the rows from top to bottom by offset, as pyte moves the buffer."""

        def moved(y: int) -> int | None:
            if not top <= y <= bottom:
                return y
            return y + offset if top <= y + offset <= bottom else None

        times = {}
        for y, when in self.times.items():
            if (to := moved(y)) is not None:
                times[to] = when
        self.times = times
        self.wrapped = {to for y in self.wrapped if (to := moved(y)) is not None}
        self.spent = {to for y in self.spent if (to := moved(y)) is not None}

    def finish(self, last: float) -> list[_Line]:
        if self.alternate:
            self._leave_alternate(last)
        self._take_rows(self.lines)
        self._flush()
        return self.taken

    # drawing and moving rows

    def draw(self, data: str) -> None:
        data = _drawable(data)
        if not data:
            return
        self.times[self.cursor.y] = self.now
        self.spent.discard(self.cursor.y)
        self._drawing = True
        try:
            super().draw(data)
        finally:
            self._drawing = False
        self.times[self.cursor.y] = self.now

    def linefeed(self) -> None:
        super().linefeed()
        self.spent.discard(self.cursor.y)  # an empty line left here is a real one
        if self._drawing:  # pyte wrapping the line onto the next row
            self.wrapped.add(self.cursor.y)
            self.times[self.cursor.y] = self.now

    def index(self) -> None:
        top, bottom = self.margins or (0, self.lines - 1)
        if self.cursor.y == bottom:
            # a row leaving the top of the screen is taken, even when the region ends higher up
            if top == 0:
                self._take(top)
            self._move_rows(top, bottom, -1)
            if top != 0:
                self.wrapped.discard(top)
        super().index()

    def reverse_index(self) -> None:
        top, bottom = self.margins or (0, self.lines - 1)
        if self.cursor.y == top:
            self._move_rows(top, bottom, 1)
            self.wrapped.discard(top + 1)
        super().reverse_index()

    def _materialise(self, top: int, bottom: int) -> None:
        # pyte's insert_lines and delete_lines leave a row as it was when the row they would move
        # into it was never written to, so make every row exist first
        for y in range(top, bottom + 1):
            self.buffer[y]

    def insert_lines(self, count: int | None = None) -> None:
        count = count or 1
        top, bottom = self.margins or (0, self.lines - 1)
        if top <= self.cursor.y <= bottom:
            self._materialise(top, bottom)
            self._move_rows(self.cursor.y, bottom, count)
            self.wrapped.discard(self.cursor.y + count)
        super().insert_lines(count)

    def delete_lines(self, count: int | None = None) -> None:
        count = count or 1
        top, bottom = self.margins or (0, self.lines - 1)
        if top <= self.cursor.y <= bottom:
            self._materialise(top, bottom)
            self._move_rows(self.cursor.y, bottom, -count)
            self.wrapped.discard(self.cursor.y)
        super().delete_lines(count)

    def erase_in_display(self, how: int = 0, *args, **kwargs) -> None:
        if how in (2, 3):
            self._take_rows(self.lines)
            self.times.clear()
            self.wrapped.clear()
            self.spent.clear()
        elif how in (0, 1):
            erased = range(self.cursor.y + 1, self.lines) if how == 0 else range(self.cursor.y)
            self.wrapped.difference_update(erased)
        else:
            return  # pyte has no meaning for it and would fail
        super().erase_in_display(how, *args, **kwargs)

    def erase_in_line(self, how: int = 0, private: bool = False) -> None:
        if how not in (0, 1, 2):
            return  # pyte has no meaning for it and would fail
        if how == 2 or (how == 0 and self.cursor.x == 0):
            self.wrapped.discard(self.cursor.y)
        super().erase_in_line(how, private)

    def select_graphic_rendition(self, *attrs: int) -> None:
        pass  # colours are dropped, and pyte fails on some it does not know

    def reset(self) -> None:
        self._take_rows(self.lines)  # a reset clears the screen
        super().reset()
        self.times = {}
        self.wrapped = set()
        self.spent = set()

    def resize(self, lines: int | None = None, columns: int | None = None) -> None:
        lines = lines or self.lines
        columns = columns or self.columns
        if columns < self.columns and not self.alternate:
            # pyte cuts every row at the new width: take the rows down to the last one that would
            # lose text, with the rest of its wrapped line, before it does
            cut = [y for y in range(self.lines) if self._row_end(y) >= columns]
            if cut:
                last = cut[-1]
                while last + 1 in self.wrapped:
                    last += 1
                self._take_and_clear(last + 1)
        if lines < self.lines:
            self._take_rows(self.lines - lines)  # pyte drops them from the top
        super().resize(lines, columns)
        self.ensure_vbounds()
        if self.cursor.x > self.columns:
            self.cursor.x = self.columns

    # the alternate screen

    def set_mode(self, *modes: int, **kwargs) -> None:
        super().set_mode(*modes, **kwargs)
        if kwargs.get("private") and _ALTERNATE.intersection(modes) and not self.alternate:
            # the screen down to the command that started the program comes out before it
            y = self.cursor.y
            self._take_and_clear(y + 1 if self._row_end(y) >= 0 else y)
            self._main = (
                self.buffer, self.times, self.wrapped, self.spent,
                copy.copy(self.cursor), self.lines, self.columns,
            )  # fmt: skip
            self.buffer = defaultdict(self.buffer.default_factory)
            self.times = {}
            self.wrapped = set()
            self.spent = set()
            self.alternate = True
            self._since = self.now

    def reset_mode(self, *modes: int, **kwargs) -> None:
        super().reset_mode(*modes, **kwargs)
        if kwargs.get("private") and _ALTERNATE.intersection(modes) and self.alternate:
            self._leave_alternate(self.now)

    def _leave_alternate(self, until: float) -> None:
        self.buffer, self.times, self.wrapped, self.spent, self.cursor, lines, columns = self._main
        self.alternate = False
        if lines > self.lines or columns > self.columns:  # the window shrank while it ran
            now_lines, now_columns = self.lines, self.columns
            self.lines, self.columns = max(lines, now_lines), max(columns, now_columns)
            self.resize(lines=now_lines, columns=now_columns)
        self.ensure_vbounds()
        self.ensure_hbounds()
        self._flush()
        self.taken.append(_Line(self._since, "", until))


def _drawable(data: str) -> str:
    """The text without characters that take no cell and combine with nothing.

    pyte's draw stops at the first of them (U+200B, U+FE0F, a stray control character), dropping
    the rest of the text.
    """
    if data.isascii() and data.isprintable():
        return data
    width = pyte.screens.wcwidth
    return "".join(c for c in data if width(c) > 0 or (width(c) == 0 and unicodedata.combining(c)))


def _size(data: str) -> tuple[int, int] | None:
    cols, _, rows = data.partition("x")
    if not (cols.isdecimal() and rows.isdecimal()):
        return None
    cols_n, rows_n = int(cols), int(rows)
    if not (1 <= cols_n <= MAX_SIZE and 1 <= rows_n <= MAX_SIZE):
        return None
    return cols_n, rows_n


class _Clock:
    def __init__(self, timestamp: int | None, tz: tzinfo) -> None:
        self.timestamp = timestamp
        self.tz = tz
        self.last_date = self.date_of(0.0)

    def date_of(self, elapsed: float) -> date | None:
        if self.timestamp is None:
            return None
        return datetime.fromtimestamp(self.timestamp + elapsed, self.tz).date()

    def time_of(self, elapsed: float) -> str:
        if self.timestamp is None:
            seconds = int(elapsed)
            return f"{seconds // 3600:02d}:{seconds // 60 % 60:02d}:{seconds % 60:02d}"
        return datetime.fromtimestamp(self.timestamp + elapsed, self.tz).strftime("%H:%M:%S")

    def lines(self, taken: list[_Line]) -> Iterator[str]:
        for line in taken:
            if line.time is None:
                yield ""
                continue
            day = self.date_of(line.time)
            # a row redrawn later can come out above an earlier one: never go back a day
            if day is not None and day > self.last_date:
                yield f"---- {day.isoformat()} ----"
                self.last_date = day
            text = line.text
            if line.until is not None:
                text = f"[full-screen program until {self.time_of(line.until)}, see the cast]"
            yield f"{self.time_of(line.time)}  {text}"


def render(header: Header, events: Iterable[tuple[float, str, str]], tz: tzinfo) -> Iterator[str]:
    """The body lines of the text copy, without line breaks."""
    screen = _TextScreen(header.cols, header.rows)
    stream = pyte.Stream(screen)
    clock = _Clock(header.timestamp, tz)
    last = 0.0
    for elapsed, code, data in events:
        last = screen.now = elapsed
        if code == "o":
            stream.feed(data)
        elif code == "r" and (size := _size(data)):
            screen.resize(lines=size[1], columns=size[0])
        if screen.taken:
            yield from clock.lines(screen.taken)
            screen.taken.clear()
    yield from clock.lines(screen.finish(last))


def text_path(cast_path: Path) -> Path:
    return cast_path.with_suffix(".txt")


def write(cast_path: Path, *, box_name: str, box_id: str, target: str, tz: tzinfo) -> Path:
    header = read_header(cast_path)
    try:
        body = list(render(header, events(cast_path), tz))
    except (CastError, OSError):
        raise
    except Exception as exc:  # pyte's own failures on input it cannot handle
        raise CastError(f"{cast_path}: could not be rendered ({type(exc).__name__})") from exc
    if header.timestamp is None:
        started = "unknown"
    else:
        started = datetime.fromtimestamp(header.timestamp, tz).strftime("%Y-%m-%d %H:%M:%S")
    lines = [
        f"box      {box_name}  {box_id}",
        f"target   {target}",
        f"started  {started}",
        f"cast     {cast_path.name}",
        "",
        *body,
    ]
    out = text_path(cast_path)
    store.write_text(out, "\n".join(lines) + "\n")
    return out


def stale(cast_path: Path) -> bool:
    """True when the text copy is missing or older than its recording."""
    out = text_path(cast_path)
    try:
        written = out.stat().st_mtime_ns
    except FileNotFoundError:
        return True
    return written < cast_path.stat().st_mtime_ns


def cast_files(box: Box, target: str | None = None) -> list[Path]:
    """Every targets/<target>/recordings/*.cast in the box, or of one target, by target then name."""
    folder = "*" if target is None else glob_escape(target)
    found = (box.path / "targets").glob(f"{folder}/recordings/*.cast")
    return sorted((p for p in found if p.is_file()), key=lambda p: (p.parent.parent.name, p.name))


def refresh(box: Box, console: Console, *, tz: tzinfo, target: str | None = None) -> None:
    """Write the text copy of every recording whose text is missing or older than its cast.

    A recording still being written is read as far as its last whole line. A cast that cannot be
    read gets one warn line and no text; the others are still written.
    """
    for cast_path in cast_files(box, target):
        shown = cast_path.relative_to(box.path).as_posix()
        target_name = cast_path.parent.parent.name
        try:
            if stale(cast_path):
                write(cast_path, box_name=box.name, box_id=box.id, target=target_name, tz=tz)
        except (CastError, OSError) as exc:
            console.warn(f"no text copy of {shown}: {exc}")
