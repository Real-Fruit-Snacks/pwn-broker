"""The timed plain-text copy of a recording (design section 7.4)."""

import copy
from collections import defaultdict
from collections.abc import Iterable, Iterator
from datetime import date, datetime, tzinfo
from pathlib import Path
from typing import NamedTuple

import pyte

from pwn_broker import store
from pwn_broker.cast import MAX_SIZE, CastError, Header, events, read_header

# private modes that switch to the alternate screen
_ALTERNATE = frozenset({1049, 1047, 47})


class _Line(NamedTuple):
    time: float | None  # seconds since the start; None for an empty line
    text: str
    until: float | None = None  # set for the full-screen program line


class _TextScreen(pyte.Screen):
    """A pyte screen that hands over each line as it leaves the screen.

    Per row it keeps the time of the last character drawn (`times`) and whether the row continues
    the row above because the line wrapped (`wrapped`). Both move with the rows.
    """

    def __init__(self, columns: int, lines: int) -> None:
        self.now = 0.0
        self.times: dict[int, float] = {}
        self.wrapped: set[int] = set()
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

    def _take(self, y: int) -> None:
        if self.alternate:
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

    def finish(self, last: float) -> list[_Line]:
        if self.alternate:
            self._leave_alternate(last)
        self._take_rows(self.lines)
        self._flush()
        return self.taken

    # drawing and moving rows

    def draw(self, data: str) -> None:
        self.times[self.cursor.y] = self.now
        self._drawing = True
        try:
            super().draw(data)
        finally:
            self._drawing = False
        self.times[self.cursor.y] = self.now

    def linefeed(self) -> None:
        super().linefeed()
        if self._drawing:  # pyte wrapping the line onto the next row
            self.wrapped.add(self.cursor.y)
            self.times[self.cursor.y] = self.now

    def index(self) -> None:
        top, bottom = self.margins or (0, self.lines - 1)
        if self.cursor.y == bottom:
            whole_screen = top == 0 and bottom == self.lines - 1
            if whole_screen:
                self._take(top)
            self._move_rows(top, bottom, -1)
            if not whole_screen:
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

    def resize(self, lines: int | None = None, columns: int | None = None) -> None:
        lines = lines or self.lines
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
            self._main = (self.buffer, self.times, self.wrapped, copy.copy(self.cursor), self.lines)
            self.buffer = defaultdict(self.buffer.default_factory)
            self.times = {}
            self.wrapped = set()
            self.alternate = True
            self._since = self.now

    def reset_mode(self, *modes: int, **kwargs) -> None:
        super().reset_mode(*modes, **kwargs)
        if kwargs.get("private") and _ALTERNATE.intersection(modes) and self.alternate:
            self._leave_alternate(self.now)

    def _leave_alternate(self, until: float) -> None:
        self.buffer, self.times, self.wrapped, self.cursor, lines = self._main
        self.alternate = False
        if lines > self.lines:  # the window got shorter while the program ran
            shorter = self.lines
            self.lines = lines
            self.resize(lines=shorter)
        self.ensure_vbounds()
        self.ensure_hbounds()
        self._flush()
        self.taken.append(_Line(self._since, "", until))


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
            if day != self.last_date:
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
