"""The timed plain-text copy of a recording (design section 7.4)."""

import copy
import os
import re
import stat
import time
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

# The time a text copy may take. pyte's work is counted in the screen's cells, not in the cast's
# bytes: four bytes clear a 1000 by 1000 screen, so a crafted cast of a few hundred bytes took
# minutes. A cast gets this many seconds for each megabyte of it, room for a real recording that
# size on a busy machine, and a base: record gives its own recording the whole of it, and refresh
# shares it between the casts it writes, each taking at most RENDER_SECONDS_EACH of it. One that
# takes longer gets a text copy that says so (section 7.4).
RENDER_SECONDS = 60
RENDER_SECONDS_PER_MB = 60
# what each cast refresh writes may take of the shared allowance at most, besides its own share by
# size: so a crafted cast early in the order spends seconds, not the minute the others need
RENDER_SECONDS_EACH = 10
# and the most one cast gets, however large: by its size alone a cast of 96 MiB from an archive
# would get more than an hour and a half, and export, finish or replay would wait for it. A real
# recording of hours is a few megabytes.
MAX_RENDER_SECONDS = 600
_clock = time.monotonic
# pyte draws a run of plain text in one call, whose cost can grow with the square of its length
# (combining marks) or with the screen's width for each character (insert mode): an event's data
# is fed in pieces this long, so the deadline is looked at between them
_FEED = 256


class Allowance(NamedTuple):
    deadline: float
    seconds: int


def allowance(size: int) -> Allowance:
    """From now, for a cast of `size` bytes with the whole base."""
    return _allowed(RENDER_SECONDS, size, _clock())


def _allowed(base: float, size: int, now: float) -> Allowance:
    seconds = min(base + RENDER_SECONDS_PER_MB * size / 1_000_000, MAX_RENDER_SECONDS)
    return Allowance(now + seconds, round(seconds))


def _spoken(seconds: int) -> str:
    if seconds < 1:
        return "less than a second"
    return "1 second" if seconds == 1 else f"{seconds} seconds"


class OutOfTime(CastError):
    """A text copy that took longer than its allowance."""


class _TooLong(Exception):
    pass


class _Timed:
    """The screen, with the deadline checked before each thing the stream asks of it."""

    def __init__(self, screen: pyte.Screen, deadline: float) -> None:
        self._screen = screen
        self._deadline = deadline

    def __getattr__(self, name: str):
        value = getattr(self._screen, name)
        if not callable(value):
            return value

        def timed(*args, **kwargs):
            if _clock() > self._deadline:
                raise _TooLong
            return value(*args, **kwargs)

        return timed


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

    def _row_text(self, y: int, full: bool = False) -> str:
        """The row's text to its last cell, or to the screen's width when `full`: a row the next one
        continues keeps its trailing spaces, which the wrap would otherwise lose."""
        line = self.buffer.get(y)
        if not line:
            return " " * self.columns if full else ""
        end = self.columns if full else min(self.columns, max(line) + 1)
        return "".join(line[x].data for x in range(end))

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
        self._pending.append(self._row_text(y, full=y + 1 in self.wrapped))
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
            self.wrapped.discard(bottom + 1)  # below a region that ends higher up
        super().index()

    def reverse_index(self) -> None:
        top, bottom = self.margins or (0, self.lines - 1)
        if self.cursor.y == top:
            self._move_rows(top, bottom, 1)
            self.wrapped.discard(top + 1)
            self.wrapped.discard(bottom + 1)
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
            self.wrapped.discard(bottom + 1)
        super().insert_lines(count)

    def delete_lines(self, count: int | None = None) -> None:
        count = count or 1
        top, bottom = self.margins or (0, self.lines - 1)
        if top <= self.cursor.y <= bottom:
            self._materialise(top, bottom)
            self._move_rows(self.cursor.y, bottom, -count)
            self.wrapped.discard(self.cursor.y)
            self.wrapped.discard(bottom + 1)
        super().delete_lines(count)

    def alignment_display(self) -> None:
        # ESC # 8, the screen alignment test: it fills every cell with E in one call, which a text
        # copy has no use for and a crafted cast leans on (seconds on a 1000 by 1000 screen)
        pass

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
        # pyte writes a blank cell into every place it erases, so a few bytes could fill a screen
        # whose cells a later call touches one by one; a cell that is not there reads as a space
        if how == 0:
            rows = range(self.cursor.y + 1, self.lines)
        elif how == 1:
            rows = range(self.cursor.y)
        else:
            rows = range(self.lines)
        for y in rows:
            self.buffer.pop(y, None)
        if how in (0, 1):
            self.erase_in_line(how)

    def erase_in_line(self, how: int = 0, private: bool = False) -> None:
        if how not in (0, 1, 2):
            return  # pyte has no meaning for it and would fail
        if how == 2 or (how == 0 and self.cursor.x == 0):
            self.wrapped.discard(self.cursor.y)
        line = self.buffer.get(self.cursor.y)
        if not line:
            return
        x = self.cursor.x
        for column in [c for c in line if how == 2 or (c >= x if how == 0 else c <= x)]:
            del line[column]

    def erase_characters(self, count: int | None = None) -> None:
        line = self.buffer.get(self.cursor.y)
        if not line:
            return
        end = min(self.cursor.x + (count or 1), self.columns)
        for column in [c for c in line if self.cursor.x <= c < end]:
            del line[column]

    def insert_characters(self, count: int | None = None) -> None:
        # pyte writes a blank cell into every column from the cursor to the edge, so three bytes
        # filled a row: move the cells there are, and store no blank ones (insert mode draws so too)
        count = count or 1
        line = self.buffer.get(self.cursor.y)
        if not line:
            return
        moved = {c + count: line.pop(c) for c in sorted(line) if c >= self.cursor.x}
        line.update((c, char) for c, char in moved.items() if c < self.columns)

    def delete_characters(self, count: int | None = None) -> None:
        count = count or 1
        line = self.buffer.get(self.cursor.y)
        if not line:
            return
        moved = {c - count: line.pop(c) for c in sorted(line) if c >= self.cursor.x}
        line.update((c, char) for c, char in moved.items() if c >= self.cursor.x)

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
        modes = _without_reverse_video(modes, kwargs)
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
        modes = _without_reverse_video(modes, kwargs)
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


def _without_reverse_video(modes: tuple[int, ...], kwargs: dict) -> tuple[int, ...]:
    # DECSCNM, private mode 5 or the plain mode pyte shifts it to (160): pyte rewrites every stored
    # cell for it; a text copy has no colours
    shift = 5 if kwargs.get("private") else 0
    return tuple(m for m in modes if m << shift != pyte.modes.DECSCNM)


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


def render(
    header: Header, events: Iterable[tuple[float, str, str]], tz: tzinfo, deadline: float | None = None
) -> Iterator[str]:
    """The body lines of the text copy, without line breaks; _TooLong past the deadline."""
    screen = _TextScreen(header.cols, header.rows)
    drawn = screen if deadline is None else _Timed(screen, deadline)
    stream = pyte.Stream(drawn)
    clock = _Clock(header.timestamp, tz)
    last = 0.0
    for elapsed, code, data in events:
        last = screen.now = elapsed
        if code == "o":
            for start in range(0, len(data), _FEED):
                # here too: an escape sequence that never ends calls no screen method
                if deadline is not None and _clock() > deadline:
                    raise _TooLong
                stream.feed(data[start : start + _FEED])
        elif code == "r" and (size := _size(data)):
            drawn.resize(lines=size[1], columns=size[0])
        if screen.taken:
            yield from clock.lines(screen.taken)
            screen.taken.clear()
    # the last flush reads every row there is, so it waits for the deadline too
    if deadline is not None and _clock() > deadline:
        raise _TooLong
    yield from clock.lines(screen.finish(last))


def text_path(cast_path: Path) -> Path:
    return cast_path.with_suffix(".txt")


def _started(cast_path: Path, header: Header, tz: tzinfo) -> str:
    if header.timestamp is None:
        return "unknown"
    try:
        return datetime.fromtimestamp(header.timestamp, tz).strftime("%Y-%m-%d %H:%M:%S")
    except (OverflowError, ValueError, OSError) as exc:
        # the header allows up to 9999 in UTC; the VM's time, or this system, may hold less
        raise CastError(cast_path, f"the start time {header.timestamp} cannot be shown as a date") from exc


def _head(cast_path: Path, box_name: str, box_id: str, target: str, started: str) -> list[str]:
    return [
        f"box      {box_name}  {box_id}",
        f"target   {target}",
        f"started  {started}",
        f"cast     {cast_path.name}",
        "",
    ]


# How a text copy is written. The name of a cast, or of the folder it is in, need not be UTF-8,
# and a text file cannot hold such a byte: it is written as "?". Refused instead, it stopped the
# export or finish that was writing the text copy, and no archive was made.
_UNWRITABLE = "replace"


def write(
    cast_path: Path,
    *,
    box_name: str,
    box_id: str,
    target: str,
    tz: tzinfo,
    allowed: Allowance | None = None,
    note: bool = True,
) -> Path:
    out = text_path(cast_path)
    # a folder or a link in its place, from an archive: the write would fail after the rendering,
    # on every command, and a link would be read through
    if os.path.lexists(out) and not stat.S_ISREG(os.lstat(out).st_mode):
        raise CastError(cast_path, f"{out.name} is not a file")
    header = read_header(cast_path)
    # first: every time in the text is the start time plus a little
    started = _started(cast_path, header, tz)
    if allowed is None:
        allowed = allowance(cast_path.stat().st_size)
    head = _head(cast_path, box_name, box_id, target, started)
    # A note, so the next export, finish or replay does not spend the time on it again: for a cast
    # past its time when it had a fair share (note), not when the casts before it spent the base;
    # for one that fails part of the way in always, as it fails the same however long it is given,
    # but not for a read error, which may be gone next time
    try:
        body = list(render(header, events(cast_path), tz, allowed.deadline))
    except _TooLong:
        took = _spoken(allowed.seconds)
        if note:
            _note(cast_path, head, f"it took longer than {took} to make; replay plays the cast")
        why = "it had less than a second to render" if allowed.seconds < 1 else f"it took longer than {took} to render"
        raise OutOfTime(cast_path, f"{why}; replay still plays it") from None
    except CastError as exc:  # a bad line after the ones before it were drawn
        if not isinstance(exc.__cause__, OSError):
            _note(cast_path, head, exc.reason)
        raise
    except Exception as exc:  # pyte's own failures on input it cannot handle, and a time past a date's
        failed = CastError(cast_path, f"could not be rendered ({type(exc).__name__})")
        _note(cast_path, head, failed.reason)
        raise failed from exc
    lines = [*head, *body]
    store.write_text(out, "\n".join(lines) + "\n", errors=_UNWRITABLE)
    # no earlier than its cast, whose time an archive may set in the future, or it stays stale
    when = max(time.time_ns(), cast_path.stat().st_mtime_ns)
    os.utime(out, ns=(when, when))
    return out


# the last line of a note, and of a text copy kept from before its recording went on
_NOTE = "[no text copy: "
_STOPS = "[the text copy stops here: "
# what is read of a text copy kept or looked at: the end, where those lines are
_TAIL = 4096


def _open_file(path: Path, writing: bool = False):
    """The file opened without following a link, or None when it is anything but a regular file,
    or, to write, a file with another name too (a hard link), which a change in place would change
    as well; OSError when it cannot be opened (a link, where the system can refuse one)."""
    flags = os.O_RDWR if writing else os.O_RDONLY
    for name in ("O_NOFOLLOW", "O_NONBLOCK", "O_BINARY"):
        flags |= getattr(os, name, 0)
    fh = os.fdopen(os.open(path, flags), "r+b" if writing else "rb")
    try:
        opened, there = os.fstat(fh.fileno()), os.lstat(path)
    except OSError:
        fh.close()
        raise
    plain = stat.S_ISREG(opened.st_mode) and stat.S_ISREG(there.st_mode) and os.path.samestat(opened, there)
    if plain and (opened.st_nlink == 1 or not writing):
        return fh
    fh.close()
    return None


def _last_line(fh) -> tuple[int, bytes]:
    """Where the file's last line starts, and the line, from no more than its last _TAIL bytes;
    -1 and those bytes for a last line longer than that."""
    size = fh.seek(0, os.SEEK_END)
    start = max(0, size - _TAIL)
    fh.seek(start)
    tail = fh.read()
    at = tail.rfind(b"\n", 0, max(0, len(tail) - 1))
    if at < 0 and start > 0:
        return -1, tail
    return start + at + 1, tail[at + 1 :]


def has_copy(cast_path: Path) -> bool:
    """True when the recording has a text copy of it, not a note saying why it has none."""
    try:
        fh = _open_file(text_path(cast_path))
    except OSError:
        return False
    if fh is None:
        return False
    with fh:
        return not _last_line(fh)[1].startswith(_NOTE.encode())


def _note(cast_path: Path, head: list[str], why: str) -> None:
    """A text copy that says why there is none, or the one the cast already has with a last line
    saying where it stops, dated no earlier than its cast, so it is no longer stale; deleting it
    tries again. A kept one is changed in place, and only its end is read, however large it is;
    one that cannot be changed safely in place (a link put there, or a hard link) is replaced by
    the note, which changes that name and nothing it points to."""
    out = text_path(cast_path)
    fh = None
    if os.path.lexists(out):
        try:
            fh = _open_file(out, writing=True)
        except OSError:
            pass
    if fh is None:
        store.write_text(out, "\n".join([*head, f"{_NOTE}{why}]"]) + "\n", errors=_UNWRITABLE)
    else:
        with fh:
            at, last = _last_line(fh)
            # a note or a stop line from an earlier time is replaced, so it is said once
            again = at >= 0 and last.startswith((_NOTE.encode(), _STOPS.encode()))
            line = _NOTE if again and last.startswith(_NOTE.encode()) else _STOPS
            if again:
                fh.seek(at)
                fh.truncate()
            else:
                fh.seek(0, os.SEEK_END)
                if last and not last.endswith(b"\n"):
                    fh.write(b"\n")
            fh.write(f"{line}{why}]\n".encode())
    when = max(time.time_ns(), cast_path.stat().st_mtime_ns)
    os.utime(out, ns=(when, when))


def stale(cast_path: Path) -> bool:
    """True when the text copy is missing or older than its recording, or is not a file, which
    write refuses with a warn line."""
    try:
        there = os.lstat(text_path(cast_path))
    except FileNotFoundError:
        return True
    return not stat.S_ISREG(there.st_mode) or there.st_mtime_ns < cast_path.stat().st_mtime_ns


# record's names: the start time to the minute, then -2, -3 and so on for later ones that minute
_CAST_NAME = re.compile(r"(\d{4}-\d{2}-\d{2}_\d{4})(?:-([1-9]\d*))?\.cast", re.ASCII)


def _made(cast_path: Path) -> tuple:
    """Sorts recordings oldest first: by start time, then number; other names after, by name."""
    match = _CAST_NAME.fullmatch(cast_path.name)
    if match is None:
        return (1, cast_path.name, 0)
    return (0, match[1], int(match[2] or 1))


def cast_files(box: Box, target: str | None = None) -> list[Path]:
    """Every targets/<target>/recordings/*.cast in the box, or of one target: by target, oldest first."""
    folder = "*" if target is None else glob_escape(target)
    found = (box.path / "targets").glob(f"{folder}/recordings/*.cast")
    return sorted((p for p in found if p.is_file()), key=lambda p: (p.parent.parent.name, _made(p)))


def refresh(box: Box, console: Console, *, tz: tzinfo, target: str | None = None) -> None:
    """Write the text copy of every recording whose text is missing or older than its cast.

    A recording still being written is read as far as its last whole line. A cast whose header
    cannot be read gets one warn line and no text, and one that fails further in a warn line and a
    text copy that says why; the others are still written.
    """
    casts = cast_files(box, target)
    # the base is shared, spent as the time goes by; the time by size is each cast's own, from its
    # own start, so casts that overrun spend the base and never another cast's time
    base_ends = _clock() + RENDER_SECONDS
    stopped = False
    left = 0
    for cast_path in casts:
        shown = cast_path.relative_to(box.path).as_posix()
        target_name = cast_path.parent.parent.name
        what = f"no text copy of {shown}"
        fair = True
        try:
            if not stale(cast_path):
                continue
            if stopped:
                left += 1
                continue
            if has_copy(cast_path):
                what = f"the text copy of {shown} is not up to date"
            now = _clock()
            base = min(RENDER_SECONDS_EACH, max(0.0, base_ends - now))
            allowed = _allowed(base, cast_path.stat().st_size, now)
            fair = base >= 1
            write(
                cast_path, box_name=box.name, box_id=box.id, target=target_name, tz=tz,
                allowed=allowed, note=fair,
            )  # fmt: skip
        except CastError as exc:
            console.warn(f"{what}: {exc.reason}")
            # one that ran out of time or failed with the base already spent ends the rendering:
            # the rest wait for the next export, finish or replay, so crafted casts cost one base
            # and one cast's time, not each their own
            stopped = not fair
        except OSError as exc:
            console.warn(f"{what}: {exc.strerror or exc}")
            stopped = not fair
    if left:
        them = "1 recording" if left == 1 else f"{left} recordings"
        console.warn(f"{them} got no text copy this time; the next export, finish or replay tries them again")
