import os
import time
from datetime import datetime

import pytest
from casts import START, TZ, cast_text, write_cast

from pwn_broker import casttext
from pwn_broker.cast import CastError, Header


def render(events, *, cols=80, rows=24, timestamp=START):
    return list(casttext.render(Header(cols, rows, timestamp, "t"), events, TZ))


def test_two_plain_lines_get_their_own_times():
    assert render([(0, "o", "one\r\n"), (5, "o", "two\r\n")]) == [
        "14:32:07  one",
        "14:32:12  two",
    ]


def test_a_line_takes_the_time_of_its_last_character():
    assert render([(0, "o", "$ "), (4, "o", "ls\r\n")]) == ["14:32:11  $ ls"]


def test_a_redrawn_line_appears_once_as_it_last_stood():
    events = [(0, "o", "50%"), (1, "o", "\r75%"), (3, "o", "\r\x1b[Kdone\r\n")]
    assert render(events) == ["14:32:10  done"]


def test_a_wrapped_line_comes_out_as_one():
    long = "".join(str(n % 10) for n in range(200))
    assert render([(0, "o", long + "\r\n")]) == ["14:32:07  " + long]


def test_a_wrapped_line_is_joined_across_a_scroll():
    long = "a" * 50 + "b" * 50 + "c" * 30
    events = [(0, "o", "one\r\ntwo\r\n"), (1, "o", long + "\r\n"), (2, "o", "end")]
    assert render(events, cols=50, rows=3) == [
        "14:32:07  one",
        "14:32:07  two",
        "14:32:08  " + long,
        "14:32:09  end",
    ]


def test_more_lines_than_rows_all_appear_in_order():
    text = "\r\n".join(f"line{n:02d}" for n in range(1, 31))
    assert render([(0, "o", text)]) == [f"14:32:07  line{n:02d}" for n in range(1, 31)]


def test_clearing_the_screen_keeps_what_was_on_it():
    events = [
        (0, "o", "one\r\ntwo\r\n$ cle"),
        (2, "o", "\x1b[2J\x1b[H$ clear\r\n"),
        (3, "o", "three"),
    ]
    assert render(events) == [
        "14:32:07  one",
        "14:32:07  two",
        "14:32:07  $ cle",
        "14:32:09  $ clear",
        "14:32:10  three",
    ]


def test_erase_3_also_takes_the_screen():
    assert render([(0, "o", "one\r\n"), (1, "o", "\x1b[H\x1b[3J"), (2, "o", "two")]) == [
        "14:32:07  one",
        "14:32:09  two",
    ]


def test_a_shorter_window_keeps_the_rows_that_no_longer_fit():
    text = "\r\n".join(f"line{n:02d}" for n in range(1, 25))
    events = [(0, "o", text), (1, "r", "80x10"), (2, "o", "\r\nafter")]
    assert render(events) == [f"14:32:07  line{n:02d}" for n in range(1, 25)] + ["14:32:09  after"]


def test_a_taller_or_wider_window_loses_nothing():
    events = [(0, "o", "one\r\n"), (1, "r", "120x40"), (2, "o", "x" * 100)]
    assert render(events) == ["14:32:07  one", "14:32:09  " + "x" * 100]


def test_a_blank_row_is_an_empty_line_and_rows_below_the_text_are_left_out():
    assert render([(0, "o", "a\r\n\r\nb\r\n\r\n")]) == ["14:32:07  a", "", "14:32:07  b"]


def test_full_screen_program_gives_one_line_and_none_of_its_content():
    events = [
        (0, "o", "$ vim notes\r\n"),
        (3, "o", "\x1b[?1049h\x1b[H\x1b[2Jvim content\r\n~\r\n"),
        (60, "o", "\x1b[2Jmore vim content"),
        (203, "o", "\x1b[?1049l"),
        (204, "o", "$ ls\r\n"),
    ]
    got = render(events)
    assert got == [
        "14:32:07  $ vim notes",
        "14:32:10  [full-screen program until 14:35:30, see the cast]",
        "14:35:31  $ ls",
    ]


@pytest.mark.parametrize("mode", ["47", "1047"])
def test_other_alternate_screen_modes(mode):
    events = [(0, "o", "$ less\r\n"), (1, "o", f"\x1b[?{mode}hpage"), (2, "o", f"\x1b[?{mode}l$ ")]
    assert render(events) == [
        "14:32:07  $ less",
        "14:32:08  [full-screen program until 14:32:09, see the cast]",
        "14:32:09  $",
    ]


def test_recording_ending_in_a_full_screen_program():
    events = [(0, "o", "$ top\r\n"), (1, "o", "\x1b[?1049hload 0.1"), (9, "m", "")]
    assert render(events) == [
        "14:32:07  $ top",
        "14:32:08  [full-screen program until 14:32:16, see the cast]",
    ]


def test_the_screen_above_a_full_screen_program_comes_out_before_it():
    text = "\r\n".join(f"line{n}" for n in range(1, 5)) + "\r\n$ vim"
    events = [(0, "o", text), (1, "o", "\x1b[?1049hx"), (2, "o", "\x1b[?1049l\r\n$ ")]
    assert render(events, rows=3) == [
        "14:32:07  line1",
        "14:32:07  line2",
        "14:32:07  line3",
        "14:32:07  line4",
        "14:32:07  $ vim",
        "14:32:08  [full-screen program until 14:32:09, see the cast]",
        "14:32:09  $",
    ]


def test_an_empty_line_after_a_full_screen_program_is_kept():
    events = [(0, "o", "$ vim\r\n"), (1, "o", "\x1b[?1049hx\x1b[?1049l"), (2, "o", "\r\n$ ")]
    assert render(events) == [
        "14:32:07  $ vim",
        "14:32:08  [full-screen program until 14:32:08, see the cast]",
        "",
        "14:32:09  $",
    ]


def test_a_full_screen_program_across_midnight_gives_one_date_line():
    late = int(datetime(2026, 11, 14, 23, 59, 50, tzinfo=TZ).timestamp())
    events = [(8, "o", "$ vim\r\n"), (12, "o", "\x1b[?1049hx"), (30, "o", "\x1b[?1049l$ ls\r\n")]
    assert render(events, timestamp=late) == [
        "23:59:58  $ vim",
        "---- 2026-11-15 ----",
        "00:00:02  [full-screen program until 00:00:20, see the cast]",
        "00:00:20  $ ls",
    ]


def test_a_date_line_never_goes_back_to_an_earlier_day():
    late = int(datetime(2026, 11, 14, 23, 59, 50, tzinfo=TZ).timestamp())
    # the last row is drawn before midnight, the one above it is redrawn after
    events = [(0, "o", "one\r\n\r\ntwo"), (20, "o", "\x1b[2;1Hlater")]
    assert render(events, timestamp=late) == [
        "23:59:50  one",
        "---- 2026-11-15 ----",
        "00:00:10  later",
        "23:59:50  two",
    ]


def test_a_scroll_region_from_the_top_still_gives_its_lines():
    # apt keeps a progress bar on the last row and scrolls the rows above it
    lines = "\r\n".join(f"dpkg{n}" for n in range(10))
    events = [(0, "o", "\x1b[5;1Hprogress\x1b[1;4r\x1b[1;1H" + lines)]
    expected = [f"14:32:07  dpkg{n}" for n in range(10)] + ["14:32:07  progress"]
    assert render(events, rows=5) == expected


def test_a_scroll_region_lower_down_drops_what_scrolls_out_of_it():
    events = [(0, "o", "top\x1b[2;3r\x1b[2;1Ha\r\nb\r\nc\r\nd")]
    assert render(events, rows=4) == ["14:32:07  top", "14:32:07  c", "14:32:07  d"]


def test_a_narrower_window_keeps_the_whole_line():
    events = [(0, "o", "$ " + "w" * 98 + "\r\n$ "), (1, "r", "40x24"), (2, "o", "ls\r\n")]
    assert render(events, cols=120) == ["14:32:07  $ " + "w" * 98, "14:32:09  $ ls"]


def test_a_narrower_window_during_a_full_screen_program_keeps_the_main_screen():
    # the cursor is on the first row, so the long row below it stays on the main screen
    events = [
        (0, "o", "one\r\n" + "w" * 100 + "\x1b[1;4H"),
        (1, "o", "\x1b[?1049hx"),
        (2, "r", "40x24"),
        (3, "o", "\x1b[?1049l\r\n$ ls"),
    ]
    assert render(events, cols=120) == [
        "14:32:07  one",
        "14:32:07  " + "w" * 100,
        "14:32:08  [full-screen program until 14:32:10, see the cast]",
        "14:32:10  $ ls",
    ]


def test_a_narrower_window_takes_a_wrapped_line_whole():
    events = [(0, "o", "a" * 50 + "b" * 10 + "\r\n$ "), (1, "r", "40x24"), (2, "o", "ls")]
    assert render(events, cols=50) == ["14:32:07  " + "a" * 50 + "b" * 10, "14:32:09  $ ls"]


def test_zero_width_characters_do_not_cut_the_line():
    events = [(0, "o", "abc​def ghi\r\n"), (0, "o", "x️yz\r\n"), (0, "o", "a\x01b\r\n")]
    assert render(events) == ["14:32:07  abcdef ghi", "14:32:07  xyz", "14:32:07  ab"]


def test_combining_characters_are_kept():
    assert render([(0, "o", "café ok\r\n")]) == ["14:32:07  café ok"]


def test_a_session_crossing_midnight_gets_the_date_line():
    late = int(datetime(2026, 11, 14, 23, 59, 50, tzinfo=TZ).timestamp())
    events = [(0, "o", "before\r\n"), (20, "o", "after\r\n"), (30, "o", "later\r\n")]
    assert render(events, timestamp=late) == [
        "23:59:50  before",
        "---- 2026-11-15 ----",
        "00:00:10  after",
        "00:00:20  later",
    ]


def test_without_a_timestamp_times_count_from_zero():
    events = [(0, "o", "a\r\n"), (90061.5, "o", "b\r\n")]
    assert render(events, timestamp=None) == ["00:00:00  a", "25:01:01  b"]


def test_colours_and_control_sequences_leave_no_trace():
    events = [
        (0, "o", "\x1b]0;window title\x07\x1b[1;31mred\x1b[0m \x1b[38;5;300mplain\x1b[m  \r\n"),
        (0, "o", "\x1b[?25l\x1b[38;2;1;2;3mtrue\x1b[0m\x1b[?25h\r\n"),
    ]
    assert render(events) == ["14:32:07  red plain", "14:32:07  true"]


def test_unknown_erase_sequences_do_not_stop_the_text():
    assert render([(0, "o", "a\x1b[4J\x1b[5Kb\r\n")]) == ["14:32:07  ab"]


def test_no_output_gives_no_lines():
    assert render([(1, "m", ""), (2, "i", "ls\r"), (3, "r", "100x30"), (4, "x", "0")]) == []
    assert render([]) == []


def test_a_bad_resize_is_ignored():
    events = [(0, "o", "a"), (1, "r", "wide"), (2, "r", "0x0"), (3, "o", "b")]
    assert render(events) == ["14:32:10  ab"]


def test_a_huge_single_event_renders():
    size = 2 * 1024 * 1024
    assert render([(0, "o", "x" * size)]) == ["14:32:07  " + "x" * size]


def _write(tmp_path, events, **kwargs):
    path = write_cast(tmp_path / "recordings" / "2026-11-14_1432.cast", events, **kwargs)
    out = casttext.write(path, box_name="forest", box_id="6f9c-id", target="dc01", tz=TZ)
    return path, out


def test_write_puts_the_text_beside_the_cast(tmp_path):
    path, out = _write(tmp_path, [(0, "o", "one\r\n"), (8, "o", "two\r\n")])
    assert out == path.with_suffix(".txt")
    assert out.read_bytes().decode("utf-8") == (
        "box      forest  6f9c-id\n"
        "target   dc01\n"
        "started  2026-11-14 14:32:07\n"
        "cast     2026-11-14_1432.cast\n"
        "\n"
        "14:32:07  one\n"
        "14:32:15  two\n"
    )


def test_write_without_a_timestamp(tmp_path):
    _, out = _write(tmp_path, [(0, "o", "one")], timestamp=None)
    assert out.read_text(encoding="utf-8").splitlines()[2] == "started  unknown"


def test_a_second_write_replaces_the_first(tmp_path):
    path, out = _write(tmp_path, [(0, "o", "first")])
    path.write_bytes(cast_text([(0, "o", "second")]).encode("utf-8"))
    casttext.write(path, box_name="forest", box_id="6f9c-id", target="dc01", tz=TZ)
    body = out.read_text(encoding="utf-8")
    assert "second" in body and "first" not in body
    assert sorted(p.name for p in path.parent.iterdir()) == [path.name, out.name]


@pytest.mark.parametrize(
    "text",
    [
        '{"version": 2, "width": 80, "height": 24}\n[1, "o", "a"]\n',
        cast_text([(0, "o", "a\r\n")]) + "[broken\n" + '[1, "o", "b"]\n',
    ],
)
def test_a_bad_cast_leaves_no_text_and_no_temporary_file(tmp_path, text):
    path = tmp_path / "recordings" / "bad.cast"
    path.parent.mkdir()
    path.write_bytes(text.encode("utf-8"))
    with pytest.raises(CastError):
        casttext.write(path, box_name="forest", box_id="6f9c-id", target="dc01", tz=TZ)
    assert [p.name for p in path.parent.iterdir()] == ["bad.cast"]


def test_a_cast_pyte_cannot_render_is_a_cast_error(tmp_path):
    # origin mode with no margins, then CSI d: pyte fails an assert of its own
    path = write_cast(tmp_path / "recordings" / "odd.cast", [(0, "o", "a\r\n\x1b[?6h\x1b[5d")])
    with pytest.raises(CastError, match="could not be rendered") as err:
        casttext.write(path, box_name="forest", box_id="6f9c-id", target="dc01", tz=TZ)
    assert str(path) in str(err.value)
    assert isinstance(err.value.__cause__, AssertionError)
    assert [p.name for p in path.parent.iterdir()] == ["odd.cast"]


@pytest.mark.parametrize(
    "text",
    [
        "[" * 200000 + "\n",
        cast_text([(0, "o", "a\ud800b"), (1, "o", "c")]),
    ],
)
def test_odd_casts_raise_only_cast_error(tmp_path, text):
    path = tmp_path / "recordings" / "odd.cast"
    path.parent.mkdir()
    path.write_bytes(text.encode("utf-8"))
    with pytest.raises(CastError):
        casttext.write(path, box_name="forest", box_id="6f9c-id", target="dc01", tz=TZ)
    assert [p.name for p in path.parent.iterdir()] == ["odd.cast"]


def test_stale(tmp_path):
    path = write_cast(tmp_path / "a.cast", [(0, "o", "a")])
    assert casttext.stale(path)
    casttext.write(path, box_name="forest", box_id="6f9c-id", target="dc01", tz=TZ)
    text = path.with_suffix(".txt")
    os.utime(path, ns=(1_000_000_000_000, 1_000_000_000_000))
    os.utime(text, ns=(2_000_000_000_000, 2_000_000_000_000))
    assert not casttext.stale(path)
    os.utime(text, ns=(500_000_000_000, 500_000_000_000))
    assert casttext.stale(path)


# ---- refresh: the text copies export, finish and replay write


def _cast_in(box, target, name, events=((0, "o", "hello\r\n"),)):
    return write_cast(box.path / "targets" / target / "recordings" / f"{name}.cast", list(events))


def _refresh(box, **kwargs):
    from pwn_broker.console import FakeConsole

    console = FakeConsole()
    casttext.refresh(box, console, tz=TZ, **kwargs)
    return console


def test_refresh_writes_missing_and_stale_texts_and_leaves_fresh_ones(box):
    missing = _cast_in(box, "dc01", "2026-11-14_1432")
    stale = _cast_in(box, "web01", "2026-11-14_1510")
    fresh = _cast_in(box, "web01", "2026-11-14_1600")
    for path in (stale, fresh):
        path.with_suffix(".txt").write_text("old\n", encoding="utf-8")
    os.utime(stale, ns=(2_000_000_000_000, 2_000_000_000_000))
    os.utime(stale.with_suffix(".txt"), ns=(1_000_000_000_000, 1_000_000_000_000))
    os.utime(fresh, ns=(1_000_000_000_000, 1_000_000_000_000))
    os.utime(fresh.with_suffix(".txt"), ns=(2_000_000_000_000, 2_000_000_000_000))
    assert _refresh(box).lines == []
    text = missing.with_suffix(".txt").read_text(encoding="utf-8")
    assert text.startswith("box      forest  2026-11-14_htb_forest\ntarget   dc01\n")
    assert "14:32:07  hello" in text
    assert "target   web01\n" in stale.with_suffix(".txt").read_text(encoding="utf-8")
    assert fresh.with_suffix(".txt").read_text(encoding="utf-8") == "old\n"


def test_refresh_survives_one_bad_cast_among_good_ones(box):
    first = _cast_in(box, "dc01", "2026-11-14_1432")
    bad = box.path / "targets/dc01/recordings/2026-11-14_1500.cast"
    bad.write_bytes(b"not a cast\n")
    last = _cast_in(box, "dc01", "2026-11-14_1600")
    console = _refresh(box)
    [(kind, text)] = console.lines
    assert (kind, text) == (
        "warn", "no text copy of targets/dc01/recordings/2026-11-14_1500.cast: the first line is not JSON"
    )
    assert first.with_suffix(".txt").exists() and last.with_suffix(".txt").exists()
    assert not bad.with_suffix(".txt").exists()


def test_refresh_for_one_target_leaves_the_others(box):
    mine = _cast_in(box, "dc01", "2026-11-14_1432")
    theirs = _cast_in(box, "web01", "2026-11-14_1432")
    _refresh(box, target="dc01")
    assert mine.with_suffix(".txt").exists() and not theirs.with_suffix(".txt").exists()


# ---- the time a text copy may take: a few bytes can fill and clear a 1000 by 1000 screen

FILL_AND_CLEAR = "\x1b#8\x1b[2J"


def ticking(monkeypatch, step=1.0):
    """casttext's clock, moving on by `step` seconds each time it is read."""
    now = [0.0]

    def clock():
        now[0] += step
        return now[0]

    monkeypatch.setattr(casttext, "_clock", clock)
    return now


def test_a_recording_that_takes_too_long_to_render_gets_no_text_copy(tmp_path, monkeypatch):
    ticking(monkeypatch)
    monkeypatch.setattr(casttext, "RENDER_SECONDS", 20)
    path = write_cast(tmp_path / "recordings" / "2026-11-14_1432.cast", [(0, "o", "x\r\n")] * 50)
    with pytest.raises(CastError, match="took longer than 20 seconds to render"):
        casttext.write(path, box_name="forest", box_id="6f9c-id", target="dc01", tz=TZ)
    assert not path.with_suffix(".txt").exists()


def test_the_time_allowed_grows_with_the_recording(tmp_path, monkeypatch):
    # a real recording that size gets its text copy: the allowance is counted in its bytes
    # a tick long enough that the base second alone is spent long before the end
    now = ticking(monkeypatch, step=0.0005)
    monkeypatch.setattr(casttext, "RENDER_SECONDS", 1)
    path = write_cast(tmp_path / "recordings" / "2026-11-14_1432.cast", [(0, "o", "x" * 70 + "\r\n")] * 4000)
    out = casttext.write(path, box_name="forest", box_id="6f9c-id", target="dc01", tz=TZ)
    assert out.read_text(encoding="utf-8").count("x" * 70) == 4000
    assert now[0] > 2


def test_refresh_counts_the_size_of_the_casts_it_writes(box, monkeypatch):
    # stale casts only: a fresh text copy costs nothing
    stale = _cast_in(box, "dc01", "2026-11-14_1432", events=[(0, "o", "x\r\n")] * 30)
    fresh = _cast_in(box, "web01", "2026-11-14_1500", events=[(0, "o", "y\r\n")] * 300)
    fresh.with_suffix(".txt").write_text("old\n", encoding="utf-8")
    os.utime(fresh, ns=(1_000_000_000_000, 1_000_000_000_000))
    sizes = []
    real = casttext.allowance
    monkeypatch.setattr(casttext, "allowance", lambda size: sizes.append(size) or real(size))
    _refresh(box)
    # the shared allowance first, from the stale casts alone
    assert sizes[0] == stale.stat().st_size and fresh.stat().st_size not in sizes


def test_a_crafted_recording_is_stopped_in_about_the_time_it_is_allowed(tmp_path, monkeypatch):
    # the real clock: each pair fills and clears the whole screen in a few bytes
    monkeypatch.setattr(casttext, "RENDER_SECONDS", 2)
    path = write_cast(
        tmp_path / "recordings" / "2026-11-14_1432.cast", [(0, "o", FILL_AND_CLEAR * 400)], cols=300, rows=300
    )
    started = time.monotonic()
    with pytest.raises(CastError, match="took longer than 2 seconds to render"):
        casttext.write(path, box_name="forest", box_id="6f9c-id", target="dc01", tz=TZ)
    assert time.monotonic() - started < 20


def test_refresh_gives_all_its_recordings_one_allowance(box, monkeypatch):
    # an archive of many small crafted casts cannot take the allowance once for each
    now = ticking(monkeypatch)
    monkeypatch.setattr(casttext, "RENDER_SECONDS", 30)
    for name in ("2026-11-14_1432", "2026-11-14_1500", "2026-11-14_1600"):
        _cast_in(box, "dc01", name, events=[(0, "o", "x\r\n")] * 20)
    console = _refresh(box)
    warned = [text for kind, text in console.lines if kind == "warn"]
    assert warned and all("took longer than 30 seconds to render" in text for text in warned)
    # once between them, not 30 seconds each
    assert now[0] < 30 + 10


def test_a_slow_cast_first_leaves_the_others_their_time(box, monkeypatch):
    # a crafted cast early in the order spends its own allowance, not the whole shared one
    # one tick a screen call; 0.05 s a byte: the slow cast is small and costly, the real one
    # larger and cheap, as a crafted and a real recording are
    ticking(monkeypatch)
    monkeypatch.setattr(casttext, "RENDER_SECONDS", 10)
    monkeypatch.setattr(casttext, "RENDER_SECONDS_PER_MB", 50_000)
    slow = _cast_in(box, "dc01", "2026-11-14_1432", events=[(0, "o", "x\n" * 200)])
    real = _cast_in(box, "dc01", "2026-11-14_1500", events=[(0, "o", "y" * 2000 + "\r\n")])
    console = _refresh(box)
    warned = [text for kind, text in console.lines if kind == "warn"]
    assert len(warned) == 1 and "2026-11-14_1432.cast" in warned[0]
    assert real.with_suffix(".txt").exists() and not slow.with_suffix(".txt").exists()


def test_one_long_run_of_text_is_timed_as_it_is_drawn(tmp_path, monkeypatch):
    # pyte draws a run of plain text in one call: combining marks make that call slow in their
    # number squared, and insert mode costs a shift for each character
    ticking(monkeypatch)
    monkeypatch.setattr(casttext, "RENDER_SECONDS", 20)
    monkeypatch.setattr(casttext, "RENDER_SECONDS_PER_MB", 0)
    path = write_cast(tmp_path / "recordings" / "2026-11-14_1432.cast", [(0, "o", "x" * 20_000)])
    with pytest.raises(CastError, match="took longer than 20 seconds to render"):
        casttext.write(path, box_name="forest", box_id="6f9c-id", target="dc01", tz=TZ)


def test_resizes_are_timed_too(tmp_path, monkeypatch):
    ticking(monkeypatch)
    monkeypatch.setattr(casttext, "RENDER_SECONDS", 20)
    path = write_cast(tmp_path / "recordings" / "2026-11-14_1432.cast", [(0, "r", "1000x1000"), (0, "r", "80x24")] * 25)
    with pytest.raises(CastError, match="took longer than 20 seconds to render"):
        casttext.write(path, box_name="forest", box_id="6f9c-id", target="dc01", tz=TZ)


def test_cast_files_are_in_name_order_and_only_casts(box):
    later = _cast_in(box, "dc01", "2026-11-14_1600")
    earlier = _cast_in(box, "dc01", "2026-11-14_1432")
    other = _cast_in(box, "web01", "2026-11-14_1000")
    (box.path / "targets/dc01/recordings/notes.txt").write_text("x")
    (box.path / "targets/dc01/recordings/folder.cast").mkdir()
    assert casttext.cast_files(box, "dc01") == [earlier, later]
    assert casttext.cast_files(box) == [earlier, later, other]
    assert casttext.cast_files(box, "nobody") == []


def test_recordings_of_one_minute_are_in_the_order_they_were_made(box):
    names = ["2026-11-14_1432-10", "2026-11-14_1432-2", "2026-11-14_1432", "2026-11-14_1431", "odd"]
    for name in [*names, "2026-11-14_1432-3"]:
        _cast_in(box, "dc01", name)
    assert [p.stem for p in casttext.cast_files(box, "dc01")] == [
        "2026-11-14_1431", "2026-11-14_1432", "2026-11-14_1432-2",
        "2026-11-14_1432-3", "2026-11-14_1432-10", "odd",
    ]  # fmt: skip


def test_a_start_time_past_what_a_date_can_hold_is_a_cast_error(tmp_path):
    # allowed by the header (the last second of 9999 UTC), but a year 10000 in the VM's time
    path = write_cast(tmp_path / "far.cast", [(0, "o", "a")], timestamp=253402300799)
    with pytest.raises(CastError, match="start time"):
        casttext.write(path, box_name="forest", box_id="6f9c-id", target="dc01", tz=TZ)
    assert [p.name for p in path.parent.iterdir()] == ["far.cast"]
