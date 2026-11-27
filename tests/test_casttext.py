import os
import time
from datetime import datetime

import pytest
from casts import START, TZ, cast_text, write_cast
from helpers import odd_name

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
        '{"version": 3}\n[1, "o", "a"]\n',
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
    assert sorted(p.name for p in path.parent.iterdir()) == ["odd.cast", "odd.txt"]
    assert path.with_suffix(".txt").read_text(encoding="utf-8").endswith(
        "[no text copy: could not be rendered (AssertionError)]\n"
    )


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
    assert {p.name for p in path.parent.iterdir()} <= {"odd.cast", "odd.txt"}


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

# line feeds at the foot of a tall screen: each moves every row up
FEEDS = "\n" * 300_000


def ticking(monkeypatch, step=1.0):
    """casttext's clock, moving on by `step` seconds each time it is read."""
    now = [0.0]

    def clock():
        now[0] += step
        return now[0]

    monkeypatch.setattr(casttext, "_clock", clock)
    return now


def test_a_recording_that_takes_too_long_to_render_gets_a_text_copy_saying_so(tmp_path, monkeypatch):
    ticking(monkeypatch)
    monkeypatch.setattr(casttext, "RENDER_SECONDS", 20)
    path = write_cast(tmp_path / "recordings" / "2026-11-14_1432.cast", [(0, "o", "x\r\n")] * 50)
    with pytest.raises(CastError, match="took longer than 20 seconds to render"):
        casttext.write(path, box_name="forest", box_id="6f9c-id", target="dc01", tz=TZ)
    text = path.with_suffix(".txt").read_text(encoding="utf-8")
    assert text.endswith("[no text copy: it took longer than 20 seconds to make; replay plays the cast]\n")
    assert "  x" not in text  # no line of the recording


def test_the_time_allowed_grows_with_the_recording(tmp_path, monkeypatch):
    # a real recording that size gets its text copy: the allowance is counted in its bytes
    # a tick long enough that the base second alone is spent long before the end
    now = ticking(monkeypatch, step=0.0005)
    monkeypatch.setattr(casttext, "RENDER_SECONDS", 1)
    path = write_cast(tmp_path / "recordings" / "2026-11-14_1432.cast", [(0, "o", "x" * 70 + "\r\n")] * 4000)
    out = casttext.write(path, box_name="forest", box_id="6f9c-id", target="dc01", tz=TZ)
    assert out.read_text(encoding="utf-8").count("x" * 70) == 4000
    assert now[0] > 2


def test_a_crafted_recording_is_stopped_in_about_the_time_it_is_allowed(tmp_path, monkeypatch):
    # the real clock: each line feed at the foot of a 1000-row screen moves every row
    monkeypatch.setattr(casttext, "RENDER_SECONDS", 2)
    monkeypatch.setattr(casttext, "RENDER_SECONDS_PER_MB", 0)
    path = write_cast(
        tmp_path / "recordings" / "2026-11-14_1432.cast", [(0, "o", "\x1b[999B" + FEEDS)], cols=1000, rows=1000
    )
    started = time.monotonic()
    with pytest.raises(CastError, match="took longer than 2 seconds to render"):
        casttext.write(path, box_name="forest", box_id="6f9c-id", target="dc01", tz=TZ)
    assert time.monotonic() - started < 20


def test_refresh_gives_all_its_recordings_one_allowance(box, monkeypatch):
    # an archive of many small crafted casts cannot take the allowance once for each
    now = ticking(monkeypatch)
    monkeypatch.setattr(casttext, "RENDER_SECONDS", 30)
    # each may take all of it, so the shared allowance is the one that ends them
    monkeypatch.setattr(casttext, "RENDER_SECONDS_EACH", 30)
    for name in ("2026-11-14_1432", "2026-11-14_1500", "2026-11-14_1600"):
        _cast_in(box, "dc01", name, events=[(0, "o", "x\r\n")] * 20)
    console = _refresh(box)
    warned = [text for kind, text in console.lines if kind == "warn"]
    # the first two say the time each had, which together is the shared 30 seconds; the second ran
    # out with the base spent, so the third waits for the next export, finish or replay
    assert len(warned) == 3 and all("took longer than" in text or "less than a second" in text for text in warned[:2])
    assert warned[2].startswith("1 recording got no text copy this time")
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
    assert "y" in real.with_suffix(".txt").read_text(encoding="utf-8")
    assert "[no text copy: it took longer than" in slow.with_suffix(".txt").read_text(encoding="utf-8")


def test_a_slow_cast_first_leaves_a_small_real_one_its_time(box, monkeypatch):
    # the allowances as they ship: a crafted cast first spends a few seconds of its own, not the
    # minute the casts share, so a short real recording after it still gets its text copy. A
    # tenth of a second a screen call: the slow cast needs 40 s, the real one about 1.
    ticking(monkeypatch, step=0.1)
    slow = _cast_in(box, "dc01", "2026-11-14_1432", events=[(0, "o", "x\n" * 200)])
    real = _cast_in(box, "dc01", "2026-11-14_1500", events=[(0, "o", "y" * 40 + "\r\n")] * 3)
    console = _refresh(box)
    warned = [text for kind, text in console.lines if kind == "warn"]
    assert len(warned) == 1 and "2026-11-14_1432.cast" in warned[0]
    assert "y" in real.with_suffix(".txt").read_text(encoding="utf-8")
    assert "[no text copy: it took longer than" in slow.with_suffix(".txt").read_text(encoding="utf-8")


def test_a_cast_stopped_by_the_shared_time_says_the_time_it_had(box, monkeypatch):
    ticking(monkeypatch)
    monkeypatch.setattr(casttext, "RENDER_SECONDS", 30)
    monkeypatch.setattr(casttext, "RENDER_SECONDS_EACH", 25)
    monkeypatch.setattr(casttext, "RENDER_SECONDS_PER_MB", 0)
    for name in ("2026-11-14_1432", "2026-11-14_1500"):
        _cast_in(box, "dc01", name, events=[(0, "o", "x\n" * 100)])
    warned = [text for kind, text in _refresh(box).lines if kind == "warn"]
    # the first had its own 25 seconds; the second what was left of the shared 30
    import re

    assert "took longer than 25 seconds" in warned[0]
    left = int(re.search(r"took longer than (\d+) seconds", warned[1])[1])
    assert left < 6


def test_slow_casts_first_leave_a_real_one_its_time_by_size(box, monkeypatch):
    # however many crafted casts come first and however long each overruns, they spend only the
    # shared base: a real recording after them still has its own time by size, from its own start
    ticking(monkeypatch, step=0.001)
    monkeypatch.setattr(casttext, "RENDER_SECONDS", 20)
    for minute in ("00", "01", "02"):
        _cast_in(box, "dc01", f"2026-11-14_14{minute}", events=[(0, "o", "x\n" * 20_000)])
    real = _cast_in(box, "dc01", "2026-11-14_1500", events=[(0, "o", "y" * 2000 + "\r\n")])
    _refresh(box)
    # the crafted ones are noted or left; the next refresh comes to the real one with the base fresh
    second = [text for kind, text in _refresh(box).lines if kind == "warn"]
    assert not any("1500.cast" in text for text in second)
    assert "y" * 2000 in real.with_suffix(".txt").read_text(encoding="utf-8")


def test_a_cast_that_ran_out_of_time_is_not_tried_again(box, monkeypatch):
    # its text copy says so, and it is no longer older than its cast
    ticking(monkeypatch)
    monkeypatch.setattr(casttext, "RENDER_SECONDS_EACH", 10)
    slow = _cast_in(box, "dc01", "2026-11-14_1432", events=[(0, "o", "x\n" * 200)])
    first = _refresh(box)
    assert [kind for kind, _ in first.lines] == ["warn"]
    text = slow.with_suffix(".txt").read_text(encoding="utf-8")
    assert text.startswith("box      forest") and "took longer than" in text and "replay" in text
    assert _refresh(box).lines == []


def test_the_screen_alignment_test_draws_nothing(tmp_path):
    # ESC # 8 fills the whole screen with E in one call, which a text copy has no use for and a
    # crafted cast leans on: on a 1000 by 1000 screen it took seconds
    path = write_cast(tmp_path / "recordings" / "2026-11-14_1432.cast", [(0, "o", "\x1b#8" * 20 + "after\r\n")],
                      cols=1000, rows=1000)
    started = time.monotonic()
    out = casttext.write(path, box_name="forest", box_id="6f9c-id", target="dc01", tz=TZ)
    assert time.monotonic() - started < 10
    text = out.read_text(encoding="utf-8")
    assert "EEEE" not in text and "after" in text


def test_a_cast_dated_in_the_future_is_not_tried_again(box, monkeypatch):
    # an archive keeps its members' times: the note must not be older than its cast
    ticking(monkeypatch)
    slow = _cast_in(box, "dc01", "2026-11-14_1432", events=[(0, "o", "x\n" * 200)])
    later = 4_070_908_800 * 1_000_000_000  # 2099
    os.utime(slow, ns=(later, later))
    assert [kind for kind, _ in _refresh(box).lines] == ["warn"]
    assert not casttext.stale(slow)
    assert _refresh(box).lines == []


def test_a_cast_left_no_time_by_the_others_gets_no_note(box, monkeypatch):
    # the shared minute spent by the casts before it: it is tried again next time, not marked
    ticking(monkeypatch)
    monkeypatch.setattr(casttext, "RENDER_SECONDS", 10)
    _cast_in(box, "dc01", "2026-11-14_1400", events=[(0, "o", "x\n" * 200)])
    short = _cast_in(box, "dc01", "2026-11-14_1500", events=[(0, "o", "x\n" * 200)])
    console = _refresh(box)
    assert len([kind for kind, _ in console.lines if kind == "warn"]) == 2
    assert not short.with_suffix(".txt").exists() and casttext.stale(short)


def test_a_text_copy_already_there_is_kept_when_the_cast_runs_out_of_time(box, monkeypatch):
    # a recording that grew after its text copy: the copy it had is better than a note
    ticking(monkeypatch)
    cast = _cast_in(box, "dc01", "2026-11-14_1432", events=[(0, "o", "x\n" * 200)])
    cast.with_suffix(".txt").write_text("box      forest\n\n14:32:07  whoami\n", encoding="utf-8")
    os.utime(cast.with_suffix(".txt"), ns=(1_000_000_000_000, 1_000_000_000_000))
    os.utime(cast, ns=(2_000_000_000_000, 2_000_000_000_000))
    _refresh(box)
    text = cast.with_suffix(".txt").read_text(encoding="utf-8")
    assert text.startswith("box      forest\n\n14:32:07  whoami\n")
    # the recording went on past it, so it says where it stops
    assert text.endswith("\n[the text copy stops here: it took longer than 10 seconds to make; replay plays the cast]\n")


def test_a_kept_text_copy_says_once_where_it_stops(box, monkeypatch):
    # the recording grows again and runs out again: the line is replaced, not added to
    ticking(monkeypatch)
    cast = _cast_in(box, "dc01", "2026-11-14_1432", events=[(0, "o", "x\n" * 200)])
    cast.with_suffix(".txt").write_text("box      forest\n\n14:32:07  whoami", encoding="utf-8")
    for n in (1, 2):
        os.utime(cast.with_suffix(".txt"), ns=(n * 1_000_000_000_000, n * 1_000_000_000_000))
        os.utime(cast, ns=(n * 1_500_000_000_000, n * 1_500_000_000_000))
        _refresh(box)
    lines = cast.with_suffix(".txt").read_text(encoding="utf-8").splitlines()
    assert lines[:3] == ["box      forest", "", "14:32:07  whoami"]
    assert len(lines) == 4 and lines[3].startswith("[the text copy stops here: ")


def test_a_text_copy_that_is_not_a_file_is_left_and_nothing_is_rendered(box, monkeypatch):
    # a folder or a link in its place, from an archive: rendering would be spent on every command
    # to fail at the write, and a link would be read through
    cast = _cast_in(box, "dc01", "2026-11-14_1432")
    cast.with_suffix(".txt").mkdir()
    os.utime(cast.with_suffix(".txt"), ns=(1_000_000_000_000, 1_000_000_000_000))
    monkeypatch.setattr(casttext, "render", lambda *args, **kwargs: pytest.fail("rendered"))
    assert _refresh(box).lines == [
        ("warn", "no text copy of targets/dc01/recordings/2026-11-14_1432.cast: 2026-11-14_1432.txt is not a file")
    ]
    assert cast.with_suffix(".txt").is_dir()


def test_a_warning_with_under_a_second_says_so(box, monkeypatch):
    ticking(monkeypatch)
    monkeypatch.setattr(casttext, "RENDER_SECONDS", 10)
    _cast_in(box, "dc01", "2026-11-14_1400", events=[(0, "o", "x\n" * 200)])
    _cast_in(box, "dc01", "2026-11-14_1500", events=[(0, "o", "x\n" * 200)])
    warned = [text for kind, text in _refresh(box).lines if kind == "warn"]
    assert "took longer than 0 seconds" not in warned[1] and "less than a second" in warned[1]


# a few bytes must not fill the screen: an erase stores nothing, so a call that touches every cell
# costs what drawing those cells cost

BLANK_ROWS = "\x1b[2K\n" * 999


def test_reverse_video_on_a_filled_screen_is_cheap(tmp_path):
    # ESC [ ? 5 h and l, the visible bell: pyte rewrites every stored cell for each
    path = write_cast(tmp_path / "recordings" / "2026-11-14_1432.cast",
                      [(0, "o", BLANK_ROWS), (0, "o", "\x1b[?5h\x1b[?5l" * 3 + "after\r\n")], cols=1000, rows=1000)
    started = time.monotonic()
    out = casttext.write(path, box_name="forest", box_id="6f9c-id", target="dc01", tz=TZ)
    assert time.monotonic() - started < 5
    assert "after" in out.read_text(encoding="utf-8")


def test_an_erased_screen_holds_no_cells_to_erase_again(tmp_path):
    path = write_cast(tmp_path / "recordings" / "2026-11-14_1432.cast",
                      [(0, "o", BLANK_ROWS), (0, "o", "\x1b[2J" * 200 + "\x1b[5X" * 40 + "after\r\n")],
                      cols=1000, rows=1000)
    started = time.monotonic()
    out = casttext.write(path, box_name="forest", box_id="6f9c-id", target="dc01", tz=TZ)
    assert time.monotonic() - started < 5
    assert "after" in out.read_text(encoding="utf-8")


def test_an_erase_leaves_the_text_as_it_was(tmp_path):
    # what is left of a line after an erase, and the rows around it
    events = [(0, "o", "keep this\r\nwipe this line\r\nhalf\x1b[2Dxx\x1b[K\r\nend\r\n")]
    path = write_cast(tmp_path / "recordings" / "2026-11-14_1432.cast", events)
    out = casttext.write(path, box_name="forest", box_id="6f9c-id", target="dc01", tz=TZ)
    body = [line.split("  ", 1)[1] for line in out.read_text(encoding="utf-8").splitlines()[5:]]
    assert body == ["keep this", "wipe this line", "haxx", "end"]


def test_a_cast_that_runs_out_with_a_text_copy_keeps_it_and_is_not_tried_again(box, monkeypatch):
    ticking(monkeypatch)
    cast = _cast_in(box, "dc01", "2026-11-14_1432", events=[(0, "o", "x\n" * 200)])
    cast.with_suffix(".txt").write_text("box      forest\n\n14:32:07  whoami\n", encoding="utf-8")
    os.utime(cast.with_suffix(".txt"), ns=(1_000_000_000_000, 1_000_000_000_000))
    os.utime(cast, ns=(2_000_000_000_000, 2_000_000_000_000))
    [(kind, text)] = _refresh(box).lines
    assert kind == "warn" and text.startswith(
        "the text copy of targets/dc01/recordings/2026-11-14_1432.cast is not up to date: it took longer than"
    )
    assert "whoami" in cast.with_suffix(".txt").read_text(encoding="utf-8")
    assert _refresh(box).lines == []


def test_once_the_base_is_spent_the_first_cast_out_of_time_ends_the_refresh(box, monkeypatch):
    # the rest are left for next time with one line, so many crafted casts cost one base and one
    # cast's time, not each their own
    ticking(monkeypatch)
    monkeypatch.setattr(casttext, "RENDER_SECONDS", 10)
    casts = [_cast_in(box, "dc01", f"2026-11-14_14{n:02}", events=[(0, "o", "x\n" * 200)]) for n in range(5)]
    console = _refresh(box)
    warned = [text for kind, text in console.lines if kind == "warn"]
    assert len(warned) == 3
    assert warned[-1] == "3 recordings got no text copy this time; the next export, finish or replay tries them again"
    assert all(casttext.stale(c) for c in casts[2:])


def test_seconds_are_said_as_people_say_them():
    assert casttext._spoken(0) == "less than a second"
    assert casttext._spoken(1) == "1 second"
    assert casttext._spoken(10) == "10 seconds"


def test_a_megabyte_gets_a_minute_besides_the_base():
    # room for a real recording on a busy machine, where short lines took up to 36 s a megabyte
    assert casttext.allowance(1_000_000).seconds == casttext.RENDER_SECONDS + 60


def test_a_cast_dated_in_the_future_that_renders_is_not_rendered_again(box, monkeypatch):
    # an archive keeps its members' times: the text copy is dated no earlier than its cast
    cast = _cast_in(box, "dc01", "2026-11-14_1432")
    later = 4_070_908_800 * 1_000_000_000  # 2099
    os.utime(cast, ns=(later, later))
    assert _refresh(box).lines == []
    assert not casttext.stale(cast)
    written = []
    monkeypatch.setattr(casttext, "write", lambda *a, **k: written.append(a))
    _refresh(box)
    assert written == []


def test_a_row_is_read_only_to_its_last_cell():
    # the last flush reads each row: a row holding one character on a 1000-column screen is that
    # character, not a thousand cells, and a row the next one continues keeps its full width
    screen = casttext._TextScreen(1000, 5)
    stream = casttext.pyte.Stream(screen)
    stream.feed("a\r\n")
    assert screen._row_text(0) == "a"
    assert screen._row_text(0, full=True) == "a" + " " * 999
    assert screen._row_text(3) == ""

def test_a_wrapped_line_keeps_its_spaces_at_the_wrap(tmp_path):
    path = write_cast(tmp_path / "recordings" / "2026-11-14_1432.cast", [(0, "o", "abc       def\r\n")], cols=10, rows=5)
    out = casttext.write(path, box_name="forest", box_id="6f9c-id", target="dc01", tz=TZ)
    assert out.read_text(encoding="utf-8").splitlines()[5].split("  ", 1)[1] == "abc       def"



def _screen(text, cols=10, rows=5):
    screen = casttext._TextScreen(cols, rows)
    casttext.pyte.Stream(screen).feed(text)
    return screen


def _cells(screen, y):
    return sorted(screen.buffer.get(y) or {})


@pytest.mark.parametrize("sequence", ["\x1b[?5h", "\x1b[?5l", "\x1b[160h", "\x1b[160l"])
def test_reverse_video_touches_no_cell(sequence):
    # private mode 5 (DECSCNM), or 160, the plain mode pyte shifts it to: pyte rewrites every
    # stored cell for it, so a screen filled once could be rewritten for every few bytes
    screen = _screen("abc")
    cell = screen.buffer[0][0]
    casttext.pyte.Stream(screen).feed(sequence)
    assert screen.buffer[0][0] is cell


def test_inserting_or_deleting_characters_stores_no_blank_cells():
    # pyte writes a blank cell into every column from the cursor to the edge for each, so three
    # bytes filled a row of a 1000-column screen
    screen = _screen("abcdef\x1b[1;3H\x1b[2@", cols=1000)
    assert screen._row_text(0) == "ab  cdef" and _cells(screen, 0) == [0, 1, 4, 5, 6, 7]
    screen = _screen("abcdef\x1b[1;2H\x1b[2P", cols=1000)
    assert screen._row_text(0) == "adef" and _cells(screen, 0) == [0, 1, 2, 3]
    assert _cells(_screen("\x1b[5@\x1b[5P\x1b[4hx", cols=1000), 0) == [0]
    assert _screen("abcdefghij\x1b[1;3H\x1b[2@")._row_text(0) == "ab  cdefgh"
    assert _cells(_screen("abcdefghij\x1b[1;3H\x1b[2@"), 0) == [0, 1, 4, 5, 6, 7, 8, 9]  # i and j are gone
    assert _screen("abc\x1b[1;1H\x1b[4hX")._row_text(0) == "Xabc"


def test_each_erase_removes_the_cells_it_erases():
    # a cell that is not there reads as a space; pyte writes a blank one in its place
    rows = "abcdef\r\nabcdef\r\nabcdef\x1b[2;3H"
    screen = _screen(rows + "\x1b[J")
    assert [_cells(screen, y) for y in range(3)] == [[0, 1, 2, 3, 4, 5], [0, 1], []]
    screen = _screen(rows + "\x1b[1J")
    assert [_cells(screen, y) for y in range(3)] == [[], [3, 4, 5], [0, 1, 2, 3, 4, 5]]
    assert [_cells(_screen(rows + "\x1b[2J"), y) for y in range(3)] == [[], [], []]
    line = "abcdef\x1b[1;3H"
    assert _cells(_screen(line + "\x1b[K"), 0) == [0, 1]
    assert _cells(_screen(line + "\x1b[1K"), 0) == [3, 4, 5]
    assert _cells(_screen(line + "\x1b[2K"), 0) == []
    assert _cells(_screen(line + "\x1b[2X"), 0) == [0, 1, 4, 5]
    assert _screen(line + "\x1b[1K")._row_text(0) == "   def"
    assert _screen(line + "\x1b[2X")._row_text(0) == "ab  ef"


def test_a_wrapped_line_keeps_the_spaces_an_erase_leaves_in_it():
    # the erased cells are gone, but a row the next one continues is still the screen's width
    assert render([(0, "o", "abcdefghij1234567890xyz\x1b[2;6H\x1b[K")], cols=10, rows=5) == [
        "14:32:07  abcdefghij12345     xyz"
    ]
    assert render([(0, "o", "abcdefghij1234567890xyz\x1b[2;1H\x1b[10X")], cols=10, rows=5) == [
        "14:32:07  abcdefghij          xyz"
    ]


def test_a_cast_given_under_a_second_of_the_base_gets_no_note(box, monkeypatch):
    # too little to be a fair try: it is tried again next time, not marked
    ticking(monkeypatch, step=0.1)
    monkeypatch.setattr(casttext, "RENDER_SECONDS", 0.5)
    cast = _cast_in(box, "dc01", "2026-11-14_1432", events=[(0, "o", "x\n" * 200)])
    assert [kind for kind, _ in _refresh(box).lines] == ["warn"]
    assert not cast.with_suffix(".txt").exists()


BAD_LINE = b'[broken\n[1, "o", "b"]\n'


def test_a_cast_that_fails_partway_gets_a_note_and_is_not_tried_again(box):
    # it may have spent its time before it failed: a text copy that says why keeps the next
    # export, finish or replay from spending it again
    odd = _cast_in(box, "dc01", "2026-11-14_1432", events=[(0, "o", "a\r\n\x1b[?6h\x1b[5d")])
    bad = _cast_in(box, "dc01", "2026-11-14_1500")
    bad.write_bytes(cast_text([]).encode("utf-8") + BAD_LINE)
    assert [kind for kind, _ in _refresh(box).lines] == ["warn", "warn"]
    text = odd.with_suffix(".txt").read_text(encoding="utf-8")
    assert text.startswith("box      forest") and text.endswith("[no text copy: could not be rendered (AssertionError)]\n")
    assert "\n[no text copy: line 2 is not a valid event (" in bad.with_suffix(".txt").read_text(encoding="utf-8")
    assert _refresh(box).lines == []


def test_a_cast_that_fails_with_no_base_left_is_noted_and_ends_the_refresh(box, monkeypatch):
    # a bad line fails however long it is given, so it is noted; and with the base spent it ends
    # the rendering, as one out of time does, or casts that fail late would each spend their time
    ticking(monkeypatch)
    monkeypatch.setattr(casttext, "RENDER_SECONDS", 10)
    _cast_in(box, "dc01", "2026-11-14_1400", events=[(0, "o", "x\n" * 200)])
    bad = _cast_in(box, "dc01", "2026-11-14_1500")
    bad.write_bytes(cast_text([]).encode("utf-8") + BAD_LINE)
    after = _cast_in(box, "dc01", "2026-11-14_1600")
    warned = [text for kind, text in _refresh(box).lines if kind == "warn"]
    assert len(warned) == 3 and "line 2 is not a valid event" in warned[1]
    assert warned[2].startswith("1 recording got no text copy this time")
    assert "\n[no text copy: line 2 is not a valid event (" in bad.with_suffix(".txt").read_text(encoding="utf-8")
    assert casttext.stale(after)


def test_a_cast_that_cannot_be_written_with_no_base_left_ends_the_refresh(box, monkeypatch):
    ticking(monkeypatch)
    monkeypatch.setattr(casttext, "RENDER_SECONDS", 10)
    _cast_in(box, "dc01", "2026-11-14_1400", events=[(0, "o", "x\n" * 200)])
    _cast_in(box, "dc01", "2026-11-14_1500")
    after = _cast_in(box, "dc01", "2026-11-14_1600")
    write = casttext.write

    def full(cast_path, **kwargs):
        if cast_path.stem == "2026-11-14_1500":
            raise OSError(28, "No space left on device")
        return write(cast_path, **kwargs)

    monkeypatch.setattr(casttext, "write", full)
    warned = [text for kind, text in _refresh(box).lines if kind == "warn"]
    assert len(warned) == 3 and warned[1].endswith("No space left on device")
    assert warned[2].startswith("1 recording got no text copy this time")
    assert casttext.stale(after)


def test_a_time_past_what_a_date_can_hold_gets_a_note(tmp_path):
    # an interval that takes the clock past what the system's dates hold: OSError on Linux and
    # Windows alike, raised when the line is given its time
    path = write_cast(tmp_path / "recordings" / "odd.cast", [(0, "o", "a\r\n"), (1e18, "o", "b\r\n")])
    with pytest.raises(CastError, match="could not be rendered"):
        casttext.write(path, box_name="forest", box_id="6f9c-id", target="dc01", tz=TZ)
    assert path.with_suffix(".txt").read_text(encoding="utf-8").endswith("]\n")


def test_a_failure_is_noted_whatever_its_share_but_a_read_error_is_not(tmp_path, monkeypatch):
    # pyte fails the same way however long it is given; a read error may be gone next time
    path = write_cast(tmp_path / "recordings" / "odd.cast", [(0, "o", "a\r\n\x1b[?6h\x1b[5d")])
    with pytest.raises(CastError, match="could not be rendered"):
        casttext.write(path, box_name="forest", box_id="6f9c-id", target="dc01", tz=TZ, note=False)
    assert path.with_suffix(".txt").read_text(encoding="utf-8").endswith("(AssertionError)]\n")
    path.with_suffix(".txt").unlink()

    def unreadable(cast_path):
        yield 0.0, "o", "a\r\n"
        raise CastError(cast_path, "cannot be read (Input/output error)") from OSError(5, "Input/output error")

    monkeypatch.setattr(casttext, "events", unreadable)
    with pytest.raises(CastError, match="cannot be read"):
        casttext.write(path, box_name="forest", box_id="6f9c-id", target="dc01", tz=TZ)
    assert not path.with_suffix(".txt").exists()


def _older(text, cast, n=1):
    os.utime(text, ns=(n * 1_000_000_000_000, n * 1_000_000_000_000))
    os.utime(cast, ns=(n * 1_500_000_000_000, n * 1_500_000_000_000))


def test_only_the_end_of_a_kept_text_copy_is_read(box, monkeypatch):
    # one from an archive may be as large as the disk allows: it is kept byte for byte
    import tracemalloc

    ticking(monkeypatch)
    cast = _cast_in(box, "dc01", "2026-11-14_1432", events=[(0, "o", "x\n" * 200)])
    text = cast.with_suffix(".txt")
    kept = b"box      forest\r\n\n14:32:07  \xff\xfe" + (b"y" * 999 + b"\n") * 3000 + b"no final break"
    text.write_bytes(kept)
    _older(text, cast)
    tracemalloc.start()
    try:
        _refresh(box)
        peak = tracemalloc.get_traced_memory()[1]
    finally:
        tracemalloc.stop()
    assert peak < 1_000_000
    assert text.read_bytes() == kept + b"\n[the text copy stops here: it took longer than 10 seconds to make; replay plays the cast]\n"


def test_a_note_whose_cast_grew_and_failed_again_is_a_note_still(box, monkeypatch):
    # its cast went on and ran out again: the note is replaced, and the warn line says there is none
    ticking(monkeypatch)
    cast = _cast_in(box, "dc01", "2026-11-14_1432", events=[(0, "o", "x\n" * 200)])
    _refresh(box)
    _older(cast.with_suffix(".txt"), cast, 2)
    [(_, warned)] = _refresh(box).lines
    assert warned.startswith("no text copy of targets/dc01/recordings/2026-11-14_1432.cast: ")
    lines = cast.with_suffix(".txt").read_text(encoding="utf-8").splitlines()
    assert lines[-1].startswith("[no text copy: ") and len(lines) == 6


def test_a_folder_where_a_text_copy_goes_is_warned_of_whatever_its_time(box, monkeypatch):
    cast = _cast_in(box, "dc01", "2026-11-14_1432")
    cast.with_suffix(".txt").mkdir()
    later = 4_070_908_800 * 1_000_000_000  # 2099
    os.utime(cast.with_suffix(".txt"), ns=(later, later))
    assert _refresh(box).lines == [
        ("warn", "no text copy of targets/dc01/recordings/2026-11-14_1432.cast: 2026-11-14_1432.txt is not a file")
    ]


def _link_or_skip(link, to):
    try:
        os.symlink(to, link)
    except (OSError, NotImplementedError) as exc:
        pytest.skip(f"no symbolic links here: {exc}")


def test_a_link_where_a_text_copy_goes_is_not_read_or_written_through(box, tmp_path, monkeypatch):
    mine = tmp_path / "mine.txt"
    mine.write_bytes(b"not for the box\n")
    cast = _cast_in(box, "dc01", "2026-11-14_1432")
    text = cast.with_suffix(".txt")
    _link_or_skip(text, mine)
    _older(mine, cast)
    monkeypatch.setattr(casttext, "render", lambda *args, **kwargs: pytest.fail("rendered"))
    assert _refresh(box).lines == [
        ("warn", "no text copy of targets/dc01/recordings/2026-11-14_1432.cast: 2026-11-14_1432.txt is not a file")
    ]
    assert text.is_symlink() and mine.read_bytes() == b"not for the box\n"


@pytest.mark.parametrize("nofollow", [True, False], ids=["O_NOFOLLOW", "as on Windows"])
def test_a_link_put_in_place_while_rendering_is_not_read_or_written_through(box, tmp_path, monkeypatch, nofollow):
    # the check before rendering is made again when the text copy is opened; Windows has no
    # O_NOFOLLOW, so what was opened is compared with what is there
    if not nofollow:
        monkeypatch.delattr(os, "O_NOFOLLOW", raising=False)
    mine = tmp_path / "mine.txt"
    mine.write_bytes(b"not for the box\n")
    cast = _cast_in(box, "dc01", "2026-11-14_1432")
    text = cast.with_suffix(".txt")
    text.write_bytes(b"box      forest\n")
    _older(text, cast)

    def swapped(*args, **kwargs):
        text.unlink()
        _link_or_skip(text, mine)
        raise AssertionError("pyte")

    monkeypatch.setattr(casttext, "render", swapped)
    [(kind, _)] = _refresh(box).lines
    assert kind == "warn"
    # the link itself is replaced by the note; what it pointed to is left as it was
    assert mine.read_bytes() == b"not for the box\n"
    assert not text.is_symlink() and text.read_text(encoding="utf-8").endswith("(AssertionError)]\n")


def test_a_kept_text_copy_with_another_name_is_not_changed_through_it(box, tmp_path, monkeypatch):
    # a hard link: a line added in place would be added to the other file too, so the note
    # replaces this name only
    ticking(monkeypatch)
    cast = _cast_in(box, "dc01", "2026-11-14_1432", events=[(0, "o", "x\n" * 200)])
    mine = tmp_path / "mine.txt"
    mine.write_bytes(b"not for the box\n")
    text = cast.with_suffix(".txt")
    os.link(mine, text)
    _older(text, cast)
    assert [kind for kind, _ in _refresh(box).lines] == ["warn"]
    assert mine.read_bytes() == b"not for the box\n"
    assert text.read_text(encoding="utf-8").startswith("box      forest")
    assert text.read_text(encoding="utf-8").endswith("replay plays the cast]\n")


def test_only_a_row_the_next_one_continues_is_read_to_the_screen_width(monkeypatch):
    # the last flush reads each row to its last cell; a full read of each would cost the screen
    asked = []
    row_text = casttext._TextScreen._row_text

    def counted(self, y, full=False):
        asked.append(full)
        return row_text(self, y, full)

    monkeypatch.setattr(casttext._TextScreen, "_row_text", counted)
    render([(0, "o", "a\r\nb\r\n" + "x" * 1500 + "\r\n")], cols=1000, rows=5)
    assert asked.count(True) == 1


@pytest.mark.parametrize(
    "scroll",
    ["\x1b[4;1H\n", "\x1b[4;1H\x1b[1M", "\x1b[1;1H\x1bM", "\x1b[1;1H\x1b[1L"],
    ids=["index", "delete lines", "reverse index", "insert lines"],
)
def test_a_scroll_inside_a_region_ends_the_wrap_into_the_row_below_it(scroll):
    # the region's bottom row changes, so the row below it no longer continues it
    lines = render([(0, "o", "\x1b[4;1Habcdefghijxyz\x1b[1;4r" + scroll)], cols=10, rows=5)
    assert lines[-1] == "14:32:07  xyz"

def test_the_last_flush_is_timed_too(tmp_path, monkeypatch):
    # past the deadline by the end of the events, the screen is not read at all
    # an event of a kind the text copy does not draw: no screen call reads the clock before the end
    now = ticking(monkeypatch, step=5)
    monkeypatch.setattr(casttext, "RENDER_SECONDS", 3)
    monkeypatch.setattr(casttext, "RENDER_SECONDS_PER_MB", 0)
    path = write_cast(tmp_path / "recordings" / "2026-11-14_1432.cast", [(0, "m", "a marker")])
    finished = []
    real = casttext._TextScreen.finish
    monkeypatch.setattr(casttext._TextScreen, "finish", lambda self, last: finished.append(1) or real(self, last))
    with pytest.raises(CastError):
        casttext.write(path, box_name="forest", box_id="6f9c-id", target="dc01", tz=TZ)
    assert finished == []


def test_a_warning_with_no_whole_second_reads_plainly(box, monkeypatch):
    ticking(monkeypatch)
    monkeypatch.setattr(casttext, "RENDER_SECONDS", 10)
    _cast_in(box, "dc01", "2026-11-14_1400", events=[(0, "o", "x\n" * 200)])
    _cast_in(box, "dc01", "2026-11-14_1500", events=[(0, "o", "x\n" * 200)])
    warned = [text for kind, text in _refresh(box).lines if kind == "warn"]
    assert "longer than less than" not in warned[1] and "it had less than a second to render" in warned[1]


def test_text_the_parser_alone_takes_in_is_timed_too(tmp_path, monkeypatch):
    # an escape sequence that never ends calls no screen method at all
    ticking(monkeypatch)
    monkeypatch.setattr(casttext, "RENDER_SECONDS", 20)
    monkeypatch.setattr(casttext, "RENDER_SECONDS_PER_MB", 0)
    path = write_cast(tmp_path / "recordings" / "2026-11-14_1432.cast", [(0, "o", "\x1b]0;" + "A" * 20_000)])
    with pytest.raises(CastError, match="took longer than 20 seconds to render"):
        casttext.write(path, box_name="forest", box_id="6f9c-id", target="dc01", tz=TZ)


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


# ---- the most a cast may cost


def test_no_cast_gets_more_than_ten_minutes_however_large():
    # by its size alone a cast of 96 MiB from an archive got 6,100 seconds
    assert casttext.MAX_RENDER_SECONDS == 600
    assert casttext.allowance(8_000_000).seconds == casttext.RENDER_SECONDS + 480
    assert casttext.allowance(9_000_000).seconds == 600
    assert casttext.allowance(96 * 1024 * 1024).seconds == 600


def test_refresh_gives_no_cast_more_than_ten_minutes_either(box, monkeypatch):
    now = ticking(monkeypatch)
    large = _cast_in(box, "dc01", "2026-11-14_1400")
    os.truncate(large, 96 * 1024 * 1024)
    small = _cast_in(box, "dc01", "2026-11-14_1500")
    given = {}

    def note_the_time(cast_path, *, allowed, **kwargs):
        given[cast_path.name] = (allowed.seconds, allowed.deadline - now[0])

    monkeypatch.setattr(casttext, "write", note_the_time)
    _refresh(box)
    assert given == {large.name: (600, 600.0), small.name: (10, pytest.approx(10.0, abs=0.01))}


def test_a_cast_with_a_line_too_long_gets_a_warn_line_and_a_note_and_is_not_tried_again(box, monkeypatch):
    from pwn_broker import cast as cast_module

    monkeypatch.setattr(cast_module, "MAX_LINE_BYTES", 2000)
    long = _cast_in(box, "dc01", "2026-11-14_1400", events=[(0, "o", "before\r\n"), (1, "o", "A" * 5000)])
    fine = _cast_in(box, "dc01", "2026-11-14_1500")
    console = _refresh(box)
    assert console.lines == [
        ("warn", "no text copy of targets/dc01/recordings/2026-11-14_1400.cast: "
                 "line 3 is longer than 4 MiB, which no line of a recording is")
    ]  # fmt: skip
    text = long.with_suffix(".txt").read_text(encoding="utf-8")
    assert text.endswith("[no text copy: line 3 is longer than 4 MiB, which no line of a recording is]\n")
    assert "hello" in fine.with_suffix(".txt").read_text(encoding="utf-8")
    assert _refresh(box).lines == []


def test_a_cast_whose_first_line_is_too_long_gets_a_warn_line_and_no_text(box, monkeypatch):
    from pwn_broker import cast as cast_module

    monkeypatch.setattr(cast_module, "MAX_LINE_BYTES", 2000)
    long = write_cast(box.path / "targets" / "dc01" / "recordings" / "2026-11-14_1400.cast", [], title="t" * 5000)
    assert _refresh(box).lines == [
        ("warn", "no text copy of targets/dc01/recordings/2026-11-14_1400.cast: "
                 "the first line is longer than 4 MiB, which no line of a recording is")
    ]  # fmt: skip
    assert not long.with_suffix(".txt").exists()


def test_a_cast_whose_name_is_not_utf8_gets_its_text_copy(box):
    # the name goes into the text copy, which cannot hold such a byte: it is written as "?"
    made = odd_name(box.path / "targets" / "dc01" / "recordings", b"2026-11-14_1432\xff.cast",
                    cast_text([(0, "o", "hello\r\n")]).encode())  # fmt: skip
    if made is None:
        pytest.skip("no file here can have a name that is not UTF-8")
    assert _refresh(box).lines == []
    text = (made[: -len(b".cast")] + b".txt").decode("utf-8", "surrogateescape")
    with open(text, encoding="utf-8") as fh:
        lines = fh.read().splitlines()
    assert lines[3] == "cast     2026-11-14_1432?.cast" and lines[-1].endswith("  hello")
    assert _refresh(box).lines == []


def test_a_cast_in_a_folder_whose_name_is_not_utf8_gets_its_text_copy(box):
    try:
        folder = os.path.join(os.fsencode(box.path / "targets"), b"web\xff", b"recordings")
        os.makedirs(folder)
    except (OSError, UnicodeError):
        pytest.skip("no folder here can have a name that is not UTF-8")
    odd_name(os.fsdecode(folder), b"2026-11-14_1432.cast", cast_text([(0, "o", "hello\r\n")]).encode())
    assert _refresh(box).lines == []
    with open(os.path.join(folder, b"2026-11-14_1432.txt"), encoding="utf-8") as fh:
        assert fh.read().splitlines()[1] == "target   web?"
