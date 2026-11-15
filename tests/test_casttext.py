import os
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
        "14:32:10  [full-screen program until 14:35:30, see the cast]",
        "14:32:07  $ vim notes",
        "14:35:31  $ ls",
    ]


@pytest.mark.parametrize("mode", ["47", "1047"])
def test_other_alternate_screen_modes(mode):
    events = [(0, "o", "$ less\r\n"), (1, "o", f"\x1b[?{mode}hpage"), (2, "o", f"\x1b[?{mode}l$ ")]
    assert render(events) == [
        "14:32:08  [full-screen program until 14:32:09, see the cast]",
        "14:32:07  $ less",
        "14:32:09  $",
    ]


def test_recording_ending_in_a_full_screen_program():
    events = [(0, "o", "$ top\r\n"), (1, "o", "\x1b[?1049hload 0.1"), (9, "m", "")]
    assert render(events) == [
        "14:32:08  [full-screen program until 14:32:16, see the cast]",
        "14:32:07  $ top",
    ]


def test_scrolled_lines_before_a_full_screen_program_come_first():
    text = "\r\n".join(f"line{n}" for n in range(1, 5)) + "\r\n$ vim"
    events = [(0, "o", text), (1, "o", "\x1b[?1049hx"), (2, "o", "\x1b[?1049l\r\n$ ")]
    assert render(events, rows=3) == [
        "14:32:07  line1",
        "14:32:07  line2",
        "14:32:08  [full-screen program until 14:32:09, see the cast]",
        "14:32:07  line3",
        "14:32:07  line4",
        "14:32:07  $ vim",
        "14:32:09  $",
    ]


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
