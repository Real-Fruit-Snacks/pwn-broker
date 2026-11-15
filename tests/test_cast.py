import json

import pytest
from casts import START, cast_text, header, write_cast

from pwn_broker import cast
from pwn_broker.cast import CastError, Header


def _write(path, text: str):
    path.write_bytes(text.encode("utf-8"))
    return path


def test_header_is_read(tmp_path):
    path = write_cast(tmp_path / "a.cast", [], cols=120, rows=40, title="forest dc01 6f9c")
    expected = Header(cols=120, rows=40, timestamp=START, title="forest dc01 6f9c")
    assert cast.read_header(path) == expected


def test_header_without_timestamp_or_title(tmp_path):
    path = _write(tmp_path / "a.cast", '{"version": 3, "term": {"cols": 80, "rows": 24}}\n')
    assert cast.read_header(path) == Header(cols=80, rows=24, timestamp=None, title="")


@pytest.mark.parametrize(
    "first, reason",
    [
        (json.dumps({**header(), "version": 2}), "version"),
        (json.dumps({"version": 3, "timestamp": START}), "term"),
        ("this is not json", "JSON"),
        (json.dumps([1, 2, 3]), "JSON object"),
        (json.dumps({**header(), "term": {"cols": 0, "rows": 24}}), "cols"),
        (json.dumps({**header(), "term": {"cols": 5000, "rows": 24}}), "cols"),
        (json.dumps({**header(), "term": {"cols": 80, "rows": True}}), "rows"),
    ],
)
def test_bad_header_is_refused(tmp_path, first, reason):
    path = _write(tmp_path / "bad.cast", first + "\n")
    with pytest.raises(CastError) as err:
        cast.read_header(path)
    assert str(path) in str(err.value)
    assert reason in str(err.value)


def test_empty_file_is_refused(tmp_path):
    path = _write(tmp_path / "empty.cast", "")
    with pytest.raises(CastError, match="empty"):
        cast.read_header(path)


def test_missing_file_is_a_cast_error(tmp_path):
    with pytest.raises(CastError):
        cast.read_header(tmp_path / "nope.cast")


def test_events_add_up_the_intervals(tmp_path):
    path = write_cast(
        tmp_path / "a.cast", [(0.5, "o", "a"), (1.25, "o", "b"), (2, "r", "100x30"), (0, "x", "0")]
    )
    assert list(cast.events(path)) == [
        (0.5, "o", "a"),
        (1.75, "o", "b"),
        (3.75, "r", "100x30"),
        (3.75, "x", "0"),
    ]


def test_comments_and_blank_lines_are_skipped(tmp_path):
    body = '# a comment\n\n[1, "o", "a"]\n   \n#[9, "o", "no"]\n[1, "o", "b"]\n'
    text = json.dumps(header()) + "\n" + body
    path = _write(tmp_path / "a.cast", text)
    assert list(cast.events(path)) == [(1, "o", "a"), (2, "o", "b")]


def test_last_line_cut_mid_json_is_ignored(tmp_path):
    path = _write(tmp_path / "a.cast", cast_text([(1, "o", "a")]) + '[0.5, "o", "hal')
    assert list(cast.events(path)) == [(1, "o", "a")]


def test_last_line_without_a_break_is_ignored(tmp_path):
    path = _write(tmp_path / "a.cast", cast_text([(1, "o", "a")]) + '[0.5, "o", "whole"]')
    assert list(cast.events(path)) == [(1, "o", "a")]


def test_bad_last_line_with_a_break_is_ignored(tmp_path):
    path = _write(tmp_path / "a.cast", cast_text([(1, "o", "a")]) + '[0.5, "o", \n')
    assert list(cast.events(path)) == [(1, "o", "a")]


def test_bad_middle_line_names_its_number(tmp_path):
    text = cast_text([(1, "o", "a")]) + "[not json\n" + '[1, "o", "b"]\n'
    path = _write(tmp_path / "a.cast", text)
    got = cast.events(path)
    assert next(got) == (1, "o", "a")
    with pytest.raises(CastError, match="line 3") as err:
        next(got)
    assert str(path) in str(err.value)


@pytest.mark.parametrize(
    "line",
    ['{"a": 1}', '[1, "o"]', '[-1, "o", "a"]', '["1", "o", "a"]', '[1, 2, "a"]', '[1, "o", 3]'],
)
def test_malformed_events_are_bad_lines(tmp_path, line):
    path = _write(tmp_path / "a.cast", cast_text([]) + line + "\n" + '[1, "o", "b"]\n')
    with pytest.raises(CastError, match="line 2"):
        list(cast.events(path))


def test_events_of_a_header_only_file(tmp_path):
    assert list(cast.events(write_cast(tmp_path / "a.cast", []))) == []


@pytest.mark.parametrize(
    "content, expected",
    [
        (b"", 0),
        (b"no line break at all", 0),
        (b"one\ntwo\n", 8),
        (b"one\ntwo\nthr", 8),
    ],
)
def test_whole_size(tmp_path, content, expected):
    path = tmp_path / "a.cast"
    path.write_bytes(content)
    assert cast.whole_size(path) == expected


def test_whole_size_reads_back_across_blocks(tmp_path):
    path = tmp_path / "a.cast"
    tail = b"x" * (cast._BLOCK * 3 + 17)
    path.write_bytes(b"0123456789\n" + tail)
    assert cast.whole_size(path) == 11
    path.write_bytes(b"0123456789\n" + tail + b"\n")
    assert cast.whole_size(path) == 11 + len(tail) + 1
