import os
import tomllib
from datetime import datetime, timedelta
from types import SimpleNamespace

import pytest

from helpers import NOW
from pwn_broker import store, toolseen
from pwn_broker.toolpkg import ToolError

ONE = "a" * 64
TWO = "b" * 64
WHERE = "https://example.invalid/index.toml"


def build(name="kerbrute", version="1.0.3", number=1, sha256=ONE):
    return SimpleNamespace(name=name, version=version, build=number, sha256=sha256)


def kept(paths):
    return {key: row.sha256 for key, row in toolseen.load(paths).items()}


def test_nothing_is_kept_before_an_index_is_read(paths):
    assert toolseen.load(paths) == {}
    assert not paths.tools_seen.exists()


def test_a_build_seen_for_the_first_time_is_kept_with_when_and_where(paths):
    # to the second: the file is read by people too
    now = NOW.replace(microsecond=887336)
    toolseen.check(paths, [build(), build("pspy", "1.2.1", 2, TWO)], where=WHERE, now=now)
    assert tomllib.loads(paths.tools_seen.read_text(encoding="utf-8")) == {
        "schema": 1,
        "build": [
            {"name": "kerbrute", "version": "1.0.3", "build": 1, "sha256": ONE, "seen": NOW, "source": WHERE},
            {"name": "pspy", "version": "1.2.1", "build": 2, "sha256": TWO, "seen": NOW, "source": WHERE},
        ],
    }  # fmt: skip
    assert paths.tools_seen.parent == paths.tools


def test_the_same_index_again_writes_nothing(paths, monkeypatch):
    toolseen.check(paths, [build()], where=WHERE, now=NOW)

    def refuse(*args, **kwargs):
        raise AssertionError("an index that gives nothing new wrote the list")

    monkeypatch.setattr(toolseen, "write_toml", refuse)
    toolseen.check(paths, [build()], where="/another/index.toml", now=NOW + timedelta(days=3))
    row = toolseen.load(paths)[("kerbrute", "1.0.3", 1)]
    # still the first sight: the time and the index it came from are not moved
    assert (row.seen, row.source) == (NOW, WHERE)


def test_a_later_build_is_added_and_the_earlier_ones_stay(paths):
    toolseen.check(paths, [build()], where=WHERE, now=NOW)
    toolseen.check(paths, [build(), build(number=2, sha256=TWO)], where=WHERE, now=NOW)
    assert kept(paths) == {("kerbrute", "1.0.3", 1): ONE, ("kerbrute", "1.0.3", 2): TWO}


def test_a_build_given_another_sha256_is_refused_with_the_build_and_both_hashes(paths):
    toolseen.check(paths, [build()], where=WHERE, now=NOW)
    with pytest.raises(toolseen.BuildChanged) as caught:
        toolseen.check(paths, [build(sha256=TWO)], where="/mirror/index.toml", now=NOW)
    said = str(caught.value)
    assert "kerbrute 1.0.3-1" in said and ONE in said and TWO in said
    # when and where the kept one came from, the index refused, and the way out
    assert "2026-11-14" in said and WHERE in said and "/mirror/index.toml" in said
    assert "tool forget kerbrute@1.0.3-1" in said
    assert isinstance(caught.value, ToolError)
    assert kept(paths) == {("kerbrute", "1.0.3", 1): ONE}


def test_an_index_that_changed_one_build_has_none_of_its_new_builds_kept(paths):
    toolseen.check(paths, [build()], where=WHERE, now=NOW)
    before = paths.tools_seen.read_bytes()
    with pytest.raises(toolseen.BuildChanged):
        toolseen.check(
            paths, [build("pspy", "1.2.1", 1, TWO), build(sha256=TWO)], where=WHERE, now=NOW
        )
    assert paths.tools_seen.read_bytes() == before


@pytest.mark.parametrize(
    ("others", "said"),
    [(1, "(1 more build differs as well)"), (2, "(2 more builds differ as well)")],
)
def test_more_than_one_changed_build_is_counted(paths, others, said):
    first = [build(number=n) for n in range(1, others + 2)]
    toolseen.check(paths, first, where=WHERE, now=NOW)
    with pytest.raises(toolseen.BuildChanged) as caught:
        toolseen.check(
            paths, [build(number=b.build, sha256=TWO) for b in first], where=WHERE, now=NOW
        )
    assert "kerbrute 1.0.3-1" in str(caught.value) and said in str(caught.value)


def test_a_hash_in_capitals_is_the_same_hash(paths):
    toolseen.check(paths, [build(sha256=ONE.upper())], where=WHERE, now=NOW)
    toolseen.check(paths, [build()], where=WHERE, now=NOW)
    toolseen.check_one(paths, build(sha256=ONE.upper()), where=WHERE)
    assert kept(paths) == {("kerbrute", "1.0.3", 1): ONE}


def test_a_version_and_a_build_are_told_apart(paths):
    # 1.0-1 is build 1 of 1.0; 1.0-1 as a version, build 1, is another build
    toolseen.check(paths, [build(version="1.0", number=1)], where=WHERE, now=NOW)
    toolseen.check(paths, [build(version="1.0-1", number=1, sha256=TWO)], where=WHERE, now=NOW)
    assert len(kept(paths)) == 2


def test_check_one_refuses_a_changed_build_and_keeps_nothing(paths):
    toolseen.check_one(paths, build(), where=WHERE)
    assert not paths.tools_seen.exists()
    toolseen.check(paths, [build()], where=WHERE, now=NOW)
    toolseen.check_one(paths, build(), where=WHERE)
    with pytest.raises(toolseen.BuildChanged, match="tool forget kerbrute@1.0.3-1"):
        toolseen.check_one(paths, build(sha256=TWO), where=WHERE)


def test_forget_drops_one_build_and_leaves_the_rest(paths):
    toolseen.check(paths, [build(), build(number=2, sha256=TWO)], where=WHERE, now=NOW)
    (first, second) = toolseen.of_tool(paths, "kerbrute")
    assert (first.build, second.build) == (1, 2)
    assert toolseen.forget(paths, first) is True
    assert kept(paths) == {("kerbrute", "1.0.3", 2): TWO}
    assert toolseen.forget(paths, first) is False
    # forgotten, the build is taken as the next index gives it
    toolseen.check(paths, [build(sha256=TWO)], where=WHERE, now=NOW)
    assert kept(paths)[("kerbrute", "1.0.3", 1)] == TWO


def test_of_tool_lists_only_that_package(paths):
    toolseen.check(paths, [build(), build("pspy", "1.2.1", 1, TWO)], where=WHERE, now=NOW)
    assert [row.name for row in toolseen.of_tool(paths, "pspy")] == ["pspy"]
    assert toolseen.of_tool(paths, "certipy") == []


# ---- a list that cannot be read is never an empty list


def row_text(**over):
    row = {
        "name": '"kerbrute"', "version": '"1.0.3"', "build": "1", "sha256": f'"{ONE}"',
        "seen": "2026-11-14T12:00:00+02:00", "source": f'"{WHERE}"',
    }  # fmt: skip
    row.update(over)
    lines = [f"{key} = {value}" for key, value in row.items() if value is not None]
    return "[[build]]\n" + "\n".join(lines) + "\n"


@pytest.mark.parametrize(
    ("text", "why"),
    [
        # not TOML: the reason is the parser's own, which changes between Python versions
        ("schema = 1\n[[build", "cannot be read ("),
        ("", "it has no schema"),
        ("schema = 1\nbuild = 3\n", "build must be a list of tables"),
        ("schema = 1\nbuild = [3]\n", "build[0]: build is not a table"),
        ("schema = 1\n" + row_text(sha256=None), "build[0]: it has no 'sha256'"),
        ("schema = 1\n" + row_text(sha256='"abc"'), "sha256 must be 64 hexadecimal characters"),
        ("schema = 1\n" + row_text(build="true"), "build must be a whole number"),
        ("schema = 1\n" + row_text(build='"1"'), "build must be a whole number"),
        ("schema = 1\n" + row_text(name="7"), "name must be a string"),
        ("schema = 1\n" + row_text(seen='"yesterday"'), "seen must be a date and time"),
        (
            "schema = 1\n" + row_text() + row_text(sha256=f'"{TWO}"'),
            "kerbrute 1.0.3-1 is there with two SHA-256",
        ),
    ],
)
def test_a_list_that_cannot_be_read_stops_the_check_and_names_the_file(paths, text, why):
    paths.tools.mkdir(parents=True)
    paths.tools_seen.write_bytes(text.encode("utf-8"))
    for call in (
        lambda: toolseen.load(paths),
        lambda: toolseen.check(paths, [build(sha256=TWO)], where=WHERE, now=NOW),
        lambda: toolseen.check_one(paths, build(sha256=TWO), where=WHERE),
    ):
        with pytest.raises(ToolError) as caught:
            call()
        assert not isinstance(caught.value, toolseen.BuildChanged)
        assert str(paths.tools_seen) in str(caught.value) and why in str(caught.value)
        assert "delete it" in str(caught.value)
    # and it is left as it was, for whoever puts it right
    assert paths.tools_seen.read_bytes() == text.encode("utf-8")


def test_a_list_from_a_newer_version_is_not_written_over(paths):
    paths.tools.mkdir(parents=True)
    paths.tools_seen.write_bytes(b"schema = 2\n")
    with pytest.raises(ToolError, match="unsupported schema 2; upgrade pwn-broker"):
        toolseen.check(paths, [build()], where=WHERE, now=NOW)
    assert paths.tools_seen.read_bytes() == b"schema = 2\n"


def test_a_row_written_twice_with_one_hash_is_one_build(paths):
    paths.tools.mkdir(parents=True)
    paths.tools_seen.write_bytes(("schema = 1\n" + row_text() + row_text()).encode("utf-8"))
    assert kept(paths) == {("kerbrute", "1.0.3", 1): ONE}


def test_a_time_written_by_hand_without_an_offset_is_local_time(paths):
    paths.tools.mkdir(parents=True)
    text = "schema = 1\n" + row_text(seen="2026-11-14T12:00:00", sha256=f'"{ONE.upper()}"')
    paths.tools_seen.write_bytes(text.encode("utf-8"))
    (row,) = toolseen.load(paths).values()
    assert row.seen == datetime(2026, 11, 14, 12, 0, 0).astimezone() and row.sha256 == ONE


def test_a_write_that_fails_leaves_the_list_as_it_was(paths, monkeypatch):
    toolseen.check(paths, [build()], where=WHERE, now=NOW)
    before = paths.tools_seen.read_bytes()

    def fail(src, dst):
        raise OSError(28, "No space left on device")

    monkeypatch.setattr(store.os, "replace", fail)
    with pytest.raises(ToolError) as caught:
        toolseen.check(paths, [build(), build(number=2, sha256=TWO)], where=WHERE, now=NOW)
    assert str(paths.tools_seen) in str(caught.value) and "No space left" in str(caught.value)
    assert paths.tools_seen.read_bytes() == before
    # nothing half-written is left beside it
    assert [p.name for p in paths.tools.iterdir()] == ["seen.toml"]


@pytest.mark.skipif(os.name == "nt", reason="needs symlinks")
def test_a_dangling_link_in_its_place_is_not_an_empty_list(paths, tmp_path):
    paths.tools.mkdir(parents=True)
    paths.tools_seen.symlink_to(tmp_path / "nowhere.toml")
    with pytest.raises(ToolError, match="cannot be read"):
        toolseen.check(paths, [build()], where=WHERE, now=NOW)


def test_differs_names_the_build_both_hashes_and_the_witness():
    said = toolseen.differs(build(sha256=TWO.upper()), held=ONE.upper(), holder="the box recorded")
    assert said == (
        f"kerbrute 1.0.3-1: the index gives it the SHA-256 {TWO}, and the box recorded {ONE}"
    )
