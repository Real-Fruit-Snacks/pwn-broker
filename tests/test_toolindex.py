import email.message
import hashlib
import http.server
import io
import os
import threading
import time
import tomllib
import urllib.request
import urllib.response
from dataclasses import replace
from datetime import timedelta

import pytest
import tomli_w

from helpers import NOW
from pwn_broker import toolindex
from pwn_broker.config import DEFAULT_TOOLS_INDEX, Settings
from pwn_broker.toolpkg import ToolError
from toolkit import make_entry, write_index

HASH = "a" * 64


def stamp_of(paths):
    return (paths.cache / "index.fetched").read_text(encoding="utf-8").splitlines()[0]


def build_row(version="1.0.3", build=1, **over):
    row = {
        "version": version,
        "build": build,
        "kind": "kali",
        "needs_root": False,
        "commands": ["kerbrute"],
        "file": f"kerbrute-{version}-{build}.zip",
        "url": f"https://example.invalid/kerbrute-{version}-{build}.zip",
        "size": 10,
        "sha256": HASH,
    }
    row.update(over)
    return row


def tool_row(builds=None, **over):
    row = {
        "name": "kerbrute",
        "description": "Kerberos user enumeration",
        "tags": ["ad", "kerberos"],
        "licence": "Apache-2.0",
        "upstream": "https://example.invalid/kerbrute",
        "latest": "1.0.3-1",
        "build": builds if builds is not None else [build_row()],
    }
    row.update(over)
    return row


def index_data(*tools):
    return {"schema": 1, "tool": list(tools) if tools else [tool_row()]}


def index_text(*tools):
    return tomli_w.dumps(index_data(*tools))


class Fetcher:
    def __init__(self, payload=b"", fail=False):
        self.payload = payload
        self.fail = fail
        self.calls = []

    def __call__(self, url, timeout):
        self.calls.append((url, timeout))
        if self.fail:
            raise OSError("offline")
        return self.payload


class Downloader:
    def __init__(self, payload=b"", fail=False):
        self.payload = payload
        self.fail = fail
        self.calls = []

    def __call__(self, url, path, limit, timeout):
        self.calls.append((url, path.name, limit, timeout))
        if self.fail:
            raise OSError("offline")
        path.write_bytes(self.payload)


URL = "https://example.invalid/index.toml"


def url_settings():
    return Settings(tools_index=URL)


# ---- parse_index


def test_parse_round_trip():
    index = toolindex.parse_index(index_data())
    tool = index.tools[0]
    assert (tool.name, tool.latest, tool.tags, tool.licence) == (
        "kerbrute",
        "1.0.3-1",
        ["ad", "kerberos"],
        "Apache-2.0",
    )
    build = tool.builds[0]
    assert build.name == "kerbrute"
    assert (build.version, build.build, build.kind, build.needs_root) == ("1.0.3", 1, "kali", False)
    assert (build.commands, build.file, build.size, build.sha256) == (
        ["kerbrute"],
        "kerbrute-1.0.3-1.zip",
        10,
        HASH,
    )


def test_parse_defaults_for_tags_commands_url():
    row = build_row(url="")
    del row["commands"]
    tool = tool_row(builds=[row])
    del tool["tags"]
    parsed = toolindex.parse_index(index_data(tool)).tools[0]
    assert parsed.tags == []
    assert parsed.builds[0].commands == []
    assert parsed.builds[0].url == ""


@pytest.mark.parametrize("schema", [5, 0, "1", True, None])
def test_parse_unknown_schema_says_to_upgrade(schema):
    data = index_data()
    data["schema"] = schema
    with pytest.raises(ToolError, match="upgrade pwn-broker"):
        toolindex.parse_index(data)


def notes_row(**over):
    row = build_row(version="2026.11.19", kind="notes", commands=[], file="playbooks-2026.11.19-1.zip")
    row.update(over)
    return row


def notes_tool(builds=None):
    return tool_row(
        name="playbooks", latest="2026.11.19-1", builds=builds if builds is not None else [notes_row()]
    )


def test_schema_3_index_with_a_notes_build_parses():
    data = {"schema": 3, "tool": [tool_row(), notes_tool()]}
    tools = toolindex.parse_index(data).tools
    notes = tools[1].builds[0]
    assert (notes.name, notes.kind, notes.commands, notes.requires, notes.needs_root) == (
        "playbooks", "notes", [], [], False,
    )  # fmt: skip
    assert tools[0].builds[0].kind == "kali"


@pytest.mark.parametrize("schema", [1, 2])
def test_notes_build_needs_a_schema_3_index(schema):
    with pytest.raises(ToolError) as err:
        toolindex.parse_index({"schema": schema, "tool": [notes_tool()]})
    assert "tool playbooks.build[0].kind: notes needs a schema 3 index" in str(err.value)


@pytest.mark.parametrize(
    "field, value",
    [("commands", ["x"]), ("requires", ["python-3.13"]), ("needs_root", True)],
)
def test_notes_build_has_no_commands_requires_or_root(field, value):
    with pytest.raises(ToolError) as err:
        toolindex.parse_index({"schema": 3, "tool": [notes_tool([notes_row(**{field: value})])]})
    assert f"tool playbooks.build[0].{field}: a notes package" in str(err.value)


def test_builds_cannot_mix_notes_with_other_kinds():
    mixed = notes_tool([notes_row(), notes_row(build=2, kind="kali", commands=["x"])])
    with pytest.raises(ToolError) as err:
        toolindex.parse_index({"schema": 3, "tool": [mixed]})
    assert "tool playbooks: its builds mix kind notes with other kinds" in str(err.value)


def test_parse_missing_schema():
    with pytest.raises(ToolError) as err:
        toolindex.parse_index({"tool": []})
    assert "cannot be read" in str(err.value) and "upgrade" not in str(err.value)


@pytest.mark.parametrize(
    "file",
    ["../x.zip", "a/b.zip", "a\\b.zip", "x.tar", "", ".zip/", "/abs.zip", "a\0.zip", "..", "C:x.zip"],
)
def test_parse_file_must_be_plain_zip_name(file):
    data = index_data(tool_row(builds=[build_row(file=file)]))
    with pytest.raises(ToolError):
        toolindex.parse_index(data)


@pytest.mark.parametrize("sha", ["abc", "g" * 64, "a" * 63, "a" * 65, 5, ""])
def test_parse_sha256_must_be_64_hex(sha):
    with pytest.raises(ToolError, match="sha256"):
        toolindex.parse_index(index_data(tool_row(builds=[build_row(sha256=sha)])))


@pytest.mark.parametrize("size", [0, -1, "5", 1.5, True])
def test_parse_size_must_be_positive_int(size):
    with pytest.raises(ToolError, match="size"):
        toolindex.parse_index(index_data(tool_row(builds=[build_row(size=size)])))


def test_parse_latest_must_name_a_build():
    with pytest.raises(ToolError, match="latest"):
        toolindex.parse_index(index_data(tool_row(latest="9.9.9-1")))


def test_parse_tool_without_builds():
    with pytest.raises(ToolError, match="no builds"):
        toolindex.parse_index(index_data(tool_row(builds=[])))


def test_parse_duplicate_tool_names():
    with pytest.raises(ToolError, match="more than once"):
        toolindex.parse_index(index_data(tool_row(), tool_row()))


def test_parse_duplicate_builds():
    with pytest.raises(ToolError, match="more than once"):
        toolindex.parse_index(index_data(tool_row(builds=[build_row(), build_row()])))


@pytest.mark.parametrize(
    "over",
    [
        {"kind": "other"},
        {"build": 0},
        {"build": True},
        {"needs_root": "no"},
        {"commands": "kerbrute"},
        {"version": ""},
        {"version": "1 0"},
    ],
)
def test_parse_bad_build_fields(over):
    with pytest.raises(ToolError):
        toolindex.parse_index(index_data(tool_row(builds=[build_row(**over)])))


@pytest.mark.parametrize("over", [{"name": "Bad Name"}, {"description": ""}, {"tags": "x"}])
def test_parse_bad_tool_fields(over):
    with pytest.raises(ToolError):
        toolindex.parse_index(index_data(tool_row(**over)))


def test_parse_tool_must_be_list_of_tables():
    with pytest.raises(ToolError):
        toolindex.parse_index({"schema": 1, "tool": "x"})


# ---- location and load_index


def test_location_default_and_setting(tmp_path):
    assert toolindex.location(Settings()) == DEFAULT_TOOLS_INDEX
    assert toolindex.location(Settings(tools_index=str(tmp_path))) == str(tmp_path)


def test_is_url():
    assert toolindex.is_url("http://x/y")
    assert toolindex.is_url("https://x/y")
    assert not toolindex.is_url("/srv/index")
    assert not toolindex.is_url("ftp://x")


def test_folder_location_reads_every_time(paths, tmp_path):
    folder = tmp_path / "idx"
    folder.mkdir()
    (folder / "index.toml").write_text(index_text(), encoding="utf-8")
    settings = Settings(tools_index=str(folder))
    first = toolindex.load_index(paths, settings, now=NOW)
    assert first.tools[0].name == "kerbrute"
    (folder / "index.toml").write_text(
        index_text(tool_row(name="other", builds=[build_row()])), encoding="utf-8"
    )
    assert toolindex.load_index(paths, settings, now=NOW).tools[0].name == "other"
    assert not (paths.cache / "index.toml").exists()


def test_folder_location_missing_says_where(paths, tmp_path):
    settings = Settings(tools_index=str(tmp_path / "nope"))
    with pytest.raises(ToolError) as err:
        toolindex.load_index(paths, settings, now=NOW)
    assert str(tmp_path / "nope") in str(err.value)
    assert "tools_index" in str(err.value) and "config.toml" in str(err.value)


def test_folder_without_index_file(paths, tmp_path):
    with pytest.raises(ToolError, match="tools_index"):
        toolindex.load_index(paths, Settings(tools_index=str(tmp_path)), now=NOW)


def test_folder_index_bad_toml(paths, tmp_path):
    (tmp_path / "index.toml").write_text("not = [valid", encoding="utf-8")
    with pytest.raises(ToolError):
        toolindex.load_index(paths, Settings(tools_index=str(tmp_path)), now=NOW)


def test_url_first_fetch_writes_cache(paths):
    fetch = Fetcher(index_text().encode())
    index = toolindex.load_index(paths, url_settings(), now=NOW, fetch=fetch)
    assert index.tools[0].name == "kerbrute"
    assert fetch.calls == [(URL, 2)]
    assert (paths.cache / "index.toml").read_text(encoding="utf-8") == index_text()
    stamp = stamp_of(paths)
    assert stamp == NOW.isoformat()


def test_url_fresh_cache_is_not_fetched(paths):
    toolindex.load_index(paths, url_settings(), now=NOW, fetch=Fetcher(index_text().encode()))
    again = Fetcher(fail=True)
    later = NOW + timedelta(hours=23)
    index = toolindex.load_index(paths, url_settings(), now=later, fetch=again)
    assert index.tools[0].name == "kerbrute"
    assert again.calls == []


def test_url_stale_cache_is_refreshed(paths):
    toolindex.load_index(paths, url_settings(), now=NOW, fetch=Fetcher(index_text().encode()))
    new = index_text(tool_row(name="fresh"))
    fetch = Fetcher(new.encode())
    later = NOW + timedelta(days=1, minutes=1)
    index = toolindex.load_index(paths, url_settings(), now=later, fetch=fetch)
    assert index.tools[0].name == "fresh"
    assert fetch.calls == [(URL, 2)]
    assert stamp_of(paths) == later.isoformat()


def test_url_force_fetches_with_longer_timeout(paths):
    toolindex.load_index(paths, url_settings(), now=NOW, fetch=Fetcher(index_text().encode()))
    fetch = Fetcher(index_text(tool_row(name="forced")).encode())
    index = toolindex.load_index(paths, url_settings(), now=NOW, fetch=fetch, force=True)
    assert index.tools[0].name == "forced"
    assert fetch.calls == [(URL, 30)]


def test_url_stale_failed_fetch_uses_cache(paths):
    toolindex.load_index(paths, url_settings(), now=NOW, fetch=Fetcher(index_text().encode()))
    later = NOW + timedelta(days=3)
    fetch = Fetcher(fail=True)
    index = toolindex.load_index(paths, url_settings(), now=later, fetch=fetch)
    assert index.tools[0].name == "kerbrute"
    assert len(fetch.calls) == 1


def test_url_forced_failed_fetch_raises_even_with_cache(paths):
    toolindex.load_index(paths, url_settings(), now=NOW, fetch=Fetcher(index_text().encode()))
    with pytest.raises(ToolError, match="offline"):
        toolindex.load_index(paths, url_settings(), now=NOW, fetch=Fetcher(fail=True), force=True)


def test_url_failed_fetch_without_cache_says_where(paths):
    with pytest.raises(ToolError) as err:
        toolindex.load_index(paths, url_settings(), now=NOW, fetch=Fetcher(fail=True))
    assert URL in str(err.value)
    assert "tools_index" in str(err.value) and "config.toml" in str(err.value)


def test_url_default_location_used(paths):
    fetch = Fetcher(index_text().encode())
    toolindex.load_index(paths, Settings(), now=NOW, fetch=fetch)
    assert fetch.calls[0][0] == DEFAULT_TOOLS_INDEX


def test_bad_download_never_replaces_good_cache(paths):
    toolindex.load_index(paths, url_settings(), now=NOW, fetch=Fetcher(index_text().encode()))
    later = NOW + timedelta(days=2)
    index = toolindex.load_index(paths, url_settings(), now=later, fetch=Fetcher(b"garbage = ["))
    assert index.tools[0].name == "kerbrute"
    assert (paths.cache / "index.toml").read_text(encoding="utf-8") == index_text()
    assert stamp_of(paths) == NOW.isoformat()


def test_bad_download_wrong_schema_is_refused_without_cache(paths):
    bad = tomli_w.dumps({"schema": 5, "tool": []}).encode()
    with pytest.raises(ToolError, match="upgrade pwn-broker"):
        toolindex.load_index(paths, url_settings(), now=NOW, fetch=Fetcher(bad))
    assert not (paths.cache / "index.toml").exists()


def test_non_utf8_download_is_a_failed_fetch(paths):
    with pytest.raises(ToolError):
        toolindex.load_index(paths, url_settings(), now=NOW, fetch=Fetcher(b"\xff\xfe"))


@pytest.mark.parametrize("stamp", [None, "garbage", "2026-11-14T12:00:00"])
def test_missing_or_unreadable_stamp_is_stale(paths, stamp):
    toolindex.load_index(paths, url_settings(), now=NOW, fetch=Fetcher(index_text().encode()))
    if stamp is None:
        (paths.cache / "index.fetched").unlink()
    else:
        (paths.cache / "index.fetched").write_text(stamp, encoding="utf-8")
    fetch = Fetcher(index_text(tool_row(name="again")).encode())
    index = toolindex.load_index(paths, url_settings(), now=NOW, fetch=fetch)
    assert index.tools[0].name == "again"
    assert len(fetch.calls) == 1


def test_cached_index_that_no_longer_parses_is_absent(paths):
    paths.cache.mkdir(parents=True)
    (paths.cache / "index.toml").write_text("broken = [", encoding="utf-8")
    (paths.cache / "index.fetched").write_text(NOW.isoformat() + "\n" + URL, encoding="utf-8")
    fetch = Fetcher(index_text().encode())
    index = toolindex.load_index(paths, url_settings(), now=NOW, fetch=fetch)
    assert index.tools[0].name == "kerbrute"
    assert len(fetch.calls) == 1


def test_unparsable_cache_and_failed_fetch_raises(paths):
    paths.cache.mkdir(parents=True)
    (paths.cache / "index.toml").write_text("broken = [", encoding="utf-8")
    (paths.cache / "index.fetched").write_text(NOW.isoformat() + "\n" + URL, encoding="utf-8")
    with pytest.raises(ToolError, match="tools_index"):
        toolindex.load_index(paths, url_settings(), now=NOW, fetch=Fetcher(fail=True))


def test_forced_bad_download_raises_and_keeps_old_cache(paths):
    toolindex.load_index(paths, url_settings(), now=NOW, fetch=Fetcher(index_text().encode()))
    later = NOW + timedelta(days=3)
    with pytest.raises(ToolError):
        toolindex.load_index(
            paths, url_settings(), now=later, fetch=Fetcher(b"garbage = ["), force=True
        )
    assert (paths.cache / "index.toml").read_text(encoding="utf-8") == index_text()
    assert stamp_of(paths) == NOW.isoformat()


def test_cache_from_another_location_is_absent(paths):
    toolindex.load_index(paths, url_settings(), now=NOW, fetch=Fetcher(index_text().encode()))
    other = Settings(tools_index="https://other.invalid/index.toml")
    with pytest.raises(ToolError):
        toolindex.load_index(paths, other, now=NOW, fetch=Fetcher(fail=True))
    fetch = Fetcher(index_text(tool_row(name="elsewhere")).encode())
    index = toolindex.load_index(paths, other, now=NOW, fetch=fetch)
    assert index.tools[0].name == "elsewhere"
    assert len(fetch.calls) == 1


def test_future_stamp_is_stale(paths):
    toolindex.load_index(paths, url_settings(), now=NOW, fetch=Fetcher(index_text().encode()))
    fetch = Fetcher(index_text(tool_row(name="again")).encode())
    earlier = NOW - timedelta(hours=1)
    index = toolindex.load_index(paths, url_settings(), now=earlier, fetch=fetch)
    assert index.tools[0].name == "again"


def test_unwritable_cache_still_returns_the_fetched_index(paths):
    # a file where the cache folder should be makes every cache write fail
    paths.opt.mkdir(parents=True)
    paths.cache.write_text("in the way", encoding="utf-8")
    index = toolindex.load_index(
        paths, url_settings(), now=NOW, fetch=Fetcher(index_text().encode())
    )
    assert index.tools[0].name == "kerbrute"


def test_stamp_is_written_only_after_the_index(paths, monkeypatch):
    written = []

    def fake_write(path, text, **kw):
        written.append(path.name)
        if path.name == "index.toml":
            raise OSError("full")

    monkeypatch.setattr(toolindex, "write_text", fake_write)
    toolindex.load_index(paths, url_settings(), now=NOW, fetch=Fetcher(index_text().encode()))
    assert written == ["index.toml"]


def test_slow_fetch_is_abandoned_at_the_deadline(paths, monkeypatch):
    monkeypatch.setattr(toolindex, "QUICK_TIMEOUT", 0.05)

    def slow(url, timeout):
        time.sleep(1)
        return index_text().encode()

    start = time.monotonic()
    with pytest.raises(ToolError):
        toolindex.load_index(paths, url_settings(), now=NOW, fetch=slow)
    assert time.monotonic() - start < 0.8
    assert not (paths.cache / "index.toml").exists()


def test_slow_fetch_with_cache_uses_the_cache(paths, monkeypatch):
    toolindex.load_index(paths, url_settings(), now=NOW, fetch=Fetcher(index_text().encode()))
    monkeypatch.setattr(toolindex, "QUICK_TIMEOUT", 0.05)

    def slow(url, timeout):
        time.sleep(1)
        return b""

    start = time.monotonic()
    index = toolindex.load_index(paths, url_settings(), now=NOW + timedelta(days=2), fetch=slow)
    assert index.tools[0].name == "kerbrute"
    assert time.monotonic() - start < 0.8


def test_oversized_index_is_a_failed_fetch(paths, monkeypatch):
    monkeypatch.setattr(toolindex, "MAX_INDEX_BYTES", 10)
    with pytest.raises(ToolError):
        toolindex.load_index(paths, url_settings(), now=NOW, fetch=Fetcher(index_text().encode()))


# ---- find, pick, search


def sample_index():
    return toolindex.parse_index(
        index_data(
            tool_row(
                builds=[
                    build_row("1.0.2", 1),
                    build_row("1.0.3", 1),
                    build_row("1.0.3", 2),
                    build_row("1.0.3", 10),
                ],
                latest="1.0.3-2",
            ),
            tool_row(
                name="ligolo-ng",
                description="Tunnelling over TUN",
                tags=["pivot"],
                builds=[build_row("0.9.2", 1)],
                latest="0.9.2-1",
            ),
        )
    )


def test_find_tool_exact_and_closest():
    index = sample_index()
    assert toolindex.find_tool(index, "ligolo-ng").name == "ligolo-ng"
    with pytest.raises(ToolError, match="kerbrute") as err:
        toolindex.find_tool(index, "kerbrut")
    assert "did you mean" in str(err.value)
    with pytest.raises(ToolError) as err:
        toolindex.find_tool(index, "zzzzzz")
    assert "did you mean" not in str(err.value)


def test_pick_build_forms():
    tool = sample_index().tools[0]
    assert toolindex.pick_build(tool, None).build == 2
    assert toolindex.pick_build(tool, "1.0.3").build == 10
    assert toolindex.pick_build(tool, "1.0.2").build == 1
    exact = toolindex.pick_build(tool, "1.0.3-2")
    assert (exact.version, exact.build) == ("1.0.3", 2)


def test_pick_build_takes_the_exact_build_before_a_version_that_reads_the_same():
    # a version may hold a hyphen, so 1.0-1 is build 1 of version 1.0 and also the version
    # 1.0-1. A box's row asks for its build by that name, and has to get that build back
    builds = [build_row("1.0", 1), build_row("1.0-1", 2)]
    tool = toolindex.parse_index(index_data(tool_row(builds=builds, latest="1.0-1-2"))).tools[0]
    exact = toolindex.pick_build(tool, "1.0-1")
    assert (exact.version, exact.build) == ("1.0", 1)
    newer = toolindex.pick_build(tool, "1.0-1-2")
    assert (newer.version, newer.build) == ("1.0-1", 2)
    assert toolindex.pick_build(tool, "1.0").build == 1


@pytest.mark.parametrize("wanted", ["9.9", "1.0.3-3", "", "1.0"])
def test_pick_build_unknown_lists_versions(wanted):
    tool = sample_index().tools[0]
    with pytest.raises(ToolError) as err:
        toolindex.pick_build(tool, wanted)
    assert "1.0.2" in str(err.value) and "1.0.3" in str(err.value)


def test_search_matches_every_word_case_insensitively():
    index = sample_index()
    names = lambda words: [t.name for t in toolindex.search(index, words)]  # noqa: E731
    assert names(["KERB"]) == ["kerbrute"]
    assert names(["tunnelling"]) == ["ligolo-ng"]
    assert names(["pivot"]) == ["ligolo-ng"]
    assert names(["ad", "enumeration"]) == ["kerbrute"]
    assert names(["ad", "pivot"]) == []
    assert names([]) == ["kerbrute", "ligolo-ng"]
    assert names(["e"]) == ["kerbrute", "ligolo-ng"]


# ---- fetch_zip


def make_zip_entry(tmp_path, payload=b"zip bytes", **over):
    entry = toolindex.parse_index(
        index_data(
            tool_row(
                builds=[
                    build_row(
                        size=len(payload), sha256=hashlib.sha256(payload).hexdigest(), **over
                    )
                ]
            )
        )
    ).tools[0].builds[0]
    return entry


def test_fetch_zip_cache_hit(paths, tmp_path):
    entry = make_zip_entry(tmp_path)
    paths.cache.mkdir(parents=True)
    (paths.cache / entry.file).write_bytes(b"zip bytes")
    download = Downloader(fail=True)
    got = toolindex.fetch_zip(paths, url_settings(), entry, download=download)
    assert got == paths.cache / entry.file
    assert download.calls == []


def test_fetch_zip_bad_cached_copy_is_replaced(paths, tmp_path):
    entry = make_zip_entry(tmp_path)
    paths.cache.mkdir(parents=True)
    (paths.cache / entry.file).write_bytes(b"tampered!")
    got = toolindex.fetch_zip(paths, url_settings(), entry, download=Downloader(b"zip bytes"))
    assert got.read_bytes() == b"zip bytes"


def test_fetch_zip_copies_from_folder(paths, tmp_path):
    folder = tmp_path / "idx"
    folder.mkdir()
    entry = make_zip_entry(tmp_path, url="")
    (folder / entry.file).write_bytes(b"zip bytes")
    got = toolindex.fetch_zip(paths, Settings(tools_index=str(folder)), entry)
    assert got == paths.cache / entry.file
    assert got.read_bytes() == b"zip bytes"
    assert list(paths.cache.glob("*.part")) == []


def test_fetch_zip_folder_missing_file(paths, tmp_path):
    entry = make_zip_entry(tmp_path)
    with pytest.raises(ToolError):
        toolindex.fetch_zip(paths, Settings(tools_index=str(tmp_path)), entry)
    assert list(paths.cache.glob("*")) == []


def test_fetch_zip_downloads(paths, tmp_path):
    entry = make_zip_entry(tmp_path)
    download = Downloader(b"zip bytes")
    got = toolindex.fetch_zip(paths, url_settings(), entry, download=download)
    assert got == paths.cache / entry.file
    assert got.read_bytes() == b"zip bytes"
    assert download.calls == [(entry.url, entry.file + ".part", entry.size, 300.0)]
    assert list(paths.cache.glob("*.part")) == []


def test_fetch_zip_wrong_hash_deletes_and_raises(paths, tmp_path):
    entry = make_zip_entry(tmp_path)
    with pytest.raises(ToolError, match="SHA-256"):
        toolindex.fetch_zip(paths, url_settings(), entry, download=Downloader(b"zip BYTES"))
    assert list(paths.cache.iterdir()) == []


def test_fetch_zip_wrong_size_deletes_and_raises(paths, tmp_path):
    entry = make_zip_entry(tmp_path)
    with pytest.raises(ToolError, match="size"):
        toolindex.fetch_zip(paths, url_settings(), entry, download=Downloader(b"zip bytes plus"))
    assert list(paths.cache.iterdir()) == []


def test_fetch_zip_failed_download(paths, tmp_path):
    entry = make_zip_entry(tmp_path)
    with pytest.raises(ToolError, match="offline"):
        toolindex.fetch_zip(paths, url_settings(), entry, download=Downloader(fail=True))
    assert list(paths.cache.iterdir()) == []


def _http_error(url, body):
    import urllib.error

    return urllib.error.HTTPError(url, 404, "Not Found", {}, body)


def test_a_refused_index_closes_the_response_it_came_with(paths):
    import io

    body = io.BytesIO(b"not found")
    # held here, so collecting the error cannot close the body in place of the code under test
    raised = []

    def refused(url, timeout):
        raised.append(_http_error(url, body))
        raise raised[-1]

    with pytest.raises(ToolError):
        toolindex.load_index(paths, url_settings(), now=NOW, fetch=refused)
    assert raised and body.closed


def test_a_refusal_after_the_deadline_closes_its_response(paths, monkeypatch):
    import io
    import threading

    monkeypatch.setattr(toolindex, "QUICK_TIMEOUT", 0.05)
    body = io.BytesIO(b"not found")
    raised = []
    late = threading.Event()

    def slow_refusal(url, timeout):
        time.sleep(0.3)
        raised.append(_http_error(url, body))
        late.set()
        raise raised[-1]

    with pytest.raises(ToolError, match="no answer"):
        toolindex.load_index(paths, url_settings(), now=NOW, fetch=slow_refusal)
    assert late.wait(5)
    deadline = time.monotonic() + 5
    while not body.closed and time.monotonic() < deadline:
        time.sleep(0.01)
    assert raised and body.closed


def test_close_response_leaves_other_errors_alone():
    class Closable(Exception):
        closed = False

        def close(self):
            self.closed = True

    error = Closable()
    toolindex.close_response(error)
    assert not error.closed


def test_a_refused_zip_closes_the_response_it_came_with(paths, tmp_path):
    import io

    body = io.BytesIO(b"not found")
    entry = make_zip_entry(tmp_path)
    # held here, so collecting the error cannot close the body in place of the code under test
    raised = []

    def refused(url, dest, limit, timeout):
        raised.append(_http_error(url, body))
        raise raised[-1]

    with pytest.raises(ToolError, match="cannot download"):
        toolindex.fetch_zip(paths, url_settings(), entry, download=refused)
    assert raised and body.closed


def test_fetch_zip_url_location_needs_a_url(paths, tmp_path):
    entry = make_zip_entry(tmp_path, url="")
    with pytest.raises(ToolError, match="no download address"):
        toolindex.fetch_zip(paths, url_settings(), entry, download=Downloader(b"zip bytes"))


@pytest.mark.parametrize("file", ["../evil.zip", "a/b.zip", "a\\b.zip", "x.tar", "", ".."])
def test_fetch_zip_rechecks_file_name(paths, tmp_path, file):
    entry = replace(make_zip_entry(tmp_path), file=file)
    download = Downloader(b"zip bytes")
    with pytest.raises(ToolError):
        toolindex.fetch_zip(paths, url_settings(), entry, download=download)
    assert download.calls == []
    assert not (tmp_path / "evil.zip").exists()
    assert not (paths.opt / "evil.zip").exists()


# ---- clear_cache


def test_clear_cache_removes_zips_and_parts_only(paths):
    paths.cache.mkdir(parents=True)
    for name in ("a.zip", "b.zip", "c.zip.part", "index.toml", "index.fetched", "notes.txt"):
        (paths.cache / name).write_text("x", encoding="utf-8")
    (paths.cache / "sub").mkdir()
    (paths.cache / "sub" / "d.zip").write_text("x", encoding="utf-8")
    assert toolindex.clear_cache(paths) == 2
    left = sorted(p.name for p in paths.cache.iterdir())
    assert left == ["index.fetched", "index.toml", "notes.txt", "sub"]
    assert (paths.cache / "sub" / "d.zip").exists()


def test_clear_cache_without_a_cache_folder(paths):
    assert toolindex.clear_cache(paths) == 0


# ---- untrusted download addresses


@pytest.mark.parametrize("url", ["file:///etc/passwd", "ftp://x/y.zip", "/dev/zero", "//x/y"])
def test_fetch_zip_refuses_non_http_urls(paths, tmp_path, url):
    entry = make_zip_entry(tmp_path, url=url)
    download = Downloader(b"zip bytes")
    with pytest.raises(ToolError, match="http"):
        toolindex.fetch_zip(paths, url_settings(), entry, download=download)
    assert download.calls == []


def test_fetch_zip_folder_entry_must_be_a_regular_file(paths, tmp_path):
    folder = tmp_path / "idx"
    (folder / "kerbrute-1.0.3-1.zip").mkdir(parents=True)
    entry = make_zip_entry(tmp_path)
    with pytest.raises(ToolError, match="regular file"):
        toolindex.fetch_zip(paths, Settings(tools_index=str(folder)), entry)
    assert list(paths.cache.glob("*")) == []


@pytest.mark.skipif(os.name == "nt", reason="needs symlinks")
def test_fetch_zip_folder_entry_may_not_be_a_link(paths, tmp_path):
    folder = tmp_path / "idx"
    folder.mkdir()
    real = tmp_path / "real"
    real.write_bytes(b"zip bytes")
    entry = make_zip_entry(tmp_path)
    (folder / entry.file).symlink_to(real)
    with pytest.raises(ToolError, match="regular file"):
        toolindex.fetch_zip(paths, Settings(tools_index=str(folder)), entry)


class _Serve:
    def __init__(self, body):
        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                try:
                    self.wfile.write(body)
                except OSError:
                    pass

            def log_message(self, *args):
                pass

        try:
            self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        except OSError:
            pytest.skip("cannot start a local server")
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return f"http://127.0.0.1:{self.server.server_address[1]}/f"

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


def test_default_download_stops_at_the_limit(tmp_path):
    target = tmp_path / "x.part"
    with _Serve(b"x" * 500_000) as url:
        with pytest.raises(ToolError, match="more than"):
            toolindex.download(url, target, 1000, 5.0)
    assert target.stat().st_size <= 1000


def test_default_download_writes_a_body_within_the_limit(tmp_path):
    target = tmp_path / "x.part"
    with _Serve(b"hello") as url:
        toolindex.download(url, target, 1000, 5.0)
    assert target.read_bytes() == b"hello"


class _Trickle:
    """A server that never quite stops: it sends a byte, waits, and sends another, for `lasts`
    seconds. Each byte arrives well inside the time allowed for one wait on the socket.

    `where` is the part it trickles: the body of the answer, or its header lines.
    """

    def __init__(self, where, lasts=4.0, pause=0.05):
        ends = []

        class Handler(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                end = time.monotonic() + lasts
                try:
                    if where == "body":
                        self.send_response(200)
                        self.send_header("Content-Length", "10000000")
                        self.end_headers()
                    else:
                        self.wfile.write(b"HTTP/1.1 200 OK\r\nX-Slow: ")
                    while time.monotonic() < end:
                        self.wfile.write(b"x")
                        self.wfile.flush()
                        time.sleep(pause)
                except OSError:
                    pass
                ends.append(time.monotonic())

            def log_message(self, *args):
                pass

        try:
            self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        except OSError:
            pytest.skip("cannot start a local server")
        self.server.daemon_threads = True
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self):
        self.thread.start()
        return f"http://127.0.0.1:{self.server.server_address[1]}/f"

    def __exit__(self, *exc):
        self.server.shutdown()
        self.server.server_close()


def _downloads_running():
    return [t for t in threading.enumerate() if t.name == toolindex.DOWNLOAD_THREAD]


def _wait_for_downloads_to_end(seconds):
    deadline = time.monotonic() + seconds
    while _downloads_running() and time.monotonic() < deadline:
        time.sleep(0.05)
    return _downloads_running() == []


def test_a_download_whose_body_trickles_is_given_up_on_after_the_whole_time_allowed(tmp_path):
    # each wait on the socket ends in time, so only a limit on the whole download ends it
    target = tmp_path / "x.part"
    started = time.monotonic()
    with _Trickle("body", lasts=4.0) as url:
        with pytest.raises(ToolError, match="took more than 0.5 seconds"):
            toolindex.download(url, target, 10_000_000, 0.5)
        assert time.monotonic() - started < 2.0
        # the transfer that was given up on ends at its next byte, long before the server
        # does, and writes nothing more
        assert _wait_for_downloads_to_end(1.5)
        size = target.stat().st_size
        time.sleep(0.3)
        assert target.stat().st_size == size


def test_a_download_whose_header_lines_trickle_is_given_up_on_too(tmp_path):
    target = tmp_path / "x.part"
    started = time.monotonic()
    with _Trickle("headers", lasts=1.5) as url:
        with pytest.raises(ToolError, match="took more than 0.5 seconds"):
            toolindex.download(url, target, 10_000_000, 0.5)
        assert time.monotonic() - started < 1.2
        # nothing was written, and the thread ends when the server ends its header lines
        assert not target.exists()
        assert _wait_for_downloads_to_end(4.0)
    assert not target.exists()


def test_a_download_within_its_time_is_not_cut_short(tmp_path):
    target = tmp_path / "x.part"
    with _Trickle("body", lasts=0.3) as url:
        toolindex.download(url, target, 10_000_000, 5.0)
    # all the server sent before it stopped; fetch_zip then finds it short of the index's size
    assert 0 < target.stat().st_size < 100
    assert set(target.read_bytes()) == {ord("x")}
    assert _downloads_running() == []


def test_a_download_error_reaches_the_caller_as_it_was(monkeypatch, tmp_path):
    def refuse(url, timeout):
        raise OSError("offline")

    monkeypatch.setattr(toolindex, "_open", refuse)
    with pytest.raises(OSError, match="offline"):
        toolindex.download(URL, tmp_path / "x.part", 100, 5.0)


def test_a_size_no_package_can_have_is_refused_in_the_index():
    limit = toolindex.MAX_ZIP_BYTES
    # what a package may unpack to, and room for its two lists of entries
    assert limit == 1024**3 + 2 * 4 * 1024 * 1024
    assert toolindex.parse_index(index_data(tool_row(builds=[build_row(size=limit)])))
    with pytest.raises(ToolError, match=rf"build\[0\]\.size: more than {limit} bytes"):
        toolindex.parse_index(index_data(tool_row(builds=[build_row(size=limit + 1)])))


def test_fetch_zip_refuses_a_size_no_package_can_have_before_it_downloads(paths, tmp_path):
    entry = replace(make_zip_entry(tmp_path), size=toolindex.MAX_ZIP_BYTES + 1)
    download = Downloader(b"zip bytes")
    with pytest.raises(ToolError, match="more than"):
        toolindex.fetch_zip(paths, url_settings(), entry, download=download)
    assert download.calls == []


def test_default_index_fetch_is_bounded(monkeypatch):
    monkeypatch.setattr(toolindex, "MAX_INDEX_BYTES", 100)
    with _Serve(b"x" * 500_000) as url:
        with pytest.raises(ToolError, match="more than"):
            toolindex._fetch_index(url, 5.0)
    with _Serve(b"small") as url:
        assert toolindex._fetch_index(url, 5.0) == b"small"


def test_known_names_reads_the_cache_without_fetching(paths):
    toolindex.load_index(paths, url_settings(), now=NOW, fetch=Fetcher(index_text().encode()))
    assert toolindex.known_names(paths, url_settings()) == ["kerbrute"]


def test_known_names_is_empty_without_a_cache_or_for_another_source(paths):
    assert toolindex.known_names(paths, url_settings()) == []
    toolindex.load_index(paths, url_settings(), now=NOW, fetch=Fetcher(index_text().encode()))
    other = Settings(tools_index="https://example.invalid/other/index.toml")
    assert toolindex.known_names(paths, other) == []


def test_known_names_reads_a_folder_index_and_survives_a_bad_one(paths, tmp_path):
    folder = tmp_path / "shop"
    folder.mkdir()
    settings = Settings(tools_index=str(folder))
    assert toolindex.known_names(paths, settings) == []
    (folder / "index.toml").write_text(index_text(), encoding="utf-8")
    assert toolindex.known_names(paths, settings) == ["kerbrute"]
    (folder / "index.toml").write_text("broken = [", encoding="utf-8")
    assert toolindex.known_names(paths, settings) == []


def folder_index(tmp_path, *tools):
    folder = tmp_path / "shop2"
    folder.mkdir()
    (folder / "index.toml").write_text(index_text(*tools), encoding="utf-8")
    return folder, Settings(tools_index=str(folder))


def test_known_names_refuses_a_file_over_the_size_cap_without_parsing(paths, tmp_path, monkeypatch):
    folder, settings = folder_index(tmp_path)
    monkeypatch.setattr(toolindex, "MAX_INDEX_BYTES", 10)
    parsed = []
    monkeypatch.setattr(toolindex, "_parse_bytes", lambda raw: parsed.append(raw))
    assert toolindex.known_names(paths, settings) == []
    assert parsed == []


def test_known_names_reads_an_unchanged_file_once(paths, tmp_path, monkeypatch):
    folder, settings = folder_index(tmp_path)
    reads = []
    real = toolindex._read_capped
    monkeypatch.setattr(toolindex, "_read_capped", lambda p: reads.append(p) or real(p))
    assert toolindex.known_names(paths, settings) == ["kerbrute"]
    assert toolindex.known_names(paths, settings) == ["kerbrute"]
    assert len(reads) == 1


def test_known_names_reads_a_changed_file_again(paths, tmp_path):
    folder, settings = folder_index(tmp_path)
    assert toolindex.known_names(paths, settings) == ["kerbrute"]
    (folder / "index.toml").write_text(
        index_text(tool_row(name="kerbrute"), tool_row(name="another-one")), encoding="utf-8"
    )
    assert toolindex.known_names(paths, settings) == ["another-one", "kerbrute"]


# ---- redirects


class StandIn(urllib.request.BaseHandler):
    # answers http and https from a table instead of the network
    handler_order = 100

    def __init__(self, answers):
        self.answers = answers
        self.asked = []

    def _answer(self, request):
        url = request.full_url
        self.asked.append(url)
        status, location, body = self.answers[url]
        headers = email.message.Message()
        if location:
            headers["Location"] = location
        response = urllib.response.addinfourl(io.BytesIO(body), headers, url, status)
        response.msg = "stand-in"
        return response

    http_open = https_open = _answer


def stand_in(monkeypatch, answers):
    handler = StandIn(answers)
    monkeypatch.setattr(toolindex, "_OPENER", toolindex._opener(handler))
    return handler


def test_the_opener_in_use_guards_redirects():
    kinds = [type(h) for h in toolindex._OPENER.handlers]
    assert toolindex._SafeRedirect in kinds
    assert urllib.request.HTTPRedirectHandler not in kinds


@pytest.mark.parametrize("code", [301, 302, 303, 307, 308])
@pytest.mark.parametrize(
    "target", ["ftp://example.invalid/index.toml", "file:///etc/passwd", "data:,schema"]
)
def test_a_redirect_away_from_http_is_refused(monkeypatch, code, target):
    handler = stand_in(monkeypatch, {URL: (code, target, b"")})
    with pytest.raises(ToolError, match="redirect"):
        toolindex._fetch_index(URL, 2)
    assert handler.asked == [URL]


def test_a_redirect_away_from_http_is_refused_for_a_zip_too(monkeypatch, tmp_path):
    stand_in(monkeypatch, {URL: (302, "ftp://example.invalid/x.zip", b"")})
    with pytest.raises(ToolError, match="redirect"):
        toolindex.download(URL, tmp_path / "x.zip", 100, 5)


@pytest.mark.parametrize("code", [301, 302, 307])
def test_a_redirect_from_https_to_http_is_refused(monkeypatch, code):
    # the index is not signed: once it came over https, a redirect may not hand it to plain http
    secure = "https://example.invalid/index.toml"
    plain = "http://example.invalid/index.toml"
    handler = stand_in(monkeypatch, {secure: (code, plain, b""), plain: (200, None, b"schema = 1\n")})
    with pytest.raises(ToolError, match="not https"):
        toolindex._fetch_index(secure, 2)
    assert handler.asked == [secure]


def test_a_redirect_from_https_to_http_is_refused_for_a_zip_too(monkeypatch, tmp_path):
    secure = "https://example.invalid/x.zip"
    stand_in(monkeypatch, {secure: (302, "http://example.invalid/x.zip", b"")})
    with pytest.raises(ToolError, match="not https"):
        toolindex.download(secure, tmp_path / "x.zip", 100, 5)


def test_a_redirect_to_https_is_followed(monkeypatch):
    other = "https://elsewhere.invalid/index.toml"
    handler = stand_in(monkeypatch, {URL: (302, other, b""), other: (200, None, b"schema = 1\n")})
    assert toolindex._fetch_index(URL, 2) == b"schema = 1\n"
    assert handler.asked == [URL, other]


# ---- one message for every failure with nothing to fall back on


def assert_says_where(err, where):
    text = str(err.value)
    assert where in text and "set tools_index in config.toml" in text, text


def test_a_timeout_without_a_cache_says_where_and_how_to_set_it(paths, monkeypatch):
    gate = threading.Event()

    def slow(url, timeout):
        gate.wait(5)
        return b""

    monkeypatch.setattr(toolindex, "QUICK_TIMEOUT", 0.05)
    try:
        with pytest.raises(ToolError) as err:
            toolindex.load_index(paths, url_settings(), now=NOW, fetch=slow)
    finally:
        gate.set()
    assert_says_where(err, URL)
    assert "no answer" in str(err.value)


def test_an_http_error_without_a_cache_says_where(paths):
    import urllib.error

    def refused(url, timeout):
        raise urllib.error.HTTPError(url, 404, "Not Found", {}, None)

    with pytest.raises(ToolError) as err:
        toolindex.load_index(paths, url_settings(), now=NOW, fetch=refused)
    assert_says_where(err, URL)


@pytest.mark.parametrize("body", [b"garbage = [", b"tool = []\n", b"schema = 5\n"])
def test_a_download_that_does_not_parse_says_where(paths, body):
    with pytest.raises(ToolError) as err:
        toolindex.load_index(paths, url_settings(), now=NOW, fetch=Fetcher(body))
    assert_says_where(err, URL)


@pytest.mark.parametrize("body", ["garbage = [", "tool = []\n", "schema = 5\n"])
def test_a_folder_index_that_does_not_parse_says_where(paths, tmp_path, body):
    (tmp_path / "index.toml").write_text(body, encoding="utf-8")
    with pytest.raises(ToolError) as err:
        toolindex.load_index(paths, Settings(tools_index=str(tmp_path)), now=NOW)
    assert_says_where(err, str(tmp_path / "index.toml"))


# ---- schema 2: runtimes and requires


def runtime_build(version="3.13.18", build=1, **over):
    row = build_row(
        version,
        build,
        kind="runtime",
        commands=[],
        file=f"python-3.13-{version}-{build}.zip",
        url=f"https://example.invalid/python-3.13-{version}-{build}.zip",
    )
    row.update(over)
    return row


def runtime_tool(builds=None, **over):
    row = tool_row(
        builds=builds if builds is not None else [runtime_build()],
        name="python-3.13",
        description="CPython 3.13, for the tools that require it",
        tags=["python"],
        licence="PSF-2.0",
        latest="3.13.18-1",
    )
    row.update(over)
    return row


def python_tool(**over):
    row = tool_row(
        builds=[build_row("5.1.0", 3, requires=["python-3.13"], file="certipy-5.1.0-3.zip")],
        name="certipy",
        description="Active Directory certificate abuse",
        tags=["ad"],
        latest="5.1.0-3",
    )
    row.update(over)
    return row


def schema2(*tools):
    return {"schema": 2, "tool": list(tools)}


def test_schema_1_index_parses_as_before():
    tool = toolindex.parse_index(index_data()).tools[0]
    assert tool.builds[0].requires == []
    assert not toolindex.is_runtime(tool)


def test_schema_1_index_refuses_requires():
    data = index_data(tool_row(builds=[build_row(requires=["python-3.13"])]))
    with pytest.raises(ToolError) as err:
        toolindex.parse_index(data)
    assert "tool kerbrute.build[0].requires: a schema 1 index has no requires" in str(err.value)


def test_schema_1_index_refuses_kind_runtime():
    with pytest.raises(ToolError) as err:
        toolindex.parse_index(index_data(runtime_tool()))
    assert "tool python-3.13.build[0].kind: runtime needs a schema 2 index" in str(err.value)


def test_schema_2_index_parses_runtimes_and_requires():
    index = toolindex.parse_index(schema2(runtime_tool(), python_tool(), tool_row()))
    runtime, certipy, kerbrute = index.tools
    assert runtime.name == "python-3.13" and runtime.builds[0].kind == "runtime"
    assert runtime.builds[0].file == "python-3.13-3.13.18-1.zip"
    assert certipy.builds[0].requires == ["python-3.13"]
    assert kerbrute.builds[0].requires == []
    assert toolindex.is_runtime(runtime)
    assert not toolindex.is_runtime(certipy) and not toolindex.is_runtime(kerbrute)


def test_is_runtime_reads_the_latest_build():
    tool = toolindex.parse_index(
        schema2(runtime_tool(builds=[runtime_build("3.13.17"), runtime_build("3.13.18")]))
    ).tools[0]
    assert toolindex.is_runtime(tool)


def test_an_entry_may_not_mix_runtime_with_other_kinds():
    mixed = runtime_tool(builds=[runtime_build(), build_row("3.13.19", 1)])
    with pytest.raises(ToolError) as err:
        toolindex.parse_index(schema2(mixed))
    assert "tool python-3.13: its builds mix kind runtime with other kinds" in str(err.value)


@pytest.mark.parametrize(
    "requires, message",
    [
        ("python-3.13", "requires: must be a list of strings"),
        ([1], "requires: must be a list of strings"),
        (["Python"], "requires: 'Python' is not a valid package name"),
        (["../x"], "requires: '../x' is not a valid package name"),
        (["a..b"], "requires: 'a..b' is not a valid package name"),
        (["python-3.13", "python-3.13"], "requires: 'python-3.13' appears more than once"),
        (["certipy"], "requires: certipy cannot require itself"),
    ],
)
def test_index_requires_rules(requires, message):
    tool = python_tool(build=[build_row("5.1.0", 3, requires=requires)])
    with pytest.raises(ToolError) as err:
        toolindex.parse_index(schema2(tool))
    assert message in str(err.value)


def test_index_runtime_requires_nothing():
    tool = runtime_tool(builds=[runtime_build(requires=["python-3.12"])])
    with pytest.raises(ToolError) as err:
        toolindex.parse_index(schema2(tool))
    assert "requires: a runtime requires nothing" in str(err.value)


@pytest.mark.parametrize("name", [".a", "a.", "a..b", "..", "Py-3.13"])
def test_index_tool_names_follow_the_package_rule(name):
    with pytest.raises(ToolError, match="name"):
        toolindex.parse_index(schema2(tool_row(name=name)))


def test_build_entry_requires_defaults_to_empty_for_positional_callers():
    entry = toolindex.BuildEntry("k", "1", 1, "kali", False, [], "k-1-1.zip", "", 1, HASH)
    assert entry.requires == []


def runtimes_index():
    return toolindex.parse_index(schema2(runtime_tool(), python_tool(), tool_row()))


def test_find_runtime():
    index = runtimes_index()
    assert toolindex.find_runtime(index, "python-3.13").name == "python-3.13"
    with pytest.raises(ToolError) as err:
        toolindex.find_runtime(index, "python-3.12")
    assert "python-3.12" in str(err.value) and "no runtime named" in str(err.value)
    with pytest.raises(ToolError) as err:
        toolindex.find_runtime(index, "certipy")
    assert "certipy is not a runtime" in str(err.value)


def test_search_leaves_runtimes_out():
    index = runtimes_index()
    names = lambda words: [t.name for t in toolindex.search(index, words)]  # noqa: E731
    assert names([]) == ["certipy", "kerbrute"]
    assert names(["python"]) == []
    assert names(["cpython"]) == []


def test_known_names_leave_runtimes_out(paths, tmp_path):
    folder = tmp_path / "shop3"
    folder.mkdir()
    (folder / "index.toml").write_text(
        tomli_w.dumps(schema2(runtime_tool(), python_tool(), tool_row())), encoding="utf-8"
    )
    settings = Settings(tools_index=str(folder))
    assert toolindex.known_names(paths, settings) == ["certipy", "kerbrute"]


def test_folder_index_written_by_the_toolkit_is_schema_2_only_when_needed(paths, tmp_path):
    _, kerbrute = make_entry(tmp_path / "zips")
    _, runtime = make_entry(tmp_path / "zips", {"kind": "runtime"})
    _, certipy = make_entry(
        tmp_path / "zips", {"name": "certipy", "requires": ["python-3.13"]}, files={}
    )
    plain = write_index(tmp_path / "one", [kerbrute])
    assert tomllib.loads(plain.read_text(encoding="utf-8"))["schema"] == 1
    both = write_index(tmp_path / "two", [kerbrute, runtime, certipy])
    data = tomllib.loads(both.read_text(encoding="utf-8"))
    assert data["schema"] == 2
    index = toolindex.load_index(paths, Settings(tools_index=str(tmp_path / "two")), now=NOW)
    assert [t.name for t in index.tools] == ["kerbrute", "python-3.13", "certipy"]
    assert toolindex.find_runtime(index, "python-3.13").builds[0].file == runtime.file
    assert toolindex.find_tool(index, "certipy").builds[0].requires == ["python-3.13"]


def test_index_runtime_has_no_commands():
    tool = runtime_tool(builds=[runtime_build(commands=["python3"])])
    with pytest.raises(ToolError) as err:
        toolindex.parse_index(schema2(tool))
    assert "tool python-3.13.build[0].commands: a runtime has no commands" in str(err.value)


def test_find_tool_never_suggests_a_runtime():
    index = runtimes_index()
    with pytest.raises(ToolError) as err:
        toolindex.find_tool(index, "python-3.1")
    assert "did you mean" not in str(err.value)
    with pytest.raises(ToolError, match="did you mean certipy"):
        toolindex.find_tool(index, "certipi")


# ---- a build's hash is kept, and an index that changes it is refused

OTHER_HASH = "b" * 64


def changed_text():
    return index_text(tool_row(builds=[build_row(sha256=OTHER_HASH)]))


def kept_hashes(paths):
    return {key: row.sha256 for key, row in toolindex.toolseen.load(paths).items()}


def assert_names_the_change(err):
    said = str(err.value)
    assert isinstance(err.value, toolindex.toolseen.BuildChanged)
    assert "kerbrute 1.0.3-1" in said and HASH in said and OTHER_HASH in said
    assert "tool forget kerbrute@1.0.3-1" in said
    # it is not the answer for an index that is missing: tools_index points at the right place
    assert "no usable tool index" not in said and "set tools_index" not in said


def test_the_first_index_read_has_every_build_kept(paths):
    # as on the first run after an upgrade: nothing is kept yet, so the first sight is
    both = tool_row(builds=[build_row(), build_row("1.0.2", 2, sha256=OTHER_HASH)])
    toolindex.load_index(paths, url_settings(), now=NOW, fetch=Fetcher(index_text(both).encode()))
    assert kept_hashes(paths) == {
        ("kerbrute", "1.0.3", 1): HASH, ("kerbrute", "1.0.2", 2): OTHER_HASH,
    }  # fmt: skip
    row = toolindex.toolseen.load(paths)[("kerbrute", "1.0.3", 1)]
    assert (row.seen, row.source) == (NOW, URL)


def test_a_folder_index_that_changes_a_build_is_refused(paths, tmp_path):
    settings = Settings(tools_index=str(tmp_path))
    file = tmp_path / "index.toml"
    file.write_text(index_text(), encoding="utf-8")
    toolindex.load_index(paths, settings, now=NOW)
    file.write_text(changed_text(), encoding="utf-8")
    for force in (False, True):
        with pytest.raises(ToolError) as err:
            toolindex.load_index(paths, settings, now=NOW, force=force)
        assert_names_the_change(err)
        # named once: the index refused is the one that first gave the build
        assert str(err.value).count(str(file)) == 1 and "since 2026-11-14." in str(err.value)
    assert kept_hashes(paths) == {("kerbrute", "1.0.3", 1): HASH}


@pytest.mark.parametrize("force", [False, True])
def test_a_download_that_changes_a_build_is_refused_and_never_replaces_the_cache(paths, force):
    toolindex.load_index(paths, url_settings(), now=NOW, fetch=Fetcher(index_text().encode()))
    cached = (paths.cache / "index.toml").read_bytes()
    stamp = (paths.cache / "index.fetched").read_bytes()
    later = NOW + timedelta(days=2)
    with pytest.raises(ToolError) as err:
        toolindex.load_index(
            paths, url_settings(), now=later, fetch=Fetcher(changed_text().encode()), force=force
        )
    assert_names_the_change(err)
    # the good copy is not used in its place without a word, and is not written over
    assert (paths.cache / "index.toml").read_bytes() == cached
    assert (paths.cache / "index.fetched").read_bytes() == stamp
    assert kept_hashes(paths) == {("kerbrute", "1.0.3", 1): HASH}


def test_a_mirror_that_gives_another_hash_for_a_build_is_refused(paths):
    toolindex.load_index(paths, url_settings(), now=NOW, fetch=Fetcher(index_text().encode()))
    mirror = Settings(tools_index="https://mirror.invalid/index.toml")
    with pytest.raises(ToolError) as err:
        toolindex.load_index(paths, mirror, now=NOW, fetch=Fetcher(changed_text().encode()))
    assert_names_the_change(err)
    assert URL in str(err.value) and "https://mirror.invalid/index.toml" in str(err.value)
    # the copy on disk is still the first index's
    assert URL in (paths.cache / "index.fetched").read_text(encoding="utf-8")


def test_a_mirror_that_gives_the_same_builds_is_taken(paths):
    toolindex.load_index(paths, url_settings(), now=NOW, fetch=Fetcher(index_text().encode()))
    mirror = Settings(tools_index="https://mirror.invalid/index.toml")
    index = toolindex.load_index(paths, mirror, now=NOW, fetch=Fetcher(index_text().encode()))
    assert index.tools[0].name == "kerbrute"
    assert toolindex.toolseen.load(paths)[("kerbrute", "1.0.3", 1)].source == URL


def test_the_cached_copy_is_held_to_the_builds_kept_too(paths):
    # the copy on disk is an index like any other: written by hand, or left by another version
    toolindex.load_index(paths, url_settings(), now=NOW, fetch=Fetcher(index_text().encode()))
    (paths.cache / "index.toml").write_text(changed_text(), encoding="utf-8")
    fetch = Fetcher(fail=True)
    with pytest.raises(ToolError) as err:
        toolindex.load_index(paths, url_settings(), now=NOW, fetch=fetch)
    assert_names_the_change(err)
    assert fetch.calls == []
    # and when the source does not answer and the copy stands in for it
    with pytest.raises(ToolError) as err:
        toolindex.load_index(paths, url_settings(), now=NOW + timedelta(days=2), fetch=fetch)
    assert_names_the_change(err)
    assert len(fetch.calls) == 1


def test_a_refused_index_has_none_of_its_new_builds_kept(paths):
    toolindex.load_index(paths, url_settings(), now=NOW, fetch=Fetcher(index_text().encode()))
    newer = tool_row(
        latest="1.0.4-1", builds=[build_row(sha256=OTHER_HASH), build_row("1.0.4", 1)]
    )
    with pytest.raises(ToolError):
        toolindex.load_index(
            paths, url_settings(), now=NOW, fetch=Fetcher(index_text(newer).encode()), force=True
        )
    assert kept_hashes(paths) == {("kerbrute", "1.0.3", 1): HASH}


def test_a_list_of_builds_that_cannot_be_read_stops_every_index(paths, tmp_path):
    paths.tools.mkdir(parents=True)
    paths.tools_seen.write_text("schema = 1\n[[build", encoding="utf-8")
    (tmp_path / "index.toml").write_text(index_text(), encoding="utf-8")
    for settings, fetch in (
        (Settings(tools_index=str(tmp_path)), Fetcher(fail=True)),
        (url_settings(), Fetcher(index_text().encode())),
    ):
        with pytest.raises(ToolError) as err:
            toolindex.load_index(paths, settings, now=NOW, fetch=fetch)
        assert str(paths.tools_seen) in str(err.value) and "set tools_index" not in str(err.value)
    # an index that could not be held to the list is not kept as the copy to fall back on
    assert not (paths.cache / "index.toml").exists()


def test_forgetting_a_build_lets_the_next_index_say_what_it_is(paths):
    toolindex.load_index(paths, url_settings(), now=NOW, fetch=Fetcher(index_text().encode()))
    (item,) = toolindex.toolseen.of_tool(paths, "kerbrute")
    assert toolindex.forget_build(paths, item) is True
    # the copy on disk agreed with the hash forgotten, so it is not taken as fresh: the index
    # is fetched, though a moment ago it was
    fetch = Fetcher(changed_text().encode())
    index = toolindex.load_index(paths, url_settings(), now=NOW, fetch=fetch)
    assert len(fetch.calls) == 1 and index.tools[0].builds[0].sha256 == OTHER_HASH
    assert kept_hashes(paths) == {("kerbrute", "1.0.3", 1): OTHER_HASH}
    # the row that was shown is gone: what is kept now is another hash, and stays
    assert toolindex.forget_build(paths, item) is False
    assert kept_hashes(paths) == {("kerbrute", "1.0.3", 1): OTHER_HASH}
    assert (paths.cache / "index.fetched").exists()


def test_fetch_zip_refuses_an_entry_whose_hash_is_not_the_one_kept(paths, tmp_path):
    entry = make_zip_entry(tmp_path)
    paths.cache.mkdir(parents=True)
    (paths.cache / entry.file).write_bytes(b"zip bytes")
    toolindex.toolseen.check(paths, [entry], where=URL, now=NOW)
    other = b"other bytes"
    changed = replace(entry, size=len(other), sha256=hashlib.sha256(other).hexdigest())
    download = Downloader(other)
    with pytest.raises(ToolError) as err:
        toolindex.fetch_zip(paths, url_settings(), changed, download=download)
    said = str(err.value)
    assert "kerbrute 1.0.3-1" in said and entry.sha256 in said and changed.sha256 in said
    # nothing was fetched, and the copy that matches the build kept is not dropped for it
    assert download.calls == []
    assert (paths.cache / entry.file).read_bytes() == b"zip bytes"
    got = toolindex.fetch_zip(paths, url_settings(), entry, download=download)
    assert got == paths.cache / entry.file and download.calls == []


def test_fetch_zip_still_replaces_a_damaged_copy_of_a_build_it_has_kept(paths, tmp_path):
    entry = make_zip_entry(tmp_path)
    toolindex.toolseen.check(paths, [entry], where=URL, now=NOW)
    paths.cache.mkdir(parents=True)
    (paths.cache / entry.file).write_bytes(b"cut sho")
    got = toolindex.fetch_zip(paths, url_settings(), entry, download=Downloader(b"zip bytes"))
    assert got.read_bytes() == b"zip bytes"
