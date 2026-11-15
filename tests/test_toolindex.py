import hashlib
import http.server
import os
import threading
import time
from dataclasses import replace
from datetime import timedelta

import pytest
import tomli_w

from helpers import NOW
from pwn_broker import toolindex
from pwn_broker.config import DEFAULT_TOOLS_INDEX, Settings
from pwn_broker.toolpkg import ToolError

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


@pytest.mark.parametrize("schema", [2, 0, "1", True, None])
def test_parse_schema_must_be_one(schema):
    data = index_data()
    data["schema"] = schema
    with pytest.raises(ToolError, match="upgrade pwn-broker"):
        toolindex.parse_index(data)


def test_parse_missing_schema():
    with pytest.raises(ToolError, match="upgrade pwn-broker"):
        toolindex.parse_index({"tool": []})


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
    bad = tomli_w.dumps({"schema": 2, "tool": []}).encode()
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
            toolindex._download(url, target, 1000, 5.0)
    assert target.stat().st_size <= 1000


def test_default_download_writes_a_body_within_the_limit(tmp_path):
    target = tmp_path / "x.part"
    with _Serve(b"hello") as url:
        toolindex._download(url, target, 1000, 5.0)
    assert target.read_bytes() == b"hello"


def test_default_index_fetch_is_bounded(monkeypatch):
    monkeypatch.setattr(toolindex, "MAX_INDEX_BYTES", 100)
    with _Serve(b"x" * 500_000) as url:
        with pytest.raises(ToolError, match="more than"):
            toolindex._fetch_index(url, 5.0)
    with _Serve(b"small") as url:
        assert toolindex._fetch_index(url, 5.0) == b"small"
