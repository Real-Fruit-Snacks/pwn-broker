import hashlib
import stat
import sys

import pytest

from pwn_broker import recorder
from pwn_broker.recorder import RecorderError, fetch, present
from pwn_broker.toolindex import ToolError

GOOD = b"pretend this is the binary"
SUM = hashlib.sha256(GOOD).hexdigest()
SIZE = len(GOOD)


def writer(data):
    seen = []

    def download(url, dest, limit, timeout):
        seen.append((url, limit, timeout))
        dest.write_bytes(data)

    download.seen = seen
    return download


def leftovers(paths):
    return sorted(p.name for p in paths.asciinema.parent.iterdir() if p.name != "asciinema")


def test_the_pin():
    assert recorder.VERSION == "3.2.1"
    assert recorder.URL == (
        "https://github.com/asciinema/asciinema/releases/download/v3.2.1/asciinema-x86_64-unknown-linux-musl"
    )
    assert recorder.SIZE == 8130064
    assert recorder.SHA256 == "bec9781bc8f297a9d3d74ff60205599507f2abba1183578b8b2f22be4c999214"


def test_present_for_the_right_file(paths):
    paths.asciinema.parent.mkdir(parents=True)
    paths.asciinema.write_bytes(GOOD)
    assert present(paths, sha256=SUM) is True


def test_present_is_false_for_a_wrong_file(paths):
    paths.asciinema.parent.mkdir(parents=True)
    paths.asciinema.write_bytes(GOOD + b"x")
    assert present(paths, sha256=SUM) is False


def test_present_is_false_for_a_folder(paths):
    paths.asciinema.mkdir(parents=True)
    assert present(paths, sha256=SUM) is False


def test_present_is_false_for_nothing(paths):
    assert present(paths, sha256=SUM) is False


def test_present_hashes_the_file_each_time(paths):
    paths.asciinema.parent.mkdir(parents=True)
    paths.asciinema.write_bytes(GOOD)
    assert present(paths, sha256=SUM) is True
    paths.asciinema.write_bytes(b"changed")
    assert present(paths, sha256=SUM) is False


def test_fetch_installs_the_right_bytes(paths):
    download = writer(GOOD)
    fetch(paths, download=download, timeout=7.0, size=SIZE, sha256=SUM)
    assert paths.asciinema.read_bytes() == GOOD
    assert download.seen == [(recorder.URL, SIZE, 7.0)]
    assert leftovers(paths) == []
    assert present(paths, sha256=SUM)


@pytest.mark.skipif(sys.platform == "win32", reason="no file modes on Windows")
def test_fetch_makes_it_executable(paths):
    fetch(paths, download=writer(GOOD), size=SIZE, sha256=SUM)
    assert stat.S_IMODE(paths.asciinema.stat().st_mode) == 0o755


def test_fetch_makes_the_folder(paths):
    assert not paths.asciinema.parent.exists()
    fetch(paths, download=writer(GOOD), size=SIZE, sha256=SUM)
    assert paths.asciinema.is_file()


def test_fetch_replaces_a_wrong_copy(paths):
    paths.asciinema.parent.mkdir(parents=True)
    paths.asciinema.write_bytes(b"old and wrong")
    fetch(paths, download=writer(GOOD), size=SIZE, sha256=SUM)
    assert paths.asciinema.read_bytes() == GOOD


def raising(error):
    def download(url, dest, limit, timeout):
        dest.write_bytes(b"partial")
        raise error

    return download


@pytest.mark.parametrize(
    "download,words",
    [
        (writer(b"x" * SIZE), "checksum"),
        (writer(GOOD[:-1]), "size"),
        (writer(GOOD + b"!"), "size"),
        (raising(ToolError("the download took too long")), "took too long"),
        (raising(OSError("no space left")), "no space left"),
    ],
)
def test_a_failed_fetch_keeps_a_good_copy_and_leaves_nothing(paths, download, words):
    paths.asciinema.parent.mkdir(parents=True)
    paths.asciinema.write_bytes(GOOD)
    with pytest.raises(RecorderError, match=words):
        fetch(paths, download=download, size=SIZE, sha256=SUM)
    assert paths.asciinema.read_bytes() == GOOD
    assert leftovers(paths) == []


def test_a_failed_first_fetch_installs_nothing(paths):
    with pytest.raises(RecorderError, match="checksum"):
        fetch(paths, download=writer(b"y" * SIZE), size=SIZE, sha256=SUM)
    assert not paths.asciinema.exists()
    assert leftovers(paths) == []


def test_the_size_is_judged_before_the_checksum(paths):
    with pytest.raises(RecorderError, match="size"):
        fetch(paths, download=writer(b"short"), size=SIZE, sha256="0" * 64)


def test_a_download_that_writes_nothing_is_a_size_failure(paths):
    with pytest.raises(RecorderError, match="size"):
        fetch(paths, download=lambda url, dest, limit, timeout: None, size=SIZE, sha256=SUM)
