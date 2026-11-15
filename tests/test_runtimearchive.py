import io
import os
import random
import stat
import sys
import tarfile
from pathlib import Path

import pytest

from pwn_broker import runtimearchive
from pwn_broker.filescan import TEMP_PREFIX, TEMP_SUFFIX
from pwn_broker.runtimearchive import MAX_BYTES, MAX_MEMBERS, check, unpack
from pwn_broker.toolpkg import ToolError

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="needs symbolic links and modes")


def folder(name, mode=0o755):
    info = tarfile.TarInfo(name)
    info.type = tarfile.DIRTYPE
    info.mode = mode
    return info


def file(name, size=0, mode=0o644, kind=tarfile.REGTYPE):
    info = tarfile.TarInfo(name)
    info.type = kind
    info.size = size
    info.mode = mode
    return info


def link(name, target):
    info = tarfile.TarInfo(name)
    info.type = tarfile.SYMTYPE
    info.linkname = target
    return info


def special(name, kind, linkname=""):
    info = tarfile.TarInfo(name)
    info.type = kind
    info.linkname = linkname
    return info


def refused(members, words):
    with pytest.raises(ToolError, match=words):
        check(members)


# ---- check: what passes


def test_a_runtime_like_tree_passes():
    check(
        [
            folder("python"),
            folder("python/bin/"),
            file("python/bin/python3.13", 10, 0o755),
            link("python/bin/python3", "python3.13"),
            folder("python/share/terminfo/a"),
            file("python/share/terminfo/a/adm1178", 5),
            folder("python/share/terminfo/1"),
            link("python/share/terminfo/1/1178", "../a/adm1178"),
        ]
    )


def test_files_may_sit_in_folders_that_are_not_members():
    check([file("python/lib/os.py", 3), link("python/lib/os2.py", "os.py")])


def test_a_link_chain_that_stays_inside_passes():
    check(
        [
            folder("python/lib"),
            link("python/bin", "lib/bin"),
            link("python/lib/bin", "../real"),
            folder("python/real"),
            link("python/run", "bin/tool"),
        ]
    )


def test_a_dangling_link_inside_passes():
    check([link("python/bin/python", "python3.99")])


def test_a_link_to_its_own_folder_inside_passes():
    check([link("python/lib/here", ".")])


def test_exactly_the_member_limit_passes():
    check([file(f"f{i}") for i in range(MAX_MEMBERS)])


def test_exactly_the_size_limit_passes():
    check([file("a", MAX_BYTES - 1), file("b", 1)])


# ---- check: member types


@pytest.mark.parametrize(
    "member",
    [
        special("python/lib/hard", tarfile.LNKTYPE, "python/lib/real"),
        special("python/dev/tty", tarfile.CHRTYPE),
        special("python/dev/sda", tarfile.BLKTYPE),
        special("python/fifo", tarfile.FIFOTYPE),
        special("python/sparse", tarfile.GNUTYPE_SPARSE),
        special("python/longname", tarfile.GNUTYPE_LONGNAME),
        special("python/longlink", tarfile.GNUTYPE_LONGLINK),
    ],
    ids=["hard link", "char device", "block device", "fifo", "sparse", "long name", "long link"],
)
def test_other_member_types_are_refused(member):
    refused([folder("python"), member], "not a regular file, folder or symbolic link")


# ---- check: names


@pytest.mark.parametrize(
    "name",
    [
        "/etc/passwd",
        "/python/bin",
        "../python",
        "python/../../etc",
        "python/..",
        "python\\bin",
        "C:/python",
        "python/a:b",
        "python/a\nb",
        "python/a\x00b",
        "python/a\x1bb",
        "python/a\x7fb",
        "python/a\x85b",
        "",
        ".",
        "./python",
        "python/./bin",
        "python//bin",
    ],
)
def test_bad_names_are_refused(name):
    refused([file(name, 1)], "runtime archive entry")


def test_a_bad_folder_name_is_refused():
    refused([folder("../up/")], "runtime archive entry")


def test_a_bad_link_name_is_refused():
    refused([link("/usr/bin/python3", "x")], "runtime archive entry")


def test_a_trailing_slash_is_allowed_on_a_folder_only():
    check([folder("python/bin/")])
    refused([file("python/bin/", 1)], "runtime archive entry")


def test_a_duplicate_name_is_refused():
    refused([folder("python"), file("python/a", 1), file("python/a", 2)], "appears twice")


def test_a_folder_named_twice_with_and_without_slash_is_refused():
    refused([folder("python"), folder("python/")], "appears twice")


def test_a_member_inside_a_file_is_refused():
    refused([file("python/a", 1), file("python/a/b", 1)], "inside the file")


# ---- check: links


@pytest.mark.parametrize(
    "target",
    ["/etc/passwd", "/", "/opt/pwn-broker/runtimes/python-3.13/python/bin"],
)
def test_an_absolute_link_target_is_refused(target):
    refused([link("python/bin/python3", target)], "target")


@pytest.mark.parametrize("target", ["", "a\\b", "a:b", "a\nb", "a\x00b"])
def test_a_link_target_with_bad_characters_is_refused(target):
    refused([link("python/bin/python3", target)], "target")


@pytest.mark.parametrize(
    "name,target",
    [
        ("python/x", "../../etc/passwd"),
        ("python/x", "../.."),
        ("x", ".."),
        ("python/bin/x", "../../../outside"),
        ("python/a/b/c", "../../../../x"),
        # out and back in through the destination's own name is still out
        ("python/x", "../../python-3.13/python/y"),
    ],
)
def test_a_link_that_leaves_is_refused(name, target):
    refused([link(name, target)], "outside the runtime's folder")


@pytest.mark.parametrize("name,target", [("x", "."), ("python/x", ".."), ("python/x", "../")])
def test_a_link_to_the_destination_itself_is_refused(name, target):
    refused([link(name, target)], "outside the runtime's folder")


def test_a_link_that_leaves_through_a_second_link_is_refused():
    refused(
        [
            # each target alone stays inside; followed together they leave
            link("python/up", ".."),
            link("python/bin/esc", "../up/../x"),
        ],
        "outside the runtime's folder",
    )


def test_a_chain_that_leaves_at_its_last_link_is_refused():
    refused(
        [
            link("python/a", "b"),
            link("python/b", "c"),
            link("python/c", "../../out"),
        ],
        "outside the runtime's folder",
    )


def test_a_link_through_a_link_member_in_its_own_target_path_is_refused():
    refused(
        [
            folder("python/lib"),
            link("python/lib/deep", "../.."),
            link("python/z", "lib/deep/../x"),
        ],
        "outside the runtime's folder",
    )


def test_a_link_loop_is_refused():
    refused([link("python/a", "b"), link("python/b", "a")], "too many links")


def test_a_link_to_itself_is_refused():
    refused([link("python/a", "a")], "too many links")


def test_a_chain_longer_than_forty_is_refused():
    chain = [link(f"python/l{i}", f"l{i + 1}") for i in range(41)]
    refused(chain, "too many links")


def test_a_chain_of_forty_passes():
    check([link(f"python/l{i}", f"l{i + 1}") for i in range(40)])


def test_a_file_through_a_link_is_refused():
    refused([link("python/lib", "real"), file("python/lib/os.py", 1)], "through the link")


def test_a_folder_through_a_link_is_refused():
    refused([link("python/lib", "real"), folder("python/lib/sub")], "through the link")


def test_a_link_through_a_link_is_refused():
    refused([link("python/lib", "real"), link("python/lib/x", "y")], "through the link")


def test_a_file_listed_before_the_link_it_passes_through_is_refused():
    refused([file("python/lib/os.py", 1), link("python/lib", "real")], "through the link")


# ---- check: limits


def test_too_many_members_are_refused():
    refused([file(f"f{i}") for i in range(MAX_MEMBERS + 1)], "entries; the limit is 20000")


def test_check_stops_reading_once_over_the_member_limit():
    read = 0

    def members():
        nonlocal read
        for i in range(MAX_MEMBERS * 3):
            read += 1
            yield file(f"f{i}")

    refused(members(), "the limit is 20000")
    assert read == MAX_MEMBERS + 1


def test_too_many_bytes_are_refused():
    refused([file("a", MAX_BYTES), file("b", 1)], "more than 1073741824 bytes")


def test_the_limits():
    assert (MAX_MEMBERS, MAX_BYTES) == (20_000, 1024**3)


# ---- unpack


def make_tar(path: Path, members, data=None, *, mode="w:gz"):
    data = data or {}
    with tarfile.open(path, mode) as tar:
        for info in members:
            if info.isreg():
                body = data.get(info.name, b"x" * info.size)
                info.size = len(body)
                tar.addfile(info, io.BytesIO(body))
            else:
                tar.addfile(info)
    return path


def sample_members():
    return [
        folder("python"),
        folder("python/bin", 0o700),
        file("python/bin/python3.13", mode=0o700),
        link("python/bin/python3", "python3.13"),
        file("python/lib/os.py", mode=0o600),
        file("python/lib/tool.sh", mode=0o744),
        folder("python/share/terminfo/a"),
        file("python/share/terminfo/a/adm1178"),
        link("python/share/terminfo/1/1178", "../a/adm1178"),
    ]


SAMPLE_DATA = {
    "python/bin/python3.13": b"#!/bin/sh\n",
    "python/lib/os.py": b"import sys\n",
    "python/lib/tool.sh": b"echo hi\n",
    "python/share/terminfo/a/adm1178": b"adm",
}


def leftovers(parent: Path, *keep: str):
    return sorted(p.name for p in parent.iterdir() if p.name not in keep)


@posix_only
def test_unpack_writes_files_folders_and_links(tmp_path):
    archive = make_tar(tmp_path / "rt.tar.gz", sample_members(), SAMPLE_DATA)
    dest = tmp_path / "python-3.13"
    unpack(archive, dest)
    for name, body in SAMPLE_DATA.items():
        assert (dest / name).read_bytes() == body
    assert os.readlink(dest / "python/bin/python3") == "python3.13"
    assert (dest / "python/bin/python3").read_bytes() == b"#!/bin/sh\n"
    assert os.readlink(dest / "python/share/terminfo/1/1178") == "../a/adm1178"
    assert (dest / "python/share/terminfo/1/1178").read_bytes() == b"adm"
    assert leftovers(tmp_path) == ["python-3.13", "rt.tar.gz"]


@posix_only
def test_unpack_sets_modes(tmp_path):
    archive = make_tar(tmp_path / "rt.tar.gz", sample_members(), SAMPLE_DATA)
    dest = tmp_path / "python-3.13"
    old = os.umask(0o077)
    try:
        unpack(archive, dest)
    finally:
        os.umask(old)

    def mode(rel):
        return stat.S_IMODE(os.lstat(dest / rel).st_mode)

    assert mode(".") == 0o755
    assert mode("python") == 0o755
    assert mode("python/bin") == 0o755
    assert mode("python/lib") == 0o755  # not a member: made for the files in it
    assert mode("python/share/terminfo/1") == 0o755
    assert mode("python/bin/python3.13") == 0o755
    assert mode("python/lib/tool.sh") == 0o755
    assert mode("python/lib/os.py") == 0o644
    assert mode("python/share/terminfo/a/adm1178") == 0o644


def test_unpack_writes_files_and_folders_on_any_platform(tmp_path):
    members = [folder("python"), file("python/lib/os.py"), folder("python/empty")]
    archive = make_tar(tmp_path / "rt.tar.gz", members, {"python/lib/os.py": b"abc"})
    dest = tmp_path / "python-3.13"
    unpack(archive, dest)
    assert (dest / "python/lib/os.py").read_bytes() == b"abc"
    assert (dest / "python/empty").is_dir()
    assert leftovers(tmp_path) == ["python-3.13", "rt.tar.gz"]


@posix_only
def test_links_are_made_after_every_file_and_folder(tmp_path, monkeypatch):
    # the link comes first in the archive; the file it points at must already exist when it is made
    members = [link("python/a", "b"), file("python/b")]
    archive = make_tar(tmp_path / "rt.tar.gz", members, {"python/b": b"data"})
    made = []
    real = os.symlink

    def watch(target, name, *args, **kwargs):
        made.append((target, os.path.exists(Path(name).parent / target)))
        return real(target, name, *args, **kwargs)

    monkeypatch.setattr(runtimearchive.os, "symlink", watch)
    unpack(archive, tmp_path / "rt")
    assert made == [("b", True)]


def test_a_refused_link_is_never_made(tmp_path, monkeypatch):
    calls = []
    monkeypatch.setattr(runtimearchive.os, "symlink", lambda *a, **k: calls.append(a))
    archive = make_tar(tmp_path / "rt.tar.gz", [file("python/a"), link("python/x", "../../x")])
    with pytest.raises(ToolError):
        unpack(archive, tmp_path / "rt")
    assert calls == []
    assert leftovers(tmp_path) == ["rt.tar.gz"]


REFUSALS = {
    "hard link": [file("python/real"), special("python/hard", tarfile.LNKTYPE, "python/real")],
    "device": [special("python/tty", tarfile.CHRTYPE)],
    "fifo": [special("python/fifo", tarfile.FIFOTYPE)],
    "absolute name": [file("/abs/x")],
    "dot dot name": [file("python/../../x")],
    "backslash": [file("python\\x")],
    "colon": [file("C:/x")],
    "control character": [file("python/a\nb")],
    "absolute target": [link("python/x", "/etc/passwd")],
    "target leaves": [link("python/x", "../../x")],
    "leaves through a link": [link("python/up", ".."), link("python/esc", "up/../x")],
    "loop": [link("python/a", "b"), link("python/b", "a")],
    "file through a link": [link("python/lib", "real"), file("python/lib/x")],
    "duplicate": [file("python/a"), file("python/a")],
}


@pytest.mark.parametrize("case", sorted(REFUSALS))
def test_each_refusal_leaves_nothing(tmp_path, case):
    # files come first, so a refusal later in the archive proves nothing was written early
    members = [folder("python"), file("python/first"), *REFUSALS[case]]
    archive = make_tar(tmp_path / "rt.tar.gz", members)
    dest = tmp_path / "python-3.13"
    with pytest.raises(ToolError, match="^runtime archive"):
        unpack(archive, dest)
    assert leftovers(tmp_path) == ["rt.tar.gz"]


def test_too_many_members_leaves_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(runtimearchive, "MAX_MEMBERS", 3)
    archive = make_tar(tmp_path / "rt.tar.gz", [file(f"f{i}") for i in range(4)])
    with pytest.raises(ToolError, match="the limit is 3"):
        unpack(archive, tmp_path / "rt")
    assert leftovers(tmp_path) == ["rt.tar.gz"]


def test_too_many_bytes_leaves_nothing(tmp_path, monkeypatch):
    monkeypatch.setattr(runtimearchive, "MAX_BYTES", 5)
    archive = make_tar(tmp_path / "rt.tar.gz", [file("a", 3), file("b", 3)])
    with pytest.raises(ToolError, match="more than 5 bytes"):
        unpack(archive, tmp_path / "rt")
    assert leftovers(tmp_path) == ["rt.tar.gz"]


def test_an_existing_dest_is_refused(tmp_path):
    archive = make_tar(tmp_path / "rt.tar.gz", [file("python/a")])
    dest = tmp_path / "rt"
    dest.mkdir()
    (dest / "mine").write_text("keep")
    with pytest.raises(ToolError, match="already exists"):
        unpack(archive, dest)
    assert [p.name for p in dest.iterdir()] == ["mine"]
    assert leftovers(tmp_path) == ["rt", "rt.tar.gz"]


def test_an_existing_empty_dest_is_refused(tmp_path):
    archive = make_tar(tmp_path / "rt.tar.gz", [file("python/a")])
    (tmp_path / "rt").mkdir()
    with pytest.raises(ToolError, match="already exists"):
        unpack(archive, tmp_path / "rt")
    assert list((tmp_path / "rt").iterdir()) == []


def test_a_truncated_archive_is_refused(tmp_path):
    whole = make_tar(tmp_path / "whole.tar.gz", [file("python/a", 200_000)])
    raw = whole.read_bytes()
    archive = tmp_path / "rt.tar.gz"
    archive.write_bytes(raw[: len(raw) // 2])
    whole.unlink()
    with pytest.raises(ToolError, match="cannot unpack rt.tar.gz"):
        unpack(archive, tmp_path / "rt")
    assert leftovers(tmp_path) == ["rt.tar.gz"]


def test_a_truncated_file_after_good_ones_leaves_nothing(tmp_path):
    # incompressible data, so cutting the gzip stream cuts into the last file's body
    body = random.Random(1).randbytes(300_000)
    members = [folder("python"), file("python/a"), file("python/b")]
    whole = make_tar(tmp_path / "whole.tar.gz", members, {"python/a": b"a", "python/b": body})
    raw = whole.read_bytes()
    whole.unlink()
    archive = tmp_path / "rt.tar.gz"
    archive.write_bytes(raw[: len(raw) - 100_000])
    with pytest.raises(ToolError, match="cannot unpack rt.tar.gz"):
        unpack(archive, tmp_path / "rt")
    assert leftovers(tmp_path) == ["rt.tar.gz"]


def test_not_a_gzip_tar_is_refused(tmp_path):
    archive = tmp_path / "rt.tar.gz"
    archive.write_bytes(b"not an archive at all")
    with pytest.raises(ToolError, match="cannot unpack rt.tar.gz"):
        unpack(archive, tmp_path / "rt")
    assert leftovers(tmp_path) == ["rt.tar.gz"]


def test_a_plain_tar_is_refused(tmp_path):
    archive = make_tar(tmp_path / "rt.tar.gz", [file("python/a")], mode="w")
    with pytest.raises(ToolError, match="cannot unpack rt.tar.gz"):
        unpack(archive, tmp_path / "rt")
    assert leftovers(tmp_path) == ["rt.tar.gz"]


def test_a_missing_archive_is_refused(tmp_path):
    with pytest.raises(ToolError, match="cannot unpack rt.tar.gz"):
        unpack(tmp_path / "rt.tar.gz", tmp_path / "rt")
    assert leftovers(tmp_path) == []


def test_a_file_longer_than_it_declares_is_refused(tmp_path, monkeypatch):
    archive = make_tar(tmp_path / "rt.tar.gz", [file("python/a")], {"python/a": b"abcdef"})

    def longer(self, member):
        # a reader that yields more than the header declares
        return io.BytesIO(b"x" * (member.size + 5))

    monkeypatch.setattr(tarfile.TarFile, "extractfile", longer)
    with pytest.raises(ToolError, match="not the size it declares"):
        unpack(archive, tmp_path / "rt")
    assert leftovers(tmp_path) == ["rt.tar.gz"]


def test_a_refused_symlink_creation_is_a_tool_error(tmp_path, monkeypatch):
    def refuse(*args, **kwargs):
        raise OSError("symbolic links are not allowed here")

    monkeypatch.setattr(runtimearchive.os, "symlink", refuse)
    archive = make_tar(tmp_path / "rt.tar.gz", [file("python/a"), link("python/b", "a")])
    with pytest.raises(ToolError, match="symbolic links are not allowed here"):
        unpack(archive, tmp_path / "rt")
    assert leftovers(tmp_path) == ["rt.tar.gz"]


def test_a_failed_rename_leaves_nothing(tmp_path, monkeypatch):
    def refuse(src, dst):
        raise OSError("rename refused")

    monkeypatch.setattr(runtimearchive.os, "rename", refuse)
    archive = make_tar(tmp_path / "rt.tar.gz", [file("python/a")])
    with pytest.raises(ToolError, match="rename refused"):
        unpack(archive, tmp_path / "rt")
    assert leftovers(tmp_path) == ["rt.tar.gz"]


def test_the_temporary_folder_is_named_as_the_apps_own(tmp_path, monkeypatch):
    seen = []
    real = os.rename

    def watch(src, dst):
        seen.append(Path(src))
        return real(src, dst)

    monkeypatch.setattr(runtimearchive.os, "rename", watch)
    archive = make_tar(tmp_path / "rt.tar.gz", [file("python/a")])
    unpack(archive, tmp_path / "rt")
    [tmp] = seen
    assert tmp.parent == tmp_path
    assert tmp.name.startswith(TEMP_PREFIX) and tmp.name.endswith(TEMP_SUFFIX)
    assert not tmp.exists()


def test_an_interrupt_leaves_nothing(tmp_path, monkeypatch):
    def interrupt(src, dst):
        raise KeyboardInterrupt

    monkeypatch.setattr(runtimearchive.os, "rename", interrupt)
    archive = make_tar(tmp_path / "rt.tar.gz", [file("python/a")])
    with pytest.raises(KeyboardInterrupt):
        unpack(archive, tmp_path / "rt")
    assert leftovers(tmp_path) == ["rt.tar.gz"]
